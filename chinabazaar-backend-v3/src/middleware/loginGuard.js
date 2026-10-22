// CBOs27.2 — Hesap kilidi + jeton sürümü durumu (kullanıcı satırı OLMAYAN
// asıl: CBAI master). Kullanıcılar ve fabrikalar kendi token_version /
// kilit sütunlarını kullanır (users / factories); master'ın DB satırı
// olmadığı için durumu bu tabloda tutulur:
//
//   login_guard (guard_key TEXT PRIMARY KEY, failed_login_count INT,
//                lock_level INT, locked_until TIMESTAMPTZ,
//                token_version INT, updated_at TIMESTAMPTZ)
//
// KİLİT POLİTİKASI (kullanıcı + master için AYNI — auth.js de buradaki saf
// geçişleri kullanır):
//   5 ardışık başarısız deneme → kilit. Süre lock_level'a göre:
//   kademe 0 → 15 dk, kademe 1 → 1 saat, kademe 2+ → 24 saat.
//   Kilit anında başarısız sayacı sıfırlanır (kilit açılınca taze 5 hak),
//   lock_level KALICIDIR (tekrarlayan hesap üst kademeden devam eder).
//   Başarılı girişte yalnız başarısız sayacı sıfırlanır.
//
// FAIL-OPEN: DB hatasında kilit/sürüm kontrolleri "bilinmiyor" (null)
// döner ve çağıran akışa devam eder (masterRevoke deseni) — kilit
// altyapısındaki bir arıza girişleri topluca kilitlemez. Hata tek
// seferlik loglanır.
const pool = require('../db');

const MASTER_GUARD_KEY = 'master:cbai';
const LOCK_THRESHOLD = 5;

let warned = false;
function warnOnce(e) {
  if (!warned) {
    warned = true;
    console.error('[login-guard] durum okunamadı (fail-open):', e && e.message ? e.message : e);
  }
}

// Kademe → kilit süresi (ms). Saf fonksiyon (birim testli).
function lockDurationMs(level) {
  const l = Number.isInteger(level) && level > 0 ? level : 0;
  if (l <= 0) return 15 * 60 * 1000; // 15 dk
  if (l === 1) return 60 * 60 * 1000; // 1 saat
  return 24 * 60 * 60 * 1000; // 24 saat
}

// Bir başarısız deneme sonrası yeni durum (saf fonksiyon, birim testli).
// prev: { failed_login_count, lock_level } (eksik alanlar 0 sayılır).
function nextFailureState(prev) {
  const count = (prev && Number.isInteger(prev.failed_login_count) ? prev.failed_login_count : 0) + 1;
  const level = prev && Number.isInteger(prev.lock_level) ? prev.lock_level : 0;
  if (count >= LOCK_THRESHOLD) {
    return { failed_login_count: 0, lock_level: level + 1, locked_for_ms: lockDurationMs(level), just_locked: true };
  }
  return { failed_login_count: count, lock_level: level, locked_for_ms: 0, just_locked: false };
}

let _tableReady = null;
function ensureLoginGuardTable() {
  if (!_tableReady) {
    _tableReady = pool
      .query(
        `CREATE TABLE IF NOT EXISTS login_guard (
           guard_key TEXT PRIMARY KEY,
           failed_login_count INT NOT NULL DEFAULT 0,
           lock_level INT NOT NULL DEFAULT 0,
           locked_until TIMESTAMPTZ,
           token_version INT NOT NULL DEFAULT 0,
           updated_at TIMESTAMPTZ DEFAULT now()
         )`
      )
      .catch((e) => {
        warnOnce(e);
        _tableReady = null; // sonraki çağrıda yeniden dene
      });
  }
  return _tableReady;
}

// Satırı okur; hata/satır yoksa null (fail-open).
async function getGuard(key) {
  try {
    await ensureLoginGuardTable();
    const { rows } = await pool.query(
      'SELECT guard_key, failed_login_count, lock_level, locked_until, token_version FROM login_guard WHERE guard_key = $1',
      [key]
    );
    return rows[0] || null;
  } catch (e) {
    warnOnce(e);
    return null;
  }
}

async function upsertGuard(key, st) {
  await ensureLoginGuardTable();
  await pool.query(
    `INSERT INTO login_guard (guard_key, failed_login_count, lock_level, locked_until, token_version, updated_at)
     VALUES ($1, $2, $3, $4, $5, now())
     ON CONFLICT (guard_key) DO UPDATE SET
       failed_login_count = EXCLUDED.failed_login_count,
       lock_level = EXCLUDED.lock_level,
       locked_until = EXCLUDED.locked_until,
       token_version = EXCLUDED.token_version,
       updated_at = now()`,
    [key, st.failed_login_count || 0, st.lock_level || 0, st.locked_until || null, st.token_version || 0]
  );
}

// Kilit durumu: { locked:false } | { locked:true, retryAfterSec }.
// Okunamazsa fail-open: { locked:false }.
async function checkGuardLock(key) {
  const row = await getGuard(key);
  if (row && row.locked_until && new Date(row.locked_until).getTime() > Date.now()) {
    return { locked: true, retryAfterSec: Math.max(1, Math.ceil((new Date(row.locked_until).getTime() - Date.now()) / 1000)) };
  }
  return { locked: false };
}

// Başarısız denemeyi işler; kilit yeni oluştuysa { justLocked:true, lockedForMs }.
async function registerGuardFailure(key) {
  try {
    const row = (await getGuard(key)) || { failed_login_count: 0, lock_level: 0, token_version: 0 };
    const st = nextFailureState(row);
    await upsertGuard(key, {
      failed_login_count: st.failed_login_count,
      lock_level: st.lock_level,
      locked_until: st.just_locked ? new Date(Date.now() + st.locked_for_ms) : row.locked_until || null,
      token_version: row.token_version || 0,
    });
    return { justLocked: st.just_locked, lockedForMs: st.locked_for_ms };
  } catch (e) {
    warnOnce(e);
    return { justLocked: false, lockedForMs: 0 };
  }
}

// Başarılı giriş: başarısız sayacı sıfırlanır (lock_level kalıcı).
async function registerGuardSuccess(key) {
  try {
    const row = await getGuard(key);
    if (!row) return;
    await upsertGuard(key, {
      failed_login_count: 0,
      lock_level: row.lock_level || 0,
      locked_until: null,
      token_version: row.token_version || 0,
    });
  } catch (e) {
    warnOnce(e);
  }
}

// Jeton sürümü: okunamazsa null (çağıran fail-open davranır).
async function getGuardTokenVersion(key) {
  const row = await getGuard(key);
  if (!row) return null;
  return Number.isInteger(row.token_version) ? row.token_version : 0;
}

// Jeton sürümünü +1 yapar (TÜM mevcut jetonlar geçersiz olur). Yeni sürümü döner.
async function bumpGuardTokenVersion(key) {
  const row = (await getGuard(key)) || { failed_login_count: 0, lock_level: 0, locked_until: null, token_version: 0 };
  const next = (row.token_version || 0) + 1;
  await upsertGuard(key, {
    failed_login_count: row.failed_login_count || 0,
    lock_level: row.lock_level || 0,
    locked_until: row.locked_until || null,
    token_version: next,
  });
  return next;
}

module.exports = {
  MASTER_GUARD_KEY,
  LOCK_THRESHOLD,
  lockDurationMs,
  nextFailureState,
  ensureLoginGuardTable,
  checkGuardLock,
  registerGuardFailure,
  registerGuardSuccess,
  getGuardTokenVersion,
  bumpGuardTokenVersion,
};
