// CBAI master jeton iptali (revocation) — 2026-10-20 güvenlik denetimi (N1).
//
// Sorun: master jetonlar `jti` taşır ama hiçbir kabul noktasında iptal
// kontrolü yoktu; sızan bir master jeton 24 saat tam yetkili kalıyordu.
//
// Tasarım:
// - `revoked_master_jtis` tablosu (jti TEXT PRIMARY KEY). Tablo ilk
//   kullanımda otomatik oluşur (CREATE TABLE IF NOT EXISTS).
// - `isMasterJtiRevoked(jti)`: DB hatasında / tablo yoksa FAIL-OPEN
//   (false döner) — iptal altyapısı hazır değilse admin paneli
//   kilitlenmez. Başarısızlık tek seferlik loglanır.
// - Yalnızca master rolündeki jetonlar için çağrılır; normal kullanıcı
//   akışına ek DB yükü getirmez.
const pool = require('../db');

let warned = false;
function warnOnce(e) {
  if (!warned) {
    warned = true;
    console.error('[master-revoke] iptal kontrolü atlandı (fail-open):', e && e.message ? e.message : e);
  }
}

async function ensureRevokeTable() {
  await pool.query(
    'CREATE TABLE IF NOT EXISTS revoked_master_jtis (jti TEXT PRIMARY KEY, revoked_at TIMESTAMPTZ DEFAULT now())'
  );
}

async function isMasterJtiRevoked(jti) {
  if (!jti || typeof jti !== 'string') return false;
  try {
    const { rows } = await pool.query('SELECT 1 FROM revoked_master_jtis WHERE jti = $1', [jti]);
    return rows.length > 0;
  } catch (e) {
    // Tablo henüz yoksa (42P01) veya DB kesintisinde: fail-open.
    warnOnce(e);
    return false;
  }
}

async function revokeMasterJti(jti) {
  await ensureRevokeTable();
  await pool.query('INSERT INTO revoked_master_jtis (jti) VALUES ($1) ON CONFLICT DO NOTHING', [jti]);
}

module.exports = { isMasterJtiRevoked, revokeMasterJti };
