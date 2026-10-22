// CBOs27.2 — Uygulama katmanı güvenlik duvarı (tarama isteklerini kesme).
//
// Bilinen tarama/keşif yolları (/.env, /.git, /.wp-admin, /wp-login.php,
// /phpmyadmin vb. ve .php uzantılı HER istek) 403 ile kesilir ve
// security_events tablosuna yazılır. Meşru API yolları bu desenlerin
// HİÇBİRİNE uymaz (tüm uçlar /api altında, .php uzantısı yok).
//
// Olay kaydı akışı BLOKLAMAZ: yazma arka planda (fire-and-forget),
// hata yutulur. Aynı (ip, path) çifti 60 sn içinde bir kez yazılır
// (sel saldırısında tablo şişmez; 403 yanıtı her seferinde verilir).
const pool = require('../db');

const SCANNER_PREFIXES = [
  '/.env',
  '/.git',
  '/.svn',
  '/.aws',
  '/.hg',
  '/wp-admin',
  '/wp-login',
  '/wp-content',
  '/wp-includes',
  '/phpmyadmin',
  '/php-my-admin',
  '/pma',
  '/vendor/phpunit',
  '/xmlrpc',
];

function normalizePath(p) {
  let s = String(p || '');
  try { s = decodeURIComponent(s); } catch (e) { /* bozuk kodlama: ham haliyle devam */ }
  return s.toLowerCase();
}

// Saf fonksiyon (birim testli): yol bir tarama yolu mu?
function isScannerPath(p) {
  const s = normalizePath(p);
  if (!s) return false;
  if (s.endsWith('.php')) return true;
  for (const pre of SCANNER_PREFIXES) {
    if (s === pre || s.startsWith(pre + '/') || s.startsWith(pre + '.')) return true;
  }
  return false;
}

let _eventsReady = null;
function ensureSecurityEventsTable() {
  if (!_eventsReady) {
    _eventsReady = (async () => {
      // CBOs27.4 (BIRLESIK TANIM): security_events TEK CREATE — CBOs27.2
      // (path) + CBOs27.3 (detail) ust kumesi. moderation.ensureSecurityEvents
      // ile BIREBIR ayni metindir; iki paketin yazdigi tum olay tipleri
      // (account_locked, scanner_probe, login_new_ip, content_blocked,
      // auto_block, client_violation, chat_report, unblock) calisir.
      await pool.query(
        `CREATE TABLE IF NOT EXISTS security_events (
           id SERIAL PRIMARY KEY,
           type TEXT NOT NULL,
           user_id TEXT,
           ip TEXT,
           path TEXT,
           detail JSONB,
           created_at TIMESTAMPTZ DEFAULT now()
         )`
      );
      // Tek-paket tanimiyla olusmus bir tablo varsa ust kumeye tamamla.
      await pool.query(`ALTER TABLE security_events ADD COLUMN IF NOT EXISTS path TEXT`);
      await pool.query(`ALTER TABLE security_events ADD COLUMN IF NOT EXISTS detail JSONB`);
    })().catch((e) => {
      console.error('[security] security_events tablosu hazir degil:', e && e.message ? e.message : e);
      _eventsReady = null; // sonraki çağrıda yeniden dene
    });
  }
  return _eventsReady;
}

const recentLogs = new Map(); // "ip|path" -> son yazım (ms) — 60 sn tekilleştirme
function logSecurityEvent(type, opts) {
  try {
    const o = opts || {};
    const ip = o.ip ? String(o.ip).slice(0, 128) : null;
    const path = o.path ? String(o.path).slice(0, 512) : null;
    const dedupKey = ip + '|' + path + '|' + type;
    const now = Date.now();
    if (type === 'scanner_probe' && recentLogs.get(dedupKey) && now - recentLogs.get(dedupKey) < 60 * 1000) return;
    recentLogs.set(dedupKey, now);
    if (recentLogs.size > 5000) recentLogs.clear();
    // Fire-and-forget: yanıt/akış beklenmez, hata yutulur.
    (async () => {
      await ensureSecurityEventsTable();
      await pool.query('INSERT INTO security_events (type, user_id, ip, path) VALUES ($1, $2, $3, $4)', [
        String(type).slice(0, 64),
        o.userId != null ? String(o.userId) : null,
        ip,
        path,
      ]);
    })().catch(() => {});
  } catch (e) { /* olay kaydı asla akışı bozmaz */ }
}

function securityGuard(req, res, next) {
  const p = req.path || '';
  if (isScannerPath(p)) {
    logSecurityEvent('scanner_probe', { ip: req.ip, path: p });
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

module.exports = { securityGuard, logSecurityEvent, isScannerPath, ensureSecurityEventsTable };
