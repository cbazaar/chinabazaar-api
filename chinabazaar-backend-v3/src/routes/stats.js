// CBOs31 — Trafik istatistikleri: hafif ziyaret kalp atisi + izlenme olaylari.
// Kendi kodumuz; ucuncu taraf takip araci yok. SAHTE SAYI YOK: her metrik
// gercek tablodan turetilir; olay tablolari bu surumden itibaren birikir
// (fabrika CBOs26.4 deseni), gecmis yalnizca toplam sayaçlarda gorunur.
//
// Uclar:
//   POST /api/stats/ping {app:'shop'|'factory', sid}
//        Kimliksiz, hiz sinirli. site_visits upsert: first_seen yalniz ilk
//        gonderimde yazilir, last_seen her kalp atisinda tazelenir.
//        Gunluk benzersiz ziyaretci = o gun first_seen'i olan sid sayisi;
//        online = son 5 dk icinde last_seen'i olan sid sayisi.
//
// Urun izlenme olayi AYRI ucla DEGIL, mevcut POST /api/products/:id/view
// ucuna recordViewEvent() ile baglanir (cift sayim olmasin diye ayri bir
// /api/stats/view ucu ACILMADI). Fabrika izlenmeleri zaten
// factory_video_view_events'e yaziliyor (CBOs26.4) — oraya dokunulmaz.
//
// Okuma ucu: GET /api/admin/traffic (routes/admin.js; requireAdmin altinda).
const express = require('express');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const asyncHandler = require('../middleware/asyncHandler');
const pool = require('../db');

const router = express.Router();

// factory/presence deseniyle ayni oturum kimligi kurali (8-64 guvenli karakter).
const SESSION_RE = /^[A-Za-z0-9._-]{8,64}$/;
const APPS = new Set(['shop', 'factory']);

let statsEnsured = false;
async function ensureStatsTables() {
  if (statsEnsured) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS site_visits (sid TEXT PRIMARY KEY, app TEXT NOT NULL DEFAULT 'shop', first_seen TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_visits_last_seen ON site_visits (last_seen)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_visits_first_seen ON site_visits (first_seen)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS view_events (id BIGSERIAL PRIMARY KEY, product_id UUID, app TEXT NOT NULL DEFAULT 'shop', sid TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_view_events_created ON view_events (created_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_view_events_product ON view_events (product_id)`);
  // Gunluk begeni/yorum serisi indeksleri — kaynak tablo henuz yoksa sessizce gec
  // (migration 033 de ayni indeksleri kurar; cift guvence).
  try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_product_likes_created ON product_likes (created_at)`); } catch (e) { /* tablo yoksa seri sorgusu zaten 0 doner */ }
  try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_comments_created ON comments (created_at)`); } catch (e) { /* ayni */ }
  statsEnsured = true;
}

// Izlenme olayi yazimi sayaci ASLA bozmaz (fabrika video-view deseni):
// hata sessizce yoksayilir, cagiran uc davranisi degismez.
async function recordViewEvent(productId, opts) {
  try {
    await ensureStatsTables();
    const o = opts || {};
    const sid = typeof o.sid === 'string' && SESSION_RE.test(o.sid) ? o.sid : null;
    const app = APPS.has(o.app) ? o.app : 'shop';
    await pool.query(`INSERT INTO view_events (product_id, app, sid) VALUES ($1, $2, $3)`, [productId || null, app, sid]);
  } catch (e) { /* olay kaydi sayaci bozmaz */ }
}

// Kalp atisi icin nazik limit (IP basina dakikada 120). Kalp atisi istemcide
// ~30 sn'de bir atilir (ziyaretci basina ~2/dk); NAT arkasindaki cok
// ziyaretciye de pay kalir. factoryPresenceLimiter deseninin aynisi.
const statsPingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'stats-ping:' + ipKeyGenerator(req.ip),
});

// Temizlik (presence deseni): en fazla dakikada bir kosar, yaniti bozmaz.
// 30 gunden eski satirlar silinir — ufuk, 14 gunluk ziyaretci serisinin
// (first_seen) geriye donuk bozulmamasi icin seriden genis tutuldu.
let statsCleanupAt = 0;

router.post('/ping', statsPingLimiter, asyncHandler(async (req, res) => {
  await ensureStatsTables();
  const app = String((req.body && req.body.app) || '');
  const sid = String((req.body && req.body.sid) || '').trim();
  if (!APPS.has(app)) return res.status(400).json({ error: 'invalid_app' });
  if (!SESSION_RE.test(sid)) return res.status(400).json({ error: 'invalid_sid' });
  await pool.query(
    `INSERT INTO site_visits (sid, app) VALUES ($1, $2)
     ON CONFLICT (sid) DO UPDATE SET last_seen = now(), app = EXCLUDED.app`,
    [sid, app]
  );
  const nowMs = Date.now();
  if (nowMs - statsCleanupAt > 60 * 1000) {
    statsCleanupAt = nowMs;
    try { await pool.query(`DELETE FROM site_visits WHERE last_seen < now() - INTERVAL '30 days'`); } catch (e) { /* temizlik yaniti bozmaz */ }
  }
  res.json({ ok: true });
}));

module.exports = router;
module.exports.ensureStatsTables = ensureStatsTables;
module.exports.recordViewEvent = recordViewEvent;
module.exports.SESSION_RE = SESSION_RE;
