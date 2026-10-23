// Push cihaz kayıt uçları (CBOs-push hazırlığı).
//
// POST /api/push/register    (auth) — Expo tokenı ya da Web Push aboneliği
// POST /api/push/unregister  (auth) — kendi cihazını sil
// GET  /api/push/vapid-public-key   — Web Push genel anahtarı (env'den; yoksa null)
// GET  /api/admin/push/devices (admin; bu yönlendirici index.js'de ikinci kez
//      /api/admin/push altına da bağlanır) — kayıtlı cihaz listesi (jetonlar
//      MASKELİ döner, abonelik içerikleri dönmez).
//
// Sahiplik jetondan çözülür: kullanıcı → 'user', fabrika → 'factory',
// master (CBAi) → 'admin'. Admin bildirimleri owner 'admin' hedefine gider.
const express = require('express');
const router = express.Router();
const pool = require('../db');
const asyncHandler = require('../middleware/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pushService = require('../services/pushService');

function resolveOwner(req) {
  const u = req.user || {};
  if (u.role === 'master') return { ownerKind: 'admin', ownerId: 'admin' };
  if (u.role === 'factory' && Number.isInteger(u.factory_id)) return { ownerKind: 'factory', ownerId: String(u.factory_id) };
  if (u.id != null) return { ownerKind: 'user', ownerId: String(u.id) };
  return null;
}

const APPS = new Set(['shop', 'factory', 'admin', 'web']);

router.post('/register', requireAuth, asyncHandler(async (req, res) => {
  const owner = resolveOwner(req);
  if (!owner) return res.status(401).json({ ok: false, error: 'unauthorized' });
  const b = req.body || {};
  const app = typeof b.app === 'string' && APPS.has(b.app) ? b.app : null;

  // Web Push aboneliği
  if (b.kind === 'web' || b.subscription) {
    const sub = b.subscription;
    if (!sub || typeof sub.endpoint !== 'string' || !sub.endpoint.startsWith('https://')
        || !sub.keys || typeof sub.keys.p256dh !== 'string' || typeof sub.keys.auth !== 'string') {
      return res.status(400).json({ ok: false, error: 'invalid_subscription' });
    }
    const id = await pushService.upsertDevice(pool, {
      token: sub.endpoint.slice(0, 2048), kind: 'web', platform: 'web', app: app || 'web',
      ownerKind: owner.ownerKind, ownerId: owner.ownerId, subscription: sub,
    });
    return res.json({ ok: true, id, kind: 'web' });
  }

  // Expo tokenı
  const token = typeof b.token === 'string' ? b.token.trim() : '';
  if (!/^(ExponentPushToken|ExpoPushToken)\[[A-Za-z0-9_-]+\]$/.test(token)) {
    return res.status(400).json({ ok: false, error: 'invalid_token' });
  }
  const platform = b.platform === 'ios' || b.platform === 'android' ? b.platform : null;
  const id = await pushService.upsertDevice(pool, {
    token, kind: 'expo', platform, app,
    ownerKind: owner.ownerKind, ownerId: owner.ownerId, subscription: null,
  });
  res.json({ ok: true, id, kind: 'expo' });
}));

router.post('/unregister', requireAuth, asyncHandler(async (req, res) => {
  const owner = resolveOwner(req);
  if (!owner) return res.status(401).json({ ok: false, error: 'unauthorized' });
  const b = req.body || {};
  const token = typeof b.token === 'string' ? b.token : (b.subscription && typeof b.subscription.endpoint === 'string' ? b.subscription.endpoint : '');
  if (!token) return res.status(400).json({ ok: false, error: 'token_required' });
  // Yalnız çağıranın KENDİ cihazı silinir.
  await pushService.ensurePushSchema(pool);
  const r = await pool.query(
    `DELETE FROM push_devices WHERE token = $1 AND owner_kind = $2 AND owner_id = $3`,
    [token.slice(0, 2048), owner.ownerKind, owner.ownerId]
  );
  res.json({ ok: true, removed: r.rowCount || 0 });
}));

router.get('/vapid-public-key', asyncHandler(async (req, res) => {
  res.json({ ok: true, publicKey: process.env.VAPID_PUBLIC_KEY || null });
}));

// Admin: kayıtlı cihazlar (bu rota /api/admin/push/devices olarak çalışır).
router.get('/devices', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const items = await pushService.listAllDevices(pool, req.query.limit);
  res.json({ ok: true, items });
}));

// Admin: toplu duyuru — bir uygulamaya kayıtlı tüm cihazlara bildirim.
// POST /api/admin/push/broadcast  { app: 'shop'|'factory', text, url? }
router.post('/broadcast', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const b = req.body || {};
  const app = b.app === 'shop' || b.app === 'factory' ? b.app : null;
  if (!app) return res.status(400).json({ ok: false, error: 'invalid_app' });
  const text = String(b.text || '').replace(/\s+/g, ' ').trim().slice(0, 300);
  if (!text) return res.status(400).json({ ok: false, error: 'empty_text' });
  const fallback = app === 'shop' ? 'https://chinabazaar.shop' : 'https://chinabazaar.com';
  const url = typeof b.url === 'string' && b.url.startsWith('https://') ? b.url.slice(0, 500) : fallback;
  const CHANNELS = ['Duyuru', 'Reklam', 'Yeni Ürün', 'Sipariş', 'Yeni Fabrika'];
  const channel = CHANNELS.includes(b.channel) ? b.channel : 'Duyuru';
  const out = await pushService.notifyApp(pool, app, { channel, preview: text, url });
  res.json({ ok: true, app, ...out });
}));

module.exports = router;
