// Admin: Cloudflare Stream video yönetimi.
// POST /api/admin/stream/upload-url — tek kullanımlık yükleme URL'si üretir
// POST /api/admin/stream/attach     — yüklenen videoyu ürüne bağlar
// GET  /api/admin/stream/status     — yapılandırma + token doğrulama (tanı)
const express = require('express');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');
const stream = require('../services/stream');

const router = express.Router();
router.use(requireAuth, requireAdmin);

router.get(
  '/status',
  asyncHandler(async (_req, res) => {
    if (!stream.enabled()) return res.json({ configured: false, token_valid: false });
    const v = await stream.verifyToken().catch(() => ({ valid: false, status: null }));
    res.json({ configured: true, token_valid: v.valid, token_status: v.status });
  })
);

router.post(
  '/upload-url',
  asyncHandler(async (_req, res) => {
    if (!stream.enabled()) return res.status(503).json({ error: 'stream_not_configured' });
    try {
      const r = await stream.createDirectUpload();
      return res.json({ upload_url: r.uploadURL, uid: r.uid });
    } catch (e) {
      // Cloudflare'in gerçek hata mesajını döndür (token sızdırmaz)
      return res.status(502).json({ error: 'stream_api_failed', detail: String((e && e.message) || e).slice(0, 300) });
    }
  })
);

router.post(
  '/attach',
  body('product_id').isUUID(),
  body('uid').isLength({ min: 8, max: 64 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (!stream.enabled()) return res.status(503).json({ error: 'stream_not_configured' });
    const { product_id, uid } = req.body;

    const { rows } = await pool.query('SELECT id FROM products WHERE id = $1', [product_id]);
    if (!rows.length) return res.status(404).json({ error: 'product_not_found' });

    const video = await stream.getVideo(uid).catch(() => null);
    const playback_url = stream.playbackUrl(uid);
    const thumbnail_url = stream.thumbnailUrl(uid);
    const status = video && video.readyToStream ? 'ready' : 'processing';

    await pool.query(
      `INSERT INTO product_videos (product_id, stream_uid, status, playback_url, thumbnail_url)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (stream_uid) DO UPDATE SET
         product_id=EXCLUDED.product_id, status=EXCLUDED.status,
         playback_url=EXCLUDED.playback_url, thumbnail_url=EXCLUDED.thumbnail_url`,
      [product_id, uid, status, playback_url, thumbnail_url]
    );
    await pool.query(
      'UPDATE products SET video_url=$2, thumb_url=COALESCE(thumb_url,$3), updated_at=NOW() WHERE id=$1',
      [product_id, playback_url, thumbnail_url]
    );
    res.json({ ok: true, status, playback_url, thumbnail_url });
  })
);

module.exports = router;
