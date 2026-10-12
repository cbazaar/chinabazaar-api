// Ürün kataloğu — ön yüz (video akış) sözleşmesine uygun JSON döner:
// { id, name, tagline, description, price_cents, price_display, currency,
//   sold_count, stock, category: {id, slug, name}, video_url, thumb_url }
const express = require('express');
const { body, param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth, optionalAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');

const router = express.Router();

function formatPrice(cents, currency) {
  const cur = ['TRY', 'USD', 'RUB'].includes(currency) ? currency : 'TRY';
  try {
    return new Intl.NumberFormat('tr-TR', { style: 'currency', currency: cur }).format(cents / 100);
  } catch {
    return new Intl.NumberFormat('tr-TR', { style: 'currency', currency: 'TRY' }).format(cents / 100);
  }
}

function toProduct(row) {
  return {
    id: row.id,
    sku: row.sku,
    name: row.name,
    tagline: row.tagline,
    description: row.description,
    price_cents: row.price_cents,
    price_display: formatPrice(row.price_cents, row.currency),
    currency: row.currency,
    color: row.color,
    size: row.size,
    dimensions: row.dimensions,
    box_dimensions: row.box_dimensions,
    weight: row.weight,
    sold_count: row.sold_count,
    stock: row.stock,
    view_count: row.view_count || 0,
    like_count: row.like_count || 0,
    favorite_count: row.favorite_count || 0,
    comment_count: row.comment_count || 0,
    share_count: row.share_count || 0,
    barcode: row.barcode || null,
    storage: row.storage || null,
    is_upcoming: !!row.is_upcoming,
    category: row.category_id
      ? { id: row.category_id, slug: row.category_slug, name: row.category_name }
      : null,
    video_url: row.video_url,
    video_mp4_url: streamMp4(row.video_url),
    thumb_url: row.thumb_url || streamThumb(row.video_url),
  };
}

// video_url'den MP4 adresi üret (iOS için)
function streamMp4(videoUrl){
  if(!videoUrl) return null;
  const m = String(videoUrl).match(/videodelivery\.net\/([a-f0-9]+)/i);
  return m ? `https://videodelivery.net/${m[1]}/downloads/default.mp4` : null;
}

// video_url bir Cloudflare Stream adresiyse otomatik küçük resim üret
function streamThumb(videoUrl){
  if(!videoUrl) return null;
  const m = String(videoUrl).match(/videodelivery\.net\/([a-f0-9]{32})/i)
         || String(videoUrl).match(/cloudflarestream\.com\/([a-f0-9]{32})/i);
  return m ? ('https://videodelivery.net/'+m[1]+'/thumbnails/thumbnail.jpg') : null;
}

const SELECT = `
  SELECT p.*, c.slug AS category_slug, c.name AS category_name,
    (SELECT COUNT(*) FROM product_likes l WHERE l.product_id = p.id)::int AS like_count,
    (SELECT COUNT(*) FROM favorites f WHERE f.product_id = p.id)::int AS favorite_count,
    (SELECT COUNT(*) FROM comments cm WHERE cm.product_id = p.id)::int AS comment_count,
    (SELECT COUNT(*) FROM product_shares s WHERE s.product_id = p.id)::int AS share_count
  FROM products p
  LEFT JOIN categories c ON c.id = p.category_id
`;

// GET /api/products?category=electronics&q=kulaklik&limit=20&offset=0&sort=popular
// Admin ?all=true ile pasif ürünleri de görür (token gerekli).
router.get(
  '/',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const { category, q } = req.query;
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const sort = req.query.sort || 'popular'; // popular | newest | price_asc | price_desc

    let showAll = false;
    if (req.query.all === 'true') {
      if (!req.user) return res.status(401).json({ error: 'unauthorized' });
      const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
      showAll = !!me[0]?.is_admin;
      if (!showAll) return res.status(403).json({ error: 'forbidden' });
    }

    const upcomingOnly = req.query.upcoming === 'true';
    const where = [showAll ? 'TRUE' : (upcomingOnly ? 'p.is_upcoming = TRUE' : '(p.is_active = TRUE AND p.is_upcoming = FALSE)')];
    const params = [];
    if (category) {
      params.push(category);
      where.push(`c.slug = $${params.length}`);
    }
    if (q) {
      params.push(`%${q}%`);
      where.push(`(p.name ILIKE $${params.length} OR p.description ILIKE $${params.length})`);
    }

    const orderBy =
      sort === 'newest' ? 'p.created_at DESC'
      : sort === 'price_asc' ? 'p.price_cents ASC'
      : sort === 'price_desc' ? 'p.price_cents DESC'
      : 'p.sold_count DESC';

    params.push(limit, offset);
    const { rows } = await pool.query(
      `${SELECT} WHERE ${where.join(' AND ')} ORDER BY ${orderBy} LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json({ items: rows.map(toProduct), limit, offset });
  })
);

// POST /api/products/:id/like — beğeni aç/kapa (toggle)
router.post(
  '/:id/like',
  param('id').isUUID(),
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    const { rows: ex } = await pool.query('SELECT 1 FROM product_likes WHERE user_id=$1 AND product_id=$2', [req.user.id, req.params.id]);
    let liked;
    if (ex.length) {
      await pool.query('DELETE FROM product_likes WHERE user_id=$1 AND product_id=$2', [req.user.id, req.params.id]);
      liked = false;
    } else {
      await pool.query('INSERT INTO product_likes (user_id, product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.id]);
      liked = true;
    }
    const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM product_likes WHERE product_id=$1', [req.params.id]);
    res.json({ liked, like_count: c[0].n });
  })
);

// POST /api/products/:id/share — paylaşım sayacı
router.post(
  '/:id/share',
  param('id').isUUID(),
  optionalAuth,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    await pool.query('INSERT INTO product_shares (product_id, user_id) VALUES ($1,$2)', [req.params.id, req.user ? req.user.id : null]);
    const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM product_shares WHERE product_id=$1', [req.params.id]);
    res.json({ share_count: c[0].n });
  })
);

// GET /api/products/:id
// ALL /api/products/enable-mp4 (GET/POST) — tüm Cloudflare videoları için MP4 indirmeyi etkinleştir (admin)
router.all('/enable-mp4', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { enableMp4DownloadDebug } = require('../services/stream');
    const { rows } = await pool.query("SELECT id, video_url FROM products WHERE video_url LIKE '%videodelivery.net%'");
    let ok = 0, fail = 0;
    const errors = [];
    for (const r of rows) {
      const m = String(r.video_url).match(/videodelivery\.net\/([a-f0-9]+)/i);
      if (!m) { fail++; errors.push('no-uid'); continue; }
      const result = await enableMp4DownloadDebug(m[1]);
      if (result.ok) ok++; else { fail++; if(errors.length<3) errors.push(result.error); }
    }
    res.json({ ok: true, enabled: ok, failed: fail, total: rows.length, errors });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

router.get(
  '/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(`${SELECT} WHERE p.id = $1 AND p.is_active = TRUE`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
    res.json(toProduct(rows[0]));
  })
);



// ---- Admin CRUD (yalnız is_admin) ----

const productValidators = [
  body('name').trim().isLength({ min: 2, max: 200 }),
  body('price').isFloat({ min: 0, max: 10000000 }).withMessage('price_must_be_non_negative'),
  body('stock').optional().isInt({ min: 0, max: 1000000 }),
  body('description').optional().trim().isLength({ max: 10000 }),
  body('tagline').optional().trim().isLength({ max: 200 }),
  body('sku').optional().trim().isLength({ max: 60 }),
  body('image_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('video_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('category').optional({ values: 'falsy' }).trim().isLength({ max: 100 }),
  body('is_active').optional().isBoolean(),
  body('is_upcoming').optional().isBoolean().toBoolean(),
  body('currency').optional().trim().isIn(['TRY', 'USD', 'RUB']),
  body('color').optional().trim().isLength({ max: 200 }),
  body('storage').optional().trim().isLength({ max: 200 }),
  body('size').optional().trim().isLength({ max: 200 }),
  body('dimensions').optional().trim().isLength({ max: 200 }),
  body('box_dimensions').optional().trim().isLength({ max: 200 }),
  body('weight').optional().trim().isLength({ max: 200 }),
  body('barcode').optional().trim().matches(/^[0-9]{8,14}$/),
];

// category: slug veya UUID kabul eder → category_id çözer (boşsa NULL)
async function resolveCategoryId(category) {
  if (!category) return null;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(category)) return category;
  const { rows } = await pool.query('SELECT id FROM categories WHERE slug = $1', [category]);
  return rows[0]?.id || null;
}

function toCents(price) {
  return Math.round(Number(price) * 100);
}

// POST /api/products — yeni ürün (admin)
router.post(
  '/',
  requireAuth,
  requireAdmin,
  ...productValidators,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { name, price, stock, description, tagline, sku, image_url, video_url, category, is_active, currency, color, size, dimensions, box_dimensions, weight, barcode, storage, is_upcoming } = req.body;
    const categoryId = await resolveCategoryId(category);
    try {
      const { rows } = await pool.query(
        `INSERT INTO products (sku, name, tagline, description, price_cents, currency, stock, category_id, video_url, thumb_url, is_active, color, size, dimensions, box_dimensions, weight, barcode, storage, is_upcoming)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
        [
          sku || null, name, tagline || null, description || null, toCents(price),
          ['TRY','USD','RUB'].includes(currency) ? currency : 'TRY',
          stock ?? 0, categoryId, video_url || null, image_url || null,
          is_active === undefined ? true : is_active,
          color || null, size || null, dimensions || null, box_dimensions || null, weight || null,
          barcode || null, storage || null, is_upcoming === true,
        ]
      );
      res.status(201).json(toProduct({ ...rows[0], category_slug: null, category_name: null }));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'sku_in_use' });
      throw err;
    }
  })
);

// PUT /api/products/:id — ürün güncelleme (admin, kısmi)
router.put(
  '/:id',
  requireAuth,
  requireAdmin,
  param('id').isUUID(),
  body('name').optional().trim().isLength({ min: 2, max: 200 }),
  body('price').optional().isFloat({ min: 0, max: 10000000 }),
  body('stock').optional().isInt({ min: 0, max: 1000000 }),
  body('description').optional().trim().isLength({ max: 10000 }),
  body('tagline').optional().trim().isLength({ max: 200 }),
  body('sku').optional().trim().isLength({ max: 60 }),
  body('image_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('video_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('category').optional({ values: 'falsy' }).trim().isLength({ max: 100 }),
  body('is_active').optional().isBoolean(),
  body('is_upcoming').optional().isBoolean().toBoolean(),
  body('currency').optional().trim().isIn(['TRY', 'USD', 'RUB']),
  body('color').optional().trim().isLength({ max: 200 }),
  body('storage').optional().trim().isLength({ max: 200 }),
  body('size').optional().trim().isLength({ max: 200 }),
  body('dimensions').optional().trim().isLength({ max: 200 }),
  body('box_dimensions').optional().trim().isLength({ max: 200 }),
  body('weight').optional().trim().isLength({ max: 200 }),
  body('barcode').optional().trim().matches(/^[0-9]{8,14}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const map = {
      name: 'name', tagline: 'tagline', description: 'description', sku: 'sku',
      video_url: 'video_url', image_url: 'thumb_url', is_active: 'is_active',
      currency: 'currency', color: 'color', storage: 'storage', is_upcoming: 'is_upcoming', size: 'size', dimensions: 'dimensions',
      box_dimensions: 'box_dimensions', weight: 'weight', barcode: 'barcode',
    };
    const sets = [];
    const params = [req.params.id];
    for (const [key, col] of Object.entries(map)) {
      if (req.body[key] !== undefined) {
        params.push(key === 'image_url' && !req.body[key] ? null : req.body[key]);
        sets.push(`${col} = $${params.length}`);
      }
    }
    if (req.body.price !== undefined) {
      params.push(toCents(req.body.price));
      sets.push(`price_cents = $${params.length}`);
    }
    if (req.body.stock !== undefined) {
      params.push(req.body.stock);
      sets.push(`stock = $${params.length}`);
    }
    if (req.body.category !== undefined) {
      params.push(await resolveCategoryId(req.body.category));
      sets.push(`category_id = $${params.length}`);
    }
    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
    sets.push('updated_at = now()');
    try {
      const { rows } = await pool.query(
        `UPDATE products SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
        params
      );
      if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
      res.json(toProduct({ ...rows[0], category_slug: null, category_name: null }));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'sku_in_use' });
      throw err;
    }
  })
);

// DELETE /api/products/:id — ürün silme (admin).
// order_items FK'si ON DELETE SET NULL: geçmiş siparişler korunur (ad/fiyat snapshot'ı durur).
router.delete(
  '/:id',
  requireAuth,
  requireAdmin,
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query('DELETE FROM products WHERE id = $1 RETURNING id', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
    res.json({ deleted: true, id: rows[0].id });
  })
);

// POST /api/products/:id/view — izlenme sayacı (herkese açık, sessiz artar)
router.post(
  '/:id/view',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await pool.query('UPDATE products SET view_count = view_count + 1 WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  })
);

// GET /api/products/:id/comments — görünür yorumlar (herkese açık)
router.get(
  '/:id/comments',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(
      `SELECT c.id, c.body, c.created_at, COALESCE(u.nickname, u.name) AS user_name
       FROM comments c JOIN users u ON u.id = c.user_id
       WHERE c.product_id = $1 AND c.is_blocked = FALSE
       ORDER BY c.created_at DESC LIMIT 100`,
      [req.params.id]
    );
    res.json({ items: rows });
  })
);

// POST /api/products/:id/comments — yorum ekle (giriş gerekli)
router.post(
  '/:id/comments',
  requireAuth,
  param('id').isUUID(),
  body('body').trim().isLength({ min: 1, max: 1000 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const me = await pool.query('SELECT is_blocked FROM users WHERE id = $1', [req.user.id]);
    if (me.rows[0]?.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    const { rows } = await pool.query(
      `INSERT INTO comments (product_id, user_id, body) VALUES ($1, $2, $3)
       RETURNING id, body, created_at`,
      [req.params.id, req.user.id, req.body.body.trim()]
    );
    res.status(201).json(rows[0]);
  })
);

module.exports = router;
