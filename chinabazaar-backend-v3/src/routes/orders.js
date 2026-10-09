// Siparişler — stok kontrollü, transaction içinde oluşturulur
const express = require('express');
const { body, param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const { STAGES, TERMINAL } = require('../orderStages');
const cfg = require('../config');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth);

function nextOrderNo() {
  // CB-2026-XXXXXX (6 haneli rastgele, benzersizlik DB constraint ile garanti)
  const rand = Math.floor(100000 + Math.random() * 900000);
  return `CB-${new Date().getFullYear()}-${rand}`;
}

// GET /api/orders — kendi siparişleri (created_at DESC).
// Admin ?all=true ile tüm siparişleri (kullanıcı e-postasıyla) görür.
router.get(
  '/',
  asyncHandler(async (req, res) => {
    if (req.query.all === 'true') {
      const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
      if (!me[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
      const { rows } = await pool.query(
        `SELECT o.*, u.email AS user_email FROM orders o
         LEFT JOIN users u ON u.id = o.user_id
         ORDER BY o.created_at DESC LIMIT 200`
      );
      return res.json({ items: rows });
    }
    const { rows } = await pool.query(
      'SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// POST /api/orders  { address_id, items: [{ product_id, qty }] }
router.post(
  '/',
  body('address_id').isUUID(),
  body('items').isArray({ min: 1 }),
  body('items.*.product_id').isUUID(),
  body('items.*.qty').isInt({ min: 1, max: 99 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;

    const { address_id, items } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Adres kullanıcıya ait mi?
      const addr = await client.query('SELECT * FROM addresses WHERE id = $1 AND user_id = $2', [
        address_id,
        req.user.id,
      ]);
      if (!addr.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'address_not_found' });
      }

      // Ürünleri kilitleyip stok kontrolü yap
      const productIds = items.map((i) => i.product_id);
      const { rows: products } = await client.query(
        'SELECT * FROM products WHERE id = ANY($1) AND is_active = TRUE FOR UPDATE',
        [productIds]
      );
      const byId = Object.fromEntries(products.map((p) => [p.id, p]));

      let subtotal = 0;
      const lines = [];
      for (const it of items) {
        const p = byId[it.product_id];
        if (!p) {
          await client.query('ROLLBACK');
          return res.status(404).json({ error: 'product_not_found', product_id: it.product_id });
        }
        if (p.stock < it.qty) {
          await client.query('ROLLBACK');
          return res.status(409).json({ error: 'insufficient_stock', product_id: p.id, available: p.stock });
        }
        subtotal += p.price_cents * it.qty;
        lines.push({ product: p, qty: it.qty });
      }

      const shipping = cfg.shippingCents;
      const total = subtotal + shipping;

      const orderNo = nextOrderNo();
      const { rows: orderRows } = await client.query(
        `INSERT INTO orders (user_id, order_no, status, subtotal_cents, shipping_cents, total_cents, currency, address_id, address_snapshot)
         VALUES ($1,$2,'pending',$3,$4,$5,'TRY',$6,$7) RETURNING *`,
        [req.user.id, orderNo, subtotal, shipping, total, address_id, JSON.stringify(addr.rows[0])]
      );
      const order = orderRows[0];

      for (const l of lines) {
        await client.query(
          'INSERT INTO order_items (order_id, product_id, name, qty, price_cents) VALUES ($1,$2,$3,$4,$5)',
          [order.id, l.product.id, l.product.name, l.qty, l.product.price_cents]
        );
        await client.query('UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2', [
          l.qty,
          l.product.id,
        ]);
      }

      await client.query('COMMIT');
      res.status(201).json({
        id: order.id,
        order_no: order.order_no,
        status: order.status,
        subtotal_cents: order.subtotal_cents,
        shipping_cents: order.shipping_cents,
        total_cents: order.total_cents,
        currency: order.currency,
      });
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '23505') return res.status(409).json({ error: 'order_no_conflict_retry' });
      throw err;
    } finally {
      client.release();
    }
  })
);

// GET /api/orders/:id — yalnız sipariş sahibi (veya admin) görebilir
router.get(
  '/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });

    const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (order.user_id !== req.user.id && !me[0]?.is_admin) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { rows: items } = await pool.query('SELECT product_id, name, qty, price_cents FROM order_items WHERE order_id = $1', [order.id]);
    const { rows: payments } = await pool.query(
      'SELECT provider, status, payment_id, amount_cents, currency, created_at FROM payments WHERE order_id = $1 ORDER BY created_at DESC',
      [order.id]
    );
    res.json({
      ...order,
      cargo: {
        company: order.cargo_company,
        tracking_number: order.tracking_number,
        shipped_at: order.shipped_at,
      },
      items,
      payments,
    });
  })
);

// PATCH /api/orders/:id/tracking — kargo bilgisi güncelleme (yalnız admin)
router.patch(
  '/:id/tracking',
  requireAdmin,
  param('id').isUUID(),
  body('cargo_company').optional().trim().isLength({ max: 60 }),
  body('tracking_number').optional().trim().isLength({ max: 60 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { cargo_company, tracking_number } = req.body;
    if (cargo_company === undefined && tracking_number === undefined) {
      return res.status(400).json({ error: 'nothing_to_update' });
    }
    const { rows } = await pool.query(
      `UPDATE orders
       SET cargo_company = COALESCE($2, cargo_company),
           tracking_number = COALESCE($3, tracking_number),
           shipped_at = CASE WHEN $3 IS NOT NULL THEN COALESCE(shipped_at, now()) ELSE shipped_at END,
           status = CASE WHEN $3 IS NOT NULL AND status IN ('packing','ready') THEN 'shipped' ELSE status END,
           updated_at = now()
       WHERE id = $1 RETURNING id, order_no, status, cargo_company, tracking_number, shipped_at`,
      [req.params.id, cargo_company ?? null, tracking_number ?? null]
    );
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    res.json(rows[0]);
  })
);

// PATCH /api/orders/:id/status — sipariş durumu güncelleme (yalnız admin)
// Kabul edilen değerler: 6 kanonik aşama (packing→ready→shipped→in_transit→arriving→delivered)
// + cancelled/refunded. Geçersiz değer 400 ile reddedilir.
router.patch(
  '/:id/status',
  requireAdmin,
  param('id').isUUID(),
  body('status')
    .isString()
    .custom((v) => [...STAGES, ...TERMINAL].includes(v))
    .withMessage('invalid_status'),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(
      `UPDATE orders SET status = $2, updated_at = now() WHERE id = $1
       RETURNING id, order_no, status, cargo_company, tracking_number, updated_at`,
      [req.params.id, req.body.status]
    );
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    res.json(rows[0]);
  })
);

module.exports = router;
