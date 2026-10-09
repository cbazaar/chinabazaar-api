// Siparişler — stok kontrollü, transaction içinde oluşturulur
const express = require('express');
const { body, validationResult } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth);

function nextOrderNo() {
  // CB-2026-XXXXXX (6 haneli rastgele, benzersizlik DB constraint ile garanti)
  const rand = Math.floor(100000 + Math.random() * 900000);
  return `CB-${new Date().getFullYear()}-${rand}`;
}

// POST /api/orders  { address_id, items: [{ product_id, qty }] }
router.post(
  '/',
  body('address_id').isUUID(),
  body('items').isArray({ min: 1 }),
  body('items.*.product_id').isUUID(),
  body('items.*.qty').isInt({ min: 1, max: 99 }),
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'validation_failed', details: errors.array() });

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
  asyncHandler(async (req, res) => {
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
    res.json({ ...order, items, payments });
  })
);

module.exports = router;
