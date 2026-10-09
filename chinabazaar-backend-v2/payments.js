// iyzico ödeme akışı (hosted checkout):
// 1) POST /api/payments/iyzico/init  { order_id }  -> { paymentPageUrl, token }
// 2) Kullanıcı iyzico sayfasında öder; iyzico token'ı callbackUrl'e POST eder
// 3) POST /api/payments/iyzico/callback { token } -> ödeme doğrulanır, sipariş "packing" olur
const express = require('express');
const { body, validationResult } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');
const iyzico = require('../services/iyzico');

const router = express.Router();
router.use(requireAuth);

// POST /api/payments/iyzico/init
router.post(
  '/iyzico/init',
  body('order_id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!iyzico.isEnabled()) return res.status(503).json({ error: 'payment_not_configured' });
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'validation_failed', details: errors.array() });

    const { rows } = await pool.query(
      `SELECT o.*, a.* FROM orders o LEFT JOIN addresses a ON a.id = o.address_id
       WHERE o.id = $1 AND o.user_id = $2`,
      [req.body.order_id, req.user.id]
    );
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });
    if (order.status !== 'pending') return res.status(409).json({ error: 'order_not_payable', status: order.status });

    const { rows: items } = await pool.query(
      `SELECT oi.name, oi.qty, oi.price_cents, c.name AS category
       FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id
       LEFT JOIN categories c ON c.id = p.category_id
       WHERE oi.order_id = $1`,
      [order.id]
    );
    const { rows: users } = await pool.query('SELECT id, email, name, phone FROM users WHERE id = $1', [req.user.id]);
    const user = users[0];

    const address = order.address_id
      ? {
          full_name: order.full_name, phone: order.phone, city: order.city,
          district: order.district, neighborhood: order.neighborhood,
          address_line: order.address_line,
        }
      : null;

    const result = await iyzico.initCheckout({
      orderNo: order.order_no,
      user,
      address,
      items,
      totalCents: order.total_cents,
      currency: order.currency,
      callbackUrl: `${cfg.baseUrl}/odeme/sonuc`,
    });

    if (result.status !== 'success' || !result.token) {
      await pool.query(
        `INSERT INTO payments (order_id, provider, status, amount_cents, currency, raw_response)
         VALUES ($1,'iyzico','failed',$2,$3,$4)`,
        [order.id, order.total_cents, order.currency, JSON.stringify(result)]
      );
      return res.status(502).json({ error: 'iyzico_init_failed' });
    }

    await pool.query(
      `INSERT INTO payments (order_id, provider, status, token, conversation_id, amount_cents, currency)
       VALUES ($1,'iyzico','pending',$2,$3,$4,$5)`,
      [order.id, result.token, order.order_no, order.total_cents, order.currency]
    );

    res.json({ paymentPageUrl: result.paymentPageUrl, token: result.token });
  })
);

// POST /api/payments/iyzico/callback  { token }
router.post(
  '/iyzico/callback',
  body('token').notEmpty(),
  asyncHandler(async (req, res) => {
    if (!iyzico.isEnabled()) return res.status(503).json({ error: 'payment_not_configured' });
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'validation_failed', details: errors.array() });

    const result = await iyzico.retrieveCheckout(req.body.token);
    const ok = result.status === 'success' && result.paymentStatus === 'SUCCESS';

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query('SELECT * FROM payments WHERE token = $1 FOR UPDATE', [req.body.token]);
      const payment = rows[0];
      if (!payment) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'payment_not_found' });
      }
      if (payment.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.json({ ok: payment.status === 'success', already_processed: true });
      }

      await client.query(
        `UPDATE payments SET status = $1, payment_id = $2, raw_response = $3, updated_at = now() WHERE id = $4`,
        [ok ? 'success' : 'failed', result.paymentId || null, JSON.stringify(result), payment.id]
      );

      if (ok) {
        await client.query(`UPDATE orders SET status = 'packing', updated_at = now() WHERE id = $1`, [payment.order_id]);
        // Satış adedini artır (ön yüz "satıldı" sayacı)
        await client.query(
          `UPDATE products p SET sold_count = sold_count + oi.qty
           FROM order_items oi WHERE oi.order_id = $1 AND oi.product_id = p.id`,
          [payment.order_id]
        );
      }

      await client.query('COMMIT');
      res.json({ ok });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  })
);

module.exports = router;
