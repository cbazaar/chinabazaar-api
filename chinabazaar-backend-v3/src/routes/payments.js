// PayTR ödeme akışı (iframe):
//
// 1) POST /api/payments/paytr/init  { order_id }  -> { iframeUrl, token }
//
//    (auth gerekli)
//
// 2) Kullanıcı PayTR iframe'inde öder; PayTR sonucu merchant_ok/fail_url'e
//
//    FORM olarak POST eder (PayTR sunucusundan gelir, auth YOK)
//
// 3) POST /api/payments/paytr/callback { merchant_oid, status, total_amount, hash }
//
//    -> imza doğrulanır, sipariş "packing" olur. Yanıt gövdesi birebir "OK" olmalı.
//
// Kart bilgisi bizde ASLA tutulmaz.
//
// My Factory aboneligi (v3):
// 4) POST /api/payments/factory-subscription/create (auth) -> { merchant_oid, paytr_token, iframe_url }
// 5) POST /api/payments/factory-subscription/callback (auth YOK, PayTR post eder) -> 'OK'
// 6) GET  /api/payments/factory-subscription/status (auth) -> { active, ends_at, plan }

const express = require('express');
const { body, validationResult } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');
const paytr = require('../services/paytr');
const crypto = require('crypto');

const router = express.Router();

const PAYTR_IPS = new Set(['185.21.211.51', '185.21.211.52', '185.21.211.53', '185.21.211.54']);

function isPaytrIp(req) {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '';
  const clean = ip.replace(/^::ffff:/, '');
  if (process.env.PAYTR_TEST_MODE === '1') return true;
  return PAYTR_IPS.has(clean);
}

// ---- PayTR geri bildirimi (auth'suz; PayTR sunucusu çağırır, form-encoded) ----
router.post(
  '/paytr/callback',
  express.urlencoded({ extended: false }),
  asyncHandler(async (req, res) => {
    if (!isPaytrIp(req)) { return res.status(403).send('FORBIDDEN'); }
    const { merchant_oid, status, total_amount, hash } = req.body || {};
    if (!paytr.verifyCallback({ merchant_oid, status, total_amount, hash })) {
      return res.status(400).send('INVALID_HASH');
    }
    const ok = status === 'success';

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT * FROM payments WHERE conversation_id = $1 AND provider = $2 FOR UPDATE',
        [merchant_oid, 'paytr']
      );
      const payment = rows[0];
      if (!payment) {
        await client.query('ROLLBACK');
        return res.status(404).send('NOT_FOUND');
      }
      if (payment.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.send('OK'); // tekrar bildirimi
      }
      // Tutar uyuşmazlığı → güvenlik nedeniyle başarısız say
      if (String(payment.amount_cents) !== String(total_amount)) {
        await client.query(
          `UPDATE payments SET status='failed', raw_response=$1, updated_at=now() WHERE id=$2`,
          [JSON.stringify({ merchant_oid, status, total_amount, amount_mismatch: true }), payment.id]
        );
        await client.query('COMMIT');
        return res.send('OK');
      }

      await client.query(
        `UPDATE payments SET status=$1, raw_response=$2, updated_at=now() WHERE id=$3`,
        [ok ? 'success' : 'failed', JSON.stringify({ merchant_oid, status, total_amount }), payment.id]
      );
      if (ok) {
        await client.query(
          `UPDATE orders SET payment_status='paid', status='pending', updated_at=now() WHERE id=$1`,
          [payment.order_id]
        );
        await client.query(
          `UPDATE products p SET sold_count = sold_count + oi.qty
           FROM order_items oi WHERE oi.order_id=$1 AND oi.product_id=p.id`,
          [payment.order_id]
        );
      }
      await client.query('COMMIT');
      return res.send('OK');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  })
);

// ---- My Factory abonelik tablosu (products.js tarafi da ayni tabloyu ensure eder) ----
async function ensureFactorySubscriptions() {
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_subscriptions (id SERIAL PRIMARY KEY, user_id INT NOT NULL, status TEXT DEFAULT 'pending', started_at TIMESTAMPTZ, ends_at TIMESTAMPTZ, paytr_merchant_oid TEXT UNIQUE, amount INT, currency TEXT DEFAULT 'USD', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
}

// PayTR paneline kaydedilecek callback adresi (sabit: Railway uretim adresi)
const FACTORY_CALLBACK_URL = 'https://grand-creativity-production-5ef5.up.railway.app/api/payments/factory-subscription/callback';

// ---- My Factory abonelik geri bildirimi (auth'suz; PayTR sunucusu cagirir, form-encoded) ----
// Dogrulama: canli /paytr/callback ile ayni paytr.verifyCallback (merchantSalt ile hash).
// FARK: canli siparis callback'indeki PayTR IP izin listesi burada uygulanmaz —
// sozlesme yalniz hash dogrulamasi ister (hash gecersizse 400).
// Idempotent: status 'pending' degilse (active/failed) satir aynen birakilir, ends_at uzatilmez.
router.post(
  '/factory-subscription/callback',
  express.urlencoded({ extended: false }),
  asyncHandler(async (req, res) => {
    const { merchant_oid, status, total_amount, hash } = req.body || {};
    if (!paytr.verifyCallback({ merchant_oid, status, total_amount, hash })) {
      return res.status(400).send('INVALID_HASH');
    }
    const ok = status === 'success';
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT * FROM factory_subscriptions WHERE paytr_merchant_oid = $1 FOR UPDATE',
        [merchant_oid]
      );
      const sub = rows[0];
      if (!sub) {
        await client.query('ROLLBACK');
        return res.status(404).send('NOT_FOUND');
      }
      if (sub.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.send('OK'); // tekrar bildirimi — ends_at iki kez uzatilmez
      }
      if (!ok) {
        await client.query(`UPDATE factory_subscriptions SET status='failed', updated_at=now() WHERE id=$1`, [sub.id]);
        await client.query('COMMIT');
        return res.send('OK');
      }
      // Tutar uyuşmazlığı → güvenlik nedeniyle başarısız say (canli siparis akisiyla ayni)
      if (String(total_amount) !== String(sub.amount)) {
        await client.query(`UPDATE factory_subscriptions SET status='failed', updated_at=now() WHERE id=$1`, [sub.id]);
        await client.query('COMMIT');
        return res.send('OK');
      }
      await client.query(
        `UPDATE factory_subscriptions SET status='active', started_at=now(), ends_at=now() + interval '30 days', updated_at=now() WHERE id=$1`,
        [sub.id]
      );
      await client.query('COMMIT');
      return res.send('OK');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  })
);

router.use(requireAuth);

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim().slice(0, 45);
  return (req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : '127.0.0.1').slice(0, 45);
}

// POST /api/payments/paytr/init  { order_id }
router.post(
  '/paytr/init',
  body('order_id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!paytr.isEnabled()) return res.status(503).json({ error: 'payment_not_configured' });
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

    // PayTR merchant_oid her denemede benzersiz olmalı
    const { rows: prev } = await pool.query(
      `SELECT count(*)::int AS n FROM payments WHERE order_id=$1 AND provider='paytr'`,
      [order.id]
    );
    const attempt = (prev[0] ? prev[0].n : 0) + 1;
    const merchantOid = attempt === 1 ? order.order_no : `${order.order_no}-${attempt}`;

    const address = order.address_id
      ? {
          full_name: order.full_name, phone: order.phone, city: order.city,
          district: order.district, neighborhood: order.neighborhood,
          address_line: order.address_line,
        }
      : null;

    let result;
    try {
      result = await paytr.initPayment({
        merchantOid,
        userIp: clientIp(req),
        email: user.email,
        userName: address?.full_name || user.name || '',
        userAddress: address
          ? `${address.address_line}, ${address.neighborhood || ''} ${address.district}/${address.city}`.slice(0, 255)
          : '',
        userPhone: address?.phone || user.phone || '',
        totalCents: order.total_cents,
        currency: order.currency,
        items,
        okUrl: `${cfg.baseUrl}/api/payments/paytr/callback`,
        failUrl: `${cfg.baseUrl}/api/payments/paytr/callback`,
      });
    } catch (e) {
      await pool.query(
        `INSERT INTO payments (order_id, provider, status, conversation_id, amount_cents, currency, raw_response)
         VALUES ($1,'paytr','failed',$2,$3,$4,$5)`,
        [order.id, merchantOid, order.total_cents, order.currency, JSON.stringify({ error: String((e && e.message) || e) })]
      );
      return res.status(502).json({ error: 'paytr_init_failed' });
    }

    await pool.query(
      `INSERT INTO payments (order_id, provider, status, token, conversation_id, amount_cents, currency)
       VALUES ($1,'paytr','pending',$2,$3,$4,$5)`,
      [order.id, result.token, merchantOid, order.total_cents, order.currency]
    );

    res.json({ iframeUrl: result.iframeUrl, token: result.token });
  })
);

// ---- My Factory aboneligi ----

// POST /api/payments/factory-subscription/create (auth)
// -> { merchant_oid, paytr_token, iframe_url }
// Bekleyen abonelik varsa ayni merchant_oid yeniden kullanilir (tekrar uretilmez);
// PayTR token her cagirida tazelenir. 5 USD = 500 minor birim.
router.post(
  '/factory-subscription/create',
  asyncHandler(async (req, res) => {
    await ensureFactorySubscriptions();
    if (!paytr.isEnabled()) return res.status(503).json({ error: 'paytr_disabled' });
    const { rows: users } = await pool.query('SELECT id, email, name, phone FROM users WHERE id = $1', [req.user.id]);
    const user = users[0];
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    let merchantOid;
    const { rows: pend } = await pool.query(
      `SELECT * FROM factory_subscriptions WHERE user_id = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    if (pend.length) {
      merchantOid = pend[0].paytr_merchant_oid;
    } else {
      merchantOid = 'MF' + req.user.id + '-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
      await pool.query(
        `INSERT INTO factory_subscriptions (user_id, status, paytr_merchant_oid, amount, currency) VALUES ($1, 'pending', $2, 500, 'USD')`,
        [req.user.id, merchantOid]
      );
    }
    let result;
    try {
      result = await paytr.initPayment({
        merchantOid,
        userIp: clientIp(req),
        email: user.email,
        userName: user.name || '',
        userAddress: '',
        userPhone: user.phone || '',
        totalCents: 500,
        currency: 'USD',
        items: [{ name: 'My Factory 30 Gunluk Erisim', price_cents: 500, qty: 1 }],
        okUrl: FACTORY_CALLBACK_URL,
        failUrl: FACTORY_CALLBACK_URL,
      });
    } catch (e) {
      await pool.query(`UPDATE factory_subscriptions SET status='failed', updated_at=now() WHERE paytr_merchant_oid=$1 AND status='pending'`, [merchantOid]);
      return res.status(502).json({ error: 'paytr_init_failed' });
    }
    res.json({ merchant_oid: merchantOid, paytr_token: result.token, iframe_url: result.iframeUrl });
  })
);

// GET /api/payments/factory-subscription/status (auth)
// -> { active, ends_at, plan }
router.get(
  '/factory-subscription/status',
  asyncHandler(async (req, res) => {
    await ensureFactorySubscriptions();
    const { rows } = await pool.query(
      `SELECT * FROM factory_subscriptions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`,
      [req.user.id]
    );
    const sub = rows[0];
    if (!sub) return res.json({ active: false, ends_at: null, plan: '5 USD / 30 gün' });
    const active = sub.status === 'active' && sub.ends_at && new Date(sub.ends_at).getTime() > Date.now();
    res.json({ active: !!active, ends_at: sub.ends_at || null, plan: '5 USD / 30 gün' });
  })
);

module.exports = router;
