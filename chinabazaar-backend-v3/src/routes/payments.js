// fix10e (2026-10-19) — güvenlik düzeltmeleri: H-F SELECT gölgeleme, M8 çift ödeme,
// M16 ödeme başlatma limiti, L17 raw_response ham hata / tutar uyuşmazlığı / aktif
// abonelik koruması / clientIp XFF, SABAH-4 isPaytrIp XFF.
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
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit'); // fix10e: v8 keyGenerator IP doğrulaması (ERR_ERL_KEY_GEN_IPV6) için gerekli
// fix10e (M16): ödeme başlatma limitleri — kullanıcı başına 15 dakika.
const payInitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'paytr-init:' + String((req.user && req.user.id) || (req.ip ? ipKeyGenerator(req.ip) : 'unknown')),
});
const factorySubLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'factory-sub:' + String((req.user && req.user.id) || (req.ip ? ipKeyGenerator(req.ip) : 'unknown')),
});


const router = express.Router();

const PAYTR_IPS = new Set(['185.21.211.51', '185.21.211.52', '185.21.211.53', '185.21.211.54']);

function isPaytrIp(req) {
  // fix10e (SABAH-4 / L17): X-Forwarded-For'un ilk girdisi istemci tarafından
  // uydurulabilir — Express'in trust proxy: 1 ile hesapladığı req.ip kullanılır.
  // Hash doğrulaması (verifyCallback) asıl kontrol olmaya devam eder.
  const ip = String(req.ip || (req.socket && req.socket.remoteAddress) || '');
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
      // fix10e (M8): sipariş satırını da kilitle — yan etkiler (ödendi işareti
      // + sold_count) sipariş başına en fazla 1 kez uygulanır. Aynı sipariş için
      // ikinci bir PayTR akışı (farklı merchant_oid) başarı bildirirse parası
      // alınmış ödeme 'success' yazılır ama yan etki tekrarlanmaz.
      const { rows: orderRows } = await client.query(
        'SELECT id, payment_status FROM orders WHERE id = $1 FOR UPDATE',
        [payment.order_id]
      );
      const orderRow = orderRows[0];
      if (!orderRow) {
        await client.query('ROLLBACK');
        return res.status(404).send('NOT_FOUND');
      }
      // Tutar uyuşmazlığı → başarısız say; ham hata yazılmaz, yeniden deneme
      // engellenmez (yeni PayTR başlatma her zaman mümkün — retry edilebilir).
      if (String(payment.amount_cents) !== String(total_amount)) {
        await client.query(
          `UPDATE payments SET status='failed', raw_response=$1, updated_at=now() WHERE id=$2`,
          [JSON.stringify({ merchant_oid, status, total_amount, amount_mismatch: true, retryable: true }), payment.id]
        );
        await client.query('COMMIT');
        return res.send('OK');
      }

      await client.query(
        `UPDATE payments SET status=$1, raw_response=$2, updated_at=now() WHERE id=$3`,
        [ok ? 'success' : 'failed', JSON.stringify({ merchant_oid, status, total_amount, ...(ok && orderRow.payment_status === 'paid' ? { already_paid: true } : {}) }), payment.id]
      );
      if (ok && orderRow.payment_status !== 'paid') {
        // Koşullu güncelleme: yarışta yalnız bir callback öder + satar.
        const { rowCount } = await client.query(
          `UPDATE orders SET payment_status='paid', status='pending', updated_at=now() WHERE id=$1 AND payment_status='unpaid'`,
          [payment.order_id]
        );
        if (rowCount === 1) {
          await client.query(
            `UPDATE products p SET sold_count = sold_count + oi.qty
             FROM order_items oi WHERE oi.order_id=$1 AND oi.product_id=p.id`,
            [payment.order_id]
          );
        }
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

// v620: Abonelik planlari (monthly / yearly) — SADECE EKLEME.
// Asagidaki uc rota, mevcut plan-siz rotalarin ONUNE kayitlidir. Express
// rotalari kayit sirasina gore eslestirdigi icin bu plan-aware surumler
// calisir; eski handler'lar aynen durur (hicbir satirina dokunulmadi).
// Eski davranis korunur: plan verilmezse 'monthly' (5 USD / 30 gun) varsayilir.
const FACTORY_SUBSCRIPTION_PLANS = {
  monthly: { amount: 500, days: 30, label: 'My Factory 30 Gunluk Erisim' },
  yearly: { amount: 6000, days: 365, label: 'My Factory 365 Gunluk Erisim' },
};
function factoryPlanOf(value) {
  if (value === 'yearly') return 'yearly';
  return 'monthly';
}
async function ensureFactorySubscriptionPlanColumn() {
  await ensureFactorySubscriptions();
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'monthly'`);
}

// v620 POST /api/payments/factory-subscription/callback (plan-aware; eski callback'in onu)
// Eski callback ile ayni sozlesme: hash dogrulamasi, idempotent (pending degilse OK,
// ends_at uzatilmez). Fark: tutar kontrolu aboneligin plan tutariyla yapilir ve
// basarida ends_at = started_at + plan suresi (monthly 30 gun / yearly 365 gun).
router.post(
  '/factory-subscription/callback',
  express.urlencoded({ extended: false }),
  asyncHandler(async (req, res) => {
    const { merchant_oid, status, total_amount, hash } = req.body || {};
    if (!paytr.verifyCallback({ merchant_oid, status, total_amount, hash })) {
      return res.status(400).send('INVALID_HASH');
    }
    const ok = status === 'success';
    await ensureFactorySubscriptionPlanColumn();
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
      // Tutar kontrolu: o aboneligin PLANININ tutariyla (yalniz 500 degil)
      const plan = factoryPlanOf(sub.plan);
      const expectedAmount = FACTORY_SUBSCRIPTION_PLANS[plan].amount;
      if (String(total_amount) !== String(expectedAmount)) {
        await client.query(`UPDATE factory_subscriptions SET status='failed', updated_at=now() WHERE id=$1`, [sub.id]);
        await client.query('COMMIT');
        return res.send('OK');
      }
      await client.query(
        `UPDATE factory_subscriptions SET status='active', started_at=now(), ends_at=now() + make_interval(days => $1), updated_at=now() WHERE id=$2`,
        [FACTORY_SUBSCRIPTION_PLANS[plan].days, sub.id]
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

// v620 POST /api/payments/factory-subscription/create (plan-aware; eski create'in onu)
// -> { merchant_oid, paytr_token, iframe_url, plan }
// { plan: 'monthly' | 'yearly' } kabul eder; plan yoksa varsayilan 'monthly'.
// Bekleyen abonelik AYNI plandaysa ayni merchant_oid doner; farkli planda yeni satir acilir.
router.post(
  '/factory-subscription/create',
  requireAuth,
  factorySubLimiter,
  asyncHandler(async (req, res) => {
    await ensureFactorySubscriptionPlanColumn();
    // fix10e (L17): aktif abonelik varken yeniden ödeme başlatılamaz.
    const { rows: activeSub } = await pool.query(
      `SELECT id, ends_at FROM factory_subscriptions WHERE user_id = $1 AND status = 'active' AND ends_at > now() ORDER BY ends_at DESC LIMIT 1`,
      [req.user.id]
    );
    if (activeSub.length) return res.status(409).json({ error: 'subscription_already_active', ends_at: activeSub[0].ends_at });
    if (!paytr.isEnabled()) return res.status(503).json({ error: 'paytr_disabled' });
    const rawPlan = req.body && req.body.plan;
    if (rawPlan !== undefined && rawPlan !== 'monthly' && rawPlan !== 'yearly') {
      return res.status(400).json({ error: 'invalid_plan' });
    }
    const plan = factoryPlanOf(rawPlan);
    const planSpec = FACTORY_SUBSCRIPTION_PLANS[plan];
    const { rows: users } = await pool.query('SELECT id, email, name, phone FROM users WHERE id = $1', [req.user.id]);
    const user = users[0];
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    let merchantOid;
    const { rows: pend } = await pool.query(
      `SELECT * FROM factory_subscriptions WHERE user_id = $1 AND status = 'pending' AND COALESCE(plan, 'monthly') = $2 ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, plan]
    );
    if (pend.length) {
      merchantOid = pend[0].paytr_merchant_oid;
    } else {
      merchantOid = 'MF' + req.user.id + '-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
      await pool.query(
        `INSERT INTO factory_subscriptions (user_id, status, paytr_merchant_oid, amount, currency, plan) VALUES ($1, 'pending', $2, $3, 'USD', $4)`,
        [req.user.id, merchantOid, planSpec.amount, plan]
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
        totalCents: planSpec.amount,
        currency: 'USD',
        items: [{ name: planSpec.label, price_cents: planSpec.amount, qty: 1 }],
        okUrl: FACTORY_CALLBACK_URL,
        failUrl: FACTORY_CALLBACK_URL,
      });
    } catch (e) {
      await pool.query(`UPDATE factory_subscriptions SET status='failed', updated_at=now() WHERE paytr_merchant_oid=$1 AND status='pending'`, [merchantOid]);
      return res.status(502).json({ error: 'paytr_init_failed' });
    }
    res.json({ merchant_oid: merchantOid, paytr_token: result.token, iframe_url: result.iframeUrl, plan });
  })
);

// v620 GET /api/payments/factory-subscription/status (plan-aware; eski status'un onu)
// -> { active, ends_at, plan } — plan 'monthly' | 'yearly'; plani olmayan eski satir 'monthly' sayilir.
// v620 duzeltme: aktif abonelik varsa (aylik VEYA yillik) o doner; yoksa en son abonelik.
// (En son aboneligi dondurmek, aylik aktifken basarisiz yillik denemesinde yanlis "pasif" gosteriyordu.)
router.get(
  '/factory-subscription/status',
  requireAuth,
  asyncHandler(async (req, res) => {
    await ensureFactorySubscriptionPlanColumn();
    let { rows } = await pool.query(
      `SELECT * FROM factory_subscriptions WHERE user_id = $1 AND status='active' AND ends_at > now() ORDER BY ends_at DESC LIMIT 1`,
      [req.user.id]
    );
    if (!rows.length) {
      ({ rows } = await pool.query(
        `SELECT * FROM factory_subscriptions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`,
        [req.user.id]
      ));
    }
    const sub = rows[0];
    if (!sub) return res.json({ active: false, ends_at: null, plan: 'monthly' });
    const active = sub.status === 'active' && sub.ends_at && new Date(sub.ends_at).getTime() > Date.now();
    res.json({ active: !!active, ends_at: sub.ends_at || null, plan: factoryPlanOf(sub.plan) });
  })
);

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
  // fix10e (L17): X-Forwarded-For'un ilk girdisi istemci tarafından uydurulabilir —
  // Express'in trust proxy: 1 ile hesapladığı req.ip kullanılır.
  return String(req.ip || (req.socket && req.socket.remoteAddress) || '127.0.0.1').slice(0, 45);
}

// POST /api/payments/paytr/init  { order_id }
router.post(
  '/paytr/init',
  payInitLimiter,
  body('order_id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!paytr.isEnabled()) return res.status(503).json({ error: 'payment_not_configured' });
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'validation_failed', details: errors.array() });
    // fix10e (H-F): SELECT o.*, a.* gölgelemesi — addresses.id / created_at /
    // updated_at, orders sütunlarının üzerine yazıyor; order.id adres id'si
    // oluyordu (ödemeler yanlış siparişe bağlanır, kalemler bulunamazdı).
    // Yalnız gerekli adres sütunları, çakışmasız takma adlarla alınır.
    const { rows } = await pool.query(
      `SELECT o.*, a.full_name AS address_full_name, a.phone AS address_phone,
              a.city AS address_city, a.district AS address_district,
              a.neighborhood AS address_neighborhood, a.address_line AS address_address_line
       FROM orders o LEFT JOIN addresses a ON a.id = o.address_id
       WHERE o.id = $1 AND o.user_id = $2`,
      [req.body.order_id, req.user.id]
    );
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });
    if (order.status !== 'pending') return res.status(409).json({ error: 'order_not_payable', status: order.status });
    // fix10e (M8): havale ile ödenmiş siparişe PayTR başlatılamaz
    // (havalede status 'pending' kalır, payment_status 'paid' olur).
    if (order.payment_status === 'paid') return res.status(409).json({ error: 'order_already_paid' });

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
          full_name: order.address_full_name, phone: order.address_phone, city: order.address_city,
          district: order.address_district, neighborhood: order.address_neighborhood,
          address_line: order.address_address_line,
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
        // fix10e (L17): ham hata (PayTR yanıtı / iç detay içerebilir) DB'ye yazılmaz.
        [order.id, merchantOid, order.total_cents, order.currency, JSON.stringify({ error: 'paytr_init_failed' })]
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
  factorySubLimiter,
  asyncHandler(async (req, res) => {
    await ensureFactorySubscriptions();
    // fix10e (L17): aktif abonelik varken yeniden ödeme başlatılamaz.
    const { rows: activeSub } = await pool.query(
      `SELECT id, ends_at FROM factory_subscriptions WHERE user_id = $1 AND status = 'active' AND ends_at > now() ORDER BY ends_at DESC LIMIT 1`,
      [req.user.id]
    );
    if (activeSub.length) return res.status(409).json({ error: 'subscription_already_active', ends_at: activeSub[0].ends_at });
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
