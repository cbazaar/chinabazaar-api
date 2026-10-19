// fix10e (2026-10-19) — güvenlik düzeltmeleri: M9 stok, M10 TCKN şifreleme+maske,
// M15 catch ReferenceError, M16 kalem max 50 + oluşturma limiti, L17 TCKN/VKN checksum + order_no.
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

// ---- fix10e: TCKN/VKN checksum + at-rest şifreleme + yanıtlarda maskeleme ----
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit'); // fix10e: v8 keyGenerator IP doğrulaması (ERR_ERL_KEY_GEN_IPV6) için gerekli

// TCKN algoritması (Nüfus): 11 hane; 1. hane 0 olamaz;
// 10. hane = ((tek konumlar toplamı * 7) - çift konumlar toplamı) mod 10;
// 11. hane = ilk 10 hanenin toplamı mod 10.
function isValidTckn(v) {
  const s = String(v || '');
  if (!/^[1-9][0-9]{10}$/.test(s)) return false;
  const d = s.split('').map(Number);
  const odd = d[0] + d[2] + d[4] + d[6] + d[8];
  const even = d[1] + d[3] + d[5] + d[7];
  if ((((odd * 7 - even) % 10) + 10) % 10 !== d[9]) return false;
  if (d.slice(0, 10).reduce((a, b) => a + b, 0) % 10 !== d[10]) return false;
  return true;
}

// VKN algoritması (GİB): 10 hane; i=1..9 için tmp = (d_i + (10 - i)) mod 10
// (0 ise 10); tmp = (tmp * 2^(10-i)) mod 9 (0 ise 9); toplam mod 10'un
// 10'a tümleyeni 10. haneye eşit olmalı.
function isValidVkn(v) {
  const s = String(v || '');
  if (!/^[0-9]{10}$/.test(s)) return false;
  const d = s.split('').map(Number);
  let total = 0;
  for (let i = 0; i < 9; i++) {
    let tmp = (d[i] + (10 - (i + 1))) % 10;
    if (tmp === 0) tmp = 10;
    tmp = (tmp * Math.pow(2, 10 - (i + 1))) % 9;
    if (tmp === 0) tmp = 9;
    total += tmp;
  }
  return ((10 - (total % 10)) % 10) === d[9];
}

// At-rest şifreleme: AES-256-GCM, anahtar TCKN_ENCRYPTION_KEY (64 hex = 32 bayt).
// Anahtar tanımsızsa eski (şifresiz) davranış korunur ama bir kez uyarı
// loglanır — dağıtımda anahtar Railway Variables'a tanımlanmalıdır.
// Eski şifresiz satırlar okunurken de maskeleme aynen uygulanır.
function getTcknKey() {
  const hex = String(process.env.TCKN_ENCRYPTION_KEY || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}
let warnedTcknKey = false;
function encryptSensitive(plain) {
  const key = getTcknKey();
  if (!key) {
    if (!warnedTcknKey) {
      warnedTcknKey = true;
      console.warn('[fix10e] TCKN_ENCRYPTION_KEY yok — TCKN/VKN şifrelenmeden saklanıyor (yalnız geçiş modu; anahtar tanımlanmalı).');
    }
    return String(plain);
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'enc:v1:' + iv.toString('base64') + ':' + tag.toString('base64') + ':' + ct.toString('base64');
}
function decryptSensitive(stored) {
  try {
    const s = String(stored || '');
    if (!s.startsWith('enc:v1:')) return s; // eski şifresiz satır
    const key = getTcknKey();
    if (!key) return null;
    const parts = s.split(':');
    if (parts.length !== 5) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[2], 'base64'));
    decipher.setAuthTag(Buffer.from(parts[3], 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(parts[4], 'base64')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
function maskTail(value, visible, totalLen) {
  if (value == null) return null;
  if (value === '') return '';
  const plain = decryptSensitive(value);
  if (plain == null || plain === '') return '*'.repeat(totalLen);
  const tail = String(plain).slice(-visible);
  return '*'.repeat(Math.max(totalLen - tail.length, 0)) + tail;
}
function maskTckn(stored) { return maskTail(stored, 2, 11); }
function maskVkn(stored) { return maskTail(stored, 2, 10); }
// Sipariş satırı yanıta çıkmadan önce TCKN/VKN maskelenir (tam değer asla dönülmez).
function sanitizeOrderRow(order) {
  if (!order) return order;
  return { ...order, invoice_tckn: maskTckn(order.invoice_tckn), invoice_vkn: maskVkn(order.invoice_vkn) };
}

// fix10e (M16): sipariş oluşturma limiti — kullanıcı başına 15 dakikada 20.
const orderCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'order-create:' + String((req.user && req.user.id) || (req.ip ? ipKeyGenerator(req.ip) : 'unknown')),
});

const router = express.Router();
router.use(requireAuth);

async function ensureCouponsTable(q) {
  await q.query(`CREATE TABLE IF NOT EXISTS coupons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT UNIQUE NOT NULL,
    discount_type VARCHAR(16) DEFAULT 'percent',
    discount_value NUMERIC DEFAULT 0,
    min_order_cents BIGINT DEFAULT 0,
    max_uses INT DEFAULT 0,
    used_count INT DEFAULT 0,
    ends_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q.query(`ALTER TABLE coupons ADD COLUMN IF NOT EXISTS min_order_cents BIGINT DEFAULT 0`);
  await q.query(`ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_uses INT DEFAULT 0`);
  await q.query(`ALTER TABLE coupons ADD COLUMN IF NOT EXISTS used_count INT DEFAULT 0`);
  await q.query(`ALTER TABLE coupons ADD COLUMN IF NOT EXISTS ends_at TIMESTAMPTZ`);
  await q.query(`ALTER TABLE coupons ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
}

// Kupon indirimi (kurus): percent -> sepet yuzdesi, fixed -> TL tutar (discount_value TL).
// Gecersiz kuponda 0 doner; gecerlilik kontrolleri cagiran tarafta yapilir.
function couponDiscountCents(coupon, subtotalCents) {
  if (!coupon || !coupon.is_active) return 0;
  if (coupon.ends_at && new Date(coupon.ends_at) < new Date()) return 0;
  if ((coupon.min_order_cents || 0) > subtotalCents) return 0;
  if ((coupon.max_uses || 0) > 0 && (coupon.used_count || 0) >= coupon.max_uses) return 0;
  let d = 0;
  if (coupon.discount_type === 'fixed') d = Math.round(Number(coupon.discount_value || 0) * 100);
  else d = Math.floor(subtotalCents * Number(coupon.discount_value || 0) / 100);
  return Math.max(0, Math.min(d, subtotalCents));
}

function nextOrderNo() {
  // fix10e (L17): tahmin edilemez sipariş no — Math.random yerine CSPRNG (48 bit).
  // Benzersizlik DB UNIQUE constraint ile garanti (çakışma ~imkânsız).
  return `CB-${new Date().getFullYear()}-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
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
        `SELECT o.*, u.email AS user_email, u.customer_code AS user_customer_code FROM orders o
         LEFT JOIN users u ON u.id = o.user_id
         ORDER BY o.created_at DESC LIMIT 200`
      );
      return res.json({ items: rows.map(sanitizeOrderRow) });
    }
    const { rows } = await pool.query(
      'SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ items: rows.map(sanitizeOrderRow) });
  })
);

// POST /api/orders/validate-coupon { code, subtotal_cents } — kupon gecerli mi, indirim ne kadar?
router.post(
  '/validate-coupon',
  body('code').isString().trim().isLength({ min: 1, max: 64 }),
  body('subtotal_cents').isInt({ min: 0 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureCouponsTable(pool);
    const code = String(req.body.code).trim().toUpperCase();
    const subtotalCents = Number(req.body.subtotal_cents);
    const { rows } = await pool.query('SELECT * FROM coupons WHERE code = $1', [code]);
    const coupon = rows[0];
    if (!coupon) return res.status(404).json({ valid: false, error: 'coupon_not_found' });
    if (!coupon.is_active) return res.status(400).json({ valid: false, error: 'coupon_inactive' });
    if (coupon.ends_at && new Date(coupon.ends_at) < new Date()) return res.status(400).json({ valid: false, error: 'coupon_expired' });
    if ((coupon.min_order_cents || 0) > subtotalCents) return res.status(400).json({ valid: false, error: 'coupon_min_order', min_order_cents: coupon.min_order_cents });
    if ((coupon.max_uses || 0) > 0 && (coupon.used_count || 0) >= coupon.max_uses) return res.status(400).json({ valid: false, error: 'coupon_max_uses' });
    res.json({ valid: true, code: coupon.code, discount_type: coupon.discount_type, discount_value: Number(coupon.discount_value || 0), discount_cents: couponDiscountCents(coupon, subtotalCents), min_order_cents: coupon.min_order_cents || 0 });
  })
);

// POST /api/orders  { address_id, items: [{ product_id, qty }] }
router.post(
  '/',
  orderCreateLimiter,
  body('address_id').isUUID(),
  // v569: opsiyonel alanlarda null da "bos" sayilir (on yuz bos fatura alanini null gonderiyordu -> validation_failed)
  body('payment_method').optional({ nullable: true }).isIn(['card', 'transfer', 'qr']), // v448: QR odeme kabul ediliyor
  body('invoice_type').optional({ nullable: true }).isIn(['bireysel', 'kurumsal']),
  body('invoice_tckn').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 11 }),
  body('invoice_vkn').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 10 }),
  body('invoice_company').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 200 }),
  body('invoice_tax_office').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 100 }),
  body('invoice_full_name').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 200 }),
  body('invoice_address').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 500 }),
  body('invoice_email').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 200 }),
  body('invoice_postcode').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 10 }),
  body('coupon_code').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 64 }),
  body('items').isArray({ min: 1, max: 50 }), // fix10e (M16): en fazla 50 kalem
  body('items.*.product_id').isUUID(),
  body('items.*.qty').isInt({ min: 1, max: 99 }),
  body('items.*.variant_color').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 100 }),
  body('items.*.variant_storage').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;

    const { address_id, items } = req.body;
    const paymentMethod = ['card', 'transfer', 'qr'].includes(req.body.payment_method) ? req.body.payment_method : 'card'; // v448: QR saklaniyor
    // Fatura bilgileri (checkout'ta müşteri seçer: bireysel -> e-Arşiv, kurumsal -> e-Fatura)
    const invoiceType = req.body.invoice_type === 'kurumsal' ? 'kurumsal' : 'bireysel';
    const invoiceTckn = invoiceType === 'bireysel' ? String(req.body.invoice_tckn || '').replace(/\D/g, '').slice(0, 11) || null : null;
    const invoiceVkn = invoiceType === 'kurumsal' ? String(req.body.invoice_vkn || '').replace(/\D/g, '').slice(0, 10) || null : null;
    const invoiceCompany = invoiceType === 'kurumsal' ? String(req.body.invoice_company || '').trim().slice(0, 200) || null : null;
    const invoiceTaxOffice = invoiceType === 'kurumsal' ? String(req.body.invoice_tax_office || '').trim().slice(0, 100) || null : null;
    const invoiceFullName = invoiceType === 'bireysel' ? String(req.body.invoice_full_name || '').trim().slice(0, 200) || null : null;
    const invoiceAddress = invoiceType === 'bireysel' ? String(req.body.invoice_address || '').trim().slice(0, 500) || null : null;
    const invoiceEmail = String(req.body.invoice_email || '').trim().slice(0, 200) || null;
    const invoicePostcode = String(req.body.invoice_postcode || '').replace(/\D/g, '').slice(0, 10) || null;
    // fix10e (L17): TCKN/VKN yalnızca verildiyse checksum ile doğrulanır (TCKN zorunlu değil).
    if (invoiceType === 'bireysel' && invoiceTckn && !isValidTckn(invoiceTckn)) {
      return res.status(400).json({ error: 'invalid_tckn_checksum' });
    }
    if (invoiceType === 'kurumsal' && invoiceVkn && !isValidVkn(invoiceVkn)) {
      return res.status(400).json({ error: 'invalid_vkn_checksum' });
    }
    let order = null; // fix10e (M15): catch bloğunda erişilebilir olmalı
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
        // fix10e (M9): stok döngüde güncellenir — aynı ürün tekrarlı kalemde
        // ikinci kez eski stokla kontrol edilemez (aksi halde stok eksiye düşer).
        p.stock -= it.qty;
        // Kampanya fiyati varsa (0 < kampanya < normal fiyat) siparis kampanyali fiyattan kesilir
        let unitCents = (p.campaign_price_cents != null && p.campaign_price_cents > 0 && p.campaign_price_cents < p.price_cents) ? p.campaign_price_cents : p.price_cents;
        // v572: Varyant — renk/depolama secimi; depolama fiyat farki urunun storage listesinden SUNUCU tarafinda hesaplanir (on yuz fiyati guvenilmez)
        let variantColor = String(it.variant_color || '').trim().slice(0, 100) || null;
        let variantStorage = String(it.variant_storage || '').trim().slice(0, 100) || null;
        if (variantColor) {
          const colors = String(p.color || '').split(',').map((s) => s.trim()).filter(Boolean);
          if (colors.length && !colors.includes(variantColor)) variantColor = null; // bilinmeyen renk: yoksay
        }
        if (variantStorage) {
          const opts = String(p.storage || '').split(',').map((s) => {
            const parts = String(s).trim().split(':');
            const label = (parts[0] || '').trim();
            const delta = parts.length > 1 ? parseFloat(String(parts[1]).replace(',', '.')) : 0;
            return { label, delta: Number.isFinite(delta) && delta > 0 ? delta : 0 };
          }).filter((o) => o.label);
          const hit = opts.find((o) => o.label === variantStorage);
          if (hit) unitCents += Math.round(hit.delta * 100);
          else variantStorage = null; // bilinmeyen depolama: yoksay
        }
        subtotal += unitCents * it.qty;
        lines.push({ product: p, qty: it.qty, unit_cents: unitCents, variant_color: variantColor, variant_storage: variantStorage });
      }

      // Kupon: sunucu tarafinda yeniden dogrulanir, indirim uygulanir, kullanim sayaci artar
      let discountCents = 0;
      let couponCode = null;
      if (req.body.coupon_code) {
        await ensureCouponsTable(client);
        couponCode = String(req.body.coupon_code).trim().toUpperCase();
        const { rows: crow } = await client.query('SELECT * FROM coupons WHERE code = $1 FOR UPDATE', [couponCode]);
        const coupon = crow[0];
        if (!coupon) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'coupon_not_found' }); }
        if (!coupon.is_active) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'coupon_inactive' }); }
        if (coupon.ends_at && new Date(coupon.ends_at) < new Date()) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'coupon_expired' }); }
        if ((coupon.min_order_cents || 0) > subtotal) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'coupon_min_order' }); }
        if ((coupon.max_uses || 0) > 0 && (coupon.used_count || 0) >= coupon.max_uses) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'coupon_max_uses' }); }
        discountCents = couponDiscountCents(coupon, subtotal);
        await client.query('UPDATE coupons SET used_count = used_count + 1, updated_at = now() WHERE id = $1', [coupon.id]);
      }

      // v573: 400 TL uzeri (kupon sonrasi urun toplami) kargo bedava
      const shipping = (subtotal - discountCents >= 40000) ? 0 : cfg.shippingCents;
      const total = subtotal + shipping - discountCents;

      const orderNo = nextOrderNo();
      // fix10e (M10): şifreli değer sığsın diye fatura kimlik sütunları TEXT olur.
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_tckn TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_vkn TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_company TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_tax_office TEXT`);
      await client.query(`ALTER TABLE orders ALTER COLUMN invoice_tckn TYPE TEXT`);
      await client.query(`ALTER TABLE orders ALTER COLUMN invoice_vkn TYPE TEXT`);
      const invoiceTcknStored = invoiceTckn ? encryptSensitive(invoiceTckn) : null;
      const invoiceVknStored = invoiceVkn ? encryptSensitive(invoiceVkn) : null;
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_full_name TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_address TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_email TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_postcode TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_cents BIGINT DEFAULT 0`);
      await client.query(`ALTER TABLE order_items ADD COLUMN IF NOT EXISTS variant_color TEXT`);
      await client.query(`ALTER TABLE order_items ADD COLUMN IF NOT EXISTS variant_storage TEXT`);
      const { rows: orderRows } = await client.query(
        `INSERT INTO orders (user_id, order_no, status, subtotal_cents, shipping_cents, total_cents, currency, address_id, address_snapshot, payment_method, invoice_type, invoice_tckn, invoice_vkn, invoice_company, invoice_tax_office, invoice_full_name, invoice_address, invoice_email, invoice_postcode, coupon_code, discount_cents)
         VALUES ($1,$2,'pending',$3,$4,$5,'TRY',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
        [req.user.id, orderNo, subtotal, shipping, total, address_id, JSON.stringify(addr.rows[0]), paymentMethod, invoiceType, invoiceTcknStored, invoiceVknStored, invoiceCompany, invoiceTaxOffice, invoiceFullName, invoiceAddress, invoiceEmail, invoicePostcode, couponCode, discountCents]
      );
      order = orderRows[0];

      for (const l of lines) {
        await client.query(
          'INSERT INTO order_items (order_id, product_id, name, qty, price_cents, barcode, variant_color, variant_storage) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [order.id, l.product.id, l.product.name, l.qty, l.unit_cents, l.product.barcode || null, l.variant_color || null, l.variant_storage || null]
        );
        await client.query('UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2', [
          l.qty,
          l.product.id,
        ]);
      }

      await client.query('COMMIT');

      // fix10e (M15): "sipariş alındı" SMS'i yalnızca COMMIT sonrası (başarılı siparişte).
      notifyOrderSms(order.id, 'received').catch(() => {});

      // OTOMATİK FATURA OLUŞTUR
      try {
        const invNo = 'FTR-' + order.order_no;
        const itemsJson = JSON.stringify(lines.map(l => ({ name: l.product.name, qty: l.qty, price_cents: l.unit_cents, variant_color: l.variant_color || null, variant_storage: l.variant_storage || null })));
        const userName = (await pool.query('SELECT name FROM users WHERE id=$1', [req.user.id])).rows[0]?.name || '';
        await pool.query(
          `INSERT INTO invoices (invoice_no, order_id, customer_name, items, subtotal_cents, vat_cents, total_cents, currency, status, invoice_date)
           VALUES ($1,$2,$3,$4,$5,0,$5,'TRY','pending',now()) ON CONFLICT (invoice_no) DO NOTHING`,
          [invNo, order.id, userName, itemsJson, total]
        );
      } catch (e) { console.error('auto-invoice failed', e.message); }

      res.status(201).json({
        id: order.id,
        order_no: order.order_no,
        status: order.status,
        subtotal_cents: order.subtotal_cents,
        shipping_cents: order.shipping_cents,
        discount_cents: order.discount_cents,
        coupon_code: order.coupon_code,
        total_cents: order.total_cents,
        currency: order.currency,
      });
    } catch (err) {
      await client.query('ROLLBACK');
      // fix10e (M15): başarısız siparişte SMS gönderilmez; `order` artık
      // try dışındaki `let` ile catch'te erişilebilir (ReferenceError yok).
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
    const { rows } = await pool.query('SELECT o.*, u.customer_code FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE o.id = $1', [req.params.id]);
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });

    const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (order.user_id !== req.user.id && !me[0]?.is_admin) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { rows: items } = await pool.query('SELECT product_id, name, qty, price_cents, barcode, variant_color, variant_storage FROM order_items WHERE order_id = $1', [order.id]);
    const { rows: payments } = await pool.query(
      'SELECT provider, status, payment_id, amount_cents, currency, created_at FROM payments WHERE order_id = $1 ORDER BY created_at DESC',
      [order.id]
    );
    res.json({
      ...sanitizeOrderRow(order),
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

// DELETE /api/orders/:id — bekleyen siparişi sil (yalnız sipariş sahibi veya admin; v570)
// Ödenmiş / kargoya verilmiş sipariş silinemez (iade akışı kullanılır).
// Silme: stok geri yazılır, kupon sayacı azaltılır, otomatik fatura + kalemler + ödemeler silinir.
router.delete(
  '/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
      const order = rows[0];
      if (!order) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'order_not_found' }); }
      const { rows: me } = await client.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
      if (order.user_id !== req.user.id && !me[0]?.is_admin) {
        await client.query('ROLLBACK'); return res.status(403).json({ error: 'forbidden' });
      }
      if (order.status !== 'pending') {
        await client.query('ROLLBACK'); return res.status(400).json({ error: 'order_not_deletable', status: order.status });
      }
      const { rows: items } = await client.query('SELECT product_id, qty FROM order_items WHERE order_id = $1', [order.id]);
      for (const it of items) {
        await client.query('UPDATE products SET stock = stock + $1, updated_at = now() WHERE id = $2', [it.qty, it.product_id]);
      }
      if (order.coupon_code) {
        await client.query('UPDATE coupons SET used_count = GREATEST(used_count - 1, 0) WHERE code = $1', [order.coupon_code]);
      }
      await client.query('DELETE FROM invoices WHERE order_id = $1', [order.id]);
      await client.query('DELETE FROM payments WHERE order_id = $1', [order.id]);
      await client.query('DELETE FROM order_items WHERE order_id = $1', [order.id]);
      await client.query('DELETE FROM orders WHERE id = $1', [order.id]);
      await client.query('COMMIT');
      res.json({ deleted: true, id: order.id, order_no: order.order_no });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  })
);

// v609: siparis SMS bildirimleri (Netgsm) — asla ana akisi bozmaz, hata yutulur.
// Turler: received (siparis alindi), shipped (kargoya verildi / yolda), delivered (teslim edildi).
async function notifyOrderSms(orderId, kind) {
  try {
    const sms = require('../services/sms');
    const cfg = await sms.getSmsSettings();
    const toggle = kind === 'received' ? cfg.notify.order_received : kind === 'shipped' ? cfg.notify.order_shipped : cfg.notify.order_delivered;
    if (toggle === false) return;
    const { rows } = await pool.query('SELECT o.order_no, u.phone FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE o.id = $1', [orderId]);
    const row = rows[0];
    if (!row || !row.phone) return;
    const no = row.order_no || '';
    const tel = String(cfg.companyPhone || '').replace(/^\+90/, '0');
    let msg = '';
    if (kind === 'received') msg = 'ChinaBazaar: Siparisiniz alindi. No: ' + no + '. ' + tel;
    else if (kind === 'shipped') msg = 'ChinaBazaar: Siparisiniz kargoya verildi, yolda. No: ' + no + '. ' + tel;
    else msg = 'ChinaBazaar: Siparisiniz teslim edildi. No: ' + no + '. Bizi tercih ettiginiz icin tesekkurler. ' + tel;
    await sms.sendSms(row.phone, msg);
  } catch (e) { /* SMS hatasi siparisi bozmaz */ }
}

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
    const { rows: oldRows } = await pool.query('SELECT status FROM orders WHERE id = $1', [req.params.id]);
    const oldStatus = oldRows[0] ? oldRows[0].status : null;
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
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    // v609: takip no eklenince durum shipped olduysa SMS
    if ((oldStatus === 'packing' || oldStatus === 'ready') && rows[0].status === 'shipped') notifyOrderSms(rows[0].id, 'shipped').catch(() => {});
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
    const { rows: oldRows } = await pool.query('SELECT status FROM orders WHERE id = $1', [req.params.id]);
    const oldStatus = oldRows[0] ? oldRows[0].status : null;
    const { rows } = await pool.query(
      `UPDATE orders SET status = $2, updated_at = now() WHERE id = $1
       RETURNING id, order_no, status, cargo_company, tracking_number, updated_at`,
      [req.params.id, req.body.status]
    );
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    // v609: durum degistiyse siparis SMS'i (shipped / delivered)
    if (oldStatus && oldStatus !== rows[0].status) {
      if (rows[0].status === 'shipped') notifyOrderSms(rows[0].id, 'shipped').catch(() => {});
      else if (rows[0].status === 'delivered') notifyOrderSms(rows[0].id, 'delivered').catch(() => {});
    }
    res.json(rows[0]);
  })
);

// ============ İADE TALEBİ (müşteri) ============
// POST /api/orders/:id/return — teslim edilmiş sipariş için iade talebi oluşturur (yalnız sipariş sahibi veya admin).
// Gövde: { reason } — sebep zorunlu (3-500 karakter). Aynı sipariş için bekleyen/onaylı talep varsa 409 döner.
router.post(
  '/:id/return',
  param('id').isUUID(),
  body('reason').isString().trim().isLength({ min: 3, max: 500 }).withMessage('invalid_reason'),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    // returns tablosunu garantile (022 migration'ı uygulanmamışsa bile çalışır)
    await pool.query(`CREATE TABLE IF NOT EXISTS returns (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      order_id UUID REFERENCES orders(id),
      user_id UUID REFERENCES users(id),
      reason TEXT,
      status VARCHAR(24) DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    )`);
    const { rows } = await pool.query('SELECT id, user_id, order_no, status FROM orders WHERE id = $1', [req.params.id]);
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });
    const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (order.user_id !== req.user.id && !me[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
    if (order.status !== 'delivered') return res.status(409).json({ error: 'order_not_delivered' });
    const { rows: dup } = await pool.query(
      "SELECT id, status FROM returns WHERE order_id = $1 AND status IN ('pending','approved') ORDER BY created_at DESC LIMIT 1",
      [req.params.id]
    );
    if (dup.length) return res.status(409).json({ error: 'return_already_exists', return: dup[0] });
    const { rows: created } = await pool.query(
      "INSERT INTO returns (order_id, user_id, reason, status) VALUES ($1,$2,$3,'pending') RETURNING *",
      [req.params.id, order.user_id, req.body.reason.trim()]
    );
    res.status(201).json({ ok: true, return: created[0] });
  })
);

// GET /api/orders/:id/return — siparişin son iade talebi (varsa) — yalnız sipariş sahibi veya admin.
router.get(
  '/:id/return',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query('SELECT id, user_id FROM orders WHERE id = $1', [req.params.id]);
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'order_not_found' });
    const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (order.user_id !== req.user.id && !me[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
    await pool.query(`CREATE TABLE IF NOT EXISTS returns (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      order_id UUID REFERENCES orders(id),
      user_id UUID REFERENCES users(id),
      reason TEXT,
      status VARCHAR(24) DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    )`);
    const { rows: ret } = await pool.query(
      'SELECT * FROM returns WHERE order_id = $1 ORDER BY created_at DESC LIMIT 1',
      [req.params.id]
    );
    res.json({ ok: true, return: ret[0] || null });
  })
);

// fix10e: test kancası — üretim davranışını değiştirmez (yalnız birim testleri için).
router.__fix10e = { isValidTckn, isValidVkn, encryptSensitive, decryptSensitive, maskTckn, maskVkn, sanitizeOrderRow, nextOrderNo };

module.exports = router;
