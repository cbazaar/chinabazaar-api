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
        `SELECT o.*, u.email AS user_email, u.customer_code AS user_customer_code FROM orders o
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
  body('address_id').isUUID(),
  // v569: opsiyonel alanlarda null da "bos" sayilir (on yuz bos fatura alanini null gonderiyordu -> validation_failed)
  body('payment_method').optional({ nullable: true }).isIn(['card', 'transfer', 'qr']), // v448: QR odeme kabul ediliyor
  body('invoice_type').optional({ nullable: true }).isIn(['bireysel', 'kurumsal']),
  body('invoice_tckn').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 11 }),
  body('invoice_vkn').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 10 }),
  body('invoice_company').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 200 }),
  body('invoice_tax_office').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 100 }),
  body('coupon_code').optional({ nullable: true }).isString().trim().isLength({ min: 0, max: 64 }),
  body('items').isArray({ min: 1 }),
  body('items.*.product_id').isUUID(),
  body('items.*.qty').isInt({ min: 1, max: 99 }),
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
        // Kampanya fiyati varsa (0 < kampanya < normal fiyat) siparis kampanyali fiyattan kesilir
        const unitCents = (p.campaign_price_cents != null && p.campaign_price_cents > 0 && p.campaign_price_cents < p.price_cents) ? p.campaign_price_cents : p.price_cents;
        subtotal += unitCents * it.qty;
        lines.push({ product: p, qty: it.qty, unit_cents: unitCents });
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

      const shipping = cfg.shippingCents;
      const total = subtotal + shipping - discountCents;

      const orderNo = nextOrderNo();
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT`);
      await client.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_cents BIGINT DEFAULT 0`);
      const { rows: orderRows } = await client.query(
        `INSERT INTO orders (user_id, order_no, status, subtotal_cents, shipping_cents, total_cents, currency, address_id, address_snapshot, payment_method, invoice_type, invoice_tckn, invoice_vkn, invoice_company, invoice_tax_office, coupon_code, discount_cents)
         VALUES ($1,$2,'pending',$3,$4,$5,'TRY',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
        [req.user.id, orderNo, subtotal, shipping, total, address_id, JSON.stringify(addr.rows[0]), paymentMethod, invoiceType, invoiceTckn, invoiceVkn, invoiceCompany, invoiceTaxOffice, couponCode, discountCents]
      );
      const order = orderRows[0];

      for (const l of lines) {
        await client.query(
          'INSERT INTO order_items (order_id, product_id, name, qty, price_cents, barcode) VALUES ($1,$2,$3,$4,$5,$6)',
          [order.id, l.product.id, l.product.name, l.qty, l.unit_cents, l.product.barcode || null]
        );
        await client.query('UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2', [
          l.qty,
          l.product.id,
        ]);
      }

      await client.query('COMMIT');

      // OTOMATİK FATURA OLUŞTUR
      try {
        const invNo = 'FTR-' + order.order_no;
        const itemsJson = JSON.stringify(lines.map(l => ({ name: l.product.name, qty: l.qty, price_cents: l.unit_cents })));
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

    const { rows: items } = await pool.query('SELECT product_id, name, qty, price_cents, barcode FROM order_items WHERE order_id = $1', [order.id]);
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

module.exports = router;
