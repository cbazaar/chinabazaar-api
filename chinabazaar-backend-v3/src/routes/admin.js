// Admin yönetim API'leri: kullanıcılar + yorum moderasyonu.
// Tüm route'lar requireAuth + requireAdmin gerektirir.
const express = require('express');
const { param, body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// GET /api/admin/users — kayıtlı profiller
router.get(
  '/users',
  asyncHandler(async (_req, res) => {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.nickname, u.phone, u.is_admin, u.is_blocked, u.email_verified, u.created_at, u.customer_code,
              (SELECT count(*)::int FROM orders o WHERE o.user_id = u.id) AS order_count
       FROM users u ORDER BY u.name ASC LIMIT 500`
    );
    res.json({ items: rows });
  })
);

// PATCH /api/admin/users/:id — { is_blocked?, is_admin? }
router.patch(
  '/users/:id',
  param('id').isUUID(),
  body('is_blocked').optional().isBoolean(),
  body('is_admin').optional().isBoolean(),
  body('nickname').optional().isString().isLength({ min: 2, max: 30 }).matches(/^[a-zA-Z0-9_.\-]+$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'cannot_modify_self' });
    const sets = [];
    const vals = [];
    if (typeof req.body.is_blocked === 'boolean') { vals.push(req.body.is_blocked); sets.push(`is_blocked = $${vals.length}`); }
    if (typeof req.body.is_admin === 'boolean') { vals.push(req.body.is_admin); sets.push(`is_admin = $${vals.length}`); }
    if (typeof req.body.nickname === 'string') { vals.push(req.body.nickname); sets.push(`nickname = $${vals.length}`); }
    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
    vals.push(req.params.id);
    const { rows } = await pool.query(
      `UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = $${vals.length}
       RETURNING id, email, name, nickname, is_admin, is_blocked`,
      vals
    );
    if (!rows.length) return res.status(404).json({ error: 'user_not_found' });
    res.json(rows[0]);
  })
);

// GET /api/admin/comments — tüm yorumlar (ürün + kullanıcı bilgisiyle)
router.get(
  '/comments',
  asyncHandler(async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
    const { rows } = await pool.query(
      `SELECT c.id, c.body, c.is_blocked, c.created_at,
              p.name AS product_name, u.id AS user_id, u.name AS user_name, u.email AS user_email, u.customer_code
       FROM comments c
       JOIN products p ON p.id = c.product_id
       JOIN users u ON u.id = c.user_id
       ORDER BY c.created_at DESC LIMIT $1`,
      [limit]
    );
    res.json({ items: rows });
  })
);

// PATCH /api/admin/comments/:id — { is_blocked } (engelle / engeli kaldır)
router.patch(
  '/comments/:id',
  param('id').isUUID(),
  body('is_blocked').isBoolean(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(
      'UPDATE comments SET is_blocked = $1 WHERE id = $2 RETURNING id, is_blocked',
      [req.body.is_blocked, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'comment_not_found' });
    res.json(rows[0]);
  })
);

// DELETE /api/admin/comments/:id — yorumu sil
router.delete(
  '/comments/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query('DELETE FROM comments WHERE id = $1 RETURNING id', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'comment_not_found' });
    res.json({ deleted: true });
  })
);

// GET /api/admin/stats — dashboard analitiği (Europe/Istanbul)
// Dönen: today/week/month özetleri, durum dağılımı, saatlik/günlük/haftalık/aylık
// seriler, en çok satan ürünler, takip numaralı siparişler.
router.get(
  '/stats',
  asyncHandler(async (_req, res) => {
    const TZ = 'Europe/Istanbul';
    const { rows: byStatus } = await pool.query(
      'SELECT status, count(*)::int AS n FROM orders GROUP BY status'
    );
    const statusMap = {};
    byStatus.forEach((r) => { statusMap[r.status] = r.n; });

    const q = (sql, params) => pool.query(sql, params).then((r) => r.rows);
    const day = `(created_at AT TIME ZONE '${TZ}')::date`;
    const todayLocal = `(now() AT TIME ZONE '${TZ}')::date`;

    const [todayR, weekR, monthR] = await Promise.all([
      q(`SELECT count(*)::int AS orders, coalesce(sum(total_cents),0)::bigint AS revenue_cents, currency
         FROM orders WHERE ${day} = ${todayLocal} GROUP BY currency`, []),
      q(`SELECT count(*)::int AS orders, coalesce(sum(total_cents),0)::bigint AS revenue_cents, currency
         FROM orders WHERE ${day} >= ${todayLocal} - interval '6 days' GROUP BY currency`, []),
      q(`SELECT count(*)::int AS orders, coalesce(sum(total_cents),0)::bigint AS revenue_cents, currency
         FROM orders WHERE ${day} >= date_trunc('month', ${todayLocal})::date GROUP BY currency`, []),
    ]);

    const [yearR] = await Promise.all([
      q(`SELECT count(*)::int AS orders, coalesce(sum(total_cents),0)::bigint AS revenue_cents, currency
         FROM orders WHERE ${day} >= date_trunc('year', ${todayLocal})::date GROUP BY currency`, []),
    ]);

    const [hourly, daily, weekly, monthly, yearly] = await Promise.all([
      q(`SELECT extract(hour from created_at AT TIME ZONE '${TZ}')::int AS h, count(*)::int AS orders
         FROM orders WHERE ${day} = ${todayLocal} GROUP BY 1 ORDER BY 1`, []),
      q(`SELECT to_char(${day}, 'YYYY-MM-DD') AS d, count(*)::int AS orders
         FROM orders WHERE ${day} >= ${todayLocal} - interval '29 days' GROUP BY 1 ORDER BY 1`, []),
      q(`SELECT to_char(date_trunc('week', created_at AT TIME ZONE '${TZ}'), 'IYYY-"W"IW') AS w, count(*)::int AS orders
         FROM orders WHERE created_at >= now() - interval '12 weeks' GROUP BY 1 ORDER BY 1`, []),
      q(`SELECT to_char(created_at AT TIME ZONE '${TZ}', 'YYYY-MM') AS m, count(*)::int AS orders
         FROM orders WHERE created_at >= now() - interval '12 months' GROUP BY 1 ORDER BY 1`, []),
      q(`SELECT to_char(created_at AT TIME ZONE '${TZ}', 'YYYY') AS y, count(*)::int AS orders
         FROM orders WHERE created_at >= now() - interval '5 years' GROUP BY 1 ORDER BY 1`, []),
    ]);

    // Muhasebe: ödeme yöntemi dağılımı (başarılı ödemeler)
    const payMethods = await q(
      `SELECT o.payment_method AS method, p.currency,
              count(*)::int AS orders, coalesce(sum(p.amount_cents),0)::bigint AS revenue_cents
       FROM payments p JOIN orders o ON o.id = p.order_id
       WHERE p.status = 'success'
       GROUP BY 1, 2 ORDER BY 4 DESC`, []
    );
    // Kasa: tüm zamanlar toplamı + satılan adet
    const [allTime, unitsSold] = await Promise.all([
      q(`SELECT currency, count(*)::int AS orders, coalesce(sum(total_cents),0)::bigint AS revenue_cents
         FROM orders GROUP BY currency ORDER BY revenue_cents DESC`, []),
      q(`SELECT coalesce(sum(qty),0)::int AS units FROM order_items`, []),
    ]);

    const topProducts = await q(
      `SELECT p.id, p.name, p.sold_count, p.stock, p.thumb_url, p.currency,
              coalesce(sum(oi.qty * oi.price_cents), 0)::bigint AS revenue_cents
       FROM products p LEFT JOIN order_items oi ON oi.product_id = p.id
       GROUP BY p.id ORDER BY p.sold_count DESC LIMIT 10`, []
    );
    const topViewed = await q(
      `SELECT id, name, view_count, thumb_url FROM products
       ORDER BY view_count DESC LIMIT 10`, []
    );
    const tracking = await q(
      `SELECT order_no, tracking_number, cargo_company, status, created_at FROM orders
       WHERE tracking_number IS NOT NULL AND tracking_number <> ''
       ORDER BY created_at DESC LIMIT 10`, []
    );

    res.json({
      by_status: statusMap,
      today: todayR, week: weekR, month: monthR, year: yearR,
      hourly, daily, weekly, monthly, yearly,
      top_products: topProducts, top_viewed: topViewed, tracking,
      pay_methods: payMethods, all_time: allTime, units_sold: unitsSold[0]?.units || 0,
    });
  })
);

// PATCH /api/admin/orders/:id/pay — havale/EFT ödemesini onayla (admin)
// Ödemesi onaylanan sipariş "beklemede" (pending) kuyruğuna düşer.
router.patch(
  '/orders/:id/pay',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `UPDATE orders SET payment_status='paid', status='pending', updated_at=now()
         WHERE id=$1 AND payment_status='unpaid' RETURNING id, order_no`,
        [req.params.id]
      );
      if (!rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'order_not_found_or_already_paid' });
      }
      await client.query(
        `UPDATE products p SET sold_count = sold_count + oi.qty
         FROM order_items oi WHERE oi.order_id=$1 AND oi.product_id=p.id`,
        [req.params.id]
      );
      await client.query('COMMIT');
      res.json({ paid: true, order_no: rows[0].order_no });
      // v610: Nebim otomatik fatura gonderimi (ayar aciksa, asla odeme onayini bozmaz)
      try {
        const { rows: nb } = await pool.query("SELECT value FROM settings WHERE key = 'acc_nebim_auto_send'");
        if (nb[0] && nb[0].value === 'true') {
          const nebim = require('../services/nebim');
          nebim.sendOrderInvoice(rows[0].id).catch(() => {});
        }
      } catch (e) { /* Nebim gonderimi odeme onayini bozmaz */ }
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  })
);

// GET /api/admin/reports/daily?date=YYYY-MM-DD — gün sonu raporu
// Belirtilen günün (Europe/Istanbul) tüm siparişleri, kalemleri, ciro ve ödeme dağılımı.
router.get(
  '/reports/daily',
  asyncHandler(async (req, res) => {
    const TZ = 'Europe/Istanbul';
    const date = /^\d{4}-\d{2}-\d{2}$/.test(req.query.date || '')
      ? req.query.date
      : new Date().toISOString().slice(0, 10);
    const dayExpr = `(o.created_at AT TIME ZONE '${TZ}')::date = $1::date`;
    const { rows: orders } = await pool.query(
      `SELECT o.id, o.order_no, o.status, o.payment_method, o.payment_status,
              o.subtotal_cents, o.shipping_cents, o.total_cents, o.currency,
              o.address_snapshot, o.created_at, u.email AS user_email, u.name AS user_name
       FROM orders o LEFT JOIN users u ON u.id = o.user_id
       WHERE ${dayExpr} ORDER BY o.created_at DESC`,
      [date]
    );
    const ids = orders.map((o) => o.id);
    let items = [];
    if (ids.length) {
      const { rows } = await pool.query(
        `SELECT order_id, name, qty, price_cents, barcode FROM order_items WHERE order_id = ANY($1)`,
        [ids]
      );
      items = rows;
    }
    const byId = {};
    orders.forEach((o) => { o.items = []; byId[o.id] = o; });
    items.forEach((it) => { if (byId[it.order_id]) byId[it.order_id].items.push(it); });

    const rev = {};
    const byMethod = {};
    let units = 0;
    orders.forEach((o) => {
      if (o.payment_status === 'paid') {
        const k = o.currency;
        rev[k] = rev[k] || { currency: k, orders: 0, revenue_cents: 0 };
        rev[k].orders += 1; rev[k].revenue_cents += Number(o.total_cents) || 0;
        const mk = o.payment_method + '|' + o.currency;
        byMethod[mk] = byMethod[mk] || { method: o.payment_method, currency: o.currency, orders: 0, revenue_cents: 0 };
        byMethod[mk].orders += 1; byMethod[mk].revenue_cents += Number(o.total_cents) || 0;
      }
      (o.items || []).forEach((it) => { units += Number(it.qty) || 0; });
    });
    const { rows: pending } = await pool.query(
      `SELECT count(*)::int AS n FROM orders WHERE status = 'pending'`
    );
    res.json({
      date,
      orders,
      revenue: Object.values(rev),
      by_method: Object.values(byMethod),
      units_sold: units,
      order_count: orders.length,
      paid_count: orders.filter((o) => o.payment_status === 'paid').length,
      pending_carry: pending[0]?.n || 0,
    });
  })
);


/* ================= canlı destek (admin) ================= */
router.get('/chat', asyncHandler(async (req, res) => {
  const r = await pool.query(`
    SELECT DISTINCT ON (m.conversation_id)
      m.conversation_id AS id,
      c.user_id, c.status, c.last_message_at,
      u.name AS user_name, u.email AS user_email, u.customer_code,
      m.body AS last_body,
      (SELECT count(*)::int FROM chat_messages m2 WHERE m2.conversation_id=m.conversation_id AND m2.sender='customer' AND NOT m2.read_by_admin) AS unread
    FROM chat_messages m
    LEFT JOIN chat_conversations c ON c.id=m.conversation_id
    LEFT JOIN users u ON u.id=c.user_id
    ORDER BY m.conversation_id, m.id DESC LIMIT 100`);
  res.json({ ok: true, items: r.rows });
}));
router.get('/chat/unread-total', asyncHandler(async (req, res) => {
  const r = await pool.query(`SELECT count(*)::int AS c FROM chat_messages WHERE sender='customer' AND NOT read_by_admin`);
  res.json({ ok: true, unread: r.rows[0].c });
}));
router.get('/chat/:id/messages', asyncHandler(async (req, res) => {
  const r = await pool.query(`SELECT * FROM chat_messages WHERE conversation_id=$1 ORDER BY id ASC LIMIT 300`, [req.params.id]);
  await pool.query(`UPDATE chat_messages SET read_by_admin=true WHERE conversation_id=$1 AND sender='customer'`, [req.params.id]);
  res.json({ ok: true, messages: r.rows });
}));
router.post('/chat/:id/reply', asyncHandler(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ ok: false, error: 'empty' });
  const m = await pool.query(
    `INSERT INTO chat_messages (conversation_id, sender, body, read_by_admin) VALUES ($1,'admin',$2,true) RETURNING *`,
    [req.params.id, body]);
  await pool.query(`UPDATE chat_conversations SET last_message_at=now(), status='open' WHERE id=$1`, [req.params.id]);
  res.json({ ok: true, message: m.rows[0] });
}));
router.patch('/chat/:id', asyncHandler(async (req, res) => {
  const st = req.body.status === 'closed' ? 'closed' : 'open';
  await pool.query(`UPDATE chat_conversations SET status=$2 WHERE id=$1`, [req.params.id, st]);
  res.json({ ok: true, status: st });
}));

// Konuşmadaki müşterinin profil bilgileri + otomatik müşteri kodu
router.get('/chat/:id/customer', asyncHandler(async (req, res) => {
  const conv = await pool.query(`SELECT user_id FROM chat_conversations WHERE id=$1`, [req.params.id]);
  if (!conv.rows[0]) return res.status(404).json({ ok: false, error: 'not_found' });
  const uid = conv.rows[0].user_id;
  const u = await pool.query(
    `SELECT id, email, name, phone, customer_code, created_at FROM users WHERE id=$1`, [uid]);
  const user = u.rows[0] || {};
  // Müşteri kodu yoksa üret ve kaydet
  if (user.id && !user.customer_code) {
    const code = 'CBM' + String(user.id).padStart(6, '0');
    await pool.query(`UPDATE users SET customer_code=$2 WHERE id=$1`, [user.id, code]);
    user.customer_code = code;
  }
  const ord = await pool.query(
    `SELECT COUNT(*)::int AS cnt, COALESCE(SUM(total_cents),0)::bigint AS total
     FROM orders WHERE user_id=$1 AND payment_status='paid'`, [uid]);
  res.json({ ok: true, customer: {
    ...user,
    order_count: ord.rows[0]?.cnt || 0,
    total_spent: Number(ord.rows[0]?.total || 0) / 100,
  }});
}));


// ============ KUPONLAR ============
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
router.get('/coupons', asyncHandler(async (req, res) => {
  await ensureCouponsTable(pool);
  const { rows } = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
  res.json({ items: rows });
}));
router.post('/coupons', asyncHandler(async (req, res) => {
  await ensureCouponsTable(pool);
  const { code, discount_type, discount_value, min_order_cents, max_uses, ends_at } = req.body;
  let rows;
  try {
    ({ rows } = await pool.query(
      `INSERT INTO coupons (code, discount_type, discount_value, min_order_cents, max_uses, ends_at)
       VALUES (UPPER($1),$2,$3,$4,$5,$6) RETURNING *`,
      [code, discount_type||'percent', discount_value||0, min_order_cents||0, max_uses||0, ends_at||null]
    ));
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'coupon_code_exists' });
    throw e;
  }
  res.json({ item: rows[0] });
}));
router.patch('/coupons/:id', asyncHandler(async (req, res) => {
  await ensureCouponsTable(pool);
  const { is_active } = req.body;
  await pool.query('UPDATE coupons SET is_active=$1 WHERE id=$2', [is_active, req.params.id]);
  res.json({ ok: true });
}));
router.delete('/coupons/:id', asyncHandler(async (req, res) => {
  await ensureCouponsTable(pool);
  await pool.query('DELETE FROM coupons WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ============ BANNERLAR ============
router.get('/banners', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM banners ORDER BY sort_order, created_at DESC');
  res.json({ items: rows });
}));
router.post('/banners', asyncHandler(async (req, res) => {
  const { title, subtitle, image_url, link_url, position, sort_order } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO banners (title, subtitle, image_url, link_url, position, sort_order)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [title, subtitle||'', image_url||'', link_url||'', position||'home_top', sort_order||0]
  );
  res.json({ item: rows[0] });
}));
router.patch('/banners/:id', asyncHandler(async (req, res) => {
  const { is_active, title, subtitle, image_url, link_url, sort_order } = req.body;
  const sets = [], vals = []; let i = 1;
  if (is_active !== undefined) { sets.push(`is_active=$${i++}`); vals.push(is_active); }
  if (title !== undefined) { sets.push(`title=$${i++}`); vals.push(title); }
  if (subtitle !== undefined) { sets.push(`subtitle=$${i++}`); vals.push(subtitle); }
  if (image_url !== undefined) { sets.push(`image_url=$${i++}`); vals.push(image_url); }
  if (link_url !== undefined) { sets.push(`link_url=$${i++}`); vals.push(link_url); }
  if (sort_order !== undefined) { sets.push(`sort_order=$${i++}`); vals.push(sort_order); }
  if (sets.length) { vals.push(req.params.id); await pool.query(`UPDATE banners SET ${sets.join(', ')} WHERE id=$${i}`, vals); }
  res.json({ ok: true });
}));
router.delete('/banners/:id', asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM banners WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ============ İADELER ============
router.get('/returns', asyncHandler(async (req, res) => {
  // returns tablosunu garantile (022 migration'ı uygulanmamışsa bile sayfa çalışır)
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
  const { rows } = await pool.query(
    `SELECT r.*, o.order_no, u.email AS user_email, u.name AS user_name, u.customer_code
     FROM returns r LEFT JOIN orders o ON o.id=r.order_id LEFT JOIN users u ON u.id=r.user_id
     ORDER BY r.created_at DESC LIMIT 200`
  );
  res.json({ items: rows });
}));
router.patch('/returns/:id', param('id').isUUID(), body('status').optional().isString(), asyncHandler(async (req, res) => {
  if (!checkValidation(req, res)) return;
  const { status, admin_note } = req.body;
  if (!['approved', 'rejected', 'completed'].includes(status)) return res.status(400).json({ error: 'invalid_status' });
  const { rows } = await pool.query('UPDATE returns SET status=$1, admin_note=$2, updated_at=now() WHERE id=$3 RETURNING order_id',
    [status, admin_note||'', req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'return_not_found' });
  // Onaylanan / tamamlanan iade → sipariş durumu "iade edildi" olur
  if (status === 'approved' || status === 'completed') {
    await pool.query("UPDATE orders SET status='refunded', updated_at=now() WHERE id=$1", [rows[0].order_id]);
  }
  res.json({ ok: true });
}));

// ============ STOK ============
router.get('/stock', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.id, p.name, p.stock, p.barcode,
      (SELECT count(*)::int FROM stock_moves sm WHERE sm.product_id=p.id) AS move_count
     FROM products p ORDER BY p.stock ASC LIMIT 200`
  );
  res.json({ items: rows });
}));
router.post('/stock/:id/adjust', asyncHandler(async (req, res) => {
  const { qty_change, reason } = req.body;
  const q = parseInt(qty_change, 10) || 0;
  await pool.query('UPDATE products SET stock = GREATEST(0, stock + $1) WHERE id=$2', [q, req.params.id]);
  await pool.query('INSERT INTO stock_moves (product_id, qty_change, reason, created_by) VALUES ($1,$2,$3,$4)',
    [req.params.id, q, reason||'manuel', req.user.id]);
  res.json({ ok: true });
}));

// v608: kategori adi -> otomatik ikon anahtari (kategori eklenince ikon otomatik atanir)
function autoCategoryIcon(name){
  const n = String(name || '').toLowerCase();
  const has = (...words) => words.some(w => n.includes(w));
  if (has('hırdavat', 'hirdavat', 'hardware', 'alet', 'tornavida', 'matkap')) return 'wrench';
  if (has('moda', 'giyim', 'tekstil', 'elbise', 'ayakkabı', 'ayakkabi', 'fashion')) return 'shirt';
  if (has('ev ', 'ev&', 'yaşam', 'yasam', 'dekor', 'mobilya', 'mutfak', 'home')) return 'home';
  if (has('güzellik', 'guzellik', 'bakım', 'bakim', 'kozmetik', 'beauty', 'cilt')) return 'sparkle';
  if (has('spor', 'outdoor', 'kamp', 'balık', 'balik', 'av ', 'fitness', 'sport')) return 'dumbbell';
  if (has('oyuncak', 'hobi', 'toy', 'lego', 'oyun hamuru')) return 'blocks';
  if (has('oyun', 'game', 'konsol', 'playstation', 'xbox')) return 'game';
  if (has('elektronik', 'teknoloji', 'electronic', 'chip')) return 'chip';
  if (has('telefon', 'phone', 'kılıf', 'kilif', 'şarj', 'sarj')) return 'phone';
  if (has('bilgisayar', 'computer', 'laptop', 'klavye', 'mouse')) return 'computer';
  if (has('hediye', 'gift', 'hediyelik')) return 'gift';
  if (has('otomotiv', 'otomobil', 'araba', 'car', 'motosiklet')) return 'car';
  if (has('bahçe', 'bahce', 'garden', 'bitki', 'çiçek', 'cicek')) return 'leaf';
  if (has('sağlık', 'saglik', 'health', 'medikal', 'eczane')) return 'heart';
  if (has('kitap', 'kırtasiye', 'kirtasiye', 'book', 'defter', 'kalem')) return 'book';
  if (has('saat', 'takı', 'taki', 'aksesuar', 'watch', 'jewel')) return 'watch';
  if (has('bebek', 'baby', 'çocuk', 'cocuk', 'kid')) return 'plush';
  return 'tag';
}

// ============ KATEGORİLER ============
router.get('/categories', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.*, (SELECT count(*)::int FROM products p WHERE p.category_id=c.id) AS product_count
     FROM categories c ORDER BY c.sort_order, c.name`
  );
  res.json({ items: rows });
}));
router.post('/categories', asyncHandler(async (req, res) => {
  const { name, slug, icon, sort_order } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name_required' });
  const finalSlug = (slug && String(slug).trim()) || String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-');
  // v608: eski veritabanlarinda icon/sort_order sutunu yoksa INSERT patliyordu (internal_error) — once sutunlari garantile
  await pool.query("ALTER TABLE categories ADD COLUMN IF NOT EXISTS icon TEXT DEFAULT ''");
  await pool.query('ALTER TABLE categories ADD COLUMN IF NOT EXISTS sort_order INT DEFAULT 0');
  // v608: ikon verilmediyse kategori adindan otomatik ata (or. Hirdavat -> wrench)
  const finalIcon = (icon && String(icon).trim()) || autoCategoryIcon(name);
  try {
    const { rows } = await pool.query(
      'INSERT INTO categories (name, slug, icon, sort_order) VALUES ($1,$2,$3,$4) RETURNING *',
      [String(name).trim(), finalSlug, finalIcon, Number(sort_order) || 0]
    );
    res.json({ item: rows[0] });
  } catch (e) {
    if (e && e.code === '23505') return res.status(409).json({ error: 'slug_exists', slug: finalSlug });
    throw e;
  }
}));
router.patch('/categories/:id', asyncHandler(async (req, res) => {
  const { name, is_active, sort_order } = req.body;
  const sets = [], vals = []; let i = 1;
  if (name !== undefined) { sets.push(`name=$${i++}`); vals.push(name); }
  if (is_active !== undefined) { sets.push(`is_active=$${i++}`); vals.push(is_active); }
  if (sort_order !== undefined) { sets.push(`sort_order=$${i++}`); vals.push(sort_order); }
  if (sets.length) { vals.push(req.params.id); await pool.query(`UPDATE categories SET ${sets.join(', ')} WHERE id=$${i}`, vals); }
  res.json({ ok: true });
}));

// v568: kategori sil — ürünü olan kategori silinemez (önce ürünler başka kategoriye taşınmalı)
router.delete('/categories/:id', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM products WHERE category_id=$1', [req.params.id]);
  if (rows[0].n > 0) return res.status(400).json({ error: 'category_has_products', count: rows[0].n });
  await pool.query('DELETE FROM categories WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ---- v557: Kullanici adi kurallari (admin: izin ver / blokla) ----
// Isimler normalize saklanir (kucuk harf, _ . - ve bosluk yok sayilir) — auth.js ile ayni kural.
function normalizeNickAdmin(n){ return String(n || '').toLowerCase().replace(/[_.\s-]+/g, ''); }

// GET /api/admin/nickname-rules — tum kurallar
router.get(
  '/nickname-rules',
  asyncHandler(async (_req, res) => {
    const { rows } = await pool.query('SELECT nickname, action, reason, created_at FROM nickname_rules ORDER BY created_at DESC');
    res.json({ items: rows });
  })
);

// POST /api/admin/nickname-rules — { nickname, action: 'allow'|'block', reason? }
router.post(
  '/nickname-rules',
  body('nickname').trim().isLength({ min: 2, max: 30 }),
  body('action').isIn(['allow', 'block']),
  body('reason').optional().isString().isLength({ max: 200 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const nick = normalizeNickAdmin(req.body.nickname);
    if (!nick) return res.status(400).json({ error: 'invalid_nickname' });
    const { rows } = await pool.query(
      `INSERT INTO nickname_rules (nickname, action, reason) VALUES ($1, $2, $3)
       ON CONFLICT (nickname) DO UPDATE SET action = EXCLUDED.action, reason = EXCLUDED.reason
       RETURNING nickname, action, reason, created_at`,
      [nick, req.body.action, req.body.reason || null]
    );
    res.status(201).json(rows[0]);
  })
);

// DELETE /api/admin/nickname-rules/:nickname — kurali kaldir (varsayilan listeye don)
router.delete(
  '/nickname-rules/:nickname',
  asyncHandler(async (req, res) => {
    const nick = normalizeNickAdmin(req.params.nickname);
    await pool.query('DELETE FROM nickname_rules WHERE nickname = $1', [nick]);
    res.json({ deleted: true });
  })
);

// v630: Fabrika video yukleme (admin) — ham govde (express.raw), yeni bagimlilik yok.
// POST /api/admin/upload-video?ext=mp4 — Content-Type: video/mp4 | video/webm
// Yalnizca mp4/webm, en fazla 200 MB. Dosya src/uploads/factory/ altina rastgele adla
// kaydedilir, herkese acik URL doner. Bu router requireAuth + requireAdmin korumalidir.
// NOT: Railway diski gecicidir — yeniden deployda silinir; kalici video icin
// shop ZIP'inin videos/ klasorune eklenmelidir.
// Donen URL'in calismasi icin index.js'de /uploads static sunumu gerekir.
const FACTORY_UPLOAD_DIR = path.join(__dirname, '..', 'uploads', 'factory');
const FACTORY_UPLOAD_MAX = 200 * 1024 * 1024; // 200 MB
const FACTORY_UPLOAD_EXTS = ['mp4', 'webm'];

function factoryUploadMagicOk(buf, ext) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  if (ext === 'webm') return buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3;
  // mp4: ilk kutu 'ftyp' (bayt 4-8)
  return buf.toString('ascii', 4, 8) === 'ftyp';
}

router.post(
  '/upload-video',
  express.raw({ type: ['video/mp4', 'video/webm', 'application/octet-stream'], limit: '201mb' }),
  asyncHandler(async (req, res) => {
    const ext = String(req.query.ext || '').toLowerCase();
    if (!FACTORY_UPLOAD_EXTS.includes(ext)) return res.status(400).json({ error: 'invalid_ext' });
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'video/mp4' && ct !== 'video/webm' && ct !== 'application/octet-stream') {
      return res.status(415).json({ error: 'invalid_content_type' });
    }
    if (!Buffer.isBuffer(req.body)) return res.status(415).json({ error: 'invalid_content_type' });
    if (!req.body.length) return res.status(400).json({ error: 'empty_file' });
    if (req.body.length > FACTORY_UPLOAD_MAX) return res.status(413).json({ error: 'file_too_large' });
    if (!factoryUploadMagicOk(req.body, ext)) return res.status(415).json({ error: 'invalid_file' });
    await fs.promises.mkdir(FACTORY_UPLOAD_DIR, { recursive: true });
    const name = 'factory-' + Date.now() + '-' + crypto.randomBytes(8).toString('hex') + '.' + ext;
    await fs.promises.writeFile(path.join(FACTORY_UPLOAD_DIR, name), req.body);
    const base = req.protocol + '://' + req.get('host');
    res.status(201).json({ ok: true, url: base + '/uploads/factory/' + name, size: req.body.length });
  })
);

// v639: Cloudflare Stream — kalici fabrika videosu (Railway diski gecici oldugu icin).
// Kimlik bilgileri Railway env'den: CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_STREAM_TOKEN.
// Env eksikse 503 stream_not_configured; jeton ASLA yanita yazilmaz.
function cfStreamCfg() {
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID || '';
  const token = process.env.CLOUDFLARE_STREAM_TOKEN || '';
  if (!accountId || !token) return null;
  return { accountId, token };
}

async function cfStreamCall(accountId, token, path, method, body) {
  const r = await fetch('https://api.cloudflare.com/client/v4/accounts/' + accountId + '/stream' + path, {
    method,
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  return { ok: r.ok && !!(data && data.success), status: r.status, data };
}

// POST /api/admin/stream-upload-url — Cloudflare direct_upload: {uploadURL, uid}
router.post(
  '/stream-upload-url',
  asyncHandler(async (_req, res) => {
    const cfg = cfStreamCfg();
    if (!cfg) return res.status(503).json({ error: 'stream_not_configured' });
    let out;
    try {
      out = await cfStreamCall(cfg.accountId, cfg.token, '/direct_upload', 'POST', { maxDurationSeconds: 3600 });
    } catch (e) {
      console.error('stream-upload-url upstream error:', e.message);
      return res.status(502).json({ error: 'stream_upstream' });
    }
    if (!out.ok || !out.data || !out.data.result || !out.data.result.uploadURL || !out.data.result.uid) {
      console.error('stream-upload-url upstream status:', out.status, JSON.stringify((out.data && out.data.errors) || null));
      return res.status(502).json({ error: 'stream_upstream' });
    }
    res.json({ uploadURL: out.data.result.uploadURL, uid: out.data.result.uid });
  })
);

// POST /api/admin/stream-download-url {uid} — MP4 indirme adresi: {url, status}
router.post(
  '/stream-download-url',
  asyncHandler(async (req, res) => {
    const uid = String((req.body && req.body.uid) || '').trim();
    if (!uid) return res.status(400).json({ error: 'invalid_uid' });
    const cfg = cfStreamCfg();
    if (!cfg) return res.status(503).json({ error: 'stream_not_configured' });
    let out;
    try {
      out = await cfStreamCall(cfg.accountId, cfg.token, '/' + encodeURIComponent(uid) + '/downloads', 'POST', undefined);
    } catch (e) {
      console.error('stream-download-url upstream error:', e.message);
      return res.status(502).json({ error: 'stream_upstream' });
    }
    if (!out.ok || !out.data || !out.data.result) {
      console.error('stream-download-url upstream status:', out.status, JSON.stringify((out.data && out.data.errors) || null));
      return res.status(502).json({ error: 'stream_upstream' });
    }
    const d = out.data.result.default || null;
    res.json({ url: d ? d.url || null : null, status: d ? d.status || 'unknown' : 'unknown' });
  })
);

module.exports = router;
