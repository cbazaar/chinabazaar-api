// Admin yönetim API'leri: kullanıcılar + yorum moderasyonu.
// Tüm route'lar requireAuth + requireAdmin gerektirir.
const express = require('express');
const { param, body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// GET /api/admin/users — kayıtlı profiller
router.get(
  '/users',
  asyncHandler(async (_req, res) => {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.phone, u.is_admin, u.is_blocked, u.email_verified, u.created_at,
              (SELECT count(*)::int FROM orders o WHERE o.user_id = u.id) AS order_count
       FROM users u ORDER BY u.created_at DESC LIMIT 500`
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
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'cannot_modify_self' });
    const sets = [];
    const vals = [];
    if (typeof req.body.is_blocked === 'boolean') { vals.push(req.body.is_blocked); sets.push(`is_blocked = $${vals.length}`); }
    if (typeof req.body.is_admin === 'boolean') { vals.push(req.body.is_admin); sets.push(`is_admin = $${vals.length}`); }
    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
    vals.push(req.params.id);
    const { rows } = await pool.query(
      `UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = $${vals.length}
       RETURNING id, email, name, is_admin, is_blocked`,
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
              p.name AS product_name, u.name AS user_name, u.email AS user_email
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

module.exports = router;
