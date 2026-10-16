// Muhasebe: özet, işlemler, banka/kasa, cari, fatura
const express = require('express');
const asyncHandler = require('../middleware/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth, requireAdmin);

// GET /api/accounting/summary?from=YYYY-MM-DD&to=YYYY-MM-DD
router.get('/summary', asyncHandler(async (req, res) => {
  const { from, to } = req.query;
  const f = from || new Date().toISOString().slice(0,10);
  const t = to || f;
  const { rows } = await pool.query(`
    SELECT kind, category, SUM(amount_cents) AS total
    FROM account_transactions WHERE tx_date BETWEEN $1 AND $2
    GROUP BY kind, category`, [f, t]);
  let income = 0, expense = 0;
  const byCat = {};
  for (const r of rows) {
    const v = Number(r.total);
    if (r.kind === 'income') income += v; else expense += v;
    byCat[r.kind + ':' + r.category] = v;
  }
  const ord = await pool.query(`
    SELECT COUNT(*) n, COALESCE(SUM(total_cents),0) s
    FROM orders WHERE created_at::date BETWEEN $1 AND $2 AND status <> 'cancelled'`, [f, t]);
  res.json({ income_cents: income, expense_cents: expense, net_cents: income - expense,
    by_category: byCat, orders: Number(ord.rows[0].n), order_total_cents: Number(ord.rows[0].s) });
}));

// GET /api/accounting/transactions?kind=&from=&to=
router.get('/transactions', asyncHandler(async (req, res) => {
  const { kind, from, to } = req.query;
  const cond = [], args = [];
  if (kind) { args.push(kind); cond.push(`kind = $${args.length}`); }
  if (from) { args.push(from); cond.push(`tx_date >= $${args.length}`); }
  if (to) { args.push(to); cond.push(`tx_date <= $${args.length}`); }
  const { rows } = await pool.query(
    `SELECT * FROM account_transactions ${cond.length ? 'WHERE ' + cond.join(' AND ') : ''} ORDER BY tx_date DESC, created_at DESC LIMIT 500`, args);
  res.json({ items: rows });
}));

// POST /api/accounting/transactions
router.post('/transactions', asyncHandler(async (req, res) => {
  const { kind, category, amount_cents, currency, bank_account_id, description, tx_date } = req.body;
  if (!['income','expense'].includes(kind) || !category || !amount_cents) return res.status(400).json({ error: 'invalid' });
  const { rows } = await pool.query(
    `INSERT INTO account_transactions (kind, category, amount_cents, currency, bank_account_id, description, tx_date)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [kind, category, Math.round(amount_cents), currency || 'TRY', bank_account_id || null, description || null, tx_date || new Date().toISOString().slice(0,10)]);
  if (bank_account_id) {
    await pool.query(`UPDATE bank_accounts SET balance_cents = balance_cents + $1 WHERE id = $2`,
      [kind === 'income' ? Math.round(amount_cents) : -Math.round(amount_cents), bank_account_id]);
  }
  res.status(201).json(rows[0]);
}));

// Banka & Kasa
router.get('/banks', asyncHandler(async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM bank_accounts ORDER BY is_cash DESC, name`);
  res.json({ items: rows });
}));
router.post('/banks', asyncHandler(async (req, res) => {
  const { name, bank_name, iban, currency, is_cash, balance_cents } = req.body;
  if (!name) return res.status(400).json({ error: 'invalid' });
  const { rows } = await pool.query(
    `INSERT INTO bank_accounts (name, bank_name, iban, currency, is_cash, balance_cents) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [name, bank_name || null, iban || null, currency || 'TRY', !!is_cash, Math.round(balance_cents || 0)]);
  res.status(201).json(rows[0]);
}));

// Cari hesaplar
router.get('/currents', asyncHandler(async (req, res) => {
  const { type } = req.query;
  const { rows } = await pool.query(
    `SELECT * FROM current_accounts ${type ? 'WHERE type = $1' : ''} ORDER BY name`, type ? [type] : []);
  res.json({ items: rows });
}));
router.post('/currents', asyncHandler(async (req, res) => {
  const { type, name, tax_no, phone, email, currency } = req.body;
  if (!['customer','supplier'].includes(type) || !name) return res.status(400).json({ error: 'invalid' });
  const { rows } = await pool.query(
    `INSERT INTO current_accounts (type, name, tax_no, phone, email, currency) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [type, name, tax_no || null, phone || null, email || null, currency || 'TRY']);
  res.status(201).json(rows[0]);
}));

// Faturalar
router.get('/invoices', asyncHandler(async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM invoices ORDER BY invoice_date DESC, created_at DESC LIMIT 200`);
  res.json({ items: rows });
}));
router.post('/invoices', asyncHandler(async (req, res) => {
  const b = req.body;
  const no = b.invoice_no || ('F' + Date.now().toString().slice(-8));
  const { rows } = await pool.query(
    `INSERT INTO invoices (invoice_no, order_id, customer_name, tax_info, items, subtotal_cents, discount_cents, vat_cents, shipping_cents, total_cents, currency, payment_method, status, invoice_date)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
    [no, b.order_id || null, b.customer_name || '', b.tax_info || null, JSON.stringify(b.items || []),
     Math.round(b.subtotal_cents || 0), Math.round(b.discount_cents || 0), Math.round(b.vat_cents || 0),
     Math.round(b.shipping_cents || 0), Math.round(b.total_cents || 0), b.currency || 'TRY',
     b.payment_method || null, b.status || 'draft', b.invoice_date || new Date().toISOString().slice(0,10)]);
  res.status(201).json(rows[0]);
}));

// ---- Nebim V3 Integrator (v610) ----
// POST /api/accounting/nebim/send-invoice { order_id } — siparis faturasini Nebim'e gonder (yalniz admin)
router.post('/nebim/send-invoice', asyncHandler(async (req, res) => {
  const orderId = req.body && req.body.order_id;
  if (!orderId) return res.status(400).json({ error: 'order_id_required' });
  const nebim = require('../services/nebim');
  const r = await nebim.sendOrderInvoice(orderId);
  res.json(r);
}));

// GET /api/accounting/nebim/sync — son Nebim gonderim kayitlari (yalniz admin)
router.get('/nebim/sync', asyncHandler(async (req, res) => {
  await pool.query(`CREATE TABLE IF NOT EXISTS nebim_sync (id SERIAL PRIMARY KEY, order_id UUID, model_type INT, status TEXT, nebim_doc_no TEXT, detail TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  const { rows } = await pool.query('SELECT ns.*, o.order_no FROM nebim_sync ns LEFT JOIN orders o ON o.id = ns.order_id ORDER BY ns.created_at DESC LIMIT 100');
  res.json({ items: rows });
}));

module.exports = router;
