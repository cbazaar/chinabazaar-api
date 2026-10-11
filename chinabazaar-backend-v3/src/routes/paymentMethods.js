// Kayıtlı ödeme yöntemleri — PCI DSS: yalnız son 4 hane saklanır.
// TAM kart numarası (PAN) ve CVV ASLA alınmaz/kaydedilmez; tahsilat PayTR üzerinden.
const express = require('express');
const { body, param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth);

const BRANDS = ['visa', 'mastercard', 'amex', 'troy', 'other'];

function publicCard(row) {
  return {
    id: row.id,
    label: row.label,
    brand: row.brand,
    last4: row.last4,
    exp_month: row.exp_month,
    exp_year: row.exp_year,
    created_at: row.created_at,
  };
}

// GET /api/payment-methods — kullanıcının kayıtlı kartları
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT id, label, brand, last4, exp_month, exp_year, created_at
       FROM payment_methods WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ items: rows.map(publicCard) });
  })
);

// POST /api/payment-methods  { label?, brand?, last4, exp_month, exp_year }
// NOT: last4 yalnız kart numarasının SON 4 hanesidir; tam numara gönderilmez.
router.post(
  '/',
  body('label').optional().trim().isLength({ min: 1, max: 60 }),
  body('brand').optional().isIn(BRANDS),
  body('last4').matches(/^[0-9]{4}$/),
  body('exp_month').isInt({ min: 1, max: 12 }),
  body('exp_year').isInt({ min: new Date().getFullYear(), max: new Date().getFullYear() + 15 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { label, brand, last4, exp_month, exp_year } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO payment_methods (user_id, label, brand, last4, exp_month, exp_year)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, label, brand, last4, exp_month, exp_year, created_at`,
      [req.user.id, label || 'Kartım', brand || 'other', last4, exp_month, exp_year]
    );
    res.status(201).json({ item: publicCard(rows[0]) });
  })
);

// DELETE /api/payment-methods/:id — yalnız kart sahibi silebilir
router.delete(
  '/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rowCount } = await pool.query(
      'DELETE FROM payment_methods WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true });
  })
);

module.exports = router;
