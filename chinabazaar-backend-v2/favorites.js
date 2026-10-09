// Favori ürünler
const express = require('express');
const { body, param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth);

// GET /api/favorites — kullanıcının favori ürünleri
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count
       FROM favorites f JOIN products p ON p.id = f.product_id
       WHERE f.user_id = $1 AND p.is_active = TRUE
       ORDER BY f.created_at DESC`,
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// POST /api/favorites  { product_id }
router.post(
  '/',
  body('product_id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { product_id } = req.body;
    const prod = await pool.query('SELECT id FROM products WHERE id = $1 AND is_active = TRUE', [product_id]);
    if (!prod.rows.length) return res.status(404).json({ error: 'product_not_found' });
    await pool.query(
      'INSERT INTO favorites (user_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, product_id]
    );
    res.status(201).json({ ok: true, product_id });
  })
);

// DELETE /api/favorites/:product_id
router.delete(
  '/:product_id',
  param('product_id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await pool.query('DELETE FROM favorites WHERE user_id = $1 AND product_id = $2', [
      req.user.id,
      req.params.product_id,
    ]);
    res.json({ ok: true });
  })
);

module.exports = router;
