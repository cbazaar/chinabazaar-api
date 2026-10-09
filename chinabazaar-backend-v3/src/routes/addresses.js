// Teslimat adresleri (Türkiye: il / ilçe / mahalle)
const express = require('express');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const pool = require('../db');

const router = express.Router();
router.use(requireAuth);

const validators = [
  body('label').optional().trim().isLength({ max: 30 }),
  body('full_name').trim().isLength({ min: 2, max: 100 }),
  body('phone').isMobilePhone('tr-TR'),
  body('city').trim().notEmpty(),          // il
  body('district').trim().notEmpty(),      // ilçe
  body('neighborhood').optional().trim(),   // mahalle
  body('address_line').trim().notEmpty(),   // sokak/cadde, bina, daire
  body('postal_code').optional().trim().isLength({ max: 10 }),
  body('is_default').optional().isBoolean(),
];

// GET /api/addresses
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      'SELECT * FROM addresses WHERE user_id = $1 ORDER BY is_default DESC, created_at DESC',
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// POST /api/addresses
router.post(
  '/',
  validators,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { label, full_name, phone, city, district, neighborhood, address_line, postal_code, is_default } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      if (is_default) {
        await client.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [req.user.id]);
      }
      const { rows } = await client.query(
        `INSERT INTO addresses (user_id, label, full_name, phone, city, district, neighborhood, address_line, postal_code, is_default)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [req.user.id, label || null, full_name, phone, city, district, neighborhood || null, address_line, postal_code || null, !!is_default]
      );
      await client.query('COMMIT');
      res.status(201).json(rows[0]);
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  })
);

module.exports = router;
