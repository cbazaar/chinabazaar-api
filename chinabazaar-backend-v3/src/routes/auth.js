// Kimlik doğrulama: kayıt + giriş (JWT)
const express = require('express');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const { signToken, requireAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');

const router = express.Router();

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, phone: row.phone, is_admin: !!row.is_admin };
}

// POST /api/auth/register  { email, password, name, phone?, admin_key? }
// admin_key: ADMIN_SETUP_KEY env doluysa ve eşleşiyorsa kullanıcı admin olur.
router.post(
  '/register',
  registerLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('name').trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  body('admin_key').optional().isString().isLength({ max: 128 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password, name, phone, admin_key } = req.body;
    const makeAdmin = Boolean(cfg.adminSetupKey && admin_key && admin_key === cfg.adminSetupKey);
    const hash = await bcrypt.hash(password, 12);
    try {
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone, is_admin)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, phone, is_admin`,
        [email, hash, name, phone || null, makeAdmin]
      );
      const user = publicUser(rows[0]);
      res.status(201).json({ user, token: signToken(user) });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'email_in_use' });
      throw err;
    }
  })
);

// POST /api/auth/login  { email, password }
router.post(
  '/login',
  loginLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const row = rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// GET /api/auth/me — giriş yapan kullanıcının profili (is_admin dahil)
router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      'SELECT id, email, name, phone, is_admin FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'user_not_found' });
    res.json(publicUser(rows[0]));
  })
);

module.exports = router;
