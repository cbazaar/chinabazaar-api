// Kimlik doğrulama: kayıt + giriş (JWT)
const express = require('express');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const { signToken } = require('../middleware/auth');
const pool = require('../db');

const router = express.Router();

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, phone: row.phone };
}

// POST /api/auth/register  { email, password, name, phone? }
router.post(
  '/register',
  registerLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('name').trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().isMobilePhone('tr-TR'),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password, name, phone } = req.body;
    const hash = await bcrypt.hash(password, 12);
    try {
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone)
         VALUES ($1, $2, $3, $4) RETURNING id, email, name, phone`,
        [email, hash, name, phone || null]
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

module.exports = router;
