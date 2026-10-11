// Kimlik doğrulama: kayıt + giriş (JWT)
const express = require('express');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const codeLimiter = require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' } });
const { signToken, requireAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');
const mailer = require('../services/mailer');
const crypto = require('crypto');

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
    if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// POST /api/auth/send-code { email } — 6 haneli doğrulama kodu gönderir (10 dk geçerli)
// Kayıt ve giriş için ortak adım. E-posta sağlayıcı yoksa 503.
router.post(
  '/send-code',
  codeLimiter,
  body('email').isEmail().normalizeEmail(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (!mailer.isEnabled()) return res.status(503).json({ error: 'email_not_configured' });
    const { email } = req.body;
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Önceki tüketilmemiş kodları geçersiz kıl
      await client.query(
        `UPDATE email_codes SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL`,
        [email]
      );
      await client.query(
        `INSERT INTO email_codes (email, purpose, code_hash, expires_at) VALUES ($1, 'auth', $2, now() + interval '10 minutes')`,
        [email, codeHash]
      );
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    try {
      await mailer.sendVerificationCode(email, code);
    } catch (e) {
      console.error('[mailer] kod gönderilemedi:', e.message);
      return res.status(502).json({ error: 'email_send_failed' });
    }
    res.json({ sent: true });
  })
);

// POST /api/auth/verify-code { email, code, password, name? }
// Kod doğruysa: kullanıcı varsa şifreyi de doğrular → giriş; yoksa name+password ile kaydeder → giriş.
router.post(
  '/verify-code',
  codeLimiter,
  body('email').isEmail().normalizeEmail(),
  body('code').matches(/^[0-9]{6}$/),
  body('password').isLength({ min: 8 }),
  body('name').optional().trim().isLength({ min: 2, max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, code, password, name } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM email_codes WHERE email = $1 AND consumed_at IS NULL AND expires_at > now()
       ORDER BY created_at DESC LIMIT 1`,
      [email]
    );
    const rec = rows[0];
    if (!rec) return res.status(400).json({ error: 'code_expired' });
    if (rec.attempts >= 5) return res.status(429).json({ error: 'too_many_attempts' });
    const ok = await bcrypt.compare(code, rec.code_hash);
    await pool.query('UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1', [rec.id]);
    if (!ok) return res.status(400).json({ error: 'code_invalid' });
    await pool.query('UPDATE email_codes SET consumed_at = now() WHERE id = $1', [rec.id]);

    const { rows: urows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (urows[0]) {
      const row = urows[0];
      if (!(await bcrypt.compare(password, row.password_hash))) {
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
      await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.id]);
      const user = publicUser(row);
      return res.json({ user, token: signToken(user) });
    }
    // Yeni kayıt
    if (!name) return res.status(400).json({ error: 'name_required' });
    const hash = await bcrypt.hash(password, 12);
    try {
      const { rows: nrows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, email_verified) VALUES ($1, $2, $3, TRUE)
         RETURNING id, email, name, phone, is_admin`,
        [email, hash, name]
      );
      const user = publicUser(nrows[0]);
      res.status(201).json({ user, token: signToken(user) });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'email_in_use' });
      throw err;
    }
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
