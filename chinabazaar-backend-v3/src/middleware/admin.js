// Admin yetkisi — requireAuth'tan SONRA kullanılır.
// req.user.id üzerinden users.is_admin kontrol eder; değilse 403.
const asyncHandler = require('./asyncHandler');
const pool = require('../db');

const requireAdmin = asyncHandler(async (req, res, next) => {
  const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
  next();
});

module.exports = { requireAdmin };
