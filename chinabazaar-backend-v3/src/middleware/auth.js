// JWT kimlik doğrulama middleware'i
// Kullanım: router.get('/x', requireAuth, handler)  -> req.user = { id, email }
const jwt = require('jsonwebtoken');
const cfg = require('../config');

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, cfg.jwtSecret, { expiresIn: '7d' });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const payload = jwt.verify(token, cfg.jwtSecret);
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

module.exports = { signToken, requireAuth };
