// JWT kimlik doğrulama middleware'i

// Kullanım: router.get('/x', requireAuth, handler)  -> req.user = { id, email, role, ... }

// fix10e M4 + L18: jwt.verify yalnızca HS256 (cfg.jwtAlgorithms) kabul eder;
// req.user artık rol de taşır (role: 'user' | 'factory' | 'master'). Fabrika/master
// jetonları requireAuth'tan geçer ama req.user.id boştur — kullanıcıya özel
// rotalar (örn. PATCH /api/auth/me) rolü kontrol edip 403 dönmelidir.

const jwt = require('jsonwebtoken');

const cfg = require('../config');


function signToken(user) {

  return jwt.sign({ sub: user.id, email: user.email, role: 'user' }, cfg.jwtSecret, { expiresIn: '30d', algorithm: 'HS256' });

}


function userFromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;
  return {
    id: payload.sub ?? null,
    email: payload.email ?? null,
    role: payload.role || 'user',
    is_admin: !!payload.is_admin,
    factory_id: Number.isInteger(payload.factory_id) ? payload.factory_id : null,
  };
}


function requireAuth(req, res, next) {

  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {

    const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });

    req.user = userFromPayload(payload);

    next();

  } catch {

    return res.status(401).json({ error: 'invalid_token' });

  }

}


// Geçerli token varsa req.user doldurur, yoksa sessizce devam eder.

function optionalAuth(req, _res, next) {

  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (token) {

    try {

      const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });

      req.user = userFromPayload(payload);

    } catch { /* yok say */ }

  }

  next();

}


module.exports = { signToken, requireAuth, optionalAuth };
