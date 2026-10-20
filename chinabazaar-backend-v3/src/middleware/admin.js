// Admin yetkisi — requireAuth'tan SONRA kullanılır.
// req.user.id üzerinden users.is_admin kontrol eder; değilse 403.
//
// fix10d — CBAI master: role 'master' + is_admin true JWT admin kabul edilir,
// master için DB kullanıcı araması ATLANIR (master'ın users satırı yok).
// Normal admin akışı aynen (users.is_admin kontrolü). Fabrika jetonu
// (role 'factory') admin rotalarında hâlâ 403 alır (master değilse DB
// aramasına düşer, fabrika hesabı users'ta admin değildir).
// fix10e L18: jwt.verify yalnızca HS256 (cfg.jwtAlgorithms) kabul eder.
// Not: Canlı requireAuth yalnızca { id, email } taşır; bu yüzden master
// iddiası Bearer <redacted> kendisinden de doğrulanır (jwt.verify: imza +
// süre). requireAuth ileride role/is_admin'i req.user'a taşırsa ilk kontrol
// zaten yakalar.
const asyncHandler = require('./asyncHandler');
const jwt = require('jsonwebtoken');
const cfg = require('../config');
const pool = require('../db');
const { isMasterJtiRevoked } = require('./masterRevoke'); // 2026-10-20 N1: master iptal kontrolü

function isMasterClaim(claim) {
  return !!claim && claim.role === 'master' && claim.is_admin === true;
}

const requireAdmin = asyncHandler(async (req, res, next) => {
  // 1) Çağrıcı role/is_admin'i req.user'a taşımışsa (ileriye dönük):
  if (isMasterClaim(req.user)) return next();
  // 2) Canlı requireAuth iddiaları taşımaz — Bearer <redacted> doğrula:
  const header = (req.headers && req.headers.authorization) || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });
      if (isMasterClaim(payload)) {
        // 2026-10-20 N1: iptal edilmiş master jeton reddedilir (sızıntı durumunda).
        if (payload.jti && (await isMasterJtiRevoked(payload.jti))) {
          return res.status(401).json({ error: 'token_revoked' });
        }
        return next();
      }
    } catch { /* geçersiz jeton: aşağıdaki normal akışa düşer */ }
  }
  // 3) Normal admin akışı (aynen):
  if (!req.user || !req.user.id) return res.status(403).json({ error: 'forbidden' });
  const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0]?.is_admin) return res.status(403).json({ error: 'forbidden' });
  next();
});

module.exports = { requireAdmin };
