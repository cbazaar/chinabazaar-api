// Site erişim kilidi (CBOs26.67) — SUNUCU TARAFLI doğrulama (2026-10-22 BULGU-5)
// CBOs27.2: fix-gate paketinden aynen entegre edildi (index.js /api/gate montajı).
// GATE_PASSWORD_HASH env'i yoksa uç 503 döner — kapı pasif, mevcut davranış aynen.
//
// Önceki uygulama şifreyi istemcide SHA-256 ile kıyaslıyordu; beklenen hash
// herkese açık JS'in içindeydi ve `sessionStorage`'a yazılarak kilit şifresiz
// açılabiliyordu. Bu uç şifreyi SUNUCUDA doğrular ve imzalı, kısa ömürlü bir
// kilit jetonu verir; ön yüz kilidin açık olduğunu /status ile doğrulatır.
//
// Şifre ASLA kodda tutulmaz: GATE_PASSWORD_HASH env değişkeninde SHA-256 hex
// (64 küçük harf) olarak tutulur. Değer loglanmaz, yanıta yazılmaz.

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { ipKeyGenerator } = require('../middleware/rateLimit');
const cfg = require('../config');

const router = express.Router();

// Çevrimiçi tahminlere karşı: 15 dk'da IP başına 20 deneme.
const gateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'gate:' + ipKeyGenerator(req.ip),
});

function gateConfigured() {
  return /^[0-9a-f]{64}$/i.test(process.env.GATE_PASSWORD_HASH || '');
}

function gatePasswordOk(pw) {
  const expected = process.env.GATE_PASSWORD_HASH || '';
  if (!/^[0-9a-f]{64}$/i.test(expected)) return false;
  if (typeof pw !== 'string' || !pw || pw.length > 128) return false;
  const hex = crypto.createHash('sha256').update(pw, 'utf8').digest('hex');
  const a = Buffer.from(hex, 'hex');
  const b = Buffer.from(expected.toLowerCase(), 'hex');
  if (a.length !== b.length) return false; // timingSafeEqual RangeError tuzağı
  return crypto.timingSafeEqual(a, b);
}

function signGateToken() {
  return jwt.sign({ gate: true }, cfg.jwtSecret, { algorithm: 'HS256', expiresIn: '12h' });
}

// POST /api/gate/verify { password } → { ok:true, gate_token } | 401 | 503
router.post(
  '/verify',
  gateLimiter,
  body('password').isString().isLength({ min: 1, max: 128 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (!gateConfigured()) return res.status(503).json({ error: 'gate_not_configured' });
    if (!gatePasswordOk(req.body.password)) return res.status(401).json({ error: 'invalid_gate_password' });
    res.json({ ok: true, gate_token: signGateToken() });
  })
);

// GET /api/gate/status — Authorization: Bearer <gate_token> → { open:true|false }
router.get('/status', (req, res) => {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.json({ open: false });
  try {
    const p = jwt.verify(m[1], cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });
    if (p && p.gate === true) return res.json({ open: true });
  } catch (e) { /* geçersiz / süresi dolmuş jeton */ }
  return res.json({ open: false });
});

module.exports = router;
