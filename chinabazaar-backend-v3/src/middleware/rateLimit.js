// Hız limitleri — brute-force ve kötüye kullanıma karşı katmanlı koruma.
// Railway proxy arkasında gerçek IP için index.js'te `trust proxy` açık olmalı.
const rateLimit = require('express-rate-limit');

function limiter({ windowMs, max, message }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message || 'too_many_requests' },
  });
}

// Tüm /api rotaları için genel limit
const apiLimiter = limiter({ windowMs: 15 * 60 * 1000, max: 300 });

// Kimlik doğrulama — sıkı limit (credential stuffing'e karşı)
const loginLimiter = limiter({ windowMs: 15 * 60 * 1000, max: 10 });
const registerLimiter = limiter({ windowMs: 60 * 60 * 1000, max: 20 });

// Herkese açık kargo takip sorgusu — numaralandırmaya (enumeration) karşı
const trackingLimiter = limiter({ windowMs: 60 * 60 * 1000, max: 60 });

module.exports = { apiLimiter, loginLimiter, registerLimiter, trackingLimiter };
