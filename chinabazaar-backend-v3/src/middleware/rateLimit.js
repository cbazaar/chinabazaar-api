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
// 2026-10-17 düzeltme: 300 → 1200. Sebep: Admin paneli tek sekmede bile
// 15 dakikada ~270 istek yapıyor (sohbet 5sn + WhatsApp 15sn + oturum 30sn
// yoklaması). Fabrika sitesi de CBAI için 5sn'de bir yokluyor. 300, normal
// kullanımda bile dolup her şeyi (fabrika listesi, giriş) kilitliyordu.
// Brute-force koruması ayrı limitlerde aynen duruyor (giriş 100, kayıt 20).
const apiLimiter = limiter({ windowMs: 15 * 60 * 1000, max: 1200 });


// Kimlik doğrulama — sıkı limit (credential stuffing'e karşı)
const loginLimiter = limiter({ windowMs: 15 * 60 * 1000, max: 100 });
const registerLimiter = limiter({ windowMs: 60 * 60 * 1000, max: 20 });


// Herkese açık kargo takip sorgusu — numaralandırmaya (enumeration) karşı
const trackingLimiter = limiter({ windowMs: 60 * 60 * 1000, max: 60 });


module.exports = { apiLimiter, loginLimiter, registerLimiter, trackingLimiter };
