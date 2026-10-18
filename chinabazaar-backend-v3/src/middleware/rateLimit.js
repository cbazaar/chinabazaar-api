// Hız limitleri — brute-force ve kötüye kullanıma karşı katmanlı koruma.

// Railway proxy arkasında gerçek IP için index.js'te `trust proxy` açık olmalı.

const rateLimit = require('express-rate-limit');


function limiter({ windowMs, max, message, skipSuccessfulRequests, keyGenerator }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message || 'too_many_requests' },
    ...(skipSuccessfulRequests ? { skipSuccessfulRequests: true } : {}),
    ...(keyGenerator ? { keyGenerator } : {}),
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

// Şifre girişi (POST /api/auth/login) için KATI limit — yalnızca BAŞARISIZ
// denemeler sayılır (skipSuccessfulRequests): IP başına 15 dakikada en fazla
// 10 başarısız giriş. Başarılı girişler sayılmaz, gerçek kullanıcı kilitlenmez.
const strictLoginLimiter = limiter({ windowMs: 15 * 60 * 1000, max: 10, skipSuccessfulRequests: true });

// Aynı tanıtan (e-posta / kullanıcı adı / telefon) için katı limit — dağıtık
// (çok IP'li) brute-force'a karşı. Anahtar yalnız gövdedeki tanıtan bilgisinden
// üretilir (IP içermez); başarısız denemeler sayılır. Bir tanıtanın kilidini
// kırmak için saldırganın hem IP hem tanıtan bütçesini aşması gerekir.
const loginIdentifierLimiter = limiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => 'login-id:' + String((req.body && (req.body.identifier ?? req.body.email)) || '').trim().toLowerCase(),
});


// Herkese açık kargo takip sorgusu — numaralandırmaya (enumeration) karşı
const trackingLimiter = limiter({ windowMs: 60 * 60 * 1000, max: 60 });


module.exports = { apiLimiter, loginLimiter, registerLimiter, trackingLimiter, strictLoginLimiter, loginIdentifierLimiter };
