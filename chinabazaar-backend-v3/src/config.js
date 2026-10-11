// ChinaBazaar API — merkezi yapılandırma. Tüm gizli değerler process.env'den gelir.
require('dotenv').config();

const cfg = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',

  databaseUrl: process.env.DATABASE_URL || '',

  jwtSecret: process.env.JWT_SECRET || '',
  baseUrl: (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, ''),

  // CORS izinli origin'ler: ALLOWED_ORIGINS (virgülle ayrılmış) + BASE_URL + üretim domainleri
  allowedOrigins: (() => {
    const fromEnv = (process.env.ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim().replace(/\/$/, ''))
      .filter(Boolean);
    const base = (process.env.BASE_URL || '').replace(/\/$/, '');
    const defaults = [
      base,
      'https://chinabazaar.com',
      'https://www.chinabazaar.com',
    ].filter(Boolean);
    return [...new Set([...defaults, ...fromEnv])];
  })(),
  shippingCents: parseInt(process.env.SHIPPING_CENTS || '0', 10),

  // İlk admin kurulum anahtarı: doluysa, kayıt sırasında body.admin_key
  // bu değerle eşleşen kullanıcı is_admin=TRUE olur. Kurulumdan sonra
  // Railway değişkenlerinden KALDIRILMASI önerilir.
  adminSetupKey: process.env.ADMIN_SETUP_KEY || '',

  // PayTR iframe API — kart ödemeleri (kart bilgisi bizde ASLA tutulmaz)
  paytr: {
    enabled: Boolean(
      process.env.PAYTR_MERCHANT_ID && process.env.PAYTR_MERCHANT_KEY && process.env.PAYTR_MERCHANT_SALT
    ),
    merchantId: (process.env.PAYTR_MERCHANT_ID || '').trim(),
    merchantKey: (process.env.PAYTR_MERCHANT_KEY || '').trim(),
    merchantSalt: (process.env.PAYTR_MERCHANT_SALT || '').trim(),
    testMode: process.env.PAYTR_TEST_MODE === '1',
  },

  // E-posta doğrulama kodları — SMTP veya Resend (yoksa kod akışı 503 verir)
  email: {
    from: (process.env.EMAIL_FROM || '').trim(),
    smtpHost: (process.env.SMTP_HOST || '').trim(),
    smtpPort: parseInt(process.env.SMTP_PORT || '587', 10),
    smtpUser: (process.env.SMTP_USER || '').trim(),
    smtpPass: process.env.SMTP_PASS || '',
    smtpSecure: process.env.SMTP_SECURE === '1',
    resendKey: (process.env.RESEND_API_KEY || '').trim(),
  },

  // Cloudflare Stream — ürün videoları (token YALNIZCA sunucuda tutulur)
  stream: {
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID || '',
    apiToken: process.env.CLOUDFLARE_STREAM_API_TOKEN || '',
  },

  // Aras Kargo kurumsal — cari/anlaşma kodu ENV'den gelir.
  // Canlı takip için ayrıca ARAS_CARGO_WSDL_URL + ARAS_CARGO_USERNAME +
  // ARAS_CARGO_PASSWORD gerekir (Aras IT'den alınır).
  arasCargo: {
    customerCode: (process.env.ARAS_CARGO_CUSTOMER_CODE || '').trim(),
    wsdlUrl: (process.env.ARAS_CARGO_WSDL_URL || '').trim(),
    username: (process.env.ARAS_CARGO_USERNAME || '').trim(),
    trackMethod: (process.env.ARAS_CARGO_TRACK_METHOD || 'getOrder').trim(),
  },
};

if (!cfg.databaseUrl) {
  throw new Error('Missing required env: DATABASE_URL');
}
if (!cfg.jwtSecret) {
  if (cfg.isProd) throw new Error('Missing required env: JWT_SECRET');
  console.warn('[warn] JWT_SECRET yok — geliştirme için geçici anahtar üretildi.');
  cfg.jwtSecret = require('crypto').randomBytes(32).toString('hex');
}

module.exports = cfg;
