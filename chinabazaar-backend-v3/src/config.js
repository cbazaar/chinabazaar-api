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

  iyzico: {
    enabled: Boolean(process.env.IYZICO_API_KEY && process.env.IYZICO_SECRET_KEY),
    apiKey: process.env.IYZICO_API_KEY || '',
    secretKey: process.env.IYZICO_SECRET_KEY || '',
    baseUrl: process.env.IYZICO_BASE_URL || 'https://sandbox-api.iyzipay.com',
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
