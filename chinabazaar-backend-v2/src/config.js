// ChinaBazaar API — merkezi yapılandırma. Tüm gizli değerler process.env'den gelir.
require('dotenv').config();

const cfg = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',

  databaseUrl: process.env.DATABASE_URL || '',

  jwtSecret: process.env.JWT_SECRET || '',
  baseUrl: (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, ''),
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
