// ChinaBazaar API — giriş noktası (güvenlik sertleştirmeli)
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cfg = require('./config');
const { apiLimiter } = require('./middleware/rateLimit');

const app = express();

// Railway / ters proxy arkasında gerçek istemci IP'si (rate-limit için şart)
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Güvenlik başlıkları: HSTS, CSP (API-only sıkı), X-Frame-Options DENY vb.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false, // salt API — gömülü kaynak yok
    frameguard: { action: 'deny' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// CORS — yalnızca izinli origin'ler (ALLOWED_ORIGINS + varsayılan domainler).
// Origin başlığı göndermeyen istemciler (mobil uygulama, curl) engellenmez.
const allowedOrigins = new Set(cfg.allowedOrigins);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.has(origin)) return cb(null, true);
      const err = new Error('cors_not_allowed');
      err.status = 403;
      return cb(err);
    },
    credentials: true,
    maxAge: 86400,
  })
);

app.use(express.json({ limit: '256kb' }));

// Railway healthcheck — minimal bilgi (sürüm/iç detay sızdırmaz)
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Genel API hız limiti
app.use('/api', apiLimiter);

// API rotaları
app.use('/api/products', require('./routes/products'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/addresses', require('./routes/addresses'));
app.use('/api/favorites', require('./routes/favorites'));
app.use('/api/orders', require('./routes/orders'));
app.use('/api/payments', require('./routes/payments'));
app.use('/api/tracking', require('./routes/tracking')); // herkese açık, sınırlı kargo sorgusu
app.use('/api/payment-methods', require('./routes/paymentMethods'));
app.use('/api/admin/stream', require('./routes/stream')); // Cloudflare Stream video yönetimi (admin)
app.use('/api/admin', require('./routes/admin')); // kullanıcı + yorum yönetimi (admin)

// 404
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

// Merkezi hata yakalayıcı:
// - Üretimde stack trace / iç detay sızdırmaz
// - Loglara PII düşmez (yalnız hata mesajı + kodu; req.body / token / kart verisi asla loglanmaz)
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  console.error('[api] hata:', status, err.code || '', err.message);
  if (status === 403 && err.message === 'cors_not_allowed') {
    return res.status(403).json({ error: 'forbidden_origin' });
  }
  res.status(status).json({
    error: status === 429 ? 'too_many_requests' : 'internal_error',
    ...(cfg.isProd ? {} : { detail: err.message }),
  });
});

app.listen(cfg.port, () => {
  console.log(`[api] dinleniyor :${cfg.port} (${cfg.nodeEnv})`);
});
