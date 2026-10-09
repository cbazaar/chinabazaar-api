// ChinaBazaar API — giriş noktası
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cfg = require('./config');

const app = express();

app.use(helmet());
app.use(cors({ origin: cfg.baseUrl, credentials: true }));
app.use(express.json({ limit: '256kb' }));

// Railway healthcheck
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// API rotaları
app.use('/api/products', require('./routes/products'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/addresses', require('./routes/addresses'));
app.use('/api/favorites', require('./routes/favorites'));
app.use('/api/orders', require('./routes/orders'));
app.use('/api/payments', require('./routes/payments'));

// 404
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

// Merkezi hata yakalayıcı (stack trace prod'da gizlenir)
app.use((err, _req, res, _next) => {
  console.error('[api] hata:', err.message);
  res.status(err.status || 500).json({
    error: 'internal_error',
    ...(cfg.isProd ? {} : { detail: err.message }),
  });
});

app.listen(cfg.port, () => {
  console.log(`[api] dinleniyor :${cfg.port} (${cfg.nodeEnv})`);
});
