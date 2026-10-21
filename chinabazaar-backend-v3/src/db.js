// PostgreSQL bağlantı havuzu (Railway uyumlu: prod'da SSL açık)
// fix10ap (CBOs26.98): havuz dayanıklılığı — bağlantı kurma zaman aşımı
// (5 sn) + boşta bağlantı zaman aşımı (30 sn) eklendi; üst sınır POOL_MAX
// env'i varsa ondan, yoksa 20. SSL ve hata dinleyicisi aynen korundu.
const { Pool } = require('pg');
const cfg = require('./config');

const pool = new Pool({
  connectionString: cfg.databaseUrl,
  ssl: cfg.isProd ? { rejectUnauthorized: false } : false,
  max: parseInt(process.env.POOL_MAX, 10) || 20,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('[db] pool hatası:', err.message);
});

module.exports = pool;
