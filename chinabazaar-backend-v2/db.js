// PostgreSQL bağlantı havuzu (Railway uyumlu: prod'da SSL açık)
const { Pool } = require('pg');
const cfg = require('./config');

const pool = new Pool({
  connectionString: cfg.databaseUrl,
  ssl: cfg.isProd ? { rejectUnauthorized: false } : false,
  max: 10,
});

pool.on('error', (err) => {
  console.error('[db] pool hatası:', err.message);
});

module.exports = pool;
