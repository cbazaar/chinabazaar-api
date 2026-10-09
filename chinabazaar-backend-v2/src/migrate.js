// Şema migrasyonu: schema.sql'i DATABASE_URL'e uygular (idempotent)
const fs = require('fs');
const path = require('path');
const pool = require('./db');

async function main() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  console.log('[migrate] şema uygulanıyor...');
  await pool.query(sql);
  console.log('[migrate] tamam.');
  await pool.end();
}

main().catch((err) => {
  console.error('[migrate] hata:', err.message);
  process.exit(1);
});
