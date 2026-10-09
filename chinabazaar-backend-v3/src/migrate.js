// Şema migrasyonu: schema.sql + migrations/*.sql dosyalarını DATABASE_URL'e uygular.
// Tüm SQL idempotent yazılır (IF NOT EXISTS), tekrar çalıştırma güvenlidir.
const fs = require('fs');
const path = require('path');
const pool = require('./db');

async function main() {
  const root = path.join(__dirname, '..');

  const schema = fs.readFileSync(path.join(root, 'schema.sql'), 'utf8');
  console.log('[migrate] schema.sql uygulanıyor...');
  await pool.query(schema);

  const migDir = path.join(root, 'migrations');
  if (fs.existsSync(migDir)) {
    const files = fs.readdirSync(migDir).filter((f) => f.endsWith('.sql')).sort();
    for (const f of files) {
      console.log(`[migrate] ${f} uygulanıyor...`);
      await pool.query(fs.readFileSync(path.join(migDir, f), 'utf8'));
    }
  }

  console.log('[migrate] tamam.');
  await pool.end();
}

main().catch((err) => {
  console.error('[migrate] hata:', err.message);
  process.exit(1);
});
