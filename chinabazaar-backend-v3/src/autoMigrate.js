// v551: açılış migrasyonu — schema.sql + migrations/*.sql uygular.
// Tüm SQL idempotent yazıldı; dosya bazında hata yakalanır, sunucu açılmaya devam eder.
const fs = require('fs');
const path = require('path');
const pool = require('./db');

async function autoMigrate() {
  try {
    const root = path.join(__dirname, '..');
    const schemaPath = path.join(root, 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      try { await pool.query(fs.readFileSync(schemaPath, 'utf8')); }
      catch (e) { console.error('[migrate] schema.sql atlandı:', e.message); }
    }
    const migDir = path.join(root, 'migrations');
    if (fs.existsSync(migDir)) {
      const files = fs.readdirSync(migDir).filter((f) => f.endsWith('.sql')).sort();
      for (const f of files) {
        try { await pool.query(fs.readFileSync(path.join(migDir, f), 'utf8')); }
        catch (e) { console.error(`[migrate] ${f} atlandı:`, e.message); }
      }
    }
    console.log('[migrate] otomatik tamam.');
  } catch (e) {
    console.error('[migrate] otomatik hata:', e.message);
  }
}

module.exports = autoMigrate;
