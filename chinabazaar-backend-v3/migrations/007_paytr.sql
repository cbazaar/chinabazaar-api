-- 007: PayTR geçişi (idempotent — tekrar çalıştırılabilir)
ALTER TABLE payments ALTER COLUMN provider SET DEFAULT 'paytr';
