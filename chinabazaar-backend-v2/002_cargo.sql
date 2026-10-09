-- 002: kargo takip alanları (idempotent — tekrar çalıştırılabilir)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_number TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS cargo_company TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipped_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_orders_tracking ON orders(tracking_number);
