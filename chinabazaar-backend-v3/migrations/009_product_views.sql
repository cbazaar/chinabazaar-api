-- 009: ürün izlenme sayacı (idempotent)
ALTER TABLE products ADD COLUMN IF NOT EXISTS view_count INT NOT NULL DEFAULT 0 CHECK (view_count >= 0);
