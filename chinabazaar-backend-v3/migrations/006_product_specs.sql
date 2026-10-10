-- 006: ürün özellik alanları (renk, boyut, ölçü, kutu ölçüleri, ağırlık)
ALTER TABLE products ADD COLUMN IF NOT EXISTS color TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS size TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS dimensions TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS box_dimensions TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS weight TEXT;
