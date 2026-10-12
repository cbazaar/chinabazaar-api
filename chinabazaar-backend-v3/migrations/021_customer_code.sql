ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_code VARCHAR(16) UNIQUE;
UPDATE users SET customer_code = 'CBM' || LPAD(id::text, 6, '0') WHERE customer_code IS NULL;
