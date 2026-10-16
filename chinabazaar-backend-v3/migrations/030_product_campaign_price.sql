ALTER TABLE products ADD COLUMN IF NOT EXISTS campaign_price_cents INTEGER DEFAULT NULL CHECK (campaign_price_cents >= 0);
