-- Beğeni ve paylaşım takibi
CREATE TABLE IF NOT EXISTS product_likes (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, product_id)
);
CREATE TABLE IF NOT EXISTS product_shares (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_likes_product ON product_likes(product_id);
CREATE INDEX IF NOT EXISTS idx_shares_product ON product_shares(product_id);
