-- 005: Cloudflare Stream ürün videoları (idempotent)
CREATE TABLE IF NOT EXISTS product_videos (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id    UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  stream_uid    TEXT NOT NULL UNIQUE,
  status        TEXT NOT NULL DEFAULT 'uploading',
  playback_url  TEXT,
  thumbnail_url TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_product_videos_product ON product_videos(product_id);
