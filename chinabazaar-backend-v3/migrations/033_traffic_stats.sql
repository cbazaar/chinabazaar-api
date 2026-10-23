-- 033: CBOs31 — panel trafik istatistikleri (idempotent)
-- SAHTE SAYI YOK: olay tablolari bu surumden itibaren birikir (fabrika
-- CBOs26.4 deseni); gecmis yalnizca toplam sayaclarda (products.view_count,
-- factory_video_views.views) gorunur.

-- Ziyaret / online takibi: hafif kalp atisi (POST /api/stats/ping).
-- sid = istemcinin urettigi oturum kimligi (kisisel veri DEGIL).
-- first_seen = ziyaretcinin ilk gorulmesi (gunluk benzersiz ziyaretci),
-- last_seen  = son kalp atisi (online = son 5 dk).
CREATE TABLE IF NOT EXISTS site_visits (
  sid        TEXT PRIMARY KEY,
  app        TEXT NOT NULL DEFAULT 'shop',
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_site_visits_last_seen  ON site_visits (last_seen);
CREATE INDEX IF NOT EXISTS idx_site_visits_first_seen ON site_visits (first_seen);

-- Magaza urun izlenme OLAYLARI. products.view_count toplam sayactir ve gun
-- bilgisi tasimaz; gunluk seri bu tablodan uretilir. FK YOK (fabrika olay
-- tablolari deseni: urun silinse de olay satiri kalir, seri bozulmaz).
CREATE TABLE IF NOT EXISTS view_events (
  id         BIGSERIAL PRIMARY KEY,
  product_id UUID,
  app        TEXT NOT NULL DEFAULT 'shop',
  sid        TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_view_events_created ON view_events (created_at);
CREATE INDEX IF NOT EXISTS idx_view_events_product ON view_events (product_id);

-- Gunluk begeni / yorum serileri icin created_at indeksleri (kucuk, zararsiz).
CREATE INDEX IF NOT EXISTS idx_product_likes_created ON product_likes (created_at);
CREATE INDEX IF NOT EXISTS idx_comments_created      ON comments (created_at);
