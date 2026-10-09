-- ChinaBazaar API — PostgreSQL şeması
-- Çalıştırma: psql $DATABASE_URL -f schema.sql   (veya: npm run migrate)
-- Para birimi: TRY. Tutarlar kuruş cinsinden (INT) tutulur.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- Kategoriler (PulSee 6 kategori)
CREATE TABLE IF NOT EXISTS categories (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,              -- Türkçe ad
  name_en     TEXT,                       -- İngilizce ad
  sort_order  INT NOT NULL DEFAULT 0,
  is_active   BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO categories (slug, name, name_en, sort_order) VALUES
  ('electronics', 'Elektronik',        'Electronics',        1),
  ('fashion',     'Moda',              'Fashion',            2),
  ('home',        'Ev & Yaşam',        'Home & Living',      3),
  ('beauty',      'Güzellik & Bakım',  'Beauty & Care',      4),
  ('sports',      'Spor & Outdoor',    'Sports & Outdoor',   5),
  ('toys',        'Oyuncak & Hobi',    'Toys & Hobbies',     6)
ON CONFLICT (slug) DO NOTHING;

-- Ürünler (ön yüz sözleşmesi: name, tagline, description, price, sold_count, stock, category, video_url, thumb_url)
CREATE TABLE IF NOT EXISTS products (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sku         TEXT UNIQUE,
  name        TEXT NOT NULL,                                  -- örn: "AirBuds Lite"
  tagline     TEXT,                                           -- kısa tanıtım (video akış kartı)
  description TEXT,                                           -- detay açıklama
  price_cents INT NOT NULL CHECK (price_cents >= 0),           -- kuruş (TRY)
  currency    CHAR(3) NOT NULL DEFAULT 'TRY',
  sold_count  INT NOT NULL DEFAULT 0 CHECK (sold_count >= 0), -- "271 satıldı"
  stock       INT NOT NULL DEFAULT 0 CHECK (stock >= 0),       -- "stok 63"
  category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
  video_url   TEXT,                                           -- dikey video (Cloudflare Stream / mp4)
  thumb_url   TEXT,                                           -- kapak görseli
  is_active   BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_products_active ON products(is_active);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);

-- Kullanıcılar
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,              -- bcrypt
  name          TEXT NOT NULL,
  phone         TEXT,                       -- E.164 (+905...)
  is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Adresler (Türkiye: il / ilçe / mahalle)
CREATE TABLE IF NOT EXISTS addresses (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label         TEXT,                       -- "Ev", "İş"
  full_name     TEXT NOT NULL,              -- alıcı adı soyadı
  phone         TEXT NOT NULL,              -- teslimat telefonu
  city          TEXT NOT NULL,              -- il
  district      TEXT NOT NULL,              -- ilçe
  neighborhood  TEXT,                       -- mahalle
  address_line  TEXT NOT NULL,              -- sokak/cadde, bina, daire
  postal_code   TEXT,                       -- posta kodu
  is_default    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_addresses_user ON addresses(user_id);

-- Favori ürünler
CREATE TABLE IF NOT EXISTS favorites (
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, product_id)
);

-- Siparişler
CREATE TABLE IF NOT EXISTS orders (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES users(id),
  order_no         TEXT UNIQUE NOT NULL,                       -- CB-2026-000123
  status           TEXT NOT NULL DEFAULT 'pending',            -- pending|paid|preparing|shipped|delivered|cancelled|refunded
  subtotal_cents   INT NOT NULL CHECK (subtotal_cents >= 0),
  shipping_cents   INT NOT NULL DEFAULT 0 CHECK (shipping_cents >= 0),
  total_cents      INT NOT NULL CHECK (total_cents >= 0),
  currency         CHAR(3) NOT NULL DEFAULT 'TRY',
  address_id       UUID REFERENCES addresses(id) ON DELETE SET NULL,
  address_snapshot TEXT,                                      -- teslimat adresi anlık kopyası (JSON)
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_no ON orders(order_no);

-- Sipariş kalemleri
CREATE TABLE IF NOT EXISTS order_items (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id  UUID REFERENCES products(id) ON DELETE SET NULL,
  name        TEXT NOT NULL,               -- snapshot (ürün adı değişse bile siparişte sabit)
  qty         INT NOT NULL CHECK (qty > 0),
  price_cents INT NOT NULL                 -- snapshot
);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);

-- Ödemeler (iyzico; kart verisi ASLA tutulmaz — yalnız token/referans)
CREATE TABLE IF NOT EXISTS payments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id        UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  provider        TEXT NOT NULL DEFAULT 'iyzico',
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending|success|failed
  token           TEXT,                             -- iyzico checkout token
  payment_id      TEXT,                             -- iyzico paymentId
  conversation_id TEXT,                             -- order_no
  amount_cents    INT NOT NULL,
  currency        CHAR(3) NOT NULL DEFAULT 'TRY',
  raw_response    JSONB,                            -- iyzico yanıtı (denetim için)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_payments_token ON payments(token);
