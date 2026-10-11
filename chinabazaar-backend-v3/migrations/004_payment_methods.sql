-- 004: kayıtlı ödeme yöntemleri (idempotent)
-- PCI DSS gereği TAM kart numarası (PAN) ve CVV ASLA saklanmaz.
-- Yalnızca son 4 hane + marka + son kullanma tarihi tutulur.
-- Gerçek tahsilat PayTR üzerinden yapılır.
CREATE TABLE IF NOT EXISTS payment_methods (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label       VARCHAR(60) NOT NULL DEFAULT 'Kartım',
  brand       VARCHAR(20) NOT NULL DEFAULT 'other'
              CHECK (brand IN ('visa','mastercard','amex','troy','other')),
  last4       CHAR(4) NOT NULL CHECK (last4 ~ '^[0-9]{4}$'),
  exp_month   INT NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
  exp_year    INT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payment_methods_user ON payment_methods(user_id);
