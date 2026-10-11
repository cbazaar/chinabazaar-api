-- 014: sipariş ödeme durumu + kalem barkod snapshot'ı (idempotent)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'unpaid'
  CONSTRAINT chk_payment_status CHECK (payment_status IN ('unpaid','paid'));
ALTER TABLE order_items ADD COLUMN IF NOT EXISTS barcode TEXT;
