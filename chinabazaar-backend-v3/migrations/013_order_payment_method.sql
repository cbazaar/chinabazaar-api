-- 013: sipariş ödeme yöntemi (idempotent)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'card';
