-- 003: sipariş statüleri 6 aşamalı kanonik enum'a geçirilir (idempotent)
-- Eski değerler eşlenir: paid → packing (ödeme tamamlanan sipariş paketlemeye girer)
UPDATE orders SET status = 'packing' WHERE status IN ('paid', 'preparing');
-- Bilinmeyen eski değerler güvenli varsayılana çekilir
UPDATE orders SET status = 'pending'
 WHERE status NOT IN ('pending','packing','ready','shipped','in_transit','arriving','delivered','cancelled','refunded');
-- Kısıt (zaten varsa hata vermez)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_orders_status') THEN
    ALTER TABLE orders ADD CONSTRAINT chk_orders_status
      CHECK (status IN ('pending','packing','ready','shipped','in_transit','arriving','delivered','cancelled','refunded'));
  END IF;
END $$;
