-- Sovos e-Arşiv Fatura entegrasyonu için invoices tablosuna Sovos alanları
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS sovos_uuid TEXT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS sovos_invoice_no TEXT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_invoices_sovos_uuid ON invoices(sovos_uuid);

-- Siparişlere Sovos fatura takibi için alanlar (eğer yoksa)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS sovos_uuid TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS sovos_invoice_no TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_sent BOOLEAN NOT NULL DEFAULT false;
