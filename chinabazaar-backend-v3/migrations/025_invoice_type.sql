-- Fatura türü: bireysel (e-Arşiv) / kurumsal (e-Fatura)
-- Müşteri checkout'ta fatura türünü seçer; Sovos gönderiminde senaryo buna göre belirlenir.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_type TEXT NOT NULL DEFAULT 'bireysel' CHECK (invoice_type IN ('bireysel', 'kurumsal'));
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_tckn TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_vkn TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_company TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS invoice_tax_office TEXT;
CREATE INDEX IF NOT EXISTS idx_orders_invoice_type ON orders(invoice_type);
