-- 027: Fatura kayıtları (Sovos gönderimi + PDF + e-posta durumu)
-- Not: sovos.js ayrıca CREATE TABLE IF NOT EXISTS ile tabloyu kendi oluşturur;
-- bu migration kayıt/dokümantasyon içindir.
CREATE TABLE IF NOT EXISTS invoices (
  id SERIAL PRIMARY KEY,
  order_id TEXT UNIQUE NOT NULL,
  user_id INTEGER,
  invoice_number TEXT,
  uuid TEXT,
  invoice_type TEXT DEFAULT 'bireysel',
  status TEXT DEFAULT 'draft',
  pdf BYTEA,
  emailed_at TIMESTAMPTZ,
  sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
