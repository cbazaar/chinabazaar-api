-- Muhasebe: kasa/banka, cari hesaplar, gelir-gider, faturalar
CREATE TABLE IF NOT EXISTS bank_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  bank_name TEXT,
  iban TEXT,
  currency TEXT NOT NULL DEFAULT 'TRY',
  balance_cents BIGINT NOT NULL DEFAULT 0,
  is_cash BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS account_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind TEXT NOT NULL CHECK (kind IN ('income','expense')),
  category TEXT NOT NULL,
  amount_cents BIGINT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'TRY',
  bank_account_id UUID REFERENCES bank_accounts(id) ON DELETE SET NULL,
  description TEXT,
  ref_type TEXT,
  ref_id TEXT,
  tx_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_acctx_date ON account_transactions(tx_date, kind);

CREATE TABLE IF NOT EXISTS current_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL CHECK (type IN ('customer','supplier')),
  name TEXT NOT NULL,
  tax_no TEXT,
  phone TEXT,
  email TEXT,
  address TEXT,
  currency TEXT NOT NULL DEFAULT 'TRY',
  balance_cents BIGINT NOT NULL DEFAULT 0,
  due_date DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  invoice_no TEXT NOT NULL UNIQUE,
  order_id UUID,
  current_account_id UUID REFERENCES current_accounts(id) ON DELETE SET NULL,
  customer_name TEXT NOT NULL,
  tax_info TEXT,
  items JSONB NOT NULL DEFAULT '[]',
  subtotal_cents BIGINT NOT NULL DEFAULT 0,
  discount_cents BIGINT NOT NULL DEFAULT 0,
  vat_cents BIGINT NOT NULL DEFAULT 0,
  shipping_cents BIGINT NOT NULL DEFAULT 0,
  total_cents BIGINT NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'TRY',
  payment_method TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','issued','paid','cancelled')),
  einvoice_status TEXT,
  invoice_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_invoices_date ON invoices(invoice_date, status);
