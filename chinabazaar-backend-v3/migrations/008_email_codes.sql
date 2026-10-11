-- 008: e-posta doğrulama kodları (idempotent — tekrar çalıştırılabilir)
CREATE TABLE IF NOT EXISTS email_codes (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT NOT NULL,
  purpose     TEXT NOT NULL,              -- register | login
  code_hash   TEXT NOT NULL,              -- bcrypt hash (kod asla düz metin tutulmaz)
  expires_at  TIMESTAMPTZ NOT NULL,
  attempts    INT NOT NULL DEFAULT 0,     -- doğrulama denemesi sayacı
  consumed_at TIMESTAMPTZ,                -- kullanıldıysa zaman damgası
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_codes(email, purpose, created_at DESC);

-- Kullanıcıların e-posta doğrulama durumu (mevcut kayıtlar doğrulanmış sayılır)
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users SET email_verified = TRUE WHERE email_verified = FALSE;
