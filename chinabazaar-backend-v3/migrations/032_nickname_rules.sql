-- 032: admin yonetiminde kullanici adi kurallari (izin ver / blokla) — v557
CREATE TABLE IF NOT EXISTS nickname_rules (
  nickname TEXT PRIMARY KEY,
  action TEXT NOT NULL CHECK (action IN ('allow', 'block')),
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_nickname_rules_action ON nickname_rules(action);
