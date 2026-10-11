-- v18: redeploy trigger
ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname ON users(nickname) WHERE nickname IS NOT NULL;
