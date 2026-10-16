-- 031: misafir yorumlar (kayıtsız) — user_id NULL olabilir (v551)
ALTER TABLE comments ALTER COLUMN user_id DROP NOT NULL;
