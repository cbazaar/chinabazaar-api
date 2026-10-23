-- 034: CBOs36 — Fabrika video anahtarı uzayı birleştirme (indis -> kanonik DB id)
--
-- SORUN: Fabrika ön yüzü video anahtarlarını eskiden FACTORIES dizisindeki
-- DİZİ SIRASIYLA üretiyordu ("0-0", "1-0", ...). CBOsF30 ile kanonik biçime
-- (fabrikanın DB id'si: "3-0", "4-0", ...) geçildi. DB'de iki uzay karışık:
-- aynı videonun izlenme/beğeni/yorum kayıtları indis anahtarında da kanonik
-- anahtarda da bulunabiliyor; birleştirme olmazsa eski sayılar yetim kalır,
-- sayaçlar eksik görünür (canlı kanıt: "0-0" -> 290 izlenme, "3-0" -> 135).
--
-- EŞLEME: indis i -> GET /api/products/factory/list ile BİREBİR aynı sıradaki
-- fabrikanın id'si. Liste sorgusu (products.js, router.get('/factory/list')):
--   SELECT * FROM factories WHERE is_active IS NOT FALSE ORDER BY id ASC
-- Bu migration eşlemeyi AYNI sorgudan kurar (id ASC, aktif filtresi dahil).
-- Video sırası (anahtarın ikinci bileşeni) AYNEN korunur.
--
-- KAPSAM (şema ensureFactoryTables ile doğrulandı):
--   factory_video_views       (video PK, views)     -> sayılar kanoniğe TOPLANIR
--   factory_video_view_events (video)               -> olay satırları taşınır
--   factory_likes             (user_id, video_key)  -> UNIQUE korunur; çakışmada
--                                                      kanonik satır kalır,
--                                                      indis satırı silinir
--   factory_favorites         (user_id, video_key)  -> likes ile aynı kural
--   factory_comments          (video_key)           -> yorumlar taşınır, kayıp yok
-- 'feed-' önekli anahtarlar hangi (fabrika, video)ya ait oldukları DB'den
-- çözülemediği için TAŞINMAZ; yedek özet tablosuna sayıları yazılır.
-- İndis aralığı dışında kalan / tanınmayan anahtarlar da taşınmaz, sayılır.
--
-- GÜVENLİK / TEKRAR ÇALIŞTIRMA:
-- - Tüm iş tek DO bloğunda = tek transaction; hata olursa hiçbir şey yazılmaz.
-- - autoMigrate bu dosyayı HER açılışta yeniden koşar; migration_markers
--   işareti bunu tam no-op yapar (taşınmış kanonik anahtar, indis sanılıp
--   ikinci kez TAŞINMAZ — bu koruma olmadan birleştirme kendini tekrarlardı).
-- - Taşımadan ÖNCE factory_key_merge_034_backup tablosuna tablo+anahtar
--   bazında yedek özet (satır sayısı, izlenme toplamı) yazılır.
-- - Taşıma, ara ad alanı ('__mig034__' öneki) üzerinden 3 fazlı yapılır:
--   indis satırları önce ara ada alınır (çakışma imkânsız), sonra kanonik
--   hedefle birleştirilir/silinir, kalanlar kanonik adını alır. Böylece
--   "3-0" gibi hem indis hem kanonik anlamlı anahtarlarda zincirleme
--   yanlış taşıma olmaz.

CREATE TABLE IF NOT EXISTS migration_markers (
  name       TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS factory_key_merge_034_backup (
  id            SERIAL PRIMARY KEY,
  table_name    TEXT NOT NULL,
  old_key       TEXT NOT NULL,
  new_key       TEXT,
  rows_affected INT  NOT NULL DEFAULT 0,
  value_sum     BIGINT,
  note          TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $merge$
DECLARE
  v_active INT := 0;
  n        BIGINT;
BEGIN
  -- 1) Zaten uygulanmışsa tam no-op.
  IF EXISTS (SELECT 1 FROM migration_markers WHERE name = '034_factory_key_merge') THEN
    RAISE NOTICE '034 CBOs36: zaten uygulanmis — atlandi.';
    RETURN;
  END IF;

  -- 2) Taze kurulum: factories tablosu henüz yoksa birleştirilecek veri de
  --    yoktur (fabrika tabloları ensureFactoryTables ile çalışma anında
  --    kurulur; yeni kurulumda indis anahtarlı kayıt hiç oluşmaz).
  IF to_regclass('public.factories') IS NULL THEN
    RAISE NOTICE '034 CBOs36: factories tablosu yok (taze kurulum) — isaretlenip gecildi.';
    INSERT INTO migration_markers(name) VALUES ('034_factory_key_merge');
    RETURN;
  END IF;

  -- 3) Yarım kalmış ara durum koruması: ara ad alanında satır kalmışsa dur.
  --    (Bu migration tek transaction çalışır; bu satır savunma amaçlıdır.
  --    Kontroller tablo başına ayrı IF içinde: birleşik koşul, eksik tabloda
  --    PL/pgSQL planlama aşamasında patlardı.)
  IF to_regclass('public.factory_video_views') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM factory_video_views WHERE substr(video, 1, 10) = '__mig034__') THEN
      RAISE EXCEPTION '034 CBOs36: __mig034__ ara ad alaninda satir var — yarim kalmis durum, once elle bakilmali.';
    END IF;
  END IF;
  IF to_regclass('public.factory_likes') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM factory_likes WHERE substr(video_key, 1, 10) = '__mig034__') THEN
      RAISE EXCEPTION '034 CBOs36: __mig034__ ara ad alaninda satir var — yarim kalmis durum, once elle bakilmali.';
    END IF;
  END IF;
  IF to_regclass('public.factory_favorites') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM factory_favorites WHERE substr(video_key, 1, 10) = '__mig034__') THEN
      RAISE EXCEPTION '034 CBOs36: __mig034__ ara ad alaninda satir var — yarim kalmis durum, once elle bakilmali.';
    END IF;
  END IF;

  -- 4) Eşleme tablosu: liste sorgusuyla birebir aynı sıra.
  CREATE TEMP TABLE _fk_map ON COMMIT DROP AS
  SELECT (ROW_NUMBER() OVER (ORDER BY id ASC) - 1)::int AS idx,
         id::int AS factory_id
  FROM factories
  WHERE is_active IS NOT FALSE
  ORDER BY id ASC;

  SELECT COUNT(*) INTO v_active FROM _fk_map;
  RAISE NOTICE '034 CBOs36: aktif fabrika = %, esleme (indis->id): %',
    v_active,
    COALESCE((SELECT string_agg(idx || '->' || factory_id, ', ' ORDER BY idx) FROM _fk_map), '(yok)');

  -- Anahtar başı (CASE ile güvenli cast: biçim tutmayan anahtar NULL üretir,
  -- eşlemeye girmez). İndis uzayı = baş, aktif listedeki bir indise denk gelir
  -- VE o indisteki fabrika id'sinden farklıdır (id hiçbir zaman indise eşit
  -- olamaz; yine de koşul açık yazıldı).

  -- ================================================================
  -- A) factory_video_views — izlenme sayıları kanoniğe TOPLANIR
  -- ================================================================
  IF to_regclass('public.factory_video_views') IS NOT NULL THEN
    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_video_views', v.video,
           m.factory_id::text || '-' || split_part(v.video, '-', 2),
           1, v.views, 'indis anahtari: kanonik anahtara tasindi/toplandi'
    FROM factory_video_views v
    JOIN _fk_map m
      ON m.idx = (CASE WHEN v.video ~ '^\d+-\d+$' THEN split_part(v.video, '-', 1)::int END)
    WHERE m.factory_id <> split_part(v.video, '-', 1)::int;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_video_views', 'feed-*', NULL, COUNT(*)::int, COALESCE(SUM(views), 0),
           'feed- onekli anahtarlar: ait olduklari (fabrika, video) DBden cozulemiyor — dokunulmadi'
    FROM factory_video_views WHERE video LIKE 'feed-%'
    HAVING COUNT(*) > 0;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_video_views', '(aralik disi/tanimlanamayan)', NULL, COUNT(*)::int, COALESCE(SUM(views), 0),
           'indis araligi disinda ve aktif fabrika idsi de degil — dokunulmadi'
    FROM factory_video_views v
    WHERE v.video NOT LIKE 'feed-%'
      AND (CASE WHEN v.video ~ '^\d+-\d+$' THEN split_part(v.video, '-', 1)::int END) IS NOT NULL
      AND (CASE WHEN v.video ~ '^\d+-\d+$' THEN split_part(v.video, '-', 1)::int END) >= v_active
      AND (CASE WHEN v.video ~ '^\d+-\d+$' THEN split_part(v.video, '-', 1)::int END)
          NOT IN (SELECT factory_id FROM _fk_map)
    HAVING COUNT(*) > 0;

    -- Faz 1: indis satırlarını ara ad alanına taşı.
    UPDATE factory_video_views v
    SET video = '__mig034__' || m.factory_id::text || '-' || split_part(v.video, '-', 2)
    FROM _fk_map m
    WHERE m.idx = (CASE WHEN v.video ~ '^\d+-\d+$' THEN split_part(v.video, '-', 1)::int END)
      AND m.factory_id <> split_part(v.video, '-', 1)::int;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_video_views faz1 (ara ada tasinan) = %', n;

    -- Faz 2: kanonik hedefi zaten var olanları hedefe TOPLA.
    UPDATE factory_video_views c
    SET views = c.views + p.views
    FROM factory_video_views p
    WHERE substr(p.video, 1, 10) = '__mig034__'
      AND c.video = substr(p.video, 11);
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_video_views faz2 (kanonige toplanan) = %', n;

    -- Faz 2b: toplamı aktarılan ara satırları sil.
    DELETE FROM factory_video_views p
    WHERE substr(p.video, 1, 10) = '__mig034__'
      AND EXISTS (SELECT 1 FROM factory_video_views c WHERE c.video = substr(p.video, 11));

    -- Faz 3: kalan ara satırlar kanonik adını alır.
    UPDATE factory_video_views
    SET video = substr(video, 11)
    WHERE substr(video, 1, 10) = '__mig034__';
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_video_views faz3 (kanonik ad alan) = %', n;
  END IF;

  -- ================================================================
  -- B) factory_video_view_events — izlenme olayları taşınır
  -- ================================================================
  IF to_regclass('public.factory_video_view_events') IS NOT NULL THEN
    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_video_view_events',
           split_part(e.video, '-', 1) || '-' || split_part(e.video, '-', 2),
           m.factory_id::text || '-' || split_part(e.video, '-', 2),
           COUNT(*)::int, NULL, 'indis anahtarli olay satirlari kanonige tasindi'
    FROM factory_video_view_events e
    JOIN _fk_map m
      ON m.idx = (CASE WHEN e.video ~ '^\d+-\d+$' THEN split_part(e.video, '-', 1)::int END)
    WHERE m.factory_id <> split_part(e.video, '-', 1)::int
    GROUP BY e.video, m.factory_id;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_video_view_events', 'feed-*', NULL, COUNT(*)::int, NULL,
           'feed- onekli anahtarlar: dokunulmadi'
    FROM factory_video_view_events WHERE video LIKE 'feed-%'
    HAVING COUNT(*) > 0;

    UPDATE factory_video_view_events e
    SET video = m.factory_id::text || '-' || split_part(e.video, '-', 2)
    FROM _fk_map m
    WHERE m.idx = (CASE WHEN e.video ~ '^\d+-\d+$' THEN split_part(e.video, '-', 1)::int END)
      AND m.factory_id <> split_part(e.video, '-', 1)::int;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_video_view_events tasinan = %', n;
  END IF;

  -- ================================================================
  -- C) factory_likes — UNIQUE(user_id, video_key) korunarak taşınır
  -- ================================================================
  IF to_regclass('public.factory_likes') IS NOT NULL THEN
    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_likes',
           split_part(l.video_key, '-', 1) || '-' || split_part(l.video_key, '-', 2),
           m.factory_id::text || '-' || split_part(l.video_key, '-', 2),
           COUNT(*)::int, NULL, 'indis anahtarli begeni satirlari (cakisanlar kanonik lehine silinir)'
    FROM factory_likes l
    JOIN _fk_map m
      ON m.idx = (CASE WHEN l.video_key ~ '^\d+-\d+$' THEN split_part(l.video_key, '-', 1)::int END)
    WHERE m.factory_id <> split_part(l.video_key, '-', 1)::int
    GROUP BY l.video_key, m.factory_id;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_likes', 'feed-*', NULL, COUNT(*)::int, NULL,
           'feed- onekli anahtarlar: dokunulmadi'
    FROM factory_likes WHERE video_key LIKE 'feed-%'
    HAVING COUNT(*) > 0;

    -- Faz 1: ara ad alanına taşı.
    UPDATE factory_likes l
    SET video_key = '__mig034__' || m.factory_id::text || '-' || split_part(l.video_key, '-', 2)
    FROM _fk_map m
    WHERE m.idx = (CASE WHEN l.video_key ~ '^\d+-\d+$' THEN split_part(l.video_key, '-', 1)::int END)
      AND m.factory_id <> split_part(l.video_key, '-', 1)::int;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_likes faz1 = %', n;

    -- Faz 2: hedefte kanonik (hareketsiz) satırı olan ara satırları SİL —
    -- kanonik satır kalır, çift sayım olmaz.
    DELETE FROM factory_likes p
    WHERE substr(p.video_key, 1, 10) = '__mig034__'
      AND EXISTS (
        SELECT 1 FROM factory_likes c
        WHERE c.user_id = p.user_id
          AND c.video_key = substr(p.video_key, 11)
          AND substr(c.video_key, 1, 10) <> '__mig034__'
      );
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_likes faz2 (kanonik lehine silinen) = %', n;

    -- Faz 3: kalan ara satırlar kanonik adını alır.
    UPDATE factory_likes
    SET video_key = substr(video_key, 11)
    WHERE substr(video_key, 1, 10) = '__mig034__';
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_likes faz3 = %', n;
  END IF;

  -- ================================================================
  -- D) factory_favorites — likes ile aynı kural
  -- ================================================================
  IF to_regclass('public.factory_favorites') IS NOT NULL THEN
    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_favorites',
           split_part(f.video_key, '-', 1) || '-' || split_part(f.video_key, '-', 2),
           m.factory_id::text || '-' || split_part(f.video_key, '-', 2),
           COUNT(*)::int, NULL, 'indis anahtarli favori satirlari (cakisanlar kanonik lehine silinir)'
    FROM factory_favorites f
    JOIN _fk_map m
      ON m.idx = (CASE WHEN f.video_key ~ '^\d+-\d+$' THEN split_part(f.video_key, '-', 1)::int END)
    WHERE m.factory_id <> split_part(f.video_key, '-', 1)::int
    GROUP BY f.video_key, m.factory_id;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_favorites', 'feed-*', NULL, COUNT(*)::int, NULL,
           'feed- onekli anahtarlar: dokunulmadi'
    FROM factory_favorites WHERE video_key LIKE 'feed-%'
    HAVING COUNT(*) > 0;

    UPDATE factory_favorites f
    SET video_key = '__mig034__' || m.factory_id::text || '-' || split_part(f.video_key, '-', 2)
    FROM _fk_map m
    WHERE m.idx = (CASE WHEN f.video_key ~ '^\d+-\d+$' THEN split_part(f.video_key, '-', 1)::int END)
      AND m.factory_id <> split_part(f.video_key, '-', 1)::int;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_favorites faz1 = %', n;

    DELETE FROM factory_favorites p
    WHERE substr(p.video_key, 1, 10) = '__mig034__'
      AND EXISTS (
        SELECT 1 FROM factory_favorites c
        WHERE c.user_id = p.user_id
          AND c.video_key = substr(p.video_key, 11)
          AND substr(c.video_key, 1, 10) <> '__mig034__'
      );
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_favorites faz2 (kanonik lehine silinen) = %', n;

    UPDATE factory_favorites
    SET video_key = substr(video_key, 11)
    WHERE substr(video_key, 1, 10) = '__mig034__';
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_favorites faz3 = %', n;
  END IF;

  -- ================================================================
  -- E) factory_comments — yorumlar taşınır (UNIQUE yok, kayıp olmaz)
  -- ================================================================
  IF to_regclass('public.factory_comments') IS NOT NULL THEN
    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_comments',
           split_part(c.video_key, '-', 1) || '-' || split_part(c.video_key, '-', 2),
           m.factory_id::text || '-' || split_part(c.video_key, '-', 2),
           COUNT(*)::int, NULL, 'indis anahtarli yorumlar kanonige tasindi'
    FROM factory_comments c
    JOIN _fk_map m
      ON m.idx = (CASE WHEN c.video_key ~ '^\d+-\d+$' THEN split_part(c.video_key, '-', 1)::int END)
    WHERE m.factory_id <> split_part(c.video_key, '-', 1)::int
    GROUP BY c.video_key, m.factory_id;

    INSERT INTO factory_key_merge_034_backup (table_name, old_key, new_key, rows_affected, value_sum, note)
    SELECT 'factory_comments', 'feed-*', NULL, COUNT(*)::int, NULL,
           'feed- onekli anahtarlar: dokunulmadi'
    FROM factory_comments WHERE video_key LIKE 'feed-%'
    HAVING COUNT(*) > 0;

    UPDATE factory_comments c
    SET video_key = m.factory_id::text || '-' || split_part(c.video_key, '-', 2)
    FROM _fk_map m
    WHERE m.idx = (CASE WHEN c.video_key ~ '^\d+-\d+$' THEN split_part(c.video_key, '-', 1)::int END)
      AND m.factory_id <> split_part(c.video_key, '-', 1)::int;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '034 CBOs36: factory_comments tasinan = %', n;
  END IF;

  -- 5) İşareti yaz: sonraki açılışlarda bu dosya tam no-op çalışır.
  INSERT INTO migration_markers(name) VALUES ('034_factory_key_merge');
  RAISE NOTICE '034 CBOs36: birlestirme tamamlandi, isaret yazildi.';
END
$merge$;
