// fix10c — FAZ 1 — My Factory (fabrika girisi) [API /factory/myfactory/*, sutunlar myfactory_*; eski fabrika giris sutunlarindaki veri gocle tasinir]: fabrika kendi hesabiyla giris yapar, kendi kaydini duzenler.
// JWT: { factory_id, role: 'factory' }, 7 gun. Sifre: auth.js ile AYNI bcryptjs hasher (cost 12).
// Yasak alanlar (name, cbf_code, is_verified, is_active) My Factory profilinde sessizce yoksayilir.
// fix10q: CBOs26.29 — Cin'den yukleme dayanikliligi. Video yuklemeleri TUS protokolü
//   (tus-js-client, 5MB parca) ile parca parca yapilir; baglanti kopsa kaldigi yerden
//   devam eder. /api/admin/stream-upload-url (admin.js)'den donen uploadURL dogrudan
//   TUS endpoint'idir (Cloudflare direct_upload); bu dosyada (products.js) islevsel
//   degisiklik YOK — videos alan dogrulamasi (cleanFactoryVideos) fix10o'daki
//   *.cloudflarestream.com / *.videodelivery.net jokerleriyle aynen gecerlidir.
// fix10s: CBOs26.37-A — fabrika kimlik bilgisi degistirme rotasi (myfactory credentials):
//   {username?, password?}; hedef cozum profile rotasiyla birebir (master -> factory_id
//   ZORUNLU / fabrika -> token'daki fabrika); myfactory_password_hash bcrypt(12); updated_at her
//   zaman guncellenir; yanit yalniz { username }, hash ASLA donulmez.
// fix10t: CBOs26.39 — kullanici adi uygunluk ucu: GET /factory/myfactory/username-available?u=<name>
//   (requireFactoryOrMasterAuth) -> { available:boolean }; format gecersizse 400. Benzersizlik
//   LOWER karsilastirmasiyla; fabrikanin KENDI mevcut kullanici adi "kullanilabilir" sayilir
//   (master icin ?factory_id= verilirse o fabrika haric tutulur).
// fix10u: CBOs26.55-A — fabrika MARKA TESCILI beyani + benzersizlik: factories'e brand_name /
//   trademark_no / trademark_office / trademark_declared_at sutunlari + normalize (trim + ic
//   bosluk tek) marka adinda kismi benzersiz dizin. PUT /factory/myfactory/brand
//   (requireFactoryOrMasterAuth; master factory_id ZORUNLU -> 400 master_factory_id_required);
//   marka baskasinda varsa 409 brand_taken; admin PUT /factory/admin/:id ayni kontrolle yazar.
//   Brand alanlari yalniz toFactoryAdmin (+owner) ile doner, PUBLIC serializer'da YOK.
// fix10v: CBOs26.56-A — beyan edilen MARKA ADI herkese acik fabrika verisinde de gorunur:
//   toFactoryPublic'e yalnizca brand_name eklendi (liste + GET /factory/:id detay kapsanir).
//   trademark_no / trademark_office / trademark_declared_at PUBLIC'e ASLA gitmez;
//   bu uc alan yalniz toFactoryAdmin (+owner) ile donmeye devam eder.
// fix10w: CBOs26.57-A — yonetici (is_admin) + CBAI master ABONELIK MUAFIYETI:
//   GET /factory/subscription/me, admin/master icin abonelik tablosuna bakmadan
//   ve SATIR YAZMADAN { has_active:true, plan:'admin' } doner (sahte odeme kaydi
//   YOKTUR; muafiyet yalniz yanit duzeyindedir). Admin tespiti: master iddiasi
//   (role 'master' + is_admin) veya req.user.is_admin iddiasi, ikisi de yoksa
//   users.is_admin DB kontrolu (requireAdmin + urun listesi ?all=true deseniyle
//   ayni; canli giris jetonu is_admin tasimayabilir). Normal kullanici akisi
//   AYNEN korunur. products.js'de abonelik kapisi olan tek yer bu uctur:
//   liste/detay iletisim gizleme kosulsuzdur (includeContact:false),
//   quotes/messages olusturma abonelik kontrolu yapmaz.
// fix10x: CBOs26.60-A — COKLU MARKA: bir fabrika birden fazla marka beyan edebilir.
//   Yeni gercek kaynak: factory_brands tablosu (id, factory_id FK CASCADE, brand_name,
//   brand_key = normalize + kucuk harf, trademark_no, trademark_office, declared_at);
//   brand_key uzerinde TAM UNIQUE dizin (bir marka adi dunyada tek fabrikada).
//   GOC: factories.brand_name dolu satirlar acilista factory_brands'a tek kayit olarak
//   tasinir (ON CONFLICT DO NOTHING — idempotent). factories.brand_* kolonlari KALIYOR
//   (geri uyum) ve ILK markayla senkron tutulur; asil kaynak factory_brands'tir.
//   UCLAR: GET/POST /factory/myfactory/brands, DELETE /factory/myfactory/brands/:brandId
//   (requireFactoryOrMasterAuth; master factory_id zorunlu). Kendi markasinin tekrari
//   409 brand_exists, baska fabrikanin markasi 409 brand_taken. Eski PUT
//   /factory/myfactory/brand GERI UYUMLU: govde tek marka = kume o tek markayla
//   degistirilir, bos = tumu temizlenir. Admin PUT /factory/admin/:id govdede brands[]
//   gelirse kume TAMAMEN onunla degisir (cakisma -> 409, hicbir sey yazilmaz); brands
//   yoksa fix10u tekil davranisi korunur ve kume ona gore senkronlanir.
//   SERILESTIRME: admin/owner'da brands: [{id, brand_name, trademark_no,
//   trademark_office, declared_at}] + eski alanlar ILK markadan; PUBLIC'te brand_name
//   = ilk marka adi + brands: [adlar] (no/ofis PUBLIC'e ASLA gitmez).
// fix10y: CBOs26.62-A — video URUN OZELLIKLERI (attributes): video ogesi
//   {title, description, url, kind, attributes?: [{name, value}]} — ad-deger
//   ciftleri (orn. Malzeme: Celik, Garanti: Bir Yil). cleanFactoryVideos artik
//   attributes'i KORUR; tum yazma yollari (owner PUT 1745, POST/upsert 2603,
//   admin PUT 2939) ayni fonksiyondan gectigi icin hepsi kapsanir. Kurallar
//   (cleanVideoAttributes): dizi degilse alan ATILIR (video yine gecerli —
//   400 YOK); en fazla 40 oge; name trim -> <=80, value trim -> <=500 (title/
//   description desenindeki gibi KESILIR); name veya value bos olan oge atilir;
//   fazladan alanlar alinmaz. Hic gecerli oge yoksa anahtar HIC eklenmez —
//   attributes'siz eski video bugunku bicimiyle kalir (geri uyum).
//   OKUMA: toFactoryPublic videos'u DB'den aynen gecirdigi icin attributes
//   public dahil her serializer'da aynen doner; GET /factory/feed'in elle
//   kurdugu video nesnesine de attributes (dizi ise) aynen eklendi.
// fix10z: CBOs26.64-A — gonderi turu FOTOGRAF (kind:'photo'): fabrikalar akista
//   video gibi fotograf da paylasir. cleanFactoryVideos 'photo'yu kabul eder;
//   url bir RESIM adresidir ve video ile AYNI denetimden gecer (https zorunlu +
//   isAllowedFactoryMediaUrl konak allowlist'i — kapak/sohbet dosyalarinin
//   geldigi kendi API konagimizdaki chat-file yolu dahil). Izin disi konak ->
//   oge atilir (invalid_videos, mevcut desen). title/description/attributes
//   (fix10y) photo'da AYNEN korunur; video-ozgu sure/oran alani photo'da
//   ARANMAZ. OKUMA: public serializer videos'u aynen gecirir (photo da doner);
//   GET /factory/feed'in video nesnesine kind da eklendi (photo ayirt edilsin).
//   Izlenme takibi (factory_video_views) DEGISMADI — photo ogeleri video
//   sayaclarina karismaz, photo icin ayri sayac YOKTUR.
// fix10aa: CBOs26.68-A — ZIYARETCI SAYILARI public yanitlarda: fabrika basina
//   page_views + site toplami site_visitors_total. Kaynak/tanim panel
//   istatistigiyle (GET /factory/myfactory/stats -> total_page_visitors)
//   BIREBIR AYNI: factory_page_views.visits (tablo yoksa 0, akis bozulmaz).
//   toFactoryPublic, satir page_views TASIRSA alani ekler — public liste
//   (GET /factory/list) ve detay (GET /factory/:id) uclari factoryPageViewsMap
//   ile doldurur; admin/owner satirlari tasimadigi icin o serializer'larin
//   ciktisi DEGISMEZ. GET /factory/list yaniti { factories: [...],
//   site_visitors_total } olur (on yuz v230+ Array.isArray ? data :
//   data.factories ile iki bicimi de kabul eder — dogrulandi). GET
//   /factory/feed meta'sina da site_visitors_total eklendi (tek aggregate
//   sorgu: factorySiteVisitorsTotal). Ekleme yalnizdir; mevcut alan yok olmaz.
// fix10ab: CBOs26.68-B — video/foto ogesinde product_description: paneldeki
//   "Urun Aciklamasi" alani (kisa description'dan AYRI, uzun urun aciklamasi).
//   cleanFactoryVideos artik product_description'i KORUR; tum yazma yollari
//   (owner PUT, admin POST/upsert+merge, admin PUT) ayni fonksiyondan gectigi
//   icin hepsi kapsanir. Kurallar: yalnizca dizgi ise alinir; trim -> <=2000
//   karakter (description desenindeki gibi KESILIR); bos ise anahtar HIC
//   eklenmez; dizgi degilse alan ATILIR (oge yine gecerli — 400 YOK).
//   Anahtar sirasi: title, description, product_description, url, kind,
//   attributes. OKUMA: serializer'lar videos'u aynen gecirir; GET
//   /factory/feed'in elle kurdugu video nesnesine de product_description
//   (dizgi ise) aynen eklendi.
// fix10ac: CBOs26.72-A — gercek "CEVRIMICI" sayisi (presence): frontend'deki
//   cevrimici gostergesi artik gercek veriden beslenir. Yeni tablo
//   factory_presence (session_id TEXT PRIMARY KEY, factory_id INT opsiyonel —
//   page_views deseninde FK YOK, last_seen TIMESTAMPTZ) ensureFactoryTables
//   icinde IF NOT EXISTS ile acilir. Yeni uc POST /factory/presence (herkese
//   acik, kimlik YOK — page-view deseni): govde {session_id (ZORUNLU,
//   /^[A-Za-z0-9._-]{8,64}$/), factory_id (opsiyonel, pozitif tamsayi)} ->
//   upsert last_seen=now(), yanit {ok:true}; gecersiz govde 400.
//   factoryPresenceLimiter (IP basina dakikada 60) kotuye kullanim freni.
//   TEMIZLIK zaman kosullu (dakikada en fazla bir kez): 1 saatten eski
//   satirlar silinir — her cagrida DELETE kosulmaz. GET /factory/list
//   yanitina site_online_now eklendi: son 120 saniyede last_seen'i olan
//   DISTINCT session sayisi (factoryOnlineNow, tek sorgu; tablo yoksa 0,
//   akis bozulmaz). fix10aa'nin site_visitors_total'i AYNEN kalir — ikisi
//   farkli seylerdir: total = tum zamanlarin sayfa goruntulenmesi toplami,
//   online_now = su an sitede olan ziyaretci sayisi.
// fix10af: CBOs26.80-A — fabrika panelinden SIRKET ADI guncelleme:
//   PUT /factory/myfactory/profile artik `name` alanini da kabul eder —
//   fabrika kendi sirket adini panelden degistirebilir. Kurallar: yalniz
//   string; trim sonrasi 2-120 krk arasindaysa factories.name guncellenir;
//   bos / 1 krk / 120'den uzun / string olmayan deger SESSIZCE atlanir
//   (diger alanlar islenir, tek basina gelirse nothing_to_update deseni).
//   cbf_code / is_verified / is_active bu yolda HALA yasaktir (sessizce
//   yoksayilir). Admin PUT davranisi AYNEN (orada name zaten kabul
//   ediliyordu). Tek degisiklik budur; baska hicbir alan/uc degismez.
// fix10ag: CBOs26.82-A — fabrika ALT ALAN ADI otomasyonu (Netlify API):
//   fabrika kullanici adi aldiginda <kullaniciadi>.chinabazaar.com adresi
//   Netlify cbfactory sitesine domain alias olarak OTOMATIK eklenir (DNS
//   jokeri Cloudflare'da; on yuz her alt adresi zaten karsiliyor). Env
//   kapisi: NETLIFY_API_TOKEN + NETLIFY_SITE_ID yoksa otomasyon SESSIZCE
//   devre disi (sahte basari yok; hicbir akis degismez). Yardimci:
//   ensureFactoryDomainAlias — etiket /^[a-z0-9][a-z0-9-]{1,40}$/ desenine
//   uymali ve rezerve listede (www/api/admin/...) OLMAMALI; Netlify'dan
//   mevcut domain_aliases alinir (custom_domain'e dokunulmaz), adres yoksa
//   PATCH ile listenin TAMAMI + yeni adres gonderilir. Fire-and-forget:
//   cagiran akis BLOKLANMAZ, hata yalniz console.error'a duser. Cagri
//   noktalari: admin fabrika olusturma (basvuru onayindan olusturma da
//   ayni POST /factory/admin ucudur — CBF merge + yeni kayit yollari),
//   admin PUT'ta kullanici adi DEGISTIYSE yeni adres. BACKFILL ucu:
//   POST /factory/admin/sync-domain-aliases (requireAdmin) — kullanici adi
//   olan TUM aktif fabrikalar icin ensure cagirir; env yoksa
//   { ok:false, reason:'netlify_not_configured' }. Node yerlesik fetch,
//   ~8 sn zaman asimi (AbortController); ek bagimlilik yok.
// fix10ae: CBOs26.79-A — fabrika SERTIFIKALARI (belgeler): fabrika nesnesine
//   certificates: [{title, url}] alani. factories.certificates JSONB sutunu
//   (ensureFactoryTables ADD COLUMN IF NOT EXISTS). YUKLEME: mevcut chat-upload
//   akisinda kind=cert destegi — PDF + resim (mevcut sihirli bayt denetimi,
//   <=10MB), SURESIz saklama (kind=cover davranisinin aynisi, expires_at NULL;
//   yalniz fabrika/master). OKUMA: toFactoryPublic certificates doner (yoksa
//   []); admin/myfactory serializer'lari zincirle kazanir. YAZMA: myfactory PUT
//   + admin PUT yollarinda TOPTAN yazilir (socials deseni) — en cok 20 oge;
//   title ZORUNLU (trim -> <=120 kesilir), url ZORUNLU ve
//   isAllowedFactoryMediaUrl denetiminden gecer; gecersiz oge ATILIR; dizi
//   olmayan deger sessizce yok sayilir. Baska hicbir davranis degismez.
// fix10ad: CBOs26.77-A — ALT ALAN ADI eslesmesi icin public ciktiya username:
//   toFactoryPublic artik username: r.myfactory_username || null doner
//   (liste + GET /factory/:id detay ayni serializer'i kullanir, ikisi de
//   kazanir; feed nesnesine EKLENMEDI). Login adi fabrikalarin paylastigi
//   acik bilgidir — iletisim alanlari (fix10e M7, includeContact:false)
//   public'e DONMEZ, o kural AYNEN. Tek degisiklik budur; baska hicbir
//   serializer/uc davranisi degismez.
// fix10e: H-B göç (transaction + doğrulama + DROP yoksa yapılmaz), H-E CBAI master
// fix10h: CBOs26.4 — /myfactory/stats: gunluk seri (daily) + ulke dagilimi (countries); /factory/video-view: olay kaydi (ulke basliktan).
// fix10i: CBOs26.5 — bildirimler: factory_messages/factory_quotes + seen_by_factory; GET/POST /myfactory/notifications[/read]; videos.description korunur.
// fix10j: CBOs26.7 — /myfactory/stats: total_page_visitors; POST /factory/page-view (sayfa ziyareti olay+sayaç, video-view deseniyle).
// fix10k: CBOs26.15 — fabrika takip (follow): factory_follows tablosu; POST /factory/:id/follow,
//   DELETE /factory/:id/unfollow, GET /factory/:id/follow-status, GET /factory/feed (takip edilenlerin videolari);
//   /factory/list + GET /factory/:id yanitlarina followers. GET /factory/:id (herkese acik tek fabrika) bu surumde eklendi
//   (tabanda yoktu; madde 6 + "detay/listede" testi geregi).
//   + KRİTİK DÜZELTME: stats handler'da fname tanımsızdı (fix10h'te gelen regresyon — stats 500 veriyordu); SELECT'e name eklendi + fname tanımlandı.
// fix10g: /myfactory/stats — toplamlar (total_videos, total_likes) + video başına like_count (factory_likes).
// (sub+jti, 1 gün, denetim kaydı), L1 dummy hash 12 + uzunluk erken dönüşü yok,
// L2 jenerik yanıtlar, L3 'cbai' rezerve, L4 şifre politikası, L7 SSRF engeli,
// L8 videos/cover_image/socials konak allowlist, L9 CBF backfill kilit+transaction,
// L18 JWT HS256 allowlist, M1 fabrika girişi tanıtan limiti, M2 ipKeyGenerator,
// M5 chat-upload (limit + sahiplik + süreli URL + mime/boyut çapraz kontrol),
// M6 fabrika e-posta/telefon benzersizliği, M7 /factory/list iletişim gizleme,
// SABAH-4: settings wa_app_secret + has_wa_app_secret (WhatsApp HMAC için).
// Ürün kataloğu — ön yüz (video akış) sözleşmesine uygun JSON döner:
// { id, name, tagline, description, price_cents, price_display, currency,
//   sold_count, stock, category: {id, slug, name}, video_url, thumb_url }
const express = require('express');
const { body, param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { requireAuth, optionalAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const pool = require('../db');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cfg = require('../config');
const { loginLimiter, loginIdentifierLimiter } = require('../middleware/rateLimit');

// Fabrika yoksa bile karsilastirma yapilir (zamanlama ile kullanici sayimini zorlastirmak icin).
const MYFACTORY_DUMMY_HASH = bcrypt.hashSync('__chinabazaar_no_such_myfactory__', 12); // fix10e L1: 10 -> 12

const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const dns = require('dns');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// SHOP SECURITY: paylasim limiti — /:id/share rotasi tarafindan kullanilir.
// TANIM KULLANIMDAN ONCE OLMALI: const TDZ — rota kaydi dosya yuklenirken
// calisir; tanim asagida olursa "Cannot access before initialization" ile
// uygulama acilista coker (Railway healthcheck FAILED).
const shopShareLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'shop-share:' + (req.user && req.user.id ? String(req.user.id) : ipKeyGenerator(req.ip)), // fix10e M2
});

// v582: Pazaryerleri kolonlari (orders.js ensure deseniyle ayni)
async function ensureMarketplaceColumns() {
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplaces TEXT DEFAULT 'chinabazaar'`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplace_image TEXT`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplace_images JSONB`);
}

// v597: Garanti sutunu — migration sirasi beklemeden backend kendisi olusturur (500 onler)
async function ensureWarrantyColumn() {
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS warranty_months INTEGER`);
}

// v584: Pazaryeri görsel listesi — en fazla 10, yalnızca http(s) URL
function cleanMpImages(v) {
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const u of v) {
    if (typeof u === 'string' && /^https?:\/\//i.test(u.trim()) && u.trim().length <= 2048) out.push(u.trim());
    if (out.length >= 10) break;
  }
  return out.length ? JSON.stringify(out) : null;
}

function formatPrice(cents, currency) {
  const cur = ['TRY', 'USD', 'RUB'].includes(currency) ? currency : 'TRY';
  try {
    return new Intl.NumberFormat('tr-TR', { style: 'currency', currency: cur }).format(cents / 100);
  } catch {
    return new Intl.NumberFormat('tr-TR', { style: 'currency', currency: 'TRY' }).format(cents / 100);
  }
}

function toProduct(row) {
  return {
    id: row.id,
    sku: row.sku,
    name: row.name,
    tagline: row.tagline,
    description: row.description,
    price_cents: row.price_cents,
    campaign_price_cents: row.campaign_price_cents ?? null,
    warranty_months: row.warranty_months ?? null,
    campaign_price: row.campaign_price_cents != null ? row.campaign_price_cents / 100 : null,
    campaign_price_display: row.campaign_price_cents != null ? formatPrice(row.campaign_price_cents, row.currency) : null,
    price_display: formatPrice(row.price_cents, row.currency),
    currency: row.currency,
    color: row.color,
    size: row.size,
    dimensions: row.dimensions,
    box_dimensions: row.box_dimensions,
    weight: row.weight,
    sold_count: row.sold_count,
    stock: row.stock,
    view_count: row.view_count || 0,
    like_count: row.like_count || 0,
    favorite_count: row.favorite_count || 0,
    comment_count: row.comment_count || 0,
    share_count: row.share_count || 0,
    barcode: row.barcode || null,
    storage: row.storage || null,
    length: row.length || null,
    connector: row.connector || null,
    power_type: row.power_type || null,
    brand: row.brand || null,
    is_upcoming: !!row.is_upcoming,
    category: row.category_id
      ? { id: row.category_id, slug: row.category_slug, name: row.category_name }
      : null,
    video_url: row.video_url,
    video_mp4_url: streamMp4(row.video_url),
    thumb_url: row.thumb_url || streamThumb(row.video_url),
    marketplaces: row.marketplaces || 'chinabazaar',
    marketplace_image: row.marketplace_image || null,
    marketplace_images: Array.isArray(row.marketplace_images) ? row.marketplace_images : [],
  };
}

// video_url'den MP4 adresi üret (iOS için)
function streamMp4(videoUrl){
  if(!videoUrl) return null;
  const m = String(videoUrl).match(/videodelivery\.net\/([a-f0-9]+)/i);
  return m ? `https://videodelivery.net/${m[1]}/downloads/default.mp4` : null;
}

// video_url bir Cloudflare Stream adresiyse otomatik küçük resim üret
function streamThumb(videoUrl){
  if(!videoUrl) return null;
  const m = String(videoUrl).match(/videodelivery\.net\/([a-f0-9]{32})/i)
         || String(videoUrl).match(/cloudflarestream\.com\/([a-f0-9]{32})/i);
  return m ? ('https://videodelivery.net/'+m[1]+'/thumbnails/thumbnail.jpg') : null;
}

const SELECT = `
  SELECT p.*, c.slug AS category_slug, c.name AS category_name,
    (SELECT COUNT(*) FROM product_likes l WHERE l.product_id = p.id)::int AS like_count,
    (SELECT COUNT(*) FROM favorites f WHERE f.product_id = p.id)::int AS favorite_count,
    (SELECT COUNT(*) FROM comments cm WHERE cm.product_id = p.id)::int AS comment_count,
    (SELECT COUNT(*) FROM product_shares s WHERE s.product_id = p.id)::int AS share_count
  FROM products p
  LEFT JOIN categories c ON c.id = p.category_id
`;

// GET /api/products?category=electronics&q=kulaklik&limit=20&offset=0&sort=popular
// Admin ?all=true ile pasif ürünleri de görür (token gerekli).
router.get(
  '/',
  optionalAuth,
  asyncHandler(async (req, res) => {
    const { category, q } = req.query;
    // SHOP SECURITY: limit/offset sayisal degilse veya negatifse varsayilana dus (NaN/negatif LIMIT Postgres 500'u verirdi).
    const limitRaw = parseInt(req.query.limit || '20', 10);
    const offsetRaw = parseInt(req.query.offset || '0', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 20;
    const offset = Number.isFinite(offsetRaw) ? Math.max(offsetRaw, 0) : 0;
    const sort = req.query.sort || 'popular'; // popular | newest | price_asc | price_desc

    let showAll = false;
    if (req.query.all === 'true') {
      if (!req.user) return res.status(401).json({ error: 'unauthorized' });
      const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
      showAll = !!me[0]?.is_admin;
      if (!showAll) return res.status(403).json({ error: 'forbidden' });
    }

    const upcomingOnly = req.query.upcoming === 'true';
    const where = [showAll ? 'TRUE' : (upcomingOnly ? 'p.is_upcoming = TRUE' : '(p.is_active = TRUE AND p.is_upcoming = FALSE)')];
    const params = [];
    if (category) {
      params.push(category);
      where.push(`c.slug = $${params.length}`);
    }
    if (q) {
      params.push(`%${q}%`);
      where.push(`(p.name ILIKE $${params.length} OR p.description ILIKE $${params.length})`);
    }

    const orderBy =
      sort === 'newest' ? 'p.created_at DESC'
      : sort === 'price_asc' ? 'p.price_cents ASC'
      : sort === 'price_desc' ? 'p.price_cents DESC'
      : 'p.sold_count DESC';

    params.push(limit, offset);
    const { rows } = await pool.query(
      `${SELECT} WHERE ${where.join(' AND ')} ORDER BY ${orderBy} LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json({ items: rows.map(toProduct), limit, offset });
  })
);

// POST /api/products/:id/like — beğeni aç/kapa (toggle)
router.post(
  '/:id/like',
  param('id').isUUID(),
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    const { rows: ex } = await pool.query('SELECT 1 FROM product_likes WHERE user_id=$1 AND product_id=$2', [req.user.id, req.params.id]);
    let liked;
    if (ex.length) {
      await pool.query('DELETE FROM product_likes WHERE user_id=$1 AND product_id=$2', [req.user.id, req.params.id]);
      liked = false;
    } else {
      await pool.query('INSERT INTO product_likes (user_id, product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.id]);
      liked = true;
    }
    const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM product_likes WHERE product_id=$1', [req.params.id]);
    res.json({ liked, like_count: c[0].n });
  })
);

// POST /api/products/:id/share — paylaşım sayacı
router.post(
  '/:id/share',
  param('id').isUUID(),
  optionalAuth,
  shopShareLimiter,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    await pool.query('INSERT INTO product_shares (product_id, user_id) VALUES ($1,$2)', [req.params.id, req.user ? req.user.id : null]);
    const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM product_shares WHERE product_id=$1', [req.params.id]);
    res.json({ share_count: c[0].n });
  })
);

// v613: WhatsApp Cloud API — webhook + admin mesajlasma paneli (yalniz admin gorur, magaza ana sayfasinda yok)
async function ensureWhatsappTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS whatsapp_conversations (id SERIAL PRIMARY KEY, wa_id TEXT UNIQUE NOT NULL, display_name TEXT DEFAULT '', unread_count INT DEFAULT 0, last_message_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS whatsapp_messages (id SERIAL PRIMARY KEY, conversation_id INT NOT NULL REFERENCES whatsapp_conversations(id) ON DELETE CASCADE, wa_message_id TEXT UNIQUE, direction TEXT NOT NULL, body TEXT DEFAULT '', msg_type TEXT DEFAULT 'text', status TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
}
async function waSettings() {
  const { rows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ('wa_phone_id', 'wa_token', 'wa_verify', 'wa_enabled', 'wa_username', 'wa_app_secret')`);
  const kv = {};
  rows.forEach((r) => { kv[r.key] = r.value; });
  return kv;
}
// WHATSAPP SECURITY: X-Hub-Signature-256 dogrulamasi (Meta App Secret ile HMAC-SHA256).
// - Secret bos/yoksa: eski davranis aynen (kabul) — geriye donuk uyumlu, kirilma yok.
// - Secret VARSA: imza eksik/gecersizse reddet (401). Yanlis imza asla kabul edilmez:
//   saldirgan secret'i bilmeden gecerli bir HMAC uretemez (yanlis govde karsilastirmasi
//   yalnizca hatali REDDE yol acabilir, hatali kabule degil — fail-closed).
// - Govde adaylari: req.rawBody (index.js express.json verify kancasi varsa, KESIN yol) ve
//   JSON.stringify(req.body) (yedek; Meta'nin compact JSON govdesiyle pratikte aynidir).
//   Tam ham-govde yakalama icin onerilen izleyen adim: index.js'te
//   express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }).
function verifyWhatsappSignature(req, secret) {
  try {
    if (!secret || !String(secret).trim()) return true; // secret yoksa: eski davranis
    const sig = String(req.headers['x-hub-signature-256'] || '');
    const m = /^sha256=([a-f0-9]{64})$/i.exec(sig);
    if (!m) return false;
    const expected = Buffer.from(m[1], 'hex');
    const candidates = [];
    if (Buffer.isBuffer(req.rawBody)) candidates.push(req.rawBody);
    try { candidates.push(Buffer.from(JSON.stringify(req.body ?? {}), 'utf8')); } catch { /* yoksay */ }
    for (const bodyBuf of candidates) {
      const hmac = crypto.createHmac('sha256', String(secret)).update(bodyBuf).digest();
      if (hmac.length === expected.length && crypto.timingSafeEqual(hmac, expected)) return true;
    }
    return false;
  } catch {
    return false; // suphede reddet (fail-closed), asla acik kapı birakma
  }
}
// GET /api/products/whatsapp/webhook — Meta dogrulama (herkese acik, jeton sart)
router.get('/whatsapp/webhook', asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const kv = await waSettings();
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && kv.wa_verify && typeof token === 'string' && timingSafeEqualStr(kv.wa_verify, token)) return res.status(200).send(challenge);
  return res.sendStatus(403);
}));
// POST /api/products/whatsapp/webhook — Meta gelen mesaj + durum bildirimi (herkese acik, her zaman 200)
// WHATSAPP SECURITY: wa_app_secret ayarlanmissa X-Hub-Signature-256 dogrulanir; imza
// gecersizse 401 (sahte webhook / sahte mesaj enjeksiyonu engellenir). Secret yoksa eski davranis.
router.post('/whatsapp/webhook', asyncHandler(async (req, res) => {
  try {
    const kvSig = await waSettings().catch(() => ({}));
    if (!verifyWhatsappSignature(req, kvSig.wa_app_secret)) return res.sendStatus(401);
    await ensureWhatsappTables();
    const entries = (req.body && req.body.entry) || [];
    for (const entry of entries) {
      for (const change of (entry.changes || [])) {
        const value = change.value || {};
        for (const st of (value.statuses || [])) {
          if (st.id) await pool.query(`UPDATE whatsapp_messages SET status=$1 WHERE wa_message_id=$2`, [String(st.status || ''), String(st.id)]);
        }
        const contacts = {};
        for (const c of (value.contacts || [])) contacts[c.wa_id] = (c.profile && c.profile.name) || '';
        for (const m of (value.messages || [])) {
          if (!m.from || !m.id) continue;
          const type = String(m.type || 'text');
          let body = '';
          if (type === 'text') body = (m.text && m.text.body) || '';
          else body = '[' + type + ']';
          body = body.slice(0, 4000);
          let conv = await pool.query(`SELECT id FROM whatsapp_conversations WHERE wa_id=$1`, [String(m.from)]);
          let convId;
          if (conv.rows.length) {
            convId = conv.rows[0].id;
            await pool.query(`UPDATE whatsapp_conversations SET display_name=COALESCE(NULLIF($1,''),display_name), updated_at=now() WHERE id=$2`, [contacts[m.from] || '', convId]);
          } else {
            const ins = await pool.query(`INSERT INTO whatsapp_conversations (wa_id, display_name, unread_count, last_message_at) VALUES ($1,$2,0,now()) RETURNING id`, [String(m.from), contacts[m.from] || '']);
            convId = ins.rows[0].id;
          }
          const ins = await pool.query(`INSERT INTO whatsapp_messages (conversation_id, wa_message_id, direction, body, msg_type, status) VALUES ($1,$2,'in',$3,$4,'received') ON CONFLICT DO NOTHING RETURNING id`, [convId, String(m.id), body, type]);
          if (ins.rows.length) await pool.query(`UPDATE whatsapp_conversations SET unread_count=unread_count+1, last_message_at=now(), updated_at=now() WHERE id=$1`, [convId]);
        }
      }
    }
  } catch (e) { console.error('[whatsapp webhook]', e.message); }
  res.sendStatus(200);
}));
// GET /api/products/whatsapp/conversations — admin konusma listesi
router.get('/whatsapp/conversations', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureWhatsappTables();
  const { rows } = await pool.query(`SELECT c.*, (SELECT body FROM whatsapp_messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_body FROM whatsapp_conversations c ORDER BY c.last_message_at DESC NULLS LAST LIMIT 100`);
  const total = await pool.query(`SELECT COALESCE(SUM(unread_count),0)::int AS unread FROM whatsapp_conversations`);
  res.json({ ok: true, items: rows, unread_total: total.rows[0].unread });
}));
// GET /api/products/whatsapp/conversations/:id/messages — admin mesajlari okur (okundu sayilir)
router.get('/whatsapp/conversations/:id/messages', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureWhatsappTables();
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ ok: false, error: 'bad_id' });
  const { rows } = await pool.query(`SELECT * FROM whatsapp_messages WHERE conversation_id=$1 ORDER BY id ASC LIMIT 500`, [id]);
  await pool.query(`UPDATE whatsapp_conversations SET unread_count=0 WHERE id=$1`, [id]);
  res.json({ ok: true, messages: rows });
}));
// POST /api/products/whatsapp/conversations/:id/send — admin cevap gonderir (Graph API)
router.post('/whatsapp/conversations/:id/send', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureWhatsappTables();
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ ok: false, error: 'bad_id' });
  const text = String((req.body && req.body.text) || '').trim().slice(0, 4000);
  if (!text) return res.json({ ok: false, error: 'empty' });
  const kv = await waSettings();
  if (!kv.wa_phone_id || !kv.wa_token) return res.json({ ok: false, error: 'not_configured', message: 'WhatsApp bilgileri eksik: Telefon Numarası ID ve Erişim Jetonu gerekli.' });
  const conv = await pool.query(`SELECT * FROM whatsapp_conversations WHERE id=$1`, [id]);
  if (!conv.rows.length) return res.status(404).json({ ok: false, error: 'not_found' });
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    let r;
    try {
      r = await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(kv.wa_phone_id)}/messages`, { method: 'POST', signal: ctrl.signal, headers: { Authorization: `Bearer ${kv.wa_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ messaging_product: 'whatsapp', to: conv.rows[0].wa_id, type: 'text', text: { body: text } }) });
    } finally { clearTimeout(t); }
    const j = await r.json().catch(() => ({}));
    if (r.status === 200 && j.messages && j.messages[0] && j.messages[0].id) {
      await pool.query(`INSERT INTO whatsapp_messages (conversation_id, wa_message_id, direction, body, msg_type, status) VALUES ($1,$2,'out',$3,'text','sent')`, [id, String(j.messages[0].id), text]);
      await pool.query(`UPDATE whatsapp_conversations SET last_message_at=now(), updated_at=now() WHERE id=$1`, [id]);
      return res.json({ ok: true });
    }
    const code = j.error && j.error.code;
    const msg = (j.error && j.error.message) || '';
    if (code === 131047) return res.json({ ok: false, error: 'window_closed', message: 'Müşteri son 24 saattir yazmadı — WhatsApp, cevap için önce müşterinin yazmasını ister. Müşterinin yazmasını bekleyin veya şablon mesajı kullanın.' });
    return res.json({ ok: false, error: 'send_failed', message: 'Gönderilemedi (HTTP ' + r.status + ')' + (msg ? ' — ' + msg : '') });
  } catch (e) { return res.json({ ok: false, error: 'send_failed', message: 'Bağlantı hatası: ' + (e && e.message ? e.message : 'bilinmeyen hata') }); }
}));
// GET /api/products/whatsapp/status — admin panel durum + webhook adresi
router.get('/whatsapp/status', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  await ensureWhatsappTables();
  const kv = await waSettings();
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS convs, COALESCE(SUM(unread_count),0)::int AS unread FROM whatsapp_conversations`);
  const origin = `${req.protocol}://${req.get('host')}`;
  res.json({ ok: true, configured: !!(kv.wa_phone_id && kv.wa_token), enabled: kv.wa_enabled === 'true', verify_set: !!kv.wa_verify, app_secret_set: !!kv.wa_app_secret, username: kv.wa_username || '', webhook_url: origin + '/api/products/whatsapp/webhook', conversations: rows[0].convs, unread: rows[0].unread });
}));

// CBF: fabrika kodu — CBF-001, CBF-002, … (buyuk harf CBF-, sifir dolgulu 3 hane).
// Ayni normalize ad (trim + lowercase) = ayni fabrika = AYNI cbf_code (tekrar kod verilmez).
function normalizeCbfCode(v) {
  if (typeof v !== 'string') return '';
  return v.trim().toUpperCase();
}
// CBF kilidi: gecerli kod /^CBF-\d+$/ bicimindedir. Gecerli kod SABIT'tir — bir kez
// verildikten sonra degistirilemez. Bozuk bicimli (örn. "CBFOO1") mevcut kod bir kez
// gecerli bicime duzeltilebilir; duzeltildikten sonra o da kilitlenir.
function isValidCbfCode(v) {
  return /^CBF-\d+$/.test(normalizeCbfCode(v));
}
function normalizeFactoryNameKey(v) {
  return String(v == null ? '' : v).trim().toLowerCase();
}
function formatCbfCode(n) {
  return 'CBF-' + String(n).padStart(3, '0');
}
function parseCbfCodeNumber(code) {
  const m = /^CBF-(\d+)$/.exec(String(code || '').trim().toUpperCase());
  return m ? parseInt(m[1], 10) : 0;
}
// Mevcut en buyuk CBF numarasinin bir fazlasi (kod yoksa 1).
async function nextCbfCodeNumber() {
  const { rows } = await pool.query(`SELECT cbf_code FROM factories WHERE cbf_code IS NOT NULL AND TRIM(cbf_code) <> ''`);
  let max = 0;
  for (const r of rows) max = Math.max(max, parseCbfCodeNumber(r.cbf_code));
  return max + 1;
}
// Yeni fabrika icin kod cozumu: ayni isimde kod varsa onu tekrar kullan, yoksa siradaki kodu ver.
async function resolveCbfCodeForName(name) {
  const key = normalizeFactoryNameKey(name);
  if (key) {
    const { rows } = await pool.query(`SELECT cbf_code FROM factories WHERE LOWER(TRIM(name)) = $1 AND cbf_code IS NOT NULL AND TRIM(cbf_code) <> '' ORDER BY id ASC LIMIT 1`, [key]);
    if (rows.length) return normalizeCbfCode(rows[0].cbf_code);
  }
  return formatCbfCode(await nextCbfCodeNumber());
}
// Backfill (idempotent): cbf_code'u bos olan fabrikalara kod ata. Ayni normalize ada sahip
// satirlar AYNI kodu alir; kodlar fabrika-id sirasina gore, mevcut max + 1'den baslayarak
// verilir. Dolu kodlar ASLA uzerine yazilmaz; baska hicbir sutuna dokunulmaz.
// fix10e L9: CBF backfill yarışı — eşzamanlı iki backfill aynı kodu iki
// fabrikaya yazmasın diye: oturum danışma kilidi (pg_advisory_xact_lock) +
// tek transaction içinde hesapla+yaz + benzersizlik çakışmasında en fazla
// 3 kez tekrar deneme. Kod ataması atomiktir; yarım backfill olmaz.
async function backfillFactoryCbfCodes() {
  for (let attempt = 0; attempt < 3; attempt++) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Danışma kilidi: aynı anda yalnızca bir backfill çalışır.
      await client.query(`SELECT pg_advisory_xact_lock(hashtext('cbf-backfill'))`);
      const { rows: pending } = await client.query(`SELECT COUNT(*)::int AS n FROM factories WHERE cbf_code IS NULL OR TRIM(cbf_code) = ''`);
      if (!pending.length || !pending[0].n) { await client.query('COMMIT'); return; }
      const { rows } = await client.query(`SELECT id, name, cbf_code FROM factories ORDER BY id ASC`);
      let max = 0;
      for (const r of rows) max = Math.max(max, parseCbfCodeNumber(r.cbf_code));
      const groups = new Map();
      const nameless = [];
      for (const r of rows) {
        const key = normalizeFactoryNameKey(r.name);
        const existing = (typeof r.cbf_code === 'string' ? r.cbf_code.trim() : '');
        if (!key) {
          if (!existing) nameless.push(r.id);
          continue;
        }
        if (!groups.has(key)) groups.set(key, { code: '', fill: [] });
        const g = groups.get(key);
        if (existing) { if (!g.code) g.code = normalizeCbfCode(existing); }
        else g.fill.push(r.id);
      }
      for (const id of nameless) { max += 1; await client.query('UPDATE factories SET cbf_code = $1 WHERE id = $2', [formatCbfCode(max), id]); }
      for (const g of groups.values()) {
        if (!g.fill.length) continue;
        if (!g.code) { max += 1; g.code = formatCbfCode(max); }
        for (const id of g.fill) await client.query('UPDATE factories SET cbf_code = $1 WHERE id = $2 AND (cbf_code IS NULL OR TRIM(cbf_code) = \'\')', [g.code, id]);
      }
      await client.query('COMMIT');
      return;
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) { /* yoksay */ }
      if (e && e.code === '23505' && attempt < 2) continue; // çakışma: tekrar dene (taze max ile)
      return; // diğer hatalar: backfill hatası akışı bozmaz
    } finally { client.release(); }
  }
}

// v615 (My Factory v3): fabrika video begeni/yorum + fabrika yonetimi (admin)
// Tum /factory/* rotalari GET /:id ONCESINE kayitli — /:id bunlari yutmaz.
async function ensureFactoryTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_likes (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, video_key TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(user_id, video_key))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_comments (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, video_key TEXT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_favorites (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, video_key TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(user_id, video_key))`);
  // v115: şema onarımı — tablo eski bir sürümle oluşmuşsa (eksik sütun / eksik UNIQUE) eksikleri tamamla.
  // CREATE TABLE IF NOT EXISTS eski tabloya dokunmaz; bu ALTER'lar olmadan eski tabloda her sorgu 500 verirdi.
  await pool.query(`ALTER TABLE factory_likes ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_likes ADD COLUMN IF NOT EXISTS video_key TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_comments ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_comments ADD COLUMN IF NOT EXISTS video_key TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_comments ADD COLUMN IF NOT EXISTS body TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_favorites ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_favorites ADD COLUMN IF NOT EXISTS video_key TEXT NOT NULL DEFAULT ''`);
  // Tekrarlı (user_id, video_key) satırları UNIQUE index'i kurmayı engeller — önce tekilleştir.
  await pool.query(`DELETE FROM factory_likes a USING factory_likes b WHERE a.id < b.id AND a.user_id = b.user_id AND a.video_key = b.video_key`);
  await pool.query(`DELETE FROM factory_favorites a USING factory_favorites b WHERE a.id < b.id AND a.user_id = b.user_id AND a.video_key = b.video_key`);
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factory_likes_user_video_uidx ON factory_likes (user_id, video_key)`); } catch (e) { /* eski şemada index kurulamazsa akış bozulmaz */ }
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factory_favorites_user_video_uidx ON factory_favorites (user_id, video_key)`); } catch (e) { /* eski şemada index kurulamazsa akış bozulmaz */ }
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_video_views (video TEXT PRIMARY KEY, views INT NOT NULL DEFAULT 0)`);
  // CBOs26.4 (fix10h): izlenme OLAYLARI — gunluk grafik + ulke dagilimi icin. Toplam sayac (factory_video_views)
  // gecmise donuk gun/ulke bilgisi tasimaz; olaylar bu surumden itibaren birikir. Eski izlenmeler yalnizca toplamda kalir.
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_video_view_events (id SERIAL PRIMARY KEY, video TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_video_view_events_video_idx ON factory_video_view_events (video)`);
  // CBOs26.7 (fix10j): SAYFA ZİYARETİ — fabrika sayfasının toplam ziyaretçisi (yalnızca kendi fabrikası). Video-view deseniyle:
  // olay satırı + sayaç; olaylar bu sürümden itibaren birikir, öncesi 0 görünür. FK yok (taze DB'de factories sırası sorunu çıkmasın).
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_page_views (factory_id INT PRIMARY KEY, visits INT NOT NULL DEFAULT 0)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_page_view_events (id SERIAL PRIMARY KEY, factory_id INT NOT NULL DEFAULT 0, country TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_page_view_events_factory_idx ON factory_page_view_events (factory_id)`);
  // CBOs26.72 (fix10ac): CEVRIMICI presence — ziyaretci kalp atisi (POST /factory/presence upsert eder,
  // GET /factory/list son 120 sn'de gorulen DISTINCT session sayisini doner). FK yok (page_views deseni:
  // factory_id yalnizca bilgi amacli; fabrika silinse de satir last_seen yaslaninca temizlikte gider).
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_presence (session_id TEXT PRIMARY KEY, factory_id INT, last_seen TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_presence_last_seen_idx ON factory_presence (last_seen)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_ratings (id SERIAL PRIMARY KEY, factory_id INT NOT NULL REFERENCES factories(id) ON DELETE CASCADE, user_id TEXT NOT NULL, rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5), created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(), UNIQUE(factory_id, user_id))`);
  // fix10k (CBOs26.15): fabrika takip — giris yapmis kullanici fabrikayi takip eder. user_id TEXT (likes/favorites deseni);
  // factory silinince takipler CASCADE ile gider (ratings deseni). UNIQUE(user_id, factory_id) = idempotent follow.
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_follows (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, factory_id INT NOT NULL REFERENCES factories(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT now(), UNIQUE(user_id, factory_id))`);
  // Tekrarli (user_id, factory_id) satirlari UNIQUE index'i kurmayi engeller — once tekillestir (v115 likes/favorites deseni).
  await pool.query(`DELETE FROM factory_follows a USING factory_follows b WHERE a.id < b.id AND a.user_id = b.user_id AND a.factory_id = b.factory_id`);
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factory_follows_user_factory_uidx ON factory_follows (user_id, factory_id)`); } catch (e) { /* eski semada index kurulamazsa akis bozulmaz */ }
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_follows_factory_idx ON factory_follows (factory_id)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_subscriptions (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, status TEXT DEFAULT 'pending', started_at TIMESTAMPTZ, ends_at TIMESTAMPTZ, paytr_merchant_oid TEXT UNIQUE, amount INT, currency TEXT DEFAULT 'USD', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  // Abonelik/VIP: admin_grant tamamlayici abonelik icin plan/provider/expires_at.
  // Eski (odemeli) satirlarda yalniz ends_at dolu olabilir — /me ikisini COALESCE ile okur,
  // grant her iki sutunu da ayni degere yazar; boylece ends_at okuyan mevcut kod bozulmaz.
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS plan TEXT`);
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS provider TEXT`);
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factories (id SERIAL PRIMARY KEY, name TEXT NOT NULL, city TEXT DEFAULT '', category TEXT DEFAULT '', description TEXT DEFAULT '', moq INT DEFAULT 0, stock INT DEFAULT 0, capacity TEXT DEFAULT '', certs TEXT DEFAULT '', features TEXT DEFAULT '', import_countries TEXT DEFAULT '', employees TEXT DEFAULT '', annual_revenue TEXT DEFAULT '', factory_area TEXT DEFAULT '', years TEXT DEFAULT '', main_products TEXT DEFAULT '', cover_image TEXT DEFAULT '', videos JSONB DEFAULT '[]', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS hashtags TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS address TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS contact TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS wechat TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS whatsapp TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS socials JSONB DEFAULT '{}'`);
  // fix10ae (CBOs26.79-A): fabrika SERTIFIKA belgeleri — [{title, url}] (JSONB dizi).
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS certificates JSONB DEFAULT '[]'`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS features TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS import_countries TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS employees TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS annual_revenue TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS factory_area TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS years TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS main_products TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS cover_image TEXT DEFAULT ''`);
  // CBF: fabrika kodu (CBF-001, …). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS cbf_code TEXT`); } catch (e) { /* cbf_code kolonu eklenemezse akis bozulmaz */ }
  // VERIFIED: dogrulanmis fabrika rozeti (is_verified BOOLEAN, varsayilan FALSE). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE`); } catch (e) { /* is_verified kolonu eklenemezse akis bozulmaz */ }
  // FACTORY EMAIL (fix5): fabrika e-posta adresi (opsiyonel, max 254, e-posta bicimi). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS email TEXT`); } catch (e) { /* email kolonu eklenemezse akis bozulmaz */ }
  // fix10c — My Factory giris hesabi: fabrika bazli kullanici adi (benzersiz) + sifre hash'i.
  // SIRA KRITIK (canlida eski fabrika giris verisi olabilir — veri kaybi YOK):
  // 1) yeni myfactory_* sutunlarini ekle, 2) eski sutunlarda veri varsa
  // yeni sutunlara KOPYALA, 3) eski sutunlari temizle.
  // Eski sutun yoksa (yeni kurulum) kopyalama adimi sessizce atlanir; hicbir sorgu cokmez.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS myfactory_username TEXT UNIQUE`); } catch (e) { /* myfactory_username kolonu eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS myfactory_password_hash TEXT`); } catch (e) { /* myfactory_password_hash kolonu eklenemezse akis bozulmaz */ }
  // fix10u (CBOs26.55-A): fabrika MARKA TESCİLİ beyanı — marka adı fabrikalar arasında BENZERSİZ
  // olmalı (uygulama katmanı normalize + LOWER karşılaştırmasıyla 409 brand_taken döner; kısmi
  // benzersiz dizin ikinci savunma hattıdır). Her ALTER kendi try/catch'indedir, hata yutulur.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS brand_name TEXT`); } catch (e) { /* brand_name kolonu eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS trademark_no TEXT`); } catch (e) { /* trademark_no kolonu eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS trademark_office TEXT`); } catch (e) { /* trademark_office kolonu eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS trademark_declared_at TIMESTAMPTZ`); } catch (e) { /* trademark_declared_at kolonu eklenemezse akis bozulmaz */ }
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factories_brand_name_uniq ON factories (LOWER(TRIM(brand_name))) WHERE brand_name IS NOT NULL AND TRIM(brand_name) <> ''`); } catch (e) { /* benzersiz dizin kurulamazsa akis bozulmaz (uygulama katmani kontrolu devrede) */ }
  // fix10x (CBOs26.60-A): ÇOKLU MARKA — factory_brands tablosu (asıl kaynak). brand_key =
  // normalize edilmiş (trim + iç boşluk tek) adın küçük harf hâli; TAM UNIQUE dizin: bir
  // marka adı dünyada tek fabrikada olabilir. Tablo, factories tablosu kurulduktan sonra
  // açılmalıdır (FK). Her ifade kendi try/catch'indedir, hata yutulur.
  try { await pool.query(`CREATE TABLE IF NOT EXISTS factory_brands (id SERIAL PRIMARY KEY, factory_id INT NOT NULL REFERENCES factories(id) ON DELETE CASCADE, brand_name TEXT NOT NULL, brand_key TEXT NOT NULL, trademark_no TEXT, trademark_office TEXT, declared_at TIMESTAMPTZ DEFAULT NOW())`); } catch (e) { /* factory_brands kurulamazsa akis bozulmaz (serializer eski sutunlara duser) */ }
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factory_brands_key_uniq ON factory_brands (brand_key)`); } catch (e) { /* benzersiz dizin kurulamazsa akis bozulmaz (uygulama katmani kontrolu devrede) */ }
  try { await pool.query(`CREATE INDEX IF NOT EXISTS factory_brands_factory_idx ON factory_brands (factory_id)`); } catch (e) { /* dizin kurulamazsa akis bozulmaz */ }
  // fix10x GÖÇ: factories.brand_name dolu satırlar factory_brands'a tek kayıt olarak taşınır.
  // ON CONFLICT (brand_key) DO NOTHING — her açılışta güvenle koşar (idempotent); aynı
  // normalize adı taşıyan ikinci bir eski kayıt (kısmi dizin varken olmamalı) sessizce atlanır.
  try {
    await pool.query(
      `INSERT INTO factory_brands (factory_id, brand_name, brand_key, trademark_no, trademark_office, declared_at)
       SELECT f.id,
              REGEXP_REPLACE(TRIM(f.brand_name), '\\s+', ' ', 'g'),
              LOWER(REGEXP_REPLACE(TRIM(f.brand_name), '\\s+', ' ', 'g')),
              f.trademark_no, f.trademark_office, COALESCE(f.trademark_declared_at, now())
         FROM factories f
        WHERE f.brand_name IS NOT NULL AND TRIM(f.brand_name) <> ''
       ON CONFLICT (brand_key) DO NOTHING`
    );
  } catch (e) { /* göç hatası akışı bozmaz — bir sonraki açılışta tekrar denenir */ }
  // fix10e H-B: eski fabrika giriş verisi göçü — transaction + doğrulama.
  // 1) Kopyalama tek transaction içinde, satır satır: MEVCUT myfactory_*
  // değeri ASLA eski değerle ezilmez (yalnız NULL olanlar doldurulur).
  // Benzersizlik çakışması yaşayan satır atlanır (sonraki çağrıda tekrar
  // denenir), diğer satırlar etkilenmez.
  // 2) Doğrulama: eski sütunda veri kalmışsa (kopyalanamamış satır varsa)
  // DROP YAPILMAZ — eski sütunlar bir sonraki çağrıda tekrar denemek için
  // korunur. Yalnız her şey kopyalanmışsa DROP edilir.
  try {
    const { rows: _mfCols } = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'factories' AND column_name IN ('workshop_username', 'workshop_password_hash')`);
    const _mfHas = new Set(_mfCols.map((r) => r.column_name));
    if (_mfHas.size) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        if (_mfHas.has('workshop_username')) {
          const { rows: _mfRows } = await client.query(`SELECT id, workshop_username FROM factories WHERE workshop_username IS NOT NULL AND myfactory_username IS NULL`);
          for (const r of _mfRows) {
            try {
              await client.query(`UPDATE factories SET myfactory_username = $1 WHERE id = $2 AND myfactory_username IS NULL`, [r.workshop_username, r.id]);
            } catch (e) { /* çakışma: bu satır atlanır, diğerleri devam eder */ }
          }
        }
        if (_mfHas.has('workshop_password_hash')) {
          const { rows: _mfRows } = await client.query(`SELECT id, workshop_password_hash FROM factories WHERE workshop_password_hash IS NOT NULL AND myfactory_password_hash IS NULL`);
          for (const r of _mfRows) {
            try {
              await client.query(`UPDATE factories SET myfactory_password_hash = $1 WHERE id = $2 AND myfactory_password_hash IS NULL`, [r.workshop_password_hash, r.id]);
            } catch (e) { /* bu satır atlanır, diğerleri devam eder */ }
          }
        }
        await client.query('COMMIT');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) { /* yoksay */ }
      } finally { client.release(); }
      // Doğrulama: kopyalanamamış eski veri kaldı mı?
      let _mfRemaining = 0;
      try {
        const conds = [];
        if (_mfHas.has('workshop_username')) conds.push(`(workshop_username IS NOT NULL AND myfactory_username IS NULL)`);
        if (_mfHas.has('workshop_password_hash')) conds.push(`(workshop_password_hash IS NOT NULL AND myfactory_password_hash IS NULL)`);
        if (conds.length) {
          const { rows: _rem } = await pool.query(`SELECT COUNT(*)::int AS n FROM factories WHERE ${conds.join(' OR ')}`);
          _mfRemaining = _rem[0] ? _rem[0].n : 0;
        }
      } catch (e) { _mfRemaining = 1; /* doğrulanamadı: DROP yapma */ }
      if (!_mfRemaining) {
        try { await pool.query(`ALTER TABLE factories DROP COLUMN IF EXISTS workshop_username`); } catch (e) { /* eski sutun yoksa / silinemezse akis bozulmaz */ }
        try { await pool.query(`ALTER TABLE factories DROP COLUMN IF EXISTS workshop_password_hash`); } catch (e) { /* eski sutun yoksa / silinemezse akis bozulmaz */ }
      }
    }
  } catch (e) { /* göç hatası akışı bozmaz — eski hesaplar bir sonraki çağrıda tekrar denenir, DROP yapılmaz */ }
  // Sutun daha once UNIQUE'siz olusmus olabilir — kucuk harfe duyarsiz benzersizlik icin ifade indexi (varsa yoksayilir).
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS factories_myfactory_username_uidx ON factories (LOWER(myfactory_username))`); } catch (e) { /* index kurulamazsa akis bozulmaz */ }
  // v118: user_id tip onarimi — users.id UUID, ama fabrika tablolari user_id'yi INT diye
  // tanimlamisti; UUID'li kullaniciyla her user_id sorgusu 500 veriyordu. INT->TEXT
  // donusumu kayipsizdir (her INT metne cevrilir); TEXT kolonda tekrar calismak no-op'tur.
  // Her ALTER kendi try/catch'indedir: bir tablodaki hata digerlerini/rotayi bozmaz.
  for (const t of ['factory_likes', 'factory_comments', 'factory_favorites', 'factory_messages', 'factory_quotes', 'factory_ratings', 'factory_subscriptions']) {
    try { await pool.query(`ALTER TABLE ${t} ALTER COLUMN user_id TYPE TEXT USING user_id::text`); } catch (e) { /* tablo/sutun yoksa veya tip zaten TEXT ise yoksay */ }
  }
  // CBF backfill: kodu bos fabrikalara kod ata (idempotent, hatada akis bozulmaz).
  await backfillFactoryCbfCodes();
  // CBOs26.33 (fix10r): fabrika ÖN KAYIT başvuruları — herkese açık formdan gelir, admin inceler.
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_applications (id SERIAL PRIMARY KEY, factory_name TEXT NOT NULL, contact_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', city TEXT DEFAULT '', sector TEXT NOT NULL DEFAULT '', annual_revenue TEXT DEFAULT '', message TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_applications_email_idx ON factory_applications (email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS factory_applications_status_idx ON factory_applications (status)`);
}

const FACTORY_VIDEO_RE = /^\d+-\d+$/;

// SECURITY v128: spam koruması — yorum + CBAI mesaj gönderimi için kullanıcı başına
// nazik limit (15 dakikada 60). Normal kullanıcı kilitlenmez; spam/bot akışı
// yavaşlatılır. rateLimit.js deseniyle aynı (message: { error }).
const factorySpamLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'factory-spam:' + (req.user && req.user.id ? String(req.user.id) : ipKeyGenerator(req.ip)), // fix10e M2
});

// SHOP SECURITY: magaza yorum + paylasim icin nazik limit (fabrika deseniyle ayni).
// Yorum: giris yapan kullanici basina 15 dakikada 60. Paylasim: kullanici/IP basina 15 dakikada 120.
// Normal kullanici kilitlenmez; botun tabloyu satirla sisirmesi yavaslatilir.
const shopSpamLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'shop-spam:' + (req.user && req.user.id ? String(req.user.id) : ipKeyGenerator(req.ip)), // fix10e M2
});

// CBOs26.33 (fix10r): herkese açık fabrika başvuru formu için nazik limit (IP başına saatte 10).
// Normal başvuru akışını engellemez; botun tabloyu doldurmasını yavaşlatır.
const factoryApplyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'factory-apply:' + ipKeyGenerator(req.ip),
});

// CBOs26.72 (fix10ac): presence kalp atisi icin nazik limit (IP basina dakikada 60).
// Kalp atisi istemcide ~30 sn'de bir atilir (IP basina ~2/dk); pay, NAT arkasindaki
// cok sekmeli/ziyaretcili baglantilara da kalir. Botun tabloyu sisirmesi yavaslatilir.
const factoryPresenceLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'factory-presence:' + ipKeyGenerator(req.ip),
});

// SHOP SECURITY: gizli jeton karsilastirmasi icin zamanlama-saldirisina dayanikli esitlik.
// fix10e L1: uzunluk erken dönüşü YOK — iki değer de SHA-256 ile sabit
// uzunluklu özetlere indirgenir, timingSafeEqual özetler üzerinde çalışır.
function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = crypto.createHash('sha256').update(a).digest();
  const bb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ab, bb);
}

// fix10e L4: şifre politikası — en az 8 karakter + en az bir harf + en az bir rakam.
function passwordStrong(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

// fix10e H-E: master işlem denetim kaydı — created_by ASLA null değil,
// master işaretli 'cbai' yazılır. Hata ana akışı bozmaz.
async function logMasterAudit(action, targetType, targetId) {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS master_audit_log (id SERIAL PRIMARY KEY, action TEXT NOT NULL, target_type TEXT, target_id TEXT, created_by TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
    await pool.query(`INSERT INTO master_audit_log (action, target_type, target_id, created_by) VALUES ($1, $2, $3, 'cbai')`, [action, targetType || null, targetId == null ? null : String(targetId)]);
  } catch (e) { /* denetim kaydı ana akışı bozmaz */ }
}

// fix10e L8: fabrika medya URL konak allowlist'i — videos / cover_image yalnız
// bu konaklardan kabul edilir (rastgele dış konak / javascript: / veri gömme yok).
// İzinli: Cloudflare Stream + ChinaBazaar alanları + Netlify dağıtımları.
const FACTORY_MEDIA_HOSTS = new Set([
  'videodelivery.net', 'cloudflarestream.com',
  'chinabazaar.com', 'www.chinabazaar.com',
  'chinabazaar.shop', 'www.chinabazaar.shop',
  'cbazaar.netlify.app', 'myfactor.netlify.app', 'cbcbcb.netlify.app',
]);
function isAllowedFactoryMediaUrl(u) {
  if (typeof u !== 'string') return false;
  const t = u.trim();
  if (!/^https:\/\//i.test(t)) return false;
  // CBOs26.2: chat-upload dondurdugu sohbet dosyasi URL'i (kendi API konagimizdaki
  // /api/products/factory/chat-file/<id>/<32hex> yolu) kapak olarak kabul edilir.
  // Jeton tahmin edilemez; baska konakta bu yol olu bir baglantidir, guvenlik acigi degildir.
  // (fix10e'de bu eksikti: fabrika chat-upload ile yukledigi kapagi kaydedemiyordu — 400.)
  if (/^https:\/\/[^/]+\/api\/products\/factory\/chat-file\/\d+\/[a-f0-9]{32}$/i.test(t)) return true;
  let host = '';
  try { host = new URL(t).hostname.toLowerCase(); } catch { return false; }
  if (FACTORY_MEDIA_HOSTS.has(host)) return true;
  if (host.endsWith('.netlify.app')) return true;
  // fix10o: Cloudflare Stream alt alan adları (customer-*.cloudflarestream.com,
  // *.videodelivery.net) — CBCloud yüklemeleri bu konaklarda barınır; fix10e'de
  // eksikti, Stream videolu fabrika kaydetmede invalid_videos veriyordu.
  if (host.endsWith('.cloudflarestream.com') || host.endsWith('.videodelivery.net')) return true;
  return false;
}
// fix10e L8: sosyal ağ konak allowlist'i — her anahtar yalnızca kendi ağının
// konaklarını kabul eder (örn. youtube alanına facebook.com yazılamaz).
const FACTORY_SOCIAL_HOSTS = {
  youtube: new Set(['youtube.com', 'www.youtube.com', 'youtu.be', 'm.youtube.com']),
  facebook: new Set(['facebook.com', 'www.facebook.com', 'fb.com', 'www.fb.com']),
  tiktok: new Set(['tiktok.com', 'www.tiktok.com']),
  instagram: new Set(['instagram.com', 'www.instagram.com']),
};
function isAllowedFactorySocialUrl(key, u) {
  if (typeof u !== 'string') return false;
  const t = u.trim();
  if (t === '') return true;
  if (!/^https:\/\//i.test(t)) return false;
  let host = '';
  try { host = new URL(t).hostname.toLowerCase(); } catch { return false; }
  const allowed = FACTORY_SOCIAL_HOSTS[key];
  return !!allowed && allowed.has(host);
}

// fix10e M6: fabrika e-posta/telefon benzersizliği (kendi dışı).
async function factoryContactTaken(field, value, excludeId) {
  if (value === undefined || value === null || String(value).trim() === '') return false;
  const v = String(value).trim();
  let sql; let params;
  if (field === 'email') {
    sql = `SELECT id FROM factories WHERE LOWER(email) = LOWER($1)`;
    params = [v];
  } else {
    sql = `SELECT id FROM factories WHERE phone = $1`;
    params = [v];
  }
  if (excludeId !== undefined && excludeId !== null) { params.push(excludeId); sql += ` AND id <> $${params.length}`; }
  const { rows } = await pool.query(sql, params);
  return rows.length > 0;
}

// fix10e L7: SSRF — iç / özel ağ engeli. URL'deki konak DNS ile çözülür;
// çözülen IP'lerden BİRİ bile özel/rezerve aralıktaysa URL reddedilir.
// (DNS rebinding TOCTOU'ya karşı tam koruma değildir; derinlik katmanıdır.)
function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::' || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('::ffff:')) {
      if (l.startsWith('::ffff:')) return isPrivateIp(l.slice(7));
      return true;
    }
    if (l.startsWith('ff')) return true; // multicast
    return false;
  }
  const parts = ip.split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}
async function assertPublicUrl(rawUrl) {
  let u;
  try { u = new URL(String(rawUrl)); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username || u.password) return false; // kimlik bilgili URL yok
  const host = u.hostname;
  if (!host || host === 'localhost') return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return !isPrivateIp(host);
  try {
    const addrs = await dns.promises.lookup(host, { all: true });
    if (!addrs.length) return false;
    for (const a of addrs) { if (isPrivateIp(a.address)) return false; }
    return true;
  } catch { return false; }
}

// Goruntulenecek ad: nickname || name || e-posta on eki (e-posta adresinin tamami ASLA donulmez)
function factoryDisplayName(u) {
  if (!u) return 'Misafir';
  if (u.nickname && String(u.nickname).trim()) return u.nickname;
  if (u.name && String(u.name).trim()) return u.name;
  if (u.email) return String(u.email).split('@')[0] || 'Misafir';
  return 'Misafir';
}

// fix10e M7: herkese açık yanıtta (GET /factory/list) iletişim bilgileri
// gösterilmez — opts.includeContact === false ise e-posta/telefon/adres/
// WhatsApp/WeChat/kontak kişi çıkarılır. Admin/MyFactory serializer'ları
// tam kaydı almaya devam eder (includeContact varsayılan true).
function toFactoryPublic(r, opts) {
  const includeContact = !opts || opts.includeContact !== false;
  // fix10x: PUBLIC marka — brand_name = İLK markanın adı; brands = yalnızca ADLAR listesi.
  // trademark_no / trademark_office PUBLIC'e ASLA gitmez (fix10v kuralı aynen).
  const publicBrands = factoryBrandsOf(r);
  let videos = r.videos;
  if (typeof videos === 'string') { try { videos = JSON.parse(videos); } catch { videos = []; } }
  if (!Array.isArray(videos)) videos = [];
  const contactFields = includeContact ? {
    address: r.address || '',
    phone: r.phone || '',
    contact: r.contact || '',
    email: r.email || null,
    wechat: r.wechat || '',
    whatsapp: r.whatsapp || '',
  } : {
    address: '',
    phone: '',
    contact: '',
    email: null,
    wechat: '',
    whatsapp: '',
  };
  return {
    ...contactFields,
    id: r.id,
    name: r.name,
    // fix10ad: alt alan adi (<username>.chinabazaar.com) eslesmesi icin login adi
    // public ciktida — fabrikalarin paylastigi acik bilgidir; iletisim gizleme
    // kurali (includeContact) AYNEN gecerlidir, bu alan onu etkilemez.
    username: r.myfactory_username || null,
    brand_name: publicBrands.length ? publicBrands[0].brand_name : null,
    brands: publicBrands.map((b) => b.brand_name),
    cbf_code: r.cbf_code || '',
    is_verified: !!r.is_verified,
    city: r.city || '',
    category: r.category || '',
    desc: r.description || '',
    moq: r.moq ?? 0,
    stock: r.stock ?? 0,
    capacity: r.capacity || '',
    certs: r.certs || '',
    features: r.features || '',
    import_countries: r.import_countries || '',
    employees: r.employees || '',
    annual_revenue: r.annual_revenue || '',
    factory_area: r.factory_area || '',
    years: r.years || '',
    main_products: r.main_products || '',
    cover_image: r.cover_image || '',
    hashtags: r.hashtags || '',
    socials: parseFactorySocials(r.socials),
    certificates: parseFactoryCertificates(r.certificates), // fix10ae: sertifika belgeleri [{title, url}] (yoksa [])
    tags: r.tags || '',
    videos,
    // fix10aa (CBOs26.68): page_views — yalnizca satir degeri TASIRSA eklenir (public liste/detay
    // uclari factoryPageViewsMap ile doldurur; tanim panel istatistigiyle ayni: factory_page_views.visits).
    // Admin/owner satirlari tasimaz -> o serializer'larin ciktisi birebir ayni kalir.
    ...(r.page_views !== undefined && r.page_views !== null ? { page_views: Number(r.page_views) || 0 } : {}),
  };
}
// v55: fabrika puan ortalamalari — tek sorgu, N+1 yok. Yoksa avg=null, count=0.
async function factoryRatingsMap(ids) {
  const map = {};
  const list = (ids || []).filter((x) => Number.isInteger(x));
  if (!list.length) return map;
  const { rows } = await pool.query('SELECT factory_id, ROUND(AVG(rating)::numeric, 1)::float AS avg, COUNT(*)::int AS cnt FROM factory_ratings WHERE factory_id = ANY($1) GROUP BY factory_id', [list]);
  for (const r of rows) map[r.factory_id] = { rating_avg: r.avg === null ? null : Number(r.avg), rating_count: r.cnt };
  return map;
}

// v110: fabrika teklif sayilari — yeni (factory_id) + eski (factory ad, normalize) teklifler birlikte sayilir.
async function factoryQuoteCountsMap(ids) {
  const map = {};
  const list = (ids || []).filter((x) => Number.isInteger(x));
  if (!list.length) return map;
  await ensureFactoryQuotesTable();
  for (const id of list) map[id] = 0;
  // yeni teklifler: factory_id ile
  const { rows: byId } = await pool.query('SELECT factory_id, COUNT(*)::int AS cnt FROM factory_quotes WHERE factory_id = ANY($1) GROUP BY factory_id', [list]);
  for (const r of byId) map[r.factory_id] = (map[r.factory_id] || 0) + r.cnt;
  // eski teklifler: factory TEXT ad ile (trim + lowercase normalize, fabrika adiyla eslestir). factory_id'li olanlar cift sayilmasin diye factory_id IS NULL sarti var.
  const { rows: facs } = await pool.query('SELECT id, name FROM factories WHERE id = ANY($1)', [list]);
  const nameToId = {};
  for (const f of facs) nameToId[String(f.name || '').trim().toLowerCase()] = f.id;
  const { rows: legacy } = await pool.query(`SELECT LOWER(TRIM(factory)) AS fname, COUNT(*)::int AS cnt FROM factory_quotes WHERE factory_id IS NULL AND factory <> '' GROUP BY LOWER(TRIM(factory))`);
  for (const r of legacy) { const fid = nameToId[r.fname]; if (fid) map[fid] = (map[fid] || 0) + r.cnt; }
  return map;
}

// fix10k (CBOs26.15): fabrika takipci sayilari — tek sorgu, N+1 yok. Takip yoksa 0 (ratings deseni).
async function factoryFollowersMap(ids) {
  const map = {};
  const list = (ids || []).filter((x) => Number.isInteger(x));
  if (!list.length) return map;
  const { rows } = await pool.query('SELECT factory_id, COUNT(*)::int AS cnt FROM factory_follows WHERE factory_id = ANY($1) GROUP BY factory_id', [list]);
  for (const r of rows) map[r.factory_id] = r.cnt;
  return map;
}

// fix10aa (CBOs26.68): fabrika sayfa goruntulenmeleri — panel istatistigiyle (myfactory/stats
// total_page_visitors) AYNI tanim/kaynak: factory_page_views.visits. Tek sorgu, N+1 yok.
// Goruntulenme yoksa 0; tablo yoksa (eski DB) hepsi 0 — panel desenindeki gibi akis bozulmaz.
async function factoryPageViewsMap(ids) {
  const map = {};
  const list = (ids || []).filter((x) => Number.isInteger(x));
  for (const id of list) map[id] = 0;
  if (!list.length) return map;
  try {
    const { rows } = await pool.query('SELECT factory_id, visits FROM factory_page_views WHERE factory_id = ANY($1)', [list]);
    for (const r of rows) map[r.factory_id] = r.visits || 0;
  } catch (e) { /* factory_page_views yoksa hepsi 0 kalir */ }
  return map;
}

// fix10aa (CBOs26.68): TUM fabrikalarin toplam sayfa goruntulenmesi (site ziyaretci sayisi).
// Tek aggregate sorgu; tablo yoksa 0.
async function factorySiteVisitorsTotal() {
  try {
    const { rows } = await pool.query('SELECT COALESCE(SUM(visits), 0)::int AS total FROM factory_page_views');
    return (rows[0] && rows[0].total) || 0;
  } catch (e) { return 0; }
}

// fix10ac (CBOs26.72): SU AN cevrimici ziyaretci sayisi — factory_presence'ta son 120 saniyede
// last_seen'i taze olan DISTINCT session sayisi. Tek sorgu; tablo yoksa 0 (akis bozulmaz).
async function factoryOnlineNow() {
  try {
    const { rows } = await pool.query(`SELECT COUNT(DISTINCT session_id)::int AS n FROM factory_presence WHERE last_seen > now() - INTERVAL '120 seconds'`);
    return (rows[0] && rows[0].n) || 0;
  } catch (e) { return 0; }
}

function toFactoryAdmin(r) {
  // myfactory_username: admin yonetimi icin doner. myfactory_password_hash ASLA donulmez (hicbir serializer'da yok).
  // fix10u: marka tescil beyani alanlari admin + owner (toFactoryMyFactory) gorunumunde doner.
  // fix10v: brand_name toFactoryPublic'te de doner; trademark_no/office/declared_at PUBLIC'te YOK.
  // fix10x: brands[] = fabrikanin TUM markalari (tam kayit); eski tekil alanlar ILK markadan
  // doldurulur (geri uyum) — fix10x oncesi davranista ilk/tek marka donuyordu, aynisi korunur.
  const adminBrands = factoryBrandsOf(r);
  const firstBrand = adminBrands.length ? adminBrands[0] : null;
  return { ...toFactoryPublic(r), myfactory_username: r.myfactory_username || null, brand_name: firstBrand ? firstBrand.brand_name : null, trademark_no: firstBrand ? (firstBrand.trademark_no || null) : null, trademark_office: firstBrand ? (firstBrand.trademark_office || null) : null, trademark_declared_at: firstBrand ? (firstBrand.declared_at || null) : null, brands: adminBrands.map(brandRowOut), is_active: r.is_active !== false, created_at: r.created_at, updated_at: r.updated_at };
}

// My Factory me/login yaniti: TAM fabrika kaydi, myfactory_username dahil, hash ASLA yok.
function toFactoryMyFactory(r) {
  return toFactoryAdmin(r);
}

// v5: fabrika sosyal aglari — {youtube, facebook, tiktok, instagram}; yalniz http(s) URL kabul edilir
function parseFactorySocials(v) {
  let o = v;
  if (typeof o === 'string') { try { o = JSON.parse(o); } catch { return { youtube: '', facebook: '', tiktok: '', instagram: '' }; } }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { youtube: '', facebook: '', tiktok: '', instagram: '' };
  const pick = (k) => (typeof o[k] === 'string' ? o[k].trim() : '');
  return { youtube: pick('youtube'), facebook: pick('facebook'), tiktok: pick('tiktok'), instagram: pick('instagram') };
}

// VERIFIED: is_verified cozumu — boolean, veya "true"/"false"/"1"/"0" string, veya 1/0 sayi.
// undefined => verilmedi (UPDATE'de dokunma, CREATE'de varsayilan false); gecersiz => null (handler 400 doner).
function parseFactoryVerified(v) {
  if (v === undefined) return undefined;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') { if (v === 1) return true; if (v === 0) return false; return null; }
  if (typeof v === 'string') {
    const t = v.trim().toLowerCase();
    if (t === 'true' || t === '1') return true;
    if (t === 'false' || t === '0') return false;
    return null;
  }
  return null;
}

// v5: duz string alan — undefined => dokunma, gecersiz/uzun => null (handler 400 doner)
function cleanFactoryText(v, max) {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (t.length > max) return null;
  return t;
}

// fix5: fabrika e-postasi — undefined => dokunma, bos string => '' (handler NULL saklar),
// gecersiz (string degil / 254'ten uzun / e-posta biciminde degil) => null (handler 400 doner)
function cleanFactoryEmail(v) {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (t === '') return '';
  if (t.length > 254) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t)) return null;
  return t;
}


// FAZ 1 — My Factory kullanici adi: undefined => dokunma, '' => yok (no-op), gecersiz => null (handler 400 doner).
// 3-50 karakter, yalniz harf/rakam/._- . Karsilastirma kucuk harfe duyarsizdir (auth.js giris deseni).
function cleanMyFactoryUsername(v) {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (t === '') return '';
  if (t.length < 3 || t.length > 50) return null;
  if (!/^[A-Za-z0-9_.\-]+$/.test(t)) return null;
  if (t.toLowerCase() === 'cbai') return null; // fix10e L3: 'cbai' rezerve
  return t;
}

// FAZ 1 — My Factory sifresi: undefined => dokunma, ''/null => koru (no-op), gecersiz => null (handler 400 doner).
// 8-100 karakter. Sifre kirpilmez (auth.js ile ayni: ham hali hash'lenir).
function cleanMyFactoryPassword(v) {
  if (v === undefined) return undefined;
  if (v === null) return '';
  if (typeof v !== 'string') return null;
  if (v === '') return '';
  if (v.length < 8 || v.length > 100) return null;
  if (!passwordStrong(v)) return null; // fix10e L4: harf + rakam zorunlu
  return v;
}

// fix10ag (CBOs26.82-A) — ALT ALAN ADI otomasyonu (Netlify API) yardimcilari.
// Env kapisi: NETLIFY_API_TOKEN + NETLIFY_SITE_ID yoksa otomasyon sessizce
// devre disi (netlifyFactoryCfg null doner; cagri noktalari akisi degistirmez).
const FACTORY_SUBDOMAIN_RESERVED = new Set(['www', 'api', 'admin', 'panel', 'mail', 'ftp', 'shop', 'store', 'app', 'blog', 'help', 'support', 'static', 'assets', 'cdn', 'ns1', 'ns2']);
const FACTORY_SUBDOMAIN_RE = /^[a-z0-9][a-z0-9-]{1,40}$/;

// Kullanici adindan alt alan adi etiketi: kucuk harfe cevrilir; desen disi
// (nokta/alt cizgi iceren kullanici adlari dahil) veya rezerve isimse null.
function factorySubdomainLabel(username) {
  if (typeof username !== 'string') return null;
  const label = username.trim().toLowerCase();
  if (!FACTORY_SUBDOMAIN_RE.test(label)) return null;
  if (FACTORY_SUBDOMAIN_RESERVED.has(label)) return null;
  return label;
}

function netlifyFactoryCfg() {
  const token = typeof process.env.NETLIFY_API_TOKEN === 'string' ? process.env.NETLIFY_API_TOKEN.trim() : '';
  const siteId = typeof process.env.NETLIFY_SITE_ID === 'string' ? process.env.NETLIFY_SITE_ID.trim() : '';
  if (!token || !siteId) return null;
  return { token, siteId };
}

// Netlify API istegi — ~8 sn zaman asimi (AbortController), yerlesik fetch.
async function netlifyFactoryFetch(cfg, pathname, options) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    return await fetch(`https://api.netlify.com/api/v1${pathname}`, {
      ...(options || {}),
      signal: ctrl.signal,
      headers: { Authorization: `Bearer ${cfg.token}`, 'Content-Type': 'application/json', ...((options && options.headers) || {}) },
    });
  } finally {
    clearTimeout(timer);
  }
}

// Sitenin mevcut domain_aliases listesi (custom_domain'e DOKUNULMAZ).
async function fetchNetlifyDomainAliases(cfg) {
  const r = await netlifyFactoryFetch(cfg, `/sites/${encodeURIComponent(cfg.siteId)}`);
  if (!r.ok) throw new Error(`netlify_get_site_${r.status}`);
  const site = await r.json();
  return Array.isArray(site && site.domain_aliases) ? site.domain_aliases.map((x) => String(x)) : [];
}

// <username>.chinabazaar.com adresini Netlify alias listesine ekler (yoksa).
// HICBIR kosulda firlatmaz: hata yalniz console.error'a duser; cagiran akis
// bloklanmaz ve istegin sonucu degismez (fire-and-forget kullanilir).
async function ensureFactoryDomainAlias(username) {
  try {
    const cfg = netlifyFactoryCfg();
    if (!cfg) return false; // env yok: sessizce devre disi
    const label = factorySubdomainLabel(username);
    if (!label) return false; // gecersiz/rezerve: API cagrisi yapilmaz
    const host = `${label}.chinabazaar.com`;
    const aliases = await fetchNetlifyDomainAliases(cfg);
    if (aliases.some((a) => a.toLowerCase() === host)) return true; // zaten ekli
    const r = await netlifyFactoryFetch(cfg, `/sites/${encodeURIComponent(cfg.siteId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ domain_aliases: [...aliases, host] }),
    });
    if (!r.ok) throw new Error(`netlify_patch_site_${r.status}`);
    return true;
  } catch (e) {
    console.error('[fix10ag] ensureFactoryDomainAlias:', e && e.message);
    return false;
  }
}

// fix9: fabrika kapak gorseli — undefined => dokunma, bos string => '' (yok),
// gecersiz (string degil / 2048'den uzun / http(s) URL degil) => null (handler 400 doner)
function cleanFactoryCoverImage(v) {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (t === '') return '';
  if (t.length > 2048) return null;
  if (!isAllowedFactoryMediaUrl(t)) return null; // fix10e L8: konak allowlist
  return t;
}

// v5: socials — obje veya JSON string; her URL bos veya kendi ağının
// konak allowlist'inde olmalı (fix10e L8), aksi halde null (400)
function cleanFactorySocials(v) {
  if (v === undefined) return undefined;
  let o = v;
  if (typeof o === 'string') { try { o = JSON.parse(o); } catch { return null; } }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const out = {};
  for (const k of ['youtube', 'facebook', 'tiktok', 'instagram']) {
    const val = o[k];
    if (val === undefined || val === null) { out[k] = ''; continue; }
    if (typeof val !== 'string') return null;
    const t = val.trim();
    if (t.length > 2048) return null;
    if (t !== '' && !isAllowedFactorySocialUrl(k, t)) return null;
    out[k] = t;
  }
  return out;
}

// v5: etiketler — virgullu duz string (hashtag degil, basina # eklenmez), tekrarlar atilir
function cleanFactoryTags(v) {
  if (v === undefined) return undefined;
  const arr = Array.isArray(v) ? v : (typeof v === 'string' ? v.split(',') : null);
  if (arr === null) return null;
  const out = [];
  for (const it of arr) {
    if (typeof it !== 'string') return null;
    const t = it.trim();
    if (!t) continue;
    if (!out.includes(t)) out.push(t);
  }
  if (out.join(', ').length > 2000) return null;
  return out.join(', ');
}

// hashtags: dizi veya virgullu string — normalize et (basina # ekle, tekrarlari at), gecersizse null
function cleanFactoryHashtags(v) {
  if (v === undefined) return undefined;
  const arr = Array.isArray(v) ? v : (typeof v === 'string' ? v.split(',') : null);
  if (arr === null) return null;
  const out = [];
  for (const it of arr) {
    if (typeof it !== 'string') return null;
    let t = it.trim();
    if (!t) continue;
    if (t.charAt(0) !== '#') t = '#' + t;
    if (!out.includes(t)) out.push(t);
  }
  if (out.join(', ').length > 2000) return null;
  return out.join(', ');
}

// fix10y (CBOs26.62): video ürün özellikleri — [{name, value}] ad-değer çiftleri.
// Dizi değilse alan atılır (null döner, video yine geçerli); en fazla 40 öğe;
// name trim -> <=80, value trim -> <=500 karakter (title/description desenindeki
// gibi kesilir); name veya value boşsa öğe atılır; fazladan alanlar alınmaz.
// Geçerli öğe yoksa null — çağıran attributes anahtarını hiç eklemez (geri uyum).
function cleanVideoAttributes(v) {
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const it of v) {
    if (out.length >= 40) break;
    if (!it || typeof it !== 'object' || Array.isArray(it)) continue;
    if (typeof it.name !== 'string' || typeof it.value !== 'string') continue;
    const name = it.name.trim().slice(0, 80);
    const value = it.value.trim().slice(0, 500);
    if (!name || !value) continue;
    out.push({ name, value });
  }
  return out.length ? out : null;
}

// fix10ae (CBOs26.79-A): fabrika SERTIFIKA belgeleri — [{title, url}].
// YAZMA (cleanFactoryCertificates): undefined => dokunma; dizi DEGILSE sessizce
// yok sayilir (undefined doner — mevcut PUT desenlerindeki gibi handler
// yazmadan gecer, 400 YOK). Dizi ise TOPTAN yazim listesi kurulur: en cok 20
// oge; title ZORUNLU (trim -> <=120 kesilir, bos ise oge atilir); url ZORUNLU
// (trim, <=2048) ve isAllowedFactoryMediaUrl konak denetiminden gecer (kendi
// API chat-file yolu + izinli konaklar) — gecemeyen oge ATILIR, yazim durmaz.
// OKUMA (parseFactoryCertificates): DB degeri (JSONB dizi veya JSON string)
// ayni bicime normalize edilir; bozuk/bos ise []. Okumada konak denetimi
// YAPILMAZ (yazarken denetlendi; eski veri geriye uyumlu doner).
function cleanFactoryCertificates(v) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) return undefined;
  const out = [];
  for (const it of v) {
    if (out.length >= 20) break;
    if (!it || typeof it !== 'object' || Array.isArray(it)) continue;
    if (typeof it.title !== 'string' || typeof it.url !== 'string') continue;
    const title = it.title.trim().slice(0, 120);
    const url = it.url.trim();
    if (!title || !url || url.length > 2048) continue;
    if (!isAllowedFactoryMediaUrl(url)) continue;
    out.push({ title, url });
  }
  return out;
}

function parseFactoryCertificates(v) {
  let arr = v;
  if (typeof arr === 'string') { try { arr = JSON.parse(arr); } catch { return []; } }
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const it of arr) {
    if (out.length >= 20) break;
    if (!it || typeof it !== 'object' || Array.isArray(it)) continue;
    if (typeof it.title !== 'string' || typeof it.url !== 'string') continue;
    const title = it.title.trim();
    const url = it.url.trim();
    if (!title || !url) continue;
    out.push({ title, url });
  }
  return out;
}

// videos: [{title?, url, kind, product_description?, attributes?}] — gecersiz oge varsa null (handler 400 doner)
// fix10z: kind 'photo' da gecerli — fotograf gonderisi; url bir resim adresidir,
// ayni konak allowlist denetiminden gecer (asagidaki url satiri tum turler icin ortak).
function cleanFactoryVideos(v) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const it of v) {
    if (!it || typeof it !== 'object' || Array.isArray(it)) return null;
    if (typeof it.url !== 'string' || !isAllowedFactoryMediaUrl(it.url.trim()) || it.url.trim().length > 2048) return null; // fix10e L8: konak allowlist
    if (it.kind !== 'video' && it.kind !== 'canli' && it.kind !== 'photo') return null; // fix10z: 'photo' fotograf gonderisi
    const rec = { title: typeof it.title === 'string' ? it.title.trim().slice(0, 200) : '', description: typeof it.description === 'string' ? it.description.trim().slice(0, 2000) : '' };
    // fix10ab: product_description — yalnizca dizgi ise korunur; trim -> <=2000 (kesilir); bos ise anahtar eklenmez; dizgi degilse atilir (oge yine gecerli)
    if (typeof it.product_description === 'string') { const pd = it.product_description.trim().slice(0, 2000); if (pd) rec.product_description = pd; }
    rec.url = it.url.trim();
    rec.kind = it.kind;
    const attrs = cleanVideoAttributes(it.attributes); // fix10y: ürün özellikleri (yoksa anahtar eklenmez)
    if (attrs) rec.attributes = attrs;
    out.push(rec);
  }
  return out;
}

// GET /api/products/factory/likes?video=F-V — begeni sayisi (herkese acik)
router.get('/factory/likes', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String(req.query.video || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_likes WHERE video_key=$1', [video]);
  res.json({ like_count: rows[0].n });
}));

// GET /api/products/factory/likes/mine — giris yapan kullanicinin begendigi videolar (Profil > Begenilen Videolar)
router.get('/factory/likes/mine', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(
    'SELECT video_key, created_at FROM factory_likes WHERE user_id=$1 ORDER BY created_at DESC, id DESC',
    [req.user.id]
  );
  res.json({ likes: rows });
}));

// POST /api/products/factory/likes {video} — begeni ac/kapa (toggle)
router.post('/factory/likes', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String((req.body && req.body.video) || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows: ex } = await pool.query('SELECT 1 FROM factory_likes WHERE user_id=$1 AND video_key=$2', [req.user.id, video]);
  let liked;
  if (ex.length) {
    await pool.query('DELETE FROM factory_likes WHERE user_id=$1 AND video_key=$2', [req.user.id, video]);
    liked = false;
  } else {
    await pool.query('INSERT INTO factory_likes (user_id, video_key) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, video]);
    liked = true;
  }
  const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_likes WHERE video_key=$1', [video]);
  res.json({ liked, like_count: c[0].n });
}));

// GET /api/products/factory/video-views?ids=F-V,F2-V2 — izlenme sayilari (herkese acik, bilinmeyen video -> 0)
router.get('/factory/video-views', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const ids = String(req.query.ids || '').split(',').map((s) => s.trim()).filter((s) => FACTORY_VIDEO_RE.test(s)).slice(0, 200);
  const out = {};
  for (const id of ids) out[id] = 0;
  if (ids.length) {
    const { rows } = await pool.query('SELECT video, views FROM factory_video_views WHERE video = ANY($1)', [ids]);
    for (const r of rows) out[r.video] = r.views;
  }
  res.json({ views: out });
}));

// CBOs26.4 (fix10h): ulke kodu yalnizca CDN/proxy basliklarindan okunur (CF-IPCountry, X-Country, X-Geo-Country,
// X-Appengine-Country). Baslik yoksa bos doner — IP->ulke eslemesi icin harici GeoIP servisi kullanilmaz, ulke UYDURULMAZ.
function factoryViewCountry(req) {
  const h = (req && req.headers) || {};
  const raw = h['cf-ipcountry'] || h['x-country'] || h['x-geo-country'] || h['x-appengine-country'] || '';
  const code = String(raw).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : '';
}

// POST /api/products/factory/video-view {video} — izlenme +1 (herkese acik, kimlik yok)
router.post('/factory/video-view', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String((req.body && req.body.video) || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows } = await pool.query(
    `INSERT INTO factory_video_views (video, views) VALUES ($1, 1) ON CONFLICT (video) DO UPDATE SET views = factory_video_views.views + 1 RETURNING views`,
    [video]
  );
  // CBOs26.4: olay satiri (gunluk grafik + ulke). Olay yazimi sayaci ASLA bozmaz — hata olursa sessizce yoksayilir.
  try { await pool.query(`INSERT INTO factory_video_view_events (video, country) VALUES ($1, $2)`, [video, factoryViewCountry(req)]); } catch (e) { /* olay kaydi sayaci bozmaz */ }
  res.json({ video, views: rows[0].views });
}));

// CBOs26.7 (fix10j): POST /api/products/factory/page-view {factory_id} — fabrika sayfasi ziyareti +1 (herkese acik, kimlik yok).
// Video-view deseniyle: sayaç + olay satiri. Oturum basina bir kez sayim icin istemci sessionStorage ile tek sefer gonderir;
// sunucu her istegi sayar (tekrar gonderim istemci tarafinda engellenir). Bilinmeyen fabrika -> 404.
router.post('/factory/page-view', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = Number(req.body && req.body.factory_id);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  const { rows: f } = await pool.query('SELECT id FROM factories WHERE id = $1', [fid]);
  if (!f.length) return res.status(404).json({ error: 'factory_not_found' });
  const { rows } = await pool.query(
    `INSERT INTO factory_page_views (factory_id, visits) VALUES ($1, 1) ON CONFLICT (factory_id) DO UPDATE SET visits = factory_page_views.visits + 1 RETURNING visits`,
    [fid]
  );
  try { await pool.query(`INSERT INTO factory_page_view_events (factory_id, country) VALUES ($1, $2)`, [fid, factoryViewCountry(req)]); } catch (e) { /* olay kaydi sayaci bozmaz */ }
  res.json({ factory_id: fid, visits: rows[0].visits });
}));

// CBOs26.72 (fix10ac): POST /api/products/factory/presence {session_id, factory_id?} — cevrimici
// kalp atisi (herkese acik, kimlik yok; page-view deseni). session_id istemcinin urettigi oturum
// kimligidir (8-64 krk guvenli desen); gecerli fabrika KONTROLU yapilmaz (factory_id yalniz bilgi:
// sayim site geneli DISTINCT session'dir, var olmayan fabrika sayimi bozmaz). Temizlik zaman
// kosullu: en fazla dakikada bir, 1 saatten eski satirlar silinir — yaniti ASLA bozmaz.
const FACTORY_SESSION_RE = /^[A-Za-z0-9._-]{8,64}$/;
let factoryPresenceCleanupAt = 0;
router.post('/factory/presence', factoryPresenceLimiter, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const sid = String((req.body && req.body.session_id) || '').trim();
  if (!FACTORY_SESSION_RE.test(sid)) return res.status(400).json({ error: 'invalid_session_id' });
  let fid = null;
  if (req.body && req.body.factory_id !== undefined && req.body.factory_id !== null && req.body.factory_id !== '') {
    fid = Number(req.body.factory_id);
    if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  }
  await pool.query(
    `INSERT INTO factory_presence (session_id, factory_id, last_seen) VALUES ($1, $2, now())
     ON CONFLICT (session_id) DO UPDATE SET last_seen = now(), factory_id = COALESCE(EXCLUDED.factory_id, factory_presence.factory_id)`,
    [sid, fid]
  );
  const nowMs = Date.now();
  if (nowMs - factoryPresenceCleanupAt > 60 * 1000) {
    factoryPresenceCleanupAt = nowMs;
    try { await pool.query(`DELETE FROM factory_presence WHERE last_seen < now() - INTERVAL '1 hour'`); } catch (e) { /* temizlik yaniti bozmaz */ }
  }
  res.json({ ok: true });
}));

// GET /api/products/factory/comments?video=F-V — en yeni 50 yorum (herkese acik)
router.get('/factory/comments', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String(req.query.video || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows } = await pool.query(
    `SELECT c.id, c.body, c.created_at, COALESCE(NULLIF(u.nickname,''), NULLIF(u.name,''), split_part(u.email,'@',1), 'Misafir') AS name
     FROM factory_comments c LEFT JOIN users u ON u.id::text = c.user_id::text
     WHERE c.video_key = $1 ORDER BY c.created_at DESC, c.id DESC LIMIT 50`,
    [video]
  );
  res.json({ comments: rows.map((r) => ({ id: r.id, name: r.name, body: r.body, created_at: r.created_at })) });
}));

// POST /api/products/factory/comments {video, body} — yorum ekle
router.post('/factory/comments', requireAuth, factorySpamLimiter,
  body('video').matches(/^\d+-\d+$/),
  body('body').trim().isLength({ min: 1, max: 1000 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    const me = await pool.query('SELECT is_blocked FROM users WHERE id = $1', [req.user.id]);
    if (me.rows[0]?.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    const video = String(req.body.video);
    const text = String(req.body.body).trim();
    const { rows } = await pool.query(
      `INSERT INTO factory_comments (user_id, video_key, body) VALUES ($1, $2, $3) RETURNING id, body, created_at`,
      [req.user.id, video, text]
    );
    const { rows: urows } = await pool.query('SELECT nickname, name, email FROM users WHERE id = $1', [req.user.id]);
    res.status(201).json({ comment: { id: rows[0].id, name: factoryDisplayName(urows[0]), body: rows[0].body, created_at: rows[0].created_at } });
  })
);

// GET /api/products/factory/favorites/count?video=F-V — favori sayisi (herkese acik)
router.get('/factory/favorites/count', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String(req.query.video || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_favorites WHERE video_key=$1', [video]);
  res.json({ favorite_count: rows[0].n });
}));

// POST /api/products/factory/favorites {video} — favori ac/kapa (toggle, begeni deseniyle ayni)
router.post('/factory/favorites', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const video = String((req.body && req.body.video) || '');
  if (!video) return res.status(400).json({ error: 'video_required' });
  if (!FACTORY_VIDEO_RE.test(video)) return res.status(400).json({ error: 'invalid_video' });
  const { rows: ex } = await pool.query('SELECT 1 FROM factory_favorites WHERE user_id=$1 AND video_key=$2', [req.user.id, video]);
  let favorited;
  if (ex.length) {
    await pool.query('DELETE FROM factory_favorites WHERE user_id=$1 AND video_key=$2', [req.user.id, video]);
    favorited = false;
  } else {
    await pool.query('INSERT INTO factory_favorites (user_id, video_key) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, video]);
    favorited = true;
  }
  const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_favorites WHERE video_key=$1', [video]);
  res.json({ favorited, favorite_count: c[0].n });
}));

// GET /api/products/factory/favorites — giris yapan kullanicinin favori video_key listesi
router.get('/factory/favorites', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query('SELECT video_key FROM factory_favorites WHERE user_id=$1 ORDER BY created_at DESC, id DESC', [req.user.id]);
  res.json({ favorites: rows.map((r) => r.video_key) });
}));


// FAZ 1 — My Factory rotalari: fabrika kendi hesabiyla giris yapar, kendi kaydini duzenler.
// JWT: { factory_id, role: 'factory' }, 7 gun. factory_id HER ZAMAN token'dan alinir;
// govdeden gelen id/factory_id ASLA guvenilmez, token'daki fabrikadan farkliysa 403 doner.
// Yasak alanlar (name, cbf_code, is_verified, is_active) sessizce yoksayilir — degistirilmez.
// Tum hata govdeleri Turkce ve dostcadir; ham hata/stack ASLA sizdirilmaz.

// My Factory kullanici adi baskasinda var mi? (kucuk harfe duyarsiz; excludeId haric tutulur)
async function myFactoryUsernameTaken(username, excludeId) {
  const params = [String(username)];
  let sql = `SELECT id FROM factories WHERE LOWER(myfactory_username) = LOWER($1)`;
  if (excludeId !== undefined && excludeId !== null) { params.push(excludeId); sql += ` AND id <> $2`; }
  const { rows } = await pool.query(sql, params);
  return rows.length > 0;
}

// fix10u (CBOs26.55-A): marka adı normalize — trim + iç boşluklar tek boşluğa iner.
// Çağıran taraf değerin string olduğunu doğrular; sonuç '' ise beyan temizleme sayılır.
function normalizeBrandName(v) {
  return String(v).trim().replace(/\s+/g, ' ');
}

// Marka adı BAŞKA fabrikada beyan edilmiş mi? (normalize edilmiş adla LOWER karşılaştırması;
// excludeId hariç tutulur — myFactoryUsernameTaken deseni)
// fix10x: kontrol artık İKİ kaynağa bakar — factory_brands (asıl kaynak, brand_key) +
// factories.brand_name (göç öncesi/geri uyum). İkisinden birinde çakışma varsa "alınmış"tır.
async function factoryBrandTaken(brandName, excludeId) {
  const key = brandKeyOf(brandName);
  const paramsB = [key];
  let sqlB = `SELECT id FROM factory_brands WHERE brand_key = $1`;
  if (excludeId !== undefined && excludeId !== null) { paramsB.push(excludeId); sqlB += ` AND factory_id <> $2`; }
  sqlB += ` LIMIT 1`;
  try {
    const { rows } = await pool.query(sqlB, paramsB);
    if (rows.length > 0) return true;
  } catch (e) { /* factory_brands yoksa eski sutun kontrolu devrede */ }
  const params = [String(brandName)];
  let sql = `SELECT id FROM factories WHERE LOWER(TRIM(brand_name)) = LOWER($1)`;
  if (excludeId !== undefined && excludeId !== null) { params.push(excludeId); sql += ` AND id <> $2`; }
  sql += ` LIMIT 1`;
  const { rows } = await pool.query(sql, params);
  return rows.length > 0;
}

// fix10x (CBOs26.60-A): brand_key — normalize edilmiş (trim + iç boşluk tek) marka adının
// küçük harf hâli. factory_brands.brand_key bu değerle saklanır; benzersizlik bunun üzerinden.
function brandKeyOf(v) {
  return normalizeBrandName(v).toLowerCase();
}

// Bir fabrikanin markalari (id sirasi = beyan sirasi; ilk marka = birincil marka).
async function factoryBrandsList(factoryId) {
  try {
    const { rows } = await pool.query(
      `SELECT id, factory_id, brand_name, brand_key, trademark_no, trademark_office, declared_at FROM factory_brands WHERE factory_id = $1 ORDER BY id ASC`,
      [factoryId]
    );
    return rows;
  } catch (e) { return []; }
}

// Toplu marka haritasi (factoryRatingsMap deseni; tek sorgu, N+1 yok).
async function factoryBrandsMap(ids) {
  const map = {};
  const list = (ids || []).filter((x) => Number.isInteger(x));
  if (!list.length) return map;
  try {
    const { rows } = await pool.query(
      `SELECT id, factory_id, brand_name, brand_key, trademark_no, trademark_office, declared_at FROM factory_brands WHERE factory_id = ANY($1) ORDER BY factory_id ASC, id ASC`,
      [list]
    );
    for (const b of rows) { (map[b.factory_id] = map[b.factory_id] || []).push(b); }
  } catch (e) { /* tablo yoksa bos harita — serializer eski sutunlara duser */ }
  return map;
}

// Fabrika satirlarina _brands ekler (serializer'lar okur). Hata olursa satirlar aynen doner.
async function attachFactoryBrands(rows) {
  if (!Array.isArray(rows) || !rows.length) return rows;
  const map = await factoryBrandsMap(rows.map((r) => r.id));
  for (const r of rows) { if (r && Number.isInteger(r.id)) r._brands = map[r.id] || []; }
  return rows;
}

// Serializer'larin marka kaynagi: _brands doluysa o; degilse eski factories.brand_*
// kolonlarindan tek elemanli liste (geri uyum). Marka yoksa [].
function factoryBrandsOf(r) {
  if (r && Array.isArray(r._brands) && r._brands.length) return r._brands;
  if (r && r.brand_name) {
    return [{ id: null, brand_name: r.brand_name, trademark_no: r.trademark_no || null, trademark_office: r.trademark_office || null, declared_at: r.trademark_declared_at || null }];
  }
  return [];
}

// Marka satirinin API bicimi (admin/owner + brands uclari). PUBLIC serializer bunu KULLANMAZ.
function brandRowOut(b) {
  return {
    id: b && b.id != null ? b.id : null,
    brand_name: b ? (b.brand_name || null) : null,
    trademark_no: b ? (b.trademark_no || null) : null,
    trademark_office: b ? (b.trademark_office || null) : null,
    declared_at: b ? (b.declared_at || null) : null,
  };
}

// factories.brand_* kolonlarini factory_brands'taki ILK markayla senkron tutar (geri uyum:
// eski okuyucular + fix10u/v davranisi kolonlardan beslenmeye devam eder). Marka yoksa NULL.
async function syncFactoryBrandColumns(factoryId) {
  const brands = await factoryBrandsList(factoryId);
  const first = brands.length ? brands[0] : null;
  await pool.query(
    `UPDATE factories SET brand_name = $2, trademark_no = $3, trademark_office = $4, trademark_declared_at = $5, updated_at = now() WHERE id = $1`,
    [factoryId, first ? first.brand_name : null, first ? (first.trademark_no || null) : null, first ? (first.trademark_office || null) : null, first ? (first.declared_at || null) : null]
  );
}

// Bir fabrikanin marka KUMESINI verilen listeyle atomik degistirir (transaction):
// eskiler silinir, yeniler yazilir, factories kolonlari ilk markayla senkronlanir.
// Benzersizlik ihlali (23505) yukari firlatilir — cagiran 409'a cevirir, transaction geri alinir.
async function replaceFactoryBrands(factoryId, list) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM factory_brands WHERE factory_id = $1`, [factoryId]);
    const out = [];
    for (const b of list) {
      const { rows } = await client.query(
        `INSERT INTO factory_brands (factory_id, brand_name, brand_key, trademark_no, trademark_office) VALUES ($1, $2, $3, $4, $5) RETURNING id, factory_id, brand_name, trademark_no, trademark_office, declared_at`,
        [factoryId, b.brand_name, brandKeyOf(b.brand_name), b.trademark_no || null, b.trademark_office || null]
      );
      out.push(rows[0]);
    }
    const first = out.length ? out[0] : null;
    await client.query(
      `UPDATE factories SET brand_name = $2, trademark_no = $3, trademark_office = $4, trademark_declared_at = $5, updated_at = now() WHERE id = $1`,
      [factoryId, first ? first.brand_name : null, first ? (first.trademark_no || null) : null, first ? (first.trademark_office || null) : null, first ? (first.declared_at || null) : null]
    );
    await client.query('COMMIT');
    return out;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) { /* yoksay */ }
    throw e;
  } finally { client.release(); }
}

// Admin PUT'ta fix10u tekil alanlari yazildiktan SONRA cagrilir: factories kolonlarindaki
// son hâli factory_brands kumesine yansitir (kume tek markaya iner; yalniz no/ofis
// guncellendiyse ilk satirin no/ofisi guncellenir, declared_at korunur).
async function reconcileFactoryBrandsFromColumns(factoryId) {
  const { rows } = await pool.query(`SELECT brand_name, trademark_no, trademark_office, trademark_declared_at FROM factories WHERE id = $1`, [factoryId]);
  if (!rows.length) return;
  const f = rows[0];
  const existing = await factoryBrandsList(factoryId);
  if (!f.brand_name) {
    if (existing.length) await pool.query(`DELETE FROM factory_brands WHERE factory_id = $1`, [factoryId]);
    return;
  }
  const key = brandKeyOf(f.brand_name);
  const keep = existing.find((b) => b.brand_key === key) || null;
  if (keep) {
    await pool.query(`UPDATE factory_brands SET trademark_no = $2, trademark_office = $3 WHERE id = $1`, [keep.id, f.trademark_no || null, f.trademark_office || null]);
    await pool.query(`DELETE FROM factory_brands WHERE factory_id = $1 AND id <> $2`, [factoryId, keep.id]);
  } else {
    await pool.query(`DELETE FROM factory_brands WHERE factory_id = $1`, [factoryId]);
    await pool.query(
      `INSERT INTO factory_brands (factory_id, brand_name, brand_key, trademark_no, trademark_office, declared_at) VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()))`,
      [factoryId, normalizeBrandName(f.brand_name), key, f.trademark_no || null, f.trademark_office || null, f.trademark_declared_at || null]
    );
  }
}

// fix10x: marka uclarinin hedef fabrika cozumu — PUT /factory/myfactory/brand ile birebir:
// master → gövde/query factory_id ZORUNLU (yoksa 400 master_factory_id_required; ikisi
// dolu ve farklıysa 400 factory_id_mismatch); fabrika → gövde/sorgudaki farklı factory_id
// 403, hedef = req.factoryId. Hata durumunda yaniti yazar ve null doner.
function resolveBrandTargetFactoryId(req, res) {
  const body = req.body || {};
  if (req.isMaster) {
    const fromBody = body.factory_id;
    const fromQuery = req.query.factory_id;
    const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
    const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
    if (!hasBody && !hasQuery) { res.status(400).json({ error: 'master_factory_id_required', message: 'Master düzenlemesi için factory_id gerekli.' }); return null; }
    if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) {
      res.status(400).json({ error: 'factory_id_mismatch', message: 'Gövde ve sorgudaki factory_id aynı olmalı.' });
      return null;
    }
    const targetFactoryId = Number(String(hasBody ? fromBody : fromQuery).trim());
    if (!Number.isInteger(targetFactoryId) || targetFactoryId < 1) { res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimliği geçerli değil.' }); return null; }
    return targetFactoryId;
  }
  for (const key of ['id', 'factory_id']) {
    if (body[key] !== undefined && body[key] !== null && body[key] !== '' && Number(body[key]) !== req.factoryId) {
      res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
      return null;
    }
  }
  const qf = req.query.factory_id;
  if (qf !== undefined && qf !== null && String(qf).trim() !== '' && Number(String(qf).trim()) !== req.factoryId) {
    res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
    return null;
  }
  return req.factoryId;
}

// Fabrika JWT dogrulamasi: Bearer token + role === 'factory' + tamsayi factory_id.
// Token yok/bozuk/suresi dolmus => 401; gecerli ama fabrika rolu degil => 403.
function requireFactoryAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized', message: 'Giriş gerekli. Lütfen ChinaBazaar My Factory hesabınızla giriş yapın.' });
  let payload;
  try { payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms }); } catch { return res.status(401).json({ error: 'invalid_token', message: 'Oturumunuz geçersiz veya süresi dolmuş. Lütfen tekrar giriş yapın.' }); }
  if (!payload || payload.role !== 'factory' || !Number.isInteger(payload.factory_id)) return res.status(403).json({ error: 'forbidden', message: 'Bu işlem için fabrika hesabı gerekli.' });
  req.factoryId = payload.factory_id;
  next();
}

// fix10c: chat-upload kullanici JWT'si VEYA ChinaBazaar My Factory (fabrika) JWT'sini kabul eder.
// Kullanici jetonu (sub) => req.user; fabrika jetonu (role 'factory') => req.factoryId.
// Jeton yok/bozuk => 401; ne kullanici ne fabrika jetonu => 401. Admin erisimi aynen kalir
// (yonetici jetonu bir kullanici jetonudur). Normal kullanici jetonu chat-upload'i kullanmaya
// DEVAM EDER (CBAI sohbet dosya yukleme) — fix10c yalnizca fabrika erisimini EKLER,
// mevcut hicbir erisimi kapatmaz.
function requireUserOrFactoryAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized', message: 'Giriş gerekli.' });
  let payload;
  try { payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms }); } catch { return res.status(401).json({ error: 'invalid_token', message: 'Oturumunuz geçersiz veya süresi dolmuş. Lütfen tekrar giriş yapın.' }); }
  if (payload && payload.role === 'factory' && Number.isInteger(payload.factory_id)) { req.factoryId = payload.factory_id; return next(); }
  if (payload && payload.role === 'master' && payload.is_admin === true) { req.isMaster = true; req.user = { id: 'cbai', email: null, role: 'master' }; return next(); }
  if (payload && payload.sub) { req.user = { id: payload.sub, email: payload.email, role: payload.role || 'user' }; return next(); }
  return res.status(401).json({ error: 'unauthorized', message: 'Giriş gerekli.' });
}

// fix10d — CBAI master + çoklu tanımlayıcılı giriş yardımcıları.
// identifier "cbai" (büyük-küçük duyarsız) REZERVE: fabrika araması yapılmaz.
function isCbaiIdentifier(v) {
  return typeof v === 'string' && v.trim().toLowerCase() === 'cbai';
}
// CBAI master şifresi YALNIZCA Railway env'den okunur (kodda/DB'de/testte ASLA yok).
function cbaiMasterConfigured() {
  return !!(process.env.CBAI_MASTER_PASSWORD || '');
}
// Timing-safe karşılaştırma — uzunluk erken dönüşü YOK (fix10e L1):
// iki değer de SHA-256 özetine indirgenir, karşılaştırma özetler üzerinde.
function cbaiMasterPasswordOk(password) {
  const expected = process.env.CBAI_MASTER_PASSWORD || '';
  if (!expected || typeof password !== 'string' || !password) return false;
  const a = crypto.createHash('sha256').update(password).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}
// fix10e H-E: sub='cbai' + jti, süre 7 gün -> 1 gün, HS256 açık.
function signMasterToken() {
  return jwt.sign({ sub: 'cbai', role: 'master', is_admin: true, jti: crypto.randomUUID() }, cfg.jwtSecret, { expiresIn: '1d', algorithm: 'HS256' });
}
// CBF tanımlayıcı normalizasyonu: "CBF-001" / "cbf001" / "cbf-001" → "CBF-001".
// Eşleşmezse '' (CBF koşulu sorguya eklenmez).
function normalizeMyFactoryCbfIdentifier(v) {
  if (typeof v !== 'string') return '';
  const t = v.trim().toUpperCase().replace(/[\s-]/g, '');
  const m = /^CBF(\d+)$/.exec(t);
  if (!m) return '';
  return 'CBF-' + String(parseInt(m[1], 10)).padStart(3, '0');
}
// Telefon varyantları: girilen + kayıtlı AYNI normalize edilir — önce ulusal numaraya
// indirgenir (+90 / 90 / 0 önekleri soyulur), sonra TÜM önek biçimleri aday olur.
function myFactoryPhoneCandidates(identifier) {
  const raw = String(identifier || '').replace(/[\s\-().]/g, '');
  if (!raw) return [];
  let national = raw;
  if (raw.startsWith('+90')) national = raw.slice(3);
  else if (raw.startsWith('90') && raw.length >= 11) national = raw.slice(2);
  else if (raw.startsWith('0')) national = raw.slice(1);
  const out = new Set([national, '0' + national, '90' + national, '+90' + national, raw]);
  return [...out];
}

// fix10d — fabrika VEYA CBAI master JWT'sini kabul eder (me + profile).
// Fabrika: role 'factory' + tamsayi factory_id → req.factoryId.
// Master: role 'master' + is_admin true → req.isMaster = true (factory_id YOK).
// Token yok/bozuk/süresi dolmuş => 401; geçerli ama ne fabrika ne master => 403.
function requireFactoryOrMasterAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized', message: 'Giriş gerekli. Lütfen ChinaBazaar My Factory hesabınızla giriş yapın.' });
  let payload;
  try { payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms }); } catch { return res.status(401).json({ error: 'invalid_token', message: 'Oturumunuz geçersiz veya süresi dolmuş. Lütfen tekrar giriş yapın.' }); }
  if (payload && payload.role === 'master' && payload.is_admin === true) { req.isMaster = true; return next(); }
  if (payload && payload.role === 'factory' && Number.isInteger(payload.factory_id)) { req.factoryId = payload.factory_id; return next(); }
  return res.status(403).json({ error: 'forbidden', message: 'Bu işlem için fabrika hesabı gerekli.' });
}

// POST /api/products/factory/myfactory/login { username, password } → { token, factory }
// Basarisiz giris (kullanici yok / sifre yanlis / sifre tanimli degil) => 401, ayirt edici bilgi verilmez.
// fix10d — çoklu tanımlayıcı: identifier = myfactory_username / e-posta / telefon / cbf_code
// (CBF-001 veya cbf001 → normalize "CBF-001"). Tam bir fabrikaya çözümlenmeli; sıfır
// veya birden fazla eşleşme (belirsiz/çakışma) → 401, ayırt edici bilgi verilmez.
// fix10d — identifier "cbai" rezerve: fabrika araması yapılmaz, master akışı çalışır.
// fix10e L2: env ayarlı değilse de jenerik 401 (master_not_configured yok).
// fix10e M1: tanıtan-bazlı limit (loginIdentifierLimiter) + IP limiti aynen.
router.post('/factory/myfactory/login', loginLimiter, loginIdentifierLimiter, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const identifier = typeof (req.body && (req.body.identifier ?? req.body.username)) === 'string' ? String(req.body.identifier ?? req.body.username).trim() : '';
  const password = req.body && req.body.password;
  if (!identifier || typeof password !== 'string' || !password) return res.status(401).json({ error: 'invalid_credentials', message: 'Kullanıcı adı veya şifre hatalı.' });
  // CBAI master (rezerve) — fabrika araması YAPILMAZ.
  if (isCbaiIdentifier(identifier)) {
    if (!cbaiMasterConfigured() || !cbaiMasterPasswordOk(password)) {
      await bcrypt.compare(password, MYFACTORY_DUMMY_HASH);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Kullanıcı adı veya şifre hatalı.' });
    }
    await logMasterAudit('master_login', 'factory', null);
    return res.json({ token: signMasterToken(), master: true });
  }
  const cbf = normalizeMyFactoryCbfIdentifier(identifier);
  const phoneCands = myFactoryPhoneCandidates(identifier);
  const conds = ['LOWER(myfactory_username) = LOWER($1)', 'LOWER(email) = LOWER($1)'];
  const params = [identifier];
  if (phoneCands.length) { params.push(phoneCands); conds.push(`REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($${params.length})`); }
  if (cbf) { params.push(cbf); conds.push(`UPPER(TRIM(cbf_code)) = $${params.length}`); }
  const { rows } = await pool.query(`SELECT * FROM factories WHERE ${conds.join(' OR ')}`, params);
  // Aynı satır birden çok tanımlayıcıyla eşleşmiş olabilir — fabrikaya göre tekilleştir.
  const byId = new Map();
  for (const r of rows) { if (!byId.has(r.id)) byId.set(r.id, r); }
  const matched = [...byId.values()];
  if (matched.length !== 1) { await bcrypt.compare(password, MYFACTORY_DUMMY_HASH); return res.status(401).json({ error: 'invalid_credentials', message: 'Kullanıcı adı veya şifre hatalı.' }); }
  const row = matched[0];
  const ok = await bcrypt.compare(password, row && row.myfactory_password_hash ? row.myfactory_password_hash : MYFACTORY_DUMMY_HASH);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials', message: 'Kullanıcı adı veya şifre hatalı.' });
  const token = jwt.sign({ factory_id: row.id, role: 'factory' }, cfg.jwtSecret, { expiresIn: '7d', algorithm: 'HS256' });
  await attachFactoryBrands([row]); // fix10x
  res.json({ token, factory: toFactoryMyFactory(row) });
}));

// GET /api/products/factory/myfactory/me — kendi fabrikasının TAM kaydı (hash ASLA yok).
// fix10d — fabrika tokenı → kendi kaydı (?factory_id farklıysa 403, izolasyon).
// Master tokenı → ?factory_id=X varsa o fabrikanın TAM kaydı; yoksa
// {master:true, factories:[{id,name,cbf_code}]} (seçici için).
router.get('/factory/myfactory/me', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  if (req.isMaster) {
    const q = req.query.factory_id;
    if (q !== undefined && q !== null && String(q).trim() !== '') {
      const fid = Number(String(q).trim());
      if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimliği geçerli değil.' });
      const { rows } = await pool.query('SELECT * FROM factories WHERE id = $1', [fid]);
      if (!rows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
      await attachFactoryBrands(rows); // fix10x
      return res.json(toFactoryMyFactory(rows[0]));
    }
    const { rows } = await pool.query('SELECT id, name, cbf_code FROM factories ORDER BY id ASC');
    return res.json({ master: true, factories: rows.map((r) => ({ id: r.id, name: r.name, cbf_code: r.cbf_code || '' })) });
  }
  // Fabrika tokenı: ?factory_id token'daki fabrikadan farklıysa 403 (izolasyon).
  const q = req.query.factory_id;
  if (q !== undefined && q !== null && String(q).trim() !== '' && Number(String(q).trim()) !== req.factoryId) {
    return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı görebilirsiniz.' });
  }
  const { rows } = await pool.query('SELECT * FROM factories WHERE id = $1', [req.factoryId]);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  await attachFactoryBrands(rows); // fix10x
  res.json(toFactoryMyFactory(rows[0]));
}));

// PUT /api/products/factory/myfactory/profile — SADECE kendi fabrikasini gunceller.
// Duzenlenebilir: name (fix10af — yalniz string, trim sonrasi 2-120 krk; baska turlu sessizce
// atlanir), desc, city, category, main_products, certs, features, hashtags, tags,
// address, phone, contact, wechat, whatsapp, email, import_countries, employees,
// annual_revenue, factory_area, years, socials, cover_image, videos, certificates (fix10ae).
// YASAK (sessizce yoksayilir): cbf_code, is_verified, is_active (+ moq/stock/capacity).
// fix10d — master: factory_id gövdede/query'de ZORUNLU (yoksa 400), master her fabrikayı
// düzenler. Fabrika tokenı: yalnızca kendi fabrikası (gövdedeki/sorgudaki farklı factory_id → 403).
router.put('/factory/myfactory/profile', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const body = req.body || {};
  // Hedef fabrika: master → gövde/query factory_id (ZORUNLU); fabrika → token'daki fabrika.
  let targetFactoryId;
  if (req.isMaster) {
    const fromBody = body.factory_id;
    const fromQuery = req.query.factory_id;
    const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
    const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
    if (!hasBody && !hasQuery) return res.status(400).json({ error: 'factory_id_required', message: 'Master düzenlemesi için factory_id gerekli.' });
    if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) {
      return res.status(400).json({ error: 'factory_id_mismatch', message: 'Gövde ve sorgudaki factory_id aynı olmalı.' });
    }
    targetFactoryId = Number(String(hasBody ? fromBody : fromQuery).trim());
    if (!Number.isInteger(targetFactoryId) || targetFactoryId < 1) return res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimliği geçerli değil.' });
  } else {
    // Govdeden gelen id ASLA guvenilmez: token'daki fabrikadan farkliysa 403.
    for (const key of ['id', 'factory_id']) {
      if (body[key] !== undefined && body[key] !== null && body[key] !== '' && Number(body[key]) !== req.factoryId) {
        return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
      }
    }
    // Sorgudaki factory_id de token'daki fabrikadan farklıysa 403 (izolasyon).
    const qf = req.query.factory_id;
    if (qf !== undefined && qf !== null && String(qf).trim() !== '' && Number(String(qf).trim()) !== req.factoryId) {
      return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
    }
    targetFactoryId = req.factoryId;
  }
  const sets = [];
  const params = [targetFactoryId];
  const push = (col, val, cast) => { params.push(val); sets.push(`${col} = $${params.length}${cast || ''}`); };
  const bad = (code, message) => res.status(400).json({ error: code, message });
  // fix10af — sirket adi (name): yalniz string kabul edilir; trim sonrasi 2-120 krk
  // arasindaysa guncellenir. Bos / 1 krk / 120'den uzun / string olmayan deger
  // sessizce atlanir (diger alanlar islenmeye devam eder).
  if (typeof body.name === 'string') {
    const factoryName = body.name.trim();
    if (factoryName.length >= 2 && factoryName.length <= 120) push('name', factoryName);
  }
  // desc / description: ikisi de kabul edilir, desc onceliklidir.
  if (body.desc !== undefined || body.description !== undefined) {
    const c = cleanFactoryText(body.desc !== undefined ? body.desc : body.description, 10000);
    if (c === null) return bad('invalid_description', 'Açıklama geçerli değil.');
    push('description', c);
  }
  if (body.city !== undefined) { const c = cleanFactoryText(body.city, 200); if (c === null) return bad('invalid_city', 'Şehir geçerli değil.'); push('city', c); }
  if (body.category !== undefined) { const c = cleanFactoryText(body.category, 200); if (c === null) return bad('invalid_category', 'Kategori geçerli değil.'); push('category', c); }
  if (body.main_products !== undefined) { const c = cleanFactoryTags(body.main_products); if (c === null) return bad('invalid_main_products', 'Ana ürünler geçerli değil.'); push('main_products', c); }
  if (body.certs !== undefined) { const c = cleanFactoryTags(body.certs); if (c === null) return bad('invalid_certs', 'Sertifikalar geçerli değil.'); push('certs', c); }
  if (body.features !== undefined) { const c = cleanFactoryTags(body.features); if (c === null) return bad('invalid_features', 'Özellikler geçerli değil.'); push('features', c); }
  if (body.hashtags !== undefined) { const c = cleanFactoryHashtags(body.hashtags); if (c === null) return bad('invalid_hashtags', 'Etiketler geçerli değil.'); push('hashtags', c); }
  if (body.tags !== undefined) { const c = cleanFactoryTags(body.tags); if (c === null) return bad('invalid_tags', 'Etiketler geçerli değil.'); push('tags', c); }
  if (body.address !== undefined) { const c = cleanFactoryText(body.address, 500); if (c === null) return bad('invalid_address', 'Adres geçerli değil.'); push('address', c); }
  if (body.phone !== undefined) { const c = cleanFactoryText(body.phone, 200); if (c === null) return bad('invalid_phone', 'Telefon geçerli değil.'); if (c !== '' && await factoryContactTaken('phone', c, targetFactoryId)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu telefon başka bir fabrikada kullanılıyor.' }); push('phone', c); } // fix10e M6
  if (body.contact !== undefined) { const c = cleanFactoryText(body.contact, 200); if (c === null) return bad('invalid_contact', 'İlgili kişi geçerli değil.'); push('contact', c); }
  if (body.wechat !== undefined) { const c = cleanFactoryText(body.wechat, 200); if (c === null) return bad('invalid_wechat', 'WeChat geçerli değil.'); push('wechat', c); }
  if (body.whatsapp !== undefined) { const c = cleanFactoryText(body.whatsapp, 200); if (c === null) return bad('invalid_whatsapp', 'WhatsApp geçerli değil.'); push('whatsapp', c); }
  if (body.email !== undefined) { const c = cleanFactoryEmail(body.email); if (c === null) return bad('invalid_email', 'E-posta adresi geçerli değil.'); if (c !== '' && await factoryContactTaken('email', c, targetFactoryId)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu e-posta başka bir fabrikada kullanılıyor.' }); push('email', c === '' ? null : c); } // fix10e M6
  if (body.import_countries !== undefined) { const c = cleanFactoryTags(body.import_countries); if (c === null) return bad('invalid_import_countries', 'İthalat ülkeleri geçerli değil.'); push('import_countries', c); }
  if (body.employees !== undefined) { const c = cleanFactoryText(body.employees, 2000); if (c === null) return bad('invalid_employees', 'Çalışan sayısı geçerli değil.'); push('employees', c); }
  if (body.annual_revenue !== undefined) { const c = cleanFactoryText(body.annual_revenue, 2000); if (c === null) return bad('invalid_annual_revenue', 'Yıllık ciro geçerli değil.'); push('annual_revenue', c); }
  if (body.factory_area !== undefined) { const c = cleanFactoryText(body.factory_area, 2000); if (c === null) return bad('invalid_factory_area', 'Fabrika alanı geçerli değil.'); push('factory_area', c); }
  if (body.years !== undefined) { const c = cleanFactoryText(body.years, 2000); if (c === null) return bad('invalid_years', 'Deneyim yılı geçerli değil.'); push('years', c); }
  if (body.socials !== undefined) { const c = cleanFactorySocials(body.socials); if (c === null) return bad('invalid_socials', 'Sosyal medya bağlantıları geçerli değil.'); push('socials', JSON.stringify(c), '::jsonb'); }
  if (body.cover_image !== undefined) { const c = cleanFactoryCoverImage(body.cover_image); if (c === null) return bad('invalid_cover_image', 'Kapak görseli geçerli bir bağlantı olmalı.'); push('cover_image', c); }
  if (body.videos !== undefined) { const c = cleanFactoryVideos(body.videos); if (c === null) return bad('invalid_videos', 'Videolar geçerli değil.'); push('videos', JSON.stringify(c), '::jsonb'); }
  // fix10ae: sertifikalar TOPTAN yazilir — dizi degilse cleaner undefined doner (sessizce yok sayilir).
  if (body.certificates !== undefined) { const c = cleanFactoryCertificates(body.certificates); if (c !== undefined) push('certificates', JSON.stringify(c), '::jsonb'); }
  if (!sets.length) return bad('nothing_to_update', 'Güncellenecek bir alan gönderilmedi.');
  sets.push('updated_at = now()');
  const { rows } = await pool.query(`UPDATE factories SET ${sets.join(', ')} WHERE id = $1 RETURNING *`, params);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  if (req.isMaster) await logMasterAudit('factory_profile_update', 'factory', targetFactoryId); // fix10e H-E
  await attachFactoryBrands(rows); // fix10x
  res.json(toFactoryMyFactory(rows[0]));
}));

// CBOs26.37-A (fix10s) — fabrika giris kimlik bilgisi degistirme rotasi (PUT, "credentials" ucu).
// Gövde {username?, password?}. Düzenlenebilir: myfactory_username, myfactory_password_hash (şifre bcrypt(12) ile
// hash'lenerek saklanır; hash ASLA yanıt dönmez). Hedef fabrika çözümü profile rotasıyla BİREBİR aynı:
// master → gövde/query factory_id ZORUNLU (yoksa 400 factory_id_required; ikisi dolu ve farklıysa 400
// factory_id_mismatch); fabrika → gövde/query'deki farklı factory_id 403, hedef = req.factoryId.
// updated_at HER ZAMAN güncellenir (admin "son güncelleme"yi görür). Yanıt: { username }.
router.put('/factory/myfactory/credentials', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const body = req.body || {};
  // Hedef fabrika: master → gövde/query factory_id (ZORUNLU); fabrika → token'daki fabrika.
  let targetFactoryId;
  if (req.isMaster) {
    const fromBody = body.factory_id;
    const fromQuery = req.query.factory_id;
    const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
    const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
    if (!hasBody && !hasQuery) return res.status(400).json({ error: 'factory_id_required', message: 'Master düzenlemesi için factory_id gerekli.' });
    if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) {
      return res.status(400).json({ error: 'factory_id_mismatch', message: 'Gövde ve sorgudaki factory_id aynı olmalı.' });
    }
    targetFactoryId = Number(String(hasBody ? fromBody : fromQuery).trim());
    if (!Number.isInteger(targetFactoryId) || targetFactoryId < 1) return res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimliği geçerli değil.' });
  } else {
    // Govdeden gelen id ASLA guvenilmez: token'daki fabrikadan farkliysa 403.
    for (const key of ['id', 'factory_id']) {
      if (body[key] !== undefined && body[key] !== null && body[key] !== '' && Number(body[key]) !== req.factoryId) {
        return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
      }
    }
    // Sorgudaki factory_id de token'daki fabrikadan farklıysa 403 (izolasyon).
    const qf = req.query.factory_id;
    if (qf !== undefined && qf !== null && String(qf).trim() !== '' && Number(String(qf).trim()) !== req.factoryId) {
      return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
    }
    targetFactoryId = req.factoryId;
  }
  const hasUsername = body.username !== undefined;
  const hasPassword = body.password !== undefined;
  if (!hasUsername && !hasPassword) return res.status(400).json({ error: 'nothing_to_update', message: 'Güncellenecek bir alan gönderilmedi.' });
  const sets = [];
  const params = [targetFactoryId];
  const bad = (code, message) => res.status(400).json({ error: code, message });
  if (hasUsername) {
    const clean = cleanMyFactoryUsername(body.username);
    // null (geçersiz) veya '' (boş — fabrika kullanıcı adını silemez) → 400.
    if (clean === null || clean === '') return bad('invalid_myfactory_username', 'Kullanıcı adı 3-50 karakter olmalı; harf, rakam, nokta, alt çizgi, tire.');
    if (await myFactoryUsernameTaken(clean, targetFactoryId)) {
      return res.status(409).json({ error: 'myfactory_username_taken', message: 'Bu kullanıcı adı başka bir fabrikada kullanılıyor.' });
    }
    params.push(clean);
    sets.push(`myfactory_username = $${params.length}`);
  }
  if (hasPassword) {
    const pw = body.password;
    if (typeof pw !== 'string' || pw.length < 6 || pw.length > 100) {
      return bad('invalid_myfactory_password', 'Şifre en az 6 karakter olmalı.');
    }
    params.push(await bcrypt.hash(pw, 12));
    sets.push(`myfactory_password_hash = $${params.length}`);
  }
  sets.push('updated_at = now()');
  const { rows } = await pool.query(`UPDATE factories SET ${sets.join(', ')} WHERE id = $1 RETURNING myfactory_username`, params);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  if (req.isMaster) await logMasterAudit('factory_credentials_update', 'factory', targetFactoryId);
  res.json({ username: rows[0].myfactory_username || null });
}));

// CBOs26.39 (fix10t) — GET /api/products/factory/myfactory/username-available?u=<name>
// Paneldeki "Kullanıcı Adı Değiştir" formunda ANLIK uygunluk göstergesi için. requireFactoryOrMasterAuth.
// Yanıt: { available: true|false }. Format geçersiz (veya 'cbai' rezerve) ise 400 invalid_myfactory_username.
// Benzersizlik LOWER karşılaştırmasıyla (myFactoryUsernameTaken deseni); fabrikanın KENDİ mevcut
// kullanıcı adı "kullanılabilir" sayılır (excludeId = token'daki fabrika; master ?factory_id= verirse o fabrika).
router.get('/factory/myfactory/username-available', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const raw = req.query.u;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return res.status(400).json({ error: 'username_required', message: 'Kullanıcı adı gerekli.' });
  }
  const clean = cleanMyFactoryUsername(String(raw));
  if (clean === null || clean === '') {
    return res.status(400).json({ error: 'invalid_myfactory_username', message: 'Kullanıcı adı 3-50 karakter olmalı; harf, rakam, nokta, alt çizgi, tire.' });
  }
  let excludeId = null;
  if (req.isMaster) {
    const qf = req.query.factory_id;
    if (qf !== undefined && qf !== null && String(qf).trim() !== '') {
      const n = Number(String(qf).trim());
      if (Number.isInteger(n) && n >= 1) excludeId = n;
    }
  } else {
    excludeId = req.factoryId;
  }
  const taken = await myFactoryUsernameTaken(clean, excludeId);
  res.json({ available: !taken });
}));

// CBOs26.55-A (fix10u) — PUT /api/products/factory/myfactory/brand
// Fabrika MARKA TESCİLİ beyanı. Gövde { brand_name?, trademark_no?, trademark_office? }.
// Hedef fabrika çözümü credentials rotasıyla aynı: master → gövde/query factory_id ZORUNLU
// (yoksa 400 master_factory_id_required; ikisi dolu ve farklıysa 400 factory_id_mismatch);
// fabrika → gövde/query'deki farklı factory_id 403, hedef = req.factoryId.
// brand_name BOŞSA beyan temizlenir (üç alan + trademark_declared_at NULL). Doluysa: normalize
// (trim + iç boşluklar tek boşluk), en çok 120 karakter; BAŞKA fabrikada aynı normalize ad
// (LOWER karşılaştırması) varsa 409 brand_taken. Kayıtta trademark_declared_at = now().
// trademark_no / trademark_office en çok 100 karaktere kırpılır. Yanıt yalnız brand alanları.
// fix10x (CBOs26.60-A): yazma factory_brands kümesine yapılır — bu uç kümenin tamamını
// gövdedeki tek markayla değiştirir (boş = tamamını temizler); factories kolonları ilk
// markayla senkronlanır, yanıt sözleşmesi birebir aynıdır.
router.put('/factory/myfactory/brand', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const body = req.body || {};
  // Hedef fabrika: master → gövde/query factory_id (ZORUNLU); fabrika → token'daki fabrika.
  let targetFactoryId;
  if (req.isMaster) {
    const fromBody = body.factory_id;
    const fromQuery = req.query.factory_id;
    const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
    const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
    if (!hasBody && !hasQuery) return res.status(400).json({ error: 'master_factory_id_required', message: 'Master düzenlemesi için factory_id gerekli.' });
    if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) {
      return res.status(400).json({ error: 'factory_id_mismatch', message: 'Gövde ve sorgudaki factory_id aynı olmalı.' });
    }
    targetFactoryId = Number(String(hasBody ? fromBody : fromQuery).trim());
    if (!Number.isInteger(targetFactoryId) || targetFactoryId < 1) return res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimliği geçerli değil.' });
  } else {
    // Gövdeden gelen id ASLA güvenilmez: token'daki fabrikadan farklıysa 403.
    for (const key of ['id', 'factory_id']) {
      if (body[key] !== undefined && body[key] !== null && body[key] !== '' && Number(body[key]) !== req.factoryId) {
        return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
      }
    }
    // Sorgudaki factory_id de token'daki fabrikadan farklıysa 403 (izolasyon).
    const qf = req.query.factory_id;
    if (qf !== undefined && qf !== null && String(qf).trim() !== '' && Number(String(qf).trim()) !== req.factoryId) {
      return res.status(403).json({ error: 'forbidden', message: 'Yalnız kendi fabrika kaydınızı düzenleyebilirsiniz.' });
    }
    targetFactoryId = req.factoryId;
  }
  // Marka adı: string değilse 400; boş/undefined ise beyan temizlenir.
  if (body.brand_name !== undefined && body.brand_name !== null && typeof body.brand_name !== 'string') {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı geçerli bir metin olmalı.' });
  }
  const brandClean = (body.brand_name === undefined || body.brand_name === null) ? '' : normalizeBrandName(body.brand_name);
  // fix10x: yazma artık factories kolonlarına değil factory_brands KÜMESİNE yapılır; bu uç
  // geri uyumlu tek-marka sözleşmesini korur: gövdedeki tek marka kümenin tamamı olur,
  // boş marka kümenin tamamını temizler. Kolonlar replaceFactoryBrands içinde senkronlanır.
  const { rows: targetRows } = await pool.query(`SELECT id FROM factories WHERE id = $1`, [targetFactoryId]);
  if (!targetRows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  if (!brandClean) {
    await replaceFactoryBrands(targetFactoryId, []);
    if (req.isMaster) await logMasterAudit('factory_brand_update', 'factory', targetFactoryId);
    return res.json({ brand_name: null, trademark_no: null, trademark_office: null, trademark_declared_at: null });
  }
  if (brandClean.length > 120) {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı en çok 120 karakter olabilir.' });
  }
  if (await factoryBrandTaken(brandClean, targetFactoryId)) {
    return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
  }
  const trademarkNo = typeof body.trademark_no === 'string' ? body.trademark_no.trim().slice(0, 100) : '';
  const trademarkOffice = typeof body.trademark_office === 'string' ? body.trademark_office.trim().slice(0, 100) : '';
  let savedBrands;
  try {
    savedBrands = await replaceFactoryBrands(targetFactoryId, [{ brand_name: brandClean, trademark_no: trademarkNo === '' ? null : trademarkNo, trademark_office: trademarkOffice === '' ? null : trademarkOffice }]);
  } catch (e) {
    if (e && e.code === '23505') return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
    throw e;
  }
  if (req.isMaster) await logMasterAudit('factory_brand_update', 'factory', targetFactoryId);
  const r = savedBrands[0];
  res.json({ brand_name: r.brand_name || null, trademark_no: r.trademark_no || null, trademark_office: r.trademark_office || null, trademark_declared_at: r.declared_at || null });
}));

// CBOs26.60-A (fix10x) — GET /api/products/factory/myfactory/brands
// Fabrikanın TÜM markaları (id sırası = beyan sırası). Hedef fabrika çözümü PUT brand ile
// aynı (fabrika → kendi; master → factory_id ZORUNLU). Yanıt { brands: [brandRowOut] }.
router.get('/factory/myfactory/brands', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const targetFactoryId = resolveBrandTargetFactoryId(req, res);
  if (targetFactoryId === null) return;
  const { rows: frows } = await pool.query(`SELECT id FROM factories WHERE id = $1`, [targetFactoryId]);
  if (!frows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  const brands = await factoryBrandsList(targetFactoryId);
  res.json({ brands: brands.map(brandRowOut) });
}));

// CBOs26.60-A (fix10x) — POST /api/products/factory/myfactory/brands
// Yeni marka EKLEr (küme büyütebilir). Gövde { brand_name*, trademark_no?, trademark_office? }.
// Doğrulama fix10u ile aynı: normalize (trim + iç boşluk tek), ad en çok 120, no/ofis en çok
// 100 karaktere kırpılır. Kendi fabrikasında aynı brand_key → 409 brand_exists; başka
// fabrikada → 409 brand_taken. Başarı: 201 { brand }.
router.post('/factory/myfactory/brands', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const targetFactoryId = resolveBrandTargetFactoryId(req, res);
  if (targetFactoryId === null) return;
  const body = req.body || {};
  const { rows: frows } = await pool.query(`SELECT id FROM factories WHERE id = $1`, [targetFactoryId]);
  if (!frows.length) return res.status(404).json({ error: 'factory_not_found', message: 'Fabrika bulunamadı.' });
  if (body.brand_name === undefined || body.brand_name === null) {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı gerekli.' });
  }
  if (typeof body.brand_name !== 'string') {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı geçerli bir metin olmalı.' });
  }
  const brandClean = normalizeBrandName(body.brand_name);
  if (!brandClean) {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı gerekli.' });
  }
  if (brandClean.length > 120) {
    return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı en çok 120 karakter olabilir.' });
  }
  const key = brandKeyOf(brandClean);
  const { rows: ownRows } = await pool.query(`SELECT id FROM factory_brands WHERE factory_id = $1 AND brand_key = $2 LIMIT 1`, [targetFactoryId, key]);
  if (ownRows.length) {
    return res.status(409).json({ error: 'brand_exists', message: 'Bu marka fabrikanızda zaten beyan edilmiş.' });
  }
  if (await factoryBrandTaken(brandClean, targetFactoryId)) {
    return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
  }
  const trademarkNo = typeof body.trademark_no === 'string' ? body.trademark_no.trim().slice(0, 100) : '';
  const trademarkOffice = typeof body.trademark_office === 'string' ? body.trademark_office.trim().slice(0, 100) : '';
  let inserted;
  try {
    const { rows } = await pool.query(
      `INSERT INTO factory_brands (factory_id, brand_name, brand_key, trademark_no, trademark_office) VALUES ($1, $2, $3, $4, $5) RETURNING id, factory_id, brand_name, trademark_no, trademark_office, declared_at`,
      [targetFactoryId, brandClean, key, trademarkNo === '' ? null : trademarkNo, trademarkOffice === '' ? null : trademarkOffice]
    );
    inserted = rows[0];
  } catch (e) {
    if (e && e.code === '23505') {
      // Yarış: arada aynı anahtar yazıldıysa sahibi kim — kendimizse brand_exists, değilse brand_taken.
      const { rows: ownerRows } = await pool.query(`SELECT factory_id FROM factory_brands WHERE brand_key = $1 LIMIT 1`, [key]);
      if (ownerRows.length && ownerRows[0].factory_id === targetFactoryId) {
        return res.status(409).json({ error: 'brand_exists', message: 'Bu marka fabrikanızda zaten beyan edilmiş.' });
      }
      return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
    }
    throw e;
  }
  await syncFactoryBrandColumns(targetFactoryId);
  if (req.isMaster) await logMasterAudit('factory_brand_create', 'factory', targetFactoryId);
  res.status(201).json({ brand: brandRowOut(inserted) });
}));

// CBOs26.60-A (fix10x) — DELETE /api/products/factory/myfactory/brands/:brandId
// Yalnızca KENDİ fabrikasının markası silinir; marka yoksa veya başka fabrikanınsa 404.
// Yanıt { ok: true }. factories kolonları kalan ilk markayla senkronlanır.
router.delete('/factory/myfactory/brands/:brandId', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const targetFactoryId = resolveBrandTargetFactoryId(req, res);
  if (targetFactoryId === null) return;
  const brandId = parseInt(req.params.brandId, 10);
  if (!Number.isInteger(brandId) || brandId < 1) return res.status(404).json({ error: 'brand_not_found', message: 'Marka bulunamadı.' });
  const { rows } = await pool.query(`DELETE FROM factory_brands WHERE id = $1 AND factory_id = $2 RETURNING id`, [brandId, targetFactoryId]);
  if (!rows.length) return res.status(404).json({ error: 'brand_not_found', message: 'Marka bulunamadı.' });
  await syncFactoryBrandColumns(targetFactoryId);
  if (req.isMaster) await logMasterAudit('factory_brand_delete', 'factory', targetFactoryId);
  res.json({ ok: true });
}));

// CBOs26.2 — GET /api/products/factory/myfactory/quotes — kendi fabrikasina gelen teklifler.
// Fabrika tokeni -> yalnizca kendi fabrikasi; master -> ?factory_id= zorunlu.
// Eski teklifler (factory_id NULL) fabrika adiyla eslesirse dahil edilir (quote-counts deseni).
router.get('/factory/myfactory/quotes', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryQuotesTable();
  let fid;
  if (req.isMaster) {
    const q = req.query.factory_id;
    if (q === undefined || q === null || String(q).trim() === '') return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
    fid = Number(String(q).trim());
    if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  } else fid = req.factoryId;
  const { rows: frows } = await pool.query('SELECT id, name FROM factories WHERE id = $1', [fid]);
  if (!frows.length) return res.status(404).json({ error: 'factory_not_found' });
  const fname = String(frows[0].name || '').trim().toLowerCase();
  const { rows } = await pool.query(
    `SELECT id, factory, factory_id, name, contact, qty, msg, created_at FROM factory_quotes WHERE factory_id = $1 OR (factory_id IS NULL AND factory <> '' AND LOWER(TRIM(factory)) = $2) ORDER BY created_at DESC, id DESC`,
    [fid, fname]
  );
  res.json({ quotes: rows });
}));

// CBOs26.4 (fix10h): gunluk seri birlestirme — SAF fonksiyon (test edilebilir). rows: [{day:'YYYY-MM-DD', cnt}]
// days: son 30 gunluk 'YYYY-MM-DD' listesi (bugun dahil). Eksik gunler 0 ile doldurulur; gecmis verisi olmayan
// gunler 0 doner (uydurma yok).
function mergeDailySeries(days, viewRows, likeRows, commentRows, quoteRows) {
  const byDay = function (rows) { const m = {}; (rows || []).forEach(function (r) { if (r && r.day) m[String(r.day)] = Number(r.cnt) || 0; }); return m; };
  const v = byDay(viewRows), l = byDay(likeRows), c = byDay(commentRows), q = byDay(quoteRows);
  return days.map(function (d) { return { date: d, views: v[d] || 0, likes: l[d] || 0, comments: c[d] || 0, quotes: q[d] || 0 }; });
}

// CBOs26.2 — GET /api/products/factory/myfactory/stats — kendi fabrikasinin GERCEK istatistigi:
// CBOs26.3 (fix10g): + toplamlar (total_videos, total_likes) + video basina like_count.
// video basina izlenme + yorum sayisi, en cok izlenenler, yorum alan videolar. Uydurma sayi yok.
router.get('/factory/myfactory/stats', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  let fid;
  if (req.isMaster) {
    const q = req.query.factory_id;
    if (q === undefined || q === null || String(q).trim() === '') return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
    fid = Number(String(q).trim());
    if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  } else fid = req.factoryId;
  const { rows: frows } = await pool.query('SELECT id, name, videos FROM factories WHERE id = $1', [fid]);
  if (!frows.length) return res.status(404).json({ error: 'factory_not_found' });
  // CBOs26.7 (fix10j): fname tanimsizdi (stats 500) — artik SELECT'te name var + burada tanimli.
  const fname = String(frows[0].name || '').trim().toLowerCase();
  const videos = Array.isArray(frows[0].videos) ? frows[0].videos : [];
  const keys = videos.map((v, i) => fid + '-' + i);
  const viewMap = {};
  if (keys.length) {
    const { rows } = await pool.query('SELECT video, views FROM factory_video_views WHERE video = ANY($1)', [keys]);
    for (const r of rows) viewMap[r.video] = r.views;
  }
  const commentMap = {};
  if (keys.length) {
    const { rows } = await pool.query(`SELECT video_key, COUNT(*)::int AS cnt FROM factory_comments WHERE video_key ~ $1 GROUP BY video_key`, ['^' + fid + '-[0-9]+$']);
    for (const r of rows) commentMap[r.video_key] = r.cnt;
  }
  const likeMap = {};
  if (keys.length) {
    const { rows } = await pool.query(`SELECT video_key, COUNT(*)::int AS cnt FROM factory_likes WHERE video_key ~ $1 GROUP BY video_key`, ['^' + fid + '-[0-9]+$']);
    for (const r of rows) likeMap[r.video_key] = r.cnt;
  }
  const perVideo = videos.map((v, i) => {
    const key = fid + '-' + i;
    return { index: i, key, title: (v && v.title) || '', url: (v && v.url) || '', views: viewMap[key] || 0, comment_count: commentMap[key] || 0, like_count: likeMap[key] || 0 };
  });
  const totalViews = perVideo.reduce((a, v) => a + v.views, 0);
  const totalComments = perVideo.reduce((a, v) => a + v.comment_count, 0);
  const totalLikes = perVideo.reduce((a, v) => a + v.like_count, 0);
  const mostWatched = [...perVideo].sort((a, b) => b.views - a.views).slice(0, 5);
  const commented = perVideo.filter((v) => v.comment_count > 0).sort((a, b) => b.comment_count - a.comment_count);
  const qmap = await factoryQuoteCountsMap([fid]);
  // CBOs26.4 (fix10h): gunluk seri (son 30 gun) + ulke dagilimi — yalnizca GERCEK satirlar. Izlenme olaylari bu
  // surumden itibaren birikir; onceki izlenmelerin gun/ulke kirilimi yoktur (seride 0 gorunur).
  const days = [];
  for (let i = 29; i >= 0; i--) { const d = new Date(); d.setUTCDate(d.getUTCDate() - i); days.push(d.toISOString().slice(0, 10)); }
  const since = days[0] + 'T00:00:00Z';
  const daySql = `SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, COUNT(*)::int AS cnt FROM %TABLE% WHERE %WHERE% AND created_at >= $1 GROUP BY day`;
  let viewRows = [];
  if (keys.length) { try { const r = await pool.query(daySql.replace('%TABLE%', 'factory_video_view_events').replace('%WHERE%', 'video = ANY($2)'), [since, keys]); viewRows = r.rows; } catch (e) { viewRows = []; } }
  const likeRows = (await pool.query(daySql.replace('%TABLE%', 'factory_likes').replace('%WHERE%', 'video_key ~ $2'), [since, '^' + fid + '-[0-9]+$'])).rows;
  const commentRows = (await pool.query(daySql.replace('%TABLE%', 'factory_comments').replace('%WHERE%', 'video_key ~ $2'), [since, '^' + fid + '-[0-9]+$'])).rows;
  const quoteRows = (await pool.query(daySql.replace('%TABLE%', 'factory_quotes').replace('%WHERE%', '(factory_id = $2 OR (factory_id IS NULL AND factory <> \'\' AND LOWER(TRIM(factory)) = $3))'), [since, fid, fname])).rows;
  const daily = mergeDailySeries(days, viewRows, likeRows, commentRows, quoteRows);
  let countries = [];
  if (keys.length) { try { const r = await pool.query(`SELECT country, COUNT(*)::int AS views FROM factory_video_view_events WHERE video = ANY($1) AND country <> '' GROUP BY country ORDER BY views DESC LIMIT 20`, [keys]); countries = r.rows; } catch (e) { countries = []; } }
  // CBOs26.7 (fix10j): toplam site ziyaretcisi (yalnizca bu fabrika). Tablo yoksa (eski DB) 0 — akis bozulmaz.
  let totalPageVisitors = 0;
  try { const { rows: pv } = await pool.query('SELECT visits FROM factory_page_views WHERE factory_id = $1', [fid]); totalPageVisitors = (pv[0] && pv[0].visits) || 0; } catch (e) { totalPageVisitors = 0; }
  res.json({ factory_id: fid, total_videos: videos.length, total_views: totalViews, total_comments: totalComments, total_likes: totalLikes, total_page_visitors: totalPageVisitors, quote_count: qmap[fid] || 0, videos: perVideo, most_watched: mostWatched, commented_videos: commented, daily: daily, countries: countries });
}));

// CBOs26.2 — GET /api/products/factory/myfactory/messages — kendi fabrikasina yazilan musteri konusmalari (kullaniciya gore gruplu).
// Fabrika tokeni -> yalnizca kendi fabrikasi (factory_id = token). Eski/global mesajlar (factory_id NULL) hicbir fabrikaya gosterilmez.
// Master -> ?factory_id= zorunlu.
router.get('/factory/myfactory/messages', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  let fid;
  if (req.isMaster) {
    const q = req.query.factory_id;
    if (q === undefined || q === null || String(q).trim() === '') return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
    fid = Number(String(q).trim());
    if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  } else fid = req.factoryId;
  const { rows } = await pool.query(
    `SELECT m.id, m.user_id, m.body, m.sender, m.attachment_url, m.kind, m.attachment_name, m.attachment_size, m.attachment_mime, m.factory_id, m.created_at,
            COALESCE(NULLIF(u.nickname,''), NULLIF(u.name,''), split_part(u.email,'@',1), 'Misafir') AS name
     FROM factory_messages m LEFT JOIN users u ON u.id::text = m.user_id::text
     WHERE m.factory_id = $1 ORDER BY m.user_id ASC, m.created_at ASC, m.id ASC`,
    [fid]
  );
  const byUser = new Map();
  for (const r of rows) {
    if (!byUser.has(r.user_id)) byUser.set(r.user_id, { user_id: r.user_id, name: r.name || 'Misafir', messages: [] });
    byUser.get(r.user_id).messages.push({ id: r.id, body: r.body, sender: r.sender, attachment_url: r.attachment_url || null, kind: r.kind || 'text', attachment_name: r.attachment_name || null, attachment_size: r.attachment_size ?? null, attachment_mime: r.attachment_mime || null, factory_id: r.factory_id, created_at: r.created_at });
  }
  res.json({ conversations: [...byUser.values()] });
}));

// CBOs26.2 — POST /api/products/factory/myfactory/messages/:id/reply — fabrika musteriye cevap verir (sender='factory'); :id = user_id.
// Yalniz bu fabrikaya yazmis musteriye cevap verilebilir (konusma yoksa 404 — rastgele kullaniciya yazilmaz).
router.post('/factory/myfactory/messages/:id/reply', requireFactoryOrMasterAuth,
  param('id').isString().trim().isLength({ min: 1, max: 100 }),
  body('body').optional().trim().isLength({ max: 1000 }),
  body('attachment_url').optional().isString().isLength({ max: 2048 }),
  body('kind').optional().isIn(['text', 'image', 'file', 'video']),
  body('attachment_name').optional().isString().isLength({ max: 200 }),
  body('attachment_size').optional().isInt({ min: 0, max: 10485760 }),
  body('attachment_mime').optional().isString().isLength({ max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    let fid;
    if (req.isMaster) {
      const fromBody = req.body.factory_id;
      const fromQuery = req.query.factory_id;
      const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
      const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
      if (!hasBody && !hasQuery) return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
      if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) return res.status(400).json({ error: 'factory_id_mismatch' });
      fid = Number(String(hasBody ? fromBody : fromQuery).trim());
      if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
    } else fid = req.factoryId;
    const userId = String(req.params.id);
    const { rows: conv } = await pool.query('SELECT id FROM factory_messages WHERE factory_id = $1 AND user_id = $2 LIMIT 1', [fid, userId]);
    if (!conv.length) return res.status(404).json({ error: 'conversation_not_found' });
    const text = (req.body.body || '').trim();
    const att = cleanChatAttachment(req.body);
    if (!att.ok) return res.status(att.status).json({ error: att.error });
    // fix10e M5: sohbet dosyasi eki baskasina ait olamaz (fabrika dosyasi: 'factory:<id>'; master dosyasi: 'cbai:master').
    if (att.attachmentUrl && att.attachmentUrl.startsWith('/api/products/factory/chat-file/')) {
      const own = await chatFileOwnedBy(att.attachmentUrl, req.isMaster ? 'cbai:master' : 'factory:' + fid);
      const factoryOwn = req.isMaster ? await chatFileOwnedBy(att.attachmentUrl, 'factory:' + fid) : false;
      if (!own && !factoryOwn) return res.status(403).json({ error: 'forbidden' });
    }
    const { rows } = await pool.query(
      `INSERT INTO factory_messages (user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime, factory_id) VALUES ($1, $2, 'factory', $3, $4, $5, $6, $7, $8) RETURNING id, user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime, factory_id, created_at`,
      [userId, text, att.attachmentUrl, att.kind, att.name, att.size, att.mime, fid]
    );
    res.status(201).json({ message: rows[0] });
  })
);

// CBOs26.5 (fix10i) — GET /api/products/factory/myfactory/notifications — okunmamis musteri mesajlari + gorulmemis teklifler.
// Fabrika tokeni -> yalnizca kendi fabrikasi; master -> ?factory_id= zorunlu (quotes/stats deseni).
// Uydurma bildirim yok: yalnizca GERCEK satirlar doner.
router.get('/factory/myfactory/notifications', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  await ensureFactoryQuotesTable();
  let fid;
  if (req.isMaster) {
    const q = req.query.factory_id;
    if (q === undefined || q === null || String(q).trim() === '') return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
    fid = Number(String(q).trim());
    if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
  } else fid = req.factoryId;
  const { rows: frows } = await pool.query('SELECT id, name FROM factories WHERE id = $1', [fid]);
  if (!frows.length) return res.status(404).json({ error: 'factory_not_found' });
  const fname = String(frows[0].name || '').trim().toLowerCase();
  const { rows: msgs } = await pool.query(
    `SELECT id, user_id, body, created_at FROM factory_messages WHERE factory_id = $1 AND sender = 'user' AND COALESCE(seen_by_factory, FALSE) = FALSE ORDER BY created_at DESC, id DESC`,
    [fid]
  );
  const { rows: quotes } = await pool.query(
    `SELECT id, name, contact, qty, msg, created_at FROM factory_quotes WHERE (factory_id = $1 OR (factory_id IS NULL AND factory <> '' AND LOWER(TRIM(factory)) = $2)) AND COALESCE(seen_by_factory, FALSE) = FALSE ORDER BY created_at DESC, id DESC`,
    [fid, fname]
  );
  const items = [];
  for (const m of msgs) items.push({ type: 'message', id: m.id, user_id: m.user_id, text: String(m.body || '').slice(0, 200), created_at: m.created_at });
  for (const q of quotes) {
    const parts = [q.name || ''];
    if (q.msg) parts.push(String(q.msg));
    if (q.qty) parts.push('Adet: ' + String(q.qty));
    items.push({ type: 'quote', id: q.id, text: parts.filter(Boolean).join(' — ').slice(0, 200), created_at: q.created_at });
  }
  items.sort((a, b) => (new Date(b.created_at) - new Date(a.created_at)) || (b.id - a.id));
  res.json({ unread_messages: msgs.length, new_quotes: quotes.length, total: msgs.length + quotes.length, items });
}));

// CBOs26.5 (fix10i) — POST /api/products/factory/myfactory/notifications/read — okundu isaretle.
// {type:'messages'|'quotes'|'all', user_id?} — yalnizca kendi fabrikasinin satirlari isaretlenir.
// Master -> govde veya sorguda factory_id zorunlu (reply deseni).
router.post('/factory/myfactory/notifications/read', requireFactoryOrMasterAuth,
  body('type').isIn(['messages', 'quotes', 'all']),
  body('user_id').optional().isString().isLength({ max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    await ensureFactoryQuotesTable();
    let fid;
    if (req.isMaster) {
      const fromBody = req.body.factory_id;
      const fromQuery = req.query.factory_id;
      const hasBody = fromBody !== undefined && fromBody !== null && String(fromBody).trim() !== '';
      const hasQuery = fromQuery !== undefined && fromQuery !== null && String(fromQuery).trim() !== '';
      if (!hasBody && !hasQuery) return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
      if (hasBody && hasQuery && Number(String(fromBody).trim()) !== Number(String(fromQuery).trim())) return res.status(400).json({ error: 'factory_id_mismatch' });
      fid = Number(String(hasBody ? fromBody : fromQuery).trim());
      if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory_id' });
    } else fid = req.factoryId;
    const { rows: frows } = await pool.query('SELECT id, name FROM factories WHERE id = $1', [fid]);
    if (!frows.length) return res.status(404).json({ error: 'factory_not_found' });
    const fname = String(frows[0].name || '').trim().toLowerCase();
    const type = req.body.type;
    const userId = req.body.user_id ? String(req.body.user_id) : null;
    let markedMessages = 0, markedQuotes = 0;
    if (type === 'messages' || type === 'all') {
      const params = [fid];
      let sql = `UPDATE factory_messages SET seen_by_factory = TRUE WHERE factory_id = $1 AND sender = 'user' AND COALESCE(seen_by_factory, FALSE) = FALSE`;
      if (userId) { params.push(userId); sql += ` AND user_id = $${params.length}`; }
      const r = await pool.query(sql, params);
      markedMessages = r.rowCount || 0;
    }
    if (type === 'quotes' || type === 'all') {
      const r = await pool.query(
        `UPDATE factory_quotes SET seen_by_factory = TRUE WHERE (factory_id = $1 OR (factory_id IS NULL AND factory <> '' AND LOWER(TRIM(factory)) = $2)) AND COALESCE(seen_by_factory, FALSE) = FALSE`,
        [fid, fname]
      );
      markedQuotes = r.rowCount || 0;
    }
    res.json({ ok: true, marked_messages: markedMessages, marked_quotes: markedQuotes });
  })
);

// POST /api/products/factory/:id/rate — fabrika puanlama (1-5). Giris gerekli, abonelik gerekmez. Ayni kullanici tekrar puan verirse guncellenir.
router.post('/factory/:id/rate', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const rating = req.body && req.body.rating;
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'invalid_rating' });
  const { rows: f } = await pool.query('SELECT id FROM factories WHERE id=$1', [fid]);
  if (!f.length) return res.status(404).json({ error: 'factory_not_found' });
  await pool.query('INSERT INTO factory_ratings (factory_id, user_id, rating) VALUES ($1,$2,$3) ON CONFLICT (factory_id, user_id) DO UPDATE SET rating=EXCLUDED.rating, updated_at=now()', [fid, req.user.id, rating]);
  const { rows: agg } = await pool.query('SELECT ROUND(AVG(rating)::numeric, 1)::float AS avg, COUNT(*)::int AS cnt FROM factory_ratings WHERE factory_id=$1', [fid]);
  res.json({ ok: true, rating_avg: agg[0].avg === null ? null : Number(agg[0].avg), rating_count: agg[0].cnt, user_rating: rating });
}));

// GET /api/products/factory/:id/my-rating — giris yapan kullanicinin bu fabrikaya verdigi puan (yoksa null)
router.get('/factory/:id/my-rating', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const { rows } = await pool.query('SELECT rating FROM factory_ratings WHERE factory_id=$1 AND user_id=$2', [fid, req.user.id]);
  res.json({ user_rating: rows.length ? rows[0].rating : null });
}));

// GET /api/products/factory/list — tum fabrikalar (herkese acik; kapali fabrikalar gorunmez)
router.get('/factory/list', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(`SELECT * FROM factories WHERE is_active IS NOT FALSE ORDER BY id ASC`);
  await attachFactoryBrands(rows); // fix10x: brands (adlar) public yanita eklenir
  const rmap = await factoryRatingsMap(rows.map((r) => r.id));
  const qmap = await factoryQuoteCountsMap(rows.map((r) => r.id));
  const fmap = await factoryFollowersMap(rows.map((r) => r.id)); // fix10k: takipci sayisi
  const pvmap = await factoryPageViewsMap(rows.map((r) => r.id)); // fix10aa: sayfa goruntulenmesi (panel tanimiyla ayni)
  const siteVisitorsTotal = await factorySiteVisitorsTotal(); // fix10aa: tum fabrikalarin toplami (tek aggregate sorgu)
  const siteOnlineNow = await factoryOnlineNow(); // fix10ac: su an cevrimici (son 120 sn, tek sorgu)
  for (const r of rows) r.page_views = pvmap[r.id] || 0; // fix10aa: toFactoryPublic satirdan okur
  // fix10aa: yanit { factories, site_visitors_total } — on yuz (v230+) Array.isArray ? data : data.factories ile iki bicimi de kabul eder.
  // fix10ac: site_online_now da ayni yanitta (ekleme yalnizdir; site_visitors_total AYNEN kalir).
  res.json({ factories: rows.map((r) => ({ ...toFactoryPublic(r, { includeContact: false }), rating_avg: (rmap[r.id] && rmap[r.id].rating_avg !== undefined) ? rmap[r.id].rating_avg : null, rating_count: (rmap[r.id] && rmap[r.id].rating_count) || 0, quote_count: qmap[r.id] || 0, followers: fmap[r.id] || 0 })), site_visitors_total: siteVisitorsTotal, site_online_now: siteOnlineNow }); // fix10e M7
}));

// GET /api/products/factory/quote-counts — her fabrikanin toplam teklif sayisi (herkese acik istatistik)
router.get('/factory/quote-counts', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(`SELECT id FROM factories WHERE is_active IS NOT FALSE ORDER BY id ASC`);
  const counts = await factoryQuoteCountsMap(rows.map((r) => r.id));
  res.json({ counts });
}));

// CBOs26.33 (fix10r): fabrika ÖN KAYIT başvurusu (herkese açık).
// POST /api/products/factory/apply — validasyon + aynı e-posta 24 saatte 1 başvuru.
router.post('/factory/apply', factoryApplyLimiter,
  body('factory_name').trim().isLength({ min: 2, max: 200 }),
  body('contact_name').trim().isLength({ min: 2, max: 100 }),
  body('email').trim().isEmail().isLength({ max: 200 }),
  body('phone').trim().isLength({ min: 5, max: 30 }),
  body('address').trim().isLength({ min: 5, max: 500 }),
  body('sector').trim().isLength({ min: 1, max: 100 }),
  body('city').optional().trim().isLength({ max: 100 }),
  body('annual_revenue').optional().trim().isLength({ max: 100 }),
  body('message').optional().trim().isLength({ max: 2000 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    const email = String(req.body.email).trim().toLowerCase();
    const { rows: dup } = await pool.query(
      `SELECT id FROM factory_applications WHERE LOWER(email)=LOWER($1) AND created_at > now() - INTERVAL '24 hours' LIMIT 1`,
      [email]
    );
    if (dup.length) return res.status(409).json({ error: 'duplicate_application' });
    const { rows } = await pool.query(
      `INSERT INTO factory_applications (factory_name, contact_name, email, phone, address, city, sector, annual_revenue, message)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at`,
      [
        String(req.body.factory_name).trim(),
        String(req.body.contact_name).trim(),
        email,
        String(req.body.phone).trim(),
        String(req.body.address).trim(),
        String(req.body.city || '').trim(),
        String(req.body.sector).trim(),
        String(req.body.annual_revenue || '').trim(),
        String(req.body.message || '').trim(),
      ]
    );
    res.json({ ok: true, id: rows[0].id });
  })
);

// CBOs26.33 (fix10r): admin başvuru listesi.
// GET /api/products/factory/admin/applications — ?status=pending|approved|rejected (opsiyonel).
router.get('/factory/admin/applications', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const status = String(req.query.status || '').trim();
  let q = `SELECT id, factory_name, contact_name, email, phone, address, city, sector, annual_revenue, message, status, created_at FROM factory_applications`;
  const params = [];
  if (status === 'pending' || status === 'approved' || status === 'rejected') {
    q += ` WHERE status=$1`;
    params.push(status);
  }
  q += ` ORDER BY created_at DESC LIMIT 200`;
  const { rows } = await pool.query(q, params);
  res.json({ items: rows });
}));

// CBOs26.33 (fix10r): admin başvuru durum güncelle.
// POST /api/products/factory/admin/applications/:id/status — {status: 'approved'|'rejected'}.
router.post('/factory/admin/applications/:id/status', requireAuth, requireAdmin,
  param('id').isInt({ min: 1 }),
  body('status').trim().isIn(['approved', 'rejected']),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    const { rows } = await pool.query(
      `UPDATE factory_applications SET status=$1 WHERE id=$2 RETURNING id, status`,
      [String(req.body.status).trim(), parseInt(req.params.id, 10)]
    );
    if (!rows.length) return res.status(404).json({ error: 'application_not_found' });
    res.json({ ok: true, id: rows[0].id, status: rows[0].status });
  })
);

// fix10k (CBOs26.15): fabrika takip (follow). Giris gerekli (misafir 401 — requireAuth).
// user_id HER ZAMAN req.user'dan (token); govdeden id alinmaz. Olmayan fabrika -> 404.
// POST /api/products/factory/:id/follow — idempotent: zaten takip ediyorsa satir degismez, sayi ayni kalir.
router.post('/factory/:id/follow', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const { rows: f } = await pool.query('SELECT id FROM factories WHERE id=$1', [fid]);
  if (!f.length) return res.status(404).json({ error: 'factory_not_found' });
  await pool.query('INSERT INTO factory_follows (user_id, factory_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, fid]);
  const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_follows WHERE factory_id=$1', [fid]);
  res.json({ following: true, followers: c[0].n });
}));

// DELETE /api/products/factory/:id/unfollow — takipten cikar (takip etmiyorsa da ayni yanit, idempotent).
router.delete('/factory/:id/unfollow', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const { rows: f } = await pool.query('SELECT id FROM factories WHERE id=$1', [fid]);
  if (!f.length) return res.status(404).json({ error: 'factory_not_found' });
  await pool.query('DELETE FROM factory_follows WHERE user_id=$1 AND factory_id=$2', [req.user.id, fid]);
  const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_follows WHERE factory_id=$1', [fid]);
  res.json({ following: false, followers: c[0].n });
}));

// GET /api/products/factory/:id/follow-status — giris yapan kullanici takip ediyor mu + toplam takipci.
router.get('/factory/:id/follow-status', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const { rows: f } = await pool.query('SELECT id FROM factories WHERE id=$1', [fid]);
  if (!f.length) return res.status(404).json({ error: 'factory_not_found' });
  const { rows: m } = await pool.query('SELECT 1 FROM factory_follows WHERE user_id=$1 AND factory_id=$2', [req.user.id, fid]);
  const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM factory_follows WHERE factory_id=$1', [fid]);
  res.json({ following: m.length > 0, followers: c[0].n });
}));

// GET /api/products/factory/feed — giris yapan kullanicinin takip ettigi fabrikalarin videolari.
// Siralama: takip zamani (factory_follows.created_at DESC, en yeni takip once). Video basina zaman damgasi
// yok (videos JSONB dizisi); fabrika ici sira kayitli dizi sirasidir — uydurma tarih/sayi uretilmez, YALNIZCA gercek veri.
// Sayfali: ?limit (varsayilan 20, en fazla 50) & ?offset. Kapali (is_active=false) fabrikalar akisa girmez.
router.get('/factory/feed', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  let limit = parseInt(req.query.limit, 10);
  if (!Number.isInteger(limit) || limit < 1) limit = 20;
  limit = Math.min(limit, 50);
  let offset = parseInt(req.query.offset, 10);
  if (!Number.isInteger(offset) || offset < 0) offset = 0;
  const { rows } = await pool.query(
    `SELECT f.id, f.name, f.cbf_code, f.cover_image, f.videos
     FROM factory_follows ff JOIN factories f ON f.id = ff.factory_id
     WHERE ff.user_id = $1 AND f.is_active IS NOT FALSE
     ORDER BY ff.created_at DESC, ff.id DESC`,
    [req.user.id]
  );
  const items = [];
  for (const r of rows) {
    let videos = r.videos;
    if (typeof videos === 'string') { try { videos = JSON.parse(videos); } catch { videos = []; } }
    if (!Array.isArray(videos)) videos = [];
    for (const v of videos) {
      if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
      const url = typeof v.url === 'string' ? v.url : '';
      if (!url) continue;
      const feedVideo = { title: typeof v.title === 'string' ? v.title : '', description: typeof v.description === 'string' ? v.description : '', url };
      if (v.kind === 'video' || v.kind === 'canli' || v.kind === 'photo') feedVideo.kind = v.kind; // fix10z (CBOs26.64): gonderi turu de doner (photo ayirt edilsin)
      if (typeof v.product_description === 'string' && v.product_description) feedVideo.product_description = v.product_description; // fix10ab (CBOs26.68-B): urun aciklamasi aynen doner
      if (Array.isArray(v.attributes)) feedVideo.attributes = v.attributes; // fix10y (CBOs26.62): ürün özellikleri aynen döner
      items.push({
        factory_id: r.id,
        factory_name: r.name,
        cbf_code: r.cbf_code || '',
        cover_image: r.cover_image || '',
        video: feedVideo,
      });
    }
  }
  const siteVisitorsTotal = await factorySiteVisitorsTotal(); // fix10aa: site toplami meta'da (tek aggregate sorgu)
  res.json({ items: items.slice(offset, offset + limit), total: items.length, limit, offset, site_visitors_total: siteVisitorsTotal });
}));

// fix10n (CBOs26.22): GET /api/products/factory/follows/mine — giris yapan kullanicinin takip ettigi fabrikalarin LISTESI.
// Yanit: [{id, name, cbf_code, cover_image, followers}]. YALNIZCA kendi takipleri (user_id filtresi).
// Siralama: takip zamani (created_at DESC, en yeni takip once) — uydurma tarih/sayi yok, YALNIZCA gercek veri.
// Kapali (is_active=false) fabrikalar listeye girmez.
// KONUM: /factory/:id tek-segment rotasindan once kayitli olmali (bu rota iki segmentli oldugu icin yutulmaz,
// ancak diger /factory/* rotalariyla ayni blokta tutulur).
router.get('/factory/follows/mine', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(
    `SELECT f.id, f.name, f.cbf_code, f.cover_image
     FROM factory_follows ff JOIN factories f ON f.id = ff.factory_id
     WHERE ff.user_id = $1 AND f.is_active IS NOT FALSE
     ORDER BY ff.created_at DESC, ff.id DESC`,
    [req.user.id]
  );
  const fmap = await factoryFollowersMap(rows.map((r) => r.id));
  res.json(rows.map((r) => ({
    id: r.id,
    name: r.name || '',
    cbf_code: r.cbf_code || '',
    cover_image: r.cover_image || '',
    followers: fmap[r.id] || 0,
  })));
}));

// fix10n (CBOs26.22): GET /api/products/factory/myfactory/followers — fabrikayi takip eden kullanicilarin LISTESI.
// Yetki: fabrika jetonu -> YALNIZ kendi fabrikasinin takipcileri; master -> ?factory_id= ZORUNLU.
// Yanit: [{user_id, nickname, name, followed_at}] — takip tarihine gore yeniden eskiye.
// GIZLILIK: e-posta/telefon ASLA donulmez; yalnizca herkese acik profil bilgileri (nickname, name).
router.get('/factory/myfactory/followers', requireFactoryOrMasterAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  let targetFactoryId;
  if (req.isMaster) {
    const qf = req.query.factory_id;
    if (qf === undefined || qf === null || String(qf).trim() === '') return res.status(400).json({ error: 'factory_id_required', message: 'Master icin factory_id gerekli.' });
    targetFactoryId = Number(String(qf).trim());
    if (!Number.isInteger(targetFactoryId) || targetFactoryId < 1) return res.status(400).json({ error: 'invalid_factory_id', message: 'Fabrika kimligi gecerli degil.' });
  } else {
    targetFactoryId = req.factoryId;
  }
  const { rows } = await pool.query(
    `SELECT ff.user_id AS user_id, u.nickname AS nickname, u.name AS name, ff.created_at AS followed_at
     FROM factory_follows ff LEFT JOIN users u ON u.id::text = ff.user_id::text
     WHERE ff.factory_id = $1
     ORDER BY ff.created_at DESC, ff.id DESC`,
    [targetFactoryId]
  );
  if (req.isMaster) await logMasterAudit('factory_followers_view', 'factory', targetFactoryId); // fix10e H-E deseni
  res.json(rows.map((r) => ({
    user_id: r.user_id,
    nickname: r.nickname || '',
    name: r.name || '',
    followed_at: r.followed_at,
  })));
}));

// GET /api/products/factory/admin/list — tum fabrikalar + created_at (admin)
router.get('/factory/admin/list', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(`SELECT * FROM factories ORDER BY id ASC`);
  await attachFactoryBrands(rows); // fix10x
  const rmap = await factoryRatingsMap(rows.map((r) => r.id));
  res.json(rows.map((r) => ({ ...toFactoryAdmin(r), rating_avg: (rmap[r.id] && rmap[r.id].rating_avg !== undefined) ? rmap[r.id].rating_avg : null, rating_count: (rmap[r.id] && rmap[r.id].rating_count) || 0 })));
}));

const factoryValidators = [
  body('name').optional().trim().isLength({ min: 1, max: 200 }),
  body('city').optional().trim().isLength({ max: 200 }),
  body('category').optional().trim().isLength({ max: 200 }),
  body('description').optional().trim().isLength({ max: 10000 }),
  body('moq').optional({ nullable: true }).isInt({ min: 0 }),
  body('stock').optional({ nullable: true }).isInt({ min: 0 }),
  body('capacity').optional().trim().isLength({ max: 500 }),
  body('certs').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_certs'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_certs'); return true; }
    throw new Error('invalid_certs');
  }),
  body('features').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_features'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_features'); return true; }
    throw new Error('invalid_features');
  }),
  body('import_countries').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_import_countries'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_import_countries'); return true; }
    throw new Error('invalid_import_countries');
  }),
  body('employees').optional().trim().isLength({ max: 2000 }),
  body('annual_revenue').optional().trim().isLength({ max: 2000 }),
  body('cover_image').optional().trim().isLength({ max: 2048 }),
  body('factory_area').optional().trim().isLength({ max: 2000 }),
  body('years').optional().trim().isLength({ max: 2000 }),
  body('main_products').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_main_products'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_main_products'); return true; }
    throw new Error('invalid_main_products');
  }),
  body('hashtags').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_hashtags'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_hashtags'); return true; }
    throw new Error('invalid_hashtags');
  }),
  body('videos').optional().isArray(),
  body('cbf_code').optional().trim().isLength({ max: 20 }),
  body('is_verified').optional().custom((v) => {
    if (parseFactoryVerified(v) === null) throw new Error('invalid_is_verified');
    return true;
  }),
  body('address').optional().trim().isLength({ max: 500 }),
  body('phone').optional().trim().isLength({ max: 200 }),
  body('contact').optional().trim().isLength({ max: 200 }),
  body('wechat').optional().trim().isLength({ max: 200 }),
  body('whatsapp').optional().trim().isLength({ max: 200 }),
  body('tags').optional().custom((v) => {
    if (typeof v === 'string') { if (v.length > 2000) throw new Error('invalid_tags'); return true; }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) { if (v.join(', ').length > 2000) throw new Error('invalid_tags'); return true; }
    throw new Error('invalid_tags');
  }),
  body('myfactory_username').optional().custom((v) => {
    if (v === '' || v === null) return true;
    if (cleanMyFactoryUsername(v) === null) throw new Error('invalid_myfactory_username');
    return true;
  }),
  body('myfactory_password').optional().custom((v) => {
    if (v === '' || v === null) return true;
    if (cleanMyFactoryPassword(v) === null) throw new Error('invalid_myfactory_password');
    return true;
  }),
  body('socials').optional().custom((v) => {
    if (cleanFactorySocials(v) === null) throw new Error('invalid_socials'); // fix10e L8: konak allowlist
    return true;
  }),
];

// POST /api/products/factory/admin — fabrika ekle (admin)
router.post('/factory/admin', requireAuth, requireAdmin,
  body('name').trim().isLength({ min: 1, max: 200 }),
  ...factoryValidators,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    // FAZ 1 — My Factory hesabi (admin): kullanici adi benzersiz olmali (cakisma 409), sifre bos degilse hash'lenir.
    // Benzersizlik kontrolu asagida yola gore yapilir (merge: hedef fabrika haric; yeni kayit: tum tablo).
    const myFactoryUsernameClean = cleanMyFactoryUsername(req.body.myfactory_username);
    if (myFactoryUsernameClean === null) return res.status(400).json({ error: 'invalid_myfactory_username', message: 'ChinaBazaar My Factory kullanıcı adı 3-50 karakter olmalı, yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.' });
    const myFactoryPasswordClean = cleanMyFactoryPassword(req.body.myfactory_password);
    if (myFactoryPasswordClean === null) return res.status(400).json({ error: 'invalid_myfactory_password', message: 'ChinaBazaar My Factory şifresi en az 8 karakter olmalı.' });
    let myFactoryPasswordHash;
    if (myFactoryPasswordClean) myFactoryPasswordHash = await bcrypt.hash(myFactoryPasswordClean, 12);
    const videos = cleanFactoryVideos(req.body.videos);
    if (videos === null) return res.status(400).json({ error: 'invalid_videos' });
    const hashtagsClean = cleanFactoryHashtags(req.body.hashtags);
    if (hashtagsClean === null) return res.status(400).json({ error: 'invalid_hashtags' });
    const addressClean = cleanFactoryText(req.body.address, 500);
    if (addressClean === null) return res.status(400).json({ error: 'invalid_address' });
    const phoneClean = cleanFactoryText(req.body.phone, 200);
    if (phoneClean === null) return res.status(400).json({ error: 'invalid_phone' });
    const contactClean = cleanFactoryText(req.body.contact, 200);
    if (contactClean === null) return res.status(400).json({ error: 'invalid_contact' });
    const wechatClean = cleanFactoryText(req.body.wechat, 200);
    if (wechatClean === null) return res.status(400).json({ error: 'invalid_wechat' });
    const whatsappClean = cleanFactoryText(req.body.whatsapp, 200);
    if (whatsappClean === null) return res.status(400).json({ error: 'invalid_whatsapp' });
    const emailClean = cleanFactoryEmail(req.body.email);
    if (emailClean === null) return res.status(400).json({ error: 'invalid_email' });
    const socialsClean = cleanFactorySocials(req.body.socials);
    if (socialsClean === null) return res.status(400).json({ error: 'invalid_socials' });
    const tagsClean = cleanFactoryTags(req.body.tags);
    if (tagsClean === null) return res.status(400).json({ error: 'invalid_tags' });
    const importCountriesClean = cleanFactoryTags(req.body.import_countries);
    if (importCountriesClean === null) return res.status(400).json({ error: 'invalid_import_countries' });
    const employeesClean = cleanFactoryText(req.body.employees, 2000);
    if (employeesClean === null) return res.status(400).json({ error: 'invalid_employees' });
    const annualRevenueClean = cleanFactoryText(req.body.annual_revenue, 2000);
    if (annualRevenueClean === null) return res.status(400).json({ error: 'invalid_annual_revenue' });
    const coverImageClean = cleanFactoryCoverImage(req.body.cover_image);
    if (coverImageClean === null) return res.status(400).json({ error: 'invalid_cover_image' });
    const factoryAreaClean = cleanFactoryText(req.body.factory_area, 2000);
    if (factoryAreaClean === null) return res.status(400).json({ error: 'invalid_factory_area' });
    const yearsClean = cleanFactoryText(req.body.years, 2000);
    if (yearsClean === null) return res.status(400).json({ error: 'invalid_years' });
    const mainProductsClean = cleanFactoryTags(req.body.main_products);
    if (mainProductsClean === null) return res.status(400).json({ error: 'invalid_main_products' });
    // VERIFIED: CREATE — body verirse sakla (boolean / "true"/"false"/"1"/"0" / 1/0), verilmezse false.
    const verifiedCleanCreate = parseFactoryVerified(req.body.is_verified);
    if (verifiedCleanCreate === null) return res.status(400).json({ error: 'invalid_is_verified' });
    const verifiedCreate = verifiedCleanCreate === undefined ? false : verifiedCleanCreate;
    // CBF upsert-by-code (Part 1b): body cbf_code'u mevcut bir fabrikanin koduyla eslesirse
    // YENI satir acilmaz — mevcut satira MERGE edilir: body videolari mevcut videolara
    // URL'ye gore tekillestirilerek eklenir (mevcut kayitlar korunur, yalniz yeni URL'ler
    // eklenir); diger skaler alanlar yalniz body'de acikca verildiyse guncellenir (PUT
    // semantiği); NAME asla degistirilmez (kod yetkili kimliktir — farkli isimle gelen
    // kod eslesmesi fabrikayi yeniden adlandiramaz). Eslesen satir toFactoryAdmin ile doner.
    // CBF kilidi (CREATE): govdede verilen kod bozuk bicimliyse reddet (400).
    if (req.body.cbf_code !== undefined && String(req.body.cbf_code).trim() !== '' && !isValidCbfCode(req.body.cbf_code)) {
      return res.status(400).json({ error: 'invalid_cbf_code', message: 'CBF kodu CBF-001 biçiminde olmalı (örn. CBF-001).' });
    }
    const incomingCbfCode = normalizeCbfCode(req.body.cbf_code);
    if (incomingCbfCode) {
      const { rows: cbfExisting } = await pool.query(
        `SELECT * FROM factories WHERE UPPER(TRIM(cbf_code)) = $1 ORDER BY id ASC LIMIT 1`,
        [incomingCbfCode]
      );
      if (cbfExisting.length) {
        const existingFactory = cbfExisting[0];
        const mergeSets = [];
        const mergeParams = [existingFactory.id];
        const mergePush = (col, val, cast) => { mergeParams.push(val); mergeSets.push(`${col} = $${mergeParams.length}${cast || ''}`); };
        // Skaler alanlar — PUT ile ayni: yalniz body'de varsa. NAME bilerek yok.
        if (req.body.city !== undefined) mergePush('city', String(req.body.city).trim());
        if (req.body.category !== undefined) mergePush('category', String(req.body.category).trim());
        if (req.body.description !== undefined) mergePush('description', String(req.body.description).trim());
        if (req.body.moq !== undefined) mergePush('moq', req.body.moq == null ? 0 : parseInt(req.body.moq, 10));
        if (req.body.stock !== undefined) mergePush('stock', req.body.stock == null ? 0 : parseInt(req.body.stock, 10));
        if (req.body.capacity !== undefined) mergePush('capacity', String(req.body.capacity).trim());
        if (req.body.certs !== undefined) mergePush('certs', Array.isArray(req.body.certs) ? req.body.certs.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.certs).trim());
        if (req.body.features !== undefined) mergePush('features', Array.isArray(req.body.features) ? req.body.features.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.features).trim());
        if (req.body.import_countries !== undefined) mergePush('import_countries', Array.isArray(req.body.import_countries) ? req.body.import_countries.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.import_countries).trim());
        if (req.body.employees !== undefined) mergePush('employees', String(req.body.employees).trim());
        if (req.body.annual_revenue !== undefined) mergePush('annual_revenue', String(req.body.annual_revenue).trim());
        if (req.body.cover_image !== undefined) mergePush('cover_image', coverImageClean);
        if (req.body.factory_area !== undefined) mergePush('factory_area', String(req.body.factory_area).trim());
        if (req.body.years !== undefined) mergePush('years', String(req.body.years).trim());
        if (req.body.main_products !== undefined) mergePush('main_products', Array.isArray(req.body.main_products) ? req.body.main_products.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.main_products).trim());
        if (req.body.hashtags !== undefined) mergePush('hashtags', hashtagsClean);
        if (req.body.address !== undefined) mergePush('address', addressClean);
        if (req.body.phone !== undefined) mergePush('phone', phoneClean);
        if (req.body.contact !== undefined) mergePush('contact', contactClean);
        if (req.body.wechat !== undefined) mergePush('wechat', wechatClean);
        if (req.body.whatsapp !== undefined) mergePush('whatsapp', whatsappClean);
        if (req.body.email !== undefined) mergePush('email', emailClean === '' ? null : emailClean);
        if (req.body.socials !== undefined) mergePush('socials', JSON.stringify(socialsClean), '::jsonb');
        if (req.body.tags !== undefined) mergePush('tags', tagsClean);
        // VERIFIED (CBF merge): body verirse guncelle, verilmezse degistirme.
        if (req.body.is_verified !== undefined) mergePush('is_verified', verifiedCreate);
        // fix10e M6: e-posta/telefon benzersizliği (CBF merge — hedef fabrika dışı).
        if (emailClean && await factoryContactTaken('email', emailClean, existingFactory.id)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu e-posta başka bir fabrikada kullanılıyor.' });
        if (phoneClean && await factoryContactTaken('phone', phoneClean, existingFactory.id)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu telefon başka bir fabrikada kullanılıyor.' });
        // FAZ 1 — My Factory hesabi (CBF merge): kullanici adi cakisirsa 409; sifre bos degilse hash'lenir.
        if (myFactoryUsernameClean) {
          if (await myFactoryUsernameTaken(myFactoryUsernameClean, existingFactory.id)) return res.status(409).json({ error: 'myfactory_username_taken', message: 'Bu ChinaBazaar My Factory kullanıcı adı başka bir fabrikada kullanılıyor.' });
          mergePush('myfactory_username', myFactoryUsernameClean);
        }
        if (myFactoryPasswordHash) mergePush('myfactory_password_hash', myFactoryPasswordHash);
        // Videolar — REPLACE degil APPEND: mevcut videolar korunur, yalniz yeni URL'ler eklenir.
        if (videos !== undefined) {
          let existingVideos = existingFactory.videos;
          if (typeof existingVideos === 'string') { try { existingVideos = JSON.parse(existingVideos); } catch { existingVideos = []; } }
          if (!Array.isArray(existingVideos)) existingVideos = [];
          const seenVideoUrls = new Set(existingVideos.map((v) => (v && typeof v.url === 'string' ? v.url.trim() : '')));
          const mergedVideos = [...existingVideos];
          for (const v of videos) {
            if (!seenVideoUrls.has(v.url.trim())) { seenVideoUrls.add(v.url.trim()); mergedVideos.push(v); }
          }
          mergePush('videos', JSON.stringify(mergedVideos), '::jsonb');
        }
        // cbf_code zaten eslesiyor — degistirilmez; name bilerek degistirilmez.
        if (!mergeSets.length) { await attachFactoryBrands([existingFactory]); return res.json(toFactoryAdmin(existingFactory)); }
        mergeSets.push('updated_at = now()');
        const { rows: mergedRows } = await pool.query(`UPDATE factories SET ${mergeSets.join(', ')} WHERE id = $1 RETURNING *`, mergeParams);
        if (!mergedRows.length) return res.status(404).json({ error: 'factory_not_found' });
        await attachFactoryBrands(mergedRows); // fix10x
        if (myFactoryUsernameClean) ensureFactoryDomainAlias(myFactoryUsernameClean); // fix10ag: alt alan adi alias'i (fire-and-forget)
        return res.json(toFactoryAdmin(mergedRows[0]));
      }
    }
    // CBF: body'de kod varsa normalize edip kullan; yoksa ayni isimde kod varsa onu tekrar kullan, yoksa siradaki kodu ata.
    let cbfCode = normalizeCbfCode(req.body.cbf_code);
    if (!cbfCode) cbfCode = await resolveCbfCodeForName(req.body.name);
    // fix10e M6: e-posta/telefon benzersizliği (yeni kayıt).
    if (emailClean && await factoryContactTaken('email', emailClean, null)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu e-posta başka bir fabrikada kullanılıyor.' });
    if (phoneClean && await factoryContactTaken('phone', phoneClean, null)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu telefon başka bir fabrikada kullanılıyor.' });
    // FAZ 1 — My Factory hesabi (yeni kayit): kullanici adi cakisirsa 409.
    if (myFactoryUsernameClean) {
      if (await myFactoryUsernameTaken(myFactoryUsernameClean, null)) return res.status(409).json({ error: 'myfactory_username_taken', message: 'Bu ChinaBazaar My Factory kullanıcı adı başka bir fabrikada kullanılıyor.' });
    }
    const { rows } = await pool.query(
      `INSERT INTO factories (name, city, category, description, moq, stock, capacity, certs, features, videos, hashtags, cbf_code, is_verified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13) RETURNING *`,
      [
        String(req.body.name).trim(),
        typeof req.body.city === 'string' ? req.body.city.trim() : '',
        typeof req.body.category === 'string' ? req.body.category.trim() : '',
        typeof req.body.description === 'string' ? req.body.description.trim() : '',
        req.body.moq == null ? 0 : parseInt(req.body.moq, 10),
        req.body.stock == null ? 0 : parseInt(req.body.stock, 10),
        typeof req.body.capacity === 'string' ? req.body.capacity.trim() : '',
        Array.isArray(req.body.certs) ? req.body.certs.map((x) => String(x).trim()).filter(Boolean).join(', ') : (typeof req.body.certs === 'string' ? req.body.certs.trim() : ''),
        Array.isArray(req.body.features) ? req.body.features.map((x) => String(x).trim()).filter(Boolean).join(', ') : (typeof req.body.features === 'string' ? req.body.features.trim() : ''),
        JSON.stringify(videos === undefined ? [] : videos),
        hashtagsClean === undefined ? '' : hashtagsClean,
        cbfCode,
        verifiedCreate,
      ]
    );
    if (addressClean !== undefined || phoneClean !== undefined || contactClean !== undefined || wechatClean !== undefined || whatsappClean !== undefined || emailClean !== undefined || socialsClean !== undefined || tagsClean !== undefined || importCountriesClean !== undefined || employeesClean !== undefined || annualRevenueClean !== undefined || coverImageClean !== undefined || factoryAreaClean !== undefined || yearsClean !== undefined || mainProductsClean !== undefined || myFactoryUsernameClean || myFactoryPasswordHash) {
      const updSets = [];
      const updParams = [rows[0].id];
      const updPush = (col, val, cast) => { updParams.push(val); updSets.push(`${col} = $${updParams.length}${cast || ''}`); };
      if (addressClean !== undefined) updPush('address', addressClean);
      if (phoneClean !== undefined) updPush('phone', phoneClean);
      if (contactClean !== undefined) updPush('contact', contactClean);
      if (wechatClean !== undefined) updPush('wechat', wechatClean);
      if (whatsappClean !== undefined) updPush('whatsapp', whatsappClean);
      if (emailClean !== undefined) updPush('email', emailClean === '' ? null : emailClean);
      if (socialsClean !== undefined) updPush('socials', JSON.stringify(socialsClean), '::jsonb');
      if (tagsClean !== undefined) updPush('tags', tagsClean);
      if (importCountriesClean !== undefined) updPush('import_countries', importCountriesClean);
      if (employeesClean !== undefined) updPush('employees', employeesClean);
      if (annualRevenueClean !== undefined) updPush('annual_revenue', annualRevenueClean);
      if (coverImageClean !== undefined) updPush('cover_image', coverImageClean);
      if (factoryAreaClean !== undefined) updPush('factory_area', factoryAreaClean);
      if (yearsClean !== undefined) updPush('years', yearsClean);
      if (mainProductsClean !== undefined) updPush('main_products', mainProductsClean);
      if (myFactoryUsernameClean) updPush('myfactory_username', myFactoryUsernameClean);
      if (myFactoryPasswordHash) updPush('myfactory_password_hash', myFactoryPasswordHash);
      const upd = await pool.query(`UPDATE factories SET ${updSets.join(', ')} WHERE id = $1 RETURNING *`, updParams);
      if (upd.rows.length) rows[0] = upd.rows[0];
    }
    await attachFactoryBrands(rows); // fix10x
    if (myFactoryUsernameClean) ensureFactoryDomainAlias(myFactoryUsernameClean); // fix10ag: alt alan adi alias'i (fire-and-forget)
    res.status(201).json(toFactoryAdmin(rows[0]));
  })
);

// PUT /api/products/factory/admin/:id — fabrika guncelle, kismi kabul edilir (admin)
router.put('/factory/admin/:id', requireAuth, requireAdmin,
  param('id').isInt({ min: 1 }),
  ...factoryValidators,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    const id = parseInt(req.params.id, 10);
    const sets = [];
    const params = [id];
    const push = (col, val, cast) => { params.push(val); sets.push(`${col} = $${params.length}${cast || ''}`); };
    if (req.body.name !== undefined) push('name', String(req.body.name).trim());
    // FAZ 1 — My Factory hesabi (admin override): kullanici adi cakisirsa 409; sifre bos degilse hash'lenir, bossa mevcut sifre korunur.
    let putAliasUsername = null; // fix10ag: kullanici adi DEGISTIYSE yeni adres, yanittan once doldurulur
    if (req.body.myfactory_username !== undefined || req.body.myfactory_password !== undefined) {
      const myFactoryUsernameCleanPut = cleanMyFactoryUsername(req.body.myfactory_username);
      if (myFactoryUsernameCleanPut === null) return res.status(400).json({ error: 'invalid_myfactory_username', message: 'ChinaBazaar My Factory kullanıcı adı 3-50 karakter olmalı, yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.' });
      const myFactoryPasswordCleanPut = cleanMyFactoryPassword(req.body.myfactory_password);
      if (myFactoryPasswordCleanPut === null) return res.status(400).json({ error: 'invalid_myfactory_password', message: 'ChinaBazaar My Factory şifresi en az 8 karakter olmalı.' });
      if (myFactoryUsernameCleanPut) {
        if (await myFactoryUsernameTaken(myFactoryUsernameCleanPut, id)) return res.status(409).json({ error: 'myfactory_username_taken', message: 'Bu ChinaBazaar My Factory kullanıcı adı başka bir fabrikada kullanılıyor.' });
        // fix10ag: degisiklik tespiti — eski kullanici adi yalniz bu blokta okunur;
        // ayni ad tekrar yazilirsa alias cagrisi yapilmaz.
        const { rows: prevUsernameRows } = await pool.query('SELECT myfactory_username FROM factories WHERE id = $1', [id]);
        const prevUsername = prevUsernameRows.length ? String(prevUsernameRows[0].myfactory_username || '') : '';
        if (prevUsername.trim().toLowerCase() !== myFactoryUsernameCleanPut.toLowerCase()) putAliasUsername = myFactoryUsernameCleanPut;
        push('myfactory_username', myFactoryUsernameCleanPut);
      }
      if (myFactoryPasswordCleanPut) push('myfactory_password_hash', await bcrypt.hash(myFactoryPasswordCleanPut, 12));
    }
    // fix10x (CBOs26.60-A) — ÇOKLU MARKA (admin): gövdede brands[] gelirse fabrikanın marka
    // kümesi TAMAMEN onunla değiştirilir. Doğrulama + çakışma kontrolü BURADA, ana UPDATE
    // çalışmadan ÖNCE yapılır: çakışma varsa 409 brand_taken ve HİÇBİR ŞEY yazılmaz.
    // brands yoksa adminBrandsSet null kalır ve fix10u tekil davranışı (alt blok) geçerlidir;
    // brands varken tekil brand_* alanları yok sayılır (küme önceliklidir).
    let adminBrandsSet = null;
    if (req.body.brands !== undefined) {
      if (!Array.isArray(req.body.brands) || req.body.brands.length > 50) return res.status(400).json({ error: 'invalid_brands', message: 'Marka listesi geçerli değil.' });
      adminBrandsSet = [];
      const seenBrandKeys = new Set();
      for (const entry of req.body.brands) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return res.status(400).json({ error: 'invalid_brands', message: 'Marka listesi geçerli değil.' });
        if (entry.brand_name === undefined || entry.brand_name === null) continue; // adsiz satir atlanir
        if (typeof entry.brand_name !== 'string') return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı geçerli bir metin olmalı.' });
        const entryName = normalizeBrandName(entry.brand_name);
        if (!entryName) continue; // bos satir atlanir
        if (entryName.length > 120) return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı en çok 120 karakter olabilir.' });
        const entryKey = brandKeyOf(entryName);
        if (seenBrandKeys.has(entryKey)) continue; // liste ici tekrar: ilki gecerli
        seenBrandKeys.add(entryKey);
        if (await factoryBrandTaken(entryName, id)) return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
        const entryNo = typeof entry.trademark_no === 'string' ? entry.trademark_no.trim().slice(0, 100) : '';
        const entryOffice = typeof entry.trademark_office === 'string' ? entry.trademark_office.trim().slice(0, 100) : '';
        adminBrandsSet.push({ brand_name: entryName, trademark_no: entryNo === '' ? null : entryNo, trademark_office: entryOffice === '' ? null : entryOffice });
      }
    }
    // fix10u (CBOs26.55-A) — MARKA TESCİLİ beyanı (admin): brand_name verilirse normalize edilir;
    // boşsa beyan temizlenir (üç alan + trademark_declared_at NULL); doluysa (en çok 120 krk)
    // başka fabrikada aynı normalize ad varsa 409 brand_taken, kayıtta trademark_declared_at = now().
    // brand_name verilmeden yalnız trademark_no/trademark_office de güncellenebilir (declared_at korunur).
    // trademark_no/trademark_office en çok 100 karaktere kırpılır; boşsa NULL yazılır.
    // fix10x: bu blok yalniz brands[] YOKKEN calisir; brands[] varken kume onceliklidir.
    if (adminBrandsSet === null && (req.body.brand_name !== undefined || req.body.trademark_no !== undefined || req.body.trademark_office !== undefined)) {
      const brandNoClean = typeof req.body.trademark_no === 'string' ? req.body.trademark_no.trim().slice(0, 100) : '';
      const brandOfficeClean = typeof req.body.trademark_office === 'string' ? req.body.trademark_office.trim().slice(0, 100) : '';
      if (req.body.brand_name !== undefined) {
        if (req.body.brand_name !== null && typeof req.body.brand_name !== 'string') return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı geçerli bir metin olmalı.' });
        const brandCleanPut = req.body.brand_name === null ? '' : normalizeBrandName(req.body.brand_name);
        if (brandCleanPut === '') {
          push('brand_name', null);
          push('trademark_no', null);
          push('trademark_office', null);
          sets.push('trademark_declared_at = NULL');
        } else {
          if (brandCleanPut.length > 120) return res.status(400).json({ error: 'invalid_brand_name', message: 'Marka adı en çok 120 karakter olabilir.' });
          if (await factoryBrandTaken(brandCleanPut, id)) return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
          push('brand_name', brandCleanPut);
          if (req.body.trademark_no !== undefined) push('trademark_no', brandNoClean === '' ? null : brandNoClean);
          if (req.body.trademark_office !== undefined) push('trademark_office', brandOfficeClean === '' ? null : brandOfficeClean);
          sets.push('trademark_declared_at = now()');
        }
      } else {
        if (req.body.trademark_no !== undefined) push('trademark_no', brandNoClean === '' ? null : brandNoClean);
        if (req.body.trademark_office !== undefined) push('trademark_office', brandOfficeClean === '' ? null : brandOfficeClean);
      }
    }
    // CBF kilidi (UPDATE): gecerli kod SABIT'tir — farkli bir kodla degistirilemez.
    // Bozuk bicimli/eksik mevcut kod, gecerli bicimli kodla bir kez duzeltilebilir.
    if (req.body.cbf_code !== undefined) {
      const cbfProvided = normalizeCbfCode(req.body.cbf_code);
      if (cbfProvided) {
        if (!isValidCbfCode(cbfProvided)) return res.status(400).json({ error: 'invalid_cbf_code', message: 'CBF kodu CBF-001 biçiminde olmalı (örn. CBF-001).' });
        const { rows: cbfExistingRows } = await pool.query('SELECT cbf_code FROM factories WHERE id = $1', [id]);
        const cbfExisting = cbfExistingRows.length ? normalizeCbfCode(cbfExistingRows[0].cbf_code) : '';
        if (cbfExisting && isValidCbfCode(cbfExisting) && cbfExisting !== cbfProvided) {
          return res.status(400).json({ error: 'cbf_code_locked', message: 'CBF kodu sabit, değiştirilemez.' });
        }
        if (cbfExisting !== cbfProvided) push('cbf_code', cbfProvided);
      }
    }
    // VERIFIED (UPDATE): body verirse ata, verilmezse degistirme.
    if (req.body.is_verified !== undefined) {
      const verifiedClean = parseFactoryVerified(req.body.is_verified);
      if (verifiedClean === null) return res.status(400).json({ error: 'invalid_is_verified' });
      push('is_verified', verifiedClean);
    }
    if (req.body.city !== undefined) push('city', String(req.body.city).trim());
    if (req.body.category !== undefined) push('category', String(req.body.category).trim());
    if (req.body.description !== undefined) push('description', String(req.body.description).trim());
    if (req.body.moq !== undefined) push('moq', req.body.moq == null ? 0 : parseInt(req.body.moq, 10));
    if (req.body.stock !== undefined) push('stock', req.body.stock == null ? 0 : parseInt(req.body.stock, 10));
    if (req.body.capacity !== undefined) push('capacity', String(req.body.capacity).trim());
    if (req.body.certs !== undefined) push('certs', Array.isArray(req.body.certs) ? req.body.certs.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.certs).trim());
    if (req.body.features !== undefined) push('features', Array.isArray(req.body.features) ? req.body.features.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.features).trim());
    if (req.body.import_countries !== undefined) push('import_countries', Array.isArray(req.body.import_countries) ? req.body.import_countries.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.import_countries).trim());
    if (req.body.employees !== undefined) push('employees', String(req.body.employees).trim());
    if (req.body.annual_revenue !== undefined) push('annual_revenue', String(req.body.annual_revenue).trim());
    if (req.body.factory_area !== undefined) push('factory_area', String(req.body.factory_area).trim());
    if (req.body.years !== undefined) push('years', String(req.body.years).trim());
    if (req.body.main_products !== undefined) push('main_products', Array.isArray(req.body.main_products) ? req.body.main_products.map((x) => String(x).trim()).filter(Boolean).join(', ') : String(req.body.main_products).trim());
    if (req.body.hashtags !== undefined) {
      const hashtagsClean = cleanFactoryHashtags(req.body.hashtags);
      if (hashtagsClean === null) return res.status(400).json({ error: 'invalid_hashtags' });
      push('hashtags', hashtagsClean);
    }
    if (req.body.address !== undefined) {
      const c = cleanFactoryText(req.body.address, 500);
      if (c === null) return res.status(400).json({ error: 'invalid_address' });
      push('address', c);
    }
    if (req.body.phone !== undefined) {
      const c = cleanFactoryText(req.body.phone, 200);
      if (c === null) return res.status(400).json({ error: 'invalid_phone' });
      if (c !== '' && await factoryContactTaken('phone', c, id)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu telefon başka bir fabrikada kullanılıyor.' }); // fix10e M6
      push('phone', c);
    }
    if (req.body.contact !== undefined) {
      const c = cleanFactoryText(req.body.contact, 200);
      if (c === null) return res.status(400).json({ error: 'invalid_contact' });
      push('contact', c);
    }
    if (req.body.wechat !== undefined) {
      const c = cleanFactoryText(req.body.wechat, 200);
      if (c === null) return res.status(400).json({ error: 'invalid_wechat' });
      push('wechat', c);
    }
    if (req.body.whatsapp !== undefined) {
      const c = cleanFactoryText(req.body.whatsapp, 200);
      if (c === null) return res.status(400).json({ error: 'invalid_whatsapp' });
      push('whatsapp', c);
    }
    if (req.body.email !== undefined) {
      const c = cleanFactoryEmail(req.body.email);
      if (c === null) return res.status(400).json({ error: 'invalid_email' });
      if (c !== '' && await factoryContactTaken('email', c, id)) return res.status(409).json({ error: 'contact_in_use', message: 'Bu e-posta başka bir fabrikada kullanılıyor.' }); // fix10e M6
      push('email', c === '' ? null : c);
    }
    if (req.body.socials !== undefined) {
      const c = cleanFactorySocials(req.body.socials);
      if (c === null) return res.status(400).json({ error: 'invalid_socials' });
      push('socials', JSON.stringify(c), '::jsonb');
    }
    if (req.body.tags !== undefined) {
      const c = cleanFactoryTags(req.body.tags);
      if (c === null) return res.status(400).json({ error: 'invalid_tags' });
      push('tags', c);
    }
    if (req.body.videos !== undefined) {
      const videos = cleanFactoryVideos(req.body.videos);
      if (videos === null) return res.status(400).json({ error: 'invalid_videos' });
      push('videos', JSON.stringify(videos), '::jsonb');
    }
    if (req.body.cover_image !== undefined) {
      const c = cleanFactoryCoverImage(req.body.cover_image);
      if (c === null) return res.status(400).json({ error: 'invalid_cover_image' });
      push('cover_image', c);
    }
    // fix10ae: sertifikalar TOPTAN yazilir — dizi degilse cleaner undefined doner (sessizce yok sayilir).
    if (req.body.certificates !== undefined) {
      const c = cleanFactoryCertificates(req.body.certificates);
      if (c !== undefined) push('certificates', JSON.stringify(c), '::jsonb');
    }
    if (!sets.length && adminBrandsSet === null) return res.status(400).json({ error: 'nothing_to_update' });
    let rows;
    if (sets.length) {
      sets.push('updated_at = now()');
      ({ rows } = await pool.query(`UPDATE factories SET ${sets.join(', ')} WHERE id = $1 RETURNING *`, params));
      if (!rows.length) return res.status(404).json({ error: 'factory_not_found' });
    } else {
      // Yalniz brands[] gonderildi: ana UPDATE yok; fabrika varligi dogrulanir.
      const { rows: existsRows } = await pool.query(`SELECT * FROM factories WHERE id = $1`, [id]);
      if (!existsRows.length) return res.status(404).json({ error: 'factory_not_found' });
      rows = existsRows;
    }
    // fix10x: marka kümesi, ana UPDATE başarıyla yazıldıktan SONRA uygulanır (atomik küme değişimi).
    if (adminBrandsSet !== null) {
      try {
        await replaceFactoryBrands(id, adminBrandsSet);
      } catch (e) {
        if (e && e.code === '23505') return res.status(409).json({ error: 'brand_taken', message: 'Bu marka başka bir fabrika tarafından beyan edilmiş.' });
        throw e;
      }
      const { rows: freshRows } = await pool.query(`SELECT * FROM factories WHERE id = $1`, [id]);
      if (freshRows.length) rows = freshRows;
    } else if (req.body.brand_name !== undefined || req.body.trademark_no !== undefined || req.body.trademark_office !== undefined) {
      // fix10x: fix10u tekil yazım yapıldıysa kümeyi kolonlardaki son hâlle senkronla
      // (küme o tek markaya iner; yalnız no/ofis güncellendiyse ilk satır güncellenir).
      try { await reconcileFactoryBrandsFromColumns(id); } catch (e) { /* küme senkronu ana akışı bozmaz */ }
      const { rows: freshRows } = await pool.query(`SELECT * FROM factories WHERE id = $1`, [id]);
      if (freshRows.length) rows = freshRows;
    }
    await attachFactoryBrands(rows);
    if (putAliasUsername) ensureFactoryDomainAlias(putAliasUsername); // fix10ag: alt alan adi alias'i (fire-and-forget)
    res.json(toFactoryAdmin(rows[0]));
  })
);

// fix10ag (CBOs26.82-A) — BACKFILL: kullanici adi olan TUM aktif fabrikalarin
// alt alan adi alias'larini Netlify ile senkronlar (admin elle tetikler).
// POST /api/products/factory/admin/sync-domain-aliases
// Env yoksa { ok:false, reason:'netlify_not_configured' } — sahte basari donmez.
router.post('/factory/admin/sync-domain-aliases', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const cfg = netlifyFactoryCfg();
  if (!cfg) return res.json({ ok: false, reason: 'netlify_not_configured' });
  await ensureFactoryTables();
  const { rows } = await pool.query(
    `SELECT myfactory_username FROM factories WHERE myfactory_username IS NOT NULL AND TRIM(myfactory_username) <> '' AND COALESCE(is_active, true) = true`
  );
  for (const row of rows) {
    await ensureFactoryDomainAlias(row.myfactory_username);
  }
  let aliases = [];
  try { aliases = await fetchNetlifyDomainAliases(cfg); } catch (e) { console.error('[fix10ag] sync-domain-aliases liste:', e && e.message); }
  res.json({ ok: true, checked: rows.length, aliases });
}));

// DELETE /api/products/factory/admin/:id — fabrika sil (admin)
router.delete('/factory/admin/:id', requireAuth, requireAdmin, param('id').isInt({ min: 1 }), asyncHandler(async (req, res) => {
  if (!checkValidation(req, res)) return;
  await ensureFactoryTables();
  const { rows } = await pool.query('DELETE FROM factories WHERE id = $1 RETURNING id', [parseInt(req.params.id, 10)]);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found' });
  res.json({ ok: true });
}));

// PATCH /api/products/factory/admin/:id/active — fabrika ac/kapa (admin; Admin v635 Fabrika Listesi Kapat/Ac)
router.patch('/factory/admin/:id/active', requireAuth, requireAdmin, param('id').isInt({ min: 1 }), asyncHandler(async (req, res) => {
  if (!checkValidation(req, res)) return;
  if (typeof req.body?.is_active !== 'boolean') return res.status(400).json({ error: 'invalid_is_active' });
  await ensureFactoryTables();
  const { rows } = await pool.query('UPDATE factories SET is_active = $2, updated_at = now() WHERE id = $1 RETURNING *', [parseInt(req.params.id, 10), req.body.is_active]);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found' });
  await attachFactoryBrands(rows); // fix10x
  res.json(toFactoryAdmin(rows[0]));
}));

// GET /api/products/factory/admin/subscriptions — abonelik listesi (admin; e-posta burada doner, baska yerde donulmez)
router.get('/factory/admin/subscriptions', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(
    `SELECT fs.id, fs.user_id, COALESCE(NULLIF(u.nickname,''), NULLIF(u.name,''), split_part(u.email,'@',1), '') AS name, u.email AS email, fs.status, fs.plan, fs.started_at, COALESCE(fs.expires_at, fs.ends_at) AS expires_at, fs.ends_at, fs.amount, fs.currency
     FROM factory_subscriptions fs LEFT JOIN users u ON u.id::text = fs.user_id::text
     ORDER BY fs.created_at DESC, fs.id DESC`
  );
  res.json(rows.map((r) => ({ id: r.id, user_id: r.user_id, name: r.name || '', email: r.email || null, status: r.status, plan: r.plan || null, started_at: r.started_at, expires_at: r.expires_at, ends_at: r.ends_at, amount: r.amount, currency: r.currency })));
}));

// Abonelik / VIP — admin_grant: odeme kaydi OLMAYAN tamamlayici abonelik.
// provider='admin_grant' satirlari ASLA sahte PayTR/odeme kaydi degildir: paytr_merchant_oid
// bos birakilir, amount yazilmaz. Aktiflik tanimi saglayicidan bagimsizdir:
// status='active' AND (expires_at IS NULL OR expires_at > now()) — provider'a gore
// filtre YOK, yani admin_grant satiri odemeli aktif satirla birebir ayni sayilir.
// Eski odemeli satirlarda yalniz ends_at dolu olabilir; okuma COALESCE(expires_at, ends_at) ile yapilir.
// UYELIK KAPISI: factory/quotes ve factory/messages olusturma su an ACIK (uyelik kontrolu yok);
// bu gorevde kilitlenmedi — mevcut davranis aynen korundu.

// fix10w: abonelik muafiyeti — CBAI master veya is_admin kullanici.
// Master: jeton iddiasi (requireAuth, payload'dan req.user'a tasir). Admin: once
// req.user.is_admin iddiasi; iddia yoksa users.is_admin DB kontrolu (canli giris
// jetonu is_admin TASIMAYABILIR — requireAdmin/middleware de ayni DB yolunu
// kullanir). DB hatasinda muaf SAYILMAZ, normal abonelik akisina dusulur.
async function isSubscriptionExemptUser(req) {
  const u = req.user || {};
  if (u.role === 'master' && u.is_admin === true) return true;
  if (u.is_admin === true) return true;
  if (u.id === null || u.id === undefined || u.id === '') return false;
  try {
    const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [u.id]);
    return !!rows[0]?.is_admin;
  } catch { return false; }
}

// GET /api/products/factory/subscription/me — giris yapan kullanicinin kendi aboneligi (baskasinin satiri donulmez)
// { has_active, plan, expires_at, is_vip } — is_vip = aktif + plan='yearly' (on yuz VIP rozeti icin).
// fix10w: admin/master MUAF — plan 'admin' ile aktif donulur, tabloya satir YAZILMAZ.
router.get('/factory/subscription/me', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  // fix10w: admin/master muafiyeti yalniz yanit duzeyindedir (sahte odeme kaydi yaratilmaz).
  if (await isSubscriptionExemptUser(req)) {
    return res.json({ has_active: true, active: true, plan: 'admin', expires_at: null, is_vip: true });
  }
  const { rows } = await pool.query(
    `SELECT id, user_id, status, plan, provider, started_at, COALESCE(expires_at, ends_at) AS expires_at
     FROM factory_subscriptions
     WHERE user_id = $1 AND status = 'active'
       AND (COALESCE(expires_at, ends_at) IS NULL OR COALESCE(expires_at, ends_at) > now())
     ORDER BY COALESCE(expires_at, ends_at) DESC NULLS LAST, id DESC LIMIT 1`,
    [String(req.user.id)]
  );
  if (!rows.length) return res.json({ has_active: false, plan: null, expires_at: null, is_vip: false });
  const plan = rows[0].plan || null;
  res.json({ has_active: true, plan, expires_at: rows[0].expires_at, is_vip: plan === 'yearly' });
}));

// POST /api/products/factory/admin/subscriptions/grant — admin tamamlayici abonelik tanimlar.
// Body { identifier, plan='yearly', months=12 }. identifier = e-posta veya nickname
// (bastaki @ isaretleri atilir: "@iiec" -> "iiec").
// (giris ile ayni eslesme: auth.js — LOWER(email) / LOWER(nickname)).
// Tabloda user_id UNIQUE yok; aktif satir varsa mukerrer olusturulmadan guncellenir
// (select-then-update), yoksa yeni aktif satir eklenir. Donus: olusturulan/guncellenen satir
// (sifre/token/baska kullanici verisi yok).
router.post('/factory/admin/subscriptions/grant', requireAuth, requireAdmin,
  body('identifier').optional().isString().trim().isLength({ min: 1, max: 320 }),
  body('plan').optional().isString().trim(),
  body('months').optional().isInt(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryTables();
    const identifierRaw = typeof req.body.identifier === 'string' ? req.body.identifier.trim() : '';
    // VIP FIX: "@iiec" -> "iiec" — bastaki @ isaretleri (hepsi) atilir, yoksa nickname eslesmez.
    const identifier = identifierRaw.replace(/^@+/, '');
    if (!identifier) return res.status(400).json({ error: 'identifier_required' });
    const plan = typeof req.body.plan === 'string' && req.body.plan.trim() ? req.body.plan.trim() : 'yearly';
    if (!['monthly', 'yearly'].includes(plan)) return res.status(400).json({ error: 'invalid_plan' });
    const monthsRaw = (req.body.months === undefined || req.body.months === null || req.body.months === '') ? 12 : req.body.months;
    const months = Number(monthsRaw);
    if (!Number.isInteger(months) || months < 1 || months > 60) return res.status(400).json({ error: 'invalid_months' });
    const { rows: urows } = await pool.query(
      `SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(nickname) = LOWER($1)
       ORDER BY CASE WHEN LOWER(email) = LOWER($1) THEN 0 ELSE 1 END LIMIT 1`,
      [identifier]
    );
    if (!urows.length) return res.status(404).json({ error: 'user_not_found' });
    const userId = String(urows[0].id);
    const { rows: existing } = await pool.query(
      `SELECT id FROM factory_subscriptions WHERE user_id = $1 AND status = 'active'
       ORDER BY COALESCE(expires_at, ends_at) DESC NULLS LAST, id DESC LIMIT 1`,
      [userId]
    );
    const RETURNING = `RETURNING id, user_id, status, plan, provider, started_at, expires_at, ends_at, amount, currency, created_at, updated_at`;
    let row;
    let statusCode = 200;
    if (existing.length) {
      const { rows } = await pool.query(
        `UPDATE factory_subscriptions SET plan = $2, provider = 'admin_grant', status = 'active',
         started_at = now(), expires_at = now() + ($3 * INTERVAL '1 month'), ends_at = now() + ($3 * INTERVAL '1 month'),
         updated_at = now() WHERE id = $1 ${RETURNING}`,
        [existing[0].id, plan, months]
      );
      row = rows[0];
    } else {
      const { rows } = await pool.query(
        `INSERT INTO factory_subscriptions (user_id, status, plan, provider, started_at, expires_at, ends_at)
         VALUES ($1, 'active', $2, 'admin_grant', now(), now() + ($3 * INTERVAL '1 month'), now() + ($3 * INTERVAL '1 month')) ${RETURNING}`,
        [userId, plan, months]
      );
      row = rows[0];
      statusCode = 201;
    }
    // Admin grant'i hesabı MyFactory müşterisi olarak da kaydeder (Müşteriler listesi
    // source='myfactory' filtresine girsin diye — örn. kaynak takibi başlamadan önce
    // kayıt olan eski hesaplar 'shop'/NULL sayıldığı için listede görünmüyordu).
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'shop'`);
    const { rowCount: sourceUpdatedCount } = await pool.query(
      `UPDATE users SET source = 'myfactory' WHERE id = $1 AND (source IS NULL OR source <> 'myfactory')`,
      [userId]
    );
    res.status(statusCode).json({ subscription: row, source_updated: sourceUpdatedCount > 0 });
  })
);


// v620: Factory mesajlasma (CBAI — SADECE MyFactory'den gelen konusmalar; magaza CBAI'ndan ayri)
// Tum /factory/* rotalari GET /:id ONCESINE kayitli — /:id bunlari yutmaz.
// E-posta adresleri hicbir yanitta donulmez (isim/nickname yeterli).
async function ensureFactoryMessagesTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_messages (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT now())`);
  // Canli DB'deki tablo eski surumle olusmus olabilir — CREATE TABLE IF NOT EXISTS
  // eksik sutunu eklemez; SELECT m.body ... bu yuzden 500 (internal_error) atiyordu.
  // Tum sutunlar ADD COLUMN IF NOT EXISTS ile guvenceye alinir (products marketplace/warranty deseni).
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS body TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS sender TEXT NOT NULL DEFAULT 'user'`);
  // CBOs26.2: mesajin hangi fabrikaya ait oldugu (fabrika paneli sohbeti icin).
  // NULL = eski/global mesaj (yalniz admin gorur, hicbir fabrika gormez).
  try { await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS factory_id INT`); } catch (e) { /* yoksay */ }
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS attachment_url TEXT`);
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'text'`);
  // CBOs26.5 (fix10i): fabrika tarafindan goruldu bayragi (bildirim zili icin).
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS seen_by_factory BOOLEAN DEFAULT FALSE`);
// fix6: dosya eki meta alanlari (PDF/Excel/resim) — her biri kendi try/catch'inde, e-posta deseni.
  try { await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS attachment_name TEXT`); } catch (e) { /* attachment_name eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS attachment_size INT`); } catch (e) { /* attachment_size eklenemezse akis bozulmaz */ }
  try { await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS attachment_mime TEXT`); } catch (e) { /* attachment_mime eklenemezse akis bozulmaz */ }
// fix7: sohbet dosyalari Postgres'te saklanir (Railway diski gecici — her redeploy
// yuklenen dosyalari siler, bu yuzden resimler bozuluyordu). token = tahmin edilemez URL anahtari.
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_chat_files (id SERIAL PRIMARY KEY, token TEXT NOT NULL UNIQUE, data BYTEA NOT NULL, mime TEXT NOT NULL, name TEXT, size INT, created_at TIMESTAMPTZ DEFAULT now())`);
  // fix10e M5: sahiplik + süreli URL — yükleyen (kullanıcı id / factory:<id> /
  // cbai:master) ve son kullanma (yüklemeden 7 gün sonra) saklanır.
  try { await pool.query(`ALTER TABLE factory_chat_files ADD COLUMN IF NOT EXISTS uploaded_by TEXT`); } catch (e) { /* yoksay */ }
  try { await pool.query(`ALTER TABLE factory_chat_files ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`); } catch (e) { /* yoksay */ }
  // v118: user_id tip onarimi (users.id UUID) — mesaj rotalari ensureFactoryTables'i
  // cagirmadigindan bu tablo icin donusum burada da calisir.
  try { await pool.query(`ALTER TABLE factory_messages ALTER COLUMN user_id TYPE TEXT USING user_id::text`); } catch (e) { /* tip zaten TEXT ise yoksay */ }
}

// Mesaj eki dogrulama: http(s) URL, /uploads/ yolu veya DB sohbet dosyasi URL'i kabul edilir.
// fix7: /api/products/factory/chat-file/<id>/<token> sekli de gecerli (eski /uploads/ URL'leri aynen).
function factoryMsgAttachmentOk(url) {
  return /^https?:\/\//i.test(url) || /^\/uploads\//i.test(url) || /^\/api\/products\/factory\/chat-file\/\d+\/[a-f0-9]{32}$/i.test(url);
}

// fix6: sohbet dosya ekleri — izinli turler (resim + PDF + Excel). Yurutulebilir/komut
// dosyalari (.exe/.js/.html/.svg/.bat/.sh vb.) bu listede YOK, asla kabul edilmez.
// fix7: + video (mp4/webm).
const CHAT_UPLOAD_MIME = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif',
  'application/pdf': 'pdf',
  'application/vnd.ms-excel': 'xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'video/mp4': 'mp4', 'video/webm': 'webm',
};
const CHAT_UPLOAD_MAX = 10 * 1024 * 1024; // 10 MB

// fix10ae (CBOs26.79-A): kind=cert yuklemeleri — fabrika SERTIFIKA belgeleri.
// Yalniz PDF + resim kabul edilir (Excel/video cert olarak yuklenemez); ayni
// sihirli bayt denetimi + <=10MB kurali gecerlidir. Kalicilik kind=cover
// desenindedir (expires_at NULL) ve cover gibi yalniz fabrika/master kullanir.
const CERT_UPLOAD_MIME = { 'application/pdf': true, 'image/jpeg': true, 'image/png': true, 'image/webp': true, 'image/gif': true };

// Dosya adi temizleme: basename al, yol ayiraci + kontrol karakterlerini at, en fazla 200 karakter.
function sanitizeChatFilename(name) {
  if (typeof name !== 'string') return '';
  const base = name.split(/[\\/]/).pop() || '';
  return base.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 200);
}

// fix6: mesaj eki meta dogrulama — kullanici + admin gonderim uclari ortak kullanir.
// Donus: { ok:true, attachmentUrl, kind, name, size, mime } veya { ok:false, status, error }.
function cleanChatAttachment(body) {
  const text = (body.body || '').trim();
  const attachmentUrl = typeof body.attachment_url === 'string' ? body.attachment_url.trim() : '';
  const rawKind = body.kind;
  let name = null, size = null, mime = null;
  if (typeof body.attachment_name === 'string' && body.attachment_name.trim()) {
    name = sanitizeChatFilename(body.attachment_name);
    if (!name) return { ok: false, status: 400, error: 'invalid_attachment_name' };
  }
  if (body.attachment_size !== undefined && body.attachment_size !== null && body.attachment_size !== '') {
    const n = Number(body.attachment_size);
    if (!Number.isInteger(n) || n < 0 || n > CHAT_UPLOAD_MAX) return { ok: false, status: 400, error: 'invalid_attachment_size' };
    size = n;
  }
  if (typeof body.attachment_mime === 'string' && body.attachment_mime.trim()) {
    mime = body.attachment_mime.trim().toLowerCase();
    if (!CHAT_UPLOAD_MIME[mime]) return { ok: false, status: 400, error: 'unsupported_file_type' };
  }
  if (attachmentUrl) {
    if (!factoryMsgAttachmentOk(attachmentUrl)) return { ok: false, status: 400, error: 'invalid_attachment_url' };
    const inferred = mime ? (mime.startsWith('image/') ? 'image' : mime.startsWith('video/') ? 'video' : 'file') : null;
    let kind;
    if (rawKind === 'image' || rawKind === 'file' || rawKind === 'video') {
      kind = rawKind;
      if (inferred && inferred !== kind) return { ok: false, status: 400, error: 'invalid_attachment_kind' };
    } else {
      kind = inferred || 'image';
    }
    return { ok: true, attachmentUrl, kind, name, size, mime };
  }
  if (name || size !== null || mime) return { ok: false, status: 400, error: 'invalid_attachment_url' };
  if (rawKind === 'image' || rawKind === 'file' || rawKind === 'video') return { ok: false, status: 400, error: 'invalid_attachment_url' };
  if (!text) return { ok: false, status: 400, error: 'empty_message' };
  return { ok: true, attachmentUrl: null, kind: 'text', name: null, size: null, mime: null };
}

// POST /api/products/factory/messages {body?, attachment_url?, kind?} — kullanici mesaj gonderir (sender='user')
// Yazi, resim, dosya veya video: ekte body bos olabilir; en az biri dolu olmali.
router.post('/factory/messages', requireAuth, factorySpamLimiter,
  body('body').optional().trim().isLength({ max: 1000 }),
  body('attachment_url').optional().isString().isLength({ max: 2048 }),
  body('kind').optional().isIn(['text', 'image', 'file', 'video']),
  body('attachment_name').optional().isString().isLength({ max: 200 }),
  body('attachment_size').optional().isInt({ min: 0, max: 10485760 }),
  body('attachment_mime').optional().isString().isLength({ max: 100 }),
  body('factory_id').optional().isInt({ min: 1 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    // CBOs26.2: fabrika kapsamli mesaj (fabrika sayfasindan gonderildiyse).
    let msgFactoryId = null;
    if (req.body.factory_id !== undefined && req.body.factory_id !== null && req.body.factory_id !== '') {
      msgFactoryId = Number(req.body.factory_id);
      if (!Number.isInteger(msgFactoryId) || msgFactoryId < 1) return res.status(400).json({ error: 'invalid_factory_id' });
      const { rows: frows } = await pool.query('SELECT id FROM factories WHERE id = $1', [msgFactoryId]);
      if (!frows.length) return res.status(400).json({ error: 'factory_not_found' });
    }
    const text = (req.body.body || '').trim();
    const att = cleanChatAttachment(req.body);
    if (!att.ok) return res.status(att.status).json({ error: att.error });
    // fix10e M5: sohbet dosyası eki başkasına ait olamaz.
    if (att.attachmentUrl && att.attachmentUrl.startsWith('/api/products/factory/chat-file/')) {
      if (!(await chatFileOwnedBy(att.attachmentUrl, req.user.id))) return res.status(403).json({ error: 'forbidden' });
    }
    const { rows } = await pool.query(
      `INSERT INTO factory_messages (user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime, factory_id) VALUES ($1, $2, 'user', $3, $4, $5, $6, $7, $8) RETURNING id, user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime, factory_id, created_at`,
      [req.user.id, text, att.attachmentUrl, att.kind, att.name, att.size, att.mime, msgFactoryId]
    );
    res.status(201).json({ message: rows[0] });
  })
);

// GET /api/products/factory/messages — giris yapan kullanicinin kendi konusmasi (eskiden yeniye)
router.get('/factory/messages', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  const { rows } = await pool.query(
    `SELECT m.id, m.user_id, m.body, m.sender, m.attachment_url, m.kind, m.attachment_name, m.attachment_size, m.attachment_mime, m.factory_id, f.name AS factory_name, m.created_at FROM factory_messages m LEFT JOIN factories f ON f.id = m.factory_id WHERE m.user_id=$1 ORDER BY m.created_at ASC, m.id ASC`,
    [req.user.id]
  );
  res.json({ messages: rows });
}));

// Teklif istekleri (Profil > Tekliflerim) — Teklif Al formu e-posta ile gonderilirken bir kopya da burada saklanir.
async function ensureFactoryQuotesTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_quotes (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, factory TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL DEFAULT '', qty TEXT NOT NULL DEFAULT '', msg TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE factory_quotes ADD COLUMN IF NOT EXISTS factory_id INT`);
  // CBOs26.5 (fix10i): fabrika tarafindan goruldu bayragi (bildirim zili icin).
  await pool.query(`ALTER TABLE factory_quotes ADD COLUMN IF NOT EXISTS seen_by_factory BOOLEAN DEFAULT FALSE`);
  // v118: user_id tip onarimi (users.id UUID) — teklif rotalari ensureFactoryTables'i
  // cagirmadigindan bu tablo icin donusum burada da calisir.
  try { await pool.query(`ALTER TABLE factory_quotes ALTER COLUMN user_id TYPE TEXT USING user_id::text`); } catch (e) { /* tip zaten TEXT ise yoksay */ }
}

// POST /api/products/factory/quotes — teklif istegi kaydet
router.post('/factory/quotes', requireAuth,
  body('factory').optional().trim().isLength({ max: 500 }),
  body('name').optional().trim().isLength({ max: 200 }),
  body('contact').optional().trim().isLength({ max: 200 }),
  body('qty').optional().trim().isLength({ max: 50 }),
  body('msg').optional().trim().isLength({ max: 2000 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryQuotesTable();
    const rawFid = req.body.factory_id;
    const factoryId = (typeof rawFid === 'number' && Number.isInteger(rawFid) && rawFid > 0) ? rawFid : (typeof rawFid === 'string' && /^\d+$/.test(rawFid.trim()) ? parseInt(rawFid.trim(), 10) : null);
    const { rows } = await pool.query(
      `INSERT INTO factory_quotes (user_id, factory, factory_id, name, contact, qty, msg) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, factory, factory_id, name, contact, qty, msg, created_at`,
      [req.user.id, req.body.factory || '', factoryId, req.body.name || '', req.body.contact || '', req.body.qty || '', req.body.msg || '']
    );
    res.status(201).json({ quote: rows[0] });
  })
);

// GET /api/products/factory/quotes — kendi teklif isteklerim (yeniden eskiye)
router.get('/factory/quotes', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryQuotesTable();
  const { rows } = await pool.query(
    `SELECT id, factory, factory_id, name, contact, qty, msg, created_at FROM factory_quotes WHERE user_id=$1 ORDER BY created_at DESC, id DESC`,
    [req.user.id]
  );
  res.json({ quotes: rows });
}));

// GET /api/products/factory/admin/messages — tum konusmalar, kullaniciya gore gruplu (admin)
router.get('/factory/admin/messages', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  const { rows } = await pool.query(
    `SELECT m.id, m.user_id, m.body, m.sender, m.attachment_url, m.kind, m.attachment_name, m.attachment_size, m.attachment_mime, m.created_at,
            COALESCE(NULLIF(u.nickname,''), NULLIF(u.name,''), split_part(u.email,'@',1), 'Misafir') AS name
     FROM factory_messages m LEFT JOIN users u ON u.id::text = m.user_id::text
     ORDER BY m.user_id ASC, m.created_at ASC, m.id ASC`
  );
  const byUser = new Map();
  for (const r of rows) {
    if (!byUser.has(r.user_id)) byUser.set(r.user_id, { user_id: r.user_id, name: r.name || 'Misafir', messages: [] });
    byUser.get(r.user_id).messages.push({ id: r.id, body: r.body, sender: r.sender, attachment_url: r.attachment_url || null, kind: r.kind || 'text', attachment_name: r.attachment_name || null, attachment_size: r.attachment_size ?? null, attachment_mime: r.attachment_mime || null, created_at: r.created_at });
  }
  res.json({ conversations: [...byUser.values()] });
}));

// POST /api/products/factory/admin/messages/:id/reply {body?, attachment_url?, kind?} — admin cevap gonderir (sender='admin'); :id = user_id
router.post('/factory/admin/messages/:id/reply', requireAuth, requireAdmin,
  param('id').isString().trim().isLength({ min: 1, max: 100 }),
  body('body').optional().trim().isLength({ max: 1000 }),
  body('attachment_url').optional().isString().isLength({ max: 2048 }),
  body('kind').optional().isIn(['text', 'image', 'file', 'video']),
  body('attachment_name').optional().isString().isLength({ max: 200 }),
  body('attachment_size').optional().isInt({ min: 0, max: 10485760 }),
  body('attachment_mime').optional().isString().isLength({ max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    const userId = String(req.params.id);
    const { rows: urows } = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (!urows.length) return res.status(404).json({ error: 'user_not_found' });
    const text = (req.body.body || '').trim();
    const att = cleanChatAttachment(req.body);
    if (!att.ok) return res.status(att.status).json({ error: att.error });
    const { rows } = await pool.query(
      `INSERT INTO factory_messages (user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime) VALUES ($1, $2, 'admin', $3, $4, $5, $6, $7) RETURNING id, user_id, body, sender, attachment_url, kind, attachment_name, attachment_size, attachment_mime, created_at`,
      [userId, text, att.attachmentUrl, att.kind, att.name, att.size, att.mime]
    );
    res.status(201).json({ message: rows[0] });
  })
);

// fix10e M5: sohbet dosyası sahiplik doğrulaması — chat-file URL'si bir mesaja
// eklenirken dosyanın o kullanıcıya ait olduğu doğrulanır. Eski satırlar
// (uploaded_by NULL) geriye uyum için kabul edilir; başkasının dosyası 403.
async function chatFileOwnedBy(url, ownerId) {
  const m = /^\/api\/products\/factory\/chat-file\/(\d+)\/([a-f0-9]{32})$/i.exec(String(url || '').trim());
  if (!m) return false;
  const { rows } = await pool.query(`SELECT uploaded_by, expires_at FROM factory_chat_files WHERE id = $1 AND token = $2`, [parseInt(m[1], 10), m[2]]);
  if (!rows.length) return false;
  if (rows[0].expires_at && new Date(rows[0].expires_at).getTime() < Date.now()) return false;
  if (!rows[0].uploaded_by) return true; // kayıt öncesi eski satır: geriye uyum
  return String(rows[0].uploaded_by) === String(ownerId);
}

// fix10e M5: chat-upload hız limiti — aktör başına 15 dakikada 30 dosya
// (kullanıcı id / fabrika id / IP; v8'de req.ip doğrudan kullanılmaz).
const chatUploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
  keyGenerator: (req) => 'chat-upload:' + (req.factoryId != null ? 'factory:' + req.factoryId : req.isMaster ? 'master' : req.user && req.user.id ? 'user:' + String(req.user.id) : ipKeyGenerator(req.ip)),
});

// POST /api/products/factory/chat-upload — CBAI sohbetine dosya yukle (giris yapmis kullanici)
// fix10c: ChinaBazaar My Factory fabrika jetonu (role 'factory') de kabul edilir.
// On yuz FormData ile gonderir (alan: `file`); ham dosya govdesi de kabul edilir.
// Multer pakette yok — multipart siniri (boundary) elle cozumlenir, yeni bagimlilik yok.
// fix6: resim (jpg/png/webp/gif) + PDF + Excel (xls/xlsx), en fazla 10MB, sihirli bayt
// kontrolu, uzanti+MIME capraz dogrulama, temizlenmis orijinal ad.
// fix7: + video (mp4/webm). Dosya diske DEGIL Postgres'e (factory_chat_files) yazilir —
// Railway diski her redeploy'da silindigi icin diske yazilan resimler bozuluyordu.
// Donen URL /api/products/factory/chat-file/:id/:token uzerinden DB'den akar, redeploy'dan etkilenmez.
// CHAT_UPLOAD_MIME + CHAT_UPLOAD_MAX + sanitizeChatFilename + cleanChatAttachment fix6'da
// mesaj uclarinin ustunde tanimli (ortak kullanim).

function chatUploadMagicOk(buf, mime) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  if (mime === 'image/jpeg') return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  if (mime === 'image/png') return buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a;
  if (mime === 'image/gif') return buf.toString('ascii', 0, 6) === 'GIF87a' || buf.toString('ascii', 0, 6) === 'GIF89a';
  if (mime === 'image/webp') return buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP';
  if (mime === 'application/pdf') return buf.toString('ascii', 0, 5) === '%PDF-';
  if (mime === 'application/vnd.ms-excel') return buf.length >= 8 && buf[0] === 0xd0 && buf[1] === 0xcf && buf[2] === 0x11 && buf[3] === 0xe0 && buf[4] === 0xa1 && buf[5] === 0xb1 && buf[6] === 0x1a && buf[7] === 0xe1;
  if (mime === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') return buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  if (mime === 'video/mp4') return buf.length >= 8 && buf.toString('ascii', 4, 8) === 'ftyp';
  if (mime === 'video/webm') return buf.length >= 4 && buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3;
  return false;
}

// Multipart (FormData) govdeden `file` alanini cikarir — Buffer uzerinde calisir, ikili veri bozulmaz.
function parseMultipartFile(buf, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  const boundary = m && (m[1] || m[2] || '').trim();
  if (!boundary) return null;
  const delim = Buffer.from('--' + boundary);
  let idx = buf.indexOf(delim);
  if (idx < 0) return null;
  let pos = idx + delim.length;
  while (pos < buf.length) {
    if (buf[pos] === 0x0d && buf[pos + 1] === 0x0a) pos += 2;
    else if (buf[pos] === 0x0a) pos += 1;
    if (buf[pos] === 0x2d && buf[pos + 1] === 0x2d) break; // kapanis siniri
    const headerEnd = buf.indexOf('\r\n\r\n', pos);
    if (headerEnd < 0) break;
    const headers = buf.subarray(pos, headerEnd).toString('latin1');
    const dataStart = headerEnd + 4;
    const nextDelim = Buffer.from('\r\n--' + boundary);
    let dataEnd = buf.indexOf(nextDelim, dataStart);
    if (dataEnd < 0) {
      dataEnd = buf.indexOf(delim, dataStart);
      if (dataEnd < 0) break;
    }
    const nameMatch = /name="([^"]*)"/i.exec(headers);
    if (nameMatch && nameMatch[1] === 'file') {
      const typeMatch = /content-type:\s*([^\r\n;]+)/i.exec(headers);
      const fnMatch = /filename="([^"]*)"/i.exec(headers); // fix6: orijinal dosya adi (meta icin)
      return {
        data: Buffer.from(buf.subarray(dataStart, dataEnd)),
        contentType: typeMatch ? typeMatch[1].trim().toLowerCase() : '',
        filename: fnMatch ? fnMatch[1] : '',
      };
    }
    pos = dataEnd + nextDelim.length;
  }
  return null;
}

// Ham govde cozumleyicisi: boyut asimi global 500'e degil 413'e donsun.
function rawBodyParser(opts) {
  const parser = express.raw(opts);
  return (req, res, next) => {
    parser(req, res, (err) => {
      if (err) {
        if (err.type === 'entity.too.large') return res.status(413).json({ error: 'file_too_large' });
        return res.status(400).json({ error: 'invalid_body' });
      }
      next();
    });
  };
}

router.post(
  '/factory/chat-upload',
  requireUserOrFactoryAuth,
  chatUploadLimiter,
  rawBodyParser({ type: '*/*', limit: '11mb' }),
  asyncHandler(async (req, res) => {
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    let file = null;
    if (ct === 'multipart/form-data') {
      if (!Buffer.isBuffer(req.body)) return res.status(400).json({ error: 'invalid_body' });
      file = parseMultipartFile(req.body, String(req.headers['content-type'] || ''));
      if (!file) return res.status(400).json({ error: 'empty_file' });
    } else if (CHAT_UPLOAD_MIME[ct]) {
      if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'empty_file' });
      file = { data: req.body, contentType: ct, filename: '' };
    } else {
      return res.status(400).json({ error: 'unsupported_file_type' });
    }
    const mime = file.contentType;
    if (!CHAT_UPLOAD_MIME[mime]) return res.status(400).json({ error: 'unsupported_file_type' });
    // fix10ae: kind=cert (fabrika/master) — sertifika belgesi yalniz PDF/resim
    // olabilir; Excel/video gibi diger izinli sohbet turleri cert olarak reddedilir.
    const isCert = String(req.query.kind || '').toLowerCase() === 'cert' && (req.factoryId != null || req.isMaster);
    if (isCert && !CERT_UPLOAD_MIME[mime]) return res.status(400).json({ error: 'unsupported_file_type' });
    // fix10e M5: mime/boyut çapraz kontrolü — beyan edilen boyut (multipart
    // Content-Length / gövde uzunluğu) gerçek arabellek uzunluğuyla aynı
    // olmalı; uyuşmazlık reddedilir. (file.data.length gövdenin kendisidir;
    // ayrıca Content-Length başlığı varsa onunla da karşılaştırılır.)
    const declaredLen = parseInt(req.headers['content-length'] || '', 10);
    if (Number.isInteger(declaredLen) && declaredLen >= 0 && String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'multipart/form-data' && declaredLen !== file.data.length) {
      return res.status(400).json({ error: 'invalid_file' });
    }
    if (file.data.length > CHAT_UPLOAD_MAX) return res.status(400).json({ error: 'file_too_large' });
    if (!chatUploadMagicOk(file.data, mime)) return res.status(415).json({ error: 'invalid_file' });
    // Uzanti + MIME capraz dogrulama (multipart'ta dosya adi varsa): uzanti MIME ile eslesmeli.
    if (file.filename) {
      const extMatch = /\.([A-Za-z0-9]+)$/.exec(file.filename.trim());
      // fix10m (CBOs26.19): .jpeg uzantısı image/jpeg için kabul edilir (jpg takma adı).
      const extLower = extMatch ? extMatch[1].toLowerCase() : '';
      const expectedExt = CHAT_UPLOAD_MIME[mime];
      const extOk = !!extMatch && (expectedExt === extLower || (expectedExt === 'jpg' && extLower === 'jpeg'));
      if (!extOk) return res.status(400).json({ error: 'unsupported_file_type' });
    }
    // fix7: dosya diske DEGIL Postgres'e yazilir (Railway diski her redeploy'da silinir).
    await ensureFactoryMessagesTable();
    const displayName = sanitizeChatFilename(file.filename) || ('dosya.' + CHAT_UPLOAD_MIME[mime]);
    const token = crypto.randomBytes(16).toString('hex');
    // fix10e M5: sahip + süre (7 gün) kaydedilir.
    const ownerId = req.factoryId != null ? 'factory:' + req.factoryId : req.isMaster ? 'cbai:master' : (req.user && req.user.id ? String(req.user.id) : null);
    // fix10l (CBOs26.16): kapak yüklemesi SÜRESİZ — fabrika/master ?kind=cover ile yükler
    // (kapak banner'ı 7 günde ölmemeli). Normal kullanıcılar kind=cover KULLANAMAZ (depolama şişmesin).
    const isCover = String(req.query.kind || '').toLowerCase() === 'cover' && (req.factoryId != null || req.isMaster);
    // fix10ae: kind=cert de SÜRESİZ saklanir (sertifika belgesi 7 gunde olmemeli) — cover deseni.
    const { rows } = await pool.query(
      `INSERT INTO factory_chat_files (token, data, mime, name, size, uploaded_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, ${isCover || isCert ? 'NULL' : "now() + interval '7 days'"}) RETURNING id`,
      [token, file.data, mime, displayName, file.data.length, ownerId]
    );
    const base = req.protocol + '://' + req.get('host');
    res.status(201).json({ ok: true, url: base + '/api/products/factory/chat-file/' + rows[0].id + '/' + token, filename: displayName, size: file.data.length, mime });
  })
);

// fix7: GET /api/products/factory/chat-file/:id/:token — DB'deki sohbet dosyasini akar.
// Kimlik dogrulama YOK: token tahmin edilemez (32 hex), URL'yi bilen indirir.
// ?download=1 ise Content-Disposition: attachment (bilgisayara kaydetme), yoksa inline.
// /factory/* rotalari GET /:id ONCESINE kayitli — /:id bunu yutmaz.
router.get('/factory/chat-file/:id/:token', asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  const id = parseInt(req.params.id, 10);
  const token = String(req.params.token || '');
  if (!Number.isInteger(id) || id <= 0 || !/^[a-f0-9]{32}$/i.test(token)) return res.status(404).json({ error: 'file_not_found' });
  const { rows } = await pool.query(`SELECT data, mime, name, size, expires_at FROM factory_chat_files WHERE id = $1 AND token = $2`, [id, token]);
  if (!rows.length) return res.status(404).json({ error: 'file_not_found' });
  const f = rows[0];
  // fix10e M5: süreli URL — süresi dolmuş dosya 404 + satır temizlenir.
  if (f.expires_at && new Date(f.expires_at).getTime() < Date.now()) {
    try { await pool.query(`DELETE FROM factory_chat_files WHERE id = $1`, [id]); } catch (_) { /* yoksay */ }
    return res.status(404).json({ error: 'file_not_found' });
  }
  // fix10e M5: saklanan boyut/gerçek boyut çapraz kontrolü — uyuşmazlıkta 404.
  if (f.size != null && Buffer.isBuffer(f.data) && f.data.length !== Number(f.size)) return res.status(404).json({ error: 'file_not_found' });
  res.set('Content-Type', f.mime);
  res.set('Cache-Control', 'private, max-age=31536000');
  // fix10p: CORP cross-origin — kapak/sohbet görselleri myfactor.netlify.app
  // (farklı origin) üzerinden <img> ile gömülüyor; same-origin tarayıcıda engeller.
  res.set('Cross-Origin-Resource-Policy', 'cross-origin');
  const safeName = sanitizeChatFilename(f.name) || 'dosya';
  const asciiName = safeName.replace(/[^\x20-\x7e]/g, '_') || 'dosya';
  res.set('Content-Disposition', (req.query.download === '1' ? 'attachment' : 'inline') + '; filename="' + asciiName.replace(/"/g, '') + '"; filename*=UTF-8\'\'' + encodeURIComponent(safeName));
  if (f.size) res.set('Content-Length', String(f.size));
  res.send(f.data);
}));

// fix10k (CBOs26.15): GET /api/products/factory/:id — tek fabrika (herkese acik).
// Bu rota tabanda YOKTU; madde 6 ("detay/listede followers") + test geregi eklendi.
// KONUM KRITIK: tum tek-segment GET /factory/* rotalarindan (/factory/list, /factory/messages,
// /factory/quotes, /factory/feed, /factory/chat-file/:id/:token) SONRA kayitli — once kayitli olsaydi
// bunlari yutar (ornegin /factory/messages -> id="messages" -> 400) ve mevcut davranis bozulurdu.
// /factory/:id/<eylem> (iki segment) rotalari bundan etkilenmez.
router.get('/factory/:id', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const fid = parseInt(req.params.id, 10);
  if (!Number.isInteger(fid) || fid < 1) return res.status(400).json({ error: 'invalid_factory' });
  const { rows } = await pool.query('SELECT * FROM factories WHERE id=$1 AND is_active IS NOT FALSE', [fid]);
  if (!rows.length) return res.status(404).json({ error: 'factory_not_found' });
  const r = rows[0];
  await attachFactoryBrands(rows); // fix10x
  const rmap = await factoryRatingsMap([r.id]);
  const qmap = await factoryQuoteCountsMap([r.id]);
  const fmap = await factoryFollowersMap([r.id]);
  const pvmap = await factoryPageViewsMap([r.id]); // fix10aa: sayfa goruntulenmesi (panel tanimiyla ayni)
  r.page_views = pvmap[r.id] || 0; // fix10aa: toFactoryPublic satirdan okur
  res.json({ ...toFactoryPublic(r, { includeContact: false }), rating_avg: (rmap[r.id] && rmap[r.id].rating_avg !== undefined) ? rmap[r.id].rating_avg : null, rating_count: (rmap[r.id] && rmap[r.id].rating_count) || 0, quote_count: qmap[r.id] || 0, followers: fmap[r.id] || 0 });
}));

// GET /api/products/:id
// GET /api/products/liked — kullanıcının beğendiği ürünler (profil: Beğendiğim Videolar, v570)
router.get(
  '/liked',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count
       FROM product_likes l JOIN products p ON p.id = l.product_id
       WHERE l.user_id = $1 AND p.is_active = TRUE ORDER BY l.created_at DESC`,
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// GET /api/products/commented — kullanıcının yorum yaptığı ürünler (profil, v570)
router.get(
  '/commented',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count,
              COUNT(c.id)::int AS comment_count,
              (SELECT c2.body FROM comments c2 WHERE c2.user_id = $1 AND c2.product_id = p.id ORDER BY c2.created_at DESC LIMIT 1) AS last_comment
       FROM comments c JOIN products p ON p.id = c.product_id
       WHERE c.user_id = $1 AND p.is_active = TRUE AND c.is_blocked = FALSE
       GROUP BY p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count
       ORDER BY MAX(c.created_at) DESC`,
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// GET /api/products/shared — kullanıcının paylaştığı ürünler (profil, v570)
router.get(
  '/shared',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count
       FROM product_shares s JOIN products p ON p.id = s.product_id
       WHERE s.user_id = $1 AND p.is_active = TRUE
       GROUP BY p.id, p.name, p.price_cents, p.currency, p.thumb_url, p.stock, p.sold_count
       ORDER BY MAX(s.created_at) DESC`,
      [req.user.id]
    );
    res.json({ items: rows });
  })
);

// GET /api/products/video/:uid — video proxy (videodelivery.net engelini aşar)
router.get('/video/:uid', async (req, res) => {
  try {
    const uid = req.params.uid;
    if (!/^[a-f0-9]{32}$/i.test(uid)) return res.status(400).json({ error: 'invalid_uid' });
    const mp4Url = `https://videodelivery.net/${uid}/downloads/default.mp4`;
    const headers = {};
    if (req.headers.range) headers.Range = req.headers.range;
    const upstream = await fetch(mp4Url, { headers, redirect: 'follow' });
    if (!upstream.ok && upstream.status !== 206) {
      return res.status(upstream.status).json({ error: 'upstream_error' });
    }
    // Üst akış başlıklarını ilet
    for (const [k, v] of upstream.headers) {
      const lk = k.toLowerCase();
      if (['content-type','content-length','content-range','accept-ranges','cache-control'].includes(lk)) {
        res.setHeader(k, v);
      }
    }
    res.status(upstream.status);
    const reader = upstream.body.getReader();
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!res.write(value)) await new Promise(r => res.once('drain', r));
      }
      res.end();
    };
    pump().catch(() => { try { res.end(); } catch(e){} });
  } catch (e) {
    if (!res.headersSent) res.status(502).json({ error: 'proxy_error' });
  }
});

// ALL /api/products/enable-mp4 (GET/POST) — tüm Cloudflare videoları için MP4 indirmeyi etkinleştir (admin)
router.all('/enable-mp4', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { enableMp4DownloadDebug } = require('../services/stream');
    const { rows } = await pool.query("SELECT id, video_url FROM products WHERE video_url LIKE '%videodelivery.net%'");
    let ok = 0, fail = 0;
    const errors = [];
    for (const r of rows) {
      const m = String(r.video_url).match(/videodelivery\.net\/([a-f0-9]+)/i);
      if (!m) { fail++; errors.push('no-uid'); continue; }
      const result = await enableMp4DownloadDebug(m[1]);
      if (result.ok) ok++; else { fail++; if(errors.length<3) errors.push(result.error); }
    }
    res.json({ ok: true, enabled: ok, failed: fail, total: rows.length, errors });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'enable_failed' });
  }
});

// v583: Pazaryeri bağlantıları (admin) — sırlar asla yanıtta dönülmez
const MP_NAMES = ['trendyol', 'hepsiburada', 'amazon'];
async function ensureMarketplaceSettings() {
  await pool.query(`CREATE TABLE IF NOT EXISTS marketplace_settings (name TEXT PRIMARY KEY, creds JSONB NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'bagli_degil', last_test_at TIMESTAMPTZ, last_error TEXT, updated_at TIMESTAMPTZ DEFAULT now())`);
}
function mpPublicRow(r) {
  return { name: r.name, status: r.status || 'bagli_degil', has_creds: !!(r.creds && Object.keys(r.creds).length), last_test_at: r.last_test_at || null, last_error: r.last_error || null };
}
// Gerçek API ile bağlantı testi — kimlik doğrulaması pazaryerinin kendi sunucusunda yapılır
async function testMarketplaceConnection(name, creds) {
  const withTimeout = async (fn) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    try { return await fn(ctrl.signal); } finally { clearTimeout(t); }
  };
  try {
    if (name === 'trendyol') {
      const { supplierId, apiKey, apiSecret } = creds || {};
      if (!supplierId || !apiKey || !apiSecret) return { ok: false, message: 'Eksik bilgi: Satıcı ID, API Key ve API Secret gerekli.' };
      const r = await withTimeout((sig) => fetch(`https://api.trendyol.com/sapigw/suppliers/${encodeURIComponent(supplierId)}/v2/products?page=0&size=1`, {
        signal: sig,
        headers: { Authorization: 'Basic ' + Buffer.from(`${apiKey}:${apiSecret}`).toString('base64'), 'User-Agent': `${supplierId} - SelfIntegration`, Accept: 'application/json' },
      }));
      if (r.status === 200) return { ok: true, message: 'Trendyol bağlantısı başarılı ✓' };
      if (r.status === 401 || r.status === 403) return { ok: false, message: 'Trendyol kimlik doğrulama başarısız (401/403) — API Key / Secret / Satıcı ID kontrol edin.' };
      return { ok: false, message: `Trendyol yanıtı: HTTP ${r.status}` };
    }
    if (name === 'amazon') {
      const { clientId, clientSecret, refreshToken } = creds || {};
      if (!clientId || !clientSecret || !refreshToken) return { ok: false, message: 'Eksik bilgi: Client ID, Client Secret ve Refresh Token gerekli.' };
      const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId, client_secret: clientSecret });
      const r = await withTimeout((sig) => fetch('https://api.amazon.com/auth/o2/token', {
        method: 'POST', signal: sig, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      }));
      if (r.status === 200) return { ok: true, message: 'Amazon SP-API bağlantısı başarılı ✓' };
      let detail = '';
      try { const j = await r.json(); detail = j.error_description || j.error || ''; } catch {}
      return { ok: false, message: `Amazon kimlik doğrulama başarısız (HTTP ${r.status})${detail ? ' — ' + detail : ''}` };
    }
    if (name === 'hepsiburada') {
      const { merchantId, username, password } = creds || {};
      if (!merchantId || !username || !password) return { ok: false, message: 'Eksik bilgi: Satıcı ID, Kullanıcı Adı ve Şifre gerekli.' };
      const r = await withTimeout((sig) => fetch(`https://oms-external.hepsiburada.com/v1/listings?merchantid=${encodeURIComponent(merchantId)}&limit=1`, {
        signal: sig,
        headers: { Authorization: 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64'), Accept: 'application/json' },
      }));
      if (r.status === 200) return { ok: true, message: 'Hepsiburada bağlantısı başarılı ✓' };
      if (r.status === 401 || r.status === 403) return { ok: false, message: 'Hepsiburada kimlik doğrulama başarısız (401/403) — kullanıcı adı / şifre / satıcı ID kontrol edin.' };
      return { ok: false, message: `Hepsiburada yanıtı: HTTP ${r.status}` };
    }
    return { ok: false, message: 'Bilinmeyen pazaryeri.' };
  } catch (e) {
    return { ok: false, message: 'Bağlantı hatası: ' + (e && e.message ? e.message : 'bilinmeyen hata') };
  }
}
router.get('/marketplaces', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureMarketplaceSettings();
  const { rows } = await pool.query('SELECT * FROM marketplace_settings ORDER BY name');
  const byName = {};
  rows.forEach((r) => { byName[r.name] = mpPublicRow(r); });
  res.json({ marketplaces: MP_NAMES.map((n) => byName[n] || { name: n, status: 'bagli_degil', has_creds: false, last_test_at: null, last_error: null }) });
}));
router.put('/marketplaces/:name', requireAuth, requireAdmin, param('name').isIn(MP_NAMES), asyncHandler(async (req, res) => {
  if (!checkValidation(req, res)) return;
  await ensureMarketplaceSettings();
  const incoming = req.body && req.body.creds && typeof req.body.creds === 'object' ? req.body.creds : {};
  const clean = {};
  for (const [k, v] of Object.entries(incoming)) { if (typeof v === 'string' && v.trim()) clean[k] = v.trim(); }
  const { rows: ex } = await pool.query('SELECT creds FROM marketplace_settings WHERE name = $1', [req.params.name]);
  const merged = { ...((ex[0] && ex[0].creds) || {}), ...clean };
  await pool.query(`INSERT INTO marketplace_settings (name, creds, status, updated_at) VALUES ($1, $2::jsonb, 'kaydedildi', now())
    ON CONFLICT (name) DO UPDATE SET creds = $2::jsonb, status = 'kaydedildi', updated_at = now()`, [req.params.name, JSON.stringify(merged)]);
  res.json({ ok: true, name: req.params.name, status: 'kaydedildi', has_creds: Object.keys(merged).length > 0 });
}));
router.post('/marketplaces/:name/test', requireAuth, requireAdmin, param('name').isIn(MP_NAMES), asyncHandler(async (req, res) => {
  if (!checkValidation(req, res)) return;
  await ensureMarketplaceSettings();
  const { rows } = await pool.query('SELECT creds FROM marketplace_settings WHERE name = $1', [req.params.name]);
  const creds = (rows[0] && rows[0].creds) || {};
  const result = await testMarketplaceConnection(req.params.name, creds);
  await pool.query('UPDATE marketplace_settings SET status = $2, last_test_at = now(), last_error = $3, updated_at = now() WHERE name = $1',
    [req.params.name, result.ok ? 'bagli' : 'hata', result.ok ? null : (result.message || 'test_failed')]);
  res.json(result);
}));

// v586: Genel ayarlar (WhatsApp vb.) — sırlar asla yanıtta dönülmez
async function ensureSettingsTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMPTZ DEFAULT now())`);
}
const WA_PUBLIC_KEYS = ['wa_phone', 'wa_username', 'wa_phone_id', 'wa_verify', 'wa_enabled', 'wa_order_notify', 'wa_shop_button'];
const ACC_PROGRAMS = ['nebim', 'logo', 'zirve', 'eta', 'akinsoft'];
const ACC_PUBLIC_KEYS_BASE = ACC_PROGRAMS.flatMap((p) => [`acc_${p}_api_url`, `acc_${p}_username`, `acc_${p}_firm`, `acc_${p}_enabled`]);
const NEBIM_EXTRA_KEYS = ['acc_nebim_user_group', 'acc_nebim_office', 'acc_nebim_warehouse', 'acc_nebim_series', 'acc_nebim_pos_terminal', 'acc_nebim_customer', 'acc_nebim_payment_code', 'acc_nebim_auto_send'];
const ACC_PUBLIC_KEYS = [...ACC_PUBLIC_KEYS_BASE, ...NEBIM_EXTRA_KEYS];
const ACC_SECRET_KEYS = ACC_PROGRAMS.map((p) => `acc_${p}_password`);
const GA_PUBLIC_KEYS = ['ga_measurement_id', 'ga_enabled'];
const GA_SECRET_KEYS = ['ga_api_secret'];
const SOCIAL_PUBLIC_KEYS = ['youtube_url', 'facebook_url', 'instagram_url', 'x_url', 'tiktok_url'];
const SMS_PUBLIC_KEYS = ['sms_netgsm_header', 'sms_company_phone', 'sms_notify_register', 'sms_notify_forgot', 'sms_notify_order_received', 'sms_notify_order_shipped', 'sms_notify_order_delivered'];
const SMS_SECRET_KEYS = ['sms_netgsm_usercode', 'sms_netgsm_password'];
const SETTINGS_PUBLIC_KEYS = [...WA_PUBLIC_KEYS, ...ACC_PUBLIC_KEYS, ...GA_PUBLIC_KEYS];
const XML_PUBLIC_KEYS = ['xml_feed_enabled', 'xml_feed_mode'];
const XML_SECRET_KEYS = ['api_key'];
const SEC_PUBLIC_KEYS = ['sec_session_minutes', 'sec_failed_login_limit'];
const SETTINGS_PUBLIC_KEYS_ALL = [...SETTINGS_PUBLIC_KEYS, ...XML_PUBLIC_KEYS, ...SEC_PUBLIC_KEYS, ...SMS_PUBLIC_KEYS, ...SOCIAL_PUBLIC_KEYS];
router.get('/settings', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const { rows } = await pool.query('SELECT key, value FROM settings');
  const settings = {};
  rows.forEach((r) => {
    if (SETTINGS_PUBLIC_KEYS_ALL.includes(r.key)) {
      let v = r.value;
      if (v === 'true' || v === 'false') v = v === 'true';
      settings[r.key] = v;
    }
  });
  settings.has_wa_token = rows.some((r) => r.key === 'wa_token' && r.value);
  settings.has_wa_app_secret = rows.some((r) => r.key === 'wa_app_secret' && r.value); // fix10e SABAH-4: App Secret yalnizca boolean doner
  ACC_PROGRAMS.forEach((p) => { settings[`has_acc_${p}_password`] = rows.some((r) => r.key === `acc_${p}_password` && r.value); });
  settings.has_ga_api_secret = rows.some((r) => r.key === 'ga_api_secret' && r.value);
  settings.has_sms_netgsm_usercode = rows.some((r) => r.key === 'sms_netgsm_usercode' && r.value);
  settings.has_sms_netgsm_password = rows.some((r) => r.key === 'sms_netgsm_password' && r.value);
  settings.has_api_key = rows.some((r) => r.key === 'api_key' && r.value);
  res.json({ settings });
}));
router.put('/settings', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const incoming = req.body && req.body.settings && typeof req.body.settings === 'object' ? req.body.settings : {};
  const allowed = [...WA_PUBLIC_KEYS, 'wa_token', 'wa_app_secret', ...ACC_PUBLIC_KEYS, ...ACC_SECRET_KEYS, ...GA_PUBLIC_KEYS, ...GA_SECRET_KEYS, ...XML_PUBLIC_KEYS, ...XML_SECRET_KEYS, ...SEC_PUBLIC_KEYS, ...SMS_PUBLIC_KEYS, ...SMS_SECRET_KEYS, ...SOCIAL_PUBLIC_KEYS]; // fix10e SABAH-4: wa_app_secret
  for (const [k, v] of Object.entries(incoming)) {
    if (!allowed.includes(k)) continue;
    if (typeof v !== 'string' && typeof v !== 'boolean') continue;
    const val = typeof v === 'boolean' ? (v ? 'true' : 'false') : v.trim();
    if (val === '') continue;
    // SHOP SECURITY: ayar degeri en fazla 4096 karakter (asiri uzun girdi DB'yi sisiremez).
    if (val.length > 4096) return res.status(400).json({ ok: false, message: 'Değer çok uzun (en fazla 4096 karakter).' });
    await pool.query(`INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()`, [k, val]);
  }
  res.json({ ok: true });
}));
router.post('/settings/whatsapp/test', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const { rows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ('wa_phone_id', 'wa_token')`);
  const kv = {};
  rows.forEach((r) => { kv[r.key] = r.value; });
  if (!kv.wa_phone_id || !kv.wa_token) return res.json({ ok: false, message: 'Eksik bilgi: Telefon Numarası ID ve Erişim Jetonu gerekli.' });
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    let r;
    try {
      r = await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(kv.wa_phone_id)}?fields=verified_name,display_phone_number,quality_rating`, { signal: ctrl.signal, headers: { Authorization: `Bearer ${kv.wa_token}` } });
    } finally { clearTimeout(t); }
    if (r.status === 200) {
      const j = await r.json();
      return res.json({ ok: true, message: `WhatsApp bağlantısı başarılı ✓ — Doğrulanan ad: ${j.verified_name || '—'}, Numara: ${j.display_phone_number || '—'}` });
    }
    let detail = '';
    try { const j = await r.json(); detail = (j.error && j.error.message) || ''; } catch {}
    return res.json({ ok: false, message: `WhatsApp doğrulama başarısız (HTTP ${r.status})${detail ? ' — ' + detail : ''}` });
  } catch (e) {
    return res.json({ ok: false, message: 'Bağlantı hatası: ' + (e && e.message ? e.message : 'bilinmeyen hata') });
  }
}));

// v588: Muhasebe programi baglanti testi — sunucuya erisilebilirlik kontrolu (kimlik dogrulama satici API'sine ozeldir)
// POST /api/products/settings/sms/test — test SMS gonder (yalniz admin, v609)
router.post('/settings/sms/test', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const phone = String((req.body && req.body.phone) || '').trim();
  if (!phone) return res.json({ ok: false, message: 'Telefon numarasi gerekli.' });
  const { sendSms } = require('../services/sms');
  const sent = await sendSms(phone, 'ChinaBazaar test mesaji: SMS baglantiniz calisiyor.');
  if (sent.ok) return res.json({ ok: true, message: 'Test SMS gonderildi.' });
  if (sent.error === 'sms_not_configured') return res.json({ ok: false, message: 'Netgsm bilgileri eksik. Once Kullanici Kodu, Sifre ve Gonderen Adi girip kaydedin.' });
  return res.json({ ok: false, message: 'SMS gonderilemedi: ' + (sent.detail || sent.error) });
}));

router.post('/settings/accounting/test', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const program = req.body && req.body.program;
  if (!ACC_PROGRAMS.includes(program)) return res.json({ ok: false, message: 'Bilinmeyen muhasebe programı.' });
  await ensureSettingsTable();
  const { rows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ($1, $2, $3)`, [`acc_${program}_api_url`, `acc_${program}_username`, `acc_${program}_password`]);
  const kv = {};
  rows.forEach((r) => { kv[r.key] = r.value; });
  const apiUrl = kv[`acc_${program}_api_url`];
  if (!apiUrl) return res.json({ ok: false, message: 'Eksik bilgi: API Adresi / Sunucu gerekli.' });
  if (!/^https?:\/\//i.test(apiUrl)) return res.json({ ok: false, message: 'API adresi http:// veya https:// ile başlamalı (örn. https://api.ornek.com).' });
  // fix10e L7: SSRF — ic/ozel ag adresine istek gonderilmez (localhost,
  // RFC1918, link-local, metadata 169.254.x.x, kimlik bilgili URL dahil).
  if (!(await assertPublicUrl(apiUrl))) return res.json({ ok: false, message: 'API adresi herkese açık bir adres olmalı (iç ağ / özel IP adreslerine bağlantı engellendi).' });
  if (program === 'nebim') { const nebim = require('../services/nebim'); const t = await nebim.testConnection(); return res.json(t); }
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    let r;
    try {
      const headers = {};
      if (kv[`acc_${program}_username`] && kv[`acc_${program}_password`]) headers.Authorization = 'Basic ' + Buffer.from(`${kv[`acc_${program}_username`]}:${kv[`acc_${program}_password`]}`).toString('base64');
      r = await fetch(apiUrl, { method: 'HEAD', signal: ctrl.signal, headers, redirect: 'manual' });
    } finally { clearTimeout(t); }
    if (r.status >= 200 && r.status < 300) return res.json({ ok: true, message: `Sunucuya erişildi ✓ (HTTP ${r.status})` });
    if (r.status === 401 || r.status === 403) return res.json({ ok: false, message: `Sunucuya erişildi, kimlik doğrulanamadı (HTTP ${r.status}) — kullanıcı adı / şifre kontrol edin.` });
    if (r.status >= 300 && r.status < 500) return res.json({ ok: false, message: `Sunucuya erişildi (HTTP ${r.status}) — API adresini kontrol edin.` });
    return res.json({ ok: false, message: `Sunucu hata döndürdü (HTTP ${r.status}).` });
  } catch (e) {
    return res.json({ ok: false, message: 'Sunucuya erişilemedi: ' + (e && e.message ? e.message : 'bilinmeyen hata') });
  }
}));

// v589: Herkese açık GA ayarı — yalnızca etkinlik + Ölçüm Kimliği (sır içermez)
router.get('/settings/public', asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const { rows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ('ga_enabled', 'ga_measurement_id', 'youtube_url', 'facebook_url', 'instagram_url', 'x_url', 'tiktok_url')`);
  const settings = { ga_enabled: false, ga_measurement_id: '', youtube_url: '', facebook_url: '', instagram_url: '', x_url: '', tiktok_url: '' };
  rows.forEach((r) => {
    if (r.key === 'ga_enabled') settings.ga_enabled = r.value === 'true';
    if (r.key === 'ga_measurement_id') settings.ga_measurement_id = r.value || '';
    if (r.key === 'youtube_url') settings.youtube_url = r.value || '';
    if (r.key === 'facebook_url') settings.facebook_url = r.value || '';
    if (r.key === 'instagram_url') settings.instagram_url = r.value || '';
    if (r.key === 'x_url') settings.x_url = r.value || '';
    if (r.key === 'tiktok_url') settings.tiktok_url = r.value || '';
  });
  res.json({ settings });
}));

// v591: XML urun akisi + API anahtari uretme
function escapeXml(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;'); }
router.get('/feed.xml', asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const { rows: srows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ('xml_feed_enabled', 'xml_feed_mode', 'api_key')`);
  const kv = {};
  srows.forEach((r) => { kv[r.key] = r.value; });
  if (kv.xml_feed_enabled !== 'true') return res.status(404).type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?>\n<error>feed_disabled</error>');
  if (kv.xml_feed_mode === 'key' && (!kv.api_key || !timingSafeEqualStr(kv.api_key, String(req.query.api_key || '')))) {
    return res.status(403).type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?>\n<error>api_key_required</error>');
  }
  const { rows } = await pool.query(`SELECT p.id, p.sku, p.name, p.price_cents, p.currency, p.stock, p.thumb_url, p.description, c.name AS category_name FROM products p LEFT JOIN categories c ON c.id = p.category_id WHERE p.is_active = TRUE ORDER BY p.name LIMIT 5000`);
  const items = rows.map((p) => `  <product>\n    <id>${escapeXml(p.id)}</id>\n    <sku>${escapeXml(p.sku)}</sku>\n    <name>${escapeXml(p.name)}</name>\n    <price>${(p.price_cents / 100).toFixed(2)}</price>\n    <currency>${escapeXml(p.currency || 'TRY')}</currency>\n    <stock>${p.stock ?? 0}</stock>\n    <image>${escapeXml(p.thumb_url || '')}</image>\n    <link>https://chinabazaar.com/</link>\n    <category>${escapeXml(p.category_name || '')}</category>\n    <description>${escapeXml((p.description || '').slice(0, 1000))}</description>\n  </product>`).join('\n');
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>\n<products>\n${items}\n</products>`);
}));
router.post('/settings/api-key/generate', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const key = 'cbz_live_' + crypto.randomBytes(24).toString('hex');
  await pool.query(`INSERT INTO settings (key, value, updated_at) VALUES ('api_key', $1, now()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = now()`, [key]);
  res.json({ ok: true, api_key: key });
}));

// GET /api/products/categories — herkese acik kategori listesi (magaza kategori sayfasi icin, v608)
// Yeni eklenen kategoriler (or. Hirdavat) API'den gelir; magaza bunlari otomatik ikonla gosterir.
router.get(
  '/categories',
  asyncHandler(async (req, res) => {
    await pool.query("ALTER TABLE categories ADD COLUMN IF NOT EXISTS icon TEXT DEFAULT ''");
    await pool.query('ALTER TABLE categories ADD COLUMN IF NOT EXISTS sort_order INT DEFAULT 0');
    const { rows } = await pool.query(
      `SELECT c.id, c.name, c.slug, COALESCE(c.icon,'') AS icon, COALESCE(c.sort_order,0) AS sort_order,
              (SELECT count(*)::int FROM products p WHERE p.category_id = c.id AND p.is_active = TRUE) AS product_count
       FROM categories c ORDER BY c.sort_order, c.name`
    );
    res.json({ items: rows });
  })
);

router.get(
  '/:id',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(`${SELECT} WHERE p.id = $1 AND p.is_active = TRUE`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
    res.json(toProduct(rows[0]));
  })
);



// ---- Admin CRUD (yalnız is_admin) ----

const productValidators = [
  body('name').trim().isLength({ min: 2, max: 200 }),
  body('price').isFloat({ min: 0, max: 10000000 }).withMessage('price_must_be_non_negative'),
  body('campaign_price').optional({ nullable: true }).isFloat({ min: 0, max: 10000000 }),
  body('warranty_months').optional({ nullable: true }).isInt({ min: 0, max: 120 }),
  body('stock').optional().isInt({ min: 0, max: 1000000 }),
  body('description').optional().trim().isLength({ max: 10000 }),
  body('tagline').optional().trim().isLength({ max: 200 }),
  body('sku').optional().trim().isLength({ max: 60 }),
  body('image_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('marketplaces').optional().trim().isLength({ max: 200 }),
  body('marketplace_image').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('marketplace_images').optional({ values: 'falsy' }).isArray({ max: 10 }),
  body('marketplace_images.*').isURL({ max_length: 2048 }),
  body('video_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('category').optional({ values: 'falsy' }).trim().isLength({ max: 100 }),
  body('is_active').optional().isBoolean(),
  body('is_upcoming').optional().isBoolean().toBoolean(),
  body('currency').optional().trim().isIn(['TRY', 'USD', 'RUB']),
  body('color').optional().trim().isLength({ max: 200 }),
  body('storage').optional().trim().isLength({ max: 200 }),
  body('size').optional().trim().isLength({ max: 200 }),
  body('dimensions').optional().trim().isLength({ max: 200 }),
  body('box_dimensions').optional().trim().isLength({ max: 200 }),
  body('weight').optional().trim().isLength({ max: 200 }),
  body('length').optional().trim().isLength({ max: 200 }),
  body('connector').optional().trim().isLength({ max: 200 }),
  body('power_type').optional().trim().isLength({ max: 200 }),
  body('barcode').optional().trim().matches(/^[0-9]{8,14}$/),
  // SHOP SECURITY: brand validator eksikti — dogrulanmadan DB'ye gidiyordu.
  body('brand').optional().trim().isLength({ max: 200 }),
];

// category: slug veya UUID kabul eder → category_id çözer (boşsa NULL)
async function resolveCategoryId(category) {
  if (!category) return null;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(category)) return category;
  const { rows } = await pool.query('SELECT id FROM categories WHERE slug = $1', [category]);
  return rows[0]?.id || null;
}

function toCents(price) {
  return Math.round(Number(price) * 100);
}

// POST /api/products — yeni ürün (admin)
router.post(
  '/',
  requireAuth,
  requireAdmin,
  ...productValidators,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { name, price, campaign_price, stock, description, tagline, sku, image_url, video_url, category, is_active, currency, color, size, dimensions, box_dimensions, weight, length, connector, power_type, barcode, storage, is_upcoming, brand, marketplaces, marketplace_image, marketplace_images, warranty_months } = req.body;
    await ensureMarketplaceColumns();
    await ensureWarrantyColumn();
    const categoryId = await resolveCategoryId(category);
    try {
      const { rows } = await pool.query(
        `INSERT INTO products (sku, name, tagline, description, price_cents, currency, stock, category_id, video_url, thumb_url, is_active, color, size, dimensions, box_dimensions, weight, length, connector, power_type, barcode, storage, is_upcoming, brand, campaign_price_cents, marketplaces, marketplace_image, marketplace_images, warranty_months)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27::jsonb,$28) RETURNING *`,
        [
          sku || null, name, tagline || null, description || null, toCents(price),
          ['TRY','USD','RUB'].includes(currency) ? currency : 'TRY',
          stock ?? 0, categoryId, video_url || null, image_url || null,
          is_active === undefined ? true : is_active,
          color || null, size || null, dimensions || null, box_dimensions || null, weight || null,
          length || null, connector || null, power_type || null,
          barcode || null, storage || null, is_upcoming === true, brand || null,
          campaign_price != null ? toCents(campaign_price) : null,
          (typeof marketplaces === 'string' && marketplaces.trim()) ? marketplaces.trim() : 'chinabazaar',
          (typeof marketplace_image === 'string' && marketplace_image.trim()) ? marketplace_image.trim() : null,
          cleanMpImages(marketplace_images),
          warranty_months != null ? parseInt(warranty_months, 10) : null,
        ]
      );
      res.status(201).json(toProduct({ ...rows[0], category_slug: null, category_name: null }));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'sku_in_use' });
      return res.status(500).json({ error: 'db_error' });
    }
  })
);

// PUT /api/products/:id — ürün güncelleme (admin, kısmi)
router.put(
  '/:id',
  requireAuth,
  requireAdmin,
  param('id').isUUID(),
  body('name').optional().trim().isLength({ min: 2, max: 200 }),
  body('price').optional().isFloat({ min: 0, max: 10000000 }),
  body('campaign_price').optional({ nullable: true }).isFloat({ min: 0, max: 10000000 }),
  body('warranty_months').optional({ nullable: true }).isInt({ min: 0, max: 120 }),
  body('stock').optional().isInt({ min: 0, max: 1000000 }),
  body('description').optional().trim().isLength({ max: 10000 }),
  body('tagline').optional().trim().isLength({ max: 200 }),
  body('sku').optional().trim().isLength({ max: 60 }),
  body('image_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('marketplaces').optional().trim().isLength({ max: 200 }),
  body('marketplace_image').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('marketplace_images').optional({ values: 'falsy' }).isArray({ max: 10 }),
  body('marketplace_images.*').isURL({ max_length: 2048 }),
  body('video_url').optional({ values: 'falsy' }).isURL({ max_length: 2048 }),
  body('category').optional({ values: 'falsy' }).trim().isLength({ max: 100 }),
  body('is_active').optional().isBoolean(),
  body('is_upcoming').optional().isBoolean().toBoolean(),
  body('currency').optional().trim().isIn(['TRY', 'USD', 'RUB']),
  body('color').optional().trim().isLength({ max: 200 }),
  body('storage').optional().trim().isLength({ max: 200 }),
  body('size').optional().trim().isLength({ max: 200 }),
  body('dimensions').optional().trim().isLength({ max: 200 }),
  body('box_dimensions').optional().trim().isLength({ max: 200 }),
  body('weight').optional().trim().isLength({ max: 200 }),
  body('length').optional().trim().isLength({ max: 200 }),
  body('connector').optional().trim().isLength({ max: 200 }),
  body('power_type').optional().trim().isLength({ max: 200 }),
  body('barcode').optional().trim().matches(/^[0-9]{8,14}$/),
  // SHOP SECURITY: brand validator eksikti — dogrulanmadan DB'ye gidiyordu.
  body('brand').optional().trim().isLength({ max: 200 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureMarketplaceColumns();
    await ensureWarrantyColumn();
    const map = {
      name: 'name', tagline: 'tagline', description: 'description', sku: 'sku',
      video_url: 'video_url', image_url: 'thumb_url', is_active: 'is_active',
      currency: 'currency', color: 'color', storage: 'storage', is_upcoming: 'is_upcoming', size: 'size', dimensions: 'dimensions',
      box_dimensions: 'box_dimensions', weight: 'weight', length: 'length', connector: 'connector', power_type: 'power_type', barcode: 'barcode', brand: 'brand',
      marketplaces: 'marketplaces', marketplace_image: 'marketplace_image', marketplace_images: 'marketplace_images',
    };
    const sets = [];
    const params = [req.params.id];
    for (const [key, col] of Object.entries(map)) {
      if (req.body[key] !== undefined) {
        if (key === 'marketplace_images') params.push(cleanMpImages(req.body[key]));
        else params.push(key === 'image_url' && !req.body[key] ? null : req.body[key]);
        sets.push(`${col} = $${params.length}${key === 'marketplace_images' ? '::jsonb' : ''}`);
      }
    }
    if (req.body.price !== undefined) {
      params.push(toCents(req.body.price));
      sets.push(`price_cents = $${params.length}`);
    }
    // Kampanya fiyati: sayi = ayarla, null = kampanyayi kaldir, undefined = degistirme
    if (req.body.campaign_price !== undefined) {
      params.push(req.body.campaign_price === null ? null : toCents(req.body.campaign_price));
      sets.push(`campaign_price_cents = $${params.length}`);
    }
    // Garanti: sayi = ayarla, null = kaldir, undefined = degistirme
    if (req.body.warranty_months !== undefined) {
      params.push(req.body.warranty_months === null ? null : parseInt(req.body.warranty_months, 10));
      sets.push(`warranty_months = $${params.length}`);
    }
    if (req.body.stock !== undefined) {
      params.push(req.body.stock);
      sets.push(`stock = $${params.length}`);
    }
    if (req.body.category !== undefined) {
      params.push(await resolveCategoryId(req.body.category));
      sets.push(`category_id = $${params.length}`);
    }
    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
    sets.push('updated_at = now()');
    try {
      const { rows } = await pool.query(
        `UPDATE products SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
        params
      );
      if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
      res.json(toProduct({ ...rows[0], category_slug: null, category_name: null }));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'sku_in_use' });
      return res.status(500).json({ error: 'db_error' });
    }
  })
);

// DELETE /api/products/:id — ürün silme (admin).
// order_items FK'si ON DELETE SET NULL: geçmiş siparişler korunur (ad/fiyat snapshot'ı durur).
router.delete(
  '/:id',
  requireAuth,
  requireAdmin,
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query('DELETE FROM products WHERE id = $1 RETURNING id', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'product_not_found' });
    res.json({ deleted: true, id: rows[0].id });
  })
);

// POST /api/products/:id/view — izlenme sayacı (herkese açık, sessiz artar)
router.post(
  '/:id/view',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await pool.query('UPDATE products SET view_count = view_count + 1 WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  })
);

// GET /api/products/:id/comments — görünür yorumlar (herkese açık)
router.get(
  '/:id/comments',
  param('id').isUUID(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(
      `SELECT c.id, c.body, c.created_at, COALESCE(u.nickname, u.name, 'Misafir') AS user_name, u.nickname AS nickname
       FROM comments c LEFT JOIN users u ON u.id = c.user_id
       WHERE c.product_id = $1 AND c.is_blocked = FALSE
       ORDER BY c.created_at DESC LIMIT 100`,
      [req.params.id]
    );
    res.json({ items: rows });
  })
);

// POST /api/products/:id/comments — yorum ekle (kayıt gerekli, v552)
router.post(
  '/:id/comments',
  requireAuth,
  param('id').isUUID(),
  body('body').trim().isLength({ min: 1, max: 1000 }),
  shopSpamLimiter,
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const me = await pool.query('SELECT is_blocked FROM users WHERE id = $1', [req.user.id]);
    if (me.rows[0]?.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    // SHOP SECURITY: olmayan/pasif urune yorum FK hatasiyla 500 degil 404 doner.
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id = $1 AND is_active = TRUE', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    const { rows } = await pool.query(
      `INSERT INTO comments (product_id, user_id, body) VALUES ($1, $2, $3)
       RETURNING id, body, created_at`,
      [req.params.id, req.user.id, req.body.body.trim()]
    );
    res.status(201).json(rows[0]);
  })
);

module.exports = router;
