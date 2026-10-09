# ChinaBazaar API

Türkiye odaklı dikey video e-ticaret backend'i. **Node.js + Express + PostgreSQL**, ödeme **iyzico** (hosted checkout — kart bilgisi bizde tutulmaz). Railway'de çalışacak şekilde paketlenmiştir.

## Mimari

- **Netlify** → mağaza ön yüzü (statik)
- **Railway** → bu API (hesaplar, siparişler, iyzico)
- **Cloudflare Stream** → dikey videolar

## Endpoint'ler

| Metod | Yol | Açıklama |
|---|---|---|
| GET | `/healthz` | Railway healthcheck |
| GET | `/api/products` | Ürün listesi (ön yüz sözleşmesi: `name, tagline, description, price_cents, price_display, sold_count, stock, category, video_url, thumb_url`); admin `?all=true` ile pasifleri de görür |
| GET | `/api/products/:id` | Ürün detayı |
| POST | `/api/products` | Ürün ekle — `name, price(TRY), stock?, description?, tagline?, sku?, image_url?, video_url?, category(slug/UUID)?, is_active?` (yalnız admin) |
| PUT | `/api/products/:id` | Ürün güncelle — kısmi alanlar (yalnız admin) |
| DELETE | `/api/products/:id` | Ürün sil — geçmiş siparişler korunur (FK SET NULL) (yalnız admin) |
| POST | `/api/auth/register` | Kayıt `{email, password, name, phone?, admin_key?}` → JWT (`admin_key` = `ADMIN_SETUP_KEY` ise admin) |
| POST | `/api/auth/login` | Giriş `{email, password}` → JWT |
| GET | `/api/auth/me` | Profil `{id, email, name, phone, is_admin}` (JWT) |
| GET | `/api/orders` | Kendi siparişleri (created_at DESC, JWT); admin `?all=true` ile tüm siparişler (kullanıcı e-postasıyla) |
| GET | `/api/addresses` | Adres listesi (JWT) |
| POST | `/api/addresses` | Adres ekle (il/ilçe/mahalle, JWT) |
| GET | `/api/favorites` | Favori ürünler (JWT) |
| POST | `/api/favorites` | Favoriye ekle `{product_id}` (JWT) |
| DELETE | `/api/favorites/:product_id` | Favoriden çıkar (JWT) |
| POST | `/api/orders` | Sipariş oluştur `{address_id, items:[{product_id, qty}]}` — stok kontrollü (JWT) |
| GET | `/api/orders/:id` | Sipariş detayı + kargo bilgisi (yalnız sahibi/admin, JWT) |
| PATCH | `/api/orders/:id/tracking` | Kargo bilgisi güncelle `{cargo_company?, tracking_number?}` (yalnız admin, JWT) |
| PATCH | `/api/orders/:id/status` | Sipariş durumu güncelle — 6 kanonik aşama + cancelled/refunded; geçersiz değer reddedilir (yalnız admin, JWT) |
| GET | `/api/tracking/:orderNo` | Herkese açık sınırlı kargo sorgusu — yalnız sipariş no, durum, kargo firması, takip no (kişisel veri dönmez, hız limitli) |
| POST | `/api/payments/iyzico/init` | Ödeme başlat `{order_id}` → `{paymentPageUrl, token}` (JWT) |
| POST | `/api/payments/iyzico/callback` | Ödeme sonucu `{token}` → sipariş `paid` olur |

JWT kullanımı: `Authorization: Bearer <token>`

## İlk admin kurulumu

1. Railway → API servisi → Variables → `ADMIN_SETUP_KEY` için güçlü rastgele değer gir (örn. `openssl rand -hex 16`).
2. `admin.html` kayıt formundaki "Kurulum anahtarı" alanına bu değeri yazarak kaydol → `is_admin=TRUE`.
3. Kurulum bitince `ADMIN_SETUP_KEY` değişkenini Railway'den SİL (artık gerekmez; mevcut admin'ler etkilenmez).

## Sipariş durumları (6 aşamalı kanonik enum)

`packing → ready → shipped → in_transit → arriving → delivered`

- Sipariş oluşur: `pending` (ödeme bekliyor) → ödeme tamamlanınca otomatik `packing`.
- Takip no girilince (`packing`/`ready` iken) otomatik `shipped`.
- Admin `PATCH /api/orders/:id/status` ile 6 aşama + `cancelled`/`refunded` arasında günceller; geçersiz değer reddedilir (DB'de CHECK kısıtı da vardır).
- `GET /api/tracking/:orderNo` yanıtında `stage` (anahtar) + `stage_index` (0–5) döner; Türkçe karşılıklar frontend'de çevrilir:
  - packing: Paketleniyor · ready: Hazırlandı · shipped: Çıkış yapıldı · in_transit: Yolda · arriving: Varmak üzere · delivered: Teslim edildi

## Railway'e deploy (sırayla)

1. **GitHub'a push'la:** Bu klasörü bir GitHub reposuna push'la (`backend/` içeriği repo kökünde olmalı).
2. **Railway'de proje aç:** [railway.app](https://railway.app) → New Project → **GitHub Repository** → reponu seç.
3. **PostgreSQL ekle:** Proje içinde **+ New → Database → PostgreSQL**. `DATABASE_URL` değişkeni otomatik dolar — elle girmene gerek yok.
4. **Env değişkenlerini gir** (servis → Variables):
   - `JWT_SECRET` — `openssl rand -hex 32` çıktısı (zorunlu)
   - `IYZICO_API_KEY` — iyzico sandbox panelinden (ödeme yoksa boş bırakılabilir)
   - `IYZICO_SECRET_KEY` — iyzico sandbox panelinden
   - `IYZICO_BASE_URL` — `https://sandbox-api.iyzipay.com` (canlıda `https://api.iyzipay.com`)
   - `BASE_URL` — `https://chinabazaar.com` (ödeme sonrası dönüş adresi)
   - `ALLOWED_ORIGINS` — CORS izinli ek origin'ler, virgülle ayrılmış (örn. Netlify önizleme domainleri). Boşsa yalnız `BASE_URL` + `https://chinabazaar.com` + `https://www.chinabazaar.com` izinlidir.
   - `SHIPPING_CENTS` — kargo ücreti (kuruş), örn. `0`
   - `NODE_ENV` — `production`
5. **Deploy et:** Railway `Dockerfile`'ı otomatik algılar (`railway.json` hazır). İlk açılışta `schema.sql` + `migrations/*.sql` otomatik uygulanır (`npm run migrate` → tablolar + 6 kategori oluşur). Migration'lar idempotent'tir (`IF NOT EXISTS`), tekrar çalıştırma güvenlidir.
6. **Domain bağla:** Servis → Settings → Networking → **Generate Domain**, sonra chinabazaar.com DNS'inde API için CNAME (örn. `api.chinabazaar.com`) tanımla.

> iyzico anahtarları yoksa API çalışır; ödeme endpoint'leri `503 payment_not_configured` döner. Sahte/test ödemesi **yoktur**.

## Aras Kargo entegrasyonu

Kargo firması: **Aras Kargo**. Takip akışı iki katmanlıdır:

1. **Manuel takip no (şu an aktif):** Admin, sipariş kargoya verildiğinde `PATCH /api/orders/:id/tracking` ile `{cargo_company: "Aras Kargo", tracking_number: "..."}` girer (ileride admin panelinden girilecek). Müşteri `GET /api/tracking/:orderNo` ile sipariş no, durum, kargo firması ve takip no'yu görür — kişisel veri dönmez.
2. **Canlı takip (opsiyonel):** Aras kurumsal web servisinden anlık durum çekilir. Aktif etmek için:
   - Aras kurumsal müşteri temsilcinizden **web servis kullanıcı adı + şifresi** ve **üretim WSDL URL'i** alınır.
   - Railway Variables'a eklenir: `ARAS_CARGO_WSDL_URL`, `ARAS_CARGO_USERNAME`, `ARAS_CARGO_PASSWORD` (gerekirse `ARAS_CARGO_TRACK_METHOD`).
   - Bu üçü doluysa `GET /api/tracking/:orderNo` yanıtına `live_status` eklenir; servis erişilemezse sessizce DB bilgisine düşülür (`live_source: "database"`).
   - Doldurulmazsa hiçbir şey kırılmaz — sistem manuel takip no ile çalışmaya devam eder.

> Not: Aras yanıt şeması hesaba göre değişebilir; `src/services/arasCargo.js` dosyasının başındaki notta hangi alanların okunduğu ve temsilcinizden teyit edilecek noktalar yazılıdır.

## Yerel geliştirme

```bash
cp .env.example .env   # değerleri doldur
npm install
npm run migrate
npm run dev
```

## Güvenlik notları

- `.env` dosyası repoya **asla** push'lanmaz (`.gitignore`'da).
- Kart bilgisi sunucuda tutulmaz; ödeme iyzico sayfasında yapılır, bizde yalnız token/referans kalır.
- Şifreler bcrypt ile hash'lenir (cost factor 12); auth endpoint'lerinde sıkı rate limit vardır (giriş: 15 dk'da 10 deneme/IP).
- Güvenlik başlıkları (helmet): HSTS (1 yıl + preload), sıkı CSP, X-Frame-Options DENY, referrer-policy no-referrer.
- CORS: yalnız `ALLOWED_ORIGINS` + üretim domainleri; bilinmeyen origin'ler 403 alır.
- Tüm `/api` rotalarında genel hız limiti (15 dk'da 300 istek/IP); herkese açık takip sorgusunda saatte 60.
- Üretimde hata yanıtları iç detay/stack trace içermez; loglara şifre, token, kart verisi yazılmaz.
- `trust proxy` açık — Railway arkasında rate-limit gerçek istemci IP'sine uygulanır.
- Girdi doğrulaması: tüm ID parametreleri UUID formatında, kayıt/giriş/adres/sipariş gövdeleri tip + uzunluk + format kontrollü (express-validator).
