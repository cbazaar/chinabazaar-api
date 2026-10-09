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
| GET | `/api/products?category=&q=&limit=&offset=&sort=` | Ürün listesi (ön yüz sözleşmesi: `name, tagline, description, price_cents, price_display, sold_count, stock, category, video_url, thumb_url`) |
| GET | `/api/products/:id` | Ürün detayı |
| POST | `/api/auth/register` | Kayıt `{email, password, name, phone?}` → JWT |
| POST | `/api/auth/login` | Giriş `{email, password}` → JWT |
| GET | `/api/addresses` | Adres listesi (JWT) |
| POST | `/api/addresses` | Adres ekle (il/ilçe/mahalle, JWT) |
| GET | `/api/favorites` | Favori ürünler (JWT) |
| POST | `/api/favorites` | Favoriye ekle `{product_id}` (JWT) |
| DELETE | `/api/favorites/:product_id` | Favoriden çıkar (JWT) |
| POST | `/api/orders` | Sipariş oluştur `{address_id, items:[{product_id, qty}]}` — stok kontrollü (JWT) |
| GET | `/api/orders/:id` | Sipariş detayı (yalnız sahibi, JWT) |
| POST | `/api/payments/iyzico/init` | Ödeme başlat `{order_id}` → `{paymentPageUrl, token}` (JWT) |
| POST | `/api/payments/iyzico/callback` | Ödeme sonucu `{token}` → sipariş `paid` olur |

JWT kullanımı: `Authorization: Bearer <token>`

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
   - `SHIPPING_CENTS` — kargo ücreti (kuruş), örn. `0`
   - `NODE_ENV` — `production`
5. **Deploy et:** Railway `Dockerfile`'ı otomatik algılar (`railway.json` hazır). İlk açılışta `schema.sql` otomatik uygulanır (`npm run migrate` → tablolar + 6 kategori oluşur).
6. **Domain bağla:** Servis → Settings → Networking → **Generate Domain**, sonra chinabazaar.com DNS'inde API için CNAME (örn. `api.chinabazaar.com`) tanımla.

> iyzico anahtarları yoksa API çalışır; ödeme endpoint'leri `503 payment_not_configured` döner. Sahte/test ödemesi **yoktur**.

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
- Şifreler bcrypt ile hash'lenir; auth endpoint'lerinde rate limit vardır.
