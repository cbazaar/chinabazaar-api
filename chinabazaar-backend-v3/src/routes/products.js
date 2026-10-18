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

const rateLimit = require('express-rate-limit');
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
  keyGenerator: (req) => 'shop-share:' + (req.user && req.user.id ? String(req.user.id) : req.ip),
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
async function backfillFactoryCbfCodes() {
  try {
    const { rows: pending } = await pool.query(`SELECT COUNT(*)::int AS n FROM factories WHERE cbf_code IS NULL OR TRIM(cbf_code) = ''`);
    if (!pending.length || !pending[0].n) return;
    const { rows } = await pool.query(`SELECT id, name, cbf_code FROM factories ORDER BY id ASC`);
    let max = 0;
    for (const r of rows) max = Math.max(max, parseCbfCodeNumber(r.cbf_code));
    const groups = new Map();
    for (const r of rows) {
      const key = normalizeFactoryNameKey(r.name);
      const existing = (typeof r.cbf_code === 'string' ? r.cbf_code.trim() : '');
      if (!key) {
        // Adsiz satir: grup yapilmaz, her biri kendi kodunu alir.
        if (!existing) { max += 1; await pool.query('UPDATE factories SET cbf_code = $1 WHERE id = $2', [formatCbfCode(max), r.id]); }
        continue;
      }
      if (!groups.has(key)) groups.set(key, { code: '', fill: [] });
      const g = groups.get(key);
      if (existing) { if (!g.code) g.code = normalizeCbfCode(existing); }
      else g.fill.push(r.id);
    }
    for (const g of groups.values()) {
      if (!g.fill.length) continue;
      if (!g.code) { max += 1; g.code = formatCbfCode(max); }
      for (const id of g.fill) await pool.query('UPDATE factories SET cbf_code = $1 WHERE id = $2', [g.code, id]);
    }
  } catch (e) { /* backfill hatasi akisi bozmaz */ }
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
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_ratings (id SERIAL PRIMARY KEY, factory_id INT NOT NULL REFERENCES factories(id) ON DELETE CASCADE, user_id TEXT NOT NULL, rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5), created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(), UNIQUE(factory_id, user_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_subscriptions (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, status TEXT DEFAULT 'pending', started_at TIMESTAMPTZ, ends_at TIMESTAMPTZ, paytr_merchant_oid TEXT UNIQUE, amount INT, currency TEXT DEFAULT 'USD', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  // Abonelik/VIP: admin_grant tamamlayici abonelik icin plan/provider/expires_at.
  // Eski (odemeli) satirlarda yalniz ends_at dolu olabilir — /me ikisini COALESCE ile okur,
  // grant her iki sutunu da ayni degere yazar; boylece ends_at okuyan mevcut kod bozulmaz.
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS plan TEXT`);
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS provider TEXT`);
  await pool.query(`ALTER TABLE factory_subscriptions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await pool.query(`CREATE TABLE IF NOT EXISTS factories (id SERIAL PRIMARY KEY, name TEXT NOT NULL, city TEXT DEFAULT '', category TEXT DEFAULT '', description TEXT DEFAULT '', moq INT DEFAULT 0, stock INT DEFAULT 0, capacity TEXT DEFAULT '', certs TEXT DEFAULT '', features TEXT DEFAULT '', import_countries TEXT DEFAULT '', employees TEXT DEFAULT '', factory_area TEXT DEFAULT '', years TEXT DEFAULT '', main_products TEXT DEFAULT '', videos JSONB DEFAULT '[]', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS hashtags TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS address TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS contact TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS wechat TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS whatsapp TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS socials JSONB DEFAULT '{}'`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS features TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS import_countries TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS employees TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS factory_area TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS years TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS main_products TEXT DEFAULT ''`);
  // CBF: fabrika kodu (CBF-001, …). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS cbf_code TEXT`); } catch (e) { /* cbf_code kolonu eklenemezse akis bozulmaz */ }
  // VERIFIED: dogrulanmis fabrika rozeti (is_verified BOOLEAN, varsayilan FALSE). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE`); } catch (e) { /* is_verified kolonu eklenemezse akis bozulmaz */ }
  // FACTORY EMAIL (fix5): fabrika e-posta adresi (opsiyonel, max 254, e-posta bicimi). Her ALTER kendi try/catch'indedir.
  try { await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS email TEXT`); } catch (e) { /* email kolonu eklenemezse akis bozulmaz */ }
  // v118: user_id tip onarimi — users.id UUID, ama fabrika tablolari user_id'yi INT diye
  // tanimlamisti; UUID'li kullaniciyla her user_id sorgusu 500 veriyordu. INT->TEXT
  // donusumu kayipsizdir (her INT metne cevrilir); TEXT kolonda tekrar calismak no-op'tur.
  // Her ALTER kendi try/catch'indedir: bir tablodaki hata digerlerini/rotayi bozmaz.
  for (const t of ['factory_likes', 'factory_comments', 'factory_favorites', 'factory_messages', 'factory_quotes', 'factory_ratings', 'factory_subscriptions']) {
    try { await pool.query(`ALTER TABLE ${t} ALTER COLUMN user_id TYPE TEXT USING user_id::text`); } catch (e) { /* tablo/sutun yoksa veya tip zaten TEXT ise yoksay */ }
  }
  // CBF backfill: kodu bos fabrikalara kod ata (idempotent, hatada akis bozulmaz).
  await backfillFactoryCbfCodes();
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
  keyGenerator: (req) => 'factory-spam:' + (req.user && req.user.id ? String(req.user.id) : req.ip),
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
  keyGenerator: (req) => 'shop-spam:' + (req.user && req.user.id ? String(req.user.id) : req.ip),
});

// SHOP SECURITY: gizli jeton karsilastirmasi icin zamanlama-saldirisina dayanikli esitlik.
function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Goruntulenecek ad: nickname || name || e-posta on eki (e-posta adresinin tamami ASLA donulmez)
function factoryDisplayName(u) {
  if (!u) return 'Misafir';
  if (u.nickname && String(u.nickname).trim()) return u.nickname;
  if (u.name && String(u.name).trim()) return u.name;
  if (u.email) return String(u.email).split('@')[0] || 'Misafir';
  return 'Misafir';
}

function toFactoryPublic(r) {
  let videos = r.videos;
  if (typeof videos === 'string') { try { videos = JSON.parse(videos); } catch { videos = []; } }
  if (!Array.isArray(videos)) videos = [];
  return {
    id: r.id,
    name: r.name,
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
    factory_area: r.factory_area || '',
    years: r.years || '',
    main_products: r.main_products || '',
    hashtags: r.hashtags || '',
    address: r.address || '',
    phone: r.phone || '',
    contact: r.contact || '',
    email: r.email || null,
    wechat: r.wechat || '',
    whatsapp: r.whatsapp || '',
    socials: parseFactorySocials(r.socials),
    tags: r.tags || '',
    videos,
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

function toFactoryAdmin(r) {
  return { ...toFactoryPublic(r), is_active: r.is_active !== false, created_at: r.created_at, updated_at: r.updated_at };
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

// v5: socials — obje veya JSON string; her URL bos veya http(s) ile baslamali, aksi halde null (400)
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
    if (t !== '' && !/^https?:\/\//i.test(t)) return null;
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

// videos: [{title?, url, kind}] — gecersiz oge varsa null (handler 400 doner)
function cleanFactoryVideos(v) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const it of v) {
    if (!it || typeof it !== 'object' || Array.isArray(it)) return null;
    if (typeof it.url !== 'string' || !/^https?:\/\//i.test(it.url.trim()) || it.url.trim().length > 2048) return null;
    if (it.kind !== 'video' && it.kind !== 'canli') return null;
    out.push({ title: typeof it.title === 'string' ? it.title.trim().slice(0, 200) : '', url: it.url.trim(), kind: it.kind });
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
  res.json({ video, views: rows[0].views });
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
  const rmap = await factoryRatingsMap(rows.map((r) => r.id));
  const qmap = await factoryQuoteCountsMap(rows.map((r) => r.id));
  res.json(rows.map((r) => ({ ...toFactoryPublic(r), rating_avg: (rmap[r.id] && rmap[r.id].rating_avg !== undefined) ? rmap[r.id].rating_avg : null, rating_count: (rmap[r.id] && rmap[r.id].rating_count) || 0, quote_count: qmap[r.id] || 0 })));
}));

// GET /api/products/factory/quote-counts — her fabrikanin toplam teklif sayisi (herkese acik istatistik)
router.get('/factory/quote-counts', asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(`SELECT id FROM factories WHERE is_active IS NOT FALSE ORDER BY id ASC`);
  const counts = await factoryQuoteCountsMap(rows.map((r) => r.id));
  res.json({ counts });
}));

// GET /api/products/factory/admin/list — tum fabrikalar + created_at (admin)
router.get('/factory/admin/list', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
  const { rows } = await pool.query(`SELECT * FROM factories ORDER BY id ASC`);
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
  body('socials').optional().custom((v) => {
    if (typeof v === 'string') { try { v = JSON.parse(v); } catch { throw new Error('invalid_socials'); } }
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('invalid_socials');
    for (const k of ['youtube', 'facebook', 'tiktok', 'instagram']) {
      const val = v[k];
      if (val === undefined || val === null || val === '') continue;
      if (typeof val !== 'string' || val.trim().length > 2048 || !/^https?:\/\//i.test(val.trim())) throw new Error('invalid_socials');
    }
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
        if (!mergeSets.length) return res.json(toFactoryAdmin(existingFactory));
        mergeSets.push('updated_at = now()');
        const { rows: mergedRows } = await pool.query(`UPDATE factories SET ${mergeSets.join(', ')} WHERE id = $1 RETURNING *`, mergeParams);
        if (!mergedRows.length) return res.status(404).json({ error: 'factory_not_found' });
        return res.json(toFactoryAdmin(mergedRows[0]));
      }
    }
    // CBF: body'de kod varsa normalize edip kullan; yoksa ayni isimde kod varsa onu tekrar kullan, yoksa siradaki kodu ata.
    let cbfCode = normalizeCbfCode(req.body.cbf_code);
    if (!cbfCode) cbfCode = await resolveCbfCodeForName(req.body.name);
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
    if (addressClean !== undefined || phoneClean !== undefined || contactClean !== undefined || wechatClean !== undefined || whatsappClean !== undefined || emailClean !== undefined || socialsClean !== undefined || tagsClean !== undefined || importCountriesClean !== undefined || employeesClean !== undefined || factoryAreaClean !== undefined || yearsClean !== undefined || mainProductsClean !== undefined) {
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
      if (factoryAreaClean !== undefined) updPush('factory_area', factoryAreaClean);
      if (yearsClean !== undefined) updPush('years', yearsClean);
      if (mainProductsClean !== undefined) updPush('main_products', mainProductsClean);
      const upd = await pool.query(`UPDATE factories SET ${updSets.join(', ')} WHERE id = $1 RETURNING *`, updParams);
      if (upd.rows.length) rows[0] = upd.rows[0];
    }
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
    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });
    sets.push('updated_at = now()');
    const { rows } = await pool.query(`UPDATE factories SET ${sets.join(', ')} WHERE id = $1 RETURNING *`, params);
    if (!rows.length) return res.status(404).json({ error: 'factory_not_found' });
    res.json(toFactoryAdmin(rows[0]));
  })
);

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

// GET /api/products/factory/subscription/me — giris yapan kullanicinin kendi aboneligi (baskasinin satiri donulmez)
// { has_active, plan, expires_at, is_vip } — is_vip = aktif + plan='yearly' (on yuz VIP rozeti icin).
router.get('/factory/subscription/me', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryTables();
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
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS attachment_url TEXT`);
  await pool.query(`ALTER TABLE factory_messages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'text'`);
  // v118: user_id tip onarimi (users.id UUID) — mesaj rotalari ensureFactoryTables'i
  // cagirmadigindan bu tablo icin donusum burada da calisir.
  try { await pool.query(`ALTER TABLE factory_messages ALTER COLUMN user_id TYPE TEXT USING user_id::text`); } catch (e) { /* tip zaten TEXT ise yoksay */ }
}

// Mesaj eki (resim) dogrulama: http(s) URL veya /uploads/ yolu kabul edilir.
function factoryMsgAttachmentOk(url) {
  return /^https?:\/\//i.test(url) || /^\/uploads\//i.test(url);
}

// POST /api/products/factory/messages {body?, attachment_url?, kind?} — kullanici mesaj gonderir (sender='user')
// Yazi veya resim: resimde body bos olabilir; en az biri dolu olmali.
router.post('/factory/messages', requireAuth, factorySpamLimiter,
  body('body').optional().trim().isLength({ max: 1000 }),
  body('attachment_url').optional().isString().isLength({ max: 2048 }),
  body('kind').optional().isIn(['text', 'image']),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    const text = (req.body.body || '').trim();
    const attachmentUrl = typeof req.body.attachment_url === 'string' ? req.body.attachment_url.trim() : '';
    let kind = req.body.kind === 'image' ? 'image' : 'text';
    if (attachmentUrl) {
      if (!factoryMsgAttachmentOk(attachmentUrl)) return res.status(400).json({ error: 'invalid_attachment_url' });
      kind = 'image';
    } else if (!text) {
      return res.status(400).json({ error: 'empty_message' });
    }
    const { rows } = await pool.query(
      `INSERT INTO factory_messages (user_id, body, sender, attachment_url, kind) VALUES ($1, $2, 'user', $3, $4) RETURNING id, user_id, body, sender, attachment_url, kind, created_at`,
      [req.user.id, text, attachmentUrl || null, kind]
    );
    res.status(201).json({ message: rows[0] });
  })
);

// GET /api/products/factory/messages — giris yapan kullanicinin kendi konusmasi (eskiden yeniye)
router.get('/factory/messages', requireAuth, asyncHandler(async (req, res) => {
  await ensureFactoryMessagesTable();
  const { rows } = await pool.query(
    `SELECT id, user_id, body, sender, attachment_url, kind, created_at FROM factory_messages WHERE user_id=$1 ORDER BY created_at ASC, id ASC`,
    [req.user.id]
  );
  res.json({ messages: rows });
}));

// Teklif istekleri (Profil > Tekliflerim) — Teklif Al formu e-posta ile gonderilirken bir kopya da burada saklanir.
async function ensureFactoryQuotesTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS factory_quotes (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, factory TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL DEFAULT '', qty TEXT NOT NULL DEFAULT '', msg TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`ALTER TABLE factory_quotes ADD COLUMN IF NOT EXISTS factory_id INT`);
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
    `SELECT m.id, m.user_id, m.body, m.sender, m.attachment_url, m.kind, m.created_at,
            COALESCE(NULLIF(u.nickname,''), NULLIF(u.name,''), split_part(u.email,'@',1), 'Misafir') AS name
     FROM factory_messages m LEFT JOIN users u ON u.id::text = m.user_id::text
     ORDER BY m.user_id ASC, m.created_at ASC, m.id ASC`
  );
  const byUser = new Map();
  for (const r of rows) {
    if (!byUser.has(r.user_id)) byUser.set(r.user_id, { user_id: r.user_id, name: r.name || 'Misafir', messages: [] });
    byUser.get(r.user_id).messages.push({ id: r.id, body: r.body, sender: r.sender, attachment_url: r.attachment_url || null, kind: r.kind || 'text', created_at: r.created_at });
  }
  res.json({ conversations: [...byUser.values()] });
}));

// POST /api/products/factory/admin/messages/:id/reply {body?, attachment_url?, kind?} — admin cevap gonderir (sender='admin'); :id = user_id
router.post('/factory/admin/messages/:id/reply', requireAuth, requireAdmin,
  param('id').isString().trim().isLength({ min: 1, max: 100 }),
  body('body').optional().trim().isLength({ max: 1000 }),
  body('attachment_url').optional().isString().isLength({ max: 2048 }),
  body('kind').optional().isIn(['text', 'image']),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureFactoryMessagesTable();
    const userId = String(req.params.id);
    const { rows: urows } = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (!urows.length) return res.status(404).json({ error: 'user_not_found' });
    const text = (req.body.body || '').trim();
    const attachmentUrl = typeof req.body.attachment_url === 'string' ? req.body.attachment_url.trim() : '';
    let kind = req.body.kind === 'image' ? 'image' : 'text';
    if (attachmentUrl) {
      if (!factoryMsgAttachmentOk(attachmentUrl)) return res.status(400).json({ error: 'invalid_attachment_url' });
      kind = 'image';
    } else if (!text) {
      return res.status(400).json({ error: 'empty_message' });
    }
    const { rows } = await pool.query(
      `INSERT INTO factory_messages (user_id, body, sender, attachment_url, kind) VALUES ($1, $2, 'admin', $3, $4) RETURNING id, user_id, body, sender, attachment_url, kind, created_at`,
      [userId, text, attachmentUrl || null, kind]
    );
    res.status(201).json({ message: rows[0] });
  })
);

// POST /api/products/factory/chat-upload — CBAI sohbetine resim yukle (giris yapmis kullanici)
// On yuz FormData ile gonderir (alan: `file`); ham resim govdesi de kabul edilir.
// Multer pakette yok — multipart siniri (boundary) elle cozumlenir, yeni bagimlilik yok.
// Yalnizca jpg/png/webp/gif, en fazla 10MB, sihirli bayt kontrolu, rastgele ad.
// Dosya src/uploads/factory-chat/ altina kaydedilir, herkese acik URL doner.
// Donen URL'in calismasi icin index.js'de /uploads static sunumu gerekir (v630'da eklendi).
const CHAT_UPLOAD_DIR = path.join(__dirname, '..', 'uploads', 'factory-chat');
const CHAT_UPLOAD_MAX = 10 * 1024 * 1024; // 10 MB
const CHAT_UPLOAD_MIME = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };

function chatUploadMagicOk(buf, mime) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return false;
  if (mime === 'image/jpeg') return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  if (mime === 'image/png') return buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a;
  if (mime === 'image/gif') return buf.toString('ascii', 0, 6) === 'GIF87a' || buf.toString('ascii', 0, 6) === 'GIF89a';
  if (mime === 'image/webp') return buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP';
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
      return {
        data: Buffer.from(buf.subarray(dataStart, dataEnd)),
        contentType: typeMatch ? typeMatch[1].trim().toLowerCase() : '',
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
  requireAuth,
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
      file = { data: req.body, contentType: ct };
    } else {
      return res.status(415).json({ error: 'invalid_content_type' });
    }
    const mime = file.contentType;
    if (!CHAT_UPLOAD_MIME[mime]) return res.status(415).json({ error: 'invalid_content_type' });
    if (file.data.length > CHAT_UPLOAD_MAX) return res.status(413).json({ error: 'file_too_large' });
    if (!chatUploadMagicOk(file.data, mime)) return res.status(415).json({ error: 'invalid_file' });
    await fs.promises.mkdir(CHAT_UPLOAD_DIR, { recursive: true });
    const name = 'chat-' + Date.now() + '-' + crypto.randomBytes(8).toString('hex') + '.' + CHAT_UPLOAD_MIME[mime];
    await fs.promises.writeFile(path.join(CHAT_UPLOAD_DIR, name), file.data);
    const base = req.protocol + '://' + req.get('host');
    res.status(201).json({ ok: true, url: base + '/uploads/factory-chat/' + name, size: file.data.length });
  })
);

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
  const allowed = [...WA_PUBLIC_KEYS, 'wa_token', ...ACC_PUBLIC_KEYS, ...ACC_SECRET_KEYS, ...GA_PUBLIC_KEYS, ...GA_SECRET_KEYS, ...XML_PUBLIC_KEYS, ...XML_SECRET_KEYS, ...SEC_PUBLIC_KEYS, ...SMS_PUBLIC_KEYS, ...SMS_SECRET_KEYS, ...SOCIAL_PUBLIC_KEYS];
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
