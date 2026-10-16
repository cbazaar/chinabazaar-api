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

const router = express.Router();

// v582: Pazaryerleri kolonlari (orders.js ensure deseniyle ayni)
async function ensureMarketplaceColumns() {
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplaces TEXT DEFAULT 'chinabazaar'`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplace_image TEXT`);
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS marketplace_images JSONB`);
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
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
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
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows: pr } = await pool.query('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!pr.length) return res.status(404).json({ error: 'product_not_found' });
    await pool.query('INSERT INTO product_shares (product_id, user_id) VALUES ($1,$2)', [req.params.id, req.user ? req.user.id : null]);
    const { rows: c } = await pool.query('SELECT COUNT(*)::int AS n FROM product_shares WHERE product_id=$1', [req.params.id]);
    res.json({ share_count: c[0].n });
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
    res.status(500).json({ ok: false, error: e.message });
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
const WA_PUBLIC_KEYS = ['wa_phone', 'wa_phone_id', 'wa_verify', 'wa_enabled', 'wa_order_notify', 'wa_shop_button'];
const ACC_PROGRAMS = ['nebim', 'logo', 'zirve', 'eta', 'akinsoft'];
const ACC_PUBLIC_KEYS = ACC_PROGRAMS.flatMap((p) => [`acc_${p}_api_url`, `acc_${p}_username`, `acc_${p}_firm`, `acc_${p}_enabled`]);
const ACC_SECRET_KEYS = ACC_PROGRAMS.map((p) => `acc_${p}_password`);
const GA_PUBLIC_KEYS = ['ga_measurement_id', 'ga_enabled'];
const GA_SECRET_KEYS = ['ga_api_secret'];
const SETTINGS_PUBLIC_KEYS = [...WA_PUBLIC_KEYS, ...ACC_PUBLIC_KEYS, ...GA_PUBLIC_KEYS];
const XML_PUBLIC_KEYS = ['xml_feed_enabled', 'xml_feed_mode'];
const XML_SECRET_KEYS = ['api_key'];
const SEC_PUBLIC_KEYS = ['sec_session_minutes', 'sec_failed_login_limit'];
const SETTINGS_PUBLIC_KEYS_ALL = [...SETTINGS_PUBLIC_KEYS, ...XML_PUBLIC_KEYS, ...SEC_PUBLIC_KEYS];
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
  settings.has_api_key = rows.some((r) => r.key === 'api_key' && r.value);
  res.json({ settings });
}));
router.put('/settings', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  await ensureSettingsTable();
  const incoming = req.body && req.body.settings && typeof req.body.settings === 'object' ? req.body.settings : {};
  const allowed = [...WA_PUBLIC_KEYS, 'wa_token', ...ACC_PUBLIC_KEYS, ...ACC_SECRET_KEYS, ...GA_PUBLIC_KEYS, ...GA_SECRET_KEYS, ...XML_PUBLIC_KEYS, ...XML_SECRET_KEYS, ...SEC_PUBLIC_KEYS];
  for (const [k, v] of Object.entries(incoming)) {
    if (!allowed.includes(k)) continue;
    if (typeof v !== 'string' && typeof v !== 'boolean') continue;
    const val = typeof v === 'boolean' ? (v ? 'true' : 'false') : v.trim();
    if (val === '') continue;
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
  const { rows } = await pool.query(`SELECT key, value FROM settings WHERE key IN ('ga_enabled', 'ga_measurement_id')`);
  const settings = { ga_enabled: false, ga_measurement_id: '' };
  rows.forEach((r) => {
    if (r.key === 'ga_enabled') settings.ga_enabled = r.value === 'true';
    if (r.key === 'ga_measurement_id') settings.ga_measurement_id = r.value || '';
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
  if (kv.xml_feed_mode === 'key' && (!kv.api_key || req.query.api_key !== kv.api_key)) {
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
    const { name, price, campaign_price, stock, description, tagline, sku, image_url, video_url, category, is_active, currency, color, size, dimensions, box_dimensions, weight, length, connector, power_type, barcode, storage, is_upcoming, brand, marketplaces, marketplace_image, marketplace_images } = req.body;
    await ensureMarketplaceColumns();
    const categoryId = await resolveCategoryId(category);
    try {
      const { rows } = await pool.query(
        `INSERT INTO products (sku, name, tagline, description, price_cents, currency, stock, category_id, video_url, thumb_url, is_active, color, size, dimensions, box_dimensions, weight, length, connector, power_type, barcode, storage, is_upcoming, brand, campaign_price_cents, marketplaces, marketplace_image, marketplace_images)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27::jsonb) RETURNING *`,
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
        ]
      );
      res.status(201).json(toProduct({ ...rows[0], category_slug: null, category_name: null }));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'sku_in_use' });
      throw err;
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
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    await ensureMarketplaceColumns();
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
      throw err;
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
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const me = await pool.query('SELECT is_blocked FROM users WHERE id = $1', [req.user.id]);
    if (me.rows[0]?.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    const { rows } = await pool.query(
      `INSERT INTO comments (product_id, user_id, body) VALUES ($1, $2, $3)
       RETURNING id, body, created_at`,
      [req.params.id, req.user.id, req.body.body.trim()]
    );
    res.status(201).json(rows[0]);
  })
);

module.exports = router;
