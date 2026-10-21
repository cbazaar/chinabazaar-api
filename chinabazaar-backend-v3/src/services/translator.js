// ============================================================================
// CANLI CEVIRI SERVISI — CBAi (chat_messages) + CBChat/CBDestek
// (factory_messages) sohbetlerinde iki dilli mesajlar icin.
//
// Sozlesme (POST /api/translate + mesaj uclari):
//   translate(text, { source?, target }) ->
//     { ok:true, translated, source, target, provider } | { ok:false, error, source, target }
//
// Saglayici zinciri (kalite sirasi):
//   (a) DEEPL_API_KEY varsa DeepL
//   (b) GOOGLE_TRANSLATE_API_KEY varsa Google Cloud Translation v2
//   (c) Google gtx genel ucu (anahtarsiz)
//   (d) MyMemory (anahtarsiz)
// Biri hata verirse siradakine gecilir; hepsi duserse { ok:false } doner —
// sohbet AKISI ASLA bloklanmaz (cagri yapan taraf cevirisiz devam eder).
//
// Sonuclar translations_cache tablosunda saklanir (anahtar:
// sha256(source|target|text)); ayni metin ikinci kez cevrilmez. Ayni istek
// icin es zamanli cift saglayici cagrisi da surec-ici kilitle engellenir.
// ============================================================================

const crypto = require('crypto');
const pool = require('../db');

const MAX_TEXT = 2000;
const PROVIDER_TIMEOUT_MS = 8000;

// ---------------------------------------------------------------------------
// Dil yardimcilari
// ---------------------------------------------------------------------------

const LANG_ALIASES = {
  cn: 'zh', 'zh-cn': 'zh', 'zh-hans': 'zh', 'zh-tw': 'zh', 'zh-hk': 'zh',
  nb: 'no', nn: 'no', iw: 'he', in: 'id', jp: 'ja', kr: 'ko',
};

// Kabul edilen dil kodlari (ISO-639-1 + zh). Disindaki deger gecersizdir.
const KNOWN_LANGS = new Set([
  'tr', 'en', 'zh', 'ru', 'ar', 'de', 'fr', 'es', 'it', 'pt', 'nl', 'pl',
  'uk', 'ja', 'ko', 'hi', 'id', 'vi', 'th', 'fa', 'ur', 'uz', 'az', 'ka',
  'el', 'sv', 'no', 'da', 'fi', 'cs', 'sk', 'hu', 'ro', 'bg', 'hr', 'sr',
  'he', 'ms', 'bn', 'ta', 'te', 'kk', 'ky', 'tg', 'tk', 'mn', 'hy', 'lt',
  'lv', 'et', 'sl', 'bs', 'mk', 'sq', 'be', 'is', 'ga', 'mt', 'af', 'sw',
]);

function normalizeLang(v) {
  if (v === undefined || v === null) return null;
  let s = String(v).trim().toLowerCase().replace('_', '-');
  if (!s) return null;
  if (LANG_ALIASES[s]) s = LANG_ALIASES[s];
  const base = s.split('-')[0];
  if (KNOWN_LANGS.has(s)) return s;
  if (KNOWN_LANGS.has(base)) return base;
  return null;
}

// Kaba ama hizli dil algisi (sozlesme sirasi: CJK->zh, Kiril->ru, Arap->ar,
// Turkce karakter->tr, diger->en). Saglayicilar kendi algisini da dondurur;
// bu yalnizca onbellek anahtari + MyMemory langpair icin kullanilir.
const TR_STRONG_WORDS = new Set([
  'merhaba', 'selam', 'tesekkur', 'tesekkurler', 'lutfen', 'urun', 'fiyat',
  'fiyati', 'kargo', 'siparis', 'gonder', 'gonderim', 'istiyorum', 'istiyoruz',
  'isterim', 'nasil', 'gunaydin', 'stok', 'stokta', 'adet', 'teslim', 'teslimat',
  'efendim', 'hayirli', 'ugurlar', 'gorusuruz', 'anlastik', 'tamamdir',
]);
function looksTurkish(t) {
  const lower = t.toLocaleLowerCase('tr');
  if (/(ne kadar|iyi gunler|iyi aksamlar|kolay gelsin|var mi|olur mu)/.test(lower)) return true;
  return lower.split(/[^\p{L}]+/u).some((w) => TR_STRONG_WORDS.has(w));
}

function detectLanguage(text) {
  const t = String(text || '');
  // Han + kana + hangul bloklari (CJK) — sozlesme geregi zh sayilir.
  if (/[㐀-鿿぀-ヿ가-힯]/.test(t)) return 'zh';
  if (/[Ѐ-ӿ]/.test(t)) return 'ru'; // Kiril
  if (/[؀-ۿݐ-ݿ]/.test(t)) return 'ar'; // Arap
  if (/[ğşıİĞŞ]/.test(t)) return 'tr'; // yalniz Turkceye ozgu harfler
  if (/[çöüÇÖÜ]/.test(t)) return 'tr'; // latin + Turkce sesli/umlu isaretler
  if (looksTurkish(t)) return 'tr'; // ASCII yazilmis Turkce (kelime ipuclari)
  return 'en';
}

// Google/MyMemory ciktisindaki HTML varliklarini cozer (&quot; &#39; &amp;…)
function decodeEntities(s) {
  return String(s || '')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_m, n) => { try { return String.fromCodePoint(parseInt(n, 10)); } catch { return _m; } })
    .replace(/&amp;/g, '&');
}

// ---------------------------------------------------------------------------
// Sema: onbellek tablosu + mesaj tablolarina ceviri sutunlari (idempotent).
// Hata olursa soz verip bir sonraki cagrida tekrar denenir; ceviri akisi
// sema olmadan da (onbelleksiz) calismaya devam eder.
// ---------------------------------------------------------------------------

let schemaPromise = null;
function ensureSchema() {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`CREATE TABLE IF NOT EXISTS translations_cache (
        key CHAR(64) PRIMARY KEY,
        source_text TEXT NOT NULL,
        source_lang VARCHAR(8),
        target_lang VARCHAR(8) NOT NULL,
        translated_text TEXT NOT NULL,
        provider VARCHAR(32),
        created_at TIMESTAMPTZ DEFAULT now()
      )`);
      for (const t of ['chat_messages', 'factory_messages']) {
        await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS translated_text TEXT`);
        await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS source_lang VARCHAR(8)`);
        await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS target_lang VARCHAR(8)`);
      }
    })().catch((e) => {
      schemaPromise = null; // bir sonraki cagrida tekrar dene
      console.error('[translator] sema hazirlanamadi:', e.message);
    });
  }
  return schemaPromise;
}

// ---------------------------------------------------------------------------
// Onbellek
// ---------------------------------------------------------------------------

function cacheKey(source, target, text) {
  return crypto.createHash('sha256').update(source + '|' + target + '|' + text, 'utf8').digest('hex');
}

async function cacheGet(key) {
  try {
    const { rows } = await pool.query('SELECT translated_text FROM translations_cache WHERE key = $1', [key]);
    return rows.length ? rows[0].translated_text : null;
  } catch { return null; }
}

async function cachePut(key, text, source, target, translated, provider) {
  try {
    await pool.query(
      `INSERT INTO translations_cache (key, source_text, source_lang, target_lang, translated_text, provider)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (key) DO NOTHING`,
      [key, text, source, target, translated, provider || null]
    );
  } catch { /* onbellek yazilamazsa ceviri yine de doner */ }
}

// ---------------------------------------------------------------------------
// Saglayicilar — her biri basarida cevrilmis metni, basarisizlikta firlatir.
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await fetch(url, { ...(opts || {}), signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function deeplCode(l) { return l === 'en' ? 'EN' : l.toUpperCase(); }
function googleCode(l) { return l === 'zh' ? 'zh-CN' : l; }

async function viaDeepL(text, source, target) {
  const key = process.env.DEEPL_API_KEY;
  const base = key.endsWith(':fx') ? 'https://api-free.deepl.com' : 'https://api.deepl.com';
  const form = new URLSearchParams();
  form.set('text', text);
  form.set('target_lang', deeplCode(target));
  if (source) form.set('source_lang', deeplCode(source));
  const res = await fetchWithTimeout(base + '/v2/translate', {
    method: 'POST',
    headers: { Authorization: 'DeepL-Auth-Key ' + key, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!res.ok) throw new Error('deepl_http_' + res.status);
  const data = await res.json();
  const out = data && data.translations && data.translations[0] && data.translations[0].text;
  if (!out) throw new Error('deepl_empty');
  return out;
}

async function viaGoogleCloud(text, source, target) {
  const key = process.env.GOOGLE_TRANSLATE_API_KEY;
  const res = await fetchWithTimeout('https://translation.googleapis.com/language/translate/v2?key=' + encodeURIComponent(key), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ q: text, target: googleCode(target), ...(source ? { source: googleCode(source) } : {}), format: 'text' }),
  });
  if (!res.ok) throw new Error('google_http_' + res.status);
  const data = await res.json();
  const t = data && data.data && data.data.translations && data.data.translations[0];
  if (!t || !t.translatedText) throw new Error('google_empty');
  return decodeEntities(t.translatedText);
}

async function viaGtx(text, source, target) {
  const url = 'https://translate.googleapis.com/translate_a/single?client=gtx'
    + '&sl=' + encodeURIComponent(source ? googleCode(source) : 'auto')
    + '&tl=' + encodeURIComponent(googleCode(target))
    + '&dt=t&q=' + encodeURIComponent(text);
  const res = await fetchWithTimeout(url, { headers: { 'User-Agent': 'Mozilla/5.0 (ChinaBazaar API)' } });
  if (!res.ok) throw new Error('gtx_http_' + res.status);
  const data = await res.json();
  if (!Array.isArray(data) || !Array.isArray(data[0])) throw new Error('gtx_bad_shape');
  const out = data[0].map((seg) => (seg && seg[0]) || '').join('');
  if (!out) throw new Error('gtx_empty');
  return out;
}

async function viaMyMemory(text, source, target) {
  // MyMemory 'auto' kaynak kabul etmez; algilanan kaynak kullanilir.
  const pair = googleCode(source) + '|' + googleCode(target);
  const url = 'https://api.mymemory.translated.net/get?q=' + encodeURIComponent(text)
    + '&langpair=' + encodeURIComponent(pair);
  const res = await fetchWithTimeout(url, { headers: { 'User-Agent': 'Mozilla/5.0 (ChinaBazaar API)' } });
  if (!res.ok) throw new Error('mymemory_http_' + res.status);
  const data = await res.json();
  const out = data && data.responseData && data.responseData.translatedText;
  const status = data && (data.responseStatus === 200 || data.responseStatus === '200');
  // MyMemory kota dolunca 429/403 + uyari metni doner; cevabi ceviri sanma.
  if (!status || !out || /MYMEMORY WARNING|QUERY LENGTH LIMIT|INVALID/i.test(out)) throw new Error('mymemory_failed');
  return decodeEntities(out);
}

function providerChain() {
  const chain = [];
  if (process.env.DEEPL_API_KEY) chain.push({ name: 'deepl', fn: viaDeepL });
  if (process.env.GOOGLE_TRANSLATE_API_KEY) chain.push({ name: 'google', fn: viaGoogleCloud });
  chain.push({ name: 'gtx', fn: viaGtx });
  chain.push({ name: 'mymemory', fn: viaMyMemory });
  return chain;
}

// ---------------------------------------------------------------------------
// Ana ceviri fonksiyonu
// ---------------------------------------------------------------------------

const inFlight = new Map(); // ayni anahtar icin es zamanli cift cagriyi engeller

async function translate(text, opts) {
  const raw = String((text === undefined || text === null) ? '' : text);
  const clean = raw.trim();
  const target = normalizeLang(opts && opts.target);
  let source = normalizeLang(opts && opts.source) || null;
  if (!clean) return { ok: false, error: 'empty', source, target };
  if (!target) return { ok: false, error: 'target_required', source, target: null };
  if (!source) source = detectLanguage(clean);
  if (source === target) return { ok: true, translated: clean, source, target, provider: 'none' };

  const capped = clean.slice(0, MAX_TEXT);
  await ensureSchema();
  const key = cacheKey(source, target, capped);

  const cached = await cacheGet(key);
  if (cached !== null) return { ok: true, translated: cached, source, target, provider: 'cache' };

  if (inFlight.has(key)) {
    try { return await inFlight.get(key); } catch { /* asagida kendi denemesini yapar */ }
  }

  const job = (async () => {
    let lastErr = null;
    for (const p of providerChain()) {
      try {
        const out = await p.fn(capped, source, target);
        const translated = String(out || '').trim();
        if (!translated) throw new Error(p.name + '_empty');
        cachePut(key, capped, source, target, translated, p.name);
        return { ok: true, translated, source, target, provider: p.name };
      } catch (e) {
        lastErr = e;
      }
    }
    console.error('[translator] tum saglayiciler dustu:', lastErr && lastErr.message);
    return { ok: false, error: 'providers_failed', source, target };
  })();

  inFlight.set(key, job);
  try { return await job; } finally { inFlight.delete(key); }
}

// ---------------------------------------------------------------------------
// Mesaj uclari icin ortak yardimci:
//  - Ister istemci hazir ceviriyi gondersin ({translated_text, source_lang,
//    target_lang}) — aynen saklanir;
//  - ister {translate_to:"zh"} versin — sunucu gondermeden once cevirir,
//    basarisizsa cevirisiz (null) kaydeder; mesaj akisi bloklanmaz.
// ---------------------------------------------------------------------------

async function resolveMessageTranslation(text, body) {
  const out = { translated_text: null, source_lang: null, target_lang: null };
  const clean = String(text || '').trim();
  if (!clean) return out;
  const b = body || {};
  if (typeof b.translated_text === 'string' && b.translated_text.trim()) {
    out.translated_text = b.translated_text.trim().slice(0, 4000);
    out.source_lang = normalizeLang(b.source_lang) || detectLanguage(clean);
    out.target_lang = normalizeLang(b.target_lang);
    return out;
  }
  const to = normalizeLang(b.translate_to);
  if (to) {
    const r = await translate(clean, { source: b.source_lang, target: to });
    if (r.ok) {
      out.translated_text = r.translated;
      out.source_lang = r.source;
      out.target_lang = r.target;
    }
  }
  return out;
}

module.exports = {
  translate,
  detectLanguage,
  normalizeLang,
  ensureSchema,
  resolveMessageTranslation,
  MAX_TEXT,
  // testler icin:
  _providerChain: providerChain,
  _cacheKey: cacheKey,
  _decodeEntities: decodeEntities,
};
