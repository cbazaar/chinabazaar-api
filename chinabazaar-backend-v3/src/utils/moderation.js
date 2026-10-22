// CBOs27.3 — Sohbet içerik denetimi + güvenlik olayları + otomatik engel.
//
// 1) checkText(text): TR/EN/ZH/RU/AR erotik-cinsel ve taciz içerik denetimi.
//    Normalizasyon: küçük harf (Türkçe duyarlı), aksan katlama, Arapça
//    hareke/uzatma temizliği, basit leetspeak katlama; kısa terimlerde
//    kelime sınırı, uzun terimlerde alt-dize, Çince'de alt-dize eşleşmesi.
//    Amaç: masum ürün/mesaj trafiğini (örn. "kırmızı elbise fiyatı nedir")
//    ASLA engellememek — listeler odaklıdır, sınır kuralları katıdır.
// 2) security_events: engelleme/şikayet/engel olaylarının kaydı
//    (CBOs27.2 securityGuard ile AYNI tablo adı/sütunlar; CREATE TABLE
//    IF NOT EXISTS — iki paket birbirini bozmadan çalışır).
// 3) Otomatik engel: sunucu denetimi bir gönderimi engellerse hesap ANINDA
//    engellenir (users: blocked + mevcut is_blocked birlikte set edilir;
//    fabrikalar `factories` tablosundadır, aynı sütunlar oraya da aynalanır).
//    Master kimliği (sub 'cbai') users/factories satırı DEĞİLDİR — engel
//    kontrolü satır bulamazsa sessizce geçer, master dalı bozulmaz.
//
// NOT: Terim listeleri bu dosyada kod olarak durur; raporlara YAZILMAZ.

'use strict';

/* ============================ terim listeleri ============================ */

const SEXUAL = {
  tr: [
    'sikiş', 'sikmek', 'sikerim', 'sikik', 'sik', 'siktir', 'amcık', 'amına',
    'yarak', 'yarrak', 'taşak', 'götveren', 'götüne', 'orospu', 'sürtük',
    'fahişe', 'pezevenk', 'porno', 'pornografi', 'seks', 'sex', 'penis',
    'vajina', 'dildo', 'mastürbasyon', 'masturbasyon', 'boşalmak', 'sakso',
    'oral seks', 'anal seks', 'tecavüz', 'çocuk pornosu',
  ],
  en: [
    'fuck', 'fucking', 'fucker', 'pussy', 'cock', 'dick', 'penis', 'vagina',
    'porn*', 'porno', 'pornography', 'sex', 'sexting', 'blowjob', 'handjob',
    'masturbate', 'masturbation', 'cum', 'orgasm', 'nude', 'nudes', 'boobs',
    'tits', 'anal sex', 'oral sex', 'hardcore', 'dildo', 'vibrator',
    'prostitute', 'slut', 'rape', 'raping', 'pedophile', 'child porn',
  ],
  zh: [
    '色情', '性爱', '做爱', '裸体', '裸照', '阴茎', '阴道', '阴蒂', '自慰',
    '手淫', '强奸', '嫖娼', '卖淫', '妓女', '约炮', '一夜情', '成人视频',
    '黄片', '性交', '口交', '肛交', '射精', '高潮', '鸡巴', '肉棒', '奶子',
    '肏', '操你', '操你妈',
  ],
  ru: [
    'хуй', 'хуя', 'хуем', 'пизд*', 'ебат*', 'ебал*', 'ебля*', 'бляд*', 'шлюх*',
    'проститут', 'порн*', 'секс', 'минет', 'мастурб', 'вагин', 'пенис',
    'залуп', 'сиськ', 'сперм', 'конча',
  ],
  ar: [
    'سكس', 'ممارسة الجنس', 'افلام جنسية', 'أفلام جنسية', 'اباحية', 'إباحية',
    'اباحي', 'زنا', 'لواط', 'سحاق', 'متناكة', 'متناك', 'شرموطة', 'شرموط',
    'قحبة', 'قحاب', 'اغتصاب', 'كس', 'طيز', 'زب', 'نيك', 'منيوك', 'كسم',
    'صور عارية', 'عاهرة', 'عاهرات', 'دعارة', 'مومس',
  ],
};

const HARASSMENT = {
  tr: [
    'geber', 'gebersin', 'seni öldürürüm', 'seni oldururum', 'öldüreceğim',
    'oldurecegim', 'kafanı kırarım', 'kafani kirarim', 'piç kurusu',
    'pic kurusu', 'şerefsiz', 'haysiyetsiz',
  ],
  en: [
    'kill you', 'i will kill you', 'kill yourself', 'kys', 'bitch', 'whore',
    'nigger', 'faggot', 'retard', 'go die',
  ],
  zh: [
    '傻逼', '滚蛋', '去死', '杀了你', '弄死你', '贱人', '婊子', '混蛋',
    '王八蛋', '脑残', '贱货',
  ],
  ru: [
    'убью', 'убью тебя', 'убей', 'сдохни', 'сука', 'ублюд', 'мразь', 'тварь',
    'нахуй', 'зарежу', 'прибью',
  ],
  ar: [
    'خول', 'عرص', 'ساقتلك', 'سأقتلك', 'اقتلك', 'اذبحك', 'يا حيوان',
    'ابن الكلب', 'منيوك', 'شرموطة',
  ],
};

const LISTS = { sexual: SEXUAL, harassment: HARASSMENT };

/* ============================ normalizasyon ============================ */

// Türkçe duyarlı küçük harf + aksan katlama + Arapça hareke temizliği +
// basit leetspeak katlama (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, 8->b, @->a, $->s).
function normalizeText(s) {
  let t = String(s == null ? '' : s);
  t = t.replace(/İ/g, 'i').replace(/I/g, 'ı');
  t = t.toLowerCase();
  // Arapça: hareke (064B-065F), üst işaret (0670) ve tatweel (0640) temizle.
  t = t.replace(/[\u0640\u064B-\u065F\u0670]/g, '');
  // Latin aksan katlama (NFD): ş->s, ğ->g, ü->u, ö->o, ç->c, â->a...
  // Kiril ё->е de bu yolla katlanır. Çince/Arapça harfler etkilenmez.
  t = t.normalize('NFD').replace(/[\u0300-\u036F]/g, '');
  // Leetspeak katlama (rakamlar/semboller harfe).
  t = t.replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
       .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
       .replace(/8/g, 'b').replace(/@/g, 'a').replace(/\$/g, 's');
  return t;
}

// Sıkıştırılmış biçim: yalnız harfler + tekrarlar teke indirilir.
// "s i k i ş", "s.i.k.i.s", "siiikis" gibi kaçamakları yakalar.
function squashText(s) {
  const n = normalizeText(s).replace(/[^\p{L}]+/gu, '');
  return n.replace(/(.)\1+/g, '$1');
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const HAS_CJK = /[\u3400-\u9FFF\uF900-\uFAFF]/;

// Terimleri bir kez ön-işle: { n (normalize), s (squash), cjk, short }
function compileList(byLang) {
  const out = [];
  for (const lang of Object.keys(byLang)) {
    for (const raw0 of byLang[lang]) {
      // Sondaki '*' = kök (stem) terim: kelime sınırına bakılmadan alt-dize
      // eşleşir (örn. Rusça 'пизд*' -> пизда/пиздец; 'порн*' -> порно/порнография).
      const stem = raw0.endsWith('*');
      const raw = stem ? raw0.slice(0, -1) : raw0;
      const n = normalizeText(raw);
      const s = squashText(raw);
      if (!s) continue;
      out.push({ n, s, stem, cjk: HAS_CJK.test(raw), short: s.length <= 4 });
    }
  }
  return out;
}

const COMPILED = {
  sexual: compileList(SEXUAL),
  harassment: compileList(HARASSMENT),
};

function termMatches(entry, normText, squashedText) {
  if (entry.cjk || entry.stem) return normText.includes(entry.n) || squashedText.includes(entry.s);
  if (entry.short) {
    // Kısa terim: yalnız kelime sınırında (örn. "sex" -> "essex" yakalanmaz,
    // "cumin" içindeki "cum" yakalanmaz, "عكس" içindeki "كس" yakalanmaz).
    const re = new RegExp('(^|[^\\p{L}\\p{N}])' + escapeRegExp(entry.n) + '($|[^\\p{L}\\p{N}])', 'u');
    return re.test(normText);
  }
  return normText.includes(entry.n) || squashedText.includes(entry.s);
}

// checkText(text) -> { blocked: boolean, category: 'sexual'|'harassment'|null }
function checkText(text) {
  const raw = String(text == null ? '' : text);
  if (!raw.trim()) return { blocked: false, category: null };
  const norm = normalizeText(raw);
  const squashed = squashText(raw);
  for (const category of ['sexual', 'harassment']) {
    for (const entry of COMPILED[category]) {
      if (termMatches(entry, norm, squashed)) return { blocked: true, category };
    }
  }
  return { blocked: false, category: null };
}

// Birden çok metin (gövde + çeviri + ek başlığı) için: ilk ihlali döner.
function checkTexts(texts) {
  for (const t of texts || []) {
    if (typeof t !== 'string' || !t.trim()) continue;
    const r = checkText(t);
    if (r.blocked) return r;
  }
  return { blocked: false, category: null };
}

/* ============================ güvenlik olayları ============================ */

let _eventsReady = null;
function ensureSecurityEvents(pool) {
  if (_eventsReady) return _eventsReady;
  _eventsReady = (async () => {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS security_events (
         id SERIAL PRIMARY KEY,
         type TEXT NOT NULL,
         user_id TEXT,
         ip TEXT,
         path TEXT,
         detail JSONB,
         created_at TIMESTAMPTZ DEFAULT now()
       )`
    );
    // CBOs27.4: tek-paket tanimiyla olusmus tabloyu ust kumeye tamamla
    // (securityGuard.ensureSecurityEventsTable ile ayni birlesik tanim).
    await pool.query(`ALTER TABLE security_events ADD COLUMN IF NOT EXISTS path TEXT`);
    await pool.query(`ALTER TABLE security_events ADD COLUMN IF NOT EXISTS detail JSONB`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_type_created ON security_events (type, created_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_user_created ON security_events (user_id, created_at)`);
  })();
  _eventsReady.catch(() => { _eventsReady = null; });
  return _eventsReady;
}

// Kayıt akışı sohbeti ASLA bloklamaz: hata sessizce yutulur.
async function logSecurityEvent(pool, ev) {
  try {
    await ensureSecurityEvents(pool);
    await pool.query(
      `INSERT INTO security_events (type, user_id, ip, detail) VALUES ($1, $2, $3, $4)`,
      [String(ev.type || 'event'), ev.userId == null ? null : String(ev.userId), ev.ip || null, ev.detail ? JSON.stringify(ev.detail) : null]
    );
  } catch (e) { /* kayıt hatası akışı bozmaz */ }
}

/* ============================ otomatik engel ============================ */

let _blockSchemaReady = null;
// users + factories engel sütunları (idempotent). users.is_blocked ZATEN var
// (mevcut giriş akışları kullanır) — ona dokunulmaz; yeni `blocked` bayrağı
// onunla birlikte set edilir, etkin engel = blocked OR is_blocked.
function ensureBlockSchema(pool) {
  if (_blockSchemaReady) return _blockSchemaReady;
  _blockSchemaReady = (async () => {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_reason TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS violation_count INT DEFAULT 0`);
    try {
      await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS blocked BOOLEAN DEFAULT FALSE`);
      await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS blocked_reason TEXT`);
      await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ`);
      await pool.query(`ALTER TABLE factories ADD COLUMN IF NOT EXISTS violation_count INT DEFAULT 0`);
    } catch (e) { /* factories yoksa kullanıcı akışı yine çalışır */ }
  })();
  _blockSchemaReady.catch(() => { _blockSchemaReady = null; });
  return _blockSchemaReady;
}

// Sunucu denetimi bir gönderimi engellediğinde çağrılır: sayaç +1 ve hesap
// ANINDA engellenir + 'content_blocked' ve 'auto_block' olayları yazılır.
// actorKind: 'user' (users) | 'factory' (factories). Master için ÇAĞRILMAZ
// (admin cevapları denetimden muaf; master'ın tablo satırı yok).
async function registerViolation(pool, opts) {
  const { actorKind, actorId, ip, category, surface } = opts || {};
  await ensureBlockSchema(pool);
  let violationCount = null;
  if (actorKind === 'factory') {
    const { rows } = await pool.query(
      `UPDATE factories SET violation_count = COALESCE(violation_count, 0) + 1,
              blocked = TRUE, blocked_reason = $2, blocked_at = now()
       WHERE id = $1 RETURNING violation_count`,
      [Number(actorId), String(category || 'content')]
    );
    if (rows[0]) violationCount = rows[0].violation_count;
  } else {
    const { rows } = await pool.query(
      `UPDATE users SET violation_count = COALESCE(violation_count, 0) + 1,
              blocked = TRUE, is_blocked = TRUE, blocked_reason = $2, blocked_at = now()
       WHERE id = $1 RETURNING violation_count`,
      [String(actorId), String(category || 'content')]
    );
    if (rows[0]) violationCount = rows[0].violation_count;
  }
  const actorRef = actorKind === 'factory' ? 'factory:' + String(actorId) : String(actorId);
  await logSecurityEvent(pool, { type: 'content_blocked', userId: actorRef, ip, detail: { category, surface: surface || null, violation_count: violationCount } });
  await logSecurityEvent(pool, { type: 'auto_block', userId: actorRef, ip, detail: { category, surface: surface || null, violation_count: violationCount, trigger: 'content_blocked' } });
  return { violationCount, blockedNow: true };
}

// İstemci bildirimi: POST /api/chat/report { type: 'violation' } — yalnız
// gönderenin KENDİ jetonuyla KENDİ denemesi için (başkası hedeflenemez).
// Sayaç +1; son 24 saatte 3 istemci bildirimi -> otomatik engel.
async function registerClientViolation(pool, opts) {
  const { userId, ip } = opts || {};
  await ensureBlockSchema(pool);
  const { rows } = await pool.query(
    `UPDATE users SET violation_count = COALESCE(violation_count, 0) + 1 WHERE id = $1 RETURNING violation_count`,
    [String(userId)]
  );
  const violationCount = rows[0] ? rows[0].violation_count : null;
  await logSecurityEvent(pool, { type: 'client_violation', userId: String(userId), ip, detail: { violation_count: violationCount } });
  const { rows: crows } = await pool.query(
    `SELECT count(*)::int AS c FROM security_events WHERE type = 'client_violation' AND user_id = $1 AND created_at > now() - interval '24 hours'`,
    [String(userId)]
  );
  const count24h = crows[0] ? crows[0].c : 0;
  let blockedNow = false;
  if (count24h >= 3) {
    await pool.query(
      `UPDATE users SET blocked = TRUE, is_blocked = TRUE, blocked_reason = 'client_violation', blocked_at = now() WHERE id = $1`,
      [String(userId)]
    );
    blockedNow = true;
    await logSecurityEvent(pool, { type: 'auto_block', userId: String(userId), ip, detail: { trigger: 'client_violation', count_24h: count24h, violation_count: violationCount } });
  }
  return { violationCount, count24h, blockedNow };
}

// Etkin engel durumu (auth ara katmanları kullanır; hata çağırana bırakılır,
// ara katman fail-open davranır — masterRevoke deseniyle aynı).
async function getUserBlockState(pool, userId) {
  await ensureBlockSchema(pool);
  const { rows } = await pool.query(
    `SELECT (COALESCE(blocked, FALSE) OR COALESCE(is_blocked, FALSE)) AS blocked FROM users WHERE id::text = $1`,
    [String(userId)]
  );
  return rows.length ? !!rows[0].blocked : false;
}

async function getFactoryBlockState(pool, factoryId) {
  await ensureBlockSchema(pool);
  const { rows } = await pool.query(
    `SELECT COALESCE(blocked, FALSE) AS blocked FROM factories WHERE id = $1`,
    [Number(factoryId)]
  );
  return rows.length ? !!rows[0].blocked : false;
}

module.exports = {
  checkText,
  checkTexts,
  normalizeText,
  ensureSecurityEvents,
  logSecurityEvent,
  ensureBlockSchema,
  registerViolation,
  registerClientViolation,
  getUserBlockState,
  getFactoryBlockState,
  // testler icin:
  _lists: LISTS,
};
