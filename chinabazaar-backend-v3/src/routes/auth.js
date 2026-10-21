// Kimlik doğrulama: kayıt + giriş (JWT)
// fix10e: H-D admin-reset-password (limit + timing-safe admin_key + jenerik yanıt),
// H-E CBAI master (sub+jti, 1 gün, denetim kaydı), L1 dummy hash cost 12 +
// uzunluk erken dönüşü yok, L2 jenerik yanıtlar, L3 'cbai' rezerve,
// L4 şifre politikası (min 8 + harf+rakam), L18 JWT HS256 allowlist,
// M6 profil e-posta/telefon benzersizliği, M11 phone-send-code (kayıt +
// cooldown), SABAH-4 forgot-password-sms jenerik yanıt, M2 ipKeyGenerator.
// fix10am: QR ile giriş (POST /qr/create, POST /qr/approve, GET /qr/status)
// — 128-bit oturum + secret hash'i, 2 dk geçerli, tek kullanım; QR sunucuda
// gömülü MIT qrcode-generator ile üretilir (harici ağ yok).
// fix10an (CBOs26.95-A): QR onay adresi chinabazaar.com -> chinabazaar.shop
// (onay ekranı şimdilik yalnız mağaza ön yüzünde canlı); başka değişiklik yok.
// fix10ao (CBOs26.96-A): qr_logins.user_id INT -> TEXT. users.id UUID olduğu
// için INT sütuna UUID yazma denemesi canlıda 500 veriyordu; CREATE tanımı
// düzeltildi + canlıda INT oluşmuş tablo için ensureQrLogins() içine
// idempotent ALTER göçü eklendi. Başka değişiklik yok.
// fix10ap (CBOs26.98): kayıtta kullanıcı adı (nickname) desteği — register
// artık nickname'i PATCH /me ile aynı sözleşmeyle doğrulayıp kaydediyor
// (geçersiz 400 validation_failed, rezerve 400 nickname_reserved, dolu 409
// conflict; verilmezse NULL — eski davranış). PATCH /me'ye de açık dolu-ad
// kontrolü eklendi (önceden yalnız DB 23505 yakalamasına dayanıyordu).
const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { loginLimiter, registerLimiter, strictLoginLimiter, loginIdentifierLimiter, adminResetLimiter, ipKeyGenerator } = require('../middleware/rateLimit');
const codeLimiter = require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' }, keyGenerator: (req) => 'code:' + ipKeyGenerator(req.ip) });
const nicknameCheckLimiter = require('express-rate-limit')({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' }, keyGenerator: (req) => 'nick:' + ipKeyGenerator(req.ip) });
const jwt = require('jsonwebtoken');
const { signToken, requireAuth, optionalAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');
const mailer = require('../services/mailer');
const crypto = require('crypto');

const router = express.Router();

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, nickname: row.nickname || null, phone: row.phone, is_admin: !!row.is_admin, customer_code: row.customer_code || null };
}

// ---- Giriş: tanıtan (identifier) yardımcıları ----
// Kullanıcı yoksa bile bcrypt karşılaştırması yapılır (zamanlama ile kullanıcı
// sayımını zorlaştırmak için); sahte hash başlangıçta bir kez üretilir.
const DUMMY_HASH = bcrypt.hashSync('__chinabazaar_no_such_user__', 12); // fix10e L1: 10 -> 12

// fix10e L1: uzunluk erken dönüşü YOK — iki değer de SHA-256 ile sabit
// uzunluklu özetlere indirgenir, timingSafeEqual özetler üzerinde çalışır.
// (Uzunluk farkı artık zamanlama ile ayırt edilemez.)
function timingSafeEqualDigest(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const da = crypto.createHash('sha256').update(a).digest();
  const db = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(da, db);
}

// fix10e L4: şifre politikası — en az 8 karakter + en az bir harf + en az bir rakam.
function passwordStrong(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

// fix10e L3: 'cbai' rezerve — kullanıcı adı / nickname olarak alınamaz.
function isCbaiNick(nick) {
  return String(nick || '').trim().toLowerCase() === 'cbai';
}

// fix10e H-E: master işlem denetim kaydı — created_by ASLA null değil,
// master işaretli 'cbai' yazılır. Tablo yoksa oluşturulur; hata akışı bozmaz.
async function logMasterAudit(action, targetType, targetId) {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS master_audit_log (id SERIAL PRIMARY KEY, action TEXT NOT NULL, target_type TEXT, target_id TEXT, created_by TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
    await pool.query(`INSERT INTO master_audit_log (action, target_type, target_id, created_by) VALUES ($1, $2, $3, 'cbai')`, [action, targetType || null, targetId == null ? null : String(targetId)]);
  } catch (e) { /* denetim kaydı ana akışı bozmaz */ }
}
// Telefon varyantları: kayıtlı numara hangi formatta yazılmış olursa olsun
// eşleşsin diye boşluk/tire/parantez atılır; +90 ↔ 0 ↔ çıplak alan kodu
// dönüşümleri denenir. Şifre ASLA loglanmaz, tanıtan şifreyle birlikte loglanmaz.
function phoneCandidates(identifier) {
  const raw = String(identifier || '').replace(/[\s\-().]/g, '');
  if (!raw) return [];
  const out = new Set([raw]);
  if (raw.startsWith('+90')) { out.add('0' + raw.slice(3)); out.add(raw.slice(3)); }
  else if (raw.startsWith('90') && raw.length >= 11) { out.add('+90' + raw.slice(2)); out.add('0' + raw.slice(2)); }
  else if (raw.startsWith('0')) { out.add('+90' + raw.slice(1)); out.add(raw.slice(1)); }
  return [...out];
}

// ---- CBAI master (fix10d + fix10e H-E/L2) ----
// Master şifresi YALNIZCA Railway env'den okunur (CBAI_MASTER_PASSWORD).
// Şifre ASLA kodda/DB'de/test dosyasında/sohbette olmaz, ASLA loglanmaz.
// fix10e H-E: jeton sub='cbai' + jti taşır, süre 7 gün -> 1 gün.
function cbaiMasterConfigured() {
  return !!(process.env.CBAI_MASTER_PASSWORD || '');
}
function cbaiMasterPasswordOk(password) {
  const expected = process.env.CBAI_MASTER_PASSWORD || '';
  if (!expected || typeof password !== 'string' || !password) return false;
  return timingSafeEqualDigest(password, expected);
}
function signMasterToken() {
  return jwt.sign({ sub: 'cbai', role: 'master', is_admin: true, jti: crypto.randomUUID() }, cfg.jwtSecret, { expiresIn: '1d', algorithm: 'HS256' });
}
// Admin kullanıcı şekli (panel login + /me): kullanıcı satırı YOK, is_admin:true.
function masterPublicUser() {
  return { id: 'cbai', email: 'cbai', name: 'CBAI', nickname: 'cbai', phone: null, is_admin: true, customer_code: null, master: true };
}

// ---- Kullanici adi korumasi ----
// v563: Sabit rezerve liste KALDIRILDI — hicbir kullanici adi koddan rezerve degil.
// Engel yalniz adminin Kullanici Adlari bolumunde ekledigi block kurallariyla olur.
function normalizeNick(n){ return String(n||'').toLowerCase().replace(/[_.\s-]+/g,''); }
async function isReserved(nick){
  if (isCbaiNick(nick)) return true; // fix10e L3: 'cbai' rezerve
  const n = normalizeNick(nick);
  if(!n) return false;
  try{
    const { rows } = await pool.query('SELECT action FROM nickname_rules WHERE nickname = $1', [n]);
    if(rows.length && rows[0].action === 'allow') return false;
    if(rows.length && rows[0].action === 'block') return true;
  }catch(e){ /* tablo yoksa rezerve degil */ }
  return false;
}

// v557: alinmis/rezerve isim icin bos alternatif oner (orn. ihsanoglu -> ihsanoglu1)
async function nicknameSuggestions(base){
  const b = String(base || '').trim();
  if(!b) return [];
  const cands = [];
  const push = (x)=>{ if(x && x.length >= 2 && x.length <= 30 && /^[\p{L}\p{N}_.-]+$/u.test(x) && !cands.includes(x)) cands.push(x); };
  for(let i=1;i<=5;i++) push(b + i);
  push(b + '_1'); push(b + '-1');
  const y = new Date().getFullYear();
  push(b + y); push(b + '_' + y);
  const out = [];
  for(const c of cands){
    if(out.length >= 3) break;
    if(await isReserved(c)) continue;
    try{
      const { rows } = await pool.query('SELECT id FROM users WHERE LOWER(nickname) = LOWER($1)', [c]);
      if(!rows.length) out.push(c);
    }catch(e){ break; }
  }
  return out;
}

// POST /api/auth/register  { email, password, name, phone?, nickname?, admin_key? }
// admin_key: ADMIN_SETUP_KEY env doluysa ve eşleşiyorsa kullanıcı admin olur.
router.post(
  '/register',
  registerLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).custom((v) => passwordStrong(v)), // fix10e L4
  body('name').trim().isLength({ min: 2, max: 100 }),
  body('nickname').optional({ values: 'falsy' }).trim().isLength({ min: 2, max: 30 }).matches(/^[\p{L}\p{N}_.-]+$/u), // fix10ap: PATCH /me ile aynı kural; boş/yok = verilmemiş
  body('phone').optional().matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  body('admin_key').optional().isString().isLength({ max: 128 }),
  body('source').optional().isIn(['myfactory', 'shop']),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password, name, phone, admin_key } = req.body;
    const nickname = typeof req.body.nickname === 'string' ? req.body.nickname.trim() : '';
    const source = req.body.source === 'myfactory' ? 'myfactory' : 'shop';
    // fix10e H-D: admin_key kıyaslaması timing-safe (uzunluk erken dönüşü yok).
    const makeAdmin = Boolean(cfg.adminSetupKey && admin_key && timingSafeEqualDigest(admin_key, cfg.adminSetupKey));
    // fix10ap: kullanıcı adı verilmişse PATCH /me ile aynı sözleşme —
    // rezerve ad 400 nickname_reserved, dolu ad 409 conflict (büyük/küçük
    // harf duyarsız LOWER karşılaştırması). Verilmemişse nickname NULL.
    if (nickname && await isReserved(nickname)) return res.status(400).json({ error: 'nickname_reserved' });
    if (nickname) {
      const { rows: nickTaken } = await pool.query('SELECT id FROM users WHERE LOWER(nickname) = LOWER($1) LIMIT 1', [nickname]);
      if (nickTaken.length) return res.status(409).json({ error: 'conflict' });
    }
    const hash = await bcrypt.hash(password, 12);
    // fix10e M6: telefon benzersizliği (normalizasyonlu; kendi dışı kontrol).
    // Çakışma da jenerik 409 döner — hangi alanın çakıştığı söylenmez (L2).
    if (phone) {
      const taken = await pool.query(
        `SELECT id FROM users WHERE REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($1) LIMIT 1`,
        [phoneCandidates(phone)]
      );
      if (taken.rows.length) return res.status(409).json({ error: 'conflict' });
    }
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'shop'`);
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone, nickname, is_admin, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, name, nickname, phone, is_admin`,
        [email, hash, name, phone || null, nickname || null, makeAdmin, source]
      );
      const user = publicUser(rows[0]);
      res.status(201).json({ user, token: signToken(user) });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'conflict' }); // fix10e L2: jenerik (e-posta sayımı yok)
      throw err;
    }
  })
);

// POST /api/auth/phone-login  { phone, code } — demo: kod 123456 (gerçek SMS bağlanana kadar)
router.post(
  '/phone-login',
  loginLimiter,
  body('phone').matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  body('code').isLength({ min: 4, max: 10 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    let { phone, code } = req.body;
    phone = String(phone).replace(/[\s\-().]/g, '');
    if (!phone.startsWith('+')) phone = '+' + phone;
    // v600: Gercek SMS kodu dogrulama (demo kod KALDIRILDI — guvenlik acigiydi)
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
    const { rows: codes } = await pool.query(
      'SELECT * FROM phone_codes WHERE phone = $1 AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1',
      [phone]
    );
    const rec = codes[0];
    if (!rec) return res.status(401).json({ error: 'invalid_code' });
    if (rec.attempts >= 5) return res.status(401).json({ error: 'too_many_attempts' });
    const codeOk = await bcrypt.compare(String(code).trim(), rec.code_hash);
    if (!codeOk) {
      await pool.query('UPDATE phone_codes SET attempts = attempts + 1 WHERE id = $1', [rec.id]);
      return res.status(401).json({ error: 'invalid_code' });
    }
    await pool.query('UPDATE phone_codes SET consumed_at = now() WHERE id = $1', [rec.id]);
    let { rows } = await pool.query('SELECT id, email, name, nickname, phone, is_admin, customer_code FROM users WHERE phone=$1', [phone]);
    let user;
    if (rows.length) {
      user = publicUser(rows[0]);
    } else {
      const email = 'phone_' + phone.replace(/\D/g, '') + '@phone.chinabazaar.local';
      const hash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 12);
      const ins = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone) VALUES ($1,$2,$3,$4)
         RETURNING id, email, name, nickname, phone, is_admin`,
        [email, hash, phone, phone]
      );
      user = publicUser(ins.rows[0]);
    }
    res.json({ user, token: signToken(user) });
  })
);

// POST /api/auth/login  { identifier | email, password }
// identifier: e-posta, kullanıcı adı (nickname) veya telefon.
// GÜVENLİK: Tüm başarısızlıklar (kullanıcı yok / yanlış şifre / bozuk tanıtan /
// engelli hesap) AYNI 401 { error: 'invalid_credentials' } cevabını döner —
// kullanıcı sayımı (enumeration) yapılamaz. Katı hız limiti: IP başına ve
// tanıtan başına 15 dakikada en fazla 10 BAŞARISIZ deneme.
router.post(
  '/login',
  strictLoginLimiter,
  loginIdentifierLimiter,
  body('identifier').optional().isString().trim().isLength({ min: 1, max: 320 }),
  body('email').optional().isString().trim().isLength({ min: 1, max: 320 }),
  body('password').optional().isString().isLength({ min: 1, max: 256 }),
  asyncHandler(async (req, res) => {
    const GENERIC = { error: 'invalid_credentials' };
    const identifier = String(req.body.identifier ?? req.body.email ?? '').trim();
    const password = req.body.password;
    if (!validationResult(req).isEmpty() || !identifier || typeof password !== 'string' || !password) {
      return res.status(401).json(GENERIC);
    }
    // fix10d — CBAI master (rezerve): identifier "cbai" ise DB'ye bakılmaz.
    // fix10e L2: env ayarlı değilse de jenerik 401 (master_not_configured yok —
    // ayar durumu sayım bilgisi sızdırmaz).
    if (identifier.toLowerCase() === 'cbai') {
      if (!cbaiMasterConfigured() || !cbaiMasterPasswordOk(password)) {
        await bcrypt.compare(password, DUMMY_HASH);
        return res.status(401).json(GENERIC);
      }
      // 2026-10-20 N1: jti denetim kaydına yazılır (şüpheli girişin jetonu
      // POST /api/admin/master/revoke ile iptal edilebilir).
      const masterToken = signMasterToken();
      const masterJti = (jwt.decode(masterToken) || {}).jti || null;
      await logMasterAudit('master_login', 'auth', masterJti);
      return res.json({ user: masterPublicUser(), token: masterToken, master: true });
    }
    const candidates = phoneCandidates(identifier);
    const { rows } = await pool.query(
      `SELECT * FROM users
       WHERE LOWER(email) = LOWER($1)
          OR LOWER(nickname) = LOWER($1)
          OR REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($2)
       ORDER BY CASE WHEN LOWER(email) = LOWER($1) THEN 0 WHEN LOWER(nickname) = LOWER($1) THEN 1 ELSE 2 END
       LIMIT 1`,
      [identifier, candidates]
    );
    const row = rows[0];
    const ok = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);
    if (!row || !ok || row.is_blocked) {
      return res.status(401).json(GENERIC);
    }
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// POST /api/auth/admin-reset-password { email, admin_key, new_password } — kurulum anahtarıyla şifre sıfırla
// fix10e H-D: hız limiti + admin_key timing-safe kıyaslama + kullanıcı yoksa
// jenerik yanıt (404 sayım yok). fix10e L4: yeni şifre min 8 + harf+rakam.
router.post(
  '/admin-reset-password',
  adminResetLimiter,
  body('email').isEmail().normalizeEmail(),
  body('admin_key').notEmpty(),
  body('new_password').isLength({ min: 8 }).custom((v) => passwordStrong(v)),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, admin_key, new_password } = req.body;
    if (!cfg.adminSetupKey || !timingSafeEqualDigest(admin_key, cfg.adminSetupKey)) {
      return res.status(403).json({ error: 'invalid_setup_key' });
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const row = rows[0];
    if (!row) return res.json({ ok: true }); // fix10e L2: jenerik (kullanıcı yokluğu söylenmez)
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hash, email]);
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// POST /api/auth/send-code { email } — 6 haneli doğrulama kodu gönderir (10 dk geçerli)
// Kayıt ve giriş için ortak adım. E-posta sağlayıcı yoksa 503.
router.post(
  '/send-code',
  codeLimiter,
  body('email').isEmail().normalizeEmail(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    if (!mailer.isEnabled()) return res.status(503).json({ error: 'email_not_configured' });
    const { email } = req.body;
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Önceki tüketilmemiş kodları geçersiz kıl
      await client.query(
        `UPDATE email_codes SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL`,
        [email]
      );
      await client.query(
        `INSERT INTO email_codes (email, purpose, code_hash, expires_at) VALUES ($1, 'auth', $2, now() + interval '10 minutes')`,
        [email, codeHash]
      );
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    try {
      await mailer.sendVerificationCode(email, code);
    } catch (e) {
      console.error('[mailer] kod gönderilemedi:', e.message);
      return res.status(502).json({ error: 'email_send_failed' });
    }
    res.json({ sent: true });
  })
);

// POST /api/auth/verify-code { email, code, password, name? }
// Kod doğruysa: kullanıcı varsa şifreyi de doğrular → giriş; yoksa name+password ile kaydeder → giriş.
router.post(
  '/verify-code',
  codeLimiter,
  body('email').isEmail().normalizeEmail(),
  body('code').matches(/^[0-9]{6}$/),
  body('password').isLength({ min: 8 }).custom((v) => passwordStrong(v)), // fix10e L4
  body('name').optional().trim().isLength({ min: 2, max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, code, password, name } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM email_codes WHERE email = $1 AND consumed_at IS NULL AND expires_at > now()
       ORDER BY created_at DESC LIMIT 1`,
      [email]
    );
    const rec = rows[0];
    if (!rec) return res.status(400).json({ error: 'code_expired' });
    if (rec.attempts >= 5) return res.status(429).json({ error: 'too_many_attempts' });
    const ok = await bcrypt.compare(code, rec.code_hash);
    await pool.query('UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1', [rec.id]);
    if (!ok) return res.status(400).json({ error: 'code_invalid' });
    await pool.query('UPDATE email_codes SET consumed_at = now() WHERE id = $1', [rec.id]);

    const { rows: urows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (urows[0]) {
      const row = urows[0];
      if (!(await bcrypt.compare(password, row.password_hash))) {
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
      await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.id]);
      const user = publicUser(row);
      return res.json({ user, token: signToken(user) });
    }


// Yeni kayıt
    if (!name) return res.status(400).json({ error: 'name_required' });
    const hash = await bcrypt.hash(password, 12);
    try {
      const { rows: nrows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, email_verified) VALUES ($1, $2, $3, TRUE)
         RETURNING id, email, name, phone, is_admin`,
        [email, hash, name]
      );
      const user = publicUser(nrows[0]);
      res.status(201).json({ user, token: signToken(user) });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'conflict' }); // fix10e L2: jenerik
      throw err;
    }
  })
);

// fix10e: login-with-code rotasi canlida verify-code handler'inin ICINE gomuluydu —
// hicbir zaman kayitli degildi (POST 404 donuyordu). Ust duzeye tasindi; davranis aynen.
// POST /api/auth/login-with-code { email, code } — şifresiz e-posta koduyla giriş
router.post(
  '/login-with-code',
  codeLimiter,
  body('email').isEmail().normalizeEmail(),
  body('code').matches(/^[0-9]{6}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, code } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM email_codes WHERE email = $1 AND consumed_at IS NULL AND expires_at > now()
       ORDER BY created_at DESC LIMIT 1`,
      [email]
    );
    const rec = rows[0];
    if (!rec) return res.status(400).json({ error: 'code_expired' });
    if (rec.attempts >= 5) return res.status(429).json({ error: 'too_many_attempts' });
    const ok = await bcrypt.compare(code, rec.code_hash);
    await pool.query('UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1', [rec.id]);
    if (!ok) return res.status(400).json({ error: 'code_invalid' });
    await pool.query('UPDATE email_codes SET consumed_at = now() WHERE id = $1', [rec.id]);
    const { rows: urows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!urows[0]) return res.status(401).json({ error: 'invalid_credentials' }); // fix10e L2: jenerik (kullanıcı yokluğu söylenmez)
    const row = urows[0];
    if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.id]);
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// GET /api/auth/me — giriş yapan kullanıcının profili (is_admin dahil)
router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    // fix10d — CBAI master: token'da kullanıcı satırı (sub) yok; panel boot()
    // /me'yi is_admin ile kontrol ettiği için master jetonuna admin şekli döner.
    if (req.user && req.user.role === 'master' && req.user.is_admin) return res.json(masterPublicUser());
    // fix10e M4: fabrika jetonu kullanıcı profili değildir — 403 (çökme yok).
    if (!req.user || !req.user.id) return res.status(403).json({ error: 'forbidden' });
    const { rows } = await pool.query(
      'SELECT id, email, name, nickname, phone, is_admin, customer_code FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'user_not_found' });
    res.json(publicUser(rows[0]));
  })
);


// GET /api/auth/nickname-available?nickname=xxx — herkese acik uygunluk kontrolu
router.get(
  '/nickname-available',
  nicknameCheckLimiter,
  optionalAuth,
  asyncHandler(async (req, res) => {
    const nick = String(req.query.nickname || '').trim();
    // fix10e L2: yalnızca { available } — neden/öneri yok (kullanıcı sayımı
    // için kullanılabilecek ayrıntı sızdırılmaz; 'cbai' rezerve).
    if(!nick || nick.length < 2 || nick.length > 30 || !/^[\p{L}\p{N}_.-]+$/u.test(nick)){
      return res.json({ available: false });
    }
    if(await isReserved(nick)) return res.json({ available: false });
    const { rows } = await pool.query('SELECT id, nickname FROM users WHERE LOWER(nickname) = LOWER($1)', [nick]);
    if(!rows.length) return res.json({ available: true });
    // Kendi adiysa musait say (gecerli token varsa optionalAuth req.user doldurur)
    if(req.user && String(req.user.id) === String(rows[0].id)) return res.json({ available: true });
    return res.json({ available: false });
  })
);

// PATCH /api/auth/me — { nickname?, name? } (v554: isim de guncellenebilir; profil formu ismi backend'e yazar)
router.patch(
  '/me',
  requireAuth,
  body('nickname').optional().trim().isLength({ min: 2, max: 30 }).matches(/^[\p{L}\p{N}_.-]+$/u),
  body('name').optional().trim().isLength({ min: 2, max: 100 }),
  body('email').optional().isEmail().normalizeEmail(),
  body('phone').optional().matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    // fix10e M4: master/fabrika jetonuyla profil güncellenemez — 403 (çökme yok).
    if (!req.user || !req.user.id || req.user.role === 'factory' || req.user.role === 'master') {
      return res.status(403).json({ error: 'forbidden' });
    }
    const nick = (req.body.nickname || '').trim();
    const name = (req.body.name || '').trim();
    const email = (req.body.email || '').trim();
    const phone = (req.body.phone || '').trim();
    if (!nick && !name && !email && !phone) return res.status(400).json({ error: 'nothing_to_update' });
    if (nick && await isReserved(nick)) return res.status(400).json({ error: 'nickname_reserved' }); // L3: 'cbai' isReserved içinde
    // fix10ap: kullanıcı adı benzersizliği AÇIK kontrol (kendi dışı, büyük/
    // küçük harf duyarsız). Önceden kontrol yoktu — yalnız aşağıdaki UPDATE'in
    // DB 23505 yakalamasına dayanılıyordu; nickname üzerinde benzersiz indeks
    // tanımlı değilse mükerrer ad sessizce yazılabiliyordu.
    if (nick) {
      const { rows: exNick } = await pool.query('SELECT id FROM users WHERE LOWER(nickname) = LOWER($1) AND id <> $2 LIMIT 1', [nick, req.user.id]);
      if (exNick.length) return res.status(409).json({ error: 'conflict' });
    }
    // fix10e M6: e-posta/telefon benzersizliği (kendi dışı). Çakışma jenerik 409.
    if (email) {
      const { rows: ex } = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id <> $2 LIMIT 1', [email, req.user.id]);
      if (ex.length) return res.status(409).json({ error: 'conflict' });
    }
    if (phone) {
      const { rows: ex } = await pool.query(
        `SELECT id FROM users WHERE REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($1) AND id <> $2 LIMIT 1`,
        [phoneCandidates(phone), req.user.id]
      );
      if (ex.length) return res.status(409).json({ error: 'conflict' });
    }
    try {
      const sets = ['updated_at = now()'];
      const vals = [];
      let i = 1;
      if (nick) { sets.push('nickname = $' + (i++)); vals.push(nick); }
      if (name) { sets.push('name = $' + (i++)); vals.push(name); }
      if (email) { sets.push('email = $' + (i++)); vals.push(email); }
      if (phone) { sets.push('phone = $' + (i++)); vals.push(phone); }
      vals.push(req.user.id);
      const { rows } = await pool.query(
        'UPDATE users SET ' + sets.join(', ') + ' WHERE id = $' + i + ' RETURNING id, email, name, nickname, phone, is_admin',
        vals
      );
      if (!rows.length) return res.status(404).json({ error: 'user_not_found' });
      res.json(publicUser(rows[0]));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'conflict' }); // fix10e L2: jenerik
      throw err;
    }
  })
);


// ---- Telefon SMS kodu (v600) ----
// POST /api/auth/phone-send-code { phone } — 6 haneli kod uretir, SMS ile gonderir
router.post(
  '/phone-send-code',
  codeLimiter,
  body('phone').matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    let phone = String(req.body.phone || '').replace(/[\s\-().]/g, '');
    if (!phone.startsWith('+')) phone = '+' + phone;
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
    // fix10e M11: kayıt kontrolü — numara kayıtlı değilse SMS gönderilmez,
    // yanıt jenerik { ok: true } (kayıt sayımı yok).
    const { rows: ureg } = await pool.query(
      `SELECT id FROM users WHERE REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($1) LIMIT 1`,
      [phoneCandidates(phone)]
    );
    if (!ureg.length) return res.json({ ok: true });
    // fix10e M11: numara başına cooldown — 60 sn içinde tüketilmemiş kod
    // varsa yeniden gönderilmez (SMS bombardımanı yok), yanıt yine { ok: true }.
    const { rows: last } = await pool.query(
      `SELECT created_at FROM phone_codes WHERE phone = $1 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`,
      [phone]
    );
    if (last.length && (Date.now() - new Date(last[0].created_at).getTime()) < 60 * 1000) return res.json({ ok: true });
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);
    await pool.query('UPDATE phone_codes SET consumed_at = now() WHERE phone = $1 AND consumed_at IS NULL', [phone]);
    await pool.query('INSERT INTO phone_codes (phone, code_hash, expires_at) VALUES ($1, $2, now() + interval \'5 minutes\')', [phone, codeHash]);
    const sms = require('../services/sms');
    const sent = await sms.sendSms(phone, 'ChinaBazaar dogrulama kodunuz: ' + code + ' (5 dakika gecerli)');
    if (!sent.ok) return res.status(503).json({ error: 'sms_not_configured' });
    res.json({ ok: true });
  })
);

// POST /api/auth/forgot-password-sms { phone } — sifre sifirlama kodu SMS ile gonderir (v609)
router.post(
  '/forgot-password-sms',
  codeLimiter,
  body('phone').matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    let phone = String(req.body.phone || '').replace(/[\s\-().]/g, '');
    if (!phone.startsWith('+')) phone = '+' + phone;
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
    // fix10e SABAH-4 + M11: kayıtlı olmayan telefonda da jenerik { ok: true },
    // SMS gönderilmez. Kayıtlı numarada 60 sn cooldown (yeniden gönderim yok).
    const { rows } = await pool.query(
      `SELECT id FROM users WHERE REGEXP_REPLACE(COALESCE(phone, ''), '[\\s\\-().]', '', 'g') = ANY($1) LIMIT 1`,
      [phoneCandidates(phone)]
    );
    if (!rows.length) return res.json({ ok: true });
    const { rows: last } = await pool.query(
      `SELECT created_at FROM phone_codes WHERE phone = $1 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`,
      [phone]
    );
    if (last.length && (Date.now() - new Date(last[0].created_at).getTime()) < 60 * 1000) return res.json({ ok: true });
    const sms = require('../services/sms');
    const cfg = await sms.getSmsSettings();
    if (cfg.notify.forgot === false) return res.status(503).json({ error: 'sms_disabled' });
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);
    await pool.query('UPDATE phone_codes SET consumed_at = now() WHERE phone = $1 AND consumed_at IS NULL', [phone]);
    await pool.query('INSERT INTO phone_codes (phone, code_hash, expires_at) VALUES ($1, $2, now() + interval \'5 minutes\')', [phone, codeHash]);
    const sent = await sms.sendSms(phone, 'ChinaBazaar sifre sifirlama kodunuz: ' + code + ' (5 dakika gecerli)');
    if (!sent.ok) return res.status(503).json({ error: 'sms_not_configured' });
    res.json({ ok: true });
  })
);

// POST /api/auth/reset-password-sms { phone, code, new_password } — kodu dogrular, sifreyi degistirir (v609)
router.post(
  '/reset-password-sms',
  loginLimiter,
  body('phone').matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  body('code').isLength({ min: 4, max: 10 }),
  body('new_password').isString().isLength({ min: 8, max: 100 }).custom((v) => passwordStrong(v)), // fix10e L4
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    let { phone, code, new_password } = req.body;
    phone = String(phone).replace(/[\s\-().]/g, '');
    if (!phone.startsWith('+')) phone = '+' + phone;
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
    const { rows: codes } = await pool.query(
      'SELECT * FROM phone_codes WHERE phone = $1 AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1',
      [phone]
    );
    const rec = codes[0];
    if (!rec) return res.status(401).json({ error: 'invalid_code' });
    if (rec.attempts >= 5) return res.status(401).json({ error: 'too_many_attempts' });
    const codeOk = await bcrypt.compare(String(code).trim(), rec.code_hash);
    if (!codeOk) {
      await pool.query('UPDATE phone_codes SET attempts = attempts + 1 WHERE id = $1', [rec.id]);
      return res.status(401).json({ error: 'invalid_code' });
    }
    await pool.query('UPDATE phone_codes SET consumed_at = now() WHERE id = $1', [rec.id]);
    const hash = await bcrypt.hash(String(new_password), 12);
    const { rows } = await pool.query('UPDATE users SET password_hash = $2 WHERE phone = $1 RETURNING id', [phone, hash]);
    if (!rows.length) return res.json({ ok: true }); // fix10e L2: jenerik (kullanıcı yokluğu söylenmez)
    res.json({ ok: true });
  })
);

// ---- Sosyal giris (v600): Google / Facebook / Apple ----
// Kimlikler Railway Variables'dan: GOOGLE_CLIENT_ID, FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, APPLE_CLIENT_ID
router.get('/social/config', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    facebookAppId: process.env.FACEBOOK_APP_ID || null,
    appleClientId: process.env.APPLE_CLIENT_ID || null,
  });
});

async function verifyGoogleIdToken(idToken) {
  const cid = process.env.GOOGLE_CLIENT_ID;
  if (!cid || !idToken) return null;
  try {
    const r = await fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=' + encodeURIComponent(idToken));
    if (!r.ok) return null;
    const j = await r.json();
    if (j.aud !== cid) return null;
    if (j.email_verified !== 'true' && j.email_verified !== true) return null;
    if (Number(j.exp) * 1000 < Date.now()) return null;
    if (!j.email) return null;
    return { email: j.email, name: j.name || j.email };
  } catch (e) { return null; }
}

async function verifyFacebookToken(accessToken) {
  const appId = process.env.FACEBOOK_APP_ID;
  const secret = process.env.FACEBOOK_APP_SECRET;
  if (!appId || !secret || !accessToken) return null;
  try {
    const dbg = await fetch('https://graph.facebook.com/debug_token?input_token=' + encodeURIComponent(accessToken) + '&access_token=' + encodeURIComponent(appId + '|' + secret));
    const dj = await dbg.json().catch(() => null);
    if (!dj || !dj.data || !dj.data.is_valid || dj.data.app_id !== appId) return null;
    const me = await fetch('https://graph.facebook.com/me?fields=id,name,email&access_token=' + encodeURIComponent(accessToken));
    const mj = await me.json().catch(() => null);
    if (!mj || !mj.email) return null;
    return { email: mj.email, name: mj.name || mj.email };
  } catch (e) { return null; }
}

async function verifyAppleIdToken(idToken) {
  const clientId = process.env.APPLE_CLIENT_ID;
  if (!clientId || !idToken) return null;
  try {
    const parts = String(idToken).split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload.iss !== 'https://appleid.apple.com') return null;
    if (payload.aud !== clientId) return null;
    if (Number(payload.exp) * 1000 < Date.now()) return null;
    if (!payload.email) return null;
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const keys = await fetch('https://appleid.apple.com/auth/keys').then((r) => r.json());
    const key = (keys.keys || []).find((k) => k.kid === header.kid);
    if (!key) return null;
    const pub = crypto.createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' });
    const ok = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), pub, Buffer.from(parts[2], 'base64url'));
    if (!ok) return null;
    return { email: payload.email, name: payload.email };
  } catch (e) { return null; }
}

async function findOrCreateSocialUser(email, name) {
  const lower = String(email).toLowerCase();
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [lower]);
  if (rows.length) {
    if (rows[0].is_blocked) return { blocked: true };
    return { user: publicUser(rows[0]) };
  }
  const hash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 12);
  const ins = await pool.query(
    'INSERT INTO users (email, password_hash, name, email_verified) VALUES ($1, $2, $3, TRUE) RETURNING id, email, name, nickname, phone, is_admin, customer_code',
    [lower, hash, String(name || lower).slice(0, 200)]
  );
  return { user: publicUser(ins.rows[0]) };
}

// POST /api/auth/social/:provider { idToken | accessToken }
router.post(
  '/social/:provider',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const provider = req.params.provider;
    let profile = null;
    if (provider === 'google') profile = await verifyGoogleIdToken(req.body.idToken);
    else if (provider === 'facebook') profile = await verifyFacebookToken(req.body.accessToken);
    else if (provider === 'apple') profile = await verifyAppleIdToken(req.body.idToken);
    else return res.status(400).json({ error: 'unknown_provider' });
    if (!profile || !profile.email) return res.status(401).json({ error: 'social_verify_failed' });
    const r = await findOrCreateSocialUser(profile.email, profile.name);
    if (r.blocked) return res.status(403).json({ error: 'user_blocked' });
    res.json({ user: r.user, token: signToken(r.user) });
  })
);

// ---------------------------------------------------------------------
// GÖMÜLÜ QR KODLAYICI — qrcode-generator v1.4.4 (Kazuhiko Arase), MIT.
// Kaynak: https://github.com/kazuhikoarase/qrcode-generator — qrcode.js
// aynen gömülmüştür; lisans metni kitaplığın kendi başlığındadır.
// Harici ağ/kitaplık KULLANILMAZ; QR sunucuda, yerel kodla üretilir.
// Kapsam notu: kitaplık UMD kuyruğunda module.exports'a yazar; aşağıdaki
// gölgeli module/exports sayesinde bu yalnız bu bloğun yerel nesnesine
// gider — auth.js'in kendi module.exports'ı (router) ETKİLENMEZ.
// ---------------------------------------------------------------------
const qrcodeGen = (function () {
  var module = { exports: {} };
  var exports = module.exports;
//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------

var qrcode = function() {

  //---------------------------------------------------------------------
  // qrcode
  //---------------------------------------------------------------------

  /**
   * qrcode
   * @param typeNumber 1 to 40
   * @param errorCorrectionLevel 'L','M','Q','H'
   */
  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    _this.addData = function(data, mode) {

      mode = mode || 'Byte';

      var newData = null;

      switch(mode) {
      case 'Numeric' :
        newData = qrNumber(data);
        break;
      case 'Alphanumeric' :
        newData = qrAlphaNum(data);
        break;
      case 'Byte' :
        newData = qr8BitByte(data);
        break;
      case 'Kanji' :
        newData = qrKanji(data);
        break;
      default :
        throw 'mode:' + mode;
      }

      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    _this.createTableTag = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var qrHtml = '';

      qrHtml += '<table style="';
      qrHtml += ' border-width: 0px; border-style: none;';
      qrHtml += ' border-collapse: collapse;';
      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';
      qrHtml += '">';
      qrHtml += '<tbody>';

      for (var r = 0; r < _this.getModuleCount(); r += 1) {

        qrHtml += '<tr>';

        for (var c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += ' border-width: 0px; border-style: none;';
          qrHtml += ' border-collapse: collapse;';
          qrHtml += ' padding: 0px; margin: 0px;';
          qrHtml += ' width: ' + cellSize + 'px;';
          qrHtml += ' height: ' + cellSize + 'px;';
          qrHtml += ' background-color: ';
          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';
          qrHtml += ';';
          qrHtml += '"/>';
        }

        qrHtml += '</tr>';
      }

      qrHtml += '</tbody>';
      qrHtml += '</table>';

      return qrHtml;
    };

    _this.createSvgTag = function(cellSize, margin, alt, title) {

      var opts = {};
      if (typeof arguments[0] == 'object') {
        // Called by options.
        opts = arguments[0];
        // overwrite cellSize and margin.
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      // Compose alt property surrogate
      alt = (typeof alt === 'string') ? {text: alt} : alt || {};
      alt.text = alt.text || null;
      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;

      // Compose title property surrogate
      title = (typeof title === 'string') ? {text: title} : title || {};
      title.text = title.text || null;
      title.id = (title.text) ? title.id || 'qrcode-title' : null;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var c, mc, r, mr, qrSvg='', rect;

      rect = 'l' + cellSize + ',0 0,' + cellSize +
        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';

      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : '';
      qrSvg += ' viewBox="0 0 ' + size + ' ' + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += (title.text || alt.text) ? ' role="img" aria-labelledby="' +
          escapeXml([title.id, alt.id].join(' ').trim() ) + '"' : '';
      qrSvg += '>';
      qrSvg += (title.text) ? '<title id="' + escapeXml(title.id) + '">' +
          escapeXml(title.text) + '</title>' : '';
      qrSvg += (alt.text) ? '<description id="' + escapeXml(alt.id) + '">' +
          escapeXml(alt.text) + '</description>' : '';
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';

      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c) ) {
            mc = c*cellSize+margin;
            qrSvg += 'M' + mc + ',' + mr + rect;
          }
        }
      }

      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += '</svg>';

      return qrSvg;
    };

    _this.createDataURL = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          var c = Math.floor( (x - min) / cellSize);
          var r = Math.floor( (y - min) / cellSize);
          return _this.isDark(r, c)? 0 : 1;
        } else {
          return 1;
        }
      } );
    };

    _this.createImgTag = function(cellSize, margin, alt) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;

      var img = '';
      img += '<img';
      img += '\u0020src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += '\u0020width="';
      img += size;
      img += '"';
      img += '\u0020height="';
      img += size;
      img += '"';
      if (alt) {
        img += '\u0020alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += '/>';

      return img;
    };

    var escapeXml = function(s) {
      var escaped = '';
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charAt(i);
        switch(c) {
        case '<': escaped += '&lt;'; break;
        case '>': escaped += '&gt;'; break;
        case '&': escaped += '&amp;'; break;
        case '"': escaped += '&quot;'; break;
        default : escaped += c; break;
        }
      }
      return escaped;
    };

    var _createHalfASCII = function(margin) {
      var cellSize = 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r1, r2, p;

      var blocks = {
        '██': '█',
        '█ ': '▀',
        ' █': '▄',
        '  ': ' '
      };

      var blocksLastLineNoMargin = {
        '██': '▀',
        '█ ': '▀',
        ' █': ' ',
        '  ': ' '
      };

      var ascii = '';
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = '█';

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = ' ';
          }

          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += ' ';
          }
          else {
            p += '█';
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];
        }

        ascii += '\n';
      }

      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;

      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }

      cellSize -= 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r, p;

      var white = Array(cellSize+1).join('██');
      var black = Array(cellSize+1).join('  ');

      var ascii = '';
      var line = '';
      for (y = 0; y < size; y += 1) {
        r = Math.floor( (y - min) / cellSize);
        line = '';
        for (x = 0; x < size; x += 1) {
          p = 1;

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          line += p ? white : black;
        }

        for (r = 0; r < cellSize; r += 1) {
          ascii += line + '\n';
        }
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      var length = _this.getModuleCount();
      for (var row = 0; row < length; row++) {
        for (var col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';
          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);
        }
      }
    }

    return _this;
  };

  //---------------------------------------------------------------------
  // qrcode.stringToBytes
  //---------------------------------------------------------------------

  qrcode.stringToBytesFuncs = {
    'default' : function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        bytes.push(c & 0xff);
      }
      return bytes;
    }
  };

  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];

  //---------------------------------------------------------------------
  // qrcode.createStringToBytes
  //---------------------------------------------------------------------

  /**
   * @param unicodeData base64 string of byte array.
   * [16bit Unicode],[16bit Bytes], ...
   * @param numChars
   */
  qrcode.createStringToBytes = function(unicodeData, numChars) {

    // create conversion map.

    var unicodeMap = function() {

      var bin = base64DecodeInputStream(unicodeData);
      var read = function() {
        var b = bin.read();
        if (b == -1) throw 'eof';
        return b;
      };

      var count = 0;
      var unicodeMap = {};
      while (true) {
        var b0 = bin.read();
        if (b0 == -1) break;
        var b1 = read();
        var b2 = read();
        var b3 = read();
        var k = String.fromCharCode( (b0 << 8) | b1);
        var v = (b2 << 8) | b3;
        unicodeMap[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + ' != ' + numChars;
      }

      return unicodeMap;
    }();

    var unknownChar = '?'.charCodeAt(0);

    return function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          var b = unicodeMap[s.charAt(i)];
          if (typeof b == 'number') {
            if ( (b & 0xff) == b) {
              // 1byte
              bytes.push(b);
            } else {
              // 2bytes
              bytes.push(b >>> 8);
              bytes.push(b & 0xff);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };

  //---------------------------------------------------------------------
  // QRMode
  //---------------------------------------------------------------------

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  //---------------------------------------------------------------------
  // QRErrorCorrectionLevel
  //---------------------------------------------------------------------

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  //---------------------------------------------------------------------
  // QRMaskPattern
  //---------------------------------------------------------------------

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  //---------------------------------------------------------------------
  // QRUtil
  //---------------------------------------------------------------------

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        // 1 - 9

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        // 10 - 26

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        // 27 - 40

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // QRMath
  //---------------------------------------------------------------------

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrPolynomial
  //---------------------------------------------------------------------

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // QRRSBlock
  //---------------------------------------------------------------------

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrBitBuffer
  //---------------------------------------------------------------------

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrNumber
  //---------------------------------------------------------------------

  var qrNumber = function(data) {

    var _mode = QRMode.MODE_NUMBER;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var data = _data;

      var i = 0;

      while (i + 2 < data.length) {
        buffer.put(strToNum(data.substring(i, i + 3) ), 10);
        i += 3;
      }

      if (i < data.length) {
        if (data.length - i == 1) {
          buffer.put(strToNum(data.substring(i, i + 1) ), 4);
        } else if (data.length - i == 2) {
          buffer.put(strToNum(data.substring(i, i + 2) ), 7);
        }
      }
    };

    var strToNum = function(s) {
      var num = 0;
      for (var i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i) );
      }
      return num;
    };

    var chatToNum = function(c) {
      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      }
      throw 'illegal char :' + c;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrAlphaNum
  //---------------------------------------------------------------------

  var qrAlphaNum = function(data) {

    var _mode = QRMode.MODE_ALPHA_NUM;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var s = _data;

      var i = 0;

      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i) ) * 45 +
          getCode(s.charAt(i + 1) ), 11);
        i += 2;
      }

      if (i < s.length) {
        buffer.put(getCode(s.charAt(i) ), 6);
      }
    };

    var getCode = function(c) {

      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      } else if ('A' <= c && c <= 'Z') {
        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
      } else {
        switch (c) {
        case ' ' : return 36;
        case '$' : return 37;
        case '%' : return 38;
        case '*' : return 39;
        case '+' : return 40;
        case '-' : return 41;
        case '.' : return 42;
        case '/' : return 43;
        case ':' : return 44;
        default :
          throw 'illegal char :' + c;
        }
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qr8BitByte
  //---------------------------------------------------------------------

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _data = data;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrKanji
  //---------------------------------------------------------------------

  var qrKanji = function(data) {

    var _mode = QRMode.MODE_KANJI;
    var _data = data;

    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];
    if (!stringToBytes) {
      throw 'sjis not supported.';
    }
    !function(c, code) {
      // self test for sjis support.
      var test = stringToBytes(c);
      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {
        throw 'sjis not supported.';
      }
    }('\u53cb', 0x9746);

    var _bytes = stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };

    _this.write = function(buffer) {

      var data = _bytes;

      var i = 0;

      while (i + 1 < data.length) {

        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);

        if (0x8140 <= c && c <= 0x9FFC) {
          c -= 0x8140;
        } else if (0xE040 <= c && c <= 0xEBBF) {
          c -= 0xC140;
        } else {
          throw 'illegal char at ' + (i + 1) + '/' + c;
        }

        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);

        buffer.put(c, 13);

        i += 2;
      }

      if (i < data.length) {
        throw 'illegal char at ' + (i + 1);
      }
    };

    return _this;
  };

  //=====================================================================
  // GIF Support etc.
  //

  //---------------------------------------------------------------------
  // byteArrayOutputStream
  //---------------------------------------------------------------------

  var byteArrayOutputStream = function() {

    var _bytes = [];

    var _this = {};

    _this.writeByte = function(b) {
      _bytes.push(b & 0xff);
    };

    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };

    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (var i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };

    _this.writeString = function(s) {
      for (var i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i) );
      }
    };

    _this.toByteArray = function() {
      return _bytes;
    };

    _this.toString = function() {
      var s = '';
      s += '[';
      for (var i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ',';
        }
        s += _bytes[i];
      }
      s += ']';
      return s;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64EncodeOutputStream
  //---------------------------------------------------------------------

  var base64EncodeOutputStream = function() {

    var _buffer = 0;
    var _buflen = 0;
    var _length = 0;
    var _base64 = '';

    var _this = {};

    var writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 0x3f) );
    };

    var encode = function(n) {
      if (n < 0) {
        // error.
      } else if (n < 26) {
        return 0x41 + n;
      } else if (n < 52) {
        return 0x61 + (n - 26);
      } else if (n < 62) {
        return 0x30 + (n - 52);
      } else if (n == 62) {
        return 0x2b;
      } else if (n == 63) {
        return 0x2f;
      }
      throw 'n:' + n;
    };

    _this.writeByte = function(n) {

      _buffer = (_buffer << 8) | (n & 0xff);
      _buflen += 8;
      _length += 1;

      while (_buflen >= 6) {
        writeEncoded(_buffer >>> (_buflen - 6) );
        _buflen -= 6;
      }
    };

    _this.flush = function() {

      if (_buflen > 0) {
        writeEncoded(_buffer << (6 - _buflen) );
        _buffer = 0;
        _buflen = 0;
      }

      if (_length % 3 != 0) {
        // padding
        var padlen = 3 - _length % 3;
        for (var i = 0; i < padlen; i += 1) {
          _base64 += '=';
        }
      }
    };

    _this.toString = function() {
      return _base64;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64DecodeInputStream
  //---------------------------------------------------------------------

  var base64DecodeInputStream = function(str) {

    var _str = str;
    var _pos = 0;
    var _buffer = 0;
    var _buflen = 0;

    var _this = {};

    _this.read = function() {

      while (_buflen < 8) {

        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw 'unexpected end of file./' + _buflen;
        }

        var c = _str.charAt(_pos);
        _pos += 1;

        if (c == '=') {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/) ) {
          // ignore if whitespace.
          continue;
        }

        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );
        _buflen += 6;
      }

      var n = (_buffer >>> (_buflen - 8) ) & 0xff;
      _buflen -= 8;
      return n;
    };

    var decode = function(c) {
      if (0x41 <= c && c <= 0x5a) {
        return c - 0x41;
      } else if (0x61 <= c && c <= 0x7a) {
        return c - 0x61 + 26;
      } else if (0x30 <= c && c <= 0x39) {
        return c - 0x30 + 52;
      } else if (c == 0x2b) {
        return 62;
      } else if (c == 0x2f) {
        return 63;
      } else {
        throw 'c:' + c;
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // gifImage (B/W)
  //---------------------------------------------------------------------

  var gifImage = function(width, height) {

    var _width = width;
    var _height = height;
    var _data = new Array(width * height);

    var _this = {};

    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };

    _this.write = function(out) {

      //---------------------------------
      // GIF Signature

      out.writeString('GIF87a');

      //---------------------------------
      // Screen Descriptor

      out.writeShort(_width);
      out.writeShort(_height);

      out.writeByte(0x80); // 2bit
      out.writeByte(0);
      out.writeByte(0);

      //---------------------------------
      // Global Color Map

      // black
      out.writeByte(0x00);
      out.writeByte(0x00);
      out.writeByte(0x00);

      // white
      out.writeByte(0xff);
      out.writeByte(0xff);
      out.writeByte(0xff);

      //---------------------------------
      // Image Descriptor

      out.writeString(',');
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);

      //---------------------------------
      // Local Color Map

      //---------------------------------
      // Raster Data

      var lzwMinCodeSize = 2;
      var raster = getLZWRaster(lzwMinCodeSize);

      out.writeByte(lzwMinCodeSize);

      var offset = 0;

      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }

      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0x00);

      //---------------------------------
      // GIF Terminator
      out.writeString(';');
    };

    var bitOutputStream = function(out) {

      var _out = out;
      var _bitLength = 0;
      var _bitBuffer = 0;

      var _this = {};

      _this.write = function(data, length) {

        if ( (data >>> length) != 0) {
          throw 'length over';
        }

        while (_bitLength + length >= 8) {
          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );
          length -= (8 - _bitLength);
          data >>>= (8 - _bitLength);
          _bitBuffer = 0;
          _bitLength = 0;
        }

        _bitBuffer = (data << _bitLength) | _bitBuffer;
        _bitLength = _bitLength + length;
      };

      _this.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };

      return _this;
    };

    var getLZWRaster = function(lzwMinCodeSize) {

      var clearCode = 1 << lzwMinCodeSize;
      var endCode = (1 << lzwMinCodeSize) + 1;
      var bitLength = lzwMinCodeSize + 1;

      // Setup LZWTable
      var table = lzwTable();

      for (var i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i) );
      }
      table.add(String.fromCharCode(clearCode) );
      table.add(String.fromCharCode(endCode) );

      var byteOut = byteArrayOutputStream();
      var bitOut = bitOutputStream(byteOut);

      // clear code
      bitOut.write(clearCode, bitLength);

      var dataIndex = 0;

      var s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;

      while (dataIndex < _data.length) {

        var c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;

        if (table.contains(s + c) ) {

          s = s + c;

        } else {

          bitOut.write(table.indexOf(s), bitLength);

          if (table.size() < 0xfff) {

            if (table.size() == (1 << bitLength) ) {
              bitLength += 1;
            }

            table.add(s + c);
          }

          s = c;
        }
      }

      bitOut.write(table.indexOf(s), bitLength);

      // end code
      bitOut.write(endCode, bitLength);

      bitOut.flush();

      return byteOut.toByteArray();
    };

    var lzwTable = function() {

      var _map = {};
      var _size = 0;

      var _this = {};

      _this.add = function(key) {
        if (_this.contains(key) ) {
          throw 'dup key:' + key;
        }
        _map[key] = _size;
        _size += 1;
      };

      _this.size = function() {
        return _size;
      };

      _this.indexOf = function(key) {
        return _map[key];
      };

      _this.contains = function(key) {
        return typeof _map[key] != 'undefined';
      };

      return _this;
    };

    return _this;
  };

  var createDataURL = function(width, height, getPixel) {
    var gif = gifImage(width, height);
    for (var y = 0; y < height; y += 1) {
      for (var x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y) );
      }
    }

    var b = byteArrayOutputStream();
    gif.write(b);

    var base64 = base64EncodeOutputStream();
    var bytes = b.toByteArray();
    for (var i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();

    return 'data:image/gif;base64,' + base64;
  };

  //---------------------------------------------------------------------
  // returns qrcode function.

  return qrcode;
}();

// multibyte support
!function() {

  qrcode.stringToBytesFuncs['UTF-8'] = function(s) {
    // http://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array
    function toUTF8Array(str) {
      var utf8 = [];
      for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
          utf8.push(0xc0 | (charcode >> 6),
              0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
          utf8.push(0xe0 | (charcode >> 12),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
          i++;
          // UTF-16 encodes 0x10000-0x10FFFF by
          // subtracting 0x10000 and splitting the
          // 20 bits of 0x0-0xFFFFF into two halves
          charcode = 0x10000 + (((charcode & 0x3ff)<<10)
            | (str.charCodeAt(i) & 0x3ff));
          utf8.push(0xf0 | (charcode >>18),
              0x80 | ((charcode>>12) & 0x3f),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
      }
      return utf8;
    }
    return toUTF8Array(s);
  };

}();

(function (factory) {
  if (typeof define === 'function' && define.amd) {
      define([], factory);
  } else if (typeof exports === 'object') {
      module.exports = factory();
  }
}(function () {
    return qrcode;
}));
  return module.exports;
})();

// QR metni -> SVG (hata düzeltme M; sürüm, sığan en küçük sürümden seçilir).
function qrSvgEncode(text) {
  let qr = null;
  for (let v = 1; v <= 12; v++) {
    try {
      const q = qrcodeGen(v, 'M');
      q.addData(text);
      q.make();
      qr = q;
      break;
    } catch (e) {
      if (!/overflow|length/i.test(String((e && e.message) || e))) throw e;
    }
  }
  if (!qr) throw new Error('qr_encode_failed');
  const count = qr.getModuleCount();
  const margin = 4;
  const total = count + margin * 2;
  let d = '';
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) d += 'M' + (c + margin) + ' ' + (r + margin) + 'h1v1h-1z';
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + total + ' ' + total + '" shape-rendering="crispEdges"><rect width="' + total + '" height="' + total + '" fill="#ffffff"/><path fill="#000000" d="' + d + '"/></svg>';
}

// ---- QR ile giriş (fix10am) ----
// Akış: misafir cihaz POST /qr/create ile oturum açar (128-bit session_id +
// 128-bit secret; DB'de yalnız secret'in SHA-256 özeti durur), QR'ı gösterir.
// Telefonda giriş yapmış kullanıcı QR'daki adresi
// (https://chinabazaar.shop/qr-onay#<session_id>) açıp onaylar:
// POST /qr/approve (requireAuth) kaydı o kullanıcıyla 'approved' yapar.
// Misafir cihaz GET /qr/status?session_id&secret ile yoklar; approved ise
// NORMAL giriş yanıtını ({ user, token }; master ise master düzeni) alır
// ve kayıt TEK KULLANIMLIK olarak silinir. Süre: 2 dakika.
const QR_LOGIN_TTL_MS = 120 * 1000;
const qrCreateLimiter = require('express-rate-limit')({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' }, keyGenerator: (req) => 'qrcreate:' + ipKeyGenerator(req.ip) });
const qrStatusLimiter = require('express-rate-limit')({ windowMs: 60 * 1000, max: 90, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' }, keyGenerator: (req) => 'qrstatus:' + ipKeyGenerator(req.ip) + ':' + String((req.query && req.query.session_id) || '') });
const qrApproveLimiter = require('express-rate-limit')({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' }, keyGenerator: (req) => 'qrapprove:' + ipKeyGenerator(req.ip) }); // 2026-10-21 F4: qr/approve savunma-derinligi limiti

async function ensureQrLogins() {
  await pool.query(`CREATE TABLE IF NOT EXISTS qr_logins (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    user_id TEXT,
    is_master BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
  )`);
  // fix10ao göçü: canlı tablo fix10am ile user_id INT olarak oluşmuş olabilir.
  // users.id UUID (TEXT) olduğundan INT sütun onayı 500'e düşürüyordu. Tip
  // hâlâ 'integer' ise TEXT'e çevir; değilse dokunma (idempotent). Göç hatası
  // akışı bozmasın ama logda görünsün.
  try {
    const { rows } = await pool.query(
      `SELECT data_type FROM information_schema.columns WHERE table_name = 'qr_logins' AND column_name = 'user_id'`
    );
    if (rows[0] && rows[0].data_type === 'integer') {
      await pool.query(`ALTER TABLE qr_logins ALTER COLUMN user_id TYPE TEXT USING user_id::TEXT`);
    }
  } catch (e) {
    console.error('[qr] user_id TEXT gocu basarisiz:', e && e.message ? e.message : e);
  }
}
function qrSecretHash(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest('hex');
}

// POST /api/auth/qr/create — misafir cihaz QR oturumu açar (giriş gerekmez).
router.post(
  '/qr/create',
  qrCreateLimiter,
  asyncHandler(async (req, res) => {
    await ensureQrLogins();
    // Süresi geçmiş kayıtları fırsat bulmuşken temizle.
    await pool.query('DELETE FROM qr_logins WHERE expires_at <= now()');
    const sessionId = crypto.randomBytes(16).toString('hex'); // 128-bit
    const secret = crypto.randomBytes(16).toString('hex'); // 128-bit
    await pool.query(
      `INSERT INTO qr_logins (id, secret_hash, status, expires_at) VALUES ($1, $2, 'pending', $3)`,
      [sessionId, qrSecretHash(secret), new Date(Date.now() + QR_LOGIN_TTL_MS)]
    );
    const qrSvg = qrSvgEncode('https://chinabazaar.shop/qr-onay#' + sessionId);
    // secret yalnız bu yanıtta (ve status yoklamasında) taşınır; DB'de hash'i durur.
    res.json({ session_id: sessionId, secret, qr_svg: qrSvg, expires_in: 120 });
  })
);

// POST /api/auth/qr/approve { session_id } — giriş yapmış kullanıcı onaylar.
// Aynı oturum ikinci kez onaylanamaz; fabrika jetonu onaylayamaz (M4 deseni).
router.post(
  '/qr/approve',
  requireAuth,
  qrApproveLimiter,
  body('session_id').isString().trim().isLength({ min: 1, max: 64 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    let userId = null;
    let isMaster = false;
    if (req.user && req.user.role === 'master' && req.user.is_admin) {
      isMaster = true;
    } else if (req.user && req.user.id) {
      userId = req.user.id;
    } else {
      return res.status(403).json({ error: 'forbidden' });
    }
    await ensureQrLogins();
    const sessionId = String(req.body.session_id || '');
    const { rows } = await pool.query('SELECT id, status, expires_at FROM qr_logins WHERE id = $1', [sessionId]);
    const rec = rows[0];
    if (!rec) return res.status(404).json({ error: 'qr_session_not_found' });
    if (rec.status !== 'pending' || new Date(rec.expires_at).getTime() <= Date.now()) {
      return res.status(409).json({ error: 'qr_already_used' });
    }
    const upd = await pool.query(
      `UPDATE qr_logins SET status = 'approved', user_id = $2, is_master = $3 WHERE id = $1 AND status = 'pending'`,
      [sessionId, userId, isMaster]
    );
    if (!upd.rowCount) return res.status(409).json({ error: 'qr_already_used' });
    res.json({ ok: true });
  })
);

// GET /api/auth/qr/status?session_id=..&secret=.. — misafir cihaz yoklar.
// secret eşleşmezse pending bile dönülmez ('expired' gibi davranılır).
router.get(
  '/qr/status',
  qrStatusLimiter,
  asyncHandler(async (req, res) => {
    const EXPIRED = { status: 'expired' };
    const sessionId = String(req.query.session_id || '');
    const secret = String(req.query.secret || '');
    if (!/^[0-9a-f]{32}$/.test(sessionId) || !secret) return res.json(EXPIRED);
    await ensureQrLogins();
    const { rows } = await pool.query('SELECT * FROM qr_logins WHERE id = $1', [sessionId]);
    const rec = rows[0];
    if (!rec) return res.json(EXPIRED);
    if (!timingSafeEqualDigest(qrSecretHash(secret), String(rec.secret_hash || ''))) return res.json(EXPIRED);
    if (new Date(rec.expires_at).getTime() <= Date.now()) {
      await pool.query('DELETE FROM qr_logins WHERE id = $1', [sessionId]);
      return res.json(EXPIRED);
    }
    if (rec.status !== 'approved') return res.json({ status: 'pending' });
    // Tek kullanim (2026-10-21 F2, atomik): SELECT+DELETE yarisi engellenir.
    // Onayli kayit tek sorguda silinir; yarisi kaybeden taraf 'expired' alir.
    const del = await pool.query(
      `DELETE FROM qr_logins WHERE id = $1 AND status = 'approved' RETURNING is_master, user_id`,
      [sessionId]
    );
    if (!del.rowCount) return res.json(EXPIRED);
    const appr = del.rows[0];
    if (appr.is_master) {
      const masterToken = signMasterToken();
      const masterJti = (jwt.decode(masterToken) || {}).jti || null;
      await logMasterAudit('master_qr_login', 'auth', masterJti);
      return res.json({ user: masterPublicUser(), token: masterToken, master: true });
    }
    const { rows: urows } = await pool.query(
      'SELECT id, email, name, nickname, phone, is_admin, customer_code, is_blocked FROM users WHERE id = $1',
      [appr.user_id]
    );
    const row = urows[0];
    if (!row || row.is_blocked) return res.json(EXPIRED);
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);


module.exports = router;

