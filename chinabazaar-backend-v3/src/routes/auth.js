// Kimlik doğrulama: kayıt + giriş (JWT)
const express = require('express');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const codeLimiter = require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' } });
const nicknameCheckLimiter = require('express-rate-limit')({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' } });
const { signToken, requireAuth, optionalAuth } = require('../middleware/auth');
const cfg = require('../config');
const pool = require('../db');
const mailer = require('../services/mailer');
const crypto = require('crypto');

const router = express.Router();

function publicUser(row) {
  return { id: row.id, email: row.email, name: row.name, nickname: row.nickname || null, phone: row.phone, is_admin: !!row.is_admin, customer_code: row.customer_code || null };
}

// ---- Kullanici adi korumasi ----
// v563: Sabit rezerve liste KALDIRILDI — hicbir kullanici adi koddan rezerve degil.
// Engel yalniz adminin Kullanici Adlari bolumunde ekledigi block kurallariyla olur.
function normalizeNick(n){ return String(n||'').toLowerCase().replace(/[_.\s-]+/g,''); }
async function isReserved(nick){
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

// POST /api/auth/register  { email, password, name, phone?, admin_key? }
// admin_key: ADMIN_SETUP_KEY env doluysa ve eşleşiyorsa kullanıcı admin olur.
router.post(
  '/register',
  registerLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('name').trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().matches(/^\+?[0-9][0-9\s\-().]{6,19}$/),
  body('admin_key').optional().isString().isLength({ max: 128 }),
  body('source').optional().isIn(['myfactory', 'shop']),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password, name, phone, admin_key } = req.body;
    const source = req.body.source === 'myfactory' ? 'myfactory' : 'shop';
    const makeAdmin = Boolean(cfg.adminSetupKey && admin_key && admin_key === cfg.adminSetupKey);
    const hash = await bcrypt.hash(password, 12);
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'shop'`);
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone, is_admin, source)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, name, phone, is_admin`,
        [email, hash, name, phone || null, makeAdmin, source]
      );
      const user = publicUser(rows[0]);
      res.status(201).json({ user, token: signToken(user) });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'email_in_use' });
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

// POST /api/auth/login  { email, password }
router.post(
  '/login',
  loginLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const row = rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

// POST /api/auth/admin-reset-password { email, admin_key, new_password } — kurulum anahtarıyla şifre sıfırla
router.post(
  '/admin-reset-password',
  body('email').isEmail().normalizeEmail(),
  body('admin_key').notEmpty(),
  body('new_password').isLength({ min: 6 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, admin_key, new_password } = req.body;
    if (!cfg.adminSetupKey || admin_key !== cfg.adminSetupKey) {
      return res.status(403).json({ error: 'invalid_setup_key' });
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'user_not_found' });
    const hash = await bcrypt.hash(new_password, 10);
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
  body('password').isLength({ min: 8 }),
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
    if (!urows[0]) return res.status(404).json({ error: 'user_not_found' });
    const row = urows[0];
    if (row.is_blocked) return res.status(403).json({ error: 'user_blocked' });
    await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.id]);
    const user = publicUser(row);
    res.json({ user, token: signToken(user) });
  })
);

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
      if (err.code === '23505') return res.status(409).json({ error: 'email_in_use' });
      throw err;
    }
  })
);

// GET /api/auth/me — giriş yapan kullanıcının profili (is_admin dahil)
router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
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
    if(!nick || nick.length < 2 || nick.length > 30 || !/^[\p{L}\p{N}_.-]+$/u.test(nick)){
      return res.json({ available: false, reason: 'invalid' });
    }
    if(await isReserved(nick)) return res.json({ available: false, reason: 'reserved', suggestions: await nicknameSuggestions(nick) });
    const { rows } = await pool.query('SELECT id, nickname FROM users WHERE LOWER(nickname) = LOWER($1)', [nick]);
    if(!rows.length) return res.json({ available: true });
    // Kendi adiysa musait say (gecerli token varsa optionalAuth req.user doldurur)
    if(req.user && String(req.user.id) === String(rows[0].id)) return res.json({ available: true, mine: true });
    return res.json({ available: false, reason: 'taken', suggestions: await nicknameSuggestions(nick) });
  })
);

// PATCH /api/auth/me — { nickname?, name? } (v554: isim de guncellenebilir; profil formu ismi backend'e yazar)
router.patch(
  '/me',
  requireAuth,
  body('nickname').optional().trim().isLength({ min: 2, max: 30 }).matches(/^[\p{L}\p{N}_.-]+$/u),
  body('name').optional().trim().isLength({ min: 2, max: 100 }),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const nick = (req.body.nickname || '').trim();
    const name = (req.body.name || '').trim();
    if (!nick && !name) return res.status(400).json({ error: 'nothing_to_update' });
    if (nick && await isReserved(nick)) return res.status(400).json({ error: 'nickname_reserved' });
    try {
      const sets = ['updated_at = now()'];
      const vals = [];
      let i = 1;
      if (nick) { sets.push('nickname = $' + (i++)); vals.push(nick); }
      if (name) { sets.push('name = $' + (i++)); vals.push(name); }
      vals.push(req.user.id);
      const { rows } = await pool.query(
        'UPDATE users SET ' + sets.join(', ') + ' WHERE id = $' + i + ' RETURNING id, email, name, nickname, phone, is_admin',
        vals
      );
      res.json(publicUser(rows[0]));
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'nickname_in_use' });
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
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = await bcrypt.hash(code, 10);
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
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
    const { rows } = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (!rows.length) return res.status(404).json({ error: 'phone_not_found' });
    const sms = require('../services/sms');
    const cfg = await sms.getSmsSettings();
    if (cfg.notify.forgot === false) return res.status(503).json({ error: 'sms_disabled' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = await bcrypt.hash(code, 10);
    await pool.query(`CREATE TABLE IF NOT EXISTS phone_codes (id SERIAL PRIMARY KEY, phone TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INT DEFAULT 0, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now())`);
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
  body('new_password').isString().isLength({ min: 6, max: 100 }),
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
    if (!rows.length) return res.status(404).json({ error: 'phone_not_found' });
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

module.exports = router;

