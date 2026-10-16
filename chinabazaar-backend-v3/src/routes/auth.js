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

// ---- Kullanici adi korumasi: ozel / marka / erotik isimler alinamaz ----
// Tam eslesme (normalize: kucuk harf + _ . - kaldir) -> marka & ozel isimler
const RESERVED_EXACT = new Set([
  // Sistem / ozel
  'admin','administrator','administrators','system','official','support','help','helpdesk','mod','moderator','moderators',
  'staff','owner','root','superadmin','superuser','manager','webmaster','info','contact','service','services',
  'customer','customercare','customerservice','musteri','musterihizmetleri','yonetici','yonetim','adminpanel','panel',
  // Marka: kendi markalar
  'chinabazaar','cbazaar','chinabazar','bazaar','cb','cbai','chinabazaarcom','chinabazaartr','cbcom',
  'gdtm','gdtmgroup','ihsanoglu','ihsanoglugroup','sportface','hai','foodsan','prescott','iiec','nivora','nivorapages','kulturyolu','wolfkingwalk','wkw','wkwtv','sadiyeihsanoglu',
  // Marka: global
  'nike','adidas','apple','samsung','xiaomi','huawei','sony','lg','google','amazon','alibaba','aliexpress','temu','shein',
  'trendyol','hepsiburada','n11','gittigidiyor','puma','reebok','vans','converse','newbalance','underarmour','zara','mango',
  'lcwaikiki','defacto','koton','mavi','lenovo','hp','dell','asus','acer','msi','logitech','razer','jbl','bose','philips',
  'bosch','siemens','arcelik','beko','vestel','oppo','vivo','realme','oneplus','nokia','motorola','casio','rolex','swatch',
  'fossil','lacoste','tommyhilfiger','calvinklein','gucci','louisvuitton','chanel','hermes','prada','versace','armani',
  'diesel','levis','ralphlauren','tommy','hm','taobao','tmall','jd','jdcom','pinduoduo','douyin','tiktok','wechat','weibo',
  'paytr','paypal','visa','mastercard','troy','amex','americanexpress','microsoft','meta','facebook','instagram','youtube',
  'twitter','x','netflix','spotify','disney','cocacola','pepsi','nestle','unilever','loreal','nivea','ikea','decathlon',
]);
// Alt dize eslesme (normalize) -> erotik / mstehcen terimler (bilesik isimleri de yakalar)
const RESERVED_SUBSTR = [
  'porn','porno','xxx','sexy','erotic','erotik','escort','eskort','fuck','bitch','pussy','dick','boobs','tits','cunt',
  'whore','slut','nude','hentai','milf','bdsm','fetish','orgasm','masturb',
  'orospu','yarrak','yarak','amcik','amcık','siktir','sikis','sikiş','sikmek','gotveren','ibne','pezevenk','kaltak',
  'tasak','taşak','memeli','azgin','azgın','seks','fahise','fahişe','hayatkadini','dalyarak','pic',
];
function normalizeNick(n){ return String(n||'').toLowerCase().replace(/[_.\s-]+/g,''); }
// v557: admin kurallari (nickname_rules) hardcoded listeyi gecer: allow > block > hardcoded
async function isReserved(nick){
  const n = normalizeNick(nick);
  if(!n) return false;
  try{
    const { rows } = await pool.query('SELECT action FROM nickname_rules WHERE nickname = $1', [n]);
    if(rows.length && rows[0].action === 'allow') return false;
    if(rows.length && rows[0].action === 'block') return true;
  }catch(e){ /* tablo yoksa (migration kosmamissa) hardcoded listeye dus */ }
  if(RESERVED_EXACT.has(n)) return true;
  for(const t of RESERVED_SUBSTR){ if(n.includes(t)) return true; }
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
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { email, password, name, phone, admin_key } = req.body;
    const makeAdmin = Boolean(cfg.adminSetupKey && admin_key && admin_key === cfg.adminSetupKey);
    const hash = await bcrypt.hash(password, 12);
    try {
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, name, phone, is_admin)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, phone, is_admin`,
        [email, hash, name, phone || null, makeAdmin]
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
    // Demo doğrulama — gerçek SMS sağlayıcısı bağlanınca burası değişecek
    if (String(code).trim() !== '123456') return res.status(401).json({ error: 'invalid_code' });
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

module.exports = router;
