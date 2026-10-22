// JWT kimlik doğrulama middleware'i

// Kullanım: router.get('/x', requireAuth, handler)  -> req.user = { id, email, role, ... }

// fix10e M4 + L18: jwt.verify yalnızca HS256 (cfg.jwtAlgorithms) kabul eder;
// req.user artık rol de taşır (role: 'user' | 'factory' | 'master'). Fabrika/master
// jetonları requireAuth'tan geçer ama req.user.id boştur — kullanıcıya özel
// rotalar (örn. PATCH /api/auth/me) rolü kontrol edip 403 dönmelidir.

// CBOs27.2: JETON İPTALİ (token_version / "tv").
// - Kullanıcı jetonu: payload.tv, users.token_version ile kıyaslanır.
// - Master jetonu: payload.tv, login_guard 'master:cbai' sürümüyle kıyaslanır.
// - Fabrika jetonu: products.js kendi middleware'inde kıyaslar (factories).
// Uyuşmazsa 401 { error: 'token_revoked' }. tv alanı OLMAYAN eski jetonlar
// tv=0 sayılır — sütun varsayılanı da 0 olduğundan, şifre değişimiyle
// sürüm ilk kez artana dek eski jetonlar çalışmaya devam eder.
// Tüm kıyaslar FAIL-OPEN: DB okunamazsa / kullanıcı satırı yoksa kontrol
// atlanır (masterRevoke deseni) — altyapı arızası toplu çıkış yaptırmaz.

const jwt = require('jsonwebtoken');

const cfg = require('../config');

const pool = require('../db');

const { isMasterJtiRevoked } = require('./masterRevoke'); // 2026-10-21 F1: iptal edilmis master jeton reddedilir

const { MASTER_GUARD_KEY, getGuardTokenVersion } = require('./loginGuard'); // CBOs27.2

const moderation = require('../utils/moderation'); // CBOs27.3: engelli hesap kontrolü

let tvWarned = false;
function tvWarnOnce(e) {
  if (!tvWarned) {
    tvWarned = true;
    console.error('[auth] token_version kontrolü atlandı (fail-open):', e && e.message ? e.message : e);
  }
}

function payloadTv(payload) {
  return payload && Number.isInteger(payload.tv) ? payload.tv : 0;
}

// CBOs27.2: payload'ın tv'si güncel sürümle uyuşuyor mu?
// true = kabul (uyuşuyor VEYA kontrol yapılamadı/fail-open),
// false = KESİN uyuşmazlık (iptal edilmiş jeton).
// Fabrika jetonları burada İŞLENMEZ (products.js kıyaslar) → true döner.
async function checkTokenVersion(payload) {
  try {
    if (!payload || typeof payload !== 'object') return true;
    if (payload.role === 'master') {
      const cur = await getGuardTokenVersion(MASTER_GUARD_KEY);
      if (cur === null) return true; // fail-open
      return cur === payloadTv(payload);
    }
    if (payload.role === 'factory') return true;
    if (payload.sub) {
      const { rows } = await pool.query('SELECT token_version FROM users WHERE id = $1', [payload.sub]);
      if (!rows.length) return true; // satır yok: mevcut davranış (handler 404 verir)
      return (Number(rows[0].token_version) || 0) === payloadTv(payload);
    }
    return true;
  } catch (e) {
    tvWarnOnce(e);
    return true;
  }
}

function signToken(user) {

  // CBOs27.2: tv — çağıran satırdaki token_version (yoksa 0).
  const tv = user && Number.isInteger(user.tv) ? user.tv : (user && Number.isInteger(user.token_version) ? user.token_version : 0);

  return jwt.sign({ sub: user.id, email: user.email, role: 'user', tv }, cfg.jwtSecret, { expiresIn: '30d', algorithm: 'HS256' });

}


function userFromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;
  return {
    id: payload.sub ?? null,
    email: payload.email ?? null,
    role: payload.role || 'user',
    is_admin: !!payload.is_admin,
    factory_id: Number.isInteger(payload.factory_id) ? payload.factory_id : null,
    tv: Number.isInteger(payload.tv) ? payload.tv : null,
  };
}


async function requireAuth(req, res, next) {

  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {

    const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });

    // 2026-10-21 F1: iptal edilmis master jeton reddedilir. Yalniz master
    // dalinda DB'ye gidilir; isMasterJtiRevoked DB hatasinda fail-open
    // oldugundan iptal altyapisi hazir degilse kilitlenme olmaz.
    if (payload && payload.role === 'master' && payload.is_admin === true && payload.jti
        && (await isMasterJtiRevoked(payload.jti))) {

      return res.status(401).json({ error: 'token_revoked' });

    }

    // CBOs27.2: sürümü geçmiş jeton reddedilir (şifre değişimi/sıfırlamada
    // token_version artar; eski jetonlar burada ölür).
    if (!(await checkTokenVersion(payload))) {

      return res.status(401).json({ error: 'token_revoked' });

    }

    // CBOs27.3: engelli hesap kimlikli uclari kullanamaz. Kontrol
    // FAIL-OPEN'dir (F1 deseni): DB/engel altyapisi hata verirse istek
    // bloklanmaz. Master (sub 'cbai') users satiri tasimaz — sorgu satir
    // bulamaz, dal aynen gecer. Fabrika jetonu factories tablosundan,
    // kullanici jetonu users tablosundan denetlenir.
    // CBOs27.4: sira — once tv (401 token_revoked), sonra engel (403).
    try {

      if (payload && payload.role === 'factory' && Number.isInteger(payload.factory_id)) {

        if (await moderation.getFactoryBlockState(pool, payload.factory_id)) {

          return res.status(403).json({ error: 'account_blocked' });

        }

      } else if (payload && payload.sub) {

        if (await moderation.getUserBlockState(pool, payload.sub)) {

          return res.status(403).json({ error: 'account_blocked' });

        }

      }

    } catch (e) { console.error('[auth] engel kontrolu atlandi:', e.message); }

    req.user = userFromPayload(payload);

    next();

  } catch {

    return res.status(401).json({ error: 'invalid_token' });

  }

}


// Geçerli token varsa req.user doldurur, yoksa sessizce devam eder.
// CBOs27.2: sürümü geçmiş jeton burada da doldurulmaz (sessizce misafir).

async function optionalAuth(req, _res, next) {

  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (token) {

    try {

      const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: cfg.jwtAlgorithms });

      if (await checkTokenVersion(payload)) req.user = userFromPayload(payload);

    } catch { /* yok say */ }

  }

  next();

}


module.exports = { signToken, requireAuth, optionalAuth, checkTokenVersion };
