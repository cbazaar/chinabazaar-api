// E-posta gönderimi — doğrulama kodları, sipariş ve fatura e-postaları.
// İki sağlayıcı desteklenir:
//   1) SMTP (önerilen): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
//      SMTP_SECURE ('1' = 465 TLS, yoksa STARTTLS), EMAIL_FROM
//   2) Resend: RESEND_API_KEY (+ EMAIL_FROM)
// CBOs26.113 (fix10as): Ayarlar artık admin panelinden de yönetilebilir —
// settings tablosundaki mail_* anahtarları ENV'i alan bazında ezer
// (DB değeri boşsa ENV kullanılır). Hiçbir kaynak yoksa isEnabled() false
// döner; kod gönderimi 503 verir.
// Kodun kendisi bu modülde üretilmez; routes/auth.js üretir ve hash'ler.
const cfg = require('../config');
const pool = require('../db');

// ENV'den gelen temel yapılandırma.
function envCfg() {
  const e = cfg.email || {};
  return {
    from: e.from || '',
    fromName: '',
    smtpHost: e.smtpHost || '',
    smtpPort: e.smtpPort ? parseInt(e.smtpPort, 10) || 587 : 587,
    smtpUser: e.smtpUser || '',
    smtpPass: e.smtpPass || '',
    smtpSecure: Boolean(e.smtpSecure),
    resendKey: e.resendKey || '',
    source: 'env',
  };
}

const MAIL_DB_KEYS = ['mail_smtp_host', 'mail_smtp_port', 'mail_smtp_user', 'mail_smtp_pass', 'mail_from', 'mail_from_name', 'mail_smtp_secure'];
let _eff = null;
let _effAt = 0;
const EFF_TTL_MS = 60000;

// Etkin yapılandırmayı çözer: settings tablosu (panel) > ENV, alan bazında.
// 60 saniyelik bellek içi önbellek; force=true ile taze okunur.
async function resolveEmailCfg(force) {
  if (!force && _eff && (Date.now() - _effAt) < EFF_TTL_MS) return _eff;
  const base = envCfg();
  let db = {};
  try {
    const { rows } = await pool.query('SELECT key, value FROM settings WHERE key = ANY($1)', [MAIL_DB_KEYS]);
    rows.forEach((r) => { db[r.key] = r.value; });
  } catch (e) {
    db = {}; // settings tablosu yoksa / DB hatasında ENV ile devam et
  }
  const pick = (dbVal, envVal) => {
    const v = typeof dbVal === 'string' ? dbVal.trim() : dbVal;
    return v ? v : envVal;
  };
  const eff = { ...base };
  eff.smtpHost = pick(db.mail_smtp_host, base.smtpHost);
  eff.smtpUser = pick(db.mail_smtp_user, base.smtpUser);
  eff.smtpPass = pick(db.mail_smtp_pass, base.smtpPass);
  eff.from = pick(db.mail_from, base.from);
  eff.fromName = pick(db.mail_from_name, base.fromName);
  const dbPort = parseInt(db.mail_smtp_port, 10);
  if (db.mail_smtp_port && !Number.isNaN(dbPort) && dbPort > 0) eff.smtpPort = dbPort;
  if (db.mail_smtp_secure === 'true') eff.smtpSecure = true;
  else if (db.mail_smtp_secure === 'false') eff.smtpSecure = false;
  eff.source = MAIL_DB_KEYS.some((k) => typeof db[k] === 'string' && db[k].trim() !== '') ? 'panel' : 'env';
  _eff = eff;
  _effAt = Date.now();
  return eff;
}

function enabledOf(eff) {
  return Boolean(eff && eff.from && ((eff.smtpHost && eff.smtpUser) || eff.resendKey));
}

// SENKRON: son çözülmüş yapılandırma (yoksa ENV) üzerinden durum.
// Eşzamanlı kullanan çağıranlar (auth akışı) geriye dönük uyumlu kalır.
function isEnabled() {
  return enabledOf(_eff || envCfg());
}

function formatFrom(eff) {
  if (eff.fromName) return `"${String(eff.fromName).replace(/"/g, '')}" <${eff.from}>`;
  return eff.from;
}

function codeEmail(code) {
  const subject = `ChinaBazaar doğrulama kodunuz: ${code}`;
  const text =
    `ChinaBazaar'a hoş geldiniz.\n\n` +
    `Doğrulama kodunuz: ${code}\n\n` +
    `Bu kod 10 dakika geçerlidir.\n` +
    `Kodunuzu kimseyle paylaşmayın. ChinaBazaar ekibi sizden asla kod istemez.\n` +
    `Bu işlemi siz yapmadıysanız bu e-postayı görmezden gelin.\n\n` +
    `---\n\n` +
    `Your ChinaBazaar verification code: ${code}\n\n` +
    `This code expires in 10 minutes.\n` +
    `Never share your code with anyone. The ChinaBazaar team will never ask for your code.\n` +
    `If you did not request this, please ignore this email.\n\n` +
    `---\n` +
    `HAi © 2026 ChinaBazaar.com Tüm Hakları Saklıdır`;
  const html =
    `<div style="margin:0;padding:24px 12px;background:#ececf0;font-family:Arial,Helvetica,sans-serif">` +
    `<table role="presentation" cellpadding="0" cellspacing="0" align="center" style="max-width:520px;width:100%;background:#ffffff;border:1px solid #e3e3ea;border-radius:16px;overflow:hidden">` +
    `<tr><td style="padding:28px 32px 0;text-align:center">` +
    `<img src="https://chinabazaar.shop/panda-logo.png" width="72" height="72" alt="ChinaBazaar" style="display:inline-block;border-radius:16px">` +
    `<div style="font-size:22px;font-weight:800;color:#141419;margin-top:12px;letter-spacing:.2px">China<span style="color:#e32645">Bazaar</span></div>` +
    `<div style="font-size:12px;color:#8a8a95;margin-top:2px">Çin Artık Cebinizde</div>` +
    `</td></tr>` +
    `<tr><td style="padding:20px 32px 0"><div style="border-top:1px solid #eeeef2"></div></td></tr>` +
    `<tr><td style="padding:20px 32px 0;text-align:center">` +
    `<div style="font-size:13px;font-weight:700;color:#55555f;text-transform:uppercase;letter-spacing:1.5px">Doğrulama Kodunuz</div>` +
    `<div style="font-size:11px;color:#9a9aa4;letter-spacing:1.2px;margin-top:2px">YOUR VERIFICATION CODE</div>` +
    `<div style="margin:18px auto 4px;background:#f7f7fa;border:1.5px solid #e8e8ef;border-radius:12px;padding:18px 8px;max-width:340px">` +
    `<span style="font-size:38px;font-weight:800;letter-spacing:10px;color:#141419">${code}</span></div>` +
    `<p style="font-size:13px;color:#6d6d77;margin:14px 0 0">Bu kod <b style="color:#141419">10 dakika</b> geçerlidir.<br>` +
    `<span style="font-size:12px">This code expires in <b>10 minutes</b>.</span></p>` +
    `</td></tr>` +
    `<tr><td style="padding:20px 32px 0">` +
    `<div style="background:#fff5f6;border:1px solid #ffd9de;border-radius:10px;padding:12px 14px;text-align:center">` +
    `<span style="font-size:13px;font-weight:700;color:#c21735">Kodunuzu kimseyle paylaşmayın.</span><br>` +
    `<span style="font-size:12px;color:#8a4a55">ChinaBazaar ekibi sizden asla kod istemez. / Never share your code — our team will never ask for it.</span>` +
    `</div>` +
    `<p style="font-size:12px;color:#9a9aa4;text-align:center;margin:14px 0 0">Bu işlemi siz yapmadıysanız bu e-postayı görmezden gelin.<br>If you did not request this, please ignore this email.</p>` +
    `</td></tr>` +
    `<tr><td style="padding:22px 32px 26px;text-align:center">` +
    `<div style="border-top:1px solid #eeeef2;padding-top:16px">` +
    `<a href="https://chinabazaar.shop" style="font-size:12px;color:#e32645;text-decoration:none;font-weight:700">www.chinabazaar.shop</a>` +
    `<span style="font-size:12px;color:#c9c9d2"> &nbsp;·&nbsp; </span>` +
    `<a href="https://chinabazaar.com" style="font-size:12px;color:#e32645;text-decoration:none;font-weight:700">www.chinabazaar.com</a>` +
    `<div style="font-size:11px;color:#a5a5af;margin-top:10px">HAi © 2026 ChinaBazaar.com Tüm Hakları Saklıdır</div>` +
    `</div></td></tr></table></div>`;
  return { subject, text, html };
}

let nodemailer = null;
let _transport = null;
let _transportKey = '';
function getTransport(eff) {
  if (!nodemailer) nodemailer = require('nodemailer');
  const key = [eff.smtpHost, eff.smtpPort, eff.smtpUser, eff.smtpSecure ? '1' : '0'].join('|');
  if (!_transport || _transportKey !== key) {
    _transport = nodemailer.createTransport({
      host: eff.smtpHost,
      port: eff.smtpPort,
      secure: eff.smtpSecure, // true: 465, false: STARTTLS
      auth: { user: eff.smtpUser, pass: eff.smtpPass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
    });
    _transportKey = key;
  }
  return _transport;
}

async function sendViaSmtp(to, { subject, text, html, attachments }, eff) {
  const info = await getTransport(eff).sendMail({
    from: formatFrom(eff),
    to,
    subject,
    text,
    html,
    attachments: (attachments || []).map((a) => ({ filename: a.filename, content: a.content })),
  });
  return info && info.messageId;
}

async function sendViaResend(to, { subject, text, html, attachments }, eff) {
  const payload = {
    from: formatFrom(eff),
    to: [to],
    subject,
    text,
    html,
  };
  if (attachments && attachments.length) {
    payload.attachments = attachments.map((a) => ({
      filename: a.filename,
      content: Buffer.isBuffer(a.content) ? a.content.toString('base64') : a.content,
    }));
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${eff.resendKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error('resend_failed: ' + (data.message || res.status));
  return data.id;
}

async function dispatch(to, mail) {
  const eff = await resolveEmailCfg();
  if (!enabledOf(eff)) throw new Error('email_not_configured');
  if (eff.resendKey) return sendViaResend(to, mail, eff);
  if (eff.smtpHost && eff.smtpUser) return sendViaSmtp(to, mail, eff);
  return sendViaResend(to, mail, eff);
}

// Doğrulama kodunu gönderir. Başarılıysa sağlayıcının mesaj kimliğini döner.
async function sendVerificationCode(to, code) {
  return dispatch(to, codeEmail(code));
}

// --- Genel e-posta gönderimi (fatura vb.) ---
// attachments: [{ filename, content: Buffer }] — SMTP'ye Buffer, Resend'e base64 gider.
async function sendMail(to, { subject, text, html: htmlBody, attachments }) {
  return dispatch(to, { subject, text, html: htmlBody, attachments });
}

// CBOs26.113: Paneldeki "Test E-postası Gönder" düğmesi için.
async function sendTestEmail(to) {
  const subject = 'ChinaBazaar — test e-postası';
  const text = 'Bu bir test e-postasıdır. E-posta ayarlarınız çalışıyor.';
  const html =
    `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#0d0d12;color:#f5f5f7;padding:32px;border-radius:12px">` +
    `<div style="font-size:20px;font-weight:700;margin-bottom:8px">ChinaBazaar</div>` +
    `<p style="color:#b9b9c2">Bu bir test e-postasıdır. E-posta ayarlarınız çalışıyor.</p>` +
    `</div>`;
  return sendMail(to, { subject, text, html });
}

// CBOs26.113: Panelin durum rozeti / ENV notu için etkin durum özeti (sır dönmez).
async function getEmailStatus() {
  const eff = await resolveEmailCfg();
  return {
    enabled: enabledOf(eff),
    from: eff.from || '',
    fromName: eff.fromName || '',
    host: eff.smtpHost || '',
    source: eff.source || 'env',
  };
}

function invoiceEmail(order, invoiceNumber) {
  const subject = `ChinaBazaar faturanız: ${invoiceNumber || order.order_no}`;
  const text =
    `Merhaba ${order.customer_name || ''},\n\n` +
    `Siparişinizin faturası ektedir.\n\n` +
    `Sipariş No: ${order.order_no}\n` +
    `Fatura No: ${invoiceNumber || '-'}\n` +
    `Faturanızı Hesabım > Siparişlerim bölümünden de her zaman indirebilirsiniz.\n\n` +
    `Teşekkürler,\nChinaBazaar`;
  const htmlBody =
    `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d0d12;color:#f5f5f7;padding:32px;border-radius:12px">` +
    `<div style="font-size:20px;font-weight:700;margin-bottom:8px">ChinaBazaar</div>` +
    `<p style="color:#b9b9c2">Merhaba ${order.customer_name || ''},</p>` +
    `<p style="color:#f5f5f7">Siparişinizin faturası ektedir.</p>` +
    `<p style="color:#b9b9c2;font-size:13px">Sipariş No: ${order.order_no}<br>Fatura No: ${invoiceNumber || '-'}</p>` +
    `<p style="color:#b9b9c2;font-size:13px">Faturanızı Hesabım &gt; Siparişlerim bölümünden de her zaman indirebilirsiniz.</p>` +
    `<p style="color:#b9b9c2;font-size:13px">Teşekkürler,<br>ChinaBazaar</p></div>`;
  return { subject, text, html: htmlBody };
}

module.exports = { isEnabled, sendVerificationCode, sendMail, invoiceEmail, sendTestEmail, getEmailStatus, resolveEmailCfg };
