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
    `Merhaba,\n\n` +
    `ChinaBazaar hesabınıza giriş için doğrulama kodunuz: ${code}\n\n` +
    `Kod 10 dakika geçerlidir.\n\n` +
    `Kodunuzu kimseyle paylaşmayın. ChinaBazaar ekibi sizden asla kod istemez.\n\n` +
    `Bu isteği siz yapmadıysanız bu e-postayı görmezden gelebilirsiniz; hesabınız güvendedir.\n\n` +
    `---\n` +
    `HAi © 2026 ChinaBazaar\n` +
    `www.chinabazaar.shop`;
  const html =
    `<!DOCTYPE html>` +
    `<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>` +
    `<body style="margin:0;padding:0;background:#F4F4F5;font-family:Arial,Helvetica,sans-serif;">` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F4F4F5;padding:32px 12px;">` +
    `<tr><td align="center">` +
    `<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#FFFFFF;border-radius:16px;overflow:hidden;border:1px solid #E7E7EA;">` +
    `  <tr><td align="center" style="padding:28px 32px 8px 32px;">` +
    `    <img src="https://chinabazaar.shop/panda-logo.png" width="64" height="64" alt="ChinaBazaar" style="display:block;border-radius:14px;">` +
    `    <div style="font-size:26px;font-weight:bold;color:#16161A;padding-top:12px;">ChinaBazaar</div>` +
    `    <div style="font-size:14px;color:#C8102E;font-weight:bold;padding-top:4px;">Çin Artık Cebinizde</div>` +
    `  </td></tr>` +
    `  <tr><td style="padding:16px 32px 0 32px;"><div style="height:3px;background:#C8102E;border-radius:2px;"></div></td></tr>` +
    `  <tr><td style="padding:24px 32px 0 32px;color:#16161A;font-size:16px;line-height:24px;">` +
    `    Merhaba,<br>ChinaBazaar hesabınıza giriş için doğrulama kodunuz:` +
    `  </td></tr>` +
    `  <tr><td align="center" style="padding:20px 32px 0 32px;">` +
    `    <div style="background:#FDF2F4;border:2px solid #C8102E;border-radius:12px;padding:18px 10px;font-size:40px;font-weight:bold;letter-spacing:12px;color:#16161A;">${code}</div>` +
    `    <div style="font-size:13px;color:#71717A;padding-top:10px;">Kod 10 dakika geçerlidir.</div>` +
    `  </td></tr>` +
    `  <tr><td style="padding:22px 32px 0 32px;">` +
    `    <div style="background:#FFF7ED;border-left:4px solid #C8102E;border-radius:8px;padding:12px 14px;font-size:14px;line-height:21px;color:#7C2D12;">` +
    `      <b style="color:#C8102E;">Kodunuzu kimseyle paylaşmayın.</b> ChinaBazaar ekibi sizden asla kod istemez.` +
    `    </div>` +
    `  </td></tr>` +
    `  <tr><td style="padding:18px 32px 28px 32px;font-size:13px;color:#A1A1AA;line-height:19px;">` +
    `    Bu isteği siz yapmadıysanız bu e-postayı görmezden gelebilirsiniz; hesabınız güvendedir.` +
    `  </td></tr>` +
    `  <tr><td align="center" style="background:#16161A;padding:16px 32px;">` +
    `    <div style="font-size:13px;color:#FFFFFF;">HAi © 2026 ChinaBazaar</div>` +
    `    <div style="font-size:12px;color:#A1A1AA;padding-top:4px;">www.chinabazaar.shop</div>` +
    `  </td></tr>` +
    `</table>` +
    `</td></tr></table>` +
    `</body></html>`;
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
