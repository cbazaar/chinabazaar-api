// E-posta gönderimi — doğrulama kodları için.
// İki sağlayıcı desteklenir (ENV ile seçilir):
//   1) SMTP (önerilen): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
//      SMTP_SECURE ('1' = 465 TLS, yoksa STARTTLS), EMAIL_FROM
//   2) Resend: RESEND_API_KEY (+ EMAIL_FROM)
// Hiçbiri yoksa isEnabled() false döner; kod gönderimi 503 verir.
// Kodun kendisi bu modülde üretilmez; routes/auth.js üretir ve hash'ler.
const cfg = require('../config');

function isEnabled() {
  const e = cfg.email || {};
  return Boolean(e.from && ((e.smtpHost && e.smtpUser) || e.resendKey));
}

function codeEmail(code) {
  const subject = `ChinaBazaar doğrulama kodunuz: ${code}`;
  const text =
    `ChinaBazaar'a hoş geldiniz.\n\n` +
    `Doğrulama kodunuz: ${code}\n\n` +
    `Bu kod 10 dakika geçerlidir. Kimseyle paylaşmayın.\n` +
    `Bu işlemi siz yapmadıysanız bu e-postayı görmezden gelin.\n\n` +
    `---\n\n` +
    `Your ChinaBazaar verification code: ${code}\n\n` +
    `This code expires in 10 minutes. Never share it with anyone.\n` +
    `If you did not request this, please ignore this email.`;
  const html =
    `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#0d0d12;color:#f5f5f7;padding:32px;border-radius:12px">` +
    `<div style="font-size:20px;font-weight:700;margin-bottom:8px">ChinaBazaar</div>` +
    `<p style="color:#b9b9c2">Doğrulama kodunuz / Your verification code:</p>` +
    `<div style="font-size:36px;font-weight:800;letter-spacing:8px;margin:16px 0;color:#fff">${code}</div>` +
    `<p style="color:#b9b9c2;font-size:13px">Bu kod 10 dakika geçerlidir. Kimseyle paylaşmayın.<br>` +
    `This code expires in 10 minutes. Never share it.</p>` +
    `</div>`;
  return { subject, text, html };
}

let nodemailer = null;
function getTransport() {
  const e = cfg.email;
  if (!nodemailer) nodemailer = require('nodemailer');
  if (!getTransport.t) {
    getTransport.t = nodemailer.createTransport({
      host: e.smtpHost,
      port: e.smtpPort,
      secure: e.smtpSecure, // true: 465, false: STARTTLS
      auth: { user: e.smtpUser, pass: e.smtpPass },
    });
  }
  return getTransport.t;
}

async function sendViaSmtp(to, { subject, text, html }) {
  const info = await getTransport().sendMail({
    from: cfg.email.from,
    to,
    subject,
    text,
    html,
  });
  return info && info.messageId;
}

async function sendViaResend(to, { subject, text, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cfg.email.resendKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: cfg.email.from, to: [to], subject, text, html }),
    signal: AbortSignal.timeout(15000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error('resend_failed: ' + (data.message || res.status));
  return data.id;
}

// Doğrulama kodunu gönderir. Başarılıysa sağlayıcının mesaj kimliğini döner.
async function sendVerificationCode(to, code) {
  if (!isEnabled()) throw new Error('email_not_configured');
  const mail = codeEmail(code);
  const e = cfg.email;
  if (e.smtpHost && e.smtpUser) return sendViaSmtp(to, mail);
  return sendViaResend(to, mail);
}

module.exports = { isEnabled, sendVerificationCode };
