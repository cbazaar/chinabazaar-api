// SMS servisi (v609) — Netgsm uzerinden SMS gonderimi.
// Ayarlar once veritabanindaki settings tablosundan okunur (admin panelindeki SMS sekmesinden kaydedilir),
// yoksa Railway Variables (NETGSM_USERCODE/PASSWORD/HEADER) kullanilir.
// Kimlikler yoksa { ok:false, error:'sms_not_configured' } doner — sahte "gonderildi" yok.
// NOT: SMS'te gonderen bir telefon numarasi olmaz; gonderen adi (Baslik, orn. CHINABAZAAR)
// Netgsm panelinden onaylanir. Firma telefonu mesajlarin sonuna iletisim icin eklenir.
const pool = require('../db');

const DEFAULT_COMPANY_PHONE = '+90 342 220 81 82';
const SMS_KEYS = [
  'sms_netgsm_usercode', 'sms_netgsm_password', 'sms_netgsm_header', 'sms_company_phone',
  'sms_notify_register', 'sms_notify_forgot', 'sms_notify_order_received', 'sms_notify_order_shipped', 'sms_notify_order_delivered',
];

function parseToggle(v, def) {
  if (v === undefined || v === null || v === '') return def;
  return v === 'true' || v === true;
}

async function getSmsSettings() {
  const cfg = {
    usercode: process.env.NETGSM_USERCODE || '',
    password: process.env.NETGSM_PASSWORD || '',
    header: process.env.NETGSM_HEADER || '',
    companyPhone: DEFAULT_COMPANY_PHONE,
    notify: { register: true, forgot: true, order_received: true, order_shipped: true, order_delivered: true },
  };
  try {
    const { rows } = await pool.query(
      'SELECT key, value FROM settings WHERE key = ANY($1)',
      [SMS_KEYS]
    );
    const kv = {};
    rows.forEach((r) => { kv[r.key] = r.value; });
    if (kv.sms_netgsm_usercode) cfg.usercode = kv.sms_netgsm_usercode;
    if (kv.sms_netgsm_password) cfg.password = kv.sms_netgsm_password;
    if (kv.sms_netgsm_header) cfg.header = kv.sms_netgsm_header;
    if (kv.sms_company_phone) cfg.companyPhone = kv.sms_company_phone;
    cfg.notify.register = parseToggle(kv.sms_notify_register, true);
    cfg.notify.forgot = parseToggle(kv.sms_notify_forgot, true);
    cfg.notify.order_received = parseToggle(kv.sms_notify_order_received, true);
    cfg.notify.order_shipped = parseToggle(kv.sms_notify_order_shipped, true);
    cfg.notify.order_delivered = parseToggle(kv.sms_notify_order_delivered, true);
  } catch (e) { /* settings tablosu yoksa env ile devam */ }
  return cfg;
}

async function sendSms(phone, message) {
  const cfg = await getSmsSettings();
  if (!cfg.usercode || !cfg.password || !cfg.header) return { ok: false, error: 'sms_not_configured' };
  try {
    const gsmno = String(phone || '').replace(/^\+/, '').replace(/\D/g, '');
    if (gsmno.length < 10) return { ok: false, error: 'invalid_phone' };
    const params = new URLSearchParams({ usercode: cfg.usercode, password: cfg.password, gsmno, message, msgheader: cfg.header });
    const r = await fetch('https://api.netgsm.com.tr/sms/send/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const text = (await r.text()).trim();
    if (text.startsWith('00')) return { ok: true, jobId: text.split(' ')[1] || null };
    // Netgsm hata kodlari (Netgsm dokumani): kodu anlasilir mesaja cevir, kodu da koru.
    const NETGSM_ERRORS = {
      '20': 'Mesaj metni bos veya hatali.',
      '30': 'Kullanici adi / sifre hatali, veya API erisim izni kapali, veya IP sinirlamasi var. Netgsm panelinde Ayarlar > API islemleri bolumunden API erisim iznini acin ve IP sinirlamasini kaldirin.',
      '40': 'Mesaj basligi (Gonderen Adi) Netgsm sisteminde kayitli degil.',
      '41': 'Mesaj basligi (Gonderen Adi) bu kullaniciya ait degil.',
      '50': 'Gecersiz birim (mesaj basina dusecek kredi).',
      '51': 'Hatali sorgu formati.',
      '52': 'Gonderim limiti asildi.',
      '60': 'Hatali telefon numarasi.',
      '70': 'Hatali sorgulama.',
      '100': 'Netgsm sistem hatasi.',
    };
    const code = text.slice(0, 2);
    const mapped = NETGSM_ERRORS[code];
    return { ok: false, error: 'sms_send_failed', detail: (mapped ? mapped + ' (Netgsm kodu: ' + code + ')' : text.slice(0, 100)) };
  } catch (e) {
    return { ok: false, error: 'sms_send_failed', detail: e.message };
  }
}

module.exports = { sendSms, getSmsSettings };
