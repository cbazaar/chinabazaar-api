// SMS servisi (v600) — Netgsm uzerinden SMS gonderimi.
// Railway Variables: NETGSM_USERCODE, NETGSM_PASSWORD, NETGSM_HEADER (onayli gonderici adi, orn. CHINABAZAAR)
// Kimlikler yoksa { ok:false, error:'sms_not_configured' } doner — sahte "gonderildi" yok.
async function sendSms(phone, message) {
  const usercode = process.env.NETGSM_USERCODE;
  const password = process.env.NETGSM_PASSWORD;
  const header = process.env.NETGSM_HEADER;
  if (!usercode || !password || !header) return { ok: false, error: 'sms_not_configured' };
  try {
    const gsmno = String(phone || '').replace(/^\+/, '').replace(/\D/g, '');
    if (gsmno.length < 10) return { ok: false, error: 'invalid_phone' };
    const params = new URLSearchParams({ usercode, password, gsmno, message, msgheader: header });
    const r = await fetch('https://api.netgsm.com.tr/sms/send/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const text = (await r.text()).trim();
    if (text.startsWith('00')) return { ok: true, jobId: text.split(' ')[1] || null };
    return { ok: false, error: 'sms_send_failed', detail: text.slice(0, 100) };
  } catch (e) {
    return { ok: false, error: 'sms_send_failed', detail: e.message };
  }
}

module.exports = { sendSms };
