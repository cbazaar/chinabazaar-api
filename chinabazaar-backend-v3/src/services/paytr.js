// PayTR iframe API — kredi/banka kartı ile ödeme.
// Resmî dokümantasyon: https://www.paytr.com/odeme (iframe API)
//
// Çalışma prensibi:
// - Kimlik bilgileri ENV'den gelir: PAYTR_MERCHANT_ID, PAYTR_MERCHANT_KEY,
//   PAYTR_MERCHANT_SALT (opsiyonel: PAYTR_TEST_MODE=1).
// - Credential'lar yoksa modül "yapılandırılmadı" modundadır: isEnabled() false
//   döner, initPayment() hata fırlatır. Sahte ödeme ASLA üretilmez.
// - Kart bilgisi bizde ASLA tutulmaz; ödeme PayTR iframe sayfasında yapılır.
// - Harici SDK gerekmez; imza HMAC-SHA256 ile Node crypto kullanılarak üretilir.
//
// Akış:
// 1) POST /api/payments/paytr/init { order_id } -> { iframeUrl, token }
// 2) Kullanıcı iframe'de öder; PayTR sonucu merchant_ok/fail_url'e POST eder
// 3) POST /api/payments/paytr/callback (PayTR sunucusundan, auth'suz) ->
//    imza doğrulanır, sipariş "packing" olur. Yanıt gövdesi birebir "OK" olmalı.
const crypto = require('crypto');
const cfg = require('../config');

const API_URL = 'https://www.paytr.com/odeme';
const IFRAME_URL = 'https://www.paytr.com/odeme/guvenli/';

function isEnabled() {
  return Boolean(cfg.paytr && cfg.paytr.enabled);
}

// PayTR para birimi kodları: TL, EUR, USD, GBP, RUB
function mapCurrency(c) {
  const m = { TRY: 'TL', TL: 'TL', USD: 'USD', RUB: 'RUB', EUR: 'EUR', GBP: 'GBP' };
  return m[String(c || '').toUpperCase()] || 'TL';
}

// İstek imzası (PayTR dokümanı):
// base64( HMAC-SHA256( merchant_id + user_ip + merchant_oid + email +
//   payment_amount + user_basket + no_installment + max_installment +
//   currency + test_mode + merchant_salt, merchant_key ) )
function makeRequestToken({ merchantId, userIp, merchantOid, email, amount, basketB64, currency, testMode }) {
  const p = cfg.paytr;
  const hashStr =
    merchantId + userIp + merchantOid + email + amount + basketB64 +
    '0' + '0' + currency + testMode + p.merchantSalt;
  return crypto.createHmac('sha256', p.merchantKey).update(hashStr, 'utf8').digest('base64');
}

// Geri bildirim imzası (PayTR dokümanı):
// base64( HMAC-SHA256( merchant_oid + merchant_salt + status + total_amount, merchant_key ) )
function verifyCallback({ merchant_oid, status, total_amount, hash }) {
  try {
    const p = cfg.paytr;
    if (!p || !p.merchantKey || !p.merchantSalt) return false;
    if (!merchant_oid || !status || !total_amount || !hash) return false;
    const hashStr = String(merchant_oid) + p.merchantSalt + String(status) + String(total_amount);
    const expected = crypto.createHmac('sha256', p.merchantKey).update(hashStr, 'utf8').digest('base64');
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(String(hash), 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// Ödeme başlatır -> { token, iframeUrl }
// totalCents: kuruş/cents cinsinden tam sayı. items: [{name, price_cents, qty}]
async function initPayment({ merchantOid, userIp, email, userName, userAddress, userPhone, totalCents, currency, items, okUrl, failUrl }) {
  if (!isEnabled()) throw new Error('paytr_not_configured');
  const p = cfg.paytr;
  const currencyCode = mapCurrency(currency);
  const amount = String(Math.round(Number(totalCents) || 0));
  const basket = (items || []).map((it) => [
    String(it.name || 'Ürün').slice(0, 100),
    ((Number(it.price_cents) || 0) * (Number(it.qty) || 1) / 100).toFixed(2),
    String(Number(it.qty) || 1),
  ]);
  const basketB64 = Buffer.from(JSON.stringify(basket), 'utf8').toString('base64');
  const testMode = p.testMode ? '1' : '0';

  const paytrToken = makeRequestToken({
    merchantId: p.merchantId,
    userIp,
    merchantOid,
    email,
    amount,
    basketB64,
    currency: currencyCode,
    testMode,
  });

  const params = new URLSearchParams({
    merchant_id: p.merchantId,
    user_ip: userIp,
    merchant_oid: merchantOid,
    email: email || '',
    payment_amount: amount,
    payment_type: 'card',
    installment_count: '0',
    currency: currencyCode,
    test_mode: testMode,
    user_basket: basketB64,
    no_installment: '0',
    max_installment: '0',
    user_name: (userName || '').slice(0, 100),
    user_address: (userAddress || '').slice(0, 255),
    user_phone: (userPhone || '').replace(/[^0-9+]/g, '').slice(0, 20),
    merchant_ok_url: okUrl,
    merchant_fail_url: failUrl,
    timeout_limit: '30',
    debug_on: '0',
    lang: 'tr',
    paytr_token: paytrToken,
  });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      signal: ctrl.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (data.status !== 'success' || !data.token) {
      throw new Error('paytr_init_failed: ' + (data.reason || 'unknown'));
    }
    return { token: data.token, iframeUrl: IFRAME_URL + data.token };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { isEnabled, initPayment, verifyCallback, mapCurrency };
