// iyzico hosted checkout (resmi iyzipay Node SDK).
// Anahtarlar yoksa enabled=false -> ödeme adımı "yakında aktif" döner, sahte ödeme YOK.
// Kart bilgisi bizde ASLA tutulmaz; ödeme iyzico sayfasında yapılır.
const cfg = require('../config');

let iyzipay = null;
if (cfg.iyzico.enabled) {
  const Iyzipay = require('iyzipay');
  iyzipay = new Iyzipay({
    apiKey: cfg.iyzico.apiKey,
    secretKey: cfg.iyzico.secretKey,
    uri: cfg.iyzico.baseUrl,
  });
}

function isEnabled() { return cfg.iyzico.enabled && !!iyzipay; }

// Ödeme formunu başlatır -> { token, paymentPageUrl }
function initCheckout({ orderNo, user, address, items, totalCents, currency, callbackUrl }) {
  return new Promise((resolve, reject) => {
    if (!isEnabled()) return reject(new Error('iyzico_not_configured'));
    const price = (totalCents / 100).toFixed(2);
    const [firstName = 'Müşteri', ...rest] = (user.name || '').split(' ');
    const request = {
      locale: 'tr',
      conversationId: orderNo,
      price,
      paidPrice: price,
      currency,
      basketId: orderNo,
      paymentGroup: 'PRODUCT',
      callbackUrl,
      buyer: {
        id: String(user.id),
        name: firstName.slice(0, 50),
        surname: (rest.join(' ') || 'Bazaar').slice(0, 50),
        email: user.email,
        gsmNumber: user.phone || '+905000000000',
        identityNumber: '11111111111', // sandbox; canlıda kullanıcıdan alınır
        registrationAddress: address ? `${address.address_line}, ${address.neighborhood || ''} ${address.district}/${address.city}`.slice(0, 255) : 'N/A',
        city: address?.city || 'İstanbul',
        country: 'Turkey',
      },
      shippingAddress: {
        contactName: address?.full_name || user.name,
        city: address?.city || 'İstanbul',
        country: 'Turkey',
        address: address ? `${address.address_line}, ${address.neighborhood || ''} ${address.district}/${address.city}`.slice(0, 255) : 'N/A',
      },
      billingAddress: {
        contactName: address?.full_name || user.name,
        city: address?.city || 'İstanbul',
        country: 'Turkey',
        address: address ? `${address.address_line}, ${address.neighborhood || ''} ${address.district}/${address.city}`.slice(0, 255) : 'N/A',
      },
      basketItems: items.map((it, i) => ({
        id: String(i + 1),
        name: String(it.name).slice(0, 100),
        category1: it.category || 'Genel',
        itemType: 'PHYSICAL',
        price: ((it.price_cents * it.qty) / 100).toFixed(2),
      })),
    };
    iyzipay.checkoutFormInitialize.create(request, (err, result) => {
      if (err) return reject(err);
      resolve(result); // { status, token, paymentPageUrl, ... }
    });
  });
}

// Callback'ten gelen token ile ödeme sonucunu doğrular
function retrieveCheckout(token) {
  return new Promise((resolve, reject) => {
    if (!isEnabled()) return reject(new Error('iyzico_not_configured'));
    iyzipay.checkoutForm.retrieve({ locale: 'tr', token }, (err, result) => {
      if (err) return reject(err);
      resolve(result); // { status, paymentStatus, paymentId, ... }
    });
  });
}

module.exports = { isEnabled, initCheckout, retrieveCheckout };
