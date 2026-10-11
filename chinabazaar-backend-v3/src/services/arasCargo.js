// Aras Kargo kurumsal web servisi — canlı kargo takip sorgusu.
//
// Çalışma prensibi:
// - Bağlantı bilgileri ENV'den gelir: ARAS_CARGO_WSDL_URL, ARAS_CARGO_USERNAME,
//   ARAS_CARGO_PASSWORD (opsiyonel: ARAS_CARGO_TRACK_METHOD).
// - Credential'lar yoksa modül "yapılandırılmadı" modundadır: isEnabled() false
//   döner, getTrackingStatus() null döner ve ASLA hata fırlatmaz. Bu durumda
//   takip, DB'deki manuel tracking_number + cargo_company bilgisiyle devam eder.
// - Servis çağrısı başarısız olursa (timeout, SOAP hatası, parse hatası) yine
//   null dönülür; çağıran taraf DB bilgisine düşer.
//
// ÖNEMLİ: Aras Kargo kurumsal web servisinin üretim URL'i ve takip metodu,
// hesabınıza özeldir; Aras kurumsal müşteri temsilcinizden alınır. Bilinen
// test URL deseni (DonanımHaber/forum kayıtları):
//   http://customerservicestest.araskargo.com.tr/arascargoservice/arascargoservice.asmx?WSDL
// Üretim URL'i temsilciniz tarafından verilir; ARAS_CARGO_WSDL_URL'e yazılır.
// Takip metodu adı da hesaba göre değişebilir (ARAS_CARGO_TRACK_METHOD).

const cfg = require('../config').arasCargo || {};
const CUSTOMER_CODE = cfg.customerCode || '';
const WSDL_URL = cfg.wsdlUrl || '';
const USERNAME = cfg.username || '';
const PASSWORD = process.env.ARAS_CARGO_PASSWORD || '';
const TRACK_METHOD = cfg.trackMethod || 'getOrder';

function isEnabled() {
  return Boolean(WSDL_URL && USERNAME && PASSWORD);
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// SOAP yanıtından durum bilgisini en iyi çabayla çıkarır.
// Aras yanıt şeması hesaba göre değişebildiği için bilinen alan adları denenir;
// hiçbiri bulunamazsa status 'unknown' olur (yine de hata değildir).
function parseStatus(xml) {
  const pick = (...names) => {
    for (const n of names) {
      const m = xml.match(new RegExp(`<${n}[^>]*>([^<]*)</${n}>`, 'i'));
      if (m && m[1].trim()) return m[1].trim();
    }
    return null;
  };
  return {
    status: pick('OrderStatus', 'Status', 'Durum', 'KargoDurumu', 'ResultMessage') || 'unknown',
    resultCode: pick('ResultCode', 'SonucKodu'),
    resultMessage: pick('ResultMessage', 'ResultDescription'),
  };
}

// Takip numarası için canlı durum sorgular.
// Başarılı: { status, resultCode, resultMessage } — Başarısız/yapılandırılmamış: null
async function getTrackingStatus(trackingNumber) {
  if (!isEnabled() || !trackingNumber) return null;
  const endpoint = WSDL_URL.replace(/\?WSDL$/i, '');
  const envelope =
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
    `<soap:Body>` +
    `<${esc(TRACK_METHOD)} xmlns="http://tempuri.org/">` +
    `<userName>${esc(USERNAME)}</userName>` +
    `<password>${esc(PASSWORD)}</password>` +
    (CUSTOMER_CODE ? `<customerCode>${esc(CUSTOMER_CODE)}</customerCode>` : '') +
    `<TradingWaybillNumber>${esc(trackingNumber)}</TradingWaybillNumber>` +
    `</${esc(TRACK_METHOD)}>` +
    `</soap:Body></soap:Envelope>`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        SOAPAction: `http://tempuri.org/${TRACK_METHOD}`,
      },
      body: envelope,
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    const xml = await res.text();
    return parseStatus(xml);
  } catch {
    return null; // timeout / ağ / parse hatası → DB bilgisine düş
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { isEnabled, getTrackingStatus, getCustomerCode: () => CUSTOMER_CODE };
