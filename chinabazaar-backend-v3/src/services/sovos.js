// Sovos Bulut e-Arşiv Fatura WS API v2.3 entegrasyonu
// Doküman: Sovos Bulut e-Arşiv Fatura WS API v2.3.pdf
// SOAP tabanlı, Basic Auth ile çalışır
//
// Gerekli Railway değişkenleri:
//   SOVOS_ENABLED=1
//   SOVOS_EARSIV_ENDPOINT=https://<sovos-verdigi-adres>/ClientEArsivServicesPort.svc
//   SOVOS_USERNAME=<sovos web servis kullanıcı adı>
//   SOVOS_PASSWORD=<sovos web servis şifresi>
//   SOVOS_SENDER_VKN=<şirket VKN>
//   SOVOS_SENDER_NAME=<şirket unvanı>
//   SOVOS_SENDER_ADDRESS=<şirket adresi>
//   SOVOS_SENDER_CITY=<şehir>
//   SOVOS_SENDER_TAX_OFFICE=<vergi dairesi>
//   SOVOS_BRANCH=default
//
// NOT: Kimlik bilgileri asla koda yazılmaz, sadece Railway değişkenlerinden okunur.
const crypto = require('crypto');
const zlib = require('zlib');
const https = require('https');
const http = require('http');
const { URL } = require('url');

function cfg() {
  return {
    enabled: process.env.SOVOS_ENABLED === '1',
    endpoint: (process.env.SOVOS_EARSIV_ENDPOINT || '').trim(),
    username: (process.env.SOVOS_USERNAME || '').trim(),
    password: (process.env.SOVOS_PASSWORD || '').trim(),
    senderVkn: (process.env.SOVOS_SENDER_VKN || '').trim(),
    senderName: (process.env.SOVOS_SENDER_NAME || '').trim(),
    senderAddress: (process.env.SOVOS_SENDER_ADDRESS || '').trim(),
    senderCity: (process.env.SOVOS_SENDER_CITY || '').trim(),
    senderTaxOffice: (process.env.SOVOS_SENDER_TAX_OFFICE || '').trim(),
    branch: (process.env.SOVOS_BRANCH || 'default').trim(),
  };
}

function isEnabled() {
  const c = cfg();
  return c.enabled && Boolean(c.endpoint && c.username && c.password && c.senderVkn);
}

function escXml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// UBL-TR 1.2 e-Arşiv fatura XML'i üret
// order: { id, order_no, customer_name, customer_email, customer_tax_no, customer_address, items: [{name, qty, price_cents}], total_cents, vat_cents, created_at }
// sender: cfg() çıktısı
function buildUblInvoice(order, sender) {
  const uuid = crypto.randomUUID().toUpperCase();
  const now = new Date(order.created_at || Date.now()).toISOString().slice(0, 19);
  const invoiceNo = order.invoice_no || ('ARS' + Date.now().toString().slice(-10));

  // KDV: toplam içinde %20 KDV varsayımı (ürünler %20 KDV'li)
  const totalCents = Math.round(order.total_cents || 0);
  const vatCents = Math.round(order.vat_cents != null ? order.vat_cents : totalCents * 20 / 120);
  const netCents = totalCents - vatCents;

  const fmt = (cents) => (cents / 100).toFixed(2);
  const items = (order.items || []).map((it, i) => {
    const qty = it.qty || it.quantity || 1;
    const unitCents = Math.round((it.price_cents || it.unit_price_cents || 0));
    const lineTotal = unitCents * qty;
    const lineVat = Math.round(lineTotal * 20 / 120);
    const lineNet = lineTotal - lineVat;
    return `    <cac:InvoiceLine>
      <cbc:ID>${i + 1}</cbc:ID>
      <cbc:InvoicedQuantity unitCode="C62">${qty}</cbc:InvoicedQuantity>
      <cbc:LineExtensionAmount currencyID="TRY">${fmt(lineNet)}</cbc:LineExtensionAmount>
      <cac:TaxTotal>
        <cbc:TaxAmount currencyID="TRY">${fmt(lineVat)}</cbc:TaxAmount>
        <cac:TaxSubtotal>
          <cbc:TaxableAmount currencyID="TRY">${fmt(lineNet)}</cbc:TaxableAmount>
          <cbc:TaxAmount currencyID="TRY">${fmt(lineVat)}</cbc:TaxAmount>
          <cbc:CalculationSequenceNumeric>1</cbc:CalculationSequenceNumeric>
          <cbc:Percent>20</cbc:Percent>
          <cac:TaxCategory>
            <cbc:TaxExemptionReasonCode>301</cbc:TaxExemptionReasonCode>
            <cac:TaxScheme><cbc:ID>VAT</cbc:ID><cbc:Name>KDV</cbc:Name><cbc:TaxTypeCode>0015</cbc:TaxTypeCode></cac:TaxScheme>
          </cac:TaxCategory>
        </cac:TaxSubtotal>
      </cac:TaxTotal>
      <cac:Item><cbc:Name>${escXml(it.name || it.title || 'Ürün')}</cbc:Name></cac:Item>
      <cac:Price><cbc:PriceAmount currencyID="TRY">${fmt(unitCents)}</cbc:PriceAmount></cac:Price>
    </cac:InvoiceLine>`;
  }).join('\n');

  // Fatura türü: bireysel -> e-Arşiv (EARSIVFATURA, TCKN), kurumsal -> e-Fatura (TEMELFATURA, VKN)
  const isCorporate = (order.invoice_type === 'kurumsal') || Boolean(order.invoice_vkn || order.invoice_company);
  const profileId = isCorporate ? 'TEMELFATURA' : 'EARSIVFATURA';
  const idScheme = isCorporate ? 'VKN' : 'TCKN';
  const customerTax = isCorporate
    ? (order.invoice_vkn || order.customer_tax_no || order.customer_vkn || '1111111111')
    : (order.invoice_tckn || order.customer_tckn || order.customer_tax_no || '11111111111');
  const customerName = isCorporate
    ? (order.invoice_company || order.customer_name || 'Firma')
    : (order.customer_name || 'Müşteri');
  const customerTaxOffice = order.invoice_tax_office || order.customer_tax_office || '';
  const customerAddr = order.customer_address || order.shipping_address || '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>TR1.2</cbc:CustomizationID>
  <cbc:ProfileID>${profileId}</cbc:ProfileID>
  <cbc:ID>${escXml(invoiceNo)}</cbc:ID>
  <cbc:CopyIndicator>false</cbc:CopyIndicator>
  <cbc:UUID>${uuid}</cbc:UUID>
  <cbc:IssueDate>${now.slice(0, 10)}</cbc:IssueDate>
  <cbc:IssueTime>${now.slice(11, 19)}</cbc:IssueTime>
  <cbc:InvoiceTypeCode>SATIS</cbc:InvoiceTypeCode>
  <cbc:Note>ChinaBazaar ${isCorporate ? 'e-Fatura' : 'e-Arşiv Fatura'}</cbc:Note>
  <cbc:DocumentCurrencyCode>TRY</cbc:DocumentCurrencyCode>
  <cbc:LineCountNumeric>${(order.items || []).length}</cbc:LineCountNumeric>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="VKN">${escXml(sender.senderVkn)}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>${escXml(sender.senderName)}</cbc:Name></cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>${escXml(sender.senderAddress)}</cbc:StreetName>
        <cbc:CityName>${escXml(sender.senderCity)}</cbc:CityName>
        <cbc:Country><cbc:IdentificationCode>TR</cbc:IdentificationCode><cbc:Name>Türkiye</cbc:Name></cbc:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme><cbc:RegistrationName>${escXml(sender.senderName)}</cbc:RegistrationName><cac:TaxScheme><cbc:Name>${escXml(sender.senderTaxOffice)}</cbc:Name></cac:TaxScheme></cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="${idScheme}">${escXml(customerTax)}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>${escXml(customerName)}</cbc:Name></cac:PartyName>${customerTaxOffice ? `
      <cac:PartyTaxScheme><cbc:RegistrationName>${escXml(customerName)}</cbc:RegistrationName><cac:TaxScheme><cbc:Name>${escXml(customerTaxOffice)}</cbc:Name></cac:TaxScheme></cac:PartyTaxScheme>` : ''}
      <cac:PostalAddress><cbc:StreetName>${escXml(customerAddr)}</cbc:StreetName><cbc:Country><cbc:IdentificationCode>TR</cbc:IdentificationCode><cbc:Name>Türkiye</cbc:Name></cbc:Country></cac:PostalAddress>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="TRY">${fmt(vatCents)}</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="TRY">${fmt(netCents)}</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="TRY">${fmt(vatCents)}</cbc:TaxAmount>
      <cbc:CalculationSequenceNumeric>1</cbc:CalculationSequenceNumeric>
      <cbc:Percent>20</cbc:Percent>
      <cac:TaxCategory><cac:TaxScheme><cbc:ID>VAT</cbc:ID><cbc:Name>KDV</cbc:Name><cbc:TaxTypeCode>0015</cbc:TaxTypeCode></cac:TaxScheme></cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="TRY">${fmt(netCents)}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="TRY">${fmt(netCents)}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="TRY">${fmt(totalCents)}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="TRY">${fmt(totalCents)}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
${items}
</Invoice>`;
}

// UBL XML'i ziple -> base64 + MD5 hash
function zipInvoice(xml) {
  // Basit ZIP: tek dosya (stored, deflate yok - Sovos her ikisini de kabul eder)
  const filename = 'invoice.xml';
  const data = Buffer.from(xml, 'utf-8');
  const crc = crc32(data);
  // Local file header
  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0x0800, 6); // UTF-8 flag
  localHeader.writeUInt16LE(0, 8); // stored (no compression)
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(data.length, 18);
  localHeader.writeUInt32LE(data.length, 22);
  localHeader.writeUInt16LE(Buffer.byteLength(filename), 26);
  localHeader.writeUInt16LE(0, 28);
  // Central directory
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(Buffer.byteLength(filename), 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt16LE(0, 38);
  central.writeUInt32LE(0, 42);
  // End of central directory
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  const centralSize = 46 + Buffer.byteLength(filename);
  const centralOffset = 30 + Buffer.byteLength(filename) + data.length;
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  eocd.writeUInt16LE(0, 20);

  const zip = Buffer.concat([
    localHeader, Buffer.from(filename), data,
    central, Buffer.from(filename),
    eocd,
  ]);
  return {
    zip,
    base64: zip.toString('base64'),
    md5: crypto.createHash('md5').update(zip).digest('hex').toUpperCase(),
  };
}

// CRC32 (ZIP için)
function crc32(buf) {
  let table = crc32._table;
  if (!table) {
    table = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[i] = c;
    }
    crc32._table = table;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// SOAP isteği gönder
function soapPost(endpoint, soapXml, username, password) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const auth = Buffer.from(`${username}:${password}`).toString('base64');
    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'sendInvoice',
        'Authorization': `Basic ${auth}`,
        'Content-Length': Buffer.byteLength(soapXml),
      },
      timeout: 60000,
    };
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(opts, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(new Error('Sovos timeout')); });
    req.on('error', reject);
    req.write(soapXml);
    req.end();
  });
}

// Sipariş kurumsal mı? (e-Fatura) — bireysel ise e-Arşiv
function isCorporateOrder(order) {
  return (order && order.invoice_type === 'kurumsal') || Boolean(order && (order.invoice_vkn || order.invoice_company));
}

// e-Fatura (kurumsal) / e-Arşiv (bireysel) fatura gönder
async function sendEArchiveInvoice(order) {
  const c = cfg();
  if (!isEnabled()) {
    return { ok: false, error: 'sovos_not_configured', message: 'Sovos entegrasyonu yapılandırılmamış (SOVOS_ENABLED=1 ve kimlik bilgileri gerekli)' };
  }
  try {
    const xml = buildUblInvoice(order, c);
    const { base64, md5 } = zipInvoice(xml);
    const fileName = `invoice_${order.id || Date.now()}.zip`;
    const soap = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:inv="http://fitcons.com/earchive/invoice">
  <soapenv:Header/>
  <soapenv:Body>
    <inv:sendInvoiceRequestType>
      <senderID>${escXml(c.senderVkn)}</senderID>
      <receiverID>${escXml(isCorporateOrder(order) ? (order.invoice_vkn || order.customer_tax_no || order.customer_vkn || '1111111111') : (order.invoice_tckn || order.customer_tckn || order.customer_tax_no || '11111111111'))}</receiverID>
      <docType>XML</docType>
      <fileName>${escXml(fileName)}</fileName>
      <hash>${md5}</hash>
      <binaryData>${base64}</binaryData>
      <customizationParams>
        <paramName>BRANCH</paramName>
        <paramValue>${escXml(c.branch)}</paramValue>
      </customizationParams>
      <responsiveOutput><outputType>PDF</outputType></responsiveOutput>
    </inv:sendInvoiceRequestType>
  </soapenv:Body>
</soapenv:Envelope>`;
    const res = await soapPost(c.endpoint, soap, c.username, c.password);
    const body = res.body || '';
    // Basit XML parse: Result, UUID, Detail
    const get = (tag) => {
      const m = body.match(new RegExp(`<${tag}>([^<]*)</${tag}>`, 'i'));
      return m ? m[1] : '';
    };
    const result = get('Result') || get('result');
    const uuid = get('UUID') || get('uuid');
    const detail = get('Detail') || get('detail');
    const invoiceNumber = get('invoiceNumber') || get('InvoiceNumber');
    if (res.status !== 200) {
      return { ok: false, error: 'sovos_http_error', status: res.status, detail: body.slice(0, 500) };
    }
    if (String(result).toUpperCase() === 'SUCCESS') {
      return { ok: true, uuid, invoiceNumber, detail, ubl: xml };
    }
    return { ok: false, error: 'sovos_rejected', result, detail: detail || body.slice(0, 500) };
  } catch (e) {
    return { ok: false, error: 'sovos_error', message: e.message };
  }
}

module.exports = { cfg, isEnabled, buildUblInvoice, zipInvoice, sendEArchiveInvoice };
