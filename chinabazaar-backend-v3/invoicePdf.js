// Fatura PDF üretimi (pdfkit). Sovos'a gönderilen faturanın müşteriye / yöneticiye
// indirilebilir PDF karşılığı. Türkçe karakterler pdfkit Helvetica (WinAnsi) ile desteklenir.
const PDFDocument = require('pdfkit');

function tl(cents) {
  return '₺' + (Math.round(cents || 0) / 100).toFixed(2).replace('.', ',');
}

function fmtDate(d) {
  try {
    return new Date(d).toLocaleDateString('tr-TR', { day: '2-digit', month: '2-digit', year: 'numeric' });
  } catch (_) {
    return '';
  }
}

// orderData: { order_no, customer_name, customer_email, customer_address,
//   invoice_type, invoice_tckn, invoice_vkn, invoice_company, invoice_tax_office,
//   items: [{name, qty, price_cents}], total_cents, vat_cents, created_at }
// invoiceMeta: { invoiceNumber, uuid, scenario }
// sender: { senderName, senderVkn, senderAddress, senderCity, senderTaxOffice }
function generateInvoicePdf(orderData, invoiceMeta, sender) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      const s = sender || {};
      const isCorp = orderData.invoice_type === 'kurumsal';
      const scenario = isCorp ? 'TEMELFATURA (e-Fatura)' : 'EARSIVFATURA (e-Arşiv Fatura)';
      const totalCents = Math.round(orderData.total_cents || 0);
      const vatCents = Math.round(
        orderData.vat_cents != null ? orderData.vat_cents : (totalCents * 20) / 120
      );
      const netCents = totalCents - vatCents;

      // --- Başlık: satıcı ---
      doc.font('Helvetica-Bold').fontSize(18).text(s.senderName || 'ChinaBazaar', { align: 'left' });
      doc.font('Helvetica').fontSize(10).fillColor('#444');
      if (s.senderAddress) doc.text(s.senderAddress);
      if (s.senderCity) doc.text(s.senderCity);
      doc.text('Vergi Dairesi: ' + (s.senderTaxOffice || '—') + '   VKN: ' + (s.senderVkn || '—'));
      doc.moveDown(1);

      // --- Fatura başlığı ---
      doc.fillColor('#000').font('Helvetica-Bold').fontSize(16)
        .text(isCorp ? 'e-FATURA' : 'e-ARŞİV FATURA', { align: 'left' });
      doc.font('Helvetica').fontSize(10).fillColor('#444');
      doc.text('Fatura No: ' + (invoiceMeta.invoiceNumber || '—'));
      doc.text('Senaryo: ' + scenario);
      doc.text('Fatura Tarihi: ' + fmtDate(orderData.created_at || Date.now()));
      doc.text('Sipariş No: ' + (orderData.order_no || '—'));
      if (invoiceMeta.uuid) doc.text('Sovos UUID: ' + invoiceMeta.uuid);
      doc.moveDown(1);

      // --- Alıcı ---
      doc.fillColor('#000').font('Helvetica-Bold').fontSize(12).text('ALICI');
      doc.font('Helvetica').fontSize(10).fillColor('#222');
      doc.text(orderData.customer_name || '—');
      if (orderData.customer_email) doc.text('E-posta: ' + orderData.customer_email);
      if (orderData.customer_address) doc.text('Adres: ' + orderData.customer_address);
      if (isCorp) {
        if (orderData.invoice_company) doc.text('Firma: ' + orderData.invoice_company);
        if (orderData.invoice_vkn) doc.text('VKN: ' + orderData.invoice_vkn);
        if (orderData.invoice_tax_office) doc.text('Vergi Dairesi: ' + orderData.invoice_tax_office);
      } else if (orderData.invoice_tckn) {
        doc.text('TCKN: ' + orderData.invoice_tckn);
      }
      doc.moveDown(1);

      // --- Kalemler ---
      const startY = doc.y;
      const colX = { no: 50, name: 80, qty: 330, unit: 380, total: 460 };
      doc.font('Helvetica-Bold').fontSize(10).fillColor('#000');
      doc.text('#', colX.no, startY);
      doc.text('Ürün', colX.name, startY);
      doc.text('Adet', colX.qty, startY);
      doc.text('Birim', colX.unit, startY);
      doc.text('Tutar', colX.total, startY, { align: 'right', width: 85 });
      doc.moveTo(50, startY + 16).lineTo(545, startY + 16).stroke();
      let y = startY + 24;
      doc.font('Helvetica').fontSize(10);
      (orderData.items || []).forEach((it, i) => {
        const qty = it.qty || it.quantity || 1;
        const unit = Math.round(it.price_cents || it.unit_price_cents || 0);
        const line = unit * qty;
        doc.text(String(i + 1), colX.no, y);
        doc.text(String(it.name || 'Ürün').slice(0, 52), colX.name, y, { width: 240 });
        doc.text(String(qty), colX.qty, y);
        doc.text(tl(unit), colX.unit, y);
        doc.text(tl(line), colX.total, y, { align: 'right', width: 85 });
        y += 20;
        if (y > 720) { doc.addPage(); y = 60; }
      });
      doc.moveTo(50, y + 4).lineTo(545, y + 4).stroke();
      y += 14;

      // --- Toplamlar ---
      doc.font('Helvetica').fontSize(11);
      doc.text('Ara Toplam (KDV Hariç):', 300, y, { width: 160, align: 'right' });
      doc.text(tl(netCents), colX.total, y, { width: 85, align: 'right' });
      y += 20;
      doc.text('KDV (%20):', 300, y, { width: 160, align: 'right' });
      doc.text(tl(vatCents), colX.total, y, { width: 85, align: 'right' });
      y += 20;
      doc.font('Helvetica-Bold').fontSize(13);
      doc.text('GENEL TOPLAM:', 300, y, { width: 160, align: 'right' });
      doc.text(tl(totalCents), colX.total, y, { width: 85, align: 'right' });
      y += 40;

      // --- Alt bilgi ---
      doc.font('Helvetica').fontSize(9).fillColor('#666');
      doc.text('Bu fatura ChinaBazaar tarafından elektronik olarak üretilmiştir. Sovos Bulut üzerinden gönderilmiştir.');
      doc.text('Fatura ile ilgili sorularınız için info@chinabazaar.com adresine yazabilirsiniz.');

      doc.end();
    } catch (e) {
      reject(e);
    }
  });
}

module.exports = { generateInvoicePdf };
