// Sovos e-Arşiv / e-Fatura entegrasyonu (admin)
// POST /api/admin/sovos/send-invoice { order_id } — sipariş için fatura gönder + PDF üret + müşteriye e-posta ile gönder
// POST /api/admin/sovos/resend-email { order_id } — faturayı müşteriye e-posta ile tekrar gönder
// GET  /api/admin/sovos/status — Sovos yapılandırma durumu
// GET  /api/admin/sovos/invoice-pdf/:order_id — fatura PDF indir (admin veya sipariş sahibi müşteri)
const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const sovos = require('../services/sovos');
const pool = require('../db');
const { generateInvoicePdf } = require('../services/invoicePdf');
const mailer = require('../services/mailer');

async function ensureInvoicesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invoices (
      id SERIAL PRIMARY KEY,
      order_id TEXT UNIQUE NOT NULL,
      user_id INTEGER,
      invoice_number TEXT,
      uuid TEXT,
      invoice_type TEXT DEFAULT 'bireysel',
      status TEXT DEFAULT 'draft',
      pdf BYTEA,
      emailed_at TIMESTAMPTZ,
      sent_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);
}

function buildOrderData(order, items) {
  return {
    id: order.id,
    order_no: order.order_no,
    customer_name: order.customer_name,
    customer_email: order.customer_email,
    customer_tax_no: order.customer_tax_no,
    customer_address: order.shipping_address || order.customer_address,
    invoice_type: order.invoice_type || 'bireysel',
    invoice_tckn: order.invoice_tckn || null,
    invoice_vkn: order.invoice_vkn || null,
    invoice_company: order.invoice_company || null,
    invoice_tax_office: order.invoice_tax_office || null,
    items: items.map((it) => ({
      name: it.product_name || it.name,
      qty: it.quantity || 1,
      price_cents: it.unit_price_cents || it.price_cents || 0,
    })),
    total_cents: order.total_cents,
    vat_cents: order.vat_cents,
    created_at: order.created_at,
  };
}

// Siparişin fatura PDF'ini döner: önce kayıtlı PDF, yoksa sipariş verisinden yeniden üret.
async function getInvoicePdfBuffer(order) {
  let pdfBuffer = null;
  try {
    await ensureInvoicesTable();
    const { rows } = await pool.query('SELECT pdf FROM invoices WHERE order_id=$1', [String(order.id)]);
    if (rows.length && rows[0].pdf) pdfBuffer = rows[0].pdf;
  } catch (_) { /* invoices tablosu yoksa yeniden üret */ }
  if (!pdfBuffer) {
    const { rows: items } = await pool.query('SELECT * FROM order_items WHERE order_id=$1', [order.id]);
    const orderData = buildOrderData(order, items);
    pdfBuffer = await generateInvoicePdf(
      orderData,
      { invoiceNumber: order.sovos_invoice_no, uuid: order.sovos_uuid },
      sovos.cfg()
    );
  }
  return pdfBuffer;
}

async function emailInvoicePdf(order, pdfBuffer) {
  const { rows: items } = await pool.query('SELECT * FROM order_items WHERE order_id=$1', [order.id]);
  const orderData = buildOrderData(order, items);
  const mail = mailer.invoiceEmail(orderData, order.sovos_invoice_no);
  const fname = 'fatura-' + (order.order_no || order.sovos_invoice_no || order.id) + '.pdf';
  await mailer.sendMail(order.customer_email, {
    subject: mail.subject,
    text: mail.text,
    html: mail.html,
    attachments: [{ filename: fname, content: pdfBuffer }],
  });
  try {
    await pool.query(`UPDATE invoices SET emailed_at=now() WHERE order_id=$1`, [String(order.id)]);
  } catch (_) { /* önemsiz */ }
}

router.get('/status', requireAuth, requireAdmin, async (_req, res) => {
  const c = sovos.cfg();
  res.json({
    enabled: sovos.isEnabled(),
    endpoint_set: Boolean(c.endpoint),
    username_set: Boolean(c.username),
    sender_vkn_set: Boolean(c.senderVkn),
    sender_name: c.senderName || null,
    branch: c.branch,
    note: sovos.isEnabled() ? 'Sovos hazır' : 'SOVOS_ENABLED=1 ve kimlik bilgileri gerekli (Railway değişkenleri)',
  });
});

router.post('/send-invoice', requireAuth, requireAdmin, async (req, res) => {
  const { order_id } = req.body || {};
  if (!order_id) return res.status(400).json({ error: 'order_id_required' });
  if (!sovos.isEnabled()) {
    return res.status(503).json({ error: 'sovos_not_configured', message: 'Sovos entegrasyonu yapılandırılmamış' });
  }
  try {
    const { rows: orders } = await pool.query('SELECT * FROM orders WHERE id=$1', [order_id]);
    if (!orders.length) return res.status(404).json({ error: 'order_not_found' });
    const order = orders[0];
    const { rows: items } = await pool.query('SELECT * FROM order_items WHERE order_id=$1', [order_id]);
    const orderData = buildOrderData(order, items);

    const result = await sovos.sendEArchiveInvoice(orderData);
    if (!result.ok) {
      return res.status(502).json({ ok: false, error: result.error, detail: result.detail || result.message });
    }

    // --- Fatura PDF üret (e-posta eki + indirilebilir kopya) ---
    const sender = sovos.cfg();
    const invoiceMeta = { invoiceNumber: result.invoiceNumber, uuid: result.uuid };
    let pdfBuffer = null;
    let pdfReady = false;
    try {
      pdfBuffer = await generateInvoicePdf(orderData, invoiceMeta, sender);
      pdfReady = true;
    } catch (e) {
      console.error('[sovos] PDF üretilemedi:', e.message);
    }

    // --- Fatura kaydını sakla (invoices tablosu) ---
    try {
      await ensureInvoicesTable();
      await pool.query(
        `INSERT INTO invoices (order_id, user_id, invoice_number, uuid, invoice_type, status, pdf, sent_at)
         VALUES ($1,$2,$3,$4,$5,'sent',$6,now())
         ON CONFLICT (order_id) DO UPDATE SET
           invoice_number=EXCLUDED.invoice_number, uuid=EXCLUDED.uuid,
           invoice_type=EXCLUDED.invoice_type, status='sent', pdf=EXCLUDED.pdf, sent_at=now()`,
        [String(order_id), order.user_id || null, result.invoiceNumber, result.uuid, orderData.invoice_type, pdfBuffer]
      );
    } catch (e) {
      console.error('[sovos] invoices kaydı yazılamadı:', e.message);
    }

    // --- Siparişi güncelle (frontend'de "Gönderildi" gösterimi için) ---
    try {
      await pool.query(
        `UPDATE orders SET sovos_uuid=$2, sovos_invoice_no=$3, invoice_sent=true WHERE id=$1`,
        [order_id, result.uuid, result.invoiceNumber]
      );
    } catch (_) { /* orders sovos alanları yoksa sorun değil */ }

    // --- Faturayı müşteriye e-posta ile gönder (en iyi çaba — e-posta başarısız olsa bile fatura gönderilmiş sayılır) ---
    let emailed = false;
    let emailError = null;
    if (order.customer_email && pdfBuffer) {
      try {
        if (!mailer.isEnabled()) {
          emailError = 'email_not_configured';
        } else {
          await emailInvoicePdf(order, pdfBuffer);
          emailed = true;
        }
      } catch (e) {
        emailError = e.message;
        console.error('[sovos] fatura e-postası gönderilemedi:', e.message);
      }
    } else if (!order.customer_email) {
      emailError = 'no_customer_email';
    } else if (!pdfBuffer) {
      emailError = 'pdf_not_generated';
    }

    return res.json({
      ok: true,
      uuid: result.uuid,
      invoiceNumber: result.invoiceNumber,
      detail: result.detail,
      pdf_ready: pdfReady,
      emailed,
      email_error: emailError,
    });
  } catch (e) {
    console.error('[sovos] send-invoice hatası:', e.message);
    return res.status(500).json({ error: 'sovos_error', message: e.message });
  }
});

// Faturayı müşteriye e-posta ile tekrar gönder (admin).
router.post('/resend-email', requireAuth, requireAdmin, async (req, res) => {
  const { order_id } = req.body || {};
  if (!order_id) return res.status(400).json({ error: 'order_id_required' });
  try {
    const { rows: orders } = await pool.query('SELECT * FROM orders WHERE id=$1', [order_id]);
    if (!orders.length) return res.status(404).json({ error: 'order_not_found' });
    const order = orders[0];
    if (!order.invoice_sent && !order.sovos_uuid) {
      return res.status(404).json({ error: 'invoice_not_found', message: 'Bu sipariş için henüz fatura gönderilmemiş' });
    }
    if (!order.customer_email) {
      return res.status(400).json({ error: 'no_customer_email', message: 'Siparişte müşteri e-postası yok' });
    }
    if (!mailer.isEnabled()) {
      return res.status(503).json({ error: 'email_not_configured', message: 'E-posta gönderimi yapılandırılmamış (Railway SMTP/Resend)' });
    }
    const pdfBuffer = await getInvoicePdfBuffer(order);
    await emailInvoicePdf(order, pdfBuffer);
    return res.json({ ok: true, emailed: true, to: order.customer_email });
  } catch (e) {
    console.error('[sovos] resend-email hatası:', e.message);
    return res.status(500).json({ error: 'sovos_error', message: e.message });
  }
});

// Fatura PDF indir — admin veya siparişin sahibi müşteri.
router.get('/invoice-pdf/:order_id', requireAuth, async (req, res) => {
  const orderId = req.params.order_id;
  try {
    const { rows: orders } = await pool.query('SELECT * FROM orders WHERE id=$1', [orderId]);
    if (!orders.length) return res.status(404).json({ error: 'order_not_found' });
    const order = orders[0];
    // Yetki: admin veya sipariş sahibi
    let isAdmin = false;
    try {
      const { rows: me } = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.id]);
      isAdmin = Boolean(me[0] && me[0].is_admin);
    } catch (_) { /* kullanıcı bulunamadı */ }
    if (!isAdmin && String(order.user_id) !== String(req.user.id)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    if (!order.invoice_sent && !order.sovos_uuid) {
      return res.status(404).json({ error: 'invoice_not_found', message: 'Bu sipariş için henüz fatura gönderilmemiş' });
    }

    const pdfBuffer = await getInvoicePdfBuffer(order);
    const fname = 'fatura-' + (order.order_no || order.sovos_invoice_no || orderId) + '.pdf';
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
    return res.send(pdfBuffer);
  } catch (e) {
    console.error('[sovos] invoice-pdf hatası:', e.message);
    // 2026-10-21 F5: ham hata metni istemciye sizdirilmaz (detay sunucu logunda kalir).
    return res.status(500).json({ error: 'sovos_error', message: 'Fatura PDF oluşturulamadı.' });
  }
});

module.exports = router;
