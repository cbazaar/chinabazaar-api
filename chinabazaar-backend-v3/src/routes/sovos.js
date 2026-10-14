// Sovos e-Arşiv Fatura entegrasyonu (admin)
// POST /api/admin/sovos/send-invoice { order_id } — sipariş için e-Arşiv fatura gönder
// GET  /api/admin/sovos/status — Sovos yapılandırma durumu
const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const sovos = require('../services/sovos');
const { pool } = require('../db');

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
    // Siparişi ve kalemleri al
    const { rows: orders } = await pool.query(
      'SELECT * FROM orders WHERE id=$1', [order_id]
    );
    if (!orders.length) return res.status(404).json({ error: 'order_not_found' });
    const order = orders[0];
    const { rows: items } = await pool.query(
      'SELECT * FROM order_items WHERE order_id=$1', [order_id]
    );
    const orderData = {
      id: order.id,
      order_no: order.order_no,
      customer_name: order.customer_name,
      customer_email: order.customer_email,
      customer_tax_no: order.customer_tax_no,
      customer_address: order.shipping_address || order.customer_address,
      items: items.map((it) => ({
        name: it.product_name || it.name,
        qty: it.quantity || 1,
        price_cents: it.unit_price_cents || it.price_cents || 0,
      })),
      total_cents: order.total_cents,
      vat_cents: order.vat_cents,
      created_at: order.created_at,
    };
    const result = await sovos.sendEArchiveInvoice(orderData);
    if (result.ok) {
      // Fatura kaydını güncelle
      try {
        await pool.query(
          `UPDATE invoices SET status='sent', sovos_uuid=$2, sovos_invoice_no=$3, sent_at=now() WHERE order_id=$1`,
          [order_id, result.uuid, result.invoiceNumber]
        );
      } catch (_) { /* invoices tablosu yoksa sorun değil */ }
      return res.json({ ok: true, uuid: result.uuid, invoiceNumber: result.invoiceNumber, detail: result.detail });
    }
    return res.status(502).json({ ok: false, error: result.error, detail: result.detail || result.message });
  } catch (e) {
    console.error('[sovos] send-invoice hatası:', e.message);
    return res.status(500).json({ error: 'sovos_error', message: e.message });
  }
});

module.exports = router;
