// Herkese açık sınırlı kargo takibi: GET /api/tracking/:orderNo
// YALNIZ sipariş no + genel durum + kargo firması + takip no döner.
// İsim, adres, telefon, e-posta gibi kişisel veri ASLA dönmez.
// Kimlik doğrulama gerekmez; numaralandırmaya karşı hız limitlidir.
//
// Davranış:
// 1) Önce DB'deki tracking_number + cargo_company bilgisi alınır.
// 2) Aras Kargo credential'ları yapılandırılmışsa (ARAS_CARGO_* env) ve siparişte
//    takip no varsa, Aras servisinden canlı durum çekilmeye çalışılır.
// 3) Canlı sorgu başarısız olursa (veya yapılandırılmamışsa) DB bilgisine
//    düşülür — yanıt yine de döner, hata verilmez.
const express = require('express');
const { param } = require('express-validator');
const asyncHandler = require('../middleware/asyncHandler');
const { checkValidation } = require('../middleware/validate');
const { trackingLimiter } = require('../middleware/rateLimit');
const arasCargo = require('../services/arasCargo');
const { stageIndex } = require('../orderStages');
const pool = require('../db');

const router = express.Router();

router.get(
  '/:orderNo',
  trackingLimiter,
  param('orderNo').matches(/^CB-\d{4}-\d{6}$/),
  asyncHandler(async (req, res) => {
    if (!checkValidation(req, res)) return;
    const { rows } = await pool.query(
      `SELECT order_no, status, cargo_company, tracking_number, shipped_at, updated_at
       FROM orders WHERE order_no = $1`,
      [req.params.orderNo]
    );
    if (!rows.length) return res.status(404).json({ error: 'order_not_found' });
    const o = rows[0];

    // Canlı durum: yalnızca Aras yapılandırılmışsa ve takip no varsa dene.
    // Başarısızlık sessizce yutulur → DB bilgisi döner.
    let liveStatus = null;
    if (o.tracking_number) {
      liveStatus = await arasCargo.getTrackingStatus(o.tracking_number);
    }

    res.json({
      order_no: o.order_no,
      status: o.status,
      // 6 aşamalı kanonik enum anahtarı — çeviri frontend'de yapılır, API yalnız anahtar döner.
      // stage_index: packing=0 … delivered=5; boru hattı dışı durumlarda (pending/cancelled/refunded) null.
      stage: o.status,
      stage_index: stageIndex(o.status),
      cargo_company: o.cargo_company,
      tracking_number: o.tracking_number,
      shipped_at: o.shipped_at,
      updated_at: o.updated_at,
      live_status: liveStatus, // null ise Aras yapılandırılmamış veya erişilemedi
      live_source: liveStatus ? 'aras' : 'database',
    });
  })
);

module.exports = router;
