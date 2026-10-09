// Sipariş durumları — 6 aşamalı kanonik enum.
// packing → ready → shipped → in_transit → arriving → delivered
// API yalnız İngilizce anahtar döner; Türkçe karşılıklar frontend'de çevrilir:
//   packing: Paketleniyor, ready: Hazırlandı, shipped: Çıkış yapıldı,
//   in_transit: Yolda, arriving: Varmak üzere, delivered: Teslim edildi
const STAGES = ['packing', 'ready', 'shipped', 'in_transit', 'arriving', 'delivered'];

// Boru hattı dışı durumlar: pending (ödeme bekliyor), cancelled, refunded
const PRE_PIPELINE = ['pending'];
const TERMINAL = ['cancelled', 'refunded'];

const ALL_STATUSES = [...PRE_PIPELINE, ...STAGES, ...TERMINAL];

function stageIndex(status) {
  const i = STAGES.indexOf(status);
  return i >= 0 ? i : null;
}

module.exports = { STAGES, PRE_PIPELINE, TERMINAL, ALL_STATUSES, stageIndex };
