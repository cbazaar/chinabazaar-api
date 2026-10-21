// POST /api/translate — canlı çeviri ucu (CBAi + CBChat + CBDestek ön yüzleri).
//
// Kimlik: mevcut sohbet jetonlarından HERHANGİ biri (kullanıcı / fabrika /
// admin / master) — hepsi aynı JWT şemasıyla requireAuth'tan geçer.
// Govde: { text, target, source? } -> { ok:true, translated, source, target, provider }
// Metin sınırı 2000 karakter. Sağlayıcıların tamamı düşerse { ok:false }
// döner; sohbet akışı bu uca bağımlı değildir ve bloklanmaz.

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { translateLimiter } = require('../middleware/rateLimit');
const asyncHandler = require('../middleware/asyncHandler');
const translator = require('../services/translator');

router.post('/', requireAuth, translateLimiter, asyncHandler(async (req, res) => {
  const b = req.body || {};
  const text = typeof b.text === 'string' ? b.text : '';
  if (!text.trim()) return res.status(400).json({ ok: false, error: 'empty' });
  if (text.length > translator.MAX_TEXT) return res.status(400).json({ ok: false, error: 'too_long' });
  const target = translator.normalizeLang(b.target);
  if (!target) return res.status(400).json({ ok: false, error: 'target_required' });
  const source = b.source !== undefined ? translator.normalizeLang(b.source) : null;
  if (b.source !== undefined && b.source !== null && String(b.source).trim() !== '' && !source) {
    return res.status(400).json({ ok: false, error: 'invalid_source' });
  }
  const r = await translator.translate(text, { target, source });
  if (!r.ok) return res.status(502).json({ ok: false, error: r.error || 'translate_failed', source: r.source, target: r.target });
  res.json({ ok: true, translated: r.translated, source: r.source, target: r.target, provider: r.provider });
}));

module.exports = router;
