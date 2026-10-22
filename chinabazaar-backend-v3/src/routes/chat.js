// Müşteri canlı destek mesajlaşması (giriş gerekli)
const express = require('express');
const router = express.Router();
const pool = require('../db');
const { requireAuth } = require('../middleware/auth');
const asyncHandler = require('../middleware/asyncHandler');
const translator = require('../services/translator');
const moderation = require('../utils/moderation'); // CBOs27.3: içerik denetimi + otomatik engel

router.use(requireAuth);

async function myConv(userId) {
  let r = await pool.query(`SELECT * FROM chat_conversations WHERE user_id=$1 AND status='open' ORDER BY id DESC LIMIT 1`, [userId]);
  if (r.rows.length) return r.rows[0];
  r = await pool.query(`INSERT INTO chat_conversations (user_id) VALUES ($1) RETURNING *`, [userId]);
  return r.rows[0];
}

// Müşteri mesaj gönderir — gövde ayrıca {translated_text, source_lang,
// target_lang} (istemci çevirisi) ya da {translate_to} (sunucu çevirisi)
// taşıyabilir; çeviri alanları RETURNING * ile yanıta aynen eklenir.
// CBOs27.3: gönderim öncesi içerik denetimi — erotik/taciz içerik 422 ile
// reddedilir, ihlal sayacı işlenir ve hesap ANINDA otomatik engellenir.
router.post('/send', asyncHandler(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ ok: false, error: 'empty' });
  const mod = moderation.checkTexts([body, req.body.translated_text]);
  if (mod.blocked) {
    await moderation.registerViolation(pool, { actorKind: 'user', actorId: req.user.id, ip: req.ip, category: mod.category, surface: 'shop_chat' });
    return res.status(422).json({ ok: false, error: 'content_blocked', category: mod.category });
  }
  await translator.ensureSchema();
  const tr = await translator.resolveMessageTranslation(body, req.body);
  const conv = await myConv(req.user.id);
  const m = await pool.query(
    `INSERT INTO chat_messages (conversation_id, sender, body, read_by_customer, translated_text, source_lang, target_lang) VALUES ($1,'customer',$2,true,$3,$4,$5) RETURNING *`,
    [conv.id, body, tr.translated_text, tr.source_lang, tr.target_lang]);
  await pool.query(`UPDATE chat_conversations SET last_message_at=now() WHERE id=$1`, [conv.id]);
  res.json({ ok: true, message: m.rows[0] });
}));

// CBOs27.3 — POST /api/chat/report
// a) Şikayet: { message_id?, reason } -> security_events 'chat_report'.
//    message_id kullanıcının kendi konuşmasındaysa doğrulanır; değilse de
//    kayıt düşülür (varlık bilgisi sızdırılmaz).
// b) İstemci ihlal bildirimi: { type: 'violation' } -> yalnizca gönderenin
//    KENDİ hesabına işlenir (jeton sahibi; gövdedeki kullanıcı alanı yok
//    sayılır — başkasını engellemek için KULLANILAMAZ). Son 24 saatte 3
//    istemci bildirimi otomatik engel doğurur.
router.post('/report', asyncHandler(async (req, res) => {
  const b = req.body || {};
  if (b.type === 'violation') {
    const r = await moderation.registerClientViolation(pool, { userId: req.user.id, ip: req.ip });
    return res.json({ ok: true, blocked: r.blockedNow });
  }
  const messageId = b.message_id != null && String(b.message_id).trim() !== '' ? String(b.message_id).trim().slice(0, 64) : null;
  const reason = typeof b.reason === 'string' ? b.reason.trim().slice(0, 500) : '';
  let verified = false;
  if (messageId && /^\d+$/.test(messageId)) {
    const chk = await pool.query(
      `SELECT m.id FROM chat_messages m JOIN chat_conversations c ON c.id = m.conversation_id WHERE m.id = $1 AND c.user_id = $2 LIMIT 1`,
      [parseInt(messageId, 10), req.user.id]
    );
    verified = chk.rows.length > 0;
  }
  await moderation.logSecurityEvent(pool, {
    type: 'chat_report', userId: req.user.id, ip: req.ip,
    detail: { message_id: messageId, reason: reason || null, verified },
  });
  res.json({ ok: true });
}));

// Müşterinin mesajları (?conversation_id ile geçmiş sohbet de okunabilir)
router.get('/messages', asyncHandler(async (req, res) => {
  let conv;
  const cid = parseInt(req.query.conversation_id, 10);
  if (cid) {
    const chk = await pool.query(`SELECT * FROM chat_conversations WHERE id=$1 AND user_id=$2`, [cid, req.user.id]);
    if (!chk.rows.length) return res.status(404).json({ ok: false, error: 'not_found' });
    conv = chk.rows[0];
  } else {
    conv = await myConv(req.user.id);
  }
  const r = await pool.query(`SELECT * FROM chat_messages WHERE conversation_id=$1 ORDER BY id ASC LIMIT 200`, [conv.id]);
  await pool.query(`UPDATE chat_messages SET read_by_customer=true WHERE conversation_id=$1 AND sender='admin'`, [conv.id]);
  res.json({ ok: true, conversation_id: conv.id, status: conv.status, messages: r.rows });
}));

// Geçmiş konuşmalar
router.get('/history', asyncHandler(async (req, res) => {
  const r = await pool.query(
    `SELECT c.*, (SELECT body FROM chat_messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_body,
     (SELECT count(*)::int FROM chat_messages m WHERE m.conversation_id=c.id) AS msg_count
     FROM chat_conversations c WHERE c.user_id=$1 ORDER BY c.last_message_at DESC LIMIT 20`, [req.user.id]);
  res.json({ ok: true, items: r.rows });
}));

// Okunmamış admin cevabı var mı
router.get('/unread', asyncHandler(async (req, res) => {
  const conv = await myConv(req.user.id);
  const r = await pool.query(`SELECT count(*)::int AS c FROM chat_messages WHERE conversation_id=$1 AND sender='admin' AND NOT read_by_customer`, [conv.id]);
  res.json({ ok: true, unread: r.rows[0].c });
}));

module.exports = router;
