// Müşteri canlı destek mesajlaşması (giriş gerekli)
const express = require('express');
const router = express.Router();
const pool = require('../db');
const { requireAuth } = require('../middleware/auth');
const asyncHandler = require('../middleware/asyncHandler');

router.use(requireAuth);

async function myConv(userId) {
  let r = await pool.query(`SELECT * FROM chat_conversations WHERE user_id=$1 AND status='open' ORDER BY id DESC LIMIT 1`, [userId]);
  if (r.rows.length) return r.rows[0];
  r = await pool.query(`INSERT INTO chat_conversations (user_id) VALUES ($1) RETURNING *`, [userId]);
  return r.rows[0];
}

// Müşteri mesaj gönderir
router.post('/send', asyncHandler(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 2000);
  if (!body) return res.status(400).json({ ok: false, error: 'empty' });
  const conv = await myConv(req.user.id);
  const m = await pool.query(
    `INSERT INTO chat_messages (conversation_id, sender, body, read_by_customer) VALUES ($1,'customer',$2,true) RETURNING *`,
    [conv.id, body]);
  await pool.query(`UPDATE chat_conversations SET last_message_at=now() WHERE id=$1`, [conv.id]);
  res.json({ ok: true, message: m.rows[0] });
}));

// Müşterinin mesajları
router.get('/messages', asyncHandler(async (req, res) => {
  const conv = await myConv(req.user.id);
  const r = await pool.query(`SELECT * FROM chat_messages WHERE conversation_id=$1 ORDER BY id ASC LIMIT 200`, [conv.id]);
  await pool.query(`UPDATE chat_messages SET read_by_customer=true WHERE conversation_id=$1 AND sender='admin'`, [conv.id]);
  res.json({ ok: true, conversation_id: conv.id, status: conv.status, messages: r.rows });
}));

// Okunmamış admin cevabı var mı
router.get('/unread', asyncHandler(async (req, res) => {
  const conv = await myConv(req.user.id);
  const r = await pool.query(`SELECT count(*)::int AS c FROM chat_messages WHERE conversation_id=$1 AND sender='admin' AND NOT read_by_customer`, [conv.id]);
  res.json({ ok: true, unread: r.rows[0].c });
}));

module.exports = router;
