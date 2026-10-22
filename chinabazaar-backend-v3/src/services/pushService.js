// Push bildirim servisi (CBOs-push hazırlığı) — kilit ekranı bildirimleri.
//
// İki kanal:
//  1) Expo Push (mobil uygulamalar): exp.host API'sine fetch ile gönderim.
//     Başlık her zaman 'chinabazaar.com'; gövde '<kanal>: <önizleme>';
//     data.url bildirime dokununca uygulamanın WebView'de açacağı adres.
//  2) Web Push (siteler): 'web-push' paketiyle, VAPID anahtarları env'den
//     okunur (VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT).
//     Anahtarlar env'de YOKSA web push sessizce atlanır; anahtar üretimi
//     burada ASLA yapılmaz (dağıtım anında üretilip Railway'e girilir).
//
// HATA KURALI (kesin): Bu servisin hiçbir fonksiyonu fırlatmaz. Bildirim
// gönderimi mesaj akışını asla bloklamaz; çağıran taraf fire-and-forget
// kullanır, buradaki tüm yollar içten try/catch ile korunur.

const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';
const PUSH_TITLE = 'chinabazaar.com';
const PREVIEW_MAX = 120;

let schemaReady = false;
let webPushWarned = false;

async function ensurePushSchema(pool) {
  if (schemaReady) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_devices (
      id SERIAL PRIMARY KEY,
      token TEXT NOT NULL UNIQUE,
      kind TEXT NOT NULL DEFAULT 'expo',
      platform TEXT,
      app TEXT,
      owner_kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      subscription JSONB,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_push_devices_owner ON push_devices (owner_kind, owner_id)`);
  schemaReady = true;
}

function cleanPreview(text, kind) {
  const t = String(text || '').replace(/\s+/g, ' ').trim();
  if (t) return t.slice(0, PREVIEW_MAX);
  if (kind === 'image') return 'Fotoğraf gönderdi';
  if (kind === 'video') return 'Video gönderdi';
  if (kind === 'file') return 'Dosya gönderdi';
  return 'Yeni mesaj';
}

// Cihaz kaydı (upsert). token: Expo tokenı ya da web aboneliği endpoint'i.
async function upsertDevice(pool, d) {
  await ensurePushSchema(pool);
  const { rows } = await pool.query(
    `INSERT INTO push_devices (token, kind, platform, app, owner_kind, owner_id, subscription)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (token) DO UPDATE SET kind = EXCLUDED.kind, platform = EXCLUDED.platform,
       app = EXCLUDED.app, owner_kind = EXCLUDED.owner_kind, owner_id = EXCLUDED.owner_id,
       subscription = EXCLUDED.subscription, updated_at = now()
     RETURNING id`,
    [d.token, d.kind || 'expo', d.platform || null, d.app || null, d.ownerKind, String(d.ownerId),
     d.subscription ? JSON.stringify(d.subscription) : null]
  );
  return rows[0] && rows[0].id;
}

async function removeDevice(pool, token) {
  await ensurePushSchema(pool);
  await pool.query(`DELETE FROM push_devices WHERE token = $1`, [token]);
}

async function listOwnerDevices(pool, ownerKind, ownerId) {
  await ensurePushSchema(pool);
  const { rows } = await pool.query(
    `SELECT id, token, kind, platform, app, subscription FROM push_devices WHERE owner_kind = $1 AND owner_id = $2`,
    [ownerKind, String(ownerId)]
  );
  return rows;
}

async function listAllDevices(pool, limit) {
  await ensurePushSchema(pool);
  const { rows } = await pool.query(
    `SELECT id, kind, platform, app, owner_kind, owner_id, created_at, updated_at
     FROM push_devices ORDER BY updated_at DESC LIMIT $1`,
    [Math.min(Math.max(parseInt(limit, 10) || 200, 1), 1000)]
  );
  return rows;
}

// --- Expo gönderimi -------------------------------------------------------
// Dönüş: { sent, deadTokens[] } — DeviceNotRegistered jetonları temizlenir.
async function sendExpoBatch(messages) {
  const res = await fetch(EXPO_PUSH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(messages),
  });
  const json = await res.json().catch(() => null);
  const dead = [];
  let sent = 0;
  const tickets = json && Array.isArray(json.data) ? json.data : [];
  tickets.forEach((t, i) => {
    if (t && t.status === 'ok') sent += 1;
    else if (t && t.details && t.details.error === 'DeviceNotRegistered' && messages[i]) dead.push(messages[i].to);
  });
  return { sent, deadTokens: dead };
}

// --- Web Push gönderimi ---------------------------------------------------
function getWebPush() {
  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'mailto:info@chinabazaar.com';
  if (!pub || !priv) return null; // VAPID yoksa web push sessizce atlanır
  let webpush;
  try {
    webpush = require('web-push');
  } catch (e) {
    if (!webPushWarned) {
      webPushWarned = true;
      console.warn('[push] web-push paketi kurulu değil — web push atlandı.');
    }
    return null;
  }
  try {
    webpush.setVapidDetails(subject, pub, priv);
  } catch (e) {
    console.error('[push] VAPID ayar hatası:', e.message);
    return null;
  }
  return webpush;
}

// Ana giriş: bir sahibe (user/factory/admin) bildirim gönderir.
// opts: { channel, preview, kind, url } — ASLA fırlatmaz.
async function notifyOwner(pool, ownerKind, ownerId, opts) {
  const out = { sent: 0, pruned: 0, skipped: 0 };
  try {
    const devices = await listOwnerDevices(pool, ownerKind, ownerId);
    if (!devices.length) return out;
    const body = `${opts.channel || 'Mesaj'}: ${cleanPreview(opts.preview, opts.kind)}`;
    const url = opts.url || 'https://chinabazaar.com';

    const expoDevices = devices.filter((d) => d.kind === 'expo');
    if (expoDevices.length) {
      const messages = expoDevices.map((d) => ({
        to: d.token,
        title: PUSH_TITLE,
        body,
        data: { url, channel: opts.channel || null },
        sound: 'default',
        priority: 'high',
      }));
      for (let i = 0; i < messages.length; i += 100) {
        try {
          const r = await sendExpoBatch(messages.slice(i, i + 100));
          out.sent += r.sent;
          for (const dead of r.deadTokens) {
            try { await removeDevice(pool, dead); out.pruned += 1; } catch (e) { /* yoksay */ }
          }
        } catch (e) {
          console.error('[push] Expo gönderim hatası:', e.message);
        }
      }
    }

    const webDevices = devices.filter((d) => d.kind === 'web' && d.subscription);
    if (webDevices.length) {
      const webpush = getWebPush();
      if (!webpush) out.skipped += webDevices.length;
      else {
        const payload = JSON.stringify({ title: PUSH_TITLE, body, url, channel: opts.channel || null });
        for (const d of webDevices) {
          try {
            const sub = typeof d.subscription === 'string' ? JSON.parse(d.subscription) : d.subscription;
            await webpush.sendNotification(sub, payload);
            out.sent += 1;
          } catch (e) {
            if (e && (e.statusCode === 404 || e.statusCode === 410)) {
              try { await removeDevice(pool, d.token); out.pruned += 1; } catch (err) { /* yoksay */ }
            } else {
              console.error('[push] Web push gönderim hatası:', e && e.message ? e.message : e);
            }
          }
        }
      }
    }
  } catch (e) {
    console.error('[push] notifyOwner hatası:', e && e.message ? e.message : e);
  }
  return out;
}

function notifyUser(pool, userId, opts) { return notifyOwner(pool, 'user', userId, opts); }
function notifyFactory(pool, factoryId, opts) { return notifyOwner(pool, 'factory', factoryId, opts); }
function notifyAdmins(pool, opts) { return notifyOwner(pool, 'admin', 'admin', opts); }

module.exports = {
  ensurePushSchema,
  upsertDevice,
  removeDevice,
  listOwnerDevices,
  listAllDevices,
  notifyOwner,
  notifyUser,
  notifyFactory,
  notifyAdmins,
  cleanPreview,
  PUSH_TITLE,
  _getWebPush: getWebPush,
};
