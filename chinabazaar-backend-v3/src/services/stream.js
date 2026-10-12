// Cloudflare Stream istemcisi — ürün videoları.
// API token YALNIZCA sunucuda tutulur; tarayıcıya asla verilmez.
// Yükleme akışı: backend tek kullanımlık "direct upload" URL'si üretir,
// video dosyası tarayıcıdan DOĞRUDAN Cloudflare'e gider (Railway üzerinden geçmez).
const cfg = require('../config');

const API_BASE = 'https://api.cloudflare.com/client/v4';

function enabled() {
  return Boolean(cfg.stream.accountId && cfg.stream.apiToken);
}

async function call(path, opts = {}) {
  const res = await fetch(`${API_BASE}/accounts/${cfg.stream.accountId}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${cfg.stream.apiToken}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* yoksay */
  }
  if (!res.ok || !data || data.success !== true) {
    const msg =
      (data && data.errors && data.errors.map((e) => e.message).join('; ')) ||
      `stream_http_${res.status}`;
    const err = new Error(msg);
    err.status = 502;
    throw err;
  }
  return data.result;
}

// Token geçerlilik kontrolü (tanı amaçlı).
async function verifyToken() {
  const res = await fetch(`${API_BASE}/user/tokens/verify`, {
    headers: { Authorization: `Bearer ${cfg.stream.apiToken}` },
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* yoksay */
  }
  return {
    valid: !!(data && data.success),
    status: (data && data.result && data.result.status) || null,
  };
}

// Tek kullanımlık yükleme URL'si (30 dk geçerli, en fazla 10 dk video).
async function createDirectUpload() {
  const result = await call('/stream/direct_upload', {
    method: 'POST',
    body: JSON.stringify({
      maxDurationSeconds: 600,
      expiry: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    }),
  });
  return { uploadURL: result.uploadURL, uid: result.uid };
}

async function getVideo(uid) {
  return call(`/stream/${encodeURIComponent(uid)}`);
}

// HLS oynatma adresi (Safari/iOS doğal; Chrome/Firefox için hls.js gerekir).
function playbackUrl(uid) {
  return `https://videodelivery.net/${uid}/manifest/video.m3u8`;
}

// MP4 doğrudan indirme adresi (iOS uyumluluğu için; downloads etkin olmalı).
function mp4Url(uid) {
  return `https://videodelivery.net/${uid}/downloads/default.mp4`;
}

// Bir video için MP4 indirmeyi etkinleştir (Cloudflare API).
async function enableMp4Download(uid) {
  if (!enabled()) return false;
  try {
    await call(`/stream/${uid}/downloads`, { method: 'POST' });
    return true;
  } catch (e) { return false; }
}

// Debug versiyonu - hata detayını döner
async function enableMp4DownloadDebug(uid) {
  if (!enabled()) return { ok: false, error: 'stream-not-configured' };
  try {
    await call(`/stream/${uid}/downloads`, { method: 'POST' });
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
}

function thumbnailUrl(uid) {
  return `https://videodelivery.net/${uid}/thumbnails/thumbnail.jpg`;
}

module.exports = {
  enabled,
  verifyToken,
  createDirectUpload,
  getVideo,
  playbackUrl,
  thumbnailUrl,
  mp4Url,
  enableMp4Download,
  enableMp4DownloadDebug
};
