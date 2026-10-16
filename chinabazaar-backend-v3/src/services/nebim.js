// Nebim V3 Integrator REST istemcisi (v610).
// Nebim sunucusundaki IIS Integrator Web Servisine HTTP ile baglanir:
//   POST {api_url}/IntegratorService/Connect  {DatabaseName, UserGroupCode, UserName, Password} -> {Token}
//   POST {api_url}/IntegratorService/GetUserInfo  (Token basligi) -> kullanici bilgisi (baglanti dogrulama)
//   POST {api_url}/IntegratorService/Post  (Token basligi) + model JSON -> fis olusturur
// Ayarlar settings tablosundan okunur (admin paneli > Sistem Ayarlari > Muhasebe Yazilimlari > Nebim).
// Token modu gerekir: Nebim IIS tarafinda "Oturum Durumu" Kapali (Off) olmalidir.
// Fatura, urun barkoduyla gonderilir (InvoiceR Lines[].UsedBarcode) — urunlerin Nebim'de
// ayni barkodla tanimli olmasi gerekir. Asla sahte "gonderildi" donmez; Nebim ne derse o gosterilir.
const pool = require('../db');

const MODEL = { RetailCustomer: 3, OrderR: 6, InvoiceR: 8, Query: 32 };

const NEBIM_KEYS = [
  'acc_nebim_api_url', 'acc_nebim_username', 'acc_nebim_password', 'acc_nebim_firm',
  'acc_nebim_user_group', 'acc_nebim_office', 'acc_nebim_warehouse', 'acc_nebim_series',
  'acc_nebim_pos_terminal', 'acc_nebim_customer', 'acc_nebim_payment_code',
  'acc_nebim_enabled', 'acc_nebim_auto_send',
];

function normBase(url) { return String(url || '').replace(/\/+$/, ''); }

async function getNebimConfig() {
  const cfg = {
    apiUrl: '', username: '', password: '', database: '', userGroup: 'V3',
    office: '', warehouse: '', series: 'A', posTerminal: 1, customer: '',
    paymentCode: '1-7-3', enabled: false, autoSend: false,
  };
  try {
    const { rows } = await pool.query('SELECT key, value FROM settings WHERE key = ANY($1)', [NEBIM_KEYS]);
    const kv = {};
    rows.forEach((r) => { kv[r.key] = r.value; });
    cfg.apiUrl = kv.acc_nebim_api_url || '';
    cfg.username = kv.acc_nebim_username || '';
    cfg.password = kv.acc_nebim_password || '';
    cfg.database = kv.acc_nebim_firm || '';
    cfg.userGroup = kv.acc_nebim_user_group || 'V3';
    cfg.office = kv.acc_nebim_office || '';
    cfg.warehouse = kv.acc_nebim_warehouse || '';
    cfg.series = kv.acc_nebim_series || 'A';
    cfg.posTerminal = parseInt(kv.acc_nebim_pos_terminal, 10) || 1;
    cfg.customer = kv.acc_nebim_customer || '';
    cfg.paymentCode = kv.acc_nebim_payment_code || '1-7-3';
    cfg.enabled = kv.acc_nebim_enabled === 'true';
    cfg.autoSend = kv.acc_nebim_auto_send === 'true';
  } catch (e) { /* settings tablosu yoksa bos ayar */ }
  return cfg;
}

async function callNebim(base, command, token, body, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs || 30000);
  try {
    const headers = {};
    if (body !== null && body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Token = token;
    const opts = { method: 'POST', headers, signal: ctrl.signal };
    if (body !== null && body !== undefined) opts.body = JSON.stringify(body);
    const r = await fetch(normBase(base) + '/IntegratorService/' + command, opts);
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch (e) { /* JSON degilse text kullanilir */ }
    return { http: r.status, json: j, text: text.slice(0, 500) };
  } finally { clearTimeout(t); }
}

async function connect(cfg) {
  const r = await callNebim(cfg.apiUrl, 'Connect', null, {
    DatabaseName: cfg.database, UserGroupCode: cfg.userGroup, UserName: cfg.username, Password: cfg.password,
  });
  if (r.http !== 200) return { ok: false, error: 'connect_failed', detail: 'HTTP ' + r.http + (r.text ? ' — ' + r.text.slice(0, 200) : '') };
  const token = r.json && r.json.Token;
  if (!token) {
    return { ok: false, error: 'session_mode', detail: 'Nebim sunucunuz Oturum (Session) modunda calisiyor gorunuyor (Token donmedi). Integrator IIS ayarlarinda "Oturum Durumu"nu Kapali (Off) yapin, Token modu gerekir.' };
  }
  return { ok: true, token };
}

async function testConnection() {
  const cfg = await getNebimConfig();
  if (!cfg.apiUrl) return { ok: false, message: 'Eksik bilgi: API Adresi / Sunucu gerekli.' };
  if (!/^https?:\/\//i.test(cfg.apiUrl)) return { ok: false, message: 'API adresi http:// veya https:// ile baslamali (orn. http://192.1.1.217:801).' };
  if (!cfg.database || !cfg.username) return { ok: false, message: 'Eksik bilgi: Veritabani Adi ve Kullanici Adi gerekli.' };
  try {
    const c = await connect(cfg);
    if (!c.ok) return { ok: false, message: 'Nebim baglantisi kurulamadi: ' + (c.detail || c.error) };
    const u = await callNebim(cfg.apiUrl, 'GetUserInfo', c.token, null);
    if (u.http !== 200 || !u.json || !u.json.UserName) return { ok: false, message: 'Baglanti kuruldu ama kullanici dogrulanamadi — kullanici adi / sifre kontrol edin.' };
    return { ok: true, message: 'Nebim baglantisi basarili — Kullanici: ' + u.json.UserName + ', Veritabani: ' + (u.json.DatabaseName || cfg.database) };
  } catch (e) {
    return { ok: false, message: 'Nebim sunucusuna erisilemedi: ' + (e && e.message ? e.message : 'bilinmeyen hata') };
  }
}

async function postModel(model) {
  const cfg = await getNebimConfig();
  if (!cfg.apiUrl || !cfg.database || !cfg.username) return { ok: false, error: 'nebim_not_configured', detail: 'Nebim ayarlari eksik.' };
  const c = await connect(cfg);
  if (!c.ok) return { ok: false, error: 'connect_failed', detail: c.detail || c.error };
  const r = await callNebim(cfg.apiUrl, 'Post', c.token, model);
  const j = r.json || {};
  const failed = r.http >= 400 || (j.StatusCode !== undefined && j.StatusCode !== 200) || j.Error || j.ErrorMessage;
  if (failed) {
    const detail = (j.Error && (j.Error.Message || j.Error)) || j.ErrorMessage || j.Message || j.Status || ('HTTP ' + r.http);
    return { ok: false, error: 'nebim_rejected', detail: String(detail).slice(0, 500), data: j };
  }
  return { ok: true, data: j };
}

function fmtDate(d) {
  const x = d instanceof Date ? d : new Date();
  const p = (n) => String(n).padStart(2, '0');
  return '' + x.getFullYear() + p(x.getMonth() + 1) + p(x.getDate());
}

async function ensureSyncTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS nebim_sync (id SERIAL PRIMARY KEY, order_id UUID, model_type INT, status TEXT, nebim_doc_no TEXT, detail TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
}

async function logSync(orderId, modelType, status, docNo, detail) {
  try {
    await ensureSyncTable();
    await pool.query('INSERT INTO nebim_sync (order_id, model_type, status, nebim_doc_no, detail) VALUES ($1,$2,$3,$4,$5)', [orderId, modelType, status, docNo || '', detail || '']);
  } catch (e) { /* log hatasi gonderimi bozmaz */ }
}

// Siparis faturasini Nebim'e InvoiceR olarak gonderir. Tekrar gonderim korumali:
// basariyla gonderilmis siparis ikinci kez gonderilmez (Nebim'de mukerrer fatura olusmaz).
async function sendOrderInvoice(orderId) {
  try {
    await ensureSyncTable();
    const { rows: prev } = await pool.query("SELECT * FROM nebim_sync WHERE order_id = $1 AND model_type = 8 AND status = 'sent' ORDER BY created_at DESC LIMIT 1", [orderId]);
    if (prev.length) return { ok: false, error: 'already_sent', message: 'Bu siparisin faturasi zaten Nebim\'e gonderilmis.' + (prev[0].nebim_doc_no ? ' (Belge: ' + prev[0].nebim_doc_no + ')' : '') };
    const cfg = await getNebimConfig();
    if (!cfg.apiUrl || !cfg.database || !cfg.username) return { ok: false, error: 'nebim_not_configured', message: 'Nebim ayarlari eksik. Once Muhasebe Yazilimlari > Nebim kartini doldurun.' };
    if (!cfg.customer) return { ok: false, error: 'nebim_customer_missing', message: 'Varsayilan Perakende Musteri Kodu girilmemis. Muhasebe Yazilimlari > Nebim kartina musterinizin Nebim kodunu yazin.' };
    const { rows: ords } = await pool.query('SELECT o.*, u.name AS user_name, u.email AS user_email, u.phone AS user_phone FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE o.id = $1', [orderId]);
    const order = ords[0];
    if (!order) return { ok: false, error: 'order_not_found', message: 'Siparis bulunamadi.' };
    const { rows: items } = await pool.query('SELECT oi.*, p.barcode, p.sku FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id WHERE oi.order_id = $1', [orderId]);
    if (!items.length) return { ok: false, error: 'no_items', message: 'Siparisin kalemi yok.' };
    const isCorporate = order.invoice_type === 'kurumsal';
    const model = {
      ModelType: MODEL.InvoiceR,
      CustomerCode: cfg.customer,
      Series: cfg.series,
      OfficeCode: cfg.office || '',
      StoreCode: cfg.office || '',
      WarehouseCode: cfg.warehouse || '',
      POSTerminalID: cfg.posTerminal,
      IsCompleted: true,
      Description: 'ChinaBazaar Siparis No: ' + (order.order_no || ''),
      InvoiceDate: fmtDate(new Date()),
      Lines: items.map((it) => {
        const line = { Qty1: Number(it.qty || 1), PriceVI: Number(it.price_cents || 0) / 100 };
        if (it.barcode) line.UsedBarcode = String(it.barcode);
        else if (it.sku) line.ItemCode = String(it.sku);
        else line.ItemCode = String(it.product_id || '');
        return line;
      }),
      Payments: [{ PaymentType: order.payment_method === 'card' ? 2 : 1, Code: cfg.paymentCode, CurrencyCode: order.currency || 'TRY', Amount: Number(order.total_cents || 0) / 100 }],
    };
    if (isCorporate) {
      model.PostalAddress = { CompanyName: order.invoice_company || '', FirstName: '', LastName: '', TaxNumber: String(order.invoice_vkn || ''), TaxOfficeCode: order.invoice_tax_office || '', IdentityNum: '' };
    } else if (order.invoice_tckn || order.invoice_full_name) {
      const nm = String(order.invoice_full_name || order.user_name || '').trim().split(/\s+/);
      model.PostalAddress = { CompanyName: '', FirstName: nm[0] || '', LastName: nm.slice(1).join(' ') || '', TaxNumber: '', TaxOfficeCode: '', IdentityNum: String(order.invoice_tckn || '') };
    }
    if (order.user_email) model.EMailAddress = order.user_email;
    const r = await postModel(model);
    if (!r.ok) {
      await logSync(orderId, MODEL.InvoiceR, 'failed', '', String(r.detail || r.error || '').slice(0, 500));
      return { ok: false, error: r.error || 'nebim_rejected', message: 'Nebim faturayi kabul etmedi: ' + String(r.detail || r.error || '').slice(0, 300) };
    }
    const j = r.data || {};
    const docNo = j.InvoiceNumber || j.DocumentNumber || j.InvoiceNo || j.SeriesNumber || '';
    await logSync(orderId, MODEL.InvoiceR, 'sent', String(docNo || ''), 'InvoiceR gonderildi.');
    return { ok: true, message: 'Fatura Nebim\'e gonderildi.' + (docNo ? ' (Belge: ' + docNo + ')' : ''), nebim_doc_no: docNo };
  } catch (e) {
    try { await logSync(orderId, MODEL.InvoiceR, 'failed', '', 'Hata: ' + e.message); } catch (_) {}
    return { ok: false, error: 'nebim_error', message: 'Nebim gonderim hatasi: ' + e.message };
  }
}

module.exports = { getNebimConfig, testConnection, connect, postModel, sendOrderInvoice, MODEL };
