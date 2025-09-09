require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// -------------------------- Config ---------------------------
const PORT = process.env.PORT || 3000;
const SHOPIFY_SECRET = process.env.SHOPIFY_SECRET || '';
const HGI_BASE_URL = (process.env.HGI_BASE_URL || '').replace(/\/?$/, '/');
const HGI_USER = process.env.HGI_USER;
const HGI_PASS = process.env.HGI_PASS;
const HGI_COMPANY = process.env.HGI_COMPANY; // cod_compania
const HGI_EMPRESA = process.env.HGI_EMPRESA; // cod_empresa
const HGI_COMPROBANTE = process.env.HGI_COMPROBANTE || 'FV';
const HGI_CUENTA_INGRESO = process.env.HGI_CUENTA_INGRESO || '413505';
const HGI_CUENTA_CLIENTE = process.env.HGI_CUENTA_CLIENTE || '130505';
const HGI_TERCERO_DEFAULT = process.env.HGI_TERCERO_DEFAULT || '';

if (!SHOPIFY_SECRET) console.warn('[WARN] SHOPIFY_SECRET vacío. No podrás validar HMAC.');
if (!HGI_BASE_URL || !HGI_USER || !HGI_PASS || !HGI_COMPANY || !HGI_EMPRESA) {
  console.error('[ERROR] Variables HGI incompletas. Revisa .env');
}

// --------------------- Token cache (JWT) ---------------------
let hgiToken = null;
let hgiExpiresAt = 0; // ms epoch

async function getHgiToken() {
  const now = Date.now();
  if (hgiToken && now < hgiExpiresAt) return hgiToken;

  const params = {
    usuario: HGI_USER,
    clave: HGI_PASS,
    cod_compania: HGI_COMPANY,
    cod_empresa: HGI_EMPRESA,
  };
  const url = `${HGI_BASE_URL}Api/Autenticar`;

  const resp = await axios.get(url, { params, timeout: 20_000 });
  const data = resp.data || {};

  // Si HGI devolvió un objeto Error, aborta con el detalle
  if (data.Error) {
    console.error('[HGI Autenticar] Error:', data.Error);
    throw new Error(data.Error?.Mensaje || 'HGI Autenticar devolvió Error');
  }

  // HGI suele devolver "JwtToken" y "PasswordExpiration" (con mayúsculas)
  const jwt = data.JwtToken || data.jwtToken;
  if (!jwt) {
    console.error('[HGI Autenticar] Respuesta inesperada:', JSON.stringify(data));
    throw new Error('No se obtuvo JwtToken de HGI');
  }
  hgiToken = jwt;

  const expStr = data.PasswordExpiration || data.passwordExpiration;
  const exp = expStr ? Date.parse(expStr) : (now + 10 * 60 * 1000);
  hgiExpiresAt = Math.max(exp - 60 * 1000, now + 2 * 60 * 1000);

  return hgiToken;
}

const hgiHeaders = (token) => ({ Authorization: `Bearer ${token}` });

// --------------- Util: verificación HMAC Shopify --------------
function verifyShopifyHmac(rawBody, headerHmac) {
  try {
    const generated = crypto.createHmac('sha256', SHOPIFY_SECRET).update(rawBody).digest('base64');
    return crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(headerHmac || '', 'utf8'));
  } catch {
    return false;
  }
}

// ----------------- Util: storage de mapeos -------------------
const MAP_PATH = path.join(process.cwd(), 'map.json');
let mapStore = { orders: {} }; // { orders: { [shopifyOrderId]: { empresa, comprobante, documento } } }
try {
  if (fs.existsSync(MAP_PATH)) mapStore = JSON.parse(fs.readFileSync(MAP_PATH, 'utf8'));
} catch (e) {
  console.warn('[WARN] No se pudo cargar map.json:', e.message);
}
function saveMap() {
  try { fs.writeFileSync(MAP_PATH, JSON.stringify(mapStore, null, 2)); } catch {}
}

// ------------------------- App -------------------------------
const app = express();
// Guardar cuerpo crudo para HMAC
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

app.get('/health', (_req, res) => res.status(200).send('OK'));

// =============================================================
// ===============  PRODUCTOS (update / delete)  ===============
// =============================================================

// products/update → HGI Productos/Actualizar
app.post('/webhook/productos/update', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const product = req.body;
    const active = (product.status || '').toLowerCase() === 'active' ? 1 : 0;

    const productos = [];
    for (const v of product.variants || []) {
      if (!v.sku) continue;
      productos.push({
        Codigo: v.sku,
        Descripcion: `${product.title}${v.title && v.title !== 'Default Title' ? ' - ' + v.title : ''}`,
        Precio1: Number(v.price || 0), // HGI usa Precio1..Precio8
        Vigente: active,               // 1 activo / 0 inactivo
        Ecommerce: 1
      });
    }
    if (!productos.length) return res.status(200).send('No SKUs to update');

    const token = await getHgiToken();
    const url = `${HGI_BASE_URL}Api/Productos/Actualizar`;
    const r = await axios.put(url, productos, { headers: hgiHeaders(token), timeout: 20_000 });

    console.log('[HGI Productos/Actualizar] ok', Array.isArray(r.data) ? r.data.length : '');
    return res.status(200).send('OK');
  } catch (e) {
    console.error('Productos update error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// "Cancelación de producto" (equivalente: products/delete) → marcar inactivo
app.post('/webhook/productos/delete', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const product = req.body;

    const productos = [];
    // Shopify envía el producto con sus variantes; si no, no pasa nada
    for (const v of product.variants || []) {
      if (!v.sku) continue;
      productos.push({
        Codigo: v.sku,
        Vigente: 0,
        Ecommerce: 0
      });
    }
    if (!productos.length) return res.status(200).send('No SKUs to disable');

    const token = await getHgiToken();
    const url = `${HGI_BASE_URL}Api/Productos/Actualizar`;
    await axios.put(url, productos, { headers: hgiHeaders(token), timeout: 20_000 });

    console.log('[HGI Productos/Actualizar] delete→inactivo', productos.length);
    return res.status(200).send('OK');
  } catch (e) {
    console.error('productos/delete error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// =============================================================
// ===================  PEDIDOS (create/updated) ===============
// =============================================================

// Helper: crea documento en HGI desde una orden Shopify (si no existe)
async function createHgiDocFromOrder(order) {
  const orderId = String(order.id);
  if (mapStore.orders[orderId]) return 'already';

  const tercero = order?.customer?.email || HGI_TERCERO_DEFAULT || null;
  const total = Number(order.total_price || 0);

  const documento = {
    Empresa: Number(HGI_EMPRESA),
    IdComprobante: HGI_COMPROBANTE,
    Fecha: order.created_at || new Date().toISOString(),
    Observaciones: `Shopify order ${orderId}`,
    ComprobanteDetalle: [
      {
        CuentaNIIF: HGI_CUENTA_INGRESO,
        Detalle: `Venta ${orderId}`,
        Referencia: orderId,
        Debito: 0,
        Credito: total
      },
      {
        CuentaNIIF: HGI_CUENTA_CLIENTE,
        Detalle: `Cliente ${tercero || 'N/A'}`,
        Tercero: tercero || undefined,
        Debito: total,
        Credito: 0
      }
    ]
  };

  const token = await getHgiToken();
  const url = `${HGI_BASE_URL}Api/DocumentosContables/Crear`;
  const r = await axios.post(url, [documento], { headers: hgiHeaders(token), timeout: 20_000 });

  const created = Array.isArray(r.data) ? r.data[0] : r.data?.[0] || r.data;
  const mapping = {
    empresa: documento.Empresa,
    comprobante: documento.IdComprobante,
    documento: created?.Documento || created?.Id || created?.documento || null,
  };

  mapStore.orders[orderId] = mapping;
  saveMap();
  console.log('[HGI DocContables/Crear] ok', mapping);
  return mapping;
}

// orders/create → crea si ya viene pagado; si no, sólo ACK
app.post('/webhook/orders/create', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    if ((order.financial_status || '').toLowerCase() === 'paid') {
      await createHgiDocFromOrder(order);
    }
    return res.status(200).send('OK');
  } catch (e) {
    console.error('orders/create error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// orders/updated → si cambia a pagado y no existe, crea
app.post('/webhook/orders/updated', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    const orderId = String(order.id);
    if ((order.financial_status || '').toLowerCase() === 'paid' && !mapStore.orders[orderId]) {
      await createHgiDocFromOrder(order);
    }
    return res.status(200).send('OK');
  } catch (e) {
    console.error('orders/updated error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// =============================================================
// ======  PEDIDOS (paid / cancelled ya existentes)  ===========
// =============================================================

// orders/paid → HGI DocContables/Crear
app.post('/webhook/orders/paid', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    const orderId = String(order.id);

    if (mapStore.orders[orderId]) {
      return res.status(200).send('Already processed');
    }
    await createHgiDocFromOrder(order);
    return res.status(200).send('OK');
  } catch (e) {
    console.error('orders/paid error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// orders/cancelled → HGI DocContables/Actualizar (Estado = 2)
app.post('/webhook/orders/cancelled', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    const orderId = String(order.id);

    const mapping = mapStore.orders[orderId];
    if (!mapping) {
      return res.status(200).send('No mapping'); // no se creó en HGI (no reintentar)
    }

    const doc = {
      Empresa: mapping.empresa,
      IdComprobante: mapping.comprobante,
      Documento: mapping.documento,
      Estado: 2, // Anulado
      Observaciones: `Shopify cancel ${orderId} (${order.cancel_reason || 'unspecified'}) ${order.cancelled_at || ''}`
    };

    const token = await getHgiToken();
    const url = `${HGI_BASE_URL}Api/DocumentosContables/Actualizar`;
    await axios.put(url, [doc], { headers: hgiHeaders(token), timeout: 20_000 });

    console.log('[HGI DocContables/Actualizar] anulado', mapping);
    return res.status(200).send('OK');
  } catch (e) {
    console.error('orders/cancelled error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// ------------------- Start server ----------------------------
app.listen(PORT, () => {
  console.log(`Middleware Shopify⇄HGI escuchando en :${PORT}`);
});
