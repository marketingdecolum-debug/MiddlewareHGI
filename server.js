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
  throw new Error('Variables HGI incompletas. No se puede continuar.');
}

// ---------- Shopify Admin API client ----------
const SHOPIFY_STORE = process.env.SHOPIFY_STORE;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';
const SHOPIFY_ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;
const SHOPIFY_LOCATION_ID = process.env.SHOPIFY_LOCATION_ID; // numérico

const shopify = axios.create({
  baseURL: `https://${SHOPIFY_STORE}/admin/api/${SHOPIFY_API_VERSION}`,
  headers: { 'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN }
});

// GraphQL helper
async function shopifyGQL(query, variables = {}) {
  const r = await shopify.post('/graphql.json', { query, variables });
  if (r.data.errors) throw new Error(JSON.stringify(r.data.errors));
  return r.data.data;
}

// Busca variante por SKU → devuelve { variantId, inventoryItemId }
async function findVariantBySKU(sku) {
  const query = `
    query($q:String!) {
      productVariants(first:1, query:$q) {
        edges { node { id sku inventoryItem { id } } }
      }
    }`;
  const data = await shopifyGQL(query, { q: `sku:${JSON.stringify(sku)}` });
  const node = data?.productVariants?.edges?.[0]?.node;
  if (!node) return null;
  return { variantId: node.id, inventoryItemId: node.inventoryItem.id };
}

// Actualiza precio de una variante (REST)
async function setVariantPrice(variantId, price) {
  const id = variantId.split('/').pop(); // GID -> numérico
  await shopify.put(`/variants/${id}.json`, { variant: { id, price: Number(price) } });
}

// Fija stock "on hand" (GraphQL)
async function setOnHand(inventoryItemId, qty) {
  const locationGID = `gid://shopify/Location/${SHOPIFY_LOCATION_ID}`;
  const mutation = `
    mutation($input: InventorySetOnHandQuantitiesInput!) {
      inventorySetOnHandQuantities(input: $input) {
        userErrors { field message }
      }
    }`;
  const input = {
    reason: "correction",
    setQuantities: [{ inventoryItemId, locationId: locationGID, quantity: Number(qty) }]
  };
  const res = await shopifyGQL(mutation, { input });
  const errs = res?.inventorySetOnHandQuantities?.userErrors;
  if (errs && errs.length) throw new Error(JSON.stringify(errs));
}

// --------------------- Token cache (JWT) ---------------------
// === HGI auth cache con candado ===
let hgiToken = null;
let hgiExpiresAt = 0;        // epoch ms
let authPromise = null;      // evita logins concurrentes

async function getHgiToken() {
  const now = Date.now();
  if (hgiToken && now < hgiExpiresAt) return hgiToken;
  if (authPromise) return authPromise;

  authPromise = (async () => {
    const url = `${HGI_BASE_URL}Api/Autenticar`;
    const params = {
      usuario: HGI_USER,
      clave: HGI_PASS,
      cod_compania: HGI_COMPANY,
      cod_empresa: HGI_EMPRESA,
    };
    try {
      const resp = await axios.get(url, { params, timeout: 20_000 });
      const data = resp.data || {};

      // HGI a veces devuelve Error { Mensaje: ... }
      if (data.Error) {
        console.error('[HGI Autenticar] Error:', data.Error);
        throw new Error(data.Error?.Mensaje || 'HGI Autenticar devolvió Error');
      }

      const jwt = data.JwtToken || data.jwtToken;
      if (!jwt) {
        console.error('[HGI Autenticar] Respuesta inesperada:', JSON.stringify(data));
        throw new Error('No se obtuvo JwtToken de HGI');
      }
      hgiToken = jwt;

      const expStr = data.PasswordExpiration || data.passwordExpiration;
      const exp = expStr ? Date.parse(expStr) : (Date.now() + 10 * 60 * 1000);
      hgiExpiresAt = Math.max(exp - 60 * 1000, Date.now() + 2 * 60 * 1000);

      return hgiToken;
    } finally {
      authPromise = null; // libera el candado
    }
  })();

  return authPromise;
}

const hgiHeaders = (token) => ({ Authorization: `Bearer ${token}` });

// --------------- Util: verificación HMAC Shopify --------------
function verifyShopifyHmac(rawBody, headerHmac) {
  try {
    const generated = crypto
      .createHmac('sha256', SHOPIFY_SECRET)
      .update(rawBody)
      .digest('base64');
    const genBuf = Buffer.from(generated, 'base64');
    const headBuf = Buffer.from(headerHmac || '', 'base64');
    if (genBuf.length !== headBuf.length) return false;
    return crypto.timingSafeEqual(genBuf, headBuf);
  } catch (e) {
    console.error('verifyShopifyHmac error:', e);
    return false;
  }
}

function verifyWebhook(req, res, next) {
  if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
    return res.status(401).send('Invalid HMAC');
  }
  next();
}

// ----------------- Util: storage de mapeos -------------------
const MAP_PATH = path.join(process.cwd(), 'map.json');
let mapStore = { orders: {} }; // { orders: { [shopifyOrderId]: { empresa, comprobante, documento } } }

async function loadMap() {
  try {
    const data = await fs.promises.readFile(MAP_PATH, 'utf8');
    mapStore = JSON.parse(data);
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.warn('[WARN] No se pudo cargar map.json:', e.message);
    }
  }
}

async function saveMap() {
  try {
    await fs.promises.writeFile(MAP_PATH, JSON.stringify(mapStore, null, 2));
  } catch (e) {
    console.error('[ERROR] No se pudo guardar map.json:', e.message);
  }
}

// ------------------------- App -------------------------------
const app = express();
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.url}`, req.headers);
  next();
});
// Guardar cuerpo crudo para HMAC
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

app.get('/health', (_req, res) => res.status(200).send('OK'));

app.use('/webhook', verifyWebhook);

// =============================================================
// ===============  PRODUCTOS (update / delete)  ===============
// =============================================================

// products/update → HGI Productos/Actualizar
app.post('/webhook/productos/update', async (req, res) => {
  try {
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
  await saveMap();
  console.log('[HGI DocContables/Crear] ok', mapping);
  return mapping;
}

// orders/create → crea si ya viene pagado; si no, sólo ACK
app.post('/webhook/orders/create', async (req, res) => {
  try {
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

// Job: trae cambios desde HGI y actualiza Shopify
app.get('/jobs/sync-hgi-to-shopify', async (req, res) => {
  if (process.env.DRY_RUN === 'true') return res.send('DRY_RUN');
  const sinceMinutes = Number(req.query.since || 30);
  const since = new Date(Date.now() - sinceMinutes * 60 * 1000).toISOString();

  try {
    const token = await getHgiToken();

    // 1) Productos cambiados (precio/estado)
    const urlProd = `${HGI_BASE_URL}Api/Productos/ObtenerLista`;
    const r1 = await axios.get(urlProd, {
      headers: hgiHeaders(token),
      params: {
        ecommerce: '*', estado: '*', kardex: '*',
        incluir_foto: false,
        fecha_inicial: since,
        fecha_final: new Date().toISOString()
      },
      timeout: 20_000
    });
    const productos = Array.isArray(r1.data) ? r1.data : [];

    for (const p of productos) {
      const sku = p.Codigo || p.codigo || p.sku;
      if (!sku) continue;
      const v = await findVariantBySKU(sku);
      if (!v) { console.warn('[SKU no encontrado en Shopify]', sku); continue; }
      if (p.Precio1 != null) {
        await setVariantPrice(v.variantId, p.Precio1);
      }
      // Si en tu respuesta viene stock en el mismo endpoint, puedes fijarlo aquí:
      // if (p.Stock != null) await setOnHand(v.inventoryItemId, p.Stock);
    }

    // 2) Stock (si HGI lo entrega en otro endpoint)
    try {
      const urlStock = `${HGI_BASE_URL}Api/Existencias/Obtener`; // cámbialo si tu manual usa otro
      const r2 = await axios.get(urlStock, {
        headers: hgiHeaders(token),
        params: { fecha_inicial: since, fecha_final: new Date().toISOString() },
        timeout: 20_000
      });
      const existencias = Array.isArray(r2.data) ? r2.data : [];
      for (const x of existencias) {
        const sku = x.Codigo || x.SKU;
        const qty = x.Cantidad ?? x.Disponible;
        if (sku == null || qty == null) continue;
        const v = await findVariantBySKU(sku);
        if (v) await setOnHand(v.inventoryItemId, qty);
      }
    } catch (e) {
      console.warn('[Stock HGI] no disponible o sin cambios:', e.response?.data || e.message);
    }

    res.send(`OK sync desde ${since}`);
  } catch (e) {
    console.error('sync-hgi-to-shopify error:', e.response?.data || e.message);
    res.status(500).send('Error');
  }
});

// ------------------- Start server ----------------------------
async function start() {
  await loadMap();
  app.listen(PORT, () => console.log(`Middleware Shopify⇄HGI escuchando en :${PORT}`));
}

start().catch(console.error);
