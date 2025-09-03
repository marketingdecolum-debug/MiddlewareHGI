/**
 * Shopify ⇄ HGI ERP Middleware (Express)
 * ------------------------------------------------------------
 * - Recibe webhooks de Shopify (JSON) y verifica HMAC.
 * - Obtiene / renueva JWT de HGI y llama a los endpoints REST.
 * - Mapea: products/update, orders/paid, orders/cancelled.
 * - Guarda el mapeo orderId ⇄ {empresa, comprobante, documento} para anulación.
 *
 * Requisitos: Node 18+, npm i express axios dotenv
 *
 * .env (ejemplo)
 * ------------------------------------------------------------
 * PORT=3000
 *
 * # Shopify
 * SHOPIFY_SECRET=__TU_SHOPIFY_WEBHOOK_SECRET__
 *
 * # HGI
 * HGI_BASE_URL=https://cloud2.hgi.com.co:9323/
 * HGI_USER=__USUARIO__
 * HGI_PASS=__CLAVE__
 * HGI_COMPANY=1                # cod_compania
 * HGI_EMPRESA=1                # cod_empresa
 * HGI_COMPROBANTE=FV           # Id del comprobante de venta (p.ej. FV)
 * HGI_CUENTA_INGRESO=413505    # Cuenta contable ingresos (crédito)
 * HGI_CUENTA_CLIENTE=130505    # Cuenta por cobrar (débito)
 * HGI_TERCERO_DEFAULT=900123456  # (opcional) si no puedes mapear el tercero
 */

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
  if (!resp.data || !resp.data.jwtToken) {
    throw new Error('No se obtuvo jwtToken de HGI');
  }
  hgiToken = resp.data.jwtToken;
  // si viene expiración, renueva 60s antes; si no, 10 min por defecto
  const exp = resp.data.passwordExpiration ? Date.parse(resp.data.passwordExpiration) : now + 10 * 60 * 1000;
  hgiExpiresAt = Math.max(exp - 60 * 1000, now + 2 * 60 * 1000);
  return hgiToken;
}

function hgiHeaders(token) {
  return { Authorization: `Bearer ${token}` };
}

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

// ----------- Shopify: products/update → HGI Productos --------
app.post('/webhook/productos/update', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const product = req.body; // payload de Shopify product
    const active = (product.status || '').toLowerCase() === 'active' ? 1 : 0;

    // Construir lista de productos HGI a partir de variantes con SKU
    const productos = [];
    for (const v of product.variants || []) {
      if (!v.sku) continue; // solo variantes con SKU
      productos.push({
        Codigo: v.sku,
        Descripcion: `${product.title}${v.title && v.title !== 'Default Title' ? ' - ' + v.title : ''}`,
        Precio: Number(v.price || 0),
        Estado: active,
        Ecommerce: 1,
      });
    }
    if (!productos.length) return res.status(200).send('No SKUs to update');

    const token = await getHgiToken();
    const url = `${HGI_BASE_URL}Api/Productos/Actualizar`;
    // HGI normalmente espera lista; enviamos un array simple
    const r = await axios.put(url, productos, { headers: hgiHeaders(token), timeout: 20_000 });

    console.log('[HGI Productos/Actualizar] ok', Array.isArray(r.data) ? r.data.length : '');
    return res.status(200).send('OK');
  } catch (e) {
    console.error('Productos update error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// ----------- Shopify: orders/paid → HGI DocContables/Crear ---
app.post('/webhook/orders/paid', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    const orderId = String(order.id);

    // Idempotencia: si ya existe el mapeo, salir con 200
    if (mapStore.orders[orderId]) {
      return res.status(200).send('Already processed');
    }

    // Tercero: intenta usar email, si no, fallback
    const tercero = order?.customer?.email || HGI_TERCERO_DEFAULT || null;

    // Total venta (sin impuestos finos, ajustar según tu plan de cuentas)
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

    // Extrae identificador del documento creado
    const created = Array.isArray(r.data) ? r.data[0] : r.data?.[0] || r.data;
    const mapping = {
      empresa: documento.Empresa,
      comprobante: documento.IdComprobante,
      documento: created?.Documento || created?.Id || created?.documento || null,
    };

    if (!mapping.documento) {
      console.warn('[WARN] No pude leer el número de documento desde la respuesta HGI. Guarda el log.');
    }

    mapStore.orders[orderId] = mapping;
    saveMap();

    console.log('[HGI DocContables/Crear] ok', mapping);
    return res.status(200).send('OK');
  } catch (e) {
    console.error('orders/paid error:', e.response?.data || e.message);
    return res.status(500).send('Error');
  }
});

// ----------- Shopify: orders/cancelled → HGI DocContables/Actualizar (Estado=2)
app.post('/webhook/orders/cancelled', async (req, res) => {
  try {
    if (!verifyShopifyHmac(req.rawBody, req.get('X-Shopify-Hmac-Sha256'))) {
      return res.status(401).send('Invalid HMAC');
    }
    const order = req.body;
    const orderId = String(order.id);

    const mapping = mapStore.orders[orderId];
    if (!mapping) {
      // No mapeo (tal vez no se facturó). Responder 200 para no reintentar.
      return res.status(200).send('No mapping');
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
