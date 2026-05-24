import { Hono } from 'hono';
import { cors } from 'hono/cors'
import { getConnInfo } from "hono/cloudflare-workers";
import { hasExceededFailedAuthLimit, isAuthenticated, isTokenVerified } from './auth_modules';
import { encryptToken, decryptToken, generateHmac } from './crypto_modules';
import { checkPaymentStatus, getForteUtcTime } from './forte_modules';

type Bindings = {
  BASIC_AUTH_USER: string;
  BASIC_AUTH_PASS: string;
  AES_ENCRYPTION_KEY: string;
  FORTE_LOCATION_ID: string;
  FORTE_API_ACCESS_ID: string;
  FORTE_SECURE_KEY: string;
  FORTE_MERCHANT_ID: string;
  FORTE_ENV: string;
};

const app = new Hono<{ Bindings: Bindings }>();

function isProduction(env: Bindings): boolean {
  return env.FORTE_ENV === "production";
}

app.use( "*", cors({
    origin: ["http://localhost:3000", "https://www.thesquarerepair.com"],
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type"],
}));

app.post("/", async (c) => {
  const info = getConnInfo(c);
  const ip = info.remote.address || "anonymous";

  if (await hasExceededFailedAuthLimit(c, ip)) {
    return c.json({ error: "Too many failed attempts. Please try again later." }, 429);
  }

  if (!(await isAuthenticated(c, ip))) {
    return c.text("Unauthorized", 401, { "WWW-Authenticate": 'Basic realm="secure"' });
  }

  const body = await c.req.parseBody();

  const amount = String(body["amount"] || "");
  const invoiceDate = String(body["invoiceDate"] || "");
  const orderNumber = String(body["orderNumber"] || "");
  const serviceDescription = String(body["serviceDescription"] || "");
  const invoiceUrl = String(body["invoiceUrl"] || "");

  if (!amount || !invoiceDate || !orderNumber || !c.env.AES_ENCRYPTION_KEY) {
    return c.json({ error: "Missing required fields or encryption key" }, 400);
  }

  const payload = `${invoiceUrl}|${orderNumber}|${amount}|${invoiceDate}`;

  const encryptedToken = await encryptToken(payload, c.env.AES_ENCRYPTION_KEY);

  const params = new URLSearchParams({
    amount,
    invoiceDate,
    orderNumber,
    serviceDescription,
    invoiceUrl,
    encryptedToken,
  });

  const baseUrl = isProduction(c.env)
      ? c.env.FRONTEND_BASE_URL
      : "http://localhost:3000";

  const paymentUrl = `${baseUrl}/payment?${params.toString()}`;

  return c.json({ paymentUrl: paymentUrl });
});

app.post("/verify", async (c) => {
  const ip = c.req.header("CF-Connecting-IP") || "unknown";

  if (await hasExceededFailedAuthLimit(c, ip)) {
    return c.json({ error: "Too many failed attempts. Please try again later." }, 429);
  }

  const localEncryptionKey = c.env.AES_ENCRYPTION_KEY;
  const locationId = c.env.FORTE_LOCATION_ID;
  const apiId = c.env.FORTE_API_ACCESS_ID;
  const secureKey = c.env.FORTE_SECURE_KEY;
  const merchantId = c.env.FORTE_MERCHANT_ID;
  const production = isProduction(c.env);

  const { amount, invoiceDate, orderNumber, encryptedToken } = await c.req.json();

  const decryptedToken = await decryptToken(encryptedToken, localEncryptionKey);
  const [decryptedInvoiceUrl, dOrder, dAmount, dDate] = decryptedToken.split("|");

  const isVerified = await isTokenVerified({ orderNumber: dOrder, amount: dAmount, invoiceDate: dDate }, { orderNumber, amount, invoiceDate }, c, ip);

  if (!isVerified) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const isAlreadyPaid = await checkPaymentStatus(orderNumber, apiId, secureKey, locationId, merchantId, production);

  if (isAlreadyPaid) {
    return c.json({ error: "Already Paid" }, 401);
  }

  const utcTime = await getForteUtcTime();

  const fortePayload = `${apiId}|sale|2.0|${amount}|${utcTime}|${orderNumber}||`;
  const forteSignature = generateHmac(secureKey, fortePayload);

  return c.json({
    apiId,
    amount,
    utcTime,
    orderNumber,
    decryptedInvoiceUrl,
    forteSignature,
    locationId
  });
});


export default app;
