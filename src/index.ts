import { Hono } from 'hono';
import CryptoJS from 'crypto-js';
import { cors } from 'hono/cors'
import { getConnInfo } from "hono/cloudflare-workers";
import { hasExceededFailedAuthLimit, isAuthenticated, isTokenVerified } from './auth_modules';
import { encryptToken, decryptToken } from './crypto_modules';


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

const Environment = Object.freeze({
  SANDBOX: "sandbox",
  PRODUCTION: "production",
});

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
    encryptedToken,
  });

  const baseUrl = c.env.ENVIRONMENT === "SANDBOX"
      ? "http://localhost:3000"
      : c.env.FRONTEND_BASE_URL;

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
  const forteEnv = c.env.FORTE_ENV;

  const { amount, invoiceDate, orderNumber, encryptedToken } = await c.req.json();

  const decryptedToken = await decryptToken(encryptedToken, localEncryptionKey);
  const [decryptedInvoiceUrl, dOrder, dAmount, dDate] = decryptedToken.split("|");

  const isVerified = await isTokenVerified({ orderNumber: dOrder, amount: dAmount, invoiceDate: dDate }, { orderNumber, amount, invoiceDate }, c, ip);
  if (!isVerified) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const isAlreadyPaid = await checkPaymentStatus(orderNumber, apiId, secureKey, locationId, merchantId, forteEnv);

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

export async function getForteUtcTime(): Promise<string> {
  const res = await fetch("https://checkout.forte.net/getUTC?callback=?", {
    headers: {
      "Connection": "close"
    }
  });

  const rawText = (await res.text()).trim();
  let utcTime;
  if (/^\d+$/.test(rawText)) {
    utcTime = rawText;
  } else {
    const match = rawText.match(/\((\d+)\)/);
    utcTime = match ? match[1] : null;
  }
  if (!utcTime) {
    throw new Error("Invalid UTC response from Forte");
  }
  return utcTime;
}

function generateHmac(secret: string, message: string): string {
  return CryptoJS.HmacMD5(message, secret).toString();
}

async function checkPaymentStatus(
    orderNumber: string,
    accessID: string,
    secureKey: string,
    locationId: string,
    merchantId: string,
    forteEnv: string
  ): Promise<boolean> {
  const orgId = `org_${merchantId}`;
  const locId = `loc_${locationId}`;

  const auth = toWindows1252Base64(`${accessID}:${secureKey}`);
  const environment = getEnvironment(forteEnv);

  const baseForteUrl = environment === Environment.SANDBOX
    ? "https://sandbox.forte.net/api/v3"
    : "https://api.forte.net/v3";

  const url = `${baseForteUrl}/organizations/${orgId}/locations/${locId}/transactions?filter=order_number+eq+${orderNumber}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Basic ${auth}`,
      "Accept": "application/json",
      "X-Forte-Auth-Organization-Id": orgId,
      "Connection": "close"
    }
  });

  const text = await response.text();
  const data = JSON.parse(text);
  return data.number_results > 0;
}

function toWindows1252Base64(str: string): string {
  const bytes = Uint8Array.from(str, c => c.charCodeAt(0) & 0xFF);
  return btoa(String.fromCharCode(...bytes));
}

function getEnvironment(forteEnv: string): string {
  return forteEnv === "production" ? Environment.PRODUCTION: Environment.SANDBOX;
}

export default app;
