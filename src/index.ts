import { Hono } from 'hono';
import CryptoJS from 'crypto-js';
import { cors } from 'hono/cors'
import { getConnInfo } from "hono/cloudflare-workers";
import { hasExceededFailedAuthLimit, isAuthenticated } from './auth_modules';

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

app.post("/verify", async (c) => {
  const info = getConnInfo(c);
  const ip = info.remote.address || "anonymous";

  if (await hasExceededFailedAuthLimit(c, ip)) {
    return c.json({ error: "Too many failed attempts. Please try again later." }, 429);
  }

  const body = await c.req.parseBody();
  const amount = String(body["amount"] || "");
  const invoiceDate = String(body["invoiceDate"] || "");
  const orderNumber = String(body["orderNumber"] || "");
  const invoiceUrl = String(body["invoiceUrl"] || "");
  const providedToken = String(body["encryptedToken"] || "");

  if (!amount || !invoiceDate || !orderNumber || !providedToken || !c.env.AES_ENCRYPTION_KEY) {
    await incrementFailureCount(c, ip);
    return c.json({ error: "Missing required verification fields" }, 400);
  }

  try {
    const expectedPayload = `${invoiceUrl}|${orderNumber}|${amount}|${invoiceDate}`;
    const decryptedPayload = await decryptToken(providedToken, c.env.AES_ENCRYPTION_KEY);

    if (decryptedPayload !== expectedPayload) {
      await incrementFailureCount(c, ip);
      return c.json({ error: "Invalid token verification payload" }, 401);
    }

    // Success: Token verified. Clean up any recorded failures for this IP.
    const kv = c.env.RATE_LIMIT_KV;
    if (kv) {
      await kv.delete(`fail:${ip}`);
    }

    return c.json({ verified: true });
  } catch (err) {
    await incrementFailureCount(c, ip);
    return c.json({ error: "Token verification failed" }, 401);
  }
});

app.post("/verify", async (c) => {
  const localEncryptionKey = c.env.AES_ENCRYPTION_KEY;
  const locationId = c.env.FORTE_LOCATION_ID;
  const apiId = c.env.FORTE_API_ACCESS_ID;
  const secureKey = c.env.FORTE_SECURE_KEY;
  const merchantId = c.env.FORTE_MERCHANT_ID;
  const forteEnv = c.env.FORTE_ENV;

  const { amount, invoiceDate, orderNumber, encryptedToken } = await c.req.json();

  const decryptedToken = await decryptToken(encryptedToken, localEncryptionKey);
  const [decryptedInvoiceUrl, dOrder, dAmount, dDate] = decryptedToken.split("|");

  if (dOrder !== orderNumber || dAmount !== amount || dDate !== invoiceDate) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const startTime = performance.now();

  const isAlreadyPaid = await checkPaymentStatus(orderNumber, apiId, secureKey, locationId, merchantId, forteEnv);

  const endTime = performance.now();
  console.log(`check payment status took ${(endTime - startTime).toFixed(2)} ms`);

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

async function encryptToken(payload: string, aesKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(aesKey),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(payload)
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  let binary = '';
  for (let i = 0; i < combined.byteLength; i++) {
    binary += String.fromCharCode(combined[i]);
  }
  return btoa(binary);
}

async function decryptToken(encryptedToken: string, aesKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const binary = atob(encryptedToken);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(aesKey),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

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
