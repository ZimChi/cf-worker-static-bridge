import CryptoJS from 'crypto-js';

function generateHmac(secret: string, message: string): string {
  return CryptoJS.HmacMD5(message, secret).toString();
}

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

export { encryptToken, decryptToken, generateHmac };
