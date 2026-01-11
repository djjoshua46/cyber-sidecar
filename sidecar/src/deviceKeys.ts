// src/deviceKeys.ts
//
// Phase-1 helper for device key registration using WebCrypto.
// Assumes: running in a secure context (https:// or http://localhost).

const DEVICE_ID_KEY = "sidecar.deviceId";
const PRIVATE_KEY_JWK_KEY = "sidecar.privateKey.jwk";
const PUBLIC_KEY_PEM_KEY = "sidecar.publicKey.pem";

/**
 * Generate or reuse a stable logical device id for this browser.
 */
export function getOrCreateDeviceId(): string {
  let id = localStorage.getItem(DEVICE_ID_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(DEVICE_ID_KEY, id);
  }
  return id;
}

/**
 * Generate a P-256 ECDSA keypair using WebCrypto.
 */
async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true, // extractable
    ["sign", "verify"],
  );
}

/**
 * Convert an ArrayBuffer SPKI to PEM string.
 */
function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function spkiToPem(spki: ArrayBuffer): string {
  const b64 = arrayBufferToBase64(spki);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/**
 * Ensure this device has a keypair, persisted locally.
 * Returns { deviceId, publicKeyPem }.
 */
export async function ensureLocalKeypair(): Promise<{
  deviceId: string;
  publicKeyPem: string;
}> {
  const deviceId = getOrCreateDeviceId();

  let publicKeyPem = localStorage.getItem(PUBLIC_KEY_PEM_KEY);
  let privateKeyJwkStr = localStorage.getItem(PRIVATE_KEY_JWK_KEY);

  if (publicKeyPem && privateKeyJwkStr) {
    return { deviceId, publicKeyPem };
  }

  const { publicKey, privateKey } = await generateKeyPair();

  // Export public key as SPKI → PEM
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  publicKeyPem = spkiToPem(spki);
  localStorage.setItem(PUBLIC_KEY_PEM_KEY, publicKeyPem);

  // Export private key as JWK (Phase-1)
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  privateKeyJwkStr = JSON.stringify(jwk);
  localStorage.setItem(PRIVATE_KEY_JWK_KEY, privateKeyJwkStr);

  return { deviceId, publicKeyPem };
}

/**
 * Call the backend to register this device's public key.
 */
export async function registerDeviceWithBackend(opts: {
  apiBase: string;
  tenantId: string;
  userId: string;
  displayName?: string;
}): Promise<string> {
  const { apiBase, tenantId, userId, displayName } = opts;
  const { deviceId, publicKeyPem } = await ensureLocalKeypair();

  const res = await fetch(`${apiBase}/api/devices/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      tenant_id: tenantId,
      user_id: userId,
      device_id: deviceId,
      display_name: displayName ?? navigator.userAgent,
      public_key_pem: publicKeyPem,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `Failed to register device: ${res.status} ${text || res.statusText}`,
    );
  }

  return deviceId;
}
