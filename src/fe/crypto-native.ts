/**
 * @module secure-crypto-kit/fe
 * Browser WebCrypto primitives — safe to import in any bundler/framework.
 * Requires the Web Crypto API (available in all modern browsers and Node ≥ 19).
 */

import type { IEncryptedPackage, EncryptResult } from '../types.js';

// ── Algorithm constants ───────────────────────────────────────────────────────
const ASYMMETRIC_ALGO      = 'RSA-OAEP'  as const;
const SYMMETRIC_ALGO       = 'AES-GCM'   as const;
const HMAC_ALGO            = 'HMAC'       as const;
const HMAC_HASH            = 'SHA-256'    as const;
const SYMMETRIC_KEY_LENGTH = 256;
const AES_GCM_IV_LENGTH    = 12;   // 96-bit — the only length formally spec'd for AES-GCM
const RSA_HASH             = 'SHA-256'   as const;
const RSA_MODULUS_LENGTH   = 4096;

// ── Encoding helpers ──────────────────────────────────────────────────────────

function str2ab(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer as ArrayBuffer;
}

/** Stack-safe base64 encoder — avoids spread into Function.apply */
function bufferToB64(buffer: ArrayBuffer | Uint8Array): string {
  const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]!);
  }
  return btoa(binary);
}

function b64ToAb(b64: string): ArrayBuffer {
  const byteString = atob(b64);
  const bytes      = new Uint8Array(byteString.length);
  for (let i = 0; i < byteString.length; i++) {
    bytes[i] = byteString.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

// ── HMAC helpers ──────────────────────────────────────────────────────────────

async function generateHmacKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: HMAC_ALGO, hash: HMAC_HASH },
    true,
    ['sign', 'verify'],
  );
}

async function signPackage(
  hmacKey: CryptoKey,
  pkg: Omit<IEncryptedPackage, 'mac'>,
): Promise<string> {
  const message = str2ab(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag);
  const sig     = await crypto.subtle.sign(HMAC_ALGO, hmacKey, message);
  return bufferToB64(sig);
}

export async function verifyPackageMac(
  hmacKey: CryptoKey,
  pkg:     IEncryptedPackage,
): Promise<boolean> {
  const message = str2ab(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag);
  return crypto.subtle.verify(HMAC_ALGO, hmacKey, b64ToAb(pkg.mac), message);
}

// ── Key management ────────────────────────────────────────────────────────────

/**
 * Generate an RSA-OAEP 4096-bit key pair.
 * The private key is **non-exportable** — it cannot be extracted from the
 * WebCrypto key store, minimising the exfiltration window.
 */
export async function generateFeKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name:           ASYMMETRIC_ALGO,
      modulusLength:  RSA_MODULUS_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash:           RSA_HASH,
    },
    false,            // private key non-exportable
    ['encrypt', 'decrypt'],
  );
}

export async function exportPublicKeyAsPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', key);
  const b64      = bufferToB64(exported);
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

export async function importPublicKeyFromPem(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '')
    .replace(/\s/g, '');
  return crypto.subtle.importKey(
    'spki',
    b64ToAb(b64),
    { name: ASYMMETRIC_ALGO, hash: RSA_HASH },
    true,
    ['encrypt'],
  );
}

// ── Encryption ────────────────────────────────────────────────────────────────

/**
 * Encrypts a payload object for the backend using hybrid encryption:
 * - Ephemeral AES-256-GCM for the payload (96-bit IV)
 * - RSA-OAEP-4096 to wrap the AES key
 * - HMAC-SHA256 over all ciphertext fields (encrypt-then-MAC)
 * - Nonce + timestamp embedded for replay protection
 *
 * @returns `encryptedPackageB64` — send as request body
 * @returns `hmacKeyB64`          — send as `X-HMAC-Key` header
 */
export async function encryptForBackend(
  payload:     object,
  bePublicKey: CryptoKey,
): Promise<EncryptResult> {
  // 1. Ephemeral AES-256-GCM key
  const symmetricKey = await crypto.subtle.generateKey(
    { name: SYMMETRIC_ALGO, length: SYMMETRIC_KEY_LENGTH },
    true,
    ['encrypt', 'decrypt'],
  );

  // 2. 96-bit IV
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));

  // 3. Embed nonce + timestamp for replay protection
  const enrichedPayload = {
    ...(payload as object),
    _nonce:    bufferToB64(crypto.getRandomValues(new Uint8Array(16))),
    _issuedAt: Date.now(),
  };

  // 4. AES-GCM encrypt
  const encryptedWithTag = await crypto.subtle.encrypt(
    { name: SYMMETRIC_ALGO, iv },
    symmetricKey,
    str2ab(JSON.stringify(enrichedPayload)),
  );
  const view             = new Uint8Array(encryptedWithTag);
  const encryptedPayload = view.slice(0, view.length - 16);
  const authTag          = view.slice(view.length - 16);

  // 5. Wrap AES key with backend RSA public key
  const rawSymKey    = await crypto.subtle.exportKey('raw', symmetricKey);
  const encryptedKey = await crypto.subtle.encrypt(
    { name: ASYMMETRIC_ALGO },
    bePublicKey,
    rawSymKey,
  );

  // 6. Assemble package (without MAC)
  const pkgWithoutMac: Omit<IEncryptedPackage, 'mac'> = {
    iv:               bufferToB64(iv),
    authTag:          bufferToB64(authTag),
    encryptedKey:     bufferToB64(encryptedKey),
    encryptedPayload: bufferToB64(encryptedPayload),
  };

  // 7. Encrypt-then-MAC
  const hmacKey    = await generateHmacKey();
  const mac        = await signPackage(hmacKey, pkgWithoutMac);
  const pkg: IEncryptedPackage = { ...pkgWithoutMac, mac };

  const rawHmacKey = await crypto.subtle.exportKey('raw', hmacKey);

  return {
    encryptedPackageB64: bufferToB64(str2ab(JSON.stringify(pkg))),
    hmacKeyB64:          bufferToB64(rawHmacKey),
  };
}

// ── Decryption ────────────────────────────────────────────────────────────────

/**
 * Decrypts a base64-encoded package sent by the backend.
 */
export async function decryptFromBackend(
  encryptedPackageB64: string,
  fePrivateKey:        CryptoKey,
): Promise<Record<string, unknown>> {
  const pkg: IEncryptedPackage = JSON.parse(atob(encryptedPackageB64)) as IEncryptedPackage;

  const rawSymKey = await crypto.subtle.decrypt(
    { name: ASYMMETRIC_ALGO },
    fePrivateKey,
    b64ToAb(pkg.encryptedKey),
  );
  const symmetricKey = await crypto.subtle.importKey(
    'raw',
    rawSymKey,
    { name: SYMMETRIC_ALGO },
    false,
    ['decrypt'],
  );

  const encryptedPayload = b64ToAb(pkg.encryptedPayload);
  const authTag          = b64ToAb(pkg.authTag);
  const full             = new Uint8Array(encryptedPayload.byteLength + authTag.byteLength);
  full.set(new Uint8Array(encryptedPayload), 0);
  full.set(new Uint8Array(authTag), encryptedPayload.byteLength);

  const decrypted = await crypto.subtle.decrypt(
    { name: SYMMETRIC_ALGO, iv: b64ToAb(pkg.iv) },
    symmetricKey,
    full.buffer as ArrayBuffer,
  );

  return JSON.parse(new TextDecoder().decode(decrypted)) as Record<string, unknown>;
}
