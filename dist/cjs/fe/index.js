'use strict';

// src/fe/crypto-native.ts
var ASYMMETRIC_ALGO = "RSA-OAEP";
var SYMMETRIC_ALGO = "AES-GCM";
var HMAC_ALGO = "HMAC";
var HMAC_HASH = "SHA-256";
var SYMMETRIC_KEY_LENGTH = 256;
var AES_GCM_IV_LENGTH = 12;
var RSA_HASH = "SHA-256";
var RSA_MODULUS_LENGTH = 4096;
function str2ab(str) {
  return new TextEncoder().encode(str).buffer;
}
function bufferToB64(buffer) {
  const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}
function b64ToAb(b64) {
  const byteString = atob(b64);
  const bytes = new Uint8Array(byteString.length);
  for (let i = 0; i < byteString.length; i++) {
    bytes[i] = byteString.charCodeAt(i);
  }
  return bytes.buffer;
}
async function generateHmacKey() {
  return crypto.subtle.generateKey(
    { name: HMAC_ALGO, hash: HMAC_HASH },
    true,
    ["sign", "verify"]
  );
}
async function signPackage(hmacKey, pkg) {
  const message = str2ab(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag);
  const sig = await crypto.subtle.sign(HMAC_ALGO, hmacKey, message);
  return bufferToB64(sig);
}
async function verifyPackageMac(hmacKey, pkg) {
  const message = str2ab(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag);
  return crypto.subtle.verify(HMAC_ALGO, hmacKey, b64ToAb(pkg.mac), message);
}
async function generateFeKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: ASYMMETRIC_ALGO,
      modulusLength: RSA_MODULUS_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: RSA_HASH
    },
    false,
    // private key non-exportable
    ["encrypt", "decrypt"]
  );
}
async function exportPublicKeyAsPem(key) {
  const exported = await crypto.subtle.exportKey("spki", key);
  const b64 = bufferToB64(exported);
  return `-----BEGIN PUBLIC KEY-----
${b64}
-----END PUBLIC KEY-----`;
}
async function importPublicKeyFromPem(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s/g, "");
  return crypto.subtle.importKey(
    "spki",
    b64ToAb(b64),
    { name: ASYMMETRIC_ALGO, hash: RSA_HASH },
    true,
    ["encrypt"]
  );
}
async function encryptForBackend(payload, bePublicKey) {
  const symmetricKey = await crypto.subtle.generateKey(
    { name: SYMMETRIC_ALGO, length: SYMMETRIC_KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));
  const enrichedPayload = {
    ...payload,
    _nonce: bufferToB64(crypto.getRandomValues(new Uint8Array(16))),
    _issuedAt: Date.now()
  };
  const encryptedWithTag = await crypto.subtle.encrypt(
    { name: SYMMETRIC_ALGO, iv },
    symmetricKey,
    str2ab(JSON.stringify(enrichedPayload))
  );
  const view = new Uint8Array(encryptedWithTag);
  const encryptedPayload = view.slice(0, view.length - 16);
  const authTag = view.slice(view.length - 16);
  const rawSymKey = await crypto.subtle.exportKey("raw", symmetricKey);
  const encryptedKey = await crypto.subtle.encrypt(
    { name: ASYMMETRIC_ALGO },
    bePublicKey,
    rawSymKey
  );
  const pkgWithoutMac = {
    iv: bufferToB64(iv),
    authTag: bufferToB64(authTag),
    encryptedKey: bufferToB64(encryptedKey),
    encryptedPayload: bufferToB64(encryptedPayload)
  };
  const hmacKey = await generateHmacKey();
  const mac = await signPackage(hmacKey, pkgWithoutMac);
  const pkg = { ...pkgWithoutMac, mac };
  const rawHmacKey = await crypto.subtle.exportKey("raw", hmacKey);
  return {
    encryptedPackageB64: bufferToB64(str2ab(JSON.stringify(pkg))),
    hmacKeyB64: bufferToB64(rawHmacKey)
  };
}
async function decryptFromBackend(encryptedPackageB64, fePrivateKey) {
  const pkg = JSON.parse(atob(encryptedPackageB64));
  const rawSymKey = await crypto.subtle.decrypt(
    { name: ASYMMETRIC_ALGO },
    fePrivateKey,
    b64ToAb(pkg.encryptedKey)
  );
  const symmetricKey = await crypto.subtle.importKey(
    "raw",
    rawSymKey,
    { name: SYMMETRIC_ALGO },
    false,
    ["decrypt"]
  );
  const encryptedPayload = b64ToAb(pkg.encryptedPayload);
  const authTag = b64ToAb(pkg.authTag);
  const full = new Uint8Array(encryptedPayload.byteLength + authTag.byteLength);
  full.set(new Uint8Array(encryptedPayload), 0);
  full.set(new Uint8Array(authTag), encryptedPayload.byteLength);
  const decrypted = await crypto.subtle.decrypt(
    { name: SYMMETRIC_ALGO, iv: b64ToAb(pkg.iv) },
    symmetricKey,
    full.buffer
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// src/fe/session.ts
var DEFAULT_SESSION_TTL_MS = 30 * 60 * 1e3;
var SecureCryptoSession = class {
  bePublicKeyPem;
  sessionTtlMs;
  bePublicKey = null;
  feKeyPair = null;
  sessionCreatedAt = 0;
  isInitialized = false;
  initializationPromise = null;
  constructor(options) {
    if (!options.bePublicKeyPem) {
      throw new Error("SecureCryptoSession: bePublicKeyPem is required.");
    }
    this.bePublicKeyPem = options.bePublicKeyPem;
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  }
  // ── Private helpers ─────────────────────────────────────────────────────────
  isSessionExpired() {
    return this.isInitialized && Date.now() - this.sessionCreatedAt > this.sessionTtlMs;
  }
  resetState() {
    this.bePublicKey = null;
    this.feKeyPair = null;
    this.sessionCreatedAt = 0;
    this.isInitialized = false;
    this.initializationPromise = null;
  }
  async ensureInitialized() {
    if (this.isSessionExpired()) this.resetState();
    if (this.isInitialized) return;
    if (this.initializationPromise) return this.initializationPromise;
    this.initializationPromise = (async () => {
      try {
        this.bePublicKey = await importPublicKeyFromPem(this.bePublicKeyPem);
        this.feKeyPair = await generateFeKeyPair();
        this.sessionCreatedAt = Date.now();
        this.isInitialized = true;
      } catch (err) {
        this.initializationPromise = null;
        throw err;
      }
    })();
    return this.initializationPromise;
  }
  // ── Public API ──────────────────────────────────────────────────────────────
  /**
   * Encrypts a payload for the backend.
   *
   * The returned `hmacKeyB64` **must** be forwarded as the `X-HMAC-Key`
   * request header — the backend will reject requests without it.
   */
  async encrypt(payload) {
    await this.ensureInitialized();
    if (!this.bePublicKey || !this.feKeyPair) {
      throw new Error("SecureCryptoSession: initialization failed unexpectedly.");
    }
    const fePublicKeyPem = await exportPublicKeyAsPem(this.feKeyPair.publicKey);
    const result = await encryptForBackend(
      { data: payload, fePublicKey: fePublicKeyPem },
      this.bePublicKey
    );
    return {
      encryptedPackageB64: result.encryptedPackageB64,
      hmacKeyB64: result.hmacKeyB64,
      fePublicKeyPem
    };
  }
  /**
   * Decrypts an encrypted response from the backend.
   */
  async decrypt(encryptedResponse) {
    await this.ensureInitialized();
    if (!this.feKeyPair) {
      throw new Error("SecureCryptoSession: initialization failed unexpectedly.");
    }
    if (!encryptedResponse?.encryptedPackageB64) {
      throw new Error("SecureCryptoSession: missing encryptedPackageB64 in response.");
    }
    return decryptFromBackend(
      encryptedResponse.encryptedPackageB64,
      this.feKeyPair.privateKey
    );
  }
  /**
   * Manually rotate the key pair before the TTL expires.
   * Useful after detecting a suspicious event.
   */
  rotateKeys() {
    this.resetState();
  }
};

exports.SecureCryptoSession = SecureCryptoSession;
exports.decryptFromBackend = decryptFromBackend;
exports.encryptForBackend = encryptForBackend;
exports.exportPublicKeyAsPem = exportPublicKeyAsPem;
exports.generateFeKeyPair = generateFeKeyPair;
exports.importPublicKeyFromPem = importPublicKeyFromPem;
exports.verifyPackageMac = verifyPackageMac;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map