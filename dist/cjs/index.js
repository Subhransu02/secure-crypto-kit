'use strict';

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget);
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/be/encrypt-response.js
var require_encrypt_response = __commonJS({
  "src/be/encrypt-response.js"(exports$1, module) {
    var {
      publicEncrypt,
      randomBytes,
      createCipheriv,
      createHmac,
      constants
    } = __require("crypto");
    var SYMMETRIC_KEY_LENGTH2 = 32;
    var AES_GCM_IV_LENGTH2 = 12;
    var RSA_PADDING = {
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    };
    var SYMMETRIC_ALGORITHM = "aes-256-gcm";
    var DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
    var PEM_HEADER_RE = /^-----BEGIN PUBLIC KEY-----/;
    function validatePem(pem) {
      if (!PEM_HEADER_RE.test(pem.trim())) {
        throw new Error("fePublicKey does not appear to be a valid PEM public key.");
      }
    }
    function signPackage2(hmacKeyB64, pkg) {
      return createHmac("sha256", Buffer.from(hmacKeyB64, "base64")).update(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag).digest("base64");
    }
    async function encryptResponsePayload(payload, fePublicKey, hmacKeyB64, options = {}) {
      const maxBytes = options.maxPayloadBytes ?? DEFAULT_MAX_BYTES;
      validatePem(fePublicKey);
      if (!hmacKeyB64) {
        throw new Error('hmacKeyB64 is required \u2014 pass req.headers["x-hmac-key"].');
      }
      const payloadJson = JSON.stringify(payload);
      if (Buffer.byteLength(payloadJson, "utf8") > maxBytes) {
        throw new Error(`Payload exceeds maximum allowed size (${maxBytes} bytes).`);
      }
      try {
        const symmetricKey = randomBytes(SYMMETRIC_KEY_LENGTH2);
        const iv = randomBytes(AES_GCM_IV_LENGTH2);
        const cipher = createCipheriv(SYMMETRIC_ALGORITHM, symmetricKey, iv);
        const encryptedPayload = Buffer.concat([
          cipher.update(payloadJson, "utf8"),
          cipher.final()
        ]);
        const authTag = cipher.getAuthTag();
        const encryptedSymmetricKey = publicEncrypt(
          { key: fePublicKey, ...RSA_PADDING },
          symmetricKey
        );
        const pkgWithoutMac = {
          iv: iv.toString("base64"),
          encryptedKey: encryptedSymmetricKey.toString("base64"),
          encryptedPayload: encryptedPayload.toString("base64"),
          authTag: authTag.toString("base64")
        };
        const mac = signPackage2(hmacKeyB64, pkgWithoutMac);
        const pkg = { ...pkgWithoutMac, mac };
        return Buffer.from(JSON.stringify(pkg)).toString("base64");
      } catch (error) {
        throw new Error("Response payload encryption failed.", { cause: error });
      }
    }
    module.exports = { encryptResponsePayload };
  }
});

// src/be/decrypt-request.js
var require_decrypt_request = __commonJS({
  "src/be/decrypt-request.js"(exports$1, module) {
    var {
      privateDecrypt,
      createDecipheriv,
      createHmac,
      constants,
      createPrivateKey
    } = __require("crypto");
    var RSA_PADDING = {
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    };
    var SYMMETRIC_ALGORITHM = "aes-256-gcm";
    var DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
    var DEFAULT_EXPIRY_MS = 5 * 60 * 1e3;
    var PEM_HEADER_RE = /^-----BEGIN PUBLIC KEY-----/;
    var _bePrivateKeyObj = null;
    function loadBePrivateKey(rawKeyEnv) {
      if (_bePrivateKeyObj) return;
      let pem;
      try {
        pem = JSON.parse(rawKeyEnv);
      } catch {
        pem = rawKeyEnv;
      }
      _bePrivateKeyObj = createPrivateKey({ key: pem, format: "pem" });
    }
    var _seenNonces = /* @__PURE__ */ new Map();
    function _pruneNonces(requestExpiryMs) {
      const cutoff = Date.now() - requestExpiryMs;
      for (const [nonce, expiresAt] of _seenNonces) {
        if (expiresAt < cutoff) _seenNonces.delete(nonce);
      }
    }
    function _checkAndRegisterNonce(nonce, issuedAt, requestExpiryMs) {
      _pruneNonces(requestExpiryMs);
      const now = Date.now();
      if (now - issuedAt > requestExpiryMs) return false;
      if (issuedAt > now + 3e4) return false;
      if (_seenNonces.has(nonce)) return false;
      _seenNonces.set(nonce, now + requestExpiryMs);
      return true;
    }
    function _verifyMac(hmacKeyB64, pkg) {
      const expected = createHmac("sha256", Buffer.from(hmacKeyB64, "base64")).update(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag).digest("base64");
      const a = Buffer.from(expected, "base64");
      const b = Buffer.from(pkg.mac, "base64");
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    }
    function _validatePem(pem) {
      if (!PEM_HEADER_RE.test(pem.trim())) {
        throw new Error("fePublicKey is not a valid PEM public key.");
      }
    }
    function decryptRequest(encryptedPackageB64, hmacKeyB64, options = {}) {
      const maxBytes = options.maxBodyBytes ?? DEFAULT_MAX_BYTES;
      const expiryMs = options.requestExpiryMs ?? DEFAULT_EXPIRY_MS;
      if (!_bePrivateKeyObj) {
        throw new Error(
          "Call loadBePrivateKey(process.env.BE_PRIVATE_KEY) during server startup before decrypting."
        );
      }
      if (Buffer.byteLength(encryptedPackageB64, "utf8") > maxBytes) {
        throw new Error("Encrypted payload exceeds maximum allowed size.");
      }
      const pkg = JSON.parse(Buffer.from(encryptedPackageB64, "base64").toString("utf8"));
      if (!pkg.iv || !pkg.encryptedKey || !pkg.encryptedPayload || !pkg.authTag || !pkg.mac) {
        throw new Error("Malformed encrypted package \u2014 missing required fields.");
      }
      if (!_verifyMac(hmacKeyB64, pkg)) {
        throw new Error("Package MAC verification failed \u2014 possible tampering.");
      }
      const symmetricKey = privateDecrypt(
        { key: _bePrivateKeyObj, ...RSA_PADDING },
        Buffer.from(pkg.encryptedKey, "base64")
      );
      const decipher = createDecipheriv(
        SYMMETRIC_ALGORITHM,
        symmetricKey,
        Buffer.from(pkg.iv, "base64")
      );
      decipher.setAuthTag(Buffer.from(pkg.authTag, "base64"));
      const decryptedStr = Buffer.concat([
        decipher.update(Buffer.from(pkg.encryptedPayload, "base64")),
        decipher.final()
      ]).toString("utf8");
      const decrypted = JSON.parse(decryptedStr);
      const { _nonce, _issuedAt } = decrypted;
      if (typeof _nonce !== "string" || typeof _issuedAt !== "number") {
        throw new Error("Missing replay-protection fields (_nonce, _issuedAt).");
      }
      if (!_checkAndRegisterNonce(_nonce, _issuedAt, expiryMs)) {
        throw new Error("Request rejected: replayed or expired.");
      }
      if (typeof decrypted.fePublicKey === "string") {
        _validatePem(decrypted.fePublicKey);
      }
      return decrypted;
    }
    function decryptWebRequestPayload(options = {}) {
      return function(req, res, next) {
        const bypassSecret = process.env.ENCRYPTION_BYPASS_SECRET;
        if (bypassSecret && req.headers["x-bypass-secret"] === bypassSecret) {
          req.body.payload = req.body.payload ?? req.body;
          next();
          return;
        }
        const encryptedPackageB64 = req.body.encryptedPackageB64;
        const hmacKeyB64 = req.headers["x-hmac-key"];
        if (!encryptedPackageB64) {
          res.status(400).json({ message: "Missing encryptedPackageB64." });
          return;
        }
        if (!hmacKeyB64) {
          res.status(400).json({ message: "Missing X-HMAC-Key header." });
          return;
        }
        try {
          const decrypted = decryptRequest(encryptedPackageB64, hmacKeyB64, options);
          req.body.fePublicKey = decrypted.fePublicKey ?? "";
          if (decrypted.data !== void 0) {
            req.body.payload = decrypted.data?.payload ?? decrypted.data;
          } else if (decrypted.payload !== void 0) {
            req.body.payload = decrypted.payload;
          } else {
            req.body.payload = decrypted;
          }
          next();
        } catch (error) {
          res.status(401).json({ message: "Invalid request." });
          next(error);
        }
      };
    }
    module.exports = {
      loadBePrivateKey,
      decryptRequest,
      decryptWebRequestPayload
    };
  }
});

// src/be/index.js
var require_be = __commonJS({
  "src/be/index.js"(exports$1, module) {
    var { encryptResponsePayload } = require_encrypt_response();
    var { loadBePrivateKey, decryptRequest, decryptWebRequestPayload } = require_decrypt_request();
    module.exports = {
      encryptResponsePayload,
      loadBePrivateKey,
      decryptRequest,
      decryptWebRequestPayload
    };
  }
});

// src/index.ts
var src_exports = {};
__export(src_exports, {
  SecureCryptoSession: () => SecureCryptoSession,
  decryptFromBackend: () => decryptFromBackend,
  encryptForBackend: () => encryptForBackend,
  exportPublicKeyAsPem: () => exportPublicKeyAsPem,
  generateFeKeyPair: () => generateFeKeyPair,
  importPublicKeyFromPem: () => importPublicKeyFromPem,
  verifyPackageMac: () => verifyPackageMac
});

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

// src/index.ts
__reExport(src_exports, __toESM(require_be()));

exports.SecureCryptoSession = SecureCryptoSession;
exports.decryptFromBackend = decryptFromBackend;
exports.encryptForBackend = encryptForBackend;
exports.exportPublicKeyAsPem = exportPublicKeyAsPem;
exports.generateFeKeyPair = generateFeKeyPair;
exports.importPublicKeyFromPem = importPublicKeyFromPem;
exports.verifyPackageMac = verifyPackageMac;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map