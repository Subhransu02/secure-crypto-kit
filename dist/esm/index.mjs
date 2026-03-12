import { __commonJS, __require, __export, verifyPackageMac, importPublicKeyFromPem, generateFeKeyPair, exportPublicKeyAsPem, encryptForBackend, decryptFromBackend, SecureCryptoSession, __reExport, __toESM } from './chunk-SSW2OLDQ.mjs';
export { SecureCryptoSession, decryptFromBackend, encryptForBackend, exportPublicKeyAsPem, generateFeKeyPair, importPublicKeyFromPem, verifyPackageMac } from './chunk-SSW2OLDQ.mjs';

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
    var SYMMETRIC_KEY_LENGTH = 32;
    var AES_GCM_IV_LENGTH = 12;
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
    function signPackage(hmacKeyB64, pkg) {
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
        const symmetricKey = randomBytes(SYMMETRIC_KEY_LENGTH);
        const iv = randomBytes(AES_GCM_IV_LENGTH);
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
        const mac = signPackage(hmacKeyB64, pkgWithoutMac);
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
__reExport(src_exports, __toESM(require_be()));
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map