/**
 * @fileoverview Backend response encryption — Node.js only.
 * Uses node:crypto (no TypeScript, pure JS with JSDoc for IDE support).
 */

'use strict';

const {
  publicEncrypt,
  randomBytes,
  createCipheriv,
  createHmac,
  constants,
} = require('node:crypto');

// ── Constants ─────────────────────────────────────────────────────────────────
const SYMMETRIC_KEY_LENGTH = 32;
const AES_GCM_IV_LENGTH    = 12;   // 96-bit — correct for AES-GCM
const RSA_PADDING          = {
  padding:  constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256',
};
const SYMMETRIC_ALGORITHM  = 'aes-256-gcm';
const DEFAULT_MAX_BYTES    = 10 * 1024 * 1024; // 10 MB
const PEM_HEADER_RE        = /^-----BEGIN PUBLIC KEY-----/;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * @param {string} pem
 * @throws {Error} if not a valid PEM public key
 */
function validatePem(pem) {
  if (!PEM_HEADER_RE.test(pem.trim())) {
    throw new Error('fePublicKey does not appear to be a valid PEM public key.');
  }
}

/**
 * HMAC-SHA256 over all ciphertext fields (encrypt-then-MAC).
 * @param {string} hmacKeyB64
 * @param {{ iv: string, encryptedKey: string, encryptedPayload: string, authTag: string }} pkg
 * @returns {string} base64 MAC
 */
function signPackage(hmacKeyB64, pkg) {
  return createHmac('sha256', Buffer.from(hmacKeyB64, 'base64'))
    .update(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag)
    .digest('base64');
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Encrypts `payload` for the frontend using hybrid AES-256-GCM + RSA-OAEP.
 *
 * @param {unknown} payload - Any JSON-serialisable value
 * @param {string}  fePublicKey - PEM public key from `req.body.fePublicKey`
 * @param {string}  hmacKeyB64  - HMAC key from `req.headers['x-hmac-key']`
 * @param {{ maxPayloadBytes?: number }} [options]
 * @returns {Promise<string>} Base64-encoded encrypted package
 *
 * @example
 * const encrypted = await encryptResponsePayload(
 *   { secret: 'hello' },
 *   req.body.fePublicKey,
 *   req.headers['x-hmac-key'],
 * );
 * res.json({ encryptedPackageB64: encrypted });
 */
async function encryptResponsePayload(payload, fePublicKey, hmacKeyB64, options = {}) {
  const maxBytes = options.maxPayloadBytes ?? DEFAULT_MAX_BYTES;

  validatePem(fePublicKey);

  if (!hmacKeyB64) {
    throw new Error('hmacKeyB64 is required — pass req.headers["x-hmac-key"].');
  }

  const payloadJson = JSON.stringify(payload);
  if (Buffer.byteLength(payloadJson, 'utf8') > maxBytes) {
    throw new Error(`Payload exceeds maximum allowed size (${maxBytes} bytes).`);
  }

  try {
    const symmetricKey     = randomBytes(SYMMETRIC_KEY_LENGTH);
    const iv               = randomBytes(AES_GCM_IV_LENGTH);
    const cipher           = createCipheriv(SYMMETRIC_ALGORITHM, symmetricKey, iv);
    const encryptedPayload = Buffer.concat([
      cipher.update(payloadJson, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const encryptedSymmetricKey = publicEncrypt(
      { key: fePublicKey, ...RSA_PADDING },
      symmetricKey,
    );

    /** @type {{ iv: string, encryptedKey: string, encryptedPayload: string, authTag: string }} */
    const pkgWithoutMac = {
      iv:               iv.toString('base64'),
      encryptedKey:     encryptedSymmetricKey.toString('base64'),
      encryptedPayload: encryptedPayload.toString('base64'),
      authTag:          authTag.toString('base64'),
    };

    const mac = signPackage(hmacKeyB64, pkgWithoutMac);
    const pkg = { ...pkgWithoutMac, mac };

    return Buffer.from(JSON.stringify(pkg)).toString('base64');
  } catch (error) {
    throw new Error('Response payload encryption failed.', { cause: error });
  }
}

module.exports = { encryptResponsePayload };
