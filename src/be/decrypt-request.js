/**
 * @fileoverview Backend request decryption — Express middleware + standalone function.
 * Node.js only. Pure JS with JSDoc for IDE type hints.
 */

'use strict';

const {
  privateDecrypt,
  createDecipheriv,
  createHmac,
  constants,
  createPrivateKey,
} = require('node:crypto');

// ── Constants ─────────────────────────────────────────────────────────────────
const RSA_PADDING = {
  padding:  constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256',
};
const SYMMETRIC_ALGORITHM = 'aes-256-gcm';
const DEFAULT_MAX_BYTES   = 10 * 1024 * 1024; // 10 MB
const DEFAULT_EXPIRY_MS   = 5 * 60 * 1000;    // 5 minutes
const PEM_HEADER_RE       = /^-----BEGIN PUBLIC KEY-----/;

// ── Private key store (module-level singleton) ────────────────────────────────

/** @type {import('node:crypto').KeyObject | null} */
let _bePrivateKeyObj = null;

/**
 * Load the backend RSA private key once at server startup.
 * Accepts a raw PEM string or a JSON-stringified PEM (as some env loaders produce).
 * Idempotent — safe to call multiple times.
 *
 * @param {string} rawKeyEnv - Value of process.env.BE_PRIVATE_KEY
 * @returns {void}
 *
 * @example
 * // app.js — call before registering any routes
 * const { loadBePrivateKey } = require('secure-crypto-kit/be');
 * loadBePrivateKey(process.env.BE_PRIVATE_KEY);
 */
function loadBePrivateKey(rawKeyEnv) {
  if (_bePrivateKeyObj) return; // idempotent

  /** @type {string} */
  let pem;
  try {
    pem = JSON.parse(rawKeyEnv); // support JSON-wrapped PEM
  } catch {
    pem = rawKeyEnv;
  }

  _bePrivateKeyObj = createPrivateKey({ key: pem, format: 'pem' });
}

// ── Nonce store — in-process replay protection ────────────────────────────────
// For multi-instance deployments replace this with a shared Redis cache.

/** @type {Map<string, number>} nonce → expiresAt timestamp */
const _seenNonces = new Map();

/**
 * @param {number} requestExpiryMs
 */
function _pruneNonces(requestExpiryMs) {
  const cutoff = Date.now() - requestExpiryMs;
  for (const [nonce, expiresAt] of _seenNonces) {
    if (expiresAt < cutoff) _seenNonces.delete(nonce);
  }
}

/**
 * Returns true if the nonce is fresh and unseen; registers it if so.
 * @param {string} nonce
 * @param {number} issuedAt
 * @param {number} requestExpiryMs
 * @returns {boolean}
 */
function _checkAndRegisterNonce(nonce, issuedAt, requestExpiryMs) {
  _pruneNonces(requestExpiryMs);
  const now = Date.now();
  if (now - issuedAt > requestExpiryMs) return false; // expired
  if (issuedAt > now + 30_000)          return false; // future clock skew (30 s)
  if (_seenNonces.has(nonce))           return false; // replay
  _seenNonces.set(nonce, now + requestExpiryMs);
  return true;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Constant-time HMAC verification.
 * @param {string} hmacKeyB64
 * @param {{ iv: string, encryptedKey: string, encryptedPayload: string, authTag: string, mac: string }} pkg
 * @returns {boolean}
 */
function _verifyMac(hmacKeyB64, pkg) {
  const expected = createHmac('sha256', Buffer.from(hmacKeyB64, 'base64'))
    .update(pkg.iv + pkg.encryptedKey + pkg.encryptedPayload + pkg.authTag)
    .digest('base64');

  const a = Buffer.from(expected, 'base64');
  const b = Buffer.from(pkg.mac,  'base64');
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * @param {string} pem
 * @throws {Error}
 */
function _validatePem(pem) {
  if (!PEM_HEADER_RE.test(pem.trim())) {
    throw new Error('fePublicKey is not a valid PEM public key.');
  }
}

// ── Core decrypt function ─────────────────────────────────────────────────────

/**
 * Framework-agnostic decrypt — use when not on Express.
 * Throws on MAC failure, replay, or decryption error.
 *
 * @param {string} encryptedPackageB64 - From req.body.encryptedPackageB64
 * @param {string} hmacKeyB64          - From req.headers['x-hmac-key']
 * @param {{ maxBodyBytes?: number, requestExpiryMs?: number }} [options]
 * @returns {{ data?: unknown, payload?: unknown, fePublicKey?: string, _nonce: string, _issuedAt: number }}
 *
 * @example
 * const { decryptRequest } = require('secure-crypto-kit/be');
 * const decrypted = decryptRequest(body.encryptedPackageB64, hmacKey);
 * const payload   = decrypted.data;
 * const feKey     = decrypted.fePublicKey;
 */
function decryptRequest(encryptedPackageB64, hmacKeyB64, options = {}) {
  const maxBytes = options.maxBodyBytes    ?? DEFAULT_MAX_BYTES;
  const expiryMs = options.requestExpiryMs ?? DEFAULT_EXPIRY_MS;

  if (!_bePrivateKeyObj) {
    throw new Error(
      'Call loadBePrivateKey(process.env.BE_PRIVATE_KEY) during server startup before decrypting.',
    );
  }

  if (Buffer.byteLength(encryptedPackageB64, 'utf8') > maxBytes) {
    throw new Error('Encrypted payload exceeds maximum allowed size.');
  }

  const pkg = JSON.parse(Buffer.from(encryptedPackageB64, 'base64').toString('utf8'));

  if (!pkg.iv || !pkg.encryptedKey || !pkg.encryptedPayload || !pkg.authTag || !pkg.mac) {
    throw new Error('Malformed encrypted package — missing required fields.');
  }

  // Verify MAC BEFORE RSA decrypt (fail-fast — avoids burning expensive RSA on garbage)
  if (!_verifyMac(hmacKeyB64, pkg)) {
    throw new Error('Package MAC verification failed — possible tampering.');
  }

  const symmetricKey = privateDecrypt(
    { key: _bePrivateKeyObj, ...RSA_PADDING },
    Buffer.from(pkg.encryptedKey, 'base64'),
  );

  const decipher = createDecipheriv(
    SYMMETRIC_ALGORITHM,
    symmetricKey,
    Buffer.from(pkg.iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(pkg.authTag, 'base64'));

  const decryptedStr = Buffer.concat([
    decipher.update(Buffer.from(pkg.encryptedPayload, 'base64')),
    decipher.final(),
  ]).toString('utf8');

  const decrypted = JSON.parse(decryptedStr);

  // Replay protection
  const { _nonce, _issuedAt } = decrypted;
  if (typeof _nonce !== 'string' || typeof _issuedAt !== 'number') {
    throw new Error('Missing replay-protection fields (_nonce, _issuedAt).');
  }
  if (!_checkAndRegisterNonce(_nonce, _issuedAt, expiryMs)) {
    throw new Error('Request rejected: replayed or expired.');
  }

  // Validate fePublicKey if present
  if (typeof decrypted.fePublicKey === 'string') {
    _validatePem(decrypted.fePublicKey);
  }

  return decrypted;
}

// ── Express middleware ────────────────────────────────────────────────────────

/**
 * Express middleware — decrypts the request body in-place.
 *
 * After this middleware runs:
 * - `req.body.payload`     → your decrypted data
 * - `req.body.fePublicKey` → FE RSA public key (pass to encryptResponsePayload)
 *
 * Returns 400 for malformed requests, 401 for security failures.
 *
 * @param {{ maxBodyBytes?: number, requestExpiryMs?: number }} [options]
 * @returns {import('express').RequestHandler}
 *
 * @example
 * const { loadBePrivateKey, decryptWebRequestPayload } = require('secure-crypto-kit/be');
 *
 * loadBePrivateKey(process.env.BE_PRIVATE_KEY);
 * app.use('/api', decryptWebRequestPayload());
 */
function decryptWebRequestPayload(options = {}) {
  return function (req, res, next) {
    // ── Dev/test bypass (secret-gated, never by User-Agent) ────────────────
    const bypassSecret = process.env.ENCRYPTION_BYPASS_SECRET;
    if (bypassSecret && req.headers['x-bypass-secret'] === bypassSecret) {
      req.body.payload = req.body.payload ?? req.body;
      next();
      return;
    }

    const encryptedPackageB64 = req.body.encryptedPackageB64;
    const hmacKeyB64          = req.headers['x-hmac-key'];

    if (!encryptedPackageB64) {
      res.status(400).json({ message: 'Missing encryptedPackageB64.' });
      return;
    }
    if (!hmacKeyB64) {
      res.status(400).json({ message: 'Missing X-HMAC-Key header.' });
      return;
    }

    try {
      const decrypted = decryptRequest(encryptedPackageB64, hmacKeyB64, options);

      req.body.fePublicKey = decrypted.fePublicKey ?? '';

      if (decrypted.data !== undefined) {
        req.body.payload = decrypted.data?.payload ?? decrypted.data;
      } else if (decrypted.payload !== undefined) {
        req.body.payload = decrypted.payload;
      } else {
        req.body.payload = decrypted;
      }

      next();
    } catch (error) {
      // Return 401 — never expose internal error details to the client
      res.status(401).json({ message: 'Invalid request.' });
      next(error); // forward to your error-logging middleware
    }
  };
}

module.exports = {
  loadBePrivateKey,
  decryptRequest,
  decryptWebRequestPayload,
};
