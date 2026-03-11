/**
 * Type declarations for secure-crypto-kit/be
 * The implementation is plain JS; this file gives TypeScript consumers full intellisense.
 */

import type { DecryptMiddlewareOptions, EncryptResponseOptions } from '../types.js';
import type { RequestHandler } from 'express';

// ── loadBePrivateKey ──────────────────────────────────────────────────────────

/**
 * Load the backend RSA private key once at server startup.
 * Accepts a raw PEM string or a JSON-stringified PEM.
 * Idempotent — safe to call multiple times.
 *
 * @example
 * loadBePrivateKey(process.env.BE_PRIVATE_KEY!);
 */
export function loadBePrivateKey(rawKeyEnv: string): void;

// ── decryptRequest ────────────────────────────────────────────────────────────

export interface DecryptedPayload {
  data?:        unknown;
  payload?:     unknown;
  fePublicKey?: string;
  _nonce:       string;
  _issuedAt:    number;
}

/**
 * Framework-agnostic decrypt function.
 * Throws on MAC failure, replay detection, or decryption error.
 *
 * @param encryptedPackageB64 - From `req.body.encryptedPackageB64`
 * @param hmacKeyB64          - From `req.headers['x-hmac-key']`
 * @param options             - Optional size / expiry limits
 */
export function decryptRequest(
  encryptedPackageB64: string,
  hmacKeyB64:          string,
  options?:            DecryptMiddlewareOptions,
): DecryptedPayload;

// ── decryptWebRequestPayload ──────────────────────────────────────────────────

/**
 * Express middleware — decrypts `req.body.encryptedPackageB64` in-place.
 *
 * After the middleware runs:
 * - `req.body.payload`     → decrypted data
 * - `req.body.fePublicKey` → frontend RSA public key PEM
 *
 * Returns `400` for malformed requests, `401` for security failures.
 *
 * @example
 * loadBePrivateKey(process.env.BE_PRIVATE_KEY!);
 * app.use('/api', decryptWebRequestPayload());
 */
export function decryptWebRequestPayload(options?: DecryptMiddlewareOptions): RequestHandler;

// ── encryptResponsePayload ────────────────────────────────────────────────────

/**
 * Encrypts `payload` for the frontend using AES-256-GCM + RSA-OAEP.
 *
 * @param payload      - Any JSON-serialisable value
 * @param fePublicKey  - PEM key from `req.body.fePublicKey`
 * @param hmacKeyB64   - HMAC key from `req.headers['x-hmac-key']`
 * @param options      - Optional size limits
 * @returns Base64-encoded encrypted package string
 *
 * @example
 * const pkg = await encryptResponsePayload({ ok: true }, req.body.fePublicKey, req.headers['x-hmac-key'] as string);
 * res.json({ encryptedPackageB64: pkg });
 */
export function encryptResponsePayload(
  payload:     unknown,
  fePublicKey: string,
  hmacKeyB64:  string,
  options?:    EncryptResponseOptions,
): Promise<string>;

export type { DecryptMiddlewareOptions, EncryptResponseOptions } from '../types.js';
