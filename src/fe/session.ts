/**
 * SecureCryptoSession — stateful FE crypto session manager.
 *
 * Usage:
 * ```ts
 * import { SecureCryptoSession } from 'secure-crypto-kit/fe';
 *
 * const session = new SecureCryptoSession({
 *   bePublicKeyPem: import.meta.env.VITE_BE_PUBLIC_KEY,
 * });
 *
 * // Encrypt a request
 * const { encryptedPackageB64, hmacKeyB64 } = await session.encrypt({ userId: 1 });
 * await fetch('/api/data', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json', 'X-HMAC-Key': hmacKeyB64 },
 *   body: JSON.stringify({ encryptedPackageB64 }),
 * });
 *
 * // Decrypt a response
 * const data = await session.decrypt(await res.json());
 * ```
 */

import {
  generateFeKeyPair,
  exportPublicKeyAsPem,
  importPublicKeyFromPem,
  encryptForBackend,
  decryptFromBackend,
} from './crypto-native.js';
import type { SessionOptions, EncryptOutput } from '../types.js';

const DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

export class SecureCryptoSession {
  private readonly bePublicKeyPem: string;
  private readonly sessionTtlMs:  number;

  private bePublicKey:           CryptoKey | null  = null;
  private feKeyPair:             CryptoKeyPair | null = null;
  private sessionCreatedAt:      number             = 0;
  private isInitialized:         boolean            = false;
  private initializationPromise: Promise<void> | null = null;

  constructor(options: SessionOptions) {
    if (!options.bePublicKeyPem) {
      throw new Error('SecureCryptoSession: bePublicKeyPem is required.');
    }
    this.bePublicKeyPem = options.bePublicKeyPem;
    this.sessionTtlMs   = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private isSessionExpired(): boolean {
    return this.isInitialized && Date.now() - this.sessionCreatedAt > this.sessionTtlMs;
  }

  private resetState(): void {
    this.bePublicKey           = null;
    this.feKeyPair             = null;
    this.sessionCreatedAt      = 0;
    this.isInitialized         = false;
    this.initializationPromise = null;
  }

  private async ensureInitialized(): Promise<void> {
    if (this.isSessionExpired()) this.resetState();
    if (this.isInitialized) return;
    if (this.initializationPromise) return this.initializationPromise;

    this.initializationPromise = (async () => {
      try {
        this.bePublicKey      = await importPublicKeyFromPem(this.bePublicKeyPem);
        this.feKeyPair        = await generateFeKeyPair();
        this.sessionCreatedAt = Date.now();
        this.isInitialized    = true;
      } catch (err) {
        this.initializationPromise = null; // allow retry
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
  async encrypt(payload: object | string): Promise<EncryptOutput> {
    await this.ensureInitialized();
    if (!this.bePublicKey || !this.feKeyPair) {
      throw new Error('SecureCryptoSession: initialization failed unexpectedly.');
    }

    const fePublicKeyPem = await exportPublicKeyAsPem(this.feKeyPair.publicKey);
    const result = await encryptForBackend(
      { data: payload, fePublicKey: fePublicKeyPem },
      this.bePublicKey,
    );

    return {
      encryptedPackageB64: result.encryptedPackageB64,
      hmacKeyB64:          result.hmacKeyB64,
      fePublicKeyPem,
    };
  }

  /**
   * Decrypts an encrypted response from the backend.
   */
  async decrypt(encryptedResponse: {
    encryptedPackageB64: string;
  }): Promise<Record<string, unknown>> {
    await this.ensureInitialized();
    if (!this.feKeyPair) {
      throw new Error('SecureCryptoSession: initialization failed unexpectedly.');
    }
    if (!encryptedResponse?.encryptedPackageB64) {
      throw new Error('SecureCryptoSession: missing encryptedPackageB64 in response.');
    }
    return decryptFromBackend(
      encryptedResponse.encryptedPackageB64,
      this.feKeyPair.privateKey,
    );
  }

  /**
   * Manually rotate the key pair before the TTL expires.
   * Useful after detecting a suspicious event.
   */
  rotateKeys(): void {
    this.resetState();
  }
}
