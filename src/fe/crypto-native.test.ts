/**
 * Unit tests — run with: npm test
 * Uses Node.js built-in WebCrypto (globalThis.crypto, Node ≥ 19)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateFeKeyPair,
  exportPublicKeyAsPem,
  importPublicKeyFromPem,
  encryptForBackend,
  decryptFromBackend,
  verifyPackageMac,
} from './crypto-native.js';

describe('FE crypto primitives', () => {
  let keyPair: CryptoKeyPair;
  let publicKeyPem: string;

  beforeAll(async () => {
    keyPair      = await generateFeKeyPair();
    publicKeyPem = await exportPublicKeyAsPem(keyPair.publicKey);
  });

  it('exports a valid PEM', () => {
    expect(publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(publicKeyPem).toMatch(/-----END PUBLIC KEY-----$/);
  });

  it('round-trips PEM import/export', async () => {
    const reimported = await importPublicKeyFromPem(publicKeyPem);
    const reexported = await exportPublicKeyAsPem(reimported);
    expect(reexported).toBe(publicKeyPem);
  });

  it('encrypts and decrypts a payload', async () => {
    const beKey   = await importPublicKeyFromPem(publicKeyPem);
    const payload = { hello: 'world', num: 42 };

    const { encryptedPackageB64 } = await encryptForBackend(payload, beKey);
    const decrypted               = await decryptFromBackend(encryptedPackageB64, keyPair.privateKey);

    expect((decrypted as any).hello).toBe('world');
    expect((decrypted as any).num).toBe(42);
  });

  it('embeds _nonce and _issuedAt in payload', async () => {
    const beKey   = await importPublicKeyFromPem(publicKeyPem);
    const payload = { test: true };

    const { encryptedPackageB64 } = await encryptForBackend(payload, beKey);
    const decrypted               = await decryptFromBackend(encryptedPackageB64, keyPair.privateKey);

    expect(typeof (decrypted as any)._nonce).toBe('string');
    expect(typeof (decrypted as any)._issuedAt).toBe('number');
    expect((decrypted as any)._issuedAt).toBeGreaterThan(0);
  });

  it('two encryptions of the same payload produce different ciphertext', async () => {
    const beKey   = await importPublicKeyFromPem(publicKeyPem);
    const payload = { same: 'payload' };

    const r1 = await encryptForBackend(payload, beKey);
    const r2 = await encryptForBackend(payload, beKey);

    expect(r1.encryptedPackageB64).not.toBe(r2.encryptedPackageB64);
  });

  it('MAC verification passes with correct key', async () => {
    const beKey  = await importPublicKeyFromPem(publicKeyPem);
    const result = await encryptForBackend({ x: 1 }, beKey);

    const pkg  = JSON.parse(atob(result.encryptedPackageB64));
    const hmac = await globalThis.crypto.subtle.importKey(
      'raw',
      Buffer.from(result.hmacKeyB64, 'base64'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const valid = await verifyPackageMac(hmac, pkg);
    expect(valid).toBe(true);
  });
});
