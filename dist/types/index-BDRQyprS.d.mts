/** Wire format of an encrypted package */
interface IEncryptedPackage {
    /** Base64-encoded 96-bit AES-GCM IV */
    iv: string;
    /** Base64-encoded RSA-OAEP wrapped AES-256 key */
    encryptedKey: string;
    /** Base64-encoded AES-GCM ciphertext (without authTag) */
    encryptedPayload: string;
    /** Base64-encoded AES-GCM 16-byte authentication tag */
    authTag: string;
    /** Base64-encoded HMAC-SHA256 over iv+encryptedKey+encryptedPayload+authTag */
    mac: string;
}
/** Result returned from encryptForBackend() */
interface EncryptResult {
    /** Base64-encoded JSON of IEncryptedPackage — use as request body */
    encryptedPackageB64: string;
    /**
     * Base64-encoded raw HMAC key.
     * Send this as the `X-HMAC-Key` request header so the backend
     * can verify package integrity without decrypting first.
     */
    hmacKeyB64: string;
}
/** Result returned from the FE session encrypt() */
interface EncryptOutput {
    encryptedPackageB64: string;
    hmacKeyB64: string;
    fePublicKeyPem: string;
}
/** Options accepted by SecureCryptoSession constructor */
interface SessionOptions {
    /** PEM-encoded RSA-OAEP public key of the backend. Required. */
    bePublicKeyPem: string;
    /**
     * Session TTL in milliseconds. After this duration the FE key pair
     * is automatically rotated on the next encrypt() call.
     * @default 1800000 (30 minutes)
     */
    sessionTtlMs?: number;
}
/** Options for the backend decrypt middleware */
interface DecryptMiddlewareOptions {
    /**
     * Max allowed body size in bytes before crypto work begins.
     * @default 10485760 (10 MB)
     */
    maxBodyBytes?: number;
    /**
     * How long (ms) a request is considered valid after _issuedAt.
     * @default 300000 (5 minutes)
     */
    requestExpiryMs?: number;
}
/** Options for encryptResponsePayload */
interface EncryptResponseOptions {
    /**
     * Max allowed payload size in bytes.
     * @default 10485760 (10 MB)
     */
    maxPayloadBytes?: number;
}

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

declare class SecureCryptoSession {
    private readonly bePublicKeyPem;
    private readonly sessionTtlMs;
    private bePublicKey;
    private feKeyPair;
    private sessionCreatedAt;
    private isInitialized;
    private initializationPromise;
    constructor(options: SessionOptions);
    private isSessionExpired;
    private resetState;
    private ensureInitialized;
    /**
     * Encrypts a payload for the backend.
     *
     * The returned `hmacKeyB64` **must** be forwarded as the `X-HMAC-Key`
     * request header — the backend will reject requests without it.
     */
    encrypt(payload: object | string): Promise<EncryptOutput>;
    /**
     * Decrypts an encrypted response from the backend.
     */
    decrypt(encryptedResponse: {
        encryptedPackageB64: string;
    }): Promise<Record<string, unknown>>;
    /**
     * Manually rotate the key pair before the TTL expires.
     * Useful after detecting a suspicious event.
     */
    rotateKeys(): void;
}

/**
 * @module secure-crypto-kit/fe
 * Browser WebCrypto primitives — safe to import in any bundler/framework.
 * Requires the Web Crypto API (available in all modern browsers and Node ≥ 19).
 */

declare function verifyPackageMac(hmacKey: CryptoKey, pkg: IEncryptedPackage): Promise<boolean>;
/**
 * Generate an RSA-OAEP 4096-bit key pair.
 * The private key is **non-exportable** — it cannot be extracted from the
 * WebCrypto key store, minimising the exfiltration window.
 */
declare function generateFeKeyPair(): Promise<CryptoKeyPair>;
declare function exportPublicKeyAsPem(key: CryptoKey): Promise<string>;
declare function importPublicKeyFromPem(pem: string): Promise<CryptoKey>;
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
declare function encryptForBackend(payload: object, bePublicKey: CryptoKey): Promise<EncryptResult>;
/**
 * Decrypts a base64-encoded package sent by the backend.
 */
declare function decryptFromBackend(encryptedPackageB64: string, fePrivateKey: CryptoKey): Promise<Record<string, unknown>>;

export { type DecryptMiddlewareOptions as D, type EncryptResponseOptions as E, type IEncryptedPackage as I, SecureCryptoSession as S, type EncryptOutput as a, type EncryptResult as b, type SessionOptions as c, decryptFromBackend as d, encryptForBackend as e, exportPublicKeyAsPem as f, generateFeKeyPair as g, importPublicKeyFromPem as i, verifyPackageMac as v };
