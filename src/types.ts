// ── Shared types ──────────────────────────────────────────────────────────────

/** Wire format of an encrypted package */
export interface IEncryptedPackage {
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
export interface EncryptResult {
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
export interface EncryptOutput {
  encryptedPackageB64: string;
  hmacKeyB64: string;
  fePublicKeyPem: string;
}

/** Options accepted by SecureCryptoSession constructor */
export interface SessionOptions {
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
export interface DecryptMiddlewareOptions {
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
export interface EncryptResponseOptions {
  /**
   * Max allowed payload size in bytes.
   * @default 10485760 (10 MB)
   */
  maxPayloadBytes?: number;
}
