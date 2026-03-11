# secure-crypto-kit

> End-to-end hybrid encryption for browser ↔ Node.js — RSA-OAEP + AES-256-GCM with replay protection, HMAC integrity, and automatic key rotation.

---

## Features

- 🔐 **Hybrid encryption** — AES-256-GCM for payload, RSA-OAEP-4096 to wrap the key
- 🛡️ **Replay protection** — per-request nonce + timestamp checked server-side
- ✅ **Tamper detection** — HMAC-SHA256 over all ciphertext fields (encrypt-then-MAC)
- 🔑 **Non-exportable private keys** — FE private key cannot be extracted from WebCrypto
- ♻️ **Automatic key rotation** — FE key pair rotates every 30 minutes (configurable)
- 📦 **Tree-shakeable** — separate `/fe` and `/be` entry points; no Node built-ins in browser bundle
- 🟦 **Full TypeScript** — 100% typed, ships declaration files

---

## Installation

```bash
npm install secure-crypto-kit
```

> **Peer dependency:** `express >= 4` is required only if you use the built-in Express middleware.

---

## Quick Start

### 1. Generate your backend RSA key pair (one-time setup)

```bash
# Generate 4096-bit private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out be-private.pem

# Extract public key
openssl rsa -pubout -in be-private.pem -out be-public.pem
```

Set environment variables:
```env
# .env (server)
BE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

# .env (frontend / Vite)
VITE_BE_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

---

### 2. Frontend usage

```ts
import { SecureCryptoSession } from 'secure-crypto-kit/fe';

const session = new SecureCryptoSession({
  bePublicKeyPem: import.meta.env.VITE_BE_PUBLIC_KEY,
  sessionTtlMs: 30 * 60 * 1000, // optional, default 30 min
});

// --- Encrypt a request ---
const { encryptedPackageB64, hmacKeyB64 } = await session.encrypt({
  userId: 123,
  action: 'transfer',
  amount: 500,
});

const res = await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-HMAC-Key': hmacKeyB64,          // ← required header
  },
  body: JSON.stringify({ encryptedPackageB64 }),
});

// --- Decrypt the response ---
const decrypted = await session.decrypt(await res.json());
console.log(decrypted); // { success: true, txId: '...' }
```

---

### 3. Backend usage (Express)

```ts
import express from 'express';
import { loadBePrivateKey, decryptWebRequestPayload, encryptResponsePayload } from 'secure-crypto-kit/be';

// Load key ONCE at startup — never store the raw string after this
loadBePrivateKey(process.env.BE_PRIVATE_KEY!);

const app = express();
app.use(express.json());

// Apply decryption middleware to all /api routes
app.use('/api', decryptWebRequestPayload({
  maxBodyBytes:    10 * 1024 * 1024, // 10 MB (default)
  requestExpiryMs: 5 * 60 * 1000,   // 5 min (default)
}));

app.post('/api/transfer', async (req, res) => {
  // req.body.payload  → your decrypted data
  // req.body.fePublicKey → FE public key for encrypting the response
  const { userId, amount } = req.body.payload as { userId: number; amount: number };

  const result = { success: true, txId: 'abc-123' };

  // Encrypt the response back to the frontend
  const encryptedPackageB64 = await encryptResponsePayload(
    result,
    req.body.fePublicKey,
    req.headers['x-hmac-key'] as string,
  );

  res.json({ encryptedPackageB64 });
});
```

---

### 4. Backend usage (without Express)

```ts
import { loadBePrivateKey, decryptRequest, encryptResponsePayload } from 'secure-crypto-kit/be';

loadBePrivateKey(process.env.BE_PRIVATE_KEY!);

// In any HTTP handler (Fastify, Hono, plain Node http, etc.)
async function handler(body: { encryptedPackageB64: string }, hmacKey: string) {
  const decrypted = decryptRequest(body.encryptedPackageB64, hmacKey);
  const payload   = decrypted.data;                  // your data
  const feKey     = decrypted.fePublicKey as string; // for encrypting response

  const encrypted = await encryptResponsePayload({ ok: true }, feKey, hmacKey);
  return { encryptedPackageB64: encrypted };
}
```

---

## API Reference

### `secure-crypto-kit/fe`

#### `new SecureCryptoSession(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `bePublicKeyPem` | `string` | **required** | PEM-encoded RSA public key of the backend |
| `sessionTtlMs` | `number` | `1800000` | Key pair rotation interval in ms |

#### `session.encrypt(payload)` → `Promise<EncryptOutput>`

Encrypts any JSON-serialisable value. Returns:

| Field | Description |
|---|---|
| `encryptedPackageB64` | Send as request body |
| `hmacKeyB64` | Send as `X-HMAC-Key` header |
| `fePublicKeyPem` | Current FE public key (automatically embedded) |

#### `session.decrypt({ encryptedPackageB64 })` → `Promise<Record<string, unknown>>`

Decrypts a backend response.

#### `session.rotateKeys()` → `void`

Manually rotates the FE key pair before the TTL expires.

---

### `secure-crypto-kit/be`

#### `loadBePrivateKey(rawKeyEnv: string)` → `void`

Call **once at startup**. Accepts PEM or JSON-stringified PEM. Idempotent.

#### `decryptWebRequestPayload(options?)` → Express middleware

After this middleware runs:
- `req.body.payload` — your decrypted data
- `req.body.fePublicKey` — FE public key for encrypting the response

Returns `400` for malformed requests, `401` for MAC failure / replay / decryption errors.

#### `decryptRequest(encryptedPackageB64, hmacKeyB64, options?)` → `DecryptedPayload`

Framework-agnostic version. Throws on any failure.

#### `encryptResponsePayload(payload, fePublicKey, hmacKeyB64, options?)` → `Promise<string>`

Encrypts a response. Returns base64-encoded package string.

---

## Security Model

```
  Browser                                          Server
  ──────────────────────────────────────────────────────────────────
  1. Generate RSA-4096 key pair (non-exportable private key)
  2. Generate ephemeral AES-256-GCM key
  3. Generate 96-bit IV
  4. Embed _nonce + _issuedAt in payload
  5. AES-GCM encrypt(payload + nonce + timestamp)
  6. RSA-OAEP wrap(AES key) using BE public key
  7. HMAC-SHA256 over (iv + encryptedKey + ciphertext + authTag)
  8. Send: body={ encryptedPackageB64 }, header: X-HMAC-Key
                                         ──────────────────────────▶
                                         9.  Verify HMAC (before RSA — fail-fast)
                                         10. RSA-OAEP unwrap AES key
                                         11. AES-GCM decrypt + verify authTag
                                         12. Check _nonce not seen before
                                         13. Check _issuedAt within 5 min window
                                         14. Validate fePublicKey PEM
                                         15. Process req.body.payload
                                         16. AES-GCM encrypt response with FE public key
                                         17. HMAC-sign response package
                          ◀──────────────────────────────────────────
  18. RSA-OAEP unwrap response AES key
  19. AES-GCM decrypt response
```

### What each layer prevents

| Mechanism | Threat |
|---|---|
| RSA-OAEP-4096 | Passive eavesdropping |
| AES-256-GCM authTag | In-transit payload tampering |
| HMAC over package fields | Cross-component splice attacks |
| Nonce | Replay attacks |
| Timestamp window | Delayed replay after nonce cache expires |
| Non-exportable private key | JS-context key exfiltration |
| Key rotation (TTL) | Long-term session compromise |
| MAC verified before RSA | DoS via expensive RSA on garbage payloads |

---

## Dev / Test Bypass

Set `ENCRYPTION_BYPASS_SECRET` on the server and send the same value as the `X-Bypass-Secret` header to skip encryption in dev/Postman. **Never set this in production.**

```env
ENCRYPTION_BYPASS_SECRET=my-local-dev-secret
```

```bash
curl -X POST http://localhost:3000/api/transfer \
  -H "X-Bypass-Secret: my-local-dev-secret" \
  -H "Content-Type: application/json" \
  -d '{ "userId": 1, "amount": 500 }'
```

---

## License

MIT
