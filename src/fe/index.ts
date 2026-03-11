/**
 * secure-crypto-kit/fe
 * Browser-side exports — safe to bundle with Vite, webpack, Next.js, etc.
 */
export { SecureCryptoSession }          from './session.js';
export {
  generateFeKeyPair,
  exportPublicKeyAsPem,
  importPublicKeyFromPem,
  encryptForBackend,
  decryptFromBackend,
  verifyPackageMac,
}                                        from './crypto-native.js';
export type {
  IEncryptedPackage,
  EncryptResult,
  EncryptOutput,
  SessionOptions,
}                                        from '../types.js';
