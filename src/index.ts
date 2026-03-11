/**
 * secure-crypto-kit
 *
 * Root barrel — re-exports everything.
 * For tree-shaking, prefer the sub-path imports:
 *   import { ... } from 'secure-crypto-kit/fe'   ← browser-safe
 *   import { ... } from 'secure-crypto-kit/be'   ← Node.js only
 */
export * from './fe/index.js';
export * from './be/index.js';
export * from './types.js';
