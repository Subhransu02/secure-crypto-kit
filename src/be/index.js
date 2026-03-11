/**
 * secure-crypto-kit/be
 * Node.js backend exports — do NOT import in browser bundles.
 *
 * @example
 * const {
 *   loadBePrivateKey,
 *   decryptWebRequestPayload,
 *   decryptRequest,
 *   encryptResponsePayload,
 * } = require('secure-crypto-kit/be');
 */

'use strict';

const { encryptResponsePayload }                          = require('./encrypt-response.js');
const { loadBePrivateKey, decryptRequest, decryptWebRequestPayload } = require('./decrypt-request.js');

module.exports = {
  encryptResponsePayload,
  loadBePrivateKey,
  decryptRequest,
  decryptWebRequestPayload,
};
