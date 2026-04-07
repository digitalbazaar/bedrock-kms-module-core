/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import {Core} from './core/index.js';
import {KmsModule} from './KmsModule.js';

/**
 * Generates a KMS module interface that uses the given `Core` interface,
 * `core`, and `KeyStorage` interface, `keyStorage`.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object with `{kmsModule, api}`.
 */
export function createKmsModule({core, keyStorage} = {}) {
  const kmsModule = new KmsModule({core, keyStorage});
  const descriptors = Object.getOwnPropertyDescriptors(kmsModule.prototype);
  const apiEntries = [];
  for(const [name, descriptor] of descriptors.entries) {
    if(typeof descriptor.value !== 'function' || name === 'constructor') {
      continue;
    }
    apiEntries.push([name, descriptor.value.bind(kmsModule)]);
  }
  const api = Object.fromEntries(apiEntries);
  return {kmsModule, api};
}

/**
 * An interface with WebKMS core functions.
 *
 * @typedef {object} Core
 * @property {function} generateKey
 * @property {function} getKeyDescription
 * @property {function} wrapKey
 * @property {function} unwrapKey
 * @property {function} sign
 * @property {function} verify
 * @property {function} deriveSecret
 */

/**
 * An interface for storing WebKMS keys.
 *
 * @typedef {object} KeyStorage
 * @property {function} insert
 * @property {function} getCount
 * @property {function} get
 */
