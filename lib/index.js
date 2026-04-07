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
 * @param {Core} options.core - The `Core` interface to use.
 * @param {KeyStorage} options.keyStorage - The `KeyStorage` interface to use.
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
 * @property {Function} generateKey
 * @property {Function} getKeyDescription
 * @property {Function} wrapKey
 * @property {Function} unwrapKey
 * @property {Function} sign
 * @property {Function} verify
 * @property {Function} deriveSecret
 */

/**
 * An interface for storing WebKMS keys.
 *
 * @typedef {object} KeyStorage
 * @property {Function} insert
 * @property {Function} getCount
 * @property {Function} get
 */
