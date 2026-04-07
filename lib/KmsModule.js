/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
*/
export class KmsModule {
  constructor({core, keyStorage} = {}) {
    this.core = core;
    this.keyStorage = keyStorage;
  }

  /**
   * Generates a new key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {string} options.controller - The key controller.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} Key information `{keyId, keyDescription}`.
   */
  async generateKey({keyId, controller, operation} = {}) {
    const {core, keyStorage} = this;
    const {key, keyDescription} = await core.generateKey({
      keyId, controller, operation
    });
    await keyStorage.insert({key});

    return {keyId, keyDescription};
  }

  /**
   * Gets the number of keys in a given keystore.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keystoreId - The ID of the keystore.
   *
   * @returns {Promise<object>} Key count information.
   */
  async getKeyCount({keystoreId} = {}) {
    const {core, keyStorage} = this;
    return keyStorage.getCount({keystoreId});
  }

  /**
   * Gets the key description (no private key material) for the given key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {string} options.controller - The key controller.
   *
   * @returns {Promise<object>} Key information.
   */
  async getKeyDescription({keyId, controller} = {}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    return core.getKeyDescription({key, controller});
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {object} options.operation - The KMS operation.
   * @param {object} [options.zcapInvocation] - The zcap invocation used to
   *   run the KMS operation; if the KMS operation was invoked via zcap.
   *
   * @returns {Promise<object>} An object containing `{wrappedKey}`.
   */
  async wrapKey({keyId, operation, zcapInvocation}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    _checkZcapInvocationRules({key, zcapInvocation});
    return core.wrapKey({key, operation});
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {object} options.operation - The KMS operation.
   * @param {object} [options.zcapInvocation] - The zcap invocation used to
   *   run the KMS operation; if the KMS operation was invoked via zcap.
   *
   * @returns {Promise<object>} An object containing `{unwrappedKey}`.
   */
  async unwrapKey({keyId, operation, zcapInvocation}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    _checkZcapInvocationRules({key, zcapInvocation});
    return core.unwrapKey({key, operation});
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {object} options.operation - The KMS operation.
   * @param {object} [options.zcapInvocation] - The zcap invocation used to
   *   run the KMS operation; if the KMS operation was invoked via zcap.
   *
   * @returns {Promise<object>} An object containing `{signatureValue}`.
   */
  async sign({keyId, operation, zcapInvocation}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    _checkZcapInvocationRules({key, zcapInvocation});
    return core.sign({key, operation});
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {object} options.operation - The KMS operation.
   * @param {object} [options.zcapInvocation] - The zcap invocation used to
   *   run the KMS operation; if the KMS operation was invoked via zcap.
   *
   * @returns {Promise<object>} An object containing `{verified}`.
   */
  async verify({keyId, operation, zcapInvocation}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    _checkZcapInvocationRules({key, zcapInvocation});
    return core.verify({key, operation});
  }

  /**
  * Derives a shared secret via the given peer public key, typically for use
  * as one parameter for computing a shared key. It should not be used as
  * a shared key itself, but rather input into a key derivation function (KDF)
  * to produce a shared key.
  *
  * @param {object} options - The options to use.
  * @param {string} options.keyId - The key ID to use.
  * @param {object} options.operation - The KMS operation.
  * @param {object} [options.zcapInvocation] - The zcap invocation used to
  *   run the KMS operation; if the KMS operation was invoked via zcap.
  *
  * @returns {Promise<object>} An object containing `{secret}`.
  */
  async deriveSecret({keyId, operation, zcapInvocation}) {
    const {core, keyStorage} = this;
    const {key} = await keyStorage.get({id: keyId});
    _checkZcapInvocationRules({key, zcapInvocation});
    return core.deriveSecret({key, operation});
  }
}

function _checkZcapInvocationRules({key, zcapInvocation}) {
  // operation not invoked via zcap
  if(!zcapInvocation) {
    return;
  }
  // no extra zcap invocation restrictions on the key
  if(key.maxCapabilityChainLength === undefined) {
    return;
  }
  // ensure zcap invocation capability change length does not exceed the
  // rules from the key record
  if(zcapInvocation.dereferencedChain.length > key.maxCapabilityChainLength) {
    throw new Error(
      'Maximum zcap invocation capability chain length ' +
      `(${key.maxCapabilityChainLength}) exceeded.`);
  }
}
