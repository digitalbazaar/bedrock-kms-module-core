/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as brSSM from '@bedrock/kms-module-core';
import * as database from '@bedrock/mongodb';
import * as helpers from './helpers.js';
import {generateId} from 'bnid';

// import is for testing purposes only; not a public export
import {_createKeyRecordCipher} from '@bedrock/kms-module-core';

/* eslint-disable */
/*
'u' + Buffer.concat([Buffer.from([0xa2, 0x01]), Buffer.from(crypto.getRandomValues(new Uint8Array(32)))]).toString('base64url')
*/
/* eslint-enable */
const testParameters = [
  {
    title: 'no encryption',
    encryptConfig: {currentKekId: null},
    shouldEncrypt: false
  },
  {
    title: 'w/aes256 encryption w/json encoding',
    encryptConfig: {
      encoding: 'cbor',
      keks: [{
        id: 'urn:test:aes256',
        secretKeyMultibase: 'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
      }]
    },
    shouldEncrypt: true
  },
  {
    title: 'w/aes256 encryption w/cbor encoding',
    encryptConfig: {
      encoding: 'json',
      keks: [{
        id: 'urn:test:aes256',
        secretKeyMultibase: 'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
      }]
    },
    shouldEncrypt: true
  }
];

for(const {title, encryptConfig, shouldEncrypt} of testParameters) {
  describe(`keystore ${title}`, () => {
    const moduleConfig = bedrock.config['ssm-mongodb'];
    const oldConfigValue = moduleConfig.keyRecordEncryption;
    before(async () => {
      moduleConfig.keyRecordEncryption = {kek: encryptConfig.kek};
      await _createKeyRecordCipher();
    });
    after(() => {
      moduleConfig.keyRecordEncryption = oldConfigValue;
    });

    describe('getKeyCount API', () => {
      it('gets an accurate key count in a keystore', async () => {
        // clear existing keys for accurate count unaffected by other tests
        await database.collections.ssm.deleteMany();

        let keystoreId;
        for(let i = 0; i < 3; ++i) {
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'urn:webkms:multikey:Ed25519';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});
          if(!keystoreId) {
            keystoreId = helpers.localId({id: keyId});
          }
        }

        const result = await brSSM.getKeyCount({keystoreId});
        result.should.be.an('object');
        result.should.have.property('count');
        result.count.should.equal(3);
      });
    });

    describe('generateKey API', () => {
      it('throws an Error if invalid type is used', async () => {
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Invalid';
        const invocationTarget = {id: keyId, type};

        let result;
        let err;
        try {
          result = await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
  });
}
