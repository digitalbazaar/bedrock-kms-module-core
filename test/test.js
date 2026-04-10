/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {Core, createKmsModule} from '@bedrock/kms-module-core';
import {KeyStorage} from '@bedrock/kms-module-key-storage';
import '@bedrock/test';

import {MOCKS} from './mocha/helpers.js';

bedrock.events.on('bedrock.init', async () => {
  MOCKS.storage = await KeyStorage.create({collectionName: 'kms-module-keys'});
  MOCKS.core = new Core();
  const {kmsModule, api} = await createKmsModule({
    core: MOCKS.core,
    keyStorage: MOCKS.storage
  });
  MOCKS.kmsModule = kmsModule;
  MOCKS.kmsModuleApi = api;
});

bedrock.start();
