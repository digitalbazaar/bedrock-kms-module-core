/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {KeyStorage} from '@bedrock/kms-module-key-storage';
import '@bedrock/kms-module-core';
import '@bedrock/test';

import {MOCKS} from './mocha/helpers.js';

bedrock.events.on('bedrock.init', async () => {
  MOCKS.storage = await KeyStorage.create({collectionName: 'kms-module-keys'});
});

bedrock.start();
