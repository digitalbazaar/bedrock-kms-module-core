/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc.
 */
import * as database from '@bedrock/mongodb';

export const MOCKS = {};

export async function clearCollection({collectionName} = {}) {
  await database.collections[collectionName].deleteMany({});
}

export function localId({id}) {
  const idx = id.lastIndexOf('/');
  return id.substring(0, idx);
}
