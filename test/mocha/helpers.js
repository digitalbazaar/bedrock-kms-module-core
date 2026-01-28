/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc.
 */
export function localId({id}) {
  const idx = id.lastIndexOf('/');
  return id.substring(0, idx);
}
