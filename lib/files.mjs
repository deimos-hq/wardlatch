// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Read a file only if it is a regular file under a size cap, with the check and the read on the same open file, so
// the file can't be swapped in between (for a huge file, a device or a pipe). Read-only: opened O_RDONLY, and
// O_NONBLOCK so that opening a pipe returns at once instead of waiting for a writer.
import { openSync, fstatSync, readFileSync, closeSync, constants } from 'node:fs';

/** The file's bytes, or null when it isn't a regular file, is larger than maxBytes, or can't be read. */
export function readCapped(path, maxBytes) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    return readFileSync(fd);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
