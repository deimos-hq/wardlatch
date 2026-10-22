// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The one way Wardlatch looks at the disk. Two rules, both learned the hard way:
//   - "There's nothing here" and "I couldn't look" are different answers. existsSync and a readdirSync wrapped in
//     try/catch both turn a folder Wardlatch can't open into "not there", and a check then reads SAFE without having
//     looked (another user's home, a root-owned virtual environment, a locked repository). Every function here says
//     which it was: gone, or denied.
//   - A file is read only if it is a regular file under a size cap, with the check and the read on the same open file
//     descriptor, opened O_RDONLY | O_NONBLOCK: a planted FIFO, device or huge file can't hang the run or exhaust
//     memory, and the file can't be swapped in between.
// Read-only throughout: nothing here writes, moves or deletes.
import { openSync, fstatSync, readFileSync, readSync, closeSync, statSync, lstatSync, readdirSync, realpathSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';

const GONE = new Set(['ENOENT', 'ENOTDIR', 'ENAMETOOLONG', 'ELOOP']);

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

/** The first `n` bytes of a regular file (fewer if it is shorter), or null when it isn't a regular file or can't be read. */
export function readHead(path, n) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    if (!fstatSync(fd).isFile()) return null;
    const buf = Buffer.alloc(n);
    return buf.subarray(0, readSync(fd, buf, 0, n, 0));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Whether a file is a compiled program (ELF, or a Mach-O thin or universal binary), not a script. */
export function isNativeProgram(path) {
  const h = readHead(path, 4);
  if (!h || h.length < 4) return false;
  const m = h.toString('hex');
  return m === '7f454c46' || ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca'].includes(m);
}

/** The file's text (UTF-8), or null as readCapped. */
export const readText = (path, maxBytes) => readCapped(path, maxBytes)?.toString('utf8') ?? null;

/** A regular file's hash (hex), or null as readCapped. Never blocks on a FIFO. */
export function hashFile(path, algorithm, maxBytes) {
  const buf = readCapped(path, maxBytes);
  return buf ? createHash(algorithm).update(buf).digest('hex') : null;
}

/**
 * What is at a path, following links: 'file', 'dir', 'other' (a FIFO, socket or device), 'gone' (nothing there), or
 * 'denied' (something may be there, but a folder on the way can't be entered).
 */
export function pathState(path) {
  try {
    const st = statSync(path);
    return st.isFile() ? 'file' : st.isDirectory() ? 'dir' : 'other';
  } catch (e) {
    return GONE.has(e.code) ? 'gone' : 'denied';
  }
}

/** Whether the path itself is a symbolic link (not followed). */
export function isLink(path) {
  try { return lstatSync(path).isSymbolicLink(); } catch { return false; }
}

/**
 * A folder's entries → { entries: Dirent[] }, or { gone: true }, or { denied: true }. Callers report a denied folder
 * as UNKNOWN; only a gone one may count as "not there".
 */
export function listDir(dir) {
  try {
    return { entries: readdirSync(dir, { withFileTypes: true }) };
  } catch (e) {
    return GONE.has(e.code) ? { gone: true } : { denied: true };
  }
}

/** The real path behind links, or null when it can't be resolved. */
export function realPath(path) {
  try { return realpathSync(path); } catch { return null; }
}

/** A file or folder's creation time (or its last status change where the file system keeps no birth time), or null. */
export function createdAt(path) {
  try { const st = statSync(path); return st.birthtimeMs || st.ctimeMs; } catch { return null; }
}
