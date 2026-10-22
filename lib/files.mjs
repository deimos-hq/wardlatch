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
import { openSync, fstatSync, readSync, closeSync, statSync, readdirSync, realpathSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';

const GONE = new Set(['ENOENT', 'ENOTDIR', 'ENAMETOOLONG', 'ELOOP']);

/** The file's bytes, or null when it isn't a regular file, is larger than maxBytes, or can't be read. The cap holds for
 *  what is read, not only the size reported at open (a Linux /proc file reports 0 and can be read without end). */
export function readCapped(path, maxBytes) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    const chunks = []; let len = 0, got;
    do {
      const chunk = Buffer.alloc(Math.min(1024 * 1024, maxBytes + 1 - len) || 1);
      got = readSync(fd, chunk, 0, chunk.length, null);
      if (got) { chunks.push(chunk.subarray(0, got)); len += got; }
      if (len > maxBytes) return null;
    } while (got > 0);
    return Buffer.concat(chunks, len);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * A regular file's text, in pieces that end at a line break, for a file too large to read whole: fn(text, firstLine) for
 * each. A line longer than two pieces is passed as it is, split. → true when read to the end; false when it isn't a
 * regular file, is over maxBytes, or can't be read.
 */
export function eachPiece(path, maxBytes, fn, piece = 4 * 1024 * 1024) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return false;
    const buf = Buffer.alloc(piece);
    let carry = Buffer.alloc(0), line = 1, total = 0, got;
    const emit = (b) => { const text = b.toString('utf8'); fn(text, line); for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) line++; };
    while ((got = readSync(fd, buf, 0, piece, null)) > 0) {
      total += got;
      if (total > maxBytes) return false;
      const data = Buffer.concat([carry, buf.subarray(0, got)]);
      const cut = data.lastIndexOf(10);
      if (cut < 0 && data.length < 2 * piece) { carry = data; continue; }
      const end = cut < 0 ? data.length : cut + 1;
      emit(data.subarray(0, end));
      carry = Buffer.from(data.subarray(end));
    }
    if (carry.length) emit(carry);
    return true;
  } catch {
    return false;
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

/**
 * Folders no search goes into: macOS's own (Library, the Trash, the Photos and Photo Booth libraries). They hold no
 * projects, and macOS's privacy protection refuses them even to root, so entering one only made a run with --paths ~
 * end "could not be opened, run with sudo", where sudo can't help.
 */
export const isSystemFolder = (name) => /^(?:Library|\.Trash|\.Trashes|Photo Booth Library|.+\.photoslibrary)$/.test(name);

/** The real path behind links, or null when it can't be resolved. */
export function realPath(path) {
  try { return realpathSync(path); } catch { return null; }
}

/** A file or folder's creation time (or its last status change where the file system keeps no birth time), or null. */
export function createdAt(path) {
  try { const st = statSync(path); return st.birthtimeMs || st.ctimeMs; } catch { return null; }
}
