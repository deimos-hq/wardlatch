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
import { join } from 'node:path';

const GONE = new Set(['ENOENT', 'ENOTDIR', 'ENAMETOOLONG', 'ELOOP']);

/** The file's bytes, or null when it isn't a regular file, is larger than maxBytes, or can't be read. The cap holds for
 *  what is read, not only the size reported at open (a Linux /proc file reports 0 and can be read without end). */
export function readCapped(path, maxBytes) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    // the first read is sized to the file (one byte more, to see that it ended), so a small file costs a small buffer:
    // a 1 MB buffer per file made the key scan spend its time collecting garbage
    const chunks = []; let len = 0, got, next = Math.min(st.size + 1, maxBytes + 1);
    do {
      const chunk = Buffer.allocUnsafe(Math.max(1, Math.min(next, maxBytes + 1 - len)));
      got = readSync(fd, chunk, 0, chunk.length, null);
      // after a short read the next one is almost always the end: a small buffer to see it (a /proc file that keeps
      // giving goes back to 1 MB reads as soon as a read fills its buffer)
      next = got === chunk.length ? 1024 * 1024 : 4096;
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
 * A regular file's text, in pieces that end at a line break, for a file too large to read whole: fn(text, firstLine,
 * { minStart, maxStart }) for each. A line longer than two pieces is cut, and the last `overlap` bytes before the cut are
 * passed again at the start of the next piece, so nothing shorter than half of it is ever split (a key on the cut of a
 * 9 MB one-line file was missed in ca530b7). Each match belongs to exactly one piece: the caller counts a match only if
 * it starts at or after `minStart` and before `maxStart` (characters into `text`), which splits the overlap at its
 * middle. A truncated token at either edge of a piece then falls outside its range, and is seen whole in the other.
 * → true when read to the end; false when it isn't a regular file, is over maxBytes, or can't be read.
 */
export function eachPiece(path, maxBytes, fn, piece = 4 * 1024 * 1024, overlap = 4096) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return false;
    const buf = Buffer.alloc(piece);
    let carry = Buffer.alloc(0), line = 1, total = 0, got, cont = false;
    const half = Math.floor(overlap / 2);
    // cut: this piece ends inside a line (the next starts `overlap` bytes before its end); cont: it starts inside one
    const emit = (b, cut) => {
      const text = b.toString('utf8');
      const chars = (n) => b.subarray(0, n).toString('utf8').length;
      fn(text, line, { minStart: cont ? chars(half) : 0, maxStart: cut ? chars(b.length - half) : Infinity });
      for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) line++;
      cont = cut;
    };
    while ((got = readSync(fd, buf, 0, piece, null)) > 0) {
      total += got;
      if (total > maxBytes) return false;
      const data = Buffer.concat([carry, buf.subarray(0, got)]);
      const cut = data.lastIndexOf(10);
      if (cut < 0 && data.length < 2 * piece) { carry = data; continue; }
      if (cut < 0) { emit(data, true); carry = Buffer.from(data.subarray(data.length - overlap)); continue; }
      emit(data.subarray(0, cut + 1), false);
      carry = Buffer.from(data.subarray(cut + 1));
    }
    if (carry.length) emit(carry, false);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Fixed byte strings in a regular file, read in pieces (never the whole file at once), for files too large to hold in
 * memory (a node binary is 60 to 300 MB). Nothing is parsed and no pattern is run on the bytes: Buffer.indexOf only, so
 * the work is linear in the file's size.
 *   count:  Buffers to count (every occurrence, overlapping ones included)
 *   around: Buffers to return with their surroundings: up to `back` bytes before each hit and `fwd` bytes after it, at
 *           most `maxHits` per needle (a version after a URL, a name in a table)
 *   select: Buffers found as `around` finds them, but each hit is kept only when `want(bytes, i, needle, pos)` says so
 *           (it sees the bytes searched, the needle at `i`, with its `fwd` bytes after it unless the bytes read end
 *           first, and at least `back` bytes before it unless the bytes read start later; `pos`: where it is in the
 *           file); with `fold`, they are found ignoring ASCII case (give them in lower case: `want` then sees the bytes
 *           with A-Z folded to a-z, and a hit kept holds the bytes as they are). `want` is asked about the first
 *           `maxLooks` hits of each needle: `taken` counts the ones it took, `chosen` keeps the first `maxHits` of them,
 *           and `unlooked` counts the hits past `maxLooks`, never looked at
 * A hit that straddles two pieces is seen exactly once: each piece is searched together with the last `back + longest
 * needle + fwd` bytes of the one before, and a hit is taken in the piece where it (with its `fwd` bytes) first ends.
 *   start, length: only these bytes of the file are read (one build in a universal Mach-O file); the whole file by
 *           default. maxBytes still caps the file's size.
 * → { counts: number[], hits: { buf, at, pos }[][], chosen: { buf, at, pos }[][], taken: number[], unlooked: number[],
 *   size } (`at`: where the needle starts in `buf`; `pos`: where it starts in the file; `size`: the bytes read), or null
 *   when it isn't a regular file, is over maxBytes, or can't be read (callers report null as "could not be tested").
 */
export function scanBytes(path, { count = [], around = [], select = [], fold = false, want = () => true, maxLooks = Infinity, back = 1024, fwd = 256, maxHits = 32, maxBytes, piece = 4 * 1024 * 1024, start = 0, length = Infinity } = {}) {
  if (!(maxBytes > 0)) throw new Error('scanBytes needs maxBytes');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return null;
    const longest = Math.max(1, ...[...count, ...around, ...select].map((b) => b.length));
    const keep = back + longest + fwd;
    const counts = count.map(() => 0), hits = around.map(() => []), chosen = select.map(() => []), taken = select.map(() => 0);
    const looks = select.map(() => 0), unlooked = select.map(() => 0);
    const buf = Buffer.allocUnsafe(piece);
    let tail = Buffer.alloc(0), total = 0, got;
    do {
      got = total < length ? readSync(fd, buf, 0, Math.min(piece, length - total), start + total) : 0;
      total += got;
      if (total > maxBytes) return null;
      const data = got ? Buffer.concat([tail, buf.subarray(0, got)]) : tail;
      const seen = tail.length;   // bytes of `data` already searched in the previous piece
      const base = start + total - data.length;   // where data[0] is in the file
      const hit = (i, n) => ({ buf: Buffer.from(data.subarray(Math.max(0, i - back), Math.min(data.length, i + n.length + fwd))), at: Math.min(i, back), pos: base + i });
      // each hit of `n` in `hay` that ends, with its `fwd` bytes, in this piece; one that ended inside the bytes already
      // searched was taken then, and one whose `fwd` bytes are in the next piece is taken there
      const each = (hay, n, fn) => {
        for (let i = hay.indexOf(n, Math.max(0, seen - n.length - fwd + 1)); i !== -1; i = hay.indexOf(n, i + 1)) {
          if (got && i + n.length + fwd > hay.length) break;
          fn(i);
        }
      };
      count.forEach((n, k) => {
        // a hit that ended inside the bytes already searched was counted then
        for (let i = data.indexOf(n, Math.max(0, seen - n.length + 1)); i !== -1; i = data.indexOf(n, i + 1)) counts[k]++;
      });
      around.forEach((n, k) => each(data, n, (i) => { if (hits[k].length < maxHits) hits[k].push(hit(i, n)); }));
      if (select.length) {
        // folded byte by byte (A-Z only), so each byte stays where it is
        const hay = fold ? Buffer.from(data) : data;
        if (fold) for (let i = 0; i < hay.length; i++) if (hay[i] >= 0x41 && hay[i] <= 0x5a) hay[i] += 0x20;
        select.forEach((n, k) => each(hay, n, (i) => {
          if (looks[k] >= maxLooks) { unlooked[k]++; return; }
          looks[k]++;
          if (!want(hay, i, n, base + i)) return;
          taken[k]++;
          if (chosen[k].length < maxHits) chosen[k].push(hit(i, n));
        }));
      }
      tail = data.length > keep ? Buffer.from(data.subarray(data.length - keep)) : data;
    } while (got > 0);
    return { counts, hits, chosen, taken, unlooked, size: total };
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

/** A regular file's size in bytes, or null when it isn't a regular file or can't be opened for reading. */
export function sizeOf(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    return st.isFile() ? st.size : null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Up to `n` bytes (at most 64 KB) of a regular file from byte `offset`, or null when it isn't a regular file, can't be
 *  read, or the range isn't a plain one. Fewer bytes than asked mean the file ended. */
export function readAt(path, offset, n) {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(n) || n < 0 || n > 64 * 1024) return null;
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    if (!fstatSync(fd).isFile()) return null;
    const buf = Buffer.alloc(n);
    return buf.subarray(0, readSync(fd, buf, 0, n, offset));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** What a file's first bytes say it is: 'native' (ELF, or a Mach-O thin or universal binary), 'other' (a script, an
 *  empty file), or null when it isn't a regular file or can't be read (mode 0111, refused, an I/O error): "couldn't look"
 *  is not "not a program". */
export function programKind(path) {
  const h = readHead(path, 4);
  if (!h) return null;
  const m = h.length < 4 ? '' : h.toString('hex');
  return m === '7f454c46' || ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(m) ? 'native' : 'other';
}

/** Whether a file is a compiled program (ELF, or a Mach-O thin or universal binary), not a script. */
export function isNativeProgram(path) {
  return programKind(path) === 'native';
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
 * Folders no search goes into: macOS's own (a Library folder that is macOS's, the Trash, the Photos and Photo Booth
 * libraries). They hold no projects, and macOS's privacy protection refuses them even to root, so entering one only made
 * a run with --paths ~ end "could not be opened, run with sudo", where sudo can't help. A folder that is merely named
 * Library (a project's) is searched: up to ca530b7 every Library folder at any depth was skipped, and a repository
 * called Library read "0 repositories", SAFE.
 */
// macOS keeps a Library folder at /, in /System, and in each home folder (on the start-up disk or another volume): only
// there, with macOS's own folders inside, is a Library macOS's (7e12f17 skipped any Library with a Caches folder). The
// Mac's disk ignores case, and the same folder has other spellings (/System/Volumes/Data/Users/ada, /users/ada), so the
// folder is compared as macOS would, and by its real path too.
const MAC_LIBRARY_PARENT = new RegExp('^(?:|/System|(?:/Volumes/[^/]+)?/Users/[^/]+|(?:/private)?/var/root)$', process.platform === 'darwin' ? 'i' : '');
const macLibraryParent = (parent) => [parent, realPath(parent)].filter(Boolean)
  .some((p) => MAC_LIBRARY_PARENT.test(String(p).replace(/\/+$/, '').replace(/^\/System\/Volumes\/Data(?=\/|$)/i, '')));
export const isSystemFolder = (name, parent) => /^(?:\.Trash|\.Trashes|Photo Booth Library|.+\.photoslibrary)$/.test(name)
  || (name === 'Library' && macLibraryParent(parent)
    && ['Preferences', 'Application Support', 'Caches'].some((d) => pathState(`${parent}/Library/${d}`) === 'dir'));

/** The user id that owns a file or folder (following links, as a socket path like /var/run/docker.sock is one), or null
 *  when it can't be told. */
export function ownerOf(path) {
  try { return statSync(path).uid; } catch { return null; }
}

/** Whether anyone but the owner can write in `path` (its group or everyone: mode g+w or o+w, as /tmp is), or null when
 *  it can't be told. */
export function writableByOthers(path) {
  try { return (statSync(path).mode & 0o022) !== 0; } catch { return null; }
}

/** The real path behind links, or null when it can't be resolved. It cleans a '..' up as text first (Node's
 *  realpathSync), so a path that may hold one after a link (from PATH, a variable, a file) goes to realPathAsWritten. */
export function realPath(path) {
  try { return realpathSync(path); } catch { return null; }
}

/**
 * The real path of a path as written, resolved by the OS (realpath(3)) as the kernel resolves it when it opens the
 * path: each link is followed before the '..' after it, so a/link/../b is the folder above the link's target, then b.
 * (Node's realpathSync cleans '..' up as text first, and reads it as a/b.) → null when it can't be resolved.
 */
export function realPathAsWritten(path) {
  try { return realpathSync.native(path); } catch { return null; }
}

/** Whether a path has a '..' part: the OS takes it after the link before it (a/link/../b is the folder above the
 *  link's target, then b), and path.join, path.resolve, path.normalize and Node's realpathSync clean it up as text
 *  first (a/b). */
export const hasDotDot = (path) => String(path).split('/').includes('..');

/** `base` and then `rest`, put together as written ('/' between them), never cleaned up as text, so the OS resolves it
 *  as a program that opens it does; path.join's when no part has a '..' (the same file to the OS: path.join then drops
 *  only '.' parts and repeated or trailing '/'). */
export function joinAsWritten(base, ...rest) {
  if (![base, ...rest].some(hasDotDot)) return join(base, ...rest);
  return [base, ...rest.filter((x) => x !== '')].join('/');
}

/** The ways a path from `base` and `rest` is read by the programs that read it: as written (C and Rust programs,
 *  shells) and cleaned up as text (Node's path.join and path.resolve, Go's filepath.Join), both when a part has a '..'
 *  and they are not one file; path.join's alone otherwise. → [paths] */
export function spellings(base, ...rest) {
  const text = join(base, ...rest);
  if (![base, ...rest].some(hasDotDot)) return [text];
  const written = joinAsWritten(base, ...rest), a = realPathAsWritten(written);
  return written === text || (a !== null && a === realPathAsWritten(text)) ? [written] : [written, text];
}

/** A file or folder's creation time (or its last status change where the file system keeps no birth time), or null. */
export function createdAt(path) {
  try { const st = statSync(path); return st.birthtimeMs || st.ctimeMs; } catch { return null; }
}
