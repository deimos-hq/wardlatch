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
  return m === '7f454c46' || ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(m);
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
 * A folder's entries → { entries: Dirent[] }, or { gone: true }, or { denied: true, code }. Callers report a denied
 * folder as UNKNOWN; only a gone one may count as "not there".
 */
// `code` is the errno, kept rather than collapsed: EPERM and EACCES are different answers (see mandatoryRefusal below),
// and up to this fix every non-GONE code became the same bare { denied: true }, so the one fact that tells a refusal
// nobody can lift from a lock anyone can set was thrown away at the only place that still had it.
export function listDir(dir) {
  try {
    return { entries: readdirSync(dir, { withFileTypes: true }) };
  } catch (e) {
    return GONE.has(e.code) ? { gone: true } : { denied: true, code: e.code };
  }
}

/**
 * Why a folder cannot be listed, as an errno ('EPERM', 'EACCES', …), or null when it can be listed now. For a folder a
 * walk reached only as a path string: the walkers hand gaps() a list of paths, not of error objects, and the errno is
 * read again at the moment the row is written, so what is reported is what a reader would see if they looked now. A
 * folder that has since become readable gives null, which claims nothing (gaps() then falls back to its owner).
 */
export function denialCode(path) {
  try { readdirSync(path); return null; } catch (e) { return e.code ?? null; }
}

/**
 * Whether a refusal to list `path` is one no unprivileged attacker could have produced — macOS's own privacy
 * protection (TCC), which sudo cannot lift — rather than a lock the owner of the folder chose.
 *
 * MEASURED on macOS 27.2 (Darwin 27.2.0), 29 October 2026, by test/support/errno-mechanisms.mjs:
 *   - TCC-protected folders refuse readdir with EPERM: ~/.Trash (0700), ~/Library/Mail (0700),
 *     ~/Pictures/Photo Booth Library (0755), ~/Pictures/Photos Library.photoslibrary (0755).
 *   - The three ways an unprivileged attacker can deny a read on a folder they own all give something else:
 *     chmod 000 → EACCES; a deny ACL (chmod +a "<user> deny read,list,search,readattr") → EACCES;
 *     chflags uchg, hidden and opaque → no effect at all, the folder still lists.
 * So EPERM cannot be forged without root, and root plus the user's own consent is what grants TCC access in the first
 * place. As root, Unix DAC never denies a read, so root's EPERM is unambiguously a mandatory refusal: the rule gets
 * SAFER with more privilege, not weaker.
 *
 * The mode test is what separates "the system refuses everyone" from "this folder is shut and the system also refuses":
 * a folder whose own permission bits would let this process in (owner r-x for its owner, or world r-x) and which still
 * refuses is being refused by something above DAC. A folder that is both mode-locked and EPERM keeps its EACCES-shaped
 * answer and stays UNKNOWN.
 *
 * NO NAME DECIDES THIS. The name list this replaces skipped .Trash, .Trashes, Photo Booth Library and *.photoslibrary,
 * so `mkdir .Trashes` hid a whole tree from every walk (AUDIT-5). It was also wrong about the real article: measured
 * the same day, a modern *.photoslibrary has NO Contents directory, so the bundle-marker gate in isSystemFolder
 * returned false for Photos and true for Photo Booth Library only by accident.
 */
export function mandatoryRefusal(path, code) {
  if (code !== 'EPERM') return false;
  let st; try { st = statSync(path); } catch { return false; }   // can't stat -> claim nothing
  if (process.getuid?.() === 0) return true;
  const mine = st.uid === process.getuid?.();
  return Boolean((mine && (st.mode & 0o500) === 0o500) || (st.mode & 0o005) === 0o005);
}

/**
 * Folders no search goes into: a Library folder that is macOS's own. A folder that is merely named Library (a project's)
 * is searched: up to ca530b7 every Library folder at any depth was skipped, and a repository called Library read
 * "0 repositories", SAFE.
 *
 * The Trash, the Photos library and the Photo Booth library used to be here too, skipped by name so that a run with
 * --paths ~ would not end in "could not be opened, run with sudo" for folders sudo cannot open. That was the right
 * complaint and the wrong fix: a name decided a walk, so `mkdir .Trashes` in a project or a web root hid a whole tree
 * from every walker and the run still read SAFE (AUDIT-5). They are now walked like any other folder, and the refusal
 * they give is read for what it is: mandatoryRefusal() above tells macOS's own refusal from a lock anyone can set, and
 * the first becomes a stated gap with the remedy that can actually work, beside the all-clear.
 */
// macOS keeps a Library folder at /, in /System, and in each home folder (on the start-up disk or another volume): only
// there, with macOS's own folders inside, is a Library macOS's (7e12f17 skipped any Library with a Caches folder). The
// Mac's disk ignores case, and the same folder has other spellings (/System/Volumes/Data/Users/ada, /users/ada), so the
// folder is compared as macOS would, and by its real path too.
const MAC_LIBRARY_PARENT = new RegExp('^(?:|/System|(?:/Volumes/[^/]+)?/Users/[^/]+|(?:/private)?/var/root)$', process.platform === 'darwin' ? 'i' : '');
const macLibraryParent = (parent) => [parent, realPath(parent)].filter(Boolean)
  .some((p) => MAC_LIBRARY_PARENT.test(String(p).replace(/\/+$/, '').replace(/^\/System\/Volumes\/Data(?=\/|$)/i, '')));
export const isSystemFolder = (name, parent) => name === 'Library' && macLibraryParent(parent)
  && ['Preferences', 'Application Support', 'Caches'].some((d) => pathState(`${parent}/Library/${d}`) === 'dir');

/** The user id that owns a file or folder (following links, as a socket path like /var/run/docker.sock is one), or null
 *  when it can't be told. */
export function ownerOf(path) {
  try { return statSync(path).uid; } catch { return null; }
}

/** A folder's permission bits and owner, for the basis a gap row states — "EPERM, mode 0755, owner you" — which a
 *  reader checks with one `ls -ld`. → { mode, uid }, or null when it can't be told. */
export function statBits(path) {
  try { const st = statSync(path); return { mode: st.mode & 0o777, uid: st.uid }; } catch { return null; }
}

/** Whether anyone but the owner can write in `path` (its group or everyone: mode g+w or o+w, as /tmp is), or null when
 *  it can't be told. */
export function writableByOthers(path) {
  try { return (statSync(path).mode & 0o022) !== 0; } catch { return null; }
}

/** What a path is on disk, following links: "<device>:<inode>", or null when it can't be told. Two spellings of one
 *  folder have the same one: on macOS another case, or NFC for a name stored as NFD, which realPath() keeps as given
 *  while git prints the name on disk (comparing the strings read a clean repository UNKNOWN in 7bdca07). */
export function fileId(path) {
  try { const st = statSync(path, { bigint: true }); return `${st.dev}:${st.ino}`; } catch { return null; }
}

/** The real path behind links, or null when it can't be resolved. */
export function realPath(path) {
  try { return realpathSync(path); } catch { return null; }
}

/** A file or folder's creation time (or its last status change where the file system keeps no birth time), or null. */
export function createdAt(path) {
  try { const st = statSync(path); return st.birthtimeMs || st.ctimeMs; } catch { return null; }
}

/**
 * The links a walk chose not to follow, minus those that lead nowhere new: a link whose target is a folder the same
 * walk already listed is not a gap, because its bytes were read. → the links worth reporting.
 *
 * `listed` holds fileId() (device:inode) for every folder the walk successfully listed, which a walker fills as it
 * goes; this runs at the END of the walk, because a link is often met before its target. fileId() is the only identity
 * that survives links, firmlinks, bind mounts and macOS's two spellings of the start-up disk, and AUDIT-25 already
 * compares roots with it.
 *
 * Why this exists: on one Mac, `--incident wordpress-plugins-2026-10 --paths ~` reported 311 folders as untested, and
 * 310 of them were links under ~/.cache/uv/wheels-vN/ that every one resolve into ~/.cache/uv/archive-v0/, a tree the
 * same run had just walked. Every row was true and the set of them was a lie: the real gaps were buried under 310
 * false ones, UNKNOWN became the footnote nobody reads, and a tool that always exits 2 teaches people `|| true`.
 *
 * Identity, not a path prefix. A target merely INSIDE a walked root is not enough: the walk skips node_modules, .git
 * and macOS's Library, and stops at a depth cap, so `~/x -> ~/p/node_modules/y` is inside the root and was never
 * opened. Only the folder itself having been listed proves the bytes were read.
 */
export function unwalkedLinks(candidates, listed) {
  const out = [];
  for (const p of [...new Set(candidates)]) {
    const id = fileId(realPath(p) ?? p);
    if (id && listed.has(id)) continue;
    out.push(p);
  }
  return out;
}
