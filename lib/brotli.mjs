// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Copies of a C decoder bundled in runtimes and packages (first use: Brotli, CVE-2026-111497), judged by the bytes of the
// file that holds the decoder, never by a version string, and never by running anything found.
//
// Why bytes: version strings lie both ways for this flaw. nodejs.org's Node.js 26.12.1 is fixed (a cherry-pick) but
// reports Brotli 1.2.0; Homebrew's node reports whatever Homebrew's brotli is, because it loads that library; Debian's
// fixed packages keep 1.0.9 and 1.1.0; a build from Brotli's master after 27 Feb 2026 says 1.2.0 and is fixed.
//
// The evidence: the fix added an error code, so the decoder's error-string table (BrotliDecoderErrorString) gains the C
// string "_ERROR_FORMAT_BLOCK_SWITCH" (the marker). Others used that error name as the sign of the fix before this
// check: OrchestratorInc/agent-orchestrator#7107 looked for the string in a library file, and baealex/BLEX#580 asked
// the decoder for it at run time (BrotliDecoderErrorString(-17)). This is the same idea, built into the check: an exact
// NUL-delimited match plus a control string, reading bytes only. "_ERROR_FORMAT_BLOCK_LENGTH_1" is in every table since
// 1.0 (the control): it shows a table is there, so a missing marker means something, and the marker counts for SAFE
// only beside it. Both are matched exactly, NUL-delimited, as string literals sit in a binary: Node also carries its
// zlib.constants names (BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH), which contain the marker as a substring and come
// from the header Node was compiled against, not from the decoder it loads (Homebrew's libnode has the names and no
// table at all). Those names never decide anything here.
//
// Brotli 1.0 writes the same table without the prefix (1.0.x's BrotliDecoderErrorString has `return #NAME;`, 1.1.0 on
// `return #PREFIX #NAME;`): a 1.0.x library (Debian 12's libbrotli1 1.0.9) holds "BLOCK_LENGTH_1", and 1.0.10, the fix
// on the 1.0 line, adds "BLOCK_SWITCH", short words another program could hold too. That form is judged (maintainer,
// 2026-10-25), and as a bare name proves nothing there, only as a whole table: the incident's run of names (table10) in
// Brotli's order around the control's name, each NUL-delimited (up to 16 NULs between two, as a compiler pads strings
// it aligns), either way round (decode.h's order, as clang and GCC lay them out, or by code), and right after the run
// either the fix's name and then after10 (1.0.10), or one of unfixed10's runs and then after10: none (1.0.4 to 1.0.9),
// or "COMPOUND_DICTIONARY" (1.0.3, which listed it after DISTANCE). Anything else in that form (a name outside such a
// run, a run followed by none of these, the fix's name anywhere but in its place) is UNKNOWN.
//
// The libraries a file links are read as the loader reads them (decision #24, 2026-10-25): from the binary format, the
// Mach-O load commands and the ELF dynamic table (linkTable), never from strings that look like paths. Strings outside
// that table are read for one thing only, a library the program may load by name while it runs (dlopen: dlopenWant).
// Which copy of a library the loader takes is not emulated: where dyld or ld.so could take a different copy, every
// candidate must be SAFE, or the file is UNKNOWN (EXPOSED if any candidate is EXPOSED): resolveLink.
import { join, dirname, basename, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
// every path is resolved by the OS as written (realPathAsWritten), never cleaned up as text first: one from PATH, a
// variable or a file may hold a '..' after a link
import { scanBytes, listDir, pathState, realPathAsWritten, hasDotDot, joinAsWritten, spellings, readCapped, readHead, readAt, programKind, hashFile, sizeOf } from './files.mjs';
import { findAllOnPath } from './binaries.mjs';
import { expand } from './installs.mjs';
import { safe } from './report.mjs';

const MAX_PROGRAM = 512 * 1024 * 1024;        // a node binary is 60 to 300 MB; a larger file is not read (UNKNOWN)
const BUDGET = 4 * 1024 * 1024 * 1024;        // what one run reads for this check; past it, each file left is UNKNOWN
const MAX_RECORD = 4 * 1024 * 1024;
const MAX_CMDS = 1024 * 1024;                 // a build's Mach-O load commands (node's take about 10 KB); more is UNKNOWN
const MAX_NAME = 4096;                        // a library's name in an ELF string table (PATH_MAX)
const MAX_LOOKS = 65536;                      // hits of libbrotlidec, or of libnode, a build is looked at for (nodejs.org's node: 417)
const DECODER = Buffer.from('libbrotlidec');
const NODE_LIB = Buffer.from('libnode');
const RELEASE = Buffer.from('nodejs.org/download/release/v');
const nul = (s) => Buffer.from(`\0${s}\0`);
// file names are compared ignoring case on macOS, whose disks (APFS, HFS+) ignore it by default
const CASELESS = process.platform === 'darwin';
const asciiLower = (s) => s.replace(/[A-Z]+/g, (x) => x.toLowerCase());

// The reasons a row gives. Every one that is not a verdict says "could not be tested".
const HAS_FIX = 'its Brotli decoder has the fix: the error text the fix added is in it, beside the error texts every Brotli decoder has';
const LACKS_FIX = 'its Brotli decoder lacks the fix: it has the error texts every Brotli decoder has, but not the one the fix added';
const SOME_LACK = 'it holds more than one Brotli decoder, and at least one of them lacks the fix';
const ODD = 'the error text the fix added is in it more often than the error texts every Brotli decoder has, which no real build shows, so whether it has the fix could not be tested';
const NO_CONTROL = 'the error text the fix added is in it, but not the error texts every Brotli decoder has, so whether its decoder has the fix could not be tested';
export const NO_TABLE = 'no Brotli decoder\'s error texts are in this file and it links no Brotli library, so whether it has the fix could not be tested';
const CROWDED = 'it holds libbrotlidec or libnode more often than Wardlatch looks at (65,536 times), so whether each is the name of a library it may load could not all be looked at, and whether it has the fix could not be tested';
const DLOPEN = (name) => `it names ${name}, the file name of a Brotli library or of libnode that is not one of the libraries it links, and a program can load a library by such a name while it runs (dlopen), so which decoder it uses, and whether that has the fix, could not be tested`;
const MALFORMED = (format, why) => `its ${format} headers could not be read as the format lays them out (${why}), so the libraries it links could not be read, and whether it has the fix could not be tested`;
const UNRECOGNISED = 'it is neither a Mach-O nor an ELF file Wardlatch can read, so the libraries it links could not be read, and whether it has the fix could not be tested';
const DYLD_ENV = (value) => `it sets the dynamic loader's own variables (LC_DYLD_ENVIRONMENT ${value}), which change where its libraries are found, so whether it has the fix could not be tested`;
const NESTED = (ref) => `it links ${ref}, a Brotli library or libnode of its own, which Wardlatch doesn't follow past the one library it reads for a program, so whether it has the fix could not be tested`;
const UNREAD = 'could not be read (it is not a regular file, reading it was refused, or it is larger than 512 MB), so it could not be tested';
const OVER_BUDGET = 'not read, because this run had already read 4 GB of files for this check, so it could not be tested';
const HAS_FIX_10 = 'its Brotli decoder has the fix: its error texts, in the form Brotli 1.0 writes them, are all there in Brotli\'s order, with the one the fix added in its place';
const LACKS_FIX_10 = 'its Brotli decoder lacks the fix: its error texts, in the form Brotli 1.0 writes them, are all there in Brotli\'s order, without the one the fix added';
const OLD_BESIDE = 'it holds a decoder with the fix, and also error texts in the form Brotli 1.0 writes them, but not as a whole table in Brotli\'s order, so a second, older decoder may be in it: whether it has the fix could not be tested';
const OLD_FORM = 'it holds error texts in the form Brotli 1.0 writes them, but not as a whole table in Brotli\'s order (scattered, out of order, only some of them, or the text the fix added away from its place), so whether it has the fix could not be tested';
const BAD_FAT = 'it is a universal (fat) Mach-O file whose list of builds could not be read, or names builds that overlap or run past the end of the file, so it could not be tested';

/**
 * Where a version manager keeps the nodes its shim starts, from the incident's `shims` (each manager's layouts, read in
 * its own source): its homes (`homes`: `$VAR` or `$VAR/rest`, `~/rest`, or an absolute path) with the `nodes`
 * patterns under each, its installs folders (`installs`) with `installsNodes` under each, and, when the shim on PATH
 * (`onPath`) sits in a folder named `folder` (volta's bin, the others' shims), the folder above that as a home too. A
 * variable that isn't set is no place; one the layout names in `lists` holds folders split on ':' (mise splits
 * MISE_SHARED_INSTALL_DIRS as it splits PATH), and any other one is a single path, a ':' in it included (mise's
 * MISE_DATA_DIR and the like, and the other managers' variables); one the layout names in `tilde` has a leading '~/'
 * (or a bare '~') read as the home folder, as its manager reads it (asdf's ASDF_DATA_DIR: internal/config/config.go,
 * normalizePath, since asdf 0.17.0); one set to a path that doesn't start at '/' is otherwise `unsure` (where the
 * manager looks then depends on the folder it is started in). No pattern runs on a value. A value (or the home folder)
 * with a '..' in it is read both ways a manager may read it (spellings): as written, as volta, mise, proto and
 * nodenv do and the OS resolves it (after the link before it), and cleaned up as text, as asdf's Go does.
 * → { patterns, folders: each pattern's folder of runtimes (the part before its first `*`), unsure: [variable names],
 *     shimDirs: its own homes' shims folders (each home's `folder`; not the one found from `onPath`) }
 */
export function shimPlaces(layout, env = {}, onPath) {
  const patterns = [], unsure = [];
  const roots = (tpl) => {
    if (tpl.startsWith('~/')) return spellings(homedir(), tpl.slice(2));
    if (!tpl.startsWith('$')) return [tpl];
    const slash = tpl.indexOf('/'), name = tpl.slice(1, slash < 0 ? tpl.length : slash), rest = slash < 0 ? '' : tpl.slice(slash + 1);
    const set = String(env[name] ?? ''), value = (layout.tilde ?? []).includes(name) && (set === '~' || set.startsWith('~/')) ? joinAsWritten(homedir(), set.slice(2)) : set;
    const values = (layout.lists ?? []).includes(name) ? value.split(':').filter(Boolean) : value ? [value] : [];
    if (values.some((v) => !v.startsWith('/'))) unsure.push(name);
    return values.filter((v) => v.startsWith('/')).flatMap((v) => spellings(v, rest));
  };
  const own = layout.homes.flatMap(roots), homes = [...own];
  if (onPath && basename(dirname(onPath)) === layout.folder) homes.unshift(dirname(dirname(onPath)));
  const add = (root, rel) => { const p = joinAsWritten(root, rel); if (!patterns.includes(p)) patterns.push(p); };
  for (const h of homes) for (const n of layout.nodes) add(h, n);
  for (const r of (layout.installs ?? []).flatMap(roots)) for (const n of layout.installsNodes ?? []) add(r, n);
  return { patterns, folders: [...new Set(patterns.map((p) => p.slice(0, p.lastIndexOf('/', p.indexOf('*')))))], unsure: [...new Set(unsure)], shimDirs: own.map((h) => joinAsWritten(h, layout.folder)) };
}

/**
 * The row for a version manager's shim on PATH (a compiled `node` with no sign of Node.js that is a link to volta-shim,
 * mise, rtx or proto-shim, or a copy of proto-shim; or a script named `node` in asdf's or nodenv's shims folder: shimKind).
 * REVIEW, not judged, only when the nodes it starts are read: at least one of its folders of runtimes (shimPlaces) is
 * there and was listed, every one that is there could be listed, and no variable names one by a relative path (for
 * asdf, only its plugins' folders count: shimPlugins). Otherwise UNKNOWN, so an unread node never ends the run in exit 0.
 */
function shimRow(file, kind, { folders, unsure, plugins }, hint) {
  const state = (f) => { const st = pathState(f); return st === 'dir' ? (listDir(f).entries ? 'read' : 'closed') : st === 'denied' ? 'closed' : 'gone'; };
  const closed = folders.filter((f) => state(f) === 'closed'), read = folders.filter((f) => state(f) === 'read');
  const list = (xs) => `${xs.slice(0, 4).join(', ')}${xs.length > 4 ? `, and ${xs.length - 4} more` : ''}`;
  const head = `${kind}, a version manager's shim, not a Node.js runtime`;
  const unknown = (why) => ({ what: 'node', file, status: 'UNKNOWN', reason: `${head}: ${why}, so the nodes it starts were not read, and whether they have the fix could not be tested. ${hint}` });
  if (unsure.length) return unknown(`${unsure.join(' and ')} ${unsure.length === 1 ? 'names' : 'name'} its folders by a path that doesn't start at '/', which leads elsewhere from each folder it is started in`);
  if (!folders.length) return unknown(`it belongs to ${plugins?.length ? `the plugin${plugins.length > 1 ? 's' : ''} ${list(plugins)}` : 'no plugin it names'}, and Wardlatch reads no folder of runtimes for that`);
  if (closed.length) return unknown(`its folder of runtimes ${list(closed)} could not be read`);
  if (!read.length) return unknown(`its folder of runtimes was not found (looked in ${list(folders)})`);
  return { what: 'node', file, status: 'REVIEW', reason: `${head}, so it was not judged: the runtimes it starts are read in ${list(read)}` };
}

/**
 * The places of a shim whose manager names its plugins in it (`pluginLine`: asdf writes one "# asdf-plugin: <plugin>
 * <version>" line per plugin and version into each shim, and reads them back by splitting the line on spaces:
 * internal/shims/shims.go, encode and parse, which skips a line of fewer than four parts): its folders of runtimes
 * narrowed to those of the plugins it names (the folder's last part is the plugin's name: installs/nodejs,
 * installs/node), so a folder of another plugin never makes its row a REVIEW. The shim is read as text only when it is
 * 64 KB or smaller (asdf writes a few hundred bytes); a larger one is not read at all, so it names no plugin and its
 * row is UNKNOWN.
 */
function shimPlugins(places, layout, shim) {
  if (!layout.pluginLine) return places;
  const lines = (readCapped(shim, 64 * 1024)?.toString('utf8') ?? '').split('\n').filter((l) => l.startsWith(layout.pluginLine));
  const plugins = [...new Set(lines.map((l) => l.split(' ')).filter((s) => s.length >= 4).map((s) => s[2]))];
  return { ...places, plugins, folders: places.folders.filter((f) => plugins.includes(basename(f))) };
}

const MAX_SHIM = 64 * 1024 * 1024;   // proto-shim is a few MB; a larger node is not read for its marker (no shim, never REVIEW)

/** Whether a file of at most MAX_SHIM bytes, that fits in what is left of the run's reading budget, holds `needle`, read
 *  as bytes (charged to the budget before it is read). */
function carries(file, needle, budget) {
  const size = sizeOf(file);
  if (size === null || size > MAX_SHIM || size > budget.left) return false;
  budget.left -= size;
  return (scanBytes(file, { count: [Buffer.from(needle)], maxBytes: MAX_SHIM })?.counts[0] ?? 0) > 0;
}

/**
 * Which version manager's shim a `node` on PATH is, if any (`layouts`: [key, layout, shimPlaces(layout, env)] for each
 * of the incident's `shims`). A compiled program: a link to the manager's own program (its real file is named like a key:
 * volta-shim, mise, rtx, proto-shim); or, for a manager whose shims are copies of its program (`copies`: proto writes
 * proto-shim's bytes to <home>/shims/node, crates/shim/src/unix.rs), one whose real path is in its shims folder, or one
 * that carries its `marker` (proto-shim's own "Invalid shim name detected" message, which only proto-shim's source,
 * crates/cli/src/main_shim.rs, holds since proto 0.26; not PROTO_SHIM_NAME, which proto's CLI holds too). A script:
 * one whose real path is in the shims folder of a manager whose shims are scripts (`script`: asdf's, nodenv's). → the
 * key, or null (no shim: a compiled node is judged as any other, and a script is UNKNOWN).
 */
function shimKind(file, layouts, budget) {
  const kind = programKind(file);
  if (kind === null) return null;
  const script = kind !== 'native', real = realPathAsWritten(file) ?? file, dir = dirname(real);
  const mine = layouts.filter(([, l]) => Boolean(l.script) === script);
  const inShims = ([, l, places]) => (l.copies || l.script) && places.shimDirs.some((d) => (realPathAsWritten(d) ?? d) === dir);
  const found = (!script && mine.find(([k]) => k === basename(real))) || mine.find(inShims)
    || (!script && mine.find(([, l]) => l.marker && carries(file, l.marker, budget)));
  return found ? found[0] : null;
}

/** A printable ASCII run of bytes around position `at` of `buf` (a version after a URL; the tail of a path). */
function printableAround(buf, at, { backward = true } = {}) {
  const ok = (b) => b >= 0x20 && b <= 0x7e;
  let s = at, e = at;
  if (backward) while (s > 0 && ok(buf[s - 1])) s--;
  while (e < buf.length && ok(buf[e])) e++;
  return buf.subarray(s, e).toString('latin1');
}

/** The C string around position `at` of `buf`: the bytes back and forward from it to a NUL, within the bytes kept; null
 *  when either end runs past them (a string seen only in part). */
function cStringAt(buf, at) {
  let s = at, e = at;
  while (s > 0 && buf[s - 1] !== 0) s--;
  while (e < buf.length && buf[e] !== 0) e++;
  return s > 0 && e < buf.length ? buf.subarray(s, e) : null;
}

// After "libbrotlidec" or "libnode": the rest of a file name the loader loads. An optional tag ("-ba690955", as
// auditwheel renames the copies it bundles), versions (".1.2.1"), then ".dylib", or ".so" and its versions (".so.1.0.9"),
// and then nothing that could go on with the name (a letter, a digit, '_'). A static archive ("libnode_base.a(
// callback.o)"), an object file (".o"), a longer word ("libnode_crates", "libbrotlidecoder") is no such name, and
// neither is a separate file of debugging information (a name that goes on to end in ".debug", as a stripped ELF
// library's .gnu_debuglink names one: "libbrotlidec.so.1.0.9.debug", Fedora's "libbrotlidec.so.1.1.0-1.1.0-4.fc40
// .x86_64.debug"), which holds no code. Bounded: each part has a cap, and it runs on at most 160 bytes.
const LOADABLE = /^(?:[-_][a-z0-9]{1,64})?(?:\.[0-9]{1,9}){0,8}\.(?:dylib|so(?:\.[0-9]{1,9}){0,8})(?![a-z0-9_])/;
const NAME_BYTE = (b) => (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2e || b === 0x2d || b === 0x5f;
// the bytes a file name goes on with, for its ending (a distribution's version may hold '+' and '~')
const RUN_BYTE = (b) => NAME_BYTE(b) || b === 0x2b || b === 0x7e;

// what could still follow a name the end of the bytes cut off, to make it one (".", "-ab", ".1", ".s", ".dy": each
// ends in a tag, a version, ".so" or ".dylib" with one of these)
const CUT_ENDS = ['', '.so', 'so', 'o', 'ylib', 'lib', 'ib', 'b', '1.so'];

/**
 * Whether the bytes at `i` of `hay` (right after a library's stem, folded to lower case when names are compared that
 * way) go on to make a file name the loader can load (LOADABLE). A name the end of the bytes read cuts off (of the
 * file, or of the build) counts as one when what could follow would make it one ("libbrotlidec." does,
 * "libbrotlidec.a" doesn't).
 */
export function loadableAt(hay, i) {
  const w = hay.subarray(i, i + 160).toString('latin1');
  if (LOADABLE.test(w)) {
    let e = 0;
    while (e < w.length && RUN_BYTE(w.charCodeAt(e))) e++;
    return !w.slice(0, e).endsWith('.debug');
  }
  let k = 0;
  while (k < w.length && NAME_BYTE(w.charCodeAt(k))) k++;
  return i + k >= hay.length && CUT_ENDS.some((x) => LOADABLE.test(w.slice(0, k) + x));
}

/** A hit of a library's stem, for a reason: its C string, or the bytes from the stem to the next NUL when the string's
 *  start was not kept. */
const hitShown = (h) => {
  const c = cStringAt(h.buf, h.at);
  if (c) return shown(c);
  const z = h.buf.indexOf(0, h.at);
  return shown(h.buf.subarray(h.at, z < 0 ? h.buf.length : z));
};

/** A name seen in a file, for a reason: printable ASCII as it is, any other byte as \xNN, at most 160 bytes. */
const shown = (bytes) => {
  let s = '';
  for (const b of bytes.subarray(0, 160)) s += b >= 0x20 && b < 0x7f && b !== 0x5c ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`;
  return bytes.length > 160 ? `${s}...` : s;
};

/**
 * Up to `n` NUL-delimited strings read outward from position `from` of `buf` (a NUL), forward (`dir` 1) or back (-1):
 * NULs are passed over (at most 16 in a row: one ends a string, the rest pad a string a compiler aligned), then a string
 * runs to the next NUL. It stops at more NULs than that, or at the end of the bytes kept, so it returns only strings
 * seen whole. Bounded: each byte kept around the hit is looked at once.
 */
function namesFrom(buf, from, dir, n) {
  const out = [];
  let i = from;
  while (out.length < n) {
    for (let nuls = 0; i >= 0 && i < buf.length && buf[i] === 0; i += dir) if (++nuls > 16) return out;
    const start = i;
    while (i >= 0 && i < buf.length && buf[i] !== 0) i += dir;
    if (i < 0 || i >= buf.length) return out;
    out.push((dir > 0 ? buf.subarray(start, i) : buf.subarray(i + 1, start + 1)).toString('latin1'));
  }
  return out;
}

/**
 * What Brotli 1.0's table around one copy of its control's name (the "\0BLOCK_LENGTH_1\0" at `at` of `buf`, `len` bytes)
 * shows: 'fixed' (the names of `run` around it in order, then the fix's name, then `after`), 'unfixed' (the run, then
 * one of the `unfixed` runs of names, then `after`: [] is `after` at once, as 1.0.4 to 1.0.9 have it), or null (anything
 * else). Matched either way round: in decode.h's order (the later names after it), or reversed, by code (the later
 * names before it).
 */
function table10At(buf, at, len, { run, anchor, fixed, after, unfixed }) {
  const a = run.indexOf(anchor), earlier = run.slice(0, a).reverse(), later = run.slice(a + 1);
  // no run, or one without the control's name: no 1.0 table can be shown (an empty run would match anything)
  if (a < 0) return null;
  const same = (got, want) => want.every((x, i) => got[i] === x);
  const read = (dir, n) => namesFrom(buf, dir > 0 ? at + len - 1 : at, dir, n);
  for (const dir of [1, -1]) {
    if (!same(read(-dir, earlier.length), earlier)) continue;
    const got = read(dir, later.length + Math.max(2, ...unfixed.map((u) => u.length + 1)));
    if (!same(got, later)) continue;
    const rest = got.slice(later.length);
    if (same(rest, [fixed, after])) return 'fixed';
    if (unfixed.some((u) => same(rest, [...u, after]))) return 'unfixed';
  }
  return null;
}

/** Brotli 1.0's form in one build: null when the control's name isn't there in that form; 'fixed' or 'unfixed' when
 *  every copy of it is in a whole table (table10At) and the fix's name is nowhere but in its place in a fixed one;
 *  'odd' otherwise (a copy outside a whole table, more copies than were kept, or a stray copy of the fix's name). */
function form10Of({ uc0, um0, t10 }) {
  if (!uc0) return null;
  if (t10.other || um0 !== t10.fixed) return 'odd';
  return t10.unfixed ? 'unfixed' : 'fixed';
}

/** The file name a library a file links has (its load command's or DT_NEEDED entry's last part), in lower case: the
 *  loader may find it under any case on a disk that ignores case, so a link is known by its name whatever the case. */
const leafOf = (ref) => asciiLower(ref.slice(ref.lastIndexOf('/') + 1));

/** Whether a library a file links (exactly a load command's or a DT_NEEDED entry's name) is a Brotli decoder library:
 *  its file name starts with libbrotlidec (libbrotlidec.1.dylib, libbrotlidec.so.1, auditwheel's
 *  libbrotlidec-ba690955.so.1.1.0), in any case. */
export const isDecoderLibName = (ref) => leafOf(ref).startsWith('libbrotlidec');

/** Whether a library a file links is the library that holds Node.js's code (a distribution's node, and Homebrew's, are
 *  launchers for it): its file name is libnode, or starts with libnode and then '.', '-' or '_' (libnode.147.dylib,
 *  libnode.so.115), in any case. */
export function isNodeLibName(ref) {
  const n = leafOf(ref);
  return n.startsWith('libnode') && (n.length === 7 || '.-_'.includes(n[7]));
}

const RELATIVE = (ref, what = '') => `it links ${ref}${what}, a relative path, which the loader looks for from the folder the program is started in, so which file it loads, and whether that has the fix, could not be tested`;

/**
 * The builds a universal (fat) Mach-O file holds, by their place in it, from its header (bounded: at most 64 builds,
 * each inside the file, none overlapping another, so together they are never more than the file). The loader maps one
 * build; strings elsewhere in the file are none of them. → null when the file isn't a universal one,
 * { slices: [{ start, length }] }, or { bad: true } when its header can't be read sensibly (builds that overlap
 * included: read build by build, they would read the same bytes again, past the run's reading budget). `budget`, when
 * given (loadable's look at a candidate): each read of the header (8 bytes, then the list of builds, at most 2,048) is
 * charged to it before it is made, and { over: true } when it has no room left.
 */
export function fatSlices(file, size, budget) {
  const room = (n) => { if (!budget) return true; if (n > budget.left) return false; budget.left -= n; return true; };
  if (!room(8)) return { over: true };
  const h = readHead(file, 8);
  if (!h || h.length < 8) return null;
  const magic = h.readUInt32BE(0);
  if (![0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].includes(magic)) return null;
  const le = magic === 0xbebafeca || magic === 0xbfbafeca, is64 = magic === 0xcafebabf || magic === 0xbfbafeca;
  const n = le ? h.readUInt32LE(4) : h.readUInt32BE(4), ent = is64 ? 32 : 20;
  if (n < 1 || n > 64) return { bad: true };
  if (!room(n * ent)) return { over: true };
  const t = readAt(file, 8, n * ent);
  if (!t || t.length < n * ent) return { bad: true };
  const u32 = (o) => (le ? t.readUInt32LE(o) : t.readUInt32BE(o));
  const u64 = (o) => Number(le ? t.readBigUInt64LE(o) : t.readBigUInt64BE(o));
  const slices = [];
  for (let i = 0; i < n; i++) {
    const o = i * ent, start = is64 ? u64(o + 8) : u32(o + 8), length = is64 ? u64(o + 16) : u32(o + 12);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || length < 4 || start < 8 + n * ent || start + length > size) return { bad: true };
    slices.push({ start, length });
  }
  const byStart = [...slices].sort((a, b) => a.start - b.start);
  for (let i = 1; i < byStart.length; i++) if (byStart[i].start < byStart[i - 1].start + byStart[i - 1].length) return { bad: true };
  return { slices };
}

// Mach-O load commands (mach-o/loader.h). A command dyld can't do without carries LC_REQ_DYLD (0x80000000); the ones read
// here are known with or without it.
const LC_DYLIB = new Map([[0x0c, 'LC_LOAD_DYLIB'], [0x18, 'LC_LOAD_WEAK_DYLIB'], [0x1f, 'LC_REEXPORT_DYLIB'], [0x20, 'LC_LAZY_LOAD_DYLIB'], [0x23, 'LC_LOAD_UPWARD_DYLIB']]);
const LC_ID_DYLIB = 0x0d, LC_RPATH = 0x1c, LC_CODE_SIGNATURE = 0x1d, LC_DYLD_ENVIRONMENT = 0x27;
const MACHO = new Map([[0xfeedface, { is64: false, le: false }], [0xcefaedfe, { is64: false, le: true }], [0xfeedfacf, { is64: true, le: false }], [0xcffaedfe, { is64: true, le: true }]]);
// ELF dynamic tags (elf.h)
const DT = { 1: 'DT_NEEDED', 5: 'DT_STRTAB', 10: 'DT_STRSZ', 14: 'DT_SONAME', 15: 'DT_RPATH', 29: 'DT_RUNPATH' };
const DT_FLAGS_1 = 0x6ffffffb, DF_1_PIE = 0x08000000;
// What CPU a build is for, as one string: a Mach-O build's cputype (its cpusubtype is not part of it: dyld loads an
// arm64e dylib into an arm64 program, probe m1e, and x86_64h beside x86_64), an ELF file's class, byte order and
// machine. A library of another one is no copy the loader can load into that build; any library of the same one is.
const machoCpu = (type) => `Mach-O cputype ${type >>> 0}`;
const elfCpu = (is64, le, machine) => `ELF ${is64 ? 64 : 32}-bit ${le ? 'little' : 'big'}-endian machine ${machine}`;

/** What makes a file's headers unreadable as its format lays them out: the file is UNKNOWN, with `message` as the why. */
class Malformed extends Error {}
/** A read the run's reading budget has no room left for: the file is UNKNOWN, not read. */
class OverBudget extends Error {}

/** `n` bytes from `offset` (`read`: linkTable's reader), in reads of at most 64 KB; null when they aren't all there. */
function readRange(read, offset, n) {
  const parts = [];
  for (let done = 0; done < n; done += 64 * 1024) {
    const k = Math.min(64 * 1024, n - done), b = read(offset + done, k);
    if (!b || b.length < k) return null;
    parts.push(b);
  }
  return Buffer.concat(parts, n);
}

/** A name as the loader reads it: the bytes of `buf` from `at` to the first NUL before `end`. Malformed when there is no
 *  NUL there, when it is empty (unless `empty`), or when the bytes aren't UTF-8 (no file name Wardlatch could look up).
 *  → [text, where its NUL is] */
function nameAt(buf, at, end, what, empty = false) {
  const z = buf.indexOf(0, at);
  if (z < 0 || z >= end) throw new Malformed(`${what}'s name has no end inside it`);
  const bytes = buf.subarray(at, z), text = bytes.toString('utf8');
  if ((!bytes.length && !empty) || !Buffer.from(text, 'utf8').equals(bytes)) throw new Malformed(`${what}'s name is empty or not UTF-8`);
  return [text, z];
}

/**
 * The identifiers in one Mach-O build's code signature (cs_blobs.h, big-endian: a SuperBlob whose CodeDirectory slots,
 * 0 and the alternates 0x1000 to 0x1004, each hold an identOffset; codesign names a file by its file name), with their
 * places in the build. Anything that doesn't fit is passed over: no identifier, nothing exempt (dlopenWant).
 */
function signIds(read, start, length, off, size) {
  const out = [];
  if (off + size > length || size < 12) return out;
  const h = read(start + off, 12);
  if (!h || h.length < 12 || h.readUInt32BE(0) !== 0xfade0cc0) return out;
  const n = h.readUInt32BE(8);
  if (n > 32 || 12 + n * 8 > size) return out;
  const index = read(start + off + 12, n * 8);
  if (!index || index.length < n * 8) return out;
  for (let k = 0; k < n; k++) {
    const type = index.readUInt32BE(k * 8), at = index.readUInt32BE(k * 8 + 4);
    if (!(type === 0 || (type >= 0x1000 && type <= 0x1004)) || at + 24 > size) continue;
    const cd = read(start + off + at, 24);
    if (!cd || cd.length < 24 || cd.readUInt32BE(0) !== 0xfade0c02) continue;
    const ident = at + cd.readUInt32BE(20);
    if (ident >= size) continue;
    const b = read(start + off + ident, Math.min(1024, size - ident)), z = b ? b.indexOf(0) : -1;
    if (z > 0) out.push({ text: b.subarray(0, z).toString('utf8'), at: off + ident, end: off + ident + z });
  }
  return out;
}

/**
 * One Mach-O build's link table, from its header and load commands (thin, 32- or 64-bit, either byte order), walked as
 * dyld walks them: `ncmds` commands, each at least 8 bytes, a multiple of 4, inside `sizeofcmds`, which is inside the
 * build. Read: LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB and LC_LOAD_UPWARD_DYLIB (`links`),
 * LC_RPATH (`rpaths`), LC_ID_DYLIB (`id`, the file's own install name), LC_DYLD_ENVIRONMENT (`env`) and the code
 * signature's identifiers (`signs`); each name at its offset in its command, up to the NUL inside the command. `own`:
 * where those names are in the build; `cpu`: the CPU it is for (machoCpu); `main`: a program (MH_EXECUTE). → null when
 * the build isn't Mach-O; Malformed when its headers don't fit.
 */
function machoTable(read, start, length) {
  const h = read(start, 32);
  const kind = h && h.length >= 4 ? MACHO.get(h.readUInt32BE(0)) : undefined;
  if (!kind) return null;
  const { is64, le } = kind, head = is64 ? 32 : 28;
  if (h.length < head || head > length) throw new Malformed('its header is cut short');
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const filetype = u32(h, 12), ncmds = u32(h, 16), sizeofcmds = u32(h, 20);
  if (sizeofcmds > MAX_CMDS) throw new Malformed(`its load commands take ${sizeofcmds} bytes, more than the 1 MB Wardlatch reads`);
  if (head + sizeofcmds > length) throw new Malformed('its load commands run past the end of the file');
  if (ncmds * 8 > sizeofcmds) throw new Malformed(`it counts ${ncmds} load commands, more than fit in their ${sizeofcmds} bytes`);
  const c = readRange(read, start + head, sizeofcmds);
  if (!c) throw new Malformed('its load commands could not all be read');
  const t = { format: 'Mach-O', main: filetype === 2, cpu: machoCpu(u32(h, 4)), links: [], rpaths: [], id: null, env: [], own: [], signs: [] };
  let sign = null;
  for (let i = 0, off = 0; i < ncmds; i++) {
    if (off + 8 > sizeofcmds) throw new Malformed(`load command ${i + 1} of ${ncmds} starts past the space they take`);
    const cmd = u32(c, off), size = u32(c, off + 4), base = cmd & 0x7fffffff;
    if (size < 8 || size % 4 || off + size > sizeofcmds) throw new Malformed(`load command ${i + 1} has a size (${size}) that doesn't fit`);
    // an lc_str: its offset from the command's start (at least the command's own fields), its name up to a NUL inside it
    const str = (min, what) => {
      if (size < min) throw new Malformed(`a ${what} command is shorter than its fields`);
      const at = u32(c, off + 8);
      if (at < min || at >= size) throw new Malformed(`a ${what} command's name starts outside it`);
      const [text, z] = nameAt(c, off + at, off + size, `a ${what} command`);
      t.own.push([head + off + at, head + z]);
      return text;
    };
    if (LC_DYLIB.has(base)) t.links.push(str(24, LC_DYLIB.get(base)));
    else if (base === LC_ID_DYLIB) {
      if (t.id !== null) throw new Malformed('it has more than one LC_ID_DYLIB');
      t.id = str(24, 'LC_ID_DYLIB');
    } else if (base === LC_RPATH) t.rpaths.push(str(12, 'LC_RPATH'));
    else if (base === LC_DYLD_ENVIRONMENT) t.env.push(str(12, 'LC_DYLD_ENVIRONMENT'));
    else if (base === LC_CODE_SIGNATURE && size >= 16) sign = [u32(c, off + 8), u32(c, off + 12)];
    off += size;
  }
  if (sign) t.signs = signIds(read, start, length, ...sign);
  return t;
}

// The largest page a loader maps with (arm64's and ppc64's 64 KB pages)
const MAX_PAGE = 64 * 1024;

/**
 * The PT_LOAD segment (of `loads`) whose bytes are at the `len` bytes from address `addr` once the file is loaded (its
 * dynamic table, its string table), for a file that doesn't contradict itself. The kernel and ld.so map the PT_LOAD
 * segments a page at a time, in order, each one over what is there, so an address in the page-rounded range of more
 * than one PT_LOAD may hold another segment's bytes than the first's: Malformed (probes E4b, E4c). So is an address no
 * PT_LOAD maps from the file (`none`). A segment's page-rounded range runs from its p_vaddr rounded down to its page to
 * its end (p_vaddr + p_memsz, or p_filesz if larger) rounded up; its page is its p_align, at most 64 KB (the largest
 * page a loader maps with), and 64 KB when its p_align is under 4 KB, which says nothing about the page.
 */
function mapAt(loads, addr, len, what, none) {
  const end = addr + Math.max(len, 1);
  const covers = loads.filter((s) => {
    const page = s.align >= 4096 ? Math.min(s.align, MAX_PAGE) : MAX_PAGE;
    return Math.floor(s.vaddr / page) * page < end && addr < Math.ceil((s.vaddr + Math.max(s.memsz, s.filesz)) / page) * page;
  });
  if (covers.length > 1) throw new Malformed(`${what} is at an address more than one PT_LOAD segment maps (on the same page), so which bytes the loader reads there could not be told`);
  const s = covers[0];
  if (!s || addr < s.vaddr || addr + len > s.vaddr + s.filesz) throw new Malformed(none);
  return s;
}

/**
 * An ELF file's link table (32- or 64-bit, either byte order), as ld.so reads it: the program headers, the one
 * PT_DYNAMIC segment, and in its table (up to DT_NULL) DT_NEEDED (`links`), DT_SONAME (`id`), DT_RPATH (`rpath`) and
 * DT_RUNPATH (`runpath`), each an offset into the string table DT_STRTAB names (an address, placed in the file through
 * the PT_LOAD segment that holds it, DT_STRSZ long), each name up to its NUL inside that table. Every read is bounded
 * and checked against the file's size. A file with no PT_DYNAMIC (statically linked) links nothing. The dynamic table is
 * read at PT_DYNAMIC's p_offset, and must be the same bytes the loader reads at its p_vaddr, placed in the file by the
 * PT_LOAD segment that maps it: a file whose two tables differ contradicts itself (Malformed), and so does one whose
 * dynamic table or string table is at an address in the page-rounded range of more than one PT_LOAD (mapAt). `own`:
 * where those names are in the file; `cpu`: the CPU it is for (elfCpu); `main`: a program for certain (ET_EXEC, or
 * flagged DF_1_PIE in DT_FLAGS_1); any other is read as a library, whose program isn't known. → null when it isn't ELF;
 * Malformed when its headers don't fit.
 */
function elfTable(read, size) {
  const h = read(0, 64);
  if (!h || h.length < 4 || h.readUInt32BE(0) !== 0x7f454c46) return null;
  if (h.length < 52 || ![1, 2].includes(h[4]) || ![1, 2].includes(h[5]) || h[6] !== 1) throw new Malformed('its identification bytes are not a class, byte order and version the format has');
  const is64 = h[4] === 2, le = h[5] === 1;
  if (is64 && h.length < 64) throw new Malformed('its header is cut short');
  const u16 = (b, o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  // a 64-bit field past what a Number holds exactly is Infinity, which no bound below lets through
  const word = (b, o) => { if (!is64) return u32(b, o); const v = le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o); return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : Infinity; };
  const phoff = word(h, is64 ? 32 : 28), phentsize = u16(h, is64 ? 54 : 42), phnum = u16(h, is64 ? 56 : 44);
  const t = { format: 'ELF', main: u16(h, 16) === 2, cpu: elfCpu(is64, le, u16(h, 18)), links: [], rpath: null, runpath: null, id: null, env: [], own: [], signs: [] };
  if (!phnum) return t;
  if (phnum === 0xffff || phentsize < (is64 ? 56 : 32) || phentsize * phnum > 64 * 1024 || phoff + phentsize * phnum > size) throw new Malformed('its program headers don\'t fit in the file');
  const ph = read(phoff, phentsize * phnum);
  if (!ph || ph.length < phentsize * phnum) throw new Malformed('its program headers could not all be read');
  const loads = [], dyns = [];
  for (let i = 0; i < phnum; i++) {
    const o = i * phentsize, type = u32(ph, o);
    const seg = is64 ? { off: word(ph, o + 8), vaddr: word(ph, o + 16), filesz: word(ph, o + 32), memsz: word(ph, o + 40), align: word(ph, o + 48) }
      : { off: u32(ph, o + 4), vaddr: u32(ph, o + 8), filesz: u32(ph, o + 16), memsz: u32(ph, o + 20), align: u32(ph, o + 28) };
    if (type === 1) loads.push(seg);
    else if (type === 2) dyns.push(seg);
  }
  if (!dyns.length) return t;
  if (dyns.length > 1) throw new Malformed('it has more than one dynamic segment');
  const { off, vaddr, filesz } = dyns[0], ent = is64 ? 16 : 8;
  if (filesz > 64 * 1024 || off + filesz > size) throw new Malformed('its dynamic segment doesn\'t fit in the file');
  const dyn = read(off, filesz);
  if (!dyn || dyn.length < filesz) throw new Malformed('its dynamic segment could not be read');
  // ld.so reads the table at its address (p_vaddr), where a PT_LOAD segment maps it: that must be the same table
  const map = mapAt(loads, vaddr, filesz, 'its dynamic table', 'its dynamic table is at an address no part of the file the loader maps holds');
  const mapped = map.off + (vaddr - map.vaddr);
  if (mapped !== off) {
    const other = mapped + filesz <= size ? read(mapped, filesz) : null;
    if (!other || !other.equals(dyn)) throw new Malformed('the dynamic table at its place in the file is not the one the loader reads at its address');
  }
  const tags = { 1: [], 5: [], 10: [], 14: [], 15: [], 29: [], [DT_FLAGS_1]: [] };
  let ended = false;
  for (let j = 0; j + ent <= dyn.length; j += ent) {
    const tag = word(dyn, j);
    if (tag === 0) { ended = true; break; }
    if (tags[tag]) tags[tag].push(word(dyn, j + ent / 2));
  }
  if (!ended) throw new Malformed('its dynamic table has no DT_NULL inside its segment');
  if (tags[DT_FLAGS_1].some((v) => v & DF_1_PIE)) t.main = true;
  for (const k of [5, 10, 14, 15, 29]) if (tags[k].length > 1) throw new Malformed(`it has more than one ${DT[k]}`);
  if (!tags[1].length && !tags[14].length && !tags[15].length && !tags[29].length) return t;
  if (!tags[5].length || !tags[10].length) throw new Malformed('it names libraries but has no string table');
  const addr = tags[5][0], strsz = tags[10][0];
  const seg = mapAt(loads, addr, strsz, 'its string table', 'its string table is in no part of the file the loader maps');
  const stroff = seg.off + (addr - seg.vaddr);
  if (stroff + strsz > size) throw new Malformed('its string table runs past the end of the file');
  const str = (v, k, empty = false) => {
    if (v >= strsz) throw new Malformed(`its ${DT[k]} points outside its string table`);
    const b = read(stroff + v, Math.min(MAX_NAME, strsz - v));
    if (!b) throw new Malformed(`its ${DT[k]} could not be read`);
    const [text, z] = nameAt(b, 0, b.length, `its ${DT[k]}`, empty);
    t.own.push([stroff + v, stroff + v + z]);
    return text;
  };
  t.links = tags[1].map((v) => str(v, 1));
  if (tags[14].length) t.id = str(tags[14][0], 14);
  // an empty search path names no folder (it is read as the folder the program starts in when a soname is looked up)
  if (tags[15].length) t.rpath = str(tags[15][0], 15, true);
  if (tags[29].length) t.runpath = str(tags[29][0], 29, true);
  return t;
}

/**
 * The libraries one build of a file links, read as the loader reads them, from the binary format and nothing else:
 * machoTable for a Mach-O build (thin, or one build of a universal file: `fat`), elfTable for an ELF file.
 * Each read is charged to the run's reading budget (`budget`) before it is made.
 * → the table, { format: null } for a file that is neither (or a build of a universal file that isn't Mach-O),
 *   { format, bad: why } for one whose headers don't fit (the file is then UNKNOWN), or { overBudget: true }.
 */
export function linkTable(file, { start = 0, length, size, fat = false, budget } = {}) {
  const read = (offset, n) => {
    if (budget) { if (n > budget.left) throw new OverBudget(); budget.left -= n; }
    return readAt(file, offset, n);
  };
  let format = 'Mach-O';
  try {
    const m = machoTable(read, start, length ?? size);
    if (m || fat) return m ?? { format: null };
    format = 'ELF';
    return elfTable(read, size) ?? { format: null };
  } catch (e) {
    if (e instanceof Malformed) return { format, bad: e.message };
    if (e instanceof OverBudget) return { overBudget: true };
    throw e;
  }
}

/**
 * Which names of a Brotli library or of libnode in one build count as ones it may load while it runs (dlopen), for
 * scanBytes's `want`: a hit of the library's stem at `i` of `hay` (`pos` in the file) counts when it goes on to a file
 * name the loader can load (loadableAt) and is none of the build's own names: not inside a name the loader reads in its
 * link table (`own`: its links, its install name or soname, its search paths, LC_DYLD_ENVIRONMENT), not a whole C
 * string equal to one of its links or to its own install name or soname, and not its code-signing identifier when that
 * equals the file's own name. Nothing else is exempt: a decoder library's own file name says nothing about the names it
 * holds. `caseless`: compared ignoring case (macOS), as `hay` is then folded. → want(hay, i, needle, pos)
 */
function dlopenWant(file, table, start, caseless) {
  if (table.bad || !table.format) return () => false;   // nothing is looked at past a table that can't be read (UNKNOWN)
  const fold = (x) => (caseless ? asciiLower(x) : x);
  const self = [basename(file), basename(realPathAsWritten(file) ?? file)].map(fold);
  const ranges = [...table.own, ...table.signs.filter((x) => self.includes(fold(x.text))).map((x) => [x.at, x.end])].sort((p, q) => p[0] - q[0]);
  const own = [];   // merged, so the last range starting at or before a place is the only one that can hold it
  for (const [s, e] of ranges) { const last = own[own.length - 1]; if (last && s <= last[1]) last[1] = Math.max(last[1], e); else own.push([s, e]); }
  const inOwn = (at) => {
    let lo = 0, hi = own.length - 1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (own[mid][0] <= at) lo = mid + 1; else hi = mid - 1; }
    return hi >= 0 && at < own[hi][1];
  };
  const entries = [...table.links, ...(table.id === null ? [] : [table.id])].map((x) => Buffer.from(fold(x), 'utf8'));
  return (hay, i, n, pos) => {
    if (!loadableAt(hay, i + n.length) || inOwn(pos - start)) return false;
    // the C string it is in, if both its NULs are within a name's length of it (bounded: no walk past MAX_NAME)
    const from = Math.max(0, i - MAX_NAME), back = hay.subarray(from, i).lastIndexOf(0), fwd = hay.subarray(i, i + MAX_NAME).indexOf(0);
    if (back < 0 || fwd < 0) return true;
    const c = hay.subarray(from + back + 1, i + fwd);
    return !entries.some((x) => x.equals(c));
  };
}

/**
 * What a file holds, for each build in it (one, or each build of a universal Mach-O file): counts of the marker and
 * control (exact, NUL-delimited), of the same two error texts in the form Brotli 1.0 writes them (no prefix: before
 * 1.1.0 BrotliDecoderErrorString returns the bare name) and, in `t10`, how many copies of that control are in a whole
 * 1.0 table with the fix, without it, or neither (table10At), of Node's constant names (only to tell a Node.js program
 * from a version manager's shim, never as evidence of a fix), its link table (`table`: linkTable) with the Brotli
 * decoder libraries (`links`) and libnode (`nodeLibs`) it links, the names of such libraries it holds outside that
 * table (`dlopen`: dlopenWant, the first 64 shown; `crowded` when there were more hits of either stem than are looked
 * at, MAX_LOOKS), and a Node release version if it embeds one (for wording only).
 * budget: { left } bytes this run may still read; each build's bytes are taken off it before they are read. → null when
 * the file can't be read; { overBudget: true } when what is left of the budget is less than the file's size (or than a
 * build's); { badFat: true } for a universal file whose header can't be read, or whose builds overlap. The whole file's
 * counts are at the top (sums), each build's in `slices`. `caseless`: library names are found and compared ignoring
 * case (by default on macOS).
 */
export function evidence(file, markers, budget, { caseless = CASELESS } = {}) {
  if (budget && budget.left <= 0) return { overBudget: true };
  const size = sizeOf(file);
  if (size === null || size > MAX_PROGRAM) return null;
  // the budget is checked against the file's size before it is read, and each build is charged to it before it is read:
  // the builds don't overlap (fatSlices), so together they are at most that size, and a run reads at most its budget (a
  // file that grows meanwhile is read up to the size it had); the reads of a build's link table (its header, load
  // commands or dynamic table, at most about 1 MB) are charged before each is made too
  if (budget && size > budget.left) return { overBudget: true };
  const fat = fatSlices(file, size);
  if (fat?.bad) return { badFat: true };
  const old = (k) => markers[k].slice(markers[k].indexOf('_ERROR_FORMAT_') === 0 ? '_ERROR_FORMAT_'.length : 0);
  const anchor10 = nul(old('table'));
  const form10 = { run: markers.table10 ?? [], anchor: old('table'), fixed: old('fixed'), after: markers.after10, unfixed: markers.unfixed10 ?? [[]] };
  const slices = [];
  let charged = 0;
  for (const { start, length } of fat?.slices ?? [{ start: 0, length: size }]) {
    charged += length;
    if (charged > size) return { badFat: true };
    if (budget) { if (length > budget.left) return { overBudget: true }; budget.left -= length; }
    const table = linkTable(file, { start, length, size, fat: Boolean(fat), budget });
    if (table.overBudget) return { overBudget: true };
    const r = scanBytes(file, {
      count: [nul(markers.fixed), nul(markers.table), Buffer.from(markers.nodeConstant + markers.fixed), Buffer.from(markers.nodeConstant + markers.table), nul(old('fixed')), anchor10],
      around: [RELEASE, anchor10], select: [DECODER, NODE_LIB], fold: caseless, want: dlopenWant(file, table, start, caseless), maxLooks: MAX_LOOKS,
      back: 1024, fwd: 256, maxHits: 64, maxBytes: MAX_PROGRAM, start, length,
    });
    if (!r) return null;
    const [m0, c0, mk, ck, um0, uc0] = r.counts;
    // Brotli 1.0's form: each copy of the control's name kept is read as a table or not; copies past the ones kept count
    // as not (`other`)
    const t10 = { fixed: 0, unfixed: 0, other: uc0 - r.hits[1].length };
    for (const h of r.hits[1]) t10[table10At(h.buf, h.at, anchor10.length, form10) ?? 'other']++;
    const release = r.hits[0].map((h) => printableAround(h.buf, h.at + RELEASE.length, { backward: false })).map((x) => {
      let i = 0; while (i < x.length && i < 16 && (x[i] === '.' || (x[i] >= '0' && x[i] <= '9'))) i++;
      return x.slice(0, i);
    }).find((x) => /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(x)) ?? '';
    const read = !table.bad && table.format;
    slices.push({
      m0, c0, mk, ck, um0, uc0, t10, release, table,
      links: read ? table.links.filter(isDecoderLibName) : [], nodeLibs: read ? table.links.filter(isNodeLibName) : [],
      dlopen: r.chosen.flat().map(hitShown), crowded: r.unlooked.some((n) => n > 0),
    });
  }
  const sum = (k) => slices.reduce((n, x) => n + x[k], 0);
  return {
    m0: sum('m0'), c0: sum('c0'), mk: sum('mk'), ck: sum('ck'), um0: sum('um0'), uc0: sum('uc0'),
    t10: { fixed: slices.reduce((n, x) => n + x.t10.fixed, 0), unfixed: slices.reduce((n, x) => n + x.t10.unfixed, 0), other: slices.reduce((n, x) => n + x.t10.other, 0) },
    links: [...new Set(slices.flatMap((x) => x.links))], nodeLibs: [...new Set(slices.flatMap((x) => x.nodeLibs))],
    dlopen: [...new Set(slices.flatMap((x) => x.dlopen))], crowded: slices.some((x) => x.crowded),
    release: slices.map((x) => x.release).find(Boolean) ?? '', slices,
  };
}

/**
 * Whether `lib` is a copy the loader may load as a library into a build for `cpu` (its link table's `cpu`): a Mach-O
 * dylib (MH_DYLIB) with a build of that CPU type, whatever its subtype (thin, or one build of a universal file: dyld
 * loads an arm64e dylib into an arm64 program), or an ELF shared object (ET_DYN) of that class, byte order and machine.
 * Anything else (another format, another CPU type, a program, a bundle, a file it can't read) is not: dyld and ld.so
 * pass over such a file and look on. Read from the headers only, each read (a universal file's list of builds too)
 * charged to the run's reading budget before it is made. → true, false, or 'over' (no room left in the budget)
 */
function loadable(lib, cpu, budget) {
  const size = sizeOf(lib);
  if (size === null || !cpu) return false;
  const fat = fatSlices(lib, size, budget);
  if (fat?.over) return 'over';
  if (fat?.bad) return false;
  for (const { start } of fat?.slices ?? [{ start: 0 }]) {
    if (budget) { if (budget.left < 64) return 'over'; budget.left -= 64; }
    const h = readAt(lib, start, 64);
    if (!h || h.length < 20) continue;
    const m = MACHO.get(h.readUInt32BE(0));
    if (m) {
      const u32 = (o) => (m.le ? h.readUInt32LE(o) : h.readUInt32BE(o));
      if (u32(12) === 6 && machoCpu(u32(4)) === cpu) return true;
    } else if (!fat && h.readUInt32BE(0) === 0x7f454c46 && [1, 2].includes(h[4]) && [1, 2].includes(h[5])) {
      const le = h[5] === 1, u16 = (o) => (le ? h.readUInt16LE(o) : h.readUInt16BE(o));
      if (u16(16) === 3 && elfCpu(h[4] === 2, le, u16(18)) === cpu) return true;
    }
  }
  return false;
}

const MAX_HWCAPS = 64;   // subfolders of a glibc-hwcaps folder looked in (glibc knows a handful); more is UNKNOWN

/**
 * Every file the loader may take for a library a file links (`ref`, exactly a load command's or a DT_NEEDED entry's
 * name), from the file's own link table (`table`). Wardlatch doesn't emulate which one the loader takes; where dyld or
 * ld.so could take a different copy, each is a candidate (every one must be SAFE, an EXPOSED one decides, and any other
 * makes the file UNKNOWN):
 *  - every folder of a search path that holds a file of that name, not just the first: each LC_RPATH entry, in order,
 *    for @rpath (an absolute path, @loader_path, or @executable_path in a main program); on Mach-O only the file's own
 *    resolved @rpath, @loader_path or absolute path is looked in. For a bare ELF soname: its own DT_RUNPATH (or its
 *    DT_RPATH without one), then the program's that loads it (`loader`, when it was followed from one: musl reads the
 *    program's DT_RUNPATH or DT_RPATH whatever the library's, glibc the program's DT_RPATH for a library with no
 *    DT_RUNPATH; both are taken), then the system's folders `sonameDirs` (every copy there, as the loader's cache, which
 *    isn't read, decides among them; UNKNOWN when what the loader is told to search could not all be read,
 *    `sonameGaps`, and for a library whose program isn't known, read without one, whose own folders don't stop the
 *    search). One thing only stops the search before the system's folders (the safe-side rule, round 8): a copy the
 *    loader can load (`load`) in a plain folder (not a glibc-hwcaps one) of the file's OWN DT_RUNPATH, or of its own
 *    DT_RPATH when it has no DT_RUNPATH, in that folder however $ORIGIN reads, with every copy found loadable and nothing
 *    left that couldn't be followed. A copy found through the program's folders (glibc never takes them for a library
 *    with a DT_RUNPATH, nor a program's DT_RUNPATH for any library: C1, C2), or only in a glibc-hwcaps subfolder (glibc
 *    looks in one only on a CPU of that level, musl never: H5), is a candidate that must be SAFE, and never stops it;
 *  - on ELF, the glibc-hwcaps/<any name>/ subfolders of every folder searched for a soname, which glibc looks in first;
 *  - on ELF, $ORIGIN (or ${ORIGIN}) as the folder of the file's real path and the folder it was reached by (`opened`, as
 *    written: glibc takes a library's $ORIGIN from the path it opened it by, and a program's from its real path);
 *    @loader_path is the file's real folder (dyld's).
 * Each candidate's path is put together as written and handed to the OS, which follows its links and then its '..' as
 * the kernel does (never cleaned up as text first), and the candidate is known by its real path. Whether the loader can
 * load it into this build (`loadable`) is read too: a copy it can't load is UNKNOWN, never SAFE. A bare name or a
 * relative path (or search folder) is looked for from the folder the program is started in; any other $ variable
 * ($LIB, $PLATFORM) or @ form can't be followed.
 * → { files: [{ file: its real path, opened: the path as written, load }], why?, via?, looked } where `why` ('relative',
 *   'cant', 'missing', 'gap', 'program') is a part that can't be followed, beside the candidates found or alone.
 */
export function resolveLink(ref, file, table, { sonameDirs = [], sonameGaps = [], opened = file, loader, budget } = {}) {
  const files = [], seen = new Map(), looked = [];
  let unsure = null;   // the first part that can't be followed
  const doubt = (why, via) => { unsure ??= { why, ...(via === undefined ? {} : { via }) }; };
  // a candidate, once by its real path → its entry
  const take = (path) => {
    const real = realPathAsWritten(path) ?? path;
    if (!seen.has(real)) { const c = { file: real, opened: path, load: loadable(real, table.cpu, budget) }; seen.set(real, c); files.push(c); }
    return seen.get(real);
  };
  // one path: a file, or not there, or something that can't be looked at
  const one = (p) => { const st = pathState(p); if (st === 'file') take(p); else doubt(st === 'gone' ? 'missing' : 'cant'); };
  // a folder of a search path → the copy there, if any; in the system's folders, a folder of that name is passed over,
  // as before
  const look = (dir, name, via, system = false) => {
    const st = pathState(`${dir}/${name}`);
    looked.push(dir);
    if (st === 'file') return take(`${dir}/${name}`);
    if (st !== 'gone' && !(system && st === 'dir')) doubt('cant', via);
    return null;
  };
  // glibc's subfolders for this CPU's levels (x86-64-v3, power10, ...), each looked in before the folder: every one
  // there is, whatever its name
  const hwcaps = (dir, name, via, system = false) => {
    const sub = `${dir}/glibc-hwcaps`, l = listDir(sub);
    if (l.denied || (l.entries?.length ?? 0) > MAX_HWCAPS) { doubt('cant', via); return; }
    for (const n of (l.entries ?? []).map((e) => e.name).sort()) look(`${sub}/${n}`, name, via, system);
  };
  const done = () => (files.length || unsure ? { files, ...unsure, looked } : { files, why: 'missing', looked });
  if (table.format === 'Mach-O') {
    const origin = dirname(realPathAsWritten(file) ?? file);
    const at = (p) => {
      for (const [k, ok] of [['@loader_path', true], ['@executable_path', table.main]]) if (p === k || p.startsWith(`${k}/`)) return ok ? origin + p.slice(k.length) : null;
      return p.startsWith('@') ? null : p;
    };
    if (ref.startsWith('@rpath/')) {
      for (const rp of table.rpaths) {
        const dir = at(rp);
        if (dir === null) doubt('cant', rp);
        else if (!dir.startsWith('/')) doubt('relative', rp);
        else look(dir, ref.slice('@rpath/'.length), rp);
      }
      return done();
    }
    const p = at(ref);
    if (p === null) doubt('cant'); else if (!p.startsWith('/')) doubt('relative'); else one(p);
    return done();
  }
  // $ORIGIN: the folder of the file's real path, and the folder it was reached by when that is another
  const origins = (f, by) => { const real = dirname(realPathAsWritten(f) ?? f), as = realPathAsWritten(dirname(by)); return as && as !== real ? [real, as] : [real]; };
  const dst = (s, origin) => {
    let out = '';
    for (let i = 0; i < s.length;) {
      if (s.startsWith('${ORIGIN}', i)) { out += origin; i += 9; } else if (s.startsWith('$ORIGIN', i) && (i + 7 === s.length || s[i + 7] === '/')) { out += origin; i += 7; } else if (s[i] === '$') return null;
      else out += s[i++];
    }
    return out;
  };
  // each way a name reads, one per origin: null when one of them can't be followed
  const readings = (s, os) => { const xs = os.map((o) => dst(s, o)); return xs.includes(null) ? null : [...new Set(xs)]; };
  const mine = origins(file, opened);
  if (ref.includes('/')) {
    const ps = readings(ref, mine);
    if (ps === null) doubt('cant');
    else for (const p of ps) { if (p.startsWith('/')) one(p); else doubt('relative'); }
    return done();
  }
  // a bare soname: its own DT_RUNPATH, or its DT_RPATH without one; then its program's. glibc reads the program's DT_RPATH
  // (for a library with no DT_RUNPATH; a DT_RPATH beside a DT_RUNPATH is never read), musl the program's DT_RUNPATH or
  // DT_RPATH whatever the library's; both are taken
  const lists = [], own = table.runpath ?? table.rpath, theirs = loader?.table.format === 'ELF' ? loader.table.runpath ?? loader.table.rpath : null;
  if (own !== null) lists.push([own, mine, true]);
  if (theirs !== null) lists.push([theirs, origins(loader.file, loader.opened ?? loader.file), false]);
  // whether a folder of the file's own search path holds, however $ORIGIN reads, a copy the loader can load (the only
  // thing that stops the search before the system's folders)
  let stops = false;
  for (const [path, os, isOwn] of lists) {
    for (const raw of path.split(':')) {
      const dirs = readings(raw, os);
      if (dirs === null) { doubt('cant', raw); continue; }
      let held = dirs.length > 0;
      for (const dir of dirs) {
        if (!dir.startsWith('/')) { doubt('relative', raw); held = false; continue; }
        hwcaps(dir, ref, raw);
        if (look(dir, ref, raw)?.load !== true) held = false;
      }
      if (isOwn && held) stops = true;
    }
  }
  // the loader goes on to the system's folders unless a copy it takes for certain was found: one in a plain folder of
  // its own search path (above), every copy found loadable, and nothing left that couldn't be followed. A copy found
  // only through the program's folders, or only in a glibc-hwcaps subfolder, never stops it
  if (stops && !unsure && files.every((f) => f.load === true)) return done();
  // a library whose program isn't known (read on its own, or followed from a library): that program's folders come
  // before the system's
  if (!table.main && !loader?.table.main) doubt('program');
  if (sonameGaps.length) { doubt('gap'); return done(); }
  for (const d of sonameDirs) { hwcaps(d, ref, d, true); look(d, ref, d, true); }
  return done();
}

/** Why a link can't be followed (resolveLink's `why`), in a row's words. `what`: what the library is, after its name. */
function linkWhy(ref, r, { sonameGaps = [] }, what = '') {
  const few = (xs) => `${xs.slice(0, 4).join(', ')}${xs.length > 4 ? `, and ${xs.length - 4} more` : ''}`;
  if (r.why === 'relative') return r.via === undefined ? RELATIVE(ref, what) : `it links ${ref}${what}, and looks for it in '${r.via}', a folder named by a relative path, which the loader takes from the folder the program is started in, so which file it loads, and whether that has the fix, could not be tested`;
  if (r.why === 'gap') return `it links ${ref}${what}, and what the dynamic loader is told to search could not all be read (${sonameGaps.slice(0, 3).join(', ')}${sonameGaps.length > 3 ? ', ...' : ''}), so which file it loads, and whether that has the fix, could not be tested`;
  if (r.why === 'missing') return `it links ${ref}${what}, which was not found${r.looked?.length ? ` (looked in ${few([...new Set(r.looked)])})` : ''}, so whether it has the fix could not be tested`;
  if (r.why === 'program') return `it links ${ref}${what}, which its own folders don't hold, and it is read as a library, whose program isn't known here: the loader looks for that name in the folders the program names (its DT_RPATH or DT_RUNPATH) before the system's, so which file it loads, and whether that has the fix, could not be tested`;
  return `it links ${ref}${what}, which Wardlatch can't follow or open${r.via ? ` (through '${r.via}')` : ''} (where it is found is decided when the program starts), so whether it has the fix could not be tested`;
}

/** A copy the loader may find for a link that it can't load into this build, in a row's words. */
const UNLOADABLE = (ref, lib, what = '') => `it links ${ref}${what}, and ${lib}, a copy the loader may find for it, is not a library it can load into this build (not a Mach-O or ELF library, or one for another CPU), so the loader may pass over it to another copy: which file it loads, and whether that has the fix, could not be tested`;

/**
 * Every copy the loader may take for each of `refs` (resolveLink), each judged by `judge` (given { file, opened }) when
 * the loader can load it into this build; a copy it can't load, or a part of a link that can't be followed, is in
 * `unsure`. `what`: what the libraries are, after their names. → { done: [{ lib, r }], unsure: [{ via, reason }] }
 */
function followLinks(file, refs, table, opts, judge, what = '') {
  const done = [], unsure = [];
  for (const ref of refs) {
    const r = resolveLink(ref, file, table, opts);
    for (const c of r.files) {
      if (c.load === 'over') done.push({ lib: c.file, r: { status: 'UNKNOWN', reason: OVER_BUDGET } });
      else if (c.load) done.push({ lib: c.file, r: judge(c) });
      else unsure.push({ via: c.file, reason: UNLOADABLE(ref, c.file, what) });
    }
    if (r.why) unsure.push({ via: ref, reason: linkWhy(ref, r, opts, what) });
  }
  return { done, unsure };
}

/** Rule 2: the Brotli libraries a file links decide (one level; `judgeLib` judges each, by rule 1 unless the caller knows
 *  more, such as a distribution's package version). Every candidate must be SAFE for SAFE; any EXPOSED one decides
 *  before a link that can't be followed or a copy the loader can't load. */
function judgeLinks(file, links, table, opts, release) {
  const { markers, judgeLib, budget, caseless } = opts;
  const one = judgeLib ?? ((lib) => judgeFile(lib, { markers, budget, caseless, follow: false }));
  const { done: libs, unsure } = followLinks(file, links, table, opts, (c) => one(c.file));
  const bad = libs.find((x) => x.r.status === 'EXPOSED');
  if (bad) return { status: 'EXPOSED', release, via: bad.lib, reason: `it uses ${bad.lib}, ${bad.r.viaText}` };
  if (unsure.length) return { status: 'UNKNOWN', release, via: unsure[0].via, reason: unsure[0].reason };
  const unk = libs.find((x) => x.r.status !== 'SAFE');
  if (unk) return { status: 'UNKNOWN', release, via: unk.lib, reason: `it uses ${unk.lib}, and for that library: ${unk.r.reason}` };
  return safe([file, ...libs.flatMap((x) => x.r.searched)], { release, via: libs.map((x) => x.lib).join(', '), reason: libs.map((x) => `it uses ${x.lib}, ${x.r.viaText}`).join('; ') });
}

/** The libnode a node launches, judged by judgeFile's rules (its own table, or the Brotli library it links), never
 *  followed to another libnode. Every candidate must be SAFE for SAFE, and an EXPOSED one decides first; the row's `via`
 *  is the library that decided. Each libnode's own links are looked for with this file as the program that loads it
 *  (`loader`) and by the path it was found by (`opened`). `nodeOwn`: libnode's own decoder decided, and libnode is
 *  Node.js's own library, so the fix is Node.js's. */
function judgeNodeLibs(file, refs, table, opts, release) {
  const what = ', the library that holds Node.js\'s code';
  const loader = { file, opened: opts.opened ?? file, table };
  const { done, unsure: un } = followLinks(file, refs, table, opts, (c) => judgeFile(c.file, { ...opts, follow: true, nodeLib: false, opened: c.opened, loader }), what);
  const unsure = un.map((u) => ({ status: 'UNKNOWN', release, via: u.via, runtimeSign: true, byHand: true, reason: u.reason }));
  const said = (x) => `it uses ${x.lib}${what}: ${x.r.reason}`;
  const bad = done.find((x) => x.r.status === 'EXPOSED');
  if (bad) return { status: 'EXPOSED', release: release || bad.r.release, via: bad.r.via ?? bad.lib, nodeOwn: !bad.r.via, reason: said(bad) };
  if (unsure.length) return unsure[0];
  const unk = done.find((x) => x.r.status !== 'SAFE');
  if (unk) return { status: 'UNKNOWN', release: release || unk.r.release, via: unk.r.via ?? unk.lib, runtimeSign: true, reason: said(unk) };
  return safe([file, ...done.flatMap((x) => x.r.searched)], { release: release || done.map((x) => x.r.release).find(Boolean) || '', via: done.map((x) => x.r.via ?? x.lib).join(', '), reason: done.map(said).join('; ') });
}

/** One build of a file (the whole file, or one build of a universal Mach-O file) by the rules judgeFile gives. */
function judgeBuild(file, ev, opts) {
  const { follow = true } = opts;
  const { m0, c0, mk, ck, release, table, links, nodeLibs, dlopen, crowded } = ev;
  // Brotli 1.0's form (no prefix): judged only as a whole table in Brotli's order (form10Of)
  const old = form10Of(ev);
  // its own table first: EXPOSED or UNKNOWN by it decides; a table with the fix (`own`: either form, or both) is SAFE
  // only when what it links is SAFE too (below)
  let own = null;
  if (c0 > 0) {
    if (m0 === c0) {
      // a second decoder in the 1.0 form beside it: the 1.1 form's marker says nothing about that one
      if (old === 'odd') return { status: 'UNKNOWN', release, reason: OLD_BESIDE };
      if (old === 'unfixed') return { status: 'EXPOSED', release, reason: SOME_LACK, viaText: 'which holds a Brotli decoder that lacks the fix' };
      own = HAS_FIX;
    } else if (m0 === 0) return { status: 'EXPOSED', release, noMarker: true, reason: LACKS_FIX, viaText: 'whose Brotli decoder lacks the fix' };
    else if (m0 < c0) return { status: 'EXPOSED', release, reason: SOME_LACK, viaText: 'which holds a Brotli decoder that lacks the fix' };
    else return { status: 'UNKNOWN', release, reason: ODD };
  } else if (m0 > 0) return { status: 'UNKNOWN', release, reason: NO_CONTROL };
  // a whole 1.0-form table without the fix's name: EXPOSED, and like the 1.1 form's, a distribution's library is then
  // judged by its package version (noMarker: Debian 12's 1.0.9-2+b6 is EXPOSED by its table and its record alike; its
  // security build 1.0.9-2+deb12u1 adds the fix's name in its place, so its table makes it SAFE before any record)
  else if (old === 'unfixed') return { status: 'EXPOSED', release, noMarker: true, reason: LACKS_FIX_10, viaText: 'whose Brotli decoder lacks the fix' };
  else if (old === 'odd') return { status: 'UNKNOWN', release, runtimeSign: true, byHand: true, reason: OLD_FORM };
  else if (old === 'fixed') own = HAS_FIX_10;
  // then what it links, read from its link table: headers that can't be read, or a format that isn't Mach-O or ELF, leave
  // it unknown, and so do loader variables it sets itself (dyld honours LC_DYLD_ENVIRONMENT, DYLD_LIBRARY_PATH and the
  // like, which move any library it links)
  if (table.bad) return { status: 'UNKNOWN', release, reason: MALFORMED(table.format, table.bad) };
  if (!table.format) return { status: 'UNKNOWN', release, reason: UNRECOGNISED };
  if (table.env.length) return { status: 'UNKNOWN', release, reason: DYLD_ENV(table.env.map((v) => `'${shown(Buffer.from(v, 'utf8'))}'`).join(', ')) };
  const ownSafe = () => safe([file], { release, reason: own, viaText: 'whose Brotli decoder has the fix' });
  const none = { status: 'UNKNOWN', release, runtimeSign: Boolean(release || mk || ck), byHand: true, noTable: true, reason: NO_TABLE };
  // a name it may load while it runs (dlopen), or more such names than were kept: UNKNOWN, unless a library it links is
  // EXPOSED (that one loads whatever else does)
  const named = dlopen.length ? DLOPEN(dlopen[0]) : crowded ? CROWDED : '';
  const ownFirst = (r) => (own ? { ...r, reason: `its own Brotli decoder has the fix, but ${r.reason}` } : r);
  if (!follow) {
    // a library judged for a program that links it: its own links to a Brotli library or to libnode are past the one
    // level read
    const nested = links[0] ?? nodeLibs[0];
    if (named || nested) return ownFirst({ status: 'UNKNOWN', release, reason: named || NESTED(nested) });
    return own ? ownSafe() : none;
  }
  // every Brotli library and libnode it links is followed, one level, and must be SAFE; libnode holds Node.js's code (a
  // distribution's node, and Homebrew's, launch it) and is judged by these same rules, never followed to another libnode.
  // An EXPOSED part decides, whichever part it is; then a name it may load; then any other part that isn't SAFE
  const node = opts.nodeLib !== false;
  const parts = [...(links.length ? [judgeLinks(file, links, table, opts, release)] : []),
    ...(nodeLibs.length ? [node ? judgeNodeLibs(file, nodeLibs, table, opts, release) : { status: 'UNKNOWN', release, reason: NESTED(nodeLibs[0]) }] : [])];
  const bad = parts.find((r) => r.status === 'EXPOSED');
  if (bad) return ownFirst(bad);
  if (named) return ownFirst({ status: 'UNKNOWN', release, reason: named });
  const unk = parts.find((r) => r.status !== 'SAFE');
  if (unk) return ownFirst(unk);
  if (!parts.length) return own ? ownSafe() : none;
  return safe([...new Set([file, ...parts.flatMap((r) => r.searched)])], {
    release: release || parts.map((r) => r.release).find(Boolean) || '', via: [...new Set(parts.map((r) => r.via))].join(', '),
    reason: [own, parts.map((r) => r.reason).join('; ')].filter(Boolean).join('; and '), ...(own ? { viaText: 'whose Brotli decoder has the fix' } : {}),
  });
}

/**
 * One file → { status, reason, via?, release?, searched?, runtimeSign?, noMarker?, viaText?, byHand?, noTable? }. The
 * rules, for each build in the file (a universal Mach-O file holds several; the loader maps one, so each must be SAFE):
 *  1. a table is there (the control is found): the marker exactly as often as the control is SAFE, as long as any
 *     1.0-form names beside it are whole tables with the fix (an unfixed one is EXPOSED, anything else UNKNOWN) and
 *     what it links is SAFE (rule 2); the control without the marker is EXPOSED, and so is fewer markers than controls
 *     (one of two decoders lacks the fix); more markers than controls is UNKNOWN. The marker without the control is
 *     UNKNOWN: no table was shown to be there.
 *  1a. Brotli 1.0's form (form10Of), with no 1.1-form table: whole tables with the fix's name in its place are SAFE (and
 *     what it links must be SAFE too), a whole table without it EXPOSED, any other 1.0-form name UNKNOWN.
 *  2. what it links, read from its link table (linkTable): every Brotli library and libnode in it is followed one level
 *     to every copy the loader could take (resolveLink) and judged (judgeLinks, judgeNodeLibs), and each must be SAFE;
 *     an EXPOSED one makes the file EXPOSED. A table that can't be read, a file that contradicts itself, a file that is
 *     neither Mach-O nor ELF, LC_DYLD_ENVIRONMENT, a link that can't be followed, a copy the loader can't load into the
 *     build, and a Brotli library's or libnode's file name it holds outside its table (it may load it by that name while
 *     it runs: dlopenWant) are UNKNOWN, beside a table too.
 *  3. otherwise UNKNOWN: Node's constant names, a version, a file name never stand in for the table.
 * A file that can't be read, or a universal file whose header can't be read, is UNKNOWN. opts: markers, budget,
 * sonameDirs, sonameGaps, judgeLib, follow (false: a library a program links, whose own links are not followed),
 * nodeLib (false: libnode itself), caseless (names compared ignoring case; by default on macOS), opened (the path the
 * file was reached by, as written: its ELF $ORIGIN may be that folder; by default `file`), loader ({ file, opened,
 * table } of the program that loads it, when it was followed from one).
 */
export function judgeFile(file, opts = {}) {
  const { markers, budget, caseless = CASELESS } = opts;
  const ev = evidence(file, markers, budget, { caseless });
  if (ev?.overBudget) return { status: 'UNKNOWN', reason: OVER_BUDGET };
  if (!ev) return { status: 'UNKNOWN', reason: UNREAD };
  if (ev.badFat) return { status: 'UNKNOWN', reason: BAD_FAT };
  const parts = ev.slices.map((x) => judgeBuild(file, x, opts));
  if (parts.length === 1) return parts[0];
  const release = ev.release, n = parts.length;
  const bad = parts.find((x) => x.status === 'EXPOSED');
  if (bad) return parts.every((x) => x.status === 'EXPOSED') ? { ...bad, release, noMarker: parts.every((x) => x.noMarker) || undefined } : { ...bad, release, noMarker: undefined, reason: `${bad.reason} (in one of the ${n} builds this universal file holds)` };
  const unk = parts.find((x) => x.status !== 'SAFE');
  if (unk) {
    if (parts.every((x) => x.noTable)) return { ...unk, release, runtimeSign: parts.some((x) => x.runtimeSign) };
    return { status: 'UNKNOWN', release, via: unk.via, runtimeSign: true, reason: `in one of the ${n} builds this universal file holds, ${unk.reason}` };
  }
  return safe([...new Set(parts.flatMap((x) => x.searched))], { release, via: parts.map((x) => x.via).filter(Boolean).join(', ') || undefined, reason: [...new Set(parts.map((x) => x.reason))].join('; '), viaText: parts[0].viaText });
}

/** The node or bun programs to read: every copy on PATH, the one running Wardlatch (npx's), and the version managers'
 *  folders. Each once by its real path. Scripts (a version manager's shim) are not programs: returned in `scripts`.
 *  What can't be looked at is never dropped: something there that isn't a regular file goes into `odd`, and a file whose
 *  first bytes can't be read (mode 0111, refused) into `unread`, both with whether they were on PATH. */
export function runtimePrograms(name, patterns, { pathEnv = process.env.PATH ?? '', extra = [], denied } = {}) {
  const odd = [], files = [], scripts = [], unread = [], seen = new Set();
  const add = (p, onPath) => {
    const real = realPathAsWritten(p) ?? p;
    if (seen.has(real)) return;
    seen.add(real);
    const kind = programKind(p);
    if (kind === null) { unread.push({ file: p, onPath }); return; }
    if (kind !== 'native') { if (onPath) scripts.push(p); return; }
    files.push({ file: p, onPath });
  };
  const onPathOdd = [];
  for (const p of findAllOnPath(name, pathEnv, onPathOdd)) add(p, true);
  odd.push(...onPathOdd.map((file) => ({ file, onPath: true })));
  for (const p of [...extra, ...patterns.flatMap((pat) => expand(pat, denied))]) {
    const st = pathState(p);
    if (st === 'file') add(p, false);
    else if (st !== 'gone') odd.push({ file: p, onPath: false });
  }
  return { files, scripts, odd, unread };
}

/** A distribution's normalized name (PEP 503): lower case, runs of -, _ and . as one -. */
const norm = (s) => String(s).toLowerCase().replace(/[-_.]+/g, '-');

/** The first CSV field of each RECORD line (paths relative to site-packages; quotes as Python's csv module writes them).
 *  Lines are read one by one with indexOf; a line longer than 4 KB is not a path a wheel writes and is passed over. */
export function recordPaths(text) {
  const out = [];
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start); if (end < 0) end = text.length;
    const line = text.slice(start, end).replace(/\r$/, '');
    start = end + 1;
    if (!line || line.length > 4096) continue;
    if (line[0] !== '"') { out.push(line.slice(0, line.indexOf(',') < 0 ? line.length : line.indexOf(','))); continue; }
    let i = 1, s = '';
    while (i < line.length) {
      if (line[i] === '"') { if (line[i + 1] === '"') { s += '"'; i += 2; continue; } break; }
      s += line[i++];
    }
    out.push(s);
  }
  return out;
}

/** Name and version from a metadata file (a dist-info's METADATA, an egg-info's or an egg's PKG-INFO; its first 8 KB),
 *  falling back to the folder name (`<name>-<version>[-py3.12-...].dist-info|.egg-info|.egg`). */
function distName(dir, info, meta = join(info, 'METADATA')) {
  const head = readHead(join(dir, meta), 8192)?.toString('utf8') ?? '';
  let name = '', version = '';
  for (const l of head.split('\n').slice(0, 40)) {
    if (!name && l.startsWith('Name: ')) name = l.slice(6).trim().slice(0, 100);
    if (!version && l.startsWith('Version: ')) version = l.slice(9).trim().slice(0, 50);
  }
  const base = info.slice(0, info.lastIndexOf('.')), parts = base.split('-');
  return { name: name || parts[0], version: version || (parts[1] ?? '') };
}

const isDecoderFileName = (n) => n.startsWith('libbrotlidec.') || n.startsWith('libbrotlidec-');
const isBindingFileName = (n) => n.startsWith('_brotli.') || n.startsWith('_brotlicffi.');
// the package folders the Brotli bindings put their extension in: brotlicffi's brotlicffi/_brotlicffi.* and the older
// brotlipy's brotli/_brotli.* (pip's Brotli puts _brotli.* at the top, beside brotli.py)
const BINDING_DIRS = ['brotli', 'brotlicffi'];

/** The lines of a plain list (an egg-info's installed-files.txt), each up to 4 KB; longer ones are passed over. */
const listLines = (text) => text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l)).filter((l) => l && l.length <= 4096);

/**
 * The files in one site-packages folder that can hold a Brotli decoder, each with the distributions whose install record
 * lists it: libbrotlidec copies (delocate's <pkg>/.dylibs, auditwheel's <dist>.libs), the Brotli bindings' own extensions
 * (_brotli.* at the top, brotli/_brotli.*, brotlicffi/_brotlicffi.*), and Node.js runtimes bundled in a package (a
 * compiled program named node). Install records: a dist-info's RECORD, and an egg-info's installed-files.txt (pip's
 * record for a setup.py install). The places a copy lives are listed on disk too, so a copy no record lists (conda, a
 * distribution's package, which drops RECORD, a copy by hand) is still returned, with no owner; an .egg folder is listed
 * like site-packages, owned by its own PKG-INFO. A folder or a link to one counts as a folder (followed once, by its
 * name, never walked). A zipped .egg of a Brotli binding can't be looked inside: returned in `zipped`.
 * → { files: [{ file, owners: [{ name, version }] }], unread: [paths], zipped: [paths] } or null when the folder can't be
 *   listed.
 */
export function sitePackagesCandidates(dir) {
  const l = listDir(dir);
  if (!l.entries) return l.denied ? null : { files: [], unread: [], zipped: [] };
  const owners = new Map(), unread = [], zipped = [], picked = new Map();
  const within = (p) => p.startsWith(dir.endsWith(sep) ? dir : dir + sep);
  const pick = (p) => { if (!picked.has(p)) picked.set(p, true); };
  const own = (p, who) => owners.set(p, [...(owners.get(p) ?? []), who]);
  const isDir = (base, e) => e.isDirectory() || (e.isSymbolicLink() && pathState(join(base, e.name)) === 'dir');
  const listed = (p) => {
    const n = basename(p);
    if (isDecoderFileName(n) || isBindingFileName(n)) pick(p);
    // a bundled runtime that can't be read is picked too, and read as "could not be tested"
    else if (n === 'node' && programKind(p) !== 'other') pick(p);
  };
  for (const e of l.entries) {
    if (!isDir(dir, e)) continue;
    const isDist = e.name.endsWith('.dist-info'), isEgg = e.name.endsWith('.egg-info');
    if (!isDist && !isEgg) continue;
    const record = join(dir, e.name, isDist ? 'RECORD' : 'installed-files.txt');
    const buf = readCapped(record, MAX_RECORD);
    if (!buf) { if (pathState(record) !== 'gone') unread.push(record); continue; }
    const who = distName(dir, e.name, join(e.name, isDist ? 'METADATA' : 'PKG-INFO'));
    // RECORD's paths are relative to site-packages, installed-files.txt's to the egg-info folder
    for (const rel of isDist ? recordPaths(buf.toString('utf8')) : listLines(buf.toString('utf8'))) {
      const base = isDist ? dir : join(dir, e.name), text = resolve(base, rel);
      if (!within(text)) continue;   // console scripts (../../bin/x) are not what is looked for here
      // the file pip wrote and the package loads: a path with a '..' is the OS's, which takes it after the link before
      // it; resolve() cleans it up as text, which may be another file (installed-files.txt's ../ paths are the same)
      const written = rel.startsWith('/') ? rel : `${base}/${rel}`, real = hasDotDot(rel) ? realPathAsWritten(written) : null;
      const p = real !== null && real !== realPathAsWritten(text) ? written : text;
      own(p, who);
      listed(p);
    }
  }
  // the places a copy lives, listed on disk too: a copy that no record lists is still a copy
  const onDisk = (root, owner) => {
    const lr = root === dir ? l : listDir(root);
    if (lr.denied) { unread.push(root); return; }
    const found = (p) => { if (owner) own(p, owner); pick(p); };
    for (const e of lr.entries ?? []) {
      if (!isDir(root, e)) { if (isBindingFileName(e.name)) found(join(root, e.name)); continue; }
      const sub = join(root, e.name);
      const dirs = e.name.endsWith('.libs') ? [[sub, isDecoderFileName]] : [[join(sub, '.dylibs'), isDecoderFileName], [join(sub, '.libs'), isDecoderFileName]];
      if (BINDING_DIRS.includes(e.name)) dirs.push([sub, isBindingFileName]);
      for (const [d, want] of dirs) {
        const ld = listDir(d);
        if (ld.denied) { unread.push(d); continue; }
        for (const f of ld.entries ?? []) if (want(f.name)) found(join(d, f.name));
      }
    }
  };
  onDisk(dir, null);
  for (const e of l.entries) {
    if (!e.name.endsWith('.egg')) continue;
    if (isDir(dir, e)) onDisk(join(dir, e.name), distName(dir, e.name, join(e.name, 'EGG-INFO', 'PKG-INFO')));
    else if (/^brotli/i.test(e.name) && pathState(join(dir, e.name)) !== 'gone') zipped.push(join(dir, e.name));
  }
  // a picked file that a record lists but isn't on disk (a half-removed package) is nothing to judge
  return { files: [...picked.keys()].filter((p) => pathState(p) !== 'gone').map((file) => ({ file, owners: owners.get(file) ?? [] })), unread, zipped };
}

/** A key=value file's values (/etc/os-release): ID, VERSION_ID, VERSION_CODENAME; surrounding quotes removed. */
function osRelease(path) {
  const out = {};
  for (const l of (readCapped(path, 64 * 1024)?.toString('utf8') ?? '').split('\n')) {
    const i = l.indexOf('=');
    if (i <= 0) continue;
    let v = l.slice(i + 1).trim();
    if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === '\'' && v.endsWith('\'')))) v = v.slice(1, -1);
    out[l.slice(0, i)] = v;
  }
  return out;
}

/**
 * The folders the dynamic loader is configured to search besides the standard ones: every absolute path in
 * /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf (comments dropped), and in musl's /etc/ld-musl-<arch>.path files (`musl`:
 * paths split by lines and colons). A soname found in any of them is one more candidate that must be SAFE, so a folder
 * too many can't make a SAFE; only a folder missed could. So everything not read is a gap: a file that is there but
 * can't be read (or is over 64 KB), a conf.d that can't be listed or holds more than 256 .conf files, and an `include`
 * line naming anything but the conf.d folder read here (`include ld.so.conf.d/*.conf`, relative to the file, or its
 * absolute path): those are not followed (no copying ldconfig's language). A gap makes every bare soname UNKNOWN.
 * → { dirs: [folders], gaps: [what was not read] }
 */
export function ldSoConfDirs({ ldSoConf, ldSoConfDir, musl = [] } = {}) {
  const files = ldSoConf ? [ldSoConf] : [], gaps = [];
  if (ldSoConfDir) {
    const l = listDir(ldSoConfDir);
    if (l.denied) gaps.push(ldSoConfDir);
    const confs = (l.entries ?? []).filter((e) => e.name.endsWith('.conf'));
    if (confs.length > 256) gaps.push(`${ldSoConfDir} (more than 256 files)`);
    for (const e of confs.slice(0, 256)) files.push(join(ldSoConfDir, e.name));
  }
  const usual = ldSoConfDir ? join(ldSoConfDir, '*.conf') : null;
  const out = [];
  for (const f of [...files, ...musl]) {
    const buf = readCapped(f, 64 * 1024);
    if (!buf) { if (pathState(f) !== 'gone') gaps.push(f); continue; }
    const isMusl = musl.includes(f);
    for (const raw of buf.toString('utf8').split('\n')) {
      const hash = isMusl ? -1 : raw.indexOf('#');
      const line = (hash < 0 ? raw : raw.slice(0, hash)).trim();
      if (!isMusl && /^include\s/.test(line)) {
        // a target with a '..' is not compared as text (resolve() cleans it up, and ldconfig's glob takes it after the
        // link before it, which may be another folder): not followed, a gap
        const target = line.slice('include'.length).trim();
        if (hasDotDot(target) || resolve(dirname(f), target) !== usual) gaps.push(`${f}: include ${target}`);
        continue;
      }
      for (const w of line.split(/[\s,:]+/)) if (w.startsWith('/') && !w.includes('*') && !out.includes(w)) out.push(w);
    }
  }
  return { dirs: out, gaps };
}

/**
 * dpkg's records of one package, read as text from its status file (Debian, Ubuntu): every installed stanza of that name
 * (a Multi-Arch: same library can be installed for several architectures), each with its binary version as dpkg records
 * it and the source version it was built from. A rebuild (a binNMU, such as 1.1.0-2+b7) keeps its source's version in
 * `Source: brotli (1.1.0-2)`; without one, the source version is the binary version. No pattern runs on the whole file:
 * indexOf, then one anchored test per stanza. → [{ arch, version, source }], or null when the file can't be read.
 */
export function dpkgStanzas(statusFile, name) {
  const text = statusFile ? readCapped(statusFile, 128 * 1024 * 1024)?.toString('utf8') : null;
  if (text == null) return null;
  const out = [], head = `Package: ${name}\n`;
  for (let i = text.indexOf(head); i >= 0; i = text.indexOf(head, i + 1)) {
    if (i > 0 && text[i - 1] !== '\n') continue;
    const end = text.indexOf('\n\n', i), stanza = `${text.slice(i, end < 0 ? text.length : end)}\n`;
    const field = (k) => { const j = stanza.indexOf(`\n${k}: `); return j < 0 ? '' : stanza.slice(j + k.length + 3, stanza.indexOf('\n', j + 1)).trim(); };
    const version = field('Version');
    if (!version || !/^[a-z]+ [a-z-]+ installed$/.test(field('Status'))) continue;
    const src = field('Source'), open = src.indexOf(' (');
    out.push({ arch: field('Architecture'), version, source: open >= 0 && src.endsWith(')') ? src.slice(open + 2, -1).trim() : version });
  }
  return out;
}

/** A package's version from apk's installed file (Alpine), read as text, for the row's label: no Alpine release is in
 *  the incident's table. → { version } or null. */
function apkVersion(apkInstalled, apkName) {
  const apk = apkInstalled ? readCapped(apkInstalled, 64 * 1024 * 1024)?.toString('utf8') : null;
  if (!apk) return null;
  const at = apk.startsWith(`P:${apkName}\n`) ? 0 : apk.indexOf(`\nP:${apkName}\n`);
  if (at < 0) return null;
  const v = apk.indexOf('\nV:', at), end = apk.indexOf('\n\n', at + 1);
  if (v < 0 || (end >= 0 && v > end)) return null;
  return { version: apk.slice(v + 3, apk.indexOf('\n', v + 1) < 0 ? apk.length : apk.indexOf('\n', v + 1)).trim() };
}

/**
 * Whether dpkg installed this very file as part of a package (one stanza, one architecture): the package's md5sums list
 * (`<name>:<arch>.md5sums`, or `<name>.md5sums` for a package that isn't Multi-Arch: same, in places.dpkgInfo) names the
 * file's real path, or a merged-/usr spelling of it that leads to the same file, and the file's MD5 is the one dpkg
 * recorded. A library at a system place that no record names (a `make install` with prefix /usr, a vendor's copy, a file
 * changed since) says nothing about the package's version. → { list, path } when it matches; 'changed' when it is listed
 * with another checksum; null when no list names it (or none can be read).
 */
function dpkgInstalled(real, places, name, arch, budget) {
  if (!places.dpkgInfo) return null;
  const names = [real];
  for (const [a, b] of [['/usr/lib/', '/lib/'], ['/usr/lib64/', '/lib64/'], ['/lib/', '/usr/lib/'], ['/lib64/', '/usr/lib64/']]) {
    if (real.startsWith(a) && realPathAsWritten(b + real.slice(a.length)) === real) names.push(b + real.slice(a.length));
  }
  for (const list of [...(arch ? [join(places.dpkgInfo, `${name}:${arch}.md5sums`)] : []), join(places.dpkgInfo, `${name}.md5sums`)]) {
    const text = readCapped(list, 4 * 1024 * 1024)?.toString('utf8');
    if (!text) continue;
    for (const raw of text.split('\n')) {
      // "<32 hex digits>  <the path, without its leading />"
      const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
      if (line.length < 35 || line.slice(32, 34) !== '  ' || !names.includes(`/${line.slice(34)}`)) continue;
      // the file is read again to hash it: that counts against the run's reading budget too
      const size = sizeOf(real);
      if (budget && (size === null || size > budget.left)) return 'over';
      if (budget) budget.left -= size;
      return hashFile(real, 'md5', 64 * 1024 * 1024) === line.slice(0, 32).toLowerCase() ? { list, path: `/${line.slice(34)}` } : 'changed';
    }
  }
  return null;
}

/**
 * A system library that has the control but not the marker: the distribution may have fixed it another way (a backport
 * without the new error code), so its own package version decides, but only for a file that package installed, as it
 * installed it (dpkgInstalled), and compared by exact string with the incident's table (never by dpkg's ordering
 * rules): `fixed` lists binary versions as dpkg records them (Debian's security builds), and `vulnerableSources` lists
 * source versions, so every rebuild of an unfixed source (1.1.0-2+b7 is built from 1.1.0-2) is matched. A file no
 * package record names, a package version Wardlatch can't read (rpm, pacman), Alpine's (not in the table), or one not in
 * the table is UNKNOWN; only a package built from a source the table lists as without the fix is EXPOSED.
 */
export function distroVerdict(file, table, places, budget) {
  const real = realPathAsWritten(file) ?? file;
  const stanzas = dpkgStanzas(places.dpkgStatus, table.dpkgName) ?? [];
  let deb = null, changed = false;
  for (const st of stanzas) {
    const m = dpkgInstalled(real, places, table.dpkgName, st.arch, budget);
    if (m === 'over') return { status: 'UNKNOWN', reason: OVER_BUDGET };
    if (m === 'changed') changed = true;
    else if (m) { deb = { ...st, ...m }; break; }
  }
  if (stanzas.length && !deb) {
    return { status: 'UNKNOWN', reason: changed
      ? `the error text the fix added isn't in it, and it is not the file ${table.dpkgName} installed (its checksum isn't the one dpkg recorded, or it could not be read to compare), so the package's version says nothing about it, and whether it has the fix could not be tested`
      : `the error text the fix added isn't in it, and dpkg's records don't list it as a file of ${table.dpkgName} (it may have been built or copied there by hand), so the package's version says nothing about it, and whether it has the fix could not be tested` };
  }
  const apk = deb ? null : apkVersion(places.apkInstalled, table.apkName);
  if (!deb && !apk) return { status: 'UNKNOWN', reason: 'the error text the fix added isn\'t in it, but your distribution may have fixed it another way, and Wardlatch can\'t read its package version here, so whether it has the fix could not be tested: check your distribution\'s security page for CVE-2026-111497' };
  const label = deb ? `${table.dpkgName} ${deb.version}` : `${table.apkName} ${apk.version}`;
  const os = osRelease(places.osRelease);
  const entry = deb && [`${os.ID}:${os.VERSION_ID}`, `${os.ID}:${os.VERSION_CODENAME}`].map((k) => table.releases?.[k]).find(Boolean);
  if (entry?.fixed?.includes(deb.version)) {
    const said = `${entry.name}'s fixed package ${label} (${entry.source})`;
    return safe([file, `${places.dpkgStatus}: ${label}`, `${deb.list}: ${deb.path}, with the same MD5`], { label, reason: `the error text the fix added isn't in it, but it is ${said}`, viaText: `which is ${said}` });
  }
  if (entry?.vulnerableSources?.includes(deb.source)) {
    const without = `${entry.name}'s package without it (built from brotli ${deb.source}; ${entry.source})`;
    return { status: 'EXPOSED', label, fix: entry.fix, reason: `its Brotli decoder lacks the fix, and ${label} is ${without}`, viaText: `whose Brotli decoder lacks the fix (${label}, ${without})` };
  }
  return { status: 'UNKNOWN', label, reason: `the error text the fix added isn't in it, but your distribution may have fixed it another way (${label} is not in Wardlatch's table), so whether it has the fix could not be tested: check your distribution's security page for CVE-2026-111497` };
}

/** The conda environment a file is in, by its path: the folder after /envs/, or base. */
const condaEnv = (file) => { const parts = file.split('/'), i = parts.lastIndexOf('envs'); return i >= 0 && parts[i + 1] ? parts[i + 1] : 'base'; };

/**
 * Every finding for a `bundled` incident. inc: the incident data. opts: pathEnv, execPath, siteDirs (from
 * lib/installs.mjs sitePackagesDirs), denied (folders that couldn't be opened, for bin/wardlatch.mjs gaps()), places
 * (osRelease, dpkgStatus, dpkgInfo, apkInstalled, ldSoConf, ldSoConfDir, ldMuslPath: a pattern), sonameDirs (patterns; the incident's by default),
 * budgetBytes (what this run may read; 4 GB), env (the variables that move a version manager's folders), caseless (file
 * names compared ignoring case; by default on macOS).
 * → { rows: [{ what, file, status, reason, fix?, searched?, version?, owner?, label?, via?, dir?, paths? }], looked: [what
 *   was looked at, for the receipt] }
 */
export function checkBundled(inc, { pathEnv = process.env.PATH ?? '', execPath, siteDirs = [], denied = [], places = {}, sonameDirs, budgetBytes = BUDGET, env = process.env, caseless = CASELESS } = {}) {
  const markers = inc.markers, budget = { left: budgetBytes };
  // rows and receipts by kind, printed in this order (programs, Python packages, libraries), but read the other way
  // round: the small library and package files first, the large programs (60 to 300 MB each) last, so many version
  // managers' nodes can't use up the reading budget before a single package or library is read
  const rows = { runtimes: [], python: [], libraries: [] }, looked = { runtimes: [], python: [], libraries: [] };
  const fill = (text, vars = {}) => Object.entries(vars).reduce((t, [k, v]) => t.replaceAll(`{${k}}`, v), text ?? '');
  const fixFor = (key, vars) => fill(inc.fixes[key], vars);
  // the library folders a bare soname is looked for in; a folder that is there but can't be entered stays in the list
  // (its soname reads "can't follow"), and a folder or loader file that couldn't be read is a gap: every bare soname is
  // then UNKNOWN, since the loader may take its copy from there
  const ld = ldSoConfDirs({ ...places, musl: places.ldMuslPath ? expand(places.ldMuslPath, []) : [] });
  const unlisted = [];
  const libDirs = [...new Set([...(sonameDirs ?? inc.sonameDirs ?? []), ...ld.dirs].flatMap((p) => (p.includes('*') ? expand(p, unlisted) : [p])))].filter((d) => pathState(d) !== 'gone');
  const sonameGaps = [...ld.gaps, ...unlisted];
  // the library places, by real path: a program that links one of them is judged as that library's own row is (a
  // distribution's package version included), and told that library's fix
  const placeOf = new Map();
  for (const place of inc.libPlaces ?? []) {
    for (const f of expand(place.pattern, denied)) if (pathState(f) === 'file') { const real = realPathAsWritten(f) ?? f; if (!placeOf.has(real)) placeOf.set(real, place); }
  }
  const verdicts = new Map();
  const judgeLib = (lib) => {
    const real = realPathAsWritten(lib) ?? lib;
    if (!verdicts.has(real)) {
      // judged (and named in a receipt) by its real path, once, whichever program or place reached it first
      let r = judgeFile(real, { markers, budget, caseless, follow: false });
      if (placeOf.get(real)?.system && r.noMarker && inc.distro) r = distroVerdict(real, inc.distro, places, budget);
      verdicts.set(real, r);
    }
    return verdicts.get(real);
  };
  const libFix = (lib) => {
    const real = realPathAsWritten(lib) ?? lib, place = placeOf.get(real);
    if (!place) return fixFor('library-other', { lib });
    if (place.system) return verdicts.get(real)?.fix ?? fixFor('system-other');
    return fixFor(place.fix, { env: condaEnv(real) });
  };
  const linkedFix = (what, lib) => fixFor('linked', { what, lib, libfix: libFix(lib) });
  // a Node.js runtime's fix, by its line: a line with no fix (Node.js 20 and older, the odd-numbered lines) is told to
  // move; the version picks the words only
  const nodeFix = (version) => {
    const major = Number(version.split('.')[0]), lines = (inc.nodeFixed ?? []).map((v) => Number(v.split('.')[0]));
    const line = (inc.nodeFixed ?? []).find((v) => Number(v.split('.')[0]) === major);
    const eol = major > 0 && !line && major < Math.max(...lines);
    return line ? fixFor('node-line', { fixed: line, major: String(major) }) : eol ? fixFor('node-eol', { major: String(major) }) : fixFor('node');
  };
  // a row as printed and in --json: the judge's working fields (viaText, noMarker, runtimeSign) stay out
  const row = (base, r, { reason = r.reason, fix } = {}) => ({
    ...base, status: r.status, reason, ...(r.via ? { via: r.via } : {}), ...(r.label && !base.label ? { label: r.label } : {}),
    ...(r.status === 'EXPOSED' && fix ? { fix } : {}), ...(r.status === 'SAFE' ? { searched: r.searched } : {}),
  });

  const seenLibs = new Set();
  for (const place of inc.libPlaces ?? []) {
    looked.libraries.push(place.pattern);
    for (const p of expand(place.pattern, denied)) {
      if (pathState(p) !== 'file') continue;
      const file = realPathAsWritten(p) ?? p;
      if (seenLibs.has(file)) continue;
      seenLibs.add(file);
      const r = judgeLib(file);
      rows.libraries.push(row({ what: 'library', label: r.label ?? place.label, file }, r, { fix: libFix(file) }));
    }
  }

  for (const dir of siteDirs) {
    const c = sitePackagesCandidates(dir);
    if (!c) { denied.push(dir); continue; }
    looked.python.push(dir);
    for (const u of c.unread) rows.python.push({ what: 'python', file: u, dir, status: 'UNKNOWN', reason: 'could not be read, so the copies of Brotli it lists could not be tested' });
    for (const z of c.zipped) rows.python.push({ what: 'python', file: z, dir, status: 'UNKNOWN', reason: 'a zipped egg of a Brotli package: Wardlatch doesn\'t look inside zip files, so the copy of Brotli in it could not be tested. Check its version by hand (Brotli 1.2.1 and brotlicffi 1.2.1.0 and later are fixed)' });
    for (const { file, owners } of c.files) {
      const r = judgeFile(file, { markers, sonameDirs: libDirs, sonameGaps, judgeLib, budget, caseless });
      const names = [...new Set(owners.map((o) => o.name))].join(' and ');
      const owner = owners.map((o) => `${o.name} ${o.version}`).join(', ');
      const isNode = basename(file) === 'node';
      const known = owners.map((o) => inc.dists?.[norm(o.name)]).find(Boolean);
      const ownFix = isNode ? fixFor('pip-node', { names: names || 'the package' }) : known ? fill(known.fix, { names }) : names ? fixFor('pip-bundled', { names }) : fixFor('pip-unowned');
      // a copy decided by a library outside the package (a system or Homebrew library) is fixed by updating that library;
      // a libnode's own decoder (nodeOwn) by updating the Node.js it belongs to
      const fix = r.via && !r.via.startsWith(dir + sep) ? fixFor('linked', { what: 'the package', lib: r.via, libfix: r.nodeOwn ? nodeFix(r.release ?? '') : libFix(r.via) }) : ownFix;
      const hint = isNode ? inc.hints.node : isBindingFileName(basename(file)) ? inc.hints.binding : inc.hints.file;
      rows.python.push(row({ what: 'python', file, dir, owner, ...(owner ? {} : { label: 'a copy no package lists' }) }, r, { fix, reason: r.byHand ? `${r.reason}. ${fill(hint, { names: names || 'the package that installed it' })}` : r.reason }));
    }
  }

  // the version managers' nodes: the incident's places, those the managers' variables name, and those beside a shim of
  // theirs on PATH (its folder's parent is its home); a shim's row says whether its folders of runtimes were read
  const shims = inc.shims ?? {}, layouts = Object.entries(shims).map(([k, l]) => [k, l, shimPlaces(l, env)]);
  const shimAt = new Map();
  for (const p of findAllOnPath('node', pathEnv)) {
    const kind = shimKind(p, layouts, budget);
    if (kind) shimAt.set(p, { kind, places: shimPlugins(shimPlaces(shims[kind], env, p), shims[kind], p) });
  }
  const tilde = (p) => (p.startsWith('~/') ? join(homedir(), p.slice(2)) : p), known = new Set((inc.nodeDirs ?? []).map(tilde));
  const managed = [...layouts.map((x) => x[2]), ...[...shimAt.values()].map((s) => s.places)].flatMap((x) => x.patterns);
  const nodeDirs = [...(inc.nodeDirs ?? []), ...new Set(managed.filter((p) => !known.has(p)))];

  for (const [name, patterns] of [['node', nodeDirs], ['bun', inc.bunDirs ?? []]]) {
    const progs = runtimePrograms(name, patterns, { pathEnv, extra: name === 'node' && execPath ? [execPath] : [], denied });
    looked.runtimes.push(`${name} on PATH: ${pathEnv}`, ...patterns.map((p) => `${name} in ${p}`));
    for (const { file, onPath } of progs.files) {
      const r = judgeFile(file, { markers, sonameDirs: libDirs, sonameGaps, judgeLib, budget, caseless });
      // a program on PATH named node with no sign of being Node.js (no table, no link, no release, none of its constant
      // names) that is a version manager's compiled shim: a REVIEW row when its runtimes are read in their own folders,
      // UNKNOWN when they could not be (shimRow). Any other is UNKNOWN (below). Bun gets no such row: a bun that shows
      // nothing is UNKNOWN.
      if (name === 'node' && onPath && r.noTable && !r.runtimeSign && shimAt.has(file)) {
        // (its places were read above, by its place on PATH)
        rows.runtimes.push(shimRow(file, shimAt.get(file).kind, shimAt.get(file).places, inc.hints.node));
        continue;
      }
      // a library it links is fixed by updating that library, except libnode's own decoder (nodeOwn): libnode is
      // Node.js's own library, so that node is told Node.js's fix
      const version = name === 'node' ? r.release ?? '' : '';
      const fix = r.via && !r.nodeOwn ? linkedFix(name === 'node' ? 'Node.js' : 'Bun', r.via) : name === 'bun' ? fixFor('bun') : nodeFix(version);
      rows.runtimes.push(row({ what: name, file, version }, r, { fix, reason: r.byHand ? `${r.reason}. ${inc.hints[name]}` : r.reason }));
    }
    for (const { file, onPath } of progs.odd) rows.runtimes.push({ what: name, file, status: 'UNKNOWN', reason: `${onPath ? 'something of this name is on PATH, but it' : 'it'} is not a regular file (or could not be looked at), so it was not read and could not be tested` });
    for (const { file } of progs.unread) rows.runtimes.push({ what: name, file, status: 'UNKNOWN', reason: `${UNREAD}. ${inc.hints[name]}` });
    // a script named node or bun on PATH is not a program: asdf's or nodenv's shim (shimKind) is a REVIEW line only when
    // the nodes it starts are read (shimRow); any other script (npm's node wrapper, a bun shim) starts a runtime whose
    // place Wardlatch doesn't know, so it is UNKNOWN, never a line that lets the run end in exit 0
    for (const file of progs.scripts) {
      const s = name === 'node' ? shimAt.get(file) : undefined;
      rows.runtimes.push(s ? shimRow(file, s.kind, s.places, inc.hints.node) : { what: name, file, status: 'UNKNOWN', reason: `a script named ${name} on PATH, not a program, and not a version manager's shim Wardlatch knows (asdf's or nodenv's, in its shims folder), so the runtime it starts was not read, and whether it has the fix could not be tested. ${inc.hints[name]}` });
    }
  }

  return { rows: [...rows.runtimes, ...rows.python, ...rows.libraries], looked: [...looked.runtimes, ...looked.python, ...looked.libraries] };
}
