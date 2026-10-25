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
// it aligns), either way round (decode.h's order, as clang lays them out, or by code), and right after the run either
// the fix's name and then after10 (1.0.10) or after10 at once (1.0.4 to 1.0.9). Anything else in that form (a name
// outside such a run, a run followed by neither, the fix's name anywhere but in its place) is UNKNOWN.
import { join, dirname, basename, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import { scanBytes, listDir, pathState, realPath, readCapped, readHead, readAt, programKind, hashFile, sizeOf } from './files.mjs';
import { findAllOnPath } from './binaries.mjs';
import { expand } from './installs.mjs';
import { safe } from './report.mjs';

const MAX_PROGRAM = 512 * 1024 * 1024;        // a node binary is 60 to 300 MB; a larger file is not read (UNKNOWN)
const BUDGET = 4 * 1024 * 1024 * 1024;        // what one run reads for this check; past it, each file left is UNKNOWN
const MAX_RECORD = 4 * 1024 * 1024;
const LINK = Buffer.from('libbrotlidec');
const NODE_LIB = Buffer.from('libnode');
const RELEASE = Buffer.from('nodejs.org/download/release/v');
const nul = (s) => Buffer.from(`\0${s}\0`);

// The reasons a row gives. Every one that is not a verdict says "could not be tested".
const HAS_FIX = 'its Brotli decoder has the fix: the error text the fix added is in it, beside the error texts every Brotli decoder has';
const LACKS_FIX = 'its Brotli decoder lacks the fix: it has the error texts every Brotli decoder has, but not the one the fix added';
const SOME_LACK = 'it holds more than one Brotli decoder, and at least one of them lacks the fix';
const ODD = 'the error text the fix added is in it more often than the error texts every Brotli decoder has, which no real build shows, so whether it has the fix could not be tested';
const NO_CONTROL = 'the error text the fix added is in it, but not the error texts every Brotli decoder has, so whether its decoder has the fix could not be tested';
export const NO_TABLE = 'no Brotli decoder\'s error texts are in this file and it links no Brotli library, so whether it has the fix could not be tested';
const CROWDED = 'it names libbrotlidec more often than Wardlatch keeps track of (64 times), so the libraries it links could not all be followed, and whether it has the fix could not be tested';
const CUT = 'it names a Brotli library in a string that could not be read whole (it doesn\'t start and end as a load command\'s path does, or starts more than 1024 bytes before the library\'s name), so the library it links could not be followed, and whether it has the fix could not be tested';
const UNREAD = 'could not be read (it is not a regular file, reading it was refused, or it is larger than 512 MB), so it could not be tested';
const OVER_BUDGET = 'not read, because this run had already read 4 GB of files for this check, so it could not be tested';
const HAS_FIX_10 = 'its Brotli decoder has the fix: its error texts, in the form Brotli 1.0 writes them, are all there in Brotli\'s order, with the one the fix added in its place';
const LACKS_FIX_10 = 'its Brotli decoder lacks the fix: its error texts, in the form Brotli 1.0 writes them, are all there in Brotli\'s order, without the one the fix added';
const OLD_BESIDE = 'it holds a decoder with the fix, and also error texts in the form Brotli 1.0 writes them, but not as a whole table in Brotli\'s order, so a second, older decoder may be in it: whether it has the fix could not be tested';
const OLD_FORM = 'it holds error texts in the form Brotli 1.0 writes them, but not as a whole table in Brotli\'s order (scattered, out of order, only some of them, or the text the fix added away from its place), so whether it has the fix could not be tested';
const BAD_FAT = 'it is a universal (fat) Mach-O file whose list of builds could not be read, or names builds that overlap or run past the end of the file, so it could not be tested';
const NODE_LIB_UNSURE = 'it names libnode, the library that holds Node.js\'s code, in a string that could not be read whole, or more often than Wardlatch keeps track of, so the library it links could not be followed, and whether it has the fix could not be tested';

/**
 * Where a version manager keeps the nodes its compiled shim starts, from the incident's `shims` (each manager's layouts,
 * read in its own source): its homes (`homes`: `$VAR` or `$VAR/rest`, `~/rest`, or an absolute path) with the `nodes`
 * patterns under each, its installs folders (`installs`) with `installsNodes` under each, and, when the shim on PATH
 * (`onPath`) sits in a folder named `folder` (volta's bin, the others' shims), the folder above that as a home too. A
 * variable that isn't set is no place; one may hold a list (split on ':'); one set to a path that doesn't start at '/'
 * is `unsure` (where the manager looks then depends on the folder it is started in). No pattern runs on a value.
 * → { patterns, folders: each pattern's folder of runtimes (the part before its first `*`), unsure: [variable names] }
 */
export function shimPlaces(layout, env = {}, onPath) {
  const patterns = [], unsure = [];
  const roots = (tpl) => {
    if (tpl.startsWith('~/')) return [join(homedir(), tpl.slice(2))];
    if (!tpl.startsWith('$')) return [tpl];
    const slash = tpl.indexOf('/'), name = tpl.slice(1, slash < 0 ? tpl.length : slash), rest = slash < 0 ? '' : tpl.slice(slash + 1);
    const values = String(env[name] ?? '').split(':').filter(Boolean);
    if (values.some((v) => !v.startsWith('/'))) unsure.push(name);
    return values.filter((v) => v.startsWith('/')).map((v) => join(v, rest));
  };
  const homes = layout.homes.flatMap(roots);
  if (onPath && basename(dirname(onPath)) === layout.folder) homes.unshift(dirname(dirname(onPath)));
  const add = (root, rel) => { const p = join(root, rel); if (!patterns.includes(p)) patterns.push(p); };
  for (const h of homes) for (const n of layout.nodes) add(h, n);
  for (const r of (layout.installs ?? []).flatMap(roots)) for (const n of layout.installsNodes ?? []) add(r, n);
  return { patterns, folders: [...new Set(patterns.map((p) => p.slice(0, p.lastIndexOf('/', p.indexOf('*')))))], unsure: [...new Set(unsure)] };
}

/**
 * The row for a version manager's compiled shim on PATH (a `node` that is a link to volta-shim, mise, rtx or
 * proto-shim, with no sign of Node.js). REVIEW, not judged, only when the nodes it starts are read: at least one of its
 * folders of runtimes (shimPlaces) is there and was listed, every one that is there could be listed, and no variable
 * names one by a relative path. Otherwise UNKNOWN, so an unread node never ends the run in exit 0.
 */
function shimRow(file, kind, { folders, unsure }, hint) {
  const state = (f) => { const st = pathState(f); return st === 'dir' ? (listDir(f).entries ? 'read' : 'closed') : st === 'denied' ? 'closed' : 'gone'; };
  const closed = folders.filter((f) => state(f) === 'closed'), read = folders.filter((f) => state(f) === 'read');
  const list = (xs) => `${xs.slice(0, 4).join(', ')}${xs.length > 4 ? `, and ${xs.length - 4} more` : ''}`;
  const head = `${kind}, a version manager's shim, not a Node.js runtime`;
  const unknown = (why) => ({ what: 'node', file, status: 'UNKNOWN', reason: `${head}: ${why}, so the nodes it starts were not read, and whether they have the fix could not be tested. ${hint}` });
  if (unsure.length) return unknown(`${unsure.join(' and ')} ${unsure.length === 1 ? 'names' : 'name'} its folders by a path that doesn't start at '/', which leads elsewhere from each folder it is started in`);
  if (closed.length) return unknown(`its folder of runtimes ${list(closed)} could not be read`);
  if (!read.length) return unknown(`its folder of runtimes was not found (looked in ${list(folders)})`);
  return { what: 'node', file, status: 'REVIEW', reason: `${head}, so it was not judged: the runtimes it starts are read in ${list(read)}` };
}

/** A printable ASCII run of bytes around position `at` of `buf` (a version after a URL; the tail of a path). */
function printableAround(buf, at, { backward = true } = {}) {
  const ok = (b) => b >= 0x20 && b <= 0x7e;
  let s = at, e = at;
  if (backward) while (s > 0 && ok(buf[s - 1])) s--;
  while (e < buf.length && ok(buf[e])) e++;
  return buf.subarray(s, e).toString('latin1');
}

/**
 * The C string around position `at` of `buf` (a path in a load command), walked back and forward over printable ASCII
 * and the bytes of UTF-8 text (a folder named José), within the bytes kept around the hit. `whole`: it starts right
 * after a NUL and ends at one, and its bytes are valid UTF-8, so it is the string the loader reads. Without that, the
 * walk may have cut a longer path to a suffix (an ASCII-only walk did, at the é), which names another file. `edge`: the
 * walk reached the start or the end of the bytes kept, so the string may go on past them (a path longer than the bytes
 * kept before the hit), and `text` is only a part of it. `name`: the part from the hit on (the library's file name, when
 * the string names one).
 */
function cStringAround(buf, at) {
  const ok = (b) => (b >= 0x20 && b <= 0x7e) || b >= 0x80;
  let s = at, e = at;
  while (s > 0 && ok(buf[s - 1])) s--;
  while (e < buf.length && ok(buf[e])) e++;
  const bytes = buf.subarray(s, e), text = bytes.toString('utf8');
  return { text, name: buf.subarray(at, e).toString('utf8'), edge: s === 0 || e === buf.length, whole: s > 0 && buf[s - 1] === 0 && e < buf.length && buf[e] === 0 && Buffer.from(text, 'utf8').equals(bytes) };
}

/** Whether a hit of a library's name whose C string is not a link `isName` accepts still names such a library, so the
 *  file can't be SAFE: the name from the hit on is such a library's file name in a string that isn't whole, whatever
 *  ended the walk (a tab, a newline, DEL or another control byte in the path, bytes that aren't UTF-8, the end of the
 *  bytes kept); or the string, its ASCII tail or the part of it seen (partialLink) is such a name. */
function unsureName(c, h, isName) {
  return (!c.whole && isName(c.name)) || isName(c.text) || isName(printableAround(h.buf, h.at)) || partialLink(c, isName);
}

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
 * `after` at once), or null (anything else). Matched either way round: in decode.h's order (the later names after it), or
 * reversed, by code (the later names before it).
 */
function table10At(buf, at, len, { run, anchor, fixed, after }) {
  const a = run.indexOf(anchor), earlier = run.slice(0, a).reverse(), later = run.slice(a + 1);
  // no run, or one without the control's name: no 1.0 table can be shown (an empty run would match anything)
  if (a < 0) return null;
  const same = (got, want) => want.every((x, i) => got[i] === x);
  const read = (dir, n) => namesFrom(buf, dir > 0 ? at + len - 1 : at, dir, n);
  for (const dir of [1, -1]) {
    if (!same(read(-dir, earlier.length), earlier)) continue;
    const got = read(dir, later.length + 2);
    if (!same(got, later)) continue;
    if (got[later.length] === fixed && got[later.length + 1] === after) return 'fixed';
    if (got[later.length] === after) return 'unfixed';
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

/** Whether a C string seen only in part (cStringAround's `edge`) may be a path to a library `isName` accepts: what is
 *  seen of it ends in such a name after a '/'. Its start was never seen, so it can't be followed, and the file can't be
 *  SAFE. A part with no '/' can't be: a library's name is at most 128 bytes, and more than that is seen before the hit. */
function partialLink(c, isName) {
  const slash = c.text.lastIndexOf('/');
  return c.edge && slash >= 0 && isName(c.text.slice(slash));
}

/** Whether a string from a binary names a Brotli decoder library: a path or soname whose last part is libbrotlidec.dylib,
 *  libbrotlidec.<n>.dylib, libbrotlidec.so or libbrotlidec.so.<n>[.<n>...]. No pattern runs on it: a loop. */
export function isDecoderLibName(s) {
  // a load command holds an absolute path, an @loader_path/@executable_path/@rpath one, a $ORIGIN one (ELF), or (ELF) a
  // bare soname; a relative path is relativeLib's; anything else is text that happens to mention the name, and is never
  // printed as a link
  if (!(s.startsWith('/') || s.startsWith('@') || s.startsWith('$') || !s.includes('/'))) return false;
  const name = s.slice(s.lastIndexOf('/') + 1);
  if (!name.startsWith('libbrotlidec') || name.length > 128) return false;
  if (name.endsWith('.dylib')) return true;
  const so = name.indexOf('.so');
  if (so < 0) return false;
  for (const part of name.slice(so + 3).split('.').slice(1)) if (!part || [...part].some((c) => c < '0' || c > '9')) return false;
  return name.slice(so + 3) === '' || name.slice(so + 3).startsWith('.');
}

/** Whether a whole C string is a relative path to a library `isName` accepts: it has a '/', starts with none of '/', '@'
 *  and '$', and its last part is such a library's name ("lib/libbrotlidec.1.dylib", "../lib/libbrotlidec.so.1"). dyld
 *  and ld.so look for it from the folder the program is started in, which Wardlatch can't know. */
const relativeLib = (s, isName) => s.includes('/') && !['/', '@', '$'].includes(s[0]) && isName(s.slice(s.lastIndexOf('/') + 1));
const isRelative = (ref) => ref.includes('/') && !['/', '@', '$'].includes(ref[0]);
const RELATIVE = (ref, what = '') => `it links ${ref}${what}, a relative path, which the loader looks for from the folder the program is started in, so which file it loads, and whether that has the fix, could not be tested`;

/** Whether a string from a binary names the library that holds Node.js's code (a distribution's node is a launcher for
 *  it): libnode.so, libnode.so.<n>[...], libnode.dylib or libnode.<n>.dylib, as a path or a soname. A loop, as above. */
export function isNodeLibName(s) {
  if (!(s.startsWith('/') || s.startsWith('@') || s.startsWith('$') || !s.includes('/'))) return false;
  const name = s.slice(s.lastIndexOf('/') + 1);
  if (!name.startsWith('libnode.') || name.length > 64) return false;
  const rest = name.slice('libnode.'.length).split('.');
  const digits = (x) => x.length > 0 && [...x].every((c) => c >= '0' && c <= '9');
  if (rest[rest.length - 1] === 'dylib') return rest.slice(0, -1).every(digits);
  return rest[0] === 'so' && rest.slice(1).every(digits);
}

/**
 * The builds a universal (fat) Mach-O file holds, by their place in it, from its header (bounded: at most 64 builds,
 * each inside the file, none overlapping another, so together they are never more than the file). The loader maps one
 * build; strings elsewhere in the file are none of them. → null when the file isn't a universal one,
 * { slices: [{ start, length }] }, or { bad: true } when its header can't be read sensibly (builds that overlap
 * included: read build by build, they would read the same bytes again, past the run's reading budget).
 */
export function fatSlices(file, size) {
  const h = readHead(file, 8);
  if (!h || h.length < 8) return null;
  const magic = h.readUInt32BE(0);
  if (![0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].includes(magic)) return null;
  const le = magic === 0xbebafeca || magic === 0xbfbafeca, is64 = magic === 0xcafebabf || magic === 0xbfbafeca;
  const n = le ? h.readUInt32LE(4) : h.readUInt32BE(4), ent = is64 ? 32 : 20;
  if (n < 1 || n > 64) return { bad: true };
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

/**
 * What a file holds, for each build in it (one, or each build of a universal Mach-O file): counts of the marker and
 * control (exact, NUL-delimited), of the same two error texts in the form Brotli 1.0 writes them (no prefix: before
 * 1.1.0 BrotliDecoderErrorString returns the bare name) and, in `t10`, how many copies of that control are in a whole
 * 1.0 table with the fix, without it, or neither (table10At), of Node's constant names (only to tell a Node.js program
 * from a version manager's shim, never as evidence of a fix), the Brotli decoder libraries it links (load-command strings;
 * `crowded` when there were more mentions of libbrotlidec than are kept, `cut` when a name was seen only inside a string
 * that isn't whole, so some could be missing), and a Node release version if it embeds one (for wording only).
 * budget: { left } bytes this run may still read; each build's bytes are taken off it before they are read. → null when
 * the file can't be read; { overBudget: true } when what is left of the budget is less than the file's size (or than a
 * build's); { badFat: true } for a universal file whose header can't be read, or whose builds overlap. The whole file's
 * counts are at the top (sums), each build's in `slices`.
 */
export function evidence(file, markers, budget) {
  if (budget && budget.left <= 0) return { overBudget: true };
  const size = sizeOf(file);
  if (size === null || size > MAX_PROGRAM) return null;
  // the budget is checked against the file's size before it is read, and each build is charged to it before it is read:
  // the builds don't overlap (fatSlices), so together they are at most that size, and a run reads at most its budget (a
  // file that grows meanwhile is read up to the size it had)
  if (budget && size > budget.left) return { overBudget: true };
  const fat = fatSlices(file, size);
  if (fat?.bad) return { badFat: true };
  const old = (k) => markers[k].slice(markers[k].indexOf('_ERROR_FORMAT_') === 0 ? '_ERROR_FORMAT_'.length : 0);
  const anchor10 = nul(old('table'));
  const form10 = { run: markers.table10 ?? [], anchor: old('table'), fixed: old('fixed'), after: markers.after10 };
  const slices = [];
  let charged = 0;
  for (const { start, length } of fat?.slices ?? [{ start: 0, length: size }]) {
    charged += length;
    if (charged > size) return { badFat: true };
    if (budget) { if (length > budget.left) return { overBudget: true }; budget.left -= length; }
    const r = scanBytes(file, {
      count: [nul(markers.fixed), nul(markers.table), Buffer.from(markers.nodeConstant + markers.fixed), Buffer.from(markers.nodeConstant + markers.table), LINK, nul(old('fixed')), anchor10, NODE_LIB],
      around: [LINK, RELEASE, NODE_LIB, anchor10], back: 1024, fwd: 256, maxHits: 64, maxBytes: MAX_PROGRAM, start, length,
    });
    if (!r) return null;
    const [m0, c0, mk, ck, named, um0, uc0, nodeNamed] = r.counts;
    // Brotli 1.0's form: each copy of the control's name kept is read as a table or not; copies past the ones kept count
    // as not (`other`)
    const t10 = { fixed: 0, unfixed: 0, other: uc0 - r.hits[3].length };
    for (const h of r.hits[3]) t10[table10At(h.buf, h.at, anchor10.length, form10) ?? 'other']++;
    // a link is followed only when its whole C string is a decoder library's name; a name seen only as part of a string
    // that isn't whole (`cut`) could be the tail of another path, so it is never followed, and the file can't be SAFE;
    // nor can a path longer than the bytes kept before the hit, whose start was never seen (partialLink)
    const links = new Set();
    let cut = false;
    for (const h of r.hits[0]) {
      const c = cStringAround(h.buf, h.at);
      // a whole relative path is kept too: it is never followed, and makes the file UNKNOWN, naming it (judgeLinks)
      if (c.whole && (isDecoderLibName(c.text) || relativeLib(c.text, isDecoderLibName))) links.add(c.text);
      else if (unsureName(c, h, isDecoderLibName)) cut = true;
    }
    const release = r.hits[1].map((h) => printableAround(h.buf, h.at + RELEASE.length, { backward: false })).map((x) => {
      let i = 0; while (i < x.length && i < 16 && (x[i] === '.' || (x[i] >= '0' && x[i] <= '9'))) i++;
      return x.slice(0, i);
    }).find((x) => /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(x)) ?? '';
    // the library that holds Node.js's code, which a distribution's node is a launcher for: by the same rules
    const nodeLibs = new Set();
    let nodeLibUnsure = nodeNamed > r.hits[2].length;
    for (const h of r.hits[2]) {
      const c = cStringAround(h.buf, h.at);
      if (c.whole && (isNodeLibName(c.text) || relativeLib(c.text, isNodeLibName))) nodeLibs.add(c.text);
      else if (unsureName(c, h, isNodeLibName)) nodeLibUnsure = true;
    }
    slices.push({ m0, c0, mk, ck, um0, uc0, t10, links: [...links], crowded: named > r.hits[0].length, cut, release, nodeLibs: [...nodeLibs], nodeLibUnsure });
  }
  const sum = (k) => slices.reduce((n, x) => n + x[k], 0);
  return {
    m0: sum('m0'), c0: sum('c0'), mk: sum('mk'), ck: sum('ck'), um0: sum('um0'), uc0: sum('uc0'),
    t10: { fixed: slices.reduce((n, x) => n + x.t10.fixed, 0), unfixed: slices.reduce((n, x) => n + x.t10.unfixed, 0), other: slices.reduce((n, x) => n + x.t10.other, 0) },
    links: [...new Set(slices.flatMap((x) => x.links))], crowded: slices.some((x) => x.crowded), cut: slices.some((x) => x.cut),
    nodeLibs: [...new Set(slices.flatMap((x) => x.nodeLibs))], nodeLibUnsure: slices.some((x) => x.nodeLibUnsure),
    release: slices.map((x) => x.release).find(Boolean) ?? '', slices,
  };
}

/**
 * Whether an ELF file sets its own library search path (DT_RPATH or DT_RUNPATH, as conda's and Linuxbrew's programs do):
 * then a bare soname it links is looked for there first, and the standard folders say nothing about which file loads.
 * Reads the ELF header, the program headers and the dynamic segment only (each bounded); anything unexpected is null.
 * → 'none', 'set', or null (not an ELF file it can read, or no dynamic segment it understands).
 */
export function elfSearchPath(file) {
  const h = readHead(file, 64);
  if (!h || h.length < 52 || h.readUInt32BE(0) !== 0x7f454c46 || ![1, 2].includes(h[4]) || ![1, 2].includes(h[5])) return null;
  const is64 = h[4] === 2, le = h[5] === 1;
  if (is64 && h.length < 64) return null;
  const u16 = (b, o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const word = (b, o) => (is64 ? Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)) : u32(b, o));
  const phoff = word(h, is64 ? 32 : 28), phentsize = u16(h, is64 ? 54 : 42), phnum = u16(h, is64 ? 56 : 44);
  if (!phnum || phnum > 512 || phentsize < (is64 ? 56 : 32) || phentsize * phnum > 64 * 1024) return null;
  const ph = readAt(file, phoff, phentsize * phnum);
  if (!ph || ph.length < phentsize * phnum) return null;
  for (let i = 0; i < phnum; i++) {
    const o = i * phentsize;
    if (u32(ph, o) !== 2) continue;   // PT_DYNAMIC
    const off = word(ph, o + (is64 ? 8 : 4)), size = word(ph, o + (is64 ? 32 : 16)), ent = is64 ? 16 : 8;
    if (size > 64 * 1024) return null;
    const dyn = readAt(file, off, size);
    if (!dyn || dyn.length < size) return null;
    for (let j = 0; j + ent <= dyn.length; j += ent) {
      const tag = word(dyn, j);
      if (tag === 0) return 'none';                      // DT_NULL: the end
      if (tag === 15 || tag === 29) return 'set';        // DT_RPATH, DT_RUNPATH
    }
    return null;                                          // no DT_NULL inside the segment: not a table it understands
  }
  return null;
}

/**
 * Where a linked library is: an absolute path as is; @loader_path/ beside the file; a bare soname (ELF DT_NEEDED) in
 * the library folders `sonameDirs`, but only for an ELF file that sets no search path of its own. @rpath/,
 * @executable_path/ (the program that loads a library isn't known), $ORIGIN, a relative path (the folder the program
 * starts in isn't known) and any other form can't be followed in this simple rule.
 * → [files] (all the candidates; possibly empty: not found) or null (can't be followed, or a folder on the way is closed)
 */
export function resolveLink(ref, file, sonameDirs = []) {
  const at = (f) => { const st = pathState(f); return st === 'file' ? [f] : st === 'gone' ? [] : null; };
  if (ref.startsWith('/')) return at(ref);
  if (ref.startsWith('@loader_path/')) return at(resolve(dirname(realPath(file) ?? file), ref.slice('@loader_path/'.length)));
  if (ref.includes('/') || ref.includes('$') || ref.startsWith('@')) return null;
  if (elfSearchPath(file) !== 'none') return null;
  const out = [], seen = new Set();
  for (const d of sonameDirs) {
    const f = join(d, ref), st = pathState(f);
    if (st === 'denied' || st === 'other') return null;
    if (st !== 'file') continue;
    const real = realPath(f) ?? f;
    if (!seen.has(real)) { seen.add(real); out.push(f); }
  }
  return out;
}

/** A bare soname, when the loader's configuration or a library folder could not all be read: the loader may take the
 *  library from a folder Wardlatch didn't see. → the reason, or '' */
const gapFor = (ref, { sonameGaps = [] }) => (sonameGaps.length && !ref.includes('/') && !ref.startsWith('@') && !ref.includes('$')
  ? `it links ${ref}, and what the dynamic loader is told to search could not all be read (${sonameGaps.slice(0, 3).join(', ')}${sonameGaps.length > 3 ? ', ...' : ''}), so which file it loads, and whether that has the fix, could not be tested`
  : '');

/** Rule 2: the Brotli libraries a file links decide (one level; `judgeLib` judges each, by rule 1 unless the caller knows
 *  more, such as a distribution's package version). Every candidate must be SAFE for SAFE. */
function judgeLinks(file, links, opts, release) {
  const { markers, sonameDirs = [], judgeLib, budget } = opts;
  const one = judgeLib ?? ((lib) => judgeFile(lib, { markers, budget, follow: false }));
  const libs = [];
  for (const ref of links) {
    if (isRelative(ref)) return { status: 'UNKNOWN', release, via: ref, reason: RELATIVE(ref) };
    if (gapFor(ref, opts)) return { status: 'UNKNOWN', release, via: ref, reason: gapFor(ref, opts) };
    const found = resolveLink(ref, file, sonameDirs);
    if (found === null) return { status: 'UNKNOWN', release, via: ref, reason: `it links ${ref}, which Wardlatch can't follow or open (where it is found is decided when the program starts), so whether it has the fix could not be tested` };
    if (!found.length) return { status: 'UNKNOWN', release, via: ref, reason: `it links ${ref}, which was not found, so whether it has the fix could not be tested` };
    for (const lib of found) libs.push({ lib, r: one(lib) });
  }
  const bad = libs.find((x) => x.r.status === 'EXPOSED');
  if (bad) return { status: 'EXPOSED', release, via: bad.lib, reason: `it uses ${bad.lib}, ${bad.r.viaText}` };
  const unk = libs.find((x) => x.r.status !== 'SAFE');
  if (unk) return { status: 'UNKNOWN', release, via: unk.lib, reason: `it uses ${unk.lib}, and for that library: ${unk.r.reason}` };
  return safe([file, ...libs.flatMap((x) => x.r.searched)], { release, via: libs.map((x) => x.lib).join(', '), reason: libs.map((x) => `it uses ${x.lib}, ${x.r.viaText}`).join('; ') });
}

/** The libnode a node launches, judged by judgeFile's rules (its own table, or the Brotli library it links), never
 *  followed to another libnode. Every candidate must be SAFE for SAFE; the row's `via` is the library that decided.
 *  `nodeOwn`: libnode's own decoder decided, and libnode is Node.js's own library, so the fix is Node.js's. */
function judgeNodeLibs(file, refs, opts, release) {
  const done = [];
  for (const ref of refs) {
    if (isRelative(ref)) return { status: 'UNKNOWN', release, via: ref, runtimeSign: true, byHand: true, reason: RELATIVE(ref, ', the library that holds Node.js\'s code') };
    if (gapFor(ref, opts)) return { status: 'UNKNOWN', release, via: ref, runtimeSign: true, byHand: true, reason: gapFor(ref, opts) };
    const found = resolveLink(ref, file, opts.sonameDirs ?? []);
    if (found === null) return { status: 'UNKNOWN', release, via: ref, runtimeSign: true, byHand: true, reason: `it links ${ref}, the library that holds Node.js's code, which Wardlatch can't follow or open (where it is found is decided when the program starts), so whether it has the fix could not be tested` };
    if (!found.length) return { status: 'UNKNOWN', release, via: ref, runtimeSign: true, byHand: true, reason: `it links ${ref}, the library that holds Node.js's code, which was not found, so whether it has the fix could not be tested` };
    for (const lib of found) done.push({ lib, r: judgeFile(lib, { ...opts, follow: true, nodeLib: false }) });
  }
  const said = (x) => `it uses ${x.lib}, the library that holds Node.js's code: ${x.r.reason}`;
  const bad = done.find((x) => x.r.status === 'EXPOSED');
  if (bad) return { status: 'EXPOSED', release: release || bad.r.release, via: bad.r.via ?? bad.lib, nodeOwn: !bad.r.via, reason: said(bad) };
  const unk = done.find((x) => x.r.status !== 'SAFE');
  if (unk) return { status: 'UNKNOWN', release: release || unk.r.release, via: unk.r.via ?? unk.lib, runtimeSign: true, reason: said(unk) };
  return safe([file, ...done.flatMap((x) => x.r.searched)], { release: release || done.map((x) => x.r.release).find(Boolean) || '', via: done.map((x) => x.r.via ?? x.lib).join(', '), reason: done.map(said).join('; ') });
}

/** One build of a file (the whole file, or one build of a universal Mach-O file) by the rules judgeFile gives. */
function judgeBuild(file, ev, opts) {
  const { follow = true } = opts;
  const { m0, c0, mk, ck, links, crowded, cut, release, nodeLibs, nodeLibUnsure } = ev;
  // a decoder library names itself (its install name, its soname): those strings are not links to another library
  const self = basename(file).startsWith('libbrotlidec');
  // Brotli 1.0's form (no prefix): judged only as a whole table in Brotli's order (form10Of)
  const old = form10Of(ev);
  // a table with the fix (either form, or both), and a Brotli library it links too: that library is used as well, so it
  // must be SAFE too
  const fixedTable = (reason) => {
    if (follow && !self && (crowded || cut)) return { status: 'UNKNOWN', release, reason: crowded ? CROWDED : CUT };
    if (follow && !self && links.length) {
      const r = judgeLinks(file, links, opts, release);
      if (r.status !== 'SAFE') return { ...r, reason: `its own Brotli decoder has the fix, but ${r.reason}` };
      return safe(r.searched, { release, via: r.via, reason: `${reason}; and ${r.reason}`, viaText: 'whose Brotli decoder has the fix' });
    }
    return safe([file], { release, reason, viaText: 'whose Brotli decoder has the fix' });
  };
  if (c0 > 0) {
    if (m0 === c0) {
      // a second decoder in the 1.0 form beside it: the 1.1 form's marker says nothing about that one
      if (old === 'odd') return { status: 'UNKNOWN', release, reason: OLD_BESIDE };
      if (old === 'unfixed') return { status: 'EXPOSED', release, reason: SOME_LACK, viaText: 'which holds a Brotli decoder that lacks the fix' };
      return fixedTable(HAS_FIX);
    }
    if (m0 === 0) return { status: 'EXPOSED', release, noMarker: true, reason: LACKS_FIX, viaText: 'whose Brotli decoder lacks the fix' };
    if (m0 < c0) return { status: 'EXPOSED', release, reason: SOME_LACK, viaText: 'which holds a Brotli decoder that lacks the fix' };
    return { status: 'UNKNOWN', release, reason: ODD };
  }
  if (m0 > 0) return { status: 'UNKNOWN', release, reason: NO_CONTROL };
  // a whole 1.0-form table without the fix's name: EXPOSED, and like the 1.1 form's, a distribution's library is then
  // judged by its package version (noMarker: Debian's fixed 1.0.9 keeps 1.0.9's table)
  if (old === 'unfixed') return { status: 'EXPOSED', release, noMarker: true, reason: LACKS_FIX_10, viaText: 'whose Brotli decoder lacks the fix' };
  if (old === 'odd') return { status: 'UNKNOWN', release, runtimeSign: true, byHand: true, reason: OLD_FORM };
  if (old === 'fixed') return fixedTable(HAS_FIX_10);
  // a link past the mentions kept could be the one that decides: none of them is enough for SAFE
  if (crowded && follow) return { status: 'UNKNOWN', release, reason: CROWDED };
  if (cut && follow) return { status: 'UNKNOWN', release, reason: CUT };
  if (links.length && follow) return judgeLinks(file, links, opts, release);
  // no table and no Brotli library of its own, but the library that holds Node.js's code (a distribution's node, a
  // launcher for libnode): that library decides, by these same rules, one level (it is not followed to another libnode)
  if (follow && opts.nodeLib !== false && nodeLibUnsure) return { status: 'UNKNOWN', release, runtimeSign: true, byHand: true, reason: NODE_LIB_UNSURE };
  if (follow && opts.nodeLib !== false && nodeLibs.length) return judgeNodeLibs(file, nodeLibs, opts, release);
  return { status: 'UNKNOWN', release, runtimeSign: Boolean(release || mk || ck), byHand: true, noTable: true, reason: NO_TABLE };
}

/**
 * One file → { status, reason, via?, release?, searched?, runtimeSign?, noMarker?, viaText?, byHand?, noTable? }. The
 * rules, for each build in the file (a universal Mach-O file holds several; the loader maps one, so each must be SAFE):
 *  1. a table is there (the control is found): the marker exactly as often as the control is SAFE, as long as any
 *     1.0-form names beside it are whole tables with the fix (an unfixed one is EXPOSED, anything else UNKNOWN) and
 *     every Brotli library it also links is SAFE (rule 2); the control without the marker is EXPOSED, and so is fewer
 *     markers than controls (one of two decoders lacks the fix); more markers than controls is UNKNOWN. The marker
 *     without the control is UNKNOWN: no table was shown to be there.
 *  1a. Brotli 1.0's form (form10Of), with no 1.1-form table: whole tables with the fix's name in its place are SAFE (and
 *     the libraries it links must be SAFE too), a whole table without it EXPOSED, any other 1.0-form name UNKNOWN.
 *  2. no table, but it links a Brotli decoder library: that library decides (judgeLinks). A file that names libbrotlidec
 *     more often than the mentions kept, or in a string that isn't whole, is UNKNOWN.
 *  3. otherwise UNKNOWN: Node's constant names, a version, a file name never stand in for the table.
 * A file that can't be read, or a universal file whose header can't be read, is UNKNOWN.
 */
export function judgeFile(file, opts = {}) {
  const { markers, budget } = opts;
  const ev = evidence(file, markers, budget);
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
    const real = realPath(p) ?? p;
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
      const p = isDist ? resolve(dir, rel) : resolve(dir, e.name, rel);
      if (!within(p)) continue;   // console scripts (../../bin/x) are not what is looked for here
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
        const target = line.slice('include'.length).trim();
        if (resolve(dirname(f), target) !== usual) gaps.push(`${f}: include ${target}`);
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
    if (real.startsWith(a) && realPath(b + real.slice(a.length)) === real) names.push(b + real.slice(a.length));
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
  const real = realPath(file) ?? file;
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
 * budgetBytes (what this run may read; 4 GB), env (the variables that move a version manager's folders).
 * → { rows: [{ what, file, status, reason, fix?, searched?, version?, owner?, label?, via?, dir?, paths? }], looked: [what
 *   was looked at, for the receipt] }
 */
export function checkBundled(inc, { pathEnv = process.env.PATH ?? '', execPath, siteDirs = [], denied = [], places = {}, sonameDirs, budgetBytes = BUDGET, env = process.env } = {}) {
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
    for (const f of expand(place.pattern, denied)) if (pathState(f) === 'file') { const real = realPath(f) ?? f; if (!placeOf.has(real)) placeOf.set(real, place); }
  }
  const verdicts = new Map();
  const judgeLib = (lib) => {
    const real = realPath(lib) ?? lib;
    if (!verdicts.has(real)) {
      // judged (and named in a receipt) by its real path, once, whichever program or place reached it first
      let r = judgeFile(real, { markers, budget, follow: false });
      if (placeOf.get(real)?.system && r.noMarker && inc.distro) r = distroVerdict(real, inc.distro, places, budget);
      verdicts.set(real, r);
    }
    return verdicts.get(real);
  };
  const libFix = (lib) => {
    const real = realPath(lib) ?? lib, place = placeOf.get(real);
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
      const file = realPath(p) ?? p;
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
      const r = judgeFile(file, { markers, sonameDirs: libDirs, sonameGaps, judgeLib, budget });
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
  const shims = inc.shims ?? {}, shimOf = (p) => { const k = basename(realPath(p) ?? p); return Object.hasOwn(shims, k) ? k : null; };
  const shimAt = new Map(findAllOnPath('node', pathEnv).filter(shimOf).map((p) => [p, shimPlaces(shims[shimOf(p)], env, p)]));
  const tilde = (p) => (p.startsWith('~/') ? join(homedir(), p.slice(2)) : p), known = new Set((inc.nodeDirs ?? []).map(tilde));
  const managed = [...Object.values(shims).map((l) => shimPlaces(l, env)), ...shimAt.values()].flatMap((x) => x.patterns);
  const nodeDirs = [...(inc.nodeDirs ?? []), ...new Set(managed.filter((p) => !known.has(p)))];

  for (const [name, patterns] of [['node', nodeDirs], ['bun', inc.bunDirs ?? []]]) {
    const progs = runtimePrograms(name, patterns, { pathEnv, extra: name === 'node' && execPath ? [execPath] : [], denied });
    looked.runtimes.push(`${name} on PATH: ${pathEnv}`, ...patterns.map((p) => `${name} in ${p}`));
    for (const { file, onPath } of progs.files) {
      const r = judgeFile(file, { markers, sonameDirs: libDirs, sonameGaps, judgeLib, budget });
      // a program on PATH named node with no sign of being Node.js (no table, no link, no release, none of its constant
      // names) that is a version manager's compiled shim: a REVIEW row when its runtimes are read in their own folders,
      // UNKNOWN when they could not be (shimRow). Any other is UNKNOWN (below). Bun gets no such row: a bun that shows
      // nothing is UNKNOWN.
      if (name === 'node' && onPath && r.noTable && !r.runtimeSign && shimOf(file)) {
        // (its places were read above, by its place on PATH; one not among them is UNKNOWN, never REVIEW)
        rows.runtimes.push(shimRow(file, shimOf(file), shimAt.get(file) ?? { folders: [], unsure: [] }, inc.hints.node));
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
    if (progs.scripts.length) rows.runtimes.push({ what: name, file: progs.scripts[0], status: 'REVIEW', paths: progs.scripts, reason: `${progs.scripts.length === 1 ? 'a script' : 'scripts'} named ${name} on PATH (a version manager's shim), not ${progs.scripts.length === 1 ? 'a program' : 'programs'}: the runtimes ${progs.scripts.length === 1 ? 'it starts are' : 'they start are'} read in the version managers' folders` });
  }

  return { rows: [...rows.runtimes, ...rows.python, ...rows.libraries], looked: [...looked.runtimes, ...looked.python, ...looked.libraries] };
}
