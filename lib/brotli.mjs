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
import { join, dirname, basename, resolve, sep } from 'node:path';
import { scanBytes, listDir, pathState, realPath, readCapped, readHead, readAt, isNativeProgram } from './files.mjs';
import { findAllOnPath } from './binaries.mjs';
import { expand } from './installs.mjs';
import { safe } from './report.mjs';

const MAX_PROGRAM = 512 * 1024 * 1024;        // a node binary is 60 to 300 MB; a larger file is not read (UNKNOWN)
const BUDGET = 4 * 1024 * 1024 * 1024;        // what one run reads for this check; past it, each file left is UNKNOWN
const MAX_RECORD = 4 * 1024 * 1024;
const LINK = Buffer.from('libbrotlidec');
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
const UNREAD = 'could not be read (it is not a regular file, reading it was refused, or it is larger than 512 MB), so it could not be tested';
const OVER_BUDGET = 'not read, because this run had already read 4 GB of files for this check, so it could not be tested';

/** A printable run of bytes around position `at` of `buf` (a path in a load command, a version after a URL). */
function printableAround(buf, at, { backward = true } = {}) {
  const ok = (b) => b >= 0x20 && b <= 0x7e;
  let s = at, e = at;
  if (backward) while (s > 0 && ok(buf[s - 1])) s--;
  while (e < buf.length && ok(buf[e])) e++;
  return buf.subarray(s, e).toString('latin1');
}

/** Whether a string from a binary names a Brotli decoder library: a path or soname whose last part is libbrotlidec.dylib,
 *  libbrotlidec.<n>.dylib, libbrotlidec.so or libbrotlidec.so.<n>[.<n>...]. No pattern runs on it: a loop. */
export function isDecoderLibName(s) {
  // a load command holds an absolute path, an @loader_path/@executable_path/@rpath one, or (ELF) a bare soname; anything
  // else is text that happens to mention the name, and is never printed as a link
  if (!(s.startsWith('/') || s.startsWith('@') || !s.includes('/'))) return false;
  const name = s.slice(s.lastIndexOf('/') + 1);
  if (!name.startsWith('libbrotlidec') || name.length > 128) return false;
  if (name.endsWith('.dylib')) return true;
  const so = name.indexOf('.so');
  if (so < 0) return false;
  for (const part of name.slice(so + 3).split('.').slice(1)) if (!part || [...part].some((c) => c < '0' || c > '9')) return false;
  return name.slice(so + 3) === '' || name.slice(so + 3).startsWith('.');
}

/**
 * What a file holds: counts of the marker and control (exact, NUL-delimited), of Node's constant names (only to tell a
 * Node.js program from a version manager's shim, never as evidence of a fix), the Brotli decoder libraries it links
 * (load-command strings; `crowded` when there were more mentions of libbrotlidec than are kept, so some could be
 * missing), and a Node release version if it embeds one (for wording only).
 * budget: { left } bytes this run may still read; the file's size is taken off it. → null when the file can't be read;
 * { overBudget: true } when the budget was used up before it.
 */
export function evidence(file, markers, budget) {
  if (budget && budget.left <= 0) return { overBudget: true };
  const r = scanBytes(file, {
    count: [nul(markers.fixed), nul(markers.table), Buffer.from(markers.nodeConstant + markers.fixed), Buffer.from(markers.nodeConstant + markers.table), LINK],
    around: [LINK, RELEASE], back: 1024, fwd: 128, maxHits: 64, maxBytes: MAX_PROGRAM,
  });
  if (!r) return null;
  if (budget) budget.left -= r.size;
  const [m0, c0, mk, ck, named] = r.counts;
  const links = [...new Set(r.hits[0].map((h) => printableAround(h.buf, h.at)).filter(isDecoderLibName))];
  const v = r.hits[1].map((h) => printableAround(h.buf, h.at + RELEASE.length, { backward: false })).map((s) => {
    let i = 0; while (i < s.length && i < 16 && (s[i] === '.' || (s[i] >= '0' && s[i] <= '9'))) i++;
    return s.slice(0, i);
  }).find((s) => /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) ?? '';
  return { m0, c0, mk, ck, links, crowded: named > r.hits[0].length, release: v };
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
 * @executable_path/ (the program that loads a library isn't known), $ORIGIN and any other form can't be followed in this
 * simple rule.
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

/**
 * One file → { status, reason, via?, release?, searched?, runtimeSign?, noMarker?, viaText? }. The rules:
 *  1. a table is there (the control is found): the marker exactly as often as the control is SAFE; the control without
 *     the marker is EXPOSED, and so is fewer markers than controls (one of two decoders lacks the fix); more markers
 *     than controls is UNKNOWN. The marker without the control is UNKNOWN: no table was shown to be there.
 *  2. no table, but it links a Brotli decoder library: that library decides (one level; `judgeLib` judges it, by rule 1
 *     unless the caller knows more, such as a distribution's package version). Every candidate must be SAFE for SAFE,
 *     and a file that names libbrotlidec more often than the mentions kept is UNKNOWN.
 *  3. otherwise UNKNOWN: Node's constant names, a version, a file name never stand in for the table.
 * A file that can't be read is UNKNOWN.
 */
export function judgeFile(file, { markers, sonameDirs = [], judgeLib, budget, follow = true } = {}) {
  const ev = evidence(file, markers, budget);
  if (ev?.overBudget) return { status: 'UNKNOWN', reason: OVER_BUDGET };
  if (!ev) return { status: 'UNKNOWN', reason: UNREAD };
  const { m0, c0, mk, ck, links, crowded, release } = ev;
  if (c0 > 0) {
    if (m0 === c0) return safe([file], { release, reason: HAS_FIX, viaText: 'whose Brotli decoder has the fix' });
    if (m0 === 0) return { status: 'EXPOSED', release, noMarker: true, reason: LACKS_FIX, viaText: 'whose Brotli decoder lacks the fix' };
    if (m0 < c0) return { status: 'EXPOSED', release, reason: SOME_LACK, viaText: 'which holds a Brotli decoder that lacks the fix' };
    return { status: 'UNKNOWN', release, reason: ODD };
  }
  if (m0 > 0) return { status: 'UNKNOWN', release, reason: NO_CONTROL };
  // a link past the mentions kept could be the one that decides: none of them is enough for SAFE
  if (crowded && follow) return { status: 'UNKNOWN', release, reason: CROWDED };
  if (links.length && follow) {
    const one = judgeLib ?? ((lib) => judgeFile(lib, { markers, budget, follow: false }));
    const libs = [];
    for (const ref of links) {
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
  return { status: 'UNKNOWN', release, runtimeSign: Boolean(release || mk || ck), reason: NO_TABLE };
}

/** The node or bun programs to read: every copy on PATH, the one running Wardlatch (npx's), and the version managers'
 *  folders. Each once by its real path. Scripts (a version manager's shim) are not programs: returned in `scripts`. */
export function runtimePrograms(name, patterns, { pathEnv = process.env.PATH ?? '', extra = [], denied } = {}) {
  const odd = [], files = [], scripts = [], seen = new Set();
  const add = (p, onPath) => {
    const real = realPath(p) ?? p;
    if (seen.has(real)) return;
    seen.add(real);
    if (!isNativeProgram(p)) { if (onPath) scripts.push(p); return; }
    files.push({ file: p, onPath });
  };
  for (const p of findAllOnPath(name, pathEnv, odd)) add(p, true);
  for (const p of extra) if (pathState(p) === 'file') add(p, false);
  for (const pat of patterns) for (const p of expand(pat, denied)) if (pathState(p) === 'file') add(p, false);
  return { files, scripts, odd };
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

/** Name and version from a dist-info's METADATA (its first 8 KB), falling back to the folder name. */
function distName(dir, info) {
  const head = readHead(join(dir, info, 'METADATA'), 8192)?.toString('utf8') ?? '';
  let name = '', version = '';
  for (const l of head.split('\n').slice(0, 40)) {
    if (!name && l.startsWith('Name: ')) name = l.slice(6).trim().slice(0, 100);
    if (!version && l.startsWith('Version: ')) version = l.slice(9).trim().slice(0, 50);
  }
  const base = info.slice(0, -'.dist-info'.length), dash = base.indexOf('-');
  return { name: name || (dash < 0 ? base : base.slice(0, dash)), version: version || (dash < 0 ? '' : base.slice(dash + 1)) };
}

const isDecoderFileName = (n) => n.startsWith('libbrotlidec.') || n.startsWith('libbrotlidec-');
const isBindingFileName = (n) => n.startsWith('_brotli.') || n.startsWith('_brotlicffi.');

/**
 * The files in one site-packages folder that can hold a Brotli decoder, each with the distributions whose RECORD lists
 * it: libbrotlidec copies (delocate's <pkg>/.dylibs, auditwheel's <dist>.libs), the Brotli bindings' own extensions, and
 * Node.js runtimes bundled in a package (a compiled program named node). A libbrotlidec no RECORD lists (conda, a copy
 * by hand) is still returned, with no owner.
 * → { files: [{ file, owners: [{ name, version }] }], unread: [paths] } or null when the folder can't be listed.
 */
export function sitePackagesCandidates(dir) {
  const l = listDir(dir);
  if (!l.entries) return l.denied ? null : { files: [], unread: [] };
  const owners = new Map(), unread = [], picked = new Map();
  const within = (p) => p.startsWith(dir.endsWith(sep) ? dir : dir + sep);
  const pick = (p) => { if (!picked.has(p)) picked.set(p, owners.get(p) ?? []); };
  for (const e of l.entries) {
    if (!e.isDirectory() || !e.name.endsWith('.dist-info')) continue;
    const buf = readCapped(join(dir, e.name, 'RECORD'), MAX_RECORD);
    if (!buf) { if (pathState(join(dir, e.name, 'RECORD')) !== 'gone') unread.push(join(dir, e.name, 'RECORD')); continue; }
    const who = distName(dir, e.name);
    for (const rel of recordPaths(buf.toString('utf8'))) {
      const p = resolve(dir, rel);
      if (!within(p)) continue;   // console scripts (../../bin/x) are not what is looked for here
      owners.set(p, [...(owners.get(p) ?? []), who]);
      const n = basename(p);
      if (isDecoderFileName(n) || isBindingFileName(n)) pick(p);
      else if (n === 'node' && isNativeProgram(p)) pick(p);
    }
  }
  // the vendored-library folders, listed on disk too: a copy that no RECORD lists is still a copy
  for (const e of l.entries) {
    if (!e.isDirectory()) continue;
    const libDirs = e.name.endsWith('.libs') ? [join(dir, e.name)] : [join(dir, e.name, '.dylibs'), join(dir, e.name, '.libs')];
    for (const d of libDirs) {
      const ld = listDir(d);
      if (ld.denied) { unread.push(d); continue; }
      for (const f of ld.entries ?? []) if (isDecoderFileName(f.name)) pick(join(d, f.name));
    }
  }
  for (const e of l.entries) if (!e.isDirectory() && isBindingFileName(e.name)) pick(join(dir, e.name));
  // a picked file that RECORD lists but isn't on disk (a half-removed package) is nothing to judge
  return { files: [...picked].filter(([p]) => pathState(p) !== 'gone').map(([file]) => ({ file, owners: owners.get(file) ?? [] })), unread };
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
 * /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf (comments dropped; `include` lines are not followed, apart from the usual
 * ld.so.conf.d, which is read anyway). A soname found in any of them is one more candidate that must be SAFE, so a
 * folder too many can't make a SAFE; only a folder missed could.
 */
export function ldSoConfDirs({ ldSoConf, ldSoConfDir } = {}) {
  const files = ldSoConf ? [ldSoConf] : [];
  if (ldSoConfDir) for (const e of (listDir(ldSoConfDir).entries ?? []).slice(0, 256)) if (e.name.endsWith('.conf')) files.push(join(ldSoConfDir, e.name));
  const out = [];
  for (const f of files) {
    for (const raw of (readCapped(f, 64 * 1024)?.toString('utf8') ?? '').split('\n')) {
      const hash = raw.indexOf('#');
      for (const w of (hash < 0 ? raw : raw.slice(0, hash)).split(/[\s,:]+/)) if (w.startsWith('/') && !w.includes('*') && !out.includes(w)) out.push(w);
    }
  }
  return out;
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
 * A system library that has the control but not the marker: the distribution may have fixed it another way (a backport
 * without the new error code), so its own package version decides, compared by exact string with the incident's table
 * (never by dpkg's ordering rules): `fixed` lists binary versions as dpkg records them (Debian's security builds), and
 * `vulnerableSources` lists source versions, so every rebuild of an unfixed source (1.1.0-2+b7 is built from 1.1.0-2)
 * is matched. A package version Wardlatch can't read (rpm, pacman), Alpine's (not in the table), or one not in the table
 * is UNKNOWN; only a package built from a source the table lists as without the fix is EXPOSED.
 */
export function distroVerdict(file, table, places) {
  const deb = dpkgStanzas(places.dpkgStatus, table.dpkgName)?.[0];
  const apk = deb ? null : apkVersion(places.apkInstalled, table.apkName);
  if (!deb && !apk) return { status: 'UNKNOWN', reason: 'the error text the fix added isn\'t in it, but your distribution may have fixed it another way, and Wardlatch can\'t read its package version here, so whether it has the fix could not be tested: check your distribution\'s security page for CVE-2026-111497' };
  const label = deb ? `${table.dpkgName} ${deb.version}` : `${table.apkName} ${apk.version}`;
  const os = osRelease(places.osRelease);
  const entry = deb && [`${os.ID}:${os.VERSION_ID}`, `${os.ID}:${os.VERSION_CODENAME}`].map((k) => table.releases?.[k]).find(Boolean);
  if (entry?.fixed?.includes(deb.version)) {
    const said = `${entry.name}'s fixed package ${label} (${entry.source})`;
    return safe([file, `${places.dpkgStatus}: ${label}`], { label, reason: `the error text the fix added isn't in it, but it is ${said}`, viaText: `which is ${said}` });
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
 * (osRelease, dpkgStatus, apkInstalled, ldSoConf, ldSoConfDir), sonameDirs (patterns; the incident's by default),
 * budgetBytes (what this run may read; 4 GB).
 * → { rows: [{ what, file, status, reason, fix?, searched?, version?, owner?, label?, via?, dir?, paths? }], looked: [what
 *   was looked at, for the receipt] }
 */
export function checkBundled(inc, { pathEnv = process.env.PATH ?? '', execPath, siteDirs = [], denied = [], places = {}, sonameDirs, budgetBytes = BUDGET } = {}) {
  const markers = inc.markers, rows = [], looked = [], budget = { left: budgetBytes };
  const fill = (text, vars = {}) => Object.entries(vars).reduce((t, [k, v]) => t.replaceAll(`{${k}}`, v), text ?? '');
  const fixFor = (key, vars) => fill(inc.fixes[key], vars);
  const libDirs = [...new Set([...(sonameDirs ?? inc.sonameDirs ?? []), ...ldSoConfDirs(places)].flatMap((p) => (p.includes('*') ? expand(p) : [p])))].filter((d) => pathState(d) === 'dir');
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
      if (placeOf.get(real)?.system && r.noMarker && inc.distro) r = distroVerdict(real, inc.distro, places);
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
  // a row as printed and in --json: the judge's working fields (viaText, noMarker, runtimeSign) stay out
  const row = (base, r, { reason = r.reason, fix } = {}) => ({
    ...base, status: r.status, reason, ...(r.via ? { via: r.via } : {}), ...(r.label && !base.label ? { label: r.label } : {}),
    ...(r.status === 'EXPOSED' && fix ? { fix } : {}), ...(r.status === 'SAFE' ? { searched: r.searched } : {}),
  });

  for (const [name, patterns] of [['node', inc.nodeDirs ?? []], ['bun', inc.bunDirs ?? []]]) {
    const progs = runtimePrograms(name, patterns, { pathEnv, extra: name === 'node' && execPath ? [execPath] : [], denied });
    looked.push(`${name} on PATH: ${pathEnv}`, ...patterns.map((p) => `${name} in ${p}`));
    for (const { file, onPath } of progs.files) {
      const r = judgeFile(file, { markers, sonameDirs: libDirs, judgeLib, budget });
      // a program on PATH named node with no sign of being Node.js (no table, no link, no release, none of its constant
      // names: a version manager's compiled shim): its runtimes are read in their own folders; named in a REVIEW row.
      // Bun gets no such row: a bun that shows nothing is UNKNOWN.
      if (name === 'node' && onPath && r.reason === NO_TABLE && !r.runtimeSign) {
        rows.push({ what: name, file, status: 'REVIEW', reason: 'not a Node.js runtime (a version manager\'s shim?), so it was not judged: the runtimes it starts are read in the version managers\' folders' });
        continue;
      }
      // the version picks the words only: a line with no fix (Node.js 20 and older, the odd-numbered lines) is told to move
      const version = name === 'node' ? r.release ?? '' : '';
      const major = Number(version.split('.')[0]), lines = (inc.nodeFixed ?? []).map((v) => Number(v.split('.')[0]));
      const line = (inc.nodeFixed ?? []).find((v) => Number(v.split('.')[0]) === major);
      const eol = major > 0 && !line && major < Math.max(...lines);
      const fix = r.via ? linkedFix(name === 'node' ? 'Node.js' : 'Bun', r.via)
        : name === 'bun' ? fixFor('bun') : line ? fixFor('node-line', { fixed: line, major: String(major) }) : eol ? fixFor('node-eol', { major: String(major) }) : fixFor('node');
      rows.push(row({ what: name, file, version }, r, { fix, reason: r.reason === NO_TABLE ? `${r.reason}. ${inc.hints[name]}` : r.reason }));
    }
    for (const p of progs.odd) rows.push({ what: name, file: p, status: 'UNKNOWN', reason: 'something of this name is on PATH, but it is not a regular file (or could not be looked at), so it was not read and could not be tested' });
    if (progs.scripts.length) rows.push({ what: name, file: progs.scripts[0], status: 'REVIEW', paths: progs.scripts, reason: `${progs.scripts.length === 1 ? 'a script' : 'scripts'} named ${name} on PATH (a version manager's shim), not ${progs.scripts.length === 1 ? 'a program' : 'programs'}: the runtimes ${progs.scripts.length === 1 ? 'it starts are' : 'they start are'} read in the version managers' folders` });
  }

  for (const dir of siteDirs) {
    const c = sitePackagesCandidates(dir);
    if (!c) { denied.push(dir); continue; }
    looked.push(dir);
    for (const u of c.unread) rows.push({ what: 'python', file: u, dir, status: 'UNKNOWN', reason: 'could not be read, so the copies of Brotli it lists could not be tested' });
    for (const { file, owners } of c.files) {
      const r = judgeFile(file, { markers, sonameDirs: libDirs, judgeLib, budget });
      const names = [...new Set(owners.map((o) => o.name))].join(' and ');
      const owner = owners.map((o) => `${o.name} ${o.version}`).join(', ');
      const isNode = basename(file) === 'node';
      const known = owners.map((o) => inc.dists?.[norm(o.name)]).find(Boolean);
      const ownFix = isNode ? fixFor('pip-node', { names: names || 'the package' }) : known ? fill(known.fix, { names }) : names ? fixFor('pip-bundled', { names }) : fixFor('pip-unowned');
      // a copy decided by a library outside the package (a system or Homebrew library) is fixed by updating that library
      const fix = r.via && !r.via.startsWith(dir + sep) ? linkedFix('the package', r.via) : ownFix;
      const hint = isNode ? inc.hints.node : isBindingFileName(basename(file)) ? inc.hints.binding : inc.hints.file;
      rows.push(row({ what: 'python', file, dir, owner, ...(owner ? {} : { label: 'a copy no package lists' }) }, r, { fix, reason: r.reason === NO_TABLE ? `${r.reason}. ${fill(hint, { names: names || 'the package that installed it' })}` : r.reason }));
    }
  }

  const seenLibs = new Set();
  for (const place of inc.libPlaces ?? []) {
    looked.push(place.pattern);
    for (const p of expand(place.pattern, denied)) {
      if (pathState(p) !== 'file') continue;
      const file = realPath(p) ?? p;
      if (seenLibs.has(file)) continue;
      seenLibs.add(file);
      const r = judgeLib(file);
      rows.push(row({ what: 'library', label: r.label ?? place.label, file }, r, { fix: libFix(file) }));
    }
  }
  return { rows, looked };
}
