// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The bundled-decoder check (lib/brotli.mjs, incident brotli-2026-10), offline, on synthetic files: Mach-O and ELF files
// laid out as their linkers write them (a header, load commands or a dynamic table, a string table, and a code signature
// where one is read) and the strings a Brotli decoder's error table holds, in the combinations real builds have. No real binary is in the repository and nothing is downloaded. Every case that
// ends EXPOSED or UNKNOWN has a clean twin. Package names are the copies the incident covers (Pillow, opencv-python, the
// Brotli bindings) or made up.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, openSync, ftruncateSync, closeSync, realpathSync, symlinkSync, statSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanBytes, readAt } from '../lib/files.mjs';
import { judgeFile, evidence, isDecoderLibName, isNodeLibName, recordPaths, sitePackagesCandidates, distroVerdict, checkBundled, linkTable, loadableAt, ldSoConfDirs, shimPlaces } from '../lib/brotli.mjs';
import { SITE_PATTERNS } from '../lib/installs.mjs';
// round 10's new exports, by name, so this file still loads (and their tests fail) at a tree without them
import * as brotli from '../lib/brotli.mjs';
import { hiddenPlaces } from './support/machine-places.cjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'brotli-2026-10.json'), 'utf8'));
const M = INC.markers;
const MARKER = M.fixed, CONTROL = M.table;
const NODE_MARKER = `${M.nodeConstant}${MARKER}`, NODE_CONTROL = `${M.nodeConstant}${CONTROL}`;   // Node's zlib.constants names
const MACHO = Buffer.from('cffaedfe', 'hex');   // a thin 64-bit Mach-O file's first bytes, as arm64 and x86_64 builds have them
let dir;
// the test's folder by its real path (macOS's temporary folder is reached through /var, a link to /private/var), so the
// paths a receipt names, each a file's real path, are the ones the test writes
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-brotli-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
const cstrings = (parts) => parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(`\0${p}\0`)));

// Mach-O load commands (mach-o/loader.h), with LC_REQ_DYLD (0x80000000) on the ones dyld can't do without
const LC = { load: 0x0c, id: 0x0d, weak: 0x80000018, reexport: 0x8000001f, lazy: 0x20, upward: 0x80000023, rpath: 0x8000001c, sign: 0x1d, env: 0x27 };

// CPU types (mach/machine.h): arm64 (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), x86_64 (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL;
// a program's carries CPU_SUBTYPE_LIB64 in its top byte), arm64e (CPU_SUBTYPE_ARM64E)
const CPU = { arm64: [0x0100000c, 0], x86_64: [0x01000007, 3], x86_64Program: [0x01000007, 0x80000003], arm64e: [0x0100000c, 2] };

/**
 * A Mach-O header and its load commands, as ld64 writes them (64-bit little-endian by default, as arm64 and x86_64
 * builds are): `type` (2 a program, 6 a library, 8 a bundle), `cpu` ([cputype, cpusubtype], arm64 by default), `id` (LC_ID_DYLIB), `links` (LC_LOAD_DYLIB names, or
 * { name, cmd, prefix }: `prefix` bytes sit in the command before the name, and the name's offset skips them), `rpaths`
 * (LC_RPATH), `env` (LC_DYLD_ENVIRONMENT values), `sign` ([offset, size] of a code signature), `bits`, `be`, `version` (a
 * dylib command's current and compatibility versions, 0x00XXYYZZ: libSystem's 1351.0.0 is 0x05470000, whose last byte,
 * right before the name in a little-endian file, is not NUL), `platform` (an LC_BUILD_VERSION for that platform: 1
 * macOS, 2 iOS, with minos 11.0 and sdk 13.0).
 */
function machoHead({ type = 2, cpu = CPU.arm64, id, links = [], rpaths = [], env = [], sign, bits = 64, be = false, version = 0, platform } = {}) {
  const align = bits === 64 ? 8 : 4;
  const w32 = (b, v, o) => (be ? b.writeUInt32BE(v >>> 0, o) : b.writeUInt32LE(v >>> 0, o));
  const lcStr = (cmd, fixed, name, prefix = '') => {
    const pre = Buffer.from(prefix), body = Buffer.concat([pre, Buffer.isBuffer(name) ? name : Buffer.from(name), Buffer.alloc(1)]);
    const size = Math.ceil((fixed + body.length) / align) * align, c = Buffer.alloc(size);
    w32(c, cmd, 0); w32(c, size, 4); w32(c, fixed + pre.length, 8);
    if (fixed === 24) { w32(c, 2, 12); w32(c, version, 16); w32(c, version, 20); }   // the timestamp, current and compatibility versions
    body.copy(c, fixed);
    return c;
  };
  const cmds = [
    ...(id === undefined ? [] : [lcStr(LC.id, 24, id)]),
    ...links.map((l) => (typeof l === 'string' || Buffer.isBuffer(l) ? lcStr(LC.load, 24, l) : lcStr(l.cmd ?? LC.load, 24, l.name, l.prefix))),
    ...rpaths.map((p) => lcStr(LC.rpath, 12, p)), ...env.map((v) => lcStr(LC.env, 12, v)),
  ];
  if (platform !== undefined) { const c = Buffer.alloc(24); w32(c, 0x32, 0); w32(c, 24, 4); w32(c, platform, 8); w32(c, 0x000b0000, 12); w32(c, 0x000d0000, 16); cmds.push(c); }
  if (sign) { const c = Buffer.alloc(16); w32(c, LC.sign, 0); w32(c, 16, 4); w32(c, sign[0], 8); w32(c, sign[1], 12); cmds.push(c); }
  const head = Buffer.alloc(bits === 64 ? 32 : 28), all = Buffer.concat(cmds);
  w32(head, bits === 64 ? 0xfeedfacf : 0xfeedface, 0); w32(head, cpu[0], 4); w32(head, cpu[1], 8); w32(head, type, 12); w32(head, cmds.length, 16); w32(head, all.length, 20);
  return Buffer.concat([head, all]);
}

/** A code signature as codesign writes one (cs_blobs.h, big-endian): a SuperBlob, one CodeDirectory, its identifier. */
function signature(ident) {
  const id = Buffer.from(`${ident}\0`), cd = Buffer.alloc(44), sb = Buffer.alloc(20);
  cd.writeUInt32BE(0xfade0c02, 0); cd.writeUInt32BE(44 + id.length, 4); cd.writeUInt32BE(0x20400, 8); cd.writeUInt32BE(44, 20);
  sb.writeUInt32BE(0xfade0cc0, 0); sb.writeUInt32BE(20 + 44 + id.length, 4); sb.writeUInt32BE(1, 8); sb.writeUInt32BE(0, 12); sb.writeUInt32BE(20, 16);
  return Buffer.concat([sb, cd, id]);
}

/** A thin Mach-O file: machoHead(o), padding, then each string as a C string literal (NUL before and after) or raw
 *  bytes; `o.signed`: a code signature with that identifier at the end. With a Buffer for `o`, that magic and the
 *  strings, and no header the loader could read. */
function bin(path, parts = [], o = {}) {
  mkdirSync(dirname(path), { recursive: true });
  const body = Buffer.concat([Buffer.alloc(60, 0x90), ...cstrings(parts), Buffer.alloc(16)]);
  let bytes;
  if (Buffer.isBuffer(o)) bytes = Buffer.concat([o, body]);
  else if (o.signed === undefined) bytes = Buffer.concat([machoHead(o), body]);
  else {
    const sig = signature(o.signed), at = machoHead({ ...o, sign: [0, 0] }).length + body.length;
    bytes = Buffer.concat([machoHead({ ...o, sign: [at, sig.length] }), body, sig]);
  }
  writeFileSync(path, bytes, { mode: 0o755 });
  return path;
}
/** Whether a file name is an ELF library's (a soname: libfoo.so, libfoo.so.1, libfoo-1a2b.so.1.2.0). */
const isSoName = (p) => /^lib[\s\S]*\.so(\.[0-9.]+)?$/.test(basename(p));

/**
 * An ELF file as a linker lays one out (64-bit little-endian x86-64 by default): a PT_LOAD segment mapping the whole file at
 * 0x10000 and a PT_DYNAMIC segment; a string table; a dynamic table with DT_NEEDED for each of `needed` (a name, or
 * { name, prefix }: `prefix` bytes sit before it in the string table, and its offset skips them), DT_SONAME, DT_RPATH and
 * DT_RUNPATH when given, DT_FLAGS_1 (`flags1`, such as DF_1_PIE) when given, then DT_STRTAB (an address), DT_STRSZ and
 * DT_NULL; then the strings, as bin() writes them. `type`: a shared object (ET_DYN, 3) for a file named like a soname, a
 * program (ET_EXEC, 2) otherwise. `machine`: e_machine (62 x86-64, 183 aarch64, 21 ppc64, 8 MIPS); `eflags`: e_flags (the
 * ABI flags: ppc64's EF_PPC64_ABI, MIPS's EF_MIPS_ABI2 and EF_MIPS_NAN2008). `split`: two PT_LOAD segments, the headers
 * at 0x10000 and the rest (the string table first) at 0x400000. `interp`: a PT_INTERP segment naming that loader (its
 * bytes in the string table's place, with its NUL; `cut`: without it, as no kernel takes one).
 */
function elf(path, parts = [], { needed = [], soname, rpath, runpath, flags1, bits = 64, be = false, type = isSoName(path) ? 3 : 2, machine = 0x3e, eflags = 0, split = false, interp, cut = false } = {}) {
  const BASE = 0x10000, ent = bits === 64 ? 16 : 8, ehsize = bits === 64 ? 64 : 52, phsize = bits === 64 ? 56 : 32;
  let strtab = Buffer.alloc(1);
  const str = (s, prefix = '') => { const at = strtab.length + Buffer.from(prefix).length; strtab = Buffer.concat([strtab, Buffer.from(prefix), Buffer.isBuffer(s) ? s : Buffer.from(s), Buffer.alloc(1)]); return at; };
  const tags = [...needed.map((n) => (typeof n === 'string' || Buffer.isBuffer(n) ? [1, str(n)] : [1, str(n.name, n.prefix)])),
    ...[[14, soname], [15, rpath], [29, runpath]].filter(([, v]) => v !== undefined).map(([t, v]) => [t, str(v)]), ...(flags1 === undefined ? [] : [[0x6ffffffb, flags1]])];
  const interpAt = interp === undefined ? -1 : str(interp), interpLen = interp === undefined ? 0 : Buffer.from(interp).length + (cut ? 0 : 1);
  const phnum = (split ? 3 : 2) + (interp === undefined ? 0 : 1), SEG2 = 0x400000;
  const strOff = ehsize + phnum * phsize, dynOff = Math.ceil((strOff + strtab.length) / 8) * 8;
  tags.push([5, split ? SEG2 : BASE + strOff], [10, strtab.length], [0, 0]);
  const tail = Buffer.concat([Buffer.alloc(16), ...cstrings(parts), Buffer.alloc(16)]);
  const h = Buffer.alloc(dynOff + tags.length * ent), total = h.length + tail.length, dynLen = tags.length * ent;
  const w16 = (v, o) => (be ? h.writeUInt16BE(v, o) : h.writeUInt16LE(v, o));
  const w32 = (v, o) => (be ? h.writeUInt32BE(v, o) : h.writeUInt32LE(v, o));
  const w64 = (v, o) => (be ? h.writeBigUInt64BE(BigInt(v), o) : h.writeBigUInt64LE(BigInt(v), o));
  const word = bits === 64 ? w64 : w32;
  h.set([0x7f, 0x45, 0x4c, 0x46, bits === 64 ? 2 : 1, be ? 2 : 1, 1], 0);
  w16(type, 16); w16(machine, 18); w32(1, 20); w32(eflags, bits === 64 ? 48 : 36);
  if (bits === 64) { w64(ehsize, 32); w16(ehsize, 52); w16(phsize, 54); w16(phnum, 56); } else { w32(ehsize, 28); w16(ehsize, 40); w16(phsize, 42); w16(phnum, 44); }
  // PT_LOAD (the whole file, or the headers and then the rest), then PT_DYNAMIC
  const segs = [...(interp === undefined ? [] : [[3, strOff + interpAt, interpLen, BASE + strOff + interpAt]]),
    ...(split ? [[1, 0, strOff, BASE], [1, strOff, total - strOff, SEG2], [2, dynOff, dynLen, SEG2 + dynOff - strOff]] : [[1, 0, total, BASE], [2, dynOff, dynLen, BASE + dynOff]])];
  segs.forEach(([type2, off, len, vaddr], i) => {
    const o = ehsize + i * phsize;
    w32(type2, o);
    if (bits === 64) { w32(type2 === 1 ? 5 : 6, o + 4); w64(off, o + 8); w64(vaddr, o + 16); w64(vaddr, o + 24); w64(len, o + 32); w64(len, o + 40); w64(8, o + 48); } else { w32(off, o + 4); w32(vaddr, o + 8); w32(vaddr, o + 12); w32(len, o + 16); w32(len, o + 20); w32(type2 === 1 ? 5 : 6, o + 24); w32(4, o + 28); }
  });
  strtab.copy(h, strOff);
  tags.forEach(([t, v], i) => { word(t, dynOff + i * ent); word(v, dynOff + i * ent + ent / 2); });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, Buffer.concat([h, tail]), { mode: 0o755 });
  return path;
}
/** A Brotli library as its platform's linker writes one: an ELF shared object (x86-64) for a soname, a Mach-O dylib
 *  (arm64) otherwise, each with the strings of a decoder's error table, with the fix or without it. */
const libFile = (p, parts, o = {}) => (isSoName(p) ? elf(p, parts, o) : bin(p, parts, { type: 6, ...o }));
const fixedLib = (p, o) => libFile(p, ['_SUCCESS', CONTROL, MARKER, '_ERROR_UNREACHABLE'], o);
const oldLib = (p, o) => libFile(p, ['_SUCCESS', CONTROL, '_ERROR_UNREACHABLE'], o);
const judge = (f, sonameDirs = [], o = {}) => judgeFile(f, { markers: M, sonameDirs, ...o });
/** The incident's version managers with their own folders moved under `root` (`~/x` and `/x` both become root/x). */
const shimsUnder = (root) => Object.fromEntries(Object.entries(INC.shims).map(([k, v]) => [k, { ...v, homes: v.homes.map((h) => (h.startsWith('~/') ? join(root, h.slice(2)) : h.startsWith('/') ? join(root, h) : h)) }]));
/** checkBundled on this test's places only: no version managers' folders (theirs are moved into the test's folder, and
 *  no variable moves them), library places or library folders unless given. */
const run = (incOver = {}, opts = {}) => checkBundled({ ...INC, nodeDirs: [], bunDirs: [], libPlaces: [], shims: shimsUnder(join(dir, 'vm-home')), ...incOver }, { pathEnv: fresh(`empty-path-${Math.random()}`), sonameDirs: [], env: {}, ...opts });

test('scanBytes: a needle across a piece boundary is counted once, and a hit keeps the bytes around it', () => {
  const needle = Buffer.from('NEEDLE');
  const f = join(fresh('scan'), 'x');
  // the needle at every offset around the 64-byte piece edges, so some straddle one
  const parts = []; for (let i = 0; i < 40; i++) parts.push(Buffer.alloc(i % 13, 0x41), needle);
  writeFileSync(f, Buffer.concat(parts));
  const expected = Buffer.concat(parts).toString('latin1').split('NEEDLE').length - 1;
  for (const piece of [7, 16, 64, 1024]) {
    const r = scanBytes(f, { count: [needle], around: [needle], back: 4, fwd: 3, maxHits: 1000, maxBytes: 1e6, piece });
    assert.equal(r.counts[0], expected, `piece ${piece}`);
    assert.equal(r.hits[0].length, expected, `piece ${piece}: every hit returned once`);
    for (const h of r.hits[0]) assert.equal(h.buf.subarray(h.at, h.at + needle.length).toString(), 'NEEDLE');
  }
  // a file over the cap is not read at all
  assert.equal(scanBytes(f, { count: [needle], maxBytes: 10 }), null);
});

test('scanBytes select: found ignoring case with fold, kept only when want takes it, every hit looked at up to maxLooks, each with its place in the file', () => {
  const f = join(fresh('scan-select'), 'x');
  // the needle in two spellings at every offset around the piece edges, each followed by '+' or '-'
  const parts = []; for (let i = 0; i < 40; i++) parts.push(Buffer.alloc(i % 13, 0x41), Buffer.from(i % 2 ? 'NeEdLe+' : 'needle-'));
  const all = Buffer.concat(parts);
  writeFileSync(f, all);
  for (const piece of [7, 16, 64, 1024]) {
    // folded: both spellings found; `want` (shown the folded bytes) takes the 20 followed by '+', the first 5 are kept
    const r = scanBytes(f, { select: [Buffer.from('needle')], fold: true, want: (hay, i, n, pos) => hay[i + n.length] === 0x2b && all[pos] === 0x4e, maxHits: 5, maxBytes: 1e6, piece, back: 4, fwd: 3 });
    assert.equal(r.taken[0], 20, `piece ${piece}`); assert.equal(r.chosen[0].length, 5); assert.equal(r.unlooked[0], 0);
    for (const h of r.chosen[0]) { assert.equal(h.buf.subarray(h.at, h.at + 6).toString(), 'NeEdLe', 'the bytes as they are'); assert.equal(all.subarray(h.pos, h.pos + 7).toString(), 'NeEdLe+', 'its place in the file'); }
    // not folded: only the lower-case spelling
    assert.equal(scanBytes(f, { select: [Buffer.from('needle')], maxBytes: 1e6, piece, back: 4, fwd: 3 }).taken[0], 20, `piece ${piece}`);
    // maxLooks: `want` is asked about the first 10, and the other 30 are counted as never looked at
    let asked = 0;
    const m = scanBytes(f, { select: [Buffer.from('needle')], fold: true, want: () => { asked++; return false; }, maxLooks: 10, maxBytes: 1e6, piece, back: 4, fwd: 3 });
    assert.equal(asked, 10); assert.equal(m.unlooked[0], 30); assert.equal(m.taken[0], 0);
  }
});

test('readAt: a bounded read at an offset; a FIFO, a folder or an oversized range gives null', () => {
  const d = fresh('readat');
  writeFileSync(join(d, 'f'), 'abcdefgh');
  assert.equal(readAt(join(d, 'f'), 2, 3).toString(), 'cde');
  assert.equal(readAt(join(d, 'f'), 6, 10).toString(), 'gh', 'a short read at the end');
  assert.equal(readAt(join(d, 'f'), 0, 64 * 1024 + 1), null);
  assert.equal(readAt(join(d, 'f'), -1, 2), null);
  assert.equal(readAt(d, 0, 2), null);
  execFileSync('mkfifo', [join(d, 'fifo')]);
  assert.equal(readAt(join(d, 'fifo'), 0, 2), null);
});

test('rule 1: the control without the marker is EXPOSED; with it, SAFE with a receipt naming the file', () => {
  const d = fresh('rule1');
  const bad = judge(oldLib(join(d, 'libbrotlidec.1.2.0.dylib')));
  assert.equal(bad.status, 'EXPOSED'); assert.match(bad.reason, /lacks the fix/);
  const good = judge(fixedLib(join(d, 'libbrotlidec.1.2.1.dylib')));
  assert.equal(good.status, 'SAFE'); assert.deepEqual(good.searched, [join(d, 'libbrotlidec.1.2.1.dylib')]);
  // two tables, one without the fix (more controls than markers): EXPOSED. These strings are unmerged, as in a file
  // linked without string merging; within one linked image ld64 and GNU ld merge identical literals, so two decoders
  // there show one table (ASSURANCE_CASE's limit), and the realistic two-decoder file is a universal one (below)
  const two = judge(bin(join(d, 'two'), [CONTROL, MARKER, CONTROL]));
  assert.equal(two.status, 'EXPOSED'); assert.match(two.reason, /more than one Brotli decoder/);
  // and its clean twin: two fixed tables
  assert.equal(judge(bin(join(d, 'two-fixed'), [CONTROL, MARKER, CONTROL, MARKER])).status, 'SAFE');
});

test('the marker counts only beside the control: alone, or more often than the control, it is UNKNOWN, never SAFE', () => {
  const d = fresh('control');
  const alone = judge(bin(join(d, 'marker-only'), ['_SUCCESS', MARKER]));
  assert.equal(alone.status, 'UNKNOWN'); assert.match(alone.reason, /could not be tested/);
  const odd = judge(bin(join(d, 'marker-twice'), [CONTROL, MARKER, MARKER]));
  assert.equal(odd.status, 'UNKNOWN'); assert.match(odd.reason, /could not be tested/);
  // a half table is not passed on to a library the file links, however fixed that library is
  fixedLib(join(d, 'libbrotlidec.1.dylib'));
  const half = judge(bin(join(d, 'half-and-link'), [MARKER], { links: [join(d, 'libbrotlidec.1.dylib')] }));
  assert.equal(half.status, 'UNKNOWN'); assert.match(half.reason, /not the error texts every Brotli decoder has/);
  // the clean twin: the same file with the control beside the one marker
  assert.equal(judge(bin(join(d, 'both'), ['_SUCCESS', CONTROL, MARKER])).status, 'SAFE');
});

/** A universal (fat) Mach-O file: the header, then each build at its offset (16-byte aligned), as bin() writes one (a
 *  build is its strings, or { parts, ...machoHead's options }). */
function fat(path, builds, { is64 = false } = {}) {
  const bodies = builds.map((b) => { const { parts, ...o } = Array.isArray(b) ? { parts: b } : b; return Buffer.concat([machoHead(o), Buffer.alloc(60, 0x90), ...cstrings(parts), Buffer.alloc(16)]); });
  const ent = is64 ? 32 : 20, head = Buffer.alloc(8 + builds.length * ent);
  head.writeUInt32BE(is64 ? 0xcafebabf : 0xcafebabe, 0); head.writeUInt32BE(builds.length, 4);
  let at = Math.ceil(head.length / 16) * 16 + 64;
  const out = [head];
  bodies.forEach((b, i) => {
    const o = 8 + i * ent;
    const cpu = (Array.isArray(builds[i]) ? undefined : builds[i].cpu) ?? CPU.arm64;
    head.writeUInt32BE(cpu[0], o); head.writeUInt32BE(cpu[1], o + 4);
    if (is64) { head.writeBigUInt64BE(BigInt(at), o + 8); head.writeBigUInt64BE(BigInt(b.length), o + 16); head.writeUInt32BE(4, o + 24); } else { head.writeUInt32BE(at, o + 8); head.writeUInt32BE(b.length, o + 12); head.writeUInt32BE(4, o + 16); }
    const pad = at - out.reduce((n, x) => n + x.length, 0);
    out.push(Buffer.alloc(pad, 0x90), b); at += b.length + 16;
  });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, Buffer.concat(out), { mode: 0o755 });
  return path;
}

test('one file, every decoder it uses: each build of a universal file, and the libraries a file with a table links too', () => {
  const d = fresh('rule1-more');
  const old = oldLib(join(d, 'old', 'libbrotlidec.1.dylib'), { type: 6 }), good = fixedLib(join(d, 'new', 'libbrotlidec.1.dylib'), { type: 6 });
  // a universal file: one build with a fixed table, the other with no table, linking an unfixed library. Counted over
  // the whole file, the one table read SAFE; the loader maps one build, so each is judged
  for (const is64 of [false, true]) {
    const mixed = judge(fat(join(d, `fat-mixed-${is64}`), [[CONTROL, MARKER], { parts: [], links: [old] }], { is64 }));
    assert.equal(mixed.status, 'EXPOSED', `fat${is64 ? ' 64' : ''}`); assert.match(mixed.reason, /lacks the fix.*one of the 2 builds/);
    const twin = judge(fat(join(d, `fat-twin-${is64}`), [[CONTROL, MARKER], { parts: [], links: [good] }], { is64 }));
    assert.equal(twin.status, 'SAFE'); assert.ok(twin.searched.includes(good), 'the receipt names the library the other build uses');
  }
  // the universal node from nodejs.org holds one table per build: SAFE; one build fixed and one not: EXPOSED
  assert.equal(judge(fat(join(d, 'fat-node'), [[CONTROL, MARKER], [CONTROL, MARKER]])).status, 'SAFE');
  assert.equal(judge(fat(join(d, 'fat-half'), [[CONTROL, MARKER], [CONTROL]])).status, 'EXPOSED');
  // one build with nothing to judge: UNKNOWN, and never the shim's REVIEW
  const blank = judge(fat(join(d, 'fat-blank'), [[CONTROL, MARKER], ['nothing']]));
  assert.equal(blank.status, 'UNKNOWN'); assert.match(blank.reason, /one of the 2 builds.*could not be tested/);
  // a universal header that doesn't fit the file: UNKNOWN
  const broken = fat(join(d, 'fat-broken'), [[CONTROL, MARKER]]);
  const b = readFileSync(broken); b.writeUInt32BE(b.length * 2, 8 + 12); writeFileSync(broken, b);
  assert.match(judge(broken).reason, /universal.*could not be read/);
  // a fixed table in a file that also links an unfixed library: the library is used too, EXPOSED
  const both = judge(bin(join(d, 'table-and-old'), [CONTROL, MARKER], { links: [old] }));
  assert.equal(both.status, 'EXPOSED'); assert.match(both.reason, /its own Brotli decoder has the fix, but it uses .*old\/libbrotlidec\.1\.dylib/);
  const bothGood = judge(bin(join(d, 'table-and-new'), [CONTROL, MARKER], { links: [good] }));
  assert.equal(bothGood.status, 'SAFE'); assert.deepEqual(bothGood.searched, [join(d, 'table-and-new'), good]);
  // every library it links is followed, however many: 70 links to the fixed one, then the unfixed one, which is followed
  // too. Since round 10 (rule 2) every Brotli library a link in the closure reaches is a candidate for every Brotli link
  // (a loader may hand a link a copy already loaded), so the two disagree: UNKNOWN (rounds 5 to 9: EXPOSED); 70 links to
  // the unfixed one EXPOSED; and copies of a name it links, in its strings, are that link (round 5 read past 64 mentions
  // as UNKNOWN)
  const copies = (n, f = good) => Array.from({ length: n }, () => f);
  assert.equal(judge(bin(join(d, 'table-many'), [CONTROL, MARKER], { links: [...copies(70), old] })).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'table-many-old'), [CONTROL, MARKER], { links: copies(70, old) })).status, 'EXPOSED');
  assert.equal(judge(bin(join(d, 'table-many-new'), [CONTROL, MARKER], { links: copies(70) })).status, 'SAFE', 'the clean twin');
  assert.equal(judge(bin(join(d, 'table-copies'), [CONTROL, MARKER, ...copies(70)], { links: [good] })).status, 'SAFE');
  // a name in its strings that is not a link: "libbrotlidec mention 0" names no file the loader loads, SAFE (round 5
  // read it UNKNOWN); a library's path behind a control byte is a name it may load, UNKNOWN
  assert.equal(judge(bin(join(d, 'table-text'), [CONTROL, MARKER, ...Array.from({ length: 10 }, (_, i) => `libbrotlidec mention ${i}`)], { links: [good] })).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'table-cut'), [CONTROL, MARKER, Buffer.from(`\0\x01${old}\0`)], { links: [good] })).status, 'UNKNOWN');
  // a decoder library's own install name is not a link: still SAFE by its table (its own names: the A-self-wide test)
  assert.equal(judge(fixedLib(join(d, 'self', 'libbrotlidec.1.2.1.dylib'), { type: 6, id: '/DLC/PIL/.dylibs/libbrotlidec.1.2.1.dylib' })).status, 'SAFE');
  // a fixed 1.1-form table beside a 1.0-form name that is no whole table (Brotli 1.0's error texts have no prefix):
  // never SAFE on the 1.1 marker
  const mix = judge(bin(join(d, 'two-forms'), [CONTROL, MARKER, 'BLOCK_LENGTH_1']));
  assert.equal(mix.status, 'UNKNOWN'); assert.match(mix.reason, /form Brotli 1\.0 writes them.*could not be tested/);
  assert.equal(judge(bin(join(d, 'one-form'), [CONTROL, MARKER, 'BLOCK_LENGTH'])).status, 'SAFE', 'the clean twin');
  // a 1.0-form name alone is no table: UNKNOWN with the reason (the 1.0 form's tests are below)
  const only = judge(bin(join(d, 'old-form'), ['SUCCESS', 'BLOCK_LENGTH_1']));
  assert.equal(only.status, 'UNKNOWN'); assert.match(only.reason, /form Brotli 1\.0 writes them, but not as a whole table in Brotli's order.*could not be tested/);
});

test('a universal file whose every build lacks the fix is EXPOSED in that build\'s own words, and its package version can still be read; one build of two says so', () => {
  const d = fresh('fat-all');
  const lacks = judge(oldLib(join(d, 'thin'))).reason;
  for (const is64 of [false, true]) {
    // every build without the marker: the build's own reason, never "in one of the 2 builds", which would say the other
    // build has the fix; and noMarker kept, so a distribution's library goes on to its package version
    const all = judgeFile(fat(join(d, `fat-old-${is64}`), [[CONTROL], [CONTROL]], { is64 }), { markers: M });
    assert.equal(all.status, 'EXPOSED'); assert.equal(all.reason, lacks); assert.equal(all.noMarker, true);
    // the twin of one fixed build and one without: EXPOSED, saying it is one of the two, and no package version speaks
    const one = judgeFile(fat(join(d, `fat-one-${is64}`), [[CONTROL, MARKER], [CONTROL]], { is64 }), { markers: M });
    assert.equal(one.status, 'EXPOSED'); assert.equal(one.reason, `${lacks} (in one of the 2 builds this universal file holds)`); assert.equal(one.noMarker, undefined);
    // and the clean twin, both fixed
    assert.equal(judge(fat(join(d, `fat-new-${is64}`), [[CONTROL, MARKER], [CONTROL, MARKER]], { is64 })).status, 'SAFE');
  }
});

// Brotli 1.0's error table as a library holds it: BrotliDecoderErrorString's strings with no prefix (1.0.x has
// `return #NAME;`, 1.1.0 on `return #PREFIX #NAME;`), one NUL after each, in decode.h's order (as clang lays them out:
// checked by compiling 1.0.9's and 1.0.10's lists; and as GCC does in Debian 12's libbrotli1, below). 1.0.10, the fix on
// the 1.0 line, added BLOCK_SWITCH (code -17) right after DISTANCE (-16), before DICTIONARY_NOT_SET (-19). 1.0.0 to 1.0.2
// had COMPOUND_DICTIONARY (-18) where DISTANCE is, and 1.0.3 both, DISTANCE then COMPOUND_DICTIONARY (decode.h at v1.0.3)
const T10_HEAD = ['NO_ERROR', 'SUCCESS', 'NEEDS_MORE_INPUT', 'NEEDS_MORE_OUTPUT', 'EXUBERANT_NIBBLE', 'RESERVED', 'EXUBERANT_META_NIBBLE', 'SIMPLE_HUFFMAN_ALPHABET', 'SIMPLE_HUFFMAN_SAME', 'CL_SPACE', 'HUFFMAN_SPACE', 'CONTEXT_MAP_REPEAT', 'BLOCK_LENGTH_1', 'BLOCK_LENGTH_2', 'TRANSFORM', 'DICTIONARY', 'WINDOW_BITS', 'PADDING_1', 'PADDING_2'];
const T10_TAIL = ['DICTIONARY_NOT_SET', 'INVALID_ARGUMENTS', 'CONTEXT_MODES', 'TREE_GROUPS', 'CONTEXT_MAP', 'RING_BUFFER_1', 'RING_BUFFER_2', 'BLOCK_TYPE_TREES', 'UNREACHABLE', 'INVALID'];
const V109 = [...T10_HEAD, 'DISTANCE', ...T10_TAIL], V1010 = [...T10_HEAD, 'DISTANCE', 'BLOCK_SWITCH', ...T10_TAIL];
const V102 = [...T10_HEAD, 'COMPOUND_DICTIONARY', ...T10_TAIL], V103 = [...T10_HEAD, 'DISTANCE', 'COMPOUND_DICTIONARY', ...T10_TAIL];
/** Strings as a compiler packs them: a NUL after each, and NULs after that up to `align` bytes (a compiler that aligns
 *  each string, as GCC does on some targets). */
const packed = (names, align = 1) => Buffer.concat([Buffer.alloc(1), ...names.map((n) => { const b = Buffer.from(`${n}\0`); return Buffer.concat([b, Buffer.alloc((align - (b.length % align)) % align)]); })]);

// Brotli 1.0's form is judged (maintainer, 2026-10-25)
test('Brotli 1.0\'s form: a whole table in Brotli\'s order decides; 1.0.9 is EXPOSED, 1.0.10 SAFE', () => {
  const d = fresh('form10');
  // packed or padded, in decode.h's order or the other way round (by code), Mach-O or ELF
  for (const align of [1, 8, 16]) {
    for (const [order, way] of [['listed', (x) => x], ['by-code', (x) => [...x].reverse()]]) {
      for (const [kind, make] of [['macho', bin], ['elf', elf]]) {
        const at = `${kind}-${order}-${align}`;
        const bad = judge(make(join(d, `libbrotlidec-109-${at}.so.1`), [packed(way(V109), align)]));
        assert.equal(bad.status, 'EXPOSED', `1.0.9 ${at}`); assert.match(bad.reason, /lacks the fix.*form Brotli 1\.0 writes them/, at);
        // 1.0.3, the first affected release: DISTANCE, then COMPOUND_DICTIONARY, then DICTIONARY_NOT_SET
        const first = judge(make(join(d, `libbrotlidec-103-${at}.so.1`), [packed(way(V103), align)]));
        assert.equal(first.status, 'EXPOSED', `1.0.3 ${at}`); assert.match(first.reason, /lacks the fix.*form Brotli 1\.0 writes them/, at);
        // the clean twin: 1.0.10
        const good = judge(make(join(d, `libbrotlidec-1010-${at}.so.1`), [packed(way(V1010), align)]));
        assert.equal(good.status, 'SAFE', `1.0.10 ${at}`); assert.match(good.reason, /has the fix.*form Brotli 1\.0 writes them/, at);
      }
    }
  }
  // a program with 1.0.9 built in (a Brotli binding's own copy), and one that links a 1.0.9 library: EXPOSED; twins SAFE
  const old = bin(join(d, 'lib', 'libbrotlidec.1.dylib'), [packed(V109)], { type: 6 });
  assert.equal(judge(bin(join(d, '_brotli.so'), [packed(V109)], { type: 8 })).status, 'EXPOSED');
  assert.equal(judge(bin(join(d, 'prog'), [], { links: [old] })).status, 'EXPOSED');
  bin(old, [packed(V1010)], { type: 6 });
  assert.equal(judge(bin(join(d, 'prog'), [], { links: [old] })).status, 'SAFE');
  assert.equal(judge(bin(join(d, '_brotli.so'), [packed(V1010)])).status, 'SAFE');
  // and beside the 1.1 form: a fixed 1.1 table with an unfixed 1.0 one is EXPOSED (one decoder lacks the fix), with a
  // fixed one SAFE; an unfixed 1.1 table is EXPOSED whatever the 1.0 one says
  const both = judge(bin(join(d, 'both-old'), [CONTROL, MARKER, packed(V109)]));
  assert.equal(both.status, 'EXPOSED'); assert.match(both.reason, /more than one Brotli decoder/);
  assert.equal(judge(bin(join(d, 'both-103'), [CONTROL, MARKER, packed(V103)])).status, 'EXPOSED');
  assert.equal(judge(bin(join(d, 'both-new'), [CONTROL, MARKER, packed(V1010)])).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'new-old'), [CONTROL, packed(V1010)])).status, 'EXPOSED');
  // a fixed 1.0 table in a file that also links an unfixed library: that library is used too, EXPOSED; a link it can't
  // follow (@rpath with no LC_RPATH to find it by), or a name it may load, UNKNOWN; the clean twin links a fixed one
  const unfixed = oldLib(join(d, 'lib11', 'libbrotlidec.1.dylib'), { type: 6 }), fixed = fixedLib(join(d, 'lib12', 'libbrotlidec.1.dylib'), { type: 6 });
  const linked = judge(bin(join(d, 'old10-links-old'), [packed(V1010)], { links: [unfixed] }));
  assert.equal(linked.status, 'EXPOSED'); assert.match(linked.reason, /its own Brotli decoder has the fix, but it uses .*lib11/);
  assert.equal(judge(bin(join(d, 'old10-links-rpath'), [packed(V1010)], { links: ['@rpath/libbrotlidec.1.dylib'] })).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'old10-dlopen'), [packed(V1010), 'libbrotlidec.so.1'], { links: [fixed] })).status, 'UNKNOWN');
  const twin = judge(bin(join(d, 'old10-links-new'), [packed(V1010)], { links: [fixed] }));
  assert.equal(twin.status, 'SAFE'); assert.deepEqual(twin.searched, [join(d, 'old10-links-new'), fixed]);
});

test('Brotli 1.0\'s form, near misses: names scattered, out of order, alone, or the fix\'s name away from its place are UNKNOWN, never SAFE', () => {
  const d = fresh('form10-near');
  const swap = (x, a, b) => { const y = [...x], i = y.indexOf(a), j = y.indexOf(b); [y[i], y[j]] = [y[j], y[i]]; return y; };
  for (const [name, parts] of [
    ['scattered', V1010.map((n) => packed([n, 'some other text']))],
    ['out-of-order', [packed(swap(V1010, 'BLOCK_LENGTH_2', 'TRANSFORM'))]],
    ['marker-out-of-order', [packed(swap(V1010, 'BLOCK_SWITCH', 'DICTIONARY_NOT_SET'))]],
    ['shuffled', [packed([...V1010].sort())]],
    ['anchor-alone', [packed(['BLOCK_LENGTH_1'])]],
    ['anchor-and-marker', [packed(['BLOCK_LENGTH_1', 'BLOCK_SWITCH'])]],
    ['half-a-run', [packed(T10_HEAD), packed(['some other text', 'DISTANCE', 'BLOCK_SWITCH', 'DICTIONARY_NOT_SET'])]],
    // the names after the control's in order, but not the ones before it
    ['no-earlier', [packed(['some other text', ...V1010.slice(V1010.indexOf('BLOCK_LENGTH_1'))])]],
    // the fix's name in its place, but not followed by the next name of the table
    ['marker-not-followed', [packed([...T10_HEAD, 'DISTANCE', 'BLOCK_SWITCH', 'some other text'])]],
    // an unfixed table with the fix's name elsewhere in the file: a stray copy never counts, and the table's own may have
    // been moved there by the linker, so it is not EXPOSED either
    ['old-and-stray-marker', [packed(V109), packed(['some other text', 'BLOCK_SWITCH'])]],
    // a fixed table and a second copy of the table's name that is in no table
    ['new-and-stray-anchor', [packed(V1010), packed(['some other text', 'BLOCK_LENGTH_1'])]],
    // more NULs between two names than a compiler's alignment pads with
    ['wide-gap', [Buffer.concat([packed(V1010.slice(0, 13)), Buffer.alloc(40), packed(V1010.slice(13))])]],
    // 1.0.0 to 1.0.2 (no DISTANCE yet: not affected, and not judged)
    ['1.0.2', [packed(V102)]],
    // 1.0.3's run, near misses: COMPOUND_DICTIONARY not followed by DICTIONARY_NOT_SET, twice, before DISTANCE, with the
    // fix's name beside it (either side), or DISTANCE alone after it
    ['1.0.3-not-followed', [packed([...T10_HEAD, 'DISTANCE', 'COMPOUND_DICTIONARY', 'some other text'])]],
    ['1.0.3-twice', [packed([...T10_HEAD, 'DISTANCE', 'COMPOUND_DICTIONARY', 'COMPOUND_DICTIONARY', ...T10_TAIL])]],
    ['1.0.3-before-distance', [packed([...T10_HEAD, 'COMPOUND_DICTIONARY', 'DISTANCE', ...T10_TAIL])]],
    ['1.0.3-and-marker', [packed([...T10_HEAD, 'DISTANCE', 'COMPOUND_DICTIONARY', 'BLOCK_SWITCH', ...T10_TAIL])]],
    ['marker-and-1.0.3', [packed([...T10_HEAD, 'DISTANCE', 'BLOCK_SWITCH', 'COMPOUND_DICTIONARY', ...T10_TAIL])]],
    ['1.0.3-run-cut', [packed([...T10_HEAD, 'DISTANCE', 'COMPOUND_DICTIONARY'])]],
    // more copies of the table than are kept (64): the ones past them are not read, and an unfixed one could be there
    ['crowded', [...Array.from({ length: 64 }, () => packed(V1010)), packed(V109)]],
  ]) {
    const r = judge(bin(join(d, name), parts));
    assert.equal(r.status, 'UNKNOWN', name); assert.match(r.reason, /form Brotli 1\.0 writes them.*could not be tested/, name);
  }
  // the last name cut by the end of the file (no NUL after it): not seen whole, so not the table's
  const cutEnd = join(d, 'cut-by-the-end');
  writeFileSync(cutEnd, Buffer.concat([MACHO, packed(V1010.slice(0, V1010.indexOf('DICTIONARY_NOT_SET'))), Buffer.from('DICTIONARY_NOT_SET')]));
  assert.equal(judge(cutEnd).status, 'UNKNOWN');
  // the clean twins: the whole table, packed or padded by 2 (separate C strings)
  assert.equal(judge(bin(join(d, 'whole'), [packed(V1010)])).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'whole-separate'), V1010)).status, 'SAFE');
  // a stray BLOCK_SWITCH beside the 1.1 form only is no 1.0 table: the 1.1 table decides
  assert.equal(judge(bin(join(d, 'stray-11-new'), [CONTROL, MARKER, packed(['BLOCK_SWITCH'])])).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'stray-11-old'), [CONTROL, packed(['BLOCK_SWITCH'])])).status, 'EXPOSED');
});

test('Brotli 1.0\'s form is read in linear time: 1 MB of hostile table names', () => {
  const d = fresh('form10-time');
  for (const [name, body] of [
    ['anchors', Buffer.from('\0BLOCK_LENGTH_1'.repeat(70000))],
    ['runs', Buffer.concat(Array.from({ length: 4000 }, () => packed([...T10_HEAD, 'DISTANCE'])))],
    ['nul-gaps', Buffer.concat(Array.from({ length: 33000 }, () => Buffer.concat([Buffer.from('\0BLOCK_LENGTH_1'), Buffer.alloc(16)])))],
  ]) {
    const f = join(d, name);
    writeFileSync(f, Buffer.concat([MACHO, body]));
    assert.ok(body.length >= 1e6, `${name}: ${body.length} bytes`);
    const t = Date.now();
    const r = judge(f);
    assert.ok(Date.now() - t < 3000, `${name}: ${Date.now() - t} ms`);
    assert.equal(r.status, 'UNKNOWN', name);
  }
});

test('the incident\'s 1.0 form: plain names, the anchor and the marker among them as the 1.1 names say', () => {
  // without a run, or with one that lacks the control's name, no copy is read as a table (an empty run would match any)
  const f = bin(join(fresh('form10-norun'), 'x'), [packed(['BLOCK_LENGTH_1', 'BLOCK_SWITCH'])]);
  for (const markers of [{ ...M, table10: undefined, after10: undefined }, { ...M, table10: ['HUFFMAN_SPACE'] }]) assert.deepEqual(evidence(f, markers).t10, { fixed: 0, unfixed: 0, other: 1 });
  const t = INC.markers.table10, strip = (s) => s.replace(/^_ERROR_FORMAT_/, '');
  assert.ok(Array.isArray(t) && t.length >= 4 && t.every((n) => /^[A-Z0-9_]+$/.test(n)));
  assert.ok(t.includes(strip(CONTROL)) && !t.includes(strip(MARKER)), 'the run holds the control\'s name, not the marker\'s');
  assert.match(INC.markers.after10, /^[A-Z0-9_]+$/);
  // the run is decode.h's order, right before the place of the fix's name
  const at = V1010.indexOf(t[0]);
  assert.deepEqual(V1010.slice(at, at + t.length + 2), [...t, strip(MARKER), INC.markers.after10]);
  // what sits between the run and after10 in a table without the fix: nothing (1.0.4 to 1.0.9) and 1.0.3's
  // COMPOUND_DICTIONARY, plain names, never the fix's name, the control's or after10
  const u = INC.markers.unfixed10;
  assert.ok(Array.isArray(u) && u.every((x) => Array.isArray(x) && x.every((n) => /^[A-Z0-9_]+$/.test(n) && ![strip(MARKER), strip(CONTROL), INC.markers.after10].includes(n))));
  for (const v of [V109, V103]) { const i = v.indexOf(t[0]); assert.ok(u.some((x) => JSON.stringify(v.slice(i, i + t.length + x.length + 1)) === JSON.stringify([...t, ...x, INC.markers.after10]))); }
  // without unfixed10 (an incident written before it), only 1.0.4 to 1.0.9's table is read as one without the fix
  const f103 = bin(join(fresh('form10-no-unfixed10'), 'x'), [packed(V103)]);
  assert.deepEqual(evidence(f103, { ...M, unfixed10: undefined }).t10, { fixed: 0, unfixed: 0, other: 1 });
  assert.deepEqual(evidence(f103, M).t10, { fixed: 0, unfixed: 1, other: 0 });
});

test('names lie: a file named 1.2.1 without the marker is EXPOSED, one named 1.2.0 with it is SAFE', () => {
  const d = fresh('names');
  assert.equal(judge(oldLib(join(d, 'libbrotlidec.1.2.1.dylib'))).status, 'EXPOSED');
  assert.equal(judge(fixedLib(join(d, 'libbrotlidec.1.2.0.dylib'))).status, 'SAFE');
});

test('exact, NUL-delimited matching: the marker inside a longer string never counts as the fix', () => {
  const d = fresh('exact');
  // an unfixed table, plus strings that contain the marker without being it: a substring search would read SAFE
  for (const [name, decoy] of [['node-constant', NODE_MARKER], ['longer', `${MARKER}ED`], ['prefixed', `X${MARKER}`], ['no-nul-after', Buffer.from(`\0${MARKER}X`)]]) {
    const f = bin(join(d, name), ['_SUCCESS', CONTROL, decoy]);
    assert.equal(evidence(f, M).m0, 0, name);
    assert.equal(judge(f).status, 'EXPOSED', `${name}: the decoy is not the fix`);
  }
  // and the control inside a longer string is not a table
  const ctl = bin(join(d, 'control-in-name'), [NODE_CONTROL, `X${CONTROL}`]);
  assert.equal(evidence(ctl, M).c0, 0);
  assert.equal(judge(ctl).status, 'UNKNOWN');
});

test('the Node constant-name trap (Homebrew libnode): the names never decide; the library it links does, or it is UNKNOWN', () => {
  const d = fresh('trap');
  oldLib(join(d, 'old', 'libbrotlidec.1.dylib'), { type: 6 }); fixedLib(join(d, 'new', 'libbrotlidec.1.dylib'), { type: 6 });
  // what Homebrew's libnode holds: zlib.constants names compiled from the header, a link to Homebrew's library, no table
  const names = [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v26.12.1'];
  const ev = evidence(bin(join(d, 'old-node'), names, { links: [join(d, 'old', 'libbrotlidec.1.dylib')] }), M);
  assert.equal(ev.m0, 0, 'a substring search would have counted the constant name as the marker');
  assert.equal(ev.mk, 1);
  const bad = judge(join(d, 'old-node'));
  assert.equal(bad.status, 'EXPOSED', 'the library it loads decides, not the header it was built with');
  assert.match(bad.reason, /it uses .*old\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix/);
  const good = judge(bin(join(d, 'new-node'), names, { links: [join(d, 'new', 'libbrotlidec.1.dylib')] }));
  assert.equal(good.status, 'SAFE');
  assert.deepEqual(good.searched, [join(d, 'new-node'), join(d, 'new', 'libbrotlidec.1.dylib')], 'the receipt names both files');
  // the names alone, no table and no link (a static Node whose table the linker merged into the names, or one built
  // against a newer header than its decoder): could not be tested, never SAFE, whichever names are there
  for (const [name, parts] of [['names-fixed', names], ['names-old', [NODE_CONTROL]]]) {
    const r = judge(bin(join(d, name), parts));
    assert.equal(r.status, 'UNKNOWN', name); assert.match(r.reason, /could not be tested/);
  }
  // and through the whole check, as node on PATH: UNKNOWN with the by-hand hint, not REVIEW (it is Node.js)
  const path = fresh('trap-path');
  bin(join(path, 'node'), names);
  const row = run({}, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node'));
  assert.equal(row.status, 'UNKNOWN'); assert.match(row.reason, /Check this one by hand/); assert.equal(row.version, '26.12.1');
});

test('a stripped or absent table is "could not be tested": node, bun, a Brotli binding, a bundled runtime', () => {
  const path = fresh('stripped-path');
  bin(join(path, 'node'), ['nodejs.org/download/release/v24.11.0', 'no table']);
  bin(join(path, 'bun'), ['no table']);
  const sp = fresh('stripped/site-packages');
  bin(join(sp, '_brotli.cpython-314-darwin.so'), ['no table']);
  mkdirSync(join(sp, 'brotli-1.1.0.dist-info'));
  writeFileSync(join(sp, 'brotli-1.1.0.dist-info', 'METADATA'), 'Name: Brotli\nVersion: 1.1.0\n');
  writeFileSync(join(sp, 'brotli-1.1.0.dist-info', 'RECORD'), '_brotli.cpython-314-darwin.so,,\n');
  bin(join(sp, 'examplepkg', 'driver', 'node'), ['nodejs.org/download/release/v24.17.0']);
  mkdirSync(join(sp, 'examplepkg-1.0.dist-info'));
  writeFileSync(join(sp, 'examplepkg-1.0.dist-info', 'RECORD'), 'examplepkg/driver/node,,\n');
  const { rows } = run({}, { pathEnv: path, siteDirs: [sp] });
  const by = (f) => rows.find((r) => r.file === f);
  for (const [f, hint] of [[join(path, 'node'), /22\.23\.4 or later on the 22 line, 24\.22\.1 or later on 24, 26\.12\.1 or later on 26 are fixed, and Node\.js 20 and older and the odd-numbered lines \(21, 23, 25\) get no fix/], [join(path, 'bun'), /1\.4\.4 or later.*1\.0\.21 to 1\.4\.3/], [join(sp, '_brotli.cpython-314-darwin.so'), /check the version of Brotli by hand/], [join(sp, 'examplepkg', 'driver', 'node'), /Node\.js 22\.23\.4/]]) {
    assert.equal(by(f).status, 'UNKNOWN', f); assert.match(by(f).reason, /could not be tested/); assert.match(by(f).reason, hint);
    assert.equal(by(f).fix, undefined, 'an UNKNOWN row gives its reason, not a fix');
  }
  // clean twin: the same places with fixed tables
  fixedLib(join(path, 'node')); fixedLib(join(path, 'bun')); fixedLib(join(sp, '_brotli.cpython-314-darwin.so')); fixedLib(join(sp, 'examplepkg', 'driver', 'node'));
  assert.deepEqual(run({}, { pathEnv: path, siteDirs: [sp] }).rows.map((r) => r.status), ['SAFE', 'SAFE', 'SAFE', 'SAFE']);
});

// What a file links is read as the loader reads it (decision #24): Mach-O load commands, the ELF dynamic table. Until
// round 6 a library was followed when its name sat in the file's bytes as a whole C string, and any other mention made
// the file UNKNOWN: nodejs.org's Node.js 26.12.1 for macOS read UNKNOWN for its debug map, Homebrew's node for its
// @rpath/libnode.147.dylib, and a load command's name offset could point past bytes the string scan read as the name.

test('Mach-O links, as dyld reads them: each command that loads a library; an absolute path, @loader_path, @executable_path in a program, @rpath through its own LC_RPATH in order; anything else UNKNOWN', () => {
  const d = fresh('macho-links');
  const fixed = fixedLib(join(d, 'new', 'libbrotlidec.1.dylib'), { type: 6 }), old = oldLib(join(d, 'old', 'libbrotlidec.1.dylib'), { type: 6 });
  // every command that loads a library, with and without LC_REQ_DYLD: an unfixed library behind it is EXPOSED beside a
  // fixed table; the clean twin links the fixed one
  for (const [name, cmd] of [['LC_LOAD_DYLIB', 0x0c], ['LC_LOAD_WEAK_DYLIB', 0x80000018], ['LC_REEXPORT_DYLIB', 0x8000001f], ['LC_LAZY_LOAD_DYLIB', 0x20], ['LC_LOAD_UPWARD_DYLIB', 0x80000023]]) {
    for (const c of [cmd, (cmd ^ 0x80000000) >>> 0]) {
      const bad = judge(bin(join(d, `${name}-${c}`), [CONTROL, MARKER], { links: ['/usr/lib/libSystem.B.dylib', { name: old, cmd: c }] }));
      assert.equal(bad.status, 'EXPOSED', `${name} ${c}`); assert.match(bad.reason, /^its own Brotli decoder has the fix, but it uses .*old\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix/);
      assert.equal(judge(bin(join(d, `${name}-${c}-twin`), [CONTROL, MARKER], { links: [{ name: fixed, cmd: c }] })).status, 'SAFE', `${name} ${c}: the clean twin`);
    }
  }
  // 32-bit and big-endian headers are read too
  for (const [bits, be] of [[32, false], [32, true], [64, true]]) {
    assert.equal(judge(bin(join(d, `head-${bits}-${be}`), [], { links: [old], bits, be })).status, 'EXPOSED', `${bits} ${be}`);
    assert.equal(judge(bin(join(d, `head-${bits}-${be}-twin`), [], { links: [fixed], bits, be })).status, 'SAFE', `${bits} ${be}: the clean twin`);
  }
  // @loader_path: beside the file (its real folder)
  const pkg = fresh('macho-links/pkg');
  fixedLib(join(pkg, 'libbrotlidec.1.2.1.dylib'), { type: 6 }); oldLib(join(pkg, 'libbrotlidec.1.2.0.dylib'), { type: 6 });
  assert.equal(judge(bin(join(pkg, 'libfreetype.6.dylib'), [], { type: 6, links: ['@loader_path/libbrotlidec.1.2.1.dylib'] })).status, 'SAFE');
  assert.equal(judge(bin(join(pkg, 'libfreetype.5.dylib'), [], { type: 6, links: ['@loader_path/libbrotlidec.1.2.0.dylib'] })).status, 'EXPOSED');
  // @executable_path: beside the file in a program (MH_EXECUTE); in a library or a bundle it is the program that loads
  // it, which isn't known
  assert.equal(judge(bin(join(pkg, 'prog-old'), [], { links: ['@executable_path/libbrotlidec.1.2.0.dylib'] })).status, 'EXPOSED');
  assert.equal(judge(bin(join(pkg, 'prog-new'), [], { links: ['@executable_path/libbrotlidec.1.2.1.dylib'] })).status, 'SAFE');
  for (const type of [6, 8]) {
    const r = judge(bin(join(pkg, `lib-exec-${type}`), [], { type, links: ['@executable_path/libbrotlidec.1.2.1.dylib'] }));
    assert.equal(r.status, 'UNKNOWN', `type ${type}`); assert.match(r.reason, /it links @executable_path\/libbrotlidec\.1\.2\.1\.dylib, which Wardlatch can't follow.*could not be tested/);
  }
  // @rpath: through the file's own LC_RPATH entries. Every folder that holds the library is a candidate, not just the
  // first (decision #25: every file of that name in a folder a loader may look in). The real attack, the first holding
  // an unfixed copy and the second a fixed one, and the other way round, which c2f3a13 read SAFE, the first deciding:
  // since round 9 a mix is UNKNOWN (rounds 7 and 8 read it EXPOSED, the unfixed copy deciding); both unfixed is EXPOSED
  const prog = join(d, 'app', 'bin', 'prog'), first = join(d, 'app', 'lib'), second = join(d, 'app', 'lib2');
  const rp = (rpaths, o = {}) => judge(bin(prog, [CONTROL, MARKER], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths, ...o }));
  const both = ['@loader_path/../lib', '@loader_path/../lib2'];
  oldLib(join(first, 'libbrotlidec.1.dylib'), { type: 6 }); fixedLib(join(second, 'libbrotlidec.1.dylib'), { type: 6 });
  const firstOld = rp(both);
  assert.equal(firstOld.status, 'UNKNOWN'); assert.equal(firstOld.via, realpathSync(join(first, 'libbrotlidec.1.dylib')));
  assert.match(firstOld.reason, /it links @rpath\/libbrotlidec\.1\.dylib, and the 2 files of that name in the folders a loader may look in are not all fixed or all unfixed \(.*lib2\/libbrotlidec\.1\.dylib has the fix, .*app\/lib\/libbrotlidec\.1\.dylib lacks it\).*could not be tested/);
  fixedLib(join(first, 'libbrotlidec.1.dylib'), { type: 6 }); oldLib(join(second, 'libbrotlidec.1.dylib'), { type: 6 });
  const secondOld = rp(both);
  assert.equal(secondOld.status, 'UNKNOWN', secondOld.reason); assert.equal(secondOld.via, realpathSync(join(second, 'libbrotlidec.1.dylib')));
  oldLib(join(first, 'libbrotlidec.1.dylib'), { type: 6 });
  const bothOld = rp(both);
  assert.equal(bothOld.status, 'EXPOSED', bothOld.reason); assert.equal(bothOld.via, realpathSync(join(first, 'libbrotlidec.1.dylib')));
  assert.match(bothOld.reason, /it uses .*app\/lib\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix; or it uses .*lib2\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix: every file of that name a loader may take lacks the fix/);
  fixedLib(join(first, 'libbrotlidec.1.dylib'), { type: 6 }); fixedLib(join(second, 'libbrotlidec.1.dylib'), { type: 6 });
  const bothNew = rp(both);
  assert.equal(bothNew.status, 'SAFE', bothNew.reason); assert.deepEqual(bothNew.searched, [prog, realpathSync(join(first, 'libbrotlidec.1.dylib')), realpathSync(join(second, 'libbrotlidec.1.dylib'))]);
  oldLib(join(second, 'libbrotlidec.1.dylib'), { type: 6 });
  // only in the second folder: it decides; an absolute LC_RPATH, @loader_path alone, @executable_path in a program
  rmSync(join(first, 'libbrotlidec.1.dylib'));
  assert.equal(rp(both).status, 'EXPOSED');
  fixedLib(join(second, 'libbrotlidec.1.dylib'), { type: 6 });
  assert.equal(rp(both).status, 'SAFE');
  for (const entries of [[second], ['@executable_path/../lib2'], ['@loader_path/../lib', '/nowhere/lib', second]]) assert.equal(rp(entries).status, 'SAFE', entries.join());
  fixedLib(join(dirname(prog), 'libbrotlidec.1.dylib'), { type: 6 });
  assert.equal(rp(['@loader_path']).status, 'SAFE');
  // what can't be followed or isn't there: UNKNOWN, named
  for (const [entries, o, says] of [[[], {}, /it links @rpath\/libbrotlidec\.1\.dylib, which was not found, so/],
    [['/nowhere/lib'], {}, /which was not found \(looked in \/nowhere\/lib\)/],
    [['lib2'], {}, /looks for it in 'lib2', a folder named by a relative path/],
    [['@executable_path/../lib2'], { type: 6 }, /can't follow or open \(through '@executable_path\/\.\.\/lib2'\)/],
    [['@other/lib2'], {}, /can't follow or open \(through '@other\/lib2'\)/]]) {
    const r = rp(entries, o);
    assert.equal(r.status, 'UNKNOWN', entries.join()); assert.match(r.reason, says, entries.join()); assert.match(r.reason, /could not be tested/);
  }
  // a bare name and a relative path: dyld looks for them from the folder the program is started in
  for (const ref of ['libbrotlidec.1.dylib', 'lib/libbrotlidec.1.dylib', '../lib/libbrotlidec.1.dylib', 'José/lib/libbrotlidec.1.2.0.dylib']) {
    const r = judge(bin(join(d, `rel-${ref.length}`), [CONTROL, MARKER], { links: [ref] }));
    assert.equal(r.status, 'UNKNOWN', ref); assert.ok(r.reason.includes(`it links ${ref}, a relative path`), r.reason);
  }
  const missing = judge(bin(join(d, 'missing'), [], { links: [join(d, 'nowhere', 'libbrotlidec.1.dylib')] }));
  assert.equal(missing.status, 'UNKNOWN'); assert.match(missing.reason, /was not found/);
  // a linked library that links a Brotli library or libnode of its own is not followed past the one level read
  const nested = bin(join(d, 'nested', 'libbrotlidec.1.dylib'), [CONTROL, MARKER], { type: 6, links: [fixed] });
  const n = judge(bin(join(d, 'nested', 'prog'), [], { links: [nested] }));
  assert.equal(n.status, 'UNKNOWN'); assert.match(n.reason, /for that library: its own Brotli decoder has the fix, but it links .*new\/libbrotlidec\.1\.dylib, a Brotli library or libnode of its own, which Wardlatch doesn't follow/);
  fixedLib(nested, { type: 6, links: ['/usr/lib/libSystem.B.dylib'] });
  assert.equal(judge(join(d, 'nested', 'prog')).status, 'SAFE', 'the clean twin: it links no Brotli library');
  // what counts as a Brotli library or libnode a file links: its file name, in any case
  for (const s of ['/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib', '@loader_path/libbrotlidec.1.2.0.dylib', 'libbrotlidec.so.1', 'libbrotlidec-ba690955.so.1.0.9', '@rpath/LibBrotliDec.1.dylib']) assert.ok(isDecoderLibName(s), s);
  for (const s of ['libbrotlienc.1.dylib', 'libbrotlicommon.so.1', '/opt/libbrotlidec/lib/libz.1.dylib']) assert.ok(!isDecoderLibName(s), s);
  for (const s of ['libnode.so.108', '@rpath/libnode.147.dylib', '/usr/lib/x86_64-linux-gnu/libnode.so.115', 'libnode.dylib', 'LIBNODE.147.DYLIB']) assert.ok(isNodeLibName(s), s);
  for (const s of ['libnodejs.so.1', 'libnodelet.so', '/opt/libnode/lib/libuv.1.dylib']) assert.ok(!isNodeLibName(s), s);
});

test('a universal node with LC_RPATH and @rpath/libnode, laid out as Homebrew\'s: each build follows its own LC_RPATH to libnode, which is judged', () => {
  const brew = fresh('brew'), cellar = join(brew, 'Cellar', 'node', '26.12.1'), opt = join(brew, 'opt', 'brotli', 'lib');
  const dec = fixedLib(join(opt, 'libbrotlidec.1.dylib'), { type: 6, id: join(opt, 'libbrotlidec.1.dylib') });
  const old = oldLib(join(brew, 'old', 'libbrotlidec.1.dylib'), { type: 6 });
  const libnode = join(cellar, 'lib', 'libnode.147.dylib'), node = join(cellar, 'bin', 'node');
  // Homebrew's libnode: its install name, the zlib constant names, Homebrew's Brotli library, no table of its own
  const makeLibnode = (decoder) => bin(libnode, [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v26.12.1'], { type: 6, id: join(brew, 'opt', 'node', 'lib', 'libnode.147.dylib'), links: ['/usr/lib/libz.1.dylib', decoder] });
  // Homebrew's node: LC_RPATH @loader_path and @loader_path/../lib, @rpath/libnode.147.dylib and Homebrew's Brotli library
  const build = (o = {}) => ({ parts: [], rpaths: ['@loader_path', '@loader_path/../lib'], links: ['@rpath/libnode.147.dylib', '/usr/lib/libz.1.dylib', dec], ...o });
  makeLibnode(dec);
  for (const is64 of [false, true]) {
    fat(node, [build(), build()], { is64 });
    const good = judge(node);
    assert.equal(good.status, 'SAFE', good.reason); assert.deepEqual(good.searched, [node, dec, realpathSync(libnode)]);
    assert.match(good.reason, /it uses .*Cellar\/node\/26\.12\.1\/lib\/libnode\.147\.dylib, the library that holds Node\.js's code: it uses .*opt\/brotli\/lib\/libbrotlidec\.1\.dylib, whose Brotli decoder has the fix/);
  }
  // libnode using an unfixed Brotli library, beside the node's own link to the fixed one: since round 10 (rule 2) each
  // is a candidate for the other's link (dyld may hand a link an image already loaded under that install name), a mix,
  // UNKNOWN (round 9: EXPOSED); a node that links no Brotli library itself: EXPOSED, through libnode
  makeLibnode(old);
  const mixed = judge(node);
  assert.equal(mixed.status, 'UNKNOWN', mixed.reason); assert.match(mixed.reason, /are not all fixed or all unfixed/);
  const own = (o = {}) => build({ links: ['@rpath/libnode.147.dylib', '/usr/lib/libz.1.dylib'], ...o });
  fat(node, [own(), own()]);
  const bad = judge(node);
  assert.equal(bad.status, 'EXPOSED'); assert.match(bad.reason, /libnode\.147\.dylib, the library that holds Node\.js's code: it uses .*old\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix/);
  // one build without its LC_RPATH: the folders a file's builds name are one set (decision #25: every folder the file's
  // own paths name), so that build's @rpath/libnode is looked for in the other build's LC_RPATH folders too, and found
  // (round 8 read it UNKNOWN, not found from that build); with neither build naming one, UNKNOWN, saying which
  makeLibnode(dec);
  for (const builds of [[build(), build({ rpaths: [] })], [build({ rpaths: [] }), build()]]) {
    fat(node, builds);
    assert.equal(judge(node).status, 'SAFE');
  }
  fat(node, [build({ rpaths: [] }), build({ rpaths: [] })]);
  const half = judge(node);
  assert.equal(half.status, 'UNKNOWN'); assert.match(half.reason, /it links @rpath\/libnode\.147\.dylib, the library that holds Node\.js's code, which was not found/);
  // through the check, as Homebrew puts it on PATH (bin/node, a link to the Cellar's): @loader_path is its real folder
  fat(node, [own(), own()]);
  const path = join(brew, 'bin');
  mkdirSync(path, { recursive: true }); symlinkSync(node, join(path, 'node'));
  const row = () => run({}, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node'));
  assert.equal(row().status, 'SAFE');
  makeLibnode(old);
  const r = row();
  assert.equal(r.status, 'EXPOSED'); assert.equal(r.via, old); assert.match(r.fix, /^It uses .*old\/libbrotlidec\.1\.dylib, so it is fixed by updating that library, not Node\.js/);
});

test('ELF links, as ld.so reads them: DT_NEEDED through DT_RUNPATH $ORIGIN/../lib (DT_RPATH only without one), then the system\'s folders; a name with a slash as it is', () => {
  const root = fresh('elf-links'), sys = fresh('elf-links-sys'), sys2 = fresh('elf-links-sys2');
  // a program laid out as conda's, Linuxbrew's or a wheel's: bin/prog with DT_RUNPATH $ORIGIN/../lib, its library in lib
  const lib = join(root, 'lib', 'libbrotlidec.so.1'), prog = join(root, 'bin', 'prog');
  const make = (o) => elf(prog, [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], ...o });
  // the system's copy is a candidate too, whatever the program's own folder holds (decision #25: no copy stops the
  // search); with the system's copy fixed too, SAFE, both named
  fixedLib(join(sys, 'libbrotlidec.so.1'));
  for (const [bits, be] of [[64, false], [32, false], [64, true], [32, true]]) {
    fixedLib(lib, { bits, be });
    for (const runpath of ['$ORIGIN/../lib', '${ORIGIN}/../lib', '/nowhere:$ORIGIN/../lib']) {
      make({ runpath, bits, be });
      const good = judge(prog, [sys]);
      assert.equal(good.status, 'SAFE', `${bits} ${be} ${runpath}: ${good.reason}`); assert.deepEqual(good.searched, [prog, realpathSync(lib), join(sys, 'libbrotlidec.so.1')]);
    }
    oldLib(lib, { bits, be });
    make({ runpath: '$ORIGIN/../lib', bits, be });
    assert.equal(judge(prog, [sys]).status, 'UNKNOWN', `${bits} ${be}: the program's copy unfixed, the system's fixed`);
  }
  // an unfixed system copy beside the program's fixed one: UNKNOWN (round 8: SAFE, the program's own DT_RUNPATH copy
  // stopped the search); both unfixed, EXPOSED
  fixedLib(lib); oldLib(join(sys, 'libbrotlidec.so.1'));
  make({ runpath: '$ORIGIN/../lib' });
  assert.equal(judge(prog, [sys]).status, 'UNKNOWN');
  oldLib(lib);
  assert.equal(judge(prog, [sys]).status, 'EXPOSED');
  // DT_RPATH, alone or beside a DT_RUNPATH (whichever a loader reads: both are taken; round 8 read glibc's way, the
  // DT_RPATH not at all beside a DT_RUNPATH, and said SAFE by the system's copy alone)
  make({ rpath: '$ORIGIN/../lib' });
  assert.equal(judge(prog, [sys]).status, 'EXPOSED');
  fixedLib(join(sys, 'libbrotlidec.so.1'));
  make({ rpath: '$ORIGIN/../lib', runpath: '/nowhere' });
  assert.equal(judge(prog, [sys]).status, 'UNKNOWN', 'DT_RPATH\'s unfixed copy beside the system\'s fixed one');
  fixedLib(lib);
  assert.equal(judge(prog, [sys]).status, 'SAFE', 'the clean twin');
  // not in the program's own folders: every copy in the system's folders is a candidate, and each must be SAFE
  rmSync(lib);
  make({ runpath: '$ORIGIN/../lib' });
  assert.equal(judge(prog, [sys]).status, 'SAFE');
  // two system folders whose copies disagree: UNKNOWN (round 8: EXPOSED, the unfixed one deciding); both unfixed EXPOSED
  oldLib(join(sys2, 'libbrotlidec.so.1'));
  assert.equal(judge(prog, [sys, sys2]).status, 'UNKNOWN');
  oldLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(prog, [sys, sys2]).status, 'EXPOSED');
  fixedLib(join(sys, 'libbrotlidec.so.1')); fixedLib(join(sys2, 'libbrotlidec.so.1'));
  const two = judge(prog, [sys, sys2]);
  assert.equal(two.status, 'SAFE'); assert.deepEqual(two.searched, [prog, join(sys, 'libbrotlidec.so.1'), join(sys2, 'libbrotlidec.so.1')]);
  const none = judge(prog, [fresh('elf-links-empty')]);
  assert.equal(none.status, 'UNKNOWN'); assert.match(none.reason, /it links libbrotlidec\.so\.1, which was not found \(looked in .*\/lib, .*elf-links-empty\)/);
  // a search path it can't follow: another variable ($LIB, $PLATFORM, $ORIGINAL is not $ORIGIN), a relative folder, an
  // empty one (the folder the program starts in): UNKNOWN, beside a fixed table, never the system's copy
  for (const [runpath, says] of [['$LIB/brotli', /through '\$LIB\/brotli'/], ['$PLATFORM', /through '\$PLATFORM'/], ['$ORIGINAL/lib', /through '\$ORIGINAL\/lib'/], ['lib', /looks for it in 'lib', a folder named by a relative path/], ['', /looks for it in '', a folder named by a relative path/], ['/nowhere::/also', /looks for it in ''/]]) {
    make({ runpath });
    const r = judge(prog, [sys]);
    assert.equal(r.status, 'UNKNOWN', runpath); assert.match(r.reason, says, runpath); assert.match(r.reason, /could not be tested/);
  }
  // a DT_NEEDED with a slash is a path, a candidate itself: $ORIGIN expanded, an absolute one as it is, a relative one
  // from the folder the program starts in (UNKNOWN, named). The system's folders' copies of that file name are
  // candidates too (decision #25): beside the system's fixed copy, UNKNOWN (round 8: EXPOSED, the path alone)
  oldLib(lib);
  for (const ref of ['$ORIGIN/../lib/libbrotlidec.so.1', '${ORIGIN}/../lib/libbrotlidec.so.1', lib]) {
    elf(prog, [CONTROL, MARKER], { needed: [ref] });
    assert.equal(judge(prog).status, 'EXPOSED', ref);
    assert.equal(judge(prog, [sys]).status, 'UNKNOWN', `${ref}, beside the system's fixed copy`);
  }
  fixedLib(lib);
  assert.equal(judge(prog, [sys]).status, 'SAFE', 'the clean twin');
  for (const ref of ['lib/libbrotlidec.so.1', '../lib/libbrotlidec.so.1', './libbrotlidec.so.1']) {
    elf(prog, [CONTROL, MARKER], { needed: [ref] });
    const r = judge(prog, [sys]);
    assert.equal(r.status, 'UNKNOWN', ref); assert.ok(r.reason.includes(`it links ${ref}, a relative path`), r.reason);
  }
  elf(prog, [CONTROL, MARKER], { needed: ['$LIB/libbrotlidec.so.1'] });
  assert.match(judge(prog, [sys]).reason, /it links \$LIB\/libbrotlidec\.so\.1, which Wardlatch can't follow/);
  // a distribution's node: its libnode the same way (a relative libnode path is UNKNOWN, named)
  const libDir = fresh('elf-links-node');
  elf(join(libDir, 'libnode.so.108'), [CONTROL, MARKER]);
  assert.equal(judge(elf(join(root, 'node'), [], { needed: ['libnode.so.108'] }), [libDir]).status, 'SAFE');
  const rel = judge(elf(join(root, 'node-rel'), [], { needed: ['libnode.so.108', '../lib/libnode.so.109'] }), [libDir]);
  assert.equal(rel.status, 'UNKNOWN'); assert.ok(rel.reason.includes('it links ../lib/libnode.so.109, the library that holds Node.js\'s code, a relative path'), rel.reason);
  // the link table itself, as read: names, soname, search paths
  const t = linkTable(elf(join(root, 'table'), [], { needed: ['libbrotlidec.so.1', 'libc.so.6'], soname: 'libx.so.1', rpath: '/a', runpath: '$ORIGIN/../lib' }), { size: readFileSync(join(root, 'table')).length });
  assert.deepEqual([t.format, t.links, t.id, t.rpath, t.runpath], ['ELF', ['libbrotlidec.so.1', 'libc.so.6'], 'libx.so.1', '/a', '$ORIGIN/../lib']);
  // the string table in the second of two PT_LOAD segments, at an address unlike its place in the file: placed by the
  // segment that maps it
  for (const [bits, be] of [[64, false], [32, true]]) {
    oldLib(lib, { bits, be });
    const split = elf(join(root, 'bin', `split-${bits}`), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN/../lib', split: true, bits, be });
    assert.equal(judge(split).status, 'EXPOSED', `split ${bits}`);
    fixedLib(lib, { bits, be });
    assert.equal(judge(split, [sys]).status, 'SAFE', `split ${bits}: the clean twin`);
  }
  // a statically linked program (no PT_DYNAMIC) links nothing: its own table decides
  const st = join(root, 'static');
  elf(st, [CONTROL, MARKER]);
  const b = readFileSync(st); b.writeUInt32LE(4, 64 + 56); writeFileSync(st, b);   // PT_DYNAMIC made PT_NOTE
  assert.deepEqual(linkTable(st, { size: b.length }).links, []); assert.equal(judge(st).status, 'SAFE');
});

// Round 6's probes (dyld m1, m1b, m5, m6, m7; ld.so E1, E1m, E2, E4) led to round 7's rule: every copy the loader could
// take must be SAFE. Rounds 7 and 8 still predicted which copies a loader can take (a copy it can't load was UNKNOWN,
// and an unfixed one it may take instead decided EXPOSED). Round 9 (decision #25, 2026-10-25) predicts nothing: every
// file of the library's name in a folder a loader may look in is a candidate, judged by its bytes; all fixed is SAFE,
// all unfixed EXPOSED, anything else UNKNOWN.

test('no copy is judged by whether a loader can load it (CPU type, subtype, format, file type): each is a candidate, judged by its bytes; a mix is UNKNOWN (m1, m1b, m1e, E1, E1m)', () => {
  const d = fresh('load');
  // m1: an arm64 program, LC_RPATH A then B; A holds a fixed copy built only for x86_64, B an unfixed arm64 one. dyld
  // passes over A's and loads B's (it printed "loaded decoder: UNFIXED"); c2f3a13 read SAFE, by A's; rounds 7 and 8
  // read EXPOSED (B's decided). Round 9: the two disagree, UNKNOWN, never SAFE
  const prog = join(d, 'm1', 'bin', 'prog'), A = join(d, 'm1', 'A'), B = join(d, 'm1', 'B');
  const m1 = () => judge(bin(prog, [CONTROL, MARKER], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths: [A, B] }));
  fixedLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.x86_64 }); oldLib(join(B, 'libbrotlidec.1.dylib'));
  const mixed = m1();
  assert.equal(mixed.status, 'UNKNOWN', mixed.reason); assert.equal(mixed.via, join(B, 'libbrotlidec.1.dylib'));
  assert.match(mixed.reason, /it links @rpath\/libbrotlidec\.1\.dylib, and the 2 files of that name .* are not all fixed or all unfixed .*could not be tested/);
  // A's copy unfixed too: every candidate lacks the fix, EXPOSED
  oldLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.x86_64 });
  assert.equal(m1().status, 'EXPOSED');
  // the clean twin: both fixed, SAFE, both named. Rounds 7 and 8 read UNKNOWN (A's copy is one dyld can't load); it
  // takes B's, or under Rosetta A's, or, past both, a copy in its fallback folders, which are the system's and are
  // candidates too (X1, X4)
  fixedLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.x86_64 }); fixedLib(join(B, 'libbrotlidec.1.dylib'));
  const good = m1();
  assert.equal(good.status, 'SAFE', good.reason); assert.deepEqual(good.searched, [prog, join(A, 'libbrotlidec.1.dylib'), join(B, 'libbrotlidec.1.dylib')]);
  // anything else in A, fixed (m1b: Debian's fixed ELF copy; a program, a bundle, a universal file without arm64): a
  // candidate judged by its bytes. Beside B's unfixed copy UNKNOWN (rounds 7 and 8: EXPOSED); beside B's fixed one SAFE
  // (rounds 7 and 8: UNKNOWN). Bytes of no format can't be read as a library: UNKNOWN either way
  for (const [what, make, alone] of [['an ELF file', (f) => elf(f, [CONTROL, MARKER], { type: 3 }), 'SAFE'], ['a program', (f) => fixedLib(f, { type: 2 }), 'SAFE'], ['a bundle', (f) => fixedLib(f, { type: 8 }), 'SAFE'],
    ['a universal file without arm64', (f) => fat(f, [{ parts: [CONTROL, MARKER], type: 6, cpu: CPU.x86_64 }]), 'SAFE'], ['bytes', (f) => writeFileSync(f, Buffer.concat(cstrings([CONTROL, MARKER]))), 'UNKNOWN']]) {
    make(join(A, 'libbrotlidec.1.dylib'));
    oldLib(join(B, 'libbrotlidec.1.dylib'));
    const r = m1();
    assert.equal(r.status, 'UNKNOWN', `${what}, beside B's unfixed copy: ${r.reason}`);
    fixedLib(join(B, 'libbrotlidec.1.dylib'));
    assert.equal(m1().status, alone, `${what}, beside B's fixed copy`);
  }
  // m1e: A's copy arm64e and unfixed, B's arm64 and fixed: dyld took A's (it printed UNFIXED). Round 8 read EXPOSED (the
  // same CPU type, judged); round 7 UNKNOWN. Round 9: a mix, UNKNOWN; both unfixed EXPOSED
  oldLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.arm64e });
  const m1e = m1();
  assert.equal(m1e.status, 'UNKNOWN', m1e.reason); assert.equal(m1e.via, join(A, 'libbrotlidec.1.dylib'));
  fat(join(A, 'libbrotlidec.1.dylib'), [{ parts: [CONTROL], type: 6, cpu: CPU.arm64e }]);
  assert.equal(m1().status, 'UNKNOWN', 'a universal file whose only build is arm64e, unfixed, beside B\'s fixed copy');
  oldLib(join(B, 'libbrotlidec.1.dylib'));
  assert.equal(m1().status, 'EXPOSED', 'both unfixed');
  // the clean twins: the arm64e copy fixed, thin or in a universal file, beside B's fixed one: SAFE, both named
  fixedLib(join(B, 'libbrotlidec.1.dylib'));
  for (const make of [(f) => fixedLib(f, { cpu: CPU.arm64e }), (f) => fat(f, [{ parts: [CONTROL, MARKER], type: 6, cpu: CPU.arm64e }])]) {
    make(join(A, 'libbrotlidec.1.dylib'));
    const r = m1();
    assert.equal(r.status, 'SAFE', r.reason); assert.deepEqual(r.searched, [prog, join(A, 'libbrotlidec.1.dylib'), join(B, 'libbrotlidec.1.dylib')]);
  }
  // by an absolute path: the copy there is a candidate whatever its CPU type (round 8: UNKNOWN for an x86_64 copy in an
  // arm64 program), SAFE when fixed and nothing else of that name is in a folder a loader may look in
  fixedLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.x86_64 });
  assert.equal(judge(bin(join(d, 'm1', 'bin', 'prog-abs'), [], { links: [join(A, 'libbrotlidec.1.dylib')] })).status, 'SAFE');
  oldLib(join(A, 'libbrotlidec.1.dylib'), { cpu: CPU.x86_64 });
  assert.equal(judge(join(d, 'm1', 'bin', 'prog-abs')).status, 'EXPOSED');
  // ELF (E1, E1m): DT_RUNPATH lib32 then lib; lib32 holds a fixed copy of another class, machine or byte order, or a
  // program, and lib an unfixed one: ld.so passes over the first (open_verify) and loads lib's. c2f3a13 read each SAFE;
  // rounds 7 and 8 EXPOSED. Round 9: UNKNOWN (a mix); with lib's fixed too, SAFE (rounds 7 and 8: UNKNOWN)
  const eprog = join(d, 'e1', 'bin', 'prog'), first = join(d, 'e1', 'lib32', 'libbrotlidec.so.1'), second = join(d, 'e1', 'lib', 'libbrotlidec.so.1'), sys = fresh('load-sys');
  const e1 = () => judge(elf(eprog, [], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib32:$ORIGIN/../lib' }), [sys]);
  for (const [what, o] of [['32-bit', { bits: 32 }], ['aarch64', { machine: 183 }], ['big-endian', { be: true }], ['a program (ET_EXEC)', { type: 2 }]]) {
    fixedLib(first, o); oldLib(second);
    const r = e1();
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.equal(r.via, second, what);
    oldLib(first, o);
    assert.equal(e1().status, 'EXPOSED', `${what}: both unfixed`);
    fixedLib(first, o); fixedLib(second);
    const u = e1();
    assert.equal(u.status, 'SAFE', `${what}: ${u.reason}`); assert.deepEqual(u.searched, [eprog, first, second], what);
  }
  // the system's copy is a candidate too, whatever the program's folders hold (rounds 7 and 8: not reached while they
  // held a copy the loader can load): unfixed beside the fixed ones, UNKNOWN; fixed, SAFE, all three named
  oldLib(join(sys, 'libbrotlidec.so.1')); fixedLib(first);
  assert.equal(e1().status, 'UNKNOWN');
  fixedLib(join(sys, 'libbrotlidec.so.1'));
  const twin = e1();
  assert.equal(twin.status, 'SAFE', twin.reason); assert.deepEqual(twin.searched, [eprog, first, second, join(sys, 'libbrotlidec.so.1')]);
});

test('a path is handed to the OS as written: \'..\' after a link to a folder goes where the kernel goes (m5, m6), never cleaned up as text first', () => {
  const d = fresh('dotdot');
  // bin/sym is a link to X/deep: bin/sym/../lib is X/lib to the kernel, bin/lib to a path cleaned up as text. X/lib holds
  // an unfixed copy, bin/lib a fixed one. dyld loaded X/lib's (UNFIXED); c2f3a13 read SAFE, by bin/lib's
  const bin_ = join(d, 'bin'), X = join(d, 'X');
  mkdirSync(join(X, 'deep'), { recursive: true }); mkdirSync(bin_, { recursive: true }); symlinkSync(join(X, 'deep'), join(bin_, 'sym'));
  fixedLib(join(bin_, 'lib', 'libbrotlidec.1.dylib')); oldLib(join(X, 'lib', 'libbrotlidec.1.dylib'));
  fixedLib(join(bin_, 'lib', 'libbrotlidec.so.1')); oldLib(join(X, 'lib', 'libbrotlidec.so.1'));
  const files = [
    ['m5: @loader_path/sym/../lib', bin(join(bin_, 'm5'), [CONTROL, MARKER], { links: ['@loader_path/sym/../lib/libbrotlidec.1.dylib'] })],
    ['m6: @rpath/../lib, LC_RPATH @loader_path/sym', bin(join(bin_, 'm6'), [CONTROL, MARKER], { links: ['@rpath/../lib/libbrotlidec.1.dylib'], rpaths: ['@loader_path/sym'] })],
    ['an absolute path through the link', bin(join(bin_, 'abs'), [CONTROL, MARKER], { links: [`${bin_}/sym/../lib/libbrotlidec.1.dylib`] })],
    ['ELF: $ORIGIN/sym/../lib in DT_NEEDED', elf(join(bin_, 'e-needed'), [CONTROL, MARKER], { needed: ['$ORIGIN/sym/../lib/libbrotlidec.so.1'] })],
    ['ELF: DT_RUNPATH $ORIGIN/sym/../lib', elf(join(bin_, 'e-runpath'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN/sym/../lib' })],
  ];
  for (const [what, f] of files) {
    const r = judge(f);
    assert.equal(r.status, 'EXPOSED', `${what}: ${r.reason}`); assert.match(r.via, /\/X\/lib\/libbrotlidec\.(1\.dylib|so\.1)$/, what);
  }
  // the clean twin: X/lib's copies fixed, SAFE, the receipt naming X/lib's by its real path
  fixedLib(join(X, 'lib', 'libbrotlidec.1.dylib')); fixedLib(join(X, 'lib', 'libbrotlidec.so.1'));
  for (const [what, f] of files) {
    const r = judge(f);
    assert.equal(r.status, 'SAFE', `${what}: ${r.reason}`); assert.ok(r.searched.some((x) => /\/X\/lib\/libbrotlidec/.test(x)), what);
  }
  // a library linked through a link to its folder (Homebrew's opt/brotli, a link into the Cellar) is named by its real
  // path, the file that was read
  const cellar = join(d, 'Cellar', 'brotli', '1.2.0', 'lib'), opt = join(d, 'opt');
  oldLib(join(cellar, 'libbrotlidec.1.dylib')); mkdirSync(opt, { recursive: true }); symlinkSync(join(d, 'Cellar', 'brotli', '1.2.0'), join(opt, 'brotli'));
  const brew = judge(bin(join(bin_, 'brew'), [], { links: [join(opt, 'brotli', 'lib', 'libbrotlidec.1.dylib')] }));
  assert.equal(brew.status, 'EXPOSED'); assert.equal(brew.via, join(cellar, 'libbrotlidec.1.dylib'));
  fixedLib(join(cellar, 'libbrotlidec.1.dylib'));
  assert.deepEqual(judge(join(bin_, 'brew')).searched, [join(bin_, 'brew'), join(cellar, 'libbrotlidec.1.dylib')]);
});

test('ELF\'s $ORIGIN, as either folder: a library reached by a link in another folder has the folder it was opened from (glibc), and its real one (finding 8)', () => {
  const d = fresh('origin2'), sys = fresh('origin2-sys');
  // node links lib/libnode.so.115 by its path (and has no search folders of its own); lib/libnode.so.115 is a link to
  // store/libnode.so.115, whose DT_RUNPATH is $ORIGIN. glibc takes libnode's $ORIGIN from the path it opened, lib/, which
  // holds an unfixed copy; libnode's real folder, store/, holds a fixed one. c2f3a13 read SAFE, by store's
  const node = elf(join(d, 'bin', 'node'), [], { needed: [join(d, 'lib', 'libnode.so.115'), 'libc.so.6'] });
  elf(join(d, 'store', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN' });
  mkdirSync(join(d, 'lib'), { recursive: true }); symlinkSync(join(d, 'store', 'libnode.so.115'), join(d, 'lib', 'libnode.so.115'));
  fixedLib(join(d, 'store', 'libbrotlidec.so.1')); oldLib(join(d, 'lib', 'libbrotlidec.so.1')); fixedLib(join(sys, 'libbrotlidec.so.1'));
  // lib/'s unfixed copy is a candidate beside store/'s and the system's fixed ones: UNKNOWN (round 8 read EXPOSED, lib/'s
  // deciding; decision #25 makes a mix UNKNOWN); every one unfixed, EXPOSED
  const bad = judge(node, [sys]);
  assert.equal(bad.status, 'UNKNOWN', bad.reason); assert.equal(bad.via, join(d, 'lib', 'libbrotlidec.so.1'));
  oldLib(join(d, 'store', 'libbrotlidec.so.1')); oldLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(node, [sys]).status, 'EXPOSED');
  // the clean twin: every copy fixed, SAFE, both folders' named
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); fixedLib(join(d, 'store', 'libbrotlidec.so.1')); fixedLib(join(sys, 'libbrotlidec.so.1'));
  const good = judge(node, [sys]);
  assert.equal(good.status, 'SAFE', good.reason);
  for (const f of [join(d, 'store', 'libbrotlidec.so.1'), join(d, 'lib', 'libbrotlidec.so.1')]) assert.ok(good.searched.includes(f), f);
  // a program reached by a link in another folder: glibc takes a program's $ORIGIN from its real path, but Wardlatch
  // doesn't predict which, so the link's folder counts too: an unfixed libnode in other/lib, which other/sub/node's
  // $ORIGIN/../lib names, is a candidate beside lib/'s fixed one, UNKNOWN (round 8: EXPOSED); the clean twin, with none
  // there, SAFE
  const node2 = elf(join(d, 'bin', 'node2'), [], { needed: ['libnode.so.115', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  mkdirSync(join(d, 'other', 'sub'), { recursive: true }); symlinkSync(node2, join(d, 'other', 'sub', 'node'));
  assert.equal(judge(join(d, 'other', 'sub', 'node'), [sys]).status, 'SAFE');
  elf(join(d, 'other', 'lib', 'libnode.so.115'), [CONTROL]);
  const viaLink = judge(join(d, 'other', 'sub', 'node'), [sys]);
  assert.equal(viaLink.status, 'UNKNOWN', viaLink.reason); assert.equal(viaLink.via, join(d, 'other', 'lib', 'libnode.so.115'));
  assert.equal(judge(node2, [sys]).status, 'SAFE', 'by its real path, the link\'s folder is not its');
});

test('ELF: a library\'s sonames are looked for in its program\'s folders too, and in every followed library\'s (E2, E2r); a library read without its program is judged by its own folders and the system\'s', () => {
  const d = fresh('rpath-chain'), sys = fresh('rpath-chain-sys');
  // E2: node (DT_RPATH $ORIGIN/../lib) links libnode.so.115 (no DT_RPATH, no DT_RUNPATH), which links libbrotlidec.so.1.
  // glibc searches node's DT_RPATH for libnode's soname before the system's folders: lib/'s unfixed copy, not the
  // system's fixed one. c2f3a13 read SAFE, by the system's; rounds 7 and 8 EXPOSED, by lib/'s. Round 9 (decision #25):
  // both are candidates and disagree, UNKNOWN; every one unfixed, EXPOSED
  elf(join(d, 'lib', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1', 'libc.so.6'] });
  oldLib(join(d, 'lib', 'libbrotlidec.so.1')); fixedLib(join(sys, 'libbrotlidec.so.1'));
  const node = (o) => elf(join(d, 'bin', 'node'), [], { needed: ['libnode.so.115', 'libc.so.6'], ...o });
  const e2 = judge(node({ rpath: '$ORIGIN/../lib' }), [sys]);
  assert.equal(e2.status, 'UNKNOWN', e2.reason); assert.equal(e2.via, join(d, 'lib', 'libbrotlidec.so.1'));
  assert.match(e2.reason, /libnode\.so\.115, the library that holds Node\.js's code: it links libbrotlidec\.so\.1, and the 2 files of that name .* are not all fixed or all unfixed/);
  // E2r: node's DT_RUNPATH instead. glibc doesn't pass it on, but musl searches the DT_RUNPATH of the program that loads
  // a library too (round 6 read glibc's way only, SAFE; rounds 7 and 8 EXPOSED): UNKNOWN the same way
  const e2r = judge(node({ runpath: '$ORIGIN/../lib' }), [sys]);
  assert.equal(e2r.status, 'UNKNOWN', e2r.reason); assert.equal(e2r.via, join(d, 'lib', 'libbrotlidec.so.1'));
  // a library with a DT_RUNPATH of its own that doesn't hold the copy: the program's folders are candidates still
  elf(join(d, 'lib', 'libnode.so.116'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.116', needed: ['libbrotlidec.so.1'], runpath: '/nowhere' });
  const own = judge(elf(join(d, 'bin', 'node116'), [], { needed: ['libnode.so.116'], runpath: '$ORIGIN/../lib' }), [sys]);
  assert.equal(own.status, 'UNKNOWN', own.reason); assert.equal(own.via, join(d, 'lib', 'libbrotlidec.so.1'));
  // a DT_RPATH beside a DT_RUNPATH: both are taken, whichever a loader reads (rounds 7 and 8 read neither, as glibc and
  // musl do, and said SAFE by the system's fixed copy); lib/'s unfixed copy is a candidate, UNKNOWN
  mkdirSync(join(d, 'lib2'), { recursive: true }); symlinkSync(join(d, 'lib', 'libnode.so.115'), join(d, 'lib2', 'libnode.so.115'));
  const both = judge(node({ rpath: '$ORIGIN/../lib', runpath: '$ORIGIN/../lib2' }), [sys]);
  assert.equal(both.status, 'UNKNOWN', both.reason);
  // every copy unfixed: EXPOSED, E2, E2r and the rest alike
  oldLib(join(sys, 'libbrotlidec.so.1'));
  for (const o of [{ rpath: '$ORIGIN/../lib' }, { runpath: '$ORIGIN/../lib' }, { rpath: '$ORIGIN/../lib', runpath: '$ORIGIN/../lib2' }]) assert.equal(judge(node(o), [sys]).status, 'EXPOSED', JSON.stringify(o));
  // and the clean twins: every copy fixed, SAFE, naming lib/'s
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); fixedLib(join(sys, 'libbrotlidec.so.1'));
  for (const o of [{ rpath: '$ORIGIN/../lib' }, { runpath: '$ORIGIN/../lib' }, { rpath: '$ORIGIN/../lib', runpath: '$ORIGIN/../lib2' }]) {
    const r = judge(node(o), [sys]);
    assert.equal(r.status, 'SAFE', r.reason); assert.ok(r.searched.includes(join(d, 'lib', 'libbrotlidec.so.1')), r.searched.join());
  }
  // a library read on its own (a package's file): the folders of the program that will load it are not known, and
  // round 9 drops rounds 7 and 8's special case for it (UNKNOWN past its own folders, a documented limit now): its
  // links are looked for in its own folders, the system's and the ones below them. The system's copy fixed: SAFE (round
  // 8: UNKNOWN); unfixed: EXPOSED (as before); its own DT_RUNPATH copy beside the system's, both fixed, SAFE
  const so = (o) => elf(join(d, 'pkg', 'libuses.so.1'), [], { needed: ['libbrotlidec.so.1'], ...o });
  const alone = judge(so({}), [sys]);
  assert.equal(alone.status, 'SAFE', alone.reason); assert.deepEqual(alone.searched, [join(d, 'pkg', 'libuses.so.1'), join(sys, 'libbrotlidec.so.1')]);
  oldLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(so({}), [sys]).status, 'EXPOSED');
  fixedLib(join(d, 'pkg', 'libbrotlidec.so.1'));
  assert.equal(judge(so({ runpath: '$ORIGIN' }), [sys]).status, 'UNKNOWN', 'its own fixed copy beside the system\'s unfixed one');
  fixedLib(join(sys, 'libbrotlidec.so.1'));
  for (const [what, f] of [['ET_EXEC', so({ type: 2 })], ['DF_1_PIE', so({ flags1: 0x08000001 })], ['DF_1_NOW', so({ flags1: 0x00000001 })], ['its own DT_RUNPATH', so({ runpath: '$ORIGIN' })], ['its own DT_RPATH', so({ rpath: '$ORIGIN' })]]) {
    assert.equal(judge(f, [sys]).status, 'SAFE', what);
  }
});

test('ELF: every subfolder of every folder searched is searched too, down to 4 levels (glibc-hwcaps/<level>), each copy there a candidate', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const d = fresh('hwcaps'), sys = fresh('hwcaps-sys');
  // glibc 2.33 and later look in <folder>/glibc-hwcaps/<level>/ before <folder>: an unfixed copy in lib/glibc-hwcaps/
  // x86-64-v3/ beside a fixed one in lib/ (c2f3a13 read SAFE, by lib/'s; rounds 7 and 8 EXPOSED, the hwcaps copy
  // deciding). Round 9 (decision #25): both candidates, a mix, UNKNOWN; all unfixed EXPOSED
  const prog = (o) => elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], ...o });
  const hw = join(d, 'lib', 'glibc-hwcaps', 'x86-64-v3', 'libbrotlidec.so.1');
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); oldLib(hw); fixedLib(join(sys, 'libbrotlidec.so.1'));
  for (const o of [{ runpath: '$ORIGIN/../lib' }, { rpath: '$ORIGIN/../lib' }]) {
    const r = judge(prog(o), [sys]);
    assert.equal(r.status, 'UNKNOWN', `${JSON.stringify(o)}: ${r.reason}`); assert.equal(r.via, hw);
  }
  oldLib(join(d, 'lib', 'libbrotlidec.so.1')); oldLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(prog({ runpath: '$ORIGIN/../lib' }), [sys]).status, 'EXPOSED', 'every copy unfixed');
  // the system's folders: their glibc-hwcaps subfolders too (the system's own copy fixed, its subfolder's unfixed)
  fixedLib(join(sys, 'libbrotlidec.so.1')); oldLib(join(sys, 'glibc-hwcaps', 'x86-64-v2', 'libbrotlidec.so.1'));
  rmSync(join(d, 'lib'), { recursive: true });
  assert.equal(judge(prog({}), [sys]).status, 'UNKNOWN');
  // the clean twin: every copy fixed, SAFE, each named (a folder's own copy, then the ones in its subfolders)
  fixedLib(join(sys, 'glibc-hwcaps', 'x86-64-v2', 'libbrotlidec.so.1')); fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); fixedLib(hw);
  const good = judge(prog({ runpath: '$ORIGIN/../lib' }), [sys]);
  assert.equal(good.status, 'SAFE', good.reason);
  assert.deepEqual(good.searched, [join(d, 'bin', 'prog'), join(d, 'lib', 'libbrotlidec.so.1'), hw, join(sys, 'libbrotlidec.so.1'), join(sys, 'glibc-hwcaps', 'x86-64-v2', 'libbrotlidec.so.1')]);
  assert.deepEqual(judge(prog({}), [sys]).searched, [join(d, 'bin', 'prog'), join(sys, 'libbrotlidec.so.1'), join(sys, 'glibc-hwcaps', 'x86-64-v2', 'libbrotlidec.so.1')]);
  // as many subfolders as there are: round 8 looked in at most 64 glibc-hwcaps subfolders (more were UNKNOWN); round 9
  // looks in every subfolder, up to 65,536 folders for a program, so a copy in the 65th is found and decides
  const many = fresh('hwcaps-many');
  fixedLib(join(many, 'libbrotlidec.so.1'));
  for (let i = 0; i < 65; i++) mkdirSync(join(many, 'glibc-hwcaps', `level-${i}`), { recursive: true });
  assert.equal(judge(prog({}), [many]).status, 'SAFE');
  oldLib(join(many, 'glibc-hwcaps', 'level-64', 'libbrotlidec.so.1'));
  const deep = judge(prog({}), [many]);
  assert.equal(deep.status, 'UNKNOWN', deep.reason); assert.equal(deep.via, join(many, 'glibc-hwcaps', 'level-64', 'libbrotlidec.so.1'));
  // down to 4 levels below a folder (glibc 2.36's old tls/haswell/avx512_1/x86_64 is 4, on an Intel CPU with AVX-512:
  // probe G3; round 9 stopped at 3, mutant A3b), and no further: a 5th level is not looked in (a documented limit)
  rmSync(join(many, 'glibc-hwcaps'), { recursive: true });
  oldLib(join(many, 'a', 'b', 'c', 'libbrotlidec.so.1'));
  assert.equal(judge(prog({}), [many]).status, 'UNKNOWN', 'the 3rd level');
  rmSync(join(many, 'a'), { recursive: true }); oldLib(join(many, 'a', 'b', 'c', 'd', 'libbrotlidec.so.1'));
  assert.equal(judge(prog({}), [many]).status, 'UNKNOWN', 'the 4th level');
  rmSync(join(many, 'a'), { recursive: true }); oldLib(join(many, 'a', 'b', 'c', 'd', 'e', 'libbrotlidec.so.1'));
  assert.equal(judge(prog({}), [many]).status, 'SAFE', 'a 5th level is past what is looked in');
  // a subfolder that can't be listed may hold a copy: UNKNOWN, naming it (one this account owns and has shut: a program
  // run by another account, root included, may still load from it)
  const locked = join(d, 'lib', 'glibc-hwcaps');
  execFileSync('chmod', ['000', locked]);
  try {
    const r = judge(prog({ runpath: '$ORIGIN/../lib' }), [sys]);
    assert.equal(r.status, 'UNKNOWN', r.reason); assert.ok(r.reason.includes(`can't follow or open (through '${locked}')`), r.reason);
  } finally { execFileSync('chmod', ['755', locked]); }
});

// Round 7's verifier found that copies found only through the program's folders (C1, C2) or only in a glibc-hwcaps
// subfolder (H5) stopped the search before the system's folders, where glibc goes on to them. Round 8 let only a copy in
// a plain folder of the file's own DT_RUNPATH (or DT_RPATH) stop it; round 8's verifier found more ways a loader takes
// another copy (L1 to L6, S7, F1 to F3). Round 9 (decision #25): nothing stops the search; every copy in a folder a
// loader may look in is a candidate, and the system's copy always is.
test('ELF: no copy stops the search: the system\'s copy is a candidate beside the program\'s and every library\'s own (C1, C2, C3, C4, H5)', () => {
  const d = fresh('stops'), sys = fresh('stops-sys'), sysLib = join(sys, 'libbrotlidec.so.1');
  // C1: node (DT_RUNPATH $ORIGIN/../lib) links libnode.so.115 (no DT_RPATH, no DT_RUNPATH), which links
  // libbrotlidec.so.1; lib/ holds a fixed copy, the system's folder an unfixed one. glibc never passes a program's
  // DT_RUNPATH on to a library, so it loads the system's copy; round 7 stopped at lib/'s and read SAFE.
  // C2: node's DT_RPATH, and libnode with a DT_RUNPATH of its own (/nowhere): glibc reads no loader's DT_RPATH for a
  // library with a DT_RUNPATH, so again the system's copy (round 7: SAFE).
  // C3: node's DT_RPATH, libnode with neither: glibc takes lib/'s (round 7: SAFE).
  // Round 8 read all three EXPOSED (the system's unfixed copy deciding); round 9 UNKNOWN: lib/'s fixed copy and the
  // system's unfixed one are both candidates, and disagree
  const chain = (name, nodeO, libnodeO) => {
    const root = join(d, name);
    fixedLib(join(root, 'lib', 'libbrotlidec.so.1'));
    elf(join(root, 'lib', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1', 'libc.so.6'], ...libnodeO });
    return elf(join(root, 'bin', 'node'), [], { needed: ['libnode.so.115', 'libc.so.6'], ...nodeO });
  };
  const cs = [['C1', chain('C1', { runpath: '$ORIGIN/../lib' }, {})], ['C2', chain('C2', { rpath: '$ORIGIN/../lib' }, { runpath: '/nowhere' })], ['C3', chain('C3', { rpath: '$ORIGIN/../lib' }, {})]];
  oldLib(sysLib);
  for (const [what, f] of cs) {
    const r = judge(f, [sys]);
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.equal(r.via, sysLib, what);
  }
  // the clean twins: the system's copy fixed too, SAFE, both copies named
  fixedLib(sysLib);
  for (const [what, f] of cs) {
    const r = judge(f, [sys]);
    assert.equal(r.status, 'SAFE', `${what}: ${r.reason}`);
    for (const x of [join(d, what, 'lib', 'libbrotlidec.so.1'), sysLib]) assert.ok(r.searched.includes(x), `${what}: ${x}`);
  }
  // a copy in a plain folder of the file's own search path doesn't stop it either (round 8: it did, SAFE beside the
  // system's unfixed copy, unread): libnode's own DT_RUNPATH ($ORIGIN), and C4, a program that links the soname itself
  // through its own DT_RUNPATH, are UNKNOWN beside the system's unfixed copy, SAFE beside a fixed one
  oldLib(sysLib);
  const own = chain('own', { runpath: '$ORIGIN/../lib' }, { runpath: '$ORIGIN' });
  const c4 = elf(join(d, 'C4', 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  fixedLib(join(d, 'C4', 'lib', 'libbrotlidec.so.1'));
  for (const [what, f] of [['libnode\'s own DT_RUNPATH', own], ['C4', c4]]) assert.equal(judge(f, [sys]).status, 'UNKNOWN', what);
  fixedLib(sysLib);
  for (const [what, f] of [['libnode\'s own DT_RUNPATH', own], ['C4', c4]]) {
    const r = judge(f, [sys]);
    assert.equal(r.status, 'SAFE', `${what}: ${r.reason}`); assert.ok(r.searched.includes(sysLib), what);
  }
  // H5: a fixed copy only in lib/glibc-hwcaps/x86-64-v4/: glibc looks there only on a CPU of that level, musl never, so
  // either may go on to the system's unfixed copy. Round 7 stopped at the hwcaps copy and read SAFE; round 8 EXPOSED;
  // round 9 UNKNOWN (a mix), and still UNKNOWN with a fixed copy in lib/ itself too (round 8: SAFE, lib/'s stopping it)
  oldLib(sysLib);
  const hwProg = () => elf(join(d, 'H5', 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN/../lib' });
  const hwLib = join(d, 'H5', 'lib', 'glibc-hwcaps', 'x86-64-v4', 'libbrotlidec.so.1');
  fixedLib(hwLib);
  const h5 = judge(hwProg(), [sys]);
  assert.equal(h5.status, 'UNKNOWN', h5.reason); assert.equal(h5.via, sysLib);
  fixedLib(join(d, 'H5', 'lib', 'libbrotlidec.so.1'));
  assert.equal(judge(hwProg(), [sys]).status, 'UNKNOWN');
  // the clean twin: the system's copy fixed, SAFE, all three named
  fixedLib(sysLib);
  const plain = judge(hwProg(), [sys]);
  assert.equal(plain.status, 'SAFE', plain.reason); assert.deepEqual(plain.searched, [join(d, 'H5', 'bin', 'prog'), join(d, 'H5', 'lib', 'libbrotlidec.so.1'), hwLib, sysLib]);
  // $ORIGIN read two ways: node links libnode by a path through a link in lib/ to store/libnode.so.115, whose DT_RUNPATH
  // is $ORIGIN: glibc takes libnode's $ORIGIN from lib/, which holds no copy, and goes on to the system's unfixed one.
  // Round 7 read SAFE (store/'s); round 8 EXPOSED; round 9 UNKNOWN, with lib/'s fixed copy too
  oldLib(sysLib);
  const o2 = join(d, 'origin2');
  elf(join(o2, 'store', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN' });
  mkdirSync(join(o2, 'lib'), { recursive: true }); symlinkSync(join(o2, 'store', 'libnode.so.115'), join(o2, 'lib', 'libnode.so.115'));
  fixedLib(join(o2, 'store', 'libbrotlidec.so.1'));
  const byLink = elf(join(o2, 'bin', 'node'), [], { needed: [join(o2, 'lib', 'libnode.so.115'), 'libc.so.6'] });
  const two = judge(byLink, [sys]);
  assert.equal(two.status, 'UNKNOWN', two.reason); assert.equal(two.via, sysLib);
  fixedLib(join(o2, 'lib', 'libbrotlidec.so.1'));
  assert.equal(judge(byLink, [sys]).status, 'UNKNOWN');
  // the clean twin: the system's copy fixed too, SAFE
  fixedLib(sysLib);
  const both = judge(byLink, [sys]);
  assert.equal(both.status, 'SAFE', both.reason); assert.ok(both.searched.includes(sysLib));
});

test('a search folder that can\'t be looked at may hold the library: UNKNOWN, never SAFE by a copy in another folder (m7, mutant R4)', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const d = fresh('closed');
  const A = join(d, 'A'), B = join(d, 'B');
  mkdirSync(A, { recursive: true }); fixedLib(join(B, 'libbrotlidec.1.dylib')); fixedLib(join(B, 'libbrotlidec.so.1'));
  const files = [['LC_RPATH', bin(join(d, 'prog'), [CONTROL, MARKER], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths: [A, B] })],
    ['DT_RUNPATH', elf(join(d, 'eprog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: `${A}:${B}` })]];
  execFileSync('chmod', ['000', A]);
  try {
    for (const [what, f] of files) {
      const r = judge(f);
      assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.ok(r.reason.includes(`can't follow or open (through '${A}')`), r.reason);
    }
  } finally { execFileSync('chmod', ['755', A]); }
  // the clean twin: A can be looked at and holds no copy
  for (const [what, f] of files) assert.equal(judge(f).status, 'SAFE', what);
  // an unfixed copy in B beside the folder that can't be looked at: A may hold a fixed copy the loader takes, so which
  // copy it loads isn't known, UNKNOWN (rounds 7 and 8 read EXPOSED, B's copy deciding; decision #25 makes every
  // candidate that can't be judged UNKNOWN); with A open again, B's unfixed copy alone is EXPOSED
  oldLib(join(B, 'libbrotlidec.1.dylib')); oldLib(join(B, 'libbrotlidec.so.1'));
  execFileSync('chmod', ['000', A]);
  try {
    for (const [what, f] of files) { const r = judge(f); assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.ok(r.reason.includes(`can't follow or open (through '${A}')`), r.reason); }
  } finally { execFileSync('chmod', ['755', A]); }
  for (const [what, f] of files) { const r = judge(f); assert.equal(r.status, 'EXPOSED', `${what}: ${r.reason}`); assert.match(r.via, /\/B\/libbrotlidec/, what); }
  // a file of the library's name that can't be judged (a FIFO, or a link into a folder that can't be entered) is a
  // candidate that can't be judged: UNKNOWN, naming it, beside B's copy fixed or not; the clean twin, A empty again
  fixedLib(join(B, 'libbrotlidec.1.dylib')); fixedLib(join(B, 'libbrotlidec.so.1'));
  const shut = fresh('closed-shut');
  for (const [kind, make] of [['a FIFO', (f) => execFileSync('mkfifo', [f])], ['a link into a closed folder', (f) => symlinkSync(join(shut, basename(f)), f)]]) {
    for (const name of ['libbrotlidec.1.dylib', 'libbrotlidec.so.1']) make(join(A, name));
    execFileSync('chmod', ['000', shut]);
    try {
      for (const [what, f] of files) {
        const r = judge(f);
        assert.equal(r.status, 'UNKNOWN', `${kind}, ${what}: ${r.reason}`); assert.match(r.reason, /can't follow or open \(through '.*\/A\/libbrotlidec/, `${kind}, ${what}`);
      }
    } finally { execFileSync('chmod', ['755', shut]); }
    for (const name of ['libbrotlidec.1.dylib', 'libbrotlidec.so.1']) rmSync(join(A, name));
  }
  for (const [what, f] of files) assert.equal(judge(f).status, 'SAFE', what);
});

test('macOS compares file names ignoring case by default, with no option given (mutant P11)', () => {
  const d = fresh('case-default'), path = fresh('case-default-path'), darwin = process.platform === 'darwin';
  // a name outside the table, in another case: found on macOS without being told to (its disks ignore case), not elsewhere
  assert.equal(judge(bin(join(d, 'upper'), [CONTROL, MARKER, 'LIBBROTLIDEC.SO.1'])).status, darwin ? 'UNKNOWN' : 'SAFE');
  bin(join(path, 'node'), [CONTROL, MARKER, 'LibNode.147.Dylib']);
  assert.equal(run({}, { pathEnv: path }).rows[0].status, darwin ? 'UNKNOWN' : 'SAFE', 'through the command, which passes no option either');
  // the clean twin: no such name
  assert.equal(judge(bin(join(d, 'none'), [CONTROL, MARKER, 'libbrotlidec mention'])).status, 'SAFE');
});

test('libnode by any of its names: libnode, libnode.*, libnode-* and libnode_* (auditwheel\'s tag), in any case, are followed (mutant P16)', () => {
  const d = fresh('libnode-names'), sys = fresh('libnode-names-sys');
  for (const s of ['libnode', 'libnode-1a2b3c4d.so.115', 'libnode_v8.so.1', '@rpath/libnode-x.dylib', '/opt/x/LIBNODE_Y.so', 'libnode.so']) assert.ok(isNodeLibName(s), s);
  for (const s of ['libnodex.so', 'libnode+.so', 'libnodes', 'libnod.so']) assert.ok(!isNodeLibName(s), s);
  // a node linking libnode by a tagged name: followed, and judged
  const node = elf(join(d, 'node'), [], { needed: ['libnode-1a2b3c4d.so.115', 'libc.so.6'] });
  elf(join(sys, 'libnode-1a2b3c4d.so.115'), [CONTROL, NODE_CONTROL]);
  const bad = judge(node, [sys]);
  assert.equal(bad.status, 'EXPOSED', bad.reason); assert.match(bad.reason, /libnode-1a2b3c4d\.so\.115, the library that holds Node\.js's code/);
  const under = bin(join(d, 'node-under'), [], { links: [join(d, 'libnode_x.dylib')] });
  bin(join(d, 'libnode_x.dylib'), [CONTROL, NODE_CONTROL], { type: 6 });
  assert.equal(judge(under).status, 'EXPOSED');
  // the clean twins: fixed
  elf(join(sys, 'libnode-1a2b3c4d.so.115'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER]); bin(join(d, 'libnode_x.dylib'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER], { type: 6 });
  assert.equal(judge(node, [sys]).status, 'SAFE'); assert.equal(judge(under).status, 'SAFE');
});

test('ELF: the dynamic table the loader reads is the one at PT_DYNAMIC\'s address; a file whose table at its offset is another contradicts itself, UNKNOWN (E4)', () => {
  const d = fresh('dyn-place'), sys = fresh('dyn-place-sys');
  oldLib(join(sys, 'libbrotlidec.so.1'));
  // the real table (DT_NEEDED libbrotlidec.so.1) where p_vaddr maps; a decoy (DT_NEEDED libc.so.6 only) appended to the
  // file, which p_offset names. ld.so reads the real one; c2f3a13 read the decoy and said SAFE
  const real = elf(join(d, 'prog'), [CONTROL, MARKER, 'x'.repeat(64)], { needed: ['libbrotlidec.so.1'] });
  const decoySrc = readFileSync(elf(join(d, 'decoy-src'), [], { needed: ['libc.so.6'] }));
  const b = readFileSync(real), dynOff = Number(b.readBigUInt64LE(64 + 56 + 8)), dynLen = Number(b.readBigUInt64LE(64 + 56 + 32));
  // the decoy's table, its DT_STRTAB pointing at the real file's string table (so its libc.so.6 is a name there: the
  // real one has none, so its DT_NEEDED is the real table's first string, libbrotlidec.so.1; make it point past it)
  const decoy = Buffer.from(decoySrc.subarray(Number(decoySrc.readBigUInt64LE(64 + 56 + 8)), Number(decoySrc.readBigUInt64LE(64 + 56 + 8)) + dynLen));
  decoy.writeBigUInt64LE(b.readBigUInt64LE(dynOff + 16 + 8), 16 + 8); decoy.writeBigUInt64LE(b.readBigUInt64LE(dynOff + 32 + 8), 32 + 8);
  decoy.writeBigUInt64LE(BigInt(1 + 'libbrotlidec.so'.length), 8);   // DT_NEEDED: the real string's tail, ".1", no Brotli library
  const at = b.length;
  const out = Buffer.concat([b, decoy]);
  // the PT_LOAD covers the whole file, the decoy included
  out.writeBigUInt64LE(BigInt(out.length), 64 + 32); out.writeBigUInt64LE(BigInt(out.length), 64 + 40);
  const consistent = Buffer.from(out);
  out.writeBigUInt64LE(BigInt(at), 64 + 56 + 8);   // PT_DYNAMIC's p_offset: the decoy; p_vaddr still the real table
  writeFileSync(real, out);
  const r = judge(real, [sys]);
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.match(r.reason, /^its ELF headers could not be read as the format lays them out \(the dynamic table at its place in the file is not the one the loader reads at its address\)/);
  // p_vaddr at an address no PT_LOAD maps: UNKNOWN
  const nowhere = Buffer.from(consistent); nowhere.writeBigUInt64LE(0x7fff0000n, 64 + 56 + 16); writeFileSync(real, nowhere);
  assert.match(judge(real, [sys]).reason, /its dynamic table is at an address no part of the file the loader maps holds/);
  // the clean twin: p_offset and p_vaddr name the same table, read as written (the system's unfixed copy: EXPOSED)
  writeFileSync(real, consistent);
  assert.equal(judge(real, [sys]).status, 'EXPOSED');
  fixedLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(real, [sys]).status, 'SAFE');
  // the same bytes at both places (a copy of the table where p_offset points) is no contradiction
  const copy = Buffer.concat([consistent, consistent.subarray(dynOff, dynOff + dynLen)]);
  copy.writeBigUInt64LE(BigInt(copy.length), 64 + 32); copy.writeBigUInt64LE(BigInt(copy.length), 64 + 40); copy.writeBigUInt64LE(BigInt(consistent.length), 64 + 56 + 8);
  writeFileSync(real, copy);
  assert.equal(judge(real, [sys]).status, 'SAFE');
});

/**
 * A program laid out by hand, as round 7's verifier's probes were (tools/elfoverlap.mjs): ELF64 ET_EXEC x86-64, its
 * string table at 0x100 ("libc.so.6", "/opt/libbrotlidec.so.1"), its table's strings at 0x200, a decoy dynamic table at
 * PT_DYNAMIC's p_offset 0x1000 (DT_NEEDED libc.so.6, DT_RUNPATH /opt/libbrotlidec.so.1), and the real one (DT_NEEDED the
 * tail of that string, libbrotlidec.so.1) at `realAt`. With `strings` ([first, second]): the string table at 0x100 is
 * the first, a second one at 0x11100, and the table at 0x1000 names DT_NEEDED and DT_RUNPATH by their first two names'
 * places (no real table). `loads`: each PT_LOAD as [p_offset, p_vaddr, size, p_align, p_memsz (the size by default)],
 * the first before PT_DYNAMIC (at 0x400000 + `dynAt`, its p_offset `dynAt`, 0x1000 by default, where the decoy is), the
 * rest after it. `machine`: e_machine (62 x86-64, 183 aarch64, 21 ppc64).
 */
function overlay(path, loads, { realAt = 0x11000, strings, machine = 62, dynAt = 0x1000 } = {}) {
  const BASE = 0x400000, b = Buffer.alloc(0x12000);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0); b.writeUInt16LE(2, 16); b.writeUInt16LE(machine, 18); b.writeUInt32LE(1, 20);
  b.writeBigUInt64LE(64n, 32); b.writeUInt16LE(64, 52); b.writeUInt16LE(56, 54); b.writeUInt16LE(1 + loads.length, 56);
  const ph = (i, type, off, vaddr, size, align, memsz = size) => {
    const p = 64 + i * 56;
    b.writeUInt32LE(type, p); b.writeUInt32LE(4, p + 4); b.writeBigUInt64LE(BigInt(off), p + 8); b.writeBigUInt64LE(BigInt(vaddr), p + 16); b.writeBigUInt64LE(BigInt(vaddr), p + 24);
    b.writeBigUInt64LE(BigInt(size), p + 32); b.writeBigUInt64LE(BigInt(memsz), p + 40); b.writeBigUInt64LE(BigInt(align), p + 48);
  };
  Buffer.from(`\0${CONTROL}\0${MARKER}\0`).copy(b, 0x200);
  const put = (at, tags) => tags.forEach(([t, v], i) => { b.writeBigUInt64LE(BigInt(t), at + i * 16); b.writeBigUInt64LE(BigInt(v), at + 8 + i * 16); });
  if (strings) {
    const [first, second] = strings.map((s) => Buffer.from(s));
    first.copy(b, 0x100); second.copy(b, 0x11100);
    put(dynAt, [[1, 1], [29, first.indexOf(0, 1) + 1], [5, BASE + 0x100], [10, first.length], [0, 0]]);
  } else {
    const strs = Buffer.from('\0libc.so.6\0/opt/libbrotlidec.so.1\0'), runAt = 11, tail = runAt + 5;
    strs.copy(b, 0x100);
    put(dynAt, [[1, 1], [29, runAt], [5, BASE + 0x100], [10, strs.length], [0, 0]]);
    put(realAt, [[1, tail], [5, BASE + 0x100], [10, strs.length], [0, 0], [0, 0]]);
  }
  ph(0, 1, ...loads[0]); ph(1, 2, dynAt, BASE + dynAt, 80, 8);
  loads.slice(1).forEach((l, i) => ph(2 + i, 1, ...l));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, b, { mode: 0o755 });
  return path;
}

test('ELF: a dynamic table or string table at an address more than one PT_LOAD maps (on the same page) contradicts itself, UNKNOWN (E4b, E4c); one PT_LOAD per address reads as before', () => {
  const d = fresh('overlay'), sys = fresh('overlay-sys'), B = 0x400000;
  oldLib(join(sys, 'libbrotlidec.so.1'));
  // the kernel and ld.so map the PT_LOAD segments in order, a page at a time, each over what is there, so a later
  // segment can put other bytes where the table's address is. Round 7 read the first PT_LOAD that holds the address, the
  // decoy at p_offset (no Brotli library), and said SAFE; the loader reads the real table (libbrotlidec.so.1, the
  // system's unfixed copy)
  for (const [what, loads, machine] of [
    ['E4b: a second PT_LOAD maps the table\'s address to the real one', [[0, B, 0x2000, 0x10000], [0x11000, B + 0x1000, 0x1000, 0x10000]]],
    ['E4c: a second PT_LOAD starts later in the same 4 KB page', [[0, B, 0x1100, 0x10000], [0x11800, B + 0x1800, 0x100, 0x10000]]],
    ['E4c with a p_align of 4 KB', [[0, B, 0x1100, 0x1000], [0x11800, B + 0x1800, 0x100, 0x1000]]],
    // the page is the kernel's, not p_align (decision #25, rule 4): off x86, 4, 16 and 64 KB are each checked, so a
    // second PT_LOAD on the same 16 or 64 KB page is a contradiction whatever p_align says (round 8 took p_align as the
    // page, 64 KB when under 4 KB; P1)
    ['aarch64, the same 16 KB page, p_align 8', [[0, B, 0x1100, 8], [0x11000, B + 0x2000, 0x1000, 8]], 183],
    ['aarch64, the same 64 KB page, p_align 4 KB', [[0, B, 0x1100, 0x1000], [0x11000, B + 0x8000, 0x1000, 0x1000]], 183],
    ['ppc64, the same 64 KB page, p_align 4 KB', [[0, B, 0x1100, 0x1000], [0x11000, B + 0x8000, 0x1000, 0x1000]], 21],
  ]) {
    const r = judge(overlay(join(d, 'prog'), loads, { machine }), [sys]);
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`);
    assert.match(r.reason, /its dynamic table is at an address more than one PT_LOAD segment maps \(on the same page\).*could not be tested/, what);
  }
  // on x86 (EM_386, EM_X86_64) pages are 4 KB only: the same layouts read as written, SAFE by the table at p_offset, the
  // one the loader reads there (round 8 read the first UNKNOWN, a p_align under 4 KB taken as 64 KB pages)
  for (const loads of [[[0, B, 0x1100, 8], [0x11000, B + 0x2000, 0x1000, 8]], [[0, B, 0x1100, 0x1000], [0x11000, B + 0x8000, 0x1000, 0x1000]]]) {
    const r = judge(overlay(join(d, 'prog'), loads), [sys]);
    assert.equal(r.status, 'SAFE', r.reason);
  }
  // the string table the same way: the table names libbrotlidec.so.1 and DT_RUNPATH $ORIGIN/fixed (a fixed copy)
  // through the string table at 0x100; a second PT_LOAD whose page holds that address (not the dynamic table's) puts the
  // second string table there, where the search path reads $ORIGIN/evil0 (an unfixed copy). Round 7 read SAFE
  const s = join(d, 's'), strings = ['\0libbrotlidec.so.1\0$ORIGIN/fixed\0', '\0libbrotlidec.so.1\0$ORIGIN/evil0\0'];
  fixedLib(join(s, 'fixed', 'libbrotlidec.so.1')); oldLib(join(s, 'evil0', 'libbrotlidec.so.1'));
  const str = judge(overlay(join(s, 'prog'), [[0, B, 0x2000, 0x1000], [0x11800, B + 0x800, 0x100, 0x1000]], { strings }), [sys]);
  assert.equal(str.status, 'UNKNOWN', str.reason); assert.match(str.reason, /its string table is at an address more than one PT_LOAD segment maps \(on the same page\).*could not be tested/);
  // the clean twins: the second PT_LOAD on pages of its own (64 KB away; with 4 KB pages, the next page): the decoy the
  // only table, SAFE by its own fixed table; the string table read as written, SAFE by $ORIGIN/fixed's copy; and the
  // real table at p_offset: EXPOSED, the system's copy
  for (const [what, loads, machine] of [['64 KB pages', [[0, B, 0x2000, 0x10000], [0x11000, B + 0x11000, 0x1000, 0x10000]]], ['4 KB pages', [[0, B, 0x1100, 0x1000], [0x11000, B + 0x2000, 0x1000, 0x1000]]],
    ['aarch64, the next 64 KB page', [[0, B, 0x1100, 0x1000], [0x11000, B + 0x10000, 0x1000, 0x1000]], 183]]) {
    const r = judge(overlay(join(d, 'prog'), loads, { machine }), [sys]);
    assert.equal(r.status, 'SAFE', `${what}: ${r.reason}`);
  }
  // (the string table's twin judged with no system folder: the system's unfixed copy would be a candidate beside
  // $ORIGIN/fixed's, UNKNOWN since round 9)
  const strTwin = judge(overlay(join(s, 'prog'), [[0, B, 0x2000, 0x1000], [0x11800, B + 0x11800, 0x100, 0x1000]], { strings }));
  assert.equal(strTwin.status, 'SAFE', strTwin.reason); assert.ok(strTwin.searched.includes(join(s, 'fixed', 'libbrotlidec.so.1')));
  const real = judge(overlay(join(d, 'prog'), [[0, B, 0x2000, 0x10000], [0x11000, B + 0x11000, 0x1000, 0x10000]], { realAt: 0x1000 }), [sys]);
  assert.equal(real.status, 'EXPOSED', real.reason); assert.equal(real.via, join(sys, 'libbrotlidec.so.1'));
});

/**
 * Round 8's verifier's P1 (tools/newprobes.mjs), laid out by hand: an ET_EXEC for `machine` whose four program headers
 * are PT_LOAD file 0..0x1100 at 0x400000, PT_DYNAMIC 0x1000 (a decoy table: DT_NEEDED libc.so.6, DT_RUNPATH
 * /opt/libbrotlidec.so.1), PT_LOAD file 0x12000.. at 0x402000 (another 4 KB page, the same 16 and 64 KB page) and PT_LOAD
 * file 0.. at 0x420000; each with p_align `align`. A kernel with 64 KB pages maps file 0x10000.. at 0x400000 for the
 * third, where the real table (DT_NEEDED libbrotlidec.so.1) is at 0x11000.
 */
function p1(path, machine, align) {
  const BASE = 0x400000, b = Buffer.alloc(0x20000);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0); b.writeUInt16LE(2, 16); b.writeUInt16LE(machine, 18); b.writeUInt32LE(1, 20);
  b.writeBigUInt64LE(64n, 32); b.writeUInt16LE(64, 52); b.writeUInt16LE(56, 54); b.writeUInt16LE(4, 56);
  const ph = (i, type, off, vaddr, sz) => { const q = 64 + i * 56; b.writeUInt32LE(type, q); b.writeUInt32LE(4, q + 4); b.writeBigUInt64LE(BigInt(off), q + 8); b.writeBigUInt64LE(BigInt(vaddr), q + 16); b.writeBigUInt64LE(BigInt(vaddr), q + 24); b.writeBigUInt64LE(BigInt(sz), q + 32); b.writeBigUInt64LE(BigInt(sz), q + 40); b.writeBigUInt64LE(BigInt(align), q + 48); };
  const strs = Buffer.from('\0libc.so.6\0/opt/libbrotlidec.so.1\0'), runAt = 11, tail = runAt + 5;
  const put = (at, tags) => tags.forEach(([t, v], i) => { b.writeBigUInt64LE(BigInt(t), at + i * 16); b.writeBigUInt64LE(BigInt(v), at + 8 + i * 16); });
  ph(0, 1, 0, BASE, 0x1100); ph(1, 2, 0x1000, BASE + 0x1000, 80); ph(2, 1, 0x12000, BASE + 0x2000, 0x1000); ph(3, 1, 0, BASE + 0x20000, 0x1100);
  strs.copy(b, 0x180); Buffer.from(`\0${CONTROL}\0${MARKER}\0`).copy(b, 0x200);
  put(0x1000, [[1, 1], [29, runAt], [5, BASE + 0x180], [10, strs.length], [0, 0]]);
  b.copy(b, 0x10000, 0, 0x180);
  put(0x11000, [[1, tail], [5, BASE + 0x20180], [10, strs.length], [0, 0], [0, 0]]);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, b, { mode: 0o755 });
  return path;
}

test('ELF: the page is the one the machine\'s kernel may map with, never p_align (P1); a segment\'s page-rounded end (M2g), its memory-only part (M2c), and a table in that part (N24) are read as the loader maps them', () => {
  const d = fresh('pages'), sys = fresh('pages-sys'), B = 0x400000;
  oldLib(join(sys, 'libbrotlidec.so.1'), { machine: 183 });
  // P1: aarch64, p_align 4 KB, the second PT_LOAD on the same 64 KB page as the dynamic table: on a 64 KB-page kernel the
  // loader reads the real table (libbrotlidec.so.1, the system's unfixed copy). Round 8 took p_align as the page and read
  // the decoy, SAFE; round 9 checks 4, 16 and 64 KB off x86: UNKNOWN. P1a (p_align 64 KB) was UNKNOWN already
  for (const [what, align] of [['P1, p_align 4 KB', 0x1000], ['P1a, p_align 64 KB', 0x10000]]) {
    const r = judge(p1(join(d, what.slice(0, 3), 'prog'), 183, align), [sys]);
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.match(r.reason, /its dynamic table is at an address more than one PT_LOAD segment maps \(on the same page\)/, what);
  }
  // P1x, the clean twin: the same layout on x86-64, whose pages are 4 KB only: the decoy is the table the loader reads,
  // SAFE by its own fixed table (no Brotli library)
  assert.equal(judge(p1(join(d, 'P1x', 'prog'), 62, 0x1000), [sys]).status, 'SAFE');
  // and on 32-bit x86 (EM_386), whose kernels use 4 KB pages only too (mutant D4: checked with 16 and 64 KB, UNKNOWN)
  assert.equal(judge(p1(join(d, 'P1x386', 'prog'), 3, 0x1000), [sys]).status, 'SAFE', 'EM_386');
  // M2g: a second PT_LOAD whose bytes end before the table but whose last page holds it (the table at 0x401800, mid-page):
  // the loader maps that whole page from the second segment (the real table at 0x11800). UNKNOWN; the twin, the second
  // segment on a page of its own, SAFE by the decoy
  const m2g = judge(overlay(join(d, 'm2g'), [[0, B, 0x2000, 0x1000], [0x11000, B + 0x1000, 0x100, 0x1000]], { dynAt: 0x1800, realAt: 0x11800 }), [sys]);
  assert.equal(m2g.status, 'UNKNOWN', m2g.reason); assert.match(m2g.reason, /more than one PT_LOAD segment maps \(on the same page\)/);
  assert.equal(judge(overlay(join(d, 'm2g-twin'), [[0, B, 0x2000, 0x1000], [0x11000, B + 0x3000, 0x100, 0x1000]], { dynAt: 0x1800, realAt: 0x11800 }), [sys]).status, 'SAFE');
  // M2c: a second PT_LOAD whose bytes in the file end before the table's page, but whose memory (p_memsz, zeros past
  // p_filesz) runs onto it: UNKNOWN; the twin, p_memsz equal to p_filesz, SAFE
  const m2c = judge(overlay(join(d, 'm2c'), [[0, B, 0x3000, 0x1000], [0x11000, B + 0x1000, 0x100, 0x1000, 0x1900]], { dynAt: 0x2800 }), [sys]);
  assert.equal(m2c.status, 'UNKNOWN', m2c.reason); assert.match(m2c.reason, /more than one PT_LOAD segment maps \(on the same page\)/);
  assert.equal(judge(overlay(join(d, 'm2c-twin'), [[0, B, 0x3000, 0x1000], [0x11000, B + 0x1000, 0x100, 0x1000]], { dynAt: 0x2800 }), [sys]).status, 'SAFE');
  // N24: the dynamic table at an address in the one PT_LOAD's memory-only part (past p_filesz: zeros once loaded), whose
  // place in the file holds a table: no part of the file the loader maps holds it, UNKNOWN; the twin, p_filesz covering
  // it, SAFE
  const n24 = judge(overlay(join(d, 'n24'), [[0, B, 0x1000, 0x1000, 0x2000]], { dynAt: 0x1800 }), [sys]);
  assert.equal(n24.status, 'UNKNOWN', n24.reason); assert.match(n24.reason, /its dynamic table is at an address no part of the file the loader maps holds/);
  assert.equal(judge(overlay(join(d, 'n24-twin'), [[0, B, 0x2000, 0x1000]], { dynAt: 0x1800 }), [sys]).status, 'SAFE');
});

test('Mach-O: a copy dyld may refuse (another subtype, another platform) never decides alone: its fallback folders, the system\'s, hold candidates too (X1, X1old, X4, D1old, D4)', () => {
  const d = fresh('fallback'), sys = fresh('fallback-sys');   // `sys` stands for /usr/local/lib and /usr/lib
  // X1 and X4: an x86_64 program whose only copy, in A, is a fixed x86_64h dylib (by @rpath through LC_RPATH A, and by
  // its absolute path). Under Rosetta 2 dyld refuses it ("incompatible architecture (have 'x86_64h', need 'x86_64')")
  // and looks in its fallback folders: /usr/local/lib and /usr/lib for a program built before Fall 2023 (X1old, the same
  // file built against SDK 13.0: the SDK isn't read, so the same here), DYLD_FALLBACK_LIBRARY_PATH's otherwise. It loaded
  // an unfixed copy from there. Round 8 read SAFE (x86_64h is the x86_64 CPU type, judged); 4fa0cbc UNKNOWN.
  // D1old and D4: an arm64 program whose only copy, in B, is a fixed arm64 dylib built for iOS ("incompatible platform
  // (have 'iOS', need 'macOS')"): round 8 read SAFE too
  const A = join(d, 'A'), B = join(d, 'B');
  fixedLib(join(A, 'libbrotlidec.1.dylib'), { cpu: [0x01000007, 8] }); fixedLib(join(B, 'libbrotlidec.1.dylib'), { platform: 2 });
  const files = [
    ['X1', bin(join(d, 'X1', 'prog'), [], { cpu: CPU.x86_64Program, links: ['@rpath/libbrotlidec.1.dylib'], rpaths: [A], platform: 1 })],
    ['X4', bin(join(d, 'X4', 'prog'), [], { cpu: CPU.x86_64Program, links: [join(A, 'libbrotlidec.1.dylib')], platform: 1 })],
    ['D1old', bin(join(d, 'D1old', 'prog'), [], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths: [B], platform: 1 })],
    ['D4', bin(join(d, 'D4', 'prog'), [], { links: [join(B, 'libbrotlidec.1.dylib')], platform: 1 })],
  ];
  // the system's folders hold an unfixed copy: a candidate beside the fixed one, UNKNOWN, never SAFE
  oldLib(join(sys, 'libbrotlidec.1.dylib'));
  for (const [what, f] of files) {
    const r = judge(f, [sys]);
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.equal(r.via, join(sys, 'libbrotlidec.1.dylib'), what);
    assert.match(r.reason, /are not all fixed or all unfixed/, what);
  }
  // the clean twins: the system's copy fixed too, SAFE, both named; or no copy there at all, SAFE by the one there is
  fixedLib(join(sys, 'libbrotlidec.1.dylib'));
  for (const [what, f] of files) {
    const r = judge(f, [sys]);
    assert.equal(r.status, 'SAFE', `${what}: ${r.reason}`); assert.ok(r.searched.includes(join(sys, 'libbrotlidec.1.dylib')), what);
    assert.equal(judge(f, [fresh(`fallback-none-${what}`)]).status, 'SAFE', what);
  }
  // every copy unfixed: EXPOSED, by whichever dyld takes
  oldLib(join(A, 'libbrotlidec.1.dylib'), { cpu: [0x01000007, 8] }); oldLib(join(B, 'libbrotlidec.1.dylib'), { platform: 2 }); oldLib(join(sys, 'libbrotlidec.1.dylib'));
  for (const [what, f] of files) assert.equal(judge(f, [sys]).status, 'EXPOSED', what);
});

test('ELF: every copy in a folder a loader may look in is a candidate: glibc 2.36\'s old hardware subfolders (L1 to L6), a library another library loaded first (S7), a copy of other ABI flags (F1 to F3)', () => {
  const d = fresh('r8');
  // L1 to L4: glibc 2.36 and older (Debian 12, Ubuntu 22.04, RHEL 9) look in a search folder's old hardware subfolders
  // (x86_64, tls, haswell, tls/haswell/x86_64, ...) before the folder itself: an unfixed copy there beside lib/'s fixed
  // one. Round 8 looked only in glibc-hwcaps/* and read SAFE; round 9 looks in every subfolder down to 3 levels: UNKNOWN.
  // The clean twins (Lt): both fixed, SAFE
  const prog = (id, o = {}) => elf(join(d, id, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib', ...o });
  for (const [id, sub] of [['L1', 'x86_64'], ['L2', 'tls'], ['L3', 'haswell'], ['L4', 'tls/haswell/x86_64']]) {
    const hw = join(d, id, 'lib', ...sub.split('/'), 'libbrotlidec.so.1');
    fixedLib(join(d, id, 'lib', 'libbrotlidec.so.1')); oldLib(hw);
    const r = judge(prog(id));
    assert.equal(r.status, 'UNKNOWN', `${id}: ${r.reason}`); assert.equal(r.via, hw, id);
    fixedLib(hw);
    const t = judge(prog(id));
    assert.equal(t.status, 'SAFE', `${id}, the clean twin: ${t.reason}`); assert.ok(t.searched.includes(hw), id);
  }
  // the subfolder a link to a folder elsewhere (lib/x86_64 -> ../v3): the loader opens lib/x86_64/libbrotlidec.so.1
  // through it, so it is gone into like any other (by its real path)
  fixedLib(join(d, 'L1l', 'lib', 'libbrotlidec.so.1')); oldLib(join(d, 'L1l', 'v3', 'libbrotlidec.so.1'));
  symlinkSync(join(d, 'L1l', 'v3'), join(d, 'L1l', 'lib', 'x86_64'));
  const linked = judge(prog('L1l'));
  assert.equal(linked.status, 'UNKNOWN', linked.reason); assert.equal(linked.via, join(d, 'L1l', 'v3', 'libbrotlidec.so.1'));
  fixedLib(join(d, 'L1l', 'v3', 'libbrotlidec.so.1'));
  assert.equal(judge(prog('L1l')).status, 'SAFE', 'L1l, the clean twin');
  // L5: no search path of its own: a system folder's copy fixed, its x86_64/ subfolder's unfixed. L6: aarch64, lib/tls/
  const l5sys = fresh('r8-L5-sys');
  fixedLib(join(l5sys, 'libbrotlidec.so.1')); oldLib(join(l5sys, 'x86_64', 'libbrotlidec.so.1'));
  const l5 = elf(join(d, 'L5', 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'] });
  assert.equal(judge(l5, [l5sys]).status, 'UNKNOWN', 'L5');
  fixedLib(join(l5sys, 'x86_64', 'libbrotlidec.so.1'));
  assert.equal(judge(l5, [l5sys]).status, 'SAFE', 'L5, the clean twin');
  fixedLib(join(d, 'L6', 'lib', 'libbrotlidec.so.1'), { machine: 183 }); oldLib(join(d, 'L6', 'lib', 'tls', 'libbrotlidec.so.1'), { machine: 183 });
  assert.equal(judge(prog('L6', { machine: 183 })).status, 'UNKNOWN', 'L6');
  fixedLib(join(d, 'L6', 'lib', 'tls', 'libbrotlidec.so.1'), { machine: 183 });
  assert.equal(judge(prog('L6', { machine: 183 })).status, 'SAFE', 'L6, the clean twin');
  // S7: node (DT_RUNPATH lib) needs libfoo.so.1, then libnode.so.115. libfoo, with no search path, links
  // libbrotlidec.so.1, so glibc loads the system's unfixed copy first; libnode's own DT_RUNPATH ($ORIGIN) holds a fixed
  // one, but glibc hands libnode the copy already loaded (by its soname). Round 8 read SAFE, by libnode's own folder;
  // round 9: the system's copy is a candidate for every link, UNKNOWN. The clean twin: the system's copy fixed too, SAFE
  const s7sys = fresh('r8-S7-sys');
  fixedLib(join(d, 'S7', 'lib', 'libbrotlidec.so.1')); oldLib(join(s7sys, 'libbrotlidec.so.1'));
  elf(join(d, 'S7', 'lib', 'libfoo.so.1'), [], { soname: 'libfoo.so.1', needed: ['libbrotlidec.so.1', 'libc.so.6'] });
  elf(join(d, 'S7', 'lib', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN' });
  const s7 = elf(join(d, 'S7', 'bin', 'node'), [], { needed: ['libfoo.so.1', 'libnode.so.115', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  const s7r = judge(s7, [s7sys]);
  assert.equal(s7r.status, 'UNKNOWN', s7r.reason); assert.equal(s7r.via, join(s7sys, 'libbrotlidec.so.1'));
  fixedLib(join(s7sys, 'libbrotlidec.so.1'));
  assert.equal(judge(s7, [s7sys]).status, 'SAFE', 'S7, the clean twin');
  // F1 to F3: glibc passes over a copy whose ABI flags differ from the program's (ppc64's ELFv1 and ELFv2, MIPS's n32
  // and o32, NaN2008 and legacy NaN) and goes on to the system's: a fixed copy of the other ABI in the program's own
  // DT_RUNPATH, an unfixed one of its own ABI in the system's folder. Round 8 read SAFE (same class, byte order and
  // machine, loadable); round 9 judges no ABI flag: UNKNOWN. The clean twins: the system's copy fixed too, SAFE
  for (const [id, o, libFlags, sysFlags] of [['F1', { bits: 64, be: true, machine: 21 }, 2, 1], ['F2', { bits: 32, be: true, machine: 8 }, 0x20, 0], ['F3', { bits: 32, be: true, machine: 8 }, 0, 0x400]]) {
    const fsys = fresh(`r8-${id}-sys`);
    fixedLib(join(d, id, 'lib', 'libbrotlidec.so.1'), { ...o, eflags: libFlags }); oldLib(join(fsys, 'libbrotlidec.so.1'), { ...o, eflags: sysFlags });
    const f = prog(id, { ...o, eflags: sysFlags });
    const r = judge(f, [fsys]);
    assert.equal(r.status, 'UNKNOWN', `${id}: ${r.reason}`); assert.equal(r.via, join(fsys, 'libbrotlidec.so.1'), id);
    fixedLib(join(fsys, 'libbrotlidec.so.1'), { ...o, eflags: sysFlags });
    assert.equal(judge(f, [fsys]).status, 'SAFE', `${id}, the clean twin`);
  }
});

test('rule 2: the libraries a file loads are followed, and the folders they name join the ones every link is looked for in; one that can\'t be read leaves them unknown', () => {
  const d = fresh('follow'), X = fresh('follow-x');
  // the program (DT_RUNPATH lib) links libfoo.so.1 (in lib/, whose own DT_RUNPATH names X) and libbrotlidec.so.1 (lib/'s
  // copy, fixed). X, which only libfoo names, holds an unfixed libbrotlidec.so.1: a folder a library it loads names is
  // one a loader may look in, so UNKNOWN. Round 8 read SAFE, never reading libfoo
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); oldLib(join(X, 'libbrotlidec.so.1'));
  const foo = (o) => elf(join(d, 'lib', 'libfoo.so.1'), [], { soname: 'libfoo.so.1', needed: ['libbrotlidec.so.1', 'libc.so.6'], ...o });
  foo({ runpath: X });
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libfoo.so.1', 'libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  const r = judge(prog);
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, join(X, 'libbrotlidec.so.1'));
  // the clean twins: X's copy fixed (SAFE, both named), or libfoo naming no folder (SAFE by lib/'s alone)
  fixedLib(join(X, 'libbrotlidec.so.1'));
  const good = judge(prog);
  assert.equal(good.status, 'SAFE', good.reason); assert.deepEqual(good.searched, [prog, join(d, 'lib', 'libbrotlidec.so.1'), join(X, 'libbrotlidec.so.1')]);
  oldLib(join(X, 'libbrotlidec.so.1')); foo({});
  assert.equal(judge(prog).status, 'SAFE');
  // and through a library it loads that loads another (libfoo, then libbar, whose DT_RPATH names X): followed as far as
  // they go
  foo({ needed: ['libbar.so.2'] }); elf(join(d, 'lib', 'libbar.so.2'), [], { soname: 'libbar.so.2', rpath: X });
  assert.equal(judge(prog).status, 'UNKNOWN', 'two levels down');
  foo({});
  // the same on Mach-O: a dylib's LC_RPATH (with its @loader_path) names X
  const m = join(d, 'macho');
  fixedLib(join(m, 'lib', 'libbrotlidec.1.dylib')); oldLib(join(X, 'libbrotlidec.1.dylib'));
  bin(join(m, 'lib', 'libfoo.1.dylib'), [], { type: 6, rpaths: [X] });
  const mprog = bin(join(m, 'bin', 'prog'), [CONTROL, MARKER], { links: ['@rpath/libfoo.1.dylib', '@rpath/libbrotlidec.1.dylib'], rpaths: ['@loader_path/../lib'] });
  assert.equal(judge(mprog).status, 'UNKNOWN');
  bin(join(m, 'lib', 'libfoo.1.dylib'), [], { type: 6 });
  assert.equal(judge(mprog).status, 'SAFE', 'the clean twin: libfoo names no folder');
  // a library it loads that can't be read as Mach-O or ELF: the folders it would name aren't known, UNKNOWN, naming it;
  // and one whose search path is relative (the folder the program starts in) or another $ word
  writeFileSync(join(d, 'lib', 'libfoo.so.1'), Buffer.from('not a library\0\x01\x02'));
  const bad = judge(prog);
  assert.equal(bad.status, 'UNKNOWN'); assert.ok(bad.reason.includes(`and ${join(d, 'lib', 'libfoo.so.1')}, a library found for it or for another library it loads, could not be read as a Mach-O or ELF library`), bad.reason);
  // plain text of that name (a linker script) or a static archive is no library a loader can load: no candidate, so
  // nothing is left unknown (round 10, rule 3; round 9 read a text file UNKNOWN as above)
  for (const [what, bytes] of [['a linker script', '/* GNU ld script */\nGROUP ( libfoo.so.1.2 )\n'], ['a static archive', '!<arch>\n/               0           0     0     0       4         `\n\0\0\0\0']]) {
    writeFileSync(join(d, 'lib', 'libfoo.so.1'), bytes);
    assert.equal(judge(prog).status, 'SAFE', what);
  }
  for (const [runpath, says] of [['rel', /looks for it in 'rel', a folder named by a relative path/], ['$PLATFORM/x', /can't follow or open \(through '\$PLATFORM\/x'\)/]]) {
    foo({ runpath });
    const u = judge(prog);
    assert.equal(u.status, 'UNKNOWN', runpath); assert.match(u.reason, says, runpath);
  }
  foo({});
  assert.equal(judge(prog).status, 'SAFE', 'the clean twin');
});

test('a candidate is a file of exactly the library\'s name, compared ignoring case where the disk ignores it (macOS): a copy under another case is one too there, and not elsewhere', () => {
  const d = fresh('case-cands'), A = join(d, 'A'), B = join(d, 'B');
  // DT_RUNPATH A then B: A's libbrotlidec.so.1 fixed, B's LIBBROTLIDEC.SO.1 unfixed. A loader on a disk that ignores
  // case opens B's for the name too, so it is a candidate: UNKNOWN. Compared by case (Linux's disks), B's is another
  // name, unless B's own file system ignores case: the name is opened in every folder as the loader opens it (round 10,
  // rule 5), so on such a disk (this test's folder on macOS) UNKNOWN, and on one that keeps case SAFE by A's
  fixedLib(join(A, 'libbrotlidec.so.1')); elf(join(B, 'LIBBROTLIDEC.SO.1'), ['_SUCCESS', CONTROL, '_ERROR_UNREACHABLE'], { type: 3 });
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: `${A}:${B}` });
  const r = judge(prog, [], { caseless: true });
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, join(B, 'LIBBROTLIDEC.SO.1'));
  const ignores = existsSync(join(B, 'libbrotlidec.so.1'));
  assert.equal(judge(prog, [], { caseless: false }).status, ignores ? 'UNKNOWN' : 'SAFE', 'compared by case');
  // the clean twin: B's copy fixed too, SAFE either way
  elf(join(B, 'LIBBROTLIDEC.SO.1'), ['_SUCCESS', CONTROL, MARKER, '_ERROR_UNREACHABLE'], { type: 3 });
  for (const caseless of [true, false]) assert.equal(judge(prog, [], { caseless }).status, 'SAFE', `the clean twin, caseless ${caseless}`);
  // a library that isn't a Brotli library, linked by a bare name: dyld looks for it from the folder the program is
  // started in, so the folders it names aren't known, and every link is UNKNOWN; the clean twin links it by its path
  fixedLib(join(A, 'libbrotlidec.1.dylib'));
  const bare = judge(bin(join(d, 'bin', 'bare'), [CONTROL, MARKER], { links: ['libfoo.1.dylib', '@rpath/libbrotlidec.1.dylib'], rpaths: [A, B] }), [], { caseless: true });
  assert.equal(bare.status, 'UNKNOWN', bare.reason); assert.match(bare.reason, /it links @rpath\/libbrotlidec\.1\.dylib, and libfoo\.1\.dylib, a library it loads \(or one of those loads\), could not be followed or opened/);
  assert.equal(judge(bin(join(d, 'bin', 'pathed'), [CONTROL, MARKER], { links: [join(A, 'libfoo.1.dylib'), '@rpath/libbrotlidec.1.dylib'], rpaths: [A, B] }), [], { caseless: true }).status, 'SAFE');
});

test('a subfolder another account owns that this account can\'t open is passed over (no program run by this account loads from it); one this account owns and can\'t open is UNKNOWN', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  // a root-owned private folder of the machine's own: macOS's /private/var/at/tabs (cron's), Debian's /etc/ssl/private
  const found = [['/private/var/at', 'tabs'], ['/etc/ssl', 'private']].find(([p, sub]) => {
    try { const st = statSync(join(p, sub)); if (st.uid === process.getuid() || !st.isDirectory()) return false; readdirSync(join(p, sub)); return false; } catch (e) { return e.code === 'EACCES'; }
  });
  if (process.platform === 'darwin') assert.ok(found, 'macOS keeps /private/var/at/tabs root\'s own');
  const d = fresh('others');
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1'));
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN/../lib' });
  if (found) {
    // lib/sys is a link to its parent folder, so the private folder is lib/sys/<it>, two levels down: passed over, SAFE
    symlinkSync(found[0], join(d, 'lib', 'sys'));
    const r = judge(prog);
    assert.equal(r.status, 'SAFE', r.reason);
    rmSync(join(d, 'lib', 'sys'));
  }
  // one this account owns and has shut: UNKNOWN, naming it (the twin: open, SAFE)
  const shut = join(d, 'lib', 'x86_64');
  mkdirSync(shut); execFileSync('chmod', ['000', shut]);
  try {
    const r = judge(prog);
    assert.equal(r.status, 'UNKNOWN', r.reason); assert.ok(r.reason.includes(`can't follow or open (through '${shut}')`), r.reason);
  } finally { execFileSync('chmod', ['755', shut]); }
  assert.equal(judge(prog).status, 'SAFE');
});

// Round 10 (decision #25 stands: no loader's search order is predicted, and never which copy wins). The round-9 verifier
// found copies a loader takes that no rule made a candidate; each is closed by a rule that only widens the candidates or
// the closure (rules 1 to 6 in linkPlaces). Each test reads at b7ba7c5 as the finding says, and has its clean twin:
// every candidate fixed, SAFE.
test('rule 1 (O1): a library reached by several paths gives the $ORIGIN of every one, so a link to it in another folder names that folder\'s $ORIGIN too', () => {
  const d = fresh('r10-o1'), sys = fresh('r10-o1-sys');
  // node's DT_RUNPATH is $ORIGIN/../top:$ORIGIN/../B/lib. libnode is in top/A/lib (a subfolder of top, met first), and
  // B/lib/libnode.so.115 is a link to it; libnode's DT_RUNPATH is $ORIGIN/../dec. glibc and musl open
  // B/lib/libnode.so.115 (glibc looks in no subfolder of top but glibc-hwcaps) and take $ORIGIN from the path they
  // opened (glibc elf/dl-object.c, musl fixup_rpath): B/dec, whose copy is unfixed. Round 9 kept the first path only,
  // top/A/lib, never looked in B/dec, and read SAFE
  const bDec = join(d, 'B', 'dec', 'libbrotlidec.so.1'), aDec = join(d, 'top', 'A', 'dec', 'libbrotlidec.so.1'), sysDec = join(sys, 'libbrotlidec.so.1');
  fixedLib(aDec); oldLib(bDec); fixedLib(sysDec);
  elf(join(d, 'top', 'A', 'lib', 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../dec' });
  mkdirSync(join(d, 'B', 'lib'), { recursive: true }); symlinkSync('../../top/A/lib/libnode.so.115', join(d, 'B', 'lib', 'libnode.so.115'));
  const node = elf(join(d, 'bin', 'node'), [], { needed: ['libnode.so.115', 'libc.so.6'], runpath: '$ORIGIN/../top:$ORIGIN/../B/lib' });
  const r = judge(node, [sys]);
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, bDec);
  // every copy unfixed: EXPOSED; the clean twin, every copy fixed: SAFE, naming B/dec's
  oldLib(aDec); oldLib(sysDec);
  assert.equal(judge(node, [sys]).status, 'EXPOSED');
  for (const f of [aDec, bDec, sysDec]) fixedLib(f);
  const good = judge(node, [sys]);
  assert.equal(good.status, 'SAFE', good.reason); assert.ok(good.searched.includes(bDec), good.searched.join());
});

test('rule 2 (N1, N10, N11, N13, G1, G1o, G1c, G1n): every Brotli library (or libnode) a link in the closure reaches, by any name, is a candidate for every Brotli (or libnode) link: a copy another library loads first, or one a loader hands out for its install name or soname', () => {
  const d = fresh('r10-rule2');
  const evilOf = (root, name = 'libbrotlidec.1.dylib') => join(d, root, 'evil', name);
  const mach = (bad, f, o) => (bad ? oldLib : fixedLib)(f, { type: 6, ...o });
  const cases = [
    // N1 (real dyld, no loader variable set): node links @rpath/libfoo.dylib, then @rpath/libnode.147.dylib (LC_RPATH
    // @loader_path/../lib). libfoo links an unfixed copy by its absolute path, whose install name is
    // @rpath/libbrotlidec.1.dylib; libnode links @rpath/libbrotlidec.1.dylib, and its own folder holds a fixed one. dyld
    // hands libnode the image it loaded for libfoo, by its install name: libnode's decoder is the unfixed one.
    // N10: the same, the unfixed copy's file named libz.1.dylib. N11: libnode links the fixed copy by its absolute path,
    // and libfoo links (by @loader_path) an unfixed copy whose install name is that same path. Round 9: SAFE, each
    ...['N1', 'N10', 'N11'].map((id) => [id, (bad) => {
      const lib = join(d, id, 'lib'), evil = evilOf(id, id === 'N10' ? 'libz.1.dylib' : undefined), fixed = join(lib, 'libbrotlidec.1.dylib');
      mach(bad, evil, { id: id === 'N11' ? fixed : '@rpath/libbrotlidec.1.dylib' }); fixedLib(fixed, { type: 6, id: id === 'N11' ? fixed : '@rpath/libbrotlidec.1.dylib' });
      bin(join(lib, 'libfoo.dylib'), [], { type: 6, id: '@rpath/libfoo.dylib', links: [id === 'N11' ? '@loader_path/../evil/libbrotlidec.1.dylib' : evil] });
      bin(join(lib, 'libnode.147.dylib'), [NODE_CONTROL, NODE_MARKER], { type: 6, id: '@rpath/libnode.147.dylib', links: [id === 'N11' ? fixed : '@rpath/libbrotlidec.1.dylib'], rpaths: ['@loader_path'] });
      return [bin(join(d, id, 'bin', 'node'), [], { links: ['@rpath/libfoo.dylib', '@rpath/libnode.147.dylib'], rpaths: ['@loader_path/../lib'] }), evil];
    }]),
    // N13: the program links evil/libz.1.dylib (unfixed; install name @rpath/libbrotlidec.1.dylib) by its path, then
    // @rpath/libbrotlidec.1.dylib (lib/ fixed): dyld hands it the libz image already loaded. Round 9: SAFE
    ['N13', (bad) => {
      const evil = evilOf('N13', 'libz.1.dylib');
      mach(bad, evil, { id: '@rpath/libbrotlidec.1.dylib' }); fixedLib(join(d, 'N13', 'lib', 'libbrotlidec.1.dylib'), { type: 6, id: '@rpath/libbrotlidec.1.dylib' });
      return [bin(join(d, 'N13', 'bin', 'prog'), [], { links: [evil, '@rpath/libbrotlidec.1.dylib'], rpaths: ['@loader_path/../lib'] }), evil];
    }],
    // G1 and G1o (glibc's source: elf/dl-load.c _dl_map_object reuses a loaded object of that DT_SONAME before any
    // search): node (DT_RUNPATH lib) needs libfoo.so.1, then libnode.so.115; libfoo needs an unfixed copy by its
    // absolute path (G1) or by $ORIGIN/../evil (G1o), whose soname is libbrotlidec.so.1; libnode (DT_RUNPATH $ORIGIN)
    // needs libbrotlidec.so.1, and lib/ holds a fixed one. Round 9: SAFE, both
    ...[['G1', 'absolute'], ['G1o', '$ORIGIN']].map(([id, how]) => [id, (bad) => {
      const lib = join(d, id, 'lib'), evil = join(d, id, 'evil', 'libbrotlidec.so.1');
      (bad ? oldLib : fixedLib)(evil, { soname: 'libbrotlidec.so.1' }); fixedLib(join(lib, 'libbrotlidec.so.1'), { soname: 'libbrotlidec.so.1' });
      elf(join(lib, 'libfoo.so.1'), [], { soname: 'libfoo.so.1', needed: [how === 'absolute' ? evil : '$ORIGIN/../evil/libbrotlidec.so.1', 'libc.so.6'] });
      elf(join(lib, 'libnode.so.115'), [NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115', needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN' });
      return [elf(join(d, id, 'bin', 'node'), [], { needed: ['libfoo.so.1', 'libnode.so.115', 'libc.so.6'], runpath: '$ORIGIN/../lib' }), evil];
    }]),
    // G1c: the program needs libz.so.1, then libbrotlidec.so.1 (DT_RUNPATH lib); lib/libz.so.1 is an unfixed Brotli
    // decoder whose soname is libbrotlidec.so.1, which glibc reuses for the second. Round 9: SAFE
    ['G1c', (bad) => {
      const evil = join(d, 'G1c', 'lib', 'libz.so.1');
      (bad ? oldLib : fixedLib)(evil, { soname: 'libbrotlidec.so.1' }); fixedLib(join(d, 'G1c', 'lib', 'libbrotlidec.so.1'));
      return [elf(join(d, 'G1c', 'bin', 'prog'), [], { needed: ['libz.so.1', 'libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib' }), evil];
    }],
    // G1n, the same for libnode: node needs libfoo.so.1, then libnode.so.115 (lib/'s, fixed); libfoo needs an unfixed
    // libnode by its absolute path, soname libnode.so.115, which glibc reuses for node's. Round 9: SAFE
    ['G1n', (bad) => {
      const lib = join(d, 'G1n', 'lib'), evil = join(d, 'G1n', 'evil', 'libnode.so.115');
      elf(evil, bad ? [CONTROL, NODE_CONTROL] : [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115' });
      elf(join(lib, 'libnode.so.115'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER], { soname: 'libnode.so.115' });
      elf(join(lib, 'libfoo.so.1'), [], { soname: 'libfoo.so.1', needed: [evil, 'libc.so.6'] });
      return [elf(join(d, 'G1n', 'bin', 'node'), [], { needed: ['libfoo.so.1', 'libnode.so.115', 'libc.so.6'], runpath: '$ORIGIN/../lib' }), evil];
    }],
  ];
  for (const [id, make] of cases) {
    const [prog, evil] = make(true);
    const r = judge(prog);
    assert.equal(r.status, 'UNKNOWN', `${id}: ${r.reason}`); assert.equal(r.via, evil, id); assert.match(r.reason, /are not all fixed or all unfixed/, id);
    // the clean twin: the copy the other library reaches fixed too, SAFE, naming it
    make(false);
    const t = judge(prog);
    assert.equal(t.status, 'SAFE', `${id}, the clean twin: ${t.reason}`); assert.ok(t.searched.includes(evil), `${id}: ${t.searched.join()}`);
  }
  // every copy unfixed: EXPOSED
  const [n1] = cases[0][1](true);
  oldLib(join(d, 'N1', 'lib', 'libbrotlidec.1.dylib'), { type: 6, id: '@rpath/libbrotlidec.1.dylib' });
  assert.equal(judge(n1).status, 'EXPOSED');
  // a library of another name with an install name of its own, which no link hands out for a Brotli library (N13t,
  // real dyld: the program's decoder is the fixed one): no candidate, SAFE by lib/'s
  const z = evilOf('N13t', 'libz.1.dylib');
  oldLib(z, { type: 6, id: z }); fixedLib(join(d, 'N13t', 'lib', 'libbrotlidec.1.dylib'), { type: 6, id: '@rpath/libbrotlidec.1.dylib' });
  assert.equal(judge(bin(join(d, 'N13t', 'bin', 'prog'), [], { links: [z, '@rpath/libbrotlidec.1.dylib'], rpaths: ['@loader_path/../lib'] })).status, 'SAFE');
});

test('rule 3 (G2, G2b): every file of a Brotli library\'s name, and every one whose soname is the link\'s, in the folders looked in is a candidate; a static archive or plain text is none, and Debian\'s and Homebrew\'s layouts read as the one file they install', () => {
  const d = fresh('r10-rule3');
  const prog = (root) => elf(join(root, 'bin', 'prog'), [], { needed: ['libbrotlidec.so.1', 'libc.so.6'] });
  // G2: the system folder's copy fixed; its glibc-hwcaps/x86-64-v3 holds libbrotlidec.so.1 (fixed) and
  // libbrotlidec.so.1.0.9 (unfixed, soname libbrotlidec.so.1): ldconfig (glibc 2.33 and later, elf/ldconfig.c
  // search_dir) caches a glibc-hwcaps subfolder's library by its own file and, of two with one soname, the higher name,
  // which ld.so loads on a CPU of that level. G2b: the subfolder holds only libbrotlidec.so.1.2.0 (unfixed; ldconfig
  // makes no soname link there). G2s: its unfixed copy is a file of another name, libz.so.1.2.0, with that soname. Round 9
  // read all three SAFE
  for (const [id, files] of [['G2', [['libbrotlidec.so.1', true], ['libbrotlidec.so.1.0.9', false]]], ['G2b', [['libbrotlidec.so.1.2.0', false]]], ['G2s', [['libz.so.1.2.0', false]]]]) {
    const sys = join(d, id, 'sys'), hw = join(sys, 'glibc-hwcaps', 'x86-64-v3'), bad = join(hw, files.find(([, good]) => !good)[0]);
    fixedLib(join(sys, 'libbrotlidec.so.1'), { soname: 'libbrotlidec.so.1' });
    for (const [name, good] of files) (good ? fixedLib : oldLib)(join(hw, name), { soname: 'libbrotlidec.so.1' });
    const r = judge(prog(join(d, id)), [sys]);
    assert.equal(r.status, 'UNKNOWN', `${id}: ${r.reason}`); assert.equal(r.via, bad, id);
    fixedLib(bad, { soname: 'libbrotlidec.so.1' });
    const t = judge(prog(join(d, id)), [sys]);
    assert.equal(t.status, 'SAFE', `${id}, the clean twin: ${t.reason}`); assert.ok(t.searched.includes(bad), id);
  }
  // Debian's libbrotli1 and libbrotli-dev: libbrotlidec.so.1.0.9 (the file), libbrotlidec.so.1 and libbrotlidec.so
  // (links to it), libbrotlidec.a (a static archive, here holding an unfixed table's text) and pkgconfig/libbrotlidec.pc
  // (text): one candidate, by its real path, SAFE or EXPOSED by it alone
  const deb = join(d, 'debian', 'usr', 'lib', 'x86_64-linux-gnu'), debLib = join(deb, 'libbrotlidec.so.1.0.9');
  fixedLib(debLib, { soname: 'libbrotlidec.so.1' });
  symlinkSync('libbrotlidec.so.1.0.9', join(deb, 'libbrotlidec.so.1')); symlinkSync('libbrotlidec.so.1', join(deb, 'libbrotlidec.so'));
  writeFileSync(join(deb, 'libbrotlidec.a'), Buffer.concat([Buffer.from('!<arch>\n'), Buffer.alloc(60, 0x20), Buffer.from(`\0_SUCCESS\0${CONTROL}\0`)]));
  mkdirSync(join(deb, 'pkgconfig')); writeFileSync(join(deb, 'pkgconfig', 'libbrotlidec.pc'), 'prefix=/usr\nlibdir=${prefix}/lib/x86_64-linux-gnu\n\nName: libbrotlidec\nVersion: 1.0.9\nLibs: -L${libdir} -lbrotlidec\n');
  const debProg = prog(join(d, 'debian'));
  const dg = judge(debProg, [deb]);
  assert.equal(dg.status, 'SAFE', dg.reason); assert.deepEqual(dg.searched, [debProg, debLib]);
  oldLib(debLib, { soname: 'libbrotlidec.so.1' });
  const db = judge(debProg, [deb]);
  assert.equal(db.status, 'EXPOSED', db.reason); assert.equal(db.via, debLib);
  // Homebrew's brotli 1.2.1: lib/libbrotlidec.1.2.1.dylib (the file), libbrotlidec.1.dylib and libbrotlidec.dylib (links
  // to it) and lib/pkgconfig/libbrotlidec.pc: one candidate
  const brew = join(d, 'brew', 'lib'), brewLib = join(brew, 'libbrotlidec.1.2.1.dylib');
  fixedLib(brewLib, { type: 6, id: join(brew, 'libbrotlidec.1.dylib') });
  symlinkSync('libbrotlidec.1.2.1.dylib', join(brew, 'libbrotlidec.1.dylib')); symlinkSync('libbrotlidec.1.2.1.dylib', join(brew, 'libbrotlidec.dylib'));
  mkdirSync(join(brew, 'pkgconfig')); writeFileSync(join(brew, 'pkgconfig', 'libbrotlidec.pc'), 'prefix=/opt/homebrew/Cellar/brotli/1.2.1\nName: libbrotlidec\nVersion: 1.2.1\n');
  const brewProg = bin(join(d, 'brew', 'bin', 'prog'), [], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths: ['@loader_path/../lib'] });
  const bg = judge(brewProg);
  assert.equal(bg.status, 'SAFE', bg.reason); assert.deepEqual(bg.searched, [brewProg, brewLib]);
  // a file of that name that is neither an archive nor text, and not Mach-O or ELF (a compressed copy): it can't be read
  // as a library, UNKNOWN, naming it (round 9: not a candidate, SAFE); the clean twin without it, SAFE
  fixedLib(debLib, { soname: 'libbrotlidec.so.1' });
  writeFileSync(join(deb, 'libbrotlidec.so.1.0.9.gz'), Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x4b, 0x04, 0]));
  const gz = judge(debProg, [deb]);
  assert.equal(gz.status, 'UNKNOWN', gz.reason); assert.ok(gz.reason.includes(`and ${join(deb, 'libbrotlidec.so.1.0.9.gz')}, a library found for it or for another library it loads, could not be read as a Mach-O or ELF library`), gz.reason);
  rmSync(join(deb, 'libbrotlidec.so.1.0.9.gz'));
  assert.equal(judge(debProg, [deb]).status, 'SAFE', 'the clean twin');
  // a wider name never stands in for the link: a file only of a Brotli library's name (another soname), with no file of
  // the link's own name or soname, leaves it not found, UNKNOWN; with the link's own, every one decides
  const only = join(d, 'only', 'sys');
  fixedLib(join(only, 'libbrotlidec.so.0.9.0'), { soname: 'libbrotlidec.so.0' });
  const nf = judge(prog(join(d, 'only')), [only]);
  assert.equal(nf.status, 'UNKNOWN', nf.reason); assert.match(nf.reason, /it links libbrotlidec\.so\.1, which was not found/);
  fixedLib(join(only, 'libbrotlidec.so.1'));
  const both = judge(prog(join(d, 'only')), [only]);
  assert.equal(both.status, 'SAFE', both.reason); assert.ok(both.searched.includes(join(only, 'libbrotlidec.so.0.9.0')), both.searched.join());
});

test('rule 4 (G3): subfolders are looked in down to 4 levels, glibc 2.36\'s tls/haswell/avx512_1/x86_64 on an Intel CPU with AVX-512 among them', () => {
  const d = fresh('r10-g3'), deep = join(d, 'lib', 'tls', 'haswell', 'avx512_1', 'x86_64', 'libbrotlidec.so.1');
  // glibc 2.36's sysdeps/x86/cpu-features.c gives such a CPU the hwcaps x86_64 and avx512_1 and the platform haswell,
  // and elf/dl-hwcaps.c adds tls: ld.so searches lib/tls/haswell/avx512_1/x86_64 first (Debian 12, Ubuntu 22.04, RHEL 8
  // and 9). Round 9 looked 3 levels down and read SAFE
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1')); oldLib(deep);
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  const r = judge(prog);
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, deep);
  fixedLib(deep);
  const t = judge(prog);
  assert.equal(t.status, 'SAFE', t.reason); assert.ok(t.searched.includes(deep));
});

test('rule 5 (G6): the link\'s file name is opened in every folder looked in, as the loader opens it, so a folder whose file system ignores case gives its copy under another case, even where names are compared by case', () => {
  const d = fresh('r10-g6'), sys = fresh('r10-g6-sys'), upper = join(d, 'lib', 'LIBBROTLIDEC.SO.1');
  fixedLib(join(sys, 'libbrotlidec.so.1')); elf(upper, ['_SUCCESS', CONTROL, '_ERROR_UNREACHABLE'], { type: 3 });
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath: '$ORIGIN/../lib' });
  // whether this test's folder ignores case: open() finds the file by the link's name there (macOS's APFS; on Linux an
  // ext4 folder with casefold, vfat, exFAT, WSL's /mnt/c), and the loader takes it; on a disk that keeps case it can't.
  // Round 9 compared names by case off macOS and read SAFE on either
  const ignores = existsSync(join(d, 'lib', 'libbrotlidec.so.1'));
  const r = judge(prog, [sys], { caseless: false });
  if (ignores) { assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, upper); } else assert.equal(r.status, 'SAFE', r.reason);
  // the clean twin: that copy fixed, SAFE, named where the folder ignores case
  elf(upper, ['_SUCCESS', CONTROL, MARKER, '_ERROR_UNREACHABLE'], { type: 3 });
  const t = judge(prog, [sys], { caseless: false });
  assert.equal(t.status, 'SAFE', t.reason); assert.equal(t.searched.includes(upper), ignores, t.searched.join());
});

test('rule 6: every library /etc/ld.so.preload names joins the closure, looked for as the program\'s own links (glibc loads them into every program first); a preload file that can\'t be read, or a name in it that can\'t be followed, is UNKNOWN', () => {
  const d = fresh('r10-preload'), pf = join(d, 'ld.so.preload');
  const pre = () => brotli.ldSoPreload?.(pf) ?? { names: [], gap: null };
  // read as glibc's elf/rtld.c reads it: '#' to the end of a line, names split on spaces, tabs, line feeds and ':'
  writeFileSync(pf, '# preloaded\n/opt/a/libx.so:/opt/b/liby.so libz.so\t# a comment: not a name\n\n');
  assert.deepEqual(brotli.ldSoPreload?.(pf), { names: ['/opt/a/libx.so', '/opt/b/liby.so', 'libz.so'], gap: null });
  assert.deepEqual(brotli.ldSoPreload(join(d, 'none')), { names: [], gap: null }, 'no file names nothing');
  assert.deepEqual(brotli.ldSoPreload(d), { names: [], gap: d }, 'a folder can\'t be read as one');
  // the program's own copy fixed; /etc/ld.so.preload names an unfixed one by its path (a candidate: rule 2), or a
  // library of another name, found in the system's folders, that links it. Round 9 never read the file: SAFE
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1'));
  const evil = oldLib(join(d, 'evil', 'libbrotlidec.so.1')), sys = join(d, 'sys');
  elf(join(sys, 'libshim.so'), [], { soname: 'libshim.so', needed: [evil, 'libc.so.6'] });
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib' });
  for (const [what, text] of [['by its path', `${evil}\n`], ['a library that links it', 'libshim.so\n']]) {
    writeFileSync(pf, text);
    const r = judge(prog, [sys], { preload: pre() });
    assert.equal(r.status, 'UNKNOWN', `${what}: ${r.reason}`); assert.equal(r.via, evil, what);
  }
  // one that can't be read, or a name in it that can't be followed (a relative path): UNKNOWN, saying so
  const gap = judge(prog, [sys], { preload: { names: [], gap: pf } });
  assert.equal(gap.status, 'UNKNOWN'); assert.match(gap.reason, /ld\.so\.preload, which names libraries the dynamic loader loads into every program first, could not be read/);
  writeFileSync(pf, 'rel/libfoo.so\n');
  const rel = judge(prog, [sys], { preload: pre() });
  assert.equal(rel.status, 'UNKNOWN'); assert.match(rel.reason, /rel\/libfoo\.so, a library \/etc\/ld\.so\.preload names .*could not be followed or opened/);
  // through the command: a node on PATH, the preload file at its place (places.ldSoPreload)
  const path = fresh('r10-preload-path');
  elf(join(path, 'node'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER], { needed: ['libbrotlidec.so.1'], runpath: join(d, 'lib') });
  writeFileSync(pf, `${evil}\n`);
  const row = () => run({}, { pathEnv: path, places: { ldSoPreload: pf } }).rows.find((x) => x.file === join(path, 'node'));
  assert.equal(row().status, 'UNKNOWN');
  // the clean twins: the preloaded copy fixed, or nothing named, SAFE
  fixedLib(evil);
  for (const [what, text] of [['by its path', `${evil}\n`], ['a library that links it', 'libshim.so\n'], ['only comments', '# nothing\n']]) {
    writeFileSync(pf, text);
    assert.equal(judge(prog, [sys], { preload: pre() }).status, 'SAFE', what);
  }
  writeFileSync(pf, `${evil}\n`);
  assert.equal(row().status, 'SAFE', 'through the command');
});

test('rule 6: a program whose PT_INTERP names a loader that is not the system\'s (Homebrew\'s on Linux, Nix\'s, a vendored glibc) is UNKNOWN: that loader searches its own folders', () => {
  const d = fresh('r10-interp');
  fixedLib(join(d, 'lib', 'libbrotlidec.so.1'));
  const prog = (interp, o = {}) => elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1', 'libc.so.6'], runpath: '$ORIGIN/../lib', interp, ...o });
  // round 9 read no PT_INTERP: SAFE, each
  for (const interp of ['/nix/store/q4mn8f2vzh7l6bry2w0a7c0d1d8b8yg8-glibc-2.40-66/lib/ld-linux-x86-64.so.2', '/home/linuxbrew/.linuxbrew/lib/ld.so', '/lib64/ld-linux-x86-64.so.2.old', 'ld-linux-x86-64.so.2']) {
    const r = judge(prog(interp));
    assert.equal(r.status, 'UNKNOWN', `${interp}: ${r.reason}`); assert.ok(r.reason.includes(`it names its own dynamic loader, ${interp} (PT_INTERP), not one of the system's`), r.reason);
  }
  // one that can't be read (its bytes don't end in a NUL, which no kernel runs): UNKNOWN too
  const cut = judge(prog('/lib64/ld-linux-x86-64.so.2', { cut: true }));
  assert.equal(cut.status, 'UNKNOWN', cut.reason); assert.match(cut.reason, /the dynamic loader it names \(PT_INTERP\) could not be read/);
  // the clean twins: the system's own loaders, glibc's and musl's, and none (a library), SAFE
  for (const interp of ['/lib64/ld-linux-x86-64.so.2', '/lib/ld-linux-aarch64.so.1', '/lib/ld-linux-armhf.so.3', '/lib/ld-musl-x86_64.so.1', '/lib/ld-musl-aarch64.so.1', '/usr/lib/ld-linux-x86-64.so.2', '/lib64/ld64.so.2', undefined]) {
    assert.equal(judge(prog(interp)).status, 'SAFE', String(interp));
  }
  // the list, exactly: glibc's and musl's per-architecture names, under /lib, /lib64 and /usr/lib
  assert.ok(brotli.SYSTEM_LOADERS?.includes('/lib64/ld-linux-x86-64.so.2'));
  assert.ok(brotli.SYSTEM_LOADERS.every((p) => /^\/(?:lib|lib64|usr\/lib)\/(?:ld-linux[a-z0-9_-]*\.so\.[123]|ld64\.so\.[12]|ld\.so\.1|ld-musl-[a-z0-9_]+\.so\.1)$/.test(p)), 'nothing else');
});

test('a folder reached again nearer a named one is gone into deeper: a search folder first met deep inside another (mutant A18)', () => {
  const d = fresh('r10-a18'), P = join(d, 'P'), deep = join(P, 'a', 'b', 'c', 'd', 'e', 'libbrotlidec.so.1');
  fixedLib(join(P, 'libbrotlidec.so.1')); oldLib(deep);
  // DT_RUNPATH P, then P/a/b/c: P's walk meets c 3 levels down and lists d, the 4th, without going into it; c, named
  // itself, is gone into again from its own level 0, so e (2 below c, 5 below P) is listed and its copy is a candidate
  const prog = (runpath) => elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: ['libbrotlidec.so.1'], runpath });
  const r = judge(prog(`${P}:${join(P, 'a', 'b', 'c')}`));
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.equal(r.via, deep);
  assert.equal(judge(prog(P)).status, 'SAFE', 'P alone: e is 5 levels below it');
  fixedLib(deep);
  assert.equal(judge(prog(`${P}:${join(P, 'a', 'b', 'c')}`)).status, 'SAFE', 'the clean twin');
});

test('a closure of more than 4,096 libraries is UNKNOWN, saying so; one of fewer is followed to its end (mutant C8)', () => {
  const d = fresh('r10-many'), lib = join(d, 'lib');
  fixedLib(join(lib, 'libbrotlidec.so.1'));
  // the program needs 64 libraries, each of which needs 64 more: 1 + 64 + 4,096 objects and the Brotli library
  const top = (i, n) => elf(join(lib, `liba${i}.so.1`), [], { soname: `liba${i}.so.1`, needed: Array.from({ length: n }, (_, j) => `libb${i}x${j}.so.1`) });
  for (let i = 0; i < 64; i++) { top(i, 64); for (let j = 0; j < 64; j++) elf(join(lib, `libb${i}x${j}.so.1`), [], { soname: `libb${i}x${j}.so.1` }); }
  const prog = elf(join(d, 'bin', 'prog'), [CONTROL, MARKER], { needed: [...Array.from({ length: 64 }, (_, i) => `liba${i}.so.1`), 'libbrotlidec.so.1'], runpath: '$ORIGIN/../lib' });
  const r = judge(prog);
  assert.equal(r.status, 'UNKNOWN', r.reason); assert.match(r.reason, /more than Wardlatch looks at \(65536 folders, 4096 libraries\)/);
  // the clean twin: two of the 64 need nothing, 4,034 objects, SAFE
  top(0, 0); top(1, 0);
  assert.equal(judge(prog).status, 'SAFE');
});

test('names outside the link table: a Brotli library\'s or libnode\'s file name the loader can load is UNKNOWN (it may be loaded while it runs, with dlopen); a static archive, an object file or a word is not', () => {
  const d = fresh('dlopen'), lib = fresh('dlopen-lib');
  const fixedDec = fixedLib(join(lib, 'libbrotlidec.1.dylib'), { type: 6 });
  fixedLib(join(lib, 'libbrotlidec.so.1')); fixedLib(join(lib, 'libbrotlidec.so.3'));
  // nodejs.org's Node.js 26.12.1 for macOS: a fixed table, and a debug map naming its static archives' members (415 of
  // libnode_base.a and libnode_crates.a, and libnode.a's), more than the 64 hits a scan keeps: SAFE
  const debugMap = Array.from({ length: 415 }, (_, i) => (i % 2 ? `/Users/admin/build/ws/out/Release/libnode_base.a(file_${i}.o)` : `libnode_crates.a(compiler_builtins-f1153aeb546e${i}.o)`));
  const map = judge(bin(join(d, 'node-debug-map'), [CONTROL, MARKER, ...debugMap, '/Users/admin/build/ws/out/Release/libnode.a(node_snapshot.o)']));
  assert.equal(map.status, 'SAFE', map.reason);
  // no file the loader loads: a static archive (.a, .a(member)), an object file, a pkg-config file, a longer word, a
  // code-signing identifier without .dylib, a separate file of debugging information (the name a stripped ELF library's
  // .gnu_debuglink gives, as objcopy writes it and as Fedora does), a word: beside a fixed table, in Mach-O and ELF, SAFE
  const not = ['libbrotlidec.a', 'lib/libbrotlidec.a(decode.o)', 'libbrotlidec-static.a', 'libbrotlidec.pc', 'built with libbrotlidec 1.2.1', 'libbrotlidec mention',
    'libnode_base.a(callback.o)', 'libnode.a', 'libnode.o', 'libbrotlidecoder.so.1', 'libnodejs.so', 'libbrotlidec.solution', 'libbrotlidec.1.2.1', 'libnode.147', 'libbrotlidec\x01.so.1', 'error: libbrotlidec\n',
    'libbrotlidec.so.1.0.9.debug', 'libbrotlidec.so.1.1.0-1.1.0-4.fc40.x86_64.debug', 'libnode.so.127-22.11.0-1.fc40.x86_64.debug', 'libnode.so.115-20.19.5+dfsg~1.debug'];
  for (const s of not) {
    for (const [what, f] of [['Mach-O', bin(join(d, `not-macho-${not.indexOf(s)}`), [CONTROL, MARKER, s])], ['ELF', elf(join(d, `not-elf-${not.indexOf(s)}`), [CONTROL, MARKER, s])], ['a 1.0 table', bin(join(d, `not-10-${not.indexOf(s)}`), [packed(V1010), s])]]) {
      const r = judge(f, [lib]);
      assert.equal(r.status, 'SAFE', `${JSON.stringify(s)} ${what}: ${r.reason}`);
    }
  }
  // a file name the loader loads, outside the table (dlopen's way, a message naming it, a path, a soname): UNKNOWN,
  // naming it, beside a fixed table, a fixed 1.0 table, a fixed library it links, and in a file with nothing else
  const loadable = ['libbrotlidec.so.1', 'libbrotlidec.so', 'libbrotlidec.dylib', 'libbrotlidec.1.dylib', '/opt/x/libbrotlidec.1.2.0.dylib', 'libbrotlidec-ba690955.so.1.1.0',
    'cannot open libbrotlidec.so.1\n', 'cannot open libbrotlidec.so.1: %s', 'libbrotlidec.so.1~', 'libbrotlidec.so.1/', 'libbrotlidec.so.1x', '@rpath/libbrotlidec.1.dylib', '../lib/libbrotlidec.so.1',
    'libnode.so.108', 'libnode.147.dylib', '/usr/lib/libnode.so.115', 'Loading libnode.so.108 failed\n', `${'x/'.repeat(600)}libbrotlidec.so.1`, 'libbrotlidec.so.1.debug.so'];
  for (const s of loadable) {
    const i = loadable.indexOf(s);
    for (const [what, f, o] of [['Mach-O, a table', bin(join(d, `yes-macho-${i}`), [CONTROL, MARKER, s])], ['ELF, a table', elf(join(d, `yes-elf-${i}`), [CONTROL, MARKER, s])],
      ['a 1.0 table', bin(join(d, `yes-10-${i}`), [packed(V1010), s])], ['a fixed library', bin(join(d, `yes-lib-${i}`), [s], { links: [fixedDec] })],
      ['nothing else', bin(join(d, `yes-bare-${i}`), [s])], ['ELF, a fixed soname', elf(join(d, `yes-so-${i}`), [s], { needed: ['libbrotlidec.so.3'] }), [lib]]]) {
      const r = judge(f, o);
      assert.equal(r.status, 'UNKNOWN', `${JSON.stringify(s.slice(-40))} ${what}`);
      assert.match(r.reason, /it names .*lib(brotlidec|node).*, the file name of a Brotli library or of libnode that is not one of the libraries it links.*\(dlopen\).*could not be tested/, `${JSON.stringify(s.slice(-40))} ${what}`);
    }
  }
  // the real-layout pair beside a fixed table: dlopen's libbrotlidec.so.1 UNKNOWN (above), the debug map's .a(member)
  // SAFE (above); and a name cut by the end of the file, which what follows could have made one, UNKNOWN
  for (const end of ['libbrotlidec.', 'libbrotlidec.so', 'libnode.1', 'libbrotlidec-ab']) {
    const f = join(d, `cut-${end}`);
    writeFileSync(f, Buffer.concat([machoHead(), ...cstrings([CONTROL, MARKER]), Buffer.from(`\0${end}`)]));
    assert.equal(judge(f).status, 'UNKNOWN', end);
  }
  const ended = join(d, 'cut-twin');
  writeFileSync(ended, Buffer.concat([machoHead(), ...cstrings([CONTROL, MARKER]), Buffer.from('\0libbrotlidec.a')]));
  assert.equal(judge(ended).status, 'SAFE', 'the clean twin: a static archive\'s name at the end');
  // a whole copy of a name it links is that link, not another library (ELF's string table, a Mach-O path): SAFE; any other
  // name, UNKNOWN
  assert.equal(judge(elf(join(d, 'copy-elf'), [CONTROL, MARKER, 'libbrotlidec.so.1'], { needed: ['libbrotlidec.so.1'] }), [lib]).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'copy-macho'), [CONTROL, MARKER, fixedDec], { links: [fixedDec] })).status, 'SAFE');
  assert.equal(judge(elf(join(d, 'other-elf'), [CONTROL, MARKER, 'libbrotlidec.so.2'], { needed: ['libbrotlidec.so.1'] }), [lib]).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'part-macho'), [CONTROL, MARKER, `/x${fixedDec}`], { links: [fixedDec] })).status, 'UNKNOWN', 'a longer path is another file');
  // what loadableAt reads after the stem
  for (const [s, want] of [['.so.1\0', true], ['.1.2.1.dylib\0', true], ['.so.1.0.9.debug\0', false], ['.so.1.debug.so\0', true], ['.so.1.debugger\0', true], ['-ba690955.so.1.1.0\0', true], ['.dylib.dSYM', true], ['.a(x.o)', false], ['_base.a(', false], ['.so.1x', true], ['.solution', false], ['coder.so', false], ['.1\0', false]]) {
    assert.equal(loadableAt(Buffer.from(`${s}${'\0'.repeat(200)}`), 0), want, JSON.stringify(s));
  }
});

test('file names ignore case on macOS: a linked name in any case is a Brotli library, and a name outside the table is found in any case there, and only as written elsewhere', () => {
  const d = fresh('case'), libDir = fresh('case-lib');
  const lower = join(libDir, 'libbrotlidec.1.dylib');
  oldLib(lower, { type: 6 });
  // whether this disk ignores case, as APFS does by default (Linux's file systems don't)
  const ignores = existsSync(join(libDir, 'LIBBROTLIDEC.1.DYLIB'));
  // the real attack: an upper-case link to an unfixed library, beside a fixed table. Its name is a Brotli library's in
  // any case, so it is followed: EXPOSED where the disk finds it, not found where it doesn't; never SAFE
  const prog = bin(join(d, 'prog'), [CONTROL, MARKER], { links: [join(libDir, 'LIBBROTLIDEC.1.DYLIB')] });
  const r = judge(prog);
  assert.equal(r.status, ignores ? 'EXPOSED' : 'UNKNOWN', r.reason);
  fixedLib(lower, { type: 6 });
  assert.equal(judge(prog).status, ignores ? 'SAFE' : 'UNKNOWN', 'the clean twin');
  for (const [ref, isDec, isNode] of [['@rpath/LIBBROTLIDEC.1.DYLIB', true, false], ['/x/LibBrotliDec.so.1', true, false], ['@rpath/LIBNODE.147.DYLIB', false, true], ['LibNode.so.108', false, true]]) {
    assert.equal(isDecoderLibName(ref), isDec, ref); assert.equal(isNodeLibName(ref), isNode, ref);
  }
  // a name outside its table: found in any case where names are compared ignoring case (macOS: caseless), and as written
  // where they aren't
  for (const s of ['LIBBROTLIDEC.SO.1', 'LibNode.147.Dylib', '/opt/X/LibBrotliDec.1.DYLIB']) {
    const f = bin(join(d, `upper-${s.length}`), [CONTROL, MARKER, s]);
    assert.equal(judge(f, [], { caseless: true }).status, 'UNKNOWN', `${s}: caseless`);
    assert.equal(judge(f, [], { caseless: false }).status, 'SAFE', `${s}: as written`);
  }
  // its own link's name in another case is its own, where case is ignored (the disk finds the same file); a different
  // name in that case is not
  const fixed = fixedLib(join(libDir, 'fixed', 'libbrotlidec.1.dylib'), { type: 6 });
  assert.equal(judge(bin(join(d, 'own-upper'), [CONTROL, MARKER, fixed.toUpperCase()], { links: [fixed] }), [], { caseless: true }).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'other-upper'), [CONTROL, MARKER, `${dirname(fixed).toUpperCase()}/LIBBROTLIDEC.2.DYLIB`], { links: [fixed] }), [], { caseless: true }).status, 'UNKNOWN');
  // and its code-signing identifier, its own file name in another case
  assert.equal(judge(fixedLib(join(d, 'libbrotlidec.1.2.1.dylib'), { type: 6, signed: 'LibBrotliDec.1.2.1.dylib' }), [], { caseless: true }).status, 'SAFE');
  assert.equal(judge(fixedLib(join(d, 'libbrotlidec.1.2.1.dylib'), { type: 6, signed: 'LibBrotliDec.1.0.9.dylib' }), [], { caseless: true }).status, 'UNKNOWN');
});

test('LC_DYLD_ENVIRONMENT: a file that sets the loader\'s own variables is UNKNOWN, beside a fixed table and a fixed library too; an unfixed table still EXPOSED', () => {
  const d = fresh('dyld-env'), fixed = fixedLib(join(d, 'lib', 'libbrotlidec.1.dylib'), { type: 6 });
  for (const env of ['DYLD_LIBRARY_PATH=/opt/old/lib', 'DYLD_INSERT_LIBRARIES=@executable_path/x.dylib', 'DYLD_FALLBACK_LIBRARY_PATH=/usr/lib']) {
    for (const [what, o] of [['a program', {}], ['a library', { type: 6 }]]) {
      const r = judge(bin(join(d, `env-${env.length}-${what.length}`), [CONTROL, MARKER], { links: [fixed], env: [env], ...o }));
      assert.equal(r.status, 'UNKNOWN', `${env} ${what}`); assert.ok(r.reason.includes(`(LC_DYLD_ENVIRONMENT '${env}')`), r.reason); assert.match(r.reason, /could not be tested/);
    }
  }
  // in one build of a universal file
  const u = judge(fat(join(d, 'fat'), [[CONTROL, MARKER], { parts: [CONTROL, MARKER], env: ['DYLD_LIBRARY_PATH=/x'] }]));
  assert.equal(u.status, 'UNKNOWN'); assert.match(u.reason, /^in one of the 2 builds this universal file holds, it sets the dynamic loader's own variables/);
  // its own unfixed table decides first
  assert.equal(judge(bin(join(d, 'env-old'), [CONTROL], { env: ['DYLD_LIBRARY_PATH=/x'] })).status, 'EXPOSED');
  // the clean twins
  assert.equal(judge(bin(join(d, 'no-env'), [CONTROL, MARKER], { links: [fixed] })).status, 'SAFE');
  assert.equal(judge(fat(join(d, 'fat-twin'), [[CONTROL, MARKER], [CONTROL, MARKER]])).status, 'SAFE');
});

test('the name the loader reads, exactly: a name offset that skips bytes in the command (the tail trick), and names with a tab, a newline, DEL, a control byte, é or a space', () => {
  const d = fresh('exact'), sys = fresh('exact-sys');
  // Mach-O: the command holds <d>/fixed and then <d>/old/libbrotlidec.1.dylib, and the name's offset skips <d>/fixed. dyld
  // loads <d>/old/libbrotlidec.1.dylib, unfixed; the whole string, read back to a NUL, names a fixed copy elsewhere
  const loaded = join(d, 'old', 'libbrotlidec.1.dylib'), decoy = `${join(d, 'fixed')}${loaded}`;
  oldLib(loaded, { type: 6 }); fixedLib(decoy, { type: 6 });
  const macho = bin(join(d, 'macho-tail'), [CONTROL, MARKER], { links: [{ name: loaded, prefix: join(d, 'fixed') }] });
  assert.deepEqual(evidence(macho, M).links, [loaded]);
  const m = judge(macho);
  assert.equal(m.status, 'EXPOSED'); assert.equal(m.via, loaded);
  // ELF: DT_NEEDED points into the tail of <d>/fixed/libbrotlidec.so.1: ld.so reads the soname libbrotlidec.so.1 and
  // finds the system's copy, unfixed
  fixedLib(join(d, 'fixed', 'libbrotlidec.so.1')); oldLib(join(sys, 'libbrotlidec.so.1'));
  const linux = elf(join(d, 'elf-tail'), [CONTROL, MARKER], { needed: [{ name: 'libbrotlidec.so.1', prefix: `${join(d, 'fixed')}/` }] });
  const e = judge(linux, [sys]);
  assert.equal(e.status, 'EXPOSED'); assert.equal(e.via, join(sys, 'libbrotlidec.so.1'));
  // the clean twins: the libraries the loader reads, fixed
  fixedLib(loaded, { type: 6 }); fixedLib(join(sys, 'libbrotlidec.so.1'));
  assert.equal(judge(macho).status, 'SAFE'); assert.equal(judge(linux, [sys]).status, 'SAFE');
  // round 4's names, as the loader reads them: a folder or file name with a tab, a newline, DEL, a control byte, an
  // escape, é, a no-break space, a space or '~', followed exactly as written, never a shorter name
  for (const [name, b] of [['tab', '\t'], ['newline', '\n'], ['del', '\x7f'], ['control', '\x01'], ['escape', '\x1b'], ['e-acute', 'é'], ['nbsp', ' '], ['space', ' '], ['tilde', '~']]) {
    // a Mach-O dylib for the Mach-O files, an ELF shared object for the ELF one
    const lib = oldLib(join(d, `pre${b}dir`, `libbrotlidec${b}.1.dylib`)), so = oldLib(join(d, `pre${b}dir`, `libbrotlidec${b}.so.1`));
    fixedLib(join(d, 'dir', `libbrotlidec${b}.1.dylib`)); fixedLib(join(d, 'dir', `libbrotlidec${b}.so.1`));   // what a scan stopping at the byte would have read
    const files = [[bin(join(d, `macho-${name}`), [CONTROL, MARKER], { links: [lib] }), lib], [elf(join(d, `elf-${name}`), [CONTROL, MARKER], { needed: [so] }), so], [bin(join(d, `form10-${name}`), [packed(V1010)], { links: [lib] }), lib]];
    for (const [f, l] of files) { const r = judge(f); assert.equal(r.status, 'EXPOSED', `${name}: ${r.reason}`); assert.equal(r.via, realpathSync(l), name); }
    fixedLib(lib); fixedLib(so);
    for (const [f] of files) assert.equal(judge(f).status, 'SAFE', `${name}: the clean twin`);
  }
  // a name that isn't UTF-8 names no file Wardlatch can look up: UNKNOWN
  const raw = Buffer.concat([Buffer.from(join(d, 'x', 'libbrotlidec')), Buffer.from([0xc3]), Buffer.from('.1.dylib')]);
  const r = judge(bin(join(d, 'not-utf8'), [CONTROL, MARKER], { links: [raw] }));
  assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /name is empty or not UTF-8.*could not be tested/);
});

test('a header that doesn\'t fit its format, or a file that is neither Mach-O nor ELF, is UNKNOWN beside a fixed table, never SAFE; an unfixed table is still EXPOSED', () => {
  const d = fresh('malformed');
  const body = Buffer.concat([Buffer.alloc(16), ...cstrings([CONTROL, MARKER]), Buffer.alloc(16)]);
  const write = (name, head, rest = body) => { const f = join(d, name); writeFileSync(f, Buffer.concat([head, rest])); return f; };
  // (a header cut short has nothing after it)
  const set32 = (b, o, v) => { const c = Buffer.from(b); c.writeUInt32LE(v >>> 0, o); return c; };
  // a 64-bit header (ncmds at 16, sizeofcmds at 20), then LC_LOAD_DYLIB of /usr/lib/libSystem.B.dylib (cmdsize 56 at 36,
  // its name's offset at 40)
  const good = machoHead({ links: ['/usr/lib/libSystem.B.dylib'] });
  assert.equal(good.readUInt32LE(36), 56);
  const noNul = Buffer.from(good); noNul.fill(0x41, 32 + 24, 32 + 56);
  // the same with a second command after it: a name read past its command's end would end at a NUL in the next one
  // (mutant P14)
  const two = machoHead({ links: ['/usr/lib/libSystem.B.dylib', '/usr/lib/libz.1.dylib'] }), noNulTwo = Buffer.from(two); noNulTwo.fill(0x41, 32 + 24, 32 + 56);
  // each with the bound it breaks, as the reason names it
  const machoCases = [['more commands than fit', set32(good, 16, 8), /it counts 8 load commands, more than fit in their 56 bytes/],
    ['commands past the file', set32(good, 20, 0x100000), /its load commands run past the end of the file/], ['commands over 1 MB', set32(good, 20, 0x100001), /more than the 1 MB Wardlatch reads/],
    ['a command under 8 bytes', set32(good, 36, 4), /load command 1 has a size \(4\) that doesn't fit/], ['a size not a multiple of 4', set32(good, 36, 54), /load command 1 has a size \(54\)/],
    ['a command past the commands', set32(good, 36, 64), /load command 1 has a size \(64\)/], ['a name inside the fields', set32(good, 40, 8), /LC_LOAD_DYLIB command's name starts outside it/],
    ['a name past the command', set32(good, 40, 56), /LC_LOAD_DYLIB command's name starts outside it/], ['a name with no NUL in its command', noNul, /LC_LOAD_DYLIB command's name has no end inside it/],
    ['a name with no NUL in its command, before another', noNulTwo, /LC_LOAD_DYLIB command's name has no end inside it/],
    ['two LC_ID_DYLIB', machoHead({ type: 6, id: '/x/libfoo.1.dylib', links: [{ name: '/x/libfoo.2.dylib', cmd: LC.id }] }), /more than one LC_ID_DYLIB/],
    ['a header cut short', MACHO, /its header is cut short/, Buffer.alloc(20)]];
  for (const [what, head, why, rest] of machoCases) {
    const r = judge(write(`macho-${what.replace(/\W/g, '_')}`, head, rest));
    assert.equal(r.status, 'UNKNOWN', what); assert.match(r.reason, /^its Mach-O headers could not be read as the format lays them out \(.+\).*could not be tested/, what); assert.match(r.reason, why, what);
  }
  // more load commands than the 1 MB read, all inside a file large enough to hold them: not read
  const huge = judge(write('macho-huge', set32(good, 20, 0x100004), Buffer.concat([Buffer.alloc(0x100100), ...cstrings([CONTROL, MARKER])])));
  assert.equal(huge.status, 'UNKNOWN'); assert.match(huge.reason, /load commands take 1048580 bytes, more than the 1 MB Wardlatch reads/);
  // ELF: a 64-bit little-endian file as elf() lays it out (program headers at 64, PT_LOAD then PT_DYNAMIC; the dynamic
  // table holds DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_NULL)
  const ef = elf(join(d, 'elf-good'), [CONTROL, MARKER], { needed: ['libc.so.6'] }), e = readFileSync(ef);
  const dyn = Number(e.readBigUInt64LE(64 + 56 + 8));
  const patch = (o, v, w = 4) => { const c = Buffer.from(e); if (w === 8) c.writeBigUInt64LE(BigInt(v), o); else if (w === 2) c.writeUInt16LE(v, o); else if (w === 1) c[o] = v; else c.writeUInt32LE(v, o); return c; };
  const elfCases = [['a class the format has not', patch(4, 3, 1), /identification bytes/], ['a version the format has not', patch(6, 2, 1), /identification bytes/],
    ['program headers too small', patch(54, 16, 2), /program headers don't fit/], ['program headers past the file', patch(32, e.length, 8), /program headers don't fit/],
    ['two dynamic segments', patch(64, 2), /more than one dynamic segment/], ['no DT_NULL', patch(dyn + 48, 0x6ffffef5, 8), /no DT_NULL inside its segment/],
    ['no string table', patch(dyn + 16, 0x6ffffef5, 8), /names libraries but has no string table/], ['a string table no segment maps', patch(dyn + 24, 0x7fff0000, 8), /string table is in no part of the file the loader maps/],
    ['DT_NEEDED past the string table', patch(dyn + 8, 1000, 8), /its DT_NEEDED points outside its string table/], ['a name with no NUL in the string table', patch(dyn + 40, 4, 8), /its DT_NEEDED's name has no end inside it/],
    ['two DT_STRTAB', patch(dyn, 5, 8), /more than one DT_STRTAB/], ['a dynamic segment past the file', patch(64 + 56 + 32, e.length, 8), /dynamic segment doesn't fit in the file/]];
  for (const [what, bytes, why] of elfCases) {
    const f = join(d, `elf-${what.replace(/\W/g, '_')}`);
    writeFileSync(f, bytes);
    const r = judge(f);
    assert.equal(r.status, 'UNKNOWN', what); assert.match(r.reason, /^its ELF headers could not be read as the format lays them out \(.+\).*could not be tested/, what); assert.match(r.reason, why, what);
  }
  // two DT_SONAME (its DT_NEEDED made one, beside its own): which the loader takes isn't certain
  const twoNames = elf(join(d, 'elf-two-sonames'), [CONTROL, MARKER], { needed: ['libc.so.6'], soname: 'libx.so.1' }), tn = readFileSync(twoNames);
  tn.writeBigUInt64LE(14n, Number(tn.readBigUInt64LE(64 + 56 + 8))); writeFileSync(twoNames, tn);
  assert.match(judge(twoNames).reason, /^its ELF headers could not be read as the format lays them out \(it has more than one DT_SONAME\)/);
  assert.equal(judge(elf(join(d, 'elf-one-soname'), [CONTROL, MARKER], { needed: ['libc.so.6'], soname: 'libx.so.1' })).status, 'SAFE', 'the clean twin');
  // neither Mach-O nor ELF (a PE file, a script, plain bytes): the libraries it links can't be read
  for (const [what, head] of [['PE', Buffer.from('MZ\x90\0')], ['script', Buffer.from('#!/bin/sh\n')], ['bytes', Buffer.alloc(64, 0x90)]]) {
    const r = judge(write(`other-${what}`, head));
    assert.equal(r.status, 'UNKNOWN', what); assert.match(r.reason, /^it is neither a Mach-O nor an ELF file Wardlatch can read/, what);
  }
  // a build of a universal file that isn't Mach-O
  const u = fat(join(d, 'fat-elf'), [[CONTROL, MARKER], [CONTROL, MARKER]]), ub = readFileSync(u);
  ub.write('\x7fELF', ub.readUInt32BE(8 + 20 + 8), 'latin1'); writeFileSync(u, ub);
  assert.match(judge(u).reason, /^in one of the 2 builds this universal file holds, it is neither a Mach-O nor an ELF file/);
  // its own unfixed table decides first: EXPOSED, whatever its headers
  assert.equal(judge(write('macho-old', set32(good, 16, 8), Buffer.concat([Buffer.alloc(16), ...cstrings([CONTROL])]))).status, 'EXPOSED');
  // the clean twins: the same headers as written
  assert.equal(judge(write('macho-good', good)).status, 'SAFE');
  assert.equal(judge(write('macho-good-two', two)).status, 'SAFE');
  assert.equal(judge(ef).status, 'SAFE');
  assert.equal(judge(fat(join(d, 'fat-good'), [[CONTROL, MARKER], [CONTROL, MARKER]])).status, 'SAFE');
});

test('a Brotli library\'s own names are its LC_ID_DYLIB or DT_SONAME, and its code-signing identifier when that is its own file name, and only those: a fixed one that links or names another decoder is never SAFE (A-self-wide)', () => {
  const d = fresh('self'), other = fresh('self-other'), sys = fresh('self-sys');
  const old = oldLib(join(other, 'libbrotlidec.1.dylib'), { type: 6 });
  const file = join(d, 'libbrotlidec.1.2.1.dylib'), id = '/DLC/PIL/.dylibs/libbrotlidec.1.2.1.dylib';
  // its install name is neither a link nor a name it may load: SAFE by its table, as a package's copy and as a library
  // row; known by its place in the load command (versions of 1351.0.0, as libSystem's, put a byte that isn't NUL right
  // before the name, so the string read back to a NUL is not the name)
  for (const version of [0, 0x05470000]) {
    fixedLib(file, { type: 6, id, links: ['/usr/lib/libSystem.B.dylib'], version });
    assert.equal(judge(file).status, 'SAFE', `version ${version}`); assert.equal(judgeFile(file, { markers: M, follow: false }).status, 'SAFE', `version ${version}`);
  }
  // the same name outside its table: a name it may load. A decoder library's own file name exempts nothing (round 5's rule
  // read any file named libbrotlidec as naming only itself)
  for (const s of [id, 'libbrotlidec.1.2.1.dylib', 'libbrotlidec.1.dylib']) {
    bin(file, [CONTROL, MARKER, s], { type: 6 });
    assert.equal(judge(file).status, 'UNKNOWN', s); assert.equal(judgeFile(file, { markers: M, follow: false }).status, 'UNKNOWN', `${s}: as a library row`);
  }
  // the real attack: a fixed decoder library that also links another, unfixed one. As a package's copy it is followed:
  // EXPOSED; as a library row, or a library a program links, its links are past the one level read: UNKNOWN, never SAFE
  fixedLib(file, { type: 6, id, links: [old] });
  const linked = judge(file);
  assert.equal(linked.status, 'EXPOSED'); assert.match(linked.reason, /its own Brotli decoder has the fix, but it uses .*self-other\/libbrotlidec\.1\.dylib/);
  const row = judgeFile(file, { markers: M, follow: false });
  assert.equal(row.status, 'UNKNOWN'); assert.match(row.reason, /it links .*self-other\/libbrotlidec\.1\.dylib, a Brotli library or libnode of its own/);
  // ... or that names another one outside its table: UNKNOWN both ways
  fixedLib(file, { type: 6, id });
  bin(file, [CONTROL, MARKER, old], { type: 6, id });
  assert.equal(judge(file).status, 'UNKNOWN'); assert.equal(judgeFile(file, { markers: M, follow: false }).status, 'UNKNOWN');
  // its code-signing identifier is its own only when it is its own file name; Homebrew's and delocate's identifiers
  // (libbrotlidec.1.2.1, libbrotlidec.1) are no file name the loader loads
  for (const [ident, want] of [['libbrotlidec.1.2.1.dylib', 'SAFE'], ['libbrotlidec.1.2.1', 'SAFE'], ['libbrotlidec.1', 'SAFE'], ['libbrotlidec.1.0.9.dylib', 'UNKNOWN'], ['libbrotlidec.1.dylib', 'UNKNOWN']]) {
    fixedLib(file, { type: 6, id: '@rpath/libbrotlidec.1.dylib', signed: ident });
    assert.equal(judge(file).status, want, ident);
  }
  // as found through a link to it (judged by its real path, whose name the identifier is)
  fixedLib(file, { type: 6, id: '@rpath/libbrotlidec.1.dylib', signed: 'libbrotlidec.1.2.1.dylib' });
  symlinkSync(file, join(d, 'libbrotlidec.1.dylib'));
  assert.equal(judge(join(d, 'libbrotlidec.1.dylib')).status, 'SAFE');
  // ELF: its soname, and a whole copy of it in its strings, are its own; another soname is not, linked or named
  const so = join(d, 'libbrotlidec.so.1.2.1');
  oldLib(join(sys, 'libbrotlidec.so.0'));
  for (const [what, parts, o, want] of [['its soname', [], {}, 'SAFE'], ['a copy of its soname', ['libbrotlidec.so.1'], {}, 'SAFE'], ['another name', ['libbrotlidec.so.0'], {}, 'UNKNOWN'],
    ['a link to another, unfixed', [], { needed: ['libbrotlicommon.so.1', 'libbrotlidec.so.0'] }, 'EXPOSED']]) {
    elf(so, [CONTROL, MARKER, ...parts], { soname: 'libbrotlidec.so.1', needed: ['libbrotlicommon.so.1'], ...o });
    assert.equal(judge(so, [sys]).status, want, what);
  }
});

test('EXPOSED decides over UNKNOWN: between the Brotli library and libnode, either way round, between two links, and over a name it may load (B-exposed-masked)', () => {
  const d = fresh('exposed-wins'), lib = fresh('exposed-wins-lib'), sys = fresh('exposed-wins-sys');
  const decOld = oldLib(join(lib, 'old', 'libbrotlidec.1.dylib'), { type: 6 }), decNew = fixedLib(join(lib, 'new', 'libbrotlidec.1.dylib'), { type: 6 });
  const nodeOld = bin(join(lib, 'old', 'libnode.147.dylib'), [CONTROL, NODE_CONTROL], { type: 6 }), nodeNew = bin(join(lib, 'new', 'libnode.147.dylib'), [CONTROL, MARKER], { type: 6 });
  const noDec = join(d, 'nowhere', 'libbrotlidec.1.dylib'), noNode = join(d, 'nowhere', 'libnode.147.dylib');
  for (const [what, links, want] of [
    ['the Brotli library not found, libnode unfixed', [noDec, nodeOld], 'EXPOSED'], ['libnode not found, the Brotli library unfixed', [noNode, decOld], 'EXPOSED'],
    ['the Brotli library unfixed, libnode not found', [decOld, noNode], 'EXPOSED'], ['libnode unfixed, the Brotli library not found', [nodeOld, noDec], 'EXPOSED'],
    ['a Brotli library not found, then an unfixed one', [noDec, decOld], 'EXPOSED'], ['a libnode not found, then an unfixed one', [noNode, nodeOld], 'EXPOSED'],
    ['the twin: one not found, the other fixed', [noDec, nodeNew], 'UNKNOWN'], ['the twin: libnode not found, the Brotli library fixed', [decNew, noNode], 'UNKNOWN'],
    ['the twin: both fixed', [decNew, nodeNew], 'SAFE']]) {
    for (const [own, parts] of [['no table', []], ['a fixed table', [CONTROL, MARKER]]]) {
      const r = judge(bin(join(d, `${what.replace(/\W/g, '_')}-${own.length}`), parts, { links }));
      assert.equal(r.status, want, `${what}, ${own}: ${r.reason}`);
    }
  }
  // an unfixed library it links decides over a name it may load; with the library fixed, the name makes it UNKNOWN
  assert.equal(judge(bin(join(d, 'dlopen-old'), [CONTROL, MARKER, 'libbrotlidec.so.1'], { links: [decOld] })).status, 'EXPOSED');
  assert.equal(judge(bin(join(d, 'dlopen-new'), [CONTROL, MARKER, 'libbrotlidec.so.1'], { links: [decNew] })).status, 'UNKNOWN');
  // ELF, a distribution's node: libnode's soname not found beside an unfixed Brotli soname, and the other way round
  oldLib(join(sys, 'libbrotlidec.so.1')); elf(join(sys, 'libnode.so.108'), [CONTROL]);
  for (const needed of [['libnode.so.999', 'libbrotlidec.so.1'], ['libbrotlidec.so.9', 'libnode.so.108']]) assert.equal(judge(elf(join(d, `elf-${needed[0]}`), [], { needed }), [sys]).status, 'EXPOSED', needed.join());
});

test('bounded: hits past the 65,536 a build is looked at for are UNKNOWN, and a file full of the library\'s name is read in time', () => {
  const d = fresh('looks');
  // more mentions of libnode than are looked at: whether one past them names a library it may load isn't known
  const many = (n) => Buffer.from('\0libnode_base.a(x.o)'.repeat(n));
  const t = Date.now();
  const crowded = judge(bin(join(d, 'crowded'), [CONTROL, MARKER, many(65537)]));
  assert.ok(Date.now() - t < 5000, `${Date.now() - t} ms`);
  assert.equal(crowded.status, 'UNKNOWN'); assert.match(crowded.reason, /more often than Wardlatch looks at \(65,536 times\).*could not be tested/);
  assert.equal(judge(bin(join(d, 'few'), [CONTROL, MARKER, many(65536)])).status, 'SAFE', 'the clean twin: all looked at');
  // hostile files: the name over and over with printable bytes, as loadable names and not
  for (const [name, body] of [['not', 'A/libbrotlidec.1.dylibA'], ['yes', 'A/libbrotlidec.1.dylib '], ['tags', 'libbrotlidec-'.repeat(8)]]) {
    const f = bin(join(d, name), [CONTROL, MARKER, Buffer.from(body.repeat(Math.ceil(4e6 / body.length)))]);
    const t2 = Date.now();
    const r = judge(f);
    assert.ok(Date.now() - t2 < 5000, `${name}: ${Date.now() - t2} ms`);
    assert.equal(r.status, 'UNKNOWN', name);
  }
});

test('ld.so.conf: the folders it names are searched too, so a library only the loader\'s configuration points at still decides', () => {
  const d = fresh('ldso'), extra = fresh('ldso-extra'), extra2 = fresh('ldso-extra2'), std = fresh('ldso-std');
  mkdirSync(join(d, 'ld.so.conf.d'));
  // the include line as Fedora writes it (relative to the file); Debian's names /etc/ld.so.conf.d/*.conf, the same folder
  writeFileSync(join(d, 'ld.so.conf'), 'include ld.so.conf.d/*.conf\n# a comment\n');
  writeFileSync(join(d, 'ld.so.conf.d', 'a.conf'), `# extra\n${extra} # trailing comment\n\n`);
  writeFileSync(join(d, 'ld.so.conf.d', 'b.conf'), `${extra2}:/also/this\n`);
  writeFileSync(join(d, 'ld.so.conf.d', 'notes.txt'), '/not/this\n');
  const places = { ldSoConf: join(d, 'ld.so.conf'), ldSoConfDir: join(d, 'ld.so.conf.d') };
  assert.deepEqual(ldSoConfDirs(places).dirs.sort(), [extra, extra2, '/also/this'].sort());
  assert.deepEqual(ldSoConfDirs(places).gaps, []);
  writeFileSync(join(d, 'ld.so.conf'), `include ${join(d, 'ld.so.conf.d')}/*.conf\n`);
  assert.deepEqual(ldSoConfDirs(places).gaps, [], 'the same folder by its absolute path');
  // a program linking the soname: the standard folder's copy is fixed, the one the configuration adds is not. Both are
  // candidates: UNKNOWN (round 8: EXPOSED, the unfixed one deciding); both unfixed EXPOSED; both fixed SAFE
  fixedLib(join(std, 'libbrotlidec.so.1')); oldLib(join(extra, 'libbrotlidec.so.1'));
  const path = fresh('ldso-path');
  elf(join(path, 'node'), [NODE_CONTROL], { needed: ['libbrotlidec.so.1'] });
  const at = () => run({}, { pathEnv: path, sonameDirs: [std], places }).rows.find((r) => r.file === join(path, 'node'));
  assert.equal(at().status, 'UNKNOWN');
  oldLib(join(std, 'libbrotlidec.so.1'));
  assert.equal(at().status, 'EXPOSED');
  fixedLib(join(std, 'libbrotlidec.so.1')); fixedLib(join(extra, 'libbrotlidec.so.1'));
  assert.equal(at().status, 'SAFE', 'the clean twin');
});

test('the loader\'s configuration: anything not read (an include elsewhere, a file or folder it can\'t read, too many files) makes a soname UNKNOWN', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const d = fresh('ldgap'), std = fresh('ldgap-std'), path = fresh('ldgap-path');
  mkdirSync(join(d, 'ld.so.conf.d'));
  const places = { ldSoConf: join(d, 'ld.so.conf'), ldSoConfDir: join(d, 'ld.so.conf.d') };
  fixedLib(join(std, 'libbrotlidec.so.1'));
  elf(join(path, 'node'), [NODE_CONTROL], { needed: ['libbrotlidec.so.1'] });
  const at = (p = places, sonameDirs = [std]) => run({}, { pathEnv: path, sonameDirs, places: p }).rows.find((r) => r.file === join(path, 'node'));
  writeFileSync(join(d, 'ld.so.conf'), 'include ld.so.conf.d/*.conf\n');
  assert.equal(at().status, 'SAFE', 'the clean twin: everything read');
  // an include naming another folder is not followed: the loader may take its copy from there
  writeFileSync(join(d, 'ld.so.conf'), 'include ld.so.conf.d/*.conf\ninclude /opt/vendor/ld.conf.d/*.conf\n');
  const inc = at();
  assert.equal(inc.status, 'UNKNOWN'); assert.match(inc.reason, /what the dynamic loader is told to search could not all be read \(.*include \/opt\/vendor.*could not be tested/);
  writeFileSync(join(d, 'ld.so.conf'), 'include ld.so.conf.d/*.conf\n');
  // a configuration file, or the conf.d folder, that can't be read
  writeFileSync(join(d, 'ld.so.conf.d', 'vendor.conf'), '/opt/vendor/lib\n');
  for (const f of [join(d, 'ld.so.conf.d', 'vendor.conf'), join(d, 'ld.so.conf'), join(d, 'ld.so.conf.d')]) {
    execFileSync('chmod', ['000', f]);
    try { assert.equal(at().status, 'UNKNOWN', f); } finally { execFileSync('chmod', [f.endsWith('.d') ? '755' : '644', f]); }
  }
  // more .conf files than are read
  for (let i = 0; i < 257; i++) writeFileSync(join(d, 'ld.so.conf.d', `x${String(i).padStart(3, '0')}.conf`), '\n');
  assert.equal(at().status, 'UNKNOWN');
  // a library folder that can't be reached (its parent is closed): its copy could be the one that loads
  const locked = fresh('ldgap-locked'), lockedLib = join(locked, 'lib');
  oldLib(join(lockedLib, 'libbrotlidec.so.1'));
  execFileSync('chmod', ['000', locked]);
  try { assert.equal(at({}, [std, lockedLib]).status, 'UNKNOWN'); } finally { execFileSync('chmod', ['755', locked]); }
  // once it can be read, its unfixed copy is a candidate beside the standard folder's fixed one: UNKNOWN (round 8:
  // EXPOSED, deciding); fixed, SAFE
  assert.equal(at({}, [std, lockedLib]).status, 'UNKNOWN', 'once it can be read, its unfixed copy is a candidate');
  fixedLib(join(lockedLib, 'libbrotlidec.so.1'));
  assert.equal(at({}, [std, lockedLib]).status, 'SAFE');
  oldLib(join(lockedLib, 'libbrotlidec.so.1'));
  assert.equal(at({}, [std]).status, 'SAFE');
  // and a pattern's folder that can't be listed (/usr/lib/*-linux-gnu under a closed /usr/lib)
  execFileSync('chmod', ['000', locked]);
  try { assert.equal(at({}, [std, join(locked, '*')]).status, 'UNKNOWN'); } finally { execFileSync('chmod', ['755', locked]); }
});

test('musl\'s loader path file: its folders are searched too', () => {
  const d = fresh('musl'), std = fresh('musl-std'), extra = fresh('musl-extra'), path = fresh('musl-path');
  fixedLib(join(std, 'libbrotlidec.so.1')); oldLib(join(extra, 'libbrotlidec.so.1'));
  writeFileSync(join(d, 'ld-musl-x86_64.path'), `/lib:/usr/local/lib\n${extra}\n`);
  elf(join(path, 'node'), [NODE_CONTROL], { needed: ['libbrotlidec.so.1'] });
  const at = (places) => run({}, { pathEnv: path, sonameDirs: [std], places }).rows.find((r) => r.file === join(path, 'node'));
  // the file's folder's unfixed copy beside the standard folder's fixed one: UNKNOWN (round 8: EXPOSED); both unfixed,
  // EXPOSED
  assert.equal(at({ ldMuslPath: join(d, 'ld-musl-*.path') }).status, 'UNKNOWN');
  oldLib(join(std, 'libbrotlidec.so.1'));
  assert.equal(at({ ldMuslPath: join(d, 'ld-musl-*.path') }).status, 'EXPOSED');
  fixedLib(join(std, 'libbrotlidec.so.1'));
  assert.equal(at({}).status, 'SAFE', 'without it, only the standard folder');
  fixedLib(join(extra, 'libbrotlidec.so.1'));
  assert.equal(at({ ldMuslPath: join(d, 'ld-musl-*.path') }).status, 'SAFE', 'the clean twin');
});

test('no table and no link is UNKNOWN; a file that can\'t be read (a FIFO, a folder, too large) is UNKNOWN, never SAFE', () => {
  const d = fresh('unread');
  assert.equal(judge(bin(join(d, 'plain'), ['hello'])).status, 'UNKNOWN');
  mkdirSync(join(d, 'libbrotlidec.1.dylib'));
  assert.equal(judge(join(d, 'libbrotlidec.1.dylib')).status, 'UNKNOWN');
  execFileSync('mkfifo', [join(d, 'libbrotlidec.so.1')]);
  const t = Date.now();
  assert.equal(judge(join(d, 'libbrotlidec.so.1')).status, 'UNKNOWN');
  assert.ok(Date.now() - t < 2000, 'a FIFO does not hang the read');
  // a sparse file over the 512 MB cap: not read
  const fd = openSync(join(d, 'huge'), 'w'); ftruncateSync(fd, 600 * 1024 * 1024); closeSync(fd);
  const huge = judge(join(d, 'huge'));
  assert.equal(huge.status, 'UNKNOWN'); assert.match(huge.reason, /512 MB/);
  assert.equal(judge(join(d, 'not-there')).status, 'UNKNOWN');
});

test('the reading budget: a file is read only if it fits in what is left, so a run reads at most its budget; nothing is skipped', () => {
  const path = fresh('budget-path');
  const a = fixedLib(join(path, 'a', 'node')), b = fixedLib(join(path, 'b', 'node'));
  const size = readFileSync(a).length;
  const nodeDirs = [join(path, '*', 'node')];
  const tight = run({ nodeDirs }, { budgetBytes: Math.floor(size * 1.5) }).rows;
  assert.deepEqual(tight.map((r) => r.file).sort(), [a, b].sort());
  assert.equal(tight.filter((r) => r.status === 'SAFE').length, 1, 'the first file fits and is read');
  const left = tight.find((r) => r.status !== 'SAFE');
  assert.equal(left.status, 'UNKNOWN'); assert.match(left.reason, /4 GB.*could not be tested/);
  // a file larger than what is left is not read at all, even the first: the budget is never overshot
  assert.deepEqual(run({ nodeDirs }, { budgetBytes: size - 1 }).rows.map((r) => r.status), ['UNKNOWN', 'UNKNOWN']);
  assert.deepEqual(run({ nodeDirs }).rows.map((r) => r.status), ['SAFE', 'SAFE'], 'with the budget, both are read');
  // reading the file's first 8 bytes (is it a universal file?) and its link table (its 64-bit Mach-O header, 32 bytes,
  // with no load commands) is charged too: its size alone is not enough, nor its size and its header (round 8 left the
  // first 8 bytes uncharged: decision #25, rule 6)
  assert.equal(judgeFile(a, { markers: M, budget: { left: size } }).status, 'UNKNOWN');
  assert.equal(judgeFile(a, { markers: M, budget: { left: size + 32 } }).status, 'UNKNOWN');
  const exact = { left: size + 8 + 32 };
  assert.equal(judgeFile(a, { markers: M, budget: exact }).status, 'SAFE', 'the clean twin: room for the file, its first 8 bytes and its header');
  assert.equal(exact.left, 0);
  // the small files are read first: a package's copy before a node of the same size, though the node's row prints first
  const sp = fresh('budget-sp');
  bin(join(sp, 'examplepkg.libs', 'libbrotlidec-1.so.1'), ['_SUCCESS', CONTROL, '_ERROR_UNREACHABLE'], { type: 6 });   // a Mach-O dylib, as the sizes above
  const order = run({ nodeDirs: [a] }, { siteDirs: [sp], budgetBytes: Math.floor(size * 1.5) }).rows;
  assert.deepEqual(order.map((r) => [r.what, r.status]), [['node', 'UNKNOWN'], ['python', 'EXPOSED']]);
});

test('the reading budget holds for the look for proto-shim\'s marker: a node on PATH read for it is charged, so the run reads at most its budget', () => {
  const path = fresh('budget-marker-path'), sp = fresh('budget-marker-sp');
  const node = fixedLib(join(path, 'node')), lib = bin(join(sp, 'examplepkg.libs', 'libbrotlidec-1.so.1'), ['_SUCCESS', CONTROL, MARKER, '_ERROR_UNREACHABLE'], { type: 6 });   // Mach-O, 32-byte header
  // each file judged is read whole, its first 8 bytes (is it a universal file?) and its link table's header (32 bytes)
  // once more; the look for the marker reads it whole
  const n0 = readFileSync(node).length, size = n0 + 8 + 32 + readFileSync(lib).length + 8 + 32;
  // the library is read, then the node for the marker (it is no shim by name or place), then the node itself: the
  // budget fits two of those reads, so the node's own read is past it
  const rows = run({}, { pathEnv: path, siteDirs: [sp], budgetBytes: size }).rows;
  assert.equal(rows.find((r) => r.file === lib).status, 'SAFE');
  const n = rows.find((r) => r.file === node);
  assert.equal(n.status, 'UNKNOWN'); assert.match(n.reason, /4 GB.*could not be tested/);
  // the clean twin: room for all three reads
  assert.deepEqual(run({}, { pathEnv: path, siteDirs: [sp], budgetBytes: size + n0 }).rows.map((r) => r.status), ['SAFE', 'SAFE']);
  // a node on PATH larger than what is left is not read for the marker at all (no overshoot), so a version manager's
  // node read after it still fits
  const big = bin(join(path, 'node'), [CONTROL, MARKER, 'x'.repeat(5000)]), managed = fixedLib(join(sp, 'nvm', 'node')), m0 = readFileSync(managed).length;
  assert.ok(readFileSync(big).length > m0 + 32 + 10);
  const rest = run({ nodeDirs: [managed] }, { pathEnv: path, budgetBytes: m0 + 32 + 10 }).rows;
  assert.equal(rest.find((r) => r.file === managed).status, 'SAFE'); assert.equal(rest.find((r) => r.file === big).status, 'UNKNOWN');
});

test('the reading budget holds for a universal file: builds that overlap are UNKNOWN and not read (only the list of builds is, charged), so no byte is read twice', () => {
  const d = fresh('budget-fat');
  // a universal header whose builds name the same bytes: read build by build, a 256 KB file was read once per build
  const overlapping = (path, n, at) => {
    const body = Buffer.concat([MACHO, Buffer.alloc(256 * 1024, 0x90), Buffer.from(`\0${CONTROL}\0\0${MARKER}\0`), Buffer.alloc(16)]);
    const head = Buffer.alloc(8 + n * 20), start = Math.ceil(head.length / 16) * 16;
    head.writeUInt32BE(0xcafebabe, 0); head.writeUInt32BE(n, 4);
    for (let i = 0; i < n; i++) {
      const o = 8 + i * 20;
      head.writeUInt32BE(0x0100000c, o); head.writeUInt32BE(start + at(i), o + 8); head.writeUInt32BE(body.length - at(i), o + 12); head.writeUInt32BE(4, o + 16);
    }
    writeFileSync(path, Buffer.concat([head, Buffer.alloc(start - head.length), body]));
    return path;
  };
  for (const [name, n, at] of [['same-bytes', 64, () => 0], ['two-same', 2, () => 0], ['second-inside-first', 2, (i) => i * 1024]]) {
    const f = overlapping(join(d, name), n, at), size = readFileSync(f).length;
    const budget = { left: size * 2 };
    const r = judgeFile(f, { markers: M, budget });
    assert.equal(r.status, 'UNKNOWN', name); assert.match(r.reason, /universal.*overlap.*could not be tested/, name);
    // its first 8 bytes and its list of builds were read to see that, and are charged (round 8 left them uncharged)
    assert.equal(budget.left, size * 2 - (8 + n * 20), `${name}: ${size * 2 - budget.left} bytes read of a ${size}-byte file`);
  }
  // the clean twin: the same builds side by side are each read once, and what is read is less than the file
  const twin = fat(join(d, 'side-by-side'), [[CONTROL, MARKER], [CONTROL, MARKER]]), size = readFileSync(twin).length;
  const budget = { left: size };
  assert.equal(judgeFile(twin, { markers: M, budget }).status, 'SAFE');
  assert.ok(budget.left > 0 && budget.left < size, `${size - budget.left} bytes read of a ${size}-byte file`);
});

test('the reading budget holds for the candidate search: each folder listed (4 KB, then 256 bytes an entry) and each file in it (its first 8 bytes; a library\'s list of builds and headers) is charged, once a run; past it, UNKNOWN', () => {
  const d = fresh('budget-places');
  // a program with LC_RPATH lib/, linking @rpath/libbrotlidec.1.dylib: lib/ is listed (it holds the library and two
  // other files), each file in it looked at (its first 8 bytes; the library's 32-byte header, no load commands, which
  // is what following it reads) and the library then judged
  const lib = fresh('budget-places/lib');
  fixedLib(join(lib, 'libbrotlidec.1.dylib')); writeFileSync(join(lib, 'a.txt'), 'a'); writeFileSync(join(lib, 'b.txt'), 'b');
  const prog = bin(join(d, 'bin', 'prog'), [], { links: ['@rpath/libbrotlidec.1.dylib'], rpaths: [lib] });
  const ev = (f) => { const b = readFileSync(f); return 8 + b.length + 32 + b.readUInt32LE(20); };   // evidence(): first 8 bytes, the file, header, load commands
  const listing = 4096 + 3 * 256, scan = 3 * 8 + 32, cost = ev(prog) + listing + scan + ev(join(lib, 'libbrotlidec.1.dylib'));
  const exact = { left: cost };
  assert.equal(judgeFile(prog, { markers: M, budget: exact }).status, 'SAFE');
  assert.equal(exact.left, 0, `${cost - exact.left} of ${cost}`);
  // the same run (the same budget) reads a folder, and each file in it, once: a second program's look at lib/ is not
  // charged again
  const again = { left: 2 * cost - listing - scan };
  assert.equal(judgeFile(prog, { markers: M, budget: again }).status, 'SAFE');
  assert.equal(judgeFile(prog, { markers: M, budget: again }).status, 'SAFE');
  assert.equal(again.left, 0, 'the second look at lib/ comes from the run\'s own listing and looks');
  // too little left to list lib/, or to look at its files: UNKNOWN, saying so, never SAFE; nothing read past the budget
  for (const left of [ev(prog) + listing - 1, ev(prog) + listing + 8 - 1, ev(prog) + listing + scan - 1]) {
    const b = { left };
    const r = judgeFile(prog, { markers: M, budget: b });
    assert.equal(r.status, 'UNKNOWN', String(left)); assert.match(r.reason, /it links @rpath\/libbrotlidec\.1\.dylib, and the folders and libraries where a loader may look for it were not all read, because this run had already read 4 GB of files for this check, so whether it has the fix could not be tested/);
    assert.ok(b.left >= 0);
  }
  // with room for the search but not for the library's own read: the library is UNKNOWN (over), and so is the program
  const short = judgeFile(prog, { markers: M, budget: { left: cost - 1 } });
  assert.equal(short.status, 'UNKNOWN'); assert.match(short.reason, /4 GB.*could not be tested/);
});

test('RECORD: plain and quoted paths, a quote inside quotes, CRLF, and a line too long to be a path', () => {
  const text = 'PIL/__init__.py,sha256=x,1\r\n"odd,name/libbrotlidec.so.1",sha256=y,2\n"a""b.py",,\n' + 'z'.repeat(5000) + ',,\nlast.py,,';
  assert.deepEqual(recordPaths(text), ['PIL/__init__.py', 'odd,name/libbrotlidec.so.1', 'a"b.py', 'last.py']);
  const t = Date.now(); recordPaths('x'.repeat(1024 * 1024)); assert.ok(Date.now() - t < 500, 'a 1 MB line is passed over quickly');
});

/** A site-packages folder like this Mac's, in miniature. */
function sitePackages(root) {
  const sp = join(root, 'lib', 'python3.14', 'site-packages');
  const dist = (info, name, version, files) => {
    mkdirSync(join(sp, info), { recursive: true });
    writeFileSync(join(sp, info, 'METADATA'), `Metadata-Version: 2.4\nName: ${name}\nVersion: ${version}\n\n`);
    writeFileSync(join(sp, info, 'RECORD'), files.map((f) => `${f.includes(',') ? `"${f}"` : f},sha256=AAAA,1`).join('\n') + `\n${info}/RECORD,,\n`);
  };
  oldLib(join(sp, 'PIL', '.dylibs', 'libbrotlidec.1.2.0.dylib'));
  bin(join(sp, 'PIL', '.dylibs', 'libfreetype.6.dylib'), [], { type: 6, links: ['@loader_path/libbrotlidec.1.2.0.dylib'] });
  // a RECORD line pointing outside site-packages (as console scripts do), at a Node program that is there
  bin(join(root, 'bin', 'node'), [CONTROL]);
  dist('pillow-12.3.0.dist-info', 'Pillow', '12.3.0', ['PIL/.dylibs/libbrotlidec.1.2.0.dylib', 'PIL/.dylibs/libfreetype.6.dylib', '../../../bin/node']);
  oldLib(join(sp, 'cv2', '.dylibs', 'libbrotlidec.1.1.0.dylib'));
  dist('opencv_python-5.0.0.93.dist-info', 'opencv-python', '5.0.0.93', ['cv2/.dylibs/libbrotlidec.1.1.0.dylib']);
  dist('opencv_contrib_python-5.0.0.93.dist-info', 'opencv-contrib-python', '5.0.0.93', ['cv2/.dylibs/libbrotlidec.1.1.0.dylib']);
  // pip says 1.2.1, the bytes say otherwise: the bytes win
  oldLib(join(sp, '_brotli.cpython-314-darwin.so'));
  dist('brotli-1.2.1.dist-info', 'Brotli', '1.2.1', ['_brotli.cpython-314-darwin.so', 'brotli.py']);
  // a Node.js runtime inside a wheel
  bin(join(sp, 'examplepkg', 'driver', 'node'), [CONTROL, 'nodejs.org/download/release/v24.17.0']);
  dist('examplepkg-1.0.0.dist-info', 'examplepkg', '1.0.0', ['examplepkg/driver/node', 'examplepkg/__init__.py']);
  // a copy no RECORD lists (put there by hand or by conda): still judged, with no owner
  oldLib(join(sp, 'orphan.libs', 'libbrotlidec-ab12cd34.so.1.2.0'));
  // a package with a fixed copy: SAFE
  fixedLib(join(sp, 'goodpkg', '.dylibs', 'libbrotlidec.1.2.1.dylib'));
  dist('goodpkg-2.0.dist-info', 'goodpkg', '2.0', ['goodpkg/.dylibs/libbrotlidec.1.2.1.dylib']);
  // a package with an unfixed copy the incident has no words for: the general fix
  oldLib(join(sp, 'otherpkg.libs', 'libbrotlidec-0f0f0f0f.so.1.0.9'));
  dist('otherpkg-3.1.dist-info', 'otherpkg', '3.1', ['otherpkg.libs/libbrotlidec-0f0f0f0f.so.1.0.9']);
  return sp;
}

test('site-packages: every copy found, owned through RECORD (both owners of a shared file), judged by its bytes, with its own fix', () => {
  const sp = sitePackages(fresh('sp1'));
  const c = sitePackagesCandidates(sp);
  const by = Object.fromEntries(c.files.map((x) => [x.file.slice(sp.length + 1), x.owners.map((o) => `${o.name} ${o.version}`).sort().join(', ')]));
  assert.deepEqual(Object.keys(by).sort(), ['PIL/.dylibs/libbrotlidec.1.2.0.dylib', '_brotli.cpython-314-darwin.so', 'cv2/.dylibs/libbrotlidec.1.1.0.dylib', 'examplepkg/driver/node', 'goodpkg/.dylibs/libbrotlidec.1.2.1.dylib', 'orphan.libs/libbrotlidec-ab12cd34.so.1.2.0', 'otherpkg.libs/libbrotlidec-0f0f0f0f.so.1.0.9'].sort());
  assert.equal(by['cv2/.dylibs/libbrotlidec.1.1.0.dylib'], 'opencv-contrib-python 5.0.0.93, opencv-python 5.0.0.93');
  assert.equal(by['orphan.libs/libbrotlidec-ab12cd34.so.1.2.0'], '');
  const { rows } = run({}, { siteDirs: [sp] });
  const status = Object.fromEntries(rows.filter((r) => r.what === 'python').map((r) => [r.file.slice(sp.length + 1), r.status]));
  assert.deepEqual(status, {
    'PIL/.dylibs/libbrotlidec.1.2.0.dylib': 'EXPOSED', 'cv2/.dylibs/libbrotlidec.1.1.0.dylib': 'EXPOSED', '_brotli.cpython-314-darwin.so': 'EXPOSED',
    'examplepkg/driver/node': 'EXPOSED', 'orphan.libs/libbrotlidec-ab12cd34.so.1.2.0': 'EXPOSED', 'otherpkg.libs/libbrotlidec-0f0f0f0f.so.1.0.9': 'EXPOSED',
    'goodpkg/.dylibs/libbrotlidec.1.2.1.dylib': 'SAFE',
  });
  const row = (rel) => rows.find((r) => r.file === join(sp, rel));
  // a bundled copy with no fixed release yet: EXPOSED, and the fix says what to do until one ships
  assert.equal(row('PIL/.dylibs/libbrotlidec.1.2.0.dylib').fix, 'No Pillow release had a fixed Brotli on 24 October 2026: update Pillow when one ships, since this copy is fixed by a Pillow release with a fixed Brotli.');
  const cv = row('cv2/.dylibs/libbrotlidec.1.1.0.dylib');
  assert.match(cv.fix, /^No (opencv-python|opencv-contrib-python) release had a fixed Brotli on 24 October 2026: update \1 when one ships, since this copy is fixed by an \1 release with a fixed Brotli\.$/);
  assert.match(cv.owner, /opencv-python 5\.0\.0\.93/); assert.match(cv.owner, /opencv-contrib-python 5\.0\.0\.93/);
  assert.match(row('_brotli.cpython-314-darwin.so').fix, /'Brotli>=1\.2\.1'/);
  assert.match(row('examplepkg/driver/node').fix, /Node\.js runtime that examplepkg carries/);
  assert.match(row('orphan.libs/libbrotlidec-ab12cd34.so.1.2.0').fix, /No package's install record lists this copy/);
  assert.equal(row('orphan.libs/libbrotlidec-ab12cd34.so.1.2.0').label, 'a copy no package lists');
  assert.match(row('otherpkg.libs/libbrotlidec-0f0f0f0f.so.1.0.9').fix, /^Update otherpkg to a release whose own copy of Brotli has the fix/);
  assert.equal(row('goodpkg/.dylibs/libbrotlidec.1.2.1.dylib').fix, undefined);
  assert.ok(!rows.some((r) => r.file.endsWith(join('sp1', 'bin', 'node'))), 'a RECORD path outside site-packages is not followed');
  // a Brotli binding that says 1.1.0 but has the fixed table: SAFE (the bytes win both ways)
  fixedLib(join(sp, '_brotli.cpython-314-darwin.so'));
  assert.equal(run({}, { siteDirs: [sp] }).rows.find((r) => r.file === join(sp, '_brotli.cpython-314-darwin.so')).status, 'SAFE');
});

test('site-packages: a clean twin with a fixed Brotli binding and no bundled copies is SAFE only for what it found', () => {
  const sp = join(fresh('sp2'), 'site-packages');
  fixedLib(join(sp, '_brotli.cpython-314-darwin.so'));
  mkdirSync(join(sp, 'brotli-1.2.1.dist-info'), { recursive: true });
  writeFileSync(join(sp, 'brotli-1.2.1.dist-info', 'RECORD'), '_brotli.cpython-314-darwin.so,,\n');
  const { rows } = run({}, { siteDirs: [sp] });
  assert.deepEqual(rows.map((r) => [r.file, r.status, r.searched]), [[join(sp, '_brotli.cpython-314-darwin.so'), 'SAFE', [join(sp, '_brotli.cpython-314-darwin.so')]]]);
});

test('site-packages: Brotli bindings without a RECORD (egg-info, .egg folders, distribution packages) and symlinked folders are found', () => {
  const sp = fresh('eggs/site-packages'), libs = fresh('eggs/elsewhere');
  const meta = (path, name, version) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n\n`); };
  // brotlicffi installed by setup.py: an egg-info with pip's installed-files.txt (paths relative to the egg-info folder)
  oldLib(join(sp, 'brotlicffi', '_brotlicffi.abi3.so'));
  meta(join(sp, 'brotlicffi-1.1.0.0-py3.12.egg-info', 'PKG-INFO'), 'brotlicffi', '1.1.0.0');
  writeFileSync(join(sp, 'brotlicffi-1.1.0.0-py3.12.egg-info', 'installed-files.txt'), '../brotlicffi/__init__.py\n../brotlicffi/_brotlicffi.abi3.so\nPKG-INFO\n');
  // brotlipy (brotli/_brotli.*) from a distribution's package: a dist-info whose RECORD was dropped
  oldLib(join(sp, 'brotli', '_brotli.abi3.so'));
  meta(join(sp, 'brotlipy-0.7.0.dist-info', 'METADATA'), 'brotlipy', '0.7.0');
  // pip's Brotli as an .egg folder, and brotlicffi inside another one
  oldLib(join(sp, 'Brotli-1.1.0-py3.12-macosx-14.0-arm64.egg', '_brotli.cpython-312-darwin.so'));
  meta(join(sp, 'Brotli-1.1.0-py3.12-macosx-14.0-arm64.egg', 'EGG-INFO', 'PKG-INFO'), 'Brotli', '1.1.0');
  oldLib(join(sp, 'brotlicffi-1.0.9.2-py3.12.egg', 'brotlicffi', '_brotlicffi.abi3.so'));
  // Pillow's package and vendored-library folders as links to folders elsewhere, with no install record
  oldLib(join(libs, 'PIL', '.dylibs', 'libbrotlidec.1.2.0.dylib')); oldLib(join(libs, 'pillow.libs', 'libbrotlidec-9ea4d3f1.so.1.2.0'));
  symlinkSync(join(libs, 'PIL'), join(sp, 'PIL')); symlinkSync(join(libs, 'pillow.libs'), join(sp, 'pillow.libs'));
  // a zipped egg of a binding: can't be looked inside
  writeFileSync(join(sp, 'brotlipy-0.6.0-py2.7-linux-x86_64.egg'), 'PK\x03\x04');
  const want = {
    'brotlicffi/_brotlicffi.abi3.so': 'brotlicffi 1.1.0.0', 'brotli/_brotli.abi3.so': '',
    'Brotli-1.1.0-py3.12-macosx-14.0-arm64.egg/_brotli.cpython-312-darwin.so': 'Brotli 1.1.0',
    'brotlicffi-1.0.9.2-py3.12.egg/brotlicffi/_brotlicffi.abi3.so': 'brotlicffi 1.0.9.2',
    'PIL/.dylibs/libbrotlidec.1.2.0.dylib': '', 'pillow.libs/libbrotlidec-9ea4d3f1.so.1.2.0': '',
  };
  const c = sitePackagesCandidates(sp);
  assert.deepEqual(Object.fromEntries(c.files.map((x) => [x.file.slice(sp.length + 1), x.owners.map((o) => `${o.name} ${o.version}`).join(', ')])), want);
  assert.deepEqual(c.zipped, [join(sp, 'brotlipy-0.6.0-py2.7-linux-x86_64.egg')]);
  const { rows } = run({}, { siteDirs: [sp] });
  for (const rel of Object.keys(want)) assert.equal(rows.find((r) => r.file === join(sp, rel))?.status, 'EXPOSED', rel);
  assert.match(rows.find((r) => r.file === join(sp, 'brotlicffi', '_brotlicffi.abi3.so')).fix, /'brotlicffi>=1\.2\.1\.0'/);
  const z = rows.find((r) => r.file === join(sp, 'brotlipy-0.6.0-py2.7-linux-x86_64.egg'));
  assert.equal(z.status, 'UNKNOWN'); assert.match(z.reason, /zipped egg.*could not be tested/);
  // the clean twin: the same places with fixed copies are SAFE, each with its receipt
  for (const rel of Object.keys(want)) fixedLib(realpathSync(join(sp, rel)));
  rmSync(join(sp, 'brotlipy-0.6.0-py2.7-linux-x86_64.egg'));
  assert.deepEqual(run({}, { siteDirs: [sp] }).rows.map((r) => r.status), Object.keys(want).map(() => 'SAFE'));
});

test('site-packages: a folder or a RECORD that can\'t be read is reported, never read as empty', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const sp = sitePackages(fresh('sp3'));
  execFileSync('chmod', ['000', join(sp, 'pillow-12.3.0.dist-info', 'RECORD')]);
  execFileSync('chmod', ['000', join(sp, 'cv2', '.dylibs')]);
  try {
    const c = sitePackagesCandidates(sp);
    assert.ok(c.unread.includes(join(sp, 'pillow-12.3.0.dist-info', 'RECORD')));
    assert.ok(c.unread.includes(join(sp, 'cv2', '.dylibs')));
    const unread = run({}, { siteDirs: [sp] }).rows.filter((r) => r.file === join(sp, 'cv2', '.dylibs'));
    assert.equal(unread.length, 1); assert.equal(unread[0].status, 'UNKNOWN'); assert.match(unread[0].reason, /could not be tested/);
    const locked = fresh('sp3-locked'); execFileSync('chmod', ['000', locked]);
    const denied = [];
    try { run({}, { siteDirs: [locked], denied }); } finally { execFileSync('chmod', ['755', locked]); }
    assert.deepEqual(denied, [locked], 'a site-packages folder that can\'t be listed goes to gaps(), not into "nothing found"');
  } finally {
    execFileSync('chmod', ['644', join(sp, 'pillow-12.3.0.dist-info', 'RECORD')]);
    execFileSync('chmod', ['755', join(sp, 'cv2', '.dylibs')]);
  }
});

test('node: PATH copies, version managers and the running node are read, never run; the fix line follows its line', () => {
  const d = fresh('rt'), path = fresh('rt-path'), ran = join(d, 'ran');
  // a script called node on PATH that would leave a marker if anything ran it
  writeFileSync(join(path, 'node'), `#!/bin/sh\ntouch "${ran}"\n`, { mode: 0o755 });
  const nvm = (v, parts) => bin(join(d, 'nvm', `v${v}`, 'bin', 'node'), [...parts, `nodejs.org/download/release/v${v}`]);
  nvm('26.12.1', [CONTROL, MARKER, NODE_MARKER]);
  for (const v of ['24.11.0', '22.1.0', '20.19.5', '25.0.0', '27.0.0']) nvm(v, [CONTROL]);
  bin(join(d, 'nvm', 'custom', 'bin', 'node'), [CONTROL, NODE_CONTROL]);   // no release string: the version is unknown
  const self = bin(join(d, 'self', 'node'), [CONTROL, MARKER, 'nodejs.org/download/release/v26.12.1']);
  const { rows, looked } = run({ nodeDirs: [join(d, 'nvm', '*', 'bin', 'node')] }, { pathEnv: path, execPath: self });
  const by = (v) => rows.find((r) => r.file === join(d, 'nvm', v, 'bin', 'node'));
  assert.equal(by('v26.12.1').status, 'SAFE'); assert.equal(by('v26.12.1').version, '26.12.1');
  for (const v of ['v24.11.0', 'v22.1.0', 'v20.19.5', 'v25.0.0', 'v27.0.0', 'custom']) assert.equal(by(v).status, 'EXPOSED', v);
  assert.match(by('v24.11.0').fix, /^Install Node\.js 24\.22\.1 or later, the fixed release for the 24 line/);
  assert.match(by('v22.1.0').fix, /^Install Node\.js 22\.23\.4 or later, the fixed release for the 22 line/);
  assert.match(by('v20.19.5').fix, /^Node\.js 20 is end-of-life and gets no fix/);
  assert.match(by('v25.0.0').fix, /^Node\.js 25 is end-of-life/, 'an odd-numbered line gets no fix either');
  assert.match(by('v27.0.0').fix, /^Install the fixed release for its line/, 'a line newer than the table: the general words');
  assert.match(by('custom').fix, /^Install the fixed release for its line/);
  assert.equal(rows.find((r) => r.file === self).status, 'SAFE');
  // a script that is no version manager's shim Wardlatch knows: the runtime it starts was not read (the script shims test below)
  const script = rows.find((r) => r.file === join(path, 'node'));
  assert.equal(script.status, 'UNKNOWN'); assert.match(script.reason, /^a script named node on PATH, not a program.*could not be tested/);
  assert.ok(looked.some((l) => l.includes(join(d, 'nvm'))), 'the receipt names the version managers\' folders');
  assert.ok(!existsSync(ran), 'nothing found was run');
  // a compiled program named node on PATH with no sign of Node.js that is a version manager's shim (volta's node links
  // to volta-shim, mise's to mise): REVIEW, never judged, when its folder of runtimes is there and read
  const vm = fresh('rt-vm');
  mkdirSync(join(vm, '.volta', 'tools', 'image', 'node'), { recursive: true }); mkdirSync(join(vm, '.local', 'share', 'mise', 'installs', 'node'), { recursive: true });
  for (const shimName of ['volta-shim', 'mise']) {
    const path2 = fresh(`rt-path2-${shimName}`);
    bin(join(d, `${shimName}-home`, shimName), ['shim']);
    symlinkSync(join(d, `${shimName}-home`, shimName), join(path2, 'node'));
    const r2 = run({ shims: shimsUnder(vm) }, { pathEnv: path2 }).rows;
    assert.equal(r2.length, 1); assert.equal(r2[0].status, 'REVIEW', shimName); assert.match(r2[0].reason, new RegExp(`^${shimName}, a version manager's shim, not a Node\\.js runtime`));
    // and without it, UNKNOWN (the end-to-end tests below are the command's)
    assert.equal(run({}, { pathEnv: path2 }).rows[0].status, 'UNKNOWN', shimName);
  }
  // any other compiled node with no sign of Node.js (packed, or a shim Wardlatch doesn't know): could not be tested
  const path4 = fresh('rt-path4');
  bin(join(path4, 'node'), ['packed']);
  const r4 = run({}, { pathEnv: path4 }).rows;
  assert.equal(r4.length, 1); assert.equal(r4[0].status, 'UNKNOWN'); assert.match(r4[0].reason, /could not be tested.*Check this one by hand/);
  // something named node or bun on PATH that isn't a regular file (a FIFO): not read, and said so
  const path3 = fresh('rt-path3');
  execFileSync('mkfifo', [join(path3, 'node')]); execFileSync('mkfifo', [join(path3, 'bun')]);
  const t = Date.now();
  const r3 = run({}, { pathEnv: path3 }).rows;
  assert.ok(Date.now() - t < 2000, 'a FIFO on PATH does not hang the run');
  assert.deepEqual(r3.map((r) => [r.file, r.status]), [[join(path3, 'node'), 'UNKNOWN'], [join(path3, 'bun'), 'UNKNOWN']]);
  for (const r of r3) assert.match(r.reason, /not a regular file.*could not be tested/);
});

test('a node or bun that can\'t be read is "could not be tested", on PATH, in a version manager\'s folder and in a package, never dropped', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const d = fresh('unreadable'), path = fresh('unreadable-path');
  const nvm = bin(join(d, 'nvm', 'v20.19.5', 'bin', 'node'), [CONTROL, 'nodejs.org/download/release/v20.19.5']);
  const onPath = bin(join(path, 'node'), [CONTROL]), bun = bin(join(path, 'bun'), [CONTROL]);
  const sp = fresh('unreadable-sp');
  const bundled = bin(join(sp, 'examplepkg', 'driver', 'node'), [CONTROL]);
  mkdirSync(join(sp, 'examplepkg-1.0.dist-info'));
  writeFileSync(join(sp, 'examplepkg-1.0.dist-info', 'RECORD'), 'examplepkg/driver/node,,\n');
  // a FIFO where a version manager keeps a runtime: not read, and said so
  mkdirSync(join(d, 'nvm', 'v22.0.0', 'bin'), { recursive: true }); execFileSync('mkfifo', [join(d, 'nvm', 'v22.0.0', 'bin', 'node')]);
  const go = () => run({ nodeDirs: [join(d, 'nvm', '*', 'bin', 'node')] }, { pathEnv: path, siteDirs: [sp] }).rows;
  const files = [nvm, onPath, bun, bundled];
  // the clean twin first: readable, each one is read (and EXPOSED: the control without the marker)
  const ok = go();
  for (const f of files) assert.equal(ok.find((r) => r.file === f)?.status, 'EXPOSED', f);
  // execute-only (mode 0111, as a hardened install can leave it): opened for reading, refused
  for (const f of files) execFileSync('chmod', ['111', f]);
  try {
    const rows = go();
    for (const f of files) {
      const r = rows.find((x) => x.file === f);
      assert.equal(r?.status, 'UNKNOWN', `${f}: a row, UNKNOWN`); assert.match(r.reason, /could not be read.*could not be tested/);
    }
    assert.ok(!rows.some((r) => r.status === 'REVIEW'), 'not a "script" or a shim');
    const fifo = rows.find((r) => r.file === join(d, 'nvm', 'v22.0.0', 'bin', 'node'));
    assert.equal(fifo?.status, 'UNKNOWN'); assert.match(fifo.reason, /^it is not a regular file.*could not be tested/);
  } finally {
    for (const f of files) execFileSync('chmod', ['755', f]);
  }
});

test('a distribution\'s node, a launcher for libnode: libnode decides, by the same rules, through the Brotli library it links', () => {
  const lib = fresh('libnode-lib'), path = fresh('libnode-path'), d = fresh('libnode');
  // Debian's /usr/bin/node names libnode.so.108, libstdc++ and libc, and nothing of Brotli; libnode links the system's
  elf(join(path, 'node'), [], { needed: ['libnode.so.108', 'libstdc++.so.6', 'libc.so.6'] });
  elf(join(lib, 'libnode.so.108'), [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v18.20.4'], { soname: 'libnode.so.108', needed: ['libbrotlidec.so.1', 'libbrotlienc.so.1'] });
  oldLib(join(lib, 'libbrotlidec.so.1'));
  const row = () => run({}, { pathEnv: path, sonameDirs: [lib] }).rows.find((r) => r.file === join(path, 'node'));
  const bad = row();
  assert.equal(bad.status, 'EXPOSED'); assert.match(bad.reason, /the library that holds Node\.js's code: it uses .*libbrotlidec\.so\.1, whose Brotli decoder lacks the fix/);
  assert.equal(bad.via, join(lib, 'libbrotlidec.so.1')); assert.match(bad.fix, /not Node\.js/);
  assert.equal(bad.version, '18.20.4', 'the release libnode holds, for the words');
  fixedLib(join(lib, 'libbrotlidec.so.1'));
  const good = row();
  assert.equal(good.status, 'SAFE'); assert.deepEqual(good.searched, [join(path, 'node'), join(lib, 'libnode.so.108'), join(lib, 'libbrotlidec.so.1')]);
  // beside it, another libnode's file name in its strings could be one it loads while it runs: UNKNOWN
  const unsure = judge(elf(join(d, 'node-unsure'), [Buffer.from(`\0\x01${join(d, 'other', 'libnode.so.108')}\0`)], { needed: ['libnode.so.108'] }), [lib]);
  assert.equal(unsure.status, 'UNKNOWN'); assert.match(unsure.reason, /it names .*libnode\.so\.108.*that is not one of the libraries it links/);
  // libnode is never followed to another libnode: one it links (here unfixed) leaves the node UNKNOWN, never SAFE
  elf(join(lib, 'libnode.so.109'), [CONTROL]);
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER], { needed: ['libnode.so.109'] });
  const nested = row();
  assert.equal(nested.status, 'UNKNOWN'); assert.match(nested.reason, /libnode\.so\.108, the library that holds Node\.js's code: its own Brotli decoder has the fix, but it links libnode\.so\.109, a Brotli library or libnode of its own/);
  // libnode with its own fixed table decides by it; with an unfixed one, EXPOSED. Every file of a libnode name in the
  // folders looked in is a candidate (round 10, rule 3), so the unfixed libnode.so.109 still there beside a fixed
  // libnode.so.108 makes the link a mix, UNKNOWN (round 9: SAFE, by libnode.so.108 alone)
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER]);
  const beside = row();
  assert.equal(beside.status, 'UNKNOWN', beside.reason); assert.match(beside.reason, /it links libnode\.so\.108, the library that holds Node\.js's code, and the 2 files of that name .* are not all fixed or all unfixed .*libnode\.so\.109 lacks it/);
  rmSync(join(lib, 'libnode.so.109'));
  assert.equal(row().status, 'SAFE');
  elf(join(lib, 'libnode.so.108'), [CONTROL]);
  assert.equal(row().status, 'EXPOSED');
  // a libnode that can't be followed or found: @rpath with no LC_RPATH that holds it, a DT_RUNPATH it can't follow, a
  // soname found nowhere: UNKNOWN, never REVIEW (beside a fixed libnode in the system's folders, which the loader may
  // take when the folder it can't follow holds none)
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER]);
  bin(join(d, 'node-rpath'), [], { links: ['@rpath/libnode.147.dylib'], rpaths: [join(d, 'nowhere')] });
  elf(join(d, 'node-runpath'), [], { needed: ['libnode.so.108'], runpath: '$LIB' });
  elf(join(d, 'node-nowhere'), [], { needed: ['libnode.so.999'] });
  for (const f of ['node-rpath', 'node-runpath', 'node-nowhere']) {
    const r = judge(join(d, f), [lib]);
    assert.equal(r.status, 'UNKNOWN', f); assert.match(r.reason, /libnode.*could not be tested/, f);
  }
  // beside a folder it can't follow, an unfixed libnode in the system's folders: the folder $LIB names may hold a fixed
  // copy the loader takes, so UNKNOWN (rounds 7 and 8 read EXPOSED, the system's copy deciding; c2f3a13 UNKNOWN). The
  // clean twin, with every folder followed: EXPOSED, the system's copy the only candidate
  elf(join(lib, 'libnode.so.108'), [CONTROL]);
  const past = judge(join(d, 'node-runpath'), [lib]);
  assert.equal(past.status, 'UNKNOWN', past.reason); assert.match(past.reason, /it links libnode\.so\.108, the library that holds Node\.js's code, which Wardlatch can't follow or open \(through '\$LIB'\)/);
  const plain = judge(elf(join(d, 'node-plain'), [], { needed: ['libnode.so.108'] }), [lib]);
  assert.equal(plain.status, 'EXPOSED', plain.reason); assert.equal(plain.via, realpathSync(join(lib, 'libnode.so.108')));
  // a node whose debug map names libnode_base.a (nodejs.org's macOS build does) is judged by its own table: a static
  // archive's member is no library it loads (round 5 read it UNKNOWN)
  assert.equal(judge(bin(join(d, 'node-debug-map'), [CONTROL, MARKER, '/Users/admin/build/ws/out/Release/libnode_base.a(async_resource.o)'])).status, 'SAFE');
  assert.equal(judge(bin(join(d, 'node-debug-map-old'), [CONTROL, '/Users/admin/build/ws/out/Release/libnode_base.a(async_resource.o)'])).status, 'EXPOSED');
});

test('libnode is Node.js\'s own library: a node it decides is told the Node.js fix, never to update libnode as a Brotli library', () => {
  const lib = fresh('libnode-fix-lib'), path = fresh('libnode-fix-path'), root = fresh('libnode-fix-sp');
  // Debian's node, a launcher for libnode, and a libnode whose own Brotli decoder lacks the fix (Node.js 22.1.0)
  elf(join(path, 'node'), [], { needed: ['libnode.so.108', 'libc.so.6'] });
  elf(join(lib, 'libnode.so.108'), [CONTROL, NODE_CONTROL, 'nodejs.org/download/release/v22.1.0']);
  // and a node a Python package carries that links the same libnode
  const sp = join(root, 'site-packages');
  elf(join(sp, 'examplepkg', 'driver', 'node'), [], { needed: ['libnode.so.108'] });
  mkdirSync(join(sp, 'examplepkg-1.0.dist-info'));
  writeFileSync(join(sp, 'examplepkg-1.0.dist-info', 'RECORD'), 'examplepkg/driver/node,,\n');
  const rows = () => run({}, { pathEnv: path, siteDirs: [sp], sonameDirs: [lib] }).rows;
  const bad = rows(), node = bad.find((r) => r.file === join(path, 'node')), pkg = bad.find((r) => r.what === 'python');
  assert.equal(node.status, 'EXPOSED'); assert.equal(node.via, join(lib, 'libnode.so.108'));
  assert.match(node.fix, /^Install Node\.js 22\.23\.4 or later, the fixed release for the 22 line/);
  assert.doesNotMatch(node.fix, /not Node\.js|Update whatever installed/);
  assert.equal(pkg.status, 'EXPOSED');
  assert.match(pkg.fix, /libnode\.so\.108, so it is fixed by updating that library, not the package: Install Node\.js 22\.23\.4 or later/);
  // a libnode that uses a Brotli library still sends the fix to that library (the libnode test above): only libnode's
  // own decoder is Node.js's. The clean twin: libnode fixed
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v22.23.4']);
  assert.deepEqual(rows().map((r) => r.status), ['SAFE', 'SAFE']);
});

test('a whole link to libnode is followed and judged beside a fixed table or a Brotli library too: an unfixed libnode is EXPOSED, one it can\'t follow UNKNOWN', () => {
  const d = fresh('ln-beside'), lib = fresh('ln-beside-lib');   // no folder named libnode here: its path would name it
  // each a Mach-O dylib for the Mach-O program and an ELF shared object for the ELF one
  const decFixed = fixedLib(join(d, 'brew', 'libbrotlidec.1.dylib')), decOld = oldLib(join(d, 'old', 'libbrotlidec.1.dylib'));
  const decFixedSo = fixedLib(join(d, 'brew', 'libbrotlidec.so.1')), decOldSo = oldLib(join(d, 'old', 'libbrotlidec.so.1'));
  const libnode = join(lib, 'libnode.147.dylib'), soname = join(lib, 'libnode.so.108');
  const besides = [['a fixed 1.1 table', [CONTROL, MARKER], [], []], ['a fixed 1.0 table', [packed(V1010)], [], []], ['a link to a fixed Brotli library', [], [decFixed], [decFixedSo]]];
  for (const [what, parts, links, needed] of besides) {
    const tag = what.replace(/[^a-z0-9]/gi, '_');
    const macho = bin(join(d, `macho-${tag}`), parts, { links: [...links, libnode] }), linux = elf(join(d, `elf-${tag}`), parts, { needed: [...needed, 'libnode.so.108'] });
    // the real attack: the libnode it links lacks the fix, by its own table or by the Brotli library it links (at
    // 9242a4f each read SAFE: libnode was looked at only when the file had no table and no Brotli library)
    for (const [how, make] of [['its own table', (f) => libFile(f, [CONTROL, NODE_CONTROL])], ['the Brotli library it links', (f) => libFile(f, [NODE_CONTROL], isSoName(f) ? { needed: [decOldSo] } : { links: [decOld] })]]) {
      make(libnode); make(soname);
      for (const [form, f] of [['Mach-O, an absolute path', macho], ['ELF, a soname', linux]]) {
        const r = judge(f, [lib]);
        // beside its own link to a fixed Brotli library, libnode's unfixed one is a candidate for that link and the
        // fixed one for libnode's (round 10, rule 2: a loader may hand a link a copy already loaded): a mix, UNKNOWN
        // (round 9: EXPOSED)
        if (links.length && how !== 'its own table') {
          assert.equal(r.status, 'UNKNOWN', `${what}, ${form}, unfixed by ${how}: ${r.reason}`); assert.match(r.reason, /are not all fixed or all unfixed/);
          continue;
        }
        assert.equal(r.status, 'EXPOSED', `${what}, ${form}, unfixed by ${how}: ${r.reason}`);
        assert.match(r.reason, /libnode\.(147\.dylib|so\.108), the library that holds Node\.js's code: (its Brotli decoder lacks the fix|it uses .*old\/libbrotlidec)/, `${what}, ${form}`);
      }
    }
    // the clean twin: libnode fixed, SAFE, its receipt naming libnode
    libFile(libnode, [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER]); libFile(soname, [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER]);
    for (const [f, l] of [[macho, libnode], [linux, soname]]) {
      const r = judge(f, [lib]);
      assert.equal(r.status, 'SAFE', `${what}: the clean twin`); assert.ok(r.searched.includes(f) && r.searched.includes(l), r.searched.join(', '));
    }
    // a libnode link it can't follow (@rpath with no LC_RPATH that holds it) or can't find: UNKNOWN, never SAFE on the
    // table or the Brotli library beside it
    for (const ref of ['@rpath/libnode.147.dylib', join(d, 'nowhere', 'libnode.147.dylib')]) {
      const r = judge(bin(join(d, `ref-${tag}-${ref.length}`), parts, { links: [...links, ref] }));
      assert.equal(r.status, 'UNKNOWN', `${what}: ${ref}`); assert.match(r.reason, /libnode\.147\.dylib, the library that holds Node\.js's code, which (Wardlatch can't follow|was not found).*could not be tested/, `${what}: ${ref}`);
    }
  }
  // through the command: a node on PATH with a fixed table, linking a libnode whose own decoder lacks the fix, is EXPOSED
  // and told the Node.js fix for libnode's line (libnode is Node.js's own library)
  const path = fresh('ln-beside-path');
  bin(libnode, [CONTROL, NODE_CONTROL, 'nodejs.org/download/release/v24.11.0'], { type: 6 });
  bin(join(path, 'node'), [CONTROL, MARKER], { links: [libnode] });
  const row = () => run({}, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node'));
  const bad = row();
  assert.equal(bad.status, 'EXPOSED'); assert.equal(bad.via, libnode); assert.match(bad.reason, /^its own Brotli decoder has the fix, but it uses .*libnode\.147\.dylib/);
  assert.match(bad.fix, /^Install Node\.js 24\.22\.1 or later, the fixed release for the 24 line/);
  bin(libnode, [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v24.22.1'], { type: 6 });
  assert.equal(row().status, 'SAFE', 'the clean twin');
});

test('a distribution\'s node whose libnode is found but can\'t be shown SAFE, or whose loader configuration could not all be read, is UNKNOWN, never SAFE', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const lib = fresh('libnode-unk-lib'), path = fresh('libnode-unk-path'), conf = fresh('libnode-unk-conf');
  elf(join(path, 'node'), [], { needed: ['libnode.so.108', 'libc.so.6'] });
  const row = (places = {}) => run({}, { pathEnv: path, sonameDirs: [lib], places }).rows.find((r) => r.file === join(path, 'node'));
  // libnode is there, but shows no table and links no Brotli library (stripped): the node can't be shown SAFE by it
  elf(join(lib, 'libnode.so.108'), [NODE_CONTROL, 'nodejs.org/download/release/v22.1.0']);
  const stripped = row();
  assert.equal(stripped.status, 'UNKNOWN'); assert.equal(stripped.via, join(lib, 'libnode.so.108'));
  assert.match(stripped.reason, /^it uses .*libnode\.so\.108, the library that holds Node\.js's code: no Brotli decoder's error texts are in this file.*could not be tested/);
  // libnode links a Brotli library by a path it can't follow ($LIB is the loader's to fill in): the same
  elf(join(lib, 'libnode.so.108'), [NODE_CONTROL], { needed: ['$LIB/libbrotlidec.so.1'] });
  const rpath = row();
  assert.equal(rpath.status, 'UNKNOWN'); assert.match(rpath.reason, /libnode\.so\.108, the library that holds Node\.js's code: it links \$LIB\/libbrotlidec\.so\.1, which Wardlatch can't follow/);
  // the clean twin: libnode with a fixed table
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER]);
  assert.equal(row().status, 'SAFE');
  // with that fixed libnode, the loader's configuration names a folder it doesn't read (an include elsewhere), or a file
  // it can't read: the loader may take libnode from there, so UNKNOWN
  mkdirSync(join(conf, 'ld.so.conf.d'), { recursive: true });
  const places = { ldSoConf: join(conf, 'ld.so.conf'), ldSoConfDir: join(conf, 'ld.so.conf.d') };
  writeFileSync(places.ldSoConf, 'include ld.so.conf.d/*.conf\ninclude /opt/vendor/ld.conf.d/*.conf\n');
  const gap = row(places);
  assert.equal(gap.status, 'UNKNOWN'); assert.equal(gap.via, 'libnode.so.108');
  assert.match(gap.reason, /^it links libnode\.so\.108, the library that holds Node\.js's code, and what the dynamic loader is told to search could not all be read \(.*include \/opt\/vendor.*could not be tested/);
  writeFileSync(places.ldSoConf, 'include ld.so.conf.d/*.conf\n'); writeFileSync(join(conf, 'ld.so.conf.d', 'vendor.conf'), '/opt/vendor/lib\n');
  execFileSync('chmod', ['000', join(conf, 'ld.so.conf.d', 'vendor.conf')]);
  try { assert.equal(row(places).status, 'UNKNOWN'); } finally { execFileSync('chmod', ['644', join(conf, 'ld.so.conf.d', 'vendor.conf')]); }
  // the clean twin: everything the configuration names read
  assert.equal(row(places).status, 'SAFE');
});

test('bun: 1.4.3\'s table is EXPOSED with the 1.4.4 fix, 1.4.4\'s is SAFE; Node\'s rules never apply; a bare bun is UNKNOWN', () => {
  const d = fresh('bun'), path = fresh('bun-path');
  const at = (parts) => { bin(join(path, 'bun'), parts); return run({}, { pathEnv: path }).rows.find((r) => r.file === join(path, 'bun')); };
  const old = at([CONTROL, 'Bun v1.4.3']);
  assert.equal(old.status, 'EXPOSED'); assert.match(old.fix, /Update Bun to 1\.4\.4 or later.*bun upgrade.*brew upgrade bun/);
  assert.equal(old.version, '', 'no Node.js version is read from a bun, even one that embeds a Node.js release URL');
  assert.equal(at([CONTROL, MARKER, 'Bun v1.4.4']).status, 'SAFE');
  // Bun's node:zlib constants are not compiled from the header: the names prove nothing, and neither does a Node release
  const names = at([NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v24.3.0']);
  assert.equal(names.status, 'UNKNOWN'); assert.equal(names.version, ''); assert.match(names.reason, /bun --version must print 1\.4\.4 or later/);
  // a compiled bun with nothing at all: UNKNOWN, not the REVIEW a node shim gets
  const bare = at(['nothing']);
  assert.equal(bare.status, 'UNKNOWN'); assert.match(bare.reason, /could not be tested/);
  // a bun that links a Homebrew-style library: that library decides, and its fix is the library's
  oldLib(join(d, 'brew', 'libbrotlidec.1.dylib'), { type: 6 });
  bin(join(path, 'bun'), [], { links: [join(d, 'brew', 'libbrotlidec.1.dylib')] });
  const linked = run({}, { pathEnv: path }).rows.find((r) => r.file === join(path, 'bun'));
  assert.equal(linked.status, 'EXPOSED'); assert.match(linked.fix, /not Bun/);
});

test('libraries: Homebrew\'s, MacPorts\' and conda\'s, and a program linking one is told that library\'s fix', () => {
  const d = fresh('libs'), path = fresh('libs-path');
  const brew = oldLib(join(d, 'brew', 'libbrotlidec.dylib')), ports = oldLib(join(d, 'ports', 'libbrotlidec.dylib'));
  const conda = oldLib(join(d, 'miniforge3', 'envs', 'ml', 'lib', 'libbrotlidec.so.1.2.0')), loose = oldLib(join(d, 'loose', 'libbrotlidec.1.dylib'));
  const libPlaces = [
    { pattern: brew, label: 'Homebrew brotli', fix: 'homebrew' }, { pattern: ports, label: 'MacPorts brotli', fix: 'macports' },
    { pattern: join(d, 'miniforge3', 'envs', '*', 'lib', 'libbrotlidec.*'), label: 'conda\'s libbrotlidec', fix: 'conda' },
  ];
  bin(join(path, 'node'), [NODE_CONTROL, NODE_MARKER], { links: [brew] });
  const { rows } = run({ libPlaces }, { pathEnv: path });
  // a library row names the file by its real path (the temporary folder may be behind a link, as /var is on macOS)
  const by = (f) => rows.find((r) => r.file === f || r.file === realpathSync(f));
  assert.match(by(brew).fix, /^brew upgrade brotli/); assert.equal(by(brew).label, 'Homebrew brotli');
  assert.match(by(ports).fix, /sudo port upgrade brotli/);
  assert.match(by(conda).fix, /^conda install -n ml 'libbrotlidec>=1\.2\.1'/);
  const node = by(join(path, 'node'));
  assert.equal(node.status, 'EXPOSED'); assert.equal(node.via, brew);
  assert.match(node.fix, /^It uses .*brew\/libbrotlidec\.dylib, so it is fixed by updating that library, not Node\.js: brew upgrade brotli/);
  // a linked library in no known place: the general words
  bin(join(path, 'node'), [NODE_CONTROL], { links: [loose] });
  assert.match(run({ libPlaces }, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node')).fix, /Update whatever installed .*loose\/libbrotlidec\.1\.dylib/);
  // clean twins
  fixedLib(brew); fixedLib(ports); fixedLib(conda);
  bin(join(path, 'node'), [NODE_CONTROL, NODE_MARKER], { links: [brew] });
  const good = run({ libPlaces }, { pathEnv: path }).rows;
  assert.deepEqual(good.map((r) => r.status), ['SAFE', 'SAFE', 'SAFE', 'SAFE']);
  assert.deepEqual(good[0].searched, [join(path, 'node'), realpathSync(brew)]);
});

test('conda: the Brotli library of every conda home whose Python packages are read is read too, base and environments', () => {
  const conda = INC.libPlaces.filter((p) => p.fix === 'conda').map((p) => p.pattern);
  // every conda home the Python search knows (lib/installs.mjs), in the same form: <home>/lib/libbrotlidec.*
  const homes = SITE_PATTERNS.filter((p) => /conda|miniforge|mambaforge|micromamba|Caskroom\/mini/.test(p) && p.endsWith('/lib/python3*/site-packages')).map((p) => p.slice(0, -'/lib/python3*/site-packages'.length));
  assert.ok(homes.length >= 15, `${homes.length} conda homes in the Python search`);
  for (const h of homes) assert.ok(conda.includes(`${h}/lib/libbrotlidec.*`), `${h}: its libbrotlidec is read`);
  // and each place, moved into a scratch root, finds an unfixed library there: EXPOSED, with the conda fix for its env
  const root = fresh('conda-root'), home = fresh('conda-home');
  const moved = conda.map((p) => (p.startsWith('~/') ? join(home, p.slice(2)) : join(root, p)));
  const files = moved.map((p) => oldLib(p.replaceAll('*', 'x').replace(/libbrotlidec\.x$/, 'libbrotlidec.1.1.0.dylib')));
  const { rows } = run({ libPlaces: moved.map((pattern) => ({ pattern, label: 'conda\'s libbrotlidec', fix: 'conda' })) });
  for (const f of files) {
    const r = rows.find((x) => x.file === realpathSync(f));
    assert.equal(r?.status, 'EXPOSED', f);
    assert.match(r.fix, new RegExp(`^conda install -n ${f.includes('/envs/') ? 'x' : 'base'} 'libbrotlidec>=1\\.2\\.1'`), f);
  }
});

test('conda installed as a Python version by pyenv, asdf or mise: its Brotli library is read, base and environments', () => {
  // the incident's own places in the home folder, moved into this test's home
  const home = fresh('conda-vm-home');
  const libPlaces = INC.libPlaces.filter((p) => p.pattern.startsWith('~/')).map((p) => ({ ...p, pattern: join(home, p.pattern.slice(2)) }));
  // the version names pyenv's python-build gives conda (anaconda3-*, miniconda3-*, miniforge3-*, mambaforge-*), which asdf
  // and mise install with it too, each in its manager's folder of Python versions
  const libs = [
    ['.pyenv/versions/miniforge3-24.3.0-0', 'base'], ['.pyenv/versions/miniforge3-24.3.0-0/envs/ml', 'ml'],
    ['.pyenv/versions/anaconda3-2024.06-1', 'base'], ['.pyenv/versions/mambaforge-22.9.0-3/envs/web', 'web'],
    ['.pyenv/versions/miniconda3-latest', 'base'], ['.asdf/installs/python/miniforge3-24.3.0-0', 'base'],
    ['.asdf/installs/python/anaconda3-2024.06-1/envs/ml', 'ml'], ['.local/share/mise/installs/python/mambaforge-22.9.0-3', 'base'],
    ['.local/share/mise/installs/python/miniconda3-3.12-24.1.2-0/envs/ml', 'ml'],
  ].map(([at, env]) => [oldLib(join(home, at, 'lib', 'libbrotlidec.1.1.0.dylib')), env]);
  const by = (rows, f) => rows.find((x) => x.file === realpathSync(f));
  const bad = run({ libPlaces }).rows;
  for (const [f, env] of libs) {
    assert.equal(by(bad, f)?.status, 'EXPOSED', f); assert.equal(by(bad, f).label, 'conda\'s libbrotlidec', f);
    assert.match(by(bad, f).fix, new RegExp(`^conda install -n ${env} 'libbrotlidec>=1\\.2\\.1'`), f);
  }
  // the clean twin: the same libraries fixed
  for (const [f] of libs) fixedLib(f);
  const good = run({ libPlaces }).rows;
  for (const [f] of libs) assert.equal(by(good, f)?.status, 'SAFE', f);
});

/** dpkg's status file as dpkg writes it: zlib1g first, then the given libbrotli1 stanzas. A rebuild (binNMU, such as
 *  1.1.0-2+b7) names its source version on the Source line; a security build (1.1.0-2+deb13u1) doesn't. */
const stanza = (version, source = '', arch = 'amd64') => `Package: libbrotli1\nStatus: install ok installed\nPriority: optional\nSection: libs\nInstalled-Size: 785\nMaintainer: Debian Brotli Maintainers <brotli@example.org>\nArchitecture: ${arch}\nMulti-Arch: same\nSource: brotli${source ? ` (${source})` : ''}\nVersion: ${version}\nDepends: libc6 (>= 2.29)\nDescription: library implementing brotli encoder and decoder (shared libraries)\n Brotli is a generic-purpose lossless compression algorithm.\n`;
const dpkgStatus = (file, ...stanzas) => writeFileSync(file, `Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:1.3.dfsg+really1.3.1-1+b1\n\n${stanzas.join('\n')}\n`);
/** dpkg's md5sums list for libbrotli1 in `info`, naming each file (by its real path) with its MD5, as dpkg writes it. */
const md5sums = (info, files, arch = 'amd64') => { mkdirSync(info, { recursive: true }); writeFileSync(join(info, `libbrotli1:${arch}.md5sums`), files.map((f) => `${createHash('md5').update(readFileSync(f)).digest('hex')}  ${realpathSync(f).slice(1)}\n`).join('')); };

test('a distribution\'s library without the marker: its own package version decides, by exact string; anything else is UNKNOWN', () => {
  const d = fresh('distro'), path = fresh('distro-path');
  const sys = oldLib(join(d, 'sys', 'libbrotlidec.so.1'));
  const status = join(d, 'status'), osr = join(d, 'os-release'), apk = join(d, 'installed'), info = join(d, 'info');
  writeFileSync(osr, 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n');
  const dpkg = (...st) => { dpkgStatus(status, ...st); md5sums(info, [sys]); };
  const libPlaces = [{ pattern: sys, label: 'the system\'s libbrotlidec', system: true }];
  // a node that links the system library (Debian's own nodejs does), by its path
  elf(join(path, 'node'), [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v18.19.0'], { needed: [sys] });
  const realSys = realpathSync(sys);
  const go = (places = { osRelease: osr, dpkgStatus: status, dpkgInfo: info }) => { const { rows } = run({ libPlaces }, { pathEnv: path, places }); return { lib: rows.find((r) => r.file === realSys), node: rows.find((r) => r.file === join(path, 'node')) }; };
  // Debian 13's security build
  dpkg(stanza('1.1.0-2+deb13u1'));
  let { lib, node } = go();
  assert.equal(lib.status, 'SAFE'); assert.match(lib.reason, /Debian's fixed package libbrotli1 1\.1\.0-2\+deb13u1 \(DSA-6582-1/); assert.equal(lib.label, 'libbrotli1 1.1.0-2+deb13u1');
  assert.deepEqual(lib.searched, [realSys, `${status}: libbrotli1 1.1.0-2+deb13u1`, `${join(info, 'libbrotli1:amd64.md5sums')}: ${realSys}, with the same MD5`]);
  assert.equal(node.status, 'SAFE', 'a program linking it is judged the same way'); assert.ok(node.searched.includes(`${status}: libbrotli1 1.1.0-2+deb13u1`));
  // stock trixie, as dpkg records it: the binNMU 1.1.0-2+b7, built from the unfixed source 1.1.0-2
  dpkg(stanza('1.1.0-2+b7', '1.1.0-2'));
  ({ lib, node } = go());
  assert.equal(lib.status, 'EXPOSED'); assert.match(lib.reason, /libbrotli1 1\.1\.0-2\+b7 is Debian's package without it \(built from brotli 1\.1\.0-2/);
  assert.match(lib.fix, /apt install --only-upgrade libbrotli1 \(Debian 13's fixed package is 1\.1\.0-2\+deb13u1\)/);
  assert.equal(node.status, 'EXPOSED'); assert.match(node.fix, /not Node\.js: sudo apt update/);
  // the unfixed source built without a rebuild suffix: the same source, EXPOSED
  dpkg(stanza('1.1.0-2'));
  assert.equal(go().lib.status, 'EXPOSED');
  // another distribution's version of it: not in the table
  dpkg(stanza('1.1.0-2ubuntu0.1'));
  ({ lib, node } = go());
  assert.equal(lib.status, 'UNKNOWN'); assert.match(lib.reason, /may have fixed it another way.*could not be tested/);
  assert.equal(node.status, 'UNKNOWN');
  // no package record names it (an rpm system, or a copy by hand): the distribution may still have fixed it, so UNKNOWN
  dpkg();
  assert.equal(go().lib.status, 'UNKNOWN');
  assert.equal(go({ osRelease: osr }).lib.status, 'UNKNOWN');
  // Debian testing, no fix yet: the binNMU 1.2.0-4+b1 of the unfixed source is EXPOSED, and the fix says so
  writeFileSync(osr, 'ID=debian\nVERSION_CODENAME=forky\n');
  dpkg(stanza('1.2.0-4+b1', '1.2.0-4'));
  assert.equal(go().lib.status, 'EXPOSED'); assert.match(go().lib.fix, /Debian had no fixed package for this release on 24 October 2026/);
  // Alpine's record is read, but nothing for Alpine is in the table yet: UNKNOWN
  writeFileSync(osr, 'ID=alpine\nVERSION_ID=3.22.2\n');
  writeFileSync(apk, 'C:Q1x\nP:musl\nV:1.2.5-r10\n\nC:Q1y\nP:brotli-libs\nV:1.1.0-r2\n\n');
  const alp = go({ osRelease: osr, apkInstalled: apk }).lib;
  assert.equal(alp.status, 'UNKNOWN'); assert.equal(alp.label, 'brotli-libs 1.1.0-r2');
  // a fixed system library needs no package record at all
  fixedLib(sys);
  assert.equal(go({}).lib.status, 'SAFE');
  // the table is exact strings: a version close to a listed one is never compared by order, and the fixed list is binary
  // versions only (a rebuild of the security build is not in it)
  oldLib(sys);
  writeFileSync(osr, 'ID=debian\nVERSION_ID="13"\n');
  for (const st of [stanza('1.1.0-2+deb13u2'), stanza('1.1.0-2+deb13u1+b1', '1.1.0-2+deb13u1'), stanza('1.1.0-2+b7', '1.1.0-2.1')]) {
    dpkg(st);
    assert.equal(distroVerdict(sys, INC.distro, { osRelease: osr, dpkgStatus: status, dpkgInfo: info }).status, 'UNKNOWN', st.split('\n').filter((l) => /^(Source|Version)/.test(l)).join(' '));
  }
  // Brotli 1.0's error texts (no _ERROR_FORMAT_ prefix) that are no whole table: no table is seen and the package record
  // is not reached, UNKNOWN, never SAFE (Debian 12's whole table is the next test)
  const old10 = bin(join(d, 'sys12', 'libbrotlidec.so.1'), ['SUCCESS', 'BLOCK_LENGTH_1', 'UNREACHABLE']);
  writeFileSync(osr, 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n');
  dpkg(stanza('1.0.9-2+deb12u1'));
  md5sums(info, [old10]);
  const r12 = run({ libPlaces: [{ pattern: old10, label: 'the system\'s libbrotlidec', system: true }] }, { places: { osRelease: osr, dpkgStatus: status, dpkgInfo: info } }).rows[0];
  assert.equal(r12.status, 'UNKNOWN'); assert.match(r12.reason, /could not be tested/);
});

test('Debian 12\'s libbrotli1 1.0.9, in Brotli 1.0\'s form: its table without the fix\'s name hands over to its package version, as before', () => {
  const d = fresh('deb12'), path = fresh('deb12-path');
  const sys = elf(join(d, 'usr', 'lib', 'x86_64-linux-gnu', 'libbrotlidec.so.1'), [packed(V109)]);
  const status = join(d, 'status'), osr = join(d, 'os-release'), info = join(d, 'info');
  writeFileSync(osr, 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n');
  const places = { osRelease: osr, dpkgStatus: status, dpkgInfo: info };
  const libPlaces = [{ pattern: sys, label: 'the system\'s libbrotlidec', system: true }];
  // Debian's own node links it by soname
  elf(join(path, 'node'), [NODE_CONTROL, 'nodejs.org/download/release/v18.19.0'], { needed: ['libbrotlidec.so.1'] });
  const go = () => { const { rows } = run({ libPlaces }, { pathEnv: path, places, sonameDirs: [dirname(sys)] }); return { lib: rows.find((r) => r.what === 'library'), node: rows.find((r) => r.what === 'node') }; };
  // a fixed package whose table lacks the fix's name (a backport without the new error code; Debian's own security
  // build adds it, the test below), the file it installed: SAFE by the package's version, the program too
  dpkgStatus(status, stanza('1.0.9-2+deb12u1')); md5sums(info, [sys]);
  let { lib, node } = go();
  assert.equal(lib.status, 'SAFE'); assert.match(lib.reason, /Debian's fixed package libbrotli1 1\.0\.9-2\+deb12u1 \(DLA-4855-1/);
  assert.equal(node.status, 'SAFE');
  // stock bookworm (1.0.9-2): EXPOSED, told Debian 12's fixed package
  dpkgStatus(status, stanza('1.0.9-2')); md5sums(info, [sys]);
  ({ lib, node } = go());
  assert.equal(lib.status, 'EXPOSED'); assert.match(lib.fix, /Debian 12's fixed package is 1\.0\.9-2\+deb12u1/);
  assert.equal(node.status, 'EXPOSED'); assert.match(node.fix, /not Node\.js: sudo apt update/);
  // a version not in the table, and a file no package record names: UNKNOWN
  dpkgStatus(status, stanza('1.0.9-2+deb12u2')); md5sums(info, [sys]);
  assert.equal(go().lib.status, 'UNKNOWN');
  dpkgStatus(status); assert.equal(go().lib.status, 'UNKNOWN');
  // the clean twin: a 1.0.10 table needs no package record
  elf(sys, [packed(V1010)]);
  assert.equal(go().lib.status, 'SAFE'); assert.equal(go().node.status, 'SAFE');
});

/** Brotli 1.0's table as GCC lays it out in Debian 12's own libbrotli1 (1.0.9-2+b6 and 1.0.9-2+deb12u1, amd64 and arm64,
 *  read from the packages on deb.debian.org): decode.h's order, the whole list from NO_ERROR on; on amd64 one NUL after
 *  each name, on arm64 each name and its NUL padded to 8 bytes; and right before NO_ERROR the last bytes of the data
 *  before it, with no NUL between. The security build has BLOCK_SWITCH between DISTANCE and DICTIONARY_NOT_SET. */
const gccTable = (names, arch) => Buffer.concat([Buffer.from([0xff, 0x42, 0x58, 0x46]), packed(names, arch === 'arm64' ? 8 : 1).subarray(1)]);

test('Debian 12\'s libbrotli1 as GCC built it: 1.0.9-2+b6 is EXPOSED by its table and its package record, the security build SAFE by its table alone', () => {
  const d = fresh('deb12-gcc'), osr = join(d, 'os-release');
  writeFileSync(osr, 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n');
  for (const [arch, triplet] of [['amd64', 'x86_64-linux-gnu'], ['arm64', 'aarch64-linux-gnu']]) {
    const lib = (v, names) => elf(join(d, v, arch, 'usr', 'lib', triplet, 'libbrotlidec.so.1.0.9'), [gccTable(names, arch)], { needed: ['libbrotlicommon.so.1', 'libc.so.6'], soname: 'libbrotlidec.so.1' });
    const status = join(d, `status-${arch}`), info = join(d, `info-${arch}`);
    const row = (file, places = {}) => run({ libPlaces: [{ pattern: file, label: 'the system\'s libbrotlidec', system: true }] }, { places }).rows[0];
    // stock bookworm: the table without the fix's name, and the record of the binNMU built from the unfixed source
    const b6 = lib('b6', V109);
    assert.deepEqual(evidence(b6, M).t10, { fixed: 0, unfixed: 1, other: 0 }, arch);
    dpkgStatus(status, stanza('1.0.9-2+b6', '1.0.9-2', arch)); md5sums(info, [b6], arch);
    const bad = row(b6, { osRelease: osr, dpkgStatus: status, dpkgInfo: info });
    assert.equal(bad.status, 'EXPOSED', arch); assert.equal(bad.label, 'libbrotli1 1.0.9-2+b6');
    assert.match(bad.fix, /Debian 12's fixed package is 1\.0\.9-2\+deb12u1/);
    // its table alone says EXPOSED; at a system place with no package record to read, the distribution may have fixed
    // it another way, so UNKNOWN
    const own = judgeFile(b6, { markers: M, follow: false });
    assert.equal(own.status, 'EXPOSED', arch); assert.ok(own.noMarker);
    assert.equal(row(b6).status, 'UNKNOWN', arch);
    // the clean twin, the security build: SAFE by its table, with no package record at all
    const u1 = lib('deb12u1', V1010);
    assert.deepEqual(evidence(u1, M).t10, { fixed: 1, unfixed: 0, other: 0 }, arch);
    const good = row(u1);
    assert.equal(good.status, 'SAFE', arch); assert.match(good.reason, /has the fix: its error texts, in the form Brotli 1\.0 writes them/);
    assert.deepEqual(good.searched, [realpathSync(u1)]);
  }
});

test('a distribution\'s package version speaks only for a file that package installed, as dpkg installed it', () => {
  const d = fresh('owned'), info = join(d, 'info'), status = join(d, 'status'), osr = join(d, 'os-release');
  writeFileSync(osr, 'ID=debian\nVERSION_ID="13"\n');
  const places = { osRelease: osr, dpkgStatus: status, dpkgInfo: info };
  const dist = oldLib(join(d, 'usr', 'lib', 'x86_64-linux-gnu', 'libbrotlidec.so.1.1.0'));
  // a hand-built 1.2.0 (`make install` with prefix /usr) beside it, at a system place: dpkg says the fixed package is
  // installed, but it never installed this file, so its version says nothing about it
  const hand = oldLib(join(d, 'usr', 'lib', 'x86_64-linux-gnu', 'libbrotlidec.so.1.2.0'));
  dpkgStatus(status, stanza('1.1.0-2+deb13u1')); md5sums(info, [dist]);
  assert.equal(distroVerdict(dist, INC.distro, places).status, 'SAFE', 'the file dpkg installed, unchanged');
  const h = distroVerdict(hand, INC.distro, places);
  assert.equal(h.status, 'UNKNOWN'); assert.match(h.reason, /dpkg's records don't list it as a file of libbrotli1.*could not be tested/);
  // through a program that links it by soname, and as the system library row: never "Debian's fixed package"
  const libPlaces = [{ pattern: hand, label: 'the system\'s libbrotlidec', system: true }];
  assert.equal(run({ libPlaces }, { places }).rows[0].status, 'UNKNOWN');
  // the file dpkg installed, changed since (its MD5 differs): UNKNOWN
  oldLib(dist); writeFileSync(dist, Buffer.concat([readFileSync(dist), Buffer.from('changed')]));
  const c = distroVerdict(dist, INC.distro, places);
  assert.equal(c.status, 'UNKNOWN'); assert.match(c.reason, /not the file libbrotli1 installed/);
  // the same for an unfixed package: only the file it installed is EXPOSED by its version
  oldLib(dist); dpkgStatus(status, stanza('1.1.0-2+b7', '1.1.0-2')); md5sums(info, [dist]);
  assert.equal(distroVerdict(dist, INC.distro, places).status, 'EXPOSED');
  assert.equal(distroVerdict(hand, INC.distro, places).status, 'UNKNOWN');
  // no md5sums to read: UNKNOWN
  assert.equal(distroVerdict(dist, INC.distro, { osRelease: osr, dpkgStatus: status }).status, 'UNKNOWN');
  // hashing it reads it again, within the run's reading budget: past it, UNKNOWN
  const over = distroVerdict(dist, INC.distro, places, { left: 10 });
  assert.equal(over.status, 'UNKNOWN'); assert.match(over.reason, /4 GB/);
  assert.equal(distroVerdict(dist, INC.distro, places, { left: 1e6 }).status, 'EXPOSED', 'the clean twin: within the budget');
  // two architectures installed (Multi-Arch: same): the one whose list names the file decides
  const i386 = oldLib(join(d, 'usr', 'lib', 'i386-linux-gnu', 'libbrotlidec.so.1.1.0'));
  dpkgStatus(status, stanza('1.1.0-2+deb13u1'), stanza('1.1.0-2+b7', '1.1.0-2', 'i386'));
  md5sums(info, [dist]); md5sums(info, [i386], 'i386');
  assert.equal(distroVerdict(dist, INC.distro, places).status, 'SAFE');
  const r = distroVerdict(i386, INC.distro, places);
  assert.equal(r.status, 'EXPOSED'); assert.equal(r.label, 'libbrotli1 1.1.0-2+b7');
});

test('words: every UNKNOWN says "could not be tested", every EXPOSED has a fix, every SAFE names what it read', () => {
  const root = fresh('words'), path = fresh('words-path');
  const sp = sitePackages(root);
  bin(join(path, 'node'), ['nodejs.org/download/release/v24.11.0', CONTROL]);
  bin(join(path, 'bun'), ['nothing']);
  bin(join(sp, 'stray.libs', 'libbrotlidec-1.so.1'), [MARKER]);
  bin(join(sp, 'stray2.libs', 'libbrotlidec-2.so.1'), [], { type: 6, links: ['@rpath/libbrotlidec.1.dylib'] });
  const { rows } = run({}, { pathEnv: path, siteDirs: [sp], budgetBytes: 1e9 });
  assert.ok(rows.length >= 10);
  for (const r of rows) {
    if (r.status === 'UNKNOWN') assert.match(r.reason, /could not be tested/, r.file);
    if (r.status === 'EXPOSED') { assert.ok(r.fix && r.fix.length > 20, r.file); assert.ok(!r.fix.includes('{'), `${r.file}: no placeholder left`); }
    if (r.status === 'SAFE') assert.ok(r.searched.includes(r.file), r.file);
    for (const k of ['viaText', 'noMarker', 'runtimeSign', 'byHand', 'noTable']) assert.ok(!(k in r), `${k} stays inside the module`);
  }
});

test('words that agree with the by-hand guide: each line\'s fixed release, the lines with no fix, and no claim beyond it', () => {
  // Node.js 22.23.4 bundles and reports Brotli 1.1.0; 24.22.1 and 26.12.1 report 1.2.0
  assert.match(INC.summary, /still report the Brotli they shipped with \(1\.1\.0 on the 22 line, 1\.2\.0 on 24 and 26\)/);
  // the odd-numbered lines get no fix, and no "and later" can be read as covering one
  for (const t of [INC.hints.node, INC.fixes.node]) assert.match(t, /odd-numbered lines/);
  for (const t of [INC.hints.node, INC.fixes.node, INC.fixes['pip-node']]) assert.match(t, /22\.23\.4 or later on the 22 line, 24\.22\.1 or later on 24, 26\.12\.1 or later on 26/);
  // a Brotli release per line, never "1.0.10, 1.1.1, 1.2.1 or later" (which reads as any version from 1.0.10 on)
  for (const t of [INC.fixes['library-other'], INC.fixes['pip-bundled'], INC.hints.file]) assert.match(t, /1\.0\.10 on the 1\.0 line, 1\.1\.1 on 1\.1, or 1\.2\.1 or later/);
  // what the check can't see is said: a library loaded under another name (the link table and the names beside it are read)
  assert.match(INC.notCovered, /a Brotli library a program loads under another name \(a link of another name, or a name it puts together while it runs\)/);
  // the bundled copies' lines say only what the guide says: no fixed release yet, update when one ships
  for (const k of ['pillow', 'opencv-python', 'opencv-contrib-python']) {
    assert.match(INC.dists[k].fix, /^No [A-Za-z-]+ release had a fixed Brotli on 24 October 2026: update [A-Za-z-]+ when one ships/);
    assert.doesNotMatch(INC.dists[k].fix, /WOFF2|FreeType|FFmpeg|way in|5\.0\.0\.93|1\.1\.0|1\.2\.0/);
  }
});

test('bounded: a file full of "libbrotlidec" with no header, as many load commands or DT_NEEDED entries as fit, and a hostile ld.so.conf line are read in time', () => {
  const d = fresh('bounded'), f = join(d, 'x');
  writeFileSync(f, Buffer.concat([MACHO, Buffer.from('A/libbrotlidec.1.dylib'.repeat(200000))]));
  const t = Date.now();
  const r = judge(f);
  assert.ok(Date.now() - t < 3000, `${Date.now() - t} ms`);
  assert.equal(r.status, 'UNKNOWN');
  // 60,000 LC_RPATH commands (960 KB of the 1 MB read), and 4,000 DT_NEEDED entries (the 64 KB of a dynamic segment read)
  for (const [what, file] of [['load commands', bin(join(d, 'cmds'), [CONTROL, MARKER], { rpaths: Array.from({ length: 60000 }, () => '/x') })],
    ['DT_NEEDED', elf(join(d, 'needed'), [CONTROL, MARKER], { needed: Array.from({ length: 4000 }, () => 'libc.so.6') })]]) {
    const t1 = Date.now();
    assert.equal(judge(file).status, 'SAFE', what);
    assert.ok(Date.now() - t1 < 3000, `${what}: ${Date.now() - t1} ms`);
  }
  // a hostile ld.so.conf line is split in linear time
  const conf = join(fresh('bounded-conf'), 'x.conf');
  writeFileSync(conf, `/${' '.repeat(60000)}/x\n`);
  const t2 = Date.now(); ldSoConfDirs({ ldSoConf: conf }); assert.ok(Date.now() - t2 < 500);
  writeFileSync(conf, `include${' '.repeat(60000)}x\n`);
  const t3 = Date.now(); ldSoConfDirs({ ldSoConf: conf }); assert.ok(Date.now() - t3 < 500);
});

// ---- the command, end to end ----------------------------------------------------------------------------------------
const PRELOAD = ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs')];
// the preload never hides this test's own folder (and hides the rest of the temporary folder like any other place)
// the variables that move a version manager's folders are cleared, so a test sees only the places it makes (one the
// person running the tests has set could name a folder in their real home)
const VM_VARS = ['VOLTA_HOME', 'MISE_DATA_DIR', 'MISE_INSTALLS_DIR', 'MISE_SYSTEM_DATA_DIR', 'MISE_SYSTEM_INSTALLS_DIR', 'MISE_SHARED_INSTALL_DIRS', 'XDG_DATA_HOME', 'RTX_DATA_DIR', 'PROTO_HOME', 'ASDF_DATA_DIR', 'NODENV_ROOT'];
const cli = (args, env) => {
  const r = spawnSync(process.execPath, [...PRELOAD, BIN, ...args], { encoding: 'utf8', env: { ...process.env, ...Object.fromEntries(VM_VARS.map((k) => [k, ''])), WARDLATCH_TEST_OWN_DIR: dir, ...env }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test('the preload hides the machine\'s server folders (/srv, /app, /var/www) and loader lists, never the code under test', () => {
  const probe = ['/srv/site/venv/lib', '/app/.venv/lib', '/var/www/html', '/etc/ld-musl-x86_64.path', '/var/lib/dpkg/status', ROOT, join(ROOT, 'lib', 'brotli.mjs')];
  const script = `const fs = require('node:fs'); console.log(JSON.stringify(${JSON.stringify(probe)}.map((p) => { try { fs.statSync(p); return 'seen'; } catch (e) { return e.message === 'hidden by the test' ? 'hidden' : 'absent'; } })));`;
  const r = spawnSync(process.execPath, [...PRELOAD, '-e', script], { encoding: 'utf8' });
  assert.deepEqual(JSON.parse(r.stdout), ['hidden', 'hidden', 'hidden', 'hidden', 'hidden', 'seen', 'seen'], r.stderr);
});

test('the preload keeps only the code under test and the test\'s own folder: the rest of a checkout in /app is hidden', () => {
  // a dev container's checkout at /app, and the test's own folder in a temporary folder under /srv
  const hidden = hiddenPlaces({ root: '/app', own: '/srv/ci/tmp/wardlatch-brotli-x', self: ['/usr/local/bin/node'] });
  for (const p of ['/app/bin/wardlatch.mjs', '/app/lib/brotli.mjs', '/app/lib/incidents/brotli-2026-10.json', '/app/test/support/fake-home.cjs', '/app/package.json', '/srv/ci/tmp/wardlatch-brotli-x/home/.nvm']) assert.equal(hidden(p), false, p);
  // /app/.venv is always read by the check: the machine's own Pillow there must not reach a test, nor anything else
  // beside the checkout's code or in the temporary folder outside the test's own folder
  for (const p of ['/app/.venv/lib/python3.12/site-packages', '/app/README.md', '/app/libx/y', '/app/binary', '/srv/ci/tmp/other/venv', '/srv/site/venv', '/usr/local/bin/node']) assert.equal(hidden(p), true, p);
});

test('CLI: an exposed copy is exit 1 with its fix, a fixed-only machine exit 0 with receipts, nothing found is one receipted SAFE', () => {
  const home = fresh('cli-home'), path = fresh('cli-path');
  // a project virtual environment under the searched folder, holding Pillow's old copy
  const venv = join(home, 'Development', 'app', '.venv');
  writeFileSync(join(fresh('cli-home/Development/app/.venv'), 'pyvenv.cfg'), 'home = /usr/bin\n');
  const sp = join(venv, 'lib', 'python3.14', 'site-packages');
  oldLib(join(sp, 'PIL', '.dylibs', 'libbrotlidec.1.2.0.dylib'));
  mkdirSync(join(sp, 'pillow-12.3.0.dist-info'), { recursive: true });
  writeFileSync(join(sp, 'pillow-12.3.0.dist-info', 'METADATA'), 'Name: Pillow\nVersion: 12.3.0\n');
  writeFileSync(join(sp, 'pillow-12.3.0.dist-info', 'RECORD'), 'PIL/.dylibs/libbrotlidec.1.2.0.dylib,,\n');
  bin(join(home, '.nvm', 'versions', 'node', 'v26.12.1', 'bin', 'node'), [CONTROL, MARKER, 'nodejs.org/download/release/v26.12.1']);
  const env = { HOME: home, PATH: path };
  const bad = cli(['--incident', 'brotli-2026-10', '--json', '--paths', join(home, 'Development')], env);
  assert.equal(bad.code, 1, bad.err);
  const j = JSON.parse(bad.out);
  const pil = j.results.find((r) => r.file?.endsWith('libbrotlidec.1.2.0.dylib'));
  assert.equal(pil.status, 'EXPOSED'); assert.equal(pil.kind, 'bundled'); assert.equal(pil.owner, 'Pillow 12.3.0'); assert.ok(pil.fix);
  const nvm = j.results.find((r) => r.file?.includes('.nvm'));
  assert.equal(nvm.status, 'SAFE'); assert.ok(nvm.searched.length);
  const text = cli(['--incident', 'brotli-2026-10', '--paths', join(home, 'Development')], env);
  assert.match(text.out, /EXPOSED {2}Pillow 12\.3\.0 {2}~\/Development\/app\/\.venv\/lib\/python3\.14\/site-packages\/PIL\/\.dylibs\/libbrotlidec\.1\.2\.0\.dylib/);
  assert.match(text.out, /fix: No Pillow release had a fixed Brotli on 24 October 2026/);
  assert.match(text.out, /SAFE {5}node 26\.12\.1 {2}~\/\.nvm\/versions\/node\/v26\.12\.1\/bin\/node/);
  assert.match(text.out, /runs nothing/);
  assert.match(text.out, /not covered: .*Envoy and Istio.*https:\/\/www\.deimoscore\.com\/wardlatch\/brotli\//);
  // clean twin: the same machine after Pillow ships a fixed copy
  fixedLib(join(sp, 'PIL', '.dylibs', 'libbrotlidec.1.2.0.dylib'));
  const good = cli(['--incident', 'brotli-2026-10', '--json', '--paths', join(home, 'Development')], env);
  assert.equal(good.code, 0, good.out);
  assert.ok(JSON.parse(good.out).results.every((r) => r.status !== 'SAFE' || r.searched?.length), 'every SAFE row has a receipt');
  // a copy whose table is stripped is exit 2, not 0
  bin(join(sp, 'PIL', '.dylibs', 'libbrotlidec.1.2.0.dylib'), [MARKER]);
  assert.equal(cli(['--incident', 'brotli-2026-10', '--json', '--paths', join(home, 'Development')], env).code, 2);
  // conda's own library in conda homes beyond the first three (mambaforge, ~/.conda/envs): read, EXPOSED, exit 1
  const chome = fresh('cli-conda-home');
  oldLib(join(chome, 'mambaforge', 'lib', 'libbrotlidec.1.1.0.dylib')); oldLib(join(chome, '.conda', 'envs', 'work', 'lib', 'libbrotlidec.1.1.0.dylib'));
  const cbad = cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh('cli-conda-empty')], { HOME: chome, PATH: fresh('cli-conda-path') });
  assert.equal(cbad.code, 1, cbad.out);
  assert.deepEqual(JSON.parse(cbad.out).results.filter((r) => r.what === 'library').map((r) => [r.status, r.file.slice(realpathSync(chome).length)]).sort(),
    [['EXPOSED', '/.conda/envs/work/lib/libbrotlidec.1.1.0.dylib'], ['EXPOSED', '/mambaforge/lib/libbrotlidec.1.1.0.dylib']]);
  fixedLib(join(chome, 'mambaforge', 'lib', 'libbrotlidec.1.1.0.dylib')); fixedLib(join(chome, '.conda', 'envs', 'work', 'lib', 'libbrotlidec.1.1.0.dylib'));
  assert.equal(cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh('cli-conda-empty')], { HOME: chome, PATH: fresh('cli-conda-path') }).code, 0, 'the clean twin');
  // nothing anywhere: one SAFE row naming where it looked
  const empty = fresh('cli-empty');
  const none = cli(['--incident', 'brotli-2026-10', '--json', '--paths', empty], { HOME: fresh('cli-empty-home'), PATH: fresh('cli-empty-path') });
  assert.equal(none.code, 0, none.out);
  const rows = JSON.parse(none.out).results;
  assert.equal(rows.length, 1); assert.equal(rows[0].status, 'SAFE'); assert.ok(rows[0].searched.some((s) => s.startsWith('node on PATH')));
  // a --paths folder that isn't there is not an all-clear: its own UNKNOWN row, in --json and in the text
  const menv = { HOME: fresh('cli-m-home'), PATH: fresh('cli-m-path') };
  const missing = cli(['--incident', 'brotli-2026-10', '--json', '--paths', join(dir, 'no-such-folder')], menv);
  assert.equal(missing.code, 2);
  const row = JSON.parse(missing.out).results.find((r) => r.reason?.startsWith('none of the folders given with --paths exist'));
  assert.equal(row?.status, 'UNKNOWN'); assert.equal(row.kind, 'bundled');
  assert.match(cli(['--incident', 'brotli-2026-10', '--paths', join(dir, 'no-such-folder')], menv).out, /^UNKNOWN {2}folders given with --paths$/m);
});

test('a version manager\'s shim on PATH is a REVIEW line only when its runtimes are read: proto and rtx too, so an unfixed one is never exit 0', () => {
  // each shim Wardlatch knows by name, and where its version manager keeps the nodes it starts
  for (const [shim, folder] of [['volta-shim', '.volta/tools/image/node/20.11.0'], ['mise', '.local/share/mise/installs/node/20.11.0'],
    ['rtx', '.local/share/rtx/installs/node/20.11.0'], ['proto-shim', '.proto/tools/node/20.11.0']]) {
    const home = fresh(`shim-home-${shim}`), path = fresh(`shim-path-${shim}`);
    bin(join(home, 'manager', shim), ['shim']);
    symlinkSync(join(home, 'manager', shim), join(path, 'node'));
    const node = join(home, folder, 'bin', 'node');
    bin(node, [CONTROL, NODE_CONTROL, 'nodejs.org/download/release/v20.11.0']);
    const go = () => cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh(`shim-empty-${shim}`)], { HOME: home, PATH: path });
    const bad = go();
    assert.equal(bad.code, 1, `${shim}: ${bad.out}`);
    const rows = JSON.parse(bad.out).results;
    assert.equal(rows.find((r) => r.file === join(path, 'node'))?.status, 'REVIEW', shim);
    assert.equal(rows.find((r) => r.file?.endsWith(`/${folder}/bin/node`))?.status, 'EXPOSED', `${shim}: the node it starts is read`);
    // the clean twin: that node fixed
    bin(node, [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v26.12.1']);
    const good = go();
    assert.equal(good.code, 0, `${shim}: ${good.out}`);
    assert.equal(JSON.parse(good.out).results.find((r) => r.file?.endsWith(`/${folder}/bin/node`))?.status, 'SAFE', shim);
  }
});

/** A version manager's compiled shim on PATH: `node` in `pathDir`, a link to a program named `kind` (what volta's,
 *  mise's, rtx's and proto's shims link to). */
const shimOnPath = (pathDir, kind) => { const real = bin(join(fresh(`shim-bin-${kind}-${Math.random()}`), kind), ['shim']); mkdirSync(pathDir, { recursive: true }); symlinkSync(real, join(pathDir, 'node')); return join(pathDir, 'node'); };
const node20 = (f) => bin(f, [CONTROL, NODE_CONTROL, 'nodejs.org/download/release/v20.11.0']);
const node26 = (f) => bin(f, [CONTROL, MARKER, NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v26.12.1']);

test('a version manager\'s shim whose folder of runtimes is not found, or can\'t be read, is UNKNOWN (exit 2), never a clean exit', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  for (const [kind, folder] of [['volta-shim', '.volta/tools/image/node'], ['mise', '.local/share/mise/installs/node'], ['rtx', '.local/share/rtx/installs/node'], ['proto-shim', '.proto/tools/node']]) {
    const home = fresh(`nowhere-home-${kind}`), path = fresh(`nowhere-path-${kind}`);
    const shim = shimOnPath(path, kind);
    const go = () => cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh(`nowhere-empty-${kind}`)], { HOME: home, PATH: path });
    // its manager keeps its nodes somewhere Wardlatch doesn't read: the shim is all there is to see
    const none = go();
    assert.equal(none.code, 2, `${kind}: ${none.out}`);
    const row = JSON.parse(none.out).results.find((r) => r.file === shim);
    assert.equal(row?.status, 'UNKNOWN', kind); assert.match(row.reason, /not found.*could not be tested/, kind);
    // its folder of runtimes there, but closed
    mkdirSync(join(home, folder), { recursive: true });
    node26(join(home, folder, '26.12.1', 'bin', 'node'));
    execFileSync('chmod', ['000', join(home, folder)]);
    try {
      const closed = go();
      assert.equal(closed.code, 2, `${kind}: ${closed.out}`);
      assert.equal(JSON.parse(closed.out).results.find((r) => r.file === shim)?.status, 'UNKNOWN', `${kind}: closed`);
    } finally { execFileSync('chmod', ['755', join(home, folder)]); }
    // the clean twin: the folder there and read, its node fixed: REVIEW and SAFE, exit 0
    const good = go();
    assert.equal(good.code, 0, `${kind}: ${good.out}`);
    const rows = JSON.parse(good.out).results;
    assert.equal(rows.find((r) => r.file === shim)?.status, 'REVIEW', kind);
    assert.equal(rows.find((r) => r.file?.endsWith('/26.12.1/bin/node'))?.status, 'SAFE', kind);
  }
});

test('every layout of volta, mise, rtx and proto is read: older ones (nodejs, volta\'s node/npm), and folders moved by their variables or found by the shim', () => {
  const cases = [
    // [what, kind, where the shim is (under home, or absolute), env (values under home), the node (under home)]
    ['rtx before its nodejs-to-node rename', 'rtx', 'bin', {}, '.local/share/rtx/installs/nodejs/20.11.0/bin/node'],
    ['mise with an asdf-era nodejs folder', 'mise', 'bin', {}, '.local/share/mise/installs/nodejs/20.11.0/bin/node'],
    ['volta\'s layouts v0 and v1 (node/<node>/<npm>)', 'volta-shim', 'bin', {}, '.volta/tools/image/node/20.11.0/10.2.4/bin/node'],
    ['VOLTA_HOME', 'volta-shim', 'bin', { VOLTA_HOME: 'vh' }, 'vh/tools/image/node/20.11.0/bin/node'],
    ['VOLTA_HOME with volta\'s older layout', 'volta-shim', 'bin', { VOLTA_HOME: 'vh' }, 'vh/tools/image/node/20.11.0/10.2.4/bin/node'],
    ['MISE_DATA_DIR', 'mise', 'bin', { MISE_DATA_DIR: 'md' }, 'md/installs/node/20.11.0/bin/node'],
    ['MISE_INSTALLS_DIR', 'mise', 'bin', { MISE_INSTALLS_DIR: 'mi' }, 'mi/node/20.11.0/bin/node'],
    ['MISE_SHARED_INSTALL_DIRS, a list', 'mise', 'bin', { MISE_SHARED_INSTALL_DIRS: 'none:ms' }, 'ms/node/20.11.0/bin/node'],
    ['XDG_DATA_HOME for mise', 'mise', 'bin', { XDG_DATA_HOME: 'xdg' }, 'xdg/mise/installs/node/20.11.0/bin/node'],
    ['RTX_DATA_DIR', 'rtx', 'bin', { RTX_DATA_DIR: 'rd' }, 'rd/installs/node/20.11.0/bin/node'],
    ['XDG_DATA_HOME for rtx', 'rtx', 'bin', { XDG_DATA_HOME: 'xdg' }, 'xdg/rtx/installs/node/20.11.0/bin/node'],
    ['PROTO_HOME', 'proto-shim', 'bin', { PROTO_HOME: 'ph' }, 'ph/tools/node/20.11.0/bin/node'],
    ['XDG_DATA_HOME for proto', 'proto-shim', 'bin', { XDG_DATA_HOME: 'xdg' }, 'xdg/proto/tools/node/20.11.0/bin/node'],
    // no variable at all: the shim's own folder says where its manager's home is
    ['mise\'s shims folder elsewhere', 'mise', 'elsewhere/mise/shims', {}, 'elsewhere/mise/installs/node/20.11.0/bin/node'],
    ['rtx\'s shims folder elsewhere', 'rtx', 'elsewhere/rtx/shims', {}, 'elsewhere/rtx/installs/nodejs/20.11.0/bin/node'],
    ['volta\'s bin folder elsewhere', 'volta-shim', 'elsewhere/volta/bin', {}, 'elsewhere/volta/tools/image/node/20.11.0/bin/node'],
    ['proto\'s shims folder elsewhere', 'proto-shim', 'elsewhere/proto/shims', {}, 'elsewhere/proto/tools/node/20.11.0/bin/node'],
  ];
  for (const [what, kind, at, vars, rel] of cases) {
    const home = fresh(`layout-${what.replace(/[^a-z0-9]/gi, '_')}`);
    const path = join(home, at), shim = shimOnPath(path, kind), node = node20(join(home, rel));
    const env = { HOME: home, PATH: path, ...Object.fromEntries(Object.entries(vars).map(([k, v]) => [k, v.split(':').map((x) => join(home, x)).join(':')])) };
    const go = () => cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh(`layout-empty-${Math.random()}`)], env);
    const bad = go();
    assert.equal(bad.code, 1, `${what}: ${bad.out}`);
    const rows = JSON.parse(bad.out).results;
    assert.equal(rows.find((r) => r.file === node)?.status, 'EXPOSED', `${what}: the node it starts is read`);
    assert.equal(rows.find((r) => r.file === shim)?.status, 'REVIEW', what);
    // the clean twin: that node fixed, exit 0
    node26(node);
    const good = go();
    assert.equal(good.code, 0, `${what}: ${good.out}`);
    assert.equal(JSON.parse(good.out).results.find((r) => r.file === node)?.status, 'SAFE', what);
  }
  // a variable that names its folder by a relative path: where the manager looks depends on the folder it is started
  // in, so its shim is UNKNOWN, even beside a folder of runtimes that is read; the clean twin is the variable not set
  const home = fresh('layout-relative'), path = join(home, 'mise', 'shims'), shim = shimOnPath(path, 'mise');
  node26(join(home, 'mise', 'installs', 'node', '26.12.1', 'bin', 'node'));
  const rel = cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh('layout-relative-empty')], { HOME: home, PATH: path, MISE_DATA_DIR: 'md' });
  assert.equal(rel.code, 2, rel.out);
  const r = JSON.parse(rel.out).results.find((x) => x.file === shim);
  assert.equal(r?.status, 'UNKNOWN'); assert.match(r.reason, /MISE_DATA_DIR.*could not be tested/);
  assert.equal(cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh('layout-relative-empty2')], { HOME: home, PATH: path }).code, 0);
  // nothing anywhere: one SAFE row, whose receipt names each place once (a manager's usual folder is not named again)
  const none = cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh('layout-none-empty')], { HOME: fresh('layout-none-home'), PATH: fresh('layout-none-path') });
  const searched = JSON.parse(none.out).results[0].searched;
  assert.equal(none.code, 0, none.out);
  const places = searched.filter((x) => x.startsWith('node in ')).map((x) => x.replace(/^node in ~\//, `node in ${realpathSync(join(dir, 'layout-none-home'))}/`).replace(join(dir, 'layout-none-home'), realpathSync(join(dir, 'layout-none-home'))));
  assert.equal(new Set(places).size, places.length, places.join('\n'));
});

test('shimPlaces: a manager\'s folders from its variables, its usual folders and the folder its shim is in; a relative variable is unsure', () => {
  const mise = shimsUnder('/R').mise;
  const r = shimPlaces(mise, { MISE_DATA_DIR: '/d', XDG_DATA_HOME: '/x', MISE_INSTALLS_DIR: '/i', MISE_SHARED_INSTALL_DIRS: '/s1::/s2' }, '/e/shims/node');
  assert.deepEqual(r.folders, ['/e/installs/node', '/e/installs/nodejs', '/d/installs/node', '/d/installs/nodejs', '/x/mise/installs/node', '/x/mise/installs/nodejs',
    '/R/.local/share/mise/installs/node', '/R/.local/share/mise/installs/nodejs', '/R/usr/local/share/mise/installs/node', '/R/usr/local/share/mise/installs/nodejs',
    '/i/node', '/i/nodejs', '/s1/node', '/s1/nodejs', '/s2/node', '/s2/nodejs']);
  assert.ok(r.patterns.includes('/e/installs/node/*/bin/node') && r.patterns.includes('/s2/nodejs/*/bin/node')); assert.deepEqual(r.unsure, []);
  // a shim in a folder of another name says nothing about its home; a variable that isn't set is no place
  assert.deepEqual(shimPlaces(mise, {}, '/e/bin/node').folders, ['/R/.local/share/mise/installs/node', '/R/.local/share/mise/installs/nodejs', '/R/usr/local/share/mise/installs/node', '/R/usr/local/share/mise/installs/nodejs']);
  // a relative value (or one with a relative part) is unsure, and names no folder
  const rel = shimPlaces(mise, { MISE_DATA_DIR: 'md', MISE_SHARED_INSTALL_DIRS: '/s1:s2' });
  assert.deepEqual(rel.unsure, ['MISE_DATA_DIR', 'MISE_SHARED_INSTALL_DIRS']); assert.ok(!rel.folders.some((f) => f.includes('md') || f.includes('s2')));
  // only the list variable is split on ':'; a single-path one is that path, ':' and all (mise reads MISE_DATA_DIR,
  // MISE_INSTALLS_DIR and XDG_DATA_HOME as one path each)
  const colon = shimPlaces(mise, { MISE_DATA_DIR: '/d:x', XDG_DATA_HOME: '/x:y', MISE_INSTALLS_DIR: '/i:/j', MISE_SYSTEM_DATA_DIR: '/s:t' });
  assert.deepEqual(colon.unsure, []);
  for (const f of ['/d:x/installs/node', '/x:y/mise/installs/node', '/i:/j/node', '/s:t/installs/node']) assert.ok(colon.folders.includes(f), f);
  for (const f of ['/d/installs/node', '/i/node', '/j/node']) assert.ok(!colon.folders.includes(f), f);
  assert.deepEqual(shimPlaces(mise, { MISE_DATA_DIR: 'd:/x' }).unsure, ['MISE_DATA_DIR'], 'one relative path, not a relative part and an absolute one');
  assert.deepEqual(shimPlaces(shimsUnder('/R')['proto-shim'], { PROTO_HOME: '/p:q' }).folders.slice(0, 1), ['/p:q/tools/node']);
  // volta's two layouts share one folder of runtimes
  assert.deepEqual(shimPlaces(shimsUnder('/R')['volta-shim'], {}, '/v/bin/node').folders, ['/v/tools/image/node', '/R/.volta/tools/image/node']);
});

test('a mise variable that holds one path is read as that path, a \':\' in it included: the node there is read, never a REVIEW over other folders', () => {
  const home = fresh('mise-colon'), path = join(home, 'bin'), shim = shimOnPath(path, 'mise');
  // MISE_DATA_DIR names one folder whose path holds a ':'; split on ':', it read as <home>/a and <home>/b, and the fixed
  // node in <home>/a made the shim a REVIEW line while the nodes mise starts went unread
  const dataDir = `${join(home, 'a')}:${join(home, 'b')}`;
  node26(join(home, 'a', 'installs', 'node', '26.12.1', 'bin', 'node'));
  const node = node20(join(dataDir, 'installs', 'node', '20.11.0', 'bin', 'node'));
  const go = () => cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh(`mise-colon-empty-${Math.random()}`)], { HOME: home, PATH: path, MISE_DATA_DIR: dataDir });
  const bad = go();
  assert.equal(bad.code, 1, bad.out);
  const rows = JSON.parse(bad.out).results;
  assert.equal(rows.find((r) => r.file === node)?.status, 'EXPOSED', 'the node in the folder MISE_DATA_DIR names is read');
  assert.equal(rows.find((r) => r.file === shim)?.status, 'REVIEW');
  // the clean twin: that node fixed, exit 0
  node26(node);
  const good = go();
  assert.equal(good.code, 0, good.out);
  assert.equal(JSON.parse(good.out).results.find((r) => r.file === node)?.status, 'SAFE');
});

test('the incident\'s version managers: each usual place is in nodeDirs, and the tests clear every variable they read', () => {
  const vars = new Set();
  for (const [kind, l] of Object.entries(INC.shims)) {
    assert.ok(['bin', 'shims'].includes(l.folder), kind);
    for (const [roots, nodes] of [[l.homes, l.nodes], [l.installs ?? [], l.installsNodes ?? []]]) {
      for (const h of roots) {
        assert.match(h, /^(\$[A-Z_]+(\/[a-z.]+)?|~\/[a-z./]+|\/[a-z./]+)$/, `${kind}: ${h}`);
        if (h.startsWith('$')) vars.add(h.slice(1).split('/')[0]);
        else for (const n of nodes) assert.ok(INC.nodeDirs.includes(`${h}/${n}`), `${kind}: ${h}/${n} is in nodeDirs`);
      }
    }
  }
  assert.deepEqual([...vars].sort(), [...VM_VARS].sort());
});

test('a version manager\'s shim: a folder of runtimes that can\'t be read beside one that is read is still UNKNOWN; a program named like Object\'s own keys is no shim', { skip: process.getuid?.() === 0 && 'root reads everything' }, () => {
  const vm = fresh('shim-closed'), path = fresh('shim-closed-path');
  shimOnPath(path, 'mise');
  node26(join(vm, '.local', 'share', 'mise', 'installs', 'node', '26.12.1', 'bin', 'node'));
  const closed = join(vm, '.local', 'share', 'mise', 'installs', 'nodejs');
  node20(join(closed, '20.11.0', 'bin', 'node'));
  const shimRowOf = () => run({ shims: shimsUnder(vm) }, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node'));
  execFileSync('chmod', ['000', closed]);
  try {
    const r = shimRowOf();
    assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /nodejs could not be read.*could not be tested/);
  } finally { execFileSync('chmod', ['755', closed]); }
  assert.equal(shimRowOf().status, 'REVIEW', 'the clean twin: both read');
  // a compiled node that links to a program named constructor or __proto__ is not a shim: UNKNOWN, never REVIEW
  for (const k of ['constructor', '__proto__', 'toString']) {
    const p = fresh(`shim-proto-${k}`);
    shimOnPath(p, k);
    assert.equal(run({ shims: shimsUnder(vm) }, { pathEnv: p }).rows.find((r) => r.file === join(p, 'node'))?.status, 'UNKNOWN', k);
  }
});


/** What the command says, by file, and its exit code. */
const cliRows = (env) => {
  const r = cli(['--incident', 'brotli-2026-10', '--json', '--paths', fresh(`cli-rows-empty-${Math.random()}`)], env);
  const rows = JSON.parse(r.out).results;
  return { code: r.code, out: r.out, at: (f) => rows.find((x) => x.file === f) };
};
/** proto-shim as proto writes it into its shims folder (crates/shim/src/unix.rs: its bytes, renamed node): a compiled
 *  program with Rust's strings packed together, no NUL between them, PROTO_SHIM_NAME among them (which proto's CLI
 *  holds too); `marker`: with the message only proto-shim holds (crates/cli/src/main_shim.rs, proto-shim's own source). */
const protoShim = (f, marker = true) => bin(f, [Buffer.from(`\0${marker ? 'proto-shim: Invalid shim name detected. Unable to execute the appropriate proto tool.\nPlease refer to the documentation or ask for support on Discord.' : ''}PROTO_SHIM_NAMEPROTO_SHIM_PATHregistry.json\0`)]);

test('proto\'s shims are copies of proto-shim named node: one in proto\'s shims folder, or one carrying proto-shim\'s marker, is a REVIEW line only when proto\'s nodes are read', () => {
  // by its place: proto's home's shims folder, under ~/.proto, $PROTO_HOME or $XDG_DATA_HOME/proto (no marker needed)
  for (const [what, vars, shims, nodes] of [['~/.proto', {}, '.proto/shims', '.proto/tools/node'], ['PROTO_HOME', { PROTO_HOME: 'ph' }, 'ph/shims', 'ph/tools/node'],
    ['XDG_DATA_HOME', { XDG_DATA_HOME: 'xdg' }, 'xdg/proto/shims', 'xdg/proto/tools/node']]) {
    const home = fresh(`proto-copy-${what.replace(/[^a-z]/gi, '')}`), path = join(home, shims), shim = protoShim(join(path, 'node'), false);
    const env = { HOME: home, PATH: path, ...Object.fromEntries(Object.entries(vars).map(([k, v]) => [k, join(home, v)])) };
    // its folder of runtimes not there: UNKNOWN, exit 2
    const none = cliRows(env);
    assert.equal(none.code, 2, `${what}: ${none.out}`);
    assert.equal(none.at(shim)?.status, 'UNKNOWN', what); assert.match(none.at(shim).reason, /^proto-shim, a version manager's shim.*not found.*could not be tested/, what);
    // its nodes read: an unfixed one EXPOSED (exit 1) and the shim a REVIEW line; the clean twin, exit 0
    const node = node20(join(home, nodes, '20.11.0', 'bin', 'node'));
    const bad = cliRows(env);
    assert.equal(bad.code, 1, `${what}: ${bad.out}`); assert.equal(bad.at(node)?.status, 'EXPOSED', what); assert.equal(bad.at(shim)?.status, 'REVIEW', what);
    node26(node);
    const good = cliRows(env);
    assert.equal(good.code, 0, `${what}: ${good.out}`); assert.equal(good.at(shim)?.status, 'REVIEW', what);
  }
  // by its bytes: a copy in a folder of its own on PATH that carries proto-shim's marker; its nodes are read in proto's home
  const home = fresh('proto-marker'), path = join(home, 'bin'), shim = protoShim(join(path, 'node'));
  const node = node20(join(home, '.proto', 'tools', 'node', '20.11.0', 'bin', 'node'));
  const bad = cliRows({ HOME: home, PATH: path });
  assert.equal(bad.code, 1, bad.out); assert.equal(bad.at(shim)?.status, 'REVIEW'); assert.equal(bad.at(node)?.status, 'EXPOSED');
  node26(node);
  assert.equal(cliRows({ HOME: home, PATH: path }).code, 0);
  // the near misses, UNKNOWN (exit 2) though proto's fixed nodes are read: the same copy without the marker outside
  // proto's shims folder, and in a folder named shims that isn't proto's
  for (const at of ['bin', 'other/shims']) {
    const h = fresh(`proto-near-${at.replace('/', '-')}`), p = join(h, at), s = protoShim(join(p, 'node'), false);
    node26(join(h, '.proto', 'tools', 'node', '26.12.1', 'bin', 'node'));
    const r = cliRows({ HOME: h, PATH: p });
    assert.equal(r.code, 2, `${at}: ${r.out}`); assert.equal(r.at(s)?.status, 'UNKNOWN', at); assert.match(r.at(s).reason, /could not be tested.*Check this one by hand/, at);
  }
  // a program holding only PROTO_SHIM_NAME (proto's CLI reads it back, crates/cli/src/main.rs, so it holds the name too)
  // is no proto shim: UNKNOWN, exit 2 (it was proto's REVIEW, exit 0, while PROTO_SHIM_NAME was the marker); the clean
  // twin, the same place holding proto-shim's own message, REVIEW, exit 0
  const h = fresh('proto-name-only'), p = join(h, 'bin'), s = bin(join(p, 'node'), ['PROTO_SHIM_NAME']);
  node26(join(h, '.proto', 'tools', 'node', '26.12.1', 'bin', 'node'));
  const nameOnly = cliRows({ HOME: h, PATH: p });
  assert.equal(nameOnly.code, 2, nameOnly.out); assert.equal(nameOnly.at(s)?.status, 'UNKNOWN');
  bin(s, ['Invalid shim name detected. Unable to execute the appropriate proto tool.']);
  const twin = cliRows({ HOME: h, PATH: p });
  assert.equal(twin.code, 0, twin.out); assert.equal(twin.at(s)?.status, 'REVIEW');
});

test('a script named node on PATH: asdf\'s or nodenv\'s shim is a REVIEW line only when its nodes are read (ASDF_DATA_DIR and NODENV_ROOT too); any other script is UNKNOWN', () => {
  // the shims as asdf (internal/shims/shims.go) and nodenv (libexec/nodenv-rehash) write them, in their shims folders
  const script = (f, text) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text, { mode: 0o755 }); return f; };
  const asdf = (f) => script(f, '#!/usr/bin/env bash\n# asdf-plugin: nodejs 20.11.0\nexec asdf exec "node" "$@"');
  const nodenv = (f) => script(f, '#!/usr/bin/env bash\nset -e\n[ -n "$NODENV_DEBUG" ] && set -x\n\nprogram="${0##*/}"\n\nexport NODENV_ROOT="/x"\nexec "/x/libexec/nodenv" exec "$program" "$@"\n');
  for (const [what, make, vars, shims, nodes] of [['asdf, ~/.asdf', asdf, {}, '.asdf/shims', '.asdf/installs/nodejs'], ['asdf, ASDF_DATA_DIR', asdf, { ASDF_DATA_DIR: 'ad' }, 'ad/shims', 'ad/installs/nodejs'],
    ['nodenv, ~/.nodenv', nodenv, {}, '.nodenv/shims', '.nodenv/versions'], ['nodenv, NODENV_ROOT', nodenv, { NODENV_ROOT: 'nr' }, 'nr/shims', 'nr/versions']]) {
    const home = fresh(`script-${what.replace(/[^a-z]/gi, '')}`), path = join(home, shims), shim = make(join(path, 'node'));
    const env = { HOME: home, PATH: path, ...Object.fromEntries(Object.entries(vars).map(([k, v]) => [k, join(home, v)])) };
    // its folder of runtimes not there: UNKNOWN, exit 2 (it was a REVIEW line, exit 0, wherever its nodes were)
    const none = cliRows(env);
    assert.equal(none.code, 2, `${what}: ${none.out}`);
    assert.equal(none.at(shim)?.status, 'UNKNOWN', what); assert.match(none.at(shim).reason, /a version manager's shim.*not found.*could not be tested/, what);
    // its nodes read: an unfixed one EXPOSED, the shim REVIEW, exit 1; the clean twin, exit 0
    const node = node20(join(home, nodes, '20.11.0', 'bin', 'node'));
    const bad = cliRows(env);
    assert.equal(bad.code, 1, `${what}: ${bad.out}`); assert.equal(bad.at(node)?.status, 'EXPOSED', what); assert.equal(bad.at(shim)?.status, 'REVIEW', what);
    assert.match(bad.at(shim).reason, new RegExp(`^${what.split(',')[0]}, a version manager's shim`));
    node26(node);
    assert.equal(cliRows(env).code, 0, what);
  }
  // ASDF_DATA_DIR's and NODENV_ROOT's nodes are read with no shim on PATH too
  for (const [k, nodes] of [['ASDF_DATA_DIR', 'installs/nodejs'], ['NODENV_ROOT', 'versions']]) {
    const home = fresh(`script-var-${k}`), node = node20(join(home, 'moved', nodes, '20.11.0', 'bin', 'node'));
    const env = { HOME: home, PATH: fresh(`script-var-path-${k}`), [k]: join(home, 'moved') };
    const bad = cliRows(env);
    assert.equal(bad.code, 1, `${k}: ${bad.out}`); assert.equal(bad.at(node)?.status, 'EXPOSED', k);
    node26(node);
    assert.equal(cliRows(env).code, 0, k);
  }
  // any other script named node or bun (npm's node wrapper, one's own), and asdf's shim text outside asdf's shims folder:
  // UNKNOWN, exit 2, even with asdf's fixed nodes read
  const home = fresh('script-other'), path = join(home, '.npm-global', 'bin');
  node26(join(home, '.asdf', 'installs', 'nodejs', '26.12.1', 'bin', 'node'));
  const wrapper = script(join(path, 'node'), '#!/bin/sh\nexec "$(dirname "$0")/../lib/node_modules/node/bin/node" "$@"\n'), bun = script(join(path, 'bun'), '#!/bin/sh\nexec bun-real "$@"\n');
  const elsewhere = fresh('script-elsewhere'), copied = asdf(join(elsewhere, 'shims', 'node'));
  for (const [f, p] of [[wrapper, path], [bun, path], [copied, dirname(copied)]]) {
    const r = cliRows({ HOME: home, PATH: p });
    assert.equal(r.code, 2, `${f}: ${r.out}`);
    assert.equal(r.at(f)?.status, 'UNKNOWN', f); assert.match(r.at(f).reason, /^a script named (node|bun) on PATH, not a program, and not a version manager's shim Wardlatch knows.*could not be tested/, f);
  }
  // a compiled node in asdf's shims folder is no asdf shim (asdf's are scripts): judged as any node, UNKNOWN
  const compiled = bin(join(home, '.asdf', 'shims', 'node'), ['nothing']);
  const c = cliRows({ HOME: home, PATH: dirname(compiled) });
  assert.equal(c.code, 2, c.out); assert.equal(c.at(compiled)?.status, 'UNKNOWN'); assert.match(c.at(compiled).reason, /Check this one by hand/);
});

test('a script named node in proto\'s shims folder is no proto shim (proto\'s are copies of a compiled program): UNKNOWN, never REVIEW', () => {
  // the attack: a script there starts a runtime Wardlatch never reads; read as proto's shim, it was a REVIEW line and the
  // run ended in exit 0 beside proto's fixed nodes (mutant m19: a script matched every manager's shims folder)
  const home = fresh('proto-script'), path = join(home, '.proto', 'shims');
  node26(join(home, '.proto', 'tools', 'node', '26.12.1', 'bin', 'node'));
  mkdirSync(path, { recursive: true });
  const shim = join(path, 'node');
  writeFileSync(shim, '#!/bin/sh\nexec "$HOME/elsewhere/bin/node" "$@"\n', { mode: 0o755 });
  const bad = cliRows({ HOME: home, PATH: path });
  assert.equal(bad.code, 2, bad.out);
  assert.equal(bad.at(shim)?.status, 'UNKNOWN'); assert.match(bad.at(shim).reason, /^a script named node on PATH, not a program, and not a version manager's shim Wardlatch knows.*could not be tested/);
  // the clean twin: proto-shim's copy in the same place is proto's shim, a REVIEW line with proto's nodes read, exit 0
  protoShim(shim);
  const good = cliRows({ HOME: home, PATH: path });
  assert.equal(good.code, 0, good.out); assert.equal(good.at(shim)?.status, 'REVIEW');
});

test('asdf: a plugin named node (installs/node) is read like nodejs, and a shim counts only the folder of the plugins it names', () => {
  // asdf's shim names its plugins, one "# asdf-plugin: <plugin> <version>" line each (internal/shims/shims.go, encode)
  const asdfShim = (f, ...plugins) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, `#!/usr/bin/env bash\n${plugins.map((p) => `# asdf-plugin: ${p} 20.11.0\n`).join('')}exec asdf exec "node" "$@"`, { mode: 0o755 }); return f; };
  // a plugin named node: its nodes in ~/.asdf/installs/node are read (they were not, and its shim was UNKNOWN, exit 2)
  const home = fresh('asdf-node'), path = join(home, '.asdf', 'shims'), shim = asdfShim(join(path, 'node'), 'node');
  const node = node20(join(home, '.asdf', 'installs', 'node', '20.11.0', 'bin', 'node'));
  const bad = cliRows({ HOME: home, PATH: path });
  assert.equal(bad.code, 1, bad.out); assert.equal(bad.at(node)?.status, 'EXPOSED'); assert.equal(bad.at(shim)?.status, 'REVIEW');
  assert.match(bad.at(shim).reason, /read in .*\.asdf\/installs\/node$/);
  node26(node);
  const good = cliRows({ HOME: home, PATH: path });
  assert.equal(good.code, 0, good.out); assert.equal(good.at(node)?.status, 'SAFE');
  // with no shim on PATH too, and under ASDF_DATA_DIR
  const moved = fresh('asdf-node-moved'), other = node20(join(moved, 'ad', 'installs', 'node', '20.11.0', 'bin', 'node'));
  const r = cliRows({ HOME: moved, PATH: fresh('asdf-node-moved-path'), ASDF_DATA_DIR: join(moved, 'ad') });
  assert.equal(r.code, 1, r.out); assert.equal(r.at(other)?.status, 'EXPOSED');
  // the shim of the nodejs plugin, with only the node plugin's folder there (its nodes fixed): the nodes it starts are
  // in installs/nodejs, which is not there, so UNKNOWN, exit 2, never a REVIEW over another plugin's folder
  asdfShim(shim, 'nodejs');
  const wrong = cliRows({ HOME: home, PATH: path });
  assert.equal(wrong.code, 2, wrong.out); assert.equal(wrong.at(shim)?.status, 'UNKNOWN'); assert.match(wrong.at(shim).reason, /installs\/nodejs\).*could not be tested/);
  // a plugin Wardlatch reads no folder for, and a shim that names none: UNKNOWN, with both folders there and fixed
  node26(join(home, '.asdf', 'installs', 'nodejs', '26.12.1', 'bin', 'node'));
  for (const [plugins, says] of [[['nodejs-lts'], /belongs to the plugin nodejs-lts, and Wardlatch reads no folder of runtimes for that/],
    [['nodejs-lts', 'iojs'], /belongs to the plugins nodejs-lts, iojs, and Wardlatch reads no folder/], [[], /belongs to no plugin it names/]]) {
    asdfShim(shim, ...plugins);
    const u = cliRows({ HOME: home, PATH: path });
    assert.equal(u.code, 2, u.out); assert.equal(u.at(shim)?.status, 'UNKNOWN', plugins.join()); assert.match(u.at(shim).reason, says);
  }
  // the clean twins: the nodejs plugin's shim with its folder there, and a shim of both plugins, REVIEW, exit 0
  for (const plugins of [['nodejs'], ['node', 'nodejs']]) {
    asdfShim(shim, ...plugins);
    const t = cliRows({ HOME: home, PATH: path });
    assert.equal(t.code, 0, t.out); assert.equal(t.at(shim)?.status, 'REVIEW', plugins.join());
  }
});

test('ASDF_DATA_DIR with a leading ~/ (or a bare ~) is the home folder, as asdf reads it; any other path not starting at / stays unsure', () => {
  // asdf (internal/config/config.go, normalizePath, since 0.17.0) joins the home folder to "~" and "~/..."; a literal
  // "~/ad" was a relative path here, so its nodes went unread and its shim was UNKNOWN (exit 2)
  const asdfShim = (f) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, '#!/usr/bin/env bash\n# asdf-plugin: nodejs 20.11.0\nexec asdf exec "node" "$@"', { mode: 0o755 }); return f; };
  for (const [value, under] of [['~/ad', 'ad'], ['~', '']]) {
    const home = fresh(`asdf-tilde-${under || 'home'}`), data = join(home, under);
    const node = node20(join(data, 'installs', 'nodejs', '20.11.0', 'bin', 'node'));
    // no shim on PATH: the node there is read
    const alone = cliRows({ HOME: home, PATH: fresh(`asdf-tilde-path-${under || 'home'}`), ASDF_DATA_DIR: value });
    assert.equal(alone.code, 1, `${value}: ${alone.out}`); assert.equal(alone.at(node)?.status, 'EXPOSED', value);
    // its shim on PATH: REVIEW, with that node EXPOSED; the clean twin, that node fixed, exit 0
    const path = join(data, 'shims'), shim = asdfShim(join(path, 'node'));
    const bad = cliRows({ HOME: home, PATH: path, ASDF_DATA_DIR: value });
    assert.equal(bad.code, 1, `${value}: ${bad.out}`); assert.equal(bad.at(shim)?.status, 'REVIEW', value); assert.equal(bad.at(node)?.status, 'EXPOSED', value);
    node26(node);
    assert.equal(cliRows({ HOME: home, PATH: path, ASDF_DATA_DIR: value }).code, 0, value);
  }
  // the near misses: "~other/ad" (asdf joins only "~" and "~/...") and "ad" are relative: the shim is UNKNOWN, exit 2
  const home = fresh('asdf-tilde-near'), path = join(home, '.asdf', 'shims'), shim = asdfShim(join(path, 'node'));
  node26(join(home, '.asdf', 'installs', 'nodejs', '26.12.1', 'bin', 'node'));
  for (const value of ['~other/ad', 'ad']) {
    const r = cliRows({ HOME: home, PATH: path, ASDF_DATA_DIR: value });
    assert.equal(r.code, 2, `${value}: ${r.out}`); assert.equal(r.at(shim)?.status, 'UNKNOWN', value); assert.match(r.at(shim).reason, /ASDF_DATA_DIR names its folders by a path that doesn't start at '\/'/, value);
  }
  // and the expansion is asdf's only: another manager's variable is read as it was
  assert.deepEqual(shimPlaces(INC.shims.mise, { MISE_DATA_DIR: '~/md' }).unsure, ['MISE_DATA_DIR']);
  assert.deepEqual(shimPlaces(INC.shims.asdf, { ASDF_DATA_DIR: '~/ad' }).unsure, []);
});

test('asdf\'s plugin lines as asdf reads them: a line of fewer than four parts names no plugin (D-3-segments), and a shim over 64 KB is not read', () => {
  // asdf's parse (internal/shims/shims.go) splits each "# asdf-plugin:" line on spaces and skips one of fewer than four
  // parts; a shim naming no plugin it reads is UNKNOWN, exit 2, never a REVIEW over the nodejs plugin's folder
  const home = fresh('asdf-parts'), path = join(home, '.asdf', 'shims'), shim = join(path, 'node');
  node26(join(home, '.asdf', 'installs', 'nodejs', '26.12.1', 'bin', 'node'));
  const write = (text) => { mkdirSync(path, { recursive: true }); writeFileSync(shim, text, { mode: 0o755 }); };
  for (const line of ['# asdf-plugin: nodejs', '# asdf-plugin: nodejs\t26.12.1', '# asdf-plugin:']) {
    write(`#!/usr/bin/env bash\n${line}\nexec asdf exec "node" "$@"`);
    const r = cliRows({ HOME: home, PATH: path });
    assert.equal(r.code, 2, `${JSON.stringify(line)}: ${r.out}`); assert.equal(r.at(shim)?.status, 'UNKNOWN', JSON.stringify(line)); assert.match(r.at(shim).reason, /belongs to no plugin it names/, JSON.stringify(line));
  }
  // the clean twin: the line asdf writes, "# asdf-plugin: <plugin> <version>"
  write('#!/usr/bin/env bash\n# asdf-plugin: nodejs 26.12.1\nexec asdf exec "node" "$@"');
  const good = cliRows({ HOME: home, PATH: path });
  assert.equal(good.code, 0, good.out); assert.equal(good.at(shim)?.status, 'REVIEW');
  // a shim of 64 KB is read; one byte more, and it is not read at all, so it names no plugin
  const padded = (n) => { const head = '#!/usr/bin/env bash\n# asdf-plugin: nodejs 26.12.1\nexec asdf exec "node" "$@"\n#'; return head + 'x'.repeat(n - head.length); };
  write(padded(64 * 1024));
  assert.equal(cliRows({ HOME: home, PATH: path }).at(shim)?.status, 'REVIEW', '64 KB');
  write(padded(64 * 1024 + 1));
  const big = cliRows({ HOME: home, PATH: path });
  assert.equal(big.code, 2, big.out); assert.equal(big.at(shim)?.status, 'UNKNOWN'); assert.match(big.at(shim).reason, /belongs to no plugin it names/);
});

// Round 8, rule 5: a path from PATH, a variable or a package's record is put together as written and handed to the OS,
// never cleaned up as text first (path.join, path.resolve and Node's realpathSync read x/sym/../bin as x/bin; the shell,
// the loader and pip take the '..' after the link, y/bin). Each place that decides which file is read, with its twin.
const linkedTree = (name) => {
  const d = fresh(name), x = join(d, 'x'), y = join(d, 'y');
  mkdirSync(join(y, 'deep'), { recursive: true }); mkdirSync(x, { recursive: true }); symlinkSync(join(y, 'deep'), join(x, 'sym'));
  return { d, x, y, via: `${x}/sym/..` };
};

test('PATH as the shell reads it: a folder x/sym/../bin is y/bin, each copy is read once by its real path, and a shim is known by its real file (round 8, rule 5)', () => {
  const { d, x, y, via } = linkedTree('asw-path'), viaBin = `${via}/bin`;
  // the shell runs y/bin/node, an unfixed one; x/bin/node is fixed. Up to round 8, path.join read x/bin/node: SAFE
  node20(join(y, 'bin', 'node')); node26(join(x, 'bin', 'node'));
  assert.deepEqual(run({}, { pathEnv: viaBin }).rows.map((r) => [r.file, r.status]), [[`${viaBin}/node`, 'EXPOSED']]);
  node26(join(y, 'bin', 'node'));
  assert.deepEqual(run({}, { pathEnv: viaBin }).rows.map((r) => [r.file, r.status]), [[`${viaBin}/node`, 'SAFE']], 'the clean twin');
  // x/bin on PATH too: two files, both read (by Node's realpathSync, x/sym/../bin/node was x/bin/node, so the real
  // x/bin/node was dropped as read already)
  node20(join(x, 'bin', 'node'));
  const both = `${viaBin}:${join(x, 'bin')}`;
  assert.deepEqual(run({}, { pathEnv: both }).rows.map((r) => [r.file, r.status]), [[`${viaBin}/node`, 'SAFE'], [join(x, 'bin', 'node'), 'EXPOSED']]);
  node26(join(x, 'bin', 'node'));
  assert.deepEqual(run({}, { pathEnv: both }).rows.map((r) => r.status), ['SAFE', 'SAFE'], 'the clean twin');
  // a version manager's shim is known by its real file as the OS resolves its path: y/bin/node is a compiled program
  // with no sign of Node.js, and x/bin/node a link to volta-shim. By Node's realpathSync, y/bin/node read as volta's
  // shim, a REVIEW line; it is UNKNOWN
  const vm = fresh('asw-path-vm');
  node26(join(vm, '.volta', 'tools', 'image', 'node', '26.12.1', 'bin', 'node'));
  bin(join(y, 'bin', 'node'), ['no sign of Node.js']);
  rmSync(join(x, 'bin', 'node')); symlinkSync(bin(join(d, 'volta', 'volta-shim'), ['shim']), join(x, 'bin', 'node'));
  const rowOf = (pathEnv) => run({ shims: shimsUnder(vm) }, { pathEnv }).rows.find((r) => r.file === `${pathEnv}/node`);
  const unk = rowOf(viaBin);
  assert.equal(unk.status, 'UNKNOWN', unk.reason); assert.match(unk.reason, /no Brotli decoder's error texts/);
  assert.equal(rowOf(join(x, 'bin')).status, 'REVIEW', 'the clean twin: the link to volta-shim is volta\'s shim');
  // a file's code-signing identifier is exempt only when it is the file's own name, as the OS resolves its path:
  // y/bin/prog is signed "libbrotlidec.1.dylib", a Brotli library's name it may load, and x/bin/prog is a link to a file
  // of that name. By Node's realpathSync the name was x's, and exempt: SAFE; it is UNKNOWN
  bin(join(y, 'bin', 'prog'), [CONTROL, MARKER], { signed: 'libbrotlidec.1.dylib' });
  symlinkSync(fixedLib(join(d, 'elsewhere', 'libbrotlidec.1.dylib')), join(x, 'bin', 'prog'));
  const signed = judge(`${viaBin}/prog`);
  assert.equal(signed.status, 'UNKNOWN', signed.reason); assert.match(signed.reason, /it names libbrotlidec\.1\.dylib/);
  bin(join(y, 'bin', 'prog'), [CONTROL, MARKER], { signed: 'prog' });
  assert.equal(judge(`${viaBin}/prog`).status, 'SAFE', 'the clean twin: signed with its own name');
});

test('a variable, the home folder, a package\'s record and the loader\'s configuration with a \'..\': read as the program that reads them does (round 8, rule 5)', () => {
  const { x, y, via } = linkedTree('asw-vars');
  // a manager's variable: VOLTA_HOME x/sym/.. is y to volta (Rust, as written); asdf's Go would clean it up as text,
  // so both are read. Up to round 8 only x's was
  const vm = shimsUnder(fresh('asw-vars-vm'));
  const voltaNode = node20(join(y, 'tools', 'image', 'node', '20.11.0', 'bin', 'node'));
  const places = shimPlaces(INC.shims['volta-shim'], { VOLTA_HOME: via });
  assert.ok(places.patterns.includes(`${via}/tools/image/node/*/bin/node`), places.patterns.join());
  assert.ok(places.patterns.includes(join(x, 'tools', 'image', 'node', '*', 'bin', 'node')), 'and cleaned up as text');
  const vrow = () => run({ shims: { 'volta-shim': vm['volta-shim'] } }, { env: { VOLTA_HOME: via } }).rows.find((r) => r.file.endsWith('/20.11.0/bin/node'));
  assert.equal(vrow()?.status, 'EXPOSED');
  node26(voltaNode);
  assert.equal(vrow()?.status, 'SAFE', 'the clean twin');
  // proto's shims are copies of proto-shim, known by their place: PROTO_HOME x/sym/.. puts its shims folder at y/shims
  // as the OS resolves it, so a copy there (without proto-shim's message) is proto's shim, a REVIEW line once proto's
  // nodes are read. By Node's realpathSync that folder was x/shims, and the copy was UNKNOWN
  const pv = shimsUnder(fresh('asw-vars-proto'));
  node26(join(y, 'tools', 'node', '26.12.1', 'bin', 'node'));
  const pshim = protoShim(join(y, 'shims', 'node'), false);
  const prow = (home) => run({ shims: { 'proto-shim': pv['proto-shim'] } }, { pathEnv: join(y, 'shims'), env: { PROTO_HOME: home } }).rows.find((r) => r.file === pshim);
  assert.equal(prow(via)?.status, 'REVIEW', prow(via)?.reason);
  assert.equal(prow(join(x, 'elsewhere'))?.status, 'UNKNOWN', 'the clean twin: proto\'s folder is elsewhere, so the copy is no shim of its');
  // the home folder: HOME x/sym/.. is y to the shell's ~ and to conda; a library place under ~ is read there (each
  // once by its real path as the OS resolves it). x/miniconda3 holds a fixed copy, y/miniconda3 an unfixed one
  oldLib(join(y, 'miniconda3', 'lib', 'libbrotlidec.1.dylib')); fixedLib(join(x, 'miniconda3', 'lib', 'libbrotlidec.1.dylib'));
  const place = INC.libPlaces.find((p) => p.pattern === '~/miniconda3/lib/libbrotlidec.*');
  const saved = process.env.HOME;
  process.env.HOME = via;
  try {
    const lrows = () => run({ libPlaces: [place] }).rows;
    const bad = lrows();
    assert.deepEqual(bad.map((r) => [r.file, r.status]), [[join(y, 'miniconda3', 'lib', 'libbrotlidec.1.dylib'), 'EXPOSED']]);
    // told its place's own fix (conda's), as by a plain home folder: the place is known by the same real path
    process.env.HOME = y;
    assert.equal(bad[0].fix, lrows()[0].fix); assert.match(bad[0].fix, /conda/);
    process.env.HOME = via;
    fixedLib(join(y, 'miniconda3', 'lib', 'libbrotlidec.1.dylib'));
    assert.deepEqual(lrows().map((r) => r.status), ['SAFE'], 'the clean twin');
    // a version manager's usual folder under ~ the same way, both readings (round 7 read only x/.volta)
    const home = shimPlaces(INC.shims['volta-shim'], {}).patterns;
    assert.ok(home.includes(`${via}/.volta/tools/image/node/*/bin/node`) && home.includes(join(x, '.volta', 'tools', 'image', 'node', '*', 'bin', 'node')), home.join());
    // and asdf's ~/ in ASDF_DATA_DIR: the home folder put in front as written, then both readings
    const asdf = shimPlaces(INC.shims.asdf, { ASDF_DATA_DIR: '~/q/../r' }).patterns;
    assert.ok(asdf.includes(`${via}/q/../r/installs/nodejs/*/bin/node`) && asdf.includes(join(x, 'r', 'installs', 'nodejs', '*', 'bin', 'node')), asdf.join());
  } finally { process.env.HOME = saved; }
  // a RECORD path with a '..': pip wrote, and the package loads, the file the OS finds. sp/pkg/link is a link to
  // sp/pkg/a/b, so pkg/link/../deep is sp/pkg/a/deep (an unfixed copy); resolve() read sp/pkg/deep (a fixed one): SAFE
  const sp = fresh('asw-vars-sp');
  mkdirSync(join(sp, 'pkg', 'a', 'b'), { recursive: true }); symlinkSync(join(sp, 'pkg', 'a', 'b'), join(sp, 'pkg', 'link'));
  oldLib(join(sp, 'pkg', 'a', 'deep', 'libbrotlidec.1.dylib')); fixedLib(join(sp, 'pkg', 'deep', 'libbrotlidec.1.dylib'));
  mkdirSync(join(sp, 'pkg-1.0.dist-info'), { recursive: true });
  writeFileSync(join(sp, 'pkg-1.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n\n');
  writeFileSync(join(sp, 'pkg-1.0.dist-info', 'RECORD'), 'pkg/link/../deep/libbrotlidec.1.dylib,,\n');
  const written = `${sp}/pkg/link/../deep/libbrotlidec.1.dylib`;
  assert.deepEqual(run({}, { siteDirs: [sp] }).rows.map((r) => [r.file, r.status, r.owner]), [[written, 'EXPOSED', 'pkg 1.0']]);
  fixedLib(join(sp, 'pkg', 'a', 'deep', 'libbrotlidec.1.dylib'));
  assert.deepEqual(run({}, { siteDirs: [sp] }).rows.map((r) => [r.file, r.status]), [[written, 'SAFE']], 'the clean twin');
  // the loader's configuration: an include whose folder holds a '..' is not compared as text (ldconfig's glob takes it
  // after the link before it, which may be another folder): not followed, a gap. Up to round 8 it read as the usual one
  const etc = fresh('asw-vars-etc'), confd = join(etc, 'ld.so.conf.d'), conf = join(etc, 'ld.so.conf');
  mkdirSync(confd, { recursive: true });
  writeFileSync(conf, 'include ld.so.conf.d/../ld.so.conf.d/*.conf\n');
  assert.deepEqual(ldSoConfDirs({ ldSoConf: conf, ldSoConfDir: confd }).gaps, [`${conf}: include ld.so.conf.d/../ld.so.conf.d/*.conf`]);
  writeFileSync(conf, 'include ld.so.conf.d/*.conf\n');
  assert.deepEqual(ldSoConfDirs({ ldSoConf: conf, ldSoConfDir: confd }).gaps, [], 'the clean twin: the usual include');
});
