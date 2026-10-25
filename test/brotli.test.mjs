// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The bundled-decoder check (lib/brotli.mjs, incident brotli-2026-10), offline, on synthetic files: a few bytes of
// Mach-O or ELF (a minimal valid header where the check reads one) and the strings a Brotli decoder's error table holds,
// in the combinations real builds have. No real binary is in the repository and nothing is downloaded. Every case that
// ends EXPOSED or UNKNOWN has a clean twin. Package names are the copies the incident covers (Pillow, opencv-python, the
// Brotli bindings) or made up.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, openSync, ftruncateSync, closeSync, realpathSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanBytes, readAt } from '../lib/files.mjs';
import { judgeFile, evidence, resolveLink, isDecoderLibName, isNodeLibName, recordPaths, sitePackagesCandidates, distroVerdict, checkBundled, elfSearchPath, ldSoConfDirs } from '../lib/brotli.mjs';
import { SITE_PATTERNS } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'brotli-2026-10.json'), 'utf8'));
const M = INC.markers;
const MARKER = M.fixed, CONTROL = M.table;
const NODE_MARKER = `${M.nodeConstant}${MARKER}`, NODE_CONTROL = `${M.nodeConstant}${CONTROL}`;   // Node's zlib.constants names
const MACHO = Buffer.from('cffaedfe', 'hex');
let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-brotli-')); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };

/** A binary-looking file: magic, padding, then each string as a C string literal (NUL before and after), or raw bytes. */
function bin(path, parts = [], magic = MACHO) {
  mkdirSync(dirname(path), { recursive: true });
  const body = parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(`\0${p}\0`)));
  writeFileSync(path, Buffer.concat([magic, Buffer.alloc(60, 0x90), ...body, Buffer.alloc(16)]), { mode: 0o755 });
  return path;
}
/** A minimal valid ELF file (64-bit little-endian by default): one PT_DYNAMIC program header and a dynamic table with
 *  DT_NEEDED, DT_RUNPATH when asked, and DT_NULL; then the strings, as bin() writes them. */
function elf(path, parts = [], { runpath = false, bits = 64, be = false } = {}) {
  const tags = [[1, 1], ...(runpath ? [[29, 1]] : []), [0, 0]];
  const ent = bits === 64 ? 16 : 8, ehsize = bits === 64 ? 64 : 52, phsize = bits === 64 ? 56 : 32, dynOff = ehsize + phsize;
  const h = Buffer.alloc(dynOff + tags.length * ent);
  const w16 = (v, o) => (be ? h.writeUInt16BE(v, o) : h.writeUInt16LE(v, o));
  const w32 = (v, o) => (be ? h.writeUInt32BE(v, o) : h.writeUInt32LE(v, o));
  const w64 = (v, o) => (be ? h.writeBigUInt64BE(BigInt(v), o) : h.writeBigUInt64LE(BigInt(v), o));
  const word = bits === 64 ? w64 : w32;
  h.set([0x7f, 0x45, 0x4c, 0x46, bits === 64 ? 2 : 1, be ? 2 : 1, 1], 0);
  w16(3, 16); w16(0x3e, 18); w32(1, 20);
  if (bits === 64) { w64(ehsize, 32); w16(ehsize, 52); w16(phsize, 54); w16(1, 56); } else { w32(ehsize, 28); w16(ehsize, 40); w16(phsize, 42); w16(1, 44); }
  w32(2, ehsize);   // PT_DYNAMIC
  if (bits === 64) { w64(dynOff, ehsize + 8); w64(tags.length * ent, ehsize + 32); } else { w32(dynOff, ehsize + 4); w32(tags.length * ent, ehsize + 16); }
  tags.forEach(([t, v], i) => { word(t, dynOff + i * ent); word(v, dynOff + i * ent + ent / 2); });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, Buffer.concat([h, Buffer.alloc(16), ...parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(`\0${p}\0`))), Buffer.alloc(16)]), { mode: 0o755 });
  return path;
}
const fixedLib = (p) => bin(p, ['_SUCCESS', CONTROL, MARKER, '_ERROR_UNREACHABLE']);
const oldLib = (p) => bin(p, ['_SUCCESS', CONTROL, '_ERROR_UNREACHABLE']);
const judge = (f, sonameDirs = []) => judgeFile(f, { markers: M, sonameDirs });
/** checkBundled on this test's places only: no version managers, library places or library folders unless given. */
const run = (incOver = {}, opts = {}) => checkBundled({ ...INC, nodeDirs: [], bunDirs: [], libPlaces: [], ...incOver }, { pathEnv: fresh(`empty-path-${Math.random()}`), sonameDirs: [], ...opts });

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
  const half = judge(bin(join(d, 'half-and-link'), [MARKER, join(d, 'libbrotlidec.1.dylib')]));
  assert.equal(half.status, 'UNKNOWN'); assert.match(half.reason, /not the error texts every Brotli decoder has/);
  // the clean twin: the same file with the control beside the one marker
  assert.equal(judge(bin(join(d, 'both'), ['_SUCCESS', CONTROL, MARKER])).status, 'SAFE');
});

/** A universal (fat) Mach-O file: the header, then each build at its offset (16-byte aligned), as bin() writes one. */
function fat(path, builds, { is64 = false } = {}) {
  const bodies = builds.map((parts) => Buffer.concat([MACHO, Buffer.alloc(60, 0x90), ...parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(`\0${p}\0`))), Buffer.alloc(16)]));
  const ent = is64 ? 32 : 20, head = Buffer.alloc(8 + builds.length * ent);
  head.writeUInt32BE(is64 ? 0xcafebabf : 0xcafebabe, 0); head.writeUInt32BE(builds.length, 4);
  let at = Math.ceil(head.length / 16) * 16 + 64;
  const out = [head];
  bodies.forEach((b, i) => {
    const o = 8 + i * ent;
    head.writeUInt32BE(0x0100000c, o); head.writeUInt32BE(0, o + 4);
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
  const old = oldLib(join(d, 'old', 'libbrotlidec.1.dylib')), good = fixedLib(join(d, 'new', 'libbrotlidec.1.dylib'));
  // a universal file: one build with a fixed table, the other with no table, linking an unfixed library. Counted over
  // the whole file, the one table read SAFE; the loader maps one build, so each is judged
  for (const is64 of [false, true]) {
    const mixed = judge(fat(join(d, `fat-mixed-${is64}`), [[CONTROL, MARKER], [old]], { is64 }));
    assert.equal(mixed.status, 'EXPOSED', `fat${is64 ? ' 64' : ''}`); assert.match(mixed.reason, /lacks the fix.*one of the 2 builds/);
    const twin = judge(fat(join(d, `fat-twin-${is64}`), [[CONTROL, MARKER], [good]], { is64 }));
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
  const both = judge(bin(join(d, 'table-and-old'), [CONTROL, MARKER, old]));
  assert.equal(both.status, 'EXPOSED'); assert.match(both.reason, /its own Brotli decoder has the fix, but it uses .*old\/libbrotlidec\.1\.dylib/);
  const bothGood = judge(bin(join(d, 'table-and-new'), [CONTROL, MARKER, good]));
  assert.equal(bothGood.status, 'SAFE'); assert.deepEqual(bothGood.searched, [join(d, 'table-and-new'), good]);
  // and links it names past the mentions kept, or in a string that isn't whole: UNKNOWN beside a table too
  const decoys = (n) => Array.from({ length: n }, (_, i) => `libbrotlidec mention ${i}`);
  assert.equal(judge(bin(join(d, 'table-crowded'), [CONTROL, MARKER, good, ...decoys(70), old])).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'table-cut'), [CONTROL, MARKER, Buffer.from(`\0\x01${old}\0`)])).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'table-few'), [CONTROL, MARKER, good, ...decoys(10)])).status, 'SAFE', 'the clean twin');
  // a decoder library's own name (its install name or soname) is not a link: still SAFE by its table
  assert.equal(judge(bin(join(d, 'self', 'libbrotlidec.1.2.1.dylib'), [CONTROL, MARKER, '/DLC/PIL/.dylibs/libbrotlidec.1.2.1.dylib'])).status, 'SAFE');
  // a fixed 1.1-form table beside a 1.0-form one (Brotli 1.0's error texts have no prefix): never SAFE on the 1.1 marker
  const mix = judge(bin(join(d, 'two-forms'), [CONTROL, MARKER, 'BLOCK_LENGTH_1']));
  assert.equal(mix.status, 'UNKNOWN'); assert.match(mix.reason, /form Brotli 1\.0 writes them.*could not be tested/);
  assert.equal(judge(bin(join(d, 'one-form'), [CONTROL, MARKER, 'BLOCK_LENGTH'])).status, 'SAFE', 'the clean twin');
  // a 1.0-form table alone (Debian 12's 1.0.9): not judged yet, UNKNOWN with the reason
  const only = judge(bin(join(d, 'old-form'), ['SUCCESS', 'BLOCK_LENGTH_1']));
  assert.equal(only.status, 'UNKNOWN'); assert.match(only.reason, /form Brotli 1\.0 writes them, which Wardlatch doesn't judge yet/);
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
  oldLib(join(d, 'old', 'libbrotlidec.1.dylib')); fixedLib(join(d, 'new', 'libbrotlidec.1.dylib'));
  // what Homebrew's libnode holds: zlib.constants names compiled from the header, a link to Homebrew's library, no table
  const names = [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v26.12.1'];
  const ev = evidence(bin(join(d, 'old-node'), [...names, join(d, 'old', 'libbrotlidec.1.dylib')]), M);
  assert.equal(ev.m0, 0, 'a substring search would have counted the constant name as the marker');
  assert.equal(ev.mk, 1);
  const bad = judge(join(d, 'old-node'));
  assert.equal(bad.status, 'EXPOSED', 'the library it loads decides, not the header it was built with');
  assert.match(bad.reason, /it uses .*old\/libbrotlidec\.1\.dylib, whose Brotli decoder lacks the fix/);
  const good = judge(bin(join(d, 'new-node'), [...names, join(d, 'new', 'libbrotlidec.1.dylib')]));
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
  for (const [f, hint] of [[join(path, 'node'), /22\.23\.4, 24\.22\.1, 26\.12\.1 and later are fixed/], [join(path, 'bun'), /1\.4\.4 or later.*1\.0\.21 to 1\.4\.3/], [join(sp, '_brotli.cpython-314-darwin.so'), /check the version of Brotli by hand/], [join(sp, 'examplepkg', 'driver', 'node'), /Node\.js 22\.23\.4/]]) {
    assert.equal(by(f).status, 'UNKNOWN', f); assert.match(by(f).reason, /could not be tested/); assert.match(by(f).reason, hint);
    assert.equal(by(f).fix, undefined, 'an UNKNOWN row gives its reason, not a fix');
  }
  // clean twin: the same places with fixed tables
  fixedLib(join(path, 'node')); fixedLib(join(path, 'bun')); fixedLib(join(sp, '_brotli.cpython-314-darwin.so')); fixedLib(join(sp, 'examplepkg', 'driver', 'node'));
  assert.deepEqual(run({}, { pathEnv: path, siteDirs: [sp] }).rows.map((r) => r.status), ['SAFE', 'SAFE', 'SAFE', 'SAFE']);
});

test('links: @loader_path beside the file, an absolute path; @rpath, @executable_path and a missing one are UNKNOWN', () => {
  const d = fresh('links');
  fixedLib(join(d, 'pkg', 'libbrotlidec.1.2.1.dylib'));
  assert.equal(judge(bin(join(d, 'pkg', 'libfreetype.6.dylib'), ['@loader_path/libbrotlidec.1.2.1.dylib'])).status, 'SAFE');
  oldLib(join(d, 'pkg2', 'libbrotlidec.1.2.0.dylib'));
  assert.equal(judge(bin(join(d, 'pkg2', 'libfreetype.6.dylib'), ['@loader_path/libbrotlidec.1.2.0.dylib'])).status, 'EXPOSED');
  for (const ref of ['@rpath/libbrotlidec.1.dylib', '@executable_path/libbrotlidec.1.2.1.dylib', '@executable_path/../pkg/libbrotlidec.1.2.1.dylib']) {
    const r = judge(bin(join(d, 'pkg', `uses-${ref.length}`), [ref]));
    assert.equal(r.status, 'UNKNOWN', ref); assert.match(r.reason, /can't follow/);
  }
  const missing = judge(bin(join(d, 'missing'), [join(d, 'nowhere', 'libbrotlidec.1.dylib')]));
  assert.equal(missing.status, 'UNKNOWN'); assert.match(missing.reason, /was not found/);
  // a linked library that itself has no table is not followed further: UNKNOWN
  bin(join(d, 'pkg3', 'libbrotlidec.1.dylib'), ['@loader_path/libbrotlidec.1.2.1.dylib']);
  assert.equal(judge(bin(join(d, 'pkg3', 'prog'), ['@loader_path/libbrotlidec.1.dylib'])).status, 'UNKNOWN');
  // a file that names libbrotlidec more often than the mentions kept: a link past them could be an old library, so the
  // fixed one it shows first is not enough
  oldLib(join(d, 'crowd', 'old', 'libbrotlidec.1.dylib'));
  const decoys = (n) => Array.from({ length: n }, (_, i) => `libbrotlidec mention ${i}`);
  const crowded = judge(bin(join(d, 'crowd', 'prog'), [join(d, 'pkg', 'libbrotlidec.1.2.1.dylib'), ...decoys(70), join(d, 'crowd', 'old', 'libbrotlidec.1.dylib')]));
  assert.equal(crowded.status, 'UNKNOWN'); assert.match(crowded.reason, /more often than Wardlatch keeps track of.*could not be tested/);
  assert.equal(judge(bin(join(d, 'crowd', 'prog-few'), [join(d, 'pkg', 'libbrotlidec.1.2.1.dylib'), ...decoys(10)])).status, 'SAFE', 'the clean twin');
  assert.equal(judge(bin(join(d, 'crowd', 'prog-few-old'), [join(d, 'pkg', 'libbrotlidec.1.2.1.dylib'), ...decoys(10), join(d, 'crowd', 'old', 'libbrotlidec.1.dylib')])).status, 'EXPOSED');
  // what counts as a decoder library's name
  for (const s of ['/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib', '@loader_path/libbrotlidec.1.2.0.dylib', 'libbrotlidec.so.1', 'libbrotlidec-ba690955.so.1.0.9', 'libbrotlidec.so']) assert.ok(isDecoderLibName(s), s);
  for (const s of ['libbrotlidec is used here', 'libbrotlidec.so.1x', 'libbrotlidec.a', 'libbrotlienc.1.dylib', 'token=AKIAEXAMPLE/libbrotlidec.so.1']) assert.ok(!isDecoderLibName(s), s);
  assert.equal(resolveLink('$ORIGIN/libbrotlidec.so.1', join(d, 'x')), null);
});

test('a link is followed only when its whole C string names the library: a non-ASCII folder is kept, a cut name is UNKNOWN', () => {
  const d = fresh('cstr');
  // a load path through a folder named José: the library there is unfixed; the ASCII tail after the é names a fixed one
  const real = oldLib(join(d, `José${d}`, 'fixed', 'libbrotlidec.1.dylib'));
  fixedLib(join(d, 'fixed', 'libbrotlidec.1.dylib'));
  const prog = bin(join(d, 'prog'), [real]);
  assert.deepEqual(evidence(prog, M).links, [real], 'the whole path, not its ASCII tail');
  const r = judge(prog);
  assert.equal(r.status, 'EXPOSED'); assert.equal(r.via, real);
  // the clean twin: the library at that path fixed
  fixedLib(real);
  assert.equal(judge(prog).status, 'SAFE');
  // a name that doesn't start right after a NUL, doesn't end at one, or isn't UTF-8: never followed, UNKNOWN
  const lib = join(d, 'fixed', 'libbrotlidec.1.dylib');
  for (const [name, raw] of [['after-a-byte', Buffer.from(`\0\x01${lib}\0`)], ['no-nul-after', Buffer.from(`\0${lib}\x01\0`)], ['bad-utf8', Buffer.concat([Buffer.from('\0'), Buffer.from([0xc3]), Buffer.from(`${lib}\0`)])]]) {
    const c = judge(bin(join(d, name), [raw]));
    assert.equal(c.status, 'UNKNOWN', name); assert.match(c.reason, /could not be read whole.*could not be tested/, name);
  }
  // beside a whole link to a fixed library, a cut name still makes it UNKNOWN: the cut one may be what loads
  assert.equal(judge(bin(join(d, 'whole-and-cut'), [lib, Buffer.from(`\0\x01${join(d, 'other', 'libbrotlidec.1.dylib')}\0`)])).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'whole-only'), [lib])).status, 'SAFE', 'the clean twin');
});

test('ELF sonames: found in the library folders only when the program sets no search path of its own; every candidate must be SAFE', () => {
  const d = fresh('elf'), libs = fresh('elf-lib'), libs2 = fresh('elf-lib2');
  fixedLib(join(libs, 'libbrotlidec.so.1'));
  const prog = elf(join(d, 'prog'), ['libbrotlidec.so.1']);
  assert.equal(elfSearchPath(prog), 'none');
  assert.equal(judge(prog, [libs]).status, 'SAFE');
  oldLib(join(libs, 'libbrotlidec.so.1'));
  assert.equal(judge(prog, [libs]).status, 'EXPOSED');
  assert.equal(judge(prog, [fresh('elf-empty')]).status, 'UNKNOWN', 'a soname found nowhere');
  // DT_RUNPATH (conda, Linuxbrew): the loader looks there first, so the standard folders prove nothing
  fixedLib(join(libs, 'libbrotlidec.so.1'));
  const rp = elf(join(d, 'prog-runpath'), ['libbrotlidec.so.1'], { runpath: true });
  assert.equal(elfSearchPath(rp), 'set');
  const r = judge(rp, [libs]);
  assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /can't follow/);
  // 32-bit big-endian headers are read too
  const be = elf(join(d, 'prog-be32'), ['libbrotlidec.so.1'], { bits: 32, be: true });
  assert.equal(elfSearchPath(be), 'none');
  assert.equal(judge(be, [libs]).status, 'SAFE');
  assert.equal(elfSearchPath(elf(join(d, 'prog-be32-rp'), ['libbrotlidec.so.1'], { bits: 32, be: true, runpath: true })), 'set');
  // ELF magic with no readable headers, and a Mach-O file with a bare name: can't be followed
  assert.equal(judge(bin(join(d, 'magic-only'), ['libbrotlidec.so.1'], Buffer.from('7f454c46', 'hex')), [libs]).status, 'UNKNOWN');
  assert.equal(judge(bin(join(d, 'macho-bare'), ['libbrotlidec.so.1']), [libs]).status, 'UNKNOWN');
  // two folders, two candidates: both must be SAFE
  oldLib(join(libs2, 'libbrotlidec.so.1'));
  assert.equal(judge(prog, [libs, libs2]).status, 'EXPOSED');
  fixedLib(join(libs2, 'libbrotlidec.so.1'));
  const both = judge(prog, [libs, libs2]);
  assert.equal(both.status, 'SAFE');
  assert.ok(both.searched.includes(join(libs, 'libbrotlidec.so.1')) && both.searched.includes(join(libs2, 'libbrotlidec.so.1')), 'the receipt names both');
});

test('ld.so.conf: the folders it names are searched too, so a library only the loader\'s configuration points at still decides', () => {
  const d = fresh('ldso'), extra = fresh('ldso-extra'), extra2 = fresh('ldso-extra2'), std = fresh('ldso-std');
  mkdirSync(join(d, 'ld.so.conf.d'));
  writeFileSync(join(d, 'ld.so.conf'), 'include /etc/ld.so.conf.d/*.conf\n# a comment\n');
  writeFileSync(join(d, 'ld.so.conf.d', 'a.conf'), `# extra\n${extra} # trailing comment\n\n`);
  writeFileSync(join(d, 'ld.so.conf.d', 'b.conf'), `${extra2}:/also/this\n`);
  writeFileSync(join(d, 'ld.so.conf.d', 'notes.txt'), '/not/this\n');
  const places = { ldSoConf: join(d, 'ld.so.conf'), ldSoConfDir: join(d, 'ld.so.conf.d') };
  assert.deepEqual(ldSoConfDirs(places).sort(), [extra, extra2, '/also/this'].sort());
  // a program linking the soname: the standard folder's copy is fixed, the one the configuration adds is not
  fixedLib(join(std, 'libbrotlidec.so.1')); oldLib(join(extra, 'libbrotlidec.so.1'));
  const path = fresh('ldso-path');
  elf(join(path, 'node'), [NODE_CONTROL, 'libbrotlidec.so.1']);
  const at = () => run({}, { pathEnv: path, sonameDirs: [std], places }).rows.find((r) => r.file === join(path, 'node'));
  assert.equal(at().status, 'EXPOSED');
  fixedLib(join(extra, 'libbrotlidec.so.1'));
  assert.equal(at().status, 'SAFE', 'the clean twin');
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

test('the reading budget: once a run has read its share, every file left is UNKNOWN, never skipped', () => {
  const path = fresh('budget-path');
  const a = fixedLib(join(path, 'a', 'node')), b = fixedLib(join(path, 'b', 'node'));
  const nodeDirs = [join(path, '*', 'node')];
  const tight = run({ nodeDirs }, { budgetBytes: 10 }).rows;
  assert.deepEqual(tight.map((r) => r.file).sort(), [a, b].sort());
  assert.equal(tight.filter((r) => r.status === 'SAFE').length, 1, 'the first file is read');
  const left = tight.find((r) => r.status !== 'SAFE');
  assert.equal(left.status, 'UNKNOWN'); assert.match(left.reason, /4 GB.*could not be tested/);
  assert.deepEqual(run({ nodeDirs }).rows.map((r) => r.status), ['SAFE', 'SAFE'], 'with the budget, both are read');
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
  bin(join(sp, 'PIL', '.dylibs', 'libfreetype.6.dylib'), ['@loader_path/libbrotlidec.1.2.0.dylib']);
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
  assert.match(row('PIL/.dylibs/libbrotlidec.1.2.0.dylib').fix, /Pillow had no release with a fixed Brotli on 24 October 2026.*Until then, don't open WOFF2 fonts/);
  const cv = row('cv2/.dylibs/libbrotlidec.1.1.0.dylib');
  assert.match(cv.fix, /^opencv-(contrib-)?python 5\.0\.0\.93 \(the latest 5\.x\) carries Brotli 1\.1\.0 through its bundled FFmpeg; we found no way in today; update when a fixed wheel ships\.$/);
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
  const shim = rows.find((r) => r.file === join(path, 'node'));
  assert.equal(shim.status, 'REVIEW'); assert.match(shim.reason, /shim/);
  assert.ok(looked.some((l) => l.includes(join(d, 'nvm'))), 'the receipt names the version managers\' folders');
  assert.ok(!existsSync(ran), 'nothing found was run');
  // a compiled program named node on PATH with no sign of Node.js that is a version manager's shim (volta's node links
  // to volta-shim, mise's to mise): REVIEW, never judged
  for (const shimName of ['volta-shim', 'mise']) {
    const path2 = fresh(`rt-path2-${shimName}`);
    bin(join(d, `${shimName}-home`, shimName), ['shim']);
    symlinkSync(join(d, `${shimName}-home`, shimName), join(path2, 'node'));
    const r2 = run({}, { pathEnv: path2 }).rows;
    assert.equal(r2.length, 1); assert.equal(r2[0].status, 'REVIEW', shimName); assert.match(r2[0].reason, new RegExp(`^${shimName}, a version manager's shim, not a Node\\.js runtime`));
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
  elf(join(path, 'node'), ['libnode.so.108', 'libstdc++.so.6', 'libc.so.6']);
  elf(join(lib, 'libnode.so.108'), [NODE_CONTROL, NODE_MARKER, 'libbrotlidec.so.1', 'libbrotlienc.so.1', 'nodejs.org/download/release/v18.20.4']);
  oldLib(join(lib, 'libbrotlidec.so.1'));
  const row = () => run({}, { pathEnv: path, sonameDirs: [lib] }).rows.find((r) => r.file === join(path, 'node'));
  const bad = row();
  assert.equal(bad.status, 'EXPOSED'); assert.match(bad.reason, /the library that holds Node\.js's code: it uses .*libbrotlidec\.so\.1, whose Brotli decoder lacks the fix/);
  assert.equal(bad.via, join(lib, 'libbrotlidec.so.1')); assert.match(bad.fix, /not Node\.js/);
  assert.equal(bad.version, '18.20.4', 'the release libnode holds, for the words');
  fixedLib(join(lib, 'libbrotlidec.so.1'));
  const good = row();
  assert.equal(good.status, 'SAFE'); assert.deepEqual(good.searched, [join(path, 'node'), join(lib, 'libnode.so.108'), join(lib, 'libbrotlidec.so.1')]);
  // beside it, a libnode name in a string that isn't whole could be the one that loads: UNKNOWN
  const unsure = judge(elf(join(d, 'node-unsure'), ['libnode.so.108', Buffer.from(`\0\x01${join(d, 'other', 'libnode.so.108')}\0`)]), [lib]);
  assert.equal(unsure.status, 'UNKNOWN'); assert.match(unsure.reason, /libnode.*could not be read whole/);
  // libnode with its own fixed table decides by it; with an unfixed one, EXPOSED
  elf(join(lib, 'libnode.so.108'), [CONTROL, MARKER]);
  assert.equal(row().status, 'SAFE');
  elf(join(lib, 'libnode.so.108'), [CONTROL]);
  assert.equal(row().status, 'EXPOSED');
  // a libnode that can't be followed (@rpath, a program with its own RUNPATH) or found: UNKNOWN, never REVIEW
  bin(join(d, 'node-rpath'), ['@rpath/libnode.147.dylib']);
  elf(join(d, 'node-runpath'), ['libnode.so.108'], { runpath: true });
  elf(join(d, 'node-nowhere'), ['libnode.so.999']);
  for (const f of ['node-rpath', 'node-runpath', 'node-nowhere']) {
    const r = judge(join(d, f), [lib]);
    assert.equal(r.status, 'UNKNOWN', f); assert.match(r.reason, /libnode.*could not be tested/, f);
  }
  // names that only look like it are not a link (libnode_base.a in a build path)
  assert.ok(!['libnode_base.a', 'libnodejs.so.1', 'libnode.147', 'libnode.so.x'].some(isNodeLibName));
  assert.ok(['libnode.so.108', '@rpath/libnode.147.dylib', '/usr/lib/x86_64-linux-gnu/libnode.so.115', 'libnode.dylib'].every(isNodeLibName));
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
  oldLib(join(d, 'brew', 'libbrotlidec.1.dylib'));
  const linked = at([join(d, 'brew', 'libbrotlidec.1.dylib')]);
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
  bin(join(path, 'node'), [NODE_CONTROL, NODE_MARKER, brew]);
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
  bin(join(path, 'node'), [NODE_CONTROL, loose]);
  assert.match(run({ libPlaces }, { pathEnv: path }).rows.find((r) => r.file === join(path, 'node')).fix, /Update whatever installed .*loose\/libbrotlidec\.1\.dylib/);
  // clean twins
  fixedLib(brew); fixedLib(ports); fixedLib(conda);
  bin(join(path, 'node'), [NODE_CONTROL, NODE_MARKER, brew]);
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
  bin(join(path, 'node'), [NODE_CONTROL, NODE_MARKER, 'nodejs.org/download/release/v18.19.0', sys]);
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
  // Debian 12 as it really is: Brotli 1.0's error texts have no _ERROR_FORMAT_ prefix (BrotliDecoderErrorString returns
  // the bare name before 1.1.0), so no table is seen and the package record is not reached: UNKNOWN, never SAFE
  const old10 = bin(join(d, 'sys12', 'libbrotlidec.so.1'), ['SUCCESS', 'BLOCK_LENGTH_1', 'UNREACHABLE']);
  writeFileSync(osr, 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n');
  dpkg(stanza('1.0.9-2+deb12u1'));
  md5sums(info, [old10]);
  const r12 = run({ libPlaces: [{ pattern: old10, label: 'the system\'s libbrotlidec', system: true }] }, { places: { osRelease: osr, dpkgStatus: status, dpkgInfo: info } }).rows[0];
  assert.equal(r12.status, 'UNKNOWN'); assert.match(r12.reason, /could not be tested/);
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
  bin(join(sp, 'stray2.libs', 'libbrotlidec-2.so.1'), ['@rpath/libbrotlidec.1.dylib']);
  const { rows } = run({}, { pathEnv: path, siteDirs: [sp], budgetBytes: 1e9 });
  assert.ok(rows.length >= 10);
  for (const r of rows) {
    if (r.status === 'UNKNOWN') assert.match(r.reason, /could not be tested/, r.file);
    if (r.status === 'EXPOSED') { assert.ok(r.fix && r.fix.length > 20, r.file); assert.ok(!r.fix.includes('{'), `${r.file}: no placeholder left`); }
    if (r.status === 'SAFE') assert.ok(r.searched.includes(r.file), r.file);
    for (const k of ['viaText', 'noMarker', 'runtimeSign', 'byHand', 'noTable']) assert.ok(!(k in r), `${k} stays inside the module`);
  }
});

test('bounded: a file full of "libbrotlidec" and printable bytes is read in time and keeps at most a few links', () => {
  const f = join(fresh('bounded'), 'x');
  writeFileSync(f, Buffer.concat([MACHO, Buffer.from('A/libbrotlidec.1.dylib'.repeat(200000))]));
  const t = Date.now();
  const r = judge(f);
  assert.ok(Date.now() - t < 3000, `${Date.now() - t} ms`);
  assert.equal(r.status, 'UNKNOWN');
  // a hostile ld.so.conf line is split in linear time
  const conf = join(fresh('bounded-conf'), 'x.conf');
  writeFileSync(conf, `/${' '.repeat(60000)}/x\n`);
  const t2 = Date.now(); ldSoConfDirs({ ldSoConf: conf }); assert.ok(Date.now() - t2 < 500);
});

// ---- the command, end to end ----------------------------------------------------------------------------------------
const PRELOAD = ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs')];
const cli = (args, env) => {
  const r = spawnSync(process.execPath, [...PRELOAD, BIN, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test('the preload hides the machine\'s server folders (/srv, /app, /var/www) and loader lists, never the code under test', () => {
  const probe = ['/srv/site/venv/lib', '/app/.venv/lib', '/var/www/html', '/etc/ld-musl-x86_64.path', '/var/lib/dpkg/status', ROOT, join(ROOT, 'lib', 'brotli.mjs')];
  const script = `const fs = require('node:fs'); console.log(JSON.stringify(${JSON.stringify(probe)}.map((p) => { try { fs.statSync(p); return 'seen'; } catch (e) { return e.message === 'hidden by the test' ? 'hidden' : 'absent'; } })));`;
  const r = spawnSync(process.execPath, [...PRELOAD, '-e', script], { encoding: 'utf8' });
  assert.deepEqual(JSON.parse(r.stdout), ['hidden', 'hidden', 'hidden', 'hidden', 'hidden', 'seen', 'seen'], r.stderr);
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
  assert.match(text.out, /fix: Pillow had no release with a fixed Brotli on 24 October 2026/);
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
