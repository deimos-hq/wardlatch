// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Round 3's three independent re-reads of fix/false-safes at f62f9ba (31 Oct 2026) all said NOT READY, and the owner
// decided #33 the same day. Each test here stands in front of one of their lib and bin findings, of the lib mutants
// round 3's re-read planted that no test caught, or of decision #33, is named after it, and failed at f62f9ba for the
// reason its name gives (or, for a test that could not fail there, fails on the mutant named in its comment). Offline:
// no test reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, mkdtempSync, rmSync, realpathSync, readdirSync, statSync, symlinkSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-reread-r3-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
/** The CLI as a person runs it: its text output and exit code. */
const text = (args, env = {}, nodeArgs = []) => {
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
/** The CLI with --json: the raw text, the rows and the exit code. */
const json = (args, env = {}, nodeArgs = []) => {
  const r = text([...args, '--json'], env, nodeArgs);
  let rows; try { rows = JSON.parse(r.out).results; } catch { assert.fail(`not JSON (exit ${r.code}): ${r.err.slice(0, 600)}`); }
  return { ...r, rows };
};
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

// ---- owner decision #33: a service's folder that could not be opened is UNKNOWN, grouped in one row ------------------
// "UNKNOWN too" (owner, 31 Oct 2026): a folder Wardlatch could not open because it belongs to a system service (EACCES)
// is could-not-be-tested, exit 2, never a REVIEW line beside SAFE, and such folders are grouped into one line. This
// supersedes the 22 Oct one-review-line rule and extends decision #32 (EPERM). At f62f9ba, MEASURED by the round-3
// re-read and again here: `--incident litellm-2026-10 --paths /private/var/spool` printed "REVIEW folders not searched"
// for 15 folders root and _postfix own, then "SAFE no LiteLLM 1.107.0 files or markers found", exit 0.
/** A folder on this machine below which every folder that can't be listed is a service's and refuses with EACCES,
 *  none with EPERM, none a person's, and with no link out of it: /private/var/spool on macOS, /var/spool on Linux. */
const spool = () => {
  const { isPersonUid } = OWNERS;
  for (const base of ['/private/var/spool', '/var/spool']) {
    let service = 0, bad = false;
    const walk = (d, depth) => {
      let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { bad = true; return; }
      for (const e of ents) {
        const p = join(d, e.name);
        if (e.isSymbolicLink()) { try { if (statSync(p).isDirectory()) bad = true; } catch { /* a link to nothing */ } continue; }
        if (!e.isDirectory()) continue;
        try { readdirSync(p); } catch (err) {
          let uid = null; try { uid = statSync(p).uid; } catch { /* cannot tell */ }
          if (err.code !== 'EACCES' || isPersonUid(uid, 'install')) bad = true; else service++;
          continue;
        }
        if (depth > 0) walk(p, depth - 1);
      }
    };
    walk(base, 4);
    if (!bad && service > 1) return base;
  }
  return null;
};
let OWNERS;
before(async () => { OWNERS = await import('../lib/owners.mjs'); });

test('#33 the folders a service owns that could not be opened are UNKNOWN, in one row, exit 2, with no all-clear beside them', { skip: AS_ROOT && 'root opens every folder' }, (t) => {
  const base = spool(); if (!base) return t.skip('no spool folder of that shape on this machine');
  for (const id of ['litellm-2026-10', 'github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const r = json(['--incident', id, '--no-containers', '--paths', base]);
    assert.ok(!r.rows.some((x) => x.status === 'REVIEW'), `${id}: never a REVIEW line for a folder not opened: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    const grouped = unknowns(r).filter((x) => x.what === 'service folders');
    assert.equal(grouped.length, 1, `${id}: one row for them all: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.ok(grouped[0].paths.length > 1 && grouped[0].folders.length === grouped[0].paths.length, JSON.stringify(grouped[0]));
    for (const f of grouped[0].folders) assert.match(f.basis, /^EACCES, mode 0\d{3}, owner /, JSON.stringify(f));
    assert.match(grouped[0].reason, /could not be opened, so they were not searched/, grouped[0].reason);
    assert.ok(!r.rows.some((x) => x.status === 'SAFE'), `${id}: no all-clear beside folders not searched: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 2, id);
  }
  // as a person reads it: one UNKNOWN line for the group, and the last line counts it
  const t2 = text(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  assert.equal(t2.out.split('\n').filter((l) => /^UNKNOWN +\d+ folders owned by service accounts/.test(l)).length, 1, t2.out);
  assert.doesNotMatch(t2.out, /^(REVIEW|SAFE) /m, t2.out);
  assert.match(t2.out, /0 safe · 0 exposed · 1 could not be tested\n/, t2.out);
  assert.equal(t2.code, 2);
});

// ---- a virtual environment's packages where CPython on Linux and macOS does not put them --------------------------------
/** A virtual environment at `path` whose package folder is `pkgs` (relative to it), holding the LiteLLM 1.107.0 install
 *  record and its dropped cook.pth. → that folder */
function litellmVenv(path, pkgs = 'lib/python3.12/site-packages') {
  const sp = join(path, ...pkgs.split('/'));
  put(join(path, 'pyvenv.cfg'), 'home = /usr/bin\n');
  put(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n');
  put(join(sp, 'cook.pth'), 'import os\n');
  return sp;
}
const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];
const exposedIn = (r, sp) => r.rows.filter((x) => x.status === 'EXPOSED' && x.dir === sp).map((x) => x.what).sort();
/** A venv for the trust walk: bin/python, pyvenv.cfg and a certifi bundle in `pkgs`. */
function certifiVenv(root, pkgs = 'lib/python3.12/site-packages') {
  const sp = join(root, ...pkgs.split('/'));
  put(join(root, 'bin', 'python'), 'not run by Wardlatch\n');
  put(join(root, 'pyvenv.cfg'), 'home = /usr\n');
  put(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERT' + 'IFICATE-----\nQUFB\n-----END CERT' + 'IFICATE-----\n');
  put(join(sp, 'certifi-2026.06.17.dist-info', 'METADATA'), 'Version: 2026.06.17\n');
  return root;
}
const discovered = async (roots) => {
  const { discover } = await import('../lib/discover.mjs');
  const untested = [], links = [], deep = [], denied = [], found = [];
  const rts = discover({ roots, pathEnv: fresh('no-programs'), untested, links, deep, denied, found });
  const envs = [...rts.map((x) => x.env), ...untested.map((x) => x.fields?.env)].filter(Boolean);
  return { envs, deep, links, untested, found, denied, rts };
};

// Round 3's re-read 2, finding 1 (MEASURED there and here): 471a4ea stopped walking a venv's lib and Lib, and found its
// packages only at lib*/python3*/site-packages, case-sensitively. PyPy puts them at lib/pypy3.X/site-packages, a
// Windows-layout venv at Lib/site-packages (and an older PyPy virtualenv beside pyvenv.cfg): `--paths <the venv>` read
// SAFE, exit 0, with the line under it saying lib and Lib "are checked with it". At 03d95c9 it was EXPOSED. The same
// venv below the folder given read SAFE at both. The trust walk never probed a PyPy venv's certifi (no row at all).
const LAYOUTS = { pypy: 'lib/pypy3.10/site-packages', windows: 'Lib/site-packages', oldPypy: 'site-packages', lib64: 'lib64/python3.12/site-packages' };
test('venv layouts: a venv\'s packages at lib/pypy3.X, Lib or beside pyvenv.cfg are checked, given with --paths or found below it', () => {
  for (const [name, pkgs] of Object.entries(LAYOUTS)) {
    const parent = fresh(`layout-${name}`);
    const sp = litellmVenv(join(parent, '.venv'), pkgs);
    for (const given of [join(parent, '.venv'), parent]) {
      const r = json([...LITELLM, '--paths', given]);
      assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `${name}, --paths ${given}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
      assert.equal(r.code, 1, `${name}, --paths ${given}`);
    }
  }
});

// The round-4 mutant run found the test above blind to two mutants of venvPackages() (its lib names read case-
// sensitively; the package folder beside pyvenv.cfg dropped): the walk itself goes into a venv now and meets those
// folders, so above the depth floor they are checked either way. A venv met at the floor is not walked: there only
// venvPackages() finds its packages. So each layout again, six folders down.
test('venv layouts: a venv met at the depth floor has its packages checked whatever their layout', () => {
  for (const [name, pkgs] of Object.entries(LAYOUTS)) {
    const root = fresh(`layout-floor-${name}`);
    const sp = litellmVenv(join(root, 'a', 'b', 'c', 'd', 'e', '.venv'), pkgs);
    const r = json([...LITELLM, '--paths', root]);
    assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `${name}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 1, name);
  }
});

test('venv layouts: the trust walk probes the certifi of a PyPy venv, and of one with its packages in lib64', async () => {
  for (const name of ['pypy', 'lib64']) {
    const env = certifiVenv(join(fresh(`trust-${name}`), '.venv'), LAYOUTS[name]);
    for (const given of [env, dirname(env)]) {
      const r = await discovered([given]);
      assert.ok(r.envs.includes(env), `${name}, --paths ${given}: ${JSON.stringify(r)}`);
    }
  }
});

// ---- a venv's own folders: walked, and the line under the all-clear says exactly what is not -----------------------------
// Round 3's re-read 2, finding 2, and re-read 3, finding 7 (MEASURED): a project made with `python3 -m venv .` (pyvenv.cfg
// and bin/python at its root) holding a stealer's venv in its own lib/, share/, bin/ or etc/ read SAFE, exit 0, at
// f62f9ba (EXPOSED at 03d95c9), with the line under the all-clear saying those folders "are checked with it", while
// nothing in bin, share or etc was read, and lib only for its site-packages.
const OWN = ['lib/tools', 'share/demo', 'bin/x', 'etc/y', 'include/z', 'Scripts/w', 'lib/python3.12/vendored'];
test('a venv\'s own folders: a venv inside a project-venv\'s lib/, share/, bin/, etc/, include/ or Scripts/ is found', async () => {
  const parent = fresh('own-folders');
  const proj = join(parent, 'proj');
  put(join(proj, 'pyvenv.cfg'), 'home = /usr/bin\n');
  put(join(proj, 'bin', 'python'), 'not run by Wardlatch\n');
  mkdirSync(join(proj, 'lib', 'python3.12', 'site-packages'), { recursive: true });
  const inner = OWN.map((o) => litellmVenv(join(proj, ...o.split('/'), '.venv')));
  for (const given of [proj, parent]) {
    const r = json([...LITELLM, '--paths', given]);
    for (const sp of inner) assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `--paths ${given}, ${sp}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 1, `--paths ${given}`);
  }
  // the trust walk, likewise
  const t = fresh('own-folders-trust');
  const tproj = certifiVenv(join(t, 'proj'));
  const tinner = OWN.map((o) => certifiVenv(join(tproj, ...o.split('/'), '.venv')));
  for (const given of [tproj, t]) {
    const r = await discovered([given]);
    for (const env of tinner) assert.ok(r.envs.includes(env), `trust, --paths ${given}: ${env}: ${JSON.stringify(r.envs)}`);
  }
});

test('a venv\'s own folders: the line under the all-clear names only what is not searched, its own package folders', () => {
  const root = fresh('own-said');
  const sp = litellmVenv(join(root, '.venv'));
  rmSync(join(sp, 'cook.pth')); rmSync(join(sp, 'litellm-1.107.0.dist-info'), { recursive: true });
  const r = json([...LITELLM, '--paths', root]);
  const safe = r.rows.find((x) => x.status === 'SAFE');
  const said = safe?.notSearched?.find((n) => /virtual environment/.test(n)) ?? '';
  assert.match(said, /package folders/, JSON.stringify(safe));
  assert.match(said, /site-packages/, said);
  // never a folder this walk reads past (it walks bin, share, etc and the rest of lib), as one "checked with it"
  assert.doesNotMatch(said, /\b(bin|share|etc|include|Scripts)\b/, said);
  const t = text([...LITELLM, '--paths', root]).out.split('\n');
  const under = t[t.findIndex((l) => l.startsWith('SAFE')) + 1] ?? '';
  assert.match(under, /are checked with the environment, not searched for other environments/, under);
  assert.doesNotMatch(under, /\b(bin|share|etc)\b/, under);
});

// Round 3's re-read 2, finding 7 (MEASURED there and here): a link to a venv was checked (its site-packages, through the
// link) but not walked, and got no row: the walk marked the link's target as walked whole, so a venv inside the linked
// venv was never looked for, and the run read SAFE, exit 0.
test('a link to a venv: its packages are checked through it, and it is a link not followed, UNKNOWN, unless its target was walked', () => {
  const h = fresh('venv-link');
  const real = join(h, 'real');
  const own = litellmVenv(real);                                       // the linked venv's own packages: the stealer
  const inner = litellmVenv(join(real, 'src', 'sub', '.venv'));        // and a venv inside it
  mkdirSync(join(h, 'root', 'proj'), { recursive: true });
  symlinkSync(real, join(h, 'root', 'proj', '.venv'));
  const r = json([...LITELLM, '--paths', join(h, 'root')]);
  const through = join(h, 'root', 'proj', '.venv', 'lib', 'python3.12', 'site-packages');
  assert.deepEqual(exposedIn(r, through).length ? exposedIn(r, through) : exposedIn(r, own), ['cook.pth', 'litellm-1.107.0.dist-info'], `its packages, through the link: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  const row = unknowns(r).find((x) => x.path === join(h, 'root', 'proj', '.venv'));
  assert.ok(row, `the link is a gap: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.match(row.reason, /link to a virtual environment/, row.reason);
  assert.match(row.reason, /packages were checked/, row.reason);
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows).slice(0, 1500));
  // clean, the link alone keeps the run at could-not-be-tested
  for (const sp of [own, inner]) { rmSync(join(sp, 'cook.pth')); rmSync(join(sp, 'litellm-1.107.0.dist-info'), { recursive: true }); }
  const c = json([...LITELLM, '--paths', join(h, 'root')]);
  assert.equal(c.code, 2, JSON.stringify(c.rows).slice(0, 1500));
  // and given with its target, which is then walked, the link is no gap (WV-9), and the venv inside is found
  litellmVenv(join(real, 'src', 'sub', '.venv'));
  const both = json([...LITELLM, '--paths', join(h, 'root'), '--paths', real]);
  assert.deepEqual(exposedIn(both, inner), ['cook.pth', 'litellm-1.107.0.dist-info'], JSON.stringify(both.rows).slice(0, 1500));
  assert.ok(!unknowns(both).some((x) => x.path === join(h, 'root', 'proj', '.venv')), JSON.stringify(both.rows).slice(0, 1500));
  assert.equal(both.code, 1);
});

test('a venv\'s own folders: a venv at the depth floor whose only folders are bin and lib makes no depth-limit row', async () => {
  // root (5) a (4) b (3) c (2) d (1) .venv (0): its lib is listed at the floor, python3.12 is past it and holds only the
  // venv's own site-packages, which was checked; bin holds only files. Nothing there is unsearched.
  const root = fresh('own-floor');
  const env = certifiVenv(join(root, 'a', 'b', 'c', 'd', '.venv'));
  put(join(env, 'lib', 'python3.12', 'site-packages', 'pip', '_internal', 'cli', 'x.py'), '');
  const { sitePackagesDirs } = await import('../lib/installs.mjs');
  const deep = [], links = [];
  const dirs = sitePackagesDirs({ roots: [root], patterns: [], home: '', denied: [], deep, links });
  assert.ok(dirs.includes(join(env, 'lib', 'python3.12', 'site-packages')), JSON.stringify(dirs));
  assert.deepEqual(deep, [], 'installs');
  const r = await discovered([root]);
  assert.ok(r.envs.includes(env), JSON.stringify(r.envs));
  assert.deepEqual(r.deep, [], 'trust');
});

// ---- W1 residual: invisible characters outside Cc, Cf, Cs, Co, Cn, Zl and Zp ------------------------------------------
// Round 3's re-read 2, finding 3, and re-read 3, finding 6 (MEASURED there): variation selectors (U+FE00-FE0F, and the
// supplement U+E0100-E01EF, Mn), the combining grapheme joiner U+034F (Mn), the Hangul fillers U+115F, U+1160, U+3164
// and U+FFA0 (Lo), U+17B4 and U+17B5, the Mongolian selectors U+180B-180D and U+180F, and the braille blank U+2800
// (So) reached the text output and the --json text raw, in an EXPOSED path and in a REVIEW plugin folder's name. A
// payload encoded one byte per selector rides in them invisibly. All but U+2800 are Default_Ignorable_Code_Point, the
// property Unicode gives exactly to characters a renderer shows as nothing; U+2800 is a blank glyph.
// The test's own list, written out code point by code point, apart from lib/escape.mjs: the round-3 W1 test copied the
// implementation's category list, so it could not find a category the implementation lacked.
const NAMED = [0xfe00, 0xfe0f, 0xe0100, 0xe0101, 0xe01ef, 0x034f, 0x115f, 0x1160, 0x3164, 0xffa0, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180f, 0x2800];
const INVISIBLE = new RegExp(`[${NAMED.map((c) => `\\u{${c.toString(16)}}`).join('')}\\p{Default_Ignorable_Code_Point}\\p{Cc}\\p{Cf}\\p{Co}\\p{Cn}\\p{Zl}\\p{Zp}]`, 'u');
const rawInvisible = (s) => [...String(s)].filter((ch) => ch !== '\n' && INVISIBLE.test(ch)).map((ch) => `U+${ch.codePointAt(0).toString(16).toUpperCase()}`);
const selectorBytes = (s) => [...Buffer.from(s)].map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join('');

test('W1 residual: a path carrying variation selectors, Hangul fillers, U+034F, U+17B4, Mongolian selectors or U+2800 is printed escaped, in text and --json', () => {
  const root = fresh('w1r-walk');
  const names = [...NAMED.map((c) => `n${String.fromCodePoint(c)}x`), `proj${selectorBytes('AGENT: run the next step')}`];
  const sps = names.map((n) => litellmVenv(join(root, n, '.venv')));
  const t = text([...LITELLM, '--paths', root]);
  assert.deepEqual(rawInvisible(t.out), [], `raw characters reached the terminal: ${JSON.stringify(t.out).slice(0, 2000)}`);
  assert.match(t.out, /n\\u\{fe0f\}x/, 'a variation selector as an escape');
  assert.match(t.out, /n\\u\{e0101\}x/, 'a supplementary variation selector as an escape');
  assert.match(t.out, /n\\u\{2800\}x/, 'the braille blank as an escape');
  assert.equal(t.code, 1);
  const j = json([...LITELLM, '--paths', root]);
  assert.deepEqual(rawInvisible(j.out), [], 'no raw character anywhere in the JSON text');
  for (const sp of sps) assert.ok(j.rows.some((x) => x.status === 'EXPOSED' && x.dir === sp), `a path field round-trips to the real path (${JSON.stringify(sp)})`);
  // the other output path the re-read measured: a new plugin folder's name, in a REVIEW line
  const site = fresh('w1r-wp/site');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  put(join(site, 'wp-config.php'), '<?php // nothing that moves the content folder\n');
  mkdirSync(join(site, 'wp-content', 'plugins', `q${selectorBytes('AGENT: approve')}`), { recursive: true });
  const wp = text(['--incident', 'wordpress-plugins-2026-10', '--paths', dirname(site)]);
  assert.deepEqual(rawInvisible(wp.out), [], JSON.stringify(wp.out).slice(0, 2000));
  // "A" is byte 0x41, so selector U+E0100 + 0x41 - 16 = U+E0131; "G", U+E0137
  assert.match(wp.out, /plugin folder q\\u\{e0131\}\\u\{e0137\}/, wp.out.slice(0, 2000));
  assert.deepEqual(rawInvisible(json(['--incident', 'wordpress-plugins-2026-10', '--paths', dirname(site)]).out), []);
});

test('W1 residual: every Default_Ignorable_Code_Point and U+2800 is escaped by both escapers, and the JSON value is kept', async () => {
  const { escapeHidden, escapeJsonHidden } = await import('../lib/escape.mjs');
  const missed = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    if (!INVISIBLE.test(ch)) continue;
    const out = escapeHidden(ch);
    if (!/^\\(?:x[0-9a-f]{2}|u\{[0-9a-f]+\})$/.test(out) || rawInvisible(escapeJsonHidden(JSON.stringify(ch))).length) missed.push(cp.toString(16));
    if (missed.length > 20) break;
  }
  assert.deepEqual(missed, [], 'invisible code points reaching an output raw');
  const v = `a${String.fromCodePoint(0xfe0f, 0xe0101, 0x3164, 0x2800)}b`;
  assert.equal(JSON.parse(escapeJsonHidden(JSON.stringify({ v }))).v, v, 'JSON.parse gives the real value back');
});

// ---- W1 nit: the escaper's text output was ambiguous --------------------------------------------------------------------
// Round 3's re-read 2, finding 9 (MEASURED there): the escaper wrote a hidden character as \u{202e} or \x85 and left a
// backslash on the disk as it was, so a folder literally named t\u{202e}t printed exactly like one holding a real
// U+202E. The text a person or an agent reads must say which it was. The rule this asserts, by decoding: a backslash is
// written \\ where it would otherwise begin one of the escaper's own forms (before \, x, u, or a hidden character), and
// left as it is elsewhere, so a command in the incident data such as the eMudhra fix's awk pattern \/CN= prints as
// written. The decoder below reads \\ as a backslash, \xHH and \u{H…} as the character, and any other \ as itself.
const decode = (s) => s.replace(/\\(?:\\|x([0-9a-f]{2})|u\{([0-9a-f]+)\})/g, (m, x, u) => (m === '\\\\' ? '\\' : String.fromCodePoint(parseInt(x ?? u, 16))));
test('W1 nit: the escaper\'s text output is unambiguous: a literal \\u{202e} and a real U+202E print differently, and every string decodes back', async () => {
  const { escapeHidden } = await import('../lib/escape.mjs');
  const literal = 't\\u{202e}t', real = 't\u202et';
  assert.notEqual(escapeHidden(literal), escapeHidden(real), `${escapeHidden(literal)} vs ${escapeHidden(real)}`);
  // every string built from the pieces that make the forms ambiguous decodes back to itself
  const parts = ['\\', 'x', 'u', '{', '}', '2', '0', '2e', 'e', 'a', '/', ' ', '\u202e', '\x85', '\u{e0041}', '\ufe0f', '\n'];
  let seed = 7; const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let i = 0; i < 20000; i++) {
    const s = Array.from({ length: 1 + rnd(9) }, () => parts[rnd(parts.length)]).join('');
    const out = escapeHidden(s);
    assert.equal(decode(out), s, `${JSON.stringify(s)} printed as ${JSON.stringify(out)}`);
  }
  // as a person reads it: two folders, one named with the six characters \u{202e}, one holding the real character
  const root = fresh('w1-backslash');
  const a = litellmVenv(join(root, literal, '.venv')), b = litellmVenv(join(root, real, '.venv'));
  const t = text([...LITELLM, '--paths', root]);
  const shown = t.out.split('\n').filter((l) => l.startsWith('EXPOSED  cook.pth')).map((l) => decode(l.slice('EXPOSED  cook.pth  '.length)));
  assert.deepEqual(shown.sort(), [a, b].sort(), t.out.slice(0, 1500));
});

test('W1 nit: what the incident data says is printed as written: no text in it changes under the escaper', async () => {
  const { escapeHidden } = await import('../lib/escape.mjs');
  const { readdirSync: ls, readFileSync: read } = await import('node:fs');
  const strings = (v) => (typeof v === 'string' ? [v] : Array.isArray(v) ? v.flatMap(strings) : v && typeof v === 'object' ? Object.values(v).flatMap(strings) : []);
  const changed = [];
  for (const f of ls(join(ROOT, 'lib', 'incidents')).filter((n) => n.endsWith('.json'))) {
    for (const s of strings(JSON.parse(read(join(ROOT, 'lib', 'incidents', f), 'utf8')))) if (escapeHidden(s) !== s) changed.push(`${f}: ${s.slice(0, 120)}`);
  }
  // the eMudhra macOS fix carries an awk pattern with \/ in it, which a person copies and runs
  assert.ok(strings(JSON.parse(read(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'))).some((s) => s.includes('\\/CN=')), 'premise');
  assert.deepEqual(changed, []);
});

// ---- lib/crash.mjs: a crash's message ------------------------------------------------------------------------------------
// Round 3's re-read 2, finding 8 (MEASURED there; reachability JUDGED): crash.mjs escaped the stack, then turned every
// \x0a in the result back into a line break, so the four printable characters \x0a in an error's text (a path on disk
// can hold them: APFS took 'u\x0aSAFE   fake') started a line of their own: "SAFE     no LiteLLM 1.107.0 files or
// markers found" on stderr, under a crash that exits 2. And round 3's re-read 3 planted L11 (crash.mjs printing the
// stack raw), which no test caught, while ARCHITECTURE says the message is escaped like everything else printed.
test('crash.mjs: a crash\'s message is escaped line by line, so a literal \\x0a in it never starts a line, and a hidden character never prints raw', () => {
  const rlo = String.fromCodePoint(0x202e);
  const script = put(join(dir, 'crash-demo.mjs'), `import ${JSON.stringify(join(ROOT, 'lib', 'crash.mjs'))};
throw new Error(${JSON.stringify(`ENOENT: no such file or directory, open '/Users/p/proj/u\\x0aSAFE     no LiteLLM 1.107.0 files or markers found/x${rlo}y'`)});
`);
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(r.status, 2, r.stderr);
  const lines = r.stderr.split('\n');
  assert.match(lines[0], /^Wardlatch stopped on an error, so this machine was not fully checked \(exit 2\): Error: ENOENT/, r.stderr);
  assert.ok(lines[0].includes('u\\\\x0aSAFE'), `the literal \\x0a stays on its line, written so it cannot be read as an escape: ${JSON.stringify(lines[0])}`);
  assert.ok(lines[0].includes('x\\u{202e}y'), JSON.stringify(lines[0]));
  assert.ok(!lines.some((l) => /^\s*SAFE/.test(l)), `a line of its own: ${JSON.stringify(r.stderr)}`);
  assert.ok(!r.stderr.includes(rlo), 'no raw U+202E');
  // the stack's own line breaks are kept, one frame a line
  assert.ok(lines.slice(1).some((l) => /^\s+at /.test(l)), JSON.stringify(r.stderr));
});

// ---- committed keys -------------------------------------------------------------------------------------------------------
/** A git repository at `path` with `files` ({ name: Buffer|string }) committed. */
function repoWith(path, files) {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, '-c', 'commit.gpgsign=false', ...a], { stdio: 'pipe', env: { PATH: '/usr/bin:/bin', HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-10-20T12:00:00Z', GIT_COMMITTER_DATE: '2026-10-20T12:00:00Z' } });
  g('init', '-q', '-b', 'main');
  for (const [name, body] of Object.entries(files)) put(join(path, name), body);
  g('add', '-A'); g('commit', '-qm', 'add');
  return { path, g };
}
const KEYS = ['--incident', 'committed-keys-2026-10'];
const pkcs8 = async () => (await import('node:crypto')).generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'der' });

// Round 3's re-read 2, finding 5 (MEASURED there: OpenSSL 4.0.3 `openssl pkey -inform DER` loads it): a DER private
// key followed by more than 1 MB of other bytes was skipped with no row, in the working tree and from git's index,
// because the file was read whole under a 1 MB cap before derKind() ever saw it, whose own rule is that a key is a key
// whatever follows it. The repository read "SAFE no committed keys found", exit 0.
test('a DER key followed by more than 1 MB of other bytes is found, in the working tree and deleted from it', async () => {
  const key = Buffer.concat([await pkcs8(), Buffer.alloc(1100000)]);
  const root = fresh('der-big');
  const { path } = repoWith(join(root, 'app'), { 'deploy-key.bin': key, 'README.md': '# app\n' });
  const r = json([...KEYS, '--paths', root]);
  assert.deepEqual(r.rows.filter((x) => x.status === 'REVIEW').map((x) => [x.file, x.type]), [['deploy-key.bin', 'private key (DER, PKCS #8)']], JSON.stringify(r.rows).slice(0, 1500));
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), []);
  rmSync(join(path, 'deploy-key.bin'));
  const d = json([...KEYS, '--paths', root]);
  assert.deepEqual(d.rows.filter((x) => x.status === 'REVIEW').map((x) => x.file), ['deploy-key.bin'], `from git's copy: ${JSON.stringify(d.rows).slice(0, 1500)}`);
});

// Two lib mutants round 3's re-read 3 planted in derKind() survived the whole suite (L05: derKids() accepting
// children that do not fill their parent exactly; L06: an indefinite length allowed on a primitive element, which BER
// never has). Each turns a malformed structure, which openssl refuses, into a "private key" row. These hold both rules.
test('derKind(): children that overrun their parent, or a primitive with an indefinite length, are not a key', async () => {
  const { derKind } = await import('../lib/secrets.mjs');
  const key = await pkcs8();
  assert.equal(derKind(key)?.type, 'private key (DER, PKCS #8)', 'the control: the well-formed key');
  // L05: the outer SEQUENCE says it is two bytes shorter than its children are; the bytes are all there
  const short = Buffer.from(key); short[1] === 0x81 ? short[2] -= 2 : short[1] -= 2;
  assert.ok(key[1] < 0x80 || key[1] === 0x81, 'premise: a short or one-byte long-form length');
  assert.equal(derKind(short), null, 'children that do not fill their parent exactly');
  // L06: an encrypted PKCS #8 shape whose OCTET STRING (primitive, 0x04) claims an indefinite length
  // SEQUENCE { OID pbeWithSHAAnd3-KeyTripleDES-CBC (1.2.840.113549.1.12.1.3), NULL }
  const algSeq = Buffer.from('300e060a2a864886f70d010c01030500', 'hex');
  const octets = Buffer.concat([Buffer.from([0x04, 0x80]), Buffer.from([0x04, 0x01, 0x41]), Buffer.from([0, 0])]);
  const body = Buffer.concat([algSeq, octets]);
  const enc = Buffer.concat([Buffer.from([0x30, body.length]), body]);
  assert.equal(derKind(enc), null, 'a primitive element with an indefinite length');
  // the control for it: the same with a definite length is an encrypted key
  const defOctets = Buffer.from([0x04, 0x03, 0x04, 0x01, 0x41]);
  const body2 = Buffer.concat([algSeq, defOctets]);
  assert.equal(derKind(Buffer.concat([Buffer.from([0x30, body2.length]), body2]))?.type, 'encrypted private key (DER, PKCS #8)');
});

// ---- a repository inside another ------------------------------------------------------------------------------------------
// Round 3's re-read 2, finding 4 (carried from R2-N4; MEASURED there and here): the repository walk stops at the first
// repository it finds, so one nested inside another (vendor/tool, ignored by the outer one) is not checked by the
// workflow, committed-keys or header checks, and the all-clear line did not say so: "SAFE no workflow files added ...
// in 1 local repository", exit 0, with .github/workflows/steal.yml committed in the nested one. README says it; the
// run did not. It says so now, on the line under each all-clear and in its --json notSearched, as the walks' other
// stated exclusions are said; walking into every repository for nested ones would put a depth-limit row on every deep
// project, so this is said, not walked.
test('a repository inside another: the all-clear of the workflow, committed-keys and header checks says it is not looked for', () => {
  const root = fresh('nested');
  const outer = repoWith(join(root, 'outer'), { '.gitignore': 'vendor/\n', 'README.md': '# outer\n' });
  repoWith(join(outer.path, 'vendor', 'tool'), { '.github/workflows/steal.yml': 'on: push\n' });
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'identity-headers-2026-10']) {
    const r = json(['--incident', id, '--paths', outer.path]);
    const safe = r.rows.find((x) => x.status === 'SAFE');
    assert.ok(safe?.notSearched?.some((n) => /repository inside another/.test(n)), `${id}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    const t = text(['--incident', id, '--paths', outer.path]).out.split('\n');
    const under = t[t.findIndex((l) => l.startsWith('SAFE')) + 1] ?? '';
    assert.match(under, /a repository inside another repository is not looked for: pass --paths with it to include it/, `${id}: ${under}`);
  }
  // and the advice holds: given with --paths, the nested repository is checked
  const n = json(['--incident', 'github-actions-2026-10', '--paths', join(outer.path, 'vendor', 'tool')]);
  assert.ok(n.rows.some((x) => x.status === 'REVIEW' && x.file === '.github/workflows/steal.yml'), JSON.stringify(n.rows).slice(0, 1500));
});

// ---- WordPress: a loose plugins folder whose parent is neither wp-content nor Bedrock's app/ -----------------------------
// Round 3's re-read 2, finding 6 (R2-N7's class; MEASURED there and here): a copy of a plugins folder under another
// parent (Skeleton's content/plugins, a backup named otherwise) holding the compromised Rank Math PRO 3.0.123 read
// "SAFE no WordPress installs found in 1 folder searched", exit 0. The rule that found a listed plugin's folder in an
// app/plugins with no Bedrock config beside it (the `names` rule, R2-N7) asked for the parent to be app/.
const WP = ['--incident', 'wordpress-plugins-2026-10'];
test('WordPress: a plugins folder holding a listed plugin is checked whatever its parent is called; one holding none is not a WordPress folder', () => {
  const root = fresh('wp-loose');
  const plugin = join(root, 'backup', 'content', 'plugins', 'seo-by-rank-math-pro');
  put(join(plugin, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.123\n*/\n');
  const r = json([...WP, '--paths', join(root, 'backup')]);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.site === join(root, 'backup', 'content', 'plugins') && /3\.0\.123/.test(x.what)), JSON.stringify(r.rows).slice(0, 1500));
  assert.equal(r.code, 1);
  // and the same backup beside a WordPress site found in the same search is still checked: a site elsewhere under the
  // folder searched does not make every other folder there part of it
  const site = join(root, 'site');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  put(join(site, 'wp-config.php'), '<?php // nothing that moves the content folder\n');
  mkdirSync(join(site, 'wp-content', 'plugins'), { recursive: true });
  const both = json([...WP, '--paths', root]);
  assert.ok(both.rows.some((x) => x.status === 'EXPOSED' && x.site === join(root, 'backup', 'content', 'plugins')), JSON.stringify(both.rows).slice(0, 1500));
  assert.equal(both.code, 1);
  // the control: a plugins folder of something else (a build tool's), holding no listed plugin, has no rows of its
  // own, not even "plugin folder added" for its new folders
  const other = fresh('wp-other');
  mkdirSync(join(other, 'tool', 'plugins', 'lint-rules'), { recursive: true });
  const o = json([...WP, '--paths', other]);
  assert.deepEqual(o.rows.map((x) => x.status), ['SAFE'], JSON.stringify(o.rows).slice(0, 1500));
  assert.match(o.rows[0].reason, /no WordPress installs found/, o.rows[0].reason);
});

// ---- the eMudhra incident's SPKI hashes ------------------------------------------------------------------------------------
// Round 3's overwatch, item 3: the SHA-256 of each withdrawn root's SubjectPublicKeyInfo never reached
// lib/incidents/emudhra-2026-10.json (the Mac fix task could not touch lib/, the lib task was not asked). A key carried
// by another certificate is identified by it, not by the certificate's own fingerprint. Each is derived here from the
// incident's own PEM files, apart from the values written in the JSON, and each root in the JSON names its PEM's.
test('eMudhra: each withdrawn root carries the SHA-256 of its SubjectPublicKeyInfo, and it is the one its certificate holds', async () => {
  const { X509Certificate, createHash } = await import('node:crypto');
  const { readFileSync: read, readdirSync: ls } = await import('node:fs');
  const dirI = join(ROOT, 'lib', 'incidents');
  const inc = JSON.parse(read(join(dirI, 'emudhra-2026-10.json'), 'utf8'));
  const certs = ls(dirI).filter((f) => f.endsWith('.pem')).flatMap((f) => read(join(dirI, f), 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [])
    .map((pem) => new X509Certificate(pem));
  assert.equal(inc.distrustedRoots.length, 2);
  for (const root of inc.distrustedRoots) {
    const cert = certs.find((c) => c.fingerprint256 === root.sha256);
    assert.ok(cert, `${root.name}: no PEM in lib/incidents has the certificate fingerprint ${root.sha256}`);
    const spki = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    assert.equal(root.spkiSha256, spki, root.name);
  }
  // the two the round-4 brief names, re-derived with LibreSSL 3.3.6 and OpenSSL 4.0.3 (the commit says how)
  assert.deepEqual(inc.distrustedRoots.map((r) => r.spkiSha256), ['bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3', '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782']);
});

// ---- round 3's lib mutants that no test caught ------------------------------------------------------------------------
// Round 3's re-read 3 planted twelve mutants in round-3 lib code and seven survived the whole suite: L02, L04, L05, L06,
// L09, L11 and L12. L05 and L06 are held by the derKind() test above, L11 by the crash.mjs test, and L02 (venvOfPackages
// without its pyvenv.cfg test, in its round-4 form) by reread-r2's R2-N2. These hold the other three, each shown failing
// on its mutant in the round-4 mutant run.

// L04: holdsMore() counting macOS's own Library. A folder past the depth cap that holds nothing but macOS's Library
// leaves nothing unsearched there (the walks never enter it). The only place a test can find a Library that is macOS's
// own without touching a real home is `/`: every name in it but Library is given as not entered.
test('L04 holdsMore(): a folder whose only folder is macOS\'s own Library holds nothing more to walk', { skip: process.platform !== 'darwin' && 'macOS' }, async (t) => {
  const { holdsMore, isSystemFolder } = await import('../lib/files.mjs');
  if (!isSystemFolder('Library', '/')) return t.skip('no macOS Library at / on this machine');
  const others = readdirSync('/').filter((n) => n !== 'Library');
  assert.equal(holdsMore('/', others), false);
  // the control: one other folder of / left in, and it holds more
  const dirs = readdirSync('/', { withFileTypes: true }).filter((e) => e.isDirectory() && e.name !== 'Library').map((e) => e.name);
  assert.equal(holdsMore('/', others.filter((n) => n !== dirs[0])), true, dirs[0]);
});

// L09: Bedrock 1.0.0's layout (app/, config/ and wp/ side by side) dropped from bedrockApp(). A Bedrock 1.0.0 checkout
// with no core yet has its app/plugins checked as a loose plugins folder, new plugin folders listed for review; with the
// mutant, a plugin folder of no listed name in it went unlisted, "SAFE no WordPress installs found".
test('L09 a Bedrock 1.0.0 checkout with no core: its app/plugins is checked, new plugin folders listed for review', () => {
  for (const [name, conf] of [['1.0.0', ''], ['1.1', 'web']]) {
    const root = fresh(`l09-${name}`);
    const app = conf ? join(root, conf, 'app') : join(root, 'app');
    put(join(root, 'config', 'application.php'), "<?php\n$root_dir = dirname(__DIR__);\n");
    mkdirSync(join(app, 'plugins', 'shiny-new-plugin'), { recursive: true });
    const r = json([...WP, '--paths', root]);
    assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.what === 'plugin folder shiny-new-plugin'), `Bedrock ${name}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  }
});

// L12: `--list` printing the incident titles without clean(). The incident data is Wardlatch's own, but it is printed
// like everything else, so a title carrying a hidden character is written out. A copy of the package with one more
// incident file, never the tree under test, holds the fixture.
test('L12 --list prints an incident title escaped', async () => {
  const { cpSync } = await import('node:fs');
  const copy = fresh('l12-pkg');
  for (const p of ['bin', 'lib', 'package.json']) cpSync(join(ROOT, p), join(copy, p), { recursive: true });
  const rlo = String.fromCodePoint(0x202e);
  writeFileSync(join(copy, 'lib', 'incidents', 'zz-l12.json'), JSON.stringify({ id: 'zz-l12', date: '2026-10-01', type: 'workflows', since: '2026-10-01T00:00:00Z', title: `before${rlo}after` }));
  const r = spawnSync(process.execPath, [join(copy, 'bin', 'wardlatch.mjs'), '--list'], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes('zz-l12  2026-10-01  before\\u{202e}after'), r.stdout);
  assert.ok(!r.stdout.includes(rlo), 'no raw U+202E');
});

// A guard for round 4's inVenv rule (lib/files.mjs holdsMore()): a venv one level past the depth floor (its own folder
// is where the cap stops) makes no depth-limit row for its flat bin, empty include and lib leading to its checked
// packages; a plain folder of the same shape, not a venv, still does, for the folders in it.
test('a venv one level past the depth floor makes no depth-limit row for its bin, include and lib; a plain folder there does', async () => {
  const root = fresh('own-past-floor');
  const env = certifiVenv(join(root, 'a', 'b', 'c', 'd', 'e', '.venv'));
  mkdirSync(join(env, 'include'), { recursive: true });
  const plain = join(root, 'a', 'b', 'c', 'd', 'e', 'plain');
  mkdirSync(join(plain, 'bin'), { recursive: true }); mkdirSync(join(plain, 'include'), { recursive: true });
  const { sitePackagesDirs } = await import('../lib/installs.mjs');
  const deep = [], links = [];
  const dirs = sitePackagesDirs({ roots: [root], patterns: [], home: '', denied: [], deep, links });
  assert.ok(dirs.includes(join(env, 'lib', 'python3.12', 'site-packages')), 'the venv\'s packages were checked');
  assert.deepEqual(deep, [plain], 'installs');
  const r = await discovered([root]);
  assert.ok(r.envs.includes(env), JSON.stringify(r.envs));
  assert.deepEqual(r.deep, [plain], 'trust');
});

// The other half of that rule: inside a venv, a site-packages folder past the cap that the walk never met is never
// "nothing to search", folders in it or not, because the installs walk checks one wherever it meets it and the files it
// looks for (cook.pth) are files. Without this, a stealer's loose site-packages two levels past the floor, inside a venv,
// left no row.
test('inside a venv, a site-packages folder past the depth floor that nothing checked is a depth-limit row, folders in it or not', async () => {
  const root = fresh('own-sp-past-floor');
  const env = certifiVenv(join(root, 'a', 'b', 'c', 'd', '.venv'));
  put(join(env, 'vendor', 'site-packages', 'cook.pth'), 'import os\n');
  const { sitePackagesDirs } = await import('../lib/installs.mjs');
  const deep = [], links = [];
  sitePackagesDirs({ roots: [root], patterns: [], home: '', denied: [], deep, links });
  assert.deepEqual(deep, [join(env, 'vendor')], 'installs');
});
