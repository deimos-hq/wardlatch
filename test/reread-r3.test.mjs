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
import { spawnSync } from 'node:child_process';
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
  assert.match(wp.out, /plugin folder q\\u\{fe01\}\\u\{e0131\}/, wp.out.slice(0, 2000));
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
