// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Round 4's strict audit, its swarm and its three re-reads (31 Oct 2026) all said NOT READY. Each test here stands in
// front of one of their findings about the virtual-environment walks, is named after it, and fails at 99a7f7d (the
// round-4 merge head) for the reason its name gives. Offline: no test here reaches a network host — the trust walk is
// exercised through lib/discover.mjs discover(), which reads files and starts nothing, never through the CLI's probes.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, mkdtempSync, rmSync, realpathSync, statSync, chmodSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
// lib/files.mjs is imported inside the tests, not at the top: isSiteName(), isLibName() and LIB_NAMES are this round's
// own, so a run of this file against the code of 99a7f7d (the red proof A2 asks for) must still load, and each test
// must fail for the reason its name gives rather than the whole file failing to import.
const files = () => import('../lib/files.mjs');

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-reread-r4-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => {
  // a test that takes the search bit off a folder puts it back, or the tree cannot be removed
  try { spawnSync('/bin/chmod', ['-R', 'u+rwX', dir]); } catch { /* best effort */ }
  rmSync(dir, { recursive: true, force: true });
});

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const text = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const json = (args, env = {}) => {
  const r = text([...args, '--json'], env);
  let rows; try { rows = JSON.parse(r.out).results; } catch { assert.fail(`not JSON (exit ${r.code}): ${r.err.slice(0, 600)}`); }
  return { ...r, rows };
};
const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];
const exposedIn = (r, sp) => r.rows.filter((x) => x.status === 'EXPOSED' && x.dir === sp).map((x) => x.what).sort();

/** A venv the installs check should find the LiteLLM 1.107.0 stealer in: → the package folder. */
function litellmVenv(root, pkgs = 'lib/python3.12/site-packages') {
  const sp = join(root, ...pkgs.split('/'));
  put(join(root, 'bin', 'python'), 'not run by Wardlatch\n');
  put(join(root, 'pyvenv.cfg'), 'home = /usr\nversion = 3.12.0\n');
  put(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n');
  put(join(sp, 'cook.pth'), 'import os\n');
  return sp;
}
/** A venv for the trust walk: bin/python, pyvenv.cfg and a certifi bundle in each of `pkgs`. */
function certifiVenv(root, pkgs = ['lib/python3.12/site-packages'], version = '2026.06.17') {
  put(join(root, 'bin', 'python'), 'not run by Wardlatch\n');
  put(join(root, 'pyvenv.cfg'), 'home = /usr\nversion = 3.12.0\n');
  for (const one of pkgs) {
    const sp = join(root, ...one.split('/'));
    put(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERT' + 'IFICATE-----\nQUFB\n-----END CERT' + 'IFICATE-----\n');
    put(join(sp, `certifi-${version}.dist-info`, 'METADATA'), `Version: ${version}\n`);
  }
  return root;
}
const discovered = async (roots) => {
  const { discover } = await import('../lib/discover.mjs');
  const untested = [], links = [], deep = [], denied = [], found = [];
  const rts = discover({ roots, pathEnv: fresh(`no-programs-${Math.random().toString(36).slice(2)}`), untested, links, deep, denied, found });
  return { untested, deep, links, found, denied, rts };
};
/** Every certifi bundle the trust walk would test (the --cacert argument of each curl row, and each untested row). */
const certifiBundles = (r) => [
  ...r.rts.filter((x) => x.certifi !== undefined).map((x) => x.args?.[1]).filter(Boolean),
  ...r.untested.filter((x) => x.fields?.certifi !== undefined).map((x) => x.fields.env),
];

/** Whether this volume opens a folder under another spelling of its name, as APFS does by default. */
const caseBlind = (() => {
  let v;
  return () => {
    if (v === undefined) {
      const d = fresh('case-probe');
      mkdirSync(join(d, 'Abc'));
      try { v = statSync(join(d, 'aBC')).isDirectory(); } catch { v = false; }
    }
    return v;
  };
})();

// ---- SN-1: a venv's package folder under a spelling the disk folds (round 4's swarm, BLOCKER) ------------------------
// 78d0dfc replaced expand('lib*/python3*/site-packages'), whose last segment the file system resolved, with a readdir
// scan comparing names exactly. On APFS (case-insensitive by default) CPython still loads `Site-Packages`,
// `SITE-PACKAGES`, `ſite-packages` (U+017F) and `site-pacKages` (U+212A) through the lib/python3.12/site-packages path
// it records, so the packages are live and Wardlatch stopped seeing them. MEASURED at 99a7f7d (venv-probe.sh, 1 Nov
// 2026): every one of those, and `Dist-Packages`, read `SAFE no LiteLLM 1.107.0 files or markers found`, exit 0, while
// `site-packages` and `dist-packages` read EXPOSED, exit 1.
const FOLDED = {
  'ASCII title case': 'Site-Packages',
  'ASCII upper case': 'SITE-PACKAGES',
  'U+017F LATIN SMALL LETTER LONG S': 'ſite-packages',
  'U+212A KELVIN SIGN': 'site-pacKages',
  'dist-packages in title case': 'Dist-Packages',
};
test('SN-1: a venv whose package folder is spelt in a way this disk folds is still searched (installs)', (t) => {
  if (!caseBlind()) return t.skip('this volume is case-sensitive, so Python would not load these spellings either');
  let i = 0;
  for (const [why, name] of Object.entries(FOLDED)) {
    const parent = fresh(`sn1-${i++}`);
    const sp = litellmVenv(join(parent, '.venv'), `lib/python3.12/${name}`);
    for (const given of [parent, join(parent, '.venv')]) {
      const r = json([...LITELLM, '--paths', given]);
      assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `${why} (${name}), --paths ${given}: exit ${r.code} ${JSON.stringify(r.rows).slice(0, 900)}`);
      assert.equal(r.code, 1, `${why}: exit code`);
    }
  }
});
test('SN-1: the trust walk tests the certifi of a venv whose package folder is spelt in a way this disk folds', async (t) => {
  if (!caseBlind()) return t.skip('this volume is case-sensitive, so Python would not load these spellings either');
  let i = 0;
  for (const [why, name] of Object.entries(FOLDED)) {
    const env = certifiVenv(join(fresh(`sn1t-${i++}`), '.venv'), [`lib/python3.12/${name}`]);
    for (const given of [dirname(env), env]) {
      const r = await discovered([given]);
      assert.equal(certifiBundles(r).length, 1, `${why} (${name}), ${given}: ${JSON.stringify({ rts: r.rts.map((x) => x.label), untested: r.untested.map((x) => x.label) })}`);
    }
  }
});
// The control for both: a spelling the disk does NOT fold must stay a folder of its own — checked by nothing as a
// venv's packages, and so WALKED like any folder. Without this, a fold table wide enough to pass the two tests above
// (NFKC, which the round-4 swarm proposed) would also take `ｓite-packages` for a venv's package folder, and a venv's
// package folder is never walked: everything inside it would stop being searched. MEASURED on this Mac (1 Nov 2026):
// stat('<d>/site-packages') does not open a folder named `ｓite-packages` (U+FF53) or `ﬆite-packages` (U+FB06).
const NOT_FOLDED = { 'U+FF53 FULLWIDTH LATIN SMALL LETTER S': 'ｓite-packages', 'U+FB06 LATIN SMALL LIGATURE ST': 'ﬆite-packages' };
test('SN-1 control: a spelling this disk does NOT fold is not a venv\'s package folder, so what is inside it is still searched', async () => {
  const { isSiteName } = await files();
  assert.equal(typeof isSiteName, 'function', 'lib/files.mjs exports no isSiteName, so no fold rule can be held to the disk\'s');
  let i = 0;
  for (const [why, name] of Object.entries(NOT_FOLDED)) {
    const d = fresh(`sn1c-${i}`);
    mkdirSync(join(d, name));
    if (!statSync(join(d, name)).isDirectory()) continue;
    let opens = false; try { opens = statSync(join(d, 'site-packages')).isDirectory(); } catch { opens = false; }
    assert.equal(opens, false, `${why}: this volume DOES fold it, so the premise of this control is wrong here`);
    assert.equal(isSiteName(name, d), false, `${why} (${name}): taken for a package folder, so its contents would stop being searched`);
    // and end to end: a stealer's venv inside such a folder, in a venv's lib, is still found
    const parent = fresh(`sn1ce-${i++}`);
    certifiVenv(join(parent, '.venv'), []);
    const sp = litellmVenv(join(parent, '.venv', 'lib', name, 'inner', '.venv'));
    const r = json([...LITELLM, '--paths', parent]);
    assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `${why}: ${JSON.stringify(r.rows).slice(0, 900)}`);
  }
});

// ---- B-78d-2: the lib folder's name (round 4's strict audit, BLOCKER) ------------------------------------------------
// LIB_NAME was /^lib/i, so `libs`, `library`, `libexec` and `lib-old` all counted as a venv's lib folder and a
// site-packages inside one was taken for the venv's own package folder: checked at its top and never walked
// (VENV_PACKAGES_SAID), so a stealer's venv at <project-venv>/libs/site-packages/inner/.venv read SAFE, exit 0, while
// the same tree under vendor/ read EXPOSED. MEASURED at 99a7f7d (venv-probe2.sh, 1 Nov 2026) for all four names. The
// receipt names only lib, lib64 and Lib, so the code and the receipt disagreed; this holds them to the receipt.
const NOT_LIB = ['libs', 'library', 'libexec', 'lib-old', 'libraries', 'vendor'];
test('B-78d-2: a folder merely beginning "lib" is not a venv\'s lib folder, so a venv inside it is still found', () => {
  for (const name of NOT_LIB) {
    const parent = fresh(`libn-${name}`);
    certifiVenv(join(parent, '.venv'), []);
    const sp = litellmVenv(join(parent, '.venv', name, 'site-packages', 'inner', '.venv'));
    const r = json([...LITELLM, '--paths', parent]);
    assert.deepEqual(exposedIn(r, sp), ['cook.pth', 'litellm-1.107.0.dist-info'], `${name}: exit ${r.code} ${JSON.stringify(r.rows).slice(0, 900)}`);
    assert.equal(r.code, 1, `${name}: exit code`);
  }
});
test('B-78d-2: the receipt names every folder the code takes for a venv\'s lib folder, and no other', async () => {
  const { LIB_NAMES, VENV_PACKAGES_SAID, isLibName, venvPackages, venvOfPackages } = await files();
  assert.ok(Array.isArray(LIB_NAMES) && typeof isLibName === 'function', 'lib/files.mjs exports no LIB_NAMES / isLibName, so the receipt and the match cannot be held to each other');
  const d = fresh('libname-unit');
  for (const name of [...LIB_NAMES, ...NOT_LIB, 'LIB', 'LIB64']) mkdirSync(join(d, name), { recursive: true });
  for (const name of LIB_NAMES) assert.equal(isLibName(name, d), true, `${name} is one of the three the receipt names`);
  for (const name of NOT_LIB) assert.equal(isLibName(name, d), false, `${name} is not named by the receipt: ${VENV_PACKAGES_SAID}`);
  // the receipt must say the three names, and that another spelling of them counts on a disk that folds it
  for (const name of LIB_NAMES) assert.ok(new RegExp(`\\b${name}\\b`).test(VENV_PACKAGES_SAID), `the receipt does not name ${name}: ${VENV_PACKAGES_SAID}`);
  assert.ok(/spelling this disk opens them by/.test(VENV_PACKAGES_SAID), `the receipt does not say that a spelling this disk folds counts: ${VENV_PACKAGES_SAID}`);
  // and the same folder under a spelling this disk folds IS one, because Python would load it
  if (caseBlind()) for (const name of ['LIB', 'LIB64']) assert.equal(isLibName(name, d), true, `${name}: this disk opens it as a lib folder, so Python loads it`);
  // venvOfPackages() reads the same rule backwards, and the two must agree. One venv per name: on a disk that folds
  // case, lib, Lib and lib64 inside ONE venv would not all be separate folders.
  let i = 0;
  for (const name of [...LIB_NAMES, ...NOT_LIB]) {
    const env = join(fresh(`libname-back-${i++}`), '.venv');
    certifiVenv(env, []);
    const sp = join(env, name, 'site-packages');
    mkdirSync(sp, { recursive: true });
    const want = LIB_NAMES.some((l) => l === name) || (caseBlind() && LIB_NAMES.some((l) => l.toLowerCase() === name.toLowerCase()));
    assert.equal(venvOfPackages(sp) === env, want, `${name}/site-packages: venvOfPackages disagrees with isLibName`);
    assert.equal(venvPackages(env).includes(sp), want, `${name}/site-packages: venvPackages disagrees with isLibName (${JSON.stringify(venvPackages(env))})`);
  }
});

// ---- B-78d-1: a folder we could not search is UNKNOWN, never SAFE (round 4's strict audit, BLOCKER) ------------------
// A folder that can be listed but not entered (mode 0444: read, no search) on the way to a venv's package folder was
// skipped in silence by venvPackages(): `pathState(...) !== 'dir'` could not tell a denied folder from a file. The
// installs walk happens to walk a venv's lib and lib/python3.12 itself and so reported them, but the TRUST walk reaches
// a venv's packages through venvPackages() alone. MEASURED at 99a7f7d (venv-probe2.sh, 1 Nov 2026): with lib or
// lib/python3.12 at 0444, the venv's certifi row vanished and no row took its place.
const UNSEARCHABLE = { 'the venv\'s lib': 'lib', 'the venv\'s lib/python3.12': join('lib', 'python3.12') };
test('B-78d-1: a folder on the way to a venv\'s packages that can be listed but not searched is a gap, not silence', async (t) => {
  if (AS_ROOT) return t.skip('root searches a folder whatever its mode');
  for (const [why, rel] of Object.entries(UNSEARCHABLE)) {
    const env = certifiVenv(join(fresh(`b78d1-${rel.replace(/\W/g, '_')}`), '.venv'));
    const shut = join(env, rel);
    // the control first: with the folder open, the bundle is found
    const open = await discovered([env]);
    assert.equal(certifiBundles(open).length, 1, `${why}: control, the bundle is not found even with the folder open`);
    chmodSync(shut, 0o444);
    try {
      const r = await discovered([env]);
      assert.ok(r.found.includes(shut) || r.found.some((p) => p.startsWith(shut)),
        `${why} (${shut}): not reported as a folder that could not be read: found=${JSON.stringify(r.found)} bundles=${JSON.stringify(certifiBundles(r))}`);
      assert.equal(certifiBundles(r).length, 0, `${why}: the bundle cannot have been read through a folder that cannot be searched`);
    } finally { chmodSync(shut, 0o755); }
  }
});
test('B-78d-1: the installs check says UNKNOWN, exit 2, for a venv behind a folder it could list but not search', (t) => {
  if (AS_ROOT) return t.skip('root searches a folder whatever its mode');
  for (const [why, rel] of Object.entries(UNSEARCHABLE)) {
    const parent = fresh(`b78d1i-${rel.replace(/\W/g, '_')}`);
    const env = join(parent, '.venv');
    litellmVenv(env);
    const shut = join(env, rel);
    chmodSync(shut, 0o444);
    try {
      for (const given of [parent, env]) {
        const r = json([...LITELLM, '--paths', given]);
        assert.equal(r.code, 2, `${why}, --paths ${given}: exit ${r.code}, wanted 2 (could not be tested): ${JSON.stringify(r.rows).slice(0, 900)}`);
        assert.ok(r.rows.some((x) => x.status === 'UNKNOWN'), `${why}, --paths ${given}: no UNKNOWN row`);
        assert.ok(!r.rows.some((x) => x.status === 'SAFE'), `${why}, --paths ${given}: an all-clear beside a folder that could not be searched`);
      }
    } finally { chmodSync(shut, 0o755); }
  }
});

// ---- SN-2: every certifi bundle in a venv, not the first in readdir order (round 4's swarm) --------------------------
// certifiIn() returned at the first package folder holding certifi/cacert.pem. `python3.12 -m venv --upgrade` leaves
// lib/python3.11 behind, and since 78d0dfc any folder one level below lib counts, so a leftover whose name sorts first
// wins: the bundle the venv's own python loads is tested by nothing and has no row. MEASURED at 99a7f7d
// (venv-probe2.sh, 1 Nov 2026): two bundles in one venv, one certifi row, whichever name came first.
test('SN-2: every certifi bundle in a virtual environment is tested, not only the first readdir returns', async () => {
  for (const other of ['python3.11', 'python3.13', 'a-leftover', 'zz-leftover']) {
    const env = certifiVenv(join(fresh(`sn2-${other}`), '.venv'), [`lib/python3.12/site-packages`, `lib/${other}/site-packages`]);
    const want = [join(env, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), join(env, 'lib', other, 'site-packages', 'certifi', 'cacert.pem')].sort();
    const r = await discovered([env]);
    assert.deepEqual(certifiBundles(r).sort(), want, `other=${other}: ${JSON.stringify({ rts: r.rts.map((x) => x.label), untested: r.untested.map((x) => x.label) })}`);
  }
});
test('SN-2: with more than one bundle each row names the package folder it came from, so the rows can be told apart', async () => {
  const env = certifiVenv(join(fresh('sn2-labels'), '.venv'), ['lib/python3.12/site-packages', 'lib/python3.11/site-packages']);
  const r = await discovered([env]);
  const labels = [...r.rts.filter((x) => x.certifi !== undefined).map((x) => x.label), ...r.untested.map((x) => x.label)];
  assert.equal(labels.length, 2, `two bundles, ${labels.length} row(s): ${JSON.stringify(labels)}`);
  assert.equal(new Set(labels).size, 2, `the two rows read alike, so one bundle looks like the other: ${JSON.stringify(labels)}`);
  for (const v of ['python3.12', 'python3.11']) assert.ok(labels.some((l) => l.includes(v)), `no row names ${v}: ${JSON.stringify(labels)}`);
});
// The completeness gate for SN-2: a venv with ONE bundle still reads as it always has, naming the environment, so the
// test above cannot pass by making every row name a package folder.
test('SN-2 control: a venv with one bundle still has one row, naming the environment', async () => {
  const env = certifiVenv(join(fresh('sn2-one'), '.venv'));
  const r = await discovered([env]);
  const labels = [...r.rts.filter((x) => x.certifi !== undefined).map((x) => x.label), ...r.untested.map((x) => x.label)];
  assert.equal(labels.length, 1, JSON.stringify(labels));
  assert.ok(labels[0].endsWith(env), `the row does not name the environment: ${labels[0]}`);
  assert.ok(!labels[0].includes(basename((await files()).SITE_NAMES[0])), `the row names a package folder where the venv has only one bundle: ${labels[0]}`);
});
