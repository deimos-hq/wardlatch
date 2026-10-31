// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The independent read of fix/false-safes at da8f5c2 (31 Oct 2026): five readers with different lenses, then five
// refuters who re-ran every finding. Each test here stands in front of one confirmed finding, is named after it, and
// failed at da8f5c2 for the reason its name gives (or, for a test that could not fail before, fails on the mutant the
// refuter planted). Offline: no test reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const EPERM = join(ROOT, 'test', 'support', 'eperm-places.cjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-independent-read-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const spawnCli = (args, env = {}, nodeArgs = [], program = process.execPath, pre = []) => spawnSync(program, [...pre, ...(program === process.execPath ? [] : [process.execPath]), ...nodeArgs, BIN, ...args, '--json'],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
const parse = (r) => { let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 600)}`); } return { code: r.status, rows }; };
const run = (args, env = {}, nodeArgs = []) => parse(spawnCli(args, env, nodeArgs));
/** The CLI with `paths` refused with EPERM (test/support/eperm-places.cjs), stat still answering. */
const refused = (args, paths, env = {}) => run(args, { ...env, WARDLATCH_TEST_EPERM: JSON.stringify(paths) }, ['--require', EPERM]);
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

/** A virtual environment holding the LiteLLM 1.107.0 install record and its dropped cook.pth. */
function litellmVenv(path) {
  const sp = join(path, 'lib', 'python3.12', 'site-packages');
  put(join(path, 'pyvenv.cfg'), 'home = /usr/bin\n');
  put(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n');
  put(join(sp, 'cook.pth'), 'import os\n');
  return sp;
}
const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];

// ---- owner decision #32 (WV-2, claims F1, M6, WV-14, WV-8) -------------------------------------------------------------
// At da8f5c2 any EPERM on a folder whose mode would let the run in was read as "macOS is protecting it" and became a
// stated gap: a REVIEW line beside SAFE, exit 0. An unprivileged sandbox profile gives exactly that EPERM, and the
// refuter turned a real EXPOSED ×2, exit 1 into SAFE, exit 0 with one. The owner's decision, 31 Oct 2026: "Yes,
// UNKNOWN" — any folder Wardlatch could not open, EPERM included, is UNKNOWN with exit 2, never SAFE.
test('decision #32 (WV-2): a folder that refuses with EPERM is could-not-be-tested, exit 2, never a stated gap beside SAFE', () => {
  const root = fresh('d32-root'), hidden = join(root, 'hidden');
  litellmVenv(join(hidden, 'proj', '.venv'));
  // the control: readable, the stealer is found
  const open = run([...LITELLM, '--paths', root]);
  assert.equal(open.code, 1, `control: ${JSON.stringify(open.rows)}`);
  const r = refused([...LITELLM, '--paths', root], [hidden]);
  const row = r.rows.find((x) => x.path === hidden);
  assert.equal(row?.status, 'UNKNOWN', `the refused folder must be its own UNKNOWN row: ${JSON.stringify(r.rows)}`);
  assert.ok(!r.rows.some((x) => x.kind === 'skipped' && JSON.stringify(x).includes(hidden)), `never in the stated-gap line: ${JSON.stringify(r.rows)}`);
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], 'no all-clear beside a folder that was not searched');
  assert.equal(r.code, 2);
  // and for every check that walks folders
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const x = refused(['--incident', id, '--paths', root], [hidden]);
    assert.equal(x.rows.find((y) => y.path === hidden)?.status, 'UNKNOWN', `${id}: ${JSON.stringify(x.rows)}`);
    assert.equal(x.code, 2, id);
  }
});

test('decision #32 (WV-14, WV-8): the EPERM row says what was measured, and never claims to know macOS is protecting the folder', () => {
  const root = fresh('d32b-root'), hidden = fresh('d32b-root/hidden');
  chmodSync(hidden, 0o755);
  const r = refused(['--incident', 'github-actions-2026-10', '--paths', root], [hidden]);
  const row = r.rows.find((x) => x.path === hidden);
  assert.ok(row, JSON.stringify(r.rows));
  assert.equal(row.code, 'EPERM');
  assert.equal(row.basis, AS_ROOT ? `EPERM, mode 0755, owner ${row.basis.split('owner ')[1]}` : 'EPERM, mode 0755, owner you');
  assert.match(row.reason, /EPERM, mode 0755/, 'the basis a reader checks with one ls -ld, in the sentence too');
  // a sandbox gives this as well as macOS's privacy protection: the row may say what is common, never which it was
  assert.doesNotMatch(row.reason, /macOS is protecting|sudo cannot open|cannot be forged/, row.reason);
  assert.match(row.reason, /sandbox/, 'a sandbox around the run is named as a cause, since it is one');
  if (process.platform === 'darwin') assert.match(row.reason, /often[^.]*privacy protection[^.]*Full Disk Access[^.]*may lift/, row.reason);
  else assert.doesNotMatch(row.reason, /macOS|Full Disk Access/, `off macOS the row does not talk about macOS: ${row.reason}`);
  // a --paths folder that refuses is UNKNOWN with the same basis
  const direct = refused(['--incident', 'github-actions-2026-10', '--paths', hidden], [hidden]);
  assert.equal(direct.rows.find((x) => x.path === hidden)?.code, 'EPERM', JSON.stringify(direct.rows));
  assert.equal(direct.code, 2);
});

// The refuter's own reproduction, with the real mechanism: an unprivileged sandbox-exec profile. A sandbox cannot be
// applied inside another one, so this skips (and says why) when the suite itself runs in one.
test('decision #32: the refuter\'s LiteLLM case under a real unprivileged sandbox is UNKNOWN, exit 2, not SAFE, exit 0',
  { skip: process.platform !== 'darwin' && 'sandbox-exec is macOS\'s' }, (t) => {
    const root = fresh('d32c-root'), hidden = join(root, 'hidden');
    litellmVenv(join(hidden, 'proj', '.venv'));
    const profile = put(join(dir, 'd32c.sb'), `(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip "localhost:*"))\n(deny file-read-data (subpath ${JSON.stringify(hidden)}))\n`);
    const raw = spawnCli([...LITELLM, '--paths', root], {}, [], '/usr/bin/sandbox-exec', ['-f', profile]);
    if (/sandbox_apply/.test(raw.stderr)) return t.skip('a sandbox cannot be applied here (this run is already inside one)');
    const r = parse(raw);
    const row = r.rows.find((x) => x.path === hidden);
    assert.equal(row?.status, 'UNKNOWN', JSON.stringify(r.rows));
    assert.equal(row.code, 'EPERM');
    assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), []);
    assert.equal(r.code, 2);
  });

// ---- MUT-12: mandatoryRefusal()'s mode test could be deleted with no test failing --------------------------------------
// The refuter replaced its last line with `return true` and the whole suite stayed green: every test handed it EACCES,
// which returns before the mode is read. The mode test is what makes "its permission bits would let this run in" true
// when a row says it, so it is held here directly, class by class, and through the command. It also had a defect of
// its own: the others' bits counted for the folder's owner, whom DAC judges by the owner's bits alone, so a folder of
// mode 0005 its owner cannot list was said to be open to them (that case fails at da8f5c2).
test('MUT-12 mandatoryRefusal() reads the permission bits that apply to this user, and only for EPERM', { skip: AS_ROOT && 'root is never refused by DAC' }, async () => {
  const { mandatoryRefusal } = await import('../lib/files.mjs');
  const at = (name, mode) => { const d = fresh(`m12-${name}`); chmodSync(d, mode); locked.push(d); return d; };
  assert.equal(mandatoryRefusal(at('open', 0o755), 'EPERM'), true, 'owner r-x: the bits let this user in, so the EPERM came from above them');
  assert.equal(mandatoryRefusal(at('ownerrx', 0o500), 'EPERM'), true, 'owner r-x only');
  assert.equal(mandatoryRefusal(at('shut', 0o000), 'EPERM'), false, 'mode 0000: the bits alone shut it');
  assert.equal(mandatoryRefusal(at('noexec', 0o600), 'EPERM'), false, 'owner rw-: no search bit');
  assert.equal(mandatoryRefusal(at('others', 0o005), 'EPERM'), false, 'mode 0005: the others\' bits do not apply to the owner');
  assert.equal(mandatoryRefusal(at('eacces', 0o755), 'EACCES'), false, 'only EPERM is a refusal from above the bits');
  // and through the command: the clause is said only when it is true
  const root = fresh('m12-root'), shut = fresh('m12-root/shut'), open = fresh('m12-root/open');
  chmodSync(shut, 0o000); locked.push(shut);
  const r = refused(['--incident', 'github-actions-2026-10', '--paths', root], [shut, open]);
  assert.match(r.rows.find((x) => x.path === open)?.reason ?? '', /permission bits would let this run in/, JSON.stringify(r.rows));
  assert.doesNotMatch(r.rows.find((x) => x.path === shut)?.reason ?? 'missing', /permission bits would let this run in/, JSON.stringify(r.rows));
  assert.equal(r.rows.find((x) => x.path === shut)?.status, 'UNKNOWN');
});

// ---- WV-6: a path longer than the system takes read as "not there" ----------------------------------------------------
// lib/files.mjs put ENAMETOOLONG in GONE, so a folder whose full path is past PATH_MAX (1,024 bytes on macOS, 4,096 on
// Linux) read as absent and a site in it read SAFE with no row. The folders are built with relative mkdir and cd, as
// the refuter's longpath.sh did, since nothing opens them by their full path; and removed with rm, which walks relatively.
const PATH_MAX = process.platform === 'darwin' ? 1024 : 4096;
const NAME = 'n'.repeat(250);
/** Folders of 250-byte names below `base` until the path is past PATH_MAX; then `then` (a shell snippet) runs in the last
 *  one. → the deepest folder's absolute path (which nothing can open). */
const tooLong = (base, then = ':') => {
  const n = Math.ceil((PATH_MAX + 1 - base.length) / (NAME.length + 1));
  execFileSync('/bin/sh', ['-c', `cd "$1" && i=0 && while [ $i -lt ${n} ]; do mkdir "$2" && cd "$2" || exit 1; i=$((i+1)); done && ${then}`, 'sh', base, NAME], { stdio: 'pipe' });
  return { deep: join(base, ...Array(n).fill(NAME)), levels: n };
};
const rmTree = (p) => execFileSync('/bin/rm', ['-rf', p], { stdio: 'pipe' });

test('WV-6 a folder whose full path is too long to open is "denied" with its errno, never "gone"', async () => {
  const { listDir, pathState } = await import('../lib/files.mjs');
  const base = fresh('wv6-unit');
  const { deep } = tooLong(base);
  try {
    assert.ok(Buffer.byteLength(deep) > PATH_MAX, 'premise: the path is past PATH_MAX');
    assert.deepEqual(listDir(deep), { denied: true, code: 'ENAMETOOLONG' });
    assert.equal(pathState(deep), 'denied');
  } finally { rmTree(base); }
});

test('WV-6 a WordPress site in a folder whose path is too long is could-not-be-tested, exit 2, not SAFE',
  { skip: process.platform !== 'darwin' && 'only macOS\'s PATH_MAX (1,024) is reached within the walk\'s 5 levels' }, () => {
    const base = fresh('wv6-cli');
    const site = 'mkdir -p site/wp-includes site/wp-content/plugins/seo-by-rank-math-pro && echo \'<?php $wp_version = "6.7";\' > site/wp-includes/version.php && printf \'<?php\\n/*\\nPlugin Name: Rank Math PRO\\nVersion: 3.0.123\\n*/\\n\' > site/wp-content/plugins/seo-by-rank-math-pro/rank-math-pro.php';
    const { deep, levels } = tooLong(base, site);
    try {
      assert.ok(levels <= 5, `premise: within the WordPress walk's 5 levels (${levels})`);
      const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', base]);
      assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], `an all-clear over a site it could not open: ${JSON.stringify(r.rows).slice(0, 2000)}`);
      const row = unknowns(r).find((x) => x.code === 'ENAMETOOLONG');
      assert.ok(row && deep.startsWith(row.path), `the folder it could not open is its own row: ${JSON.stringify(r.rows).slice(0, 2000)}`);
      assert.match(row.reason, /longer than this system lets a program open/, row.reason);
      assert.doesNotMatch(row.reason, /sudo|Full Disk Access/, 'neither can open it');
      assert.equal(r.code, 2);
    } finally { rmTree(base); }
  });

// ---- WV-1: a venv, site-packages or plugins folder given directly with --paths was never examined ----------------------
// Each walker tested only the ENTRIES of a folder it walked, never the folder itself: `--paths <the venv>` read SAFE, exit
// 0, with the venv named in the receipt and litellm-1.107.0.dist-info inside it. That is also what the trust check's own
// advice for a linked venv ("Give it to --paths directly") led to.
/** A WordPress core with Rank Math PRO at `version` (3.0.123 is the backdoored release). */
function wpSite(root, version = '3.0.123') {
  put(join(root, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  put(join(root, 'wp-config.php'), '<?php // nothing that moves the content folder\n');
  put(join(root, 'wp-content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'), `<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: ${version}\n*/\n`);
  return root;
}
/** A venv with certifi, for the trust walk (lib/discover.mjs). */
function certifiVenv(root) {
  const sp = join(root, 'lib', 'python3.12', 'site-packages');
  put(join(root, 'bin', 'python'), 'not run by Wardlatch\n');
  put(join(root, 'pyvenv.cfg'), 'home = /usr\n');
  put(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERT' + 'IFICATE-----\nQUFB\n-----END CERT' + 'IFICATE-----\n');
  put(join(sp, 'certifi-2026.06.17.dist-info', 'METADATA'), 'Version: 2026.06.17\n');
  return root;
}

test('WV-1 a venv, its lib or its site-packages given with --paths is examined: the stealer is EXPOSED, exit 1', () => {
  const venv = join(fresh('wv1-proj'), '.venv');
  const sp = litellmVenv(venv);
  for (const given of [venv, join(venv, 'lib'), sp]) {
    const r = run([...LITELLM, '--paths', given]);
    assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.dir === sp), `--paths ${given}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 1, given);
  }
});

test('WV-1 the trust walk probes a venv given with --paths, or a link to one, rather than finding nothing', async () => {
  const { discover } = await import('../lib/discover.mjs');
  const env = certifiVenv(join(fresh('wv1-trust'), 'realenv'));
  const link = join(fresh('wv1-trust-link'), '.venv'); symlinkSync(env, link);
  for (const root of [env, link]) {
    const untested = [], links = [];
    const rts = discover({ roots: [root], pathEnv: fresh('wv1-no-programs'), untested, links });
    const mentioned = rts.some((x) => x.env === root) || untested.some((x) => x.fields?.env === root);
    assert.ok(mentioned, `--paths ${root}: the environment is neither probed nor reported: ${JSON.stringify({ rts, untested, links })}`);
  }
});

test('WV-1 a WordPress plugins folder, a wp-content folder or a plugin\'s own folder given with --paths is checked', () => {
  const site = wpSite(fresh('wv1-site'));
  const plugins = join(site, 'wp-content', 'plugins');
  for (const given of [plugins, join(site, 'wp-content'), join(plugins, 'seo-by-rank-math-pro')]) {
    const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', given]);
    assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /seo-by-rank-math-pro 3\.0\.123/.test(x.what)), `--paths ${given}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 1, given);
  }
  // and a clean one says what it checked, rather than "no WordPress installs found" alone
  const clean = wpSite(fresh('wv1-clean'), '3.0.124');
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(clean, 'wp-content', 'plugins')]);
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && /seo-by-rank-math-pro 3\.0\.124/.test(x.what)), JSON.stringify(r.rows));
});
