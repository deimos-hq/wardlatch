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
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, symlinkSync, readFileSync } from 'node:fs';
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

// ---- WV-3: a link counted as covered when its target was only LISTED, not walked ----------------------------------------
// unwalkedLinks() dropped a link whose target any walk had listed: at the depth floor (its subfolders never opened), or
// in the installs check's two-level quick look round the home folder. Both reopened AUDIT-8 (a LiteLLM venv below a
// linked folder, SAFE with exit 0), the first in the default run.
test('WV-3 the default run: ~/Development/x -> ~/clients, with the stealer in ~/clients/client/app/.venv, is not SAFE, exit 0', () => {
  const h = fresh('wv3-home');
  mkdirSync(join(h, 'Development'));
  litellmVenv(join(h, 'clients', 'client', 'app', '.venv'));
  symlinkSync(join(h, 'clients'), join(h, 'Development', 'x'));
  const r = run(LITELLM, { HOME: h });
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], `an all-clear over a link whose target was only listed: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.ok(unknowns(r).some((x) => x.path === join(h, 'Development', 'x')), `the link is a gap: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.notEqual(r.code, 0);
});

test('WV-3 a link to a folder listed only at the walk\'s depth floor is a gap: a site below it is not passed over', () => {
  const root = fresh('wv3-root');
  wpSite(join(root, 'a', 'b', 'c', 'd', 'e', 'site'));
  symlinkSync(join(root, 'a', 'b', 'c', 'd', 'e'), join(root, 'shortcut'));
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], `an all-clear with the site one link away: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.ok(unknowns(r).some((x) => x.path === join(root, 'shortcut')), JSON.stringify(r.rows).slice(0, 1500));
  assert.notEqual(r.code, 0);
  // the control the refuter used: through the link itself, it is EXPOSED
  assert.equal(run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(root, 'shortcut')]).code, 1);
});

// ---- WV-7: the walkers' depth caps were silent --------------------------------------------------------------------------
// Something one level past a walker's cap (5 levels for WordPress, venvs and the trust walk; 4 for repositories) read
// SAFE with no row, while the indicator search in the same file reports its own cap. A folder past the cap that holds
// more to walk is now one UNKNOWN row per check; one that holds only files is not (nothing a deeper walk would open).
test('WV-7 a site, a venv or a repository one level past the depth cap is could-not-be-tested, never a silent SAFE', () => {
  const w = fresh('wv7-wp');
  const site = wpSite(join(w, 'a', 'b', 'c', 'd', 'e', 'site'));
  const wr = run(['--incident', 'wordpress-plugins-2026-10', '--paths', w]);
  assert.deepEqual(wr.rows.filter((x) => x.status === 'SAFE'), [], `WordPress: ${JSON.stringify(wr.rows).slice(0, 1500)}`);
  assert.ok(unknowns(wr).some((x) => x.what === 'depth limit' && x.paths.includes(site)), JSON.stringify(wr.rows).slice(0, 1500));
  assert.equal(wr.code, 2);
  // the refuter's control: one level nearer, it is found
  assert.equal(run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(w, 'a')]).code, 1);

  const v = fresh('wv7-venv');
  litellmVenv(join(v, 'a', 'b', 'c', 'd', 'e', 'f', '.venv'));
  const vr = run([...LITELLM, '--paths', v]);
  assert.deepEqual(vr.rows.filter((x) => x.status === 'SAFE'), [], `LiteLLM: ${JSON.stringify(vr.rows).slice(0, 1500)}`);
  assert.ok(unknowns(vr).some((x) => x.what === 'depth limit'), JSON.stringify(vr.rows).slice(0, 1500));
  assert.equal(vr.code, 2);

  const g = fresh('wv7-git');
  mkdirSync(join(g, 'a', 'b', 'c', 'd', 'repo', '.git'), { recursive: true });
  const gr = run(['--incident', 'github-actions-2026-10', '--paths', g]);
  assert.deepEqual(gr.rows.filter((x) => x.status === 'SAFE'), [], `workflows: ${JSON.stringify(gr.rows).slice(0, 1500)}`);
  assert.ok(unknowns(gr).some((x) => x.what === 'depth limit' && x.paths.includes(join(g, 'a', 'b', 'c', 'd', 'repo'))), JSON.stringify(gr.rows).slice(0, 1500));
  assert.equal(gr.code, 2);
});

test('WV-7 a folder past the cap that holds only files is not a gap: nothing a deeper walk would open', () => {
  const w = fresh('wv7-leaf');
  put(join(w, 'a', 'b', 'c', 'd', 'e', 'leaf', 'notes.txt'), 'x');
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', w]);
  assert.equal(unknowns(r).length, 0, JSON.stringify(r.rows));
  assert.equal(r.code, 0);
});

// ---- WV-4: names hid whole trees, with no row, while the docs said no name decides a walk ------------------------------
// node_modules, .git, .venv and venv are still not walked (a node_modules tree is no place for a site and is huge), but
// they are no longer hidden: every all-clear that rests on a walk names them, in its sentence and in --json.
test('WV-4 every all-clear that rests on a walk names the folder names it never enters', () => {
  const root = fresh('wv4-root');
  wpSite(join(root, 'node_modules', 'site'));
  mkdirSync(join(root, 'venv', 'repo', '.git'), { recursive: true });
  litellmVenv(join(root, 'node_modules', 'pkg', '.venv'));
  for (const [id, names] of [['wordpress-plugins-2026-10', ['node_modules', '.git', '.venv']], ['github-actions-2026-10', ['node_modules', '.venv', 'venv']],
    ['committed-keys-2026-10', ['node_modules', '.venv', 'venv']], ['litellm-2026-10', ['node_modules', '.git']]]) {
    const r = run(['--incident', id, '--no-containers', '--paths', root]);
    const safe = r.rows.find((x) => x.status === 'SAFE');
    assert.ok(safe, `${id}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    for (const n of names) assert.ok(safe.notSearched?.includes(n), `${id}: the receipt must name ${n}: ${JSON.stringify(safe)}`);
    // and the line under the all-clear a reader is given says so
    const text = spawnSync(process.execPath, [BIN, '--incident', id, '--no-containers', '--paths', root], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C' }, cwd: dir, timeout: 180000 }).stdout;
    const under = text.split('\n')[text.split('\n').findIndex((l) => l.startsWith('SAFE')) + 1] ?? '';
    for (const n of names) assert.ok(under.includes(n), `${id}: the line under the all-clear must name ${n}: ${JSON.stringify(under)}`);
    assert.match(under, /are not searched/, under);
  }
});

// ---- WV-5: the trust walk dropped a link to a folder that holds environments --------------------------------------------
// discover() reported a declined link only when its name or contents looked like an environment, and the command never
// read the `links` it filled: ~/Development/work -> /Volumes/Work, with app/.venv in it, had no row of any kind.
/** A stand-in loaded into the command for the trust check: no network, and no program run but this Node. */
const offline = () => put(join(dir, 'offline.cjs'), `'use strict';
const tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), { EventEmitter } = require('node:events');
tls.connect = (...a) => { const s = new EventEmitter(); s.end = s.destroy = () => s; process.nextTick(() => s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
require('node:module').syncBuiltinESMExports();
`);

test('WV-5 the trust check reports a link to a folder holding environments, as it does a linked environment', async () => {
  const d = fresh('wv5');
  certifiVenv(join(d, 'volume', 'app', '.venv'));
  const root = fresh('wv5/root');
  symlinkSync(join(d, 'volume'), join(root, 'work'));
  certifiVenv(join(root, 'x', '.venv'));
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], { PATH: fresh('wv5-empty-path') }, ['--require', offline()]);
  assert.ok(unknowns(r).some((x) => x.path === join(root, 'work')), `the link is a gap: ${JSON.stringify(r.rows).slice(0, 2000)}`);
  // and a link that looks like an environment is still reported once, as an untested environment, not twice
  const { discover } = await import('../lib/discover.mjs');
  const e = fresh('wv5-env');
  certifiVenv(join(e, 'elsewhere', 'venv'));
  const er = fresh('wv5-env/root');
  symlinkSync(join(e, 'elsewhere', 'venv'), join(er, '.venv'));
  const links = [], untested = [];
  discover({ roots: [er], pathEnv: fresh('wv5-no-programs'), links, untested });
  assert.deepEqual([untested.map((x) => x.fields.env), links], [[join(er, '.venv')], []]);
});

// ---- a committed DER private key under any name was skipped with no row --------------------------------------------------
// Every binary file was skipped, and only a binary file whose name says text was reported. A repository holding
// deploy-key.der (`openssl rsa -outform der`) read "SAFE no committed keys found ... in 1 local repository".
/** A git repository at `path` with `files` ({ name: Buffer|string }) committed. */
function repoWith(path, files) {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, '-c', 'commit.gpgsign=false', ...a], { stdio: 'pipe', env: { PATH: '/usr/bin:/bin', HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' } });
  g('init', '-q', '-b', 'main');
  for (const [name, body] of Object.entries(files)) put(join(path, name), body);
  g('add', '-A'); g('commit', '-qm', 'add');
  return path;
}
const KEYS = '--incident committed-keys-2026-10'.split(' ');

test('a committed private key in DER is found whatever its name: PKCS #1, PKCS #8, encrypted PKCS #8, SEC1 EC', async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  const files = {
    'deploy-key.der': rsa.export({ type: 'pkcs1', format: 'der' }),
    'ci/signing.bin': rsa.export({ type: 'pkcs8', format: 'der' }),
    'secrets/vault': rsa.export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: 'not-a-real-passphrase' }),
    'certs/ec.key': ec.export({ type: 'sec1', format: 'der' }),
    'README.md': '# app\n',
  };
  const root = fresh('der-keys');
  repoWith(join(root, 'app'), files);
  const r = run([...KEYS, '--paths', root]);
  const found = r.rows.filter((x) => x.status === 'REVIEW').map((x) => x.file).sort();
  assert.deepEqual(found, Object.keys(files).filter((f) => f !== 'README.md').sort(), JSON.stringify(r.rows).slice(0, 2000));
  assert.ok(r.rows.filter((x) => x.status === 'REVIEW').every((x) => /private key/.test(x.type) && !x.masked.includes('MII')), 'a type, never the key');
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), []);
});

// ---- WV-12: a DER certificate was UNKNOWN, "named as a text file but reads as binary" -----------------------------------
// DER is a standard encoding for a .crt or a .pem; a repository with a DER fixture exited 2 for ever, and the sentence was
// untrue. A certificate is no secret: no row. A binary file under a text name that is not a DER key or certificate stays
// UNKNOWN, with a sentence that is true.
test('WV-12 a DER certificate named .crt or .pem is not a gap; other binary under a text name still is, truly worded', () => {
  const pem = readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10-root-aaa.pem'), 'utf8');
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const root = fresh('wv12');
  repoWith(join(root, 'app'), { 'certs/root-ca.crt': der, 'certs/root-ca.pem': der, 'README.md': '# app\n' });
  const r = run([...KEYS, '--paths', root]);
  assert.deepEqual(unknowns(r), [], `a DER certificate is neither a secret nor a gap: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.equal(r.code, 0);
  // the guard: a binary file under a text name that is no DER key or certificate is still could-not-be-tested
  const other = fresh('wv12-other');
  repoWith(join(other, 'app'), { 'config.yml': Buffer.from('#\0hidden: below a NUL\n') });
  const o = run([...KEYS, '--paths', other]);
  const row = unknowns(o).find((x) => x.file === 'config.yml');
  assert.ok(row, JSON.stringify(o.rows));
  assert.doesNotMatch(row.reason, /named as a text file/, row.reason);
  assert.equal(o.code, 2);
});

// ---- WV-9: a link to a repository or venv the same walk found and checked was UNKNOWN -----------------------------------
// reposUnder() and discover() never recorded a found repository or environment as walked, so a link to one (current ->
// proj, .venv -> app/.venv) was UNKNOWN beside its own clean row, and the printed advice (--paths it) changed nothing.
test('WV-9 a link to a repository or an environment the same walk checked is not a gap', async () => {
  const root = fresh('wv9');
  repoWith(join(root, 'proj'), { 'README.md': '# proj\n' });
  symlinkSync(join(root, 'proj'), join(root, 'current'));
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10']) {
    for (const paths of [[root], [root, join(root, 'proj')]]) {
      const r = run(['--incident', id, ...paths.flatMap((p) => ['--paths', p])]);
      assert.deepEqual(unknowns(r), [], `${id} ${paths.length} paths: ${JSON.stringify(r.rows).slice(0, 1500)}`);
      assert.equal(r.code, 0, id);
    }
  }
  const { discover } = await import('../lib/discover.mjs');
  const t = fresh('wv9-trust');
  certifiVenv(join(t, 'app', '.venv'));
  symlinkSync(join(t, 'app', '.venv'), join(t, '.venv'));
  const untested = [], links = [];
  const rts = discover({ roots: [t], pathEnv: fresh('wv9-no-programs'), untested, links });
  assert.ok(rts.some((x) => x.env === join(t, 'app', '.venv')), 'premise: the environment is probed');
  assert.deepEqual([untested, links], [[], []], 'and the link to it is no gap');
});

// ---- WV-10: the header check put every link into the "could not be opened ... run with sudo" channel --------------------
// lib/headers.mjs called reposUnder() without `links`, so links fell back into `denied`: a link to a readable folder was
// "could not be opened ... run Wardlatch with sudo", and a link to a folder root owns rode in the REVIEW line beside SAFE,
// exit 0, while every other check makes a link it did not follow UNKNOWN.
test('WV-10 the header check reports a link it did not follow as a link, never as a folder it could not open', () => {
  const root = fresh('wv10'), mine = fresh('wv10-target');
  mkdirSync(join(root, 'projects'));
  symlinkSync(mine, join(root, 'projects', 'shared'));
  symlinkSync('/usr', join(root, 'projects', 'system'));   // a folder root owns
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', root]);
  for (const name of ['shared', 'system']) {
    const row = unknowns(r).find((x) => x.path === join(root, 'projects', name));
    assert.ok(row, `${name}: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.match(row.reason, /is a link to a folder somewhere else, so it was not followed/, row.reason);
    assert.doesNotMatch(row.reason, /could not be opened|sudo|Full Disk Access/, row.reason);
  }
  assert.ok(!r.rows.some((x) => x.kind === 'skipped'), `no link in the stated-gap line: ${JSON.stringify(r.rows).slice(0, 1500)}`);
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), []);
  assert.equal(r.code, 2);
});

// ---- WV-11: every clean Rank Math PRO install read UNKNOWN for the indicator search -------------------------------------
// Ordinary plugin files (readme.txt, a .pot, .json files, LICENSE) were neither CODE nor INERT, so each was "not searched",
// and every clean site exited 2 for ever. They are read and searched now: more reading, never less.
test('WV-11 a plugin\'s readme.txt, .pot, .json and LICENSE are searched for the indicator, not reported as unsearched', async () => {
  const { checkSite } = await import('../lib/wordpress.mjs');
  const site = wpSite(fresh('wv11-site'), '3.0.124');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  put(join(plugin, 'readme.txt'), '=== Rank Math PRO ===\n'); put(join(plugin, 'languages', 'rank-math-pro.pot'), 'msgid ""\n');
  put(join(plugin, 'assets', 'block.json'), '{"name":"x"}\n'); put(join(plugin, 'LICENSE'), 'GPL\n');
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', site]);
  assert.deepEqual(unknowns(r), [], JSON.stringify(r.rows).slice(0, 1500));
  assert.equal(r.code, 0);
  // and they are really read: the indicator in one of them is found
  const rules = [{ plugin: 'seo-by-rank-math-pro', mainFile: 'rank-math-pro.php', bad: ['3.0.123'], indicator: 'rank1cdn', fix: 'x' }];
  put(join(plugin, 'assets', 'block.json'), '{"src":"https://rank1cdn.example/x.js"}\n');
  assert.ok(checkSite(site, rules).some((f) => f.status === 'EXPOSED' && /block\.json/.test(f.what)), JSON.stringify(checkSite(site, rules)));
});

// ---- WV-13: the home folder's quick look reported every link it declined ------------------------------------------------
// The installs check's quick look round the home folder (two levels, best effort) says nothing about a folder it cannot
// open, by design, but it made every link it declined an UNKNOWN row: ~/OneDrive -> ~/Library/CloudStorage/... made every
// LiteLLM run exit 2, even one whose --paths named a different folder. The links below the searched folders still are.
test('WV-13 a link the home folder\'s quick look declines is not a gap; one below a searched folder still is', () => {
  const h = fresh('wv13-home'), away = fresh('wv13-elsewhere');
  mkdirSync(join(h, 'Library', 'CloudStorage', 'OneDrive-Personal'), { recursive: true });
  symlinkSync(join(h, 'Library', 'CloudStorage', 'OneDrive-Personal'), join(h, 'OneDrive'));
  mkdirSync(join(h, 'proj'));
  symlinkSync(away, join(h, 'proj', 'shared'));
  const r = run([...LITELLM, '--paths', fresh('wv13-empty')], { HOME: h });
  assert.deepEqual(unknowns(r), [], JSON.stringify(r.rows).slice(0, 1500));
  assert.equal(r.code, 0);
  // the same link below a folder given with --paths is reported
  const s = run([...LITELLM, '--paths', join(h, 'proj')], { HOME: h });
  assert.ok(unknowns(s).some((x) => x.path === join(h, 'proj', 'shared')), JSON.stringify(s.rows).slice(0, 1500));
});

// ---- M2 / WV-18: errno-mechanisms.mjs exited 0 without measuring, and counted a failed setup as a claim that holds -------
// Its exit code was the pass condition, yet a run that measured no folder macOS protects exited 0, and its ACL and
// chflags claims "held" when chmod +a or chflags could not run (`d === null ||`). Now a claim that could not be
// measured is UNMEASURED, said apart from one that holds, and the run exits 2: nothing broke, and not everything was
// confirmed. Run here with a home of the test's own (so no folder macOS protects is there to measure) and, on macOS,
// with no program on PATH (so chmod +a, chflags and id cannot run).
test('M2 errno-mechanisms.mjs exits non-zero when it could not measure, and never counts a failed setup as holding', () => {
  const script = join(ROOT, 'test', 'support', 'errno-mechanisms.mjs');
  const h = fresh('m2-home');
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', env: { HOME: h, PATH: '/usr/bin:/bin', LANG: 'C' }, cwd: dir, timeout: 120000 });
  assert.notEqual(r.status, 0, `the TCC half was not measured, so the run must not exit 0:\n${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /UNMEASURED +the TCC half/, r.stdout);
  if (process.platform !== 'darwin' || AS_ROOT) return;
  const bare = spawnSync(process.execPath, [script], { encoding: 'utf8', env: { HOME: h, PATH: fresh('m2-no-programs'), LANG: 'C' }, cwd: dir, timeout: 120000 });
  assert.notEqual(bare.status, 0, `${bare.stdout}${bare.stderr}`);
  for (const what of ['a deny ACL gives EACCES', 'chflags uchg', 'chflags hidden', 'chflags opaque']) {
    assert.doesNotMatch(bare.stdout, new RegExp(`HOLDS x2 +${what}`), `${what}: nothing was applied, so nothing holds:\n${bare.stdout}`);
    assert.match(bare.stdout, new RegExp(`UNMEASURED +${what}`), `${what}:\n${bare.stdout}`);
  }
});

// ---- MUT-8: a stale PATH entry could turn an all-clear into "UNKNOWN internal error" with no test failing ---------------
// findAllOnPath() puts a PATH folder in the receipt only when it is there. The refuter dropped that filter and the whole
// suite stayed green, while a run with a PATH entry that no longer exists (an ordinary leftover) read "UNKNOWN internal
// error: an all-clear that names /no/such/stale/entry ... please report this", exit 2. This holds the filter.
test('MUT-8 a PATH entry that is not there does not withdraw the "not found on PATH" all-clear', () => {
  const stale = join(dir, 'no', 'such', 'stale', 'entry'), real = fresh('mut8-bin');
  const r = run(['--incident', 'ovhcloud-cli-2026-10', '--no-containers', '--paths', fresh('mut8-root')], { PATH: `${real}:${stale}` });
  const safe = r.rows.find((x) => x.kind === 'binary');
  assert.equal(safe?.status, 'SAFE', JSON.stringify(r.rows));
  assert.ok(safe.searched.includes(real), `the PATH folder that is there is in the receipt: ${JSON.stringify(safe.searched)}`);
  assert.ok(!safe.searched.includes(stale), `the one that is not there is not: ${JSON.stringify(safe.searched)}`);
  assert.equal(r.code, 0);
});
