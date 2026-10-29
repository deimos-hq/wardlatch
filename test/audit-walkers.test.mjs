// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026. Every directory walk in lib/ decides for itself what it will not enter, and none of them
// records what it declined. Two kinds of folder are stepped over in silence:
//   - a folder reached through a symbolic link (lib/discover.mjs:82, lib/wordpress.mjs:121, lib/workflows.mjs:24, and
//     below the first level in lib/installs.mjs:140);
//   - a folder named .Trash, .Trashes, Photo Booth Library or *.photoslibrary, wherever it is and on any platform
//     (lib/files.mjs:161).
// Neither lands in `denied`, `found` or `review`, so bin/wardlatch.mjs gaps() says nothing and the run reads SAFE with
// a receipt naming the folder it walked past. The receipt rule cannot catch it: the folder in the receipt exists.
// These tests fail on 0.1.10. Each one names what it proves.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../lib/discover.mjs';
import { sitePackagesDirs } from '../lib/installs.mjs';
import { wordpressUnder } from '../lib/wordpress.mjs';
import { reposUnder } from '../lib/workflows.mjs';
import { isSystemFolder } from '../lib/files.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-walk-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-audit-walk-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

/** The CLI, offline, with the tests' own home and a bare PATH. */
const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

/** A WordPress core with the backdoored Rank Math PRO 3.0.123 in it. */
function wpSite(root) {
  mkdirSync(join(root, 'wp-includes'), { recursive: true });
  writeFileSync(join(root, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  writeFileSync(join(root, 'wp-config.php'), '<?php // nothing that moves the content folder\n');
  const p = join(root, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  mkdirSync(p, { recursive: true });
  writeFileSync(join(p, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.123\n*/\n');
  return root;
}

/** A Python virtual environment, with certifi and (when asked) the LiteLLM 1.107.0 install record. */
function venv(root, { litellm = false } = {}) {
  const sp = join(root, 'lib', 'python3.12', 'site-packages');
  mkdirSync(join(sp, 'certifi'), { recursive: true });
  mkdirSync(join(sp, 'certifi-2026.06.17.dist-info'), { recursive: true });
  mkdirSync(join(root, 'bin'), { recursive: true });
  writeFileSync(join(root, 'bin', 'python'), 'not run by Wardlatch\n');
  writeFileSync(join(root, 'pyvenv.cfg'), 'home = /usr\n');
  writeFileSync(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERT' + 'IFICATE-----\nQUFB\n-----END CERT' + 'IFICATE-----\n');
  writeFileSync(join(sp, 'certifi-2026.06.17.dist-info', 'METADATA'), 'Version: 2026.06.17\n');
  if (litellm) { mkdirSync(join(sp, 'litellm-1.107.0.dist-info'), { recursive: true }); writeFileSync(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Version: 1.107.0\n'); }
  return root;
}

/** A git repository with an AWS access key in a tracked file. */
function keyRepo(path) {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env: { ...process.env, HOME: home, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q');
  writeFileSync(join(path, 'deploy.sh'), `AWS_ACCESS_KEY_ID=${'AKIA'}Q1W2E3R4T5Y6U7I8\n`);
  g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add');
  return path;
}

test('AUDIT-1 the trust check never sees a virtual environment reached through a link, and records no gap for it (the installs check sees the same one)', () => {
  const d = join(dir, 'a1');
  venv(join(d, 'elsewhere', 'venv'));
  const root = join(d, 'root');
  mkdirSync(join(root, 'app'), { recursive: true });
  symlinkSync(join(d, 'elsewhere', 'venv'), join(root, 'app', '.venv'));
  // the control: a plain virtual environment beside it
  venv(join(root, 'app2', '.venv'));

  const denied = [], found = [], notRun = [], untested = [];
  const rts = discover({ roots: [root], pathEnv: join(d, 'no-programs-here'), denied, found, notRun, untested });
  const mentioned = JSON.stringify([rts, denied, found, untested]);
  assert.ok(mentioned.includes(join(root, 'app2', '.venv')), 'the plain virtual environment is mentioned somewhere');
  // the installs check finds the linked one, so the trust check cannot call it absent
  assert.ok(sitePackagesDirs({ roots: [root], home: '', patterns: [] }).includes(join(root, 'app', '.venv', 'lib', 'python3.12', 'site-packages')),
    'the installs check does see the linked virtual environment');
  assert.ok(mentioned.includes(join(root, 'app', '.venv')),
    'the linked virtual environment, whose certifi bundle was not tested, is nowhere in discover()\'s rows or its denied, found and untested lists');
});

test('AUDIT-2 a virtual environment two levels under a linked folder is invisible to the installs check too, with no gap recorded', () => {
  const d = join(dir, 'a2');
  venv(join(d, 'volume', 'app', '.venv'), { litellm: true });
  const root = join(d, 'root');
  mkdirSync(root, { recursive: true });
  symlinkSync(join(d, 'volume'), join(root, 'work'));        // ~/Development/work -> /Volumes/Work
  const denied = [], found = [];
  const dirs = sitePackagesDirs({ roots: [root], home: '', patterns: [], denied, found });
  // either searched, or recorded as not searched: lib/installs.mjs:140 does neither (its first level of link is
  // followed, which is why AUDIT-1's own .venv is found and this one, one level deeper, is not)
  assert.ok(dirs.length || denied.length || found.length,
    `LiteLLM 1.107.0 is installed below the link, and the folder it is in was neither searched nor reported as unsearched: ${JSON.stringify({ dirs, denied, found })}`);
});

test('AUDIT-3 a WordPress site linked into a web root is invisible, and records no gap', () => {
  const d = join(dir, 'a3');
  wpSite(join(d, 'sites', 'example.com'));
  const root = join(d, 'webroot');
  mkdirSync(root, { recursive: true });
  symlinkSync(join(d, 'sites', 'example.com'), join(root, 'html'));   // /var/www/html -> /srv/sites/example.com
  const denied = [], privateDot = [], coreOnly = [];
  const sites = wordpressUnder([root], 5, denied, privateDot, coreOnly);
  // either found, or recorded as not searched: lib/wordpress.mjs:121 does neither
  assert.ok(sites.length || denied.length || privateDot.length || coreOnly.length,
    `the site below the link was neither found nor reported as unsearched: ${JSON.stringify({ sites, denied, privateDot, coreOnly })}`);
});

test('AUDIT-4 a repository linked in, or under a dot-folder, is invisible to the key scan and the workflow review, and records no gap', () => {
  const d = join(dir, 'a4');
  keyRepo(join(d, 'elsewhere', 'app'));
  const linked = join(d, 'linked');
  mkdirSync(linked, { recursive: true });
  symlinkSync(join(d, 'elsewhere', 'app'), join(linked, 'app'));
  const dotted = join(d, 'dotted');
  keyRepo(join(dotted, '.worktrees', 'app'));

  for (const [what, root] of [['linked in', linked], ['under a dot-folder', dotted]]) {
    const denied = [];
    const repos = reposUnder([root], 4, denied);
    // either read, or recorded as not read: lib/workflows.mjs:24 does neither
    assert.ok(repos.length || denied.length, `${what}: the repository was neither read nor reported as unread: ${JSON.stringify({ repos, denied })}`);
  }
});

test('AUDIT-5 .Trash, .Trashes and *.photoslibrary are skipped under ANY parent, unlike Library, which is gated on its place', () => {
  // the Library rule is gated: only at /, in /System, in a home folder or /var/root, and only with macOS's own
  // folders inside it, so a project folder called Library is still searched. These four names have no gate at all,
  // so `mkdir .Trashes` in a web root or a project is a hiding place from every walk, on any platform.
  assert.equal(isSystemFolder('Library', '/var/www'), false, 'premise: Library is gated on its parent');
  for (const name of ['.Trash', '.Trashes', 'Photo Booth Library', 'anything.photoslibrary']) {
    assert.equal(isSystemFolder(name, '/var/www'), false, `${name} under a web root is not where macOS keeps one`);
    assert.equal(isSystemFolder(name, '/srv/app/wp-content'), false, `${name} inside a site's content folder is not where macOS keeps one`);
  }
});

test('AUDIT-6 a WordPress site inside a folder called .Trashes reads SAFE, exit 0, with the backdoored plugin on disk', () => {
  const d = join(dir, 'a6');
  wpSite(join(d, 'webroot', '.Trashes', 'live'));
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(d, 'webroot')]);
  assert.notEqual(r.code, 0, `exit 0 with Rank Math PRO 3.0.123 on disk:\n${r.out}`);
  assert.doesNotMatch(r.out, /SAFE {5}no WordPress installs found/, 'an all-clear for a folder it declined to enter');
});

test('AUDIT-7 a WordPress site linked into the searched folder reads SAFE, exit 0, with the backdoored plugin on disk', () => {
  const d = join(dir, 'a7');
  wpSite(join(d, 'sites', 'example.com'));
  const root = join(d, 'webroot');
  mkdirSync(root, { recursive: true });
  symlinkSync(join(d, 'sites', 'example.com'), join(root, 'html'));
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.notEqual(r.code, 0, `exit 0 with Rank Math PRO 3.0.123 on disk:\n${r.out}`);
  assert.doesNotMatch(r.out, /SAFE {5}no WordPress installs found/, 'an all-clear for a link it declined to follow');
});

test('AUDIT-8 the LiteLLM check reads SAFE, exit 0, with litellm-1.107.0.dist-info below a linked folder in the searched folder', () => {
  const d = join(dir, 'a8');
  venv(join(d, 'volume', 'app', '.venv'), { litellm: true });
  const root = join(d, 'root');
  mkdirSync(root, { recursive: true });
  symlinkSync(join(d, 'volume'), join(root, 'work'));
  const r = run(['--incident', 'litellm-2026-10', '--no-containers', '--json', '--paths', root]);
  const rows = JSON.parse(r.out).results;
  assert.notEqual(r.code, 0, `exit 0 with the compromised release installed:\n${JSON.stringify(rows, null, 1)}`);
  assert.deepEqual(rows.filter((x) => x.status === 'SAFE'), [], 'an all-clear for a link it declined to follow');
});

test('AUDIT-25 two spellings of one folder given with --paths are counted twice: one site, "2 WordPress installs found"', () => {
  // the same folder named twice (a script passing both spellings; on macOS /x and /System/Volumes/Data/x, or /tmp/x
  // and /private/tmp/x, are one folder). sitePackagesDirs() dedupes by realPath; these two walks dedupe by nothing,
  // and lib/files.mjs fileId() exists for exactly this comparison but no walk uses it.
  const d = join(dir, 'a25');
  const root = join(d, 'root');
  wpSite(join(root, 'site'));
  keyRepo(join(root, 'app'));
  symlinkSync(root, join(d, 'rootlink'));
  const pair = [root, join(d, 'rootlink')];
  assert.equal(wordpressUnder(pair, 5, []).length, 1, `one site on disk, counted ${wordpressUnder(pair, 5, []).length} times`);
  assert.equal(reposUnder(pair, 4, []).length, 1, `one repository on disk, counted ${reposUnder(pair, 4, []).length} times`);
});

test('AUDIT-9 the committed-keys line flips from a finding to SAFE when the repository is reached through a link', () => {
  const d = join(dir, 'a9');
  keyRepo(join(d, 'direct', 'app'));
  keyRepo(join(d, 'elsewhere', 'app'));
  const linked = join(d, 'linked');
  mkdirSync(linked, { recursive: true });
  symlinkSync(join(d, 'elsewhere', 'app'), join(linked, 'app'));
  const direct = run(['--incident', 'committed-keys-2026-10', '--paths', join(d, 'direct')]);
  assert.match(direct.out, /REVIEW.*AWS access key/s, `the control must find the key:\n${direct.out}`);
  const through = run(['--incident', 'committed-keys-2026-10', '--paths', linked]);
  assert.doesNotMatch(through.out, /SAFE {5}no committed keys found in the files of 0 local repositories/,
    'an all-clear that says it read no repositories at all, for a folder that holds one');
});
