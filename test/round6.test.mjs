// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The panel of 2 Nov 2026. Each of these failed on integrate/r5 at f7e1fbc.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../lib/secrets.mjs';
import { canaryExpired } from '../lib/probe.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
let dir, home;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-r6-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-r6-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const gitEnv = () => ({ ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' });
const git = (cwd, ...args) => { const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: gitEnv() }); assert.equal(r.status, 0, r.stderr); };
const repoWith = (name, files) => {
  const repo = join(dir, name); mkdirSync(repo, { recursive: true });
  git(repo, 'init', '-q');
  for (const [f, body] of Object.entries(files)) writeFileSync(join(repo, f), body);
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'x');
  return repo;
};
const cli = (args) => {
  const r = spawnSync(process.execPath, [BIN, '--json', ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home } });
  assert.ok(r.stdout, `no output (exit ${r.status}): ${r.stderr}`);
  return { code: r.status, results: JSON.parse(r.stdout).results };
};

// The same PKCS #8 key three ways. The rewrites keep every byte of the key and change only how the DER says its
// lengths, and LibreSSL reads all three.
const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'der' });
const body = key.subarray(4); // 30 82 LL LL, then the body
const beLen = (n) => Buffer.from([(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);
const longForm = Buffer.concat([Buffer.from([0x30, 0x85, 0]), beLen(body.length), body]);
const wideVersion = (() => {
  const b = Buffer.concat([Buffer.from([2, 2, 0, 0]), body.subarray(3)]);
  return Buffer.concat([Buffer.from([0x30, 0x82, b.length >> 8, b.length & 255]), b]);
})();

test('F2 a key in DER that the parser cannot read is a gap, never skipped in silence, whatever the file is called', () => {
  const repo = repoWith('f2', { 'minimal.p12': key, 'longform.p12': longForm, 'wide.p12': wideVersion });
  const found = scanRepo(repo);
  assert.ok(found.some((h) => h.file === 'minimal.p12' && !h.unread), 'the positive control: the minimal key must be a finding');
  for (const f of ['longform.p12', 'wide.p12']) assert.ok(found.some((h) => h.file === f && h.unread), `${f} left no row: ${JSON.stringify(found.map((h) => h.file))}`);
});

test('F2 the same two, deleted from the working tree but still tracked: git\'s copy is held to the same rule', () => {
  const repo = repoWith('f2-gone', { 'longform.p12': longForm, 'wide.p12': wideVersion });
  rmSync(join(repo, 'longform.p12')); rmSync(join(repo, 'wide.p12'));
  const found = scanRepo(repo);
  for (const f of ['longform.p12', 'wide.p12']) assert.ok(found.some((h) => h.file === f && h.unread), `${f} left no row`);
});

test('F2 its control: a binary that does not begin like DER is still skipped, or every picture would be UNKNOWN', () => {
  const repo = repoWith('f2-quiet', { 'a.png': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 13]), 'b.bin': Buffer.from([0x31, 0, 1, 2]), 'sig.p7s': Buffer.from([0x30, 0x82, 0, 8, 6, 3, 0, 0, 0, 1, 2, 3]) });
  assert.deepEqual(scanRepo(repo), []);
});

test('F2 end to end: the all-clear is gone and the run is could-not-be-tested', () => {
  const repo = repoWith('f2-cli', { 'longform.p12': longForm });
  const { code, results } = cli(['--incident', 'committed-keys-2026-10', '--no-containers', '--paths', repo]);
  assert.equal(code, 2, JSON.stringify(results));
  assert.ok(results.some((r) => r.status === 'UNKNOWN' && r.file === 'longform.p12'));
  assert.ok(!results.some((r) => r.status === 'SAFE'), 'an all-clear beside an unread key');
});

test('F3 the containers\' date gate closes on a date it cannot read', () => {
  const when = Date.parse('2027-01-01T00:00:00Z');
  assert.equal(canaryExpired({ canaryNotAfter: '2027-05-03' }, when), false, 'the control: a readable future date is not expired');
  assert.equal(canaryExpired({ canaryNotAfter: '2026-05-03' }, when), true);
  assert.equal(canaryExpired({ canaryNotAfter: 'not a date' }, when), true);
  assert.equal(canaryExpired({}, when), true);
});

test('--paths: a folder that is not there is could-not-be-tested on the checks that do not search it, as the README says', () => {
  const gone = join(dir, 'no-such-folder');
  for (const id of ['gitlab-2026-10', 'plex-2026-10', 'ovhcloud-cli-2026-10']) {
    const { code, results } = cli(['--incident', id, '--no-containers', '--paths', gone]);
    assert.equal(code, 2, `${id}: ${JSON.stringify(results)}`);
    assert.ok(results.some((r) => r.status === 'UNKNOWN' && r.path === gone), `${id}: no row names the folder`);
  }
  // its control: a folder that IS there, and plays no part, must not cost an exit 2
  const here = join(dir, 'here'); mkdirSync(here, { recursive: true });
  assert.equal(cli(['--incident', 'gitlab-2026-10', '--no-containers', '--paths', here]).code, 0);
});
