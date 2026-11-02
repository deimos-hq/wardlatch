// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The panel of 2 Nov 2026. Each of these failed on integrate/r5 at f7e1fbc.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../lib/secrets.mjs';
import { canaryExpired } from '../lib/probe.mjs';
import { pathState, listDir } from '../lib/files.mjs';
import { copiesMatching, tempDirs } from '../lib/binaries.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
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
const cli = (args, env = {}, wrap = []) => {
  const r = spawnSync(wrap[0] ?? process.execPath, [...wrap.slice(1), ...(wrap.length ? [process.execPath] : []), BIN, '--json', ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
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

// ---- seat 5, the same day: the modules seat 1 did not reach. Each of these reads SAFE on 0.1.10 too.
const asRoot = process.getuid?.() === 0;
const realpathOf = (p) => spawnSync('/bin/realpath', [p], { encoding: 'utf8' }).stdout.trim() || p;

test('seat 5 F1: a path built from a name that could not be decoded is unread, never "not there"', () => {
  const odd = join(dir, 'caf\uFFFD');
  assert.equal(pathState(odd), 'denied');
  assert.ok(listDir(odd).denied, 'listDir must say denied');
  // the control: an ordinary name that isn't there stays gone, or every missing folder would be UNKNOWN
  assert.equal(pathState(join(dir, 'plain-gone')), 'gone');
  assert.ok(listDir(join(dir, 'plain-gone')).gone);
});

test('seat 5 F2: a folder the home look cannot open is could-not-be-tested, not a stealer read as SAFE', { skip: asRoot }, () => {
  const h = join(dir, 's5f2-home');
  const sp = join(h, 'Documents', 'proj', '.venv', 'lib', 'python3.12', 'site-packages');
  mkdirSync(join(sp, 'litellm-1.107.0.dist-info'), { recursive: true });
  writeFileSync(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n');
  writeFileSync(join(sp, 'cook.pth'), 'import os\n');
  writeFileSync(join(h, 'Documents', 'proj', '.venv', 'pyvenv.cfg'), 'home = /usr/bin\n');
  assert.equal(cli(['--incident', 'litellm-2026-10', '--no-containers'], { HOME: h, TMPDIR: h }).code, 1, 'the control: a readable folder is EXPOSED');
  chmodSync(join(h, 'Documents'), 0);
  try {
    const { code, results } = cli(['--incident', 'litellm-2026-10', '--no-containers'], { HOME: h, TMPDIR: h });
    assert.equal(code, 2, JSON.stringify(results));
    assert.ok(!results.some((r) => r.status === 'SAFE'), 'an all-clear beside a folder that was not opened');
  } finally { chmodSync(join(h, 'Documents'), 0o755); }
});

test('seat 5 F3: a settings file the system refuses with EPERM is could-not-be-tested, not "not used"', { skip: process.platform !== 'darwin' || !existsSync('/usr/bin/sandbox-exec') }, () => {
  const h = join(dir, 's5f3-home'); mkdirSync(h, { recursive: true });
  writeFileSync(join(h, '.gitconfig'), '[user]\n\tname = Ada Example\n\temail = ada@example.invalid\n');
  writeFileSync(join(h, '.curlrc'), 'header = "X-User: ada@example.invalid"\n');
  const env = { HOME: h, TMPDIR: h };
  assert.equal(cli(['--incident', 'identity-headers-2026-10', '--no-containers'], env).code, 1, 'the control: readable, it is EXPOSED');
  const profile = `(version 1)(allow default)(deny file-read* (literal "${realpathOf(join(h, '.curlrc'))}"))`;
  const { code, results } = cli(['--incident', 'identity-headers-2026-10', '--no-containers'], env, ['/usr/bin/sandbox-exec', '-p', profile]);
  assert.equal(code, 2, JSON.stringify(results));
});

test('seat 5 F4: this user\'s own temp folder that can\'t be listed stays in the list, so it becomes an UNKNOWN row', { skip: asRoot }, () => {
  const root = join(dir, 's5f4'); const t = join(root, 'aa', 'bb', 'T');
  mkdirSync(t, { recursive: true });
  mkdirSync(join(root, 'aa', 'cc'), { recursive: true }); // no T: nothing to report
  chmodSync(t, 0);
  try {
    assert.ok(tempDirs('darwin', root).includes(t), 'the refused folder was dropped');
    assert.ok(!tempDirs('darwin', root).includes(join(root, 'aa', 'cc', 'T')));
  } finally { chmodSync(t, 0o755); }
});

test('seat 5 F6: a PATH folder that can be entered but not listed is could-not-be-tested for a rule with several names', { skip: asRoot }, () => {
  const d = join(dir, 's5f6'); mkdirSync(d, { recursive: true });
  writeFileSync(join(d, 'php8.1'), '#!/bin/sh\necho PHP 8.1.2\n', { mode: 0o755 });
  const odd = [];
  assert.equal(copiesMatching('^php(?:\\d+(?:\\.\\d+)?)?$', d, [], odd, 'php').run.length, 1, 'the control: listable, the copy is found');
  assert.deepEqual(odd, []);
  chmodSync(d, 0o111);
  try {
    const odd2 = [];
    copiesMatching('^php(?:\\d+(?:\\.\\d+)?)?$', d, [], odd2, 'php');
    assert.deepEqual(odd2, [d]);
  } finally { chmodSync(d, 0o755); }
});

test('seat 5 F2: what macOS keeps to itself is not reported from the home look, or every healthy run exits 2', { skip: asRoot }, () => {
  const h = join(dir, 's5f2b-home');
  for (const name of ['.Trash', 'Pictures/Photos Library.photoslibrary', 'Pictures/Photo Booth Library']) { mkdirSync(join(h, name), { recursive: true }); chmodSync(join(h, name), 0); }
  try {
    const { code, results } = cli(['--incident', 'litellm-2026-10', '--no-containers'], { HOME: h, TMPDIR: h });
    assert.equal(code, 0, JSON.stringify(results));
  } finally { for (const name of ['.Trash', 'Pictures/Photos Library.photoslibrary', 'Pictures/Photo Booth Library']) chmodSync(join(h, name), 0o755); }
});
