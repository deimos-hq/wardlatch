// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release round of 0.1.9 (owner's decisions, 22 Oct 2026, after the overseer): one rule for locked folders, by owner;
// nothing-to-search is SAFE with a receipt; a local DOCKER_HOST socket is followed; one rule for later copies on PATH;
// and the reverts that made 0.1.9 smaller. Each test pairs a clean machine that must stay exit 0 with the case that must
// still be caught, and failed on e0e1c35 or fails when its fix is reverted. Offline: no test reaches a network host, and stand-ins replace every program a
// check would run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, readFileSync, statSync, symlinkSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { envFor } from '../lib/run.mjs';
import { probe, check } from '../lib/probe.mjs';
import { readCapped, eachPiece } from '../lib/files.mjs';
import { scanText } from '../lib/secrets.mjs';
import { execFileSync } from 'node:child_process';
import { discover } from '../lib/discover.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-release-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body, shell = '/bin/sh') => put(p, `#!${shell}\n${body}\n`, 0o755);
const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };

// A stand-in loaded into the command: system paths hidden, no real connection, no program run outside this test's folder.
// online: every test host answers the reachability handshake with `issuer`, except hosts matching `down`.
const preload = (name, { online = false, issuer = 'EM DV TLS CA - G3B', down = null, extra = '' } = {}) => {
  const p = join(dir, `${name}.cjs`);
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), { EventEmitter } = require('node:events');
const SYS = /^\\/(usr|etc|opt|bin|System|Library)\\//;
const ex = fs.existsSync; fs.existsSync = (p) => !SYS.test(String(p)) && ex(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) { const o = fs[k]; fs[k] = (p, ...a) => { if (SYS.test(String(p))) throw Object.assign(new Error('hidden'), { code: 'ENOENT' }); return o(p, ...a); }; }
const DOWN = ${down ? `new RegExp(${JSON.stringify(down)})` : 'null'};
tls.connect = (...a) => { const o = a.find((x) => x && typeof x === 'object') || {}, cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s;
  s.getPeerCertificate = () => ({ issuer: { CN: ${JSON.stringify(issuer)} } });
  const up = ${online} && !(DOWN && DOWN.test(String(o.host)));
  process.nextTick(() => (up ? cb && cb() : s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' })))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const DIR = ${JSON.stringify(dir)};
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
${extra}
require('node:module').syncBuiltinESMExports();
`);
  return p;
};
const spawnCli = (args, env = {}, nodeArgs = []) => spawnSync(process.execPath, [...nodeArgs, BIN, ...args, '--json'], { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), LANG: 'C', ...env }, cwd: dir, timeout: 120000, killSignal: 'SIGKILL' });
const run = (args, env = {}, nodeArgs = []) => {
  const r = spawnCli(args, env, nodeArgs);
  let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 500)}`); }
  return { code: r.status, rows };
};
const CANARY = /-emudhra\.we-have-a-problem\.com/;
// a docker stand-in: ps lists one container; exec runs the probe script inside a box whose curl answers per `curlBody`.
// `execFails`: a shell pattern of URLs for which `docker exec` itself fails as docker does (exit 1, daemon error).
const engine = (name, { curlBody, execFails = '' } = {}) => {
  const box = fresh(`${name}-box`), eng = fresh(`${name}-engine`);
  exe(join(box, 'curl'), `for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done\n${curlBody ?? 'case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac'}`);
  exe(join(eng, 'docker'), `if [ "$1" = ps ]; then printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0; fi
if [ "$1" = images ]; then echo 'python:3.12@sha256:0000'; exit 0; fi
if [ "$1" = exec ]; then
  ${execFails ? `for a in "$@"; do case "$a" in ${execFails}) echo 'Error response from daemon: container c0ffee is not running' >&2; exit 1;; esac; done` : ':'}
  while [ $# -gt 0 ] && [ "$1" != sh ]; do shift; done; shift; PATH=${JSON.stringify(box)} exec /bin/sh "$@"; fi
exit 0`);
  return eng;
};
// a node stand-in on PATH: forced roots (WARDLATCH_CA) connect; otherwise it connects where `trusts` (a shell pattern) matches
const nodeStandIn = (name, trusts) => {
  const d = fresh(`${name}-node`);
  exe(join(d, 'node'), `[ "$1" = -v ] && { echo v20.0.0; exit 0; }
for a in "$@"; do u="$a"; done
[ -n "$WARDLATCH_CA" ] && exit 0
case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; ${trusts}) exit 0;; *) exit 1;; esac`);
  return d;
};
const status = (rows, kind) => rows.filter((x) => x.kind === kind || (kind === 'node' && x.kind === 'node')).map((x) => x.status);


const gitRepo = (path) => {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q', '-b', 'main');
  return { g, commit: (msg = 'add', date) => { g('add', '-A'); execFileSync('git', ['-C', path, '-c', 'commit.gpgsign=false', 'commit', '-qm', msg], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x', ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}) } }); } };
};
const AWS = ['AKIA', 'Q'.repeat(16)].join('');
const sys = (args, env = {}) => run(args, { PATH: '/usr/bin:/bin', ...env });
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

// ---- locked folders, by owner ------------------------------------------------------------------------------------------
// A real system folder on this machine whose only locked descendants are owned by a service and can be looked at (a
// user can't chown a test folder to another account): picked at run time, or the test is skipped.
let isPersonUid;
before(async () => { ({ isPersonUid } = await import('../lib/owners.mjs')); });
const serviceLockedRoot = () => {
  const isPerson = (uid) => isPersonUid(uid, 'workflow');
  const ok = (d, depth) => {   // the number of service-owned locked folders below d, or -1 if anything else is locked
    let ents; try { ents = readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.name.startsWith('.')); } catch { return -1; }
    let n = 0;
    for (const e of ents) {
      const p = join(d, e.name); let st; try { st = statSync(p); } catch { return -1; }
      try { readdirSync(p); } catch { if (isPerson(st.uid)) return -1; n++; continue; }
      if (depth > 0) { const k = ok(p, depth - 1); if (k < 0) return -1; n += k; }
    }
    return n;
  };
  for (const base of ['/private/var/db', '/private/var']) {
    let ents; try { ents = readdirSync(base, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) if (e.isDirectory() && ok(join(base, e.name), 5) > 0) return join(base, e.name);
  }
  return null;
};
test('a folder a service owns (root\'s, on this Mac) that can\'t be opened is one review line, and a clean run passes', { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS, as a user' }, (t) => {
  const root = serviceLockedRoot(); if (!root) return t.skip('no suitable system folder on this machine');
  for (const id of ['wordpress-plugins-2026-10', 'github-actions-2026-10']) {
    const r = sys(['--incident', id, '--paths', root]);
    const skipped = r.rows.find((x) => x.kind === 'skipped');
    assert.ok(skipped && skipped.status === 'REVIEW' && skipped.paths.length, `${id} in ${root}: ${JSON.stringify(r.rows)}`);
    assert.equal(unknowns(r).length, 0, `${id}: ${JSON.stringify(r.rows)}`);
    assert.ok(r.rows.some((x) => x.status === 'SAFE'), `${id}: the summary line is still there beside the skipped line`);
    assert.equal(r.code, 0, id);
  }
});

test('a folder a person owns that can\'t be opened is still could-not-be-tested', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const root = fresh('o2-root'), mine = fresh('o2-root/projects'); lock(mine);
  const r = sys(['--incident', 'github-actions-2026-10', '--paths', root]);
  assert.ok(unknowns(r).some((x) => x.path === mine), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('a skipped-folders line never stands in for the machine\'s runtimes, and never hides a summary line', { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS, as a user' }, () => {
  const root = serviceLockedRoot(); if (!root) return;
  const t = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], {}, ['--require', preload('o3-online', { online: true })]);
  assert.ok(t.rows.some((x) => x.kind === 'skipped'), 'the fixture: a skipped line');
  assert.ok(t.rows.some((x) => x.kind === 'runtimes' && x.status === 'UNKNOWN'), `no runtime found must still be its own UNKNOWN line: ${JSON.stringify(t.rows)}`);
  assert.equal(t.code, 2);
});

test('WordPress: a dot-folder in the web root (/var/www/.ssh, www-data\'s own) is not searched or reported', { skip: AS_ROOT && 'root' }, () => {
  const root = fresh('o4-www'); lock(fresh('o4-www/.ssh'));
  const r = sys(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.equal(unknowns(r).length, 0, JSON.stringify(r.rows)); assert.equal(r.code, 0);
});

// ---- nothing to search ---------------------------------------------------------------------------------------------------
test('with none of the usual folders on the machine (a fresh server, a CI runner), the folder checks are SAFE with a receipt, exit 0', () => {
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const r = run(['--incident', id], { HOME: fresh(`n1-home-${id}`), PATH: '/usr/bin:/bin' }, ['--require', preload('n1-offline')]);
    const safe = r.rows.find((x) => x.status === 'SAFE');
    assert.ok(safe && /none of the usual folders exist/.test(safe.reason) && safe.searched.length, `${id}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 0, id);
  }
  // but a --paths folder that isn't there is still could-not-be-tested
  assert.equal(sys(['--incident', 'github-actions-2026-10', '--paths', join(dir, 'n1-gone')]).code, 2);
});

// ---- DOCKER_HOST ---------------------------------------------------------------------------------------------------------
test('DOCKER_HOST: a local socket this user owns is followed; tcp, ssh, or a path that isn\'t a socket is refused', async () => {
  const { engineHost } = await import('../lib/containers.mjs');
  const { createServer } = await import('node:net');
  const sock = join(dir, 'd1.sock'); const srv = createServer(); await new Promise((res) => srv.listen(sock, res));
  try {
    assert.deepEqual(engineHost({ DOCKER_HOST: `unix://${sock}` }), { env: { DOCKER_HOST: `unix://${sock}` }, refused: [] });
    for (const v of ['tcp://10.0.0.1:2375', 'ssh://prod.invalid', `unix://${put(join(dir, 'd1.file'), '')}`]) assert.deepEqual(engineHost({ DOCKER_HOST: v }).refused, ['DOCKER_HOST'], v);
    assert.deepEqual(engineHost({ DOCKER_CONTEXT: 'prod' }).refused, ['DOCKER_CONTEXT']);
  } finally { srv.close(); }
});

test('DOCKER_HOST set with no docker or podman installed: no row, and a clean run passes', () => {
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('d2-root')], { DOCKER_HOST: 'tcp://10.0.0.1:2375', HOME: fresh('d2-home') }, ['--require', preload('d2-offline')]);
  assert.ok(!r.rows.some((x) => x.kind === 'containers'), JSON.stringify(r.rows));
  assert.equal(r.code, 0, JSON.stringify(r.rows));
});

// ---- the header check ----------------------------------------------------------------------------------------------------
test('headers: settings switched off with /dev/null (CI), and a ~/.config this user can\'t open, are not could-not-be-tested', { skip: AS_ROOT && 'root' }, () => {
  const h = fresh('h1-home'); put(join(h, '.gitconfig'), '[user]\n\temail = ada.lovelace@example.org\n');
  const a = sys(['--incident', 'identity-headers-2026-10', '--paths', fresh('h1-root')], { HOME: h, GIT_CONFIG_GLOBAL: '/dev/null', NPM_CONFIG_USERCONFIG: '/dev/null', WGETRC: '/dev/null' });
  assert.equal(a.code, 0, JSON.stringify(a.rows));
  put(join(h, '.config', 'curlrc'), '-H "From: ada.lovelace@example.org"\n'); lock(join(h, '.config'));
  const b = sys(['--incident', 'identity-headers-2026-10', '--paths', fresh('h1b-root')], { HOME: h });
  assert.equal(unknowns(b).length, 0, JSON.stringify(b.rows)); assert.equal(b.code, 0);
  // the bad case: a readable ~/.curlrc with the email is still EXPOSED
  put(join(h, '.curlrc'), '-H "From: ada.lovelace@example.org"\n');
  assert.equal(sys(['--incident', 'identity-headers-2026-10', '--paths', fresh('h1c-root')], { HOME: h }).code, 1);
});

// ---- the key scan: git's own records -------------------------------------------------------------------------------------
test('keys: a committed link into a locked folder, an empty .gitkeep in one, and a submodule are no could-not-be-tested; a key still is found', { skip: AS_ROOT && 'root' }, () => {
  const root = fresh('k1-root'), app = join(root, 'app'), repo = gitRepo(app);
  // the link's target is outside the repository, in a folder this user can't open (certbot's live/ keys, say)
  const outside = fresh('k1-outside'); put(join(outside, 'live', 'privkey.pem'), 'x'); symlinkSync(join(outside, 'live', 'privkey.pem'), join(app, 'link.pem'));
  put(join(app, 'pgdata', '.gitkeep'), '');
  const lib = gitRepo(join(dir, 'k1-lib')); put(join(dir, 'k1-lib', 'a.txt'), 'a\n'); lib.commit();
  repo.g('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', join(dir, 'k1-lib'), 'vendor/lib');
  repo.commit(); lock(join(outside, 'live')); lock(join(app, 'pgdata'));
  const clean = sys(['--incident', 'committed-keys-2026-10', '--paths', root]);
  assert.equal(unknowns(clean).length, 0, JSON.stringify(clean.rows)); assert.equal(clean.code, 0);
  put(join(app, 'k.py'), `k = "${AWS}"\n`); repo.commit();
  assert.ok(sys(['--incident', 'committed-keys-2026-10', '--paths', root]).rows.some((x) => x.status === 'REVIEW' && x.file === 'k.py'));
});

// ---- the workflow review -------------------------------------------------------------------------------------------------
test('workflows: merging main into an old branch doesn\'t list main\'s old workflows again; a workflow only a merge adds is listed', () => {
  const root = fresh('w1-root'), app = join(root, 'app'), r = gitRepo(app);
  put(join(app, 'a'), 'a\n'); r.commit('A', '2024-01-01T12:00:00Z');
  r.g('checkout', '-qb', 'stale');
  r.g('checkout', '-q', 'main'); put(join(app, '.github', 'workflows', 'ci.yml'), 'on: push\n'); r.commit('ci', '2024-02-01T12:00:00Z');
  r.g('checkout', '-q', 'stale');
  execFileSync('git', ['-C', app, '-c', 'commit.gpgsign=false', 'merge', '-q', '--no-ff', '-m', 'sync main', 'main'], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x', GIT_AUTHOR_DATE: '2026-10-01T12:00:00Z', GIT_COMMITTER_DATE: '2026-10-01T12:00:00Z' } });
  const clean = sys(['--incident', 'github-actions-2026-10', '--paths', root]);
  assert.equal(clean.rows.filter((x) => x.status === 'REVIEW').length, 0, JSON.stringify(clean.rows)); assert.equal(clean.code, 0);
});

test('git\'s hints are never the reason shown, and too much output or a timeout is said plainly', async () => {
  const { gitError } = await import('../lib/git.mjs');
  assert.equal(gitError({ stderr: 'hint: Support for <GIT_DIR>/info/grafts is deprecated\nhint: more\nfatal: bad object' }), 'fatal: bad object');
  assert.equal(gitError({ code: 'ENOBUFS', stderr: 'hint: x' }), 'git wrote more than could be read');
  assert.equal(gitError({ code: 'ETIMEDOUT', stderr: 'hint: x' }), 'git did not finish in time');
});

test('a --paths entry that is a file is could-not-be-tested only in checks that search folders, not in Plex\'s or GitLab\'s', () => {
  const f = put(join(dir, 'p1-file'), 'x');
  for (const id of ['plex-2026-10', 'gitlab-2026-10', 'php-2026-10']) assert.ok(!sys(['--incident', id, '--paths', f]).rows.some((x) => x.path === f), id);
  for (const id of ['github-actions-2026-10', 'litellm-2026-10']) assert.equal(sys(['--incident', id, '--paths', f]).code, 2, id);
});

// ---- from the final narrow check (76849c4) -------------------------------------------------------------------------------
test('the owner rule at its edges: people, services, nobody, a directory\'s accounts, rootless containers, web servers', async () => {
  const { isPersonUid, accounts, subuidRanges } = await import('../lib/owners.mjs');
  const names = accounts('root:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/bin/sh\npostgres:x:999:999::/x:/bin/sh\n', 'linux');
  const subuids = subuidRanges('ada:100000:65536\n');
  const linux = { os: 'linux', self: 4242, names, subuids };
  const cases = [[0, false], [33, false], [999, false], [1000, true], [59999, true], [60000, true], [1234500001, true], [65534, false], [100000, false], [165535, false], [165536, true], [4242, true], [null, true]];
  for (const [uid, person] of cases) assert.equal(isPersonUid(uid, 'workflow', linux), person, `linux uid ${uid}`);
  assert.equal(isPersonUid(33, 'wordpress', linux), true, 'www-data owns websites');
  const mac = { os: 'darwin', self: 501, names: accounts('', 'darwin'), subuids: [] };
  for (const [uid, person] of [[70, false], [500, false], [501, true], [502, true], [1234500001, true]]) assert.equal(isPersonUid(uid, 'workflow', mac), person, `macOS uid ${uid}`);
  assert.equal(isPersonUid(70, 'wordpress', mac), true, '_www owns websites on macOS');
});

test('a searched root that can\'t be opened is always could-not-be-tested, whoever owns it', { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS (/private/var/root), as a user' }, () => {
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10', 'identity-headers-2026-10']) {
    const r = sys(['--incident', id, '--paths', '/private/var/root'], { HOME: fresh(`lr-home-${id}`) });
    assert.ok(unknowns(r).some((x) => x.path === '/private/var/root'), `${id}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 2, id);
  }
});

test('WordPress: a site in a dot-folder (.staging) is checked; a locked dot-folder is a review line, never could-not-be-tested', { skip: AS_ROOT && 'root' }, () => {
  const root = fresh('wd-root'), site = join(root, '.staging');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  put(join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'), '<?php\n/*\n * Version: 3.0.123\n */\n');
  const r = sys(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), JSON.stringify(r.rows)); assert.equal(r.code, 1);
  const www = fresh('wd-www'); lock(fresh('wd-www/.ssh'));
  const w = sys(['--incident', 'wordpress-plugins-2026-10', '--paths', www]);
  assert.equal(unknowns(w).length, 0, JSON.stringify(w.rows));
  assert.ok(w.rows.some((x) => x.kind === 'skipped' && x.paths.includes(join(www, '.ssh'))), JSON.stringify(w.rows)); assert.equal(w.code, 0);
});

test('a known install place that can\'t be opened (~/.local/lib, a temp folder) is could-not-be-tested, whoever owns it, and not in the receipt', { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS (/private/var/root), as a user' }, () => {
  const h = fresh('fp-home'); mkdirSync(join(h, '.local'), { recursive: true }); symlinkSync('/private/var/root', join(h, '.local', 'lib'));
  const a = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('fp-root')], { HOME: h }, ['--require', preload('fp-offline')]);
  assert.ok(unknowns(a).some((x) => x.path === join(h, '.local', 'lib')), JSON.stringify(a.rows)); assert.equal(a.code, 2);
  const b = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('fp-root2')], { HOME: fresh('fp-home2'), TMPDIR: '/private/var/root' }, ['--require', preload('fp-offline')]);
  assert.ok(unknowns(b).some((x) => x.path === '/private/var/root'), JSON.stringify(b.rows));
  assert.equal(b.code, 2, 'an unread temp folder is could-not-be-tested, never part of a SAFE');
});

test('headers: a settings file this user can\'t read is not used: no could-not-be-tested', { skip: AS_ROOT && 'root' }, () => {
  const h = fresh('hu-home'); put(join(h, '.gitconfig'), '[user]\n\temail = ada.lovelace@example.org\n');
  lock(put(join(h, '.curlrc'), '-H "From: ada.lovelace@example.org"\n'));
  const r = sys(['--incident', 'identity-headers-2026-10', '--paths', fresh('hu-root')], { HOME: h });
  assert.equal(unknowns(r).length, 0, JSON.stringify(r.rows)); assert.equal(r.code, 0);
});

test('a program an incident says may be malware is never run, so every copy on PATH is checked by its hash', () => {
  const a = fresh('nx-a'), b = fresh('nx-b'), ran = join(dir, 'nx-ran');
  for (const d of [a, b]) exe(join(d, 'ovhcloud'), `touch ${JSON.stringify(ran)}; echo "ovhcloud 0.1.0"`);
  const r = sys(['--incident', 'ovhcloud-cli-2026-10'], { PATH: `${a}:${b}` });
  assert.equal(r.rows.filter((x) => x.kind === 'binary' && x.bin && x.bin.endsWith('ovhcloud')).length, 2, JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.kind === 'not-run'), 'no copy is "not run": none is run, all are hashed');
  assert.equal(existsSync(ran), false, 'a copy was run');
});

test('compiled programs are told by their first bytes: ELF, Mach-O thin, universal and 64-bit universal; scripts are not', async () => {
  const { isNativeProgram } = await import('../lib/files.mjs');
  for (const hex of ['7f454c46', 'feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca']) assert.equal(isNativeProgram(put(join(dir, `nat-${hex}`), Buffer.concat([Buffer.from(hex, 'hex'), Buffer.alloc(16)]))), true, hex);
  assert.equal(isNativeProgram(put(join(dir, 'nat-script'), '#!/bin/sh\necho hi\n')), false);
});

test('keys: a file in a merge conflict (three stages in git\'s record) is scanned once', () => {
  const root = fresh('mc-root'), app = join(root, 'app'), r = gitRepo(app);
  put(join(app, 'k.py'), `k = "${AWS}"\nmode = "a"\n`); r.commit('base');
  r.g('checkout', '-qb', 'side'); put(join(app, 'k.py'), `k = "${AWS}"\nmode = "b"\n`); r.commit('side');
  r.g('checkout', '-q', 'main'); put(join(app, 'k.py'), `k = "${AWS}"\nmode = "c"\n`); r.commit('main');
  try { r.g('merge', '-q', 'side'); } catch { /* the conflict is the fixture */ }
  assert.ok(r.g('ls-files', '-s').toString().split('\n').filter((l) => l.endsWith('\tk.py')).length >= 2, 'the fixture: k.py has several stages');
  assert.deepEqual(sys(['--incident', 'committed-keys-2026-10', '--paths', root]).rows.filter((x) => x.status === 'REVIEW').map((x) => `${x.file}:${x.line}`), ['k.py:1']);
});

test('DOCKER_HOST to a local socket settles the engine: a DOCKER_CONTEXT beside it is not refused', async () => {
  const { engineHost } = await import('../lib/containers.mjs');
  const { createServer } = await import('node:net');
  const sock = join(dir, 'dc.sock'); const srv = createServer(); await new Promise((res) => srv.listen(sock, res));
  try { assert.deepEqual(engineHost({ DOCKER_HOST: `unix://${sock}`, DOCKER_CONTEXT: 'prod' }).refused, []); } finally { srv.close(); }
});

// ---- from the narrow check of c5b2509 ------------------------------------------------------------------------------------
// (its wildcard item was tried in 70e7030 and taken back: the quick check of 70e7030 found that judging a wildcard-matched
// folder by its owner let a root-owned python3.X read SAFE; a locked place a pattern reaches is always UNKNOWN)
test('on Windows a folder\'s owner can\'t be read, so it counts as a person\'s', async () => {
  const { isPersonUid: person } = await import('../lib/owners.mjs');
  assert.equal(person(0, 'workflow', { os: 'win32', self: undefined, names: new Map(), subuids: [] }), true);
});

test('the trust check names a later node on PATH that is a script, in --json too, without running it', () => {
  const first = nodeStandIn('nr1', 'NOTHING'), second = fresh('nr2'), ran = join(dir, 'nr2-ran');
  exe(join(second, 'node'), `touch ${JSON.stringify(ran)}; echo v18.0.0`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('nr-root')], { PATH: `${first}:${second}` }, ['--require', preload('nr-online', { online: true })]);
  assert.ok(r.rows.some((x) => x.kind === 'not-run' && x.status === 'REVIEW' && x.paths.includes(join(second, 'node'))), JSON.stringify(r.rows));
  assert.equal(existsSync(ran), false, 'the later script ran');
});

// ---- from the last check before release (581bfc6): false SAFEs already in 0.1.8 --------------------------------------
test('Plex held at a vulnerable version (apt-mark hold, or marked for removal) is EXPOSED; a fixed one is SAFE', async () => {
  const { checkVersionFiles } = await import('../lib/installs.mjs');
  const rule = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'plex-2026-10.json'), 'utf8')).versionFiles;
  const status = (want, version) => {
    const root = fresh(`px-${want}-${version}`);
    put(join(root, 'var', 'lib', 'dpkg', 'status'), `Package: plexmediaserver\nStatus: ${want} ok installed\nPriority: optional\nVersion: ${version}-c6bbc1b53\n\n`);
    return checkVersionFiles(rule, { root }).filter((r) => r.label === 'Debian or Ubuntu package').map((r) => r.status);
  };
  for (const want of ['install', 'hold', 'deinstall']) {
    assert.deepEqual(status(want, '1.41.2.9200'), ['EXPOSED'], want);
    assert.deepEqual(status(want, '1.43.3.10861'), ['SAFE'], `${want}, fixed`);
  }
});

test('PHP: a release candidate or -dev build of a fixed version is EXPOSED (it predates the fix); the release is SAFE', () => {
  for (const [v, code] of [['8.4.27RC1', 1], ['8.4.27-dev', 1], ['8.5.12RC1', 1], ['8.4.27', 0], ['8.3.6-1ubuntu1.24', 1], ['8.4.28', 0]]) {
    const d = fresh(`php-${v}`); exe(join(d, 'php'), `echo "PHP ${v} (cli) (built: Oct 21 2026)"`);
    const r = sys(['--incident', 'php-2026-10'], { PATH: d });
    assert.equal(r.code, code, `${v}: ${JSON.stringify(r.rows)}`);
  }
});

test('a virtual environment\'s certifi on a machine with no curl is could-not-be-tested, never dropped', () => {
  const root = fresh('nc-root'), v = join(root, 'app', '.venv');
  put(join(v, 'pyvenv.cfg'), 'home = /x\n'); put(join(v, 'bin', 'python'), '');
  put(join(v, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], { PATH: nodeStandIn('nc', 'NOTHING') }, ['--require', preload('nc-online', { online: true })]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.env === v && /no curl/.test(x.reason)), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});
