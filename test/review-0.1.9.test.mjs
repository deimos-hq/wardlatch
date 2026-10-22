// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The strict final review of 0.1.9's first cut (eb82857) reproduced these; each test here failed on eb82857 for the
// reason its name gives, and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace
// every program a check would run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync } from 'node:fs';
import { tmpdir, userInfo, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { envFor } from '../lib/run.mjs';
import { safe } from '../lib/report.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-review-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body) => put(p, `#!/bin/sh\n${body}\n`, 0o755);
const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };
const gitRepo = (path) => {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q');
  return () => { g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add'); };
};

// A stand-in loaded into the command: system paths hidden from every way of looking, no real connection, no program run
// outside this test's folder. online: every test host "answers" the reachability handshake with the compromised issuer.
const preload = (mode, extra = '', name = mode) => {
  const p = join(dir, `${name}.cjs`);
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), { EventEmitter } = require('node:events');
const SYS = /^\\/(usr|etc|opt|bin|System|Library)\\//;
const ex = fs.existsSync; fs.existsSync = (p) => !SYS.test(String(p)) && ex(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) { const o = fs[k]; fs[k] = (p, ...a) => { if (SYS.test(String(p))) throw Object.assign(new Error('hidden'), { code: 'ENOENT' }); return o(p, ...a); }; }
tls.connect = (...a) => { const cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s;
  s.getPeerCertificate = () => ({ issuer: { CN: 'EM DV TLS CA - G3B' } });
  process.nextTick(() => (${mode === 'online'} ? cb && cb() : s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' })))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const DIR = ${JSON.stringify(dir)};
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
${extra}
require('node:module').syncBuiltinESMExports();
`);
  return p;
};
const run = (args, env = {}, nodeArgs = []) => {
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args, '--json'], { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), LANG: 'C', ...env }, cwd: dir, timeout: 120000, killSignal: 'SIGKILL' });
  let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 500)}`); }
  return { code: r.status, rows };
};
// a docker stand-in: ps lists one container; exec runs the probe script with a curl that opens the control site only
const engine = (name) => {
  const box = fresh(`${name}-box`), eng = fresh(`${name}-engine`);
  exe(join(box, 'curl'), 'for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done\ncase "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac');
  exe(join(eng, 'docker'), `if [ "$1" = ps ]; then printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0; fi
if [ "$1" = exec ]; then while [ $# -gt 0 ] && [ "$1" != sh ]; do shift; done; shift; PATH=${JSON.stringify(box)} exec /bin/sh "$@"; fi
exit 0`);
  return eng;
};

test('a checked container never stands in for the machine\'s own runtimes: no host runtime found is UNKNOWN, exit 2', () => {
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('x1-root')], { PATH: engine('x1') }, ['--require', preload('online')]);
  assert.ok(r.rows.some((x) => x.kind === 'container'), 'the fixture: the container was checked');
  assert.ok(r.rows.some((x) => x.kind === 'runtimes' && x.status === 'UNKNOWN'), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('one --paths entry that isn\'t there, beside one that is, is its own UNKNOWN row: never a SAFE, exit 2', () => {
  const real = fresh('mixed-real'), gone = join(dir, 'mixed-gone');
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const r = run(['--incident', id, '--paths', real, '--paths', gone]);
    assert.equal(r.code, 2, id);
    assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === gone), `${id}: ${JSON.stringify(r.rows)}`);
    assert.ok(!r.rows.some((x) => x.status === 'SAFE'), `${id}: a SAFE beside a folder that wasn't searched`);
  }
});

test('under sudo, every check searches the sudo user\'s home, not root\'s: the LiteLLM check\'s own folders too', { skip: AS_ROOT && 'already root' }, () => {
  // the stand-in makes the command believe it runs as root under sudo; HOME is root's (here: an empty folder). The
  // LiteLLM check finds ~/... site-packages through os.homedir(): in eb82857 that stayed root's home.
  const me = userInfo().username, realHome = homedir(), rootsHome = fresh('roots-home');
  put(join(rootsHome, '.local', 'lib', 'python3.12', 'site-packages', 'x'), '');
  const sudo = preload('offline', `process.getuid = () => 0;`, 'sudo');
  const r = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('sudo-root')], { HOME: rootsHome, SUDO_USER: me }, ['--require', sudo]);
  const searched = r.rows.flatMap((x) => x.searched ?? []).concat(r.rows.map((x) => x.dir ?? x.path ?? ''));
  assert.ok(!searched.some((p) => p.startsWith(rootsHome)), `root's home was searched: ${JSON.stringify(searched.filter((p) => p.startsWith(rootsHome)))}`);
});

test('a locked folder under --paths in the trust check is an UNKNOWN row, never dropped', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const root = fresh('venv-root'), vault = join(root, 'vault'), v = join(vault, 'app', '.venv');
  put(join(v, 'pyvenv.cfg'), 'home = /x\n'); put(join(v, 'bin', 'python'), ''); put(join(v, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  lock(vault);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], {}, ['--require', preload('offline')]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === vault), JSON.stringify(r.rows));
});

test('a tracked file the key scan can\'t read, or one too big to scan, is UNKNOWN, not a silent skip', { skip: AS_ROOT && 'root reads every file' }, () => {
  const root = fresh('keys-root'), repo = join(root, 'app'); const commit = gitRepo(repo);
  put(join(repo, 'locked.py'), `k = "AKIA${'Q'.repeat(16)}"\n`); put(join(repo, 'big.txt'), 'x'.repeat(9 * 1024 * 1024)); commit();
  lock(join(repo, 'locked.py'));
  const r = run(['--incident', 'committed-keys-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
  const unknown = r.rows.filter((x) => x.status === 'UNKNOWN').map((x) => x.file).sort();
  assert.deepEqual(unknown, ['big.txt', 'locked.py'], JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('a home config with more items than the header walk reads through is UNKNOWN, never SAFE', () => {
  const h = fresh('cap-home');
  put(join(h, '.gitconfig'), '[user]\n\temail = ada.lovelace@example.org\n');
  const projects = {}; for (let i = 0; i < 250000; i++) projects[`/p/${i}`] = { a: 1 };
  // the header first in the file: a stack walk reaches it last, after the projects, so a silent cap would skip it
  put(join(h, '.claude.json'), JSON.stringify({ mcpServers: { x: { headers: { 'X-User': 'ada.lovelace@example.org' } } }, projects }));
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('cap-root')], { HOME: h, PATH: '/usr/bin:/bin' });
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows).slice(0, 400));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' || x.status === 'REVIEW' || (x.status === 'UNKNOWN' && x.file === join(h, '.claude.json'))));
});

test('DOCKER_HOST (or a docker context or config) set while a local engine answers: an UNKNOWN row says it was not followed', () => {
  for (const v of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'CONTAINER_HOST']) {
    const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh(`dh-root-${v}`)], { PATH: engine(`dh-${v}`), [v]: 'ssh://prod.invalid' }, ['--require', preload('online')]);
    assert.ok(r.rows.some((x) => x.kind === 'containers' && x.status === 'UNKNOWN' && x.reason.includes(v)), `${v}: ${JSON.stringify(r.rows)}`);
  }
});

test('only NODE_OPTIONS\' trust flags reach a trust probe, and nothing that loads code or points at caller-chosen files', () => {
  const env = envFor('probe', {}, { NODE_OPTIONS: '--use-openssl-ca --snapshot-blob x.blob -r y.js --require=z.js --import w --experimental-loader v --use-system-ca', LD_PRELOAD: '/x.so', DYLD_INSERT_LIBRARIES: '/x.dylib', CURL_HOME: '/x', PYTHONPATH: '/x', SSL_CERT_FILE: '/ca.pem' });
  assert.equal(env.NODE_OPTIONS, '--use-openssl-ca --use-system-ca');
  for (const k of ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'CURL_HOME', 'PYTHONPATH']) assert.equal(env[k], undefined, k);
  assert.equal(env.SSL_CERT_FILE, '/ca.pem', 'the person\'s CA settings still reach the probe');
  const engineEnv = envFor('engine', {}, { DOCKER_HOST: 'x', DOCKER_CONTEXT: 'x', DOCKER_CONFIG: 'x', CONTAINER_HOST: 'x', HOME: '/h', PATH: '/p' });
  assert.deepEqual(Object.keys(engineEnv).filter((k) => /DOCKER|CONTAINER/.test(k)), []);
});

test('after the test hosts\' certificates expire, a container is UNKNOWN, never SAFE', () => {
  // the online stand-in, with the clock moved past canaryNotAfter (one file: a second stand-in would undo the first)
  const later = preload('online', `const D = Date; Date.now = () => D.parse('2028-01-01T00:00:00Z');`, 'online-2028');
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('exp-root')], { PATH: engine('exp') }, ['--require', later]);
  // the fixture can produce SAFE today: the same container, with today's clock, refuses the test hosts and reads SAFE
  const now = run(['--incident', 'emudhra-2026-10', '--paths', fresh('exp-root-now')], { PATH: engine('exp-now') }, ['--require', preload('online')]);
  assert.deepEqual(now.rows.filter((x) => x.kind === 'container').map((x) => x.status), ['SAFE'], 'harness sanity');
  const c = r.rows.filter((x) => x.kind === 'container');
  assert.ok(c.length, 'the fixture: a container was seen');
  assert.ok(c.every((x) => x.status === 'UNKNOWN'), JSON.stringify(c));
});

test('go and cloudflared not found on PATH each get a receipt row naming PATH', () => {
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('nf-root')], {}, ['--require', preload('offline')]);
  for (const b of ['cloudflared', 'go']) {
    const row = r.rows.find((x) => x.kind === 'binary' && x.reason?.startsWith(`${b} not found on PATH`));
    assert.ok(row && row.searched?.some((s) => s.startsWith('PATH: ')), `${b}: ${JSON.stringify(r.rows)}`);
  }
});

test('safe(): the fields can never override the status or the receipt', () => {
  const r = safe(['/a'], { status: 'EXPOSED', searched: [], note: 'x' });
  assert.equal(r.status, 'SAFE'); assert.deepEqual(r.searched, ['/a']); assert.equal(r.note, 'x');
  assert.throws(() => safe([], {}), /receipt/);
});
