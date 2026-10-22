// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The second strict review of 0.1.9 (27cdfbd) reproduced these; each test here failed on 27cdfbd for the reason its name
// gives, and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace every program a
// check would run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { envFor } from '../lib/run.mjs';
import { probe } from '../lib/probe.mjs';
import { discover } from '../lib/discover.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-review2-')); home = join(dir, 'home'); mkdirSync(home); });
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

// ---- M1 ----------------------------------------------------------------------------------------------------------------
test('M1 a container that stops mid-check (docker exec fails with exit 1) is UNKNOWN, never SAFE', () => {
  const sane = run(['--incident', 'emudhra-2026-10', '--paths', fresh('m1a')], { PATH: engine('m1a', { curlBody: 'case "$u" in https://self-signed*) exit 60;; *) exit 0;; esac' }) }, ['--require', preload('m1-online', { online: true })]);
  assert.deepEqual(status(sane.rows, 'container'), ['EXPOSED'], 'harness sanity: the running container trusts the test hosts');
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('m1b')], { PATH: engine('m1b', { curlBody: 'case "$u" in https://self-signed*) exit 60;; *) exit 0;; esac', execFails: '*-emudhra.we-have-a-problem.com*' }) }, ['--require', preload('m1-online', { online: true })]);
  assert.deepEqual(status(r.rows, 'container'), ['UNKNOWN'], JSON.stringify(r.rows.filter((x) => x.kind === 'container')));
});

// ---- M2 ----------------------------------------------------------------------------------------------------------------
test('M2 a runtime that trusts only one distrusted root, while that root\'s test hosts are down, is UNKNOWN, never SAFE', () => {
  const sane = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('m2a')], { PATH: nodeStandIn('m2a', '*-aaa-emudhra*') }, ['--require', preload('m2-up', { online: true })]);
  assert.deepEqual(status(sane.rows, 'node'), ['EXPOSED'], `harness sanity: ${JSON.stringify(sane.rows)}`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('m2b')], { PATH: nodeStandIn('m2b', '*-aaa-emudhra*') }, ['--require', preload('m2-aaa-down', { online: true, down: '-aaa-emudhra' })]);
  assert.deepEqual(status(r.rows, 'node'), ['UNKNOWN'], JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('M2 the same for a container: only one root\'s test hosts answering is UNKNOWN, never SAFE', () => {
  const body = 'case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; *-aaa-emudhra*) exit 0;; *) exit 60;; esac';
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('m2c')], { PATH: engine('m2c', { curlBody: body }) }, ['--require', preload('m2-aaa-down', { online: true, down: '-aaa-emudhra' })]);
  assert.deepEqual(status(r.rows, 'container'), ['UNKNOWN'], JSON.stringify(r.rows.filter((x) => x.kind === 'container')));
});

test('M2 every test host belongs to exactly one distrusted root in the incident file', () => {
  const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
  assert.ok(Array.isArray(inc.canaryRoots) && inc.canaryRoots.length === inc.distrustedRoots.length, 'one group per distrusted root');
  const ids = inc.canaryRoots.flatMap((g) => g.canaries);
  assert.deepEqual([...ids].sort(), [...inc.canaries].sort());
  for (const g of inc.canaryRoots) assert.ok(g.root && g.canaries.length, JSON.stringify(g));
});

test('a test host answered by something else (a TLS-inspecting firewall) is never used: no SAFE', () => {
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('imp')], { PATH: nodeStandIn('imp', 'NOTHING') }, ['--require', preload('impostor', { online: true, issuer: 'FortiGate CA' })]);
  assert.deepEqual(status(r.rows, 'node'), ['UNKNOWN'], JSON.stringify(r.rows));
});

// ---- M3 ----------------------------------------------------------------------------------------------------------------
test('M3 the header check with a --paths folder that isn\'t there: an UNKNOWN row, never SAFE, exit 2', () => {
  const gone = join(dir, 'm3-gone');
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', gone], { HOME: fresh('m3-home') });
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === gone), JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

// ---- M4 ----------------------------------------------------------------------------------------------------------------
test('M4 a header nested deeper than the walk reads is UNKNOWN for its file, never SAFE', () => {
  const h = fresh('m4-home');
  put(join(h, '.gitconfig'), '[user]\n\temail = ada.lovelace@example.org\n');
  let deep = { headers: { 'X-User': 'ada.lovelace@example.org' } };
  for (let i = 0; i < 70; i++) deep = { n: deep };
  put(join(h, '.cursor', 'mcp.json'), JSON.stringify(deep));
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('m4-root')], { HOME: h });
  const row = r.rows.find((x) => x.file === join(h, '.cursor', 'mcp.json'));
  assert.ok(row && row.status !== 'SAFE', JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows));
});

// ---- M5 ----------------------------------------------------------------------------------------------------------------
test('M5 the image check with DOCKER_HOST or DOCKER_CONTEXT set while a local engine answers: an UNKNOWN row says so, exit 2', () => {
  for (const v of ['DOCKER_HOST', 'DOCKER_CONTEXT']) {
    const r = run(['--incident', 'litellm-2026-10', '--paths', fresh(`m5-${v}`)], { PATH: engine(`m5-${v}`), [v]: 'ssh://prod.invalid' }, ['--require', preload('m5-offline')]);
    assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && String(x.reason).includes(v)), `${v}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 2, v);
  }
});

// ---- M6 ----------------------------------------------------------------------------------------------------------------
test('M6 a virtual environment whose lib folder can\'t be opened is reported, never dropped', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const root = fresh('m6-root'), v = join(root, 'app', '.venv');
  put(join(v, 'pyvenv.cfg'), 'home = /x\n'); put(join(v, 'bin', 'python'), '');
  put(join(v, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  lock(join(v, 'lib'));
  const denied = [];
  discover({ roots: [root], pathEnv: '', denied });
  assert.ok(denied.some((d) => d.startsWith(v)), `denied: ${JSON.stringify(denied)}`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], {}, ['--require', preload('m6-offline')]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && String(x.path ?? '').startsWith(v)), JSON.stringify(r.rows));
});

// ---- M7 ----------------------------------------------------------------------------------------------------------------
test('M7 a trust probe gets an allowlisted environment: trust and proxy settings, never code-loading or file-pointing ones', () => {
  const caller = {
    PATH: '/bin', HOME: '/h', SSL_CERT_FILE: '/ca.pem', SSL_CERT_DIR: '/certs', NODE_EXTRA_CA_CERTS: '/extra.pem', HTTPS_PROXY: 'http://proxy:3128', no_proxy: 'localhost',
    NODE_OPTIONS: '--use_openssl_ca --require /evil.js --use-system-ca',
    OPENSSL_CONF: '/evil.cnf', OPENSSL_MODULES: '/evil', SHELLOPTS: 'xtrace', PS4: '$(touch /tmp/x)', 'BASH_FUNC_curl%%': '() { :; }', GCONV_PATH: '/evil',
    RUBYOPT: '-r/evil', PERL5OPT: '-M/evil', JAVA_TOOL_OPTIONS: '-javaagent:/evil', SSLKEYLOGFILE: '/keys', XDG_CONFIG_HOME: '/evil-config', LD_PRELOAD: '/evil.so', DYLD_INSERT_LIBRARIES: '/evil.dylib',
  };
  const e = envFor('probe', {}, caller);
  for (const k of ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'HTTPS_PROXY', 'no_proxy', 'PATH', 'HOME']) assert.equal(e[k], caller[k], `${k} kept`);
  assert.equal(e.NODE_OPTIONS, '--use_openssl_ca --use-system-ca', 'only trust flags, in either spelling');
  for (const k of ['OPENSSL_CONF', 'OPENSSL_MODULES', 'SHELLOPTS', 'PS4', 'BASH_FUNC_curl%%', 'GCONV_PATH', 'RUBYOPT', 'PERL5OPT', 'JAVA_TOOL_OPTIONS', 'SSLKEYLOGFILE', 'XDG_CONFIG_HOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'])
    assert.equal(e[k], undefined, `${k} dropped`);
});

test('M7 a bash shim runtime with SHELLOPTS=xtrace and a PS4 command in the caller\'s environment runs no command', async () => {
  const mark = join(dir, 'm7-ps4-ran');
  const shim = exe(join(fresh('m7-shim'), 'node'), 'exit 1', '/bin/bash');
  const saved = { SHELLOPTS: process.env.SHELLOPTS, PS4: process.env.PS4 };
  process.env.SHELLOPTS = 'xtrace'; process.env.PS4 = `$(touch ${mark})`;
  try { await probe({ kind: 'node', bin: shim }, 'https://127.0.0.1:1/', { timeoutMs: 2000 }); }
  finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
  assert.equal(existsSync(mark), false, 'PS4 ran a command inside the probe');
});

test('M7 the caller\'s NODE_OPTIONS --require never runs inside a probe (a probe that actually starts a child)', async () => {
  const mark = join(dir, 'm7-require-ran');
  const marker = put(join(dir, 'm7-marker.cjs'), `require('fs').writeFileSync(${JSON.stringify(mark)}, 'ran');\n`);
  const saved = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = `--require ${marker}`;
  try { await probe({ kind: 'node', bin: process.execPath }, 'https://127.0.0.1:1/', { timeoutMs: 2000 }); }
  finally { if (saved === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = saved; }
  assert.equal(existsSync(mark), false, 'the caller\'s NODE_OPTIONS --require ran inside a probe');
});

// ---- M8 ----------------------------------------------------------------------------------------------------------------
test('M8 the docs say what the code does', () => {
  const read = (f) => readFileSync(join(ROOT, f), 'utf8');
  for (const f of ['README.md', 'docs/ARCHITECTURE.md']) assert.doesNotMatch(read(f), /every `?node`?, `?curl`? and `?python3`? on (your )?`?PATH/i, `${f}: only the first of each is probed`);
  assert.doesNotMatch(read('docs/ARCHITECTURE.md'), /512 KB/, 'the key scan reads up to 8 MB');
  assert.doesNotMatch(read('SECURITY.md'), /wherever `?DOCKER_HOST`?/, 'DOCKER_HOST is not followed');
  for (const d of ['/srv/www', '/Library/WebServer/Documents']) assert.ok(read('README.md').includes(d), `README lists the default folder ${d}`);
});

// ---- should-fix items ---------------------------------------------------------------------------------------------------
test('under sudo, git keeps SUDO_UID, so repositories the person owns are not refused as "dubious ownership"', () => {
  assert.equal(envFor('git', {}, { PATH: '/bin', SUDO_UID: '501' }).SUDO_UID, '501');
});

test('under sudo with no home folder for the sudo user, an UNKNOWN row says root\'s home was searched instead', { skip: AS_ROOT && 'already root' }, () => {
  const sudo = preload('sudo-nohome', { extra: 'process.getuid = () => 0;' });
  const r = run(['--incident', 'github-actions-2026-10', '--paths', fresh('nohome-root')], { HOME: fresh('nohome-roots-home'), SUDO_USER: 'no-such-user-wardlatch' }, ['--require', sudo]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && String(x.reason).includes('no-such-user-wardlatch')), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('a --paths entry that is a file, not a folder, is an UNKNOWN row: never a SAFE, exit 2', () => {
  const real = fresh('pf-real'), file = put(join(dir, 'pf-file'), 'x');
  const r = run(['--incident', 'github-actions-2026-10', '--paths', real, '--paths', file]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === file), JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('a plugin file too big for the indicator search is UNKNOWN, not a silent skip', () => {
  const root = fresh('wp-root'), site = join(root, 'site');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  put(join(plugin, 'rank-math-pro.php'), '<?php\n/*\n * Version: 3.0.124\n */\n');
  put(join(plugin, 'vendor', 'big.php'), `<?php /* ${'x'.repeat(3 * 1024 * 1024)} */ $u = "rank1cdn";`);
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.ok(r.rows.some((x) => x.status !== 'SAFE' && x.status !== 'REVIEW' && /big\.php|too big|over/i.test(`${x.what} ${x.reason}`)), JSON.stringify(r.rows));
  assert.equal(r.code === 0, false);
});

test('a crash inside Wardlatch exits 2 (could not be tested), never 1 (exposed)', () => {
  const crash = preload('crash', { extra: 'const P = JSON.parse; JSON.parse = (...a) => { if (String(a[0]).includes(\'"canaries"\') || String(a[0]).includes(\'"id"\')) throw new TypeError(\'planted crash\'); return P(...a); };' });
  const r = spawnCli(['--incident', 'github-actions-2026-10', '--paths', fresh('crash-root')], {}, ['--require', crash]);
  assert.match(r.stderr, /planted crash/, 'the fixture: it crashed');
  assert.equal(r.status, 2, r.stderr.slice(0, 300));
});
