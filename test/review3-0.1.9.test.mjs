// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The third strict review of 0.1.9 (d59e114) reproduced these, or found a fix no test held; each test here failed on
// d59e114 for the reason its name gives (or fails when its fix is reverted), and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace every program a
// check would run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { envFor } from '../lib/run.mjs';
import { probe, check } from '../lib/probe.mjs';
import { readCapped } from '../lib/files.mjs';
import { discover } from '../lib/discover.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-review3-')); home = join(dir, 'home'); mkdirSync(home); });
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


// ---- 1: the per-root control forces only that root -------------------------------------------------------------------
test('1 each root\'s control host gets only its own root forced: a chain that finishes at the other root proves nothing', async () => {
  // a curl stand-in for a runtime that trusts only "AAA": a chain completes only through the emSign root (the AAA hosts
  // here send no cross-certificate), so with both roots forced, the AAA host's control passed through emSign
  const pki = fresh('r1-pki');
  const aaa = put(join(pki, 'aaa.pem'), 'ROOT-AAA\n'), ems = put(join(pki, 'ems.pem'), 'ROOT-EMS\n'), both = put(join(pki, 'both.pem'), 'ROOT-AAA\nROOT-EMS\n');
  const curl = exe(join(pki, 'curl'), `ca=; u=; while [ $# -gt 0 ]; do case "$1" in --cacert) ca="$2"; shift;; http*://*) u="$1";; esac; shift; done
[ -n "$ca" ] && grep -q ROOT-EMS "$ca" && exit 0
exit 60`);
  const canaries = [
    { id: 'a', url: 'https://a-aaa.invalid/', up: true, root: 'AAA', pem: aaa },
    { id: 'e', url: 'https://e.invalid/', up: true, root: 'EMS', pem: ems },
  ];
  const r = await check({ kind: 'curl', bin: curl, version: '' }, canaries, { rootsPem: both, controlUrl: 'https://control.invalid/', timeoutMs: 2000 });
  assert.equal(r.status, 'UNKNOWN', JSON.stringify(r));
});

// ---- 2: the person's NODE_TLS_REJECT_UNAUTHORIZED reaches the Node probe --------------------------------------------
test('2 a Node run with certificate checking off in this environment reads EXPOSED, never SAFE', () => {
  const d = fresh('r2-node');
  exe(join(d, 'node'), `[ "$1" = -v ] && { echo v20.0.0; exit 0; }
for a in "$@"; do u="$a"; done
[ -n "$WARDLATCH_CA" ] && exit 0
case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; esac
[ "$NODE_TLS_REJECT_UNAUTHORIZED" = 0 ] && exit 0
exit 1`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('r2-root')], { PATH: d, NODE_TLS_REJECT_UNAUTHORIZED: '0' }, ['--require', preload('r2-online', { online: true })]);
  assert.deepEqual(r.rows.filter((x) => x.kind === 'node').map((x) => x.status), ['EXPOSED'], JSON.stringify(r.rows));
});

// ---- 3: trust settings the probe doesn't get are an UNKNOWN row ------------------------------------------------------
test('3 a CA added through NODE_OPTIONS --require is not tested: an UNKNOWN row in --json, exit 2; a memory flag is not', () => {
  const inject = put(join(dir, 'r3-inject.cjs'), '// adds a CA, as mac-ca does\n');
  const node = nodeStandIn('r3', 'NOTHING');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('r3-root')], { PATH: node, NODE_OPTIONS: `--require ${inject}` }, ['--require', preload('r3-online', { online: true })]);
  assert.ok(r.rows.some((x) => x.kind === 'environment' && x.status === 'UNKNOWN' && x.reason.includes('NODE_OPTIONS')), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
  const b = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('r3b-root')], { PATH: node, NODE_OPTIONS: '--max-old-space-size=4096' }, ['--require', preload('r3-online', { online: true })]);
  assert.ok(!b.rows.some((x) => x.kind === 'environment'), JSON.stringify(b.rows));
});

// ---- 4: a sudo user name that isn't a plain word ---------------------------------------------------------------------
test('4 under sudo by a directory user (ada@corp.example) with no home folder found: an UNKNOWN row, never root\'s home as SAFE', { skip: AS_ROOT && 'already root' }, () => {
  const sudo = preload('r4-sudo', { extra: 'process.getuid = () => 0;' });
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('r4-root')], { HOME: fresh('r4-roots-home'), SUDO_USER: 'ada@corp.example' }, ['--require', sudo]);
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && String(x.reason).includes('ada@corp.example')), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

// ---- 5: the receipt guard --------------------------------------------------------------------------------------------
test('5 a SAFE row without a receipt is withdrawn, and the CLI runs every row through the guard', async () => {
  const { withdrawUnreceipted } = await import('../lib/report.mjs');
  const rows = [{ kind: 'x', status: 'SAFE' }, { kind: 'y', status: 'SAFE', searched: ['  '] }, { kind: 'z', status: 'SAFE', searched: ['/a'] }, { kind: 'w', status: 'EXPOSED' }];
  const out = withdrawUnreceipted(rows);
  assert.deepEqual(rows.map((r) => r.status), ['UNKNOWN', 'UNKNOWN', 'SAFE', 'EXPOSED']);
  assert.equal(out.length, 2);
  const bin = readFileSync(BIN, 'utf8');
  assert.match(bin, /withdrawUnreceipted\(all\)[\s\S]*const count = \{/, 'the guard runs on every row before the count and the exit code');
});

// ---- 6: WordPress search caps ----------------------------------------------------------------------------------------
const wpSite = (name) => {
  const root = fresh(name), site = join(root, 'site');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  put(join(plugin, 'rank-math-pro.php'), '<?php\n/*\n * Version: 3.0.124\n */\n');
  return { root, plugin };
};
test('6 the indicator search past 4,000 files, or deeper than 12 folders, is UNKNOWN, not a silent SAFE', () => {
  const many = wpSite('r6-many');
  for (let i = 0; i < 4001; i++) put(join(many.plugin, 'f', `${i}.php`), '<?php');
  const a = run(['--incident', 'wordpress-plugins-2026-10', '--paths', many.root]);
  assert.ok(a.rows.some((x) => x.status === 'UNKNOWN' && /4000|4,000/.test(String(x.reason))), JSON.stringify(a.rows.filter((x) => x.status !== 'SAFE')));
  const deep = wpSite('r6-deep');
  put(join(deep.plugin, ...Array.from({ length: 14 }, (_, i) => `d${i}`), 'x.php'), '<?php $u = "rank1cdn";');
  const b = run(['--incident', 'wordpress-plugins-2026-10', '--paths', deep.root]);
  assert.ok(b.rows.some((x) => x.status !== 'SAFE' && /deeper|EXPOSED/.test(`${x.reason} ${x.status}`)), JSON.stringify(b.rows));
  assert.notEqual(b.code, 0);
});

// ---- 7: a locked site-packages folder --------------------------------------------------------------------------------
test('7 a virtual environment whose site-packages can\'t be opened is reported, never dropped', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const root = fresh('r7-root'), v = join(root, 'app', '.venv'), sp = join(v, 'lib', 'python3.12', 'site-packages');
  put(join(v, 'pyvenv.cfg'), 'home = /x\n'); put(join(v, 'bin', 'python'), '');
  put(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  lock(sp);
  const denied = [];
  discover({ roots: [root], pathEnv: '', denied });
  assert.ok(denied.includes(sp), `denied: ${JSON.stringify(denied)}`);
});

// ---- 8: the container probe's python3 --------------------------------------------------------------------------------
test('8 a python3 inside a container that crashes (exit 1) on the test hosts is an error, never a refusal', () => {
  const box = fresh('r8-box'), eng = fresh('r8-engine');
  // answers as the probe's own script would: a certificate refusal with the code that script uses for one (read from
  // the script it is given), and on the test hosts a crash, which Python exits 1 for
  exe(join(box, 'python3'), `for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done
refused=1; case "$*" in *"sys.exit(10 if"*) refused=10;; esac
case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; https://self-signed*) exit $refused;; *) exit 1;; esac`);
  exe(join(eng, 'docker'), `if [ "$1" = ps ]; then printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0; fi
if [ "$1" = exec ]; then while [ $# -gt 0 ] && [ "$1" != sh ]; do shift; done; shift; PATH=${JSON.stringify(box)} exec /bin/sh "$@"; fi
exit 0`);
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('r8-root')], { PATH: eng }, ['--require', preload('r8-online', { online: true })]);
  assert.deepEqual(r.rows.filter((x) => x.kind === 'container').map((x) => x.status), ['UNKNOWN'], JSON.stringify(r.rows.filter((x) => x.kind === 'container')));
});

// ---- 9: the header check's locked folders ----------------------------------------------------------------------------
test('9 a folder under --paths the header check can\'t open is an UNKNOWN row, never SAFE', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const root = fresh('r9-root'), vault = join(root, 'vault');
  put(join(vault, 'app', '.git', 'HEAD'), 'ref: refs/heads/main\n');
  lock(vault);
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', root], { HOME: fresh('r9-home') });
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === vault), JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'), JSON.stringify(r.rows));
});

// ---- 10: exactly one result line -------------------------------------------------------------------------------------
test('10 a container whose output carries a second result line of its own is UNKNOWN, never SAFE', () => {
  const body = 'case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; https://self-signed*) exit 60;; *) echo "tool=curl wardlatch-result=refused"; exit 0;; esac';
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('r10-root')], { PATH: engine('r10', { curlBody: body }) }, ['--require', preload('r10-online', { online: true })]);
  assert.deepEqual(r.rows.filter((x) => x.kind === 'container').map((x) => x.status), ['UNKNOWN'], JSON.stringify(r.rows.filter((x) => x.kind === 'container')));
});

// ---- 11: a crash after an EXPOSED line --------------------------------------------------------------------------------
test('11 a crash after an EXPOSED line exits 1 (exposed), not 2', () => {
  const d = fresh('r11-path');
  exe(join(d, 'php'), 'echo "PHP 8.2.0 (cli)"');
  const crash = preload('r11-crash', { extra: 'const S = JSON.stringify; JSON.stringify = (v, ...a) => { if (v && v.tool === \'wardlatch\') throw new TypeError(\'planted crash\'); return S(v, ...a); };' });
  const r = spawnCli(['--incident', 'php-2026-10'], { PATH: d }, ['--require', crash]);
  assert.match(r.stderr, /planted crash/, 'the fixture: it crashed while writing the results');
  assert.equal(r.status, 1, r.stderr.slice(0, 300));
});

// ---- 12: reads are capped by what is read -----------------------------------------------------------------------------
test('12 a file that reports size 0 but has more is still capped (Linux /proc)', { skip: process.platform !== 'linux' && 'needs /proc' }, () => {
  assert.equal(readCapped('/proc/self/status', 16), null);
  assert.ok(readCapped('/proc/self/status', 1024 * 1024)?.length > 16);
});
