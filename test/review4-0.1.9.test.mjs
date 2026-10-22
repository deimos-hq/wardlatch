// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The fourth strict review of 0.1.9 (47d4638) reproduced these, or found a fix no test held; each test here failed on
// 47d4638 for the reason its name gives (or fails when its fix is reverted), and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace every program a
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
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-review4-')); home = join(dir, 'home'); mkdirSync(home); });
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



const trust = (name, env, extra = {}) => run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh(`${name}-root`)], { PATH: nodeStandIn(name, 'NOTHING'), ...env }, ['--require', preload(`${name}-online`, { online: true, ...extra })]);
const envRow = (r) => r.rows.find((x) => x.kind === 'environment');

test('1 NODE_OPTIONS that add no trust, in either spelling, are not an UNKNOWN row: a clean machine exits 0', () => {
  for (const o of ['--max_old_space_size=4096', '--max-old-space-size=4096', '--openssl-legacy-provider', '--dns-result-order=ipv4first', '--no_warnings']) {
    const r = trust(`n${o.replace(/\W/g, '')}`, { NODE_OPTIONS: o });
    assert.equal(envRow(r), undefined, `${o}: ${JSON.stringify(envRow(r))}`);
    assert.equal(r.code, 0, `${o}: ${JSON.stringify(r.rows)}`);
  }
});

test('2 a curl start-up file the person\'s curl reads through CURL_HOME or XDG_CONFIG_HOME, and the probe\'s doesn\'t: an UNKNOWN row', () => {
  const h = fresh('c2-home');
  for (const [k, rel] of [['CURL_HOME', '.curlrc'], ['CURL_HOME', join('.config', 'curlrc')], ['XDG_CONFIG_HOME', 'curlrc']]) {
    const base = fresh(`c2-${k}-${rel.replace(/\W/g, '')}`);
    put(join(base, rel), 'insecure\n');
    const r = trust(`c2${k}${rel.replace(/\W/g, '')}`, { HOME: h, [k]: base });
    assert.ok(envRow(r)?.reason.includes('curl'), `${k}/${rel}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 2);
  }
  // the same file the probe reads anyway (XDG_CONFIG_HOME=~/.config) is no row
  const h2 = fresh('c2-home2'); put(join(h2, '.config', 'curlrc'), 'insecure\n');
  const same = trust('c2same', { HOME: h2, XDG_CONFIG_HOME: join(h2, '.config') });
  assert.equal(envRow(same), undefined, JSON.stringify(envRow(same)));
});

test('3 OPENSSL_CONF in the environment: an UNKNOWN row, exit 2', () => {
  const r = trust('o3', { OPENSSL_CONF: put(join(dir, 'o3.cnf'), '# a config\n') });
  assert.ok(envRow(r)?.reason.includes('OPENSSL_CONF'), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

test('4 a trust probe gets NIX_SSL_CERT_FILE (Nix\'s CA file), as the person\'s programs do', () => {
  assert.equal(envFor('probe', {}, { PATH: '/bin', NIX_SSL_CERT_FILE: '/nix/ca.pem' }).NIX_SSL_CERT_FILE, '/nix/ca.pem');
});

test('5 an environment row never stands in for the machine\'s own runtimes: none found is still its own UNKNOWN row', () => {
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('h5-root')], { OPENSSL_CONF: '/x.cnf' }, ['--require', preload('h5-online', { online: true })]);
  assert.ok(envRow(r), 'the fixture: an environment row');
  assert.ok(r.rows.some((x) => x.kind === 'runtimes' && x.status === 'UNKNOWN'), JSON.stringify(r.rows));
});

test('6 root running sudo (SUDO_USER=root) searches root\'s own home: no "home not found" row', { skip: AS_ROOT && 'already root' }, () => {
  const sudo = preload('s6-sudo', { extra: 'process.getuid = () => 0;' });
  const r = run(['--incident', 'github-actions-2026-10', '--paths', fresh('s6-root')], { HOME: fresh('s6-home'), SUDO_USER: 'root' }, ['--require', sudo]);
  assert.ok(!r.rows.some((x) => x.kind === 'home'), JSON.stringify(r.rows));
  assert.equal(r.code, 0, JSON.stringify(r.rows));
});
