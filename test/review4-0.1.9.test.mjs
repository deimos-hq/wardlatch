// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The fourth strict review of 0.1.9 (47d4638) reproduced these, or found a fix no test held; each test here failed on
// 47d4638 for the reason its name gives (or fails when its fix is reverted), and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace every program a
// check would run.
import './support/no-real-home.cjs';
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
import { checked } from './support/output-checks.mjs';

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
const spawnCli = (args, env = {}, nodeArgs = []) => checked([...args, '--json'], spawnSync(process.execPath, [...nodeArgs, BIN, ...args, '--json'], { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), LANG: 'C', ...env }, cwd: dir, timeout: 120000, killSignal: 'SIGKILL' }));
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
  // (--disable-warning only where this Node accepts it in NODE_OPTIONS: Node 18 refuses to start with it)
  for (const o of ['--max_old_space_size=4096', '--max-old-space-size=4096', '--openssl-legacy-provider', '--dns-result-order=ipv4first', '--no_warnings', '--disable-warning=ExperimentalWarning', '--experimental-vm-modules'].filter((f) => process.allowedNodeEnvironmentFlags.has(f.split('=')[0]))) {
    const r = trust(`n${o.replace(/\W/g, '')}`, { NODE_OPTIONS: o });
    assert.equal(envRow(r), undefined, `${o}: ${JSON.stringify(envRow(r))}`);
    assert.equal(r.code, 0, `${o}: ${JSON.stringify(r.rows)}`);
  }
});

test('2 the probe\'s curl reads the start-up file the person\'s curl reads (CURL_HOME, XDG_CONFIG_HOME): one that turns checking off reads EXPOSED', () => {
  // a curl stand-in that reads its start-up file the way curl 8.7.1 does: $CURL_HOME/.curlrc, $CURL_HOME/.config/curlrc,
  // $XDG_CONFIG_HOME/.curlrc, then ~/.curlrc; `insecure` there makes every connection succeed
  const d = fresh('c2-path');
  exe(join(d, 'curl'), `[ "$1" = --version ] && { echo "curl 8.7.1"; exit 0; }
for f in "\${CURL_HOME:+$CURL_HOME/.curlrc}" "\${CURL_HOME:+$CURL_HOME/.config/curlrc}" "\${XDG_CONFIG_HOME:+$XDG_CONFIG_HOME/.curlrc}" "$HOME/.curlrc"; do
  [ -n "$f" ] && [ -f "$f" ] && { /usr/bin/grep -q insecure "$f" && exit 0; break; }
done
for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done
case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; esac
for a in "$@"; do [ "$a" = --cacert ] && exit 0; done
exit 60`);
  for (const [k, rel] of [['CURL_HOME', '.curlrc'], ['CURL_HOME', join('.config', 'curlrc')], ['XDG_CONFIG_HOME', '.curlrc']]) {
    const base = fresh(`c2-${k}-${rel.replace(/\W/g, '')}`);
    put(join(base, rel), 'insecure\n');
    const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh(`c2-${k}-${rel.replace(/\W/g, '')}-root`)], { PATH: d, HOME: fresh(`c2-${k}-${rel.replace(/\W/g, '')}-home`), [k]: base }, ['--require', preload('c2-online', { online: true })]);
    assert.deepEqual(r.rows.filter((x) => x.kind === 'curl').map((x) => x.status), ['EXPOSED'], `${k}/${rel}: ${JSON.stringify(r.rows)}`);
  }
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

test('7 a relative CA file in the person\'s environment is made absolute before a probe runs from /', () => {
  // the probe runs from /: a relative NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE or REQUESTS_CA_BUNDLE would name another file
  const d = fresh('ca7-path'), log = join(dir, 'ca7.log');
  exe(join(d, 'node'), `[ "$1" = -v ] && { echo v20.0.0; exit 0; }
echo "$NODE_EXTRA_CA_CERTS|$CURL_CA_BUNDLE|$REQUESTS_CA_BUNDLE" >> ${JSON.stringify(log)}
exit 1`);
  run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('ca7-root')], { PATH: d, NODE_EXTRA_CA_CERTS: 'ca/extra.pem', CURL_CA_BUNDLE: 'ca/curl.pem', REQUESTS_CA_BUNDLE: 'ca/req.pem' }, ['--require', preload('ca7-online', { online: true })]);
  const seen = readFileSync(log, 'utf8').trim().split('\n').at(-1).split('|');
  assert.deepEqual(seen, [join(dir, 'ca/extra.pem'), join(dir, 'ca/curl.pem'), join(dir, 'ca/req.pem')]);
});

test('8 macOS\'s own folders (the Trash, the Photos library) are never searched, so --paths ~ doesn\'t end in UNKNOWN for them', { skip: AS_ROOT && 'root opens every folder' }, () => {
  const h = fresh('m8-home');
  for (const p of [join(h, '.Trash', 'x'), join(h, 'Pictures', 'Photos Library.photoslibrary', 'x'), join(h, 'Pictures', 'Photo Booth Library', 'x')]) { put(join(p, 'f'), ''); lock(dirname(join(p, 'f'))); }
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const r = run(['--incident', id, '--paths', h], { HOME: h, PATH: '/usr/bin:/bin' });
    assert.ok(!r.rows.some((x) => x.status === 'UNKNOWN'), `${id}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 0, id);
  }
});

test('9 the header check reads $CURL_HOME/.config/curlrc, which curl reads too', () => {
  const h = fresh('h9-home'), ch = fresh('h9-curlhome');
  put(join(h, '.gitconfig'), '[user]\n\temail = ada.lovelace@example.org\n');
  put(join(ch, '.config', 'curlrc'), '-H "From: ada.lovelace@example.org"\n');
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('h9-root')], { HOME: h, CURL_HOME: ch });
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.file === join(ch, '.config', 'curlrc')), JSON.stringify(r.rows));
});
