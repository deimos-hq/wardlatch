// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Red-team scenarios (from the 0.1.9 bug hunt): each test recreates one real-world machine setup and asserts what a
// CORRECT tool would say. A failing test is a finding. Offline: no test reaches a network host (the TLS handshake is
// faked in a --require preload, net.connect throws, and every program a check runs is a stand-in in the test folder,
// except real git in the git-based scenarios, which never fetches). Nothing is written inside the repository.
// Part of `npm test`; point it at another checkout with WARDLATCH_DIR=/path/to/wardlatch.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checked } from './support/output-checks.mjs';

const WL = process.env.WARDLATCH_DIR || join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(WL, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
const DARWIN = process.platform === 'darwin';
const CC = ['/usr/bin/cc', '/usr/bin/gcc', '/usr/bin/clang'].find((p) => existsSync(p));
// Documented limits: scenarios the released code is documented NOT to meet (CHANGELOG.md 0.1.9: "Known limits", and one
// owner decision under "Not tested, now said"). They run as
// todo, so they stay visible in every run without failing it; closing one is a code change with its own CHANGELOG line,
// and then its entry here goes. A scenario that is not in this list and fails is a finding.
const KNOWN_LIMITS = new Map([
  ['trust: a PyPy virtual environment (lib/pypy3.10/site-packages) with an old certifi is tested, not dropped',
    'searches don\'t reach PyPy environments (lib/pypy3.x)'],
  ['containers: a DNS filter on the containers\' network (Docker daemon.json "dns") answers the test hosts with its own certificate: not SAFE',
    'inside containers, a refusal can\'t be told from a DNS filter or TLS-inspecting proxy answering with its own certificate'],
  ['containers: DOCKER_HOST set to Colima\'s socket while Colima is stopped (socket gone) is not could-not-be-tested',
    'DOCKER_HOST naming a socket whose folder is gone is not followed: UNKNOWN'],
  ['php: an OpenLiteSpeed/CyberPanel server whose sites run lsphp81 (/usr/local/lsws/lsphp81/bin) is not SAFE because /usr/bin/php is fixed',
    'searches don\'t reach OpenLiteSpeed\'s lsphp installs'],
  ['php: a DirectAdmin server\'s second PHP (/usr/local/php81/bin/php, php-fpm81 in sbin) is not SAFE because /usr/bin/php is fixed',
    'searches don\'t reach DirectAdmin\'s /usr/local/php* installs'],
  ['php: PATH written as "~/bin:..." (bash and sh expand the ~; Wardlatch drops the entry) hides the old php the shell runs',
    'a ~ written literally in PATH is dropped with the other relative entries'],
  ['litellm: the compromised image on a Mac where Docker Desktop is quit (its images still on disk) is not SAFE',
    'a stopped Docker Desktop or Podman machine gives a REVIEW line saying its local images weren\'t checked (owner, 23 Oct; CHANGELOG 0.1.9, "Not tested, now said")'],
  ['keys: a repository in a hidden folder under the searched folder (~/Development/.archive/legacy) is scanned',
    'searches don\'t reach repositories in hidden folders'],
  ['keys: a repository five levels down (`--paths ~` with ~/go/src/github.com/acme/api) is scanned, or the gap is reported',
    'searches don\'t reach repositories more than 4 levels down'],
  ['keys: a repository linked into the searched folder (~/Development/api -> /Volumes/Work/api) is scanned',
    'searches don\'t reach repositories linked in by a symbolic link'],
  ['workflows: a workflow committed on 10 Oct, followed by a commit from a machine with a wrong clock (dated August), is still listed',
    'git stops reading a branch at a commit dated before the incident, so a workflow behind a wrong-clock commit can be missed'],
  ['wordpress: a site linked into the web root (/var/www/html -> /srv/wordpress) is checked',
    'searches don\'t reach a site linked into a web root by a symbolic link'],
  ['--paths given for a folder and a folder inside it reports each finding once',
    'a finding in the inner folder is reported twice'],
  ['--list --json prints the incident list as JSON',
    '--list --json prints text'],
]);
const declared = new Set();
const scenario = (name, ...rest) => {
  const fn = rest.pop(), opts = rest[0] ?? {};
  declared.add(name);
  return test(name, KNOWN_LIMITS.has(name) ? { ...opts, todo: `documented limit (CHANGELOG 0.1.9): ${KNOWN_LIMITS.get(name)}` } : opts, fn);
};
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-redteam-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => {
  for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } }
  rmSync(dir, { recursive: true, force: true });
});

// ---- helpers ------------------------------------------------------------------------------------------------------------
const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body) => put(p, `#!/bin/sh\n${body}\n`, 0o755);
let n = 0;
const fresh = (name) => { const d = join(dir, `${name}-${++n}`); mkdirSync(d, { recursive: true }); return d; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };
// a compiled program that prints `text` (a later copy on PATH is run only when it is compiled)
const native = (path, text) => {
  mkdirSync(dirname(path), { recursive: true });
  const src = `${path}.c`; writeFileSync(src, `#include <stdio.h>\nint main(void){puts(${JSON.stringify(text)});return 0;}\n`);
  execFileSync(CC, ['-o', path, src], { stdio: 'pipe' }); rmSync(src); return path;
};

// The preload: system folders hidden, chosen absolute paths redirected into fixtures (fs and child_process alike), owners
// faked per path, the clock moved, the reachability handshake faked (per-host issuer, hosts down), the network blocked, and
// no program run outside this test's folder.
const preload = (name, { online = false, issuer = 'EM DV TLS CA - G3B', issuerFor = [], down = null, redirects = {}, uids = {}, now = null, extra = '' } = {}) => {
  const p = join(dir, `${name}-${++n}.cjs`);
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), { EventEmitter } = require('node:events');
const RED = ${JSON.stringify(Object.entries(redirects))};
const UIDS = new Map(${JSON.stringify(Object.entries(uids))});
const SYS = /^\\/(usr|etc|opt|bin|sbin|System|Library|Applications|home|var\\/lib|var\\/www|srv)(\\/|$)/;
// never hide the code under test, this test's folder or Node itself (on CI they live under /home and /opt)
const KEEP = ${JSON.stringify([WL, dir, dirname(process.execPath)])};
const hidden = (p) => typeof p === 'string' && SYS.test(p) && !KEEP.some((k) => p === k || p.startsWith(k + '/'));
const map = (p) => { if (Buffer.isBuffer(p)) p = p.toString(); if (typeof p !== 'string') return p; for (const [f, t] of RED) if (p === f || p.startsWith(f + '/')) return t + p.slice(f.length); return p; };
const gone = () => Object.assign(new Error('hidden'), { code: 'ENOENT' });
const ex = fs.existsSync; fs.existsSync = (p) => { p = map(p); return !hidden(p) && ex(p); };
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync', 'accessSync', 'readFileSync']) {
  const o = fs[k], native = o.native;
  fs[k] = function (p, ...a) {
    p = map(p);
    if (hidden(p)) throw gone();
    const r = o.call(this, p, ...a);
    if ((k === 'statSync' || k === 'lstatSync') && r && UIDS.has(String(p))) return Object.assign(Object.create(Object.getPrototypeOf(r)), r, { uid: UIDS.get(String(p)) });
    return r;
  };
  if (native) fs[k].native = fs[k];
}
${now ? `Date.now = () => ${Number(now)};` : ''}
const DOWN = ${down ? `new RegExp(${JSON.stringify(down)})` : 'null'};
const ISS = ${JSON.stringify(issuerFor)}.map(([r, i]) => [new RegExp(r), i]);
tls.connect = (...a) => { const o = a.find((x) => x && typeof x === 'object') || {}, cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s;
  const host = String(o.host || o.servername);
  const iss = (ISS.find(([r]) => r.test(host)) || [null, ${JSON.stringify(issuer)}])[1];
  s.getPeerCertificate = () => ({ issuer: { CN: iss } });
  const up = ${online} && !(DOWN && DOWN.test(host));
  process.nextTick(() => (up ? cb && cb() : s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' })))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const DIR = ${JSON.stringify(dir)};
const guard = (o) => function (f, ...r) { f = map(f); if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
${extra}
require('node:module').syncBuiltinESMExports();
`);
  return ['--require', p];
};

const spawnCli = (args, env = {}, nodeArgs = [], { cwd = dir, json = true } = {}) => checked([...args, ...(json ? ['--json'] : [])], spawnSync(process.execPath, [...nodeArgs, BIN, ...args, ...(json ? ['--json'] : [])],
  { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), LANG: 'C', ...env }, cwd, timeout: 180000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024 }));
const run = (args, env = {}, nodeArgs = [], opts = {}) => {
  const r = spawnCli(args, env, nodeArgs, opts);
  let j; try { j = JSON.parse(r.stdout); } catch { assert.fail(`not JSON (exit ${r.status}, signal ${r.signal}): ${String(r.stderr).slice(0, 600)}`); }
  return { code: r.status, rows: j.results, json: j };
};
// real git, no preload (only git runs in these incidents)
const sys = (args, env = {}) => run(args, { PATH: '/usr/bin:/bin', ...env });
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');
const show = (r) => JSON.stringify(r.rows.map(({ incident, searched, fix, ...x }) => x)).slice(0, 1500);

const GITENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' };
const gitRepo = (path) => {
  mkdirSync(path, { recursive: true });
  const g = (args, env = {}) => execFileSync('git', ['-C', path, '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', ...args], { stdio: 'pipe', env: { ...GITENV, ...env } }).toString();
  g(['init', '-q', '-b', 'main']);
  const commit = (msg = 'add', date, committerDate = date) => { g(['add', '-A']); g(['commit', '-qm', msg, '--allow-empty'], date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: committerDate } : {}); };
  return { g, commit };
};
const AWS = 'AKIA' + 'Z7Q4R2M8K3W6P5N1';   // shaped like a real key ID, no placeholder word in it
const EMAIL = 'ada.lovelace@example.org';
const gitconfigId = (h) => put(join(h, '.gitconfig'), `[user]\n\tname = Ada Lovelace\n\temail = ${EMAIL}\n`);

// stand-in runtimes. The positive control forces the incident's root PEMs in (node: WARDLATCH_CA, python: a 6th arg,
// curl: a --cacert ending in root-*.pem / roots.pem).
const ROOTPEM = 'root-aaa.pem|*root-emsign.pem|*roots.pem';
const nodeRt = (d, normal = 'exit 1', forced = 'exit 0') => exe(join(d, 'node'), `[ "$1" = -v ] && { echo v22.0.0; exit 0; }
u="$3"
if [ -n "$WARDLATCH_CA" ]; then ${forced}; fi
${normal}`);
const pythonRt = (d, normal = 'exit 1', forced = 'exit 0') => exe(join(d, 'python3'), `[ "$1" = -V ] && { echo "Python 3.12.1"; exit 0; }
u="$5"
if [ -n "$6" ]; then ${forced}; fi
${normal}`);
const curlRt = (d, normal = 'exit 60', forced = 'exit 0') => exe(join(d, 'curl'), `[ "$1" = --version ] && { echo "curl 8.7.1 (x86_64-apple-darwin) libcurl/8.7.1"; exit 0; }
ca=""; prev=""; u=""
for a in "$@"; do [ "$prev" = --cacert ] && ca="$a"; case "$a" in http*://*) u="$a";; esac; prev="$a"; done
case "$ca" in *${ROOTPEM}) ${forced};; esac
${normal}`);

// a docker stand-in: ps lists one container; exec runs the probe script in a box whose curl answers per `curlBody`
const engine = (name, { ps = "printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0", exec = '', curlBody, images = "echo 'python:3.12@sha256:0000'; exit 0" } = {}) => {
  const box = fresh(`${name}-box`), eng = fresh(`${name}-engine`);
  exe(join(box, 'curl'), `for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done\n${curlBody ?? 'case "$u" in https://self-signed*) exit 60;; https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac'}`);
  exe(join(eng, 'docker'), `if [ "$1" = ps ]; then ${ps}; fi
if [ "$1" = images ]; then ${images}; fi
if [ "$1" = exec ]; then
  ${exec || ':'}
  while [ $# -gt 0 ] && [ "$1" != sh ]; do shift; done; shift; PATH=${JSON.stringify(box)} exec /bin/sh "$@"; fi
exit 0`);
  return eng;
};
const trust = (env, pre, extraArgs = ['--no-containers']) => run(['--incident', 'emudhra-2026-10', ...extraArgs, '--paths', fresh('trust-root')], env, pre);
const ofKind = (r, kind) => r.rows.filter((x) => x.kind === kind);

// =========================================================================================================================
// TRUST (emudhra-2026-10)
// =========================================================================================================================
scenario('trust: a Python that trusts only one of the two roots (emSign) is EXPOSED for that root\'s hosts', () => {
  const d = fresh('t1');
  pythonRt(d, 'case "$u" in *-aaa-emudhra*) exit 1;; *-emudhra.we-have-a-problem.com*) exit 0;; esac; exit 1');
  const r = trust({ PATH: d }, preload('t1', { online: true }));
  const py = ofKind(r, 'python');
  assert.deepEqual(py.map((x) => x.status), ['EXPOSED'], show(r));
  assert.equal(py[0].trusted.length, 6, show(r));
  assert.equal(r.code, 1);
});

scenario('trust: behind a TLS-inspecting corporate proxy (HTTPS_PROXY) every connection is re-signed: UNKNOWN, never SAFE', () => {
  const d = fresh('t2');
  pythonRt(d, '[ -n "$HTTPS_PROXY" ] && exit 1; exit 1', '[ -n "$HTTPS_PROXY" ] && exit 1; exit 0');
  const r = trust({ PATH: d, HTTPS_PROXY: 'http://proxy.corp.invalid:3128' }, preload('t2', { online: true }));
  assert.deepEqual(ofKind(r, 'python').map((x) => x.status), ['UNKNOWN'], show(r));
  assert.equal(r.code, 2);
});

scenario('trust: a proxy that refuses CONNECT to the test hosts (curl exit 56) is UNKNOWN, never SAFE', () => {
  const d = fresh('t3');
  curlRt(d, '[ -n "$https_proxy" ] && exit 56; exit 60', '[ -n "$https_proxy" ] && exit 56; exit 0');
  const r = trust({ PATH: d, https_proxy: 'http://proxy.corp.invalid:3128' }, preload('t3', { online: true }));
  assert.deepEqual(ofKind(r, 'curl').map((x) => x.status), ['UNKNOWN'], show(r));
  assert.equal(r.code, 2);
});

scenario('trust: SSL_CERT_FILE (a relative path) pointing at a stale bundle makes Python EXPOSED', () => {
  const d = fresh('t4'), cwd = fresh('t4-cwd'); put(join(cwd, 'stale.pem'), '-----BEGIN CERTIFICATE-----\n');
  pythonRt(d, 'case "$SSL_CERT_FILE" in /*) [ -f "$SSL_CERT_FILE" ] && exit 0;; esac; exit 1');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('t4-root')], { PATH: d, SSL_CERT_FILE: 'stale.pem' }, preload('t4', { online: true }), { cwd });
  assert.deepEqual(ofKind(r, 'python').map((x) => x.status), ['EXPOSED'], show(r));
  assert.equal(r.code, 1);
});

scenario('trust: a project virtual environment with certifi 2024.2.2 is EXPOSED (its bundle tested with curl --cacert)', () => {
  const d = fresh('t5'), root = fresh('t5-root'), v = join(root, 'api', '.venv');
  const bundle = put(join(v, 'lib', 'python3.11', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  put(join(v, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(v, 'bin', 'python'), '');
  put(join(v, 'lib', 'python3.11', 'site-packages', 'certifi-2024.2.2.dist-info', 'METADATA'), 'Name: certifi\nVersion: 2024.2.2\n');
  curlRt(d, `[ "$ca" = ${JSON.stringify(bundle)} ] && exit 0; exit 60`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], { PATH: d }, preload('t5', { online: true }));
  const row = r.rows.find((x) => x.env === v);
  assert.ok(row && row.status === 'EXPOSED' && row.certifi === '2024.2.2', show(r));
  assert.equal(r.code, 1);
});

scenario('trust: a PyPy virtual environment (lib/pypy3.10/site-packages) with an old certifi is tested, not dropped', () => {
  const d = fresh('t6'), root = fresh('t6-root'), v = join(root, 'worker', '.venv');
  const bundle = put(join(v, 'lib', 'pypy3.10', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  put(join(v, 'pyvenv.cfg'), 'home = /opt/pypy/bin\nimplementation = PyPy\n'); put(join(v, 'bin', 'python'), '');
  put(join(v, 'lib', 'pypy3.10', 'site-packages', 'certifi-2024.2.2.dist-info', 'METADATA'), 'Name: certifi\nVersion: 2024.2.2\n');
  curlRt(d, `[ "$ca" = ${JSON.stringify(bundle)} ] && exit 0; exit 60`);
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', root], { PATH: d }, preload('t6', { online: true }));
  const row = r.rows.find((x) => x.env === v);
  assert.ok(row && row.status !== 'SAFE', `the PyPy environment's certifi has no row: ${show(r)}`);
  assert.notEqual(r.code, 0);
});

scenario('trust: NODE_EXTRA_CA_CERTS adding the compromised root makes Node EXPOSED', () => {
  const d = fresh('t7'), extra = put(join(fresh('t7-ca'), 'corp-extra.pem'), '-----BEGIN CERTIFICATE-----\n');
  nodeRt(d, '[ -n "$NODE_EXTRA_CA_CERTS" ] && [ -f "$NODE_EXTRA_CA_CERTS" ] && exit 0; exit 1');
  const r = trust({ PATH: d, NODE_EXTRA_CA_CERTS: extra }, preload('t7', { online: true }));
  assert.deepEqual(ofKind(r, 'node').map((x) => x.status), ['EXPOSED'], show(r));
});

scenario('trust: REQUESTS_CA_BUNDLE pointing at a stale corporate bundle (what requests and pip use) is not reported SAFE', () => {
  // urllib (the probe) ignores REQUESTS_CA_BUNDLE, as the real one does; the bundle itself trusts the compromised roots
  const d = fresh('t8'), stale = put(join(fresh('t8-ca'), 'corp-bundle.pem'), '-----BEGIN CERTIFICATE-----\n');
  pythonRt(d); nodeRt(d); curlRt(d, `[ "$ca" = ${JSON.stringify(stale)} ] && exit 0; exit 60`);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: stale }, preload('t8', { online: true }));
  assert.notEqual(r.code, 0, `a stale REQUESTS_CA_BUNDLE was never tested and the run passed: ${show(r)}`);
});

scenario('trust: test hosts partly down (both roots still covered) on a fixed machine is a real SAFE, exit 0', () => {
  const d = fresh('t9'); nodeRt(d);
  const r = trust({ PATH: d }, preload('t9', { online: true, down: '^(dv|ov)-g3b' }));
  assert.deepEqual(ofKind(r, 'node').map((x) => x.status), ['SAFE'], show(r));
  assert.equal(r.code, 0, show(r));
});

scenario('trust: every AAA test host answered by an impostor issuer (FortiGate) leaves a refusing runtime UNKNOWN', () => {
  const d = fresh('t10'); nodeRt(d);
  const r = trust({ PATH: d }, preload('t10', { online: true, issuerFor: [['-aaa-', 'FortiGate CA']] }));
  assert.deepEqual(ofKind(r, 'node').map((x) => x.status), ['UNKNOWN'], show(r));
  assert.equal(r.code, 2);
});

scenario('trust: after the test certificates expire (clock at 2027-06-01) containers and host runtimes are UNKNOWN, never SAFE', () => {
  const d = fresh('t11'); curlRt(d, 'exit 60', 'exit 60');   // an expired leaf fails verification even with the roots forced in
  const eng = engine('t11', { curlBody: 'case "$u" in https://self-signed*) exit 60;; https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac' });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('t11-root')], { PATH: `${eng}:${d}` }, preload('t11', { online: true, now: Date.parse('2027-06-01T00:00:00Z') }));
  assert.deepEqual(ofKind(r, 'container').map((x) => x.status), ['UNKNOWN'], show(r));
  assert.deepEqual(ofKind(r, 'curl').map((x) => x.status), ['UNKNOWN'], show(r));
});

scenario('containers: a paused container (docker exec refuses: "is paused") is UNKNOWN', () => {
  const d = fresh('t12'); nodeRt(d);
  const eng = engine('t12', { exec: 'echo "Error response from daemon: container c0ffee is paused, unpause the container before exec" >&2; exit 1' });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('t12-root')], { PATH: `${eng}:${d}` }, preload('t12', { online: true }));
  assert.deepEqual(ofKind(r, 'container').map((x) => x.status), ['UNKNOWN'], show(r));
  assert.equal(r.code, 2);
});

scenario('containers: a distroless image with no shell (docker exec exits 126) is UNKNOWN', () => {
  const d = fresh('t13'); nodeRt(d);
  const eng = engine('t13', { exec: 'echo \'OCI runtime exec failed: exec failed: unable to start container process: exec: "sh": executable file not found in $PATH: unknown\' >&2; exit 126' });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('t13-root')], { PATH: `${eng}:${d}` }, preload('t13', { online: true }));
  assert.deepEqual(ofKind(r, 'container').map((x) => x.status), ['UNKNOWN'], show(r));
});

scenario('containers: a DNS filter on the containers\' network (Docker daemon.json "dns") answers the test hosts with its own certificate: not SAFE', () => {
  // the host's own handshake reaches the real test hosts (right issuer); inside the container the block page's
  // certificate is refused with curl 60, exactly like a fixed trust store. There is no forced-roots control in a container.
  const d = fresh('t14'); nodeRt(d);
  const eng = engine('t14', { curlBody: 'case "$u" in https://self-signed*) exit 60;; https://emudhra.we-have-a-problem.com/) exit 0;; *) exit 60;; esac' });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('t14-root')], { PATH: `${eng}:${d}` }, preload('t14', { online: true }));
  const ct = ofKind(r, 'container');
  assert.equal(ct.length, 1, show(r));
  assert.notEqual(ct[0].status, 'SAFE', `a refusal from a filtered network read as the image's own trust: ${show(r)}`);
});

scenario('containers: DOCKER_HOST set to Colima\'s socket while Colima is stopped (socket gone) is not could-not-be-tested', () => {
  const d = fresh('t15'); nodeRt(d);
  const sock = join(dir, 't15-colima', 'default', 'docker.sock');
  const eng = engine('t15', { ps: `echo "Cannot connect to the Docker daemon at unix://${sock}. Is the docker daemon running?" >&2; exit 1` });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('t15-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: `unix://${sock}` }, preload('t15', { online: true }));
  assert.equal(unknowns(r).length, 0, `a stopped local engine read as an unfollowed remote host: ${show(r)}`);
  assert.equal(r.code, 0);
});

// =========================================================================================================================
// VERSIONS (php-2026-10, cloudflared and go in emudhra-2026-10)
// =========================================================================================================================
const phpRun = (env, redirects = {}) => run(['--incident', 'php-2026-10'], env, preload('php', { redirects }));
const phpScript = (p, v, sapi = 'cli') => exe(p, `echo "PHP ${v} (${sapi}) (built: Oct 21 2026 10:00:00) (NTS)"`);

scenario('php: after `brew unlink php@8.1`, the keg\'s old php-fpm (/opt/homebrew/opt/php@8.1/sbin) is EXPOSED beside a fixed php on PATH', () => {
  const p = fresh('v1-path'), opt = fresh('v1-opt'); phpScript(join(p, 'php'), '8.4.27');
  phpScript(join(opt, 'php@8.1', 'sbin', 'php-fpm'), '8.1.30', 'fpm-fcgi'); phpScript(join(opt, 'php@8.1', 'bin', 'php'), '8.1.30');
  const r = phpRun({ PATH: p }, { '/opt/homebrew/opt': opt });
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /php@8\.1/.test(x.bin)), show(r));
  assert.equal(r.code, 1);
});

scenario('php: an OpenLiteSpeed/CyberPanel server whose sites run lsphp81 (/usr/local/lsws/lsphp81/bin) is not SAFE because /usr/bin/php is fixed', () => {
  const p = fresh('v2-path'), lsws = fresh('v2-lsws'); phpScript(join(p, 'php'), '8.3.36');
  phpScript(join(lsws, 'lsphp81', 'bin', 'php'), '8.1.31'); phpScript(join(lsws, 'lsphp81', 'bin', 'lsphp'), '8.1.31', 'litespeed');
  const r = phpRun({ PATH: p }, { '/usr/local/lsws': lsws });
  assert.notEqual(r.code, 0, `the PHP serving the sites was never looked at: ${show(r)}`);
});

scenario('php: a DirectAdmin server\'s second PHP (/usr/local/php81/bin/php, php-fpm81 in sbin) is not SAFE because /usr/bin/php is fixed', () => {
  const p = fresh('v3-path'), da = fresh('v3-php81'); phpScript(join(p, 'php'), '8.3.36');
  phpScript(join(da, 'bin', 'php'), '8.1.31'); phpScript(join(da, 'sbin', 'php-fpm81'), '8.1.31', 'fpm-fcgi');
  const r = phpRun({ PATH: p }, { '/usr/local/php81': da });
  assert.notEqual(r.code, 0, `DirectAdmin's PHP was never looked at: ${show(r)}`);
});

scenario('php: Debian\'s "8.3.36~rc1" pre-release is EXPOSED; "8.2.35-1+deb12u1" is SAFE', () => {
  for (const [v, code] of [['8.3.36~rc1-1', 1], ['8.2.35-1+deb12u1', 0], ['8.5.12-dev', 1], ['8.4.27alpha2', 1]]) {
    const p = fresh('v4'); phpScript(join(p, 'php'), v);
    assert.equal(phpRun({ PATH: p }).code, code, v);
  }
});

scenario('php: Alpine-style php83 and php-fpm83 at a fixed version are SAFE, exit 0 (no false could-not-be-tested)', () => {
  const p = fresh('v5'); phpScript(join(p, 'php83'), '8.3.36'); phpScript(join(p, 'php-fpm83'), '8.3.36', 'fpm-fcgi');
  const r = phpRun({ PATH: p });
  assert.deepEqual(r.rows.filter((x) => x.kind === 'binary').map((x) => x.status), ['SAFE', 'SAFE'], show(r));
  assert.equal(r.code, 0);
});

scenario('php: PATH written as "~/bin:..." (bash and sh expand the ~; Wardlatch drops the entry) hides the old php the shell runs', () => {
  const h = fresh('v6-home'), fixed = fresh('v6-fixed');
  phpScript(join(h, 'bin', 'php'), '8.1.2'); phpScript(join(fixed, 'php'), '8.4.27');
  // the fixture: bash runs ~/bin/php
  assert.match(execFileSync('/bin/bash', ['-c', 'php'], { env: { HOME: h, PATH: `~/bin:${fixed}` } }).toString(), /8\.1\.2/);
  const r = phpRun({ HOME: h, PATH: `~/bin:${fixed}` });
  assert.notEqual(r.code, 0, `the php the shell runs was never checked: ${show(r)}`);
});

scenario('cloudflared: a fixed copy first and an old compiled copy later on PATH (the one a systemd unit runs) is EXPOSED', { skip: !CC && 'no C compiler' }, () => {
  const a = fresh('v7-a'), b = fresh('v7-b');
  exe(join(a, 'cloudflared'), 'echo "cloudflared version 2026.10.2 (built 2026-10-20-1200 UTC)"');
  native(join(b, 'cloudflared'), 'cloudflared version 2026.9.1 (built 2026-09-15-0900 UTC)');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('v7-root')], { PATH: `${a}:${b}` }, preload('v7'));
  const rows = r.rows.filter((x) => x.binary === 'cloudflared');
  assert.deepEqual(rows.map((x) => x.status), ['SAFE', 'EXPOSED'], show(r));
  assert.equal(r.code, 1);
});

scenario('go: a fixed go first and an old compiled go later on PATH is EXPOSED', { skip: !CC && 'no C compiler' }, () => {
  const a = fresh('v8-a'), b = fresh('v8-b');
  exe(join(a, 'go'), 'echo "go version go1.27.3 darwin/arm64"');
  native(join(b, 'go'), 'go version go1.26.5 linux/amd64');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('v8-root')], { PATH: `${a}:${b}` }, preload('v8'));
  assert.deepEqual(r.rows.filter((x) => x.binary === 'go').map((x) => x.status), ['SAFE', 'EXPOSED'], show(r));
});

scenario('go: GOTOOLCHAIN=go1.26.5 written by `go env -w` (CRLF go env file) makes a fixed go EXPOSED', () => {
  const h = fresh('v9-home'), a = fresh('v9-a');
  exe(join(a, 'go'), 'echo "go version go1.27.3 darwin/arm64"');
  put(DARWIN ? join(h, 'Library', 'Application Support', 'go', 'env') : join(h, '.config', 'go', 'env'), 'GOPRIVATE=example.org/*\r\nGOTOOLCHAIN=go1.26.5\r\n');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('v9-root')], { PATH: a, HOME: h }, preload('v9'));
  assert.deepEqual(r.rows.filter((x) => x.binary === 'go').map((x) => x.status), ['EXPOSED'], show(r));
});

scenario('go: GOENV naming a custom env file with GOTOOLCHAIN=go1.26.5+auto makes a fixed go EXPOSED', () => {
  const a = fresh('v10-a'), envf = put(join(fresh('v10-cfg'), 'go.env'), 'GOTOOLCHAIN=go1.26.5+auto\n');
  exe(join(a, 'go'), 'echo "go version go1.27.3 darwin/arm64"');
  const r = run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('v10-root')], { PATH: a, GOENV: envf }, preload('v10'));
  assert.deepEqual(r.rows.filter((x) => x.binary === 'go').map((x) => x.status), ['EXPOSED'], show(r));
});

// =========================================================================================================================
// INSTALLS (plex, gitlab, litellm, ovhcloud)
// =========================================================================================================================
const dpkg = (stanza) => put(join(fresh('dpkg'), 'status'), `Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\n${stanza}\nPackage: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13\n`);
const plexStanza = (status, v) => `Package: plexmediaserver\nStatus: ${status}\nPriority: optional\nSection: video\nInstalled-Size: 280000\nMaintainer: Plex Inc.\nArchitecture: amd64\nVersion: ${v}\nDescription: Plex Media Server\n`;

scenario('plex: a server held at 1.41.2 with `apt-mark hold` (dpkg "hold ok installed") is EXPOSED', () => {
  const r = run(['--incident', 'plex-2026-10'], {}, preload('i1', { redirects: { '/var/lib/dpkg/status': dpkg(plexStanza('hold ok installed', '1.41.2.9200-c6bbc1b53')) } }));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

scenario('plex: the macOS app in ~/Applications at 1.41.2 is EXPOSED', () => {
  const h = fresh('i2-home');
  put(join(h, 'Applications', 'Plex Media Server.app', 'Contents', 'Info.plist'), '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>1.41.2</string>\n\t<key>CFBundleVersion</key>\n\t<string>1.41.2.9200</string>\n</dict></plist>\n');
  const r = run(['--incident', 'plex-2026-10'], { HOME: h }, preload('i2'));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

scenario('plex: a fixed server (1.43.3.10861) is SAFE, exit 0', () => {
  const r = run(['--incident', 'plex-2026-10'], {}, preload('i3', { redirects: { '/var/lib/dpkg/status': dpkg(plexStanza('install ok installed', '1.43.3.10861-a1b2c3d4e')) } }));
  assert.equal(r.code, 0, show(r));
});

scenario('gitlab: an Omnibus install whose version-manifest says gitlab-ee 19.4.2 is EXPOSED', () => {
  const g = fresh('i4'); put(join(g, 'version-manifest.txt'), 'gitlab-ee 19.4.2\n\nComponent    Installed Version    Version GUID\n---------------------------------------------\ngitlab-rails  v19.4.2-ee  git:abc\n');
  const r = run(['--incident', 'gitlab-2026-10'], {}, preload('i4', { redirects: { '/opt/gitlab': g } }));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

scenario('gitlab: an Omnibus install with only gitlab-rails/VERSION 18.10.4-ee (an end-of-life line) is EXPOSED', () => {
  const g = fresh('i5'); put(join(g, 'embedded', 'service', 'gitlab-rails', 'VERSION'), '18.10.4-ee\n');
  const r = run(['--incident', 'gitlab-2026-10'], {}, preload('i5', { redirects: { '/opt/gitlab': g } }));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /end of life/.test(x.reason)), show(r)); assert.equal(r.code, 1);
});

scenario('gitlab: a source install (/home/git/gitlab/VERSION) at 19.5.1 is REVIEW (exit 0); at 19.2.8 it is EXPOSED', () => {
  const a = fresh('i6a'); put(join(a, 'VERSION'), '19.5.1\n');
  const ok = run(['--incident', 'gitlab-2026-10'], {}, preload('i6a', { redirects: { '/home/git/gitlab': a } }));
  assert.deepEqual(ok.rows.filter((x) => x.kind === 'install').map((x) => x.status), ['REVIEW'], show(ok)); assert.equal(ok.code, 0);
  const b = fresh('i6b'); put(join(b, 'VERSION'), '19.2.8\n');
  assert.equal(run(['--incident', 'gitlab-2026-10'], {}, preload('i6b', { redirects: { '/home/git/gitlab': b } })).code, 1);
});

scenario('litellm: litellm-1.107.0.dist-info in a service\'s virtual environment is EXPOSED', () => {
  const root = fresh('i7-root'), v = join(root, 'proxy', '.venv');
  put(join(v, 'pyvenv.cfg'), 'home = /usr/bin\n'); mkdirSync(join(v, 'lib', 'python3.12', 'site-packages', 'litellm-1.107.0.dist-info'), { recursive: true });
  put(join(v, 'lib', 'python3.12', 'site-packages', 'litellm-1.107.0.dist-info', 'METADATA'), 'Name: litellm\nVersion: 1.107.0\n');
  const r = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', root], { HOME: fresh('i7-home'), TMPDIR: fresh('i7-tmp') }, preload('i7'));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /litellm-1\.107\.0/.test(x.what)), show(r)); assert.equal(r.code, 1);
});

scenario('litellm: the stealer\'s .pc_once_ marker in the temp folder is EXPOSED', () => {
  const t = fresh('i8-tmp'); put(join(t, '.pc_once_72129118c59f5636c0bb'), '');
  const r = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('i8-root')], { HOME: fresh('i8-home'), TMPDIR: t }, preload('i8'));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /pc_once/.test(x.path)), show(r)); assert.equal(r.code, 1);
});

scenario('litellm: an old pulled main-latest image at a compromised digest, and a podman-style docker.io v1.107.0 tag, are EXPOSED', () => {
  const eng = engine('i9', { images: "printf 'ghcr.io/berriai/litellm:main-latest@sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5\\ndocker.io/litellm/litellm:v1.107.0@<none>\\npostgres:16@sha256:1111\\n'; exit 0" });
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('i9-root')], { PATH: eng, HOME: fresh('i9-home'), TMPDIR: fresh('i9-tmp') }, preload('i9'));
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 2, show(r)); assert.equal(r.code, 1);
});

scenario('litellm: the compromised image on a Mac where Docker Desktop is quit (its images still on disk) is not SAFE', () => {
  const eng = engine('i10', { images: 'echo "Cannot connect to the Docker daemon at unix:///Users/ada/.docker/run/docker.sock. Is the docker daemon running?" >&2; exit 1' });
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('i10-root')], { PATH: eng, HOME: fresh('i10-home'), TMPDIR: fresh('i10-tmp') }, preload('i10'));
  assert.notEqual(r.code, 0, `local images were not looked at and the run passed: ${show(r)}`);
});

scenario('ovhcloud: the stealer\'s envchecker folder in the temp folder is EXPOSED; a clean ovhcloud on PATH is hashed, never run', () => {
  const t = fresh('i11-tmp'); mkdirSync(join(t, 'envchecker-1729345678'));
  const p = fresh('i11-path'), ran = join(dir, 'i11-ran'); exe(join(p, 'ovhcloud'), `touch ${JSON.stringify(ran)}; echo ovhcloud 0.16.0`);
  const r = run(['--incident', 'ovhcloud-cli-2026-10'], { PATH: p, TMPDIR: t }, preload('i11'));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /envchecker/.test(x.bin)), show(r));
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && x.bin === join(p, 'ovhcloud')), show(r));
  assert.equal(existsSync(ran), false, 'ovhcloud was run'); assert.equal(r.code, 1);
});

// =========================================================================================================================
// KEY SCAN (committed-keys-2026-10)
// =========================================================================================================================
const keys = (root) => sys(['--incident', 'committed-keys-2026-10', '--paths', root], { HOME: fresh('k-home') });
const keyRows = (r) => r.rows.filter((x) => x.kind === 'secret' && x.status === 'REVIEW');

scenario('keys: an AWS key past the first 8 MB of a 12 MB tracked fixture file is found', () => {
  const root = fresh('k1'), app = join(root, 'app'), g = gitRepo(app);
  const filler = `${'{"id":1,"name":"row","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'}\n`.repeat(140000);
  put(join(app, 'fixtures', 'dump.jsonl'), `${filler}{"aws_access_key_id":"${AWS}"}\n${filler.slice(0, 2_000_000)}`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['fixtures/dump.jsonl']);
});

scenario('keys: a key in a 3 MB minified bundle with example.com elsewhere on the same line is found', () => {
  const root = fresh('k2'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'dist', 'app.min.js'), `var u="https://example.com/docs";${'var a=1;'.repeat(200000)}const k="${AWS}";${'var b=2;'.repeat(200000)}\n`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['dist/app.min.js']);
});

scenario('keys: a key in a CRLF file from a Windows editor is found, on the right line', () => {
  const root = fresh('k3'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'deploy.ps1'), `# deploy\r\n$env:AWS_ACCESS_KEY_ID = "${AWS}"\r\n`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => `${x.file}:${x.line}`), ['deploy.ps1:2']);
});

scenario('keys: a real key in a .env copied from .env.example, with the docs\' example key left in a comment beside it, is found', () => {
  const root = fresh('k4'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, '.env'), `AWS_ACCESS_KEY_ID=${AWS}  # e.g. AKIAIOSFODNN7EXAMPLE\n`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['.env'], 'a real key hidden by a placeholder in the comment next to it');
});

scenario('keys: a key in a file deleted from the working tree but still tracked and in the last commit is found', () => {
  const root = fresh('k5'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'config', 'prod.yml'), `aws_access_key_id: ${AWS}\n`); put(join(app, 'README'), 'x\n'); g.commit();
  rmSync(join(app, 'config', 'prod.yml'));   // deleted locally, not committed: still in HEAD, the index and every push
  assert.match(g.g(['ls-files']), /config\/prod\.yml/, 'the fixture: still tracked');
  const r = keys(root);
  assert.ok(keyRows(r).length || unknowns(r).length, `a committed key read SAFE: ${show(r)}`);
});

scenario('keys: a key in a UTF-16 text file (PowerShell 5 `Out-File` / `>`) is found, not skipped as binary', () => {
  const root = fresh('k6'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'creds.txt'), Buffer.from(`﻿[default]\r\naws_access_key_id = ${AWS}\r\n`, 'utf16le')); g.commit();
  const r = keys(root);
  assert.ok(keyRows(r).length || unknowns(r).length, `a committed key read SAFE: ${show(r)}`);
});

scenario('keys: a repository in a hidden folder under the searched folder (~/Development/.archive/legacy) is scanned', () => {
  const root = fresh('k7'), app = join(root, '.archive', 'legacy'), g = gitRepo(app);
  put(join(app, 'settings.py'), `AWS_KEY = "${AWS}"\n`); g.commit();
  const r = keys(root);
  assert.ok(keyRows(r).length || unknowns(r).length, `the repository was never looked at: ${show(r)}`);
});

scenario('keys: a repository five levels down (`--paths ~` with ~/go/src/github.com/acme/api) is scanned, or the gap is reported', () => {
  const root = fresh('k8'), app = join(root, 'go', 'src', 'github.com', 'acme', 'api'), g = gitRepo(app);
  put(join(app, 'main.go'), `const key = "${AWS}"\n`); g.commit();
  const r = keys(root);
  assert.ok(keyRows(r).length || unknowns(r).length, `the repository was never looked at: ${show(r)}`);
});

scenario('keys: a repository linked into the searched folder (~/Development/api -> /Volumes/Work/api) is scanned', () => {
  const root = fresh('k9'), outside = join(fresh('k9-volume'), 'api'), g = gitRepo(outside);
  put(join(outside, 'deploy.sh'), `export AWS_ACCESS_KEY_ID=${AWS}\n`); g.commit();
  symlinkSync(outside, join(root, 'api'));
  const r = keys(root);
  assert.ok(keyRows(r).length || unknowns(r).length, `the repository was never looked at: ${show(r)}`);
});

// =========================================================================================================================
// WORKFLOWS (github-actions-2026-10)
// =========================================================================================================================
const wf = (root) => sys(['--incident', 'github-actions-2026-10', '--paths', root], { HOME: fresh('w-home') });
const wfRows = (r) => r.rows.filter((x) => x.kind === 'workflow' && x.status === 'REVIEW').map((x) => x.file);

scenario('workflows: a workflow added on 10 Oct is listed for review (exit 0)', () => {
  const root = fresh('w1'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'a'), 'a\n'); g.commit('A', '2025-03-01T12:00:00Z');
  put(join(app, '.github', 'workflows', 'format-check.yml'), 'on: push\n'); g.commit('ci', '2026-10-10T12:00:00Z');
  const r = wf(root);
  assert.deepEqual(wfRows(r), ['.github/workflows/format-check.yml'], show(r)); assert.equal(r.code, 0);
});

scenario('workflows: a workflow that only an "evil merge" adds is listed', () => {
  const root = fresh('w2'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'a'), 'a\n'); g.commit('A', '2025-01-01T12:00:00Z');
  g.g(['checkout', '-qb', 'feature']); put(join(app, 'b'), 'b\n'); g.commit('B', '2025-02-01T12:00:00Z');
  g.g(['checkout', '-q', 'main']); put(join(app, 'c'), 'c\n'); g.commit('C', '2025-03-01T12:00:00Z');
  const d = { GIT_AUTHOR_DATE: '2026-10-11T12:00:00Z', GIT_COMMITTER_DATE: '2026-10-11T12:00:00Z' };
  g.g(['merge', '-q', '--no-ff', '--no-commit', 'feature'], d);
  put(join(app, '.github', 'workflows', 'sync.yml'), 'on: push\n'); g.g(['add', '-A']); g.g(['commit', '-qm', 'Merge feature'], d);
  assert.deepEqual(wfRows(wf(root)), ['.github/workflows/sync.yml']);
});

scenario('workflows: a workflow renamed into place (git mv docs/build.yml .github/workflows/) is listed', () => {
  const root = fresh('w3'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'docs', 'build.yml'), 'on: push\njobs: {}\n'); g.commit('docs', '2025-01-01T12:00:00Z');
  mkdirSync(join(app, '.github', 'workflows'), { recursive: true });
  g.g(['mv', 'docs/build.yml', '.github/workflows/build.yml']); g.commit('move', '2026-10-12T12:00:00Z');
  assert.deepEqual(wfRows(wf(root)), ['.github/workflows/build.yml']);
});

scenario('workflows: a blobless partial clone is read without fetching, and its new workflow listed', () => {
  const src = join(fresh('w4-src'), 'origin'), g = gitRepo(src);
  put(join(src, 'a'), 'a\n'); g.commit('A', '2025-01-01T12:00:00Z');
  put(join(src, '.github', 'workflows', 'deploy.yml'), 'on: push\n'); g.commit('ci', '2026-10-13T12:00:00Z');
  g.g(['config', 'uploadpack.allowFilter', 'true']);
  const root = fresh('w4'); execFileSync('git', ['clone', '-q', '--filter=blob:none', '--no-local', `file://${src}`, join(root, 'clone')], { stdio: 'pipe', env: GITENV });
  const r = wf(root);
  assert.deepEqual(wfRows(r), ['.github/workflows/deploy.yml'], show(r));
});

scenario('workflows: a workflow committed on 10 Oct, followed by a commit from a machine with a wrong clock (dated August), is still listed', () => {
  const root = fresh('w5'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'a'), 'a\n'); g.commit('A', '2025-03-01T12:00:00Z');
  put(join(app, '.github', 'workflows', 'cache.yml'), 'on: push\n'); g.commit('ci', '2026-10-10T12:00:00Z');
  put(join(app, 'b'), 'b\n'); g.commit('docs', '2026-08-01T12:00:00Z');   // the workflow commit itself is correctly dated
  const r = wf(root);
  assert.deepEqual(wfRows(r), ['.github/workflows/cache.yml'], `a correctly dated workflow was hidden by a later commit's date: ${show(r)}`);
});

// =========================================================================================================================
// WORDPRESS (wordpress-plugins-2026-10)
// =========================================================================================================================
const wp = (root) => run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
const site = (d) => { put(join(d, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); mkdirSync(join(d, 'wp-content', 'plugins'), { recursive: true }); return d; };
const plugin = (pluginsDir, slug, main, v, extra = '') => put(join(pluginsDir, slug, main), `<?php\n/*\nPlugin Name: ${slug}\nVersion: ${v}\nAuthor: x\n*/\n${extra}`);

scenario('wordpress: UpdraftPlus 1.26.12 and UpdraftPlus Premium 2.26.12.25 are EXPOSED', () => {
  const root = fresh('p1');
  plugin(join(site(join(root, 'blog')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  plugin(join(site(join(root, 'shop')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '2.26.12.25');
  const r = wp(root);
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 2, show(r)); assert.equal(r.code, 1);
});

scenario('wordpress: Rank Math PRO 3.0.123 is EXPOSED, and the rank1cdn indicator in a 3.0.124 copy is EXPOSED', () => {
  const root = fresh('p2');
  plugin(join(site(join(root, 'a')), 'wp-content', 'plugins'), 'seo-by-rank-math-pro', 'rank-math-pro.php', '3.0.123');
  const b = join(site(join(root, 'b')), 'wp-content', 'plugins');
  plugin(b, 'seo-by-rank-math-pro', 'rank-math-pro.php', '3.0.124'); put(join(b, 'seo-by-rank-math-pro', 'includes', 'loader.php'), '<?php $u = "https://rank1cdn.example/x.js";');
  const r = wp(root);
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 2, show(r));
});

scenario('wordpress: a site whose plugins folder can\'t be opened is UNKNOWN, never SAFE', { skip: AS_ROOT && 'root' }, () => {
  const root = fresh('p3'), s = site(join(root, 'site'));
  plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12'); lock(join(s, 'wp-content', 'plugins'));
  const r = wp(root);
  assert.ok(unknowns(r).length, show(r)); assert.equal(r.code, 2);
});

scenario('wordpress: a Bedrock site (web/wp core, web/app/plugins) with an outdated UpdraftPlus is not SAFE', () => {
  const root = fresh('p4'), b = join(root, 'example.com');
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); put(join(b, 'web', 'wp-config.php'), '<?php require dirname(__DIR__) . "/config/application.php";');
  put(join(b, 'config', 'application.php'), "<?php Config::define('CONTENT_DIR', '/app'); Config::define('WP_CONTENT_DIR', $webroot_dir . '/app');");
  plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.notEqual(r.code, 0, `the site was not found and the run passed: ${show(r)}`);
});

scenario('wordpress: a site linked into the web root (/var/www/html -> /srv/wordpress) is checked', () => {
  const www = fresh('p5-www'), real = site(join(fresh('p5-srv'), 'wordpress'));
  plugin(join(real, 'wp-content', 'plugins'), 'seo-by-rank-math-pro', 'rank-math-pro.php', '3.0.123');
  symlinkSync(real, join(www, 'html'));
  const r = wp(www);
  assert.notEqual(r.code, 0, `the linked site was never looked at: ${show(r)}`);
});

scenario('wordpress: a staging copy in a dot-folder (.staging) is checked', () => {
  const root = fresh('p6'), s = site(join(root, '.staging'));
  plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  assert.equal(wp(root).code, 1);
});

// =========================================================================================================================
// HEADERS (identity-headers-2026-10)
// =========================================================================================================================
const hdr = (h, env = {}, root = fresh('h-root')) => run(['--incident', 'identity-headers-2026-10', '--paths', root], { HOME: h, ...env });

scenario('headers: your email in a CRLF ~/.curlrc is EXPOSED', () => {
  const h = fresh('h1'); gitconfigId(h); put(join(h, '.curlrc'), `--silent\r\n-H "From: ${EMAIL}"\r\n`);
  const r = hdr(h); assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.file === join(h, '.curlrc')), show(r)); assert.equal(r.code, 1);
});

scenario('headers: ~/.curlrc `header = @~/.curl-headers` (curl reads the headers from that file) carrying your email is EXPOSED', () => {
  const h = fresh('h2'); gitconfigId(h);
  const f = put(join(h, '.curl-headers'), `From: ${EMAIL}\nX-Team: platform\n`);
  put(join(h, '.curlrc'), `header = "@${f}"\n`);
  const r = hdr(h);
  assert.equal(r.code, 1, `curl sends your email to every site and the run did not say so: ${show(r)}`);
});

scenario('headers: git\'s global http.extraHeader with your email is EXPOSED (sent to every remote)', () => {
  const h = fresh('h3'); put(join(h, '.gitconfig'), `[user]\n\tname = Ada Lovelace\n\temail = ${EMAIL}\n[http]\n\textraHeader = X-Requested-By: ${EMAIL}\n`);
  const r = hdr(h); assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

scenario('headers: a repository\'s .mcp.json header with your email is REVIEW (exit 0)', () => {
  const h = fresh('h4'), root = fresh('h4-root'), app = join(root, 'app'); gitconfigId(h); gitRepo(app);
  put(join(app, '.mcp.json'), JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://mcp.example.net', headers: { 'X-User-Email': EMAIL } } } }));
  const r = hdr(h, {}, root);
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.file === join(app, '.mcp.json')), show(r)); assert.equal(r.code, 0);
});

scenario('headers: OTEL_EXPORTER_OTLP_HEADERS carrying your email is REVIEW', () => {
  const h = fresh('h5'); gitconfigId(h);
  const r = hdr(h, { OTEL_EXPORTER_OTLP_HEADERS: `x-honeycomb-team=abc123,x-user=${EMAIL}` });
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.file === '$OTEL_EXPORTER_OTLP_HEADERS'), show(r));
});

scenario('headers: VS Code settings.json with the last setting commented out (a trailing comma before a comment) is not could-not-be-tested', () => {
  const h = fresh('h6'); gitconfigId(h);
  const p = DARWIN ? join(h, 'Library', 'Application Support', 'Code', 'User', 'settings.json') : join(h, '.config', 'Code', 'User', 'settings.json');
  put(p, '{\n  "editor.fontSize": 14,\n  "files.autoSave": "afterDelay",\n  // "http.proxy": "http://proxy.corp:8080"\n}\n');
  const r = hdr(h);
  assert.equal(unknowns(r).length, 0, `a file VS Code reads fine made the run exit 2: ${show(r)}`); assert.equal(r.code, 0);
});

scenario('headers: JSON with comments (~/.claude/settings.json) carrying your email in ANTHROPIC_CUSTOM_HEADERS is REVIEW', () => {
  const h = fresh('h7'); gitconfigId(h);
  put(join(h, '.claude', 'settings.json'), `{\n  // team settings\n  "env": {\n    /* gateway */\n    "ANTHROPIC_CUSTOM_HEADERS": "X-User: ${EMAIL}",\n  },\n}\n`);
  const r = hdr(h);
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.file === join(h, '.claude', 'settings.json')), show(r));
});

// =========================================================================================================================
// CROSS-CUTTING
// =========================================================================================================================
scenario('--paths "" (an unset variable in a CI script) is could-not-be-tested, not a search of the current folder', () => {
  // refused before anything is searched: a usage error (exit 2, no JSON), as CHANGELOG 0.1.9 says
  const cwd = fresh('x1-cwd');
  const r = spawnCli(['--incident', 'github-actions-2026-10', '--paths', ''], { PATH: '/usr/bin:/bin' }, [], { cwd });
  assert.equal(r.status, 2, `an empty --paths was not refused: exit ${r.status}: ${String(r.stdout).slice(0, 600)}`);
  assert.match(String(r.stderr), /--paths needs a value/);
});
scenario('every known limit names a scenario in this file', () => {
  for (const name of KNOWN_LIMITS.keys()) assert.ok(declared.has(name), `stale known limit: ${name}`);
});

scenario('--incident given twice checks both, or refuses: it never checks only the first and passes', () => {
  const st = dpkg(plexStanza('install ok installed', '1.41.2.9200-c6bbc1b53'));
  const r = run(['--incident', 'php-2026-10', '--incident', 'plex-2026-10'], {}, preload('x2', { redirects: { '/var/lib/dpkg/status': st } }));
  assert.ok(r.code === 1 || (r.code === 2 && !r.rows.length), `ran ${r.json.incidents.map((i) => i.id)} only, exit ${r.code}`);
});

scenario('sudo: the person\'s own home is searched, not root\'s (SUDO_USER\'s ~/.curlrc carries the email)', { skip: !DARWIN && 'macOS home layout' }, () => {
  const person = fresh('x3-person'), rootHome = fresh('x3-roothome'); gitconfigId(person); put(join(person, '.curlrc'), `-H "From: ${EMAIL}"\n`);
  const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('x3-root')], { HOME: rootHome, SUDO_USER: 'redteam-ada' },
    preload('x3', { redirects: { '/Users/redteam-ada': person }, extra: 'process.getuid = () => 0;' }));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

scenario('owners: a locked folder of another person (uid 502) is UNKNOWN; one root owns is a review line and the run passes', { skip: AS_ROOT && 'root' }, () => {
  const a = fresh('x4a'), theirs = join(a, 'projects'); mkdirSync(theirs); lock(theirs);
  const r1 = run(['--incident', 'github-actions-2026-10', '--paths', a], { PATH: '/usr/bin:/bin' }, preload('x4a', { uids: { [theirs]: 502 } }));
  assert.ok(unknowns(r1).some((x) => x.path === theirs), show(r1)); assert.equal(r1.code, 2);
  const b = fresh('x4b'), svc = join(b, 'pgdata'); mkdirSync(svc); lock(svc);
  const r2 = run(['--incident', 'github-actions-2026-10', '--paths', b], { PATH: '/usr/bin:/bin' }, preload('x4b', { uids: { [svc]: 0 } }));
  assert.ok(r2.rows.some((x) => x.kind === 'skipped' && x.paths.includes(svc)), show(r2)); assert.equal(r2.code, 0);
});

scenario('symlink loops in the searched folder, and a FIFO planted as ~/.curlrc, never hang the run', () => {
  const root = fresh('x5'); symlinkSync('.', join(root, 'loop')); mkdirSync(join(root, 'a')); symlinkSync('../a', join(root, 'a', 'b'));
  symlinkSync(join(root, 'self'), join(root, 'self'));
  const h = fresh('x5-home'); execFileSync('mkfifo', [join(h, '.curlrc')]);
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10', 'identity-headers-2026-10']) {
    const t0 = Date.now(); const r = spawnCli(['--incident', id, '--paths', root], { HOME: h, PATH: '/usr/bin:/bin' });
    assert.ok(r.status !== null && Date.now() - t0 < 60000, `${id} hung (${r.signal})`);
  }
});

scenario('a huge folder (20,000 subfolders) is searched in reasonable time, exit 0', () => {
  const root = fresh('x6'); for (let i = 0; i < 20000; i++) mkdirSync(join(root, `d${i}`));
  const t0 = Date.now(); const r = run(['--incident', 'github-actions-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
  assert.equal(r.code, 0); assert.ok(Date.now() - t0 < 60000, `${Date.now() - t0} ms`);
});

scenario('CI runner: CI=true, GITHUB_ACTIONS, TMPDIR pointing at a folder that doesn\'t exist, settings switched off with /dev/null: exit 0', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', RUNNER_TEMP: join(dir, 'x7-gone'), TMPDIR: join(dir, 'x7-gone'), HOME: fresh('x7-home'), GIT_CONFIG_GLOBAL: '/dev/null', NPM_CONFIG_USERCONFIG: '/dev/null', NODE_OPTIONS: '--max-old-space-size=4096' };
  for (const id of ['identity-headers-2026-10', 'litellm-2026-10', 'ovhcloud-cli-2026-10', 'github-actions-2026-10']) {
    const r = run(['--incident', id], env, preload(`x7-${id}`));
    assert.equal(r.code, 0, `${id}: ${show(r)}`);
  }
});

scenario('no git installed, with repositories present: could-not-be-tested (exit 2), never "0 repositories"', () => {
  const root = fresh('x8'), app = join(root, 'app'), g = gitRepo(app); put(join(app, 'k.py'), `k = "${AWS}"\n`); g.commit();
  for (const id of ['committed-keys-2026-10', 'github-actions-2026-10']) {
    const r = run(['--incident', id, '--paths', root], { PATH: fresh('x8-nogit') });
    assert.ok(unknowns(r).some((x) => x.repo === app), `${id}: ${show(r)}`); assert.equal(r.code, 2, id);
  }
});

scenario('--json completeness: every row names its incident, kind and status; every SAFE has a receipt, every UNKNOWN a reason, every EXPOSED a fix', () => {
  const root = fresh('x9'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'k.py'), `k = "${AWS}"\n`); put(join(app, '.github', 'workflows', 'x.yml'), 'on: push\n'); g.commit('x', '2026-10-10T12:00:00Z');
  plugin(join(site(join(root, 'blog')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const gitbin = fresh('x9-git'); symlinkSync('/usr/bin/git', join(gitbin, 'git'));
  const h = fresh('x9-home'); gitconfigId(h); put(join(h, '.curlrc'), `-H "From: ${EMAIL}"\n`);
  const r = run(['--no-containers', '--paths', root], { PATH: gitbin, HOME: h, TMPDIR: fresh('x9-tmp') }, preload('x9', { online: false }));
  const ids = r.json.incidents.map((i) => i.id);
  assert.equal(ids.length, 10);
  const bad = r.rows.filter((x) => !ids.includes(x.incident) || typeof x.kind !== 'string' || !x.kind || !['SAFE', 'EXPOSED', 'UNKNOWN', 'REVIEW'].includes(x.status)
    || (x.status === 'SAFE' && !(Array.isArray(x.searched) && x.searched.length)) || (x.status === 'UNKNOWN' && !x.reason) || (x.status === 'EXPOSED' && !x.fix));
  assert.deepEqual(bad, []);
  for (const id of ids) assert.ok(r.rows.some((x) => x.incident === id), `no row at all for ${id}`);
  assert.equal(r.code, 1, 'EXPOSED beside UNKNOWN is exit 1');
});

scenario('exit codes: REVIEW lines alone are exit 0; one UNKNOWN beside them is exit 2', () => {
  const root = fresh('x10'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, '.github', 'workflows', 'x.yml'), 'on: push\n'); g.commit('x', '2026-10-10T12:00:00Z');
  assert.equal(wf(root).code, 0);
  assert.equal(sys(['--incident', 'github-actions-2026-10', '--paths', root, '--paths', join(dir, 'x10-gone')]).code, 2);
});

scenario('--paths given for a folder and a folder inside it reports each finding once', () => {
  const root = fresh('x11'), app = join(root, 'app'), g = gitRepo(app); put(join(app, 'k.py'), `k = "${AWS}"\n`); g.commit();
  const r = sys(['--incident', 'committed-keys-2026-10', '--paths', root, '--paths', app]);
  assert.equal(keyRows(r).length, 1, show(r));
});

scenario('--list --json prints the incident list as JSON', () => {
  const r = spawnCli(['--list'], {}, [], { json: true });
  assert.doesNotThrow(() => JSON.parse(r.stdout), `not JSON: ${r.stdout.slice(0, 120)}`);
});
