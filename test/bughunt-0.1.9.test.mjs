// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The bug hunt of 0.1.9 (b03e7be): a red team's scenario tests and a mutation run (614 planted bugs) found these. Each
// bad-case test failed on b03e7be for the reason its name gives, and sits beside a clean-machine test that must keep
// passing. Offline: no test reaches a network host (the TLS handshake is faked in a --require preload, net.connect
// throws, and every program a check runs is a stand-in in the test folder, except real git in the git-based tests).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const WL = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(WL, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
const DARWIN = process.platform === 'darwin';
const CC = ['/usr/bin/cc', '/usr/bin/gcc', '/usr/bin/clang'].find((p) => existsSync(p));
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-bughunt-')); home = join(dir, 'home'); mkdirSync(home); });
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
const map = (p) => { if (Buffer.isBuffer(p)) p = p.toString(); if (typeof p !== 'string') return p; for (const [f, t] of RED) if (p === f || p.startsWith(f + '/')) return t + p.slice(f.length); return p; };
const gone = () => Object.assign(new Error('hidden'), { code: 'ENOENT' });
const ex = fs.existsSync; fs.existsSync = (p) => { p = map(p); return !(typeof p === 'string' && SYS.test(p)) && ex(p); };
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync', 'accessSync', 'readFileSync']) {
  const o = fs[k], native = o.native;
  fs[k] = function (p, ...a) {
    p = map(p);
    if (typeof p === 'string' && SYS.test(p)) throw gone();
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

const spawnCli = (args, env = {}, nodeArgs = [], { cwd = dir, json = true } = {}) => spawnSync(process.execPath, [...nodeArgs, BIN, ...args, ...(json ? ['--json'] : [])],
  { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), LANG: 'C', ...env }, cwd, timeout: 180000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024 });
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
const dpkg = (stanza) => put(join(fresh('dpkg'), 'status'), `Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\n${stanza}\nPackage: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13\n`);
const plexStanza = (status, v) => `Package: plexmediaserver\nStatus: ${status}\nPriority: optional\nSection: video\nInstalled-Size: 280000\nMaintainer: Plex Inc.\nArchitecture: amd64\nVersion: ${v}\nDescription: Plex Media Server\n`;
const keys = (root) => sys(['--incident', 'committed-keys-2026-10', '--paths', root], { HOME: fresh('k-home') });
const keyRows = (r) => r.rows.filter((x) => x.kind === 'secret' && x.status === 'REVIEW');
const wp = (root) => run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
const site = (d) => { put(join(d, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); mkdirSync(join(d, 'wp-content', 'plugins'), { recursive: true }); return d; };
const plugin = (pluginsDir, slug, main, v, extra = '') => put(join(pluginsDir, slug, main), `<?php\n/*\nPlugin Name: ${slug}\nVersion: ${v}\nAuthor: x\n*/\n${extra}`);
const hdr = (h, env = {}, root = fresh('h-root')) => run(['--incident', 'identity-headers-2026-10', '--paths', root], { HOME: h, ...env });

// =========================================================================================================================
// OPTIONS
// =========================================================================================================================
test('--paths "" (an unset variable in a CI script) is refused, exit 2, not a search of the current folder', () => {
  const cwd = fresh('o1-cwd');
  const r = spawnCli(['--incident', 'github-actions-2026-10', '--paths', ''], { PATH: '/usr/bin:/bin' }, [], { cwd, json: false });
  assert.equal(r.status, 2, `an empty --paths searched ${cwd}: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /--paths needs a value/);
});

test('--incident "" is refused, exit 2', () => {
  const r = spawnCli(['--incident', ''], {}, [], { json: false });
  assert.equal(r.status, 2); assert.match(r.stderr, /--incident needs a value/);
});

test('--incident given twice checks both incidents', () => {
  const st = dpkg(plexStanza('install ok installed', '1.41.2.9200-c6bbc1b53'));
  const r = run(['--incident', 'php-2026-10', '--incident', 'plex-2026-10'], {}, preload('o3', { redirects: { '/var/lib/dpkg/status': st } }));
  assert.deepEqual(r.json.incidents.map((i) => i.id).sort(), ['php-2026-10', 'plex-2026-10']);
  assert.equal(r.code, 1, show(r));
});

test('--incident with one known and one unknown id is refused, exit 2, naming the unknown one', () => {
  const r = spawnCli(['--incident', 'php-2026-10', '--incident', 'no-such-incident'], {}, [], { json: false });
  assert.equal(r.status, 2); assert.match(r.stderr, /unknown incident "no-such-incident"/);
});

// =========================================================================================================================
// CONTAINER ENGINES
// =========================================================================================================================
test('containers: DOCKER_HOST naming a local socket that is gone (Colima stopped) is "not running", not an unfollowed host', () => {
  const d = fresh('c1'); nodeRt(d);
  const sock = join(dir, 'c1-colima', 'default', 'docker.sock');
  const eng = engine('c1', { ps: `echo "Cannot connect to the Docker daemon at unix://${sock}. Is the docker daemon running?" >&2; exit 1` });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('c1-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: `unix://${sock}` }, preload('c1', { online: true }));
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('containers: DOCKER_HOST naming a remote host is still not followed (UNKNOWN when the engine does not answer)', () => {
  const d = fresh('c2'); nodeRt(d);
  const eng = engine('c2', { ps: 'echo "Cannot connect to the Docker daemon at tcp://10.0.0.5:2375. Is the docker daemon running?" >&2; exit 1' });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('c2-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: 'tcp://10.0.0.5:2375' }, preload('c2', { online: true }));
  assert.ok(unknowns(r).some((x) => /DOCKER_HOST/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

const PODMAN_DENIED = 'Cannot connect to Podman. Please verify your connection to the Linux system using `podman system connection list`, or try `podman machine init` and `podman machine start` to manage a new Linux VM\nError: unable to connect to Podman socket: Get "http://d/v5.0.0/libpod/_ping": dial unix /run/podman/podman.sock: connect: permission denied';
const podman = (name, body) => { const d = fresh(name); exe(join(d, 'podman'), body); return d; };

test('images: podman refusing its socket (permission denied) is UNKNOWN in the image check, as in the container check', () => {
  const eng = podman('c3', `/bin/cat >&2 <<'EOF'\n${PODMAN_DENIED}\nEOF\nexit 125`);
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('c3-root')], { PATH: eng, HOME: fresh('c3-home'), TMPDIR: fresh('c3-tmp') }, preload('c3'));
  assert.ok(unknowns(r).some((x) => x.engine === 'podman' && /permission denied/.test(x.reason)), show(r));
  assert.equal(r.code, 2);
});

test('images: podman not running (its machine stopped) is still "not running", exit 0', () => {
  const eng = podman('c4', `/bin/cat >&2 <<'EOF'\n${PODMAN_DENIED.replace(/dial unix .*$/, 'failed to connect: dial tcp 127.0.0.1:53049: connect: connection refused')}\nEOF\nexit 125`);
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('c4-root')], { PATH: eng, HOME: fresh('c4-home'), TMPDIR: fresh('c4-tmp') }, preload('c4'));
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

// =========================================================================================================================
// HEADERS
// =========================================================================================================================
test('headers: a JSONC file whose last setting is commented out after a trailing comma is read, not UNKNOWN', () => {
  const h = fresh('h1'); gitconfigId(h);
  const p = DARWIN ? join(h, 'Library', 'Application Support', 'Code', 'User', 'settings.json') : join(h, '.config', 'Code', 'User', 'settings.json');
  put(p, '{\n  "editor.fontSize": 14,\n  "files.autoSave": "afterDelay",\n  // "http.proxy": "http://proxy.corp:8080"\n}\n');
  const r = hdr(h);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('headers: a header in such a file (trailing comma, then a block comment) is still found', () => {
  const h = fresh('h2'); gitconfigId(h);
  put(join(h, '.cursor', 'mcp.json'), `{ "mcpServers": { "x": { "url": "https://x.example", "headers": { "From": "${EMAIL}" }, /* "y": 1 */ } } }\n`);
  const r = hdr(h);
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.carries === 'your email'), show(r));
});

test('headers: malformed JSONC (a lone slash) is still UNKNOWN, never "repaired"', () => {
  const h = fresh('h3'); gitconfigId(h);
  put(join(h, '.cursor', 'mcp.json'), '{ "a": 1, / "headers": { "From": "x" } */ }\n');
  const r = hdr(h);
  assert.ok(unknowns(r).some((x) => /mcp\.json/.test(JSON.stringify(x))), show(r)); assert.equal(r.code, 2);
});

test('headers: ~/.curlrc `header = "@file"` carrying your email is EXPOSED (curl reads the headers from that file)', () => {
  const h = fresh('h4'); gitconfigId(h);
  const f = put(join(h, '.curl-headers'), `From: ${EMAIL}\nX-Team: platform\n`);
  put(join(h, '.curlrc'), `header = "@${f}"\n`);
  const r = hdr(h);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.carries === 'your email'), show(r)); assert.equal(r.code, 1);
});

test('headers: a curl header file with nothing of yours is SAFE, even when its path holds your email\'s user name', () => {
  const h = fresh('h5'); gitconfigId(h);
  const f = put(join(h, 'ada.lovelace', 'curl-headers'), 'X-Team: platform\nAccept: application/json\n');
  put(join(h, '.curlrc'), `-H @${f}\n`);
  const r = hdr(h);
  assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, show(r)); assert.equal(r.code, 0);
});

test('headers: a curl header file that is gone sends nothing (SAFE); one that cannot be read is UNKNOWN', () => {
  const h = fresh('h6'); gitconfigId(h);
  put(join(h, '.curlrc'), `-H @${join(h, 'missing-headers')}\n`);
  const r = hdr(h);
  assert.equal(r.code, 0, show(r));
  if (AS_ROOT) return;   // root reads a mode-000 file
  const h2 = fresh('h6b'); gitconfigId(h2);
  const f = put(join(h2, 'locked-headers'), `From: ${EMAIL}\n`); lock(f);
  put(join(h2, '.curlrc'), `-H @${f}\n`);
  const r2 = hdr(h2);
  assert.ok(unknowns(r2).length, show(r2)); assert.equal(r2.code, 2);
});

test('headers: a curl header file named by a relative path is UNKNOWN (curl reads it from wherever it runs); @/dev/null is empty', () => {
  const h = fresh('h7'); gitconfigId(h);
  put(join(h, '.curlrc'), '-H @headers.txt\n');
  const r = hdr(h);
  assert.ok(unknowns(r).some((x) => /relative path/.test(x.reason)), show(r)); assert.equal(r.code, 2);
  const h2 = fresh('h7b'); gitconfigId(h2); put(join(h2, '.curlrc'), '-H @/dev/null\n');
  assert.equal(hdr(h2).code, 0);
});

// =========================================================================================================================
// KEYS
// =========================================================================================================================
test('keys: a real key beside the docs\' example key on the same line is found', () => {
  const root = fresh('k1'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, '.env'), `AWS_ACCESS_KEY_ID=${AWS}  # e.g. AKIAIOSFODNN7EXAMPLE\n`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['.env']);
});

test('keys: the docs\' example key alone, and a key with a placeholder word right beside it, are not findings', () => {
  const root = fresh('k2'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, '.env.example'), 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'); put(join(app, 'docs.md'), `use your_key here: ${AWS}\n`); g.commit();
  const r = keys(root);
  assert.equal(keyRows(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('keys: a key in a tracked file deleted from the working tree (still in the index and HEAD) is found', () => {
  const root = fresh('k3'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'config', 'prod.yml'), `aws_access_key_id: ${AWS}\n`); put(join(app, 'README'), 'x\n'); g.commit();
  rmSync(join(app, 'config', 'prod.yml'));
  const r = keys(root);
  assert.deepEqual(keyRows(r).map((x) => x.file), ['config/prod.yml'], show(r)); assert.equal(r.code, 0);
});

test('keys: a deleted tracked file with no key in it is SAFE', () => {
  const root = fresh('k4'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'notes.txt'), 'nothing here\n'); put(join(app, 'README'), 'x\n'); g.commit();
  rmSync(join(app, 'notes.txt'));
  const r = keys(root);
  assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, show(r)); assert.equal(r.code, 0);
});

test('keys: a key in a UTF-16 file (little- or big-endian, with a BOM) is found', () => {
  const root = fresh('k5'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'creds.txt'), Buffer.from(`﻿[default]\r\naws_access_key_id = ${AWS}\r\n`, 'utf16le'));
  put(join(app, 'creds-be.txt'), Buffer.from(Buffer.from(`﻿key=${AWS}\n`, 'utf16le')).swap16());
  g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file).sort(), ['creds-be.txt', 'creds.txt']);
});

test('keys: a UTF-16 file with no key, and a real binary file, are SAFE', () => {
  const root = fresh('k6'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'notes.txt'), Buffer.from('﻿hello\r\n', 'utf16le'));
  put(join(app, 'blob.bin'), Buffer.from([0xff, 0xfe, 0, 0, 1, 2, 3, 0, 0, 0]));
  g.commit();
  const r = keys(root);
  assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, show(r)); assert.equal(r.code, 0);
});

// =========================================================================================================================
// TRUST
// =========================================================================================================================
test('trust: REQUESTS_CA_BUNDLE pointing at a bundle that trusts the compromised roots is EXPOSED', () => {
  const d = fresh('t1'), stale = put(join(fresh('t1-ca'), 'corp-bundle.pem'), '-----BEGIN CERTIFICATE-----\n');
  pythonRt(d); nodeRt(d); curlRt(d, `[ "$ca" = ${JSON.stringify(stale)} ] && exit 0; exit 60`);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: stale }, preload('t1', { online: true }));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.caVar === 'REQUESTS_CA_BUNDLE' && x.fix), show(r)); assert.equal(r.code, 1);
});

test('trust: REQUESTS_CA_BUNDLE pointing at a bundle that refuses them is SAFE', () => {
  const d = fresh('t2'), good = put(join(fresh('t2-ca'), 'bundle.pem'), '-----BEGIN CERTIFICATE-----\n');
  pythonRt(d); nodeRt(d); curlRt(d);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: good }, preload('t2', { online: true }));
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && x.caVar === 'REQUESTS_CA_BUNDLE'), show(r)); assert.equal(r.code, 0);
});

test('trust: REQUESTS_CA_BUNDLE with no curl to test it is UNKNOWN; one naming a missing file adds nothing', () => {
  const d = fresh('t3'), b = put(join(fresh('t3-ca'), 'bundle.pem'), '-----BEGIN CERTIFICATE-----\n');
  pythonRt(d); nodeRt(d);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: b }, preload('t3', { online: true }));
  assert.ok(unknowns(r).some((x) => x.caVar === 'REQUESTS_CA_BUNDLE'), show(r)); assert.equal(r.code, 2);
  const d2 = fresh('t3b'); pythonRt(d2); nodeRt(d2); curlRt(d2);
  const r2 = trust({ PATH: d2, REQUESTS_CA_BUNDLE: join(dir, 'no-such.pem') }, preload('t3b', { online: true }));
  assert.ok(!r2.rows.some((x) => x.caVar), show(r2)); assert.equal(r2.code, 0);
});

// =========================================================================================================================
// WORDPRESS
// =========================================================================================================================
const bedrock = (b, v) => {
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); put(join(b, 'web', 'wp-config.php'), '<?php require dirname(__DIR__) . "/config/application.php";');
  put(join(b, 'config', 'application.php'), "<?php Config::define('CONTENT_DIR', '/app');");
  if (v) plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', v); else mkdirSync(join(b, 'web', 'app', 'plugins'), { recursive: true });
  return b;
};

test('wordpress: a Bedrock site (core in web/wp, plugins in web/app/plugins) with an outdated UpdraftPlus is EXPOSED', () => {
  const root = fresh('w1'); bedrock(join(root, 'example.com'), '1.26.12');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /updraftplus/.test(x.what)), show(r)); assert.equal(r.code, 1);
});

test('wordpress: a Bedrock site with a fixed UpdraftPlus is SAFE', () => {
  const root = fresh('w2'); bedrock(join(root, 'example.com'), '1.26.13');
  const r = wp(root);
  // (the plugin folder, created just now, is also listed for review as newly added)
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && x.what === 'updraftplus 1.26.13'), show(r));
  assert.equal(r.rows.filter((x) => ['EXPOSED', 'UNKNOWN'].includes(x.status)).length, 0, show(r)); assert.equal(r.code, 0);
});

test('wordpress: core in its own folder with wp-content beside it (WordPress in its own directory) is checked', () => {
  const root = fresh('w3'), s = join(root, 'site');
  put(join(s, 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), show(r)); assert.equal(r.code, 1);
});

test('wordpress: core found with no content folder anywhere it is looked for is UNKNOWN, never SAFE', () => {
  const root = fresh('w4');
  put(join(root, 'custom', 'core', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  const r = wp(root);
  assert.ok(unknowns(r).some((x) => /plugins/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('wordpress: a site that is found and has none of the listed plugins says so, not "no WordPress installs found"', () => {
  const root = fresh('w5'); site(join(root, 'blog'));
  const r = wp(root);
  assert.equal(r.code, 0, show(r));
  const safeRow = r.rows.find((x) => x.status === 'SAFE');
  assert.ok(safeRow && !/no WordPress installs found/.test(safeRow.reason) && /1 WordPress install/.test(safeRow.reason), show(r));
});
