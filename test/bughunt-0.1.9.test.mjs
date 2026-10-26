// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The bug hunt of 0.1.9 (b03e7be): a red team's scenario tests and a mutation run (614 planted bugs) found these. Each
// bad-case test failed on b03e7be for the reason its name gives, and sits beside a clean-machine test that must keep
// passing. Offline: no test reaches a network host (the TLS handshake is faked in a --require preload, net.connect
// throws, and every program a check runs is a stand-in in the test folder, except real git in the git-based tests).
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checked } from './support/output-checks.mjs';

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
// a value as JavaScript, for code a preload runs: JSON.stringify's text with <, > and the two line separators (JSON
// leaves them as they are) written as \u escapes, the same value wherever the code is put
// (CodeQL's js/bad-code-sanitization)
const SPELLED = { '<': '\\u003c', '>': '\\u003e', '\u2028': '\\u2028', '\u2029': '\\u2029' };
const js = (v) => JSON.stringify(v).replace(/[<>\u2028\u2029]/g, (c) => SPELLED[c]);
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
// what the command prints on screen (no --json); spawnCli checks T0 and T1 on it
const text = (args, env = {}, nodeArgs = [], opts = {}) => spawnCli(args, env, nodeArgs, { ...opts, json: false }).stdout;
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
// the URL and the forced CA file follow the script, wherever the options before -c put it (0.1.9 had -I -S, now -I -S -B);
// the version is answered wherever -V is among those options (the version check runs python3 -B -V, up to d807932 -V).
// `first`: shell lines run before anything else (a recording, below)
const pythonRt = (d, normal = 'exit 1', forced = 'exit 0', first = '') => exe(join(d, 'python3'), `${first ? `${first}\n` : ''}for a in "$@"; do [ "$a" = -c ] && break; [ "$a" = -V ] && { echo "Python 3.12.1"; exit 0; }; done
while [ $# -gt 0 ] && [ "$1" != -c ]; do shift; done; shift 2
u="$1"
if [ -n "$2" ]; then ${forced}; fi
${normal}`);
const curlRt = (d, normal = 'exit 60', forced = 'exit 0') => exe(join(d, 'curl'), `[ "$1" = --version ] && { echo "curl 8.7.1 (x86_64-apple-darwin) libcurl/8.7.1"; exit 0; }
ca=""; prev=""; u=""
for a in "$@"; do [ "$prev" = --cacert ] && ca="$a"; case "$a" in http*://*) u="$a";; esac; prev="$a"; done
case "$ca" in *${ROOTPEM}) ${forced};; esac
${normal}`);

// a docker stand-in: ps lists one container; exec runs the probe script in a box whose curl answers per `curlBody`
// (`tools`: the box's programs instead of that curl, { name: shell lines })
const engine = (name, { ps = "printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0", exec = '', curlBody, tools, images = "echo 'python:3.12@sha256:0000'; exit 0" } = {}) => {
  const box = fresh(`${name}-box`), eng = fresh(`${name}-engine`);
  const curl = `for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done\n${curlBody ?? 'case "$u" in https://self-signed*) exit 60;; https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac'}`;
  for (const [tool, body] of Object.entries(tools ?? { curl })) exe(join(box, tool), body);
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
  const sock = join(fresh('c1-colima'), 'docker.sock');   // Colima stopped: its folder is there, the socket gone
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

test('headers: a curl header file that is gone, or that this user cannot read, sends nothing (curl exits 26): SAFE', () => {
  const h = fresh('h6'); gitconfigId(h);
  put(join(h, '.curlrc'), `-H @${join(h, 'missing-headers')}\n`);
  const r = hdr(h);
  assert.equal(r.code, 0, show(r));
  if (AS_ROOT) return;   // root reads a mode-000 file
  const h2 = fresh('h6b'); gitconfigId(h2);
  const f = put(join(h2, 'locked-headers'), `From: ${EMAIL}\n`); lock(f);
  put(join(h2, '.curlrc'), `-H @${f}\n`);
  const r2 = hdr(h2);
  assert.equal(unknowns(r2).length, 0, show(r2)); assert.equal(r2.code, 0);
});

// each form was run through curl 8.7.1 against a local listener: these send your email
test('headers: .curlrc lines curl sends your email from (attached values, short-option clusters, header files) are EXPOSED', () => {
  const lines = ['-H@{f}', '-sH@{f}', '-H "@{f}"', 'header=@{f}', `-HFrom:${EMAIL}`, `-sH "From: ${EMAIL}"`, `-svH "From: ${EMAIL}"`, `-sA "ua ${EMAIL}"`, `-A${EMAIL}`, `header: "From: ${EMAIL}"`];
  for (const [i, line] of lines.entries()) {
    const h = fresh(`h8-${i}`); gitconfigId(h);
    const f = put(join(h, 'my-headers'), `From: ${EMAIL}\n`);   // no space: an unquoted path ends at one
    put(join(h, '.curlrc'), `${line.replace('{f}', f)}\n`);
    const r = hdr(h);
    assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.carries === 'your email'), `${line}: ${show(r)}`); assert.equal(r.code, 1, line);
  }
});

// read on the safe side: a line curl refuses, or reads only in part, is still reported (fix or remove it)
test('headers: .curlrc lines curl refuses or cuts short (--header=, an attached value plus a word, -oH, unquoted spaces) are still EXPOSED', () => {
  const lines = ['--header=@{f}', `-H"From: ${EMAIL}"`, `-HFrom: ${EMAIL}`, `-oH "From: ${EMAIL}"`, `-H From: ${EMAIL}`, `header = From: ${EMAIL}`, `-HFrom:${EMAIL}   # so admins can reach me`, `HEADER = "From: ${EMAIL}"`, `-A "${EMAIL}"\n-A "other"`];
  for (const [i, line] of lines.entries()) {
    const h = fresh(`h9-${i}`); gitconfigId(h);
    const f = put(join(h, 'hf'), `From: ${EMAIL}\n`);
    put(join(h, '.curlrc'), `${line.replace('{f}', f)}\n`);
    const r = hdr(h);
    assert.ok(r.rows.some((x) => x.status === 'EXPOSED'), `${line}: ${show(r)}`); assert.equal(r.code, 1, line);
  }
});

test('headers: .curlrc lines that send nothing of yours, or are not header options (-a, -h, --cacert, -k), are SAFE', () => {
  const h = fresh('h10'); gitconfigId(h);
  put(join(h, '.curlrc'), `﻿-a ${EMAIL}\n-h\n--cacert /x/${EMAIL}.pem\n-k\n-H "X-Team: platform"\n-sA "curl-wrapper/1.0"\nheader:\n`);
  const r = hdr(h);
  assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, show(r)); assert.equal(r.code, 0);
});

test('headers: curl 8.3\'s expand-header, expand-user-agent and proxy-header, and -sH@file word, are EXPOSED', () => {
  const lines = [`expand-header = "From: ${EMAIL}"`, `--expand-user-agent "ua ${EMAIL}"`, `proxy-header = "From: ${EMAIL}"`, '-sH@{f} word', `-H "From: ada.lovelace\\@example.org"`];
  for (const [i, line] of lines.entries()) {
    const h = fresh(`h11-${i}`); gitconfigId(h);
    const f = put(join(h, 'hf'), `From: ${EMAIL}\n`);
    put(join(h, '.curlrc'), `${line.replace('{f}', f)}\n`);
    const r = hdr(h);
    assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.carries === 'your email'), `${line}: ${show(r)}`); assert.equal(r.code, 1, line);
  }
});

test('headers: a config file curl brings in (config = file, -K file) is read too; a relative one is UNKNOWN; a loop ends', () => {
  const h = fresh('h12'); gitconfigId(h);
  const work = put(join(h, '.curl-work'), `-H "From: ${EMAIL}"\n`);
  put(join(h, '.curlrc'), `config = "${work}"\n`);
  const r = hdr(h);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.carries === 'your email'), show(r)); assert.equal(r.code, 1);
  const h2 = fresh('h12b'); gitconfigId(h2);
  const a = join(h2, 'a.rc'), b = join(h2, 'b.rc'); put(a, `-K ${b}\n`); put(b, `-K ${a}\n-H "X: 1"\n`); put(join(h2, '.curlrc'), `-K ${a}\n`);
  assert.equal(hdr(h2).code, 0, 'a loop of config files ends');
  const h3 = fresh('h12c'); gitconfigId(h3); put(join(h3, '.curlrc'), 'config = work.rc\n');
  const r3 = hdr(h3);
  assert.ok(unknowns(r3).some((x) => /relative path/.test(x.reason)), show(r3)); assert.equal(r3.code, 2);
});

test('headers: curl variables (a variable line, or {{name}} in an expand- line) are UNKNOWN: a header can be built from pieces', () => {
  for (const [i, rc] of [`variable = "u=ada.lovelace"\nexpand-header = "From: {{u}}@example.org"\n`, 'variable = %MYMAIL\n', 'expand-user-agent = "{{a}} {{b}}"\n'].entries()) {
    const h = fresh(`h13-${i}`); gitconfigId(h); put(join(h, '.curlrc'), rc);
    const r = hdr(h);
    assert.ok(unknowns(r).some((x) => /curl variables/.test(x.reason)), `rc ${i}: ${show(r)}`); assert.equal(r.code, 2, `rc ${i}`);
  }
  const h = fresh('h13-ok'); gitconfigId(h); put(join(h, '.curlrc'), 'expand-header = "X-Team: platform"\n');
  assert.equal(hdr(h).code, 0, 'an expand- line with no variable in it is an ordinary header');
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

test('trust: every python3 Wardlatch starts has -B (the version check, the probe, the container probe), read from what each run was given', () => {
  // A recording python3 stands in first on PATH, for /usr/bin/python3 and inside a container, and logs the options each
  // run was started with (the arguments before -c, -m or a script), one run a line, before answering. The command logs
  // every program named python* it starts: one started from anywhere else (refused here: nothing outside this test's
  // folder runs) leaves the recorded runs short of that count. Failed on d807932, whose version check ran python3 -V.
  const log = join(dir, `py-runs-${++n}.log`);
  const rec = (tag) => `o=""; for a in "$@"; do case "$a" in -c|-m) break;; -*) o="$o $a";; *) break;; esac; done; echo "${tag}$o" >> ${JSON.stringify(log)}`;
  const d = fresh('pyB'), sys = pythonRt(fresh('pyB-usr-bin'), 'exit 1', 'exit 0', rec('usr-bin'));
  pythonRt(d, 'exit 1', 'exit 0', rec('path'));
  // inside the container python3 is the only tool: the control site opens; the self-signed site and the test hosts are refused
  const eng = engine('pyB', { tools: { python3: `${rec('container')}\nwhile [ $# -gt 0 ] && [ "$1" != -c ]; do shift; done; shift 2\ncase "$1" in https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 10;; esac` } });
  const starts = `for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) { const o = cp[k]; cp[k] = function (f, ...r) { if (/^python/.test(String(f).split('/').pop())) fs.appendFileSync(${js(log)}, 'started ' + f + '\\n'); return o.call(this, f, ...r); }; }`;
  const r = trust({ PATH: `${eng}:${d}` }, preload('pyB', { online: true, redirects: { '/usr/bin/python3': sys }, extra: starts }), []);
  const lines = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean) : [];
  const runs = lines.filter((l) => !l.startsWith('started ')).map((l) => l.split(' '));
  const of = (tag, version) => runs.filter(([t, ...o]) => t === tag && o.includes('-V') === version).length;
  for (const [tag, version] of [['path', true], ['path', false], ['usr-bin', true], ['usr-bin', false], ['container', false]]) {
    assert.ok(of(tag, version), `the fixture: no ${version ? 'version check' : 'probe'} of the ${tag} python3 was recorded: ${lines.join(' | ')} ${show(r)}`);
  }
  assert.equal(lines.filter((l) => l.startsWith('started ')).length, runs.filter(([t]) => t !== 'container').length, `a python the command started is not a recording stand-in: ${lines.join(' | ')}`);
  for (const [tag, ...opts] of runs) assert.ok(opts.includes('-B'), `the ${tag} python3 was started with "${opts.join(' ')}", without -B`);
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
  // and on screen: the line for it is UNKNOWN too (bin/wardlatch.mjs:487, a separate line from the row)
  const t = text(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
  assert.ok(t.split('\n').some((l) => /^UNKNOWN {2}\S.* · plugins folder$/.test(l)), t);
});

test('wordpress: a site that is found and has none of the listed plugins says so, not "no WordPress installs found"', () => {
  const root = fresh('w5'); site(join(root, 'blog'));
  const r = wp(root);
  assert.equal(r.code, 0, show(r));
  const safeRow = r.rows.find((x) => x.status === 'SAFE');
  assert.ok(safeRow && !/no WordPress installs found/.test(safeRow.reason) && /1 WordPress install/.test(safeRow.reason), show(r));
});

test('wordpress: a core that still holds its bundled wp-content beside the live one is checked in both (the live plugin is EXPOSED)', () => {
  const root = fresh('w6'), s = join(root, 'site');
  put(join(s, 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(s, 'wp', 'wp-content', 'plugins'), 'akismet', 'akismet.php', '5.3');
  plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && /updraftplus/.test(x.what)), show(r)); assert.equal(r.code, 1);
});

test('wordpress: a wp-config.php that sets WP_CONTENT_DIR is UNKNOWN (Wardlatch does not read PHP), and the leftover folder is still checked', () => {
  const root = fresh('w7'), s = site(join(root, 'site'));
  plugin(join(s, 'wp-content', 'plugins'), 'akismet', 'akismet.php', '5.3');
  put(join(s, 'wp-config.php'), "<?php\ndefine( 'WP_CONTENT_DIR', __DIR__ . '/content' );\nrequire_once ABSPATH . 'wp-settings.php';\n");
  plugin(join(s, 'content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(unknowns(r).some((x) => /moves the plugins folder/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('wordpress: any mention of WP_CONTENT_DIR or WP_PLUGIN_DIR in wp-config.php, in any form (even a comment), is UNKNOWN', () => {
  const forms = ["<?php\ndefine('WP_PLUGIN_DIR', getenv('PLUGINS'));\n", "<?php\n// define('WP_PLUGIN_DIR', getenv('PLUGINS'));\n",
    "<?php\nif ( ! defined('WP_CONTENT_DIR') ) define('WP_CONTENT_DIR', __DIR__ . '/content');\n", "<?php define('WP_CONTENT_DIR', __DIR__ . '/content');\n",
    "<?php\nDEFINE('wp_content_dir', dirname( __FILE__ ) . '/content');\n", "<?php\nforeach ($s as $k => $v) define($k, $v); // WP_CONTENT_DIR comes from $s\n",
    "<?php\nconst MY_A = 1, WP_CONTENT_DIR = __DIR__ . '/content';\n", "<?php\n$uploads = WP_CONTENT_DIR . '/uploads';\n", "<?php\n$t = <<<EOT\nIt's WP_PLUGIN_DIR\nEOT;\n"];
  for (const [i, cfg] of forms.entries()) {
    const root = fresh(`w8-${i}`); site(join(root, 'site')); put(join(root, 'site', 'wp-config.php'), cfg);
    const r = wp(root);
    assert.ok(unknowns(r).some((x) => /moves the plugins folder/.test(x.reason)), `form ${i}: ${show(r)}`); assert.equal(r.code, 2, `form ${i}`);
  }
});

test('wordpress: a stock wp-config.php (database settings, salts, table prefix, WP_DEBUG, ABSPATH) leaves no doubt: SAFE', () => {
  const root = fresh('w8-stock'), s = site(join(root, 'site'));
  plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  put(join(s, 'wp-config.php'), "<?php\ndefine( 'DB_NAME', 'wp' );\ndefine( 'DB_USER', 'wp' );\ndefine( 'DB_PASSWORD', 'x' );\ndefine( 'DB_HOST', 'localhost' );\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\n$table_prefix = 'wp_';\ndefine( 'WP_DEBUG', false );\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\nrequire_once ABSPATH . 'wp-settings.php';\n");
  const r = wp(root);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('wordpress: a site inside another site\'s folder (public_html/blog) is searched too', () => {
  const root = fresh('w9'), top = site(join(root, 'public_html'));
  plugin(join(top, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  plugin(join(site(join(top, 'blog')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.site === join(top, 'blog')), show(r));
  assert.equal(r.rows.filter((x) => x.what === 'updraftplus 1.26.13').length, 1, `the outer site's plugin is checked once: ${show(r)}`);
  assert.equal(r.code, 1);
});

test('containers: a gone DOCKER_HOST socket whose folder is not there either is not followed (nothing vouches for it)', () => {
  const d = fresh('c5'); nodeRt(d);
  const sock = join(dir, 'c5-no-such-folder', 'docker.sock');
  const eng = engine('c5', { ps: `echo "Cannot connect to the Docker daemon at unix://${sock}. Is the docker daemon running?" >&2; exit 1` });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('c5-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: `unix://${sock}` }, preload('c5', { online: true }));
  assert.ok(unknowns(r).some((x) => /DOCKER_HOST/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('keys: a text file with a zero byte past its first 8,000 bytes is still scanned (git decides by the head too)', () => {
  const root = fresh('k7'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'dump.sql'), Buffer.concat([Buffer.from(`${'x'.repeat(9000)}\n\n`), Buffer.from([0]), Buffer.from(`\nkey=${AWS}\n`)]));
  g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => [x.file, x.line]), [['dump.sql', 4]]);
});

test('keys: an example key of another kind beside a real key does not hide it', () => {
  const root = fresh('k8'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'cfg.json'), `{"aws":"${AWS}","gh":"ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE12"}\n`); g.commit();
  assert.deepEqual(keyRows(keys(root)).map((x) => x.type), ['AWS access key']);
});

test('keys: a tracked file replaced by a folder is read from git\'s copy (a key in it is found)', () => {
  const root = fresh('k9'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'conf'), `key=${AWS}\n`); put(join(app, 'README'), 'x\n'); g.commit();
  rmSync(join(app, 'conf')); mkdirSync(join(app, 'conf'));
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['conf']);
});

test('keys: a deleted tracked file whose copy git no longer has is UNKNOWN, never silently skipped', () => {
  const root = fresh('k10'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, 'gone.txt'), `secret stuff ${'y'.repeat(50)}\n`); put(join(app, 'README'), 'x\n'); g.commit();
  const blob = g.g(['rev-parse', ':gone.txt']).trim();
  rmSync(join(app, 'gone.txt')); rmSync(join(app, '.git', 'objects', blob.slice(0, 2), blob.slice(2)));
  const r = keys(root);
  assert.ok(unknowns(r).some((x) => x.file === 'gone.txt'), show(r)); assert.equal(r.code, 2);
  // and on screen: the line for it is UNKNOWN too (bin/wardlatch.mjs:471, a separate line from the row)
  const t = text(['--incident', 'committed-keys-2026-10', '--paths', root], { PATH: '/usr/bin:/bin', HOME: fresh('k-home') });
  assert.ok(t.split('\n').includes(`UNKNOWN  ${join(app, 'gone.txt')}`), t);
});

test('keys: 3,000 deleted tracked files are read in one batch, in seconds', () => {
  const root = fresh('k11'), app = join(root, 'app'), g = gitRepo(app);
  for (let i = 0; i < 3000; i++) put(join(app, 'd', `f${i}.txt`), `line ${i}\n`);
  put(join(app, 'd', 'f77.txt'), `key=${AWS}\n`); g.commit();
  rmSync(join(app, 'd'), { recursive: true, force: true });
  const t = Date.now(); const r = keys(root); const ms = Date.now() - t;
  assert.deepEqual(keyRows(r).map((x) => x.file), ['d/f77.txt'], show(r));
  assert.ok(ms < 15000, `took ${ms} ms`);
});

test('keys: files a sparse checkout of a partial clone leaves out are not reported (a clean monorepo clone is SAFE)', () => {
  const src = fresh('k12-src'), g0 = gitRepo(src);
  for (let i = 0; i < 20; i++) put(join(src, 'b', `f${i}.txt`), `x ${i}\n`);
  put(join(src, 'a', 'keep.txt'), 'keep\n'); g0.commit(); g0.g(['config', 'uploadpack.allowFilter', 'true']);
  const root = fresh('k12'), app = join(root, 'app');
  execFileSync('git', ['clone', '-q', '--filter=blob:none', '--sparse', `file://${src}`, app], { stdio: 'pipe', env: GITENV });
  execFileSync('git', ['-C', app, 'sparse-checkout', 'set', 'a'], { stdio: 'pipe', env: GITENV });
  assert.equal(existsSync(join(app, 'b')), false, 'the fixture: b is outside the sparse checkout');
  const r = keys(root);
  assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, show(r)); assert.equal(r.code, 0);
});

test('keys: a UTF-16 file over the in-memory size is UNKNOWN (it is not read in pieces), and a binary that starts FF FE is skipped', async () => {
  const { scanRepo } = await import('../lib/secrets.mjs');
  const root = fresh('k13'), g = gitRepo(root);
  put(join(root, 'big16.txt'), Buffer.from(`﻿${'hello world\r\n'.repeat(200)}`, 'utf16le'));
  put(join(root, 'bin.dat'), Buffer.concat([Buffer.from([0xff, 0xfe, 0, 0, 0, 0]), Buffer.alloc(5000, 7)]));
  g.commit();
  const found = scanRepo(root, { maxBytes: 1024 });
  assert.deepEqual(found.map((x) => [x.file, Boolean(x.unread)]), [['big16.txt', true]]);
});

test('trust: REQUESTS_CA_BUNDLE naming a folder is UNKNOWN (not tested), never dropped', () => {
  const d = fresh('t4'), folder = fresh('t4-certs');
  pythonRt(d); nodeRt(d); curlRt(d);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: folder }, preload('t4', { online: true }));
  assert.ok(unknowns(r).some((x) => x.caVar === 'REQUESTS_CA_BUNDLE' && /not a file/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

// ---- the strict check of 66621a5 ----------------------------------------------------------------------------------------
test('keys: a file marked skip-worktree that is on disk (update-index --skip-worktree on a config) is scanned', () => {
  const root = fresh('s1'), app = join(root, 'app'), g = gitRepo(app);
  put(join(app, '.env.production'), `AWS=${AWS}\n`); g.commit();
  g.g(['update-index', '--skip-worktree', '.env.production']);
  assert.deepEqual(keyRows(keys(root)).map((x) => x.file), ['.env.production']);
});

test('keys: deleted files are read in runs of at most the in-memory size, and one larger than it is UNKNOWN', async () => {
  const { scanRepo } = await import('../lib/secrets.mjs');
  const root = fresh('s2'), g = gitRepo(root);
  for (let i = 0; i < 4; i++) put(join(root, `f${i}.txt`), i === 2 ? `key=${AWS}\n` : `${'z'.repeat(60)}\n`);
  put(join(root, 'big.txt'), `${'q'.repeat(400)}\n`); put(join(root, 'README'), 'x\n'); g.commit();
  for (const f of ['f0.txt', 'f1.txt', 'f2.txt', 'f3.txt', 'big.txt']) rmSync(join(root, f));
  const found = scanRepo(root, { maxIndexed: 100 });
  assert.deepEqual(found.filter((x) => x.type).map((x) => x.file), ['f2.txt']);
  assert.deepEqual(found.filter((x) => x.unread).map((x) => x.file), ['big.txt']);
});

test('the program runner: a program gets no standard input unless it is given (runSync), and run() refuses input', async () => {
  const { runSync, run: runAsync } = await import('../lib/run.mjs');
  assert.equal(runSync('/bin/sh', ['-c', '[ -p /dev/stdin ] && echo pipe || echo none'], { purpose: 'version', timeout: 5000 }).trim(), 'none');
  assert.equal(runSync('/bin/sh', ['-c', 'cat'], { purpose: 'version', timeout: 5000, input: 'hi' }), 'hi');
  const t = Date.now(); const r = await runAsync('/bin/cat', [], { purpose: 'version', timeout: 5000 });
  assert.ok(Date.now() - t < 3000 && r.stdout === '', 'cat ends at once: its standard input is closed');
  assert.match(String((await runAsync('/bin/cat', [], { purpose: 'version', timeout: 5000, input: 'x' })).err), /runSync only/);
});

test('containers: a gone DOCKER_HOST socket in a folder others can write to (as /tmp) is not followed', () => {
  const d = fresh('s4'); nodeRt(d);
  const open = fresh('s4-open'); chmodSync(open, 0o777);
  const sock = join(open, 'docker.sock');
  const eng = engine('s4', { ps: `echo "Cannot connect to the Docker daemon at unix://${sock}. Is the docker daemon running?" >&2; exit 1` });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('s4-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: `unix://${sock}` }, preload('s4', { online: true }));
  assert.ok(unknowns(r).some((x) => /DOCKER_HOST/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('headers: the SAFE receipt lists the curl header file it read', () => {
  const h = fresh('s5'); gitconfigId(h);
  const f = put(join(h, 'hdrs'), 'X-Team: platform\n'); put(join(h, '.curlrc'), `-H @${f}\n`);
  const r = hdr(h);
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && x.searched?.includes(f)), show(r)); assert.equal(r.code, 0);
});

// a site whose live plugins are in content/ (UpdraftPlus 1.26.12), with the core's bundled wp-content left beside it
const moved = (name, cfg, cfgAt = 'core') => {
  const root = fresh(name), s = join(root, 'site');
  put(join(s, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(s, 'wp-content', 'plugins'), 'akismet', 'akismet.php', '5.3');
  plugin(join(s, 'content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  if (cfg !== null) put(join(cfgAt === 'core' ? s : root, 'wp-config.php'), cfg);
  return root;
};
const exposedOrUnknown = (r) => r.rows.some((x) => x.status === 'EXPOSED' && /updraftplus/.test(x.what)) || unknowns(r).length > 0;



test('wordpress: a wp-config.php that cannot be opened, or a move set in a form that cannot be followed, is UNKNOWN', { skip: AS_ROOT && 'root reads a mode-000 file' }, () => {
  const root = moved('s7', "<?php\ndefine('WP_CONTENT_DIR', __DIR__ . '/content');\n"); lock(join(root, 'site', 'wp-config.php'));
  const r = wp(root);
  assert.ok(unknowns(r).some((x) => /could not be opened/.test(x.reason)), show(r)); assert.equal(r.code, 2);
  const forms = ["<?php\ndefine('WP_CONTENT_DIR', MY_ROOT . '/content');\n", "<?php\nconst WP_CONTENT_DIR = __DIR__ . '/content';\n",
    "<?php\n$site = 'x';\ndefine('WP_CONTENT_DIR', \"/srv/{$site}/content\");\n", "<?php\ndefine('WP_PLUGIN_DIR', __DIR__ . \"/$p\");\n", "<?php\ndefine( \"WP_CONTENT_DIR\", getenv('C') );\n"];
  for (const [i, cfg] of forms.entries()) {
    const r2 = wp(moved(`s7b-${i}`, cfg));
    assert.ok(exposedOrUnknown(r2) && unknowns(r2).length, `form ${i}: ${show(r2)}`); assert.notEqual(r2.code, 0, `form ${i}`);
  }
});

test('wordpress: the wp-config.php a level up is read only when the core has none (as WordPress does): a locked unrelated one is not UNKNOWN', { skip: AS_ROOT && 'root reads a mode-000 file' }, () => {
  const root = fresh('s7e'), s = site(join(root, 'site')); put(join(s, 'wp-config.php'), "<?php\ndefine('DB_NAME', 'x');\n");
  const other = put(join(root, 'wp-config.php'), '<?php\n'); lock(other);
  const r = wp(root);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
  const root2 = fresh('s7f'), s2 = join(root2, 'site');
  put(join(s2, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); plugin(join(s2, 'content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  put(join(root2, 'wp-config.php'), "<?php\ndefine('WP_CONTENT_DIR', __DIR__ . '/site/content');\n");
  const r2 = wp(root2);
  assert.ok(unknowns(r2).some((x) => x.reason.startsWith(join(root2, 'wp-config.php'))), `with no wp-config.php of its own, the one a level up is read: ${show(r2)}`);
});

test('wordpress: earlier Bedrock (a plain define of CONTENT_DIR in application.php) is followed, with no UNKNOWN', () => {
  const root = fresh('s7g'), b = join(root, 'example.com');
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  put(join(b, 'config', 'application.php'), "<?php\ndefine('CONTENT_DIR', '/app');\ndefine('WP_CONTENT_DIR', $webroot_dir . CONTENT_DIR);\n");
  plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  const r = wp(root);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('wordpress: a core with no plugins folder on disk but a wp-config.php that moves it is a site, UNKNOWN (not "no plugins folder")', () => {
  const root = fresh('s9'), s = join(root, 'site');
  put(join(s, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); put(join(s, 'wp-config.php'), "<?php\ndefine('WP_PLUGIN_DIR', __DIR__ . '/plugs');\n");
  plugin(join(s, 'plugs'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(unknowns(r).some((x) => /moves the plugins folder/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('wordpress: one plugins folder reached two ways (wp-content linked to the core\'s) is checked once, with no plugins field', () => {
  const root = fresh('s10'), s = join(root, 'site'), core = join(s, 'wp');
  put(join(core, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(core, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  symlinkSync(join(core, 'wp-content'), join(s, 'wp-content'));
  const r = wp(root);
  const rows = r.rows.filter((x) => x.what === 'updraftplus 1.26.13');
  assert.equal(rows.length, 1, show(r)); assert.equal(rows[0].plugins, undefined);
});

test('wordpress: Bedrock with any CONTENT_DIR but its stock /app (in application.php or an environment file), or an unreadable application.php, is UNKNOWN', { skip: AS_ROOT && 'root reads a mode-000 file' }, () => {
  const mk = (name, app, env) => {
    const root = fresh(name), b = join(root, 'example.com');
    put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
    plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
    put(join(b, 'config', 'application.php'), app);
    if (env) put(join(b, 'config', 'environments', 'production.php'), env);
    return { root, app: join(b, 'config', 'application.php') };
  };
  for (const [i, [app, env]] of [["<?php\nConfig::define('CONTENT_DIR', '/content');\n"], ["<?php\nConfig::define('CONTENT_DIR', env('CONTENT_DIR'));\n"],
    ["<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', '/srv/shared/content');\n"], ["<?php\nConfig::define('CONTENT_DIR', '/app');\n", "<?php\nConfig::define('CONTENT_DIR', '/content');\n"]].entries()) {
    const r = wp(mk(`s11-${i}`, app, env).root);
    assert.ok(unknowns(r).length, `case ${i}: ${show(r)}`); assert.equal(r.code, 2, `case ${i}`);
  }
  const locked = mk('s11-locked', "<?php\nConfig::define('CONTENT_DIR', '/app');\n"); lock(locked.app);
  const r = wp(locked.root);
  assert.ok(unknowns(r).some((x) => /could not be opened/.test(x.reason)), show(r)); assert.equal(r.code, 2);
  const stock = mk('s11-stock', "<?php\nuse Roots\\WPConfig\\Config;\n$webroot_dir = $root_dir . '/web';\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\nConfig::define('WP_CONTENT_URL', Config::get('WP_HOME') . Config::get('CONTENT_DIR'));\n");
  assert.equal(wp(stock.root).code, 0, 'stock Bedrock leaves no doubt');
});

test('wordpress: a staging copy inside a site\'s wp-content is a site of its own', () => {
  const root = fresh('s12'), top = site(join(root, 'site'));
  plugin(join(site(join(top, 'wp-content', 'staging')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.site === join(top, 'wp-content', 'staging')), show(r)); assert.equal(r.code, 1);
});

// ---- the strict check of b827dc6 ----------------------------------------------------------------------------------------
test('keys: the batch parser reads past an object git no longer has, and keeps blobs that hold newlines', async () => {
  const { parseBatch } = await import('../lib/secrets.mjs');
  const a = Buffer.from('line1\nline2\n'), b = Buffer.from('x\n0 blob 5\nfake\n');
  const out = Buffer.concat([Buffer.from(`aaa blob ${a.length}\n`), a, Buffer.from('\nbbb missing\n'), Buffer.from(`ccc blob ${b.length}\n`), b, Buffer.from('\n')]);
  assert.deepEqual(parseBatch(out).map((o) => (o.missing ? [o.blob, 'missing'] : [o.blob, o.body.toString()])), [['aaa', 'line1\nline2\n'], ['bbb', 'missing'], ['ccc', 'x\n0 blob 5\nfake\n']]);
});

test('keys: deleted files are read in one --batch run per maxIndexed bytes (counted through a git that logs its calls)', async () => {
  const { scanRepo } = await import('../lib/secrets.mjs');
  const root = fresh('s13'), g = gitRepo(root);
  for (let i = 0; i < 4; i++) put(join(root, `f${i}.txt`), `${'z'.repeat(60)} ${i}\n`);
  put(join(root, 'README'), 'x\n'); g.commit();
  for (let i = 0; i < 4; i++) rmSync(join(root, `f${i}.txt`));
  const wrap = fresh('s13-bin'), log = join(dir, 's13.log'), real = execFileSync('/bin/sh', ['-c', 'command -v git'], { env: { PATH: '/usr/bin:/bin' } }).toString().trim();
  exe(join(wrap, 'git'), `echo "$*" >> ${JSON.stringify(log)}\nexec ${JSON.stringify(real)} "$@"`);
  const saved = process.env.PATH; process.env.PATH = `${wrap}:/usr/bin:/bin`;
  try { scanRepo(root, { maxIndexed: 130 }); } finally { process.env.PATH = saved; }
  const runs = readFileSync(log, 'utf8').split('\n').filter((l) => /cat-file --batch$/.test(l));
  assert.equal(runs.length, 2, 'four 63-byte files in runs of at most 130 bytes: two runs');
});

test('headers: a folder where a settings or header file would be is not used (SAFE), as curl and git skip it', () => {
  const h = fresh('s14'); gitconfigId(h); mkdirSync(join(h, '.curlrc'));
  assert.equal(hdr(h).code, 0);
  const h2 = fresh('s14b'); gitconfigId(h2); mkdirSync(join(h2, 'hdrdir')); put(join(h2, '.curlrc'), `-H @${join(h2, 'hdrdir')}\n`);
  const r2 = hdr(h2);
  assert.equal(unknowns(r2).length, 0, show(r2)); assert.equal(r2.code, 0);
});

test('trust: REQUESTS_CA_BUNDLE that cannot be opened is UNKNOWN and says so', { skip: AS_ROOT && 'root opens a mode-000 file' }, () => {
  const d = fresh('s15'), b = put(join(fresh('s15-ca'), 'bundle.pem'), 'x\n'); lock(dirname(b));
  pythonRt(d); nodeRt(d); curlRt(d);
  const r = trust({ PATH: d, REQUESTS_CA_BUNDLE: b }, preload('s15', { online: true }));
  assert.ok(unknowns(r).some((x) => x.caVar === 'REQUESTS_CA_BUNDLE' && /could not be opened/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('containers: a gone DOCKER_HOST socket in a group-writable folder is not followed; the reason says why', () => {
  const d = fresh('s16'); nodeRt(d);
  const grp = fresh('s16-grp'); chmodSync(grp, 0o775);
  const sock = join(grp, 'docker.sock');
  const eng = engine('s16', { ps: `echo "Cannot connect to the Docker daemon at unix://${sock}. Is the docker daemon running?" >&2; exit 1` });
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('s16-root')], { PATH: `${eng}:${d}`, DOCKER_HOST: `unix://${sock}` }, preload('s16', { online: true }));
  assert.ok(unknowns(r).some((x) => /others can write to/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

test('wordpress: a clean staging copy inside wp-content is found and SAFE', () => {
  const root = fresh('s17'), top = site(join(root, 'site'));
  plugin(join(site(join(top, 'wp-content', 'staging')), 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  const r = wp(root);
  assert.ok(r.rows.some((x) => x.status === 'SAFE' && x.site === join(top, 'wp-content', 'staging')), show(r));
  assert.equal(r.rows.filter((x) => ['EXPOSED', 'UNKNOWN'].includes(x.status)).length, 0, show(r)); assert.equal(r.code, 0);
});

test('headers: curl files brought in are capped (32 files, 1 MB each): past that UNKNOWN, never a hang', () => {
  const h = fresh('s18'); gitconfigId(h);
  const many = Array.from({ length: 40 }, (_, i) => put(join(h, 'k', `c${i}.rc`), '-H "X: 1"\n'));
  put(join(h, '.curlrc'), many.map((f) => `-K ${f}`).join('\n') + '\n');
  const t = Date.now(); const r = hdr(h);
  assert.ok(unknowns(r).some((x) => /more files than the 32/.test(x.reason)), show(r)); assert.equal(r.code, 2); assert.ok(Date.now() - t < 20000);
  const h2 = fresh('s18b'); gitconfigId(h2);
  const big = put(join(h2, 'big-headers'), 'X: y\n'.repeat(300000)); put(join(h2, '.curlrc'), `-H @${big}\n`);
  const r2 = hdr(h2);
  assert.ok(unknowns(r2).some((x) => x.file === big), show(r2)); assert.equal(r2.code, 2);
});

test('headers: a capital K inside another option\'s value (-uKen:pw, -eKnown) brings in no file; -sK file does', () => {
  const h = fresh('s19'); gitconfigId(h); put(join(h, '.curlrc'), '-uKen:secret\n-eKnown\n');
  const r = hdr(h);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
  const h2 = fresh('s19b'); gitconfigId(h2); const w = put(join(h2, 'w.rc'), `-H "From: ${EMAIL}"\n`); put(join(h2, '.curlrc'), `-sK ${w}\n`);
  assert.equal(hdr(h2).code, 1);
});

// ---- owner decisions, 23 Oct 2026 ---------------------------------------------------------------------------------------
test('images: Docker installed but not running (Docker Desktop quit) is a REVIEW line saying its images were not checked; exit 0', () => {
  const eng = engine('o1', { images: 'echo "Cannot connect to the Docker daemon at unix:///Users/ada/.docker/run/docker.sock. Is the docker daemon running?" >&2; exit 1' });
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('o1-root')], { PATH: eng, HOME: fresh('o1-home'), TMPDIR: fresh('o1-tmp') }, preload('o1'));
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.engine === 'docker' && x.notRunning && /not running, so its local images were not checked/.test(x.reason)), show(r));
  assert.ok(r.rows.some((x) => x.status === 'SAFE'), `the all-clear for what was looked at stays: ${show(r)}`);
  assert.equal(r.code, 0);
});

test('trust (Linux): the distribution\'s CA bundle with neither curl nor python3 to test it is UNKNOWN; with python3 it is not', () => {
  const bundle = put(join(fresh('o2-ca'), 'ca-certificates.crt'), '-----BEGIN CERTIFICATE-----\n');
  const linux = (name) => preload(name, { online: true, redirects: { '/etc/ssl/certs/ca-certificates.crt': bundle }, extra: "Object.defineProperty(process, 'platform', { value: 'linux' });" });
  const d = fresh('o2'); nodeRt(d);
  const r = trust({ PATH: d }, linux('o2'));
  assert.ok(unknowns(r).some((x) => x.system && /neither curl nor python3/.test(x.reason)), show(r)); assert.equal(r.code, 2);
  // and on screen: the line for it is UNKNOWN too (bin/wardlatch.mjs:301, a separate line from the row)
  const t = text(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('trust-root')], { PATH: d }, linux('o2'));
  assert.ok(t.split('\n').includes('UNKNOWN  Linux system trust store (/etc/ssl/certs/ca-certificates.crt)'), t);
  const d2 = fresh('o2b'); nodeRt(d2); pythonRt(d2);
  const r2 = trust({ PATH: d2 }, linux('o2b'));
  assert.ok(!r2.rows.some((x) => x.system && x.status === 'UNKNOWN'), show(r2));
});

test('headers: a planted .curlrc of thousands of relative or over-the-cap file lines makes one UNKNOWN row of each kind, quickly', () => {
  const h = fresh('s20'); gitconfigId(h);
  const lines = [...Array.from({ length: 5000 }, (_, i) => `-H @rel${i}.txt`), ...Array.from({ length: 5000 }, (_, i) => `-K /nowhere/c${i}.rc`)];
  put(join(h, '.curlrc'), lines.join('\n') + '\n');
  const t = Date.now(); const r = hdr(h);
  assert.equal(unknowns(r).length, 2, show(r)); assert.ok(Date.now() - t < 20000);
});

// ---- the strict check of 50af5ea ----------------------------------------------------------------------------------------
const curlCase = (name, rc, files = {}, env = {}) => {
  const h = fresh(name); gitconfigId(h);
  const paths = Object.fromEntries(Object.entries(files).map(([k, v]) => [k, put(join(h, k), v)]));
  put(join(h, '.curlrc'), rc.replace(/\{(\w[\w.]*)\}/g, (_, k) => paths[k] ?? `{${k}}`));
  return hdr(h, env);
};
const FROM = `From: ${EMAIL}\n`;

test('headers: config files curl brings in every way are read: -K/path attached, expand-config, an escaped name', () => {
  for (const [i, rc] of ['-K{c.rc}', 'expand-config = "{c.rc}"', '-K "{c.rc}"'].entries()) {
    const r = curlCase(`t50-${i}`, `${rc}\n`, { 'c.rc': `header = "${FROM.trim()}"\n` });
    assert.equal(r.code, 1, `${rc}: ${show(r)}`);
  }
  const h = fresh('t50-esc'); gitconfigId(h); const c = put(join(h, 'cfg.rc'), `-H "${FROM.trim()}"\n`);
  put(join(h, '.curlrc'), `config = "${c.replace('cfg', 'c\\fg')}"\nheader = "\\@${put(join(h, 'hdr'), FROM)}"\n`);
  const r = hdr(h);
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 2, `escaped names are read as curl reads them: ${show(r)}`);
});

test('headers: a user agent that starts with @/ is a user agent, not a header file (curl sends it as it is)', () => {
  for (const [i, rc] of [`user-agent = "@/x ${EMAIL}"`, '-A "@/ Ada Lovelace"'].entries()) {
    const r = curlCase(`t51-${i}`, `${rc}\n`);
    assert.equal(r.code, 1, `${rc}: ${show(r)}`);
  }
});

test('headers: one file brought in both as headers and as config is read both ways', () => {
  const h = fresh('t52'); gitconfigId(h);
  const y = put(join(h, 'y'), FROM), x = put(join(h, 'x'), `header = @${y}\n`);
  put(join(h, '.curlrc'), `header = @${x}\nconfig = ${x}\n`);
  assert.equal(hdr(h).code, 1);
});

test('headers: expand-proxy-header counts; \\t in a quoted value is white space (a tab between first and last name)', () => {
  assert.equal(curlCase('t53a', `expand-proxy-header = "${FROM.trim()}"\n`).code, 1);
  assert.equal(curlCase('t53b', '-A "Ada\\tLovelace"\n').code, 1);
});

test('headers: -K - and -H @- read standard input, never a file named "-" (no UNKNOWN)', () => {
  const r = curlCase('t54', '-K -\n-H @-\n');
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('headers: a header file is read as curl reads it, line by line and as written (no escapes undone)', () => {
  const r = curlCase('t55', '-H @{h}\n', { h: 'X-Who: Ada\\ Lovelace\n' });
  assert.equal(r.code, 0, `curl sends the backslash too, which is not the name: ${show(r)}`);
});

test('headers: a .curlrc that brings in itself is read once (one finding, not two)', () => {
  const h = fresh('t56'); gitconfigId(h); const rc = join(h, '.curlrc');
  put(rc, `-H "${FROM.trim()}"\n-K ${rc}\n`);
  const r = hdr(h);
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 1, show(r));
});

const bedrockSite = (name, { app, envs = {}, envMode } = {}) => {
  const root = fresh(name), b = join(root, 'example.com');
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  put(join(b, 'config', 'application.php'), app ?? "<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\n");
  for (const [f, t] of Object.entries(envs)) put(join(b, 'config', 'environments', f), t);
  if (envMode !== undefined) { chmodSync(join(b, 'config', 'environments'), envMode); locked.push(join(b, 'config', 'environments')); }
  return { root, web: join(b, 'web') };
};

test('wordpress: Bedrock environment files: stock ones (and non-PHP files) leave no doubt; one naming WP_PLUGIN_DIR does', () => {
  const stock = bedrockSite('t57a', { envs: { 'development.php': "<?php\nConfig::define('SAVEQUERIES', true);\nConfig::define('WP_DEBUG', true);\n", 'README.md': 'CONTENT_DIR notes\n' } });
  assert.equal(wp(stock.root).code, 0);
  const moved = bedrockSite('t57b', { envs: { 'production.php': "<?php\nConfig::define('WP_PLUGIN_DIR', '/srv/plugins');\n" } });
  assert.equal(wp(moved.root).code, 2);
  const app = bedrockSite('t57c', { app: "<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_PLUGIN_DIR', '/srv/plugins');\n" });
  assert.equal(wp(app.root).code, 2);
});

test('wordpress: a Bedrock environments folder that cannot be opened or listed is a doubt (UNKNOWN), even searched from web/', { skip: AS_ROOT && 'root opens any folder' }, () => {
  for (const [i, mode] of [0o000, 0o111].entries()) {
    const s = bedrockSite(`t58-${i}`, { envs: { 'production.php': "<?php\nConfig::define('CONTENT_DIR', '/content');\n" }, envMode: mode });
    const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', s.web]);
    assert.ok(unknowns(r).some((x) => /environments could not be opened \(run Wardlatch with sudo\)/.test(x.reason)), `mode ${mode.toString(8)}: ${show(r)}`); assert.equal(r.code, 2);
  }
});

test('wordpress: an app/ folder of another program beside a core is not Bedrock: a core with no plugins folder there is UNKNOWN', () => {
  const root = fresh('t59'), s = join(root, 'site');
  put(join(s, 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); put(join(s, 'app', 'Http', 'Kernel.php'), '<?php\n');
  const r = wp(root);
  assert.ok(unknowns(r).some((x) => /plugins folder/.test(x.what)), show(r)); assert.equal(r.code, 2);
});

test('wordpress: a parent wp-config.php is not read when that folder holds a wp-settings.php of its own', () => {
  const root = fresh('t60'), s = join(root, 'site');
  put(join(s, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); mkdirSync(join(s, 'wp-content', 'plugins'), { recursive: true });
  put(join(root, 'wp-settings.php'), '<?php\n'); put(join(root, 'wp-config.php'), "<?php\ndefine('WP_CONTENT_DIR', '/elsewhere');\n");
  assert.equal(wp(root).code, 0);
});

// ---- the strict check of f92b7ae ----------------------------------------------------------------------------------------
test('headers: a file name with a backslash or an escaped quote is read as curl reads it (escapes undone only in quotes)', () => {
  const h = fresh('t61'); gitconfigId(h);
  const back = put(join(h, 'a\\b'), FROM), quote = put(join(h, 'q"x'), FROM), cfg = put(join(h, 'c\\d.rc'), `-H "${FROM.trim()}"\n`);
  for (const [i, line] of [`-H @${back}`, `header = @${back}`, `-H@${back}`, `-K ${cfg}`, `config = ${cfg}`, `-K${cfg}`,
    `header = "@${quote.replace('"', '\\"')}"`, `-K "${put(join(h, 'k"y.rc'), `-H "${FROM.trim()}"\n`).replace('"', '\\"')}"`].entries()) {
    const h2 = fresh(`t61-${i}`); gitconfigId(h2); put(join(h2, '.curlrc'), `${line}\n`);
    assert.equal(hdr(h2).code, 1, line);
  }
});

test('headers: an expand-config line with {{ in it is UNKNOWN; a plain header with {{ in it is an ordinary header', () => {
  const r = curlCase('t62', 'expand-config = "/x/{{d}}c.rc"\n');
  assert.ok(unknowns(r).some((x) => /curl variables/.test(x.reason)), show(r)); assert.equal(r.code, 2);
  const r2 = curlCase('t62b', '-H "X-Tmpl: {{a}}"\n');
  assert.equal(unknowns(r2).length, 0, show(r2)); assert.equal(r2.code, 0);
});

test('headers: clean twins: -K/path, expand-config and a both-ways file with nothing of yours, and user-agent = "@acme-bot/2.0", are SAFE', () => {
  for (const [i, [rc, files]] of [['-K{c.rc}\n', { 'c.rc': '-H "X: 1"\n' }], ['expand-config = "{c.rc}"\n', { 'c.rc': '-H "X: 1"\n' }],
    ['header = @{x}\nconfig = {x}\n', { x: 'X-Team: platform\n' }], ['user-agent = "@acme-bot/2.0"\n', {}]].entries()) {
    const r = curlCase(`t63-${i}`, rc, files);
    assert.equal(r.rows.filter((x) => x.status !== 'SAFE').length, 0, `${rc}: ${show(r)}`); assert.equal(r.code, 0);
  }
});

test('wordpress: Bedrock app/plugins, or config/environments, linked into a folder that cannot be opened is UNKNOWN', { skip: AS_ROOT && 'root opens any folder' }, () => {
  // each link points into a folder whose parent can't be opened, so the link itself can't be followed
  const s1 = bedrockSite('t64a'), lockedParent = fresh('t64a-locked'), lockedPlugins = join(lockedParent, 'plugins');
  plugin(lockedPlugins, 'updraftplus', 'updraftplus.php', '1.26.12'); rmSync(join(s1.web, 'app', 'plugins'), { recursive: true });
  symlinkSync(lockedPlugins, join(s1.web, 'app', 'plugins')); lock(lockedParent);
  const r1 = wp(s1.root);
  assert.ok(unknowns(r1).length, show(r1)); assert.equal(r1.code, 2);
  const s2 = bedrockSite('t64b'), lockedEnvParent = fresh('t64b-locked'), lockedEnv = join(lockedEnvParent, 'environments');
  put(join(lockedEnv, 'production.php'), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
  symlinkSync(lockedEnv, join(dirname(s2.web), 'config', 'environments')); lock(lockedEnvParent);
  const r2 = wp(s2.root);
  assert.ok(unknowns(r2).some((x) => /environments could not be opened/.test(x.reason)), show(r2)); assert.equal(r2.code, 2);
});

test('wordpress: Bedrock whose app/ has no plugins folder yet is a site, SAFE (as a classic core with an empty wp-content is)', () => {
  const s = bedrockSite('t65'); rmSync(join(s.web, 'app', 'plugins'), { recursive: true }); mkdirSync(join(s.web, 'app', 'themes'));
  const r = wp(s.root);
  assert.equal(unknowns(r).length, 0, show(r)); assert.equal(r.code, 0);
});

test('wordpress: a define of WP_CONTENT_DIR tucked inside Bedrock\'s WP_CONTENT_URL line is not a stock line: UNKNOWN', () => {
  const s = bedrockSite('t66', { app: "<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_URL', Config::define('WP_CONTENT_DIR', '/srv/x'));\n" });
  assert.equal(wp(s.root).code, 2);
});

// ---- the strict check of 284ffbb ----------------------------------------------------------------------------------------
test('headers: a file name with a no-break or narrow space (as macOS names files) is one name, as curl reads it', () => {
  for (const sp of [' ', ' ']) {
    const h = fresh(`t67-${sp.charCodeAt(0)}`); gitconfigId(h);
    const f = put(join(h, `team${sp}headers`), FROM), c = put(join(h, `my${sp}cfg.rc`), `-H "${FROM.trim()}"\n`);
    for (const [i, line] of [`-H @${f}`, `header = @${f}`, `-H@${f}`, `-K ${c}`, `-K${c}`, `config = ${c}`, `header = "@${f.replace(sp, `\\${' '}`).replace(' ', sp)}"`].entries()) {
      const h2 = fresh(`t67-${sp.charCodeAt(0)}-${i}`); gitconfigId(h2); put(join(h2, '.curlrc'), `${line}\n`);
      assert.equal(hdr(h2).code, 1, JSON.stringify(line));
    }
  }
});

test('headers: an escaped line separator inside a quoted file name is undone like any escape', () => {
  const h = fresh('t67b'); gitconfigId(h); const f = put(join(h, 'a b'), FROM);
  put(join(h, '.curlrc'), `header = "@${f.replace(' ', '\\ ')}"\n`);
  assert.equal(hdr(h).code, 1);
});

test('headers: proxy-header @file is read like header @file', () => {
  assert.equal(curlCase('t69', 'proxy-header = @{h}\n', { h: FROM }).code, 1);
});

test('headers: a quoted value attached to its option (-H"@file", -K"file") is not a file name curl opens', () => {
  const r = curlCase('t71', '-H"@{h}"\n', { h: FROM });
  assert.equal(r.code, 0, show(r));
  const r2 = curlCase('t71b', '-K"{c.rc}"\n', { 'c.rc': `-H "${FROM.trim()}"\n` });
  assert.ok(unknowns(r2).some((x) => /relative path/.test(x.reason)), show(r2)); assert.equal(r2.code, 2);
});

test('headers: clean twin: an unquoted name a\\b is read as a\\b, not ab (the one holding your email)', () => {
  const h = fresh('t72'); gitconfigId(h);
  const clean = put(join(h, 'a\\b'), 'X-Team: platform\n'); put(join(h, 'ab'), FROM);
  put(join(h, '.curlrc'), `-H @${clean}\n`);
  assert.equal(hdr(h).code, 0);
});

test('wordpress: any define tucked inside Bedrock\'s WP_CONTENT_URL line (CONTENT_DIR, WP_PLUGIN_DIR) is not a stock line: UNKNOWN', () => {
  for (const [i, inner] of ["Config::define('CONTENT_DIR', '/content')", "Config::define('WP_PLUGIN_DIR', '/srv/p')"].entries()) {
    const s = bedrockSite(`t68-${i}`, { app: `<?php\nConfig::define('WP_CONTENT_URL', Config::get('WP_HOME') . ${inner});\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\n` });
    assert.equal(wp(s.root).code, 2, inner);
  }
});

test('wordpress: app/plugins linked into a folder that cannot be opened, with no Bedrock config, is UNKNOWN (the core\'s bundled plugins aside)', { skip: AS_ROOT && 'root opens any folder' }, () => {
  const root = fresh('t70'), s = join(root, 'site'), core = join(s, 'wp');
  put(join(core, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";'); plugin(join(core, 'wp-content', 'plugins'), 'akismet', 'akismet.php', '5.3');
  const parent = fresh('t70-locked'); plugin(join(parent, 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  mkdirSync(join(s, 'app')); symlinkSync(join(parent, 'plugins'), join(s, 'app', 'plugins')); lock(parent);
  const r = wp(root);
  assert.ok(unknowns(r).length, show(r)); assert.equal(r.code, 2);
});

// ---- the strict check of c7e903d ----------------------------------------------------------------------------------------
test('wordpress: Bedrock\'s URL line counts as stock only in its exact forms: a define written any way PHP allows on it is UNKNOWN', () => {
  const inners = ["define('WP_PLUGIN_DIR', '/srv/p')", "define ('WP_PLUGIN_DIR', '/srv/p')", "'define'('WP_PLUGIN_DIR', '/srv/p')", "call_user_func('define', 'WP_PLUGIN_DIR', '/srv/p')",
    "define/**/('WP_PLUGIN_DIR', '/srv/p')", "\"define\"('WP_CONTENT_DIR', '/srv/c')", "[Config::class, 'define']('WP_PLUGIN_DIR', '/srv/p')", "[Config::class, 'define']('CONTENT_DIR', '/content')"];
  for (const [i, inner] of inners.entries()) {
    const s = bedrockSite(`t73-${i}`, { app: `<?php\nConfig::define('WP_CONTENT_URL', Config::get('WP_HOME') . ${inner});\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\n` });
    assert.equal(wp(s.root).code, 2, inner);
  }
});

test('wordpress: both exact stock URL lines (Bedrock 1.9+ and earlier), plain and CRLF, leave no doubt', () => {
  const forms = ["<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\nConfig::define('WP_CONTENT_URL', Config::get('WP_HOME') . Config::get('CONTENT_DIR'));\n",
    "<?php\ndefine('CONTENT_DIR', '/app');\ndefine('WP_CONTENT_DIR', $webroot_dir . CONTENT_DIR);\ndefine('WP_CONTENT_URL', WP_HOME . CONTENT_DIR);\n"];
  for (const [i, app] of [...forms, ...forms.map((f) => f.replace(/\n/g, '\r\n'))].entries()) assert.equal(wp(bedrockSite(`t74-${i}`, { app }).root).code, 0, `form ${i}`);
});

test('headers: a file name that ends in a non-ASCII space (no-break, narrow, ideographic) is read with it, even beside a clean twin', () => {
  for (const sp of [' ', ' ', '　']) {
    const h = fresh(`t75-${sp.charCodeAt(0)}`); gitconfigId(h);
    put(join(h, 'a'), 'X-Team: platform\n'); const f = put(join(h, `a${sp}`), FROM), c = put(join(h, `c${sp}`), `-H "${FROM.trim()}"\n`);
    for (const [i, line] of [`-H @${f}`, `header = @${f}`, `-K ${c}`, `config = ${c}`].entries()) {
      const h2 = fresh(`t75-${sp.charCodeAt(0)}-${i}`); gitconfigId(h2); put(join(h2, '.curlrc'), `${line}\r\n`);
      assert.equal(hdr(h2).code, 1, JSON.stringify(line));
    }
  }
});

test('headers: ASCII separators split as curl splits: a tab after a file name, a vertical tab after -H, indented lines', () => {
  for (const [i, rc] of ['-H @{h}\tx\n', '-H\v@{h}\n', `\t-H "${FROM.trim()}"\n`, `  header = "${FROM.trim()}"\n`, `-H @{h}\fy\n`].entries()) {
    assert.equal(curlCase(`t76-${i}`, rc, { h: FROM }).code, 1, JSON.stringify(rc));
  }
});

test('headers: --header="@file" and --config="file" (curl refuses the =) do not open a file named by the quotes', () => {
  assert.equal(curlCase('t77', '--header="@{h}"\n', { h: FROM }).code, 0);
  const r = curlCase('t77b', '--config="{c.rc}"\n', { 'c.rc': `-H "${FROM.trim()}"\n` });
  assert.ok(unknowns(r).some((x) => /relative path/.test(x.reason)), show(r)); assert.equal(r.code, 2);
});

// ---- the strict check of c2ee54e ----------------------------------------------------------------------------------------
test('headers: a planted .curlrc line with a million spaces in the middle is read in linear time', async () => {
  const { headersInRc } = await import('../lib/headers.mjs');
  for (const line of [`header a${' '.repeat(1e6)}x\r`, `-H a${' '.repeat(1e6)}b`, `-K a${'\t'.repeat(1e6)}b`]) {
    const t = Date.now(); headersInRc(line, 'curl'); assert.ok(Date.now() - t < 1000, `${Date.now() - t} ms`);
  }
});

const bedrock100 = (name, app, env) => {
  const root = fresh(name), b = join(root, 'example.com');
  put(join(b, 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "4.0";');
  put(join(b, 'wp-config.php'), "<?php\nrequire_once(dirname(__FILE__) . '/config/application.php');\nrequire_once(ABSPATH . 'wp-settings.php');\n");
  put(join(b, 'config', 'application.php'), app);
  if (env) put(join(b, 'config', 'environments', 'production.php'), env);
  plugin(join(b, 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  plugin(join(b, 'content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  return root;
};
const STOCK100 = "<?php\n$root_dir = dirname(dirname(__FILE__));\ndefine('CONTENT_DIR', '/app');\ndefine('WP_CONTENT_DIR', $root_dir . CONTENT_DIR);\ndefine('WP_CONTENT_URL', 'http://' . $_SERVER['HTTP_HOST'] . CONTENT_DIR);\n";

test('wordpress: Bedrock 1.0.0 (app/, config/ and wp/ side by side): stock reads SAFE; a moved CONTENT_DIR or WP_PLUGIN_DIR in its config is UNKNOWN', () => {
  assert.equal(wp(bedrock100('t78a', STOCK100)).code, 0);
  assert.equal(wp(bedrock100('t78b', STOCK100.replace("'/app'", "'/content'"))).code, 2);
  assert.equal(wp(bedrock100('t78c', STOCK100, "<?php\ndefine('WP_PLUGIN_DIR', '/srv/p');\n")).code, 2);
});

test('wordpress: anything more on a stock URL line (a move before or after it, a define in place of WP_HOME or after the stock part) is UNKNOWN', () => {
  const modern = "Config::define('WP_CONTENT_URL', Config::get('WP_HOME') . Config::get('CONTENT_DIR'));", old = "define('WP_CONTENT_URL', WP_HOME . CONTENT_DIR);";
  const mv = "Config::define('WP_PLUGIN_DIR', '/srv/p');";
  const lines = [`${mv} ${modern}`, `${modern} ${mv}`, `${mv} ${old}`, `${old} ${mv}`, "define('WP_CONTENT_URL', define('WP_PLUGIN_DIR', '/srv/p') . CONTENT_DIR);",
    `Config::define('WP_CONTENT_URL', Config::get('WP_HOME') . Config::get('CONTENT_DIR') . Config::define('WP_PLUGIN_DIR', '/srv/p'));`, "define('WP_CONTENT_URL', WP_HOME . CONTENT_DIR . define('WP_PLUGIN_DIR', '/srv/p'));"];
  for (const [i, line] of lines.entries()) {
    const sb = bedrockSite(`t79-${i}`, { app: `<?php\nConfig::define('CONTENT_DIR', '/app');\nConfig::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));\n${line}\n` });
    assert.equal(wp(sb.root).code, 2, line);
  }
});

test('headers: a vertical tab or a CR inside an unquoted file name ends it, as curl splits; a line starting with a no-break space is not an option', () => {
  for (const [i, sep] of ['\v', '\r'].entries()) {
    const r = curlCase(`t80-${i}`, `-H @{h}${sep}junk\n`, { h: FROM });
    assert.equal(r.code, 1, JSON.stringify(sep));
  }
  const r = curlCase('t80-nbsp', ` header = "${FROM.trim()}"\n`);
  assert.equal(r.code, 0, `curl refuses that line as an unknown option: ${show(r)}`);
});

// ---- the strict check of 5a0d790 ----------------------------------------------------------------------------------------
test('wordpress: 1.0.0\'s $root_dir line in a Bedrock 1.1+ config moves the content folder: not stock there, UNKNOWN', () => {
  for (const [i, line] of ["define('WP_CONTENT_DIR', $root_dir . CONTENT_DIR);", "Config::define('WP_CONTENT_DIR', $root_dir . Config::get('CONTENT_DIR'));"].entries()) {
    const sb = bedrockSite(`t81-${i}`, { app: `<?php\nConfig::define('CONTENT_DIR', '/app');\n${line}\n` });
    plugin(join(dirname(sb.web), 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
    assert.equal(wp(sb.root).code, 2, line);
  }
});

test('wordpress: a Rails app (app/, config/application.rb, config/environments/*.rb) beside a core is not Bedrock: a core with no content folder is UNKNOWN', () => {
  const root = fresh('t82'), r = join(root, 'railsapp');
  put(join(r, 'app', 'models', 'user.rb'), 'class User; end\n'); put(join(r, 'config', 'application.rb'), 'module App; end\n');
  put(join(r, 'config', 'environments', 'production.rb'), 'Rails.application.configure do; end\n');
  put(join(r, 'blog', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  const res = wp(root);
  assert.ok(unknowns(res).some((x) => /plugins folder/.test(x.what)), show(res)); assert.equal(res.code, 2);
});

test('wordpress: Bedrock 1.0.0\'s URL line counts as stock only exactly: a move before or after it, or inside it, is UNKNOWN', () => {
  const url = "define('WP_CONTENT_URL', 'http://' . $_SERVER['HTTP_HOST'] . CONTENT_DIR);", mv = "define('WP_PLUGIN_DIR', '/srv/p');";
  for (const [i, line] of [`${mv} ${url}`, `${url} ${mv}`, "define('WP_CONTENT_URL', 'http://' . $_SERVER['HTTP_HOST'] . CONTENT_DIR . define('WP_PLUGIN_DIR', '/srv/p'));"].entries()) {
    assert.equal(wp(bedrock100(`t83-${i}`, STOCK100.replace(url, line))).code, 2, line);
  }
});

test('wordpress: a content folder built from another variable ($dir . CONTENT_DIR) is not stock: UNKNOWN', () => {
  assert.equal(wp(bedrock100('t84', STOCK100.replace('$root_dir . CONTENT_DIR', '$dir . CONTENT_DIR'))).code, 2);
});

test('wordpress: Bedrock environment files with no application.php are still read (a move there is UNKNOWN)', () => {
  const root = fresh('t85'), b = join(root, 'example.com');
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  put(join(b, 'config', 'environments', 'production.php'), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
  assert.equal(wp(root).code, 2);
});

test('wordpress: a Bedrock 1.0.0 config folder that cannot be entered is UNKNOWN, searched from the core itself', { skip: AS_ROOT && 'root enters any folder' }, () => {
  const root = bedrock100('t86', STOCK100); const conf = join(root, 'example.com', 'config'); lock(conf);
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(root, 'example.com', 'wp')]);
  assert.ok(unknowns(r).length, show(r)); assert.equal(r.code, 2);
});

// ---- the strict check of cd45cb7 ----------------------------------------------------------------------------------------
const envOnly = (name, mode, envFile = 'production.php') => {
  const root = fresh(name), b = join(root, 'example.com');
  put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  plugin(join(b, 'web', 'content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.12');
  put(join(b, 'config', 'environments', envFile), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
  if (mode !== undefined) { chmodSync(join(b, 'config', 'environments'), mode); locked.push(join(b, 'config', 'environments')); }
  return { root, wpDir: join(b, 'web', 'wp') };
};

test('wordpress: Bedrock environments/ that cannot be opened or listed, with no application.php, is UNKNOWN (searched from web/wp)', { skip: AS_ROOT && 'root lists any folder' }, () => {
  for (const mode of [0o000, 0o311]) {
    const e = envOnly(`t87-${mode}`, mode);
    const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', e.wpDir]);
    assert.equal(r.code, 2, `mode ${mode.toString(8)}: ${show(r)}`);
  }
});

test('wordpress: a move in an environment file named in capitals (production.PHP) is read too', () => {
  assert.equal(wp(envOnly('t88', undefined, 'production.PHP').root).code, 2);
});

test('wordpress: both content lines count as stock only exactly (a move before, after or inside either is UNKNOWN)', () => {
  const mv = "define('WP_PLUGIN_DIR', '/srv/p');";
  const l100 = "define('WP_CONTENT_DIR', $root_dir . CONTENT_DIR);";
  for (const [i, line] of [`${mv} ${l100}`, `${l100} ${mv}`, "define('WP_CONTENT_DIR', $root_dir . CONTENT_DIR . define('WP_PLUGIN_DIR', '/srv/p'));"].entries()) {
    assert.equal(wp(bedrock100(`t89a-${i}`, STOCK100.replace(l100, line))).code, 2, line);
  }
  const l11 = "Config::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR'));";
  for (const [i, line] of [`${mv} ${l11}`, `${l11} ${mv}`, "Config::define('WP_CONTENT_DIR', $webroot_dir . Config::get('CONTENT_DIR') . define('WP_PLUGIN_DIR', '/srv/p'));"].entries()) {
    const sb = bedrockSite(`t89b-${i}`, { app: `<?php\nConfig::define('CONTENT_DIR', '/app');\n${line}\n` });
    assert.equal(wp(sb.root).code, 2, line);
  }
});

test('wordpress: with both config folders (beside the web root and beside the core), a move in either one is UNKNOWN', () => {
  for (const [i, where] of ['webroot', 'core'].entries()) {
    const sb = bedrockSite(`t90-${i}`);
    const coreConf = join(sb.web, 'config', 'application.php');
    put(coreConf, "<?php\ndefine('CONTENT_DIR', '/app');\n");
    if (where === 'core') put(coreConf, "<?php\ndefine('CONTENT_DIR', '/content');\n");
    else put(join(dirname(sb.web), 'config', 'application.php'), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
    assert.equal(wp(sb.root).code, 2, where);
  }
});

// ---- the strict check of 53416ca (tests only) ---------------------------------------------------------------------------
test('wordpress: Bedrock environments/ or application.php linked into a folder that cannot be entered is UNKNOWN (searched from web/wp)', { skip: AS_ROOT && 'root enters any folder' }, () => {
  for (const [i, what] of ['environments', 'application.php'].entries()) {
    const root = fresh(`t91-${i}`), b = join(root, 'example.com'), conf = join(b, 'config');
    put(join(b, 'web', 'wp', 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
    plugin(join(b, 'web', 'app', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
    const parent = fresh(`t91-locked-${i}`);
    const target = what === 'environments' ? join(parent, 'environments') : join(parent, 'application.php');
    if (what === 'environments') put(join(target, 'production.php'), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
    else put(target, "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
    mkdirSync(conf, { recursive: true }); symlinkSync(target, join(conf, what)); lock(parent);
    const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(b, 'web', 'wp')]);
    assert.equal(r.code, 2, `${what}: ${show(r)}`);
  }
});

test('wordpress: an environments/ holding only production.php.bak is not Bedrock\'s PHP (clean twin)', () => {
  const root = fresh('t92'), r = join(root, 'site');
  put(join(r, 'config', 'environments', 'production.php.bak'), "<?php\nConfig::define('CONTENT_DIR', '/content');\n");
  const s = site(join(r, 'wp')); plugin(join(s, 'wp-content', 'plugins'), 'updraftplus', 'updraftplus.php', '1.26.13');
  const res = wp(root);
  assert.equal(unknowns(res).length, 0, show(res)); assert.equal(res.code, 0);
});
