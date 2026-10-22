// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The sixth strict review of 0.1.9 (ca530b7) reproduced these, or found a fix no test held; each test here failed on
// ca530b7 for the reason its name gives (or fails when its fix is reverted), and holds the fix in place. Offline: no test reaches a network host, and stand-ins replace every program a
// check would run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, existsSync, readFileSync } from 'node:fs';
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
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-review6-')); home = join(dir, 'home'); mkdirSync(home); });
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
  g('init', '-q');
  return { g, commit: () => { g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add'); } };
};
const AWS = `AKIA${'Q'.repeat(16)}`;
const keys = (root) => run(['--incident', 'committed-keys-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
const review = (r) => r.rows.filter((x) => x.status === 'REVIEW').map((x) => `${x.file}:${x.line}`);

test('1 a key on the cut of a giant one-line file is found (pieces overlap), once', () => {
  const root = fresh('k1-root'), repo = gitRepo(join(root, 'app'));
  const at = 8 * 1024 * 1024 - 10;   // 10 bytes before the cut at two 4 MB pieces
  put(join(root, 'app', 'data.json'), `${'x'.repeat(at)} "${AWS}" ${'y'.repeat(1024 * 1024)}`);
  repo.commit();
  assert.deepEqual(review(keys(root)), ['data.json:1']);
});

test('2 a placeholder word counts only next to the key: "example.com" elsewhere on a minified line hides nothing', () => {
  const stripe = `sk_live_${'A'.repeat(24)}`;
  assert.equal(scanText(`var u="https://docs.example.com/";${'x'.repeat(5000)};var k="${stripe}";`).length, 1, 'far placeholder');
  assert.equal(scanText(`const fakeTimers=1;${'x'.repeat(100)}const k="${AWS}"`).length, 1, 'fake far away');
  assert.equal(scanText('aws_access_key_id = AKIAIOSFODNN7EXAMPLE').length, 0, 'AWS\'s own documented example key');
  assert.equal(scanText(`key = "${AWS}" // a fake key for the docs`).length, 0, 'placeholder right next to it');
  assert.equal(scanText(`k = "${AWS}"  # gitleaks:allow`).length, 0, 'a reviewed-line marker on a normal line');
  assert.equal(scanText(`${'x'.repeat(3000)} gitleaks:allow ${'x'.repeat(3000)} "${AWS}"`).length, 1, 'a marker far away on a minified line');
});

test('3 a checked-out git submodule\'s files are scanned too', () => {
  const root = fresh('k3-root'), lib = gitRepo(join(dir, 'k3-lib'));
  put(join(dir, 'k3-lib', 'keys.py'), `k = "${AWS}"\n`); lib.commit();
  const app = gitRepo(join(root, 'app'));
  put(join(root, 'app', 'main.py'), 'print(1)\n');
  app.g('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', join(dir, 'k3-lib'), 'vendor/lib');
  app.commit();
  assert.deepEqual(review(keys(root)), ['vendor/lib/keys.py:1']);
});

test('4 a project folder named Library is searched, even with a Caches folder inside; macOS\'s own Library is not', async () => {
  const { isSystemFolder } = await import('../lib/files.mjs');
  const root = fresh('k4-root');
  const proj = gitRepo(join(root, 'Library')); put(join(root, 'Library', 'k.py'), `k = "${AWS}"\n`); put(join(root, 'Library', 'Caches', 'c.py'), `c = "${AWS.replace('Q', 'R')}"\n`); proj.commit();
  assert.deepEqual(review(keys(root)).sort(), ['Caches/c.py:1', 'k.py:1'], 'the project called Library, Caches folder and all');
  // a folder that only looks like macOS's (macOS's folders inside) but isn't where macOS keeps one is searched
  mkdirSync(join(fresh('k4-home'), 'Library', 'Preferences'), { recursive: true });
  assert.equal(isSystemFolder('Library', join(dir, 'k4-home')), false);
  assert.equal(isSystemFolder('.Trash', join(dir, 'k4-home')), true);
  if (process.platform === 'darwin') {
    assert.equal(isSystemFolder('Library', homedir()), true, 'this Mac\'s ~/Library');
    assert.equal(isSystemFolder('Library', '/'), true, '/Library');
  }
});

test('5 a trust probe gets CURL_SSL_BACKEND, which picks macOS curl\'s trust store', () => {
  assert.equal(envFor('probe', {}, { PATH: '/bin', CURL_SSL_BACKEND: 'secure-transport' }).CURL_SSL_BACKEND, 'secure-transport');
});

test('6 pieces end at line breaks, keep line numbers, and nothing is lost at the end of a file without a final newline', () => {
  const f = put(join(dir, 'p6.txt'), Array.from({ length: 400 }, (_, i) => `line ${i + 1} ${'z'.repeat(i % 37)}`).join('\n') + `\nlast ${AWS}`);
  const pieces = [];
  assert.equal(eachPiece(f, 1e9, (text, first) => pieces.push({ text, first }), 256, 32), true);
  for (const p of pieces.slice(0, -1)) assert.ok(p.text.endsWith('\n'), `a piece ends mid-line: ${JSON.stringify(p.text.slice(-20))}`);
  for (const p of pieces) assert.ok(p.text.startsWith(`line ${p.first} `) || p.text.startsWith('last '), `line number ${p.first} for ${JSON.stringify(p.text.slice(0, 20))}`);
  assert.ok(pieces.at(-1).text.includes(AWS), 'the last line, after the final break, is passed');
});

test('7 a container whose tool can\'t reach the self-signed site is UNKNOWN: it can\'t be shown to check certificates', () => {
  const body = 'case "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; https://self-signed*) exit 28;; *) exit 60;; esac';
  const r = run(['--incident', 'emudhra-2026-10', '--paths', fresh('k7-root')], { PATH: engine('k7', { curlBody: body }) }, ['--require', preload('k7-online', { online: true })]);
  assert.deepEqual(r.rows.filter((x) => x.kind === 'container').map((x) => x.status), ['UNKNOWN'], JSON.stringify(r.rows.filter((x) => x.kind === 'container')));
});

test('8 a folder that can be entered but not listed (mode 0311) is reported, never "0 repositories", SAFE', { skip: AS_ROOT && 'root lists every folder' }, () => {
  const root = fresh('k8-root'), shut = fresh('k8-root/shut');
  chmodSync(shut, 0o311); locked.push(shut);
  const r = run(['--incident', 'github-actions-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === shut), JSON.stringify(r.rows));
  assert.ok(!r.rows.some((x) => x.status === 'SAFE'));
});

test('9 on macOS, a folder that can\'t be opened says what can help: sudo for another user\'s, Full Disk Access for a protected one', { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS, not root' }, () => {
  const root = fresh('k9-root'), shut = fresh('k9-root/shut'); lock(shut);
  const r = run(['--incident', 'github-actions-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
  assert.match(r.rows.find((x) => x.path === shut)?.reason ?? '', /Full Disk Access/);
});

// ---- from the final check (7e12f17) ------------------------------------------------------------------------------------
// scanText over every piece of `text`, cut by eachPiece with small pieces, as lib/secrets.mjs does for a large file
// (with half the overlap longer than any key, as in use: 4 KB pieces' 4,096-byte overlap; here 512 and 256)
const pieceScan = (name, text, piece = 512, overlap = 256) => {
  const f = put(join(dir, name), text), hits = [];
  eachPiece(f, 1e9, (t, first, range) => { for (const h of scanText(t, range)) hits.push({ ...h, line: h.line + first - 1 }); }, piece, overlap);
  return hits;
};

test('10 every match belongs to exactly one piece: no key twice, no part of a token as a key, no placeholder lost at a cut', () => {
  const ghp = `ghp_${'a1B2'.repeat(15)}`;   // 64 characters
  for (let at = 860; at < 1180; at += 7) {   // a one-line text cut at 1,024 bytes; the key at every offset around the cut
    const text = `${'x'.repeat(at)} ${AWS} ${'y'.repeat(2000 - at)}`;
    assert.equal(pieceScan(`p10a-${at}.txt`, text).length, 1, `the key at ${at}: found exactly once`);
    const g = pieceScan(`p10b-${at}.txt`, `${'x'.repeat(at)} ${ghp} ${'y'.repeat(2000 - at)}`);
    assert.deepEqual(g.map((h) => h.masked), [`ghp_…(64 chars)`], `the token at ${at}: once, whole`);
    assert.equal(pieceScan(`p10c-${at}.txt`, `${'x'.repeat(at)} ${AWS} EXAMPLE ${'y'.repeat(2000 - at)}`).length, 0, `a placeholder right after the key at ${at} still counts`);
  }
  // 34 letters starting with AKIA is no key wherever a cut falls
  for (let at = 860; at < 1180; at += 11) assert.equal(pieceScan(`p10d-${at}.txt`, `${'x'.repeat(at)}AKIA${'Z'.repeat(30)}${'y'.repeat(2000 - at)}`).length, 0, `at ${at}`);
});

test('11 a key inside the overlap of a 12 MB one-line file is reported once (the command, end to end)', () => {
  const root = fresh('k11-root'), repo = gitRepo(join(root, 'app'));
  put(join(root, 'app', 'data.json'), `${'x'.repeat(8 * 1024 * 1024 - 2000)} "${AWS}" ${'y'.repeat(4 * 1024 * 1024)}`);
  repo.commit();
  assert.deepEqual(review(keys(root)), ['data.json:1']);
});

test('12 a reviewed-line marker anywhere on a line of up to 2,000 characters counts, however far from the key', () => {
  assert.equal(scanText(`k = "${AWS}"; ${'x'.repeat(1200)} // gitleaks:allow`).length, 0);
  assert.equal(scanText(`k = "${AWS}"; ${'x'.repeat(2500)} // gitleaks:allow`).length, 1, 'on a longer line only near the key');
});

test('13 a repository inside another one is scanned too: a gitignored checkout, and an embedded repository; a submodule only once', () => {
  const root = fresh('k13-root'), outer = gitRepo(join(root, 'outer'));
  put(join(root, 'outer', '.gitignore'), 'tools/\n'); put(join(root, 'outer', 'a.py'), 'print(1)\n'); outer.commit();
  const inner = gitRepo(join(root, 'outer', 'tools', 'inner')); put(join(root, 'outer', 'tools', 'inner', 'k.py'), `k = "${AWS}"\n`); inner.commit();
  const r = keys(root);
  assert.deepEqual(r.rows.filter((x) => x.status === 'REVIEW').map((x) => `${x.repo.slice(root.length + 1)}/${x.file}`), ['outer/tools/inner/k.py']);
  // a submodule: found through the outer repository's scan, and not again as a repository of its own
  const lib = gitRepo(join(dir, 'k13-lib')); put(join(dir, 'k13-lib', 's.py'), `s = "${AWS.replace('Q', 'S')}"\n`); lib.commit();
  outer.g('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', join(dir, 'k13-lib'), 'vendor/lib'); outer.commit();
  const r2 = keys(root);
  assert.deepEqual(r2.rows.filter((x) => x.status === 'REVIEW').map((x) => `${x.repo.slice(root.length + 1)}/${x.file}`).sort(), ['outer/tools/inner/k.py', 'outer/vendor/lib/s.py']);
});
