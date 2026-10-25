// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Gaps a mutation-testing run of 0.1.9 (b03e7be) found: behaviour the code has right, and no test held. Each test pins
// one or more of those behaviours, and fails when the one-line change its comment names is made. Offline: no test
// reaches a network host, stand-ins replace every program a check would run, and the machine's own files (system folders,
// the real home folder) are hidden or replaced by a made-up home folder.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, symlinkSync, utimesSync, statSync, existsSync, readFileSync } from 'node:fs';
import os, { tmpdir } from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseGitConfig, identityFrom, carries, headersInJson, headersInRc, headersInToml, stripJsonc, places, scanHeaders } from '../lib/headers.mjs';
import { listContainers, checkContainer } from '../lib/containers.mjs';
import { check } from '../lib/probe.mjs';
import { droppedNodeOptions } from '../lib/run.mjs';
import { checkBinaryAll, copiesToRun, goToolchain, judgeVersion } from '../lib/binaries.mjs';
import { readCapped, eachPiece, isNativeProgram } from '../lib/files.mjs';
import { scanText } from '../lib/secrets.mjs';
import { sitePackagesDirs, checkSitePackages } from '../lib/installs.mjs';
import { reposUnder } from '../lib/workflows.mjs';
import { wordpressUnder, checkSite } from '../lib/wordpress.mjs';
import { accounts, subuidRanges } from '../lib/owners.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const LIB_URL = pathToFileURL(join(ROOT, 'lib')).href;
const AS_ROOT = process.getuid?.() === 0;
const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-gaps-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body, shell = '/bin/sh') => put(p, `#!${shell}\n${body}\n`, 0o755);
const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };
const AWS = ['AKIA', 'Q'.repeat(16)].join('');

// process.env for the length of fn (a key set to undefined is removed), for the library calls that read it
const withEnv = async (vars, fn) => {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  const set = (o) => { for (const [k, v] of Object.entries(o)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } };
  set(vars);
  try { return await fn(); } finally { set(saved); }
};
// os.platform() for the length of fn, for the library calls that read it
const withPlatform = (p, fn) => {
  const o = os.platform;
  os.platform = () => p; syncBuiltinESMExports();
  try { return fn(); } finally { os.platform = o; syncBuiltinESMExports(); }
};
const NO_ENGINE_VARS = { DOCKER_HOST: undefined, CONTAINER_HOST: undefined, DOCKER_CONTEXT: undefined, DOCKER_CONFIG: undefined, CONTAINER_CONNECTION: undefined };

// A stand-in loaded into a child Node: the machine's system folders hidden (this test's folder and the code excepted),
// `map` paths rewritten into this test's folder (a /Users/<name> home, macOS's nscurl, a Linux CA bundle), no real
// connection, no program run outside this test's folder, and the platform and user id it is told to report.
const preload = (name, { platform, uid, map = {}, onExit = '' } = {}) => {
  const p = join(dir, `${name}.cjs`);
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), os = require('node:os'), { EventEmitter } = require('node:events');
const DIR = ${JSON.stringify(dir)}, ROOT = ${JSON.stringify(ROOT)}, MAP = ${JSON.stringify(map)};
const SYS = /^\\/(?:usr|etc|opt|bin|sbin|System|Library|Applications|var|private|tmp|home|srv|snap|nix)(?:\\/|$)/;
const mine = (p) => p === DIR || p.startsWith(DIR + '/') || p.startsWith(ROOT + '/');
const where = (p) => { if (typeof p !== 'string') return p; for (const [k, v] of Object.entries(MAP)) if (p === k || p.startsWith(k + '/')) return v + p.slice(k.length); return p; };
const hidden = (p) => typeof p === 'string' && SYS.test(p) && !mine(p);
const ex = fs.existsSync; fs.existsSync = (p) => { const q = where(p); return !hidden(q) && ex(q); };
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) { const o = fs[k]; fs[k] = (p, ...a) => { const q = where(p); if (hidden(q)) throw Object.assign(new Error('hidden by the test'), { code: 'ENOENT' }); return o(q, ...a); }; }
tls.connect = (...a) => { const cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s; process.nextTick(() => s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
${platform ? `os.platform = () => ${JSON.stringify(platform)}; Object.defineProperty(process, 'platform', { value: ${JSON.stringify(platform)} });` : ''}
${uid !== undefined ? `process.getuid = () => ${uid};` : ''}
${onExit ? `process.on('exit', () => { ${onExit} });` : ''}
require('node:module').syncBuiltinESMExports();
`);
  return p;
};
const childEnv = (env) => ({ HOME: home, PATH: fresh('empty-path'), LANG: 'C', TMPDIR: fresh('empty-tmp'), ...env });
// the command, with --json; `pre`: the stand-in's options (none: no stand-in, for the checks that run the real git)
const run = (args, env = {}, pre) => {
  const nodeArgs = pre ? ['--require', preload(pre.name, pre)] : [];
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args, '--json'], { encoding: 'utf8', env: childEnv(env), cwd: dir, timeout: 120000, killSignal: 'SIGKILL' });
  let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 500)}`); }
  return { code: r.status, rows };
};
// library code run in a child Node behind the stand-in; it prints one JSON value. `L` is the lib folder's URL.
const lib = (name, code, pre = {}) => {
  const r = spawnSync(process.execPath, ['--require', preload(name, pre), '--input-type=module', '-e', `const L = ${JSON.stringify(LIB_URL)};\n${code}`], { encoding: 'utf8', env: childEnv(pre.env), cwd: dir, timeout: 60000, killSignal: 'SIGKILL' });
  try { return JSON.parse(r.stdout); } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 500)}`); }
};
// a virtual environment: pyvenv.cfg, a bin/python that is never run, and (with `certifi`) a certifi bundle
const venv = (p, { certifi = true } = {}) => {
  put(join(p, 'pyvenv.cfg'), 'home = /usr/bin\n'); exe(join(p, 'bin', 'python'), 'exit 1');
  const sp = join(p, 'lib', 'python3.12', 'site-packages'); mkdirSync(sp, { recursive: true });
  if (certifi) put(join(sp, 'certifi', 'cacert.pem'), '-----BEGIN CERTIFICATE-----\n');
  return sp;
};
const gitRepo = (path) => {
  mkdirSync(path, { recursive: true });
  const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' };
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env });
  g('init', '-q');
  return { g, commit: () => { g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add'); } };
};

// ---- containers --------------------------------------------------------------------------------------------------------
// a docker stand-in whose `exec` runs the probe script in a box holding only `tool`, which answers as `body` says
const containerEngine = (name, tool, body) => {
  const box = fresh(`${name}-box`), eng = fresh(`${name}-engine`);
  exe(join(box, tool), body);
  exe(join(eng, 'docker'), `if [ "$1" = exec ]; then shift 3; PATH=${JSON.stringify(box)} exec /bin/sh "$@"; fi\nexit 0`);
  return eng;
};
const CANARY = [{ id: 'c1', up: true, url: 'https://canary1.test/', root: 'R', host: 'canary1.test' }];
const inContainer = (eng) => withEnv({ PATH: eng, ...NO_ENGINE_VARS }, () => checkContainer('docker', { id: 'x', name: 'web', image: 'debian:13' }, CANARY, { controlUrl: 'https://advisory.test/', timeoutMs: 3000 }));

test('a container whose normal-site control is refused is UNKNOWN, even when every later site is refused too', async () => {
  // lib/containers.mjs:113 (the control's own refusal returns UNKNOWN)
  const r = await inContainer(containerEngine('ct113', 'curl', 'exit 60'));
  assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /control failed: this container could not open a normal site/); assert.equal(r.tool, 'curl');
});

test('a python3-only or wget-only container reads its tool\'s answers: control ok, certificates refused, SAFE', async () => {
  // lib/containers.mjs:35 and :36 (python3's and wget's "ok" lines in the in-container probe)
  const py = await inContainer(containerEngine('ct35', 'python3', 'for a in "$@"; do case "$a" in https://*) u="$a";; esac; done\ncase "$u" in *self-signed*) exit 10;; *advisory*) exit 0;; *) exit 10;; esac'));
  assert.equal(py.status, 'SAFE', JSON.stringify(py)); assert.equal(py.tool, 'python3');
  const wg = await inContainer(containerEngine('ct36', 'wget', 'case "$6" in *self-signed*) exit 5;; *advisory*) exit 0;; *) exit 5;; esac'));
  assert.equal(wg.status, 'SAFE', JSON.stringify(wg)); assert.equal(wg.tool, 'wget');
});

test('podman saying "permission denied" is an error to report, even beside "Cannot connect to Podman"', async () => {
  // lib/containers.mjs:77 (permission denied is checked before the not-running message)
  const eng = fresh('ct77-engine');
  exe(join(eng, 'podman'), `echo "Cannot connect to Podman. Please verify your connection to the Linux system" >&2
echo 'Error: unable to connect to Podman socket: dial unix /run/user/1000/podman/podman.sock: connect: permission denied' >&2
exit 125`);
  const r = await withEnv({ PATH: eng, ...NO_ENGINE_VARS }, () => listContainers('podman'));
  assert.match(r?.error ?? '', /^permission denied/, JSON.stringify(r));
});

test('a container engine that can\'t be started at all (ENOENT) is "not running", not an error', async () => {
  // lib/containers.mjs:76 (ENOENT returns null)
  const eng = fresh('ct76-engine');
  put(join(eng, 'docker'), '#!/nonexistent/interpreter\n', 0o755);
  assert.equal(await withEnv({ PATH: eng, ...NO_ENGINE_VARS }, () => listContainers('docker')), null);
});

// ---- the trust probe ---------------------------------------------------------------------------------------------------
const probeCanaries = () => {
  const d = fresh('probe-pems');
  const pem = (n) => put(join(d, `${n}.pem`), `-----BEGIN CERTIFICATE-----\n${n}\n-----END CERTIFICATE-----\n`);
  return [
    { id: 'a1', up: true, url: 'https://canary-a1.test/', host: 'canary-a1.test', root: 'A', pem: pem('A') },
    { id: 'b1', up: true, url: 'https://canary-b1.test/', host: 'canary-b1.test', root: 'B', pem: pem('B') },
  ];
};

test('the forced-roots control must pass for every root: root A connecting and root B refused is UNKNOWN', async () => {
  // lib/probe.mjs:135 (any forced result that is neither ok nor blocked fails the control)
  const curl = exe(join(fresh('pr127'), 'curl'), 'case "$*" in *B.pem*) exit 60;; *A.pem*) exit 0;; *) exit 60;; esac');
  const r = await check({ kind: 'curl', bin: curl }, probeCanaries(), { controlUrl: 'https://advisory.test/', timeoutMs: 2000 });
  assert.equal(r.status, 'UNKNOWN', JSON.stringify(r)); assert.match(r.reason, /positive control failed/);
});

test('Node blocking the compromised keys (CERT_REVOKED) but unable to open a normal site is UNKNOWN, not SAFE', async () => {
  // lib/probe.mjs:140 (a blocked control still needs the normal site to open)
  const node = exe(join(fresh('pr132'), 'node'), 'case "$3" in *canary*) exit 4;; *) exit 3;; esac');
  const r = await check({ kind: 'node', bin: node }, probeCanaries(), { controlUrl: 'https://advisory.test/', timeoutMs: 2000 });
  assert.equal(r.status, 'UNKNOWN', JSON.stringify(r)); assert.match(r.reason, /could not open a normal site either/);
});

// ---- identity headers --------------------------------------------------------------------------------------------------
test('git config: user.signingkey doesn\'t replace the email, http.cookiefile is no header, a key with no value doesn\'t crash', () => {
  // lib/headers.mjs:34 (a line that isn't key = value is skipped), :37 (only user.email is the email), :38 (only
  // http.extraHeader and http.userAgent are headers)
  const g = parseGitConfig('[user]\n\tname = Ada Lovelace\n\temail = ada@example.org\n\tsigningkey = ABCDEF0123456789\n[http]\n\tcookiefile = /Users/ada/.cookies\n\tsslVerify\n');
  assert.deepEqual(g, { name: 'Ada Lovelace', email: 'ada@example.org', headers: [] });
});

test('who you are: GIT_AUTHOR_NAME alone gives the name', () => {
  // lib/headers.mjs:53 (either name variable is enough)
  assert.deepEqual(identityFrom(fresh('id53-home'), { GIT_AUTHOR_NAME: 'Ada Lovelace' }), { name: 'Ada Lovelace', email: '' });
});

test('a name of exactly six letters counts, as does an email user name of exactly six; five is too short', () => {
  // lib/headers.mjs:68 (six characters, or a space, make a name long enough) and :73 (six for the email's user name)
  assert.equal(carries('X-By: Hopper', { name: 'Hopper', email: '' }), 'your name');
  assert.equal(carries('X-By: Hoppe', { name: 'Hoppe', email: '' }), null);
  assert.equal(carries('X-By: hopper', { name: '', email: 'hopper@example.org' }), 'your email\'s user name');
  assert.equal(carries('X-By: hoppe', { name: '', email: 'hoppe@example.org' }), null);
});

test('JSON: objects and strings inside arrays are walked, null is skipped, numbers in arrays don\'t count toward the cap, which allows exactly 200,000 items', () => {
  // lib/headers.mjs:110 (the item cap is "more than"), :119 (null and other non-objects are skipped), :125 and :126 (only
  // objects and strings inside arrays are walked)
  assert.deepEqual(headersInJson({ servers: [{ headers: { 'X-Who': 'ada' } }] }), [{ where: 'servers.0.headers.X-Who', value: 'ada' }]);
  assert.deepEqual(headersInJson({ headers: ['X-Who: ada'] }), [{ where: 'headers.0', value: 'X-Who: ada' }]);
  assert.deepEqual(headersInJson({ x: null, list: [null], headers: { X: 'v' } }), [{ where: 'headers.X', value: 'v' }]);
  let deep = 'x'; for (let i = 0; i < 70; i++) deep = [deep];
  assert.throws(() => headersInJson({ a: deep }), RangeError, 'nesting inside arrays is capped too');
  assert.deepEqual(headersInJson({ data: Array(200001).fill(1), headers: { X: 'v' } }), [{ where: 'headers.X', value: 'v' }]);
  assert.equal(headersInJson({ headers: Array(199999).fill('h') }).length, 199999, '200,000 items are read through');
  assert.throws(() => headersInJson({ headers: Array(200000).fill('h') }), RangeError, '200,001 are not');
});

test('JSONC: a lone slash is not the start of a comment, so malformed JSON stays malformed', () => {
  // lib/headers.mjs:90 (a block comment starts only at "/*")
  const text = '{"headers": {"X": "ada@example.org"}} / junk */';
  assert.equal(stripJsonc(text), text);
  assert.throws(() => JSON.parse(stripJsonc(text)), SyntaxError);
});

test('curl\'s cacert line and a commented TOML header line are not headers', () => {
  // lib/headers.mjs:153 (a bare option counts only when it is header or user-agent) and :170 (TOML comments are skipped)
  assert.deepEqual(headersInRc('cacert = /Users/ada.lovelace/ca.pem\n', 'curl'), []);
  assert.deepEqual(headersInToml('# X-Header = "ada@example.org"\n[mcp_servers.x]\n'), []);
});

test('the agents\' app-data folder: Application Support on macOS, APPDATA on Windows, XDG_CONFIG_HOME elsewhere', () => {
  // lib/headers.mjs:197 (the app-data folder by platform, and APPDATA first on Windows)
  const desktop = (p, env) => withPlatform(p, () => places(home, env).map((x) => x.file).filter((f) => f.endsWith('claude_desktop_config.json')));
  assert.deepEqual(desktop('darwin', {}), [join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')]);
  assert.deepEqual(desktop('win32', { APPDATA: '/appdata' }), [join('/appdata', 'Claude', 'claude_desktop_config.json')]);
  assert.deepEqual(desktop('linux', { XDG_CONFIG_HOME: '/xdg' }), [join('/xdg', 'Claude', 'claude_desktop_config.json')]);
});

test('the scan reads a repository\'s .mcp.json and Codex\'s config as TOML; an .npmrc email line is no header', () => {
  // lib/headers.mjs:216 (each repository's settings files are listed), :228 (TOML is read as TOML) and :182 (only the
  // .npmrc user-agent line is a header)
  const h = fresh('hs-home'), root = fresh('hs-root');
  put(join(h, '.codex', 'config.toml'), '[mcp_servers.docs.http_headers]\nX-User = "ada@example.org"\n');
  put(join(h, '.npmrc'), 'email=ada@example.org\n');
  mkdirSync(join(root, 'app', '.git'), { recursive: true });
  put(join(root, 'app', '.mcp.json'), JSON.stringify({ mcpServers: { x: { headers: { From: 'ada@example.org' } } } }));
  const r = scanHeaders({ home: h, env: {}, roots: [root] });
  assert.deepEqual(r.unread, []);
  assert.deepEqual(r.findings.map((f) => `${f.status} ${f.file}`).sort(), [`REVIEW ${join(h, '.codex', 'config.toml')}`, `REVIEW ${join(root, 'app', '.mcp.json')}`]);
});

test('a FIFO .curlrc and an oversize repository .mcp.json are reported unread, not skipped', () => {
  // lib/headers.mjs:251 (only /dev/null is read as empty) and :253 (only an unreadable regular file is "not used")
  const h = fresh('hf-home'), root = fresh('hf-root');
  execFileSync('mkfifo', [join(h, '.curlrc')]);
  mkdirSync(join(root, 'app', '.git'), { recursive: true });
  put(join(root, 'app', '.mcp.json'), JSON.stringify({ pad: 'x'.repeat(1100 * 1024) }));
  const r = scanHeaders({ home: h, env: {}, roots: [root] });
  assert.deepEqual(r.unread.map((u) => u.file).sort(), [join(h, '.curlrc'), join(root, 'app', '.mcp.json')].sort());
  assert.deepEqual(r.notUsed, []);
});

// ---- the probes' environment -------------------------------------------------------------------------------------------
test('droppedNodeOptions: nothing when NODE_OPTIONS is unset, and a trust flag is never counted as dropped', () => {
  // lib/run.mjs:56 (empty words and trust flags are not "dropped")
  assert.deepEqual(droppedNodeOptions({}), []);
  assert.deepEqual(droppedNodeOptions({ NODE_OPTIONS: '--use-openssl-ca' }), []);
  assert.deepEqual(droppedNodeOptions({ NODE_OPTIONS: '--use-openssl-ca --require mac-ca' }), ['--require', 'mac-ca']);
});

// ---- the command -------------------------------------------------------------------------------------------------------
test('on Windows the installs check says it was not checked: UNKNOWN, exit 2', () => {
  // bin/wardlatch.mjs:239 (the Windows row is kept)
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('w239-root')], {}, { name: 'w239', platform: 'win32' });
  assert.deepEqual(r.rows.map((x) => [x.kind, x.status, x.reason]), [['install', 'UNKNOWN', 'not checked on Windows yet (Windows is not supported)']]);
  assert.equal(r.code, 2);
});

test('a --paths folder below a locked one is UNKNOWN in the LiteLLM check, beside a folder that was searched', { skip: AS_ROOT && 'root opens every folder' }, () => {
  // bin/wardlatch.mjs:378 (the --paths folders that can't be opened go to the gaps)
  const shut = fresh('l378-locked'), inner = join(shut, 'inner'); lock(shut);
  const r = run(['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('l378-ok'), '--paths', inner], {}, { name: 'l378' });
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.path === inner), JSON.stringify(r.rows));
  assert.equal(r.code, 2);
});

// a docker stand-in for the local-images check: `images` prints `images`; every call leaves a mark
const imageEngine = (name, { images = '', fail = '' } = {}) => {
  const eng = fresh(`${name}-engine`), mark = join(dir, `${name}-engine-called`);
  exe(join(eng, 'docker'), `touch ${JSON.stringify(mark)}\n${fail ? `echo ${JSON.stringify(fail)} >&2; exit 1` : `[ "$1" = images ] && printf '%s\\n' ${images.split('\n').map((l) => JSON.stringify(l)).join(' ')}\nexit 0`}`);
  return { eng, mark };
};

test('a local LiteLLM image with a compromised digest is EXPOSED, with no all-clear beside it', () => {
  // bin/wardlatch.mjs:396 (only a null list means "not running") and :406 (no all-clear beside a finding)
  const { eng } = imageEngine('i396', { images: 'python:3.12@sha256:0000\nghcr.io/berriai/litellm:main-stable@sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e' });
  const r = run(['--incident', 'litellm-2026-10', '--paths', fresh('i396-root')], { PATH: eng }, { name: 'i396' });
  assert.deepEqual(r.rows.map((x) => [x.status, x.engine]), [['EXPOSED', 'docker']], JSON.stringify(r.rows));
  assert.equal(r.code, 1);
});

test('--no-containers, and incidents without image digests, never ask the container engine', () => {
  // bin/wardlatch.mjs:391 (images are listed only for an incident with digests, and not with --no-containers)
  const { eng, mark } = imageEngine('e391', { fail: 'permission denied while trying to connect to the Docker daemon socket' });
  for (const args of [['--incident', 'litellm-2026-10', '--no-containers'], ['--incident', 'plex-2026-10'], ['--incident', 'gitlab-2026-10']]) {
    const r = run([...args, '--paths', fresh('e391-root')], { PATH: eng }, { name: 'e391' });
    assert.equal(existsSync(mark), false, `${args.join(' ')}: the engine was asked`);
    assert.deepEqual(r.rows.map((x) => x.status), ['SAFE'], `${args.join(' ')}: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 0);
  }
});

test('Plex and GitLab with an existing --paths folder are SAFE, with a receipt naming where they looked', () => {
  // bin/wardlatch.mjs:373 (the version files' places go into the receipt)
  for (const id of ['plex-2026-10', 'gitlab-2026-10']) {
    const r = run(['--incident', id, '--paths', fresh('v373-root')], {}, { name: 'v373' });
    assert.deepEqual(r.rows.map((x) => [x.status, x.searched]), [['SAFE', [incident(id).versionFiles.lookedIn]]], id);
    assert.equal(r.code, 0, id);
  }
});

test('as root: no SUDO_USER runs normally, and SUDO_USER=.. is never taken as a home folder', () => {
  // bin/wardlatch.mjs:95 (a missing SUDO_USER is not looked up) and :97 (a name with .. is refused)
  const args = ['--incident', 'identity-headers-2026-10', '--paths', fresh('s95-root')];
  const plain = run(args, {}, { name: 's95', uid: 0 });
  assert.deepEqual(plain.rows.filter((x) => x.kind === 'home'), []); assert.equal(plain.code, 0);
  const dots = run(args, { SUDO_USER: '..' }, { name: 's95', uid: 0 });
  assert.match(dots.rows.find((x) => x.kind === 'home')?.reason ?? '', /^run under sudo by \.\., whose home folder was not found/, JSON.stringify(dots.rows));
  assert.equal(dots.code, 2);
});

test('under sudo, the person\'s home is /Users/<name> on macOS and /home/<name> on Linux, and it is the one searched', () => {
  // bin/wardlatch.mjs:97 (the home folder's place by platform) and :98 (a home that is there is used)
  for (const [platform, place] of [['darwin', '/Users/wl-gaps-sudo'], ['linux', '/home/wl-gaps-sudo']]) {
    const theirs = fresh(`s97-${platform}`);
    put(join(theirs, '.gitconfig'), '[http]\n\textraHeader = From: someone@example.org\n');
    const r = run(['--incident', 'identity-headers-2026-10', '--paths', fresh('s97-root')], { SUDO_USER: 'wl-gaps-sudo' }, { name: `s97-${platform}`, uid: 0, platform, map: { [place]: theirs } });
    assert.deepEqual(r.rows.filter((x) => x.kind === 'home'), [], platform);
    assert.deepEqual(r.rows.filter((x) => x.kind === 'header').map((x) => [x.status, x.file]), [['EXPOSED', `${place}/.gitconfig`]], `${platform}: ${JSON.stringify(r.rows)}`);
  }
});

test('every SSL_CERT_DIR entry is made absolute, against the folder Wardlatch started in', () => {
  // bin/wardlatch.mjs:40 (SSL_CERT_DIR is split into folders first)
  const out = join(dir, 'ssl-cert-dir.txt');
  const pre = preload('s40', { onExit: `fs.writeFileSync(${JSON.stringify(out)}, String(process.env.SSL_CERT_DIR))` });
  const r = spawnSync(process.execPath, ['--require', pre, BIN, '--list'], { encoding: 'utf8', env: childEnv({ SSL_CERT_DIR: 'certs-a:certs-b' }), cwd: dir, timeout: 60000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readFileSync(out, 'utf8'), `${join(dir, 'certs-a')}:${join(dir, 'certs-b')}`);
});

test('a folder where a tracked file was is not a gap: SAFE, exit 0', () => {
  // lib/secrets.mjs:83 (a tracked path that is now a folder is skipped)
  const root = fresh('k83-root'), app = join(root, 'app'), repo = gitRepo(app);
  put(join(app, 'app.py'), 'print(1)\n'); put(join(app, 'notes.txt'), 'hello\n'); repo.commit();
  rmSync(join(app, 'notes.txt')); mkdirSync(join(app, 'notes.txt'));
  const r = run(['--incident', 'committed-keys-2026-10', '--paths', root], { PATH: '/usr/bin:/bin' });
  assert.deepEqual(r.rows.map((x) => x.status), ['SAFE'], JSON.stringify(r.rows));
  assert.equal(r.code, 0);
});

// ---- discovery of runtimes ---------------------------------------------------------------------------------------------
const curlDir = () => { const d = fresh('disc-curl'); exe(join(d, 'curl'), 'echo "curl 8.0.0"'); return d; };
// the virtual environments discover() found under `roots`, tested (env rows) or not (untested)
const discovered = (name, roots) => lib(name, `const { discover } = await import(L + '/discover.mjs');
const untested = [];
const out = discover({ roots: ${JSON.stringify(roots)}, pathEnv: ${JSON.stringify(curlDir())}, untested });
console.log(JSON.stringify({ envs: out.filter((r) => r.env).map((r) => r.env).sort(), untested: untested.map((u) => u.env) }));`);

test('a virtual environment without certifi gives no row; one with certifi does', () => {
  // lib/discover.mjs:28 (no certifi bundle, no row)
  const root = fresh('d28-root');
  venv(join(root, 'plain', '.venv'), { certifi: false }); venv(join(root, 'withca', '.venv'));
  assert.deepEqual(discovered('d28', [root]), { envs: [join(root, 'withca', '.venv')], untested: [] });
});

test('discovery doesn\'t follow links or go into node_modules', () => {
  // lib/discover.mjs:79 (links, node_modules, .git and macOS's own folders are skipped)
  const root = fresh('d79-root'), elsewhere = fresh('d79-elsewhere');
  venv(join(root, 'node_modules', 'pkg', '.venv')); venv(join(elsewhere, 'venv')); symlinkSync(join(elsewhere, 'venv'), join(root, 'linked'));
  venv(join(root, 'proj', '.venv'));
  assert.deepEqual(discovered('d79', [root]), { envs: [join(root, 'proj', '.venv')], untested: [] });
});

test('the search depths: a virtual environment six folders down, a repository four down, a site five down', () => {
  // lib/discover.mjs:75, lib/workflows.mjs:16 and lib/wordpress.mjs:16 (each walk lists the folder at depth 0)
  const v = fresh('d75-root');
  venv(join(v, '1', '2', '3', '4', '5', 'v6')); venv(join(v, '1', '2', '3', '4', '5', '6', 'v7'));
  assert.deepEqual(discovered('d75', [v]), { envs: [join(v, '1', '2', '3', '4', '5', 'v6')], untested: [] });
  const g = fresh('w16-root');
  mkdirSync(join(g, '1', '2', '3', '4', '.git'), { recursive: true }); mkdirSync(join(g, '1', '2', '3', 'x', '5', '.git'), { recursive: true });
  assert.deepEqual(reposUnder([g], 4), [join(g, '1', '2', '3', '4')]);
  const w = fresh('wp16-root');
  const site = (p) => { put(join(p, 'wp-includes', 'version.php'), '<?php\n'); mkdirSync(join(p, 'wp-content'), { recursive: true }); };
  site(join(w, '1', '2', '3', '4', '5')); site(join(w, '1', '2', '3', '4', 'x', '6'));
  assert.deepEqual(wordpressUnder([w], 5), [join(w, '1', '2', '3', '4', '5')]);
});

test('the OS\'s own trust: the macOS system row, and the Linux store row only with a bundle and a curl', () => {
  // lib/discover.mjs:66 to :72 (the macos-system row on macOS; the Linux bundle, curl and row)
  const nscurl = exe(join(fresh('os-nscurl'), 'nscurl'), 'exit 0'), bundle = put(join(fresh('os-bundle'), 'ca.crt'), '-----BEGIN CERTIFICATE-----\n');
  const map = { '/usr/bin/nscurl': nscurl, '/etc/ssl/certs/ca-certificates.crt': bundle };
  const system = (name, platform, pathEnv) => lib(name, `const { discover } = await import(L + '/discover.mjs');
console.log(JSON.stringify(discover({ roots: [], pathEnv: ${JSON.stringify(pathEnv)} }).filter((r) => r.kind === 'macos-system' || r.system).map((r) => [r.kind, r.bin ?? null, r.args ?? null])));`, { platform, map: platform === 'darwin' ? { '/usr/bin/nscurl': nscurl } : map });
  assert.deepEqual(system('os-mac', 'darwin', ''), [['macos-system', '/usr/bin/nscurl', null]]);
  const curl = curlDir();
  assert.deepEqual(system('os-linux', 'linux', curl), [['curl', join(curl, 'curl'), ['--cacert', '/etc/ssl/certs/ca-certificates.crt']]]);
  assert.deepEqual(system('os-linux', 'linux', fresh('os-no-curl')), [], 'no curl, no row');
});

// ---- program checks ----------------------------------------------------------------------------------------------------
test('GOTOOLCHAIN matters only to the go rule', async () => {
  // lib/binaries.mjs:189 (a rule for any other program returns its own verdict)
  const d = fresh('b189');
  exe(join(d, 'cloudflared'), 'echo "cloudflared version 2026.10.5 (built x)"'); exe(join(d, 'go'), 'echo "go version go1.27.3 linux/amd64"');
  const [cloudflared, go] = incident('emudhra-2026-10').binaries;
  await withEnv({ GOTOOLCHAIN: 'go1.20.0', HOME: home }, () => {
    assert.deepEqual(checkBinaryAll(cloudflared, d).map((x) => x.status), ['SAFE']);
    assert.deepEqual(checkBinaryAll(go, d).map((x) => x.status), ['EXPOSED'], 'go runs the pinned toolchain');
  });
});

test('the go env file: Application Support on macOS, ~/.config or XDG_CONFIG_HOME elsewhere', () => {
  // lib/binaries.mjs:210 and :211 (where `go env -w` writes, by platform)
  const h = fresh('b210-home');
  put(join(h, 'Library', 'Application Support', 'go', 'env'), 'GOTOOLCHAIN=go1.26.5\n');
  put(join(h, '.config', 'go', 'env'), 'GOTOOLCHAIN=go1.26.6\n');
  put(join(h, 'xdg', 'go', 'env'), 'GOTOOLCHAIN=go1.26.7\n');
  assert.equal(goToolchain({}, 'darwin', h), 'go1.26.5');
  assert.equal(goToolchain({}, 'linux', h), 'go1.26.6');
  assert.equal(goToolchain({ XDG_CONFIG_HOME: join(h, 'xdg') }, 'linux', h), 'go1.26.7');
});

test('a dangling php8.1 link on PATH is ignored', () => {
  // lib/binaries.mjs:76 (a name that isn't a regular file is skipped)
  const d = fresh('b76');
  exe(join(d, 'php'), 'echo "PHP 8.4.27 (cli)"'); symlinkSync(join(d, 'no-such-php'), join(d, 'php8.1'));
  const rows = checkBinaryAll({ ...incident('php-2026-10').binaries[0], extraDirs: [] }, d);
  assert.deepEqual(rows.map((x) => [x.status, x.bin]), [['SAFE', join(d, 'php')]]);
});

test('a later copy on PATH that can\'t be read (mode 111) or is empty is not run', () => {
  // lib/files.mjs:108 (no readable 4-byte header, not a compiled program)
  const a = fresh('f108-a'), b = fresh('f108-b'), c = fresh('f108-c');
  exe(join(a, 'node'), 'echo v20.0.0'); put(join(b, 'node'), '#!/bin/sh\necho v20.0.0\n', 0o111); put(join(c, 'node'), '', 0o755);
  assert.deepEqual(copiesToRun('node', [a, b, c].join(':')), { run: [join(a, 'node')], notRun: [join(b, 'node'), join(c, 'node')] });
  assert.equal(isNativeProgram(join(dir, 'no-such-program')), false);
  assert.equal(isNativeProgram(a), false, 'a folder');
});

// ---- installed software ------------------------------------------------------------------------------------------------
test('a virtual environment three levels under the home folder is found, and its cook.pth is EXPOSED', () => {
  // lib/installs.mjs:130 (the walk lists the folder at depth 0)
  const h = fresh('i130-home');
  const sp = venv(join(h, 'a', 'b', 'venv'), { certifi: false }); put(join(sp, 'cook.pth'), 'import cook\n');
  venv(join(h, 'a', 'b', 'c', 'deeper'), { certifi: false });
  const dirs = sitePackagesDirs({ roots: [], patterns: [], home: h });
  assert.deepEqual(dirs, [sp]);
  assert.deepEqual(checkSitePackages(incident('litellm-2026-10').sitePackages, dirs).map((x) => [x.status, x.what]), [['EXPOSED', 'cook.pth']]);
});

test('virtual environments inside node_modules, .git or the Trash are not looked at, and a locked node_modules is no gap', () => {
  // lib/installs.mjs:136 (node_modules, .git and macOS's own folders are skipped)
  const root = fresh('i136-root');
  for (const p of ['node_modules/pkg/.venv', '.git/x/.venv', '.Trash/old/.venv']) venv(join(root, p), { certifi: false });
  const keep = venv(join(root, 'proj', '.venv'), { certifi: false });
  if (!AS_ROOT) { mkdirSync(join(root, 'web', 'node_modules'), { recursive: true }); lock(join(root, 'web', 'node_modules')); }
  const denied = [];
  assert.deepEqual(sitePackagesDirs({ roots: [root], patterns: [], home: '', denied }), [keep]);
  assert.deepEqual(denied, []);
});

// ---- WordPress ---------------------------------------------------------------------------------------------------------
test('a folder with only wp-content is not a site: the full site inside it is found', () => {
  // lib/wordpress.mjs:17 (a site has both wp-includes/version.php and wp-content)
  const root = fresh('wp17-root');
  mkdirSync(join(root, 'a', 'wp-content'), { recursive: true });
  put(join(root, 'a', 'blog', 'wp-includes', 'version.php'), '<?php\n'); mkdirSync(join(root, 'a', 'blog', 'wp-content'), { recursive: true });
  assert.deepEqual(wordpressUnder([root], 5), [join(root, 'a', 'blog')]);
});

test('a plugin folder older than the incident\'s date is not REVIEW; a newer one is', () => {
  // lib/wordpress.mjs:91 (REVIEW only on or after the date)
  const site = fresh('wp91-site');
  mkdirSync(join(site, 'wp-content', 'plugins', 'hello'), { recursive: true });
  assert.deepEqual(checkSite(site, [], '2999-01-01T00:00:00Z'), []);
  assert.deepEqual(checkSite(site, [], '2000-01-01T00:00:00Z').map((x) => [x.status, x.what]), [['REVIEW', 'plugin folder hello']]);
});

test('a backdated plugin folder is judged by its birth time, not by when its status last changed', { skip: process.platform !== 'darwin' && 'only macOS moves a folder\'s birth time back with utimes' }, (t) => {
  // lib/files.mjs:178 (createdAt is the birth time where there is one)
  const site = fresh('f178-site'), old = join(site, 'wp-content', 'plugins', 'old');
  mkdirSync(old, { recursive: true });
  const then = new Date('2020-01-01T00:00:00Z');
  utimesSync(old, then, then);
  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  if (!(statSync(old).birthtimeMs < Date.parse(since))) return t.skip('this file system did not move the birth time back');
  assert.ok(statSync(old).ctimeMs >= Date.parse(since), 'its status changed just now');
  assert.deepEqual(checkSite(site, [], since), []);
});

// ---- reading files -----------------------------------------------------------------------------------------------------
test('a file exactly at the size cap is read whole; one byte over it is not read, and says so', () => {
  // lib/files.mjs:24 and :35 (readCapped's cap is "more than"), :59 and :73 (eachPiece's cap, and false past it)
  const text = Array.from({ length: 100 }, (_, i) => `line ${i}`).join('\n') + '\n', n = Buffer.byteLength(text);
  const f = put(join(dir, 'cap.txt'), text);
  assert.equal(readCapped(f, n)?.toString('utf8'), text);
  assert.equal(readCapped(f, n - 1), null);
  const seen = [];
  assert.equal(eachPiece(f, n, (t) => seen.push(t)), true); assert.equal(seen.join(''), text);
  const over = [];
  assert.equal(eachPiece(f, n - 1, (t) => over.push(t)), false); assert.deepEqual(over, []);
});

test('a last piece that is a line break and a short key keeps the key', () => {
  // lib/files.mjs:77 (a piece that starts with its only line break is cut there, not treated as having none)
  const f = put(join(dir, 'p77.txt'), `${'x'.repeat(127)}\n\n${AWS}`);
  const hits = [];
  assert.equal(eachPiece(f, 1e9, (t, first, range) => { for (const h of scanText(t, range)) hits.push(h.line + first - 1); }, 128, 128), true);
  assert.deepEqual(hits, [3]);
});

test('eachPiece on a missing file returns false and doesn\'t throw', () => {
  // lib/files.mjs:84 (false when it can't be read) and :86 (only an opened file is closed)
  assert.equal(eachPiece(join(dir, 'no-such-file'), 100, () => assert.fail('called')), false);
});

// ---- versions and owners -----------------------------------------------------------------------------------------------
test('version boundaries: GitLab 7.0.0, both ends of a bad range, a prerelease of the minimum version, a pending fix', () => {
  // lib/binaries.mjs:234 (affectedFrom is inclusive), :235 (so are both ends of bad), :237 (a prerelease of minVersion
  // is older than it) and :249 (a pending fix is UNKNOWN)
  const gl = incident('gitlab-2026-10').versionFiles;
  assert.equal(judgeVersion('7.0.0', gl).status, 'EXPOSED');
  assert.equal(judgeVersion('6.9.9', gl).status, 'SAFE');
  const bad = { bad: { from: '0.11.0', to: '0.15.0' } };
  assert.equal(judgeVersion('0.11.0', bad).status, 'EXPOSED'); assert.equal(judgeVersion('0.15.0', bad).status, 'EXPOSED');
  assert.equal(judgeVersion('1.43.3.10861-beta', { minVersion: '1.43.3.10861' }).status, 'EXPOSED');
  assert.deepEqual(judgeVersion('1.2.3', { pendingUntil: '2026-11-01', pendingNote: 'no fix yet' }), { status: 'UNKNOWN', reason: 'no fix yet' });
});

test('accounts: macOS\'s _www (uid 70) is added only on macOS; a malformed subuid line is ignored', () => {
  // lib/owners.mjs:18 (_www only on darwin) and :25 (a subuid line needs both numbers)
  const pw = 'root:x:0:0:root:/root:/bin/sh\nada:x:1000:1000::/home/ada:/bin/sh\n';
  assert.equal(accounts(pw, 'linux').has(70), false);
  assert.equal(accounts(pw, 'darwin').get(70), '_www');
  assert.deepEqual(subuidRanges('ada:100000:65536\nbob::65536\ncarol:200000:\n'), [[100000, 165535]]);
});
