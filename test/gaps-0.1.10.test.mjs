// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Known test gaps closed for 0.1.10: places where an 'UNKNOWN' or 'EXPOSED' changed to 'SAFE' made no test fail, listed
// in scripts/mutants-gaps.json. Each test names the planted bugs it catches by their place in that list as it was at
// 4d2aa38 (#1 to #42, in its order) and the line they were on there, fails on each of them and passes on the code as it
// is, and has a clean-machine twin beside it. Every run of the command here also goes through T0 and T1
// (test/support/output-checks.mjs). Offline: no test reaches a network host, stand-ins replace every program a check
// would run, and the machine's system folders and the real home folder are hidden.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checked } from './support/output-checks.mjs';
import { STAND_IN_MS } from './support/timeouts.mjs';
import { checkVersionFiles } from '../lib/installs.mjs';
import { check } from '../lib/probe.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
const EMAIL = 'ada.lovelace@example.org';
const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
const esc = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
// a value as JavaScript, for the stand-in's code: JSON.stringify's text with <, > and the two line separators (JSON
// leaves them as they are) written as \u escapes, the same value wherever the code is put
// (CodeQL's js/bad-code-sanitization)
const SPELLED = { '<': '\\u003c', '>': '\\u003e', '\u2028': '\\u2028', '\u2029': '\\u2029' };
const js = (v) => JSON.stringify(v).replace(/[<>\u2028\u2029]/g, (c) => SPELLED[c]);
let dir, home, n = 0;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-gaps10-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body) => put(p, `#!/bin/sh\n${body}\n`, 0o755);
const fresh = (name) => { const d = join(dir, `${name}-${++n}`); mkdirSync(d, { recursive: true }); return d; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };

// A stand-in loaded into the command: the machine's system folders hidden (this test's folder and the code excepted), no
// real connection (every test host is down), no program run outside this test's folder, and the platform and user id
// it is told to report.
const preload = (name, { platform, uid } = {}) => {
  const p = join(dir, `${name}.cjs`);
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), cp = require('node:child_process'), os = require('node:os'), { EventEmitter } = require('node:events');
const DIR = ${js(dir)}, ROOT = ${js(ROOT)};
const SYS = /^\\/(?:usr|etc|opt|bin|sbin|System|Library|Applications|var|private|tmp|home|srv|snap|nix)(?:\\/|$)/;
const mine = (p) => p === DIR || p.startsWith(DIR + '/') || p.startsWith(ROOT + '/');
const hidden = (p) => typeof p === 'string' && SYS.test(p) && !mine(p);
const ex = fs.existsSync; fs.existsSync = (p) => !hidden(p) && ex(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) { const o = fs[k]; fs[k] = (p, ...a) => { if (hidden(p)) throw Object.assign(new Error('hidden by the test'), { code: 'ENOENT' }); return o(p, ...a); }; }
tls.connect = (...a) => { const s = new EventEmitter(); s.end = s.destroy = () => s; process.nextTick(() => s.emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }))); return s; };
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
${platform ? `os.platform = () => ${js(platform)}; Object.defineProperty(process, 'platform', { value: ${js(platform)} });` : ''}
${uid !== undefined ? `process.getuid = () => ${uid};` : ''}
require('node:module').syncBuiltinESMExports();
`);
  return p;
};
// the command behind the stand-in, with T0 and T1 checked → { code, out, err, rows (with --json) }
const cli = (args, env = {}, pre = {}) => {
  const r = checked(args, spawnSync(process.execPath, ['--require', preload(pre.name ?? 'plain', pre), BIN, ...args],
    { encoding: 'utf8', env: { HOME: home, PATH: fresh('empty-path'), TMPDIR: fresh('empty-tmp'), LANG: 'C', ...env }, cwd: dir, timeout: 120000, killSignal: 'SIGKILL' }));
  const out = { code: r.status, out: r.stdout, err: r.stderr };
  if (args.includes('--json')) { try { out.rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 500)}`); } }
  return out;
};
// the screen lines that start with `status`
const lines = (out, status) => out.split('\n').filter((l) => new RegExp(`^${status} {2,}`).test(l));

// ---- shown SAFE while EXPOSED ------------------------------------------------------------------------------------------

test('#36 identity headers: a ~/.wgetrc header carrying your email is EXPOSED, exit 1; one carrying nothing of yours is not', () => {
  // lib/headers.mjs:296 (a wget header is EXPOSED: wget sends it to every site it opens)
  const h = fresh('h36-home'), args = ['--incident', 'identity-headers-2026-10', '--paths', fresh('h36-root')];
  put(join(h, '.gitconfig'), `[user]\n\tname = Ada Lovelace\n\temail = ${EMAIL}\n`);
  put(join(h, '.wgetrc'), `header = From: ${EMAIL}\n`);
  const j = cli([...args, '--json'], { HOME: h }, { name: 'h36' });
  assert.deepEqual(j.rows.map((x) => [x.status, x.file, x.carries]), [['EXPOSED', join(h, '.wgetrc'), 'your email']], JSON.stringify(j.rows));
  assert.equal(j.code, 1);
  const t = cli(args, { HOME: h }, { name: 'h36' });
  assert.deepEqual(lines(t.out, 'EXPOSED').map((l) => l.split(' · ')[0]), ['EXPOSED  ~/.wgetrc'], t.out);
  assert.deepEqual(lines(t.out, 'SAFE'), [], t.out);
  assert.equal(t.code, 1);
  // the clean twin: a wget header with no name or email in it
  const c = fresh('h36c-home');
  put(join(c, '.gitconfig'), `[user]\n\tname = Ada Lovelace\n\temail = ${EMAIL}\n`);
  put(join(c, '.wgetrc'), 'header = Accept-Language: en\n');
  const cj = cli([...args, '--json'], { HOME: c }, { name: 'h36' });
  assert.deepEqual(cj.rows.map((x) => x.status), ['SAFE'], JSON.stringify(cj.rows));
  assert.equal(cj.code, 0);
});

test('#8 Windows (not supported): an OVHcloud trace in the temp folder is an EXPOSED line on screen, and no SAFE line, exit 1', () => {
  // bin/wardlatch.mjs:235 (the trace's screen line, a separate line of code from its --json row)
  const win = { name: 'win32', platform: 'win32' }, args = ['--incident', 'ovhcloud-cli-2026-10', '--paths', fresh('w8-root')];
  const tmp = fresh('w8-tmp'), trace = join(tmp, 'envchecker-1760900000'); mkdirSync(trace);
  const r = cli(args, { TMPDIR: tmp, TMP: tmp, TEMP: tmp }, win);
  assert.deepEqual(lines(r.out, 'EXPOSED'), [`EXPOSED  ovhcloud  ${trace}`], r.out);
  assert.deepEqual(lines(r.out, 'SAFE'), [], r.out);
  assert.match(r.out, new RegExp(`^ {9}the malware ran on this machine: it left ${esc(trace)}\\n {9}fix: Do not run an ovhcloud binary`, 'm'));
  assert.equal(r.code, 1);
  // the clean twin: an empty temp folder is no EXPOSED line (the check itself is not done on Windows: UNKNOWN, exit 2)
  const e = fresh('w8c-tmp');
  const c = cli(args, { TMPDIR: e, TMP: e, TEMP: e }, win);
  assert.deepEqual(lines(c.out, 'EXPOSED'), [], c.out);
  assert.deepEqual(lines(c.out, 'SAFE'), [], c.out);
  assert.equal(c.code, 2);
});

// ---- shown SAFE while not checked --------------------------------------------------------------------------------------

test('#9 #10 Windows (not supported): the program checks and the installs check are UNKNOWN lines on screen, never SAFE (exit 2)', () => {
  // bin/wardlatch.mjs:239 (the program checks' screen line) and :247 (the installs check's), separate lines of code from
  // their --json rows
  const win = { name: 'win32', platform: 'win32' }, e = fresh('w9-tmp');
  for (const id of ['php-2026-10', 'ovhcloud-cli-2026-10', 'litellm-2026-10']) {
    const r = cli(['--incident', id, '--paths', fresh('w9-root')], { TMPDIR: e, TMP: e, TEMP: e }, win);
    assert.deepEqual(lines(r.out, 'UNKNOWN'), ['UNKNOWN  not checked on Windows yet'], `${id}: ${r.out}`);
    assert.deepEqual(lines(r.out, 'SAFE'), [], `${id}: ${r.out}`);
    assert.equal(r.code, 2, id);
  }
  // the clean twin: the same checks on Linux, with nothing installed, are no UNKNOWN line (exit 0)
  for (const id of ['php-2026-10', 'ovhcloud-cli-2026-10', 'litellm-2026-10']) {
    const r = cli(['--incident', id, '--no-containers', '--paths', fresh('w9c-root')], { TMPDIR: e }, { name: 'linux', platform: 'linux' });
    assert.deepEqual(lines(r.out, 'UNKNOWN'), [], `${id}: ${r.out}`);
    assert.equal(r.code, 0, `${id}: ${r.out}`);
  }
});

test('#5 #6 DOCKER_HOST naming a remote host: the images there are an UNKNOWN line on screen and an UNKNOWN row, never SAFE', () => {
  // bin/wardlatch.mjs:209 (the row) and :210 (its screen line)
  const eng = fresh('d6-engine'); exe(join(eng, 'docker'), 'exit 0');
  const args = ['--incident', 'litellm-2026-10', '--paths', fresh('d6-root')], env = { PATH: eng, DOCKER_HOST: 'tcp://example.invalid:2375' };
  const t = cli(args, env, { name: 'd6' });
  assert.deepEqual(lines(t.out, 'UNKNOWN'), ['UNKNOWN  images named by the environment'], t.out);
  assert.equal(t.code, 2);
  const j = cli([...args, '--json'], env, { name: 'd6' });
  const rows = j.rows.filter((x) => x.kind === 'containers');
  assert.deepEqual(rows.map((x) => [x.status, x.engine]), [['UNKNOWN', 'DOCKER_HOST']], JSON.stringify(j.rows));
  assert.match(rows[0].reason, /^DOCKER_HOST is set, and not followed \(whoever starts Wardlatch can point it at any host\): the images there were not checked/);
  // the clean twin: no DOCKER_HOST, no such line or row (exit 0)
  const c = cli(args, { PATH: eng }, { name: 'd6' });
  assert.deepEqual(lines(c.out, 'UNKNOWN'), [], c.out);
  assert.equal(c.code, 0);
});

test('#7 as root under sudo, for a person whose home folder is not found: an UNKNOWN "home folder" line on screen, never SAFE', () => {
  // bin/wardlatch.mjs:224, the second UNKNOWN on the line (the screen line; the first is the --json row)
  const args = ['--incident', 'identity-headers-2026-10', '--paths', fresh('s7-root')];
  const r = cli(args, { SUDO_USER: '..' }, { name: 'root', uid: 0 });
  assert.deepEqual(lines(r.out, 'UNKNOWN'), ['UNKNOWN  home folder'], r.out);
  assert.match(r.out, /^UNKNOWN {2}home folder\n {9}run under sudo by \.\., whose home folder was not found/m);
  assert.equal(r.code, 2);
  // the clean twin: root with no SUDO_USER (its own home) has no such line, exit 0
  const c = cli(args, {}, { name: 'root', uid: 0 });
  assert.deepEqual(lines(c.out, 'UNKNOWN'), [], c.out);
  assert.equal(c.code, 0);
});

test('#11 #12 OPENSSL_CONF set, so not given to the probes: an UNKNOWN line on screen and an UNKNOWN row of its own', () => {
  // bin/wardlatch.mjs:280 (the row) and :281 (its screen line)
  const conf = put(join(fresh('e12'), 'openssl.cnf'), '');
  const args = ['--incident', 'emudhra-2026-10', '--no-containers', '--paths', fresh('e12-root')];
  const t = cli(args, { OPENSSL_CONF: conf }, { name: 'e12' });
  assert.ok(lines(t.out, 'UNKNOWN').includes('UNKNOWN  settings not given to the probes'), t.out);
  assert.equal(t.code, 2);
  const j = cli([...args, '--json'], { OPENSSL_CONF: conf }, { name: 'e12' });
  const rows = j.rows.filter((x) => x.kind === 'environment');
  assert.deepEqual(rows.map((x) => x.status), ['UNKNOWN'], JSON.stringify(j.rows));
  assert.match(rows[0].reason, /^OPENSSL_CONF: set in this environment and not given to the probes/);
  // the clean twin: without it, no such line or row
  const c = cli(args, {}, { name: 'e12' });
  assert.ok(!c.out.includes('settings not given to the probes'), c.out);
});

test('#17 a container engine that cannot list its containers: an UNKNOWN "docker containers" line on screen, never SAFE', () => {
  // bin/wardlatch.mjs:313, the second UNKNOWN on the line (the screen line; the first is the --json row)
  const failing = fresh('c17-fail');
  exe(join(failing, 'docker'), 'echo \'error during connect: Get "http://%2F%2F.%2Fpipe%2Fdocker_engine/v1.47/containers/json": EOF\' >&2\nexit 1');
  const args = ['--incident', 'emudhra-2026-10', '--paths', fresh('c17-root')];
  const r = cli(args, { PATH: failing }, { name: 'c17' });
  assert.ok(lines(r.out, 'UNKNOWN').includes('UNKNOWN  docker containers'), r.out);
  assert.match(r.out, /^UNKNOWN {2}docker containers\n {9}could not list its containers \(error during connect: /m);
  assert.equal(r.code, 2);
  // the clean twin: a daemon that is not running has no containers to check, and no such line
  const stopped = fresh('c17-stopped');
  exe(join(stopped, 'docker'), 'echo \'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\' >&2\nexit 1');
  const c = cli(args, { PATH: stopped }, { name: 'c17' });
  assert.ok(!lines(c.out, 'UNKNOWN').some((l) => l.includes('docker')), c.out);
  assert.match(c.out, /docker: not running, so no running containers to check/);
});

test('#22 #23 a LiteLLM marker in the temp folder: the EXPOSED row carries the fix in --json, and its screen line has a fix line', () => {
  // bin/wardlatch.mjs:369 (an EXPOSED install row gets the fix) and :372 (an EXPOSED install line gets its fix line)
  const inc = incident('litellm-2026-10'), args = ['--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('l22-root')];
  const tmp = fresh('l22-tmp'), marker = put(join(tmp, 'remote_code_loader.lock'), '');
  const j = cli([...args, '--json'], { TMPDIR: tmp }, { name: 'l22' });
  assert.deepEqual(j.rows.map((x) => [x.status, x.path, x.fix]), [['EXPOSED', marker, inc.tmpFix]], JSON.stringify(j.rows));
  assert.equal(j.code, 1);
  const t = cli(args, { TMPDIR: tmp }, { name: 'l22' });
  assert.match(t.out, new RegExp(`^EXPOSED {2}${esc(marker)}\\n {9}the malware ran on this machine[^\\n]*\\n {9}fix: ${esc(inc.tmpFix)}\\n`, 'm'));
  assert.equal(t.code, 1);
  // the clean twin: an empty temp folder is the all-clear, with no fix
  const c = cli([...args, '--json'], { TMPDIR: fresh('l22c-tmp') }, { name: 'l22' });
  assert.deepEqual(c.rows.map((x) => [x.status, x.fix]), [['SAFE', undefined]], JSON.stringify(c.rows));
  assert.equal(c.code, 0);
});

test('#37 GitLab: a version file larger than expected is UNKNOWN; beside a file of the same install that gives a version, it is dropped', () => {
  // lib/installs.mjs:69 (a version file found but not read is UNKNOWN, and so dropped when its install answered elsewhere)
  const rule = incident('gitlab-2026-10').versionFiles, root = fresh('v37');
  const manifest = put(join(root, 'opt', 'gitlab', 'version-manifest.txt'), `gitlab-ee 19.5.1\n${'#'.repeat(4 * 1024 * 1024)}\n`);
  assert.deepEqual(checkVersionFiles(rule, { root }).map((r) => [r.status, r.path, r.reason]),
    [['UNKNOWN', manifest, 'found, but the file could not be read (or is larger than expected)']]);
  // the clean twin: the same install's VERSION file says 19.5.1, so it answers for the install alone
  const version = put(join(root, 'opt', 'gitlab', 'embedded', 'service', 'gitlab-rails', 'VERSION'), '19.5.1\n');
  assert.deepEqual(checkVersionFiles(rule, { root }).map((r) => [r.status, r.path, r.version]), [['SAFE', version, '19.5.1']]);
});

test('#38 the trust probe: when no test host chained to one of the two roots answers, a runtime that refused the rest is UNKNOWN', async () => {
  // lib/probe.mjs:156 (a refusal proves nothing about a root that had no test host to refuse)
  const d = fresh('p38'), pem = (r) => put(join(d, `${r}.pem`), `-----BEGIN CERTIFICATE-----\n${r}\n-----END CERTIFICATE-----\n`);
  // a curl that connects with only the forced root trusted (the control passes) and refuses every test host without it
  const curl = exe(join(d, 'curl'), 'case "$*" in *--cacert*) exit 0;; *) exit 60;; esac');
  const canaries = (aaaUp) => [
    { id: 'a1', up: aaaUp, url: 'https://a1-aaa.test/', host: 'a1-aaa.test', root: 'AAA Certificate Services', pem: pem('aaa') },
    { id: 'e1', up: true, url: 'https://e1-emsign.test/', host: 'e1-emsign.test', root: 'emSign Root CA - G1', pem: pem('emsign') },
  ];
  const opts = { controlUrl: 'https://advisory.test/', timeoutMs: STAND_IN_MS };
  const r = await check({ kind: 'curl', bin: curl, version: '' }, canaries(false), opts);
  assert.deepEqual([r.status, r.reason], ['UNKNOWN', 'no test host chained to AAA Certificate Services answered, so this runtime\'s trust in that root could not be tested'], JSON.stringify(r));
  // the clean twin: both roots' hosts answer and are refused: SAFE, with both hosts in the receipt
  const s = await check({ kind: 'curl', bin: curl, version: '' }, canaries(true), opts);
  assert.deepEqual([s.status, s.searched], ['SAFE', ['a1-aaa.test', 'e1-emsign.test']], JSON.stringify(s));
});

test('#41 a WordPress plugin with an attack indicator, one of whose folders cannot be opened: that folder is UNKNOWN, never SAFE', { skip: AS_ROOT && 'root opens a mode-000 folder' }, () => {
  // lib/wordpress.mjs:191 (a folder inside the plugin that the indicator search can't open is UNKNOWN)
  const root = fresh('p41'), site = join(root, 'shop'), pl = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8.3";');
  put(join(pl, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.124\n*/\n');
  put(join(pl, 'includes', 'loader.php'), '<?php\n');
  const args = ['--incident', 'wordpress-plugins-2026-10', '--paths', root];
  // the clean twin first, with every folder open: the plugin is SAFE and nothing is UNKNOWN (exit 0)
  const c = cli([...args, '--json'], {}, { name: 'p41' });
  assert.deepEqual(c.rows.filter((x) => x.status !== 'REVIEW').map((x) => [x.status, x.what]), [['SAFE', 'seo-by-rank-math-pro 3.0.124']], JSON.stringify(c.rows));
  assert.equal(c.code, 0);
  lock(join(pl, 'includes'));
  const j = cli([...args, '--json'], {}, { name: 'p41' });
  // (the search for sites also meets the locked folder, and says so in a row of its own: not this one)
  assert.deepEqual(j.rows.filter((x) => x.what === 'seo-by-rank-math-pro: includes').map((x) => [x.status, x.reason]),
    [['UNKNOWN', 'this folder could not be opened, so the indicator was not searched for in it: run Wardlatch with sudo']], JSON.stringify(j.rows));
  assert.equal(j.code, 2);
  const t = cli(args, {}, { name: 'p41' });
  assert.ok(lines(t.out, 'UNKNOWN').some((l) => l.includes(' · seo-by-rank-math-pro: includes  this folder could not be opened')), t.out);
  assert.equal(t.code, 2);
});
