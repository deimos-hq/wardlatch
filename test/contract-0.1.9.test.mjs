// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The 0.1.9 contract: written before, and independently of, the 0.1.9 implementation. Every test here failed on 0.1.8
// for the reason its name gives. Do not weaken a test to make it pass: change the code, or argue the rule with the owner.
//
// ==== CONTRACT (what 0.1.9 must satisfy) =============================================================================
// Behaviour is tested through the CLI (`--json` rows and the exit code) wherever possible. The public functions named
// below are tested directly only where the CLI can't reach them offline; their names and signatures are part of the
// contract: check(rt, canaries, { rootsPem, controlUrl, timeoutMs }) in lib/probe.mjs; checkContainer(engine, ct,
// canaries, { controlUrl, timeoutMs }) in lib/containers.mjs; checkBinary(rule, pathEnv, { tmpDirs }) and tempDirs() in
// lib/binaries.mjs; scanText(text) in lib/secrets.mjs; headersInRc(text, kind), headersInToml(text) and
// scanHeaders({ home, env, roots }) in lib/headers.mjs.
//
// R1  Forced roots. A runtime is SAFE only if its forced-roots probe really connected (the canary server sees the HTTP
//     request), or if it failed with the runtime's own, specific block of the compromised keys. A forced-roots failure
//     for any other reason (connection reset, timeout, hostname mismatch, a chain that doesn't lead to the forced roots)
//     while the control site opens is UNKNOWN, never SAFE. Real curl has no block of its own, so a curl forced-roots
//     refusal is never a block. nscurl: a date error (-1201 bad date, -1204 not yet valid) is not a refusal: not SAFE.
// R2  Containers. A container whose tool fails on the test hosts for a reason other than a certificate refusal (curl
//     exit 28 timeout, 6 DNS, and so on) while its control works is UNKNOWN, never SAFE.
// R3  Temp markers. lib/binaries.mjs exports tempDirs(): the default temp folders, resolved without $TMPDIR. With
//     $TMPDIR unset it still lists /tmp, /var/tmp and, on macOS, the per-user temp folder (confstr
//     _CS_DARWIN_USER_TEMP_DIR, `getconf DARWIN_USER_TEMP_DIR`). checkBinary keeps its injectable { tmpDirs } list.
//     The CLI's receipt for the OVHcloud check names the per-user temp folder it searched.
// R4  Unreadable folders. A folder under the searched roots (or a temp folder) that exists but can't be listed is
//     UNKNOWN (exit 2), named in a row, never silently skipped: workflow and secret repos, WordPress sites, Python
//     virtual environments, temp folders. A SAFE row never claims a folder it couldn't read.
// R5  Nothing searched. An explicit --paths that doesn't exist is UNKNOWN (exit 2), named in a row, for the workflow,
//     secret, WordPress and LiteLLM checks; the first three print no SAFE line at all. And the text and --json outputs
//     agree: every SAFE / EXPOSED / UNKNOWN / REVIEW line in the text is a row of that status in --json, and the
//     summary counts them. Every SAFE row carries its receipt: `searched`, a non-empty array of non-empty strings that
//     says what was looked at.
// R6  Versions. Every copy of a version-checked program on PATH that may be run is judged: the first, and later ones that
//     are compiled programs (a later script is named in a REVIEW row, not run; owner, 22 Oct). A program that isn't found is reported as not found on PATH: the receipt says PATH, never a bare
//     "not installed".
// R7  Workflow review lists: a workflow introduced by a merge commit; and a .git/info/grafts file can't hide a workflow.
//     (Also listed here first: a workflow added by a commit dated earlier than its parent, a backdated commit. Taken
//     out of 0.1.9, owner 22 Oct: a known limit in the CHANGELOG.)
// R8  The trust check runs only the first node, python3 and curl on PATH: a shadowed copy later on PATH never runs.
// R9  Header files also read: a CRLF ~/.curlrc, $CURL_HOME/.curlrc, ~/.config/curlrc (XDG, no dot), and the file
//     GIT_CONFIG_GLOBAL names.
// R10 Environment allowlist. Programs Wardlatch runs to read versions, git, and the container engine's listing get
//     none of: GIT_DIR, GIT_EXEC_PATH, DEVELOPER_DIR, TMPDIR, CURL_HOME, NODE_OPTIONS, PYTHONPATH, PYTHONSTARTUP,
//     OPENSSL_CONF, DOCKER_HOST, GOFLAGS, PHPRC. A --require (or --import, --loader) in the caller's NODE_OPTIONS never
//     runs in any child, the trust probes included (a probe may carry NODE_OPTIONS' trust flags, such as
//     --use-openssl-ca, over as explicit arguments: dropping them could turn an exposed app's runtime into a SAFE).
//     (DOCKER_HOST: the --help text's "if DOCKER_HOST ... points at a remote one" must change with this.)
// R11 Bounded work. scanText of a 512 KB service-account-shaped file: < 1 s. headersInRc of a 4000-space line ending
//     "x\r": < 500 ms. headersInToml of a 62 KB adversarial line: < 500 ms. scanHeaders over a 16 MB .mcp.json:
//     <= 300 MB RSS growth, or the file is reported unread. A FIFO named ovhcloud on PATH, GOENV naming a FIFO, and a
//     version-queried program that ignores SIGTERM do not hang the run (it exits within 30 s).
// X1  (found while writing this) A container row never hides that no runtime on the machine itself was tested.
// R12 A runtime row's `env` (a virtual environment's path, a string) is never spread into a child's environment: no
//     numeric keys "0", "1", ... in it.
// G1  Only lib/run.mjs mentions node:child_process (bin/ and lib/, comments ignored).
// G2  Only lib/files.mjs imports node:fs (or fs, fs/promises), and no other file names readFileSync, existsSync,
//     readdirSync, statSync, realpathSync or lstatSync. lib/files.mjs exports listDir and readCapped.
// G3  A SAFE status is made in exactly one place: `export function safe(` in lib/report.mjs, the only quoted 'SAFE'
//     literal in bin/ and lib/ that is not the right-hand side of === or !==. (Comparisons like r.status === 'SAFE'
//     are allowed anywhere; print('SAFE', ...), status: 'SAFE', a ternary yielding 'SAFE', n('SAFE') are not.)
//
// Existing tests that contradict this contract and must be changed with it (they can't be edited from here):
// cli.test.mjs "a missing tool is SAFE" (/SAFE {5}php not installed/: R6), "workflow files added ..." and "WordPress:
// ... no site found is SAFE" (SAFE for a --paths that doesn't exist: R5); wardlatch.test.mjs "a runtime that refuses
// the compromised keys even with their roots forced in ... is SAFE" uses a curl stand-in, which R1 rules out for curl.
// ======================================================================================================================
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, realpathSync, chmodSync, symlinkSync } from 'node:fs';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createNetServer, connect as netConnect } from 'node:net';
import { tmpdir } from 'node:os';
import { join, dirname, delimiter, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const LIB = join(ROOT, 'lib');
const libUrl = (m) => pathToFileURL(join(LIB, m)).href;
const AS_ROOT = process.getuid?.() === 0;
const IS_MAC = process.platform === 'darwin';
const onPath = (name) => (process.env.PATH ?? '').split(delimiter).filter(Boolean).map((d) => join(d, name)).find(existsSync);
const GIT = onPath('git');
const SYS_PATH = [...new Set([GIT && dirname(GIT), '/usr/bin', '/bin'].filter(Boolean))].join(delimiter);
const OPENSSL = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl'].find(existsSync);
const CURL = existsSync('/usr/bin/curl') ? '/usr/bin/curl' : undefined;
const INCIDENTS = readdirSync(join(LIB, 'incidents')).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)).sort();

let dir, home, emptyPath, emptyTmp, emptyRoot;
const locked = new Set();
const lock = (p) => { chmodSync(p, 0o000); locked.add(p); };
const unlock = (p) => { chmodSync(p, 0o755); locked.delete(p); };

before(() => {
  // realpath: paths in the output then match the ones built here (macOS: /var -> /private/var)
  dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-contract-'));
  home = join(dir, 'home'); emptyPath = join(dir, 'empty-path'); emptyTmp = join(dir, 'empty-tmp'); emptyRoot = join(dir, 'empty-root');
  for (const d of [home, emptyPath, emptyTmp, emptyRoot]) mkdirSync(d, { recursive: true });
});
after(() => { for (const p of [...locked]) { try { unlock(p); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

// ---- helpers ----------------------------------------------------------------------------------------------------------

/** A hermetic environment: nothing inherited from whoever runs the tests. A key set to undefined is left out. */
const envOf = (extra = {}) => {
  const e = { HOME: home, PATH: emptyPath, TMPDIR: emptyTmp, LANG: 'C', ...extra };
  for (const k of Object.keys(e)) if (e[k] === undefined) delete e[k];
  return e;
};
const run = (args, extra = {}, nodeArgs = [], timeout = 120000) => {
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args], { encoding: 'utf8', env: envOf(extra), cwd: dir, maxBuffer: 256 * 1024 * 1024, timeout, killSignal: 'SIGKILL' });
  return { code: r.status, signal: r.signal, out: r.stdout ?? '', err: r.stderr ?? '' };
};
const runJson = (args, extra = {}, nodeArgs = [], timeout) => {
  const r = run([...args, '--json'], extra, nodeArgs, timeout);
  let j;
  try { j = JSON.parse(r.out); } catch { assert.fail(`--json output is not JSON (exit ${r.code}, signal ${r.signal}): ${r.err.slice(0, 600)}`); }
  return { ...r, rows: j.results };
};
/** The CLI without blocking the test process, killed after timeoutMs. */
const runAsync = (args, extra = {}, nodeArgs = [], timeoutMs = 30000) => new Promise((res) => {
  const t0 = Date.now();
  const c = spawn(process.execPath, [...nodeArgs, BIN, ...args], { env: envOf(extra), cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', done = false;
  c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; });
  const timer = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
  const finish = (code, signal) => { if (done) return; done = true; clearTimeout(timer); res({ code, signal, out, err, ms: Date.now() - t0 }); };
  // stdout is complete at 'close'; a grandchild left holding a pipe can't keep the test waiting more than 2 s after 'exit'
  c.on('exit', (code, signal) => { c.on('close', () => finish(code, signal)); setTimeout(() => finish(code, signal), 2000).unref(); });
});
const lines = (out, status) => out.split('\n').filter((l) => new RegExp(`^${status} {2,}`).test(l));
const mentions = (row, p) => JSON.stringify(row).includes(JSON.stringify(p).slice(1, -1));
const exe = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 }); return p; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };

/** A throwaway repository; every commit date is explicit, so nothing depends on today's date. */
const repo = (path) => {
  mkdirSync(path, { recursive: true });
  const g = (args, { date = '2026-10-15T12:00:00Z', input } = {}) => execFileSync(GIT, ['-C', path, '-c', 'commit.gpgsign=false', '-c', 'advice.graftFileDeprecated=false', ...args], {
    encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: SYS_PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x', GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
  }).trim();
  g(['init', '-q', '-b', 'main']);
  return { g, commit: (msg = 'c', date) => { g(['add', '-A']); g(['commit', '-qm', msg], { date }); return g(['rev-parse', 'HEAD']); } };
};
const workflow = (repoPath, name) => put(join(repoPath, '.github', 'workflows', name), 'on: push\n');

/**
 * Stand-ins loaded into the command (node --require). Both hide the Unix paths discover() looks at, refuse every network
 * connection the command itself could open, and replace any network-capable program outside this test's folder
 * (curl, nscurl, wget, python, node, docker, podman ...) with a node that exits 97, so nothing can leave the machine
 * whatever the implementation does. offline: no test host answers. online: every test host "answers" the
 * reachability handshake (no real connection is made), so the container probes run, against stand-in engines only.
 */
const preload = (mode) => {
  const p = join(dir, `${mode}.cjs`);
  if (existsSync(p)) return p;
  writeFileSync(p, `'use strict';
const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), http = require('node:http'), https = require('node:https');
const cp = require('node:child_process'), path = require('node:path'), { EventEmitter } = require('node:events');
const exists = fs.existsSync;
fs.existsSync = (p) => !/^\\/(usr|etc|opt|bin)\\//.test(String(p)) && exists(p);
// hidden from every way of looking, not only existsSync: 0.1.9 reads the disk through statSync and friends, and X1
// passed for the wrong reason while only existsSync was covered (the strict review of eb82857)
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) { const o = fs[k]; fs[k] = (p, ...a) => { if (/^\\/(usr|etc|opt|bin)\\//.test(String(p))) throw Object.assign(new Error('hidden by the test'), { code: 'ENOENT' }); return o(p, ...a); }; }
const fake = (ok) => (...a) => {
  const cb = a.find((x) => typeof x === 'function'), s = new EventEmitter();
  s.end = s.destroy = s.setTimeout = s.write = s.setNoDelay = s.setKeepAlive = () => s;
  // a real test host presents the compromised chain's issuer (0.1.9 checks it, so an impostor can't stand in for one)
  s.getPeerCertificate = () => ({ issuer: { CN: 'EM DV TLS CA - G3B', O: 'eMudhra BV' } });
  process.nextTick(() => (ok ? cb && cb() : s.emit('error', Object.assign(new Error('offline (test stand-in)'), { code: 'ECONNREFUSED' }))));
  return s;
};
tls.connect = fake(${mode === 'online'});
net.connect = net.createConnection = fake(false);
http.request = http.get = https.request = https.get = () => { throw new Error('no network in these tests'); };
const DIR = ${JSON.stringify(dir)};
const NET = /^(curl|nscurl|wget|python[0-9.]*|node|docker|podman|openssl|nc|ssh)$/;
// a bare name is what a lookup on PATH would run
const resolve = (f) => (f.includes('/') ? f : (process.env.PATH || '').split(':').filter(Boolean).map((d) => path.join(d, f)).find((p) => exists(p)) || f);
const allowed = (f) => { const s = resolve(String(f)); return s === process.execPath || s.startsWith(DIR + '/') || !NET.test(path.basename(s)); };
const guard = (orig) => function (file, ...rest) {
  if (allowed(file)) return orig.call(this, file, ...rest);
  return orig.call(this, process.execPath, ['-e', 'process.exit(97)'], ...(Array.isArray(rest[0]) ? rest.slice(1) : rest));
};
for (const n of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) cp[n] = guard(cp[n]);
require('node:module').syncBuiltinESMExports();
`);
  return p;
};

/** What is wrong with a run that should be UNKNOWN about `p`: exit 2, an UNKNOWN row that names `p`, no SAFE row that
 *  claims `p`; noSafe: no SAFE row or line at all. → [] when nothing is. */
const unknownProblems = (label, args, extra, p, { noSafe = false, nodeArgs = [] } = {}) => {
  const j = runJson(args, extra, nodeArgs), out = [];
  const rows = JSON.stringify(j.rows).slice(0, 600);
  if (!j.rows.some((r) => r.status === 'UNKNOWN' && mentions(r, p))) out.push(`${label}: no UNKNOWN row names ${p} (rows: ${rows})`);
  if (j.rows.some((r) => r.status === 'SAFE' && mentions(r, p))) out.push(`${label}: a SAFE row claims ${p}`);
  if (j.code !== 2) out.push(`${label}: exit code ${j.code}, not 2`);
  if (noSafe) {
    if (j.rows.some((r) => r.status === 'SAFE')) out.push(`${label}: a SAFE row although nothing was searched`);
    const t = run(args, extra, nodeArgs);
    for (const l of lines(t.out, 'SAFE')) out.push(`${label}: a SAFE line although nothing was searched: ${l}`);
  }
  return out;
};

// ---- R1: forced roots -------------------------------------------------------------------------------------------------

let pki;   // local CAs and leaf certificates (127.0.0.1 only)
const certs = () => {
  if (pki) return pki;
  const d = fresh('pki'), o = (...a) => execFileSync(OPENSSL, a, { cwd: d, stdio: 'pipe' });
  for (const n of ['bad-root', 'other-root', 'ctl-root']) o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${n}.key`, '-out', `${n}.pem`, '-days', '2', '-subj', `/CN=${n}`, '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  const leaf = (name, ca, san) => {
    writeFileSync(join(d, `${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`);
    o('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=127.0.0.1');
    o('x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-CAcreateserial', '-out', `${name}.pem`, '-days', '2', '-extfile', `${name}.ext`);
    return { key: readFileSync(join(d, `${name}.key`)), cert: readFileSync(join(d, `${name}.pem`)) };
  };
  pki = {
    badCa: join(d, 'bad-root.pem'), ctlCa: join(d, 'ctl-root.pem'),
    canary: leaf('canary', 'bad-root', 'IP:127.0.0.1'),          // a test host signed by the compromised root
    mismatch: leaf('mismatch', 'bad-root', 'DNS:wrong.invalid'),   // signed by it, for another name
    wrongIssuer: leaf('wrong-issuer', 'other-root', 'IP:127.0.0.1'), // a chain that doesn't lead to the forced roots
    control: leaf('control', 'ctl-root', 'IP:127.0.0.1'),          // the normal site: the runtimes trust ctl-root
  };
  return pki;
};
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', r));
/** An HTTPS server that counts the HTTP requests it gets: a request means a client completed a verified handshake. */
const tlsHost = async (leaf) => {
  const host = { requests: 0 };
  host.server = createHttpsServer(leaf, (_q, res) => { host.requests++; res.end('x'); });
  await listen(host.server);
  host.url = `https://127.0.0.1:${host.server.address().port}/`;
  host.close = () => host.server.close();
  return host;
};
/** A TCP front for `target` whose FIRST connection is reset ('reset') or held without an answer ('hang'). */
const flakyFront = async (target, mode) => {
  let n = 0; const held = [];
  const server = createNetServer((sock) => {
    n++; sock.on('error', () => {});
    if (n === 1) {
      if (mode === 'reset') sock.resetAndDestroy();
      else { held.push(sock); setTimeout(() => sock.destroy(), 20000).unref(); }
      return;
    }
    const up = netConnect(target.server.address().port, '127.0.0.1');
    up.on('error', () => sock.destroy());
    sock.pipe(up).pipe(sock);
  });
  await listen(server);
  return { url: `https://127.0.0.1:${server.address().port}/`, close: () => { held.forEach((s) => s.destroy()); server.close(); } };
};
const runtimes = () => {
  const { ctlCa } = certs();
  return [
    ['node', { kind: 'node', bin: process.execPath, version: '', env: { NODE_EXTRA_CA_CERTS: ctlCa, NODE_USE_SYSTEM_CA: '', NODE_OPTIONS: '' } }],
    ...(CURL ? [['curl', { kind: 'curl', bin: CURL, version: '', args: ['--cacert', ctlCa] }]] : []),
  ];
};

test('R1 harness: a runtime that does not trust the local bad root, with a working forced-roots control, is SAFE (sanity, passes on 0.1.8)', { skip: !OPENSSL && 'no openssl' }, async () => {
  const { check } = await import(libUrl('probe.mjs'));
  const { badCa, canary: cl, control: ctl } = certs();
  const control = await tlsHost(ctl);
  try {
    for (const [name, rt] of runtimes()) {
      const canary = await tlsHost(cl);
      try {
        const r = await check(rt, [{ id: 'c', url: canary.url, up: true }], { rootsPem: badCa, controlUrl: control.url, timeoutMs: 3000 });
        assert.equal(r.status, 'SAFE', `${name}: ${JSON.stringify(r)}`);
        assert.ok(canary.requests >= 1, `${name}: the forced-roots probe connected`);
      } finally { canary.close(); }
    }
  } finally { control.close(); }
});

for (const mode of ['reset', 'hang']) {
  test(`R1 forced roots: a forced-roots probe whose connection is ${mode === 'reset' ? 'reset' : 'left unanswered (timeout)'}, while the control site opens, is never SAFE (node, curl)`, { skip: !OPENSSL && 'no openssl' }, async () => {
    const { check } = await import(libUrl('probe.mjs'));
    const { badCa, canary: cl, control: ctl } = certs();
    const control = await tlsHost(ctl), problems = [];
    try {
      for (const [name, rt] of runtimes()) {
        const canary = await tlsHost(cl), front = await flakyFront(canary, mode);
        try {
          const r = await check(rt, [{ id: 'c', url: front.url, up: true }], { rootsPem: badCa, controlUrl: control.url, timeoutMs: 2000 });
          if (r.status === 'EXPOSED') problems.push(`${name}: EXPOSED ${JSON.stringify(r)}`);
          // SAFE is allowed only if a forced-roots connection really went through (a retry may do it): then the canary got
          // its HTTP request. 0.1.8 read the failure as "blocks the compromised keys itself" and said SAFE without one.
          if (r.status === 'SAFE' && canary.requests === 0) problems.push(`${name}: SAFE although the forced-roots control never connected: ${JSON.stringify(r)}`);
        } finally { front.close(); canary.close(); }
      }
    } finally { control.close(); }
    assert.deepEqual(problems, []);
  });
}

for (const [what, leafKey] of [['a hostname mismatch', 'mismatch'], ['a chain that does not lead to the forced roots (wrong issuer)', 'wrongIssuer']]) {
  test(`R1 forced roots: a forced-roots refusal for ${what}, while the control site opens, is never SAFE (node, curl)`, { skip: !OPENSSL && 'no openssl' }, async () => {
    const { check } = await import(libUrl('probe.mjs'));
    const p = certs();
    const control = await tlsHost(p.control), canary = await tlsHost(p[leafKey]), problems = [];
    try {
      for (const [name, rt] of runtimes()) {
        const r = await check(rt, [{ id: 'c', url: canary.url, up: true }], { rootsPem: p.badCa, controlUrl: control.url, timeoutMs: 3000 });
        if (r.status !== 'UNKNOWN') problems.push(`${name}: ${JSON.stringify(r)}`);
      }
      assert.equal(canary.requests, 0, 'the fixture: no verifying client can complete this handshake');
    } finally { control.close(); canary.close(); }
    assert.deepEqual(problems, []);
  });
}

test('R1 nscurl: a certificate date error (-1201 bad date, -1204 not yet valid) is not a refusal: never SAFE', async () => {
  const { check } = await import(libUrl('probe.mjs'));
  const fake = (code) => exe(join(dir, 'nscurl', `nscurl${code}`), `for a in "$@"; do case "$a" in *control*) exit 0;; esac; done\necho "Load failed with error: Error Domain=NSURLErrorDomain Code=${code}" >&2\nexit 0`);
  const host = { id: 'h', url: 'https://canary.invalid/', up: true };
  const got = [];
  for (const code of ['-1201', '-1204']) got.push([code, (await check({ kind: 'macos-system', bin: fake(code), version: '' }, [host], { controlUrl: 'https://control.invalid/', timeoutMs: 2000 })).status]);
  assert.deepEqual(got.filter(([, s]) => s === 'SAFE'), [], `nscurl date errors read as SAFE: ${JSON.stringify(got)}`);
});

// ---- R2: containers ---------------------------------------------------------------------------------------------------

test('R2 containers: a container whose curl times out (exit 28) or cannot resolve (exit 6) the test hosts, while its control works, is UNKNOWN (CLI)', () => {
  const online = preload('online');
  const setup = (name, canaryExit) => {
    const box = fresh(`r2-${name}-box`), eng = fresh(`r2-${name}-engine`);
    // curl inside the "container": the control site opens, a test host fails with canaryExit, anything else (the
    // self-signed control, whatever site an implementation picks for it) is refused as curl refuses an untrusted cert
    exe(join(box, 'curl'), `for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done
case "$u" in
  https://emudhra.we-have-a-problem.com*) exit 0;;
  *-emudhra.we-have-a-problem.com*) exit ${canaryExit};;
  *) echo "curl: (60) SSL certificate problem: self-signed certificate" >&2; exit 60;;
esac`);
    // docker: ps lists one container; exec runs the probe script with only that curl on PATH; anything else succeeds quietly
    exe(join(eng, 'docker'), `if [ "$1" = ps ]; then printf 'c0ffee\\tweb\\tdebian:11\\n'; exit 0; fi
if [ "$1" = exec ]; then
  while [ $# -gt 0 ] && [ "$1" != sh ] && [ "$1" != /bin/sh ]; do shift; done
  [ $# -gt 0 ] || exit 125
  shift
  PATH=${JSON.stringify(box)} exec /bin/sh "$@"
fi
exit 0`);
    return eng;
  };
  const containerRows = (eng) => runJson(['--incident', 'emudhra-2026-10', '--paths', emptyRoot], { PATH: eng }, ['--require', online]).rows.filter((r) => r.kind === 'container');
  // the harness can produce SAFE: a container whose curl refuses the test hosts (exit 60) and opens the control
  assert.deepEqual(containerRows(setup('refuses', 60)).map((r) => r.status), ['SAFE'], 'harness sanity: a refusing container is SAFE');
  for (const [name, code] of [['timeout', 28], ['dns', 6]]) {
    const rows = containerRows(setup(name, code));
    assert.equal(rows.length, 1, `${name}: the container was checked`);
    assert.equal(rows[0].status, 'UNKNOWN', `${name} (curl exit ${code}): ${JSON.stringify(rows[0])}`);
  }
});

test('X1 (found while writing this contract) a checked container never hides that no runtime on the machine itself was tested: not exit 0', () => {
  // discover() finds nothing here (the stand-in hides /usr/bin and PATH holds only the engine); one container answers as
  // a fixed one. 0.1.8 printed only the container's SAFE line and exited 0: the machine's own trust was never tested.
  const box = fresh('x1-box'), eng = fresh('x1-engine');
  exe(join(box, 'curl'), 'for a in "$@"; do case "$a" in http*://*) u="$a";; esac; done\ncase "$u" in https://emudhra.we-have-a-problem.com*) exit 0;; *) exit 60;; esac');
  exe(join(eng, 'docker'), `if [ "$1" = ps ]; then printf 'c0ffee\\tweb\\tdebian:13\\n'; exit 0; fi
if [ "$1" = exec ]; then
  while [ $# -gt 0 ] && [ "$1" != sh ] && [ "$1" != /bin/sh ]; do shift; done
  [ $# -gt 0 ] || exit 125
  shift
  PATH=${JSON.stringify(box)} exec /bin/sh "$@"
fi
exit 0`);
  const j = runJson(['--incident', 'emudhra-2026-10', '--paths', emptyRoot], { PATH: eng }, ['--require', preload('online')]);
  assert.ok(j.rows.some((r) => r.kind === 'container'), 'the fixture: the container was checked');
  assert.ok(j.rows.some((r) => r.kind !== 'container' && r.status === 'UNKNOWN'), `no row says the machine's own runtimes were not tested: ${JSON.stringify(j.rows)}`);
  assert.equal(j.code, 2);
});

// ---- R3: temp markers without $TMPDIR ---------------------------------------------------------------------------------

const userTemp = () => (IS_MAC ? execFileSync('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR'], { encoding: 'utf8' }).trim().replace(/\/+$/, '') : '');
const sameDir = (a, b) => { const n = (p) => { const s = String(p).replace(/\/+$/, ''); try { return realpathSync(s); } catch { return s; } }; return n(a) === n(b); };

test('R3 temp markers: tempDirs() resolves the default temp folders without $TMPDIR (per-user temp on macOS, /tmp, /var/tmp); checkBinary keeps its injectable tmpDirs', async () => {
  // run where $TMPDIR is unset (sudo, cron), so os.tmpdir() can't hand the per-user folder over by accident
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(libUrl('binaries.mjs'))}); console.log(JSON.stringify(typeof m.tempDirs === 'function' ? m.tempDirs() : null));`], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', HOME: home } });
  const list = JSON.parse(r.stdout || 'null');
  assert.ok(Array.isArray(list), `lib/binaries.mjs must export tempDirs() returning an array (${r.stderr.slice(0, 300)})`);
  for (const d of ['/tmp', '/var/tmp']) assert.ok(list.some((x) => sameDir(x, d)), `${d} is not in ${JSON.stringify(list)}`);
  if (IS_MAC) assert.ok(list.some((x) => sameDir(x, userTemp())), `the per-user temp folder ${userTemp()} is not in ${JSON.stringify(list)} with $TMPDIR unset`);
  // the injectable list still works (regression guard)
  const { checkBinary } = await import(libUrl('binaries.mjs'));
  const t = fresh('r3-tmp'); mkdirSync(join(t, 'envchecker-123456789'));
  const hit = checkBinary({ binary: 'ovhcloud', noExec: true, md5Bad: [], tmpTrace: '^envchecker-[0-9]+$' }, emptyPath, { tmpDirs: [t] });
  assert.equal(hit?.status, 'EXPOSED');
});

test('R3 temp markers: with TMPDIR unset, the OVHcloud check names the per-user temp folder it searched (macOS)', { skip: !IS_MAC && 'the per-user temp folder is a macOS thing' }, () => {
  const j = runJson(['--incident', 'ovhcloud-cli-2026-10', '--paths', emptyRoot], { TMPDIR: undefined });
  const ut = userTemp(), real = realpathSync(ut);
  assert.ok(j.rows.length >= 1, 'no row at all: the not-found receipt is missing from --json');
  assert.ok(j.rows.some((r) => mentions(r, ut) || mentions(r, real)), `no row names the per-user temp folder ${ut}: ${JSON.stringify(j.rows)}`);
});

// ---- R4: folders that can't be read -----------------------------------------------------------------------------------

const skipRoot = AS_ROOT && 'root can open every folder';

test('R4 unreadable: a repository with a planted workflow inside a folder that cannot be opened is UNKNOWN (exit 2), never SAFE', { skip: skipRoot }, () => {
  const root = fresh('r4-wf'), box = join(root, 'locked'), app = join(box, 'app');
  const r = repo(app); workflow(app, 'evil.yml'); r.commit();
  const args = ['--incident', 'github-actions-2026-10', '--paths', root], env = { PATH: SYS_PATH };
  assert.deepEqual(runJson(args, env).rows.map((x) => [x.status, x.file]), [['REVIEW', '.github/workflows/evil.yml']], 'control: readable, it is listed');
  lock(box);
  let problems; try { problems = unknownProblems('workflow', args, env, box, { noSafe: true }); } finally { unlock(box); }
  assert.deepEqual(problems, []);
});

test('R4 unreadable: a repository with a committed key inside a folder that cannot be opened is UNKNOWN (exit 2), never SAFE', { skip: skipRoot }, () => {
  const root = fresh('r4-keys'), box = join(root, 'locked'), app = join(box, 'svc');
  const r = repo(app); put(join(app, 'config.js'), `const k = "${'AKIA' + 'Q7RZM2LPX9TBK4WD'}";\n`); r.commit();
  const args = ['--incident', 'committed-keys-2026-10', '--paths', root], env = { PATH: SYS_PATH };
  assert.deepEqual(runJson(args, env).rows.map((x) => [x.status, x.file]), [['REVIEW', 'config.js']], 'control: readable, it is found');
  lock(box);
  let problems; try { problems = unknownProblems('secret', args, env, box, { noSafe: true }); } finally { unlock(box); }
  assert.deepEqual(problems, []);
});

test('R4 unreadable: a WordPress site inside a folder that cannot be opened is UNKNOWN (exit 2), never SAFE', { skip: skipRoot }, () => {
  const root = fresh('r4-wp'), box = join(root, 'locked'), site = join(box, 'shop');
  put(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  put(join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'), '<?php\n/**\n * Plugin Name: Rank Math PRO\n * Version: 3.0.123\n */\n');
  const args = ['--incident', 'wordpress-plugins-2026-10', '--paths', root];
  assert.equal(runJson(args).code, 1, 'control: readable, the compromised plugin is EXPOSED');
  lock(box);
  let problems; try { problems = unknownProblems('wordpress', args, {}, box, { noSafe: true }); } finally { unlock(box); }
  assert.deepEqual(problems, []);
});

test('R4 unreadable: a virtual environment holding cook.pth whose folder cannot be opened is UNKNOWN (exit 2), never SAFE', { skip: skipRoot }, () => {
  const root = fresh('r4-venv'), venv = join(root, 'proj', '.venv');
  put(join(venv, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(venv, 'lib', 'python3.12', 'site-packages', 'cook.pth'), 'import os\n');
  const args = ['--incident', 'litellm-2026-10', '--no-containers', '--paths', root];
  assert.ok(runJson(args).rows.some((r) => r.status === 'EXPOSED' && r.what === 'cook.pth'), 'control: readable, cook.pth is EXPOSED');
  lock(venv);
  let problems; try { problems = unknownProblems('litellm', args, {}, venv); } finally { unlock(venv); }
  assert.deepEqual(problems, []);
});

test('R4 unreadable: a temp folder that cannot be listed is UNKNOWN (exit 2) for the OVHcloud and LiteLLM marker checks, never SAFE', { skip: skipRoot }, () => {
  const t = fresh('r4-tmp');
  lock(t);
  const problems = [];
  try {
    problems.push(...unknownProblems('ovhcloud', ['--incident', 'ovhcloud-cli-2026-10', '--paths', emptyRoot], { TMPDIR: t }, t));
    problems.push(...unknownProblems('litellm', ['--incident', 'litellm-2026-10', '--no-containers', '--paths', emptyRoot], { TMPDIR: t }, t));
  } finally { unlock(t); }
  assert.deepEqual(problems, []);
});

// ---- R5: nothing searched, and text = json ----------------------------------------------------------------------------

test('R5 nothing searched: --paths that does not exist is UNKNOWN (exit 2) for the workflow, secret, WordPress and LiteLLM checks', () => {
  const missing = `/nonexistent-wardlatch-${process.pid}-${Date.now()}`;
  assert.equal(existsSync(missing), false);
  const problems = [];
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    problems.push(...unknownProblems(id, ['--incident', id, '--paths', missing], { PATH: SYS_PATH }, missing, { noSafe: true }));
  }
  problems.push(...unknownProblems('litellm-2026-10', ['--incident', 'litellm-2026-10', '--no-containers', '--paths', missing], {}, missing));
  assert.deepEqual(problems, []);
});

test('R5 text = json: every status line printed is a row of that status in --json, the summary counts them, and every SAFE row carries a `searched` receipt', () => {
  const offline = preload('offline'), problems = [];
  for (const id of INCIDENTS) {
    const args = ['--incident', id, '--no-containers', '--paths', emptyRoot], env = { PATH: SYS_PATH };
    const nodeArgs = id.startsWith('emudhra') ? ['--require', offline] : [];
    const text = run(args, env, nodeArgs), j = runJson(args, env, nodeArgs);
    const counts = {};
    for (const s of ['SAFE', 'EXPOSED', 'UNKNOWN', 'REVIEW']) {
      counts[s] = lines(text.out, s).length;
      const n = j.rows.filter((r) => r.status === s).length;
      if (n !== counts[s]) problems.push(`${id}: ${counts[s]} ${s} line(s) in the text, ${n} ${s} row(s) in --json`);
    }
    const sum = /^(\d+) safe · (\d+) exposed · (\d+) could not be tested(?: · (\d+) to review)?$/m.exec(text.out);
    if (!sum) problems.push(`${id}: no summary line`);
    else if (`${[+sum[1], +sum[2], +sum[3], +(sum[4] ?? 0)]}` !== `${[counts.SAFE, counts.EXPOSED, counts.UNKNOWN, counts.REVIEW]}`) problems.push(`${id}: the summary "${sum[0]}" does not count what was printed`);
    for (const r of j.rows.filter((x) => x.status === 'SAFE')) {
      if (!(Array.isArray(r.searched) && r.searched.length && r.searched.every((x) => typeof x === 'string' && x.trim()))) problems.push(`${id}: a SAFE row without a \`searched\` receipt: ${JSON.stringify(r).slice(0, 200)}`);
    }
  }
  assert.deepEqual(problems, []);
});

// ---- R6: versions -----------------------------------------------------------------------------------------------------

test('R6 versions: every copy on PATH that may be run is judged: a later compiled program is run, a later script is not', async () => {
  // owner, 22 Oct: one rule (lib/binaries.mjs copiesToRun) for the trust check and the version checks
  const { copiesToRun } = await import(libUrl('binaries.mjs'));
  const a = fresh('r6-a'), b = fresh('r6-b'), c = fresh('r6-c');
  exe(join(a, 'php'), 'echo "PHP 8.4.27 (cli)"');
  put(join(b, 'php'), Buffer.concat([Buffer.from('7f454c46', 'hex'), Buffer.alloc(60)])); chmodSync(join(b, 'php'), 0o755);   // an ELF program
  exe(join(c, 'php'), 'echo "PHP 8.4.26 (cli)"');
  assert.deepEqual(copiesToRun('php', `${a}:${b}:${c}`), { run: [join(a, 'php'), join(b, 'php')], notRun: [join(c, 'php')] });
});

test('R6 versions: a later copy on PATH that is a script is named, never silently dropped (a review line, in --json too)', () => {
  const fixed = fresh('r6-fixed'), bad = fresh('r6-bad');
  exe(join(fixed, 'php'), 'echo "PHP 8.4.27 (cli)"'); exe(join(bad, 'php'), 'echo "PHP 8.4.26 (cli)"');
  const j = runJson(['--incident', 'php-2026-10', '--paths', emptyRoot], { PATH: `${fixed}:${bad}` });
  assert.ok(j.rows.some((r) => r.kind === 'not-run' && r.status === 'REVIEW' && r.paths.includes(join(bad, 'php'))), JSON.stringify(j.rows));
  assert.equal(j.code, 0, 'a review line does not change the exit code');
});

test('R6 versions: a program not found says it searched PATH, never a bare "not installed"', () => {
  const args = ['--incident', 'php-2026-10', '--paths', emptyRoot];
  const text = run(args), j = runJson(args);
  assert.doesNotMatch(text.out, /^SAFE {2,}php not installed\s*$/m, 'a bare "not installed" after looking only on PATH');
  const safe = lines(text.out, 'SAFE');
  assert.ok(safe.length >= 1, `the not-found result is not printed:\n${text.out}`);
  for (const l of safe) assert.match(l, /PATH|\d+\.\d+\.\d+/, l);
  const rows = j.rows.filter((r) => r.status === 'SAFE');
  assert.ok(rows.length >= 1 && rows.some((r) => /PATH/.test(JSON.stringify(r))), `no SAFE row in --json says it searched PATH: ${JSON.stringify(j.rows)}`);
});

// ---- R7: workflow review ----------------------------------------------------------------------------------------------

const reviewed = (root) => runJson(['--incident', 'github-actions-2026-10', '--paths', root], { PATH: SYS_PATH }).rows.filter((r) => r.status === 'REVIEW').map((r) => r.file).sort();

test('R7 workflows: a workflow introduced by a merge commit is listed', () => {
  const root = fresh('r7-merge'), path = join(root, 'app'), r = repo(path);
  put(join(path, 'a'), 'a\n'); r.commit('A');
  r.g(['checkout', '-qb', 'side']); put(join(path, 'b'), 'b\n'); r.commit('B');
  r.g(['checkout', '-q', 'main']); put(join(path, 'c'), 'c\n'); r.commit('C');
  try { r.g(['merge', '--no-ff', '--no-commit', 'side']); } catch { /* --no-commit stops before committing */ }
  workflow(path, 'merge.yml'); r.commit('merge');
  assert.equal(r.g(['rev-list', '--parents', '-n', '1', 'HEAD']).split(' ').length, 3, 'the fixture: HEAD is a merge commit');
  assert.deepEqual(reviewed(root), ['.github/workflows/merge.yml']);
});

test('R7 workflows: a .git/info/grafts file cannot hide a planted workflow', () => {
  const root = fresh('r7-grafts'), path = join(root, 'app'), r = repo(path);
  put(join(path, 'a'), 'a\n'); r.commit('A', '2026-10-01T12:00:00Z');
  workflow(path, 'evil.yml'); const b = r.commit('B', '2026-10-10T12:00:00Z');
  assert.deepEqual(reviewed(root), ['.github/workflows/evil.yml'], 'control: without grafts, it is listed');
  // a dangling, backdated root commit with B's own tree, grafted in as B's parent: B then "adds" nothing
  const d = r.g(['commit-tree', `${b}^{tree}`, '-m', 'D'], { date: '2026-08-01T12:00:00Z' });
  writeFileSync(join(path, '.git', 'info', 'grafts'), `${b} ${d}\n`);
  assert.deepEqual(reviewed(root), ['.github/workflows/evil.yml']);
});

// ---- R8: shadowed copies on PATH --------------------------------------------------------------------------------------

test('R8 shadowed PATH copies: a python3, node or curl later on PATH, behind a real one, is never run by the trust check', () => {
  const offline = preload('offline');
  const first = fresh('r8-first'), second = fresh('r8-second'), marks = fresh('r8-ran');
  const real = { node: process.execPath, python3: onPath('python3'), curl: CURL ?? onPath('curl') };
  const names = Object.keys(real).filter((n) => real[n]);
  assert.ok(names.length >= 1, 'no real runtime to put first');
  for (const n of names) { symlinkSync(real[n], join(first, n)); exe(join(second, n), `/usr/bin/touch ${JSON.stringify(join(marks, n))}\necho "${n} 1.2.3"\nexit 0`); }
  run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', emptyRoot], { PATH: `${first}:${second}` }, ['--require', offline]);
  assert.deepEqual(readdirSync(marks), [], 'a shadowed copy later on PATH was run');
});

// ---- R9: header files -------------------------------------------------------------------------------------------------

const headerHome = (name) => { const h = fresh(`r9-${name}`); put(join(h, '.gitconfig'), '[user]\n\tname = Ada Lovelace\n\temail = ada.lovelace@example.org\n'); return h; };
const headerFiles = (h, extra = {}) => {
  const j = runJson(['--incident', 'identity-headers-2026-10', '--paths', emptyRoot], { HOME: h, PATH: '/usr/bin:/bin', ...extra });
  return { code: j.code, exposed: j.rows.filter((r) => r.status === 'EXPOSED').map((r) => r.file), rows: j.rows };
};

test('R9 headers: a ~/.curlrc saved with CRLF line ends is read', () => {
  const h = headerHome('crlf'); const f = put(join(h, '.curlrc'), '# mine\r\nheader = "X-Contact: ada.lovelace@example.org"\r\n');
  const r = headerFiles(h);
  assert.deepEqual(r.exposed, [f], JSON.stringify(r.rows)); assert.equal(r.code, 1);
});

test('R9 headers: $CURL_HOME/.curlrc is read', () => {
  const h = headerHome('curlhome'); const ch = fresh('r9-curlhome-dir'); const f = put(join(ch, '.curlrc'), 'header = "X-Contact: ada.lovelace@example.org"\n');
  const r = headerFiles(h, { CURL_HOME: ch });
  assert.ok(r.exposed.includes(f), JSON.stringify(r.rows)); assert.equal(r.code, 1);
});

test('R9 headers: ~/.config/curlrc (XDG, no dot) is read', () => {
  const h = headerHome('xdg'); const f = put(join(h, '.config', 'curlrc'), 'header = "X-Contact: ada.lovelace@example.org"\n');
  const r = headerFiles(h);
  assert.deepEqual(r.exposed, [f], JSON.stringify(r.rows)); assert.equal(r.code, 1);
});

test('R9 headers: the file GIT_CONFIG_GLOBAL names is read', () => {
  const h = headerHome('gitglobal'); const f = put(join(dir, 'r9-gitglobal.conf'), '[http]\n\textraHeader = From: ada.lovelace@example.org\n');
  const r = headerFiles(h, { GIT_CONFIG_GLOBAL: f });
  assert.ok(r.exposed.includes(f), JSON.stringify(r.rows)); assert.equal(r.code, 1);
});

// ---- R10: environment allowlist ---------------------------------------------------------------------------------------

const POISON = ['GIT_DIR', 'GIT_EXEC_PATH', 'DEVELOPER_DIR', 'TMPDIR', 'CURL_HOME', 'NODE_OPTIONS', 'PYTHONPATH', 'PYTHONSTARTUP', 'OPENSSL_CONF', 'DOCKER_HOST', 'GOFLAGS', 'PHPRC'];

test('R10 environment: version reads, git and the engine listing get none of the poisoned variables, for every incident; NODE_OPTIONS --require never runs in a child', () => {
  const offline = preload('offline');
  const bin = fresh('r10-bin'), log = join(dir, 'r10-env.log'), markLog = join(dir, 'r10-node-options.log'), poison = fresh('r10-poison');
  const marker = put(join(poison, 'marker.cjs'), `require('fs').appendFileSync(${JSON.stringify(markLog)}, String(process.argv[1]) + '\\n');\n`);
  const outputs = { git: '', php: 'echo "PHP 8.4.27 (cli)"', go: 'echo "go version go1.27.3 darwin/arm64"', docker: '', podman: '', node: 'echo v26.12.1', python3: 'echo "Python 3.12.0"', curl: 'echo "curl 8.7.1 (x86_64-apple-darwin)"', cloudflared: 'echo "cloudflared version 2026.10.2"', ovhcloud: '' };
  for (const [name, body] of Object.entries(outputs)) exe(join(bin, name), `printf '@@ %s\\n' ${JSON.stringify(name)} >> ${JSON.stringify(log)}\n/usr/bin/env >> ${JSON.stringify(log)}\n${body}\nexit 0`);
  const root = fresh('r10-root'); mkdirSync(join(root, 'app', '.git'), { recursive: true });
  const tmp = fresh('r10-tmp'), curlHome = fresh('r10-curlhome');
  const env = {
    PATH: bin, TMPDIR: tmp, CURL_HOME: curlHome, GIT_DIR: join(poison, 'gitdir'), GIT_EXEC_PATH: poison, DEVELOPER_DIR: poison,
    NODE_OPTIONS: `--require ${marker}`, PYTHONPATH: poison, PYTHONSTARTUP: join(poison, 'startup.py'), OPENSSL_CONF: join(poison, 'openssl.cnf'),
    DOCKER_HOST: 'tcp://127.0.0.1:1', GOFLAGS: '-poisoned', PHPRC: poison,
  };
  for (const id of INCIDENTS) run(['--incident', id, '--paths', root], env, id.startsWith('emudhra') ? ['--require', offline] : []);
  const blocks = readFileSync(log, 'utf8').split(/^@@ /m).filter(Boolean);
  const ran = new Set(blocks.map((b) => b.split('\n')[0]));
  for (const p of ['git', 'php', 'go', 'docker', 'node', 'python3', 'curl']) assert.ok(ran.has(p), `the fixture: ${p} was never run (ran: ${[...ran].join(', ')})`);
  const leaks = [];
  for (const b of blocks) {
    const [name, ...vars] = b.split('\n');
    const keys = new Set(vars.map((l) => l.split('=')[0]));
    for (const k of POISON) if (keys.has(k)) leaks.push(`${name} got ${k}`);
  }
  assert.deepEqual([...new Set(leaks)], [], 'children got poisoned variables');
  const marks = existsSync(markLog) ? readFileSync(markLog, 'utf8').trim().split('\n') : [];
  assert.deepEqual(marks.filter((m) => m !== BIN), [], 'NODE_OPTIONS --require ran in a child');
});

test('R10 environment: NODE_OPTIONS from the caller never reaches a trust probe (its --require never runs)', async () => {
  const { check } = await import(libUrl('probe.mjs'));
  const markLog = join(dir, 'r10-probe-node-options.log');
  const marker = put(join(dir, 'r10-probe-marker.cjs'), `require('fs').appendFileSync(${JSON.stringify(markLog)}, 'ran\\n');\n`);
  const saved = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = `--require ${marker}`;
  try {
    const dead = { id: 'dead', url: 'https://127.0.0.1:1/', up: true };
    // the real roots file: a missing one returns before any child starts, and the test passed with NODE_OPTIONS unfiltered
    await check({ kind: 'node', bin: process.execPath, version: '' }, [dead], { rootsPem: join(LIB, 'incidents', 'emudhra-2026-10-roots.pem'), controlUrl: dead.url, timeoutMs: 2000 });
  } finally { if (saved === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = saved; }
  assert.equal(existsSync(markLog), false, 'the caller\'s NODE_OPTIONS --require ran inside a probe');
});

// ---- R11: bounded work ------------------------------------------------------------------------------------------------

/** Run `body` (an ES module source) in its own node, killed after killMs → { ms, out, err, killed }. */
const timed = (body, killMs = 10000, nodeArgs = []) => new Promise((res) => {
  const t0 = Date.now();
  const c = spawn(process.execPath, [...nodeArgs, '--input-type=module', '-e', body], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', HOME: home } });
  let out = '', err = '';
  c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; });
  const timer = setTimeout(() => c.kill('SIGKILL'), killMs);
  c.on('close', (code, signal) => { clearTimeout(timer); res({ ms: Date.now() - t0, out, err, code, killed: signal === 'SIGKILL' }); });
});
const measure = (mod, expr) => `const m = await import(${JSON.stringify(libUrl(mod))}); const input = ${expr}; const t = performance.now(); FN(input); console.log(Math.round(performance.now() - t));`;

test('R11 bounded work: adversarial input to the scanners finishes in time', { concurrency: true }, async (t) => {
  await Promise.all([
    t.test('scanText: 512 KB of "type": "service_account" without a private_key, < 1 s', async () => {
      const r = await timed(measure('secrets.mjs', `'"type": "service_account",\\n'.repeat(Math.floor(512 * 1024 / 27))`).replace('FN', 'm.scanText'));
      assert.ok(!r.killed, 'scanText was still running after 10 s'); assert.equal(r.code, 0, r.err);
      assert.ok(+r.out < 1000, `scanText took ${r.out.trim()} ms`);
    }),
    t.test('headersInRc: "header", 4000 spaces, then "x\\r" on one line, < 500 ms', async () => {
      const r = await timed(measure('headers.mjs', `'header' + ' '.repeat(4000) + 'x\\r'`).replace('FN(input)', 'm.headersInRc(input, "curl")'));
      assert.ok(!r.killed, 'headersInRc was still running after 10 s'); assert.equal(r.code, 0, r.err);
      assert.ok(+r.out < 500, `headersInRc took ${r.out.trim()} ms`);
    }),
    t.test('headersInToml: "[", 62 KB of spaces, "x" (an unclosed table header), < 500 ms', async () => {
      const r = await timed(measure('headers.mjs', `'[' + ' '.repeat(62 * 1024) + 'x'`).replace('FN', 'm.headersInToml'));
      assert.ok(!r.killed, 'headersInToml was still running after 10 s'); assert.equal(r.code, 0, r.err);
      assert.ok(+r.out < 500, `headersInToml took ${r.out.trim()} ms`);
    }),
  ]);
});

test('R11 bounded work: a 16 MB .mcp.json grows memory by at most ~300 MB, or is reported unread', async () => {
  const h = fresh('r11-mem-home'), root = fresh('r11-mem-root'), app = join(root, 'app');
  mkdirSync(join(app, '.git'), { recursive: true });
  const pre = '{"mcpServers":{"s":{"args":[', post = '"a"]}}}';
  const n = Math.floor((16 * 1024 * 1024 - pre.length - post.length) / 4);
  const file = put(join(app, '.mcp.json'), pre + '"a",'.repeat(n) + post);
  const r = await timed(`const { scanHeaders } = await import(${JSON.stringify(libUrl('headers.mjs'))});
globalThis.gc?.();
const before = process.memoryUsage().rss;
const res = scanHeaders({ home: ${JSON.stringify(h)}, env: { PATH: '/usr/bin:/bin' }, roots: [${JSON.stringify(root)}] });
console.log(JSON.stringify({ growthMB: Math.round((process.resourceUsage().maxRSS * 1024 - before) / 1048576), unread: res.unread.map((u) => u.file) }));`, 60000, ['--expose-gc']);
  assert.ok(!r.killed, 'the scan was still running after 60 s'); assert.equal(r.code, 0, `the scan crashed: ${r.err.slice(-600)}`);
  const m = JSON.parse(r.out);
  assert.ok(m.growthMB <= 300 || m.unread.includes(file), `the scan grew memory by ${m.growthMB} MB and read the file`);
});

test('R11 bounded work: nothing on PATH or in the environment can hang the run (each run exits within 30 s)', { concurrency: true }, async (t) => {
  const offline = preload('offline');
  await Promise.all([
    t.test('a FIFO named ovhcloud on PATH', async () => {
      const b = fresh('r11-fifo-bin'); execFileSync('mkfifo', [join(b, 'ovhcloud')]);
      const r = await runAsync(['--incident', 'ovhcloud-cli-2026-10', '--json', '--paths', emptyRoot], { PATH: b });
      assert.ok(r.signal === null && r.ms < 30000, `the run hung (${r.ms} ms, ${r.signal})`);
      assert.equal(r.code, 2, r.out); assert.ok(JSON.parse(r.out).results.some((x) => x.status === 'UNKNOWN'), r.out);
    }),
    t.test('GOENV naming a FIFO', async () => {
      const b = fresh('r11-goenv-bin'); exe(join(b, 'go'), 'echo "go version go1.27.3 darwin/arm64"');
      const fifo = join(dir, 'r11-goenv-fifo'); execFileSync('mkfifo', [fifo]);
      const r = await runAsync(['--incident', 'emudhra-2026-10', '--json', '--no-containers', '--paths', emptyRoot], { PATH: b, GOENV: fifo }, ['--require', offline]);
      assert.ok(r.signal === null && r.ms < 30000, `the run hung (${r.ms} ms, ${r.signal})`);
      assert.ok(Array.isArray(JSON.parse(r.out).results));
    }),
    t.test('a version-queried program that ignores SIGTERM and sleeps', async () => {
      const b = fresh('r11-sigterm-bin'); exe(join(b, 'php'), "trap '' TERM\nexec /bin/sleep 45");
      const r = await runAsync(['--incident', 'php-2026-10', '--json', '--paths', emptyRoot], { PATH: b });
      assert.ok(r.signal === null && r.ms < 30000, `the run hung (${r.ms} ms, ${r.signal})`);
      assert.equal(r.code, 2, r.out); assert.deepEqual(JSON.parse(r.out).results.map((x) => x.status), ['UNKNOWN']);
    }),
  ]);
});

// ---- R12: a runtime's env string --------------------------------------------------------------------------------------

test('R12 probe environment: a runtime row whose `env` is a virtual environment\'s path never puts numeric keys ("0", "1", ...) into the child\'s environment', async () => {
  const { check } = await import(libUrl('probe.mjs'));
  const log = join(dir, 'r12-env.log'), ca = put(join(dir, 'r12-ca.pem'), 'x\n');
  const curl = exe(join(dir, 'r12-bin', 'curl'), `/usr/bin/env >> ${JSON.stringify(log)}\nexit 0`);
  await check({ kind: 'curl', bin: curl, version: '', env: '/Users/someone/project/.venv' }, [{ id: 'c', url: 'https://canary.invalid/', up: true }], { rootsPem: ca, controlUrl: 'https://control.invalid/', timeoutMs: 2000 });
  assert.ok(existsSync(log), 'the fixture: the stand-in curl ran');
  assert.deepEqual(readFileSync(log, 'utf8').split('\n').filter((l) => /^\d+=/.test(l)), [], 'the env string was spread into the environment');
});

// ---- guards: mechanical conventions -----------------------------------------------------------------------------------

const shipped = () => {
  const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.mjs') ? [join(d, e.name)] : []));
  return [...walk(join(ROOT, 'bin')), ...walk(LIB)].map((f) => relative(ROOT, f));
};
/** Source without comments (block comments, and // comments that start a line or follow white space); lines keep their numbers. */
const code = (f) => readFileSync(join(ROOT, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).replace(/(^|\s)\/\/.*$/gm, '$1');

test('G1 only lib/run.mjs mentions node:child_process', () => {
  const offenders = shipped().filter((f) => f !== 'lib/run.mjs' && /child_process/.test(code(f)));
  assert.deepEqual(offenders, [], 'these files reach child_process directly instead of through lib/run.mjs');
});

test('G2 only lib/files.mjs touches node:fs; nobody else names readFileSync, existsSync, readdirSync, statSync, realpathSync or lstatSync; lib/files.mjs exports listDir and readCapped', () => {
  const offenders = [];
  for (const f of shipped().filter((x) => x !== 'lib/files.mjs')) {
    const src = code(f);
    if (/(?:from\s*|import\(\s*|require\(\s*)['"](?:node:)?fs(?:\/promises)?['"]/.test(src)) offenders.push(`${f}: imports node:fs`);
    for (const m of src.matchAll(/\b(readFileSync|existsSync|readdirSync|statSync|realpathSync|lstatSync)\b/g)) offenders.push(`${f}: ${m[1]}`);
  }
  assert.deepEqual([...new Set(offenders)], []);
  const files = existsSync(join(LIB, 'files.mjs')) ? code('lib/files.mjs') : '';
  for (const fn of ['listDir', 'readCapped']) assert.match(files, new RegExp(`export\\s+(?:async\\s+)?(?:function\\s+${fn}\\b|const\\s+${fn}\\b)`), `lib/files.mjs exports ${fn}`);
});

test('G3 a SAFE status is made in exactly one place: export function safe( in lib/report.mjs', () => {
  const made = [];   // quoted 'SAFE' literals that are not the right-hand side of === or !==
  for (const f of shipped()) {
    const src = code(f);
    for (const m of src.matchAll(/(['"`])SAFE\1/g)) {
      if (/[!=]==\s*$/.test(src.slice(Math.max(0, m.index - 8), m.index))) continue;
      made.push({ f, at: m.index, line: src.slice(0, m.index).split('\n').length, src });
    }
  }
  const outside = made.filter((x) => x.f !== 'lib/report.mjs').map((x) => `${x.f}:${x.line}`);
  assert.deepEqual(outside, [], 'a SAFE status made outside lib/report.mjs safe()');
  const inside = made.filter((x) => x.f === 'lib/report.mjs');
  assert.equal(inside.length, 1, `lib/report.mjs must make SAFE exactly once (found ${inside.length})`);
  const src = inside[0].src, start = src.search(/export\s+function\s+safe\s*\(/);
  assert.ok(start >= 0 && inside[0].at > start && inside[0].at < (src.indexOf('\n}', start) >>> 0), 'the one SAFE literal is inside export function safe(');
});

