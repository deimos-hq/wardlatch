// Against a LOCAL stand-in for a compromised CA: a throwaway root signs a cert for 127.0.0.1, an HTTPS "canary" serves
// it, and runtimes either trust that root (exposed) or don't (safe). Nothing leaves the machine.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, reachable, nscurlOk, canForceCa } from '../lib/probe.mjs';
import { discover } from '../lib/discover.mjs';
import { cmp, checkBinary } from '../lib/binaries.mjs';
import { workflowsAddedSince } from '../lib/workflows.mjs';
import { scanText } from '../lib/secrets.mjs';

const OPENSSL = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl'].find(existsSync);
let dir, server, canary, badCa, otherCa;
const node = (env) => ({ kind: 'node', bin: process.execPath, env: { NODE_EXTRA_CA_CERTS: '', NODE_USE_SYSTEM_CA: '', NODE_OPTIONS: '', ...env } });

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'wardlatch-'));
  const o = (...a) => execFileSync(OPENSSL, a, { cwd: dir, stdio: 'pipe' });
  for (const n of ['bad-root', 'other-root']) o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${n}.key`, '-out', `${n}.pem`, '-days', '2', '-subj', `/CN=${n}`);
  writeFileSync(join(dir, 'leaf.ext'), 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
  o('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=127.0.0.1');
  o('x509', '-req', '-in', 'leaf.csr', '-CA', 'bad-root.pem', '-CAkey', 'bad-root.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '2', '-extfile', 'leaf.ext');
  badCa = join(dir, 'bad-root.pem'); otherCa = join(dir, 'other-root.pem');
  server = createServer({ key: readFileSync(join(dir, 'leaf.key')), cert: readFileSync(join(dir, 'leaf.pem')) }, (_q, s) => s.end('canary'));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  canary = { id: 'local', url: `https://127.0.0.1:${port}/`, up: await reachable('127.0.0.1', port, 2000) };
});
after(() => server.close());

test('the canary is reachable (control for the control)', () => assert.equal(canary.up, true));

test('a runtime that does not trust the compromised root is SAFE', async () => {
  const r = await check(node(), [canary], { rootsPem: badCa, timeoutMs: 3000 });
  assert.equal(r.status, 'SAFE'); assert.equal(r.tested, 1);
});

test('a runtime that trusts it is EXPOSED, and says through which host', async () => {
  const r = await check(node({ NODE_EXTRA_CA_CERTS: badCa }), [canary], { rootsPem: badCa, timeoutMs: 3000 });
  assert.equal(r.status, 'EXPOSED'); assert.deepEqual(r.trusted, ['local']);
});

test('no host answering is UNKNOWN, never SAFE', async () => {
  const r = await check(node(), [{ ...canary, up: false }], { rootsPem: badCa });
  assert.equal(r.status, 'UNKNOWN');
});

test('a probe that cannot see exposure (positive control fails) is UNKNOWN, never SAFE', async () => {
  const r = await check(node(), [canary], { rootsPem: otherCa, timeoutMs: 3000 });
  assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /positive control failed/);
});

test('curl is checked the same way', { skip: !existsSync('/usr/bin/curl') }, async () => {
  const r = await check({ kind: 'curl', bin: '/usr/bin/curl' }, [canary], { rootsPem: badCa, timeoutMs: 3000 });
  assert.equal(r.status, 'SAFE');
});

test('discovery finds node on PATH and a virtual environment, and changes nothing', () => {
  const root = join(dir, 'proj'); mkdirSync(join(root, 'app', '.venv', 'bin'), { recursive: true });
  writeFileSync(join(root, 'app', '.venv', 'pyvenv.cfg'), 'home = /usr/bin\n');
  const py = ['/opt/homebrew/bin/python3', '/usr/bin/python3'].find(existsSync);
  if (py) execFileSync('ln', ['-s', py, join(root, 'app', '.venv', 'bin', 'python')]);
  const found = discover({ roots: [root], pathEnv: join(process.execPath, '..') });
  assert.ok(found.some((r) => r.kind === 'node' && r.version));
  if (py) assert.ok(found.some((r) => r.env === join(root, 'app', '.venv')));
});

test('the macOS system probe reads only a refusal as a refusal', () => {
  assert.equal(nscurlOk('Load failed with error: Error Domain=NSURLErrorDomain Code=-1202'), false);
  assert.equal(nscurlOk(''), true);
  assert.equal(canForceCa('macos-system'), false); assert.equal(canForceCa('curl'), true);
});

test('a system probe that cannot open a normal site is UNKNOWN, never SAFE', async () => {
  const r = await check({ kind: 'macos-system', bin: '/usr/bin/false' }, [canary], { controlUrl: canary.url, timeoutMs: 2000 });
  assert.equal(r.status, 'UNKNOWN'); assert.match(r.reason, /control failed/);
});

test('version checks: affected range, fixed version, one fix per release line', () => {
  assert.equal(cmp('0.15.0', '0.11.0'), 1); assert.equal(cmp('2026.10.2', '2026.10.2'), 0); assert.equal(cmp('1.26.9', '1.26.10'), -1);
  const bin = join(dir, 'bin'); mkdirSync(bin, { recursive: true });
  const fake = (name, out) => { writeFileSync(join(bin, name), `#!/bin/sh\necho "${out}"\n`, { mode: 0o755 }); };
  fake('ovhcloud', 'ovhcloud CLI 0.13.0'); fake('cloudflared', 'cloudflared version 2026.9.1 (built x)'); fake('go', 'go version go1.26.10 darwin/arm64');
  assert.equal(checkBinary({ binary: 'ovhcloud', bad: { from: '0.11.0', to: '0.15.0' } }, bin).status, 'EXPOSED');
  assert.equal(checkBinary({ binary: 'cloudflared', versionRe: 'version (\\d+\\.\\d+\\.\\d+)', fixedIn: '2026.10.2' }, bin).status, 'EXPOSED');
  assert.equal(checkBinary({ binary: 'go', versionArgs: ['version'], versionRe: 'go(\\d+\\.\\d+(?:\\.\\d+)?)', fixedIn: ['1.26.10', '1.27.3'] }, bin).status, 'SAFE');
  assert.equal(checkBinary({ binary: 'not-installed-anywhere' }, bin), null);
});

test('workflow review lists each workflow file added since the date, once', () => {
  const repo = join(dir, 'repo'); mkdirSync(join(repo, '.github', 'workflows'), { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', repo, ...a], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q'); writeFileSync(join(repo, '.github', 'workflows', 'audit.yml'), 'on: push\n'); g('add', '.'); g('commit', '-qm', 'add');
  const found = workflowsAddedSince(repo, '2000-01-01');
  assert.equal(found.length, 1); assert.equal(found[0].file, '.github/workflows/audit.yml');
});

test('committed keys: found by shape, never printed, reviewed lines and doc placeholders skipped', () => {
  const key = 'AKIA' + 'Q7RZ' + 'M2LP' + 'X9TB' + 'K4WD';            // built at runtime so this file holds no key literal
  const hits = scanText(`const k = "${key}";\nconst e = "AKIAIOSFODNN7EXAMPLE";\nconst t = "${key}"; // secrets-ok: a made-up test value`);
  assert.equal(hits.length, 1); assert.equal(hits[0].type, 'AWS access key'); assert.equal(hits[0].line, 1);
  assert.ok(!JSON.stringify(hits).includes(key), 'the key itself never appears in a finding');
  const pem = '-----BEGIN ' + 'PRIVATE KEY-----';
  assert.equal(scanText(`x\n${pem}\nabc`)[0].type, 'private key');
});
