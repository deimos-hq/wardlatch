// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Against a LOCAL stand-in for a compromised CA: a throwaway root signs a cert for 127.0.0.1, an HTTPS "canary" serves
// it, and runtimes either trust that root (exposed) or don't (safe). Nothing leaves the machine.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, reachable, nscurlOk, canForceCa } from '../lib/probe.mjs';
import { discover } from '../lib/discover.mjs';
import { cmp, checkBinary, md5File, tmpTraces, judgeVersion } from '../lib/binaries.mjs';
import { expand, checkVersionFiles, sitePackagesDirs, checkSitePackages, checkImages, localImageDigests } from '../lib/installs.mjs';
import { createHash } from 'node:crypto';
import { workflowsAddedSince } from '../lib/workflows.mjs';
import { scanText } from '../lib/secrets.mjs';
import { wordpressUnder, checkSite } from '../lib/wordpress.mjs';
import { listContainers, checkContainer } from '../lib/containers.mjs';
import { readCapped } from '../lib/files.mjs';

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

test('discovery finds node on PATH, and never runs a found environment\'s own python', () => {
  const root = join(dir, 'proj'); const env = join(root, 'app', '.venv'); mkdirSync(join(env, 'bin'), { recursive: true });
  writeFileSync(join(env, 'pyvenv.cfg'), 'home = /usr/bin\n');
  // a planted interpreter, as a cloned repository could ship: running it would leave a marker file
  const marker = join(dir, 'planted-python-ran');
  writeFileSync(join(env, 'bin', 'python'), `#!/bin/sh\ntouch "${marker}"\necho "Python 3.12.0"\n`, { mode: 0o755 });
  const sp = join(env, 'lib', 'python3.12', 'site-packages'); mkdirSync(join(sp, 'certifi'), { recursive: true }); mkdirSync(join(sp, 'certifi-2026.10.18.dist-info'));
  writeFileSync(join(sp, 'certifi', 'cacert.pem'), readFileSync(badCa)); writeFileSync(join(sp, 'certifi-2026.10.18.dist-info', 'METADATA'), 'Name: certifi\nVersion: 2026.10.18\n');
  const found = discover({ roots: [root], pathEnv: join(process.execPath, '..') });
  assert.ok(found.some((r) => r.kind === 'node' && r.version));
  assert.equal(existsSync(marker), false, 'the environment\'s own bin/python must never be executed');
  const env1 = found.find((r) => r.env === env);
  if (existsSync('/usr/bin/curl')) {
    assert.ok(env1, 'the environment\'s certifi bundle is still checked');
    assert.equal(env1.certifi, '2026.10.18'); assert.equal(env1.bin, '/usr/bin/curl'); assert.deepEqual(env1.args, ['--cacert', join(sp, 'certifi', 'cacert.pem')]);
    assert.equal(env1.fixKey, 'python-certifi');
  }
});

test('a found environment\'s certifi bundle is tested with a trusted curl: a bundle holding the bad root is EXPOSED', { skip: !existsSync('/usr/bin/curl') }, async () => {
  const env1 = discover({ roots: [join(dir, 'proj')], pathEnv: '' }).find((r) => r.env);
  const r = await check(env1, [canary], { rootsPem: badCa, timeoutMs: 3000 });
  assert.equal(r.status, 'EXPOSED');
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

test('a program an incident marks as possible malware is never run: it is checked by its hash and its temp-folder trace', () => {
  const bin = join(dir, 'nx'), tmp = join(dir, 'nx-tmp'), ran = join(dir, 'nx-ran');
  mkdirSync(bin, { recursive: true }); mkdirSync(tmp, { recursive: true });
  writeFileSync(join(bin, 'ovhcloud'), `#!/bin/sh\ntouch "${ran}"\necho "ovhcloud 0.13.0"\n`, { mode: 0o755 });
  const rule = { binary: 'ovhcloud', noExec: true, md5Bad: ['0'.repeat(32)], tmpTrace: '^envchecker-[0-9]{9,10}$' };
  let r = checkBinary(rule, bin, { tmpDirs: [tmp] });
  assert.equal(r.status, 'SAFE'); assert.match(r.reason, /not run/);
  r = checkBinary({ ...rule, md5Bad: [md5File(join(bin, 'ovhcloud'))] }, bin, { tmpDirs: [tmp] });
  assert.equal(r.status, 'EXPOSED'); assert.match(r.reason, /compromised builds/);
  mkdirSync(join(tmp, 'envchecker-123456789'));
  r = checkBinary(rule, join(dir, 'no-such-path'), { tmpDirs: [tmp] });
  assert.equal(r.status, 'EXPOSED'); assert.match(r.reason, /envchecker-123456789/);
  assert.equal(existsSync(ran), false, 'the program was run');
});

test('the OVHcloud CLI incident never runs the program and carries the five published hashes', () => {
  const rule = JSON.parse(readFileSync(new URL('../lib/incidents/ovhcloud-cli-2026-10.json', import.meta.url), 'utf8')).binaries[0];
  assert.equal(rule.noExec, true); assert.equal(rule.md5Bad.length, 5); assert.ok(rule.md5Bad.every((h) => /^[0-9a-f]{32}$/.test(h)));
  const bin = join(dir, 'ovh'), ran = join(dir, 'ovh-ran'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'ovhcloud'), `#!/bin/sh\ntouch "${ran}"\n`, { mode: 0o755 });
  assert.equal(checkBinary(rule, bin, { tmpDirs: [] }).status, 'SAFE');
  assert.equal(existsSync(ran), false, 'the program was run');
});

test('a version read from a product file is judged per release line, and the file is only read', () => {
  const root = join(dir, 'vf');
  mkdirSync(join(root, 'opt', 'app', 'a'), { recursive: true }); mkdirSync(join(root, 'opt', 'app', 'b'), { recursive: true });
  writeFileSync(join(root, 'opt', 'app', 'a', 'VERSION'), '19.4.2\n', { mode: 0o755 });
  writeFileSync(join(root, 'opt', 'app', 'b', 'VERSION'), 'garbage\n');
  const rule = { product: 'App', files: [{ path: '/opt/app/*/VERSION', re: '^(\\d+\\.\\d+\\.\\d+)' }], fixedIn: ['19.5.1', '19.4.3', '18.11.13'] };
  const r = checkVersionFiles(rule, { root });
  assert.equal(r.length, 2);
  const a = r.find((x) => x.path.includes('/a/')), b = r.find((x) => x.path.includes('/b/'));
  assert.equal(a.status, 'EXPOSED'); assert.equal(a.version, '19.4.2'); assert.match(a.reason, /fixed in 19\.4\.3/);
  assert.equal(b.status, 'UNKNOWN');
  writeFileSync(join(root, 'opt', 'app', 'a', 'VERSION'), '19.4.3\n'); assert.equal(checkVersionFiles(rule, { root }).find((x) => x.path.includes('/a/')).status, 'SAFE');
  writeFileSync(join(root, 'opt', 'app', 'a', 'VERSION'), '17.2.0\n'); assert.match(checkVersionFiles(rule, { root }).find((x) => x.path.includes('/a/')).reason, /end of life/);
  assert.deepEqual(checkVersionFiles({ ...rule, files: [{ path: '/nowhere/VERSION', re: '(.*)' }] }, { root }), []);
});

test('site-packages: a dropped file is EXPOSED only when its hash matches; the same name otherwise is REVIEW; the bad release record is EXPOSED', () => {
  const env = join(dir, 'proj', '.venv'); const sp = join(env, 'lib', 'python3.12', 'site-packages');
  mkdirSync(sp, { recursive: true }); writeFileSync(join(env, 'pyvenv.cfg'), 'home = /usr/bin\n');
  const bad = 'import cook\n', h = createHash('sha256').update(bad).digest('hex');
  writeFileSync(join(sp, 'cook.pth'), bad); writeFileSync(join(sp, 'sitecustomize.py'), '# legit\n');
  mkdirSync(join(sp, 'evil-9.9.9.dist-info'));
  assert.ok(sitePackagesDirs({ roots: [join(dir, 'proj')], patterns: [], home: '' }).includes(sp), 'the venv under the root is found');
  const rule = { iocFiles: [{ name: 'cook.pth', sha256: h }, { name: 'sitecustomize.py', sha256: 'f'.repeat(64) }], distInfo: ['evil-9.9.9.dist-info'] };
  const r = checkSitePackages(rule, [sp]);
  assert.equal(r.find((x) => x.what === 'cook.pth').status, 'EXPOSED');
  assert.equal(r.find((x) => x.what === 'sitecustomize.py').status, 'REVIEW');
  assert.equal(r.find((x) => x.what === 'evil-9.9.9.dist-info').status, 'EXPOSED');
  assert.deepEqual(checkSitePackages(rule, [join(dir, 'nothing-here')]), []);
});

test('path patterns expand against the disk; image digests and temp markers are matched exactly', () => {
  const base = join(dir, 'exp'); mkdirSync(join(base, 'python3.11', 'site-packages'), { recursive: true }); mkdirSync(join(base, 'python3.12', 'site-packages'), { recursive: true });
  assert.equal(expand(`${base}/python3*/site-packages`).length, 2);
  assert.deepEqual(expand(`${base}/python2*/site-packages`), []);
  const d = 'sha256:' + 'a'.repeat(64);
  assert.equal(checkImages({ dockerDigests: [d] }, { docker: [`ghcr.io/x/y@${d}`, `ghcr.io/x/z@sha256:${'b'.repeat(64)}`] }).length, 1);
  const t = join(dir, 'tmpm'); mkdirSync(t, { recursive: true }); writeFileSync(join(t, '.pc_once_0123abcd'), '');
  assert.equal(tmpTraces('^\\.pc_once_[0-9a-f]+$', [t]).length, 1);
});

test('regression: a suffix never hides a version part (NaN compared as equal and read 19.4.2-ee as fixed)', () => {
  assert.equal(cmp('19.4.2-ee', '19.4.3'), -1); assert.equal(cmp('19.5.1-ee', '19.5.1'), 0); assert.equal(cmp('19.5.0-ce.0', '19.5.1'), -1);
  assert.equal(cmp('1.41.3.9313-c6bbc1b53', '1.41.3.9314'), -1); assert.equal(cmp('1.41.2.9200-c6bbc1b53', '1.41.2.9200'), 0);
  const g = { fixedIn: ['19.5.1', '19.4.3', '19.3.5'] };
  assert.equal(judgeVersion('19.4.2-ee', g).status, 'EXPOSED'); assert.equal(judgeVersion('19.4.3-ee', g).status, 'SAFE');
  assert.equal(judgeVersion('19.5.1-rc1-ee', g).status, 'EXPOSED', 'a pre-release of the fix is older than the fix');
  assert.equal(judgeVersion('v19.4.2', g).status, 'EXPOSED'); assert.equal(judgeVersion('unknown', g).status, 'UNKNOWN');
  assert.equal(judgeVersion('1.41.3.9313-xxx', { fixedIn: '1.41.3.9314' }).status, 'EXPOSED');
});

test('container images: an engine that refuses, hangs or floods is UNKNOWN, never "not running"; a stopped daemon is null', () => {
  const eng = (name, body) => { const p = join(dir, `eng-${name}`); writeFileSync(p, `#!/bin/sh\n${body}\n`); chmodSync(p, 0o755); return p; };
  const d = 'a'.repeat(64);
  assert.deepEqual(localImageDigests(eng('ok', `echo "x/y@sha256:${d}"; echo "<none>@<none>"`)), [`x/y@sha256:${d}`]);
  assert.equal(localImageDigests(eng('down', "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?' >&2; exit 1")), null);
  assert.match(localImageDigests(eng('perm', "echo 'permission denied while trying to connect to the Docker daemon socket' >&2; exit 1")).error, /permission denied/);
  assert.match(localImageDigests(eng('odd', "echo 'error: something else' >&2; exit 125")).error, /something else/);
  const big = localImageDigests(eng('big', `awk 'BEGIN{for(i=0;i<20000;i++) printf "r%07d@sha256:%064d\\n", i, 0}'; echo "x/y@sha256:${d}"`));
  assert.ok(Array.isArray(big) && big.includes(`x/y@sha256:${d}`), 'more than 1 MB of images is still read to the end');
  assert.deepEqual(localImageDigests(join(dir, 'no-such-engine')), []);
});

test('site-packages: a name nothing legitimate installs is EXPOSED by name alone; links are looked at once, never walked', () => {
  const root = join(dir, 'sp2'); const env = join(root, 'a', '.venv'); const sp = join(env, 'lib', 'python3.12', 'site-packages');
  mkdirSync(sp, { recursive: true }); writeFileSync(join(env, 'pyvenv.cfg'), 'x\n'); symlinkSync('lib', join(env, 'lib64'));
  writeFileSync(join(sp, 'cook.pth'), 'import cook  # a variant\n');
  const away = join(dir, 'sp2-away', 'env'); mkdirSync(join(away, 'lib', 'python3.12', 'site-packages'), { recursive: true }); writeFileSync(join(away, 'pyvenv.cfg'), 'x\n');
  symlinkSync(away, join(root, '.venv-link')); symlinkSync('.', join(root, 'loop'));
  const dirs = sitePackagesDirs({ roots: [root], patterns: [], home: '' });
  assert.equal(dirs.length, 2, 'lib64 -> lib is one folder; the linked venv is found; the loop is not followed');
  const r = checkSitePackages({ iocFiles: [{ name: 'cook.pth', sha256: ['0'.repeat(64), '1'.repeat(64)], nameAlone: 'EXPOSED' }] }, dirs);
  assert.equal(r.length, 1); assert.equal(r[0].status, 'EXPOSED'); assert.match(r[0].reason, /variant/);
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

test('WordPress: compromised Rank Math PRO, old UpdraftPlus, the indicator, and new plugin folders', () => {
  const site = join(dir, 'www', 'shop'); const pl = join(site, 'wp-content', 'plugins');
  mkdirSync(join(site, 'wp-includes'), { recursive: true }); writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  const plugin = (name, file, version, extra = '') => { mkdirSync(join(pl, name), { recursive: true }); writeFileSync(join(pl, name, file), `<?php\n/**\n * Plugin Name: ${name}\n * Version: ${version}\n */\n${extra}`); };
  plugin('seo-by-rank-math-pro', 'rank-math-pro.php', '3.0.123', '$u = "https://rank1cdn.example/x";');
  plugin('updraftplus', 'updraftplus.php', '1.26.11');
  assert.deepEqual(wordpressUnder([join(dir, 'www')]), [site]);
  const rules = [
    { plugin: 'seo-by-rank-math-pro', mainFile: 'rank-math-pro.php', bad: ['3.0.123'], indicator: 'rank1cdn', fix: 'restore' },
    { plugin: 'updraftplus', mainFile: 'updraftplus.php', fixedIn: '1.26.13', fixedInMajor: { 2: '2.26.13' }, fix: 'update' },
  ];
  const f = checkSite(site, rules, '2000-01-01T00:00:00Z');
  assert.equal(f.filter((x) => x.status === 'EXPOSED' && x.what.startsWith('seo-by-rank-math-pro')).length, 2, 'the version and the indicator');
  assert.ok(f.some((x) => x.status === 'EXPOSED' && x.what === 'updraftplus 1.26.11'));
  assert.ok(f.some((x) => x.status === 'REVIEW' && x.what === 'plugin folder updraftplus'));
  plugin('updraftplus', 'updraftplus.php', '2.26.13');
  assert.ok(checkSite(site, rules).some((x) => x.status === 'SAFE' && x.what === 'updraftplus 2.26.13'), 'premium line fixed in 2.26.13');
});

test('PHP-style fixes per release line: patched, unpatched, and end of life', () => {
  const bin = join(dir, 'phpbin'); mkdirSync(bin, { recursive: true });
  const php = (v) => writeFileSync(join(bin, 'php'), `#!/bin/sh\necho "PHP ${v} (cli)"\n`, { mode: 0o755 });
  const rule = { binary: 'php', versionArgs: ['-v'], versionRe: 'PHP (\\d+\\.\\d+\\.\\d+)', fixedIn: ['8.2.40', '8.3.40', '8.4.30', '8.5.15'] };
  php('8.3.40'); assert.equal(checkBinary(rule, bin).status, 'SAFE');
  php('8.3.39'); assert.match(checkBinary(rule, bin).reason, /fixed in 8\.3\.40/);
  php('7.4.33'); assert.match(checkBinary(rule, bin).reason, /end of life/);
});

test('containers: each running one is checked from inside, with a normal-site and a self-signed control', async () => {
  const bin = join(dir, 'engine'); mkdirSync(bin, { recursive: true });
  // A stand-in for `docker`: ps lists four containers; exec answers as the tool inside each would ($7 is the URL).
  writeFileSync(join(bin, 'docker'), `#!/bin/sh
if [ "$1" = ps ]; then printf 'a1\\told-bundle\\tdebian:11\\nb2\\tdistroless\\tgcr.io/app\\nc3\\tno-verify\\talpine\\nd4\\tfixed\\tdebian:13\\n'; exit 0; fi
[ "$1" = exec ] || exit 1
case "$2" in
  a1) echo tool=curl; case "$7" in *self-signed*) exit 1;; *) exit 0;; esac;;
  b2) exit 126;;
  c3) echo tool=wget; exit 0;;
  d4) echo tool=curl; case "$7" in *self-signed*|*-emudhra.*) exit 1;; *) exit 0;; esac;;
esac
exit 1
`, { mode: 0o755 });
  const engine = join(bin, 'docker');
  const list = listContainers(engine);
  assert.deepEqual(list.map((x) => x.name), ['old-bundle', 'distroless', 'no-verify', 'fixed']);
  const canaries = [{ id: 'dv-g3b', url: 'https://dv-g3b-emudhra.we-have-a-problem.com/', up: true }];
  const opts = { controlUrl: 'https://emudhra.we-have-a-problem.com/', timeoutMs: 2000 };
  const [old, none, noverify, fixed] = await Promise.all(list.map((ct) => checkContainer(engine, ct, canaries, opts)));
  assert.equal(old.status, 'EXPOSED'); assert.equal(old.tool, 'curl'); assert.deepEqual(old.trusted, ['dv-g3b']);
  assert.equal(none.status, 'UNKNOWN'); assert.match(none.reason, /no shell, curl, python3 or wget/);
  assert.equal(noverify.status, 'UNKNOWN'); assert.match(noverify.reason, /self-signed/);
  assert.equal(fixed.status, 'SAFE');
  assert.equal(await checkContainer(engine, list[0], [{ ...canaries[0], up: false }], opts).then((r) => r.status), 'UNKNOWN', 'no test host up is never SAFE');
  writeFileSync(join(bin, 'down'), '#!/bin/sh\necho "Cannot connect to the Docker daemon" >&2; exit 1\n', { mode: 0o755 });
  assert.equal(listContainers(join(bin, 'down')), null, 'a stopped daemon means no running containers, not a failure');
});

test('files are read only when they are regular and small, checked and read through one open file', () => {
  const d = join(dir, 'files'); mkdirSync(d, { recursive: true });
  writeFileSync(join(d, 'small.txt'), 'abc'); writeFileSync(join(d, 'big.txt'), 'x'.repeat(2048));
  assert.equal(readCapped(join(d, 'small.txt'), 1024).toString(), 'abc');
  assert.equal(readCapped(join(d, 'big.txt'), 1024), null, 'over the cap');
  assert.equal(readCapped(d, 1024), null, 'a directory');
  assert.equal(readCapped(join(d, 'missing.txt'), 1024), null, 'missing');
  execFileSync('mkfifo', [join(d, 'pipe')]);
  assert.equal(readCapped(join(d, 'pipe'), 1024), null, 'a pipe returns at once instead of waiting for a writer');
});

test('WordPress: a plugin whose version cannot be read is UNKNOWN, never SAFE', () => {
  const site = join(dir, 'www2', 'blog'); const pl = join(site, 'wp-content', 'plugins', 'updraftplus');
  mkdirSync(join(site, 'wp-includes'), { recursive: true }); writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php');
  mkdirSync(pl, { recursive: true }); writeFileSync(join(pl, 'updraftplus.php'), '<?php\n/* Plugin Name: UpdraftPlus (no version header) */\n');
  const f = checkSite(site, [{ plugin: 'updraftplus', mainFile: 'updraftplus.php', fixedIn: '1.26.13', fix: 'update' }]);
  assert.equal(f.length, 1); assert.equal(f[0].status, 'UNKNOWN'); assert.match(f[0].reason, /could not be checked/);
});

test('PHP 21 Oct 2026: the real fixed versions per branch, and end of life below 8.2', () => {
  const rule = JSON.parse(readFileSync(new URL('../lib/incidents/php-2026-10.json', import.meta.url), 'utf8')).binaries[0];
  const bin = join(dir, 'phpreal'); mkdirSync(bin, { recursive: true });
  const php = (v) => writeFileSync(join(bin, 'php'), `#!/bin/sh\necho "PHP ${v} (cli)"\n`, { mode: 0o755 });
  php('8.4.27'); assert.equal(checkBinary(rule, bin).status, 'SAFE');
  php('8.5.12'); assert.equal(checkBinary(rule, bin).status, 'SAFE');
  php('8.4.26'); assert.equal(checkBinary(rule, bin).status, 'EXPOSED');
  php('8.2.34'); assert.match(checkBinary(rule, bin).reason, /fixed in 8\.2\.35/);
  php('8.1.31'); assert.match(checkBinary(rule, bin).reason, /end of life/);
});

test('a runtime that refuses the compromised keys even with their roots forced in, but opens a normal site, is SAFE', async () => {
  const bin = join(dir, 'blockcurl'); mkdirSync(bin, { recursive: true });
  // a stand-in curl that blocks the bad keys outright: refuses with --cacert (the forced roots), opens the control site
  writeFileSync(join(bin, 'curl'), '#!/bin/sh\nfor a in "$@"; do case "$a" in --cacert) exit 60;; esac; done\nfor a in "$@"; do last="$a"; done\ncase "$last" in *control*) exit 0;; *) exit 60;; esac\n', { mode: 0o755 });
  const rt = { kind: 'curl', bin: join(bin, 'curl') };
  const c1 = [{ id: 'x', url: 'https://canary.invalid/', up: true }];
  const r = await check(rt, c1, { rootsPem: badCa, controlUrl: 'https://control.invalid/', timeoutMs: 2000 });
  assert.equal(r.status, 'SAFE'); assert.match(r.note, /blocks the compromised keys/);
  const r2 = await check(rt, c1, { rootsPem: badCa, timeoutMs: 2000 });
  assert.equal(r2.status, 'UNKNOWN', 'without a control site it still cannot tell');
});
