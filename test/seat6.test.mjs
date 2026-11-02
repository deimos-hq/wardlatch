// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The second read of round 6, 2 Nov 2026 (seat 6). Each test says what should happen. Every one marked DEFECT read SAFE,
// or a false alarm, on 0.1.11 at 50c741c, with its control passing. No emudhra incident runs here, and nothing connects.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, chmodSync, symlinkSync, mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const WL = fileURLToPath(new URL('..', import.meta.url)), RIG = mkdtempSync(join(tmpdir(), 'wl-seat6-'));
const BIN = join(WL, 'bin', 'wardlatch.mjs');
const lib = (f) => import(pathToFileURL(join(WL, 'lib', f)).href);
const box = mkdtempSync(join(RIG, 't-'));
const asRoot = process.getuid?.() === 0;
const mac = process.platform !== 'darwin';
const unlock = [];
after(() => { for (const p of unlock) { try { chmodSync(p, 0o755); } catch { /* */ } } });
let n = 0;
const fresh = (name) => { const d = join(box, `${String(++n).padStart(2, '0')}-${name}`); mkdirSync(d, { recursive: true }); return d; };
const put = (p, body = '') => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); return p; };
const lock = (p) => { chmodSync(p, 0); unlock.push(p); };
const unlockNow = (p) => chmodSync(p, 0o755);
const cli = (args, { home, env = {}, nodeArgs = [] } = {}) => {
  const h = home ?? fresh('home');
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, '--json', ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 60000, env: { HOME: h, PATH: '/usr/bin:/bin', LANG: 'C', TMPDIR: join(RIG, 'tmp'), ...env } });
  assert.ok(r.stdout, `CONTROL no output (exit ${r.status}): ${r.stderr.slice(0, 300)}`);
  return { code: r.status, rows: JSON.parse(r.stdout).results };
};
const brief = (r) => r.rows.map((x) => `${x.status}:${x.kind}:${String(x.what ?? x.path ?? x.file ?? x.dir ?? '').slice(-40)}`).join(' | ');
const has = (r, s) => r.rows.some((x) => x.status === s);
const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];
const WP = ['--incident', 'wordpress-plugins-2026-10', '--no-containers'];
const WF = ['--incident', 'github-actions-2026-10', '--no-containers'];
const KEYS = ['--incident', 'committed-keys-2026-10', '--no-containers'];
const HDR = ['--incident', 'identity-headers-2026-10', '--no-containers'];

const venv = (d, drop = {}) => {
  put(join(d, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(d, 'bin', 'python'), '');
  const sp = join(d, 'lib', 'python3.12', 'site-packages'); mkdirSync(sp, { recursive: true });
  for (const [f, body] of Object.entries(drop)) put(join(sp, f), body);
  return sp;
};
const stealer = { 'litellm-1.107.0.dist-info/METADATA': 'Name: litellm\nVersion: 1.107.0\n', 'cook.pth': 'import cook\n' };
const site = (d) => { put(join(d, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";\n'); put(join(d, 'wp-config.php'), "<?php\ndefine('DB_NAME', 'x');\n"); mkdirSync(join(d, 'wp-content', 'plugins'), { recursive: true }); return d; };
const rankMath = (plugins, name = 'seo-by-rank-math-pro', version = '3.0.123') => put(join(plugins, name, 'rank-math-pro.php'), `<?php\n/*\n * Plugin Name: Rank Math PRO\n * Version: ${version}\n */\n`);
const gitIn = (cwd, ...args) => { const r = spawnSync('/usr/bin/git', args, { cwd, encoding: 'utf8', env: { HOME: join(RIG, 'tmp'), PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' } }); assert.equal(r.status, 0, `CONTROL git ${args[0]}: ${r.stderr}`); return r.stdout; };
const repoWith = (d, files) => { mkdirSync(d, { recursive: true }); gitIn(d, 'init', '-q'); for (const [f, b] of Object.entries(files)) put(join(d, f), b); gitIn(d, 'add', '-A'); gitIn(d, 'commit', '-q', '-m', 'x'); return d; };
const identity = (home, more = '') => put(join(home, '.gitconfig'), `[user]\n\tname = Ada Example\n\temail = ada@example.invalid\n${more}`);

// ---- item 4: seat 5's leftovers --------------------------------------------------------------------------------------
test('I4-rule sitecustomize.py that is not the published file: the docstring at lib/installs.mjs:236 says REVIEW', () => {
  const root = fresh('i4-rule');
  venv(join(root, 'ctl', '.venv'), stealer);
  const ctl = cli([...LITELLM, '--paths', join(root, 'ctl')]);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL ${brief(ctl)}`);
  const body = '# same stealer, one byte changed\nimport os\n';
  venv(join(root, 'var', '.venv'), { 'sitecustomize.py': body });
  const r = cli([...LITELLM, '--paths', join(root, 'var')]);
  assert.ok(r.rows.some((x) => x.what === 'sitecustomize.py'), `DEFECT sitecustomize.py variant has no row, exit ${r.code}: ${brief(r)}`);
});

test('I4-H1 Apple python: a stealer in /Library/Python/3.9/site-packages (where `sudo pip3` installs) is looked at', { skip: mac }, () => {
  const home = fresh('i4-h1-home'); const rig = fresh('i4-h1');
  const run = (from, to) => {
    const log = join(rig, `${n}-log.txt`); put(log);
    const r = cli([...LITELLM, '--paths', fresh('i4-h1-empty')], { home, env: { S6_FROM: from, S6_TO: to, S6_LOG: log }, nodeArgs: ['--require', join(dirname(new URL(import.meta.url).pathname), 'support', 'map-library.cjs')] });
    return { r, opened: readFileSync(log, 'utf8').split('\n').filter(Boolean) };
  };
  // the control: the same shim and the same plant in a framework Python, a place SITE_PATTERNS names
  const fw = join(rig, 'fw'); put(join(fw, 'Versions/3.13/lib/python3.13/site-packages/cook.pth'), 'import cook\n');
  const c = run('/Library/Frameworks/Python.framework', fw);
  assert.ok(has(c.r, 'EXPOSED'), `CONTROL the shim works on a named place: ${brief(c.r)}`);
  assert.ok(c.opened.length > 0, 'CONTROL shim saw no opens');
  const lp = join(rig, 'lp'); put(join(lp, '3.9/site-packages/cook.pth'), 'import cook\n'); put(join(lp, '3.9/site-packages/litellm-1.107.0.dist-info/METADATA'), 'x\n');
  const p = run('/Library/Python', lp);
  assert.ok(p.opened.length > 0 && has(p.r, 'EXPOSED'), `DEFECT ${p.opened.length} opens under /Library/Python, exit ${p.r.code}: ${brief(p.r)}`);
});

test('I4-H1b Apple python: a stealer in the Command Line Tools python site folder is looked at', { skip: mac || !existsSync('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages') }, () => {
  const real = '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework';
    const rig = fresh('i4-h1b'); const to = join(rig, 'clt'); put(join(to, 'Versions/3.9/lib/python3.9/site-packages/cook.pth'), 'import cook\n');
  const log = join(rig, 'log.txt'); put(log);
  const r = cli([...LITELLM, '--paths', fresh('i4-h1b-empty')], { env: { S6_FROM: real, S6_TO: to, S6_LOG: log }, nodeArgs: ['--require', join(dirname(new URL(import.meta.url).pathname), 'support', 'map-library.cjs')] });
  const opened = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  assert.ok(opened.length > 0 && has(r, 'EXPOSED'), `DEFECT ${opened.length} opens, exit ${r.code}: ${brief(r)}`);
});

test('I4-H2 a venv with only bin/python3 is found, and a FIFO in place of its certifi bundle is a gap', async () => {
  const { discover } = await lib('discover.mjs');
  const root = fresh('i4-h2');
  const a = join(root, 'p3'); put(join(a, 'pyvenv.cfg'), 'x\n'); put(join(a, 'bin', 'python3'), ''); put(join(a, 'lib/python3.12/site-packages/certifi/cacert.pem'), 'pem\n');
  const b = join(root, 'fifo'); put(join(b, 'pyvenv.cfg'), 'x\n'); put(join(b, 'bin', 'python'), ''); mkdirSync(join(b, 'lib/python3.12/site-packages/certifi'), { recursive: true });
  assert.equal(spawnSync('/usr/bin/mkfifo', [join(b, 'lib/python3.12/site-packages/certifi/cacert.pem')]).status, 0, 'CONTROL mkfifo');
  const denied = [], found = [], notRun = [], untested = [], links = [], deep = [];
  const rows = discover({ roots: [root], pathEnv: '/usr/bin:/bin', denied, found, notRun, untested, links, deep });
  assert.ok(rows.some((x) => x.env === a), `bin/python3-only venv has no row: ${JSON.stringify(rows.map((x) => x.env ?? x.kind))}`);
  assert.ok(found.some((x) => x.startsWith(b)), `FIFO bundle not reported: ${JSON.stringify(found)}`);
});

// ---- item 6: second read ---------------------------------------------------------------------------------------------
const lockedLink = (root, plant) => {
  const outer = fresh('lockedlink-outer'); const inner = join(outer, 'locked', 'inner'); mkdirSync(inner, { recursive: true }); plant(inner);
  symlinkSync(inner, join(root, 'proj'));
  return { locked: join(outer, 'locked') };
};
test('R1 installs walk: a link to a folder this run cannot reach is reported, not dropped', { skip: asRoot }, () => {
  const root = fresh('r1'); const { locked } = lockedLink(root, (d) => venv(join(d, 'app', '.venv'), stealer));
  const ctl = cli([...LITELLM, '--paths', root]);
  assert.ok(ctl.code !== 0 && !has(ctl, 'SAFE'), `CONTROL reachable link: ${brief(ctl)}`);
  lock(locked);
  const r = cli([...LITELLM, '--paths', root]);
  unlockNow(locked);
  assert.ok(r.code !== 0 && !has(r, 'SAFE'), `DEFECT exit ${r.code}: ${brief(r)}`);
});
test('R1b repository walk: same, a repository behind a link to a locked folder', { skip: asRoot }, () => {
  const root = fresh('r1b'); const { locked } = lockedLink(root, (d) => repoWith(join(d, 'repo'), { '.github/workflows/x.yml': 'on: push\n' }));
  const ctl = cli([...WF, '--paths', root]);
  assert.ok(ctl.code !== 0 && !has(ctl, 'SAFE'), `CONTROL reachable link: ${brief(ctl)}`);
  lock(locked);
  const r = cli([...WF, '--paths', root]);
  unlockNow(locked);
  assert.ok(r.code !== 0 && !has(r, 'SAFE'), `DEFECT exit ${r.code}: ${brief(r)}`);
});
test('R1c WordPress walk: same, a site behind a link to a locked folder', { skip: asRoot }, () => {
  const root = fresh('r1c'); const { locked } = lockedLink(root, (d) => { const s = site(join(d, 'site')); rankMath(join(s, 'wp-content', 'plugins')); });
  const ctl = cli([...WP, '--paths', root]);
  assert.ok(ctl.code !== 0 && !has(ctl, 'SAFE'), `CONTROL reachable link: ${brief(ctl)}`);
  lock(locked);
  const r = cli([...WP, '--paths', root]);
  unlockNow(locked);
  assert.ok(r.code !== 0 && !has(r, 'SAFE'), `DEFECT exit ${r.code}: ${brief(r)}`);
});
test('R1d trust walk (discover direct): same, a venv behind a link to a locked folder', { skip: asRoot }, async () => {
  const { discover } = await lib('discover.mjs');
  const root = fresh('r1d'); const { locked } = lockedLink(root, (d) => venv(join(d, 'app', '.venv'), { 'certifi/cacert.pem': 'pem\n' }));
  const go = () => { const denied = [], found = [], notRun = [], untested = [], links = [], deep = []; discover({ roots: [root], pathEnv: '/usr/bin:/bin', denied, found, notRun, untested, links, deep }); return [...denied, ...found, ...links, ...untested.map((u) => u.label)]; };
  assert.ok(go().length > 0, 'CONTROL reachable link is reported');
  lock(locked);
  const g = go();
  unlockNow(locked);
  assert.ok(g.length > 0, 'DEFECT no list holds the link');
});

test('R2 quick look: a locked folder is UNKNOWN whatever it is called (AUDIT-5: "no name decides this")', { skip: asRoot }, () => {
  const go = (name) => {
    const home = fresh('r2-home'); const d = join(home, 'Documents', name); venv(join(d, 'app', '.venv'), stealer); lock(d);
    const r = cli([...LITELLM, '--paths', fresh('r2-empty')], { home }); unlockNow(d); return r;
  };
  const ctl = go('work');
  assert.ok(ctl.code === 2 && !has(ctl, 'SAFE'), `CONTROL a locked folder called work: ${brief(ctl)}`);
  const bad = [];
  for (const name of ['clients.photoslibrary', 'Photo Booth Library', '.Trash']) {
    const r = go(name);
    if (!(r.code === 2 && !has(r, 'SAFE'))) bad.push(`${name} exit ${r.code}`);
  }
  assert.deepEqual(bad, [], `DEFECT ${bad.join('; ')}`);
});

test('R3 temp tree: a folder above T that this user cannot list is a gap (the fix covers T itself)', { skip: asRoot }, async () => {
  const { tempDirs } = await lib('binaries.mjs');
  const root = fresh('r3'); const t = join(root, 'aa', 'bb', 'T'); mkdirSync(t, { recursive: true });
  assert.ok(tempDirs('darwin', root).includes(t), 'CONTROL a readable T is listed');
  lock(t);
  assert.ok(tempDirs('darwin', root).includes(t), 'CONTROL the fix: a locked T stays listed');
  unlockNow(t);
  const bad = [];
  for (const up of [join(root, 'aa', 'bb'), join(root, 'aa'), root]) {
    lock(up);
    const has2 = tempDirs('darwin', root).some((x) => x === t || x === up || x.startsWith(root));
    unlockNow(up);
    if (!has2) bad.push(up.slice(root.length) || '(the top folder)');
  }
  assert.deepEqual(bad, [], `DEFECT locked and absent from the list, so no row can follow: ${bad.join(', ')}`);
});

test('R3b the same, with a real marker: a trace is found through tmpTraces, and locking the level above T loses it with no gap', { skip: asRoot }, async () => {
  const { tempDirs, tmpTraces } = await lib('binaries.mjs');
  const root = fresh('r3b'); const t = join(root, 'aa', 'bb', 'T'); put(join(t, 'remote_code_loader.lock'), '');
  const re = '^remote_code_loader\\.lock$';
  const go = () => { const denied = []; const traces = tmpTraces(re, tempDirs('darwin', root).filter((x) => x.startsWith(root)), denied); return { traces, denied }; };
  assert.equal(go().traces.length, 1, 'CONTROL the trace is found');
  lock(join(root, 'aa'));
  const g = go();
  unlockNow(join(root, 'aa'));
  assert.ok(g.traces.length || g.denied.length, 'DEFECT no trace and no gap');
});

test('R4 WordPress: a leftover in <core>/content/plugins beside a stock site is checked, like <core>/backup/plugins', () => {
  const a = site(join(fresh('r4-ctl'), 'site')); rankMath(join(a, 'backup', 'plugins'));
  const ctl = cli([...WP, '--paths', a]);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL backup/plugins: ${brief(ctl)}`);
  const b = site(join(fresh('r4'), 'site')); rankMath(join(b, 'content', 'plugins'));
  const r = cli([...WP, '--paths', b]);
  assert.ok(has(r, 'EXPOSED') || has(r, 'UNKNOWN'), `DEFECT stock wp-config, exit ${r.code}: ${brief(r)}`);
});

test('R5 WordPress: a copy macOS or a person named with a space is that plugin too', () => {
  const a = site(join(fresh('r5-ctl'), 'site')); rankMath(join(a, 'backup', 'plugins'), 'seo-by-rank-math-pro-old');
  const ctl = cli([...WP, '--paths', a]);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL -old suffix: ${brief(ctl)}`);
  const bad = [];
  for (const name of ['seo-by-rank-math-pro copy', 'seo-by-rank-math-pro 2', 'old-seo-by-rank-math-pro']) {
    const b = site(join(fresh('r5'), 'site')); rankMath(join(b, 'backup', 'plugins'), name);
    const r = cli([...WP, '--paths', b]);
    if (!has(r, 'EXPOSED')) bad.push(`backup/plugins/${name}: exit ${r.code} ${brief(r)}`);
  }
  // the same in the site's live plugins folder: what the "added since" line says there
  const c = site(join(fresh('r5-live'), 'site')); rankMath(join(c, 'wp-content', 'plugins'), 'seo-by-rank-math-pro copy');
  const live = cli([...WP, '--paths', c]);
  if (!has(live, 'EXPOSED')) bad.push(`wp-content/plugins/...copy: exit ${live.code} ${brief(live)}`);
  assert.deepEqual(bad, [], `DEFECT ${bad.join(' ;; ')}`);
});

test('R6 WordPress: a copy with its main file gone still has its indicator searched, as the exact name does (R2-N7)', () => {
  const a = fresh('r6-ctl'); put(join(a, 'plugins.bak', 'seo-by-rank-math-pro', 'includes', 'x.php'), '<?php // rank1cdn\n');
  const ctl = cli([...WP, '--paths', a]);
  assert.ok(ctl.rows.some((x) => x.status === 'EXPOSED'), `CONTROL exact name, no main file: ${brief(ctl)}`);
  const b = fresh('r6'); put(join(b, 'plugins.bak', 'seo-by-rank-math-pro-3.0.123', 'includes', 'x.php'), '<?php // rank1cdn\n');
  const r = cli([...WP, '--paths', b]);
  assert.ok(has(r, 'EXPOSED') || has(r, 'UNKNOWN'), `DEFECT exit ${r.code}: ${brief(r)}`);
});

test('R7 WordPress: --paths naming a copy of the plugin itself is checked, as the exact name is', () => {
  const a = fresh('r7-ctl'); rankMath(a);
  const ctl = cli([...WP, '--paths', join(a, 'seo-by-rank-math-pro')]);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL exact name: ${brief(ctl)}`);
  const b = fresh('r7'); rankMath(b, 'seo-by-rank-math-pro-3.0.123');
  const r = cli([...WP, '--paths', join(b, 'seo-by-rank-math-pro-3.0.123')]);
  assert.ok(has(r, 'EXPOSED') || has(r, 'UNKNOWN'), `DEFECT exit ${r.code}: ${brief(r)}`);
});

test('R8 TOML: --header in an inline table is read, as the same args are in a table of their own (seat 5 F11)', () => {
  const h1 = fresh('r8-ctl'); identity(h1); put(join(h1, '.codex', 'config.toml'), '[mcp_servers.x]\nargs = ["mcp-remote", "https://x.example", "--header", "X-User: ada@example.invalid"]\n');
  const ctl = cli([...HDR], { home: h1 });
  assert.ok(has(ctl, 'REVIEW'), `CONTROL own table: ${brief(ctl)}`);
  const h2 = fresh('r8'); identity(h2); put(join(h2, '.codex', 'config.toml'), '[mcp_servers]\nx = { command = "npx", args = ["mcp-remote", "https://x.example", "--header", "X-User: ada@example.invalid"] }\n');
  const r = cli([...HDR], { home: h2 });
  assert.ok(has(r, 'REVIEW'), `DEFECT exit ${r.code}: ${brief(r)}`);
});

test('R9 git config: a value continued by a backslash at the very end of the file, which git reads', () => {
  const body = '[http]\n\textraHeader = X-User: ada@example.invalid\\';
  const h1 = fresh('r9-ctl'); identity(h1, `${body}\n`);
  const ctl = cli([...HDR], { home: h1 });
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL with a final newline: ${brief(ctl)}`);
  const h2 = fresh('r9'); identity(h2, body);
  const g = spawnSync('/usr/bin/git', ['config', '--file', join(h2, '.gitconfig'), '--get', 'http.extraheader'], { encoding: 'utf8' });
  assert.match(g.stdout, /ada@example\.invalid/, `CONTROL git itself reads it (git: ${g.status} ${g.stderr})`);
  const r = cli([...HDR], { home: h2 });
  assert.ok(has(r, 'EXPOSED'), `DEFECT git reads the header, exit ${r.code}: ${brief(r)}`);
});

test('R10 a FIFO at .mcp.json in a project with no .git is UNKNOWN, as it is in a project with one (seat 5 F14)', () => {
  const home = fresh('r10-home'); identity(home);
  const a = fresh('r10-ctl'); repoWith(join(a, 'p'), { 'a.txt': 'x\n' });
  assert.equal(spawnSync('/usr/bin/mkfifo', [join(a, 'p', '.mcp.json')]).status, 0);
  const ctl = cli([...HDR, '--paths', a], { home });
  assert.ok(has(ctl, 'UNKNOWN'), `CONTROL with .git: ${brief(ctl)}`);
  const b = fresh('r10'); mkdirSync(join(b, 'p'));
  assert.equal(spawnSync('/usr/bin/mkfifo', [join(b, 'p', '.mcp.json')]).status, 0);
  const r = cli([...HDR, '--paths', b], { home });
  assert.ok(has(r, 'UNKNOWN'), `DEFECT exit ${r.code}: ${brief(r)}`);
});

test('R11 a bare repository with a workflow in the window is a REVIEW line (seat 5 F12: the fix holds)', () => {
  const root = fresh('r11'); const src = repoWith(join(root, 'src'), { '.github/workflows/x.yml': 'on: push\n' });
  const out = join(fresh('r11-bare'), 'b.git'); gitIn(root, 'clone', '-q', '--bare', src, out);
  const r = cli([...WF, '--paths', dirname(out)]);
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.file === '.github/workflows/x.yml'), `exit ${r.code}: ${brief(r)}`);
});

test('R12 an ENCRYPTED PKCS #8 key with a long-form outer length, which LibreSSL reads, leaves a row (lib/secrets.mjs:282 admits it does not)', () => {
  const d = fresh('r12');
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: 'seat6-not-a-secret' });
  assert.equal(key[1], 0x82, 'CONTROL shape');
  const body = key.subarray(4);
  const long = Buffer.concat([Buffer.from([0x30, 0x85, 0, 0, 0, body.length >> 8, body.length & 255]), body]);
  const f = put(join(d, 'long.der'), long);
  const o = spawnSync('/usr/bin/openssl', ['pkcs8', '-inform', 'DER', '-in', f, '-passin', 'pass:seat6-not-a-secret', '-out', '/dev/null'], { encoding: 'utf8' });
  if (process.platform === 'darwin') assert.equal(o.status, 0, `CONTROL LibreSSL reads the rewritten key: ${o.stderr.slice(0, 200)}`);
  const ctl = cli([...KEYS, '--paths', repoWith(join(d, 'ctl'), { 'minimal.der': key })]);
  assert.ok(has(ctl, 'REVIEW'), `CONTROL minimal form: ${brief(ctl)}`);
  const r = cli([...KEYS, '--paths', repoWith(join(d, 'probe'), { 'long.der': long })]);
  assert.ok(!has(r, 'SAFE'), `DEFECT exit ${r.code}: ${brief(r)}`);
});

test('R13 not a false SAFE, a false alarm: a public key in PKCS #1 DER stays quiet, as the comment at lib/secrets.mjs:279 says public keys do', () => {
  const d = fresh('r13');
  const pub = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'pkcs1', format: 'der' });
  const r = cli([...KEYS, '--paths', repoWith(join(d, 'r'), { 'pub.der': pub })]);
  assert.ok(!has(r, 'UNKNOWN') && r.code === 0, `DEFECT exit ${r.code}: ${brief(r)}`);
});
