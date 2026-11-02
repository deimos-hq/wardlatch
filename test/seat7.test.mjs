// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The review of 0.1.12's first draft, 2 Nov 2026 (seat 7). Each test marked DEFECT read SAFE on that draft, with its control
// passing; REFUTED ones held. Keys are made here, used, never printed. Nothing connects.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, readFileSync, mkdirSync, symlinkSync, chmodSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { fresh, put, cli, NEW, KEYS, WP, LITELLM, HDR, repoWith, gitIn, brief, has, safeOnly, old, tlv, kids } from './support/seat7-lib.mjs';
const O = '/usr/bin/openssl', PW = 'seat7-not-a-secret';
const ssl = (args) => spawnSync(O, args, { encoding: 'buffer' });
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const p1 = rsa.privateKey.export({ type: 'pkcs1', format: 'der' });
const p8 = rsa.privateKey.export({ type: 'pkcs8', format: 'der' });
const enc = rsa.privateKey.export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: PW });
const sec1 = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'sec1', format: 'der' });
const V2 = Buffer.from([2, 2, 1, 0]);
const swapV = (der, v) => tlv(0x30, Buffer.concat([v, ...kids(der).slice(1)]));
const repoKey = (der, name = 'key.der') => repoWith(join(fresh('r'), 'r'), { [name]: der });
const key = (tree, der, name) => cli(tree, [...KEYS, '--paths', repoKey(der, name)]);
const file = (der) => put(join(fresh('k'), 'k.bin'), der);
const undo = []; const lock = (p, m = 0) => { chmodSync(p, m); undo.push(p); };
after(() => { for (const p of undo) { try { chmodSync(p, 0o755); } catch { /* */ } } });

// ---- D1 ------------------------------------------------------------------------------------------------------------
test('D1 REGRESSION a working RSA private key with a two-byte version reads SAFE (0.1.11: UNKNOWN)', () => {
  const ctl = key(NEW, p1);
  assert.ok(has(ctl, 'REVIEW'), `CONTROL the same key as made: ${brief(ctl)}`);
  const bad = swapV(p1, V2), f = file(bad);
  assert.equal(ssl(['rsa', '-inform', 'DER', '-in', f, '-noout']).status, 0, 'CONTROL LibreSSL loads it');
  const d = fresh('sig'), msg = put(join(d, 'm'), 'seat 7\n'), pub = put(join(d, 'p.pem'), rsa.publicKey.export({ type: 'spki', format: 'pem' })), pem = join(d, 'k.pem');
  writeFileSync(pem, ssl(['rsa', '-inform', 'DER', '-in', f]).stdout);
  assert.equal(ssl(['dgst', '-sha256', '-sign', pem, '-out', join(d, 's'), msg]).status, 0, 'CONTROL it signs');
  assert.equal(ssl(['dgst', '-sha256', '-verify', pub, '-signature', join(d, 's'), msg]).status, 0, 'CONTROL the signature verifies against the original public key');
  rmSync(pem);
  const r = key(NEW, bad);
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D1b REGRESSION the same, PKCS #8', () => {
  assert.ok(has(key(NEW, p8), 'REVIEW'), 'CONTROL as made');
  const bad = swapV(p8, V2);
  assert.equal(ssl(['pkcs8', '-inform', 'DER', '-nocrypt', '-in', file(bad), '-out', '/dev/null']).status, 0, 'CONTROL LibreSSL loads it');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D1c REGRESSION the same, SEC1 EC', () => {
  assert.ok(has(key(NEW, sec1), 'REVIEW'), 'CONTROL as made');
  const bad = swapV(sec1, V2);
  assert.equal(ssl(['ec', '-inform', 'DER', '-in', file(bad), '-noout']).status, 0, 'CONTROL LibreSSL loads it');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D1d REGRESSION the same, PKCS #12 with a two-byte version: the key comes out with the password', () => {
  const d = fresh('p12'), kp = put(join(d, 'k.pem'), rsa.privateKey.export({ type: 'pkcs8', format: 'pem' })), c = join(d, 'c.pem'), p = join(d, 'k.p12');
  assert.equal(ssl(['req', '-new', '-x509', '-key', kp, '-subj', '/CN=seat7', '-days', '2', '-out', c]).status, 0, 'CONTROL cert');
  assert.equal(ssl(['pkcs12', '-export', '-inkey', kp, '-in', c, '-passout', `pass:${PW}`, '-out', p]).status, 0, 'CONTROL p12');
  const made = readFileSync(p); rmSync(kp);
  assert.ok(has(key(NEW, made), 'REVIEW'), 'CONTROL as made');
  const bad = tlv(0x30, Buffer.concat([Buffer.from([2, 2, 1, 3]), ...kids(made).slice(1)]));
  assert.equal(ssl(['pkcs12', '-in', file(bad), '-nodes', '-passin', `pass:${PW}`, '-out', '/dev/null']).status, 0, 'CONTROL LibreSSL reads the key out');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D1e REGRESSION the same bytes under a name that says text are UNKNOWN: the file name decides, and deleted files too', () => {
  const bad = swapV(p1, V2);
  const ctl = key(NEW, bad, 'server.pem');
  assert.ok(!safeOnly(ctl), `CONTROL server.pem: ${brief(ctl)}`);
  const d = repoKey(bad); rmSync(join(d, 'key.der'));
  const r = cli(NEW, [...KEYS, '--paths', d]);
  assert.ok(!safeOnly(r), `DEFECT tracked file deleted from the working tree, read from git's store: ${brief(r)}`);
});
// ---- D5 PBE window -------------------------------------------------------------------------------------------------
const longLen = (len, n) => { const b = Buffer.alloc(n); let x = len; for (let i = n - 1; i >= 0 && x; i--) { b[i] = x & 255; x = Math.floor(x / 256); } return Buffer.concat([Buffer.from([0x80 | n]), b]); };
const [alg, data] = kids(enc);
const algBody = alg.subarray(alg[1] < 0x80 ? 2 : 2 + (alg[1] & 0x7f));
const padAlg = (n) => tlv(0x30, Buffer.concat([Buffer.from([0x30]), longLen(algBody.length, n), algBody, data]));
test('D5 the PBE window: an encrypted key with its OID pushed past 32 bytes reads SAFE (the CHANGELOG says UNKNOWN now)', () => {
  const near = key(NEW, padAlg(16));
  assert.equal(near.code, 2, `CONTROL 16 length bytes, OID inside the window: ${brief(near)}`);
  const bad = padAlg(32);
  assert.equal(ssl(['pkcs8', '-inform', 'DER', '-in', file(bad), '-passin', `pass:${PW}`, '-out', '/dev/null']).status, 0, 'CONTROL LibreSSL opens it with the password');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
// ---- D6 indefinite, text gate, high tag ------------------------------------------------------------------------------
const indef = (b) => Buffer.concat([Buffer.from([0x30, 0x80]), b, Buffer.from([0, 0])]);
const dataBody = data.subarray(data[1] < 0x80 ? 2 : 2 + (data[1] & 0x7f));
const conOct = (b) => Buffer.concat([Buffer.from([0x24, 0x80]), tlv(4, b.subarray(0, 100)), tlv(4, b.subarray(100)), Buffer.from([0, 0])]);
test('D6a indefinite outer with a constructed OCTET STRING: an encrypted key reads SAFE', () => {
  const ctl = key(NEW, indef(Buffer.concat([alg, data])));
  assert.ok(has(ctl, 'REVIEW'), `CONTROL indefinite outer alone: ${brief(ctl)}`);
  const bad = indef(Buffer.concat([alg, conOct(dataBody)]));
  assert.equal(ssl(['pkcs8', '-inform', 'DER', '-in', file(bad), '-passin', `pass:${PW}`, '-out', '/dev/null']).status, 0, 'CONTROL LibreSSL opens it');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D6b indefinite outer with a constructed OCTET STRING: a plain PKCS #8 key reads SAFE', () => {
  const [v, a, o] = kids(p8), body = o.subarray(o[1] < 0x80 ? 2 : 2 + (o[1] & 0x7f));
  const ctl = key(NEW, tlv(0x30, Buffer.concat([v, a, conOct(body)])));
  assert.ok(!safeOnly(ctl), `CONTROL stated outer length: ${brief(ctl)}`);
  const bad = indef(Buffer.concat([v, a, conOct(body)]));
  assert.equal(ssl(['pkcs8', '-inform', 'DER', '-nocrypt', '-in', file(bad), '-out', '/dev/null']).status, 0, 'CONTROL LibreSSL loads it');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D6c the text gate: a NUL-free SEC1 key with a short outer length and version 2 reads SAFE', () => {
  let k;
  for (let i = 0; i < 500 && !k; i++) { const s = kids(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'sec1', format: 'der' })); if (!Buffer.concat([s[1], s[2]]).includes(0)) k = s; }
  assert.ok(k, 'CONTROL a key with no NUL byte');
  const ctl = key(NEW, tlv(0x30, Buffer.concat([k[0], k[1], k[2]])));
  assert.ok(has(ctl, 'REVIEW'), `CONTROL version 1: ${brief(ctl)}`);
  const bad = tlv(0x30, Buffer.concat([Buffer.from([2, 1, 2]), k[1], k[2]]));
  assert.ok(!bad.includes(0), 'CONTROL no NUL'); assert.equal(ssl(['ec', '-inform', 'DER', '-in', file(bad), '-noout']).status, 0, 'CONTROL LibreSSL loads it');
  const r = key(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D6d high-tag form: outer 3f 10, or the version as 1f 02, loads and reads SAFE', () => {
  const a = Buffer.concat([Buffer.from([0x3f, 0x10]), p1.subarray(1)]), b = swapV(p1, Buffer.from([0x1f, 2, 1, 0]));
  assert.equal(ssl(['rsa', '-inform', 'DER', '-in', file(a), '-noout']).status, 0, 'CONTROL LibreSSL loads the first');
  assert.equal(ssl(['rsa', '-inform', 'DER', '-in', file(b), '-noout']).status, 0, 'CONTROL LibreSSL loads the second');
  const ra = key(NEW, a), rb = key(NEW, b);
  assert.ok(!safeOnly(ra) && !safeOnly(rb), `DEFECT ${brief(ra)} ;; ${brief(rb)}`);
});
test('REFUTED R13 stays quiet, and a padded version 0 is found', () => {
  const pub = rsa.publicKey.export({ type: 'pkcs1', format: 'der' });
  assert.equal(key(NEW, pub).code, 0, 'a PKCS #1 public key is quiet');
  assert.ok(!safeOnly(key(NEW, swapV(p1, Buffer.from([2, 2, 0, 0])))), 'a padded version 0 has a row');
});
// ---- D2 WordPress ----------------------------------------------------------------------------------------------------
const site = (d) => { put(join(d, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";\n'); put(join(d, 'wp-config.php'), "<?php\ndefine('DB_NAME', 'x');\n"); mkdirSync(join(d, 'wp-content', 'plugins'), { recursive: true }); return d; };
const rm = (p, v = '3.0.123') => put(p, `<?php\n/*\n * Plugin Name: Rank Math PRO\n * Version: ${v}\n */\n`);
const live = (name, body) => { const s = site(join(fresh('wp'), 'site')), pl = join(s, 'wp-content', 'plugins'), f = join(pl, name); body(f, s, pl); old(f); old(pl); return cli(NEW, [...WP, '--paths', s]); };
test('D2 a compromised Rank Math PRO in a live plugin folder of any other name reads SAFE (WordPress loads it from any folder)', () => {
  const ctl = live('seo-by-rank-math-pro copy', (f) => rm(join(f, 'rank-math-pro.php')));
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL: ${brief(ctl)}`);
  const bad = [];
  for (const n of ['rank-math-pro', 'seo-by-rank-math-pro2', 'seo-by-rank-math-pro3.0.123', 'seo-by-rank-math-probak', 'SEO-BY-RANK-MATH-PRO-old', 'oldseo-by-rank-math-pro seo-by-rank-math-pro']) {
    const r = live(n, (f) => rm(join(f, 'rank-math-pro.php')));
    if (safeOnly(r)) bad.push(n);
  }
  assert.deepEqual(bad, [], `DEFECT read SAFE, exit 0: ${bad.join(' ; ')}`);
});
test('D3 R6: a copy with its main file gone reads SAFE, the exact name in that state is UNKNOWN', () => {
  const ctl = live('updraftplus', (f) => put(join(f, 'includes', 'x.php'), '<?php\n'));
  assert.equal(ctl.code, 2, `CONTROL exact name: ${brief(ctl)}`);
  const a = live('updraftplus-old', (f) => put(join(f, 'includes', 'x.php'), '<?php\n'));
  const b = live('seo-by-rank-math-pro copy', (f) => put(join(f, 'includes', 'x.php'), '<?php\n'));
  const c = live('updraftplus copy', (f) => put(join(f, 'updraftplus', 'updraftplus.php'), '<?php\n/*\nVersion: 1.26.12\n*/\n'));
  assert.ok(!safeOnly(a) && !safeOnly(b) && !safeOnly(c), `DEFECT ${brief(a)} ;; ${brief(b)} ;; old version nested in a copy: ${brief(c)}`);
});
test('D4 a link at a copy name into the same walk reads SAFE, the link at the exact name is EXPOSED', () => {
  const ln = (name) => { const s = site(join(fresh('wp'), 'site')); rm(join(s, 'stash', 'rm', 'rank-math-pro.php')); symlinkSync('../../stash/rm', join(s, 'wp-content', 'plugins', name)); return cli(NEW, [...WP, '--paths', s]); };
  const ctl = ln('seo-by-rank-math-pro');
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL: ${brief(ctl)}`);
  const r = ln('seo-by-rank-math-pro copy');
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D7 a leftover whose parent folder has no "plugins" in its name reads SAFE', () => {
  const at = (parent) => { const s = site(join(fresh('wp'), 'site')); rm(join(s, parent, 'seo-by-rank-math-pro', 'rank-math-pro.php')); return cli(NEW, [...WP, '--paths', s]); };
  const ctl = at('backup/plugins');
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL: ${brief(ctl)}`);
  const bad = ['wp-content/upgrade', 'backup/plugin-backups', 'backup/old'].filter((p) => safeOnly(at(p)));
  assert.deepEqual(bad, [], `DEFECT read SAFE, exit 0: ${bad.join(' ; ')}`);
});
test('D7b --paths naming a link to the plugin reads SAFE, --paths naming the plugin is EXPOSED', () => {
  const r0 = fresh('wp'); rm(join(r0, 'seo-by-rank-math-pro', 'rank-math-pro.php')); symlinkSync(join(r0, 'seo-by-rank-math-pro'), join(r0, 'current'));
  const ctl = cli(NEW, [...WP, '--paths', join(r0, 'seo-by-rank-math-pro')]);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL: ${brief(ctl)}`);
  const r = cli(NEW, [...WP, '--paths', join(r0, 'current')]);
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('REFUTED sitesOwn/unsettled: stock site EXPOSED; a site whose config is in doubt is UNKNOWN, never SAFE', () => {
  const s = site(join(fresh('wp'), 'site')); rm(join(s, 'content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'));
  assert.ok(has(cli(NEW, [...WP, '--paths', s]), 'EXPOSED'), 'stock');
  put(join(s, 'wp-config.php'), '<?php\n// WP_CONTENT_DIR\n');
  assert.equal(cli(NEW, [...WP, '--paths', s]).code, 2, 'config names the setting');
});
// ---- D8 quick look ---------------------------------------------------------------------------------------------------
const stealer = { 'litellm-1.107.0.dist-info/METADATA': 'Name: litellm\nVersion: 1.107.0\n', 'cook.pth': 'import cook\n' };
const venv = (d, drop = stealer) => { put(join(d, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(d, 'bin', 'python'), ''); const sp = join(d, 'lib', 'python3.12', 'site-packages'); mkdirSync(sp, { recursive: true }); for (const [f, b] of Object.entries(drop)) put(join(sp, f), b); return sp; };
test('D8 R1 in the quick look: ~/app/.venv as a link is EXPOSED, and with its target locked reads SAFE', () => {
  const go = (locked) => { const h = fresh('h'), o = fresh('out'); venv(join(o, 'locked', 'env')); mkdirSync(join(h, 'app')); symlinkSync(join(o, 'locked', 'env'), join(h, 'app', '.venv')); if (locked) lock(join(o, 'locked')); return cli(NEW, [...LITELLM, '--paths', fresh('empty')], { home: h }); };
  const ctl = go(false);
  assert.ok(has(ctl, 'EXPOSED'), `CONTROL reachable: ${brief(ctl)}`);
  const r = go(true);
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('D8b quick look: ~/app/.venv of mode 0644 reads SAFE, --paths on the same folder is UNKNOWN', () => {
  const r0 = fresh('p'); venv(join(r0, 'app', '.venv')); lock(join(r0, 'app', '.venv'), 0o644);
  const ctl = cli(NEW, [...LITELLM, '--paths', r0]);
  assert.equal(ctl.code, 2, `CONTROL --paths: ${brief(ctl)}`);
  const h = fresh('h'); venv(join(h, 'app', '.venv')); lock(join(h, 'app', '.venv'), 0o644);
  const r = cli(NEW, [...LITELLM, '--paths', fresh('empty')], { home: h });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('REFUTED mayBeFolder in the --paths walks: a locked link target is UNKNOWN in the installs, header and key walks, and past the floor', () => {
  const go = (tree, args, plant) => { const r0 = fresh('p'), o = fresh('out'); plant(join(o, 'locked', 'in')); symlinkSync(join(o, 'locked', 'in'), join(r0, 'proj')); chmodSync(join(o, 'locked'), 0); const x = cli(tree, [...args, '--paths', r0]); chmodSync(join(o, 'locked'), 0o755); return x; };
  for (const [args, plant] of [[LITELLM, (d) => venv(join(d, '.venv'))], [HDR, (d) => put(join(d, '.mcp.json'), '{}')], [KEYS, (d) => repoWith(d, { a: 'x' })]]) {
    assert.equal(go(NEW, args, plant).code, 2);
  }
});
// ---- D9 TOML ---------------------------------------------------------------------------------------------------------
const E = 'ada@example.invalid', H = `"X-User: ${E}"`;
const toml = (t) => { const h = fresh('h'); put(join(h, '.gitconfig'), `[user]\n\tname = Ada Example\n\temail = ${E}\n`); put(join(h, '.codex', 'config.toml'), t); return cli(NEW, HDR, { home: h }); };
const parses = (t) => { const f = put(join(fresh('t'), 'c.toml'), t); const p = spawnSync('/Library/Frameworks/Python.framework/Versions/3.14/bin/python3', ['-I', '-c', 'import tomllib,sys;print(tomllib.load(open(sys.argv[1],"rb")))', f], { encoding: 'utf8' }); assert.equal(p.status, 0, `CONTROL tomllib refused: ${p.stderr}`); assert.match(p.stdout, /ada@example\.invalid/, 'CONTROL tomllib reads the address'); };
const tomlCase = (name, t) => test(`D9 TOML, valid and read by tomllib, SAFE here: ${name}`, () => { assert.ok(has(toml(`[mcp_servers.x]\nargs = ["--header", ${H}]\n`), 'REVIEW'), 'CONTROL own table'); parses(t); const r = toml(t); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`); });
tomlCase('a closing brace from a nested table before a multi-line array', `[mcp_servers]\nx = { env = {}, args = ["--header",\n ${H}] }\n`);
tomlCase('http_headers inside an inline table', `[mcp_servers]\nx = { url = "https://x.example", http_headers = { "X-User" = "${E}" } }\n`);
tomlCase('a quoted key holding an equals sign', `[mcp_servers]\n"a=b" = { args = ["--header", ${H}] }\n`);
tomlCase('a ] in a comment inside a multi-line array', `[mcp_servers.x]\nargs = [ # see ]\n "--header",\n ${H}]\n`);
tomlCase('a quoted word in a comment after --header', `[mcp_servers.x]\nargs = ["--header", # "fake"\n ${H}]\n`);
tomlCase('a triple-quoted value', `[mcp_servers.x]\nargs = ["--header", """X-User: ${E}"""]\n`);
tomlCase('\\u0040 in a value', `[mcp_servers.x]\nargs = ["--header", "X-User: ada\\u0040example.invalid"]\n`);
test('REFUTED R8 itself: a one-line inline table and an inline table with a multi-line array are read', () => {
  assert.ok(has(toml(`[mcp_servers]\nx = { command = "npx", args = ["--header", ${H}] }\n`), 'REVIEW'));
  assert.ok(has(toml(`[mcp_servers]\nx = { command = "npx", args = ["--header",\n ${H}] }\n`), 'REVIEW'));
});
// ---- git, .mcp.json --------------------------------------------------------------------------------------------------
const gc = (tree, t) => { const h = fresh('h'); put(join(h, '.gitconfig'), t); const r = cli(tree, HDR, { home: h }); return { r, h }; };
const gitReads = (h) => spawnSync('/usr/bin/git', ['config', '--file', join(h, '.gitconfig'), '--get', 'http.extraheader'], { encoding: 'utf8', env: { HOME: h, PATH: '/usr/bin:/bin' } }).stdout;
const id = `[user]\n\tname = Ada Example\n\temail = ${E}\n`;
test('REFUTED git trailing backslash: every form git reads is EXPOSED, and each read SAFE on 0.1.11', () => {
  for (const t of [`${id}[http]\n\textraHeader = X-User: ${E}\\`, `${id}[http]\n\textraHeader = X-User: ${E} \\\n\\\n\\`, `${id}[http]\n\textraHeader = X-User: ada@exam\\\nple.invalid\\`, `${id}[http]extraHeader=X-User: ${E}\\`]) {
    const a = gc(NEW, t);
    assert.match(gitReads(a.h), /ada@example\.invalid/, 'CONTROL git reads it');
    assert.ok(has(a.r, 'EXPOSED'), brief(a.r));
  }
});
test('D10 git: quotes inside a value. git sends the address, this reads SAFE', () => {
  assert.ok(has(gc(NEW, `${id}[http]\n\textraHeader = "X-User: ${E}"\n`).r, 'EXPOSED'), 'CONTROL quoted whole');
  const a = gc(NEW, `${id}[http]\n\textraHeader = X-User: ada"@"example.invalid\n`);
  assert.match(gitReads(a.h), /ada@example\.invalid/, 'CONTROL git reads the address');
  assert.ok(!safeOnly(a.r), `DEFECT ${brief(a.r)}`);
});
const proj = (tree, build, git = false) => { const h = fresh('h'); put(join(h, '.gitconfig'), id); const r0 = fresh('p'), p = join(r0, 'proj'); mkdirSync(p); if (git) repoWith(p, { 'a.txt': 'x' }); build(p); return cli(tree, [...HDR, '--paths', r0], { home: h }); };
const J = JSON.stringify({ mcpServers: { x: { headers: { 'X-User': E } } } });
test('REFUTED .mcp.json rule: FIFO, a FIFO behind a link, and a FIFO settings file are UNKNOWN with no .git', () => {
  const ff = (p) => spawnSync('/usr/bin/mkfifo', [p]);
  for (const b of [(p) => ff(join(p, '.mcp.json')), (p) => { mkdirSync(join(p, '.claude')); ff(join(p, '.claude', 'settings.json')); }, (p) => { const o = fresh('o'); ff(join(o, 'f')); symlinkSync(join(o, 'f'), join(p, '.mcp.json')); }]) {
    assert.equal(proj(NEW, b).code, 2);
  }
});
// ---- sitecustomize, expand --------------------------------------------------------------------------------------------
test('D12 sitecustomize as a package reads SAFE; Python runs it at start (logs/pypkg.log)', () => {
  const go = (drop) => { const r0 = fresh('p'); venv(join(r0, '.venv'), drop); return cli(NEW, [...LITELLM, '--paths', r0]); };
  assert.ok(has(go({ 'sitecustomize.py': '# x\n' }), 'REVIEW'), 'CONTROL the file form is REVIEW');
  const r = go({ 'sitecustomize/__init__.py': 'import os\n' });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('REFUTED expand() takes the new patterns: * mid-segment matches Xcode*.app and refuses what it should', async () => {
  const { expand } = await import(join(NEW, 'lib', 'installs.mjs'));
  const d = fresh('xc'); for (const n of ['Xcode.app', 'Xcode-beta.app', 'Xcode 16.app', 'Xcodeapp', 'XcodeXapp', 'NotXcode.app']) mkdirSync(join(d, n, 'py'), { recursive: true });
  const got = expand(`${d}/Xcode*.app/py`).map((p) => p.slice(d.length + 1)).sort();
  assert.deepEqual(got, ['Xcode 16.app/py', 'Xcode-beta.app/py', 'Xcode.app/py']);
});

// EPERM needs a sandbox, and one can't be applied inside another: these skip there.
const sandboxed = (home, deny) => {
  const rule = deny ? `(deny file-read-data (subpath "${realpathSync(deny)}"))` : '';
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', `(version 1)(allow default)${rule}`, process.execPath, join(NEW, 'bin/wardlatch.mjs'), '--json', '--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('empty')], { encoding: 'utf8', maxBuffer: 1 << 26, env: { HOME: home, PATH: '/usr/bin:/bin', TMPDIR: fresh('t') } });
  return r.stdout ? { code: r.status, rows: JSON.parse(r.stdout).results } : null;
};
const planted = (sub) => { const h = fresh('h'), v = join(h, sub, '.venv'); put(join(v, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(v, 'bin', 'python')); put(join(v, 'lib/python3.12/site-packages/cook.pth'), 'import cook\n'); return h; };
for (const [sub, re] of [['.Trash', /\.Trash/], ['Pictures/anything.photoslibrary', /photoslibrary/]]) {
  test(`D13 EPERM on ~/${sub}, stealer inside: the SAFE row says this folder was not searched`, { skip: process.platform !== 'darwin' }, (t) => {
    const h = planted(sub), ctl = sandboxed(h);
    if (!ctl) return t.skip('a sandbox cannot be applied here (this run is already inside one)');
    assert.equal(ctl.code, 1, 'CONTROL with no refusal it is EXPOSED');
    const r = sandboxed(h, join(h, sub));
    assert.equal(r.code, 0, 'the stealer is out of reach: this is the all-clear the row must qualify');
    assert.match(JSON.stringify(r.rows.flatMap((x) => [x.reason, ...(x.notSearched ?? [])])), re, 'nothing in the row names it');
  });
}
