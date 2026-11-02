// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The review of 0.1.12's second draft, 2 Nov 2026 (seat 9). Each DEFECT read SAFE there, or a false alarm, with its control
// passing; REFUTED ones held. tomllib stands as the reference where a Python that has it is found. Keys are made here,
// used, never printed. Nothing connects.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, chmodSync, realpathSync, writeFileSync, existsSync, rmSync, symlinkSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fresh, put, cli, NEW, KEYS, WP, LITELLM, HDR, repoWith, gitIn, brief, has, safeOnly, RIG, tlv, kids } from './support/seat7-lib.mjs';
import { FORMS, loads, O, PW } from './support/der-forms.mjs';

const PY = existsSync('/opt/homebrew/bin/python3') ? '/opt/homebrew/bin/python3' : null;
const READS = "import sys, tomllib, json\ntry:\n  d = tomllib.load(open(sys.argv[1], 'rb'))\nexcept Exception:\n  print('invalid'); sys.exit()\nprint('yes' if 'ada' in json.dumps(d) else 'no')\n";
const reads = (text, none = 'yes') => { if (!PY) return none; const f = put(join(fresh('t'), 'c.toml'), text); return spawnSync(PY, ['-I', '-c', READS, f], { encoding: 'utf8' }).stdout.trim(); };
const undo = []; const lock = (p, m = 0) => { chmodSync(p, m); undo.push(p); };
after(() => { for (const p of undo) { try { chmodSync(p, 0o755); } catch { /* */ } } });
const opened = () => { for (const p of undo.splice(0)) chmodSync(p, 0o755); };
const homeFor = (files = {}) => { const h = realpathSync(fresh('h')); put(join(h, '.gitconfig'), '[user]\n\tname = Ada Lovelace\n\temail = ada@example.org\n'); for (const [f, b] of Object.entries(files)) put(join(h, f), b); return h; };
const codex = (tree, text) => cli(tree, HDR, { home: homeFor({ '.codex/config.toml': text }) });
const HT = '[mcp_servers.x.http_headers]\nX-User = "ada@example.org"\n';

// ---- TOML ----------------------------------------------------------------------------------------------------------
test('T1 REGRESSION a multi-line string ending in an even run of backslashes swallows the rest of the file', () => {
  const bad = `y = """C:\\\\"""\n${HT}`;
  assert.equal(reads(bad), 'yes', 'CONTROL tomllib reads the header');
  assert.ok(has(codex(NEW, `y = """C:\\"""\n${HT}`.replace('\\"""', '"""')), 'REVIEW'), 'CONTROL no backslash: found');
  const r = codex(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('T2 a dotted key in an inline table, split by a quote or a space, hides the header name', () => {
  for (const bad of ['x = { http_headers."X-User" = "ada@example.org" }\n', 'x = { "http_headers"."X" = "ada@example.org" }\n', 'x = { http_headers . X = "ada@example.org" }\n']) {
    assert.equal(reads(bad), 'yes', 'CONTROL tomllib reads the header');
    assert.ok(has(codex(NEW, 'x = { http_headers.X = "ada@example.org" }\n'), 'REVIEW'), 'CONTROL unsplit: found');
    const r = codex(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${JSON.stringify(bad)} ${brief(r)}`);
  }
});
test('T3 a line-ending backslash with white space after it leaves the value in two pieces', () => {
  const bad = '[a.http_headers]\nX = """ada@\\  \n    example.org"""\n';
  assert.equal(reads(bad), 'yes', 'CONTROL tomllib reads the address');
  const ok = '[a.http_headers]\nX = """ada@\\\n    example.org"""\n';
  assert.equal(reads(ok), 'yes', 'CONTROL'); assert.ok(has(codex(NEW, ok), 'REVIEW'), 'CONTROL no spaces: found');
  const r = codex(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('T4 NOT LINEAR: a planted config.toml of 1.6 MB takes over 20 s', () => {
  let s = 'headers = ['; for (let i = 0; s.length < 1.6e6; i++) s += `"s${i}",`; const planted = `${s}]\n`;
  const timed = (tree, text) => { const h = homeFor({ '.codex/config.toml': text }), t = Date.now(); const r = spawnSync(process.execPath, [join(tree, 'bin/wardlatch.mjs'), '--json', ...HDR], { encoding: 'utf8', timeout: 20000, maxBuffer: 1 << 26, env: { HOME: h, PATH: '/usr/bin:/bin', TMPDIR: join(RIG, 'tmp') } }); return { ms: Date.now() - t, killed: Boolean(r.signal) }; };
  const b = timed(NEW, `headers = [${'"x",'.repeat(4e5)}]\n`); assert.ok(!b.killed && b.ms < 5000, `CONTROL 95b0503, same size, one string repeated: ${b.ms} ms`);
  const c = timed(NEW, planted); assert.ok(!c.killed && c.ms < 5000, `DEFECT ${c.ms} ms${c.killed ? ', killed at 20 s' : ''}`);
});
test('T5 REGRESSION a byte-order mark before the first table', () => {
  assert.ok(has(codex(NEW, HT), 'REVIEW'), 'CONTROL no mark: found');
  const r = codex(NEW, `\ufeff${HT}`); assert.ok(!safeOnly(r), `DEFECT (tomllib refuses this file; toml_parser and toml_edit, read in source, strip the mark) ${brief(r)}`);
});
test('T6 REGRESSION an unterminated """ reads the rest of the file as a string, and SAFE', () => {
  const bad = `y = """a\n${HT}`;
  assert.equal(reads(bad, 'invalid'), 'invalid', 'CONTROL no parser reads this file');
  const broken = cli(NEW, HDR, { home: homeFor({ '.claude/settings.json': '{ "a": ' }) });
  assert.ok(has(broken, 'UNKNOWN'), 'CONTROL a broken JSON settings file is UNKNOWN');
  const r = codex(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('T7 an address in an escaped key under a header table', () => {
  const bad = '[a.http_headers]\n"X\\u003a ada\\u0040example.org" = 1\n';
  assert.equal(reads(bad), 'yes', 'CONTROL tomllib reads the key');
  assert.ok(has(codex(NEW, '[a.http_headers]\n"X: ada@example.org" = 1\n'), 'REVIEW'), 'CONTROL no escape: found');
  const r = codex(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});

// ---- git -------------------------------------------------------------------------------------------------------------
test('G1 OLD a CR or U+2028 inside a git value drops the whole line', () => {
  for (const sep of ['\u2028', '\r']) {
    const text = `[user]\n\temail = ada@example.org\n[http]\n\textraHeader = X-User: ada@example.org${sep}z\n`;
    const h = realpathSync(fresh('h')); put(join(h, '.gitconfig'), text);
    const g = spawnSync('/usr/bin/git', ['config', '--file', join(h, '.gitconfig'), '--get', 'http.extraheader'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', HOME: h } });
    assert.ok(g.status === 0 && g.stdout.includes('ada@example.org'), 'CONTROL git reads the address');
    assert.ok(has(cli(NEW, HDR, { home: (() => { const o = realpathSync(fresh('h')); put(join(o, '.gitconfig'), text.replace(sep, ' ')); return o; })() }), 'EXPOSED'), 'CONTROL a space there: EXPOSED');
    const r = cli(NEW, HDR, { home: h }); assert.ok(!safeOnly(r), `DEFECT ${JSON.stringify(sep)} ${brief(r)}`);
  }
});

// ---- DER -------------------------------------------------------------------------------------------------------------
const keyRun = (tree, der) => cli(tree, [...KEYS, '--paths', repoWith(join(fresh('r'), 'r'), { 'k.bin': der })]);
const loadsNow = (kind, der) => loads(kind, put(join(fresh('k'), 'k'), der));
const P = (name) => FORMS[name];
const DER_CASES = {
  'K1 REGRESSION in this commit (UNKNOWN on 3c19f0c): encrypted key, OID 1f 06': ['enc oid 1f 06', 'ctl enc outer 3f 10 (found by shape)'],
  'K2 no NUL, short outer, version 8': ['SEC1 no NUL v8', 'ctl SEC1 no NUL v2 (D6c, fixed)'],
  'K3 no NUL, short outer, two-byte version': ['SEC1 no NUL two-byte version', 'ctl SEC1 no NUL v2 (D6c, fixed)'],
  'K4 no NUL, short outer, version 1f 02': ['SEC1 no NUL version 1f 02', 'ctl SEC1 no NUL v2 (D6c, fixed)'],
  'K5 no NUL, PKCS #8 EC, version 9': ['PKCS8 EC no NUL v9', 'ctl SEC1 no NUL v2 (D6c, fixed)'],
  'K6 padded high tag, outer 3f 80 10': ['outer 3f 80 10 RSA', 'ctl outer 3f 10 RSA (D6d, fixed)'],
  'K7 padded high tag, version 1f 80 02': ['version 1f 80 02 RSA', 'ctl version 1f 02 RSA (D6d, fixed)'],
  'K8 encrypted key, algorithm 3f 10': ['enc alg 3f 10', 'ctl enc outer 3f 10 (found by shape)'],
  'K9 encrypted key, outer and algorithm 3f 10': ['enc outer 3f 10 alg 3f 10', 'ctl enc outer 3f 10 (found by shape)'],
  'K10 30 80, RSA, version 2': ['30 80 RSA version 2', 'ctl 30 80 RSA as made (found)'],
  'K11 30 80, RSA, two-byte version': ['30 80 RSA two-byte version', 'ctl 30 80 RSA as made (found)'],
  'K12 30 80, RSA, version 1f 02': ['30 80 RSA version 1f 02', 'ctl 30 80 RSA as made (found)'],
  'K13 30 80, PKCS #8, version 2': ['30 80 PKCS8 version 2', 'ctl 30 80 RSA as made (found)'],
  'K14 30 80, SEC1, constructed OCTET STRING': ['30 80 SEC1 constructed octets', 'ctl 30 80 RSA as made (found)'],
  'K15 30 80, encrypted, algorithm 3f 10': ['30 80 enc alg 3f 10', 'ctl 30 80 enc as made (found)'],
};
for (const [name, [form, ctl]] of Object.entries(DER_CASES)) {
  test(`${name}: LibreSSL loads it, no row`, () => {
    const [kind, der] = P(form), [ckind, cder] = P(ctl);
    assert.ok(loadsNow(kind, der), 'CONTROL LibreSSL loads this form');
    assert.ok(loadsNow(ckind, cder), 'CONTROL LibreSSL loads the control form');
    assert.ok(!safeOnly(keyRun(NEW, cder)), 'CONTROL the near form has a row');
    const r = keyRun(NEW, der); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
  });
}
test('K16 REFUTED a PKCS #1 public key stays quiet, and nothing loads that shape as a private key', () => {
  const pub = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'pkcs1', format: 'der' });
  assert.ok(safeOnly(keyRun(NEW, pub)), 'quiet on 95b0503');
  for (const k of ['rsa', 'ec', 'p8', 'enc', 'any']) assert.equal(loadsNow(k, pub), false, `${k} does not load it`);
});
test('K17 REFUTED every prefix of every key form: no crash, and a text file behind 3f 10 still has its text scanned', async () => {
  const { scanRepo } = await import(`file://${join(NEW, 'lib/secrets.mjs')}`);
  const files = {}; let n = 0;
  for (const [, der] of Object.values(FORMS)) for (const cut of [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 20, 40, 64, 200, der.length - 3, der.length - 1]) if (cut > 0 && cut < der.length) files[`p${n++}.bin`] = der.subarray(0, cut);
  const repo = repoWith(join(fresh('r'), 'r'), files);
  assert.ok(Array.isArray(scanRepo(repo)), `read ${n} prefixes without a throw`);
  const text = Buffer.concat([Buffer.from([0x3f, 0x10]), Buffer.from(' AKIAIOSFODNN7QQQQQQQ\n')]);
  assert.ok(has(keyRun(NEW, text), 'REVIEW'), 'the AWS-shaped key is still found');
});

// ---- PKCS #12 ----------------------------------------------------------------------------------------------------------
test('K18 30 80 PKCS #12 with a two-byte version, and padded high tags: LibreSSL opens them, no row', () => {
  const d = realpathSync(fresh('p12')), q = (a) => spawnSync(O, a, { encoding: 'buffer' });
  q(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'k'), '-out', join(d, 'c'), '-subj', '/CN=x', '-days', '2']);
  q(['pkcs12', '-export', '-inkey', join(d, 'k'), '-in', join(d, 'c'), '-out', join(d, 'p'), '-passout', `pass:${PW}`]);
  const p = readFileSync(join(d, 'p')), k = kids(p); rmSync(join(d, 'k'));
  const indef = (kk) => Buffer.concat([Buffer.from([0x30, 0x80]), ...kk, Buffer.from([0, 0])]);
  const open = (der) => q(['pkcs12', '-in', put(join(fresh('f'), 'f'), der), '-passin', `pass:${PW}`, '-nodes', '-out', '/dev/null']).status === 0;
  const near = indef(k); assert.ok(open(near), 'CONTROL'); assert.ok(!safeOnly(keyRun(NEW, near)), 'CONTROL 30 80 as made has a row');
  for (const bad of [indef([Buffer.from([2, 2, 1, 3]), ...k.slice(1)]), tlv([0x3f, 0x80, 0x10], Buffer.concat(k))]) {
    assert.ok(open(bad), 'CONTROL LibreSSL opens it with the password');
    const r = keyRun(NEW, bad); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
  }
});

// ---- WordPress ----------------------------------------------------------------------------------------------------------
const PL = 'seo-by-rank-math-pro';
const rm = (p, v = '3.0.123') => put(join(p, 'rank-math-pro.php'), `<?php\n/*\n * Plugin Name: Rank Math PRO\n * Version: ${v}\n */\n`);
const core = (site) => { put(join(site, 'wp-includes', 'version.php'), "<?php $wp_version = '6.8';\n"); put(join(site, 'wp-config.php'), '<?php\n'); mkdirSync(join(site, 'wp-content', 'plugins'), { recursive: true }); };
const wp = (tree, build) => { const r = realpathSync(fresh('wp')); const args = build(r) ?? [r]; return cli(tree, [...WP, ...args.flatMap((a) => ['--paths', a])]); };
test('W1 REGRESSION --paths at a link named as the plugin, target another name (Capistrano shape)', () => {
  const shape = (r) => { rm(join(r, 'rel/20261101')); mkdirSync(join(r, 'x')); symlinkSync(join(r, 'rel/20261101'), join(r, 'x', PL)); return [join(r, 'x', PL)]; };
  assert.ok(has(wp(NEW, (r) => { rm(join(r, 'rel', PL)); mkdirSync(join(r, 'x')); symlinkSync(join(r, 'rel', PL), join(r, 'x/current')); return [join(r, 'x/current')]; }), 'EXPOSED'), 'CONTROL D7b still holds');
  const r = wp(NEW, shape); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('W2 --paths at a link at a copy name, target another name', () => {
  assert.ok(has(wp(NEW, (r) => { rm(join(r, 'x', `${PL}-live`)); return [join(r, 'x', `${PL}-live`)]; }), 'EXPOSED'), 'CONTROL the folder itself at that name');
  const r = wp(NEW, (d) => { rm(join(d, 'rel/v3')); mkdirSync(join(d, 'x')); symlinkSync(join(d, 'rel/v3'), join(d, 'x', `${PL}-live`)); return [join(d, 'x', `${PL}-live`)]; });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('W3 the main-file rule stops at the live folder', () => {
  assert.ok(has(wp(NEW, (r) => { core(r); rm(join(r, 'wp-content/plugins/rank-math-pro')); }), 'EXPOSED'), 'CONTROL live folder, any name');
  assert.ok(has(wp(NEW, (r) => { rm(join(r, 'backup/plugins', PL)); }), 'EXPOSED'), 'CONTROL leftover, exact name');
  for (const [where, build] of Object.entries({
    'backup/plugins/rank-math-pro': (r) => { rm(join(r, 'backup/plugins/rank-math-pro')); },
    'wp-content/upgrade/rank-math-pro': (r) => { core(r); rm(join(r, 'wp-content/upgrade/rank-math-pro')); },
    'backup/old/SEO-BY-RANK-MATH-PRO': (r) => { rm(join(r, 'backup/old/SEO-BY-RANK-MATH-PRO')); },
    '--paths plugins/rank-math-pro': (r) => { rm(join(r, 'wp-content/plugins/rank-math-pro')); return [join(r, 'wp-content/plugins/rank-math-pro')]; },
  })) { const r = wp(NEW, build); assert.ok(!safeOnly(r), `DEFECT ${where}: ${brief(r)}`); }
});
test('W4 exact name, main file gone, indicator inside, parent without "plugins" in its name', () => {
  assert.ok(has(wp(NEW, (r) => { put(join(r, 'backup/plugins', PL, 'x.php'), 'rank1cdn'); }), 'EXPOSED'), 'CONTROL the same folder under backup/plugins');
  const r = wp(NEW, (d) => { put(join(d, 'backup/old', PL, 'x.php'), 'rank1cdn'); });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('W5 --paths at a copy whose parent can be entered but not listed', { skip: process.getuid?.() === 0 }, () => {
  const build = (name) => (r) => { const b = join(r, 'x'); rm(join(b, name)); lock(b, 0o311); return [join(b, name)]; };
  const c = wp(NEW, build(PL)); opened(); assert.ok(has(c, 'EXPOSED'), `CONTROL exact name: ${brief(c)}`);
  const r = wp(NEW, build(`${PL}-old`)); opened(); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('W6 count: --paths a plugins folder and its plugin through a link root counts one finding twice', () => {
  const shape = (r) => { rm(join(r, 'real/plugins', PL)); symlinkSync(join(r, 'real'), join(r, 'lnk')); return [join(r, 'lnk/plugins'), join(r, 'lnk/plugins', PL)]; };
  const n = (x) => x.rows.filter((y) => y.status === 'EXPOSED').length;
  assert.equal(n(wp(NEW, (r) => { rm(join(r, 'real/plugins', PL)); return [join(r, 'real/plugins'), join(r, 'real/plugins', PL)]; })), 1, 'CONTROL no link: one row');
  const r = wp(NEW, shape); assert.equal(n(r), 1, `DEFECT ${brief(r)}`);
});

test('W7 REGRESSION on a case-insensitive disk: a change of case under a leftover plugins folder', () => {
  const shape = (r) => { rm(join(r, 'backup/plugins/SEO-BY-RANK-MATH-PRO')); };
  const r0 = realpathSync(fresh('case')); put(join(r0, 'Aa'), 'x');
  assert.ok(existsSync(join(r0, 'aA')), 'CONTROL this disk folds case, as a Mac disk does');
  assert.ok(has(wp(NEW, (r) => { rm(join(r, 'backup/plugins', PL)); }), 'EXPOSED'), 'CONTROL the exact spelling, 95b0503: EXPOSED');
  const r = wp(NEW, shape); assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`);
});
test('W8 an indicator search left unfinished in a copy is a line to look at; in the exact name it is UNKNOWN', () => {
  const big = (name) => (r) => { core(r); put(join(r, 'wp-content/plugins', name, 'big.js'), `${'x'.repeat(3e6)}rank1cdn`); };
  assert.equal(wp(NEW, big(PL)).code, 2, 'CONTROL the exact name in that state: exit 2');
  const r = wp(NEW, big(`${PL}-old`)); assert.ok(has(r, 'REVIEW') && r.code === 0, brief(r));
});

// ---- places(): a repository's subfolders --------------------------------------------------------------------------------
const J = JSON.stringify({ a: { headers: { 'X-User': 'ada@example.org' } } });
const proj = (root, git) => { const p = join(root, 'proj'); mkdirSync(p, { recursive: true }); if (git) gitIn(p, 'init', '-q'); return p; };
const hdr = (build, git) => { const root = realpathSync(fresh('i')); build(proj(root, git), root); const r = cli(NEW, [...HDR, '--paths', root], { home: homeFor() }); opened(); return r; };

// ---- installs -----------------------------------------------------------------------------------------------------------
test('P1 a sourceless sitecustomize runs at start and has no row', () => {
  const root = realpathSync(fresh('v')), v = join(root, 'env'), PYA = '/usr/bin/python3';
  assert.equal(spawnSync(PYA, ['-m', 'venv', '--without-pip', v]).status, 0, 'CONTROL venv');
  const site = spawnSync(join(v, 'bin/python'), ['-c', 'import sys;print([p for p in sys.path if p.endswith("site-packages")][0])'], { encoding: 'utf8' }).stdout.trim();
  const marker = join(root, 'ran'), body = `open(${JSON.stringify(marker)},'w').write('x')\n`;
  const clear = () => { for (const n of ['sitecustomize', 'sitecustomize.py', 'sitecustomize.pyc', '__pycache__']) rmSync(join(site, n), { recursive: true, force: true }); rmSync(marker, { force: true }); };
  const compile = (dst) => { const p = put(`${dst}.src.py`, body); assert.equal(spawnSync(join(v, 'bin/python'), ['-S', '-c', `import py_compile;py_compile.compile(${JSON.stringify(p)},${JSON.stringify(dst)},doraise=True)`]).status, 0); rmSync(p); };
  const ran = () => { spawnSync(join(v, 'bin/python'), ['-c', 'pass']); const y = existsSync(marker); rmSync(marker, { force: true }); return y; };
  put(join(site, 'sitecustomize/__init__.py'), body); assert.ok(ran(), 'CONTROL Python runs the package'); assert.ok(has(cli(NEW, [...LITELLM, '--paths', root]), 'REVIEW'), 'CONTROL its row');
  clear(); mkdirSync(join(site, 'sitecustomize')); compile(join(site, 'sitecustomize/__init__.pyc')); assert.ok(ran(), 'CONTROL Python runs the sourceless package');
  const a = cli(NEW, [...LITELLM, '--paths', root]);
  clear(); compile(join(site, 'sitecustomize.pyc')); assert.ok(ran(), 'CONTROL Python runs the sourceless file');
  const b = cli(NEW, [...LITELLM, '--paths', root]); clear();
  assert.ok(!safeOnly(a) && !safeOnly(b), `DEFECT package: ${brief(a)}; file: ${brief(b)}`);
});
test('P2 FALSE ALARM ~/app/.env, a link to a file in a locked folder, exit 2 with a sentence about opening a folder', { skip: process.getuid?.() === 0 }, () => {
  const go = (locked) => { const h = realpathSync(fresh('h')), o = realpathSync(fresh('o')); put(join(o, 's/app.env'), 'A=1\n'); mkdirSync(join(h, 'app')); symlinkSync(join(o, 's/app.env'), join(h, 'app/.env')); if (locked) lock(join(o, 's')); const r = cli(NEW, LITELLM, { home: h }); opened(); return r; };
  assert.equal(go(false).code, 0, 'CONTROL reachable: exit 0');
  const r = go(true); assert.equal(r.code, 0, `DEFECT ${brief(r)}`);
});

// ---- tempDirs: REFUTED --------------------------------------------------------------------------------------------------
test('D1 REFUTED each level above T that is refused keeps a row', async () => {
  const load = (tree) => import(`file://${join(tree, 'lib/binaries.mjs')}`);
  const rig = () => { const f = realpathSync(fresh('folders')); mkdirSync(join(f, 'ab/userdir/T'), { recursive: true }); return f; };
  const rows = (mod, lockAt) => { const f = rig(); lock(join(f, lockAt)); const den = []; mod.tmpTraces('^nothing$', mod.tempDirs('darwin', f).filter((x) => x.startsWith(f)), den); opened(); return den.length; };
  const now = await load(NEW);
  for (const at of ['.', 'ab', 'ab/userdir', 'ab/userdir/T']) assert.equal(rows(now, at), 1, `level ${at}`);
});
