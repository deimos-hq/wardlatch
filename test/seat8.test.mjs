// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The second review of 0.1.12's first draft, 2 Nov 2026 (seat 8): what it found, and a test for each fix that reverting
// left green. Nothing connects.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fresh, put, cli, NEW, WP, LITELLM, HDR, brief, has, safeOnly } from './support/seat7-lib.mjs';
import { headersInToml } from '../lib/headers.mjs';
import { holdsMore } from '../lib/files.mjs';
import { tempDirs } from '../lib/binaries.mjs';
import { SITE_PATTERNS } from '../lib/installs.mjs';
import { isCopyName, checkPluginsFolder } from '../lib/wordpress.mjs';

const asRoot = process.getuid?.() === 0, notMac = process.platform !== 'darwin';
const undo = []; const lock = (p) => { chmodSync(p, 0); undo.push(p); };
after(() => { for (const p of undo) { try { chmodSync(p, 0o755); } catch { /* */ } } });
const venv = (d, drop) => { put(join(d, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(d, 'bin', 'python')); for (const [f, b] of Object.entries(drop)) put(join(d, 'lib/python3.12/site-packages', f), b); };
const rank = (plugins, name, v = '3.0.123') => put(join(plugins, name, 'rank-math-pro.php'), `<?php\n/*\n * Plugin Name: Rank Math PRO\n * Version: ${v}\n */\n`);
const REVIEW_ADVICE = /runs every time this Python starts/;

test('the sitecustomize advice reaches its own row, in text and JSON, and no row about an image', () => {
  const root = fresh('adv'); venv(join(root, '.venv'), { 'sitecustomize.py': '# ours\n' });
  const bin = fresh('bin'); put(join(bin, 'docker'), `#!/bin/sh\ncase "$1" in images) echo 'litellm/litellm:latest@sha256:${'f'.repeat(64)}';; esac\nexit 0\n`); chmodSync(join(bin, 'docker'), 0o755);
  const run = (json) => spawnSync(process.execPath, [join(NEW, 'bin/wardlatch.mjs'), ...(json ? ['--json'] : []), '--incident', 'litellm-2026-10', '--paths', root], { encoding: 'utf8', env: { HOME: fresh('h'), PATH: `${bin}:/usr/bin:/bin`, TMPDIR: fresh('t') } });
  const rows = JSON.parse(run(true).stdout).results;
  const file = rows.find((x) => x.what === 'sitecustomize.py'), image = rows.find((x) => x.engine === 'docker' && x.status === 'REVIEW');
  assert.ok(file && image, JSON.stringify(rows.map((x) => [x.status, x.what])));
  assert.match(file.fix, REVIEW_ADVICE);
  assert.equal(image.fix, undefined);
  assert.equal(run(false).stdout.match(new RegExp(REVIEW_ADVICE, 'g'))?.length, 1, 'printed once, under the file');
});

test('a link to a file behind a locked folder says what happened, and not to pass --paths', { skip: asRoot }, () => {
  const root = fresh('lf'), outer = fresh('lf-out'); put(join(outer, 'locked', 'a.txt'), 'x'); symlinkSync(join(outer, 'locked', 'a.txt'), join(root, 'note'));
  lock(join(outer, 'locked'));
  const r = cli(NEW, [...LITELLM, '--paths', root]);
  chmodSync(join(outer, 'locked'), 0o755);
  const row = r.rows.find((x) => /note$/.test(String(x.path ?? '')));
  assert.match(row?.reason ?? '', /could not follow to its end/, brief(r));
  assert.doesNotMatch(row.reason, /pass --paths/);
});

test('three --paths at three copies are three rows, not nine', () => {
  const p = fresh('n'); for (const n of ['seo-by-rank-math-pro-1', 'seo-by-rank-math-pro-2', 'seo-by-rank-math-pro-3']) rank(p, n);
  const r = cli(NEW, [...WP, '--paths', join(p, 'seo-by-rank-math-pro-1'), '--paths', join(p, 'seo-by-rank-math-pro-2'), '--paths', join(p, 'seo-by-rank-math-pro-3')]);
  assert.equal(r.rows.filter((x) => x.status === 'EXPOSED').length, 3, brief(r));
});

test('a copy with its main file gone and a big log in it stays a line to look at, not a stop', () => {
  const s = fresh('log'); mkdirSync(join(s, 'wp-includes')); writeFileSync(join(s, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  put(join(s, 'wp-content/plugins/seo-by-rank-math-pro-logs/big.log'), 'x'.repeat(3e6));
  const r = cli(NEW, [...WP, '--paths', s]);
  assert.equal(r.code, 0, brief(r)); assert.ok(has(r, 'REVIEW'), brief(r));
});

test('isCopyName: the name set off by anything but a letter or digit', () => {
  for (const n of ['updraftplus copy', 'updraftplus 2', 'old-updraftplus', 'updraftplus.old', 'updraftplus-3.0']) assert.ok(isCopyName(n, 'updraftplus'), n);
  for (const n of ['updraftplus', 'updraftplus2', 'myupdraftplus', 'updraft']) assert.ok(!isCopyName(n, 'updraftplus'), n);
});

test('a copy of a longer listed plugin is that plugin\'s alone', () => {
  const p = fresh('longer'); rank(p, 'seo-by-rank-math-pro copy');
  const rules = [{ plugin: 'seo-by-rank-math', mainFile: 'rank-math.php', fixedIn: '1.0.0', fix: 'x' }, { plugin: 'seo-by-rank-math-pro', mainFile: 'rank-math-pro.php', bad: ['3.0.123'], fix: 'x' }];
  const rows = checkPluginsFolder(p, rules).filter((x) => /copy/.test(x.what));
  assert.deepEqual(rows.map((x) => x.status), ['EXPOSED'], JSON.stringify(rows));
});

test('a core with no plugins folder: a leftover beside it is reported, beside the row for the core', () => {
  const s = fresh('core'); put(join(s, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";'); rank(join(s, 'content', 'plugins'), 'seo-by-rank-math-pro');
  assert.ok(has(cli(NEW, [...WP, '--paths', s]), 'EXPOSED'));
});

test('a link the walk can\'t reach counts as more to walk, at the floor and one level down', { skip: asRoot }, () => {
  const d = fresh('more'), outer = fresh('more-out'); mkdirSync(join(outer, 'locked')); symlinkSync(join(outer, 'locked', 'x'), join(d, 'link'));
  lock(join(outer, 'locked'));
  const none = fresh('more-none'), inner = fresh('more-inner'); mkdirSync(join(inner, 'a')); symlinkSync(join(outer, 'locked', 'x'), join(inner, 'a', 'link'));
  const results = [holdsMore(d), holdsMore(none), holdsMore(inner, [], { checked: () => false, inVenv: true })];
  chmodSync(join(outer, 'locked'), 0o755);
  assert.deepEqual(results, [true, false, true]);
});

test('temp folders: a level above T is a gap, zz is not, and a refused per-user folder is one row', { skip: asRoot }, () => {
  const root = fresh('tmp'), t = join(root, 'aa', 'bb', 'T'); mkdirSync(t, { recursive: true }); mkdirSync(join(root, 'zz', 'cc', 'T'), { recursive: true });
  const look = (p) => { lock(p); const out = tempDirs('darwin', root).filter((x) => x.startsWith(root)); chmodSync(p, 0o755); return out; };
  assert.ok(look(join(root, 'aa')).includes(join(root, 'aa')));
  assert.ok(!look(join(root, 'zz')).includes(join(root, 'zz')));
  assert.deepEqual(look(join(root, 'aa', 'bb')).filter((x) => x.includes('aa')), [t]);
});

test('Xcode\'s Python is on the list, as the Command Line Tools\' is', () => {
  assert.ok(SITE_PATTERNS.some((p) => p.startsWith('/Applications/Xcode')));
  assert.ok(SITE_PATTERNS.some((p) => p.startsWith('/Library/Developer/CommandLineTools')));
});

test('MAC_KEEPS is a place and an errno: EPERM on those names elsewhere is UNKNOWN', { skip: notMac }, (t) => {
  const go = (sub) => {
    const h = fresh('mk');
    const v = join(h, sub, '.venv'); venv(v, { 'cook.pth': 'import cook\n' });
    const r = spawnSync('/usr/bin/sandbox-exec', ['-p', `(version 1)(allow default)(deny file-read-data (subpath "${realpathSync(join(h, sub))}"))`, process.execPath, join(NEW, 'bin/wardlatch.mjs'), '--json', '--incident', 'litellm-2026-10', '--no-containers', '--paths', fresh('e')], { encoding: 'utf8', env: { HOME: h, PATH: '/usr/bin:/bin', TMPDIR: fresh('t') } });
    return r.stdout ? r.status : null;
  };
  const a = go('Documents/.Trash');
  if (a === null) return t.skip('a sandbox cannot be applied here (this run is already inside one)');
  assert.equal(a, 2);
  assert.equal(go('Documents/clients.photoslibrary'), 2);
});

test('TOML: what the first draft swallowed', () => {
  const hit = (toml) => headersInToml(toml).length > 0;
  assert.ok(hit('note = """\nends with = {\n"""\n[mcp.http_headers]\n"X-User" = "ada"\n'), 'a multi-line string that looks like an inline table');
  assert.ok(hit('[mcp]\nx = {\n  http_headers = { "X-User" = "ada" }\n}\n'), 'a multi-line inline table');
  assert.ok(hit('x = { broken = 1\n[mcp.http_headers]\n"X-User" = "ada"\n'), 'an inline table that never closes');
  assert.ok(!hit('[mcp]\nx = { command = "npx", env = { A = "1" } }\n'), 'the control: nothing about headers');
});
