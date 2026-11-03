// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The checks on 0.1.12's advisories, 2 Nov 2026 (CHECK-reproduce F7, F9). Each DEFECT read SAFE on 0.1.12 with its control
// passing. Nothing connects.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, chmodSync, realpathSync, symlinkSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { fresh, put, cli, NEW, LITELLM, HDR, brief, has, safeOnly } from './support/seat7-lib.mjs';

const asRoot = process.getuid?.() === 0;
const undo = []; const lock = (p) => { chmodSync(p, 0); undo.push(p); };
after(() => { for (const p of undo) { try { chmodSync(p, 0o755); } catch { /* */ } } });
const opened = () => { for (const p of undo.splice(0)) chmodSync(p, 0o755); };
const stealer = { 'litellm-1.107.0.dist-info/METADATA': 'Name: litellm\nVersion: 1.107.0\n', 'cook.pth': 'import cook\n' };
const venv = (d) => { put(join(d, 'pyvenv.cfg'), 'home = /usr/bin\n'); put(join(d, 'bin', 'python'), ''); for (const [f, b] of Object.entries(stealer)) put(join(d, 'lib', 'python3.12', 'site-packages', f), b); return d; };
const home = () => { const h = realpathSync(fresh('h')); put(join(h, '.gitconfig'), '[user]\n\tname = Ada Lovelace\n\temail = ada@example.org\n'); return h; };
const MCP = JSON.stringify({ mcpServers: { x: { url: 'https://example.org', headers: { 'X-User': 'ada@example.org' } } } });

test('H1 a project file one level past the header walk, in a project with no .git, is read', () => {
  const root = fresh('r'), h = home();
  const near = cli(NEW, [...HDR, '--paths', root], { home: (put(join(root, 'a/b/c/d/.mcp.json'), MCP), h) });
  assert.ok(has(near, 'REVIEW'), `CONTROL at the last level walked: ${brief(near)}`);
  const far = fresh('r');
  put(join(far, 'a/b/c/d/e/.mcp.json'), MCP);
  const r = cli(NEW, [...HDR, '--paths', far], { home: h });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`); assert.ok(has(r, 'REVIEW'), brief(r));
});
test('H2 a folder past the walk with no project file makes no row', () => {
  const root = fresh('r'), h = home();
  put(join(root, 'a/b/c/d/e/notes.txt'), 'hello\n');
  const r = cli(NEW, [...HDR, '--paths', root], { home: h });
  assert.ok(safeOnly(r), brief(r));
});

test('Q1 the quick look reads through a link to a project', () => {
  const h = home(), away = fresh('away');
  venv(join(away, '.venv'));
  mkdirSync(join(h, 'app'));
  const real = home(); venv(join(real, 'app', 'proj', '.venv'));
  assert.ok(has(cli(NEW, LITELLM, { home: real }), 'EXPOSED'), 'CONTROL the same project as a folder');
  symlinkSync(away, join(h, 'app', 'proj'));
  const r = cli(NEW, LITELLM, { home: h });
  assert.ok(has(r, 'EXPOSED'), `DEFECT ${brief(r)}`);
});
test('Q2 a link the quick look can\'t follow to a locked folder is UNKNOWN', { skip: asRoot }, () => {
  const h = home(), away = fresh('away');
  venv(join(away, '.venv'));
  mkdirSync(join(h, 'app'));
  symlinkSync(away, join(h, 'app', 'proj'));
  lock(away);
  const r = cli(NEW, LITELLM, { home: h });
  opened();
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`); assert.ok(has(r, 'UNKNOWN'), brief(r));
});
test('Q3 no false alarm: a dangling link, a link to a file, a loop, and a link to a clean folder', () => {
  const h = home(), away = fresh('away');
  put(join(away, 'x', 'notes.txt'), 'hello\n');
  mkdirSync(join(h, 'app'));
  symlinkSync(join(h, 'nowhere'), join(h, 'app', 'gone'));
  symlinkSync(join(h, '.gitconfig'), join(h, 'app', 'file'));
  symlinkSync(join(h, 'app'), join(h, 'app', 'self'));
  symlinkSync(h, join(h, 'up'));
  symlinkSync(away, join(h, 'app', 'clean'));
  const r = cli(NEW, LITELLM, { home: h });
  assert.ok(safeOnly(r), brief(r));
});
test('Q4 a link goes no deeper than a folder would', () => {
  const h = home(), away = fresh('away');
  venv(join(away, 'x', 'y', '.venv'));
  mkdirSync(join(h, 'app'));
  symlinkSync(away, join(h, 'app', 'proj'));
  const real = home(); venv(join(real, 'app', 'proj', 'x', 'y', '.venv'));
  const f = cli(NEW, LITELLM, { home: real }), l = cli(NEW, LITELLM, { home: h });
  assert.equal(has(l, 'EXPOSED'), has(f, 'EXPOSED'), `folder ${brief(f)}; link ${brief(l)}`);
});

test('L1 a venv whose own name is no UTF-8, at the quick look\'s floor, has a row', { skip: process.platform !== 'linux' }, () => {
  const h = home(), bad = Buffer.from('.venv\xe9', 'latin1');
  const plain = home(); venv(join(plain, 'app', 'x', '.venv'));
  assert.ok(has(cli(NEW, LITELLM, { home: plain }), 'EXPOSED'), 'CONTROL a plain name');
  const made = venv(join(h, 'made'));
  mkdirSync(join(h, 'app', 'x'), { recursive: true });
  renameSync(made, Buffer.concat([Buffer.from(join(h, 'app', 'x') + '/'), bad]));
  const r = cli(NEW, LITELLM, { home: h });
  assert.ok(!safeOnly(r), `DEFECT ${brief(r)}`); assert.ok(has(r, 'UNKNOWN'), brief(r));
});

// EPERM needs a sandbox, and one can't be applied inside another: this skips there.
test('Q5 EPERM behind a link is said under the all-clear, and exits 0: the shape of ~/OneDrive (WV-13)', { skip: process.platform !== 'darwin' }, (t) => {
  const h = home(), away = realpathSync(fresh('away'));
  venv(join(away, '.venv'));
  mkdirSync(join(h, 'app'));
  symlinkSync(away, join(h, 'app', 'proj'));
  const run = (rule) => { const r = spawnSync('/usr/bin/sandbox-exec', ['-p', `(version 1)(allow default)${rule}`, process.execPath, join(NEW, 'bin/wardlatch.mjs'), '--json', ...LITELLM, '--paths', fresh('empty')], { encoding: 'utf8', maxBuffer: 1 << 26, env: { HOME: h, PATH: '/usr/bin:/bin' } }); return r.stdout ? { code: r.status, rows: JSON.parse(r.stdout).results } : null; };
  const ctl = run('');
  if (!ctl) return t.skip('a sandbox cannot be applied here (this run is already inside one)');
  assert.equal(ctl.code, 1, 'CONTROL with no refusal it is EXPOSED');
  const r = run(`(deny file-read-data (subpath "${away}"))`);
  assert.equal(r.code, 0, brief(r));
  assert.match(JSON.stringify(r.rows.flatMap((x) => [x.reason, ...(x.notSearched ?? [])])), /Full Disk Access/, 'nothing in the row names it');
});
