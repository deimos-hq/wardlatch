// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.16: the Brotli check (brotli-2026-10) on today's base, end to end. Found by running it on a real Mac on 10 Nov
// 2026: the check's call into the virtual-environment walk passed no list for the folders the walk stopped at (its depth
// cap) or the links it declined, so on that base the run stopped on an error (exit 2), and on the branch's old base the
// same folders went unsaid beside a Brotli all-clear. Each case here failed on the commit before its fix.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const PRELOAD = ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs')];
const VM_VARS = ['VOLTA_HOME', 'MISE_DATA_DIR', 'MISE_INSTALLS_DIR', 'MISE_SYSTEM_DATA_DIR', 'MISE_SYSTEM_INSTALLS_DIR', 'MISE_SHARED_INSTALL_DIRS', 'XDG_DATA_HOME', 'RTX_DATA_DIR', 'PROTO_HOME', 'ASDF_DATA_DIR', 'NODENV_ROOT'];
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-brotli16-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
// the runner's NODE_OPTIONS (CI sets --throw-deprecation) never reaches the child: 41e5efd
const cli = (args, env) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  const r = spawnSync(process.execPath, [...PRELOAD, BIN, ...args], { encoding: 'utf8', env: { ...rest, ...Object.fromEntries(VM_VARS.map((k) => [k, ''])), WARDLATCH_TEST_OWN_DIR: dir, ...env }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const rowsOf = (r) => { try { return JSON.parse(r.out).results; } catch { assert.fail(`not JSON (exit ${r.code}): ${r.out.slice(0, 600)} ${r.err.slice(0, 600)}`); } };

test('0.1.16 B1 a folder past the walk\'s depth cap is a Brotli row of its own (could not be tested), never a crash or a silent all-clear', () => {
  const home = fresh('b1-home'), root = fresh('b1-root');
  // a venv six levels down: past the venv walk's cap of five, with more to walk inside it
  const deepVenv = join(root, 'a', 'b', 'c', 'd', 'e', 'f', '.venv');
  mkdirSync(join(deepVenv, 'lib', 'python3.14', 'site-packages'), { recursive: true });
  writeFileSync(join(deepVenv, 'pyvenv.cfg'), 'home = /usr/bin\n');
  const r = cli(['--incident', 'brotli-2026-10', '--json', '--paths', root], { HOME: home, PATH: fresh('b1-path') });
  assert.doesNotMatch(r.out + r.err, /stopped on an error/, 'the run must not stop on an error');
  const rows = rowsOf(r);
  // macOS's own copy is a row of its own on a Mac (appleSystemRow), not an all-clear for the folders
  assert.deepEqual(rows.filter((x) => x.status === 'SAFE' && x.what !== 'macOS'), [], JSON.stringify(rows).slice(0, 1500));
  assert.ok(rows.some((x) => x.status === 'UNKNOWN' && x.what === 'depth limit'), JSON.stringify(rows).slice(0, 1500));
  assert.equal(r.code, 2);
  // the control: one level nearer, the same venv is walked, and with nothing in it the check is one receipted SAFE
  const near = cli(['--incident', 'brotli-2026-10', '--json', '--paths', join(root, 'a', 'b')], { HOME: home, PATH: fresh('b1-path2') });
  assert.equal(near.code, 0, near.out + near.err);
  assert.ok(rowsOf(near).every((x) => x.status !== 'SAFE' || x.searched?.length));
});

test('0.1.16 B2 a link the walk declines is said beside the Brotli check, not dropped', () => {
  const home = fresh('b2-home'), root = fresh('b2-root'), elsewhere = fresh('b2-elsewhere');
  const venv = join(elsewhere, 'proj', '.venv');
  mkdirSync(join(venv, 'lib', 'python3.14', 'site-packages'), { recursive: true });
  writeFileSync(join(venv, 'pyvenv.cfg'), 'home = /usr/bin\n');
  symlinkSync(join(elsewhere, 'proj'), join(root, 'proj-link'));
  const r = cli(['--incident', 'brotli-2026-10', '--json', '--paths', root], { HOME: home, PATH: fresh('b2-path') });
  assert.doesNotMatch(r.out + r.err, /stopped on an error/);
  const rows = rowsOf(r);
  // the same treatment the LiteLLM check (type installs) gives the same tree: compare, so this test follows that rule
  const twin = rowsOf(cli(['--incident', 'litellm-2026-10', '--json', '--no-containers', '--paths', root], { HOME: home, PATH: fresh('b2-path2') }));
  const said = (rs) => rs.filter((x) => x.status !== 'SAFE').map((x) => x.what).sort();
  assert.ok(said(twin).length, `the control must say something of the link: ${JSON.stringify(twin).slice(0, 800)}`);
  assert.deepEqual(said(rows), said(twin), `${JSON.stringify(rows).slice(0, 1200)}\nvs\n${JSON.stringify(twin).slice(0, 1200)}`);
});

// ---- macOS's own Brotli (Apple's security notes, 9 Nov 2026) ---------------------------------------------------------
import { appleSystemRow, SYSTEM_VERSION_PLIST } from '../lib/macos.mjs';
const INC = JSON.parse((await import('node:fs')).readFileSync(join(ROOT, 'lib', 'incidents', 'brotli-2026-10.json'), 'utf8'));

test('0.1.16 B3 macOS\'s own copy: one row from the version and Apple\'s notes, in every state, and it says it read no bytes', () => {
  const a = INC.appleSystem;
  assert.deepEqual(a.releases, ['27.2.1', '26.7.3', '15.8.3']);
  assert.deepEqual(a.sources, ['https://support.apple.com/en-us/149718', 'https://support.apple.com/en-us/149719', 'https://support.apple.com/en-us/149720']);
  for (const v of ['27.2.1', '27.3', '26.7.3', '26.8', '15.8.3', '15.9', '28.0']) {
    const r = appleSystemRow(INC, v);
    assert.equal(r.status, 'SAFE', v); assert.deepEqual(r.searched, [SYSTEM_VERSION_PLIST]);
    assert.match(r.reason, /Apple's copy is inside the system and is not read here: this rests on the version and Apple's notes$/);
  }
  for (const [v, want] of [['27.2', '27.2.1'], ['27.0', '27.2.1'], ['26.7.2', '26.7.3'], ['15.8.2', '15.8.3'], ['15.0', '15.8.3']]) {
    const r = appleSystemRow(INC, v);
    assert.equal(r.status, 'EXPOSED', v); assert.equal(r.fix, `Update macOS to ${want} or later (System Settings, General, Software Update): Apple's notes list the fix for its own Brotli there (macOS 27.2.1, 26.7.3 and 15.8.3, 9 Nov 2026).`);
    assert.match(r.reason, /this Mac doesn't have that update yet$/);
  }
  // Apple names no update for 14 and older, and its notes don't say they're unaffected: UNKNOWN, never SAFE
  for (const v of ['14.7.1', '13.0', '10.15.7']) { const r = appleSystemRow(INC, v); assert.equal(r.status, 'UNKNOWN', v); assert.match(r.reason, /Apple's notes don't say whether this release is affected$/); }
  assert.equal(appleSystemRow(INC, '').status, 'UNKNOWN'); assert.match(appleSystemRow(INC, '').reason, /^the macOS version could not be read/);
  assert.equal(appleSystemRow(INC, '20.1').status, 'UNKNOWN');
  assert.equal(appleSystemRow({ ...INC, appleSystem: undefined }, '27.2'), null);
});

test('0.1.16 B4 on a Mac, the command prints that row first, with Apple\'s fix when the release is older', { skip: process.platform !== 'darwin' && 'macOS only: the row is read on a Mac' }, () => {
  const home = fresh('b4-home'), v = join(fresh('b4-plist'), 'SystemVersion.plist'), pre = join(fresh('b4-pre'), 'as-272.cjs');
  writeFileSync(v, '<plist version="1.0">\n<dict>\n  <key>ProductVersion</key>\n  <string>27.2</string>\n</dict>\n</plist>\n');
  writeFileSync(pre, `const fs = require('node:fs'); const P = ${JSON.stringify(SYSTEM_VERSION_PLIST)}, V = ${JSON.stringify(v)};
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'openSync', 'existsSync']) { const o = fs[k]; fs[k] = (p, ...a) => o(String(p) === P ? V : p, ...a); }
require('node:module').syncBuiltinESMExports();\n`);
  const { NODE_OPTIONS, ...rest } = process.env;
  const r = spawnSync(process.execPath, [...PRELOAD, '--require', pre, BIN, '--incident', 'brotli-2026-10', '--paths', fresh('b4-root')], { encoding: 'utf8', env: { ...rest, ...Object.fromEntries(VM_VARS.map((k) => [k, ''])), WARDLATCH_TEST_OWN_DIR: dir, HOME: home, PATH: fresh('b4-path') } });
  const lines = r.stdout.split('\n');
  const at = lines.findIndex((l) => l.startsWith('EXPOSED  macOS\'s own Brotli (Safari and Apple\'s apps)'));
  assert.ok(at > 0, r.stdout + r.stderr);
  assert.match(lines[at + 1], /macOS 27\.2, read from \/System\/Library\/CoreServices\/SystemVersion\.plist: Apple's security notes of 9 Nov 2026 list CVE-2026-111497/);
  assert.match(r.stdout, /fix: Update macOS to 27\.2\.1 or later/);
  // the all-clear for copies on disk is still there: the macOS row stands in for no other
  assert.match(r.stdout, /^SAFE {5}no copy of the Brotli decoder found/m);
  assert.equal(r.status, 1);
});
