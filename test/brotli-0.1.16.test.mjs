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
  assert.deepEqual(rows.filter((x) => x.status === 'SAFE'), [], JSON.stringify(rows).slice(0, 1500));
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
