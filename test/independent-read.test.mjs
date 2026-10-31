// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The independent read of fix/false-safes at da8f5c2 (31 Oct 2026): five readers with different lenses, then five
// refuters who re-ran every finding. Each test here stands in front of one confirmed finding, is named after it, and
// failed at da8f5c2 for the reason its name gives (or, for a test that could not fail before, fails on the mutant the
// refuter planted). Offline: no test reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const EPERM = join(ROOT, 'test', 'support', 'eperm-places.cjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-independent-read-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } } rmSync(dir, { recursive: true, force: true }); });

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const spawnCli = (args, env = {}, nodeArgs = [], program = process.execPath, pre = []) => spawnSync(program, [...pre, ...(program === process.execPath ? [] : [process.execPath]), ...nodeArgs, BIN, ...args, '--json'],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
const parse = (r) => { let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 600)}`); } return { code: r.status, rows }; };
const run = (args, env = {}, nodeArgs = []) => parse(spawnCli(args, env, nodeArgs));
/** The CLI with `paths` refused with EPERM (test/support/eperm-places.cjs), stat still answering. */
const refused = (args, paths, env = {}) => run(args, { ...env, WARDLATCH_TEST_EPERM: JSON.stringify(paths) }, ['--require', EPERM]);
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

/** A virtual environment holding the LiteLLM 1.107.0 install record and its dropped cook.pth. */
function litellmVenv(path) {
  const sp = join(path, 'lib', 'python3.12', 'site-packages');
  put(join(path, 'pyvenv.cfg'), 'home = /usr/bin\n');
  put(join(sp, 'litellm-1.107.0.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n');
  put(join(sp, 'cook.pth'), 'import os\n');
  return sp;
}
const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];

// ---- owner decision #32 (WV-2, claims F1, M6, WV-14, WV-8) -------------------------------------------------------------
// At da8f5c2 any EPERM on a folder whose mode would let the run in was read as "macOS is protecting it" and became a
// stated gap: a REVIEW line beside SAFE, exit 0. An unprivileged sandbox profile gives exactly that EPERM, and the
// refuter turned a real EXPOSED ×2, exit 1 into SAFE, exit 0 with one. The owner's decision, 31 Oct 2026: "Yes,
// UNKNOWN" — any folder Wardlatch could not open, EPERM included, is UNKNOWN with exit 2, never SAFE.
test('decision #32 (WV-2): a folder that refuses with EPERM is could-not-be-tested, exit 2, never a stated gap beside SAFE', () => {
  const root = fresh('d32-root'), hidden = join(root, 'hidden');
  litellmVenv(join(hidden, 'proj', '.venv'));
  // the control: readable, the stealer is found
  const open = run([...LITELLM, '--paths', root]);
  assert.equal(open.code, 1, `control: ${JSON.stringify(open.rows)}`);
  const r = refused([...LITELLM, '--paths', root], [hidden]);
  const row = r.rows.find((x) => x.path === hidden);
  assert.equal(row?.status, 'UNKNOWN', `the refused folder must be its own UNKNOWN row: ${JSON.stringify(r.rows)}`);
  assert.ok(!r.rows.some((x) => x.kind === 'skipped' && JSON.stringify(x).includes(hidden)), `never in the stated-gap line: ${JSON.stringify(r.rows)}`);
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], 'no all-clear beside a folder that was not searched');
  assert.equal(r.code, 2);
  // and for every check that walks folders
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const x = refused(['--incident', id, '--paths', root], [hidden]);
    assert.equal(x.rows.find((y) => y.path === hidden)?.status, 'UNKNOWN', `${id}: ${JSON.stringify(x.rows)}`);
    assert.equal(x.code, 2, id);
  }
});

test('decision #32 (WV-14, WV-8): the EPERM row says what was measured, and never claims to know macOS is protecting the folder', () => {
  const root = fresh('d32b-root'), hidden = fresh('d32b-root/hidden');
  chmodSync(hidden, 0o755);
  const r = refused(['--incident', 'github-actions-2026-10', '--paths', root], [hidden]);
  const row = r.rows.find((x) => x.path === hidden);
  assert.ok(row, JSON.stringify(r.rows));
  assert.equal(row.code, 'EPERM');
  assert.equal(row.basis, AS_ROOT ? `EPERM, mode 0755, owner ${row.basis.split('owner ')[1]}` : 'EPERM, mode 0755, owner you');
  assert.match(row.reason, /EPERM, mode 0755/, 'the basis a reader checks with one ls -ld, in the sentence too');
  // a sandbox gives this as well as macOS's privacy protection: the row may say what is common, never which it was
  assert.doesNotMatch(row.reason, /macOS is protecting|sudo cannot open|cannot be forged/, row.reason);
  assert.match(row.reason, /sandbox/, 'a sandbox around the run is named as a cause, since it is one');
  if (process.platform === 'darwin') assert.match(row.reason, /often[^.]*privacy protection[^.]*Full Disk Access[^.]*may lift/, row.reason);
  else assert.doesNotMatch(row.reason, /macOS|Full Disk Access/, `off macOS the row does not talk about macOS: ${row.reason}`);
  // a --paths folder that refuses is UNKNOWN with the same basis
  const direct = refused(['--incident', 'github-actions-2026-10', '--paths', hidden], [hidden]);
  assert.equal(direct.rows.find((x) => x.path === hidden)?.code, 'EPERM', JSON.stringify(direct.rows));
  assert.equal(direct.code, 2);
});

// The refuter's own reproduction, with the real mechanism: an unprivileged sandbox-exec profile. A sandbox cannot be
// applied inside another one, so this skips (and says why) when the suite itself runs in one.
test('decision #32: the refuter\'s LiteLLM case under a real unprivileged sandbox is UNKNOWN, exit 2, not SAFE, exit 0',
  { skip: process.platform !== 'darwin' && 'sandbox-exec is macOS\'s' }, (t) => {
    const root = fresh('d32c-root'), hidden = join(root, 'hidden');
    litellmVenv(join(hidden, 'proj', '.venv'));
    const profile = put(join(dir, 'd32c.sb'), `(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip "localhost:*"))\n(deny file-read-data (subpath ${JSON.stringify(hidden)}))\n`);
    const raw = spawnCli([...LITELLM, '--paths', root], {}, [], '/usr/bin/sandbox-exec', ['-f', profile]);
    if (/sandbox_apply/.test(raw.stderr)) return t.skip('a sandbox cannot be applied here (this run is already inside one)');
    const r = parse(raw);
    const row = r.rows.find((x) => x.path === hidden);
    assert.equal(row?.status, 'UNKNOWN', JSON.stringify(r.rows));
    assert.equal(row.code, 'EPERM');
    assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), []);
    assert.equal(r.code, 2);
  });
