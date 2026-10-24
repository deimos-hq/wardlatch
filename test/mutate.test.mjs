// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The mutation gate, scripts/mutate.mjs --critical, on a tiny throwaway repository: it passes only when a behaviour test
// catches every planted SAFE, and fails on a survivor, a timeout, a stale allow-list entry or a failing baseline. The
// static test that rejects every SAFE literal is skipped in the copies, so it can't make a survivor look caught.
// Offline; needs rsync and Node 22.1 or later, as the script does.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'mutate.mjs'), 'utf8');
const [maj, min] = process.versions.node.split('.').map(Number);
const SKIP = (maj < 22 || (maj === 22 && min < 1)) ? 'needs Node 22.1+ (--test-skip-pattern)'
  : !['/usr/bin/rsync', '/bin/rsync', '/usr/local/bin/rsync', '/opt/homebrew/bin/rsync'].some(existsSync) && 'needs rsync';
const HEAD = '// SPDX-License-Identifier: Apache-2.0\n// Copyright 2026 Deimos AI LLC\n';
const LIB = `${HEAD}export const check = (bad, known) => (!known ? { status: 'UNKNOWN' } : bad ? { status: 'EXPOSED' } : { status: 'OK' });\n`;
const BOTH = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { check } from '../lib/x.mjs';
test('exposed', () => assert.equal(check(true, true).status, 'EXPOSED'));
test('unknown', () => assert.equal(check(false, false).status, 'UNKNOWN'));\n`;
const ONLY_EXPOSED = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { check } from '../lib/x.mjs';
test('exposed', () => assert.equal(check(true, true).status, 'EXPOSED'));\n`;
// the static rule the real suite has: any SAFE literal in lib/ fails it; the gate must skip it
const STATIC = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { readFileSync } from 'node:fs';
test('G3 a SAFE status is made in exactly one place: here', () => assert.doesNotMatch(readFileSync(new URL('../lib/x.mjs', import.meta.url), 'utf8'), /'SAFE'/));\n`;
let base, n = 0;
before(() => { base = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-mutate-test-')); });
after(() => rmSync(base, { recursive: true, force: true }));

const repo = (files) => {
  const dir = join(base, `r${++n}`);
  const put = (p, t) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), t); };
  put('scripts/mutate.mjs', SCRIPT);
  put('bin/wardlatch.mjs', `${HEAD}export {};\n`);
  put('lib/x.mjs', LIB);
  for (const [p, t] of Object.entries(files)) put(p, t);
  return dir;
};
const gate = (dir, ...extra) => {
  const r = spawnSync(process.execPath, ['scripts/mutate.mjs', '--critical', '--jobs', '2', '--out', join(base, `out${++n}`), ...extra],
    { cwd: dir, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};

test('every planted SAFE caught by a behaviour test: passes, and says which test caught each', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': BOTH });
  const r = gate(dir);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /caught 2, survived 0/);
  const out = r.out.match(/^results: (.+)$/m)[1];
  const res = JSON.parse(readFileSync(out.startsWith('/') ? out : join(dir, out), 'utf8'));
  assert.deepEqual(res.map((x) => x.by[0]).sort(), ['exposed', 'unknown']);
});

test('a planted SAFE no behaviour test catches: fails, naming it, even though a static SAFE test would have', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/static.test.mjs': STATIC });
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /SURVIVED lib\/x\.mjs:3 \[unknown->safe\]/);
  assert.match(r.out, /FAIL: 1 new planted bug\(s\) no test catches/);
});

test('a survivor listed as equivalent with a reason passes; a stale entry fails', { skip: SKIP }, () => {
  const entry = { file: 'lib/x.mjs', op: 'unknown->safe', before: LIB.split('\n')[2].trim(), why: 'test' };
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'scripts/mutants-allowed.json': JSON.stringify([entry]) });
  assert.equal(gate(dir).code, 0);
  writeFileSync(join(dir, 'scripts/mutants-allowed.json'), JSON.stringify([entry, { ...entry, before: 'gone', why: 'stale' }]));
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /STALE allow-list entry/);
});

test('known test gaps: a listed gap passes; a gap a test now catches fails until it comes off the list; a stale gap fails', { skip: SKIP }, () => {
  const gap = { file: 'lib/x.mjs', op: 'unknown->safe', before: LIB.split('\n')[2].trim(), why: 'test gap' };
  let dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'scripts/mutants-gaps.json': JSON.stringify([gap]) });
  let r = gate(dir);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /1 listed as known test gaps/); assert.match(r.out, /^GAP lib\/x\.mjs:3 \[unknown->safe\]/m);
  dir = repo({ 'test/x.test.mjs': BOTH, 'scripts/mutants-gaps.json': JSON.stringify([gap]) });
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /CLOSED gap \(now caught by: unknown\)/);
  dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'scripts/mutants-gaps.json': JSON.stringify([gap, { ...gap, before: 'gone' }]) });
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /STALE gaps-list entry/);
});

test('one planted bug in both lists (equivalent and a gap) is refused (exit 2)', { skip: SKIP }, () => {
  const e = { file: 'lib/x.mjs', op: 'unknown->safe', before: LIB.split('\n')[2].trim(), why: 'x' };
  const r = gate(repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'scripts/mutants-gaps.json': JSON.stringify([e]), 'scripts/mutants-allowed.json': JSON.stringify([e]) }));
  assert.equal(r.code, 2, r.out); assert.match(r.out, /in both the allow list and the gaps list/);
});

test('a copy whose suite times out is a failure, not a catch', { skip: SKIP }, () => {
  const hang = `${HEAD}import { test } from 'node:test';\nimport { check } from '../lib/x.mjs';
test('spins while unknown reads SAFE', () => { const end = Date.now() + 60000; while (check(false, false).status === 'SAFE' && Date.now() < end); });
test('spins while exposed reads SAFE', () => { const end = Date.now() + 60000; while (check(true, true).status === 'SAFE' && Date.now() < end); });\n`;
  const r = gate(repo({ 'test/x.test.mjs': hang }), '--timeout', '3000');
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /timeout 2/);
  assert.match(r.out, /2 timed out/);
});

test('a baseline that doesn\'t pass: refused before any mutant runs (exit 2)', { skip: SKIP }, () => {
  const broken = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\ntest('always fails', () => assert.fail('broken'));\n`;
  const r = gate(repo({ 'test/x.test.mjs': broken }));
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /baseline does not pass[^\n]*always fails/);
});

test('--only naming a file that is not mutated is refused (exit 2)', { skip: SKIP }, () => {
  const r = gate(repo({ 'test/x.test.mjs': BOTH }), '--only', 'lib/typo.mjs');
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /is not one of the files mutated/);
});
