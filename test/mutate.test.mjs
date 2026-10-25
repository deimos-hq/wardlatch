// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The mutation gate, scripts/mutate.mjs --critical, on a tiny throwaway repository. It passes only when a behaviour
// test catches every planted SAFE. A catch is a test that failed in the suite and then fails on its own on the planted
// bug and passes on its own on the unmutated code, 3 times each, interleaved; a crash, a signal or a timeout is never
// one. A test seen giving different results on the same code ends the run with exit 2, naming it: between the
// unmutated suite runs, a suite failure that doesn't repeat alone, a test that fails alone on the unmutated code, or
// any change in its runs alone, each driven here by a test that fails on a fixed schedule. What that leaves, shown here
// too: an uncaught bug still reads caught if a test failing at random fails in exactly the right runs, probability
// p^4(1-p)^3 for one planted bug, p^4(1-p)^5 for the whole gate to pass with it (scripts/mutate.mjs). Seeded runs of a
// test failing at random with p = 0.3 never pass the gate here. It fails on a survivor, a timeout, an error, a stale or
// caught list entry, and refuses bad lists and options. The static test that rejects every SAFE literal (G3) is skipped
// in the copies, so it can't make a survivor look caught, and the script stops if that test isn't where it expects it.
// Stopping the script kills every suite it started, with everything those started. Also scripts/gaps-only-shrink.mjs,
// the check that the two lists of survivors (known gaps, equivalent) only shrink. Offline; the gate needs rsync and
// Node 22.1 or later, as the script does.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');
const SCRIPT = readFileSync(join(SCRIPTS, 'mutate.mjs'), 'utf8');
const REPORTER = readFileSync(join(SCRIPTS, 'mutate-reporter.mjs'), 'utf8');
const SHRINK = readFileSync(join(SCRIPTS, 'gaps-only-shrink.mjs'), 'utf8');
// the static test's exact name, read from the script (written out here, this file would declare it too)
const G3 = SCRIPT.match(/^const STATIC_NAME = '([^']+)';/m)[1];
const [maj, min] = process.versions.node.split('.').map(Number);
const SKIP = (maj < 22 || (maj === 22 && min < 1)) ? 'needs Node 22.1+ (--test-skip-pattern)'
  : !['/usr/bin/rsync', '/bin/rsync', '/usr/local/bin/rsync', '/opt/homebrew/bin/rsync'].some(existsSync) && 'needs rsync';
const HEAD = '// SPDX-License-Identifier: Apache-2.0\n// Copyright 2026 Deimos AI LLC\n';
const LIB = `${HEAD}export const check = (bad, known) => (!known ? { status: 'UNKNOWN' } : bad ? { status: 'EXPOSED' } : { status: 'OK' });\n`;
const IMPORTS = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { check } from '../lib/x.mjs';\n`;
const BOTH = `${IMPORTS}test('exposed', () => assert.equal(check(true, true).status, 'EXPOSED'));
test('unknown', () => assert.equal(check(false, false).status, 'UNKNOWN'));\n`;
const ONLY_EXPOSED = `${IMPORTS}test('exposed', () => assert.equal(check(true, true).status, 'EXPOSED'));\n`;
// the static rule the real suite has, where the script expects it: any SAFE literal in lib/ fails it; the gate skips it
const STATIC = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { readFileSync } from 'node:fs';
test('${G3}', () => assert.doesNotMatch(readFileSync(new URL('../lib/x.mjs', import.meta.url), 'utf8'), /'SAFE'/));\n`;
const PLANTED = "check(false, false).status === 'SAFE' || check(true, true).status === 'SAFE'";
let base, n = 0;
before(() => { base = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-mutate-test-')); });
after(() => rmSync(base, { recursive: true, force: true }));

const repo = (files) => {
  const dir = join(base, `r${++n}`);
  const put = (p, t) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), t); };
  put('scripts/mutate.mjs', SCRIPT);
  put('scripts/mutate-reporter.mjs', REPORTER);
  put('bin/wardlatch.mjs', `${HEAD}export {};\n`);
  put('lib/x.mjs', LIB);
  put('test/contract-0.1.9.test.mjs', STATIC);
  for (const [p, t] of Object.entries(files)) if (t === null) rmSync(join(dir, p)); else put(p, t);
  return dir;
};
const args = (extra) => ['scripts/mutate.mjs', '--critical', '--jobs', '2', '--out', join(base, `out${++n}`), ...extra];
const gate = (dir, extra = [], env = {}) => {
  const r = spawnSync(process.execPath, args(extra), { cwd: dir, encoding: 'utf8', timeout: 120000, env: { ...process.env, ...env } });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const resultsOf = (dir, out) => {
  const f = out.match(/^results: (.+)$/m)[1];
  const p = f.startsWith('/') ? f : join(dir, f);
  return { results: JSON.parse(readFileSync(p, 'utf8')), summary: readFileSync(join(dirname(p), 'summary.md'), 'utf8') };
};
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
const until = async (cond, ms) => { const end = Date.now() + ms; while (!cond() && Date.now() < end) await new Promise((r) => setTimeout(r, 100)); return cond(); };
// a test that hangs on a planted SAFE, with a program it started (same process group): both pids written to $WL_PIDS
const HANGS = `${HEAD}import { test } from 'node:test';\nimport { spawn } from 'node:child_process';\nimport { writeFileSync } from 'node:fs';
import { join } from 'node:path';\nimport { check } from '../lib/x.mjs';
test('hangs on a planted SAFE', async () => {
  if (!(${PLANTED})) return;
  const c = spawn('sleep', ['300'], { stdio: 'ignore' });
  writeFileSync(join(process.env.WL_PIDS, \`\${process.pid}-\${c.pid}\`), '');
  await new Promise((r) => setTimeout(r, 300000));
});\n`;
const pidsIn = (d) => readdirSync(d).flatMap((f) => f.split('-').map(Number));

test('every planted SAFE caught by a behaviour test: passes, and names the test that caught each, in results.json and summary.md', { skip: SKIP }, () => {
  // the tests of the scripts themselves never run in the copies: this one would fail the baseline
  const dir = repo({ 'test/x.test.mjs': BOTH, 'test/mutate.test.mjs': `${IMPORTS}test('a tool test', () => assert.fail('ran in a copy'));\n` });
  const r = gate(dir);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /caught 2, survived 0/);
  const { results, summary } = resultsOf(dir, r.out);
  assert.deepEqual(results.map((x) => x.caughtBy).sort(), ['test/x.test.mjs: exposed', 'test/x.test.mjs: unknown']);
  assert.match(summary, /\| caught \| `lib\/x\.mjs:3` \| exposed->safe \| test\/x\.test\.mjs: exposed \|/);
  assert.match(summary, /\| caught \| `lib\/x\.mjs:3` \| unknown->safe \| test\/x\.test\.mjs: unknown \|/);
});

test('a planted SAFE no behaviour test catches: fails, naming it, even though the static SAFE test would have', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED });
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /SURVIVED lib\/x\.mjs:3 \[unknown->safe\]/);
  assert.match(r.out, /FAIL: 1 new planted bug\(s\) no test catches/);
});

test('a test that fails once at random is not a catch: its failure doesn\'t repeat alone, so it is unreliable (exit 2), named', { skip: SKIP }, () => {
  // fails the first time it runs on a planted SAFE in a copy, and passes after: a failure the planted bug didn't cause
  const flaky = `${IMPORTS}import { mkdirSync } from 'node:fs';
test('fails once at random', () => { if (${PLANTED}) { try { mkdirSync('.failed-once'); } catch { return; } assert.fail('at random'); } });\n`;
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/flaky.test.mjs': flaky });
  const r = gate(dir);
  assert.equal(r.code, 2, r.out);
  // (seen on both planted bugs: the exposed one, where it fails too, is still caught by 'exposed', and the run still exits 2)
  assert.match(r.out, /^UNRELIABLE test\/flaky\.test\.mjs: fails once at random: [^\n]*failed in the suite on the planted bug, then passed on its own on it \(lib\/x\.mjs:3 \[unknown->safe\]\)/m);
  assert.match(r.out, /UNRELIABLE: 1 test\(s\) gave different results on the same code/);
  const { results, summary } = resultsOf(dir, r.out);
  const u = results.find((x) => x.op === 'unknown->safe');
  assert.equal(u.result, 'unreliable');
  assert.deepEqual(u.tried, [{ test: 'test/flaky.test.mjs: fails once at random', verdict: 'unreliable', runs: ['copy pass'] }]);
  assert.match(summary, /\*\*Unreliable tests\*\*/);
});

test('a test that fails on the planted bug but also fails on its own on the unmutated code is not a catch: unreliable (exit 2)', { skip: SKIP }, () => {
  // 'second' needs 'first' to have run: alone, it fails whatever the code does
  const ordered = `${IMPORTS}let ran = false;
test('first', () => { ran = true; });
test('second', () => { assert.ok(ran, 'needs first'); assert.equal(check(false, false).status, 'UNKNOWN'); });\n`;
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/ordered.test.mjs': ordered });
  const r = gate(dir);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /^UNRELIABLE test\/ordered\.test\.mjs: second: passed in every suite run of the unmutated code, but failed on its own on it/m);
  const u = resultsOf(dir, r.out).results.find((x) => x.op === 'unknown->safe');
  assert.deepEqual(u.tried, [{ test: 'test/ordered.test.mjs: second', verdict: 'unreliable', runs: ['copy fail', 'unmutated fail'] }]);
});

test('a planted bug that kills a test file (a signal, no test named as failing) is an error, not a catch', { skip: SKIP }, () => {
  const kills = `${IMPORTS}test('dies on a planted SAFE', () => { if (${PLANTED}) process.kill(process.pid, 'SIGKILL'); });\n`;
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/kills.test.mjs': kills });
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  // (the file is reported failed under its own name; were the test that died named too, it could never be run alone)
  assert.match(r.out, /ERROR lib\/x\.mjs:3 \[unknown->safe\]  (exit 1, no test named as failing, whole files failed: test\/kills\.test\.mjs|tests failed in the suite, but none could be run on its own)/);
  assert.match(r.out, /1 ended in an error/);
});

test('\'REVIEW\' changed to \'SAFE\' is planted by the report run (no --critical), not by the gate', { skip: SKIP }, () => {
  const lib = `${LIB}export const look = (x) => (x ? { status: 'REVIEW' } : { status: 'OK' });\n`;
  const look = `${HEAD}import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { look } from '../lib/x.mjs';
test('review', () => assert.equal(look(true).status, 'REVIEW'));\n`;
  const dir = repo({ 'lib/x.mjs': lib, 'test/x.test.mjs': BOTH, 'test/look.test.mjs': look });
  const r = gate(dir);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /caught 2, survived 0/);
  assert.deepEqual(resultsOf(dir, r.out).results.map((x) => x.op).sort(), ['exposed->safe', 'unknown->safe']);
  const out = join(base, `out${++n}`);
  const rr = spawnSync(process.execPath, ['scripts/mutate.mjs', '--jobs', '2', '--out', out], { cwd: dir, encoding: 'utf8', timeout: 120000 });
  assert.equal(rr.status, 0, `${rr.stdout}${rr.stderr}`); assert.match(rr.stdout, /caught 3, survived 0/);
  assert.equal(JSON.parse(readFileSync(join(out, 'results.json'), 'utf8')).find((x) => x.op === 'review->safe').caughtBy, 'test/look.test.mjs: review');
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
  assert.equal(r.code, 1, r.out); assert.match(r.out, /CLOSED gap \(now caught by: test\/x\.test\.mjs: unknown\)/);
  dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'scripts/mutants-gaps.json': JSON.stringify([gap, { ...gap, before: 'gone' }]) });
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /STALE gaps-list entry/);
});

test('bad lists are refused before anything runs (exit 2): in both lists, twice in one, a file not mutated, an unknown operator', { skip: SKIP }, () => {
  const e = { file: 'lib/x.mjs', op: 'unknown->safe', before: LIB.split('\n')[2].trim(), why: 'x' };
  for (const [files, why] of [
    [{ 'scripts/mutants-gaps.json': JSON.stringify([e]), 'scripts/mutants-allowed.json': JSON.stringify([e]) }, /in both the allow list and the gaps list/],
    [{ 'scripts/mutants-gaps.json': JSON.stringify([e, { ...e, nth: 1, why: 'again' }]) }, /mutants-gaps\.json: the same planted bug is listed twice/],
    [{ 'scripts/mutants-allowed.json': JSON.stringify([e, e]) }, /mutants-allowed\.json: the same planted bug is listed twice/],
    [{ 'scripts/mutants-gaps.json': JSON.stringify([{ ...e, file: 'lib/typo.mjs' }]) }, /"lib\/typo\.mjs" is not one of the files mutated/],
    [{ 'scripts/mutants-allowed.json': JSON.stringify([{ ...e, op: 'unknown->SAFE' }]) }, /unknown operator "unknown->SAFE"/],
    [{ 'scripts/mutants-gaps.json': JSON.stringify([{ ...e, nth: 0 }]) }, /"nth" must be a whole number from 1/],
  ]) {
    const r = gate(repo({ 'test/x.test.mjs': ONLY_EXPOSED, ...files }));
    assert.equal(r.code, 2, r.out); assert.match(r.out, why);
    assert.doesNotMatch(r.out, /baseline/);
  }
});

test('bad options are refused (exit 2): --limit or --shard with --critical, an unknown option, --only naming a file not mutated', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': BOTH });
  for (const [extra, why] of [
    [['--limit', '1'], /--critical plants every one: --limit and --shard are for the report run/],
    [['--shard', '0/2'], /--critical plants every one/],
    [['--jbos', '4'], /unknown argument "--jbos"/],
    [['--jobs', '0'], /--jobs needs a whole number of at least 1/],
    [['--baseline-runs', '1'], /--baseline-runs needs a whole number of at least 2/],
    [['--confirm-runs', '2'], /--confirm-runs needs a whole number of at least 3/],
    [['--only', 'lib/typo.mjs'], /is not one of the files mutated/],
  ]) {
    const r = gate(dir, extra);
    assert.equal(r.code, 2, r.out); assert.match(r.out, why);
  }
});

test('the static G3 test must be where the script expects it, by its exact name, once: renamed, twice or elsewhere stops it (exit 2)', { skip: SKIP }, () => {
  for (const files of [
    { 'test/contract-0.1.9.test.mjs': STATIC.replace(G3, `${G3} (renamed)`) },
    { 'test/contract-0.1.9.test.mjs': null, 'test/other.test.mjs': STATIC },
    { 'test/contract-0.1.9.test.mjs': STATIC + STATIC.split('\n').slice(-2).join('\n') },
    { 'test/other.test.mjs': `${STATIC.split('\n').slice(0, 4).join('\n')}\ntest('${G3}', () => {});\n` },
  ]) {
    const r = gate(repo({ 'test/x.test.mjs': BOTH, ...files }));
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /must declare test\('G3 a SAFE status is made in exactly one place: export function safe\( in lib\/report\.mjs', \.\.\.\) exactly once/);
  }
});

test('--gate without --critical is a gate too: --limit or --shard is refused, and files with nothing to plant stop it (exit 2), before anything runs', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': BOTH });
  for (const [extra, why] of [[['--limit', '1'], /--gate plants every one: --limit and --shard are for the report run/],
    [['--shard', '0/2'], /--gate plants every one/], [['--only', 'bin/wardlatch.mjs'], /no planted bug in the files asked for: a gate that plants nothing checks nothing/]]) {
    const r = spawnSync(process.execPath, ['scripts/mutate.mjs', '--gate', '--jobs', '2', '--out', join(base, `out${++n}`), ...extra], { cwd: dir, encoding: 'utf8', timeout: 120000 });
    const out = `${r.stdout}${r.stderr}`;
    assert.equal(r.status, 2, `${extra.join(' ')}\n${out}`); assert.match(out, why); assert.doesNotMatch(out, /baseline/);
  }
  const r = gate(dir, ['--only', 'bin/wardlatch.mjs']);
  assert.equal(r.code, 2, r.out); assert.match(r.out, /no UNKNOWN or EXPOSED in the files asked for/);
});

test('with no --jobs it runs one suite at a time (CLAUDE.md: heavy jobs one at a time on a laptop; CI passes --jobs 4)', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': BOTH });
  const r = spawnSync(process.execPath, ['scripts/mutate.mjs', '--critical', '--out', join(base, `out${++n}`)], { cwd: dir, encoding: 'utf8', timeout: 120000 });
  const out = `${r.stdout}${r.stderr}`;
  assert.equal(r.status, 0, out); assert.match(out, /, 1 at a time,/); assert.match(out, /baseline passes, 2 runs at --jobs 1/);
});

// The static probe: a copy with an inert SAFE in code that never runs, at the end of every file planted in. A test that
// fails there reads the code's text, as G3 does, and is never a catch.
const SECOND_STATIC = STATIC.replace(G3, 'no SAFE literal in lib');

test('a second static test, under another name, never counts as a catch: what no behaviour test catches survives (exit 1), and it is named', { skip: SKIP }, () => {
  const dir = repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/static2.test.mjs': SECOND_STATIC });
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /^STATIC test\/static2\.test\.mjs: no SAFE literal in lib: /m);
  assert.match(r.out, /caught 1, survived 1/); assert.match(r.out, /SURVIVED lib\/x\.mjs:3 \[unknown->safe\][^\n]*only static tests failed/);
  const { results, summary } = resultsOf(dir, r.out);
  assert.equal(results.find((x) => x.op === 'exposed->safe').caughtBy, 'test/x.test.mjs: exposed');
  assert.match(summary, /\*\*Static tests\*\*/);
});

test('a stub under G3\'s name with the real static test renamed beside it: G3 doesn\'t fail on the static probe, so the run stops (exit 2)', { skip: SKIP }, () => {
  const stub = `${HEAD}import { test } from 'node:test';\ntest('${G3}', () => {});\n`;
  const r = gate(repo({ 'test/x.test.mjs': ONLY_EXPOSED, 'test/contract-0.1.9.test.mjs': stub, 'test/static2.test.mjs': SECOND_STATIC }));
  assert.equal(r.code, 2, r.out); assert.match(r.out, /the static probe didn't make "G3 [^"]*" fail/); assert.doesNotMatch(r.out, /caught 2/);
});

test('a copy whose suite times out is a failure, not a catch, and everything the suite started is killed', { skip: SKIP }, async () => {
  const pids = mkdtempSync(join(base, 'pids-'));
  const r = gate(repo({ 'test/x.test.mjs': HANGS }), ['--timeout', '8000'], { WL_PIDS: pids });
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /timeout 2/);
  assert.match(r.out, /2 timed out/);
  const started = pidsIn(pids);
  assert.equal(started.length, 4, 'two test files, each with the program it started');
  assert.ok(await until(() => !started.some(alive), 5000), `still running: ${started.filter(alive).join(' ')}`);
});

test('stopping the script (SIGTERM, SIGINT) kills every running suite, with everything it started', { skip: SKIP }, async () => {
  for (const sig of ['SIGTERM', 'SIGINT']) {
    const pids = mkdtempSync(join(base, 'pids-'));
    const c = spawn(process.execPath, args([]), { cwd: repo({ 'test/x.test.mjs': HANGS }), env: { ...process.env, WL_PIDS: pids }, stdio: 'ignore' });
    const exited = new Promise((res) => c.on('exit', (code, signal) => res(code ?? signal)));
    assert.ok(await until(() => readdirSync(pids).length === 2, 60000), 'both planted bugs started hanging');
    const started = pidsIn(pids);
    c.kill(sig);
    assert.equal(await exited, sig === 'SIGTERM' ? 143 : 130);
    assert.ok(await until(() => !started.some(alive), 5000), `${sig}: still running: ${started.filter(alive).join(' ')}`);
  }
});

test('a baseline that doesn\'t pass: refused before any planted bug runs (exit 2)', { skip: SKIP }, () => {
  const broken = `${IMPORTS}test('always fails', () => assert.fail('broken'));\n`;
  const r = gate(repo({ 'test/x.test.mjs': broken }));
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /the unmutated code is not stably green over 2 suite runs at --jobs 2: 2 run\(s\) failed, 0 test\(s\) gave different results[^]*always fails/);
});

test('a baseline that passes only some of the time: refused (it runs more than once, at the same --jobs)', { skip: SKIP }, () => {
  // passes in exactly one run of the unmutated code (the first to make the folder), fails in the others
  const once = `${IMPORTS}import { mkdirSync } from 'node:fs';\nimport { join } from 'node:path';
test('passes once', () => { try { mkdirSync(join(process.env.WL_ONCE, 'm')); } catch { assert.fail('not the first run'); } });\n`;
  const r = gate(repo({ 'test/x.test.mjs': BOTH, 'test/once.test.mjs': once }), ['--baseline-runs', '3'], { WL_ONCE: mkdtempSync(join(base, 'once-')) });
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /not stably green over 3 suite runs at --jobs 2: 2 run\(s\) failed, 1 test\(s\) gave different results/);
  assert.match(r.out, /UNRELIABLE \(different results on the same code\):\n  test\/once\.test\.mjs: passes once \((pass|fail); (pass|fail); (pass|fail)\)/);
});

// ---- a test that fails at random ------------------------------------------------------------------------------------
// One planted bug no test catches (the only UNKNOWN), beside a test that passes or fails as $WL_SCHEDULE says, one
// character per run of it anywhere in the gate, in the order the runs take a number in $WL_SEQ (f fails; p, or past the
// end, passes). The gate runs it: the 2 unmutated suite runs (0 and 1, side by side), the suite on the static probe (2),
// the planted bug's suite run (3), then that test alone, on the copy and on the unmutated code by turns (4 to 9).
const LIB_U = `${HEAD}export const check = (known) => (!known ? { status: 'UNKNOWN' } : { status: 'OK' });\n`;
const KNOWN = `${IMPORTS}test('known', () => assert.equal(check(true).status, 'OK'));\n`;
const SCHEDULED = `${IMPORTS}import { mkdirSync } from 'node:fs';\nimport { join } from 'node:path';
test('fails on schedule', () => {
  let n = 0;
  for (;; n++) { try { mkdirSync(join(process.env.WL_SEQ, String(n))); break; } catch (e) { if (e.code !== 'EEXIST') throw e; } }
  assert.notEqual((process.env.WL_SCHEDULE ?? '')[n], 'f', \`run \${n} fails on schedule\`);
});\n`;
// what the rule gives for a schedule: 2 when the test is seen unreliable, 1 when the planted bug survives (a test that
// failed on the static probe is never a catch), 0 when it is counted caught (wrongly: nothing catches it)
const expected = (sch) => {
  const f = (k) => sch[k] === 'f';
  if (f(0) || f(1)) return 2;
  if (f(2) || !f(3)) return 1;
  for (let k = 4; k <= 9; k++) if (f(k) !== (k % 2 === 0)) return 2;   // on the copy (4, 6, 8) it must fail, unmutated pass
  return 0;
};
const gateAsync = (dir, extra, env) => new Promise((res) => {
  const c = spawn(process.execPath, args(extra), { cwd: dir, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
  c.on('close', (code) => res({ code, out }));
});
const onSchedule = async (schedules) => {
  const got = [];
  for (let i = 0; i < schedules.length; i += 4) {
    got.push(...await Promise.all(schedules.slice(i, i + 4).map((sch) => gateAsync(repo({ 'lib/x.mjs': LIB_U, 'test/x.test.mjs': KNOWN, 'test/s.test.mjs': SCHEDULED }),
      [], { WL_SCHEDULE: sch, WL_SEQ: mkdtempSync(join(base, 'seq-')) }))));
  }
  return got;
};

test('a test with a different result on the same code, anywhere, ends the run with exit 2, naming it; only the exact residual schedule passes', { skip: SKIP }, async () => {
  const cases = [
    ['fp', /not stably green over 2 suite runs at --jobs 2: 1 run\(s\) failed, 1 test\(s\) gave different results[^]*test\/s\.test\.mjs: fails on schedule \((pass; fail|fail; pass)\)/],
    ['ff', /not stably green over 2 suite runs at --jobs 2: 2 run\(s\) failed/],
    ['pppp', /SURVIVED lib\/x\.mjs:3 \[unknown->safe\]/],
    ['pppfp', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: failed in the suite on the planted bug, then passed on its own on it/],
    ['pppfff', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: passed in every suite run of the unmutated code, but failed on its own on it/],
    ['pppffpp', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: failed on its own on the planted bug, then passed on the same code/],
    ['pppffpff', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: passed on its own on the unmutated code, then failed on the same code/],
    // two good rounds are not enough: the third run on the copy passes
    ['pppffpfpp', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: failed on its own on the planted bug, then passed on the same code/],
    ['pppffpfpff', /UNRELIABLE test\/s\.test\.mjs: fails on schedule: passed on its own on the unmutated code, then failed on the same code/],
    // the residual scripts/mutate.mjs computes: passing on the static probe, failing in the suite and then in exactly
    // the right 6 runs alone, it reads as a catch
    ['pppffpfpfp', /caught 1, survived 0/],
    // the same, but failing on the static probe too: never a catch
    ['ppfffpfpfp', /^STATIC test\/s\.test\.mjs: fails on schedule[^]*SURVIVED lib\/x\.mjs:3 \[unknown->safe\]/m],
  ];
  const got = await onSchedule(cases.map(([sch]) => sch));
  cases.forEach(([sch, why], i) => {
    assert.equal(got[i].code, expected(sch), `${sch}\n${got[i].out}`);
    assert.match(got[i].out, why, sch);
    if (got[i].code === 2 && expected(sch) === 2 && sch.length > 2) assert.match(got[i].out, /UNRELIABLE: 1 test\(s\) gave different results/, sch);
  });
});

test('a test failing at random (p = 0.3, 24 seeded schedules): the gate never passes; failing on the static probe it is never a catch (exit 1), and otherwise it exits 2 whenever that test failed', { skip: SKIP }, async () => {
  // mulberry32: the same schedules every run of this test
  const draw = (seed) => {
    let a = seed >>> 0;
    return Array.from({ length: 12 }, () => {
      a = (a + 0x6D2B79F5) >>> 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296 < 0.3 ? 'f' : 'p';
    }).join('');
  };
  const schedules = Array.from({ length: 24 }, (_, i) => draw(i + 1));
  const got = await onSchedule(schedules);
  schedules.forEach((sch, i) => {
    assert.notEqual(got[i].code, 0, `${sch}: the gate passed\n${got[i].out}`);
    assert.equal(got[i].code, expected(sch), `${sch}\n${got[i].out}`);
    // exit 1 only when the test failed on the static probe (never a catch then), or never failed before the planted
    // bug's suite run passed: nothing showed it
    if (got[i].code === 1) assert.match(sch, /^pp(f|pp)/);
  });
  assert.deepEqual([...new Set(got.map((g) => g.code))].sort(), [1, 2]);
});

// ---- scripts/gaps-only-shrink.mjs -----------------------------------------------------------------------------------
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' };
const gitIn = (dir, ...a) => execFileSync('git', a, { cwd: dir, env: GIT_ENV, encoding: 'utf8' }).trim();
// commits the gaps list (null: no list), and the allow list when given (null: no list; left as it is when not given)
const gaps = (dir, list, allowed) => {
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  if (list) writeFileSync(join(dir, 'scripts/mutants-gaps.json'), JSON.stringify(list, null, 1)); else rmSync(join(dir, 'scripts/mutants-gaps.json'), { force: true });
  if (allowed) writeFileSync(join(dir, 'scripts/mutants-allowed.json'), JSON.stringify(allowed, null, 1));
  else if (allowed === null) rmSync(join(dir, 'scripts/mutants-allowed.json'), { force: true });
  writeFileSync(join(dir, 'scripts/gaps-only-shrink.mjs'), SHRINK);
  gitIn(dir, 'add', '-A'); gitIn(dir, 'commit', '-q', '--allow-empty', '-m', 'gaps');
  return gitIn(dir, 'rev-parse', 'HEAD');
};
const shrink = (dir, ...a) => {
  const r = spawnSync(process.execPath, ['scripts/gaps-only-shrink.mjs', ...a], { cwd: dir, env: GIT_ENV, encoding: 'utf8' });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const G = (k) => ({ file: 'lib/x.mjs', op: 'unknown->safe', before: `line ${k}`, why: 'test gap' });

test('the gaps list only shrinks: an entry the base doesn\'t have fails (exit 1), naming it; fewer, or reworded reasons, pass', () => {
  const dir = join(base, `g${++n}`); mkdirSync(dir); gitIn(dir, 'init', '-q', '-b', 'main');
  const at = gaps(dir, [G(1), G(2)]);
  gaps(dir, [G(1), G(2), G(3)]);
  let r = shrink(dir, at);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /gained 1 entry not in it at/); assert.match(r.out, /lib\/x\.mjs \[unknown->safe\] line 3/);
  gaps(dir, [G(1), { ...G(2), nth: 2 }]);   // the same line's second occurrence is another planted bug
  r = shrink(dir, at); assert.equal(r.code, 1, r.out); assert.match(r.out, /\[unknown->safe #2\] line 2/);
  gaps(dir, [{ ...G(2), why: 'reworded', nth: 1 }]);
  r = shrink(dir, at); assert.equal(r.code, 0, r.out); assert.match(r.out, /none new/);
  gaps(dir, []);
  assert.equal(shrink(dir, at).code, 0);
});

test('the allow list only shrinks too: a new equivalent entry fails (exit 1), and so does a gap moved onto it', () => {
  const dir = join(base, `g${++n}`); mkdirSync(dir); gitIn(dir, 'init', '-q', '-b', 'main');
  const at = gaps(dir, [G(1), G(2)], []);
  gaps(dir, [G(1), G(2)], [{ ...G(9), why: 'equivalent (a reviewer agreed)' }]);
  let r = shrink(dir, at);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /mutants-allowed\.json gained 1 entry not in it at [0-9a-f]{12}:\n {2}lib\/x\.mjs \[unknown->safe\] line 9/);
  gaps(dir, [G(1)], [{ ...G(2), why: 'equivalent' }]);   // off the gaps list (it shrank), onto the allow list
  r = shrink(dir, at);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /ok: scripts\/mutants-gaps\.json has 1 entry/); assert.match(r.out, /mutants-allowed\.json gained 1 entry[^]*line 2/);
  gaps(dir, [G(1)], []);
  r = shrink(dir, at); assert.equal(r.code, 0, r.out);
});

test('a list the base doesn\'t have is compared with the last release that has it, or with nothing; a base that isn\'t a commit stops it (exit 2)', () => {
  const dir = join(base, `g${++n}`); mkdirSync(dir); gitIn(dir, 'init', '-q', '-b', 'main');
  const at = gaps(dir, null);
  gaps(dir, [G(1)]);
  let r = shrink(dir, at);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /mutants-gaps\.json gained 1 entry not in it at nothing \(not at [0-9a-f]{12}, nor in any release before it\)/);
  // deleted after a release that had it, then back longer: the release's list is the base
  gitIn(dir, 'tag', 'v0.1.9', gaps(dir, [G(1), G(2)]));
  const gone = gaps(dir, null);
  gaps(dir, [G(1), G(2), G(3)]);
  r = shrink(dir, gone);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /gained 1 entry not in it at v0\.1\.9 \(not at [0-9a-f]{12}\):\n {2}lib\/x\.mjs \[unknown->safe\] line 3/);
  gaps(dir, [G(2)]);
  r = shrink(dir, gone); assert.equal(r.code, 0, r.out); assert.match(r.out, /none new since v0\.1\.9/);
  r = shrink(dir, 'no-such-commit');
  assert.equal(r.code, 2, r.out); assert.match(r.out, /no-such-commit is not a commit here/);
  // with no base given: where HEAD left origin/main
  const origin = `${dir}-origin.git`; gitIn(base, 'init', '-q', '--bare', origin);
  gitIn(dir, 'remote', 'add', 'origin', origin); gitIn(dir, 'push', '-q', 'origin', 'main'); gitIn(dir, 'fetch', '-q', 'origin');
  gaps(dir, [G(1), G(2)]);
  r = shrink(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /gained 1 entry[^\n]*:\n {2}lib\/x\.mjs \[unknown->safe\] line 1\n/);
});
