#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Mutation testing: plant one small bug at a time in a copy of the code, run the test suite on the copy, and record
// which test caught it. A planted bug no test catches is a gap in the tests.
//
//   node scripts/mutate.mjs [--critical] [--gate] [--jobs N] [--only lib/a.mjs,lib/b.mjs] [--limit N] [--shard K/N]
//                           [--timeout ms] [--baseline-runs N] [--confirm-runs K] [--out <dir>]
//                           [--allow scripts/mutants-allowed.json] [--gaps scripts/mutants-gaps.json]
//
// --critical plants only the bugs that matter most for this tool: each 'UNKNOWN' or 'EXPOSED' in the code (a status
// made, passed, returned or compared), one occurrence at a time, becomes 'SAFE'. --limit and --shard are for the report
// run only: a gate (--critical, or --gate) plants every one in the files asked for (--only; all of them by default), and
// stops (exit 2) if that is none. Each 'REVIEW' becoming 'SAFE' is a false all-clear too, but it is planted only by
// the report run (without --critical), with every other kind of bug: making it part of the gate needs a test for each
// one no test catches yet, or the maintainer's word to list it as a known gap (CONTRIBUTING.md says how many are
// planted; the weekly report, how many are caught).
//
// What "caught" means. A planted bug counts as caught only when the suite on its copy exits 1 with at least one named
// failing test, and one of those tests (up to five are tried, in turn) then fails on its own on the copy and passes on
// its own on the unmutated code, K times each in a row (--confirm-runs, default 3), the runs interleaved and run afresh
// for every planted bug (never reused), each read for that exact test (--test-name-pattern, its name escaped, so a
// pattern that matches nothing is never a pass or a fail); that test is recorded. A suite that times out, is killed by
// a signal, crashes, exits other than 0 or 1, or fails with no test named, is a timeout or an error, never a catch. A
// static test, one that also fails in every run on the static probe (an inert SAFE in code that never runs, below), is
// never a catch.
//
// A test whose result on the same code ever differs is UNRELIABLE, and named: between the unmutated suite runs, between
// the suite runs on the static probe, between a suite failure on a copy and the same test on its own there, between its
// own runs alone, or a test that passes in the unmutated suite but fails on its own on the unmutated code. Any
// unreliable test ends the run with exit 2, whatever else it found, gate or report: what it measured can't be trusted
// until the test is fixed.
//
// What that guarantees, and what it doesn't. A test that fails at random is very likely to be seen, not certain to be.
// A planted bug no test catches is still counted caught if an unrelated test that fails at random, independently, with
// probability p each run, fails in that copy's suite run, then fails in each of its K runs alone on the copy and passes
// in each of its K runs alone on the unmutated code: probability p^(K+1)(1-p)^K, at most 0.84% (at p = 4/7) for K = 3.
// For the whole run to pass with it, the R unmutated suite runs must all have passed too: p^(K+1)(1-p)^(K+R), at most
// 0.21% (p = 4/9) with R = 2, 0.074% (p = 4/11) with R = 4 as in CI, and 0.14% at p = 0.3 with R = 2 (and it must have
// passed in each of the R suite runs on the static probe as well, R more factors (1-p), so these are upper bounds).
// That is for each such planted bug; once a real catching test is confirmed, the other tests that failed beside it are
// not examined. A test that passes at random can make a caught bug look like a survivor: that errs on the side of the
// gate failing.
//
// Two lists explain a survivor. scripts/mutants-allowed.json: planted bugs a reviewer judged EQUIVALENT (no behaviour
// can tell them apart). scripts/mutants-gaps.json: known TEST GAPS, real bugs no test catches yet, listed so they are
// seen and closed. Both lists only shrink: scripts/gaps-only-shrink.mjs checks each pull request and each push to main
// in CI, and the release gate (scripts/release-check.mjs) checks against the last release that every entry added since
// carries the maintainer's "approved": "maintainer, YYYY-MM-DD". An entry in either list that names a file not
// mutated, an unknown operator, or the same planted bug twice is refused (exit 2).
// With --critical or --gate the exit code is 1 when a survivor is in neither list, when a listed one is now caught
// (take it off its list), when an entry in either list matches no planted bug (stale), or when any copy timed out or
// ended in an error; 2 when the unmutated code isn't stably green or any test was unreliable. Without them it only
// reports (exit 0), but still exits 2 on those.
//
// The control: the unmutated code runs first, --baseline-runs times (at least 2; by default as many as --jobs, and at
// the same --jobs as the planted bugs, so it sees the same load). Every run must pass, and every test must give the
// same result in each, or the run stops (exit 2), naming the tests.
// The suite runs with the one static test that rejects any SAFE literal outside lib/report.mjs's safe() skipped (G3
// below): it fails on every planted SAFE whatever the code does, so it would make every bug look caught. The script
// stops unless test/contract-0.1.9.test.mjs declares that test, by its exact name, exactly once, and checks that the
// skip pattern matches it and that it never runs in the copies. The tests of these scripts and of the workflows
// (TOOL_TESTS) don't run in the copies either: they exercise scripts/ and .github/, never bin/ or lib/, so they can't
// catch a planted bug, and test/mutate.test.mjs would start nested mutation runs inside every copy.
// results.json and summary.md (in --out) list every planted bug, its result and the test that caught it.
// Stopping the script (SIGINT, SIGTERM, SIGHUP) kills every running suite's whole process group.
// Needs rsync and Node 22.1 or later (--test-skip-pattern). Runs N copies at a time (default 1: one suite at a time, as
// CLAUDE.md asks of heavy jobs on a laptop; CI passes --jobs 4).
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, mkdtempSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const REPORTER = pathToFileURL(join(REPO, 'scripts', 'mutate-reporter.mjs')).href;
const STATIC_FILE = 'test/contract-0.1.9.test.mjs';
const STATIC_NAME = 'G3 a SAFE status is made in exactly one place: export function safe( in lib/report.mjs';
const TOOL_TESTS = ['test/mutate.test.mjs', 'test/release-check.test.mjs', 'test/corpus.test.mjs', 'test/guardrails.test.mjs'];
const TRIES = 5;   // failing tests examined alone, in turn, for one planted bug
const reEscape = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
const STATIC = `^${reEscape(STATIC_NAME)}$`;
const die = (msg) => { console.error(msg); process.exit(2); };

// ---- options --------------------------------------------------------------------------------------------------------
const BOOL = ['--critical', '--gate'];
const VALUED = ['--jobs', '--only', '--limit', '--shard', '--timeout', '--baseline-runs', '--confirm-runs', '--out', '--allow', '--gaps'];
const opts = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (BOOL.includes(a)) opts[a] = true;
  else if (VALUED.includes(a)) { if (i + 1 >= process.argv.length) die(`${a} needs a value`); opts[a] = process.argv[++i]; }
  else die(`unknown argument "${a}" (options: ${[...BOOL, ...VALUED].join(' ')})`);
}
const whole = (k, d, min) => {
  if (!(k in opts)) return d;
  if (!/^\d+$/.test(opts[k]) || Number(opts[k]) < min) die(`${k} needs a whole number of at least ${min}`);
  return Number(opts[k]);
};
const CRITICAL = !!opts['--critical'], GATE = CRITICAL || !!opts['--gate'];
if (GATE && ('--limit' in opts || '--shard' in opts)) die(`${CRITICAL ? '--critical' : '--gate'} plants every one: --limit and --shard are for the report run`);
const JOBS = whole('--jobs', 1, 1), LIMIT = whole('--limit', Infinity, 1), TIMEOUT_MS = whole('--timeout', 300000, 1000);
const BASELINE_RUNS = whole('--baseline-runs', Math.max(2, JOBS), 2), K = whole('--confirm-runs', 3, 3);
const ONLY = opts['--only'] ?? '';
const shard = /^(\d+)\/(\d+)$/.exec(opts['--shard'] ?? '0/1');
if (!shard || Number(shard[2]) < 1 || Number(shard[1]) >= Number(shard[2])) die('--shard needs K/N with 0 <= K < N');
const [SHARD_K, SHARD_N] = [Number(shard[1]), Number(shard[2])];
const [maj, min] = process.versions.node.split('.').map(Number);
if (maj < 22 || (maj === 22 && min < 1)) die(`Node ${process.versions.node}: needs 22.1 or later for --test-skip-pattern`);
const OUT = resolve(opts['--out'] || mkdtempSync(join(tmpdir(), 'wardlatch-mutate-')));
if (OUT === REPO || OUT.startsWith(REPO + '/')) die('--out must be outside the repository (it would be copied into every copy)');
mkdirSync(OUT, { recursive: true });
const ALLOW_FILE = resolve(REPO, opts['--allow'] ?? 'scripts/mutants-allowed.json');
const GAPS_FILE = resolve(REPO, opts['--gaps'] ?? 'scripts/mutants-gaps.json');

// ---- the static test that must be skipped ---------------------------------------------------------------------------
const testFiles = readdirSync(join(REPO, 'test')).filter((x) => x.endsWith('.test.mjs')).map((x) => `test/${x}`);
{
  const src = existsSync(join(REPO, STATIC_FILE)) ? readFileSync(join(REPO, STATIC_FILE), 'utf8') : '';
  const found = src.split(`test('${STATIC_NAME}',`).length - 1;
  const quoted = new RegExp(`(['"\`])${reEscape(STATIC_NAME)}\\1`);   // the name as a string, which the skip would also skip
  const elsewhere = testFiles.filter((f) => f !== STATIC_FILE && quoted.test(readFileSync(join(REPO, f), 'utf8')));
  if (found !== 1 || elsewhere.length) {
    die(`${STATIC_FILE} must declare test('${STATIC_NAME}', ...) exactly once, and no other test file may use that name `
      + `(found ${found}${elsewhere.length ? `; also in ${elsewhere.join(', ')}` : ''}). It is the static test every copy skips: `
      + 'if it was renamed, rename it in scripts/mutate.mjs too.');
  }
}

// ---- what is planted ------------------------------------------------------------------------------------------------
const all = [...readdirSync(join(REPO, 'lib')).filter((f) => f.endsWith('.mjs')).map((f) => `lib/${f}`), 'bin/wardlatch.mjs'];
const wanted = ONLY ? ONLY.split(',') : all;
for (const f of wanted) if (!all.includes(f)) die(`--only: ${f} is not one of the files mutated (${all.join(', ')})`);

// Each operator: a name, and a function from a line to the mutated lines (one per place it applies).
const once = (re, to) => (l) => (re.test(l) ? [l.replace(re, to)] : []);
const each = (re, to) => (l) => [...l.matchAll(re)].map((m) => l.slice(0, m.index) + to + l.slice(m.index + m[0].length));
const SAFE_OPS = [
  ['unknown->safe', each(/'UNKNOWN'/g, "'SAFE'")],
  ['exposed->safe', each(/'EXPOSED'/g, "'SAFE'")],
];
const OTHER_OPS = [
  ['review->safe', each(/'REVIEW'/g, "'SAFE'")],
  ['===->!==', once(/ === /, ' !== ')],
  ['!==->===', once(/ !== /, ' === ')],
  ['>=->>', once(/ >= /, ' > ')],
  ['<=-><', once(/ <= /, ' < ')],
  ['>->=', once(/ > (?!=)/, ' >= ')],
  ['<-<=', once(/ < (?!=)/, ' <= ')],
  ['&&->||', once(/ && /, ' || ')],
  ['||->&&', once(/ \|\| /, ' && ')],
  ['true->false', once(/return true\b/, 'return false')],
  ['false->true', once(/return false\b/, 'return true')],
  ['drop-continue', (l) => (/^\s*if \(.*\) continue;\s*$/.test(l) ? [l.replace(/continue;\s*$/, '{}')] : [])],
  ['drop-push', (l) => (/^\s*[\w.?]+\.push\(.*\);\s*$/.test(l) && !/=>/.test(l) ? [l.replace(/\S.*$/, 'void 0;')] : [])],
  ['drop-return-early', (l) => (/^\s*if \(.*\) return [^;]+;\s*$/.test(l) ? [l.replace(/return [^;]+;\s*$/, '{}')] : [])],
];
const OPS = CRITICAL ? SAFE_OPS : [...SAFE_OPS, ...OTHER_OPS];
const OP_NAMES = [...SAFE_OPS, ...OTHER_OPS].map(([op]) => op);

// Planted bugs a reviewer has judged equivalent, and known test gaps, each with its reason. Matched by file, operator,
// the line's text and which occurrence of that text it is (nth, default 1), not the line number, so an unrelated edit
// above it doesn't break the match and a copy of the line elsewhere isn't covered by it.
const key = (x) => `${x.file}\0${x.op}\0${x.before}\0${x.nth ?? 1}`;
const list = (f) => {
  let l = [];
  try { if (existsSync(f)) l = JSON.parse(readFileSync(f, 'utf8')); } catch (e) { die(`${f}: not JSON (${e.message})`); }
  if (!Array.isArray(l)) die(`${f}: must be a JSON array`);
  const keys = new Set();
  for (const a of l) {
    if (!a || typeof a !== 'object' || !a.file || !a.op || !a.before || !a.why) die(`${f}: every entry needs file, op, before and why`);
    if (!all.includes(a.file)) die(`${f}: "${a.file}" is not one of the files mutated (${all.join(', ')})`);
    if (!OP_NAMES.includes(a.op)) die(`${f}: unknown operator "${a.op}" (known: ${OP_NAMES.join(' ')})`);
    if (a.nth !== undefined && !(Number.isInteger(a.nth) && a.nth >= 1)) die(`${f}: "nth" must be a whole number from 1 (${a.file} ${a.before})`);
    if (keys.has(key(a))) die(`${f}: the same planted bug is listed twice: ${a.file} [${a.op}${(a.nth ?? 1) > 1 ? ` #${a.nth}` : ''}] ${a.before}`);
    keys.add(key(a));
  }
  return l;
};
const ALLOWED = list(ALLOW_FILE), GAPS = list(GAPS_FILE);
const allowedKeys = new Set(ALLOWED.map(key)), gapKeys = new Set(GAPS.map(key));
for (const k of allowedKeys) if (gapKeys.has(k)) die('an entry is in both the allow list and the gaps list: it is either equivalent or a gap');

const isCode = (l) => { const t = l.trim(); return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*'); };
const mutants = [], seen = new Map();
for (const f of all) {
  const lines = readFileSync(join(REPO, f), 'utf8').split('\n');
  lines.forEach((l, i) => {
    if (!isCode(l)) return;
    for (const [op, fn] of OPS) {
      for (const m of fn(l)) {
        if (m === l) continue;
        const x = { file: f, line: i + 1, op, before: l.trim(), after: m.trim(), text: m };
        const k = `${x.file}\0${x.op}\0${x.before}`; x.nth = (seen.get(k) ?? 0) + 1; seen.set(k, x.nth);
        mutants.push(x);
      }
    }
  });
}
const mine = mutants.filter((m, i) => wanted.includes(m.file) && i % SHARD_N === SHARD_K);
const todo = mine.slice(0, LIMIT);
console.error(`${mutants.length} planted bugs in all, ${todo.length} here${SHARD_N > 1 ? ` (shard ${SHARD_K}/${SHARD_N})` : ''}, `
  + `${JOBS} at a time, copies in ${OUT}`);
if (GATE && !todo.length) die(`no ${CRITICAL ? 'UNKNOWN or EXPOSED' : 'planted bug'} in the files asked for: a gate that plants nothing checks nothing`);

// ---- running the suite ----------------------------------------------------------------------------------------------
const tests = testFiles.filter((f) => !TOOL_TESTS.includes(f));
// The copy's environment: its own folder for the red-team scenarios, and none of a parent test runner's variables (run
// under node --test, NODE_TEST_CONTEXT makes the inner run report to the outer one and exit 0 whatever fails).
const copyEnv = (dir) => {
  const env = { ...process.env, WARDLATCH_DIR: dir };
  for (const k of Object.keys(env)) if (k.startsWith('NODE_TEST')) delete env[k];
  return env;
};
// Every run is its own process group, so a timeout, or this script being stopped, kills everything it started (the CLI,
// the programs it runs), not just the runner.
const live = new Set();
const killGroup = (pid) => { try { process.kill(-pid, 'SIGKILL'); } catch { /* the group is gone */ } };
process.on('exit', () => { for (const pid of live) killGroup(pid); });
for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(sig, () => {
    const n = live.size;
    for (const pid of live) killGroup(pid);
    console.error(`\nstopped by ${sig}: ${n} running test run(s) killed, with everything they started`);
    process.exit(code);
  });
}
// node --test on a copy → { code, signal, timedOut, events: [{ ev: pass|fail, name, nesting, file, todo, skip }] }
const runTests = (dir, args) => new Promise((res) => {
  const c = spawn(process.execPath, ['--test', `--test-reporter=${REPORTER}`, ...args],
    { cwd: dir, detached: true, stdio: ['ignore', 'pipe', 'ignore'], env: copyEnv(dir) });
  if (c.pid) live.add(c.pid);
  let out = '', timedOut = false;
  c.stdout.on('data', (d) => { if (out.length < 8e6) out += d; });
  const timer = setTimeout(() => { timedOut = true; killGroup(c.pid); }, TIMEOUT_MS);
  c.on('error', () => { /* reported by close, with no code */ });
  c.on('close', (code, signal) => {
    clearTimeout(timer);
    if (c.pid) { killGroup(c.pid); live.delete(c.pid); }
    const events = [];
    for (const line of out.split('\n')) {
      if (!line.startsWith('{')) continue;
      try { const e = JSON.parse(line); if (e['wardlatch-mutate'] === 1) events.push(e); } catch { /* not a line of ours */ }
    }
    res({ code, signal, timedOut, events });
  });
});
const suite = (dir) => runTests(dir, [`--test-skip-pattern=${STATIC}`, ...tests]);
const label = (t) => `${t.file}: ${t.name}`;
// a whole file failing (it crashed, or was killed) is reported under the file's own name: that names no test
const fileLevel = (e, dir) => !e.file || e.name === e.file || resolve(dir, e.name) === resolve(dir, e.file);
const failures = (r) => r.events.filter((e) => e.ev === 'fail' && e.nesting === 0 && !e.todo && !e.skip);
// one run of the suite, read: pass, fail (with the named tests that failed), timeout, or error (with why)
const outcome = (r, dir) => {
  const failed = failures(r).filter((e) => !fileLevel(e, dir)), crashed = failures(r).filter((e) => fileLevel(e, dir));
  if (r.timedOut) return { kind: 'timeout', failed };
  if (r.code === 0 && !failures(r).length) return { kind: 'pass', failed };
  if (r.code === 1 && failed.length) return { kind: 'fail', failed };
  const why = [r.code === null ? `killed by ${r.signal}` : `exit ${r.code}`];
  if (!failed.length) why.push('no test named as failing');
  if (crashed.length) why.push(`whole files failed: ${crashed.map((e) => e.file ?? e.name).join(', ')}`);
  return { kind: 'error', failed, why: why.join(', ') };
};
// one test, on its own: pass, fail, or why it gave neither (not run, timeout, more than one test of that name, ...)
const alone = async (dir, t) => {
  const r = await runTests(dir, [`--test-skip-pattern=${STATIC}`, `--test-name-pattern=^${reEscape(t.name)}$`, t.file]);
  if (r.timedOut) return 'timeout';
  const e = r.events.filter((x) => x.nesting === 0 && x.name === t.name && x.file === t.file);
  if (e.length !== 1) return e.length ? 'ambiguous' : 'not run';
  if (e[0].todo || e[0].skip) return 'todo or skip';
  return e[0].ev;
};
const copy = (name) => {
  const dir = join(OUT, name);
  rmSync(dir, { recursive: true, force: true });
  execFileSync('rsync', ['-a', '--exclude', '.git', '--exclude', 'node_modules', `${REPO}/`, `${dir}/`]);
  return dir;
};
const drop = (dir) => {
  try { execFileSync('chmod', ['-R', 'u+rwx', dir], { stdio: 'ignore' }); } catch { /* some tests lock folders */ }
  rmSync(dir, { recursive: true, force: true });
};
// fn over items, n at a time
const pool = async (items, n, fn) => {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const k = next++; await fn(items[k], k); }
  }));
};

// ---- the control: the unmutated code, stably green ------------------------------------------------------------------
const BASE = copy('baseline');   // kept until the end: each catching test must pass on its own here
{
  const dirs = [BASE, ...Array.from({ length: BASELINE_RUNS - 1 }, (_, i) => copy(`baseline-${i + 1}`))];
  const runs = [];
  await pool(dirs, JOBS, async (d, k) => { const r = await suite(d); runs[k] = { r, o: outcome(r, d) }; if (d !== BASE) drop(d); });
  // every test's result in each run (its file, nesting and name; a test reported twice in a run, both results)
  const statusOf = (e) => (e.skip ? 'skipped' : e.todo ? `todo, ${e.ev === 'pass' ? 'passing' : 'failing'}` : e.ev === 'pass' ? 'pass' : 'fail');
  const seenIn = runs.map(({ r }) => {
    const m = new Map();
    for (const e of r.events) { const k = `${e.file}: ${e.name}${e.nesting ? ` (subtest, level ${e.nesting})` : ''}`; m.set(k, [...(m.get(k) ?? []), statusOf(e)].sort()); }
    return m;
  });
  const names = new Set(seenIn.flatMap((m) => [...m.keys()]));
  const differs = [...names].map((k) => [k, seenIn.map((m) => (m.get(k) ?? ['not reported']).join(' and '))])
    .filter(([, got]) => new Set(got).size > 1).map(([k, got]) => `${k} (${got.join('; ')})`);
  const bad = runs.map(({ o }, k) => (o.kind === 'pass' ? '' : `run ${k + 1}: ${o.kind}${o.why ? ` (${o.why})` : ''}`
    + `${o.failed.length ? `: ${o.failed.slice(0, 5).map(label).join('; ')}` : ''}`)).filter(Boolean);
  // (a Node that reports tests left out by a pattern reports them as skipped)
  const staticRan = runs.some(({ r }) => r.events.some((e) => e.name === STATIC_NAME && !e.skip));
  if (bad.length || differs.length || staticRan) drop(BASE);
  if (bad.length || differs.length) {
    die(`the unmutated code is not stably green over ${BASELINE_RUNS} suite runs at --jobs ${JOBS}: `
      + `${bad.length} run(s) failed, ${differs.length} test(s) gave different results`
      + `${bad.length ? `\n  ${bad.join('\n  ')}` : ''}${differs.length ? `\nUNRELIABLE (different results on the same code):\n  ${differs.join('\n  ')}` : ''}`);
  }
  if (staticRan) die(`the static test "${STATIC_NAME}" ran in the baseline: the skip pattern did not skip it`);
  const g3 = await runTests(BASE, [`--test-name-pattern=${STATIC}`, STATIC_FILE]);
  if (g3.events.filter((e) => e.name === STATIC_NAME && e.nesting === 0 && e.ev === 'pass' && !e.skip).length !== 1)
    die(`the skip pattern for the static test matches no passing test in ${STATIC_FILE}: it would skip nothing`);
  console.error(`baseline passes, ${BASELINE_RUNS} runs at --jobs ${JOBS}, every test the same in each`);
}

// ---- the static probe: which tests read the code's text instead of running it --------------------------------------
// One more copy: every file planted in gets, at its end, an inert SAFE in code that never runs (an exported function
// nothing calls). A test that fails on that copy fails on a SAFE literal whatever the code does, as G3 does, so it would
// make every planted SAFE look caught: it is a STATIC test, named, and never counted as a catch. That holds however it
// is named, so a stub under G3's name with the real check renamed, or a second check like G3, catches nothing. The
// suite runs on the probe --baseline-runs times (at least 2, at the same --jobs), each on a copy of its own: a static
// test fails in every run, and one that fails in some and passes in others is UNRELIABLE, named, and the run stops
// (exit 2). The control: G3 itself must fail on the probe, or the probe is not the kind of change a static test sees,
// and the run stops (exit 2), as it does if a suite on the probe ends other than by passing or failing named tests.
const PROBE = "\n// scripts/mutate.mjs, the static probe: an inert SAFE that nothing calls\nexport const mutateStaticProbe = (r) => (r === 'SAFE' ? { status: 'SAFE' } : r);\n";
const staticTests = new Map();   // label → the test
{
  const dirs = Array.from({ length: BASELINE_RUNS }, (_, i) => copy(`static-probe-${i + 1}`));
  for (const dir of dirs) for (const f of all) writeFileSync(join(dir, f), `${readFileSync(join(dir, f), 'utf8')}${PROBE}`);
  const g3 = await runTests(dirs[0], [`--test-name-pattern=${STATIC}`, STATIC_FILE]);
  const g3failed = g3.events.filter((e) => e.name === STATIC_NAME && e.nesting === 0 && e.ev === 'fail' && !e.skip).length === 1;
  const outcomes = [];
  await pool(dirs, JOBS, async (d, k) => { outcomes[k] = outcome(await suite(d), d); drop(d); });
  if (!g3failed) {
    die(`the static probe didn't make "${STATIC_NAME}" fail: a SAFE literal in code that never runs should, so either that `
      + 'test no longer checks the code\'s text (a stub under its name?) or the probe is not the kind of change it sees');
  }
  const o = outcomes.find((x) => x.kind === 'timeout' || x.kind === 'error');
  if (o) die(`the suite on the static probe ended in ${o.kind === 'timeout' ? 'a timeout' : `an error (${o.why})`}: which tests are static can't be told`);
  // every test that failed on the probe, and in how many of the runs
  const failedIn = new Map();
  for (const x of outcomes) for (const t of new Map(x.failed.map((f) => [label(f), f])).values()) failedIn.set(label(t), { t, n: (failedIn.get(label(t))?.n ?? 0) + 1 });
  const sometimes = [...failedIn].filter(([, { n }]) => n < outcomes.length).map(([l, { n }]) => `${l} (failed in ${n} of the ${outcomes.length} runs)`);
  if (sometimes.length) {
    die(`UNRELIABLE (different results on the same code, the static probe): ${sometimes.length} test(s) failed in some suite runs on `
      + `the static probe and passed in others, so whether each reads the code's text can't be told:\n  ${sometimes.join('\n  ')}`);
  }
  for (const [l, { t }] of failedIn) staticTests.set(l, t);
  console.error(`static probe, ${outcomes.length} runs: ${staticTests.size ? `${staticTests.size} static test(s), never counted as a catch: ${[...staticTests.keys()].join('; ')}` : 'no test besides G3 fails on it'}`);
}

// One test that failed in the suite on a copy: on its own on the copy, then on the unmutated code, K times, afresh.
// → { verdict: catch | unreliable | unrunnable, runs: ['copy fail', 'unmutated pass', ...], why }
// It stops at the first run that isn't what a catch needs. That run is unreliable unless it is the very first run on
// that code and gave neither a pass nor a fail (a timeout, no such test, two tests of that name): unrunnable.
const examine = async (dir, t) => {
  const runs = [];
  for (let i = 0; i < K; i++) {
    for (const [where, d, want] of [['copy', dir, 'fail'], ['unmutated', BASE, 'pass']]) {
      const got = await alone(d, t);
      runs.push(`${where} ${got}`);
      if (got === want) continue;
      if (i === 0 && got !== 'pass' && got !== 'fail') return { verdict: 'unrunnable', runs };
      const why = i === 0 && where === 'copy' ? 'failed in the suite on the planted bug, then passed on its own on it'
        : i === 0 ? 'passed in every suite run of the unmutated code, but failed on its own on it'
          : `${where === 'copy' ? 'failed on its own on the planted bug' : 'passed on its own on the unmutated code'}, then ${got === 'pass' ? 'passed' : got === 'fail' ? 'failed' : `gave "${got}"`} on the same code`;
      return { verdict: 'unreliable', runs, why };
    }
  }
  return { verdict: 'catch', runs };
};

// ---- the planted bugs -----------------------------------------------------------------------------------------------
const runOne = async (m, k) => {
  const dir = copy(`m${k}`);
  const t0 = Date.now(), ms = () => Date.now() - t0;
  try {
    const p = join(dir, m.file), lines = readFileSync(p, 'utf8').split('\n');
    lines[m.line - 1] = m.text; writeFileSync(p, lines.join('\n'));
    try { execFileSync(process.execPath, ['--check', p], { stdio: 'ignore' }); } catch { return { ...m, result: 'invalid' }; }
    const o = outcome(await suite(dir), dir);
    const by = o.failed.map(label);
    if (o.kind === 'pass') return { ...m, result: 'SURVIVED', by: [], ms: ms() };
    if (o.kind === 'timeout') return { ...m, result: 'timeout', by, ms: ms() };
    if (o.kind === 'error') return { ...m, result: 'error', reason: o.why, by, ms: ms() };
    // a static test (it failed on the probe) is never a catch: only the others are examined
    const behaviour = o.failed.filter((t) => !staticTests.has(label(t)));
    if (!behaviour.length) return { ...m, result: 'SURVIVED', by, staticOnly: true, ms: ms() };
    const tried = [], unreliable = [];
    for (const t of behaviour.slice(0, TRIES)) {
      const e = await examine(dir, t);
      tried.push({ test: label(t), verdict: e.verdict, runs: e.runs });
      if (e.verdict === 'unreliable') unreliable.push({ test: label(t), why: e.why });
      if (e.verdict === 'catch') return { ...m, result: 'caught', caughtBy: label(t), by, tried, unreliable, ms: ms() };
    }
    if (unreliable.length) return { ...m, result: 'unreliable', by, tried, unreliable, ms: ms() };
    return { ...m, result: 'error', reason: `tests failed in the suite, but none could be run on its own: ${tried.map((x) => `${x.test} (${x.runs.join(', ')})`).join('; ')}`, by, tried, ms: ms() };
  } finally { drop(dir); }
};

const results = []; let done = 0;
const save = () => writeFileSync(join(OUT, 'results.json'), JSON.stringify(results.map(({ text, ...x }) => x), null, 1));
await pool(todo, JOBS, async (m, k) => {
  const r = await runOne(m, k); results.push(r);
  const note = r.result !== 'caught' || r.unreliable?.length;
  if (++done % 10 === 0 || note) console.error(`${done}/${todo.length}${note ? `  ${r.result} ${r.file}:${r.line} ${r.op}` : ''}`);
  save();
});
drop(BASE);
save();

// ---- the verdict ----------------------------------------------------------------------------------------------------
const count = (x) => results.filter((r) => r.result === x).length;
const where = (r) => `${r.file}:${r.line} [${r.op}${r.nth > 1 ? ` #${r.nth}` : ''}]`;
const byPlace = (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.op.localeCompare(b.op) || a.nth - b.nth;
const survivors = results.filter((x) => x.result === 'SURVIVED').sort(byPlace);
const timeouts = results.filter((x) => x.result === 'timeout').sort(byPlace);
const errors = results.filter((x) => x.result === 'error').sort(byPlace);
// every test seen giving different results on the same code, with the planted bugs where it was seen
const unreliable = new Map();
for (const r of [...results].sort(byPlace)) for (const u of r.unreliable ?? []) unreliable.set(u.test, [...(unreliable.get(u.test) ?? []), `${u.why} (${where(r)})`]);
const unexplained = survivors.filter((m) => !allowedKeys.has(key(m)) && !gapKeys.has(key(m)));
const equivalent = survivors.filter((m) => allowedKeys.has(key(m))).length, known = survivors.filter((m) => gapKeys.has(key(m))).length;
const tally = `caught ${count('caught')}, survived ${survivors.length} (${equivalent} listed as equivalent, ${known} listed as known test gaps), `
  + `timeout ${timeouts.length}, error ${errors.length}, unreliable ${count('unreliable')}, invalid ${count('invalid')}`
  + `${unreliable.size ? `; ${unreliable.size} unreliable test(s)` : ''}`;
console.log(tally);
for (const [t] of staticTests) console.log(`STATIC ${t}: fails on an inert SAFE in code that never runs, so it reads the code's text; never counted as a catch`);
for (const r of survivors) console.log(`${allowedKeys.has(key(r)) ? 'EQUIVALENT' : gapKeys.has(key(r)) ? 'GAP' : 'SURVIVED'} ${where(r)}  ${r.before}  →  ${r.after}${r.staticOnly ? '  (only static tests failed)' : ''}`);
for (const r of timeouts) console.log(`TIMEOUT ${where(r)}  ${r.before}`);
for (const r of errors) console.log(`ERROR ${where(r)}  ${r.reason}`);
for (const [t, seen] of unreliable) console.log(`UNRELIABLE ${t}: ${seen.join('; ')}`);
// an entry that no planted bug in the files asked for matches is stale: it could hide a future survivor
const kinds = new Set(OPS.map(([op]) => op));
const isStale = (a) => wanted.includes(a.file) && kinds.has(a.op) && !mutants.some((m) => key(m) === key(a));
const stale = [...ALLOWED, ...GAPS].filter(isStale);
for (const a of stale) console.log(`STALE ${gapKeys.has(key(a)) ? 'gaps' : 'allow'}-list entry (no such line any more): ${a.file} [${a.op}] ${a.before}`);
// the lists only shrink: a listed planted bug that a test now catches comes off its list
const closed = results.filter((r) => r.result === 'caught' && (gapKeys.has(key(r)) || allowedKeys.has(key(r)))).sort(byPlace);
for (const r of closed) console.log(`CLOSED ${gapKeys.has(key(r)) ? 'gap' : 'equivalent entry'} (now caught by: ${r.caughtBy}): take it off its list: ${where(r)}`);
console.log(`results: ${relative(process.cwd(), join(OUT, 'results.json')) || join(OUT, 'results.json')}`);

// a test's name or a reason, in the summary's table and lists: each | escaped, and each backslash too, so one in the
// text shows as written and never escapes the character after it (a \| in a name would lose its backslash); a line
// break becomes a space
const cell = (s) => String(s ?? '').replace(/[\\|]/g, '\\$&').replace(/\n/g, ' ');
const md = [`## ${CRITICAL ? 'Critical mutants' : 'Mutation run'}${SHARD_N > 1 ? ` (shard ${SHARD_K}/${SHARD_N})` : ''}`, '', tally, '',
  `Caught: the suite failed, and the test named here then failed on its own on the planted bug and passed on its own on `
  + `the unmutated code, ${K} times each, interleaved. A test that fails at random, independently, with probability p can `
  + `still make an uncaught bug look caught, with probability p^${K + 1}(1-p)^${K} (scripts/mutate.mjs says more).`, ''];
if (staticTests.size) {
  md.push('**Static tests** (they fail on an inert SAFE in code that never runs, so they read the code\'s text; never counted as a catch):', '');
  for (const [t] of staticTests) md.push(`- ${cell(t)}`);
  md.push('');
}
if (unreliable.size) {
  md.push('**Unreliable tests** (different results on the same code; the run exits 2):', '');
  for (const [t, seen] of unreliable) md.push(`- ${cell(t)}: ${cell(seen.join('; '))}`);
  md.push('');
}
md.push('| result | where | planted bug | caught by, or why not |', '|---|---|---|---|');
for (const r of [...results].sort(byPlace)) {
  const res = r.result !== 'SURVIVED' ? r.result : allowedKeys.has(key(r)) ? 'equivalent' : gapKeys.has(key(r)) ? 'known gap' : '**SURVIVED**';
  const why = r.caughtBy ?? r.reason ?? (r.result === 'timeout' ? `over ${TIMEOUT_MS} ms` : r.staticOnly ? `only static tests failed: ${r.by.join('; ')}`
    : r.unreliable?.map((u) => `${u.test}: ${u.why}`).join('; ') ?? '');
  md.push(`| ${res} | \`${r.file}:${r.line}\` | ${r.op}${r.nth > 1 ? ` #${r.nth}` : ''} | ${cell(why)} |`);
}
writeFileSync(join(OUT, 'summary.md'), `${md.join('\n')}\n`);

if (unreliable.size) {
  console.log(`\nUNRELIABLE: ${unreliable.size} test(s) gave different results on the same code (listed above). Nothing this run `
    + 'measured can be trusted until each is fixed: a test that fails at random can make a planted bug look caught.');
  process.exit(2);
}
if (GATE && (unexplained.length || timeouts.length || errors.length || stale.length || closed.length)) {
  console.log(`\nFAIL: ${unexplained.length} new planted bug(s) no test catches, ${timeouts.length} timed out, ${errors.length} ended in an `
    + `error, ${stale.length} stale list entr${stale.length === 1 ? 'y' : 'ies'}, ${closed.length} listed one(s) now caught. Add a test `
    + `that fails on each new survivor (only if no behaviour can tell it apart, list it in ${relative(REPO, ALLOW_FILE)} with the `
    + 'reason); take caught ones off their list; re-run timed-out ones and errors on a quieter machine.');
  process.exit(1);
}
