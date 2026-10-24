#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Mutation testing: plant one small bug at a time in a copy of the code, run the test suite on the copy, and record
// which test caught it. A planted bug no test catches is a gap in the tests.
//
//   node scripts/mutate.mjs [--critical] [--gate] [--jobs N] [--only lib/a.mjs,lib/b.mjs] [--limit N] [--shard K/N]
//                           [--timeout ms] [--baseline-runs N] [--out <dir>]
//                           [--allow scripts/mutants-allowed.json] [--gaps scripts/mutants-gaps.json]
//
// --critical plants only the bugs that matter most for this tool: each 'UNKNOWN' or 'EXPOSED' in the code (a status
// made, passed, returned or compared), one occurrence at a time, becomes 'SAFE'. --limit and --shard are for
// the report run only; the gate plants every one.
//
// Caught means caught by a test, not by a busy machine. A planted bug counts as caught only when the suite exits 1 with
// at least one named failing test, and one of those tests (up to five are tried) fails again when run on its own on the
// planted bug (--test-name-pattern, its name escaped) and passes on its own on the unmutated code; that test is
// recorded. If none does, the whole suite runs once more on the copy: a pass then is a survivor. Any other end is an
// error, as a timeout is: a run killed by a signal, a crash, an exit code other than 0 or 1, failures with no test
// named, or failures that never happen again alone.
//
// Two lists explain a survivor. scripts/mutants-allowed.json: planted bugs a reviewer judged EQUIVALENT (no behaviour
// can tell them apart). scripts/mutants-gaps.json: known TEST GAPS, real bugs no test catches yet, listed so they are
// seen and closed; the list may only shrink. An entry in either list
// that names a file not mutated, an unknown operator, or the same planted bug twice is refused (exit 2).
// With --critical or --gate the exit code is 1 when a survivor is in neither list, when a listed one is now caught
// (take it off its list), when an entry in either list matches no planted bug (stale), or when any copy timed out or
// ended in an error; 2 when the unmutated code isn't stably green. Without them it only reports.
//
// The control: the unmutated code runs first, --baseline-runs times (at least 2; by default as many as --jobs, and at
// the same --jobs as the planted bugs, so it sees the same load), and every run must pass.
// The suite runs with the one static test that rejects any SAFE literal outside lib/report.mjs's safe() skipped (G3
// below): it fails on every planted SAFE whatever the code does, so it would make every bug look caught. The script
// stops unless test/contract-0.1.9.test.mjs declares that test, by its exact name, exactly once, and checks that the
// skip pattern matches it and that it never runs in the copies. The tests of these scripts (TOOL_TESTS) don't run in
// the copies either: they exercise scripts/, never bin/ or lib/, so they can't catch a planted bug, and
// test/mutate.test.mjs would start nested mutation runs inside every copy.
// results.json and summary.md (in --out) list every planted bug, its result and the test that caught it.
// Stopping the script (SIGINT, SIGTERM, SIGHUP) kills every running suite's whole process group.
// Needs rsync and Node 22.1 or later (--test-skip-pattern). Runs N copies at a time (default 2; CI passes --jobs 4).
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, mkdtempSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const REPORTER = pathToFileURL(join(REPO, 'scripts', 'mutate-reporter.mjs')).href;
const STATIC_FILE = 'test/contract-0.1.9.test.mjs';
const STATIC_NAME = 'G3 a SAFE status is made in exactly one place: export function safe( in lib/report.mjs';
const TOOL_TESTS = ['test/mutate.test.mjs', 'test/release-check.test.mjs', 'test/corpus.test.mjs'];
const CONFIRM_TRIES = 5;
const reEscape = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
const STATIC = `^${reEscape(STATIC_NAME)}$`;
const die = (msg) => { console.error(msg); process.exit(2); };

// ---- options ----------------------------------------------------------------------------------------------------------
const BOOL = ['--critical', '--gate'];
const VALUED = ['--jobs', '--only', '--limit', '--shard', '--timeout', '--baseline-runs', '--out', '--allow', '--gaps'];
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
if (CRITICAL && ('--limit' in opts || '--shard' in opts)) die('--critical plants every one: --limit and --shard are for the report run');
const JOBS = whole('--jobs', 2, 1), LIMIT = whole('--limit', Infinity, 1), TIMEOUT_MS = whole('--timeout', 300000, 1000);
const BASELINE_RUNS = whole('--baseline-runs', Math.max(2, JOBS), 2);
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

// ---- what is planted ----------------------------------------------------------------------------------------------------
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
if (CRITICAL && !todo.length) die('no UNKNOWN or EXPOSED found to mutate in the files asked for');

// ---- running the suite -------------------------------------------------------------------------------------------------
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
  const bad = [];
  let staticRan = false;
  await pool(dirs, JOBS, async (d, k) => {
    const r = await suite(d), o = outcome(r, d);
    // (a Node that reports tests left out by a pattern reports them as skipped)
    if (r.events.some((e) => e.name === STATIC_NAME && !e.skip)) staticRan = true;
    if (o.kind !== 'pass') {
      bad.push(`run ${k + 1}: ${o.kind}${o.why ? ` (${o.why})` : ''}${o.failed.length ? `: ${o.failed.slice(0, 5).map(label).join('; ')}` : ''}`);
    }
    if (d !== BASE) drop(d);
  });
  if (bad.length || staticRan) drop(BASE);
  if (bad.length) die(`the unmutated baseline does not pass stably: ${bad.length} of ${BASELINE_RUNS} runs at --jobs ${JOBS} failed\n  ${bad.join('\n  ')}`);
  if (staticRan) die(`the static test "${STATIC_NAME}" ran in the baseline: the skip pattern did not skip it`);
  const g3 = await runTests(BASE, [`--test-name-pattern=${STATIC}`, STATIC_FILE]);
  if (g3.events.filter((e) => e.name === STATIC_NAME && e.nesting === 0 && e.ev === 'pass' && !e.skip).length !== 1)
    die(`the skip pattern for the static test matches no passing test in ${STATIC_FILE}: it would skip nothing`);
  console.error(`baseline passes, ${BASELINE_RUNS} runs at --jobs ${JOBS}`);
}
const onBaseline = new Map();
const passesOnBaseline = (t) => {
  const k = `${t.file}\0${t.name}`;
  if (!onBaseline.has(k)) onBaseline.set(k, alone(BASE, t).then((s) => s === 'pass'));
  return onBaseline.get(k);
};
// the first failing test that fails again on its own on the copy and passes on its own on the unmutated code
const confirm = async (dir, failed, tried) => {
  for (const t of failed) {
    const k = `${t.file}\0${t.name}`;
    if (tried.has(k)) continue;
    if (tried.size >= CONFIRM_TRIES) break;
    const onMutant = await alone(dir, t), base = onMutant === 'fail' ? await passesOnBaseline(t) : null;
    tried.set(k, { test: label(t), onMutant, passesOnBaseline: base });
    if (onMutant === 'fail' && base) return t;
  }
  return null;
};

// ---- the planted bugs ---------------------------------------------------------------------------------------------------
const runOne = async (m, k) => {
  const dir = copy(`m${k}`);
  const t0 = Date.now(), ms = () => Date.now() - t0;
  try {
    const p = join(dir, m.file), lines = readFileSync(p, 'utf8').split('\n');
    lines[m.line - 1] = m.text; writeFileSync(p, lines.join('\n'));
    try { execFileSync(process.execPath, ['--check', p], { stdio: 'ignore' }); } catch { return { ...m, result: 'invalid' }; }
    const tried = new Map(), tries = () => [...tried.values()];
    let o = outcome(await suite(dir), dir);
    const by = o.failed.map(label);
    if (o.kind === 'fail') {
      let t = await confirm(dir, o.failed, tried);
      if (t) return { ...m, result: 'caught', caughtBy: label(t), by, tried: tries(), ms: ms() };
      // failures that didn't happen again alone: the whole suite once more
      o = outcome(await suite(dir), dir);
      if (o.kind === 'pass') return { ...m, result: 'SURVIVED', by: [], notRepeated: by, tried: tries(), ms: ms() };
      if (o.kind === 'fail' && (t = await confirm(dir, o.failed, tried))) {
        return { ...m, result: 'caught', caughtBy: label(t), by: o.failed.map(label), notRepeated: by, tried: tries(), ms: ms() };
      }
      if (o.kind === 'fail') o = { kind: 'error', why: 'tests failed in the suite, but none failed again on its own while passing on its own on the unmutated code' };
    }
    if (o.kind === 'pass') return { ...m, result: 'SURVIVED', by: [], ms: ms() };
    if (o.kind === 'timeout') return { ...m, result: 'timeout', by, ms: ms() };
    return { ...m, result: 'error', reason: o.why, by, tried: tries(), ms: ms() };
  } finally { drop(dir); }
};

const results = []; let done = 0;
const save = () => writeFileSync(join(OUT, 'results.json'), JSON.stringify(results.map(({ text, ...x }) => x), null, 1));
await pool(todo, JOBS, async (m, k) => {
  const r = await runOne(m, k); results.push(r);
  if (++done % 10 === 0 || r.result !== 'caught') console.error(`${done}/${todo.length}${r.result !== 'caught' ? `  ${r.result} ${r.file}:${r.line} ${r.op}` : ''}`);
  save();
});
drop(BASE);
save();

// ---- the verdict --------------------------------------------------------------------------------------------------------
const count = (x) => results.filter((r) => r.result === x).length;
const byPlace = (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.op.localeCompare(b.op) || a.nth - b.nth;
const survivors = results.filter((x) => x.result === 'SURVIVED').sort(byPlace);
const timeouts = results.filter((x) => x.result === 'timeout').sort(byPlace);
const errors = results.filter((x) => x.result === 'error').sort(byPlace);
const unexplained = survivors.filter((m) => !allowedKeys.has(key(m)) && !gapKeys.has(key(m)));
const equivalent = survivors.filter((m) => allowedKeys.has(key(m))).length, known = survivors.filter((m) => gapKeys.has(key(m))).length;
const where = (r) => `${r.file}:${r.line} [${r.op}${r.nth > 1 ? ` #${r.nth}` : ''}]`;
const tally = `caught ${count('caught')}, survived ${survivors.length} (${equivalent} listed as equivalent, ${known} listed as known test gaps), `
  + `timeout ${timeouts.length}, error ${errors.length}, invalid ${count('invalid')}`;
console.log(tally);
for (const r of survivors) console.log(`${allowedKeys.has(key(r)) ? 'EQUIVALENT' : gapKeys.has(key(r)) ? 'GAP' : 'SURVIVED'} ${where(r)}  ${r.before}  →  ${r.after}`);
for (const r of timeouts) console.log(`TIMEOUT ${where(r)}  ${r.before}`);
for (const r of errors) console.log(`ERROR ${where(r)}  ${r.reason}`);
// an entry that no planted bug in the files asked for matches is stale: it could hide a future survivor
const kinds = new Set(OPS.map(([op]) => op));
const isStale = (a) => wanted.includes(a.file) && kinds.has(a.op) && !mutants.some((m) => key(m) === key(a));
const stale = [...ALLOWED, ...GAPS].filter(isStale);
for (const a of stale) console.log(`STALE ${gapKeys.has(key(a)) ? 'gaps' : 'allow'}-list entry (no such line any more): ${a.file} [${a.op}] ${a.before}`);
// the lists only shrink: a listed planted bug that a test now catches comes off its list
const closed = results.filter((r) => r.result === 'caught' && (gapKeys.has(key(r)) || allowedKeys.has(key(r)))).sort(byPlace);
for (const r of closed) console.log(`CLOSED ${gapKeys.has(key(r)) ? 'gap' : 'equivalent entry'} (now caught by: ${r.caughtBy}): take it off its list: ${where(r)}`);
console.log(`results: ${relative(process.cwd(), join(OUT, 'results.json')) || join(OUT, 'results.json')}`);

const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const md = [`## ${CRITICAL ? 'Critical mutants' : 'Mutation run'}${SHARD_N > 1 ? ` (shard ${SHARD_K}/${SHARD_N})` : ''}`, '', tally, '',
  'Caught: the suite failed, and the test named here then failed again on its own on the planted bug and passed on its own '
  + 'on the unmutated code.', '', '| result | where | planted bug | caught by, or why not |', '|---|---|---|---|'];
for (const r of [...results].sort(byPlace)) {
  const res = r.result !== 'SURVIVED' ? r.result : allowedKeys.has(key(r)) ? 'equivalent' : gapKeys.has(key(r)) ? 'known gap' : '**SURVIVED**';
  const why = r.caughtBy ?? r.reason ?? (r.result === 'timeout' ? `over ${TIMEOUT_MS} ms` : '');
  md.push(`| ${res} | \`${r.file}:${r.line}\` | ${r.op}${r.nth > 1 ? ` #${r.nth}` : ''} | ${cell(why)} |`);
}
writeFileSync(join(OUT, 'summary.md'), `${md.join('\n')}\n`);

if (GATE && (unexplained.length || timeouts.length || errors.length || stale.length || closed.length)) {
  console.log(`\nFAIL: ${unexplained.length} new planted bug(s) no test catches, ${timeouts.length} timed out, ${errors.length} ended in an `
    + `error, ${stale.length} stale list entr${stale.length === 1 ? 'y' : 'ies'}, ${closed.length} listed one(s) now caught. Add a test `
    + `that fails on each new survivor (only if no behaviour can tell it apart, list it in ${relative(REPO, ALLOW_FILE)} with the `
    + 'reason); take caught ones off their list; re-run timed-out ones and errors on a quieter machine, and fix a test that '
    + 'fails at random.');
  process.exit(1);
}
