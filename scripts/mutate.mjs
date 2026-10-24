#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Mutation testing: plant one small bug at a time in a copy of the code, run the whole test suite on the copy, and record
// which tests caught it. A planted bug no test catches is a gap in the tests.
//
//   node scripts/mutate.mjs [--critical] [--gate] [--jobs N] [--only lib/a.mjs,lib/b.mjs] [--limit N] [--shard K/N]
//                           [--timeout ms] [--out <dir>] [--allow scripts/mutants-allowed.json] [--gaps scripts/mutants-gaps.json]
//
// --critical plants only the bug that matters most for this tool: each 'UNKNOWN' or 'EXPOSED' in the code (a status
// made, passed, returned or compared), one occurrence at a time, becomes 'SAFE'. Every one must be caught.
// Two lists explain a survivor. scripts/mutants-allowed.json: planted bugs a reviewer judged EQUIVALENT (no behaviour can
// tell them apart). scripts/mutants-gaps.json: known TEST GAPS, real bugs no test catches yet, listed so they are seen
// and closed; the list may only shrink. With --critical or --gate the exit code is 1 when a survivor is in neither
// list, when a listed gap is now caught (take it off the list), when an entry in either list matches no planted bug
// (stale), or when any copy's suite times out (an overloaded machine is not a catch); 2 when the unmutated baseline
// doesn't pass. Without them it only reports.
// The suite runs with the one static test that rejects any SAFE literal outside lib/report.mjs's safe() skipped (STATIC
// below): it fails on every planted SAFE whatever the code does, so it would make every bug look caught. The tests that
// caught each bug are recorded in results.json.
// Needs rsync and Node 22.1 or later (--test-skip-pattern). Runs N copies at a time (default 2; CI passes --jobs 4).
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, mkdtempSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const STATIC = '^G3 a SAFE status is made in exactly one place';   // test/contract-0.1.9.test.mjs
const argv = process.argv.slice(2);
const flag = (k) => argv.includes(k);
const arg = (k, d) => { const i = argv.indexOf(k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const CRITICAL = flag('--critical'), GATE = CRITICAL || flag('--gate');
const JOBS = Math.max(1, Number(arg('--jobs', 2))), LIMIT = Number(arg('--limit', 100000)), ONLY = arg('--only', '');
const TIMEOUT_MS = Number(arg('--timeout', 300000));
const [SHARD_K, SHARD_N] = arg('--shard', '0/1').split('/').map(Number);
const OUT = resolve(arg('--out', '') || mkdtempSync(join(tmpdir(), 'wardlatch-mutate-')));
const ALLOW_FILE = resolve(REPO, arg('--allow', 'scripts/mutants-allowed.json'));
const GAPS_FILE = resolve(REPO, arg('--gaps', 'scripts/mutants-gaps.json'));
const die = (msg) => { console.error(msg); process.exit(2); };
if (![JOBS, LIMIT, TIMEOUT_MS, SHARD_K, SHARD_N].every(Number.isFinite) || SHARD_N < 1 || SHARD_K < 0 || SHARD_K >= SHARD_N) die('bad number');
const [maj, min] = process.versions.node.split('.').map(Number);
if (maj < 22 || (maj === 22 && min < 1)) die(`Node ${process.versions.node}: needs 22.1 or later for --test-skip-pattern`);
if (OUT === REPO || OUT.startsWith(REPO + '/')) die('--out must be outside the repository (it would be copied into every copy)');
mkdirSync(OUT, { recursive: true });

// Planted bugs a reviewer has judged equivalent (no behaviour can tell them apart), each with its reason. Matched by
// file, operator, the line's text and which occurrence of that text it is (nth, default 1), not the line number, so an
// unrelated edit above it doesn't break the match and a copy of the line elsewhere isn't covered by it.
const list = (f) => {
  const l = existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : [];
  for (const a of l) if (!a.file || !a.op || !a.before || !a.why) die(`${f}: every entry needs file, op, before and why`);
  return l;
};
const ALLOWED = list(ALLOW_FILE), GAPS = list(GAPS_FILE);
const key = (x) => `${x.file}\0${x.op}\0${x.before}\0${x.nth ?? 1}`;
const allowedKeys = new Set(ALLOWED.map(key)), gapKeys = new Set(GAPS.map(key));
for (const k of allowedKeys) if (gapKeys.has(k)) die('an entry is in both the allow list and the gaps list: it is either equivalent or a gap');

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
console.error(`${mutants.length} planted bugs in all, ${todo.length} here${SHARD_N > 1 ? ` (shard ${SHARD_K}/${SHARD_N})` : ''}, ${JOBS} at a time, copies in ${OUT}`);
if (CRITICAL && !todo.length) die('no UNKNOWN or EXPOSED found to mutate in the files asked for');

const tests = readdirSync(join(REPO, 'test')).filter((x) => x.endsWith('.test.mjs')).map((x) => join('test', x));
// The copy's environment: its own folder for the red-team scenarios, and none of a parent test runner's variables (run
// under node --test, NODE_TEST_CONTEXT makes the inner run report to the outer one and exit 0 whatever fails).
const copyEnv = (dir) => {
  const env = { ...process.env, WARDLATCH_DIR: dir };
  for (const k of Object.keys(env)) if (k.startsWith('NODE_TEST')) delete env[k];
  return env;
};
// The suite on one copy: returns { code, timedOut, failed: [test names] }. Its own process group, so a timeout kills
// everything the suite started (the CLI, the programs it runs), not just the runner.
const suite = (dir) => new Promise((res) => {
  const c = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-skip-pattern=${STATIC}`, ...tests],
    { cwd: dir, detached: true, stdio: ['ignore', 'pipe', 'ignore'], env: copyEnv(dir) });
  let out = '', timedOut = false;
  c.stdout.on('data', (d) => { if (out.length < 8e6) out += d; });
  const timer = setTimeout(() => { timedOut = true; try { process.kill(-c.pid, 'SIGKILL'); } catch { /* gone */ } }, TIMEOUT_MS);
  c.on('close', (code) => {
    clearTimeout(timer);
    try { process.kill(-c.pid, 'SIGKILL'); } catch { /* the group is gone */ }
    // a failing todo test is reported as "not ok … # TODO", and is not a catch
    const failed = [...out.matchAll(/^\s*not ok \d+ - (.+)$/gm)].map((m) => m[1]).filter((l) => !/\s#\s(TODO|SKIP)\b/i.test(l))
      .map((l) => l.replace(/\s+#\s.*$/, '')).filter((n) => !/\.test\.mjs$/.test(n));
    res({ code, timedOut, failed: [...new Set(failed)] });
  });
});
const copy = (name) => {
  const dir = join(OUT, name);
  rmSync(dir, { recursive: true, force: true });
  execFileSync('rsync', ['-a', '--exclude', '.git', '--exclude', 'node_modules', `${REPO}/`, `${dir}/`]);
  return dir;
};
const drop = (dir) => { try { execFileSync('chmod', ['-R', 'u+rwx', dir], { stdio: 'ignore' }); } catch { /* some tests lock folders */ } rmSync(dir, { recursive: true, force: true }); };

// The control: the unmutated code must pass, or every "catch" below would mean nothing.
{
  const dir = copy('baseline');
  const b = await suite(dir);
  drop(dir);
  if (b.timedOut || b.code !== 0) die(`the unmutated baseline does not pass (exit ${b.code}${b.timedOut ? ', timed out' : ''}): ${b.failed.slice(0, 5).join('; ')}`);
  console.error('baseline passes');
}

const runOne = async (m, k) => {
  const dir = copy(`m${k}`);
  const p = join(dir, m.file), lines = readFileSync(p, 'utf8').split('\n');
  lines[m.line - 1] = m.text; writeFileSync(p, lines.join('\n'));
  try { execFileSync(process.execPath, ['--check', p], { stdio: 'ignore' }); } catch { drop(dir); return { ...m, result: 'invalid' }; }
  const t0 = Date.now(), r = await suite(dir);
  drop(dir);
  return { ...m, result: r.timedOut ? 'timeout' : r.code === 0 ? 'SURVIVED' : 'caught', by: r.failed.slice(0, 5), ms: Date.now() - t0 };
};

const results = []; let next = 0, done = 0;
await Promise.all(Array.from({ length: JOBS }, async () => {
  while (next < todo.length) {
    const k = next++; const r = await runOne(todo[k], k); results.push(r);
    if (++done % 10 === 0 || r.result !== 'caught') console.error(`${done}/${todo.length}${r.result !== 'caught' ? `  ${r.result} ${r.file}:${r.line} ${r.op}` : ''}`);
    writeFileSync(join(OUT, 'results.json'), JSON.stringify(results.map(({ text, ...x }) => x), null, 1));
  }
}));
const count = (x) => results.filter((r) => r.result === x).length;
const byPlace = (a, b) => a.file.localeCompare(b.file) || a.line - b.line;
const survivors = results.filter((x) => x.result === 'SURVIVED').sort(byPlace);
const timeouts = results.filter((x) => x.result === 'timeout').sort(byPlace);
const unexplained = survivors.filter((m) => !allowedKeys.has(key(m)) && !gapKeys.has(key(m)));
const equivalent = survivors.filter((m) => allowedKeys.has(key(m))).length, known = survivors.filter((m) => gapKeys.has(key(m))).length;
console.log(`caught ${count('caught')}, survived ${survivors.length} (${equivalent} listed as equivalent, ${known} listed as known test gaps), timeout ${timeouts.length}, invalid ${count('invalid')}`);
for (const r of survivors) console.log(`${allowedKeys.has(key(r)) ? 'EQUIVALENT' : gapKeys.has(key(r)) ? 'GAP' : 'SURVIVED'} ${r.file}:${r.line} [${r.op}${r.nth > 1 ? ` #${r.nth}` : ''}]  ${r.before}  →  ${r.after}`);
for (const r of timeouts) console.log(`TIMEOUT ${r.file}:${r.line} [${r.op}]  ${r.before}`);
// an allow-list entry that no planted bug in the files asked for matches is stale: it could hide a future survivor
const kinds = new Set(OPS.map(([op]) => op));
const isStale = (a) => wanted.includes(a.file) && kinds.has(a.op) && !mutants.some((m) => key(m) === key(a));
const stale = [...ALLOWED, ...GAPS].filter(isStale);
for (const a of stale) console.log(`STALE ${gapKeys.has(key(a)) ? 'gaps' : 'allow'}-list entry (no such line any more): ${a.file} [${a.op}] ${a.before}`);
// the gaps list only shrinks: a listed gap that a test now catches comes off it
const closed = results.filter((r) => r.result === 'caught' && gapKeys.has(key(r)));
for (const r of closed) console.log(`CLOSED gap (now caught by: ${r.by.slice(0, 2).join('; ')}): take it off the gaps list: ${r.file}:${r.line} [${r.op}]`);
console.log(`results: ${relative(process.cwd(), join(OUT, 'results.json')) || join(OUT, 'results.json')}`);
if (GATE && (unexplained.length || timeouts.length || stale.length || closed.length)) {
  console.log(`\nFAIL: ${unexplained.length} new planted bug(s) no test catches, ${timeouts.length} timed out, ${stale.length} stale list entr${stale.length === 1 ? 'y' : 'ies'}, ${closed.length} closed gap(s) still listed. Add a test that fails on each new survivor (only if no behaviour can tell it apart, list it in ${relative(REPO, ALLOW_FILE)} with the reason); take closed gaps off ${relative(REPO, GAPS_FILE)}; re-run timed-out ones on a quieter machine.`);
  process.exit(1);
}
