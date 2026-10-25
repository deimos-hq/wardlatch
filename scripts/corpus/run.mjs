#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Differential test corpus, part 2: runs two Wardlatch checkouts over every layout that scripts/corpus/build.mjs made,
// one incident at a time, and lists every layout × incident where they differ in exit code or in row counts by status.
//
//   node scripts/corpus/run.mjs <corpusdir> <wardlatchA> <wardlatchB> [--timeout <ms>] [--jobs <n>] [--out <file>]
//                                [--only <layout>[,<layout>…]] [--gate]
//
// <wardlatchA>, <wardlatchB>: a checkout's bin/wardlatch.mjs each (A is the baseline, e.g. 0.1.8; B the candidate).
// Each run gets --json --no-containers --incident <id>, the layout's --paths, and an environment of only the layout's
// HOME, PATH=/usr/bin:/bin and the layout's own variables; it starts in the layout's HOME.
// --gate: exit 1 only when B, the candidate, misses its layouts' own expectations: a clean layout × incident that doesn't
// exit 0 with its JSON, a bad layout its incident (catchBy) doesn't catch (no EXPOSED or REVIEW row), a bad layout that
// must read EXPOSED ("expect" in its manifest) reading REVIEW only, a bad layout with the wrong exit code for what it
// found (1 with an EXPOSED row; 0 or 2 with REVIEW rows only, which don't change the exit code: README, "exit code"), or
// a run that timed out. Differences from A are listed for review but don't fail. A gate needs something to check: it
// stops (exit 2) unless the corpus has at least one clean layout and one bad layout, every bad layout names an incident
// this script runs, and says what it must find ("expect": EXPOSED or REVIEW). Without --gate, any difference exits 1.
// Either way an --only name that is not in the corpus, no layout to run at all, or a --jobs or --timeout that isn't a
// whole number of at least 1 (or has no value) stops it (exit 2); and the gate stops (exit 2) rather than pass unless
// every layout × incident ran.
// Prints a markdown report (differences, then clean layouts that did not exit 0 and bad layouts that were not caught,
// then time per version) and writes every run to <corpusdir>/results.json, or --out.
// The emudhra incident is not run: it connects to its public test hosts, and this corpus contacts no network host.
// The checks run here read files and run local programs (git, and the programs on PATH for their versions) only.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const INCIDENTS = ['committed-keys-2026-10', 'github-actions-2026-10', 'wordpress-plugins-2026-10', 'identity-headers-2026-10',
  'litellm-2026-10', 'php-2026-10', 'ovhcloud-cli-2026-10', 'plex-2026-10', 'gitlab-2026-10'];
const STATUSES = ['SAFE', 'EXPOSED', 'UNKNOWN', 'REVIEW'];

const argv = process.argv.slice(2);
const usage = (msg) => { console.error(msg); process.exit(2); };
// an option's value: the next argument, which must be there and not be another option
const opt = (name, dflt) => {
  const i = argv.indexOf(name);
  if (i < 0) return dflt;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith('--')) usage(`${name} needs a value`);
  argv.splice(i, 2);
  return v;
};
// a whole number of at least 1: a --jobs that isn't one would start no worker, and the gate would pass having run nothing
const whole = (name, dflt) => { const v = opt(name, dflt); if (!/^\d+$/.test(v) || Number(v) < 1) usage(`${name} needs a whole number of at least 1 (not "${v}")`); return Number(v); };
const timeout = whole('--timeout', '120000');
const jobs = whole('--jobs', '1');
const only = opt('--only', '');
const outArg = opt('--out', '');
const gi = argv.indexOf('--gate'); const GATE = gi >= 0; if (GATE) argv.splice(gi, 1);
if (argv.length !== 3) {
  console.error('usage: node run.mjs <corpusdir> <wardlatchA/bin/wardlatch.mjs> <wardlatchB/bin/wardlatch.mjs> [--timeout ms] [--jobs n] [--out file] [--only a,b] [--gate]');
  process.exit(2);
}
const [corpus, binA, binB] = argv.map((a) => resolve(a));
for (const b of [binA, binB]) if (!existsSync(b)) { console.error(`not found: ${b}`); process.exit(2); }
const outFile = outArg ? resolve(outArg) : join(corpus, 'results.json');
const versionOf = (bin) => { try { return JSON.parse(readFileSync(join(bin, '..', '..', 'package.json'), 'utf8')).version; } catch { return '?'; } };
const VERSIONS = { A: { bin: binA, version: versionOf(binA) }, B: { bin: binB, version: versionOf(binB) } };

const stop = (msg) => { console.error(msg); process.exit(2); };
let names = JSON.parse(readFileSync(join(corpus, 'corpus.json'), 'utf8')).layouts;
if (!Array.isArray(names)) stop(`${join(corpus, 'corpus.json')}: no "layouts" list`);
if (only) {
  const want = only.split(','), unknown = want.filter((n) => !names.includes(n));
  if (unknown.length) stop(`--only: no layout named ${unknown.join(', ')} in ${corpus} (it has ${names.length})`);
  names = names.filter((n) => want.includes(n));
}
if (!names.length) stop(`no layouts to run in ${corpus}`);
const layouts = names.map((n) => JSON.parse(readFileSync(join(corpus, n, 'manifest.json'), 'utf8')));
if (GATE) {
  const clean = layouts.filter((L) => L.class === 'clean'), bad = layouts.filter((L) => L.class === 'bad');
  const odd = layouts.filter((L) => L.class !== 'clean' && L.class !== 'bad').map((L) => L.name);
  const unchecked = bad.filter((L) => !(L.catchBy ?? []).some((i) => INCIDENTS.includes(i))).map((L) => L.name);
  if (odd.length) stop(`--gate: every layout's class is clean or bad (not: ${odd.join(', ')})`);
  if (!clean.length || !bad.length) stop(`--gate needs at least one clean layout and one bad layout (here ${clean.length} clean, ${bad.length} bad): it would check nothing`);
  if (unchecked.length) stop(`--gate: a bad layout must name in catchBy an incident run here (${INCIDENTS.join(', ')}), or nothing checks it: ${unchecked.join(', ')}`);
  const unstated = bad.filter((L) => !['EXPOSED', 'REVIEW'].includes(L.expect)).map((L) => L.name);
  if (unstated.length) stop(`--gate: every bad layout says what its incident must find ("expect": "EXPOSED" or "REVIEW"), or a weaker finding would pass: ${unstated.join(', ')}`);
}

/** One run of one version on one layout for one incident. */
function runOne(bin, L, incident) {
  const args = [bin, '--json', '--no-containers', '--incident', incident, ...L.paths.flatMap((p) => ['--paths', p])];
  const env = { HOME: L.HOME, PATH: '/usr/bin:/bin', ...L.env };
  return new Promise((done) => {
    const t0 = process.hrtime.bigint();
    const child = spawn(process.execPath, args, { cwd: L.HOME, env, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; let timedOut = false;
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      const stdout = Buffer.concat(out).toString('utf8'), stderr = Buffer.concat(err).toString('utf8');
      const r = { exit: timedOut ? 'timeout' : code ?? `signal ${signal}`, ms: Math.round(ms), counts: Object.fromEntries(STATUSES.map((s) => [s, 0])), unknownReasons: [], rows: 0 };
      try {
        const j = JSON.parse(stdout);
        r.version = j.version;
        for (const row of j.results ?? []) {
          r.rows++;
          if (row.status in r.counts) r.counts[row.status]++; else r.counts[row.status] = (r.counts[row.status] ?? 0) + 1;
          if (row.status === 'UNKNOWN') r.unknownReasons.push({ kind: row.kind, where: row.path ?? row.repo ?? row.file ?? row.dir ?? row.site ?? '', reason: row.reason });
        }
        r.found = (j.results ?? []).filter((row) => row.status === 'EXPOSED' || row.status === 'REVIEW').map((row) => ({ status: row.status, kind: row.kind, what: row.what ?? row.file ?? row.binary ?? '', where: row.repo ?? row.site ?? row.path ?? '' }));
      } catch (e) {
        r.parseError = `${e.message}`.slice(0, 200);
        r.stdoutHead = stdout.slice(0, 500);
      }
      if (stderr.trim()) r.stderr = stderr.slice(0, 2000);
      done(r);
    });
  });
}

// every (layout, incident) pair; A then B for each, so both see the machine in the same state
const tasks = [];
for (const L of layouts) for (const inc of INCIDENTS) tasks.push({ L, inc });
const results = [];
let next = 0, doneCount = 0;
async function worker() {
  while (next < tasks.length) {
    const { L, inc } = tasks[next++];
    const A = await runOne(binA, L, inc);
    const B = await runOne(binB, L, inc);
    results.push({ layout: L.name, group: L.group, class: L.class, catchBy: L.catchBy, expect: L.expect, incident: inc, A, B });
    doneCount++;
    if (process.stderr.isTTY) process.stderr.write(`\r${doneCount}/${tasks.length} pairs`);
  }
}
const started = Date.now();
await Promise.all(Array.from({ length: Math.min(jobs, tasks.length) }, worker));
if (process.stderr.isTTY) process.stderr.write('\n');
const order = new Map(tasks.map((t, i) => [`${t.L.name}|${t.inc}`, i]));
results.sort((a, b) => order.get(`${a.layout}|${a.incident}`) - order.get(`${b.layout}|${b.incident}`));

// ---- compare --------------------------------------------------------------------------------------------------------

const countsKey = (c) => STATUSES.map((s) => c[s] ?? 0).join('/') + Object.keys(c).filter((s) => !STATUSES.includes(s)).map((s) => `+${s}:${c[s]}`).join('');
const fmt = (r) => r.parseError ? `no JSON (${r.parseError.slice(0, 40)})` : STATUSES.map((s) => `${s[0]}${r.counts[s] ?? 0}`).join(' ');
for (const r of results) {
  r.differs = r.A.exit !== r.B.exit || countsKey(r.A.counts) !== countsKey(r.B.counts) || !!r.A.parseError !== !!r.B.parseError;
  // a first sort for the classification: the exit code changed; a count other than SAFE changed; or only SAFE rows did
  // (0.1.9 adds a SAFE receipt row to --json for every all-clear, which 0.1.8 printed only as text)
  const notSafe = (c) => countsKey({ ...c, SAFE: 0 });
  r.diffKind = !r.differs ? '' : r.A.exit !== r.B.exit || !!r.A.parseError !== !!r.B.parseError ? 'exit' : notSafe(r.A.counts) !== notSafe(r.B.counts) ? 'counts' : 'SAFE only';
  const ra = new Set(r.A.unknownReasons.map((u) => u.reason)), rb = new Set(r.B.unknownReasons.map((u) => u.reason));
  r.reasonsOnlyA = [...ra].filter((x) => !rb.has(x));
  r.reasonsOnlyB = [...rb].filter((x) => !ra.has(x));
}
const diffs = results.filter((r) => r.differs);
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const cut = (s, n = 140) => (s.length > n ? `${s.slice(0, n)}…` : s);

const total = (v) => results.reduce((t, r) => t + r[v].ms, 0);
const timeouts = (v) => results.filter((r) => r[v].exit === 'timeout').length;
const slowest = (v) => [...results].sort((a, b) => b[v].ms - a[v].ms)[0];

const md = [];
md.push(`# Wardlatch differential run`);
md.push('');
md.push(`- A: ${VERSIONS.A.version} \`${binA}\``);
md.push(`- B: ${VERSIONS.B.version} \`${binB}\``);
md.push(`- Corpus: \`${corpus}\` (${layouts.length} layouts × ${INCIDENTS.length} incidents = ${results.length} pairs; emudhra not run)`);
md.push('');
md.push(`## Differences (${diffs.length})`);
md.push('');
if (!diffs.length) md.push('None: A and B agree on exit code and row counts by status for every layout × incident.');
else {
  const by = (k) => diffs.filter((r) => r.diffKind === k).length;
  md.push(`Exit code differs: ${by('exit')} · other counts differ: ${by('counts')} · only the SAFE count differs: ${by('SAFE only')}. Counts are S(afe) E(xposed) U(nknown) R(eview).`);
  md.push('');
  md.push('| layout | class | incident | differs in | A exit | B exit | A counts | B counts | UNKNOWN reasons only in A | only in B |');
  md.push('|---|---|---|---|---|---|---|---|---|---|');
  for (const r of diffs) md.push(`| ${r.layout} | ${r.class} | ${r.incident} | ${r.diffKind} | ${r.A.exit} | ${r.B.exit} | ${fmt(r.A)} | ${fmt(r.B)} | ${esc(r.reasonsOnlyA.map((x) => cut(x)).join('; '))} | ${esc(r.reasonsOnlyB.map((x) => cut(x)).join('; '))} |`);
}
md.push('');
// the release criterion, per version: clean layouts exit 0; each bad layout's incident finds something (EXPOSED or REVIEW)
md.push('## Against the layouts\' own expectations');
md.push('');
md.push('| version | clean layout × incident not exiting 0 | bad layouts not caught by their incident | bad layouts finding less than they should | bad layouts with the wrong exit code |');
md.push('|---|---|---|---|---|');
const expectations = {};
for (const v of ['A', 'B']) {
  const notZero = results.filter((r) => r.class === 'clean' && (r[v].exit !== 0 || r[v].parseError)).map((r) => `${r.layout}/${r.incident} (${r[v].parseError ? 'no JSON' : r[v].exit})`);
  const caughtBy = results.filter((r) => r.class === 'bad' && (r.catchBy ?? []).includes(r.incident));
  const found = (r) => (r[v].counts.EXPOSED ?? 0) + (r[v].counts.REVIEW ?? 0);
  const missed = caughtBy.filter((r) => !found(r)).map((r) => `${r.layout}/${r.incident}`);
  // a layout that must read EXPOSED reading REVIEW only: a weaker finding, and an exit code that no longer fails
  const weaker = caughtBy.filter((r) => found(r) && r.expect === 'EXPOSED' && !(r[v].counts.EXPOSED ?? 0)).map((r) => `${r.layout}/${r.incident} (REVIEW only, expected EXPOSED)`);
  // exit 1 when anything is EXPOSED; REVIEW rows don't change the exit code, so a REVIEW-only catch exits 0 or 2
  const wrongExit = caughtBy.filter((r) => found(r) && !((r[v].counts.EXPOSED ?? 0) ? [1] : [0, 2]).includes(r[v].exit))
    .map((r) => `${r.layout}/${r.incident} (${r[v].exit}${r[v].counts.EXPOSED ? ', EXPOSED' : ', REVIEW only'})`);
  expectations[v] = { notZero, missed, weaker, wrongExit };
  const list = (l) => (l.length ? esc(l.join(', ')) : 'none');
  md.push(`| ${v} ${VERSIONS[v].version} | ${list(notZero)} | ${list(missed)} | ${list(weaker)} | ${list(wrongExit)} |`);
}
md.push('');
md.push('## Time');
md.push('');
md.push('| version | total run time | runs | timeouts | slowest run |');
md.push('|---|---|---|---|---|');
for (const v of ['A', 'B']) {
  const s = slowest(v);
  md.push(`| ${v} ${VERSIONS[v].version} | ${(total(v) / 1000).toFixed(1)} s | ${results.length} | ${timeouts(v)} | ${s ? `${s.layout}/${s.incident} ${(s[v].ms / 1000).toFixed(2)} s` : ''} |`);
}
md.push('');
md.push(`Wall time ${((Date.now() - started) / 1000).toFixed(1)} s with --jobs ${jobs}, timeout ${timeout} ms per run. Full results: \`${outFile}\``);
console.log(md.join('\n'));

writeFileSync(outFile, `${JSON.stringify({
  versions: VERSIONS, corpus, incidents: INCIDENTS, timeoutMs: timeout, jobs,
  totals: { A: { ms: total('A'), timeouts: timeouts('A') }, B: { ms: total('B'), timeouts: timeouts('B') } },
  differences: diffs.length, results,
}, null, 1)}\n`);
if (GATE) {
  // never a pass on less than every layout × incident: each one run, with both versions
  const want = layouts.length * INCIDENTS.length;
  if (results.length !== want || new Set(results.map((r) => r.layout)).size !== layouts.length) {
    console.log(`\nGATE STOPPED: ${results.length} of the ${want} layout × incident pairs ran; a gate that didn't run them all checked nothing.`);
    process.exit(2);
  }
  const { notZero, missed, weaker, wrongExit } = expectations.B;
  const failed = notZero.length + missed.length + weaker.length + wrongExit.length + timeouts('B');
  const ran = (c) => new Set(results.filter((r) => r.class === c).map((r) => r.layout)).size;
  console.log(failed ? `\nGATE FAILED for B ${VERSIONS.B.version}: ${notZero.length} clean not exiting 0, ${missed.length} bad not caught, ${weaker.length} bad finding less than it should, ${wrongExit.length} bad with the wrong exit code, ${timeouts('B')} timed out.`
    : `\nGATE PASSED for B ${VERSIONS.B.version}: every clean layout exits 0 (${ran('clean')}) and every bad layout is caught as it should be (EXPOSED where it must be), with the exit code it should have (${ran('bad')}); ${diffs.length} difference(s) from A listed above for review.`);
  process.exitCode = failed ? 1 : 0;
} else {
  process.exitCode = diffs.length ? 1 : 0;
}
