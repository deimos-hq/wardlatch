// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The corpus runner, scripts/corpus/run.mjs, on tiny made-up corpora and a stand-in for Wardlatch (a script that answers
// as each layout's FAKE variable says): --gate passes only when the candidate meets every layout's expectations, with
// the exit code each finding should give, and it never passes having checked nothing (an --only name that isn't in the
// corpus, no layouts, no clean or no bad layout, or a bad layout no incident run here checks). Offline: nothing real runs.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUN = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'corpus', 'run.mjs');
// The stand-in: FAKE is "clean" (a SAFE row, exit 0), or "<what>:<incident>" for that incident: "exposed" (an EXPOSED row,
// exit 1), "exposed-exit-0" (an EXPOSED row, exit 0: the wrong exit code), "review" (a REVIEW row, exit 0), "missed" (a
// SAFE row, exit 0), "exit-1" (a SAFE row, exit 1).
const FAKE = `const inc = process.argv[process.argv.indexOf('--incident') + 1];
const [what, on] = (process.env.FAKE ?? 'clean').split(':');
const mine = on === inc;
const status = mine && what.startsWith('exposed') ? 'EXPOSED' : mine && what === 'review' ? 'REVIEW' : 'SAFE';
console.log(JSON.stringify({ version: 'fake', results: [{ incident: inc, status }] }));
process.exitCode = mine && (what === 'exposed' || what === 'exit-1') ? 1 : 0;
`;
let base, n = 0;
before(() => { base = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-corpus-test-')); });
after(() => rmSync(base, { recursive: true, force: true }));

const bin = (() => { let b; return () => { if (!b) { b = join(base, 'wl', 'bin', 'wardlatch.mjs'); mkdirSync(dirname(b), { recursive: true }); writeFileSync(b, FAKE); writeFileSync(join(base, 'wl', 'package.json'), '{"version":"fake"}'); } return b; }; })();
// layouts: [name, class, catchBy, FAKE]
const corpus = (layouts) => {
  const dir = join(base, `c${++n}`); mkdirSync(dir);
  for (const [name, cls, catchBy, fake] of layouts) {
    const home = join(dir, name, 'home'); mkdirSync(home, { recursive: true });
    writeFileSync(join(dir, name, 'manifest.json'), JSON.stringify({ name, group: 't', class: cls, catchBy, HOME: home, paths: [], env: { FAKE: fake } }));
  }
  writeFileSync(join(dir, 'corpus.json'), JSON.stringify({ layouts: layouts.map(([name]) => name) }));
  return dir;
};
const run = (dir, ...extra) => {
  const r = spawnSync(process.execPath, [RUN, dir, bin(), bin(), '--jobs', '4', '--out', join(dir, 'results.json'), ...extra], { encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const KEYS = 'committed-keys-2026-10', WP = 'wordpress-plugins-2026-10';
const CLEAN = ['laptop', 'clean', [], 'clean'];
const BAD_EXPOSED = ['old-plugin', 'bad', [WP], `exposed:${WP}`];
const BAD_REVIEW = ['committed-key', 'bad', [KEYS], `review:${KEYS}`];

test('--gate: every clean layout exits 0, every bad layout is caught with the exit code its finding gives: passes', () => {
  const r = run(corpus([CLEAN, BAD_EXPOSED, BAD_REVIEW]), '--gate');
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /GATE PASSED for B fake: every clean layout exits 0 \(1\) and every bad layout is caught, with the exit code it should have \(2\)/);
});

test('--gate: a bad layout not caught, an EXPOSED that exits 0, or a clean layout that doesn\'t exit 0 fails (exit 1)', () => {
  for (const [layouts, why] of [
    [[CLEAN, ['old-plugin', 'bad', [WP], `missed:${WP}`]], /1 bad not caught/],
    [[CLEAN, ['old-plugin', 'bad', [WP], `exposed-exit-0:${WP}`]], /1 bad with the wrong exit code/],
    [[['laptop', 'clean', [], `exit-1:${KEYS}`], BAD_EXPOSED], /1 clean not exiting 0/],
  ]) {
    const r = run(corpus(layouts), '--gate');
    assert.equal(r.code, 1, r.out); assert.match(r.out, /GATE FAILED for B fake/); assert.match(r.out, why);
  }
});

test('--gate never passes having checked nothing: no clean layout, no bad layout, or a bad layout no incident here checks (exit 2)', () => {
  for (const [layouts, why] of [
    [[CLEAN], /--gate needs at least one clean layout and one bad layout \(here 1 clean, 0 bad\)/],
    [[BAD_EXPOSED], /--gate needs at least one clean layout and one bad layout \(here 0 clean, 1 bad\)/],
    [[CLEAN, ['tls-only', 'bad', ['emudhra-2026-10'], 'clean']], /a bad layout must name in catchBy an incident run here[^\n]*tls-only/],
    [[CLEAN, ['odd', 'maybe', [], 'clean']], /every layout's class is clean or bad \(not: odd\)/],
  ]) {
    const r = run(corpus(layouts), '--gate');
    assert.equal(r.code, 2, r.out); assert.match(r.out, why); assert.doesNotMatch(r.out, /GATE PASSED/);
  }
  // --only picking just the clean layouts of a good corpus is a gate that checks nothing, too
  const r = run(corpus([CLEAN, BAD_EXPOSED]), '--gate', '--only', 'laptop');
  assert.equal(r.code, 2, r.out);
});

test('an --only name that is not in the corpus, or no layouts at all, stops the run (exit 2), with --gate or without', () => {
  for (const extra of [[], ['--gate']]) {
    let r = run(corpus([CLEAN, BAD_EXPOSED]), '--only', 'laptop,lapotp', ...extra);
    assert.equal(r.code, 2, r.out); assert.match(r.out, /--only: no layout named lapotp/);
    r = run(corpus([]), ...extra);
    assert.equal(r.code, 2, r.out); assert.match(r.out, /no layouts to run/);
  }
});

test('without --gate: the same answers from A and B exit 0; --only runs just the layouts named', () => {
  const r = run(corpus([CLEAN, BAD_EXPOSED, BAD_REVIEW]), '--only', 'laptop,committed-key');
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /2 layouts × 9 incidents = 18 pairs/);
  assert.match(r.out, /## Differences \(0\)/);
});
