// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release gate, scripts/release-check.mjs, on throwaway repositories: it passes a release whose reviews are on file
// for the code being released, and refuses each way one can be wrong. It needs every GitHub check passed, with --ci too
// (gh is always a stand-in on PATH, which answers only for HEAD, and gives every page only to --paginate --slurp, as gh
// does); without --ci, also a clean main at origin/main (a local bare repository). Offline; git runs with no user config,
// and no GITHUB_* variable of a CI runner reaches the gate.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync, renameSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const GATE = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'release-check.mjs'), 'utf8');
const ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' };
const A = 'GHSA-aaaa-bbbb-cccc', B = 'GHSA-dddd-eeee-ffff';
let base, n = 0;
before(() => { base = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-gate-')); });
after(() => rmSync(base, { recursive: true, force: true }));

const put = (dir, p, text) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), text); };
const git = (dir, ...a) => execFileSync('git', a, { cwd: dir, env: ENV, encoding: 'utf8' }).trim();
const changelog = (version, { unreleased = '', date = ' - 2026-11-02' } = {}) =>
  `# Changelog\n\n## [Unreleased]\n${unreleased}\n## [${version}]${date}\n\n- ${A} and ${B}.\n\n## [0.1.9] - 2026-10-23\n`;
const review = (sha, verdict = 'READY') => `# Review\n\nCommit: ${sha}\nVerdict: ${verdict}\n`;
// the corpus gate's last line (scripts/corpus/run.mjs --gate, run as root before a release), quoted in the class audit
const CORPUS = 'GATE PASSED for B 0.2.0: every clean layout exits 0 (13) and every bad layout is caught as it should be.';

// a repository at the given version with the release commit reviewed, after the last release (a commit tagged v0.1.9
// holding the files in `last`, unless tag is false); `files` go into the release commit; returns its folder
const repo = ({ version = '0.2.0', log, audit, skip = [], last = {}, files = {}, tag = true } = {}) => {
  const dir = join(base, `r${++n}`);
  mkdirSync(dir);
  git(dir, 'init', '-q', '-b', 'main');
  put(dir, 'lib/a.mjs', 'export const a = 1;\n');
  for (const [p, t] of Object.entries(last)) put(dir, p, t);
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'the last release');
  if (tag) git(dir, 'tag', 'v0.1.9');
  put(dir, 'package.json', JSON.stringify({ name: 'wardlatch', version }));
  put(dir, 'CHANGELOG.md', log ?? changelog(version));
  put(dir, 'scripts/release-check.mjs', GATE);
  for (const [p, t] of Object.entries(files)) put(dir, p, t);
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'release');
  const sha = git(dir, 'rev-parse', 'HEAD');
  if (!skip.includes('class')) put(dir, `docs/reviews/${version}/CLASS-AUDIT.md`, audit ?? `${review(sha)}\n${A}: looked again.\n${B}: looked again.\n\n${CORPUS}\n`);
  if (!skip.includes('independent')) put(dir, `docs/reviews/${version}/INDEPENDENT-REVIEW.md`, review(sha));
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', 'reviews');
  return dir;
};
const CHECKS = ['critical mutants', 'corpus (report against last release)', 'test (node 22, ubuntu-latest)'];
const PASSING = CHECKS.map((name) => ({ name, status: 'completed', conclusion: 'success' }));
// gh replaced by a script that prints the given pages of check runs for HEAD (none for any other commit): every page with
// --paginate --slurp, as gh does, and only the first without
const ghStub = (dir, { runs = PASSING, pages = [runs], ghFails = false } = {}) => {
  const bin = mkdtempSync(join(base, 'gh-')), sha = git(dir, 'rev-parse', 'HEAD');
  const all = pages.map((p) => ({ total_count: pages.flat().length, check_runs: p }));
  writeFileSync(join(bin, 'all.json'), JSON.stringify(all)); writeFileSync(join(bin, 'first.json'), JSON.stringify(all[0]));
  writeFileSync(join(bin, 'gh'), ghFails ? '#!/bin/sh\necho "gh: not logged in" >&2\nexit 1\n' : `#!/bin/sh
p=; s=; u=
for a in "$@"; do case "$a" in --paginate) p=1 ;; --slurp) s=1 ;; repos/*) u="$a" ;; esac; done
case "$u" in */commits/${sha}/check-runs*) ;; *) echo '[{"total_count":0,"check_runs":[]}]'; exit 0 ;; esac
if [ -n "$p" ] && [ -n "$s" ]; then cat '${join(bin, 'all.json')}'; else cat '${join(bin, 'first.json')}'; fi
`);
  chmodSync(join(bin, 'gh'), 0o755);
  return { PATH: `${bin}:${process.env.PATH}` };
};
// the release workflow's checkout: HEAD is on main at the origin (a bare repository beside it)
const pushMain = (dir) => {
  const origin = `${dir}-origin.git`;
  if (!existsSync(origin)) { git(base, 'init', '-q', '--bare', origin); git(dir, 'remote', 'add', 'origin', origin); }
  git(dir, 'push', '-q', '-f', 'origin', 'HEAD:refs/heads/main'); git(dir, 'fetch', '-q', 'origin');
};
const gate = (dir, { ci = true, env = {}, onMain = true } = {}) => {
  if (ci && onMain) pushMain(dir);
  const e = { ...ENV, ...(env.PATH ? {} : ghStub(dir)), ...env };
  for (const k of ['GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_REPOSITORY', 'GH_TOKEN', 'GITHUB_TOKEN']) if (!(k in env)) delete e[k];
  const r = spawnSync(process.execPath, ['scripts/release-check.mjs', ...(ci ? ['--ci'] : [])], { cwd: dir, env: e, encoding: 'utf8' });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const commit = (dir, msg) => { git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', msg); };
// for the full gate: an origin (a bare repository) at HEAD, and gh's stand-in
const full = (dir, opts) => {
  const origin = `${dir}-origin.git`;
  git(base, 'init', '-q', '--bare', origin);
  git(dir, 'remote', 'add', 'origin', origin); git(dir, 'push', '-q', 'origin', 'main'); git(dir, 'fetch', '-q', 'origin');
  return ghStub(dir, opts);
};

test('a release whose two reviews are READY for its code, with every advisory looked at again, passes', () => {
  const r = gate(repo());
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /READY to tag v0\.2\.0/);
});

test('no class audit, or no independent review: refused', () => {
  for (const skip of ['class', 'independent']) {
    const r = gate(repo({ skip: [skip] }));
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /is missing/);
  }
});

test('a review whose verdict is not READY: refused', () => {
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(git(dir, 'rev-parse', 'HEAD~1'), 'NOT READY'));
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /no line "Verdict: READY"/);
});

test('code changed after the reviewed commit: refused; a docs-only change after it is fine', () => {
  const dir = repo();
  put(dir, 'README.md', 'docs only\n'); git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'docs');
  assert.equal(gate(dir).code, 0);
  put(dir, 'lib/a.mjs', 'export const a = 2;\n'); git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'late fix');
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /code changed after the reviewed commit[^\n]*lib\/a\.mjs/);
});

test('a reviewed commit that is not in this history: refused', () => {
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review('0123456789abcdef0123456789abcdef01234567')}\n${A} ${B}\n`);
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /not in this repository/);
});

test('a review of a commit on another branch (same code, not this history): refused', () => {
  const dir = repo();
  const main = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'checkout', '-q', '-b', 'side', 'HEAD~1');
  put(dir, 'NOTES.md', 'side\n'); git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'side');
  const side = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'checkout', '-q', 'main');
  assert.notEqual(side, main);
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(side));
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /is not an ancestor of HEAD/);
});

test('a class audit that leaves out one advisory: refused, naming it', () => {
  const dir = repo({ audit: 'placeholder' });
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${A}: looked again.\n`);
  const r = gate(dir);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, new RegExp(`doesn't name 1 of the 2 advisories: ${B}`));
});

test('the class audit quotes the corpus gate\'s GATE PASSED (docs/RELEASING.md, step 5): missing, or a GATE FAILED beside it, is refused', () => {
  for (const [extra, why] of [['', /the class audit doesn't quote the corpus gate's GATE PASSED/],
    [`${CORPUS}\nGATE FAILED for B 0.2.0: 0 clean not exiting 0, 1 bad not caught`, /the class audit quotes a GATE FAILED/]]) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${A} ${B}\n${extra}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, r.out); assert.match(r.out, why); assert.doesNotMatch(r.out, /READY to tag/);
  }
  // quoted in a code block or a quote, it counts
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${A} ${B}\n\n\`\`\`\n${CORPUS}\n\`\`\`\n`);
  assert.equal(gate(dir).code, 0);
});

test('the changelog: lines left under Unreleased, a missing date, or a top section for another version: refused', () => {
  for (const [log, why] of [
    [changelog('0.2.0', { unreleased: '\n- something\n' }), /Unreleased" is not empty/],
    [changelog('0.2.0', { date: '' }), /has no date/],
    [changelog('0.2.1'), /first release section is \[0\.2\.1\], not \[0\.2\.0\]/],
  ]) {
    const r = gate(repo({ log }));
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, why);
  }
});

test('0.1.0 to 0.1.9, released before the gate: nothing to check on the maintainer\'s machine; a tag for one now is refused', () => {
  for (const version of ['0.1.0', '0.1.9']) {
    const r = gate(repo({ version, skip: ['class', 'independent'] }), { ci: false });
    assert.equal(r.code, 0, r.out); assert.match(r.out, /predates the release gate/);
  }
  // the release workflow: a tag for 0.1.9 now would attest another commit as 0.1.9, with no reviews
  const r = gate(repo({ version: '0.1.9', skip: ['class', 'independent'] }));
  assert.equal(r.code, 1, r.out); assert.match(r.out, /0\.1\.9 is older than the release gate[^\n]*re-tag/); assert.doesNotMatch(r.out, /READY to tag/);
});

test('a version older than the gate that was never released (0.0.3): refused, with --ci or without', () => {
  for (const ci of [false, true]) {
    const r = gate(repo({ version: '0.0.3', skip: ['class', 'independent'] }), { ci });
    assert.equal(r.code, 1, r.out); assert.match(r.out, /0\.0\.3 is older than the release gate[^\n]*never released/);
    assert.doesNotMatch(r.out, /predates|READY to tag/);
  }
});

test('the changelog: no Unreleased section first, or no advisory named anywhere: refused', () => {
  let r = gate(repo({ log: `# Changelog\n\n## [0.2.0] - 2026-11-02\n\n- ${A} and ${B}.\n` }));
  assert.equal(r.code, 1, r.out); assert.match(r.out, /first section is not "## \[Unreleased\]"/);
  r = gate(repo({ log: '# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-11-02\n\n- no advisories\n' }));
  assert.equal(r.code, 1, r.out); assert.match(r.out, /names no advisory/);
});

test('advisory ids match whatever their case: named in another case passes, left out in any case is refused', () => {
  assert.equal(gate(repo({ log: changelog('0.2.0').replace(A, A.toUpperCase()) })).code, 0);
  const C = 'GHSA-GGGG-HHHH-JJJJ';
  const r = gate(repo({ log: changelog('0.2.0').replace(`${A} and ${B}.`, `${A} and ${B}.\n- ${C}.`) }));
  assert.equal(r.code, 1, r.out); assert.match(r.out, new RegExp(`doesn't name 1 of the 3 advisories: ${C}`));
});

test('package.json is code: a script or bin changed after the review is refused; a version bump is not', () => {
  const dir = repo();
  put(dir, 'package.json', JSON.stringify({ name: 'wardlatch', version: '0.2.0', marker: 1 })); commit(dir, 'bump');
  // (the version is unchanged here; what changed is a field)
  let r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /package\.json \(beyond its version\)/);
  const ok = repo({ version: '0.1.99' });
  put(ok, 'package.json', JSON.stringify({ name: 'wardlatch', version: '0.2.0' }));
  put(ok, 'CHANGELOG.md', changelog('0.2.0'));
  const sha = git(ok, 'rev-parse', 'HEAD~1');
  put(ok, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(sha)}\n${A} ${B}\n${CORPUS}\n`); put(ok, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(sha));
  commit(ok, 'version and changelog after the reviews');
  r = gate(ok);
  assert.equal(r.code, 0, r.out);
});

test('a review file with two verdicts, or two commits, is refused, even if one says READY', () => {
  const dir = repo();
  const sha = git(dir, 'rev-parse', 'HEAD~1');
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(sha)}\nRound 2\n${review(sha, 'NOT READY')}`);
  let r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /exactly one "Verdict:" line[^\n]*\(found 2\)/);
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `Commit: ${sha}\nCommit: ${sha}\nVerdict: READY\n`);
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /exactly one "Commit:" line[^\n]*\(found 2\)/);
});

test('code moved out of lib/ after the review counts as lib/ changing', () => {
  const dir = repo();
  mkdirSync(join(dir, 'docs'), { recursive: true }); renameSync(join(dir, 'lib/a.mjs'), join(dir, 'docs/a.mjs')); commit(dir, 'move');
  const r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /code changed after the reviewed commit[^\n]*lib\/a\.mjs/);
});

test('a file with a non-ASCII name added to lib/ after the review is seen', () => {
  const dir = repo();
  put(dir, 'lib/incidents/\u00e9.json', '{}\n'); commit(dir, 'add');
  const r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /lib\/incidents\/\u00e9\.json/);
});

test('full gate: a clean main at origin/main with every GitHub check passed is READY', () => {
  const dir = repo();
  const r = gate(dir, { ci: false, env: full(dir) });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /all 3 GitHub checks passed/);
});

test('full gate: a dirty tree, another branch, or HEAD not at origin/main: refused', () => {
  let dir = repo(); let env = full(dir);
  put(dir, 'stray.txt', 'x\n');
  let r = gate(dir, { ci: false, env }); assert.equal(r.code, 1, r.out); assert.match(r.out, /working tree has changes/);
  dir = repo(); env = full(dir); git(dir, 'checkout', '-q', '-b', 'release-prep');
  r = gate(dir, { ci: false, env }); assert.equal(r.code, 1, r.out); assert.match(r.out, /on branch release-prep, not main/);
  dir = repo(); env = full(dir); commit(dir, 'not pushed');
  r = gate(dir, { ci: false, env }); assert.equal(r.code, 1, r.out); assert.match(r.out, /HEAD is not origin\/main/);
});

test('full gate: a failed check, a required check missing, or gh unable to answer: refused', () => {
  let dir = repo();
  let r = gate(dir, { ci: false, env: full(dir, { runs: CHECKS.map((name, i) => ({ name, status: 'completed', conclusion: i === 2 ? 'failure' : 'success' })) }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /checks not passed[^\n]*test \(node 22, ubuntu-latest\) \(failure\)/);
  dir = repo();
  r = gate(dir, { ci: false, env: full(dir, { runs: [{ name: 'critical mutants', status: 'completed', conclusion: 'success' }] }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /required checks didn't run or pass[^\n]*corpus/);
  dir = repo();
  r = gate(dir, { ci: false, env: full(dir, { ghFails: true }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /couldn't read GitHub's checks/);
});

test('a verdict line counts however it is dressed: a second one in bold, a quote, a list, code or a sentence is refused', () => {
  for (const extra of ['**Verdict:** NOT READY', '> Verdict: NOT READY', '- Verdict: NOT READY', '**Verdict**: NOT READY', '`Verdict: NOT READY`',
    'Final verdict: NOT READY', '> **Verdict:** READY WITH NITS']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${extra}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${extra}\n${r.out}`); assert.match(r.out, /exactly one "Verdict:" line[^\n]*\(found 2\)/, extra);
  }
  // the one verdict, dressed: READY in bold is READY; NOT READY in a quote is not
  let dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `Commit: ${git(dir, 'rev-parse', 'HEAD~1')}\n**Verdict:** READY\n`);
  assert.equal(gate(dir).code, 0);
  dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `Commit: ${git(dir, 'rev-parse', 'HEAD~1')}\n> Verdict: NOT READY\n`);
  const r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /no line "Verdict: READY" \(it says "NOT READY"\)/);
});

test('a NOT READY however it is written (a heading, a table, an em-dash, a round, "=", a full-width colon, a hidden character) beside a READY in a comment or code: refused', () => {
  const hidden = '<!--\nVerdict: READY\n-->';
  for (const text of [
    '## Verdict\n\n**NOT READY**: S1 (a false SAFE) is open.\n\nWhen S1 is fixed and re-reviewed, this file is updated to `Verdict: READY`',
    '| Verdict | NOT READY |\n|---|---|\n\nOnce fixed this becomes: Verdict: READY',
    `**Verdict \u2014 NOT READY**\n\n${hidden}`,
    `Verdict (round 2): NOT READY\n\n${hidden}`,
    `VERDICT = NOT READY\n\n${hidden}`,
    `Verdict\uFF1ANOT READY\n\n${hidden}`,
    'Ver\u200Bdict: NOT READY\nVerdict: READY',
    'Result: not ready, S1 is open.\nVerdict: READY',
    'Outcome: READY WITH NITS\nVerdict: READY',
  ]) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `# Review\n\nCommit: ${git(dir, 'rev-parse', 'HEAD~1')}\n\n${text}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${text}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, text);
    assert.match(r.out, /FAIL {2}docs\/reviews\/0\.2\.0\/INDEPENDENT-REVIEW\.md/, text);
  }
});

test('a commit hidden in a comment behind another in a table, a heading or a round: refused', () => {
  for (const shown of ['| Commit | 0000000 |\n|---|---|', '## Commit\n\n0000000', 'Commit (round 1): 0000000', 'Reviewed commit \u2014 0000000']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `# Review\n\n${shown}\n\n<!--\nCommit: ${git(dir, 'rev-parse', 'HEAD~1')}\n-->\n\nVerdict: READY\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${shown}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, shown);
  }
  // and without the comment, two commits in sight: refused too
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `| Commit | 0000000 |\n|---|---|\n\nCommit: ${git(dir, 'rev-parse', 'HEAD~1')}\nVerdict: READY\n`);
  const r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /exactly one "Commit:" line[^\n]*\(found 2\)/);
});

test('the plain forms still pass: a verdict and a commit in a quote, a list or bold, with "commit" and "ready" in prose', () => {
  for (const text of ['> **Commit:** SHA\n> **Verdict:** READY', '- Commit: SHA\n- Verdict: READY',
    'Each fix\ncommit was checked again; the branch is ready to tag.\n\nCommit: SHA\nVerdict: READY']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `# Review\n\n${text.replace(/SHA/g, git(dir, 'rev-parse', 'HEAD~1'))}\n`);
    const r = gate(dir);
    assert.equal(r.code, 0, `${text}\n${r.out}`);
  }
});

test('reading a review is linear: a 1 MB hostile line takes the gate no longer than a short one would', () => {
  const dir = repo();
  const hostile = ['commit ('.repeat(131072), 'not '.repeat(262144), '| commit x '.repeat(104858), '>'.repeat(1 << 20)].join('\n');
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${hostile}\n`);
  const t0 = Date.now(), r = gate(dir);
  assert.equal(r.code, 0, r.out.slice(0, 2000));
  assert.ok(Date.now() - t0 < 10000, `${Date.now() - t0} ms`);
});

test('a commit line counts however it is dressed: a second one in bold or a list is refused', () => {
  for (const extra of ['**Commit:** 0123456', '- Commit: 0123456', '> `Commit:` 0123456']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${extra}\n${A} ${B}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${extra}\n${r.out}`); assert.match(r.out, /exactly one "Commit:" line[^\n]*\(found 2\)/, extra);
  }
});

test('every folder that runs counts: a change in bin/, test/, scripts/, fix/ or .github/ after the review is refused', () => {
  for (const f of ['bin/wardlatch.mjs', 'test/a.test.mjs', 'scripts/x.mjs', 'fix/fix-macos.sh', '.github/workflows/ci.yml']) {
    const dir = repo();
    put(dir, f, 'changed after the review\n'); commit(dir, 'late');
    const r = gate(dir);
    assert.equal(r.code, 1, r.out); assert.match(r.out, new RegExp(`code changed after the reviewed commit[^\\n]*${f.replace(/\./g, '\\.')}`), f);
  }
});

test('GitHub\'s checks are read page by page: a required check, or a failed one, on the second page counts', () => {
  const [mutants, corpus, tests] = PASSING;
  let dir = repo();
  let r = gate(dir, { ci: false, env: full(dir, { pages: [[mutants, tests], [corpus]] }) });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /all 3 GitHub checks passed/);
  dir = repo();
  r = gate(dir, { ci: false, env: full(dir, { pages: [PASSING, [{ name: 'analyze', status: 'completed', conclusion: 'failure' }]] }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /checks not passed[^\n]*analyze \(failure\)/);
});

const L = (k, extra = {}) => ({ file: 'lib/a.mjs', op: 'unknown->safe', before: `line ${k}`, why: 'test gap', ...extra });
const json = (l) => `${JSON.stringify(l, null, 1)}\n`;
const GAPS = 'scripts/mutants-gaps.json', ALLOWED = 'scripts/mutants-allowed.json';

test('the lists of survivors only shrink between releases: an entry added since the last release without the maintainer\'s approval is refused, named', () => {
  for (const [last, files, why] of [
    [{ [GAPS]: json([L(1)]) }, { [GAPS]: json([L(1), L(2)]) }, /mutants-gaps\.json: 1 of the 1 entry added since v0\.1\.9 lacks the maintainer's approval[^\n]*lib\/a\.mjs \[unknown->safe\] line 2/],
    // a gap moved onto the allow list, which the CI check alone would compare only with the push before
    [{ [GAPS]: json([L(1)]) }, { [GAPS]: '[]\n', [ALLOWED]: json([L(1, { why: 'equivalent' })]) }, /mutants-allowed\.json: 1 of the 1 entry added since v0\.1\.9 lacks/],
    // a list the last release didn't have: every entry in it is new
    [{}, { [GAPS]: json([L(1), L(2)]) }, /mutants-gaps\.json: 2 of the 2 entries added since v0\.1\.9 lack the maintainer's approval/],
    // an approval in another form, or by someone else, is not the maintainer's
    [{}, { [GAPS]: json([L(1, { approved: 'reviewer, 2026-10-25' })]) }, /1 of the 1 entry added since v0\.1\.9 lacks/],
    [{}, { [GAPS]: json([L(1, { approved: 'maintainer' })]) }, /1 of the 1 entry added since v0\.1\.9 lacks/],
  ]) {
    const r = gate(repo({ last, files }));
    assert.equal(r.code, 1, r.out); assert.match(r.out, why); assert.doesNotMatch(r.out, /READY to tag/);
  }
});

test('the lists of survivors: one that shrank, or an entry added with the maintainer\'s approval (listed), passes', () => {
  let r = gate(repo({ last: { [GAPS]: json([L(1), L(2)]) }, files: { [GAPS]: json([L(2, { why: 'reworded' })]) } }));
  assert.equal(r.code, 0, r.out); assert.match(r.out, /mutants-gaps\.json: no entry added since v0\.1\.9 \(1 entry now, 2 entries then\)/);
  r = gate(repo({ last: { [GAPS]: json([L(1)]) }, files: { [GAPS]: json([L(1), L(2, { approved: 'maintainer, 2026-10-25' })]) } }));
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /mutants-gaps\.json: 1 entry added since v0\.1\.9, each approved by the maintainer: lib\/a\.mjs \[unknown->safe\] line 2 \(maintainer, 2026-10-25\)/);
});

test('no earlier release tag in this history to compare the lists with: refused', () => {
  const r = gate(repo({ tag: false }));
  assert.equal(r.code, 1, r.out); assert.match(r.out, /no earlier release tag/);
});

test('--ci: the tagged commit must be on main: one on a branch never merged, or with no origin/main to tell, is refused; one behind main passes', () => {
  let dir = repo();
  pushMain(dir);
  git(dir, 'checkout', '-q', '-b', 'pr-head'); put(dir, 'NOTES.md', 'docs only\n'); commit(dir, 'not merged');
  let r = gate(dir, { onMain: false });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /[0-9a-f]{12} is not on main \(origin\/main\)/); assert.doesNotMatch(r.out, /READY to tag/);
  git(dir, 'checkout', '-q', 'main'); put(dir, 'NOTES.md', 'later\n'); commit(dir, 'later docs'); pushMain(dir);
  git(dir, 'checkout', '-q', '--detach', 'HEAD~1');
  r = gate(dir, { onMain: false });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /is on main/);
  dir = repo();
  r = gate(dir, { onMain: false });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /no origin\/main here/);
});

test('--ci (the release workflow) reads GitHub\'s checks too, for GITHUB_SHA, leaving out only this workflow run\'s own jobs', () => {
  const dir = repo(), head = git(dir, 'rev-parse', 'HEAD');
  const own = { name: 'release', status: 'in_progress', conclusion: null, details_url: 'https://github.com/deimos-hq/wardlatch/actions/runs/777/job/9' };
  let r = gate(dir, { env: { ...ghStub(dir, { runs: [...PASSING, own] }), GITHUB_SHA: head, GITHUB_RUN_ID: '777' } });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /all 3 GitHub checks passed/);
  r = gate(dir, { env: { ...ghStub(dir, { runs: [...PASSING, own] }), GITHUB_SHA: head, GITHUB_RUN_ID: '778' } });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /checks not passed[^\n]*release \(in_progress\)/);
  r = gate(dir, { env: { ...ghStub(dir, { runs: PASSING.slice(1) }), GITHUB_SHA: head } });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /required checks didn't run or pass[^\n]*critical mutants/);
  r = gate(dir, { env: { ...ghStub(dir), GITHUB_SHA: git(dir, 'rev-parse', 'HEAD~1') } });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /GITHUB_SHA [0-9a-f]{12} is not HEAD/);
  r = gate(dir, { env: ghStub(dir, { ghFails: true }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /couldn't read GitHub's checks/);
});
