// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release gate, scripts/release-check.mjs, on throwaway repositories: it passes a release whose reviews are on file
// for the code being released, and refuses each way one can be wrong. It needs every GitHub check passed, with --ci too
// (gh is always a stand-in on PATH, which answers the checks only for HEAD, lists v0.1.9 as released unless a test says
// otherwise, and gives every page only to --paginate --slurp, as gh does); without --ci, also a clean main at origin/main
// (a local bare repository). Offline; git runs with no user config, and no GITHUB_* variable of a CI runner reaches the
// gate.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync, renameSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const GATE = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'release-check.mjs'), 'utf8');
const RUN = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'corpus', 'run.mjs');
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
// the block a review begins with: all the gate reads of it
const review = (sha, verdict = 'READY') => `\`\`\`\nCommit: ${sha}\nVerdict: ${verdict}\n\`\`\`\n\n# Review\n`;
// the corpus gate's last line (scripts/corpus/run.mjs --gate, run as root before a release) for the code in dir's bin/
// and lib/, quoted in the class audit; its SHA-256 worked out here from the files, as the corpus gate does
const sha256 = (x) => createHash('sha256').update(x).digest('hex');
const corpusLine = (dir, version = '0.2.0') => {
  const code = sha256(git(dir, 'ls-files', '-z', '--', 'bin', 'lib').split('\0').filter(Boolean).sort()
    .map((f) => `${f}\0${sha256(readFileSync(join(dir, f)))}\n`).join(''));
  return `GATE PASSED for B ${version} (bin/ and lib/ sha256 ${code}): every clean layout exits 0 (13) and every bad layout is caught `
    + 'as it should be (EXPOSED where it must be), with the exit code it should have (8); 0 difference(s) from A listed above for review.';
};

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
  if (!skip.includes('class')) put(dir, `docs/reviews/${version}/CLASS-AUDIT.md`, audit ?? `${review(sha)}\n${A}: looked again.\n${B}: looked again.\n\n${corpusLine(dir, version)}\n`);
  if (!skip.includes('independent')) put(dir, `docs/reviews/${version}/INDEPENDENT-REVIEW.md`, review(sha));
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', 'reviews');
  return dir;
};
const CHECKS = ['critical mutants', 'corpus (report against last release)', 'test (node 22, ubuntu-latest)'];
const PASSING = CHECKS.map((name) => ({ name, status: 'completed', conclusion: 'success' }));
// a GitHub release, as the release workflow publishes one
const REL = (tag, extra = {}) => ({ tag_name: tag, draft: false, author: { login: 'github-actions[bot]' }, ...extra });
// gh replaced by a script that prints the given pages of check runs for HEAD (none for any other commit), and the given
// pages of releases (v0.1.9's by default): every page with --paginate --slurp, as gh does, and only the first without
const ghStub = (dir, { runs = PASSING, pages = [runs], ghFails = false, releases = [[REL('v0.1.9')]] } = {}) => {
  const bin = mkdtempSync(join(base, 'gh-')), sha = git(dir, 'rev-parse', 'HEAD');
  const all = pages.map((p) => ({ total_count: pages.flat().length, check_runs: p }));
  writeFileSync(join(bin, 'all.json'), JSON.stringify(all)); writeFileSync(join(bin, 'first.json'), JSON.stringify(all[0]));
  writeFileSync(join(bin, 'rel-all.json'), JSON.stringify(releases)); writeFileSync(join(bin, 'rel-first.json'), JSON.stringify(releases[0]));
  writeFileSync(join(bin, 'gh'), ghFails ? '#!/bin/sh\necho "gh: not logged in" >&2\nexit 1\n' : `#!/bin/sh
p=; s=; u=
for a in "$@"; do case "$a" in --paginate) p=1 ;; --slurp) s=1 ;; repos/*) u="$a" ;; esac; done
case "$u" in */releases*) if [ -n "$p" ] && [ -n "$s" ]; then cat '${join(bin, 'rel-all.json')}'; else cat '${join(bin, 'rel-first.json')}'; fi; exit 0 ;; esac
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
  assert.match(r.out, /the block's verdict is "NOT READY", not READY/);
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

test('the class audit quotes the corpus gate\'s GATE PASSED for this code (docs/RELEASING.md, step 5): missing, a GATE FAILED beside it, one for other code, or one that doesn\'t name the code is refused', () => {
  for (const [extra, why] of [[() => '', /the class audit doesn't quote the corpus gate's GATE PASSED/],
    [(d) => `${corpusLine(d)}\nGATE FAILED for B 0.2.0: 0 clean not exiting 0, 1 bad not caught`, /the class audit quotes a GATE FAILED/],
    // a run on other code: the SHA-256 of another bin/ and lib/
    [(d) => corpusLine(d).replace(/sha256 [0-9a-f]{64}/, `sha256 ${'0'.repeat(64)}`), /quotes a GATE PASSED for other code \(bin\/ and lib\/ sha256 0{12}\), not for this commit's \([0-9a-f]{12}\)/],
    // the line as the corpus gate printed it before it named the code it ran
    [(d) => corpusLine(d).replace(/ \(bin\/ and lib\/ sha256 [0-9a-f]{64}\)/, ''), /the class audit doesn't quote the corpus gate's GATE PASSED/]]) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${A} ${B}\n${extra(dir)}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, r.out); assert.match(r.out, why); assert.doesNotMatch(r.out, /READY to tag/);
  }
  // quoted in a code block or a quote, it counts
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${A} ${B}\n\n\`\`\`\n${corpusLine(dir)}\n\`\`\`\n`);
  const r = gate(dir);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /quotes the corpus gate's GATE PASSED for this code/);
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
  put(ok, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(sha)}\n${A} ${B}\n${corpusLine(ok)}\n`); put(ok, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(sha));
  commit(ok, 'version and changelog after the reviews');
  r = gate(ok);
  assert.equal(r.code, 0, r.out);
});

test('a review with a second verdict, or a second commit, after its block is refused, even though the block says READY', () => {
  const dir = repo();
  const sha = git(dir, 'rev-parse', 'HEAD~1');
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(sha)}\nRound 2\n\n${review(sha, 'NOT READY')}`);
  let r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /INDEPENDENT-REVIEW\.md, line 11 says "Commit" outside the block/);
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(sha)}\nVerdict: NOT READY\n`);
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /INDEPENDENT-REVIEW\.md, line 8 says "Verdict" outside the block/);
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(sha)}\nCommit: ${sha}\n`);
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /INDEPENDENT-REVIEW\.md, line 8 says "Commit" outside the block/);
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

test('a second verdict after the block counts however it is dressed: in bold, a quote, a list, code or a sentence it is refused', () => {
  for (const extra of ['**Verdict:** NOT READY', '> Verdict: NOT READY', '- Verdict: NOT READY', '**Verdict**: NOT READY', '`Verdict: NOT READY`',
    'Final verdict: NOT READY', '> **Verdict:** READY WITH NITS']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${extra}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${extra}\n${r.out}`); assert.match(r.out, /line 8 says "verdict" outside the block/i, extra);
  }
});

test('the block is read only as it is written, at the top: dressed, indented, under a title, or with a look-alike or hidden character in it, it is refused', () => {
  for (const text of [(sha) => `**Commit:** ${sha}\n**Verdict:** READY\n`, (sha) => `> \`\`\`\n> Commit: ${sha}\n> Verdict: READY\n> \`\`\`\n`,
    (sha) => `# Review\n\n${review(sha)}`, (sha) => `    Commit: ${sha}\n    Verdict: READY\n`, (sha) => `\`\`\`text\nCommit: ${sha}\nVerdict: READY\n\`\`\`\n`,
    (sha) => review(sha).replace('Verdict: ', 'Verdict： '), (sha) => review(sha).replace('READY', 'READY​'),
    (sha) => `﻿${review(sha)}`, (sha) => review(sha).replace(/\n/g, '\r\n'), (sha) => review(sha, 'READY WITH NITS'),
    (sha) => review(sha).replace('Commit', 'Commit (round 2)')]) {
    const dir = repo(), t = text(git(dir, 'rev-parse', 'HEAD~1'));
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', t);
    const r = gate(dir);
    assert.equal(r.code, 1, `${t}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, t);
    assert.match(r.out, /FAIL {2}docs\/reviews\/0\.2\.0\/INDEPENDENT-REVIEW\.md(:| must begin with the block)/, t);
  }
});

test('a NOT READY however it is written (a heading, a table, an em-dash, a round, "=", a full-width colon, a hidden character) after a READY block: refused', () => {
  const hidden = '<!--\nVerdict: READY\n-->';
  for (const text of [
    '## Verdict\n\n**NOT READY**: S1 (a false SAFE) is open.\n\nWhen S1 is fixed and re-reviewed, this file is updated to `Verdict: READY`',
    '| Verdict | NOT READY |\n|---|---|\n\nOnce fixed this becomes: Verdict: READY',
    `**Verdict — NOT READY**\n\n${hidden}`,
    `Verdict (round 2): NOT READY\n\n${hidden}`,
    `VERDICT = NOT READY\n\n${hidden}`,
    `Verdict：NOT READY\n\n${hidden}`,
    'Ver​dict: NOT READY',
    'Result: not ready, S1 is open.',
    'Outcome: READY WITH NITS',
    hidden,
  ]) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${text}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${text}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, text);
    assert.match(r.out, /FAIL {2}docs\/reviews\/0\.2\.0\/INDEPENDENT-REVIEW\.md, line 8 (says "(verdict|ready)" outside the block|has an HTML comment)/i, text);
  }
});

test('another commit shown after the block, in a table, a heading, a round or a sentence, is refused; so is the reviewed one hidden in a comment behind one shown', () => {
  for (const shown of ['| Commit | 0000000 |\n|---|---|', '## Commit\n\n0000000', 'Commit (round 1): 0000000', 'Reviewed commit — 0000000',
    'Reviewed at 0000000, before the fixes.']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${shown}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${shown}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, shown);
    assert.match(r.out, /INDEPENDENT-REVIEW\.md, line 8 (says "commit" outside the block|has "0000000", a commit id, outside the block)/i, shown);
  }
  // with no block, the commit read was the one hidden: now there is nothing to read
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `# Review\n\n| Commit | 0000000 |\n|---|---|\n\n<!--\nCommit: ${git(dir, 'rev-parse', 'HEAD~1')}\n-->\n\nVerdict: READY\n`);
  const r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /INDEPENDENT-REVIEW\.md must begin with the block the gate reads/);
});

test('a commit id must be written as git prints it, lower-case hex: "Commit: <SHA in capitals>" or a name is refused', () => {
  for (const id of ['UPPER', 'HEAD', 'main']) {
    const dir = repo(), sha = git(dir, 'rev-parse', 'HEAD~1');
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(id === 'UPPER' ? sha.toUpperCase() : id));
    const r = gate(dir);
    assert.equal(r.code, 1, `${id}\n${r.out}`); assert.match(r.out, /the block's commit must read "Commit: <sha>", in lower-case hex/, id);
  }
});

test('the plain form passes: the block, then prose that says neither a verdict nor a commit again, with tables, advisories, a SHA-256 and an incident named committed-keys', () => {
  const prose = '# Independent review\n\nEach fix was checked again by a fresh agent, who wrote none of it; the branch can be tagged.\n\n'
    + '| finding | class | fixed |\n|---|---|---|\n| S1 | MUST-FIX | yes, with a test that fails without it |\n\n'
    + `The committed-keys-2026-10 check reads at most 1 MiB of a file. fix/fix-macos.sh: sha256 ${'ab'.repeat(32)}.\n\n${A}: looked again.\n`;
  const dir = repo();
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${prose}`);
  const r = gate(dir);
  assert.equal(r.code, 0, r.out);
});

// The verifier's probes (F1). Each passed beside "Verdict: READY": a READY hidden from the page in a link reference
// definition's title that spans lines, a NOT READY in look-alike letters, "isn't ready" in lower case, and a second
// commit labelled "Commit reviewed:". The gate now reads only the block at the top, shown as written, and nothing after
// it may say its words again or name a commit; each probe, and its kin, is refused.
test('F1: a READY hidden in a link reference definition, a look-alike NOT READY, a lower-case "isn\'t ready", or "Commit reviewed:": refused', () => {
  const probes = [
    [(sha) => `# Review\n\nThe release isn't ready yet: S1 is open.\n\n[r]: https://example.com "\nCommit: ${sha}\nVerdict: READY\n"\n`, /must begin with the block/],
    [(sha) => `[r]: https://example.com "\n${review(sha)}"\n\nS1 is open.\n`, /must begin with the block/],
    [(sha) => `${review(sha)}\n[//]: # (Verdict: NOT READY)\n`, /line 8 says "Verdict" outside the block/],
    [(sha) => `${review(sha)}\n[S1](https://example.com "\nVerdict: NOT READY\n")\n`, /line 9 says "Verdict" outside the block/],
    [(sha) => `<script>\n${review(sha)}</script>\n\nS1 is open.\n`, /must begin with the block/],
    // look-alike letters: Cyrillic in NOT READY, an all-Greek NOT, an all-Cherokee READY, a READY struck through
    [(sha) => `${review(sha)}\nOutcome: NОТ RЕАDY\n`, /line 8 has a letter outside ASCII \("О", U\+041E\)/],
    [(sha) => `${review(sha)}\nOutcome: ΝΟΤ so.\n`, /line 8 has a letter outside ASCII \("Ν", U\+039D\)/],
    [(sha) => `${review(sha)}\nOutcome: ᏒᎬᎪᎠᎽ? No.\n`, /line 8 has a letter outside ASCII \("Ꮢ", U\+13D2\)/],
    [(sha) => `${review(sha)}\nOutcome: R̶E̶A̶D̶Y̶\n`, /line 8 has a letter outside ASCII \("̶", U\+0336\)/],
    // "ready" in lower case, inside other words, or split by an invisible character
    [(sha) => `${review(sha)}\nThe code isn't ready yet; not yet ready to ship.\n`, /line 8 says "ready" outside the block/],
    [(sha) => `${review(sha)}\nUnready: S1 is open.\n`, /line 8 says "ready" outside the block/],
    [(sha) => `${review(sha)}\nnot_ready, see S1\n`, /line 8 says "ready" outside the block/],
    [(sha) => `${review(sha)}\nrea­dy? Not yet.\n`, /line 8 says "ready" outside the block/],
    // a second commit, labelled any way, or named with no label
    [(sha, other) => `${review(sha)}\nCommit reviewed: ${other}\n`, /line 8 says "Commit" outside the block/],
    [(sha, other) => `${review(sha)}\nCode reviewed: ${other.slice(0, 7)}\n`, /line 8 has "[0-9a-f]{7}", a commit id, outside the block/],
    [(sha, other) => `${review(sha)}\nReviewed at ${other.toUpperCase()}.\n`, /line 8 has "[0-9A-F]{40}", a commit id, outside the block/],
    [(sha) => `${review(sha)}\nCommits reviewed: main\n`, /line 8 says "Commits" outside the block/],
  ];
  for (const [probe, why] of probes) {
    const dir = repo(), text = probe(git(dir, 'rev-parse', 'HEAD~1'), git(dir, 'rev-parse', 'HEAD~2'));
    put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', text);
    const r = gate(dir);
    assert.equal(r.code, 1, `${text}\n${r.out}`); assert.doesNotMatch(r.out, /READY to tag/, text);
    assert.match(r.out, /FAIL {2}docs\/reviews\/0\.2\.0\/INDEPENDENT-REVIEW\.md/, text); assert.match(r.out, why, text);
  }
});

test('reading a review is linear: a 1 MB hostile line takes the gate no longer than a short one would', () => {
  const dir = repo();
  const hostile = ['commitment '.repeat(95326), 'not '.repeat(262144), '0123456789abcdef'.repeat(65536), '>'.repeat(1 << 20), 'rea'.repeat(349526)].join('\n');
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${hostile}\n`);
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${readFileSync(join(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md'), 'utf8')}\nGATE PASSED for B ${'x'.repeat(1 << 20)}\n${hostile}\n`);
  const t0 = Date.now(), r = gate(dir);
  assert.equal(r.code, 0, r.out.slice(0, 2000));
  assert.ok(Date.now() - t0 < 10000, `${Date.now() - t0} ms`);
});

test('a second commit after the block counts however it is dressed: in bold, a list or code it is refused', () => {
  for (const extra of ['**Commit:** 0123456', '- Commit: 0123456', '> `Commit:` 0123456']) {
    const dir = repo();
    put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(git(dir, 'rev-parse', 'HEAD~1'))}\n${extra}\n${A} ${B}\n${corpusLine(dir)}\n`);
    const r = gate(dir);
    assert.equal(r.code, 1, `${extra}\n${r.out}`); assert.match(r.out, /CLASS-AUDIT\.md, line 8 says "Commit" outside the block/, extra);
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
  assert.equal(r.code, 1, r.out); assert.match(r.out, /no earlier release \(a tag older than v0\.2\.0 in this history, with a GitHub release the release workflow published\)/);
});

test('the lists are compared with the last release GitHub has, published by the release workflow: a tag with none (pushed by hand, or refused by the gate) launders no entry', () => {
  // v0.1.10 tags the release commit, which already holds the unapproved entry: as the baseline, nothing would be added since
  const make = () => { const dir = repo({ last: { [GAPS]: json([L(1)]) }, files: { [GAPS]: json([L(1), L(2)]) } }); git(dir, 'tag', 'v0.1.10', 'HEAD~1'); return dir; };
  for (const releases of [[[REL('v0.1.9')]], [[REL('v0.1.10', { draft: true }), REL('v0.1.9')]],
    [[REL('v0.1.10', { author: { login: 'someone' } }), REL('v0.1.9')]]]) {
    const dir = make();
    const r = gate(dir, { env: ghStub(dir, { releases }) });
    assert.equal(r.code, 1, r.out); assert.doesNotMatch(r.out, /READY to tag/);
    assert.match(r.out, /mutants-gaps\.json: 1 of the 1 entry added since v0\.1\.9 lacks the maintainer's approval[^\n]*lib\/a\.mjs \[unknown->safe\] line 2/);
  }
  // the twin: v0.1.10, released by the workflow, is the last release, and nothing was added since
  const dir = make();
  const r = gate(dir, { env: ghStub(dir, { releases: [[REL('v0.1.10'), REL('v0.1.9')]] }) });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /mutants-gaps\.json: no entry added since v0\.1\.10/);
});

test('GitHub\'s releases are read page by page; a release on the second page counts, and none older in this history is refused', () => {
  let dir = repo();
  let r = gate(dir, { env: ghStub(dir, { releases: [[REL('v0.0.1')], [REL('v0.1.9')]] }) });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /no entry added since v0\.1\.9/);
  dir = repo();
  r = gate(dir, { env: ghStub(dir, { releases: [[REL('v0.0.1')]] }) });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /no earlier release \(a tag older than v0\.2\.0/);
});

test('the corpus gate\'s own GATE PASSED, run on the release\'s bin/ and lib/, passes the release gate; its line for a copy with other code in lib/ is refused', () => {
  // a stand-in for Wardlatch as the release's bin/ (it finds what each layout's FAKE says), and a corpus of a clean layout
  // and a bad one
  const fake = `const inc = process.argv[process.argv.indexOf('--incident') + 1];
const [what, on] = (process.env.FAKE ?? 'clean').split(':');
const status = what === 'exposed' && on === inc ? 'EXPOSED' : 'SAFE';
console.log(JSON.stringify({ version: 'fake', results: [{ incident: inc, status }] }));
process.exitCode = status === 'EXPOSED' ? 1 : 0;
`;
  const WP = 'wordpress-plugins-2026-10', corpus = join(base, `corpus${++n}`);
  for (const [name, cls, catchBy, fakeIs, expect] of [['laptop', 'clean', [], 'clean'], ['old-plugin', 'bad', [WP], `exposed:${WP}`, 'EXPOSED']]) {
    const home = join(corpus, name, 'home'); mkdirSync(home, { recursive: true });
    writeFileSync(join(corpus, name, 'manifest.json'), JSON.stringify({ name, group: 't', class: cls, catchBy, expect, HOME: home, paths: [], env: { FAKE: fakeIs } }));
  }
  writeFileSync(join(corpus, 'corpus.json'), JSON.stringify({ layouts: ['laptop', 'old-plugin'] }));
  const passed = (dir) => {
    const bin = join(dir, 'bin', 'wardlatch.mjs');
    const r = spawnSync(process.execPath, [RUN, corpus, bin, bin, '--gate', '--out', join(corpus, 'results.json')], { encoding: 'utf8', timeout: 120000 });
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    return r.stdout.trim().split('\n').at(-1);
  };
  const dir = repo({ files: { 'bin/wardlatch.mjs': fake } }), sha = git(dir, 'rev-parse', 'HEAD~1');
  const audit = (line) => `${review(sha)}\n${A}: looked again.\n${B}: looked again.\n\n${line}\n`;
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', audit(passed(dir))); commit(dir, 'the corpus gate, quoted');
  let r = gate(dir);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /quotes the corpus gate's GATE PASSED for this code/);
  const other = join(base, `other${n}`);
  put(other, 'package.json', JSON.stringify({ version: '0.2.0' })); put(other, 'bin/wardlatch.mjs', fake); put(other, 'lib/a.mjs', 'export const a = 2;\n');
  put(dir, 'docs/reviews/0.2.0/CLASS-AUDIT.md', audit(passed(other))); commit(dir, 'a corpus gate run on other code, quoted');
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /quotes a GATE PASSED for other code/); assert.doesNotMatch(r.out, /READY to tag/);
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
  assert.equal(r.code, 1, r.out); assert.match(r.out, /couldn't read GitHub's checks/); assert.match(r.out, /couldn't read GitHub's releases/);
});
