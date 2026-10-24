// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release gate, scripts/release-check.mjs, on throwaway repositories: it passes a release whose reviews are on file
// for the code being released, and refuses each way one can be wrong. Without --ci it also needs a clean main at
// origin/main (a local bare repository) and every GitHub check passed (gh is a stand-in on PATH). Offline; git runs with
// no user config.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync, renameSync, chmodSync } from 'node:fs';
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

// a repository at the given version with the release commit reviewed; returns its folder
const repo = ({ version = '0.2.0', log, audit, skip = [] } = {}) => {
  const dir = join(base, `r${++n}`);
  mkdirSync(dir);
  git(dir, 'init', '-q', '-b', 'main');
  put(dir, 'package.json', JSON.stringify({ name: 'wardlatch', version }));
  put(dir, 'CHANGELOG.md', log ?? changelog(version));
  put(dir, 'scripts/release-check.mjs', GATE);
  put(dir, 'lib/a.mjs', 'export const a = 1;\n');
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'release');
  const sha = git(dir, 'rev-parse', 'HEAD');
  if (!skip.includes('class')) put(dir, `docs/reviews/${version}/CLASS-AUDIT.md`, audit ?? `${review(sha)}\n${A}: looked again.\n${B}: looked again.\n`);
  if (!skip.includes('independent')) put(dir, `docs/reviews/${version}/INDEPENDENT-REVIEW.md`, review(sha));
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', 'reviews');
  return dir;
};
const gate = (dir, { ci = true, env = {} } = {}) => {
  const r = spawnSync(process.execPath, ['scripts/release-check.mjs', ...(ci ? ['--ci'] : [])], { cwd: dir, env: { ...ENV, ...env }, encoding: 'utf8' });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const commit = (dir, msg) => { git(dir, 'add', '-A'); git(dir, 'commit', '-q', '--allow-empty', '-m', msg); };
// for the full gate: an origin (a bare repository) at HEAD, and gh replaced by a script that prints the given checks
const CHECKS = ['critical mutants', 'corpus (report against last release)', 'test (node 22, ubuntu-latest)'];
const full = (dir, { runs = CHECKS.map((name) => ({ name, status: 'completed', conclusion: 'success' })), ghFails = false } = {}) => {
  const origin = `${dir}-origin.git`;
  git(base, 'init', '-q', '--bare', origin);
  git(dir, 'remote', 'add', 'origin', origin); git(dir, 'push', '-q', 'origin', 'main'); git(dir, 'fetch', '-q', 'origin');
  const bin = `${dir}-bin`; mkdirSync(bin);
  writeFileSync(join(bin, 'checks.json'), JSON.stringify([{ total_count: runs.length, check_runs: runs }]));
  writeFileSync(join(bin, 'gh'), ghFails ? '#!/bin/sh\necho "gh: not logged in" >&2\nexit 1\n' : `#!/bin/sh\ncat '${join(bin, 'checks.json')}'\n`);
  chmodSync(join(bin, 'gh'), 0o755);
  return { PATH: `${bin}:${process.env.PATH}` };
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

test('0.1.9 and earlier predate the gate: nothing to check', () => {
  const r = gate(repo({ version: '0.1.9', skip: ['class', 'independent'] }));
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /predates the release gate/);
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
  put(ok, 'docs/reviews/0.2.0/CLASS-AUDIT.md', `${review(sha)}\n${A} ${B}\n`); put(ok, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', review(sha));
  commit(ok, 'version and changelog after the reviews');
  r = gate(ok);
  assert.equal(r.code, 0, r.out);
});

test('a review file with two verdicts, or two commits, is refused, even if one says READY', () => {
  const dir = repo();
  const sha = git(dir, 'rev-parse', 'HEAD~1');
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `${review(sha)}\nRound 2\n${review(sha, 'NOT READY')}`);
  let r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /exactly one "Verdict:" line \(found 2\)/);
  put(dir, 'docs/reviews/0.2.0/INDEPENDENT-REVIEW.md', `Commit: ${sha}\nCommit: ${sha}\nVerdict: READY\n`);
  r = gate(dir);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /exactly one "Commit:" line \(found 2\)/);
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
