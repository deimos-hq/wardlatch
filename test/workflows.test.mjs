// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The workflow review's window, end to end. 0.1.0 to 0.1.9 gave git the bare date "2026-09-01", which git reads as
// 1 Sep at the current time of day in the machine's zone: a workflow committed on 31 Aug, or on 1 Sep before the hour
// the check ran, read SAFE. The window now starts at an explicit instant, 30 Aug 2026 00:00 UTC, so these tests give
// the same result at any time of day: workflows planted just inside it (in two zones), the advisory's own file names,
// a clean twin one second before it, a start that isn't an explicit instant, and a git that reads the start otherwise.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as workflows from '../lib/workflows.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const START = Date.parse('2026-08-30T00:00:00Z') / 1000;
const SAFE_TEXT = 'no workflow files added in commits dated on or after 30 Aug 2026 00:00 UTC (committer date) in 1 local repository';
const WF = '.github/workflows/planted.yml';
// the command drops TZ before git runs (lib/run.mjs), so these only show that the reader's zone changes nothing:
// UTC+14, where 31 Aug begins at 10:00 UTC on 30 Aug, and UTC-7 (CI runners use UTC)
const ZONES = ['Pacific/Kiritimati', 'America/Los_Angeles'];
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-wf-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-wf-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

/** The command (or a copy of it) on the workflow incident → { code, out, rows }; --json unless `text`. HOME is an
 *  empty folder of the tests' own. */
const run = (paths, env = {}, { bin = BIN, text = false } = {}) => {
  const r = spawnSync(process.execPath, [bin, '--incident', 'github-actions-2026-10', '--paths', paths, ...(text ? [] : ['--json'])], { encoding: 'utf8', env: { ...process.env, HOME: home, ...env } });
  let rows = [];
  if (!text) {
    try { rows = JSON.parse(r.stdout).results; } catch { throw new Error(`no JSON from the command (exit ${r.status}): ${r.stderr}`); }
  }
  return { code: r.status, out: r.stdout, rows };
};

/** A repository at `path`: a 2025 commit, then one commit per entry { files, date (the committer date), author?, at? }.
 *  Each committer time is checked against the instant meant (`at`, or `date`), so a fixture git read otherwise can't
 *  make a test pass. */
const repo = (path, commits) => {
  const g = (args, extra = {}) => execFileSync('git', ['-C', path, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x', ...extra } }).trim();
  mkdirSync(path, { recursive: true }); g(['init', '-q']);
  for (const c of [{ files: { 'README.md': 'app\n' }, date: '2025-06-01T12:00:00Z' }, ...commits]) {
    for (const [f, text] of Object.entries(c.files)) { mkdirSync(dirname(join(path, f)), { recursive: true }); writeFileSync(join(path, f), text); }
    g(['add', '-A']); g(['-c', 'commit.gpgsign=false', 'commit', '-qm', 'c'], { GIT_AUTHOR_DATE: c.author ?? c.date, GIT_COMMITTER_DATE: c.date });
    assert.equal(Number(g(['log', '-1', '--format=%ct'])), Date.parse(c.at ?? c.date) / 1000, `the fixture's committer date, ${c.date}`);
  }
  return path;
};
const later = { files: { 'later.txt': 'x\n' }, date: '2026-10-10T12:00:00Z' };

test('workflows: one committed just inside the window is listed, in any zone and at any time of day', () => {
  const root = join(dir, 'inside');
  // [repository, committer date, the instant, the date shown (git's %cs, in the commit's own zone)]
  const cases = [
    ['first-second', '2026-08-30T00:00:01Z', '2026-08-30T00:00:01Z', '2026-08-30'],
    ['utc8-morning', '2026-08-31T05:00:00+0800', '2026-08-30T21:00:00Z', '2026-08-31'],   // 31 Aug where it was made
    ['sep1-0900', '2026-09-01T09:00:00Z', '2026-09-01T09:00:00Z', '2026-09-01'],          // 0.1.9 missed it from 09:00 UTC on
  ];
  for (const [name, date, at] of cases) repo(join(root, name), [{ files: { [WF]: 'on: push\n' }, date, at }, later]);
  for (const TZ of ZONES) {
    const r = run(root, { TZ });
    assert.deepEqual(r.rows.map((x) => [x.status, x.repo && basename(x.repo), x.file, x.commit?.split(' ')[1]]).sort(),
      cases.map(([name, , , shown]) => ['REVIEW', name, WF, shown]).sort(), `TZ=${TZ}: ${r.out}`);
    assert.equal(r.code, 0, 'review lines don\'t change the exit code');
  }
});

test('workflows: the advisory\'s own file names, committed on 31 Aug, are listed', () => {
  // both before 10:00 UTC on 31 Aug, earlier than 1 Sep begins in any zone: 0.1.9 missed them at every hour
  const root = join(dir, 'named');
  repo(join(root, 'app'), [
    { files: { '.github/workflows/github_actions_security.yml': 'on: push\n' }, date: '2026-08-31T00:30:00Z' },
    { files: { '.github/workflows/security-audit.yml': 'on: push\n' }, date: '2026-08-31T09:00:00Z' }, later]);
  for (const TZ of ZONES) {
    const r = run(root, { TZ });
    assert.deepEqual(r.rows.map((x) => [x.status, x.file]).sort(), [['REVIEW', '.github/workflows/github_actions_security.yml'], ['REVIEW', '.github/workflows/security-audit.yml']], `TZ=${TZ}: ${r.out}`);
  }
});

test('workflows: clean twin, one committed a second before the window is SAFE, and the line names the instant and the date it filters on', () => {
  const root = join(dir, 'before');
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, later]);
  for (const TZ of ZONES) {
    const r = run(root, { TZ });
    assert.deepEqual(r.rows.map((x) => [x.status, x.reason, x.searched]), [['SAFE', SAFE_TEXT, [root]]], `TZ=${TZ}: ${r.out}`);
    assert.equal(r.code, 0);
  }
  assert.match(run(root, {}, { text: true }).out, new RegExp(`\\nSAFE {5}${SAFE_TEXT.replace(/[()]/g, '\\$&')}\\n`));
});

test('workflows: the committer date is the one filtered on, and the one a review line shows', () => {
  // authored before the window, committed inside it: listed, with the committer date (0.1.9 showed the author date)
  const a = join(dir, 'dates-in');
  repo(join(a, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-15T12:00:00Z', author: '2026-08-01T12:00:00Z' }]);
  assert.match(run(a, {}, { text: true }).out, /REVIEW {2}.*app\/\.github\/workflows\/planted\.yml {2}added [0-9a-f]{7,} 2026-09-15 t\n/);
  assert.equal(run(a).rows[0].commit.split(' ')[1], '2026-09-15');
  // authored inside the window, committed before it: not read (a commit can claim any date: the known limits)
  const b = join(dir, 'dates-out');
  repo(join(b, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T12:00:00Z', author: '2026-09-15T12:00:00Z' }]);
  assert.deepEqual(run(b).rows.map((x) => [x.status, x.reason]), [['SAFE', SAFE_TEXT]]);
});

test('workflows: a start that is not an explicit UTC instant is UNKNOWN, never SAFE', () => {
  const root = join(dir, 'bare'), app = repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-15T12:00:00Z' }]);
  for (const since of ['2026-09-01', '2026-08-30 00:00:00', '2026-08-30T00:00:00', '2026-08-30T00:00:00+00:00', '2026-08-30T00:00:00.000Z', '2026-02-30T00:00:00Z', '2026-08-30T24:00:00Z', '', undefined, START]) {
    const got = workflows.workflowsAddedSince(app, since);
    assert.ok(!Array.isArray(got) && got.error, `${JSON.stringify(since)}: ${JSON.stringify(got)}`);
  }
  assert.deepEqual(workflows.workflowsAddedSince(app, '2026-08-30T00:00:00Z').map((x) => x.file), [WF], 'control: the same repository, with the instant');
  // the command, from a copy of itself whose incident gives the bare date 0.1.9 had: one UNKNOWN row, exit 2, whether
  // or not there is anything to find
  const copy = join(dir, 'copy');
  for (const d of ['bin', 'lib', 'package.json']) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
  const inc = join(copy, 'lib', 'incidents', 'github-actions-2026-10.json');
  writeFileSync(inc, `${JSON.stringify({ ...JSON.parse(readFileSync(inc, 'utf8')), since: '2026-09-01' }, null, 2)}\n`);
  const empty = join(dir, 'bare-empty'); mkdirSync(empty);
  for (const paths of [root, empty]) {
    const r = run(paths, {}, { bin: join(copy, 'bin', 'wardlatch.mjs') });
    assert.deepEqual(r.rows.map((x) => [x.kind, x.status]), [['workflow', 'UNKNOWN']], `${paths}: ${r.out}`);
    assert.match(r.rows[0].reason, /"2026-09-01", is not an explicit UTC instant/);
    assert.equal(r.code, 2);
  }
});

test('workflows: a git that reads the start as another instant (an old or unusual one) makes the repository UNKNOWN', () => {
  const root = join(dir, 'oddgit');
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-15T12:00:00Z' }]);
  const real = execFileSync('/bin/sh', ['-c', 'command -v git'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } }).trim();
  const wrap = (name, body) => { const d = join(dir, name); mkdirSync(d); writeFileSync(join(d, 'git'), `#!/bin/sh\n${body}exec "${real}" "$@"\n`, { mode: 0o755 }); return d; };
  // one day late, as git reads a bare date at this hour: rev-parse prints the --max-age git log would filter with
  const late = wrap('git-late', `case " $* " in *" rev-parse "*) echo "--max-age=${START + 86400}"; exit 0;; esac\n`);
  const r = run(root, { PATH: `${late}:/usr/bin:/bin` });
  assert.deepEqual(r.rows.map((x) => [x.status, x.repo]), [['UNKNOWN', join(root, 'app')]], r.out);
  assert.equal(r.rows[0].reason, 'this git reads the window\'s start, 30 Aug 2026 00:00 UTC (--since="@1788048000 +0000"), as "--max-age=1788134400", not --max-age=1788048000: an old or unusual git, so the commits it would read are not the window\'s');
  assert.equal(r.code, 2);
  // control: the same kind of wrapper, passing rev-parse through to git, lists the workflow
  assert.deepEqual(run(root, { PATH: `${wrap('git-same', '')}:/usr/bin:/bin` }).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
});

test('workflows: git reads the start it is given as the same instant in every zone; the line names it in UTC', () => {
  const s = workflows.windowStart('2026-08-30T00:00:00Z');
  assert.deepEqual(s, { seconds: START, arg: `@${START} +0000`, label: '30 Aug 2026 00:00 UTC' });
  const r = repo(join(dir, 'zones'), []);
  // git run directly, with TZ, as a git that got the caller's zone would read it (lib/run.mjs gives git none)
  for (const TZ of [...ZONES, 'UTC', 'Asia/Kolkata']) assert.equal(execFileSync('git', ['-C', r, 'rev-parse', `--since=${s.arg}`], { encoding: 'utf8', env: { ...process.env, TZ } }).trim(), `--max-age=${START}`, TZ);
  assert.equal(workflows.windowStart('2026-08-30T10:00:05Z').label, '30 Aug 2026 10:00:05 UTC');
});
