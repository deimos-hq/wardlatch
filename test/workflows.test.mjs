// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The workflow review's window, end to end. 0.1.0 to 0.1.9 gave git the bare date "2026-09-01", which git reads as
// 1 Sep at the current time of day in the zone it runs in (up to 0.1.8 the zone of the TZ Wardlatch was started with,
// the machine's when TZ was unset, which git got with the rest of the caller's environment; in 0.1.9, which gives git
// no TZ, the machine's): a workflow committed on 31 Aug, or on 1 Sep before the hour the check ran, read SAFE. And
// whatever start git got, `git log --since` stops following a line of history at the first commit dated before it: one
// back-dated commit on top hid every workflow beneath it (0.1.0 to 0.1.9, and 44bb10f and 6cac72b on this branch). git
// now gets no date at all: it lists every commit with its committer time (%ct), the review keeps those on or after
// 30 Aug 2026 00:00 UTC by comparing whole numbers, and git lists the workflow files those commits added. These
// tests: workflows just inside the window (in two zones, and at the start's own second, made at UTC-7, whose review
// line must show the date in UTC), the advisory's file names, clean twins a second before it, back-dated commits on
// top, in between and on a merged side branch, a workflow added and removed on a side branch, a replace ref and a
// grafts file that would hide a workflow, shallow repositories (UNKNOWN wherever the cut is: inside the window, before
// it, at a back-dated tip, or a shallow file written into a full repository), partial clones whose remote is gone,
// committer times that aren't whole numbers, a start that isn't an explicit instant, a git that must get no date at
// all, and the CHANGELOG's hand check, found wherever a release puts it and run as written, against the review.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, renameSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as workflows from '../lib/workflows.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const START = Date.parse('2026-08-30T00:00:00Z') / 1000;
const SAFE_TEXT = 'no workflow files added in commits dated on or after 30 Aug 2026 00:00 UTC (committer date) in 1 local repository';
const WF = '.github/workflows/planted.yml';
const BACK = '2025-01-01T00:00:00Z';   // a back-dated commit's date: long before the window
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
const safe = (root) => { const r = run(root); return [r.rows.map((x) => [x.status, x.reason]), r.code]; };

/** git in `path`, as the fixture's author, with the commit dates given (`date` for the committer, `author` for the
 *  author), no signing, file:// clones allowed. */
const gitIn = (path) => (args, { date = '2026-10-15T12:00:00Z', author = date, input } = {}) => execFileSync('git', ['-C', path, '-c', 'commit.gpgsign=false', '-c', 'advice.graftFileDeprecated=false', '-c', 'protocol.file.allow=always', ...args], {
  encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x', GIT_AUTHOR_DATE: author, GIT_COMMITTER_DATE: date },
}).trim();

/** Writes `files` in `path` (path → text; null removes it), commits everything, and checks the committer time against
 *  the instant meant (`at`, or `date`), so a fixture git read otherwise can't make a test pass → the commit's hash. */
const commit = (path, files, date, { at = date, author } = {}) => {
  const g = gitIn(path);
  for (const [f, text] of Object.entries(files)) {
    if (text === null) rmSync(join(path, f));
    else { mkdirSync(dirname(join(path, f)), { recursive: true }); writeFileSync(join(path, f), text); }
  }
  g(['add', '-A'], { date }); g(['commit', '-q', '--allow-empty', '-m', 'c'], { date, author });
  assert.equal(Number(g(['log', '-1', '--format=%ct'])), Date.parse(at) / 1000, `the fixture's committer date, ${date}`);
  return g(['rev-parse', 'HEAD']);
};

/** A repository at `path`: a 2025 commit, then one commit per entry { files, date (the committer date), author?, at? }. */
const repo = (path, commits) => {
  mkdirSync(path, { recursive: true }); gitIn(path)(['init', '-q']);
  for (const c of [{ files: { 'README.md': 'app\n' }, date: '2025-06-01T12:00:00Z' }, ...commits]) commit(path, c.files, c.date, c);
  return path;
};
const later = { files: { 'later.txt': 'x\n' }, date: '2026-10-10T12:00:00Z' };

/** What git as it runs by default (replace refs and grafts followed) lists as added → [[committer time, file]] */
const plainAdds = (path) => {
  const out = []; let t;
  for (const l of gitIn(path)(['log', '--all', '--diff-filter=A', '--name-only', '--format=@%ct', '--', '.github/workflows']).split('\n')) {
    if (l.startsWith('@')) t = Number(l.slice(1)); else if (l.trim()) out.push([t, l.trim()]);
  }
  return out;
};

const REAL = execFileSync('/bin/sh', ['-c', 'command -v git'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } }).trim();
/** A git of the tests' own: a folder (in the tests' temp folder) holding a `git` that runs `body` (sh), then the real
 *  git with "$@". First on PATH, it is the git the command runs (lib/git.mjs finds git on PATH). */
const wrap = (name, body) => {
  const d = join(dir, name); mkdirSync(d); writeFileSync(join(d, 'git'), `#!/bin/sh\n${body}exec "${REAL}" "$@"\n`, { mode: 0o755 }); return d;
};

test('workflows: one committed just inside the window is listed, in any zone and at any time of day', () => {
  const root = join(dir, 'inside');
  // [repository, committer date, the instant, the date shown (the date in UTC, the zone the SAFE line names its instant in)]
  const cases = [
    ['first-second', '2026-08-30T00:00:01Z', '2026-08-30T00:00:01Z', '2026-08-30'],
    ['utc8-morning', '2026-08-31T05:00:00+0800', '2026-08-30T21:00:00Z', '2026-08-30'],   // 31 Aug where it was made
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

test('workflows: clean twin, one committed a second before the window is SAFE, and the line names the instant and the date it compares', () => {
  const root = join(dir, 'before');
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, later]);
  for (const TZ of ZONES) {
    const r = run(root, { TZ });
    assert.deepEqual(r.rows.map((x) => [x.status, x.reason, x.searched]), [['SAFE', SAFE_TEXT, [root]]], `TZ=${TZ}: ${r.out}`);
    assert.equal(r.code, 0);
  }
  assert.match(run(root, {}, { text: true }).out, new RegExp(`\\nSAFE {5}${SAFE_TEXT.replace(/[()]/g, '\\$&')}\\n`));
});

test('workflows: committer time 1788048000, the start\'s own second, is in the window, and its line shows the date in UTC; 1788047999 is not', () => {
  // both made at UTC-7, where it was still 29 Aug: 3dbf26b showed git's %cs, the date in the commit's own zone
  // ("2026-08-29"), beside a SAFE line that names 30 Aug 2026 00:00 UTC
  assert.equal(START, 1788048000);
  const root = join(dir, 'edge');
  repo(join(root, 'at'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T17:00:00-0700', at: '2026-08-30T00:00:00Z' }]);
  repo(join(root, 'before'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T16:59:59-0700', at: '2026-08-29T23:59:59Z' }]);
  assert.equal(gitIn(join(root, 'at'))(['log', '-1', '--format=%cs %ci']), '2026-08-29 2026-08-29 17:00:00 -0700', 'the fixture: 29 Aug in its own zone');
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.repo && basename(x.repo), x.file, x.commit?.split(' ')[1]]), [['REVIEW', 'at', WF, '2026-08-30']], r.out);
  assert.match(run(root, {}, { text: true }).out, /REVIEW {2}.*at\/\.github\/workflows\/planted\.yml {2}added [0-9a-f]{7,} 2026-08-30 t\n/);
  // clean twin: the one a second before, on its own
  const twin = join(dir, 'edge-twin'); cpSync(join(root, 'before'), join(twin, 'before'), { recursive: true });
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

test('workflows: the committer date is the one compared, and the one a review line shows', () => {
  // authored before the window, committed inside it: listed, with the committer date (0.1.9 showed the author date)
  const a = join(dir, 'dates-in');
  repo(join(a, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-15T12:00:00Z', author: '2026-08-01T12:00:00Z' }]);
  assert.match(run(a, {}, { text: true }).out, /REVIEW {2}.*app\/\.github\/workflows\/planted\.yml {2}added [0-9a-f]{7,} 2026-09-15 t\n/);
  assert.equal(run(a).rows[0].commit.split(' ')[1], '2026-09-15');
  // authored inside the window, committed before it: not listed (whoever makes a commit sets its date: the known limits)
  const b = join(dir, 'dates-out');
  repo(join(b, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T12:00:00Z', author: '2026-09-15T12:00:00Z' }]);
  assert.deepEqual(run(b).rows.map((x) => [x.status, x.reason]), [['SAFE', SAFE_TEXT]]);
});

test('workflows: a back-dated commit on top of a workflow committed inside the window doesn\'t hide it; clean twin, SAFE', () => {
  // git log --since stops following a line of history at the first commit dated before the start (git's revision.c
  // skips it before queuing its parents): with this commit on top, 0.1.0 to 0.1.9 and 6cac72b read SAFE, exit code 0
  const root = join(dir, 'back-top');
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-10-10T00:00:00Z' }, { files: { 'README.md': 'x\n' }, date: BACK }]);
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), [['REVIEW', WF, '2026-10-10']], r.out);
  assert.equal(r.code, 0);
  // clean twin: the workflow a second before the window, the same back-dated commit on top
  const twin = join(dir, 'back-top-twin');
  repo(join(twin, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, { files: { 'README.md': 'x\n' }, date: BACK }]);
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

test('workflows: a back-dated commit between two workflows committed inside the window: both listed', () => {
  // 6cac72b listed only the one above the back-dated commit
  const root = join(dir, 'back-between');
  repo(join(root, 'app'), [
    { files: { '.github/workflows/first.yml': 'on: push\n' }, date: '2026-09-05T00:00:00Z' },
    { files: { 'README.md': 'x\n' }, date: BACK },
    { files: { '.github/workflows/second.yml': 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]);
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]).sort(), [['REVIEW', '.github/workflows/first.yml', '2026-09-05'], ['REVIEW', '.github/workflows/second.yml', '2026-09-10']], r.out);
});

/** A repository whose side branch (made from its first commit) gets `side` (commit specs, in order), merged into the
 *  main branch on `mergeDate` after a main-branch commit on `mainDate`; the side branch is then deleted. */
const merged = (path, side, mainDate, mergeDate) => {
  repo(path, []); const g = gitIn(path), main = g(['symbolic-ref', '--short', 'HEAD']);
  g(['checkout', '-q', '-b', 'side']);
  for (const c of side) commit(path, c.files, c.date);
  g(['checkout', '-q', main]); commit(path, { 'm.txt': 'm\n' }, mainDate);
  g(['merge', '-q', '--no-ff', '--no-edit', '-m', 'merge', 'side'], { date: mergeDate }); g(['branch', '-q', '-D', 'side']);
  assert.equal(g(['rev-list', '--parents', '-n', '1', 'HEAD']).split(' ').length, 3, 'the fixture: HEAD is a merge');
  assert.equal(g(['for-each-ref', '--format=%(refname)', 'refs/heads']), `refs/heads/${main}`, 'the fixture: the side branch is gone');
  return path;
};

test('workflows: a workflow on a side branch, behind a back-dated commit, reached only through a merge, is listed; clean twin, SAFE', () => {
  const root = join(dir, 'side');
  merged(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { 'README.md': 'x\n' }, date: BACK }], '2025-07-01T00:00:00Z', '2026-10-01T00:00:00Z');
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), [['REVIEW', WF, '2026-09-05']], r.out);
  const twin = join(dir, 'side-twin');
  merged(join(twin, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, { files: { 'README.md': 'x\n' }, date: BACK }], '2025-07-01T00:00:00Z', '2026-10-01T00:00:00Z');
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

test('workflows: a workflow added on a side branch and removed again before the merge is listed; clean twin, SAFE', () => {
  // given a path, git log follows only the parent whose files a merge matches, and passed this side branch by: 0.1.9
  // and 6cac72b read SAFE, though the workflow was in the repository's history for a day (and ran, if it was pushed)
  const root = join(dir, 'gone');
  merged(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { [WF]: null }, date: '2026-09-06T00:00:00Z' }], '2026-09-04T00:00:00Z', '2026-09-07T00:00:00Z');
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), [['REVIEW', WF, '2026-09-05']], r.out);
  const twin = join(dir, 'gone-twin');
  merged(join(twin, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, { files: { [WF]: null }, date: '2026-09-06T00:00:00Z' }], '2026-09-04T00:00:00Z', '2026-09-07T00:00:00Z');
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

test('workflows: a replace ref can\'t swap the workflow\'s commit for one without it; clean twin, SAFE', () => {
  // refs/replace/<commit> makes git show another commit in its place (git replace). lib/git.mjs sets
  // GIT_NO_REPLACE_OBJECTS=1, so the review reads the commit itself.
  const build = (path, date) => {
    repo(path, []); const g = gitIn(path), parent = g(['rev-parse', 'HEAD']), tree = g(['rev-parse', 'HEAD^{tree}']);
    const real = commit(path, { [WF]: 'on: push\n' }, date);
    g(['replace', real, g(['commit-tree', tree, '-p', parent, '-m', 'c'], { date })]);   // the same commit, without it
    return real;
  };
  const root = join(dir, 'replace'), real = build(join(root, 'app'), '2026-10-10T00:00:00Z');
  assert.deepEqual(plainAdds(join(root, 'app')), [], 'the test means something: git as it runs by default shows the stand-in, which adds nothing');
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file]), [['REVIEW', WF]], r.out);
  assert.ok(real.startsWith(r.rows[0].commit.split(' ')[0]), 'listed at the real commit');
  const twin = join(dir, 'replace-twin'); build(join(twin, 'app'), '2026-08-29T23:59:59Z');
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

test('workflows: a grafts file can\'t cut the history above a workflow, or re-parent its commit; clean twin, SAFE', () => {
  // .git/info/grafts gives a commit other parents, or none. lib/git.mjs points GIT_GRAFT_FILE at an empty file
  // (/dev/null), which git reads in its place (git's repository.c and commit.c, 2.31 to 2.54).
  const root = join(dir, 'grafts');
  // cut: the back-dated commit on top made a root, so what is below it isn't history
  const cut = repo(join(root, 'cut'), [{ files: { '.github/workflows/cut.yml': 'on: push\n' }, date: '2026-10-10T00:00:00Z' }, { files: { 'README.md': 'x\n' }, date: BACK }]);
  writeFileSync(join(cut, '.git', 'info', 'grafts'), `${gitIn(cut)(['rev-parse', 'HEAD'])}\n`);
  // re-parent: the workflow's commit grafted onto a dangling, back-dated commit with its own tree, so it adds nothing
  const rep = repo(join(root, 'reparent'), [{ files: { '.github/workflows/reparent.yml': 'on: push\n' }, date: '2026-10-10T00:00:00Z' }]);
  const g = gitIn(rep), wfc = g(['rev-parse', 'HEAD']);
  writeFileSync(join(rep, '.git', 'info', 'grafts'), `${wfc} ${g(['commit-tree', `${wfc}^{tree}`, '-m', 'D'], { date: '2025-02-01T00:00:00Z' })}\n`);
  // the test means something: git as it runs by default follows the grafts, and shows each workflow added before the window
  for (const p of [cut, rep]) assert.ok(plainAdds(p).every(([t]) => t < START) && plainAdds(p).length, JSON.stringify(plainAdds(p)));
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]).sort(), [['REVIEW', '.github/workflows/cut.yml', '2026-10-10'], ['REVIEW', '.github/workflows/reparent.yml', '2026-10-10']], r.out);
  // clean twin: a grafts file that would make a commit inside the window add a workflow committed on 1 Aug
  const twin = join(dir, 'grafts-twin'), t = repo(join(twin, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-01T00:00:00Z' }, later]);
  writeFileSync(join(t, '.git', 'info', 'grafts'), `${gitIn(t)(['rev-parse', 'HEAD'])} ${gitIn(t)(['rev-parse', 'HEAD~2'])}\n`);
  assert.ok(plainAdds(t).some(([at]) => at >= START), 'the twin means something: git as it runs by default shows the workflow added inside the window');
  assert.deepEqual(safe(twin), [[['SAFE', SAFE_TEXT]], 0]);
});

/** A clone of `from` at `root`/app (file://, so --depth works), with git clone's `opts` → its path. */
const clone = (from, root, ...opts) => { mkdirSync(root, { recursive: true }); gitIn(root)(['clone', '-q', ...opts, `file://${from}`, 'app']); return join(root, 'app'); };
/** The reason a repository whose history is cut is UNKNOWN; `cut` is "<commit>, dated <instant>" for the newest cut. */
const cutText = (cut) => `its history is cut (a shallow repository${cut ? `; the newest cut is commit ${cut}` : ''}), so workflows added below the cut can't be seen: run git fetch --unshallow, then run again`;
/** The one row and exit code of the command on `root` → [[status, reason]], code */
const rows = (root) => { const r = run(root); return [r.rows.map((x) => [x.status, x.reason ?? x.file]), r.code]; };

test('workflows: a shallow clone is UNKNOWN wherever its history is cut, naming the newest cut; the same history cloned whole is read', () => {
  // git has no history below a shallow clone's cut, and the cut commit's date says nothing about what is below it.
  // 3dbf26b read a clone cut before the start as the whole window: SAFE for one, a listed workflow for the other.
  // Inside the window: a workflow was added and removed again below the cut, and 0.1.9 and 6cac72b read SAFE.
  const srv = repo(join(dir, 'srv-cut-in'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { [WF]: null }, date: '2026-09-06T00:00:00Z' }, later]);
  gitIn(srv)(['branch', 'other', 'HEAD~1']);
  const app = clone(srv, join(dir, 'shallow-in'), '--depth', '1');
  assert.equal(readFileSync(join(app, '.git', 'shallow'), 'utf8').trim(), gitIn(app)(['rev-parse', 'HEAD']), 'the fixture: cut at its one commit');
  const r = run(dirname(app));
  assert.deepEqual([r.rows.map((x) => [x.status, x.repo, x.reason]), r.code], [[['UNKNOWN', app, cutText(`${gitIn(app)(['rev-parse', 'HEAD']).slice(0, 12)}, dated 10 Oct 2026 12:00 UTC`)]], 2], r.out);
  // two cuts, one per branch: the newest is named
  const two = clone(srv, join(dir, 'shallow-two'), '--depth', '1', '--no-single-branch');
  assert.equal(readFileSync(join(two, '.git', 'shallow'), 'utf8').trim().split('\n').length, 2, 'the fixture: cut at two commits');
  assert.deepEqual(rows(dirname(two)), [[['UNKNOWN', cutText(`${gitIn(srv)(['rev-parse', 'HEAD']).slice(0, 12)}, dated 10 Oct 2026 12:00 UTC`)]], 2]);
  // clean twin: the same history, cloned whole, lists the workflow the cut hid
  const whole = clone(srv, join(dir, 'shallow-whole'));
  assert.deepEqual(rows(dirname(whole)), [[['REVIEW', WF]], 0]);
  // cut before the window: a history that ends on 15 Aug, cloned at depth 1 (3dbf26b: SAFE); cloned whole, SAFE
  const old = repo(join(dir, 'srv-cut-out'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-01T00:00:00Z' }, { files: { 'a.txt': 'a\n' }, date: '2026-08-15T00:00:00Z' }]);
  assert.deepEqual(rows(dirname(clone(old, join(dir, 'shallow-out'), '--depth', '1'))), [[['UNKNOWN', cutText(`${gitIn(old)(['rev-parse', 'HEAD']).slice(0, 12)}, dated 15 Aug 2026 00:00 UTC`)]], 2]);
  assert.deepEqual(safe(dirname(clone(old, join(dir, 'shallow-out-whole')))), [[['SAFE', SAFE_TEXT]], 0]);
  // cut before the window, a workflow added above the cut, inside it (3dbf26b: listed, as if nothing could be below)
  const mix = repo(join(dir, 'srv-cut-mix'), [{ files: { 'a.txt': '1\n' }, date: '2026-08-15T00:00:00Z' }, { files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]);
  assert.deepEqual(rows(dirname(clone(mix, join(dir, 'shallow-mix'), '--depth', '2'))), [[['UNKNOWN', cutText(`${gitIn(mix)(['rev-parse', 'HEAD~1']).slice(0, 12)}, dated 15 Aug 2026 00:00 UTC`)]], 2]);
  assert.deepEqual(rows(dirname(clone(mix, join(dir, 'shallow-mix-whole')))), [[['REVIEW', WF]], 0]);
  // a shallow file that can't be read (here a folder) leaves it unknown whether the history is cut
  mkdirSync(join(whole, '.git', 'shallow'));
  const unread = run(dirname(whole));
  assert.deepEqual([unread.rows.map((x) => x.status), unread.code], [['UNKNOWN'], 2], unread.out);
  assert.equal(unread.rows[0].reason, `its shallow file (${join(whole, '.git', 'shallow')}) could not be read, so whether its history is all here is not known`);
});

test('workflows: a --depth 1 clone of a back-dated tip, over a workflow committed on 5 Sep, is UNKNOWN, never SAFE; cloned whole, listed', () => {
  // The cut is at the back-dated commit, so every commit the clone has is dated before the window. 3dbf26b took a cut
  // dated before the start as the window all here and read SAFE, exit code 0, with the workflow file in the clone's tree.
  const srv = repo(join(dir, 'srv-backcut'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { 'a.txt': 'a\n' }, date: BACK }]);
  const app = clone(srv, join(dir, 'backcut'), '--depth', '1');
  assert.ok(existsSync(join(app, WF)), 'the fixture: the workflow is in the clone\'s tree');
  assert.deepEqual(gitIn(app)(['log', '--all', '--format=%ct']), String(Date.parse(BACK) / 1000), 'the fixture: the clone\'s one commit is the back-dated one');
  assert.deepEqual(rows(dirname(app)), [[['UNKNOWN', cutText(`${gitIn(srv)(['rev-parse', 'HEAD']).slice(0, 12)}, dated 1 Jan 2025 00:00 UTC`)]], 2]);
  // clean twin: the same history cloned whole, the workflow listed at its own commit
  const whole = run(dirname(clone(srv, join(dir, 'backcut-whole'))));
  assert.deepEqual([whole.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), whole.code], [[['REVIEW', WF, '2026-09-05']], 0], whole.out);
});

test('workflows: a shallow file written into a full repository is UNKNOWN, empty or not; without it, the same repository is read', () => {
  // git gives each commit the shallow file names no parents, so a full repository with one written into it shows
  // nothing below that commit: here a back-dated commit on top of a workflow committed on 5 Sep
  const app = repo(join(dir, 'planted-shallow', 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { 'a.txt': 'a\n' }, date: BACK }]);
  const g = gitIn(app), top = g(['rev-parse', 'HEAD']), file = join(app, '.git', 'shallow');
  writeFileSync(file, `${top}\n`);
  assert.equal(g(['log', '--all', '--format=%H']), top, 'the test means something: git reads only the commit the file names');
  assert.deepEqual(rows(dirname(app)), [[['UNKNOWN', cutText(`${top.slice(0, 12)}, dated 1 Jan 2025 00:00 UTC`)]], 2]);
  // empty: git says the repository is shallow, with no cut to name
  writeFileSync(file, '');
  assert.equal(g(['rev-parse', '--is-shallow-repository']), 'true', 'the fixture: git takes an empty shallow file as shallow');
  assert.deepEqual(rows(dirname(app)), [[['UNKNOWN', cutText()]], 2]);
  // clean twin: the same repository without it
  rmSync(file);
  assert.deepEqual(rows(dirname(app)), [[['REVIEW', WF]], 0]);
});

test('workflows: a git that says a repository isn\'t shallow while its shallow file names a commit is UNKNOWN, so is one that says it is with no shallow file, and one that doesn\'t answer; passing git\'s answer through, listed', () => {
  // either sign is enough: git's answer (rev-parse --is-shallow-repository) or a shallow file that isn't empty
  const app = repo(join(dir, 'says', 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { 'a.txt': 'a\n' }, date: BACK }]);
  const top = gitIn(app)(['rev-parse', 'HEAD']), file = join(app, '.git', 'shallow');
  const stub = (name, sed) => `${wrap(name, `for a in "$@"; do case "$a" in --is-shallow-repository) "${REAL}" "$@" | sed '${sed}'; exit;; esac; done\n`)}:/usr/bin:/bin`;
  const no = stub('git-says-no', '1s/^true$/false/'), yes = stub('git-says-yes', '1s/^false$/true/'), dumb = stub('git-says-maybe', '1s/^.*$/maybe/'), same = stub('git-says-same', 's/^//');
  const as = (root, PATH) => { const r = run(root, { PATH }); return [r.rows.map((x) => [x.status, x.reason ?? x.file]), r.code]; };
  writeFileSync(file, `${top}\n`);
  assert.deepEqual(as(dirname(app), no), [[['UNKNOWN', cutText(`${top.slice(0, 12)}, dated 1 Jan 2025 00:00 UTC`)]], 2]);
  rmSync(file);
  // git's answer alone, with no shallow file to name a cut (a git that disagrees with its own --git-path)
  assert.deepEqual(as(dirname(app), yes), [[['UNKNOWN', cutText()]], 2]);
  assert.deepEqual(as(dirname(app), dumb), [[['UNKNOWN', 'git didn\'t say whether its history is cut (git rev-parse gave "maybe\\n.git/shallow\\n"), so whether its history is all here is not known']], 2]);
  // clean twins: the same gits in the same repository without the shallow file
  assert.deepEqual(as(dirname(app), no), [[['REVIEW', WF]], 0]);
  assert.deepEqual(as(dirname(app), same), [[['REVIEW', WF]], 0]);
});

test('workflows: partial clones whose remote is gone are read with nothing fetched: blobless listed, treeless UNKNOWN with commits in the window, SAFE without', () => {
  // A fetch would run the program the clone's config names (remote.origin.uploadpack), which leaves a marker. A
  // treeless clone (--filter=tree:0) lacks the trees of the commits in the window, so it can't be read: UNKNOWN, never
  // a SAFE because a fetch failed. With no commit in the window no tree is needed, and it reads SAFE, as before.
  const marker = join(dir, 'pc-fetched'), pack = join(dir, 'pc-uploadpack');
  writeFileSync(pack, `#!/bin/sh\ntouch "${marker}"\nexit 1\n`, { mode: 0o755 });
  const busy = repo(join(dir, 'pc-srv'), [{ files: { '.github/workflows/old.yml': 'on: push\n' }, date: '2026-08-01T00:00:00Z' }, { files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }, later]);
  const quiet = repo(join(dir, 'pc-srv-quiet'), [{ files: { '.github/workflows/old.yml': 'on: push\n' }, date: '2026-08-01T00:00:00Z' }, { files: { 'b.txt': 'b\n' }, date: '2026-08-10T00:00:00Z' }]);
  for (const s of [busy, quiet]) gitIn(s)(['config', 'uploadpack.allowFilter', 'true']);
  const clone = (from, name, filter) => {
    const root = join(dir, name); mkdirSync(root);
    gitIn(root)(['clone', '-q', '--no-local', `--filter=${filter}`, `file://${from}`, 'app']); gitIn(join(root, 'app'))(['config', 'remote.origin.uploadpack', pack]);
    return root;
  };
  const blobless = clone(busy, 'pc-blobless', 'blob:none'), treeless = clone(busy, 'pc-treeless', 'tree:0'), quietTreeless = clone(quiet, 'pc-quiet-treeless', 'tree:0');
  renameSync(busy, `${busy}-gone`); renameSync(quiet, `${quiet}-gone`);
  // the test means something: git as it runs by default tries to fetch the trees a treeless clone lacks
  try { plainAdds(join(treeless, 'app')); } catch { /* the fetch fails; the marker is what counts */ }
  assert.ok(existsSync(marker), 'git log fetches through the configured program'); rmSync(marker);
  const b = run(blobless);
  assert.deepEqual([b.rows.map((x) => [x.status, x.file]), b.code], [[['REVIEW', WF]], 0], b.out);
  const t = run(treeless);
  assert.deepEqual([t.rows.map((x) => [x.status, x.repo]), t.code], [[['UNKNOWN', join(treeless, 'app')]], 2], t.out);
  assert.match(t.rows[0].reason, /^git could not read this repository \(/);
  assert.deepEqual(safe(quietTreeless), [[['SAFE', SAFE_TEXT]], 0]);
  assert.equal(existsSync(marker), false, 'the review made git fetch');
});

test('workflows: a commit whose committer time git can\'t read makes the repository UNKNOWN, never SAFE; clean twin, listed', () => {
  // git prints no %ct for a committer line without a date it can read; git's --since walk took such a commit as dated
  // 1970 and stopped there, so on top of a workflow it hid it as a back-dated commit does
  const build = (root, when) => {
    const path = repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]), g = gitIn(path);
    const body = `tree ${g(['rev-parse', 'HEAD^{tree}'])}\nparent ${g(['rev-parse', 'HEAD'])}\nauthor t <t@x> 1790000000 +0000\ncommitter t <t@x>${when}\n\nc\n`;
    g(['update-ref', 'HEAD', g(['hash-object', '-t', 'commit', '-w', '--literally', '--stdin'], { input: body })]);
    return path;
  };
  for (const [name, when] of [['no-date', ''], ['words', ' soon +0000'], ['no-zone', ' 1790000000']]) {
    const root = join(dir, `ct-${name}`), path = build(root, when);
    assert.equal(gitIn(path)(['log', '-1', '--format=%ct']), '', `the fixture: git prints no %ct for "committer t <t@x>${when}"`);
    const r = run(root);
    assert.deepEqual([r.rows.map((x) => [x.status, x.repo]), r.code], [[['UNKNOWN', path]], 2], r.out);
    assert.match(r.rows[0].reason, /^commit [0-9a-f]{12} has no committer time Wardlatch can read \(git's %ct gave ""\), so whether it is in the window is not known$/);
  }
  const twin = join(dir, 'ct-twin'); build(twin, ' 1790000000 +0000');
  assert.deepEqual(run(twin).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
});

test('workflows: a git that prints a committer time that isn\'t a plain whole number makes the repository UNKNOWN; the same git passing it through, listed', () => {
  const root = join(dir, 'garbage');
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]);
  // each runs git and rewrites the committer times in what one call prints: the list of commits (`--format=%H %ct`),
  // or the commit lines of the workflow files (`--format=@@%H %ct ...`)
  const stub = (name, format, sed) => wrap(name, `for a in "$@"; do case "$a" in ${format}) "${REAL}" "$@" | sed '${sed}'; exit;; esac; done\n`);
  const cases = [['', '""'], ['x', '"x"'], ['-5', '"-5"'], ['1.5', '"1.5"'], ['1790000000x', '"1790000000x"'], ['+1790000000', '"+1790000000"'], [' 1790000000', '" 1790000000"']];
  cases.forEach(([v, shown], i) => {
    const r = run(root, { PATH: `${stub(`git-ct-${i}`, "'--format=%H %ct'", `s/ [0-9]*$/ ${v}/`)}:/usr/bin:/bin` });
    assert.deepEqual([r.rows.map((x) => x.status), r.code], [['UNKNOWN'], 2], `${JSON.stringify(v)}: ${r.out}`);
    assert.equal(r.rows[0].reason, `commit ${r.rows[0].reason.slice(7, 19)} has no committer time Wardlatch can read (git's %ct gave ${shown}), so whether it is in the window is not known`);
  });
  const late = run(root, { PATH: `${stub('git-ct-files', "--format=@@*", 's/^\\(@@[0-9a-f]*\\) [0-9]*/\\1 x/')}:/usr/bin:/bin` });
  assert.deepEqual([late.rows.map((x) => x.status), late.code], [['UNKNOWN'], 2], late.out);
  assert.match(late.rows[0].reason, /^git listed a commit in a form Wardlatch can't read \("@@[0-9a-f]{40} x [0-9a-f]+ t"\), so its workflow files are not known$/);
  // clean twin: the same kind of git, rewriting nothing
  assert.deepEqual(run(root, { PATH: `${stub('git-ct-same', "'--format=%H %ct'", 's/^//')}:/usr/bin:/bin` }).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
});

test('workflows: a committer time past what a date can hold is listed, its date shown as git writes a raw time; the same git passing times through, the date in UTC', () => {
  // the review line's date is worked out from %ct: one beyond the year 275760 has no date, and is still in the window
  const root = join(dir, 'far'), far = '99999999999999999999';
  repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]);
  const stub = (name, t) => `${wrap(name, `for a in "$@"; do case "$a" in '--format=%H %ct') "${REAL}" "$@" | sed 's/ [0-9]*$/ ${t}/'; exit;; --format=@@*) "${REAL}" "$@" | sed 's/^\\(@@[0-9a-f]*\\) [0-9]*/\\1 ${t}/'; exit;; esac; done\n`)}:/usr/bin:/bin`;
  const r = run(root, { PATH: stub('git-ct-far', far) });
  assert.deepEqual([r.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), r.code], [[['REVIEW', WF, `@${far}`]], 0], r.out);
  // clean twin: the same kind of git, giving the commit's own time (2026-09-10T00:00:00Z)
  const t = run(root, { PATH: stub('git-ct-own', String(Date.parse('2026-09-10T00:00:00Z') / 1000)) });
  assert.deepEqual([t.rows.map((x) => [x.status, x.file, x.commit?.split(' ')[1]]), t.code], [[['REVIEW', WF, '2026-09-10']], 0], t.out);
});

test('workflows: a start that is not an explicit UTC instant is UNKNOWN, never SAFE', () => {
  const root = join(dir, 'bare'), app = repo(join(root, 'app'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-15T12:00:00Z' }]);
  // the extended years round-trip through Date as they are written, so only the form's own check refuses them
  for (const since of ['2026-09-01', '2026-08-30 00:00:00', '2026-08-30T00:00:00', '2026-08-30T00:00:00+00:00', '2026-08-30T00:00:00.000Z', '2026-02-30T00:00:00Z', '2026-08-30T24:00:00Z',
    '+010000-01-01T00:00:00Z', '+275760-09-13T00:00:00Z', '-000001-01-01T00:00:00Z', '', undefined, START]) {
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

test('workflows: git gets no date: no --since, --after, --until, --before, --max-age, --min-age or --since-as-filter, in any call', () => {
  // A date given to git log stops its walk at the first commit dated before it (the back-dated tests above). This git
  // writes down each argument list it gets, in this test's own folder: the count, then each argument, NUL-separated.
  // Two repositories: a workflow on 31 Aug, listed, and a clean twin, one committed a second before the window.
  const root = join(dir, 'argv'), calls = join(dir, 'argv-calls');
  repo(join(root, 'in'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-31T00:30:00Z' }, later]);
  repo(join(root, 'before'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }, later]);
  const r = run(root, { PATH: `${wrap('git-argv', `printf '%s\\0' "$#" "$@" >> "${calls}"\n`)}:/usr/bin:/bin` });
  assert.deepEqual(r.rows.map((x) => [x.status, x.repo && basename(x.repo), x.file]), [['REVIEW', 'in', WF]], r.out);
  assert.equal(r.code, 0);
  const argvs = [];
  for (let f = readFileSync(calls, 'utf8').split('\0'), i = 0; i < f.length - 1; i += 1 + Number(f[i])) argvs.push(f.slice(i + 1, i + 1 + Number(f[i])));
  // each repository: whether it is shallow and where its shallow file is, every commit with its time, then the files
  // the kept commits added
  assert.deepEqual(argvs.map((a) => a[a.indexOf('-C') + 2]), ['rev-parse', 'log', 'log', 'rev-parse', 'log', 'log'], JSON.stringify(argvs));
  for (const a of argvs.filter((x) => x[x.indexOf('-C') + 2] === 'rev-parse')) assert.deepEqual(a.slice(a.indexOf('-C') + 2), ['rev-parse', '--is-shallow-repository', '--git-path', 'shallow']);
  for (const a of argvs) assert.deepEqual(a.filter((x) => /^--(?:since|after|until|before|max-age|min-age)/i.test(x)), [], JSON.stringify(a));
  assert.equal(argvs.filter((a) => a.includes('--all') && a.includes('--format=%H %ct')).length, 2, 'every commit, with its committer time in seconds');
  assert.equal(argvs.filter((a) => a.includes('--no-walk=unsorted') && a.includes('--stdin') && !a.includes('--all')).length, 2, 'the files of exactly the commits kept');
});

test('workflows: the window\'s start is its instant in seconds, named in UTC', () => {
  assert.deepEqual(workflows.windowStart('2026-08-30T00:00:00Z'), { seconds: START, label: '30 Aug 2026 00:00 UTC' });
  assert.equal(workflows.windowStart('2026-08-30T10:00:05Z').label, '30 Aug 2026 10:00:05 UTC');
});

const CHANGELOG = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8');
/** The CHANGELOG's hand check for this review: the one command in backticks, anywhere in `text` (the CHANGELOG), that
 *  runs `git ... log ... -- .github/workflows` → { line, bullet } (the list item that gives it, up to the next item or
 *  heading). Anywhere, not by its section's name: a release moves the [Unreleased] entries under "## [X.Y.Z] - date"
 *  (docs/RELEASING.md), and an earlier cut of this test, which looked only in [Unreleased], failed there. */
const handCheck = (text = CHANGELOG) => {
  const found = [...text.matchAll(/`([^`\n]*\bgit\b[^`\n]* log [^`\n]*-- \.github\/workflows)`/g)];
  assert.equal(found.length, 1, `one hand check in the CHANGELOG: ${JSON.stringify(found.map((m) => m[1]))}`);
  const at = found[0].index, ends = ['\n- ', '\n  - ', '\n#'].map((s) => text.indexOf(s, at)).filter((i) => i >= 0);
  return { line: found[0][1], bullet: text.slice(Math.max(text.lastIndexOf('\n- ', at), text.lastIndexOf('\n  - ', at)), ends.length ? Math.min(...ends) : undefined) };
};

/** The hand check run as a person runs it: pasted into a shell (/bin/sh), in the repository, with their own
 *  environment (and `env`), here in a zone west of UTC (UTC-7), so a line that shows dates in the reader's zone or the
 *  commit's can't pass → [{ commit, date, file }] */
const runHand = (line, path, env = {}) => {
  const out = execFileSync('/bin/sh', ['-c', line], { cwd: path, encoding: 'utf8', env: { ...process.env, TZ: 'America/Los_Angeles', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const found = [], withTime = line.includes('%ct'); let commit = '', ct, date = '', rest;
  for (const l of out.split('\n')) {
    if (l.startsWith('.github/workflows/')) found.push({ commit, ct, date, file: l });
    else if (l.trim()) [commit, ...rest] = l.split(' '), [ct, date = ''] = withTime ? [rest[0] ?? '', rest[1] ?? ''] : [undefined, rest[0] ?? ''];
  }
  return found;
};

/** Writes `path`'s commit-graph file and makes `commit` a root in it (its first parent "none"), as a crafted file can:
 *  git then reads no parent for that commit, unless told not to use the file (core.commitGraph=false). */
const craftGraph = (path, commit) => {
  gitIn(path)(['commit-graph', 'write', '--reachable']);
  const file = join(path, '.git', 'objects', 'info', 'commit-graph'), buf = readFileSync(file);
  const hashLen = buf[5] === 2 ? 32 : 20, chunk = (id) => {
    for (let i = 0; i < buf[6]; i++) if (buf.toString('latin1', 8 + i * 12, 12 + i * 12) === id) return Number(buf.readBigUInt64BE(12 + i * 12));
    throw new Error(`no ${id} chunk in ${file}`);
  };
  const oids = chunk('OIDL'), total = buf.readUInt32BE(chunk('OIDF') + 255 * 4);
  const i = Array.from({ length: total }, (_, k) => buf.toString('hex', oids + k * hashLen, oids + (k + 1) * hashLen)).indexOf(commit);
  assert.ok(i >= 0, `the fixture: ${commit} is in the commit-graph`);
  buf.writeUInt32BE(0x70000000, chunk('CDAT') + i * (hashLen + 16) + hashLen);
  rmSync(file); writeFileSync(file, buf);
};

test('workflows: the CHANGELOG\'s hand check is found wherever a release puts it; none, or two, is an error', () => {
  // docs/RELEASING.md: move "Unreleased" under "## [X.Y.Z] - YYYY-MM-DD". v0.1.8 and v0.1.9 kept an empty [Unreleased]
  // above the new section; the release workflow runs these tests on the commit that does it. Both layouts, made from
  // the heading the line is under now, whatever it is: an empty [Unreleased] above a version's heading, or the
  // heading renamed in place.
  const here = handCheck(), head = CHANGELOG.lastIndexOf('\n## [', CHANGELOG.indexOf(`\`${here.line}\``));
  assert.ok(head >= 0, 'the fixture: the line is under a "## [" heading');
  const [above, below] = [CHANGELOG.slice(0, head), CHANGELOG.slice(CHANGELOG.indexOf('\n', head + 1))];
  const released = `${above}\n## [Unreleased]\n\n## [9.9.9] - 2026-10-26${below}`, renamed = `${above}\n## [9.9.9] - 2026-10-26${below}`;
  for (const text of [released, renamed]) assert.deepEqual(handCheck(text), here);
  // none, or a second one a reader could paste instead, fails the test rather than leaving a line untested
  assert.throws(() => handCheck(CHANGELOG.replace(`\`${here.line}\``, '')), /one hand check in the CHANGELOG: \[\]/);
  assert.throws(() => handCheck(`${released}\n  - \`${here.line.replace('--all', '--branches')}\`\n`), /one hand check in the CHANGELOG: \[".*",".*"\]/);
});

test('workflows: the CHANGELOG\'s hand check, run as written, lists every workflow the review lists, at the same commit and UTC date', () => {
  // So the documented command can't drift from what lib/workflows.mjs runs. The line 3dbf26b gave listed nothing for a
  // workflow that only a merge commit adds, missed one renamed within .github/workflows, listed nothing for a root
  // commit under log.showRoot=false, and followed a replace ref and a grafts file. The one baa9955 gave started, on a
  // terminal, the pager a repository's config names, and in a partial clone fetched through the program it names.
  const { line, bullet } = handCheck();
  assert.doesNotMatch(line, /--(?:since|after|until|before|max-age|min-age)/, 'no date: given one, git stops reading a branch at the first commit dated before it');
  assert.match(bullet, /2026-08-30/, 'the item says which dates are in the window');
  assert.match(bullet, /UTC/, 'and in which zone they are shown');
  const root = join(dir, 'hand'), W = '.github/workflows';
  const built = {};
  // a replace ref: (a) the workflow's commit replaced by one without it; (b) a back-dated commit on top replaced by a
  // parentless stand-in with the same tree, so git as it runs by default shows the workflow added in 2025
  { const a = repo(join(root, 'replace-a'), []), g = gitIn(a), parent = g(['rev-parse', 'HEAD']), tree = g(['rev-parse', 'HEAD^{tree}']);
    const real = commit(a, { [`${W}/ra.yml`]: 'on: push\n' }, '2026-10-10T00:00:00Z');
    g(['replace', real, g(['commit-tree', tree, '-p', parent, '-m', 'c'], { date: '2026-10-10T00:00:00Z' })]);
    built[a] = [`${W}/ra.yml`]; }
  { const b = repo(join(root, 'replace-b'), [{ files: { [`${W}/rb.yml`]: 'on: push\n' }, date: '2026-10-10T00:00:00Z' }, { files: { 'README.md': 'y\n' }, date: BACK }]), g = gitIn(b);
    g(['replace', g(['rev-parse', 'HEAD']), g(['commit-tree', g(['rev-parse', 'HEAD^{tree}']), '-m', 's'], { date: BACK })]);
    built[b] = [`${W}/rb.yml`]; }
  // a workflow that only a merge commit adds, neither parent having it
  { const m = repo(join(root, 'merge-only'), []), g = gitIn(m), main = g(['symbolic-ref', '--short', 'HEAD']);
    g(['checkout', '-q', '-b', 'side']); commit(m, { 's.txt': 's\n' }, '2025-07-01T00:00:00Z');
    g(['checkout', '-q', main]); commit(m, { 'm.txt': 'm\n' }, '2025-07-02T00:00:00Z');
    g(['merge', '-q', '--no-ff', '--no-commit', 'side'], { date: '2026-09-20T00:00:00Z' });
    commit(m, { [`${W}/merge.yml`]: 'on: push\n' }, '2026-09-20T00:00:00Z'); g(['branch', '-q', '-D', 'side']);
    assert.equal(g(['rev-list', '--parents', '-n', '1', 'HEAD']).split(' ').length, 3, 'the fixture: the workflow is added by a merge');
    built[m] = [`${W}/merge.yml`]; }
  // a root commit that adds the workflow, in a repository whose config says log.showRoot=false
  { const r = join(root, 'root-commit'); mkdirSync(r, { recursive: true }); gitIn(r)(['init', '-q']);
    commit(r, { [`${W}/root.yml`]: 'on: push\n' }, '2026-09-10T00:00:00Z'); gitIn(r)(['config', 'log.showRoot', 'false']);
    assert.equal(gitIn(r)(['log', '--diff-filter=A', '--name-only', '--format=']), '', 'the test means something: git shows no files for the root commit');
    built[r] = [`${W}/root.yml`]; }
  // renamed into .github/workflows from elsewhere, and within it
  { const n = repo(join(root, 'rename'), [{ files: { 'ci/x.yml': 'on: [push]\n# x\n', [`${W}/a.yml`]: 'on: push\n# a\n' }, date: '2025-07-01T00:00:00Z' },
    { files: { 'ci/x.yml': null, [`${W}/x.yml`]: 'on: [push]\n# x\n', [`${W}/a.yml`]: null, [`${W}/b.yml`]: 'on: push\n# a\n' }, date: '2026-09-10T00:00:00Z' }]);
    assert.match(gitIn(n)(['log', '-1', '--name-status', '--format=']), /^R100\t\.github\/workflows\/a\.yml\t\.github\/workflows\/b\.yml$/m, 'the test means something: git calls it a rename');
    built[n] = [`${W}/b.yml`, `${W}/x.yml`]; }
  // committed at the start's own second from UTC-7, where it was 29 Aug: in the window, shown as 2026-08-30
  built[repo(join(root, 'edge'), [{ files: { [`${W}/at.yml`]: 'on: push\n' }, date: '2026-08-29T17:00:00-0700', at: '2026-08-30T00:00:00Z' }])] = [`${W}/at.yml`];
  // only on a branch that isn't checked out
  { const o = repo(join(root, 'other-branch'), []), g = gitIn(o), main = g(['symbolic-ref', '--short', 'HEAD']);
    g(['checkout', '-q', '-b', 'side']); commit(o, { [`${W}/side.yml`]: 'on: push\n' }, '2026-09-12T00:00:00Z'); g(['checkout', '-q', main]);
    built[o] = [`${W}/side.yml`]; }
  // added and removed again on a merged side branch (git log -- <path> without --full-history passes it by)
  built[merged(join(root, 'side-gone'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { [WF]: null }, date: '2026-09-06T00:00:00Z' }], '2026-09-04T00:00:00Z', '2026-09-07T00:00:00Z')] = [WF];
  // a commit-graph file crafted to make the back-dated commit on top a root
  { const c = repo(join(root, 'graph'), [{ files: { [`${W}/graph.yml`]: 'on: push\n' }, date: '2026-10-10T00:00:00Z' }, { files: { 'README.md': 'z\n' }, date: BACK }]);
    craftGraph(c, gitIn(c)(['rev-parse', 'HEAD']));
    assert.deepEqual(plainAdds(c), [[Date.parse(BACK) / 1000, `${W}/graph.yml`]], 'the test means something: git as it runs by default reads the crafted file');
    built[c] = [`${W}/graph.yml`]; }
  // a signed commit (a gpgsig header) that adds a workflow, in a repository whose config sets log.showSignature and
  // names a gpg.program that leaves a marker: the line must not run it
  const marker = join(dir, 'hand-gpg-ran');
  { const s = repo(join(root, 'signed'), []), g = gitIn(s), prog = join(dir, 'hand-gpg');
    writeFileSync(prog, `#!/bin/sh\ntouch "${marker}"\nexit 1\n`, { mode: 0o755 });
    mkdirSync(join(s, W), { recursive: true }); writeFileSync(join(s, W, 'signed.yml'), 'on: push\n'); g(['add', '-A']);
    const body = `tree ${g(['write-tree'])}\nparent ${g(['rev-parse', 'HEAD'])}\nauthor t <t@x> 1790000000 +0000\ncommitter t <t@x> 1790000000 +0000\n`
      + 'gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n';
    g(['update-ref', 'HEAD', g(['hash-object', '-t', 'commit', '-w', '--stdin'], { input: body })]);
    g(['config', 'gpg.program', prog]); g(['config', 'log.showSignature', 'true']);
    try { g(['log', '-1']); } catch { /* the marker is what counts */ }
    assert.ok(existsSync(marker), 'the test means something: git log runs the gpg.program the config names'); rmSync(marker);
    built[s] = [`${W}/signed.yml`]; }
  // authored before the window, committed inside it: the line must show the committer date, the one the review
  // compares (with the author date, %ad, it would show 2026-08-01, and a reader would pass it by)
  built[repo(join(root, 'author-before'), [{ files: { [`${W}/ab.yml`]: 'on: push\n' }, date: '2026-09-15T12:00:00Z', author: '2026-08-01T12:00:00Z' }])] = [`${W}/ab.yml`];
  // partial clones whose remote is gone, with a workflow in the window: a fetch would run the uploadpack program the
  // clone's config names, which leaves a marker. Blobless (no file contents) is read without one, by the review and
  // the line; treeless is below.
  const fetched = join(dir, 'hand-fetched'), pack = join(dir, 'hand-uploadpack');
  writeFileSync(pack, `#!/bin/sh\ntouch "${fetched}"\nexit 1\n`, { mode: 0o755 });
  const srv = repo(join(dir, 'hand-srv'), [{ files: { [`${W}/pc.yml`]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }, later]);
  gitIn(srv)(['config', 'uploadpack.allowFilter', 'true']);
  const partial = (name, filter) => {
    gitIn(root)(['clone', '-q', '--no-local', `--filter=${filter}`, `file://${srv}`, name]); gitIn(join(root, name))(['config', 'remote.origin.uploadpack', pack]);
    return join(root, name);
  };
  built[partial('partial-blobless', 'blob:none')] = [`${W}/pc.yml`];
  const treeless = partial('partial-treeless', 'tree:0');
  renameSync(srv, `${srv}-gone`);
  for (const [path, files] of Object.entries(built)) {
    const review = workflows.workflowsAddedSince(path, '2026-08-30T00:00:00Z'), hand = runHand(line, path);
    assert.deepEqual(review.map((x) => x.file).sort(), files, `${basename(path)}: the review lists ${files}`);
    for (const { file, commit: c } of review) {
      const [hash, day] = c.split(' ');
      assert.ok(hand.some((x) => x.file === file && (x.commit.startsWith(hash) || hash.startsWith(x.commit)) && x.date.slice(0, 10) === day && /(?:Z|\+00:00)$/.test(x.date)),
        `${basename(path)}: the hand check lists ${file} at ${c}, its date in UTC: ${JSON.stringify(hand)}`);
    }
  }
  assert.equal(existsSync(marker), false, 'the line ran the gpg.program a repository\'s config names');
  assert.equal(existsSync(fetched), false, 'the line made git fetch in a blobless clone');
  // treeless: the trees of the commits in the window aren't here, so the review is UNKNOWN, and the line stops with an
  // error instead of fetching them
  assert.ok(workflows.workflowsAddedSince(treeless, '2026-08-30T00:00:00Z').error, 'the review can\'t read a treeless clone');
  const shell = (l, cwd) => spawnSync('/bin/sh', ['-c', l], { cwd, encoding: 'utf8', env: { ...process.env, TZ: 'America/Los_Angeles' } });
  const stopped = shell(line, treeless);
  assert.ok(stopped.status !== 0 && /fatal: /.test(stopped.stderr), `the line stops with an error in a treeless clone: ${stopped.stdout}${stopped.stderr}`);
  assert.equal(existsSync(fetched), false, 'the line made git fetch in a treeless clone');
  // the test means something: without the line's two settings that stop a fetch, git fetches through the program
  const fetching = line.replace(/\bGIT_NO_LAZY_FETCH=1 /, '').replace(/\bGIT_ALLOW_PROTOCOL=none /, '');
  assert.equal(fetching.length, line.length - 'GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL=none '.length, 'the line sets both');
  shell(fetching, treeless);
  assert.ok(existsSync(fetched), 'git as the line runs it, without those two settings, fetches through the program the config names');
  // What no run above can tell: git gets --no-pager (writing to a pipe, as here, git starts no pager; on a terminal it
  // starts the one the repository's config names, core.pager or pager.log) and both settings that stop a fetch (on
  // this git either one alone stops it: GIT_NO_LAZY_FETCH=1 for newer git, GIT_ALLOW_PROTOCOL=none, which refuses
  // every transport, for older). This git writes down those settings and its arguments, then runs the real one.
  const seen = join(dir, 'hand-argv'), rec = wrap('git-hand-argv', `printf '%s\\0' "$TZ" "$GIT_NO_LAZY_FETCH" "$GIT_ALLOW_PROTOCOL" "$@" > "${seen}"\n`);
  const edge = Object.keys(built).find((p) => basename(p) === 'edge');
  assert.deepEqual(runHand(line, edge, { PATH: `${rec}:${process.env.PATH}` }).map((x) => x.file), [`${W}/at.yml`]);
  const [tz, lazy, proto, ...args] = readFileSync(seen, 'utf8').split('\0').slice(0, -1);
  assert.deepEqual([tz, lazy, proto], ['UTC', '1', 'none'], 'git gets TZ=UTC, GIT_NO_LAZY_FETCH=1 and GIT_ALLOW_PROTOCOL=none');
  assert.ok(args.indexOf('--no-pager') >= 0 && args.indexOf('--no-pager') < args.indexOf('log'), `git gets --no-pager before log: ${JSON.stringify(args)}`);
  // a workflow added by a commit whose committer line has no date git can read: the review is UNKNOWN for the
  // repository, and the line lists the file with no number and no date (three spaces after the hash), which the item says to count as
  // in the window
  assert.match(bullet, /no number and no date \(three spaces\s+after\s+its hash\)/, 'the item says what a blank date means');
  { const n = repo(join(root, 'no-date'), []), g = gitIn(n);
    mkdirSync(join(n, W), { recursive: true }); writeFileSync(join(n, W, 'nodate.yml'), 'on: push\n'); g(['add', '-A']);
    const body = `tree ${g(['write-tree'])}\nparent ${g(['rev-parse', 'HEAD'])}\nauthor t <t@x> 1790000000 +0000\ncommitter t <t@x>\n\nc\n`;
    g(['update-ref', 'HEAD', g(['hash-object', '-t', 'commit', '-w', '--literally', '--stdin'], { input: body })]);
    assert.match(workflows.workflowsAddedSince(n, '2026-08-30T00:00:00Z').error, /has no committer time Wardlatch can read/);
    assert.deepEqual(runHand(line, n).map((x) => [x.file, x.date]), [[`${W}/nodate.yml`, '']]); }
  // committer times too far in the future for git to turn into a date. At 2^63-1 git prints 1970-01-01T00:00:00Z; for
  // 67767976233532800 to 67768036191676799 it prints a NEGATIVE year (-2147482895-02-16T20:26:40Z). The reader here is
  // the item's words: it compares the number (the %ct field) with the start it names, or counts a field that is blank
  // or not a plain number. The date text is never read, so no date string can mislead.
  assert.match(bullet, /1788048000/, 'the item names the start as a number of seconds');
  assert.match(bullet, /or isn't a plain\s+number/, 'and counts a field that is not a plain number');
  assert.equal(Date.parse('2026-08-30T00:00:00Z') / 1000, 1788048000, 'that number is the start');
  const startSecs = Number(bullet.match(/\b(1788\d{6})\b/)?.[1]);
  const readerCounts = (x) => x.ct === '' || !/^\d+$/.test(x.ct) || BigInt(x.ct) >= BigInt(startSecs);
  for (const [name, ct, listed] of [['far-future', '9223372036854775807', true], ['far-negyear', '67768000000000000', true],
    ['far-negyear-low', '67767976233532800', true], ['far-negyear-high', '67768036191676799', true], ['edge-seconds-before', '1788047999', false]]) {
    const f = repo(join(root, name), []), g = gitIn(f);
    mkdirSync(join(f, W), { recursive: true }); writeFileSync(join(f, W, 'far.yml'), 'on: push\n'); g(['add', '-A']);
    const body = `tree ${g(['write-tree'])}\nparent ${g(['rev-parse', 'HEAD'])}\nauthor t <t@x> 1790000000 +0000\ncommitter t <t@x> ${ct} +0000\n\nc\n`;
    g(['update-ref', 'HEAD', g(['hash-object', '-t', 'commit', '-w', '--literally', '--stdin'], { input: body })]);
    const hand = runHand(line, f).filter((x) => x.file === `${W}/far.yml`);
    assert.equal(hand.length, 1, `${name}: the line lists the file`);
    assert.equal(hand[0].ct, ct, `${name}: the line shows the raw committer time`);
    const review = workflows.workflowsAddedSince(f, '2026-08-30T00:00:00Z').map((x) => x.file);
    assert.deepEqual(review, listed ? [`${W}/far.yml`] : [], `${name}: the review${listed ? ' lists it' : ' lists nothing'}`);
    assert.equal(readerCounts(hand[0]), listed, `${name}: a reader following the item counts ${JSON.stringify(hand[0])} ${listed ? 'in' : 'out of'} the window`);
  }
  assert.match(bullet, /top folder of each repository/, 'the item says where to paste the line');
  // clean twins: a second before the window, from UTC-7, the review lists nothing, and the line shows a date the reader
  // can tell is before it (2026-08-29T23:59:59Z, though 16:59:59 on 29 Aug where it was made); and the same for one
  // authored inside the window but committed a second before it (the line's date is the committer's)
  const twin = repo(join(root, 'edge-before'), [{ files: { [`${W}/before.yml`]: 'on: push\n' }, date: '2026-08-29T16:59:59-0700', at: '2026-08-29T23:59:59Z' }]);
  const authorAfter = repo(join(root, 'author-after'), [{ files: { [`${W}/before.yml`]: 'on: push\n' }, date: '2026-08-29T23:59:59Z', author: '2026-09-15T12:00:00Z' }]);
  for (const t of [twin, authorAfter]) {
    assert.deepEqual(workflows.workflowsAddedSince(t, '2026-08-30T00:00:00Z'), []);
    assert.deepEqual(runHand(line, t).map((x) => [x.file, x.date.slice(0, 19)]), [[`${W}/before.yml`, '2026-08-29T23:59:59']], basename(t));
  }
  // a grafts file: git follows it, and no git option turns that off, so the item says the line can't be trusted where
  // there is one. Here it re-dates what the review lists: (a) the back-dated commit on top made a root; (b) the
  // workflow's commit grafted onto a 2025 commit with the same tree.
  assert.match(bullet, /`\.git\/info\/grafts`/, 'the item says a grafts file makes the line unreliable');
  const ga = repo(join(root, 'grafts-a'), [{ files: { [`${W}/ga.yml`]: 'on: push\n' }, date: '2026-10-10T00:00:00Z' }, { files: { 'README.md': 'x\n' }, date: BACK }]);
  writeFileSync(join(ga, '.git', 'info', 'grafts'), `${gitIn(ga)(['rev-parse', 'HEAD'])}\n`);
  const gb = repo(join(root, 'grafts-b'), [{ files: { [`${W}/gb.yml`]: 'on: push\n' }, date: '2026-10-10T00:00:00Z' }]), w = gitIn(gb)(['rev-parse', 'HEAD']);
  writeFileSync(join(gb, '.git', 'info', 'grafts'), `${w} ${gitIn(gb)(['commit-tree', `${w}^{tree}`, '-m', 'D'], { date: '2025-03-03T00:00:00Z' })}\n`);
  for (const [path, file] of [[ga, `${W}/ga.yml`], [gb, `${W}/gb.yml`]]) {
    assert.deepEqual(workflows.workflowsAddedSince(path, '2026-08-30T00:00:00Z').map((x) => [x.file, x.commit.split(' ')[1]]), [[file, '2026-10-10']]);
    const hand = runHand(line, path).filter((x) => x.file === file);
    assert.ok(hand.length && hand.every((x) => x.date < '2026-08-30'), `${basename(path)}: following the grafts file, the hand check lists ${file} only before the window: ${JSON.stringify(hand)}`);
  }
});
