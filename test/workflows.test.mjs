// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The workflow review's window, end to end. 0.1.0 to 0.1.9 gave git the bare date "2026-09-01", which git reads as
// 1 Sep at the current time of day in the zone it runs in (the caller's TZ, which 0.1.0 to 0.1.8 passed to git; the
// machine's zone in 0.1.9, which dropped it): a workflow committed on 31 Aug, or on 1 Sep before the hour the check
// ran, read SAFE. And whatever start git got, `git log --since` stops following a line of history at the first commit
// dated before it: one back-dated commit on top hid every workflow beneath it (0.1.0 to 0.1.9, and 44bb10f and 6cac72b
// on this branch). git now gets no date at all: it lists every commit with its committer time (%ct), the review keeps
// those on or after 30 Aug 2026 00:00 UTC by comparing whole numbers, and git lists the workflow files those commits
// added. These tests: workflows just inside the window (in two zones, and at the start's own second), the advisory's
// file names, clean twins a second before it, back-dated commits on top, in between and on a merged side branch, a
// workflow added and removed on a side branch, a replace ref and a grafts file that would hide a workflow, shallow
// clones cut inside and before the window, partial clones whose remote is gone, committer times that aren't whole
// numbers, a start that isn't an explicit instant, and a git that must get no date at all.
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

test('workflows: committer time 1788048000, the start\'s own second, is in the window; 1788047999 is not', () => {
  assert.equal(START, 1788048000);
  const root = join(dir, 'edge');
  repo(join(root, 'at'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-30T00:00:00Z' }]);
  repo(join(root, 'before'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-29T23:59:59Z' }]);
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.repo && basename(x.repo), x.file, x.commit?.split(' ')[1]]), [['REVIEW', 'at', WF, '2026-08-30']], r.out);
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

test('workflows: a shallow clone cut inside the window is UNKNOWN, naming the cut; one cut before it is read as whole', () => {
  // git has no history below a shallow clone's cut. Here a workflow was added and removed again below it, and 0.1.9 and
  // 6cac72b read SAFE. A cut dated before the start leaves the window whole (as far as commit dates tell).
  const clone = (from, root, ...opts) => { mkdirSync(root, { recursive: true }); gitIn(root)(['clone', '-q', ...opts, `file://${from}`, 'app']); return join(root, 'app'); };
  const srv = repo(join(dir, 'srv-cut-in'), [{ files: { [WF]: 'on: push\n' }, date: '2026-09-05T00:00:00Z' }, { files: { [WF]: null }, date: '2026-09-06T00:00:00Z' }, later]);
  const root = join(dir, 'shallow-in'), app = clone(srv, root, '--depth', '1');
  assert.equal(readFileSync(join(app, '.git', 'shallow'), 'utf8').trim(), gitIn(app)(['rev-parse', 'HEAD']), 'the fixture: cut at its one commit');
  const r = run(root);
  assert.deepEqual(r.rows.map((x) => [x.status, x.repo]), [['UNKNOWN', app]], r.out);
  assert.match(r.rows[0].reason, /^a shallow clone: the history is cut at 10 Oct 2026 12:00 UTC \(commit [0-9a-f]{12}\), inside the window that starts 30 Aug 2026 00:00 UTC, so the commits before the cut aren't here to read \(git fetch --unshallow fetches them\)$/);
  assert.equal(r.code, 2);
  // what the cut hid: the same history, cloned whole, lists the workflow
  const whole = clone(srv, join(dir, 'shallow-whole'));
  assert.deepEqual(run(dirname(whole)).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
  // a shallow file that can't be read (here a folder) leaves it unknown where the history is cut
  mkdirSync(join(whole, '.git', 'shallow'));
  const unread = run(dirname(whole));
  assert.deepEqual([unread.rows.map((x) => x.status), unread.code], [['UNKNOWN'], 2], unread.out);
  assert.equal(unread.rows[0].reason, `its shallow file (${join(whole, '.git', 'shallow')}) could not be read, so whether its history is all here is not known`);
  // clean twin, cut before the window: a history that ends on 15 Aug, cloned at depth 1
  const old = repo(join(dir, 'srv-cut-out'), [{ files: { [WF]: 'on: push\n' }, date: '2026-08-01T00:00:00Z' }, { files: { 'a.txt': 'a\n' }, date: '2026-08-15T00:00:00Z' }]);
  const out = clone(old, join(dir, 'shallow-out'), '--depth', '1');
  assert.ok(existsSync(join(out, '.git', 'shallow')), 'the twin is shallow');
  assert.deepEqual(safe(dirname(out)), [[['SAFE', SAFE_TEXT]], 0]);
  // cut before the window, a workflow added above the cut, inside it: listed
  const mix = repo(join(dir, 'srv-cut-mix'), [{ files: { 'a.txt': '1\n' }, date: '2026-08-15T00:00:00Z' }, { files: { [WF]: 'on: push\n' }, date: '2026-09-10T00:00:00Z' }]);
  assert.deepEqual(run(dirname(clone(mix, join(dir, 'shallow-mix'), '--depth', '2'))).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
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
  assert.match(late.rows[0].reason, /^git listed a commit in a form Wardlatch can't read \("@@[0-9a-f]{40} x [0-9a-f]+ 2026-09-10 t"\), so its workflow files are not known$/);
  // clean twin: the same kind of git, rewriting nothing
  assert.deepEqual(run(root, { PATH: `${stub('git-ct-same', "'--format=%H %ct'", 's/^//')}:/usr/bin:/bin` }).rows.map((x) => [x.status, x.file]), [['REVIEW', WF]]);
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
  // each repository: where its shallow file is, every commit with its time, then the files the kept commits added
  assert.deepEqual(argvs.map((a) => a[a.indexOf('-C') + 2]), ['rev-parse', 'log', 'log', 'rev-parse', 'log', 'log'], JSON.stringify(argvs));
  for (const a of argvs) assert.deepEqual(a.filter((x) => /^--(?:since|after|until|before|max-age|min-age)/i.test(x)), [], JSON.stringify(a));
  assert.equal(argvs.filter((a) => a.includes('--all') && a.includes('--format=%H %ct')).length, 2, 'every commit, with its committer time in seconds');
  assert.equal(argvs.filter((a) => a.includes('--no-walk=unsorted') && a.includes('--stdin') && !a.includes('--all')).length, 2, 'the files of exactly the commits kept');
});

test('workflows: the window\'s start is its instant in seconds, named in UTC', () => {
  assert.deepEqual(workflows.windowStart('2026-08-30T00:00:00Z'), { seconds: START, label: '30 Aug 2026 00:00 UTC' });
  assert.equal(workflows.windowStart('2026-08-30T10:00:05Z').label, '30 Aug 2026 10:00:05 UTC');
});
