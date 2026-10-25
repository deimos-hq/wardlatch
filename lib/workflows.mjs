// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// by commits dated on or after an instant. Read-only: git log, with the repository's own config overridden wherever it
// could run a program (lib/git.mjs). It can't tell good from bad; it shows what to look at.
import { listDir, pathState, isSystemFolder } from './files.mjs';
import { join, resolve } from 'node:path';
import { git, gitError } from './git.mjs';

/** Git repositories under `roots` (4 levels by default): the walk stops at the first repository it finds, as in 0.1.8 (a
 *  repository nested inside another one is not looked for: the CHANGELOG's known limits). A folder on the way that can't
 *  be opened goes into `denied` (when given), for bin/wardlatch.mjs gaps() to report by its owner. */
export function reposUnder(roots, maxDepth = 4, denied) {
  const out = [];
  const walk = (d, depth) => {
    if (depth < 0) return;
    // a folder that can't be entered can't be told from a repository: it is a folder that couldn't be opened
    const git = pathState(join(d, '.git'));
    if (git === 'denied') { denied?.push(d); return; }
    if (git !== 'gone') { out.push(d); return; }
    const l = listDir(d);
    if (l.denied) { denied?.push(d); return; }
    for (const e of l.entries ?? []) if (e.isDirectory() && !['node_modules', '.venv', 'venv'].includes(e.name) && !isSystemFolder(e.name, d) && !e.name.startsWith('.')) walk(join(d, e.name), depth - 1);
  };
  for (const r of roots) walk(resolve(r), maxDepth);
  return out;
}

// The window's start is an explicit UTC instant ("2026-08-30T00:00:00Z") and nothing else. Up to 0.1.9 the incident
// gave a bare date ("2026-09-01"), passed to git as it was, and git reads a bare date as that day at the current time
// of day in the machine's zone (git gets no TZ: lib/run.mjs). All of 31 Aug and part of 1 Sep went unread, and the
// review read SAFE. Anything but an explicit UTC instant is now UNKNOWN, never a guess.
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** The start of the window → { seconds, arg, label }, or { error } when `since` is not an explicit UTC instant
 *  (YYYY-MM-DDTHH:MM:SSZ) that exists. `arg` is what git's --since gets: git's raw form, "@" with the seconds since
 *  1970 and the zone +0000, which git reads as exactly that instant whatever the zone or the clock (the check in
 *  workflowsAddedSince makes sure this git does). `label` is the instant as the SAFE line names it. */
export function windowStart(since) {
  const ms = typeof since === 'string' && INSTANT.test(since) ? Date.parse(since) : NaN;
  // a day or an hour that doesn't exist (30 Feb, 24:00) is refused, not rolled over into the next one
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== since.replace('Z', '.000Z')) {
    return { error: `the incident's start, ${JSON.stringify(since) ?? 'missing'}, is not an explicit UTC instant (YYYY-MM-DDTHH:MM:SSZ), so which commits to read is not known` };
  }
  const d = new Date(ms), two = (n) => String(n).padStart(2, '0'), s = d.getUTCSeconds();
  return { seconds: ms / 1000, arg: `@${ms / 1000} +0000`, label: `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}${s ? `:${two(s)}` : ''} UTC` };
}

// What this git makes of the start, checked once per run (per PATH and start): `git rev-parse --since=<arg>` prints
// the --max-age that `git log --since=<arg>` filters with. A git that reads the start as another instant (an old or
// unusual build) makes each repository UNKNOWN, never a SAFE over a window nobody chose. rev-parse needs a
// repository, so it runs in the first one read; only a git that passed is remembered.
const readsExactly = new Set();

/** Workflow files added in `repo` by commits whose committer date is on or after `since` (an explicit UTC instant)
 *  → [{ file, commit: "<hash> <committer date> <author>" }], or { error } (UNKNOWN; `badStart` when the start
 *  itself, or this git's reading of it, is at fault rather than the repository). */
export function workflowsAddedSince(repo, since) {
  const start = windowStart(since);
  if (start.error) return { error: start.error, badStart: true };
  try {
    const key = `${process.env.PATH}\n${start.arg}`;
    if (!readsExactly.has(key)) {
      const got = String(git(repo, ['rev-parse', `--since=${start.arg}`], { timeout: 20000 })).trim();
      if (got !== `--max-age=${start.seconds}`) return { error: `this git reads the window's start, ${start.label} (--since="${start.arg}"), as ${JSON.stringify(got.slice(0, 60))}, not --max-age=${start.seconds}: an old or unusual git, so the commits it would read are not the window's`, badStart: true };
      readsExactly.add(key);
    }
    // no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --since: commits whose committer date is on or after the window's start. A commit can claim any date, so one
    // dated earlier is not seen (the CHANGELOG's known limits); reading the whole history to catch that cost too much
    // on large repositories (0.1.9's first cut lost its findings past about 1.3 million commits).
    // --diff-merges=combined: a workflow that only a merge commit adds (an "evil merge") is listed too; one a merge only
    // brings in from a branch is listed at the commit that added it, not again at every merge.
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    // %cs: the committer date, the one --since filters on (up to 0.1.9 the line showed the author date, %as)
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-merges=combined', '--all', `--since=${start.arg}`, '--diff-filter=A', '--name-only', '--format=@@%h %cs %an', '--', '.github/workflows'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 });
    const found = []; let head = '';
    for (const line of o.split('\n')) { if (line.startsWith('@@')) head = line.slice(2); else if (line.trim()) found.push({ file: line.trim(), commit: head }); }
    // one line per file: git log runs newest first, so keep the last (earliest) commit that added it
    const byFile = new Map(); for (const f of found) byFile.set(f.file, f);
    return [...byFile.values()];
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
