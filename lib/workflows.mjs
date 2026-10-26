// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// by commits dated on or after an instant. Read-only: git rev-parse and git log, with the repository's own config
// overridden wherever it could run a program or change the history git reads (lib/git.mjs). It can't tell good from
// bad; it shows what to look at.
import { listDir, pathState, isSystemFolder, readText } from './files.mjs';
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
// of day (in the caller's zone up to 0.1.8, the machine's in 0.1.9). All of 31 Aug and part of 1 Sep went unread, and
// the review read SAFE. Anything but an explicit UTC instant is now UNKNOWN, never a guess, and git gets no date at all:
// the start is compared with each commit's time here (workflowsAddedSince).
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Seconds since 1970 as a line names the instant: "30 Aug 2026 00:00 UTC" (the seconds only when not 0). */
const utc = (seconds) => {
  const d = new Date(seconds * 1000), two = (n) => String(n).padStart(2, '0');
  if (!Number.isFinite(d.getTime())) return `${seconds} seconds after 1 Jan 1970 UTC`;
  const s = d.getUTCSeconds();
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}${s ? `:${two(s)}` : ''} UTC`;
};

/** The start of the window → { seconds, label }, or { error } when `since` is not an explicit UTC instant
 *  (YYYY-MM-DDTHH:MM:SSZ) that exists. `seconds` is what each commit's committer time is compared with; `label` is the
 *  instant as the SAFE line names it. */
export function windowStart(since) {
  const ms = typeof since === 'string' && INSTANT.test(since) ? Date.parse(since) : NaN;
  // a day or an hour that doesn't exist (30 Feb, 24:00) is refused, not rolled over into the next one
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== since.replace('Z', '.000Z')) {
    return { error: `the incident's start, ${JSON.stringify(since) ?? 'missing'}, is not an explicit UTC instant (YYYY-MM-DDTHH:MM:SSZ), so which commits to read is not known` };
  }
  return { seconds: ms / 1000, label: utc(ms / 1000) };
}

// A committer time as git prints it (%ct): the seconds since 1970, a plain whole number. git prints nothing for a
// commit whose committer line has no date it can read; that, or anything but digits, is UNKNOWN, never a commit left out.
const SECONDS = /^\d+$/;
const HASH = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** The commits a shallow clone's history is cut at (git gives each no parents), from the file git reads, which
 *  `git rev-parse --git-path shallow` names → { cut: Set of hashes } (empty when the repository isn't shallow), or
 *  { error }. git takes each line's leading hex digits, in either case, as one commit. */
function shallowCut(repo) {
  const path = resolve(repo, String(git(repo, ['rev-parse', '--git-path', 'shallow'], { timeout: 20000 })).replace(/\n$/, ''));
  const state = pathState(path);
  if (state === 'gone') return { cut: new Set() };
  const text = state === 'file' ? readText(path, 64 * 1024 * 1024) : null;
  if (text === null) return { error: `its shallow file (${path}) could not be read, so whether its history is all here is not known` };
  const cut = new Set();
  for (const line of text.split('\n')) {
    const hex = /^[0-9a-f]+/i.exec(line)?.[0].toLowerCase();
    if (hex) { cut.add(hex.slice(0, 40)); cut.add(hex.slice(0, 64)); }
  }
  return { cut };
}

/** Workflow files added in `repo` by commits whose committer time is on or after `since` (an explicit UTC instant)
 *  → [{ file, commit: "<hash> <committer date> <author>" }], or { error } (UNKNOWN; `own` when the reason is the
 *  review's own, to be shown as it is: a bad start, a shallow clone cut inside the window, a commit time that can't be
 *  read).
 *
 *  git gets no date. Up to this fix it got the start as --since, and git's walk stops following a line of history at
 *  the first commit dated before it (revision.c skips that commit before queueing its parents, unless
 *  --since-as-filter, git 2.37+, is given; Ubuntu 22.04 has 2.34.1): one back-dated commit on top of a branch hid every
 *  workflow added beneath it, however they were dated. Now:
 *  1. `git log --all --format=%H %ct`: every commit that any ref or HEAD leads to, whatever its date, with its committer
 *     time. The commits on or after the start are kept, by a comparison of whole numbers here.
 *  2. `git log --no-walk=unsorted --stdin`, given exactly the kept commits: the workflow files each one added. No walk,
 *     so no history simplification (git log -- <path> follows only the parent a merge matches, and passed by a
 *     workflow added and removed again on a merged side branch), and only the kept commits are compared with their
 *     parents (a treeless partial clone with nothing in the window needs no tree and reads SAFE, as before, instead
 *     of failing on the trees it doesn't have). Nothing kept: no second call (with no commit given, git log would
 *     read HEAD).
 *  lib/git.mjs makes git read the real history: no replace refs, no grafts, no commit-graph file, no lazy fetch. A
 *  shallow clone has no history below its cut: a cut on or after the start leaves part of the window off this machine
 *  (UNKNOWN); a cut dated before it leaves the window whole, as far as commit dates tell (the known limits). */
export function workflowsAddedSince(repo, since) {
  const start = windowStart(since);
  if (start.error) return { error: start.error, own: true };
  try {
    const shallow = shallowCut(repo);
    if (shallow.error) return { error: shallow.error, own: true };
    // 1. about 52 bytes a commit: 256 MB holds about 5 million (0.1.9's first cut read at most 64 MB, and past about
    // 1.3 million commits git wrote more than that: the repository was UNKNOWN)
    const all = git(repo, ['log', '--no-show-signature', '--all', '--format=%H %ct'], { timeout: 20000, maxBuffer: 256 * 1024 * 1024 });
    const kept = []; let cuts = 0, newest;
    for (const line of all.split('\n')) {
      if (!line) continue;
      const sp = line.indexOf(' '), hash = line.slice(0, sp), t = line.slice(sp + 1);
      if (sp < 0 || !HASH.test(hash)) return { error: `git listed a commit in a form Wardlatch can't read (${JSON.stringify(line.slice(0, 80))}), so which commits are in the window is not known`, own: true };
      if (!SECONDS.test(t)) return { error: `commit ${hash.slice(0, 12)} has no committer time Wardlatch can read (git's %ct gave ${JSON.stringify(t.slice(0, 40))}), so whether it is in the window is not known`, own: true };
      if (Number(t) < start.seconds) continue;
      kept.push(hash);
      if (shallow.cut.has(hash)) { cuts++; if (!newest || Number(t) > newest.t) newest = { hash, t: Number(t) }; }
    }
    if (newest) return { error: `a shallow clone: the history is cut at ${utc(newest.t)} (commit ${newest.hash.slice(0, 12)}${cuts > 1 ? `, and at ${cuts - 1} more commit${cuts > 2 ? 's' : ''} in the window` : ''}), inside the window that starts ${start.label}, so the commits before the cut aren't here to read (git fetch --unshallow fetches them)`, own: true };
    if (!kept.length) return [];
    // 2. no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --diff-merges=combined: a workflow that only a merge commit adds (an "evil merge") is listed too; one a merge only
    // brings in from a branch is listed at the commit that added it, not again at every merge.
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    // %cs: the committer date, the one compared (up to 0.1.9 the line showed the author date, %as)
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-merges=combined', '--no-walk=unsorted', '--stdin', '--diff-filter=A', '--name-only', '--format=@@%H %ct %h %cs %an', '--', '.github/workflows'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024, input: `${kept.join('\n')}\n` });
    // `head`: the commit line for the file lines that follow it; null for a commit outside the window (none was given)
    const found = []; let head;
    for (const line of o.split('\n')) {
      if (line.startsWith('@@')) {
        const [hash, t, ...shown] = line.slice(2).split(' ');
        if (!HASH.test(hash) || !SECONDS.test(t ?? '')) return { error: `git listed a commit in a form Wardlatch can't read (${JSON.stringify(line.slice(0, 80))}), so its workflow files are not known`, own: true };
        head = Number(t) >= start.seconds ? shown.join(' ') : null;
      } else if (line.trim()) {
        if (head === undefined) return { error: `git listed a file before any commit (${JSON.stringify(line.slice(0, 80))}), so which commit added it is not known`, own: true };
        if (head !== null) found.push({ file: line.trim(), commit: head });
      }
    }
    // one line per file: given newest first, as git log walks, so keep the last (earliest) commit that added it
    const byFile = new Map(); for (const f of found) byFile.set(f.file, f);
    return [...byFile.values()];
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
