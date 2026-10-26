// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// by commits dated on or after an instant. Read-only: git rev-parse and git log, with the repository's own config
// overridden wherever it could run a program or change the history git reads (lib/git.mjs). It can't tell good from
// bad; it shows what to look at.
import { listDir, pathState, isSystemFolder, readText } from './files.mjs';
import { join, resolve } from 'node:path';
import { git, gitError, ownGitDir } from './git.mjs';

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
// of day, in the zone git runs in: up to 0.1.8 the zone of the TZ Wardlatch was started with (the machine's when TZ was
// unset), which git got with the rest of the caller's environment; in 0.1.9, which gives git no TZ, the machine's.
// All of 31 Aug and part of 1 Sep went unread, and the review read SAFE. Anything but an explicit UTC instant is now
// UNKNOWN, never a guess, and git gets no date at all: the start is compared with each commit's time here
// (workflowsAddedSince).
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Seconds since 1970 as a line names the instant: "30 Aug 2026 00:00 UTC" (the seconds only when not 0). */
const utc = (seconds) => {
  const d = new Date(seconds * 1000), two = (n) => String(n).padStart(2, '0');
  if (!Number.isFinite(d.getTime())) return `${seconds} seconds after 1 Jan 1970 UTC`;
  const s = d.getUTCSeconds();
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}${s ? `:${two(s)}` : ''} UTC`;
};

/** Seconds since 1970 as a review line shows the day: "2026-08-30", the date in UTC, the zone the SAFE line's instant
 *  is named in (an earlier cut of this fix showed git's %cs, the date in the commit's own zone: a commit at 30 Aug 00:00
 *  UTC made at UTC-7 showed 2026-08-29). `t` is %ct as git printed it; a time past what a date can hold shows as git
 *  writes a raw one, "@<seconds>". */
const utcDay = (t) => {
  const d = new Date(Number(t) * 1000), two = (n) => String(n).padStart(2, '0');
  if (!Number.isFinite(d.getTime())) return `@${t}`;
  return `${String(d.getUTCFullYear()).padStart(4, '0')}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}`;
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

/** Whether `repo`'s history is cut, as git reads it: a shallow clone, or a shallow file written into a full repository
 *  (git gives each commit the file names no parents, so nothing below it is read) → { cut: Set of the hashes the file
 *  names } when it is, {} when it isn't, or { error } when that can't be told. Cut: git says so
 *  (`rev-parse --is-shallow-repository`; an empty shallow file makes it true), or the shallow file git reads (which
 *  `rev-parse --git-path shallow` names) is there and not empty. One that is there but can't be read (git takes it as
 *  not there) is { error }. git takes each line's leading hex digits, in either case, as one commit. */
function shallowState(repo) {
  const out = String(git(repo, ['rev-parse', '--is-shallow-repository', '--git-path', 'shallow'], { timeout: 20000 }));
  const nl = out.indexOf('\n'), answer = out.slice(0, nl), file = out.slice(nl + 1).replace(/\n$/, '');
  if (nl < 0 || !['true', 'false'].includes(answer) || !file) return { error: `git didn't say whether its history is cut (git rev-parse gave ${JSON.stringify(out.slice(0, 80))}), so whether its history is all here is not known` };
  const path = resolve(repo, file), state = pathState(path);
  if (state === 'gone') return answer === 'true' ? { cut: new Set() } : {};
  const text = state === 'file' ? readText(path, 64 * 1024 * 1024) : null;
  if (text === null) return { error: `its shallow file (${path}) could not be read, so whether its history is all here is not known` };
  if (answer === 'false' && !text) return {};
  const cut = new Set();
  for (const line of text.split('\n')) {
    const hex = /^[0-9a-f]+/i.exec(line)?.[0].toLowerCase();
    if (hex) { cut.add(hex.slice(0, 40)); cut.add(hex.slice(0, 64)); }
  }
  return { cut };
}

/** Why a repository whose history is cut is UNKNOWN, naming the newest cut commit (by its committer time) and its date
 *  when git lists it. Any cut, whatever its date: a commit's date is whatever its maker wrote (a --depth 1 clone of a
 *  back-dated tip is cut below every workflow beneath it: an earlier cut of this fix read that SAFE), and a shallow
 *  file can be written into a full repository. */
function cutReason(repo, cut) {
  let newest;
  try {
    for (const line of String(git(repo, ['log', '--no-show-signature', '--all', '--format=%H %ct'], { timeout: 20000, maxBuffer: 256 * 1024 * 1024 })).split('\n')) {
      const [hash, t] = line.split(' ');
      if (cut.has(hash) && SECONDS.test(t ?? '') && (!newest || Number(t) > newest.t)) newest = { hash, t: Number(t) };
    }
  } catch { /* the cut's date is left out; the history is still cut */ }
  return `its history is cut (a shallow repository${newest ? `; the newest cut is commit ${newest.hash.slice(0, 12)}, dated ${utc(newest.t)}` : ''}), so workflows added below the cut can't be seen: run git fetch --unshallow, then run again`;
}

/** Workflow files added in `repo` by commits whose committer time is on or after `since` (an explicit UTC instant)
 *  → [{ file, commit: "<hash> <committer date in UTC> <author>" }], one per (file, commit that added it), newest
 *  first (a file added, deleted and added again is listed at each commit that added it), or { error } (UNKNOWN;
 *  `own` when the reason is the review's own, to be shown as it is: a bad start, a history that is cut (shallow), a
 *  commit time that can't be read). Added files only, as the campaign added them: a change to a workflow file that
 *  already existed isn't listed (the CHANGELOG's known limits).
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
 *  lib/git.mjs makes git read the commits as they are: a replace ref (refs/replace/) can't put another commit in a
 *  commit's place (the commit it points to is still read, as an ordinary tip of --all), and no grafts file, no
 *  commit-graph file, no lazy fetch, and paths read from the top of the folder Wardlatch found, whatever core.worktree
 *  says. A .git folder whose history git reads from elsewhere (a commondir file) is UNKNOWN. A repository whose
 *  history is cut (shallow) is UNKNOWN, wherever the cut is: what is below the cut isn't
 *  on this machine, and the cut commit's date says nothing about what is (an earlier cut of this
 *  fix read a history cut before the start as the whole window, and a --depth 1 clone of a back-dated tip read SAFE). */
export function workflowsAddedSince(repo, since) {
  const start = windowStart(since);
  if (start.error) return { error: start.error, own: true };
  try {
    const elsewhere = ownGitDir(repo);
    if (elsewhere) return { error: `${elsewhere}, so which workflow files it holds is not known`, own: true };
    const shallow = shallowState(repo);
    if (shallow.error) return { error: shallow.error, own: true };
    if (shallow.cut) return { error: cutReason(repo, shallow.cut), own: true };
    // 1. about 52 bytes a commit: 256 MB holds about 5 million (0.1.9's first cut read at most 64 MB, and past about
    // 1.3 million commits git wrote more than that: the repository was UNKNOWN)
    const all = git(repo, ['log', '--no-show-signature', '--all', '--format=%H %ct'], { timeout: 20000, maxBuffer: 256 * 1024 * 1024 });
    const kept = [];
    for (const line of all.split('\n')) {
      if (!line) continue;
      const sp = line.indexOf(' '), hash = line.slice(0, sp), t = line.slice(sp + 1);
      if (sp < 0 || !HASH.test(hash)) return { error: `git listed a commit in a form Wardlatch can't read (${JSON.stringify(line.slice(0, 80))}), so which commits are in the window is not known`, own: true };
      if (!SECONDS.test(t)) return { error: `commit ${hash.slice(0, 12)} has no committer time Wardlatch can read (git's %ct gave ${JSON.stringify(t.slice(0, 40))}), so whether it is in the window is not known`, own: true };
      if (Number(t) >= start.seconds) kept.push(hash);
    }
    if (!kept.length) return [];
    // 2. no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --diff-merges=combined: a workflow that only a merge commit adds (an "evil merge") is listed too; one a merge only
    // brings in from a branch is listed at the commit that added it, not again at every merge.
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    // the line shows the committer date, the one compared (up to 0.1.9 it showed the author date, %as), as the date in
    // UTC of its committer time (%ct), the zone the SAFE line's instant is named in (an earlier cut of this fix showed
    // %cs, the date in the commit's own zone)
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-merges=combined', '--no-walk=unsorted', '--stdin', '--diff-filter=A', '--name-only', '--format=@@%H %ct %h %an', '--', '.github/workflows'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024, input: `${kept.join('\n')}\n` });
    // `head`: the commit line for the file lines that follow it; null for a commit outside the window (none was given)
    const found = []; let head, headT;
    for (const line of o.split('\n')) {
      if (line.startsWith('@@')) {
        const [hash, t, short, ...author] = line.slice(2).split(' ');
        if (!HASH.test(hash) || !SECONDS.test(t ?? '') || !short) return { error: `git listed a commit in a form Wardlatch can't read (${JSON.stringify(line.slice(0, 80))}), so its workflow files are not known`, own: true };
        head = Number(t) >= start.seconds ? [short, utcDay(t), ...author].join(' ') : null;
        headT = Number(t);
      } else if (line.trim()) {
        if (head === undefined) return { error: `git listed a file before any commit (${JSON.stringify(line.slice(0, 80))}), so which commit added it is not known`, own: true };
        if (head !== null) found.push({ file: line.trim(), commit: head, t: headT });
      }
    }
    // one line per (file, commit that added it), newest first (by committer time; a tie keeps git's order). Up to
    // 3cff5c5 one line per file, at the earliest commit: a file added, deleted and added again in the window (Alice's
    // ci.yml on 5 Sep, Mallory's on 8 Oct) was listed once, at Alice's commit, and Mallory's wasn't shown.
    return found.sort((a, b) => b.t - a.t).map(({ file, commit }) => ({ file, commit }));
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
