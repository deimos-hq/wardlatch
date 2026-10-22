// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// since a date. Read-only: git log, with the repository's own config overridden wherever it could run a program
// (lib/git.mjs). It can't tell good from bad; it shows what to look at.
import { listDir, pathState } from './files.mjs';
import { join, resolve } from 'node:path';
import { git, gitError } from './git.mjs';

/** Git repositories under `roots` (4 levels by default). A folder on the way that can't be opened goes into `denied`
 *  (when given): a repository inside it was not looked at, which is not the same as there being none. */
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
    for (const e of l.entries ?? []) if (e.isDirectory() && !['node_modules', '.venv', 'venv', 'Library', '.Trash'].includes(e.name) && !e.name.startsWith('.')) walk(join(d, e.name), depth - 1);
  };
  for (const r of roots) walk(resolve(r), maxDepth);
  return out;
}

export function workflowsAddedSince(repo, since) {
  try {
    // no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --diff-merges=first-parent: a workflow that only a merge commit adds (an "evil merge") is listed too; plain log shows
    // no files for merges.
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    // No --since: commit dates are the committer's to set, and a planted commit can claim to be older than the date. Every
    // addition is read, and kept when it is dated on or after `since`, or dated before one of its own parents (a commit
    // can't come before the commit it was made on: it was backdated). A planted commit dated old on an old parent still
    // can't be told from a real old one (the incident's notCovered says so).
    const opts = { timeout: 20000, maxBuffer: 64 * 1024 * 1024 };
    const when = new Map();
    for (const line of git(repo, ['log', '--all', '--diff-merges=off', '--format=%H %ct'], opts).split('\n')) {
      const [h, t] = line.split(' '); if (h) when.set(h, Number(t));
    }
    const from = Date.parse(since) / 1000;
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-merges=first-parent', '--all', '--diff-filter=A', '--name-only', '--format=@@%H %ct %P%x09%h %as %an', '--', '.github/workflows'], opts);
    const found = []; let head = '', keep = false;
    for (const line of o.split('\n')) {
      if (line.startsWith('@@')) {
        const [meta, shown] = line.slice(2).split('\t');
        const [, t, ...parents] = meta.split(' ');
        const ct = Number(t);
        const backdated = parents.some((p) => when.has(p) && ct < when.get(p));
        keep = ct >= from || backdated;
        head = backdated ? `${shown} (dated before its parent: backdated)` : shown;
      } else if (line.trim() && keep) found.push({ file: line.trim(), commit: head });
    }
    // one line per file: git log runs newest first, so keep the last (earliest) commit that added it
    const byFile = new Map(); for (const f of found) byFile.set(f.file, f);
    return [...byFile.values()];
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
