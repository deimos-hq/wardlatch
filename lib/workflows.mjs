// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// since a date. Read-only: git log, with the repository's own config overridden wherever it could run a program
// (lib/git.mjs). It can't tell good from bad; it shows what to look at.
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

export function workflowsAddedSince(repo, since) {
  try {
    // no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --since, as in 0.1.8: commits dated on or after the incident's date. A commit can claim any date, so one dated
    // earlier is not seen (the CHANGELOG's known limits); reading the whole history to catch that cost too much on
    // large repositories (0.1.9's first cut lost its findings past about 1.3 million commits).
    // --diff-merges=combined: a workflow that only a merge commit adds (an "evil merge") is listed too; one a merge only
    // brings in from a branch is listed at the commit that added it, not again at every merge.
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-merges=combined', '--all', `--since=${since}`, '--diff-filter=A', '--name-only', '--format=@@%h %as %an', '--', '.github/workflows'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 });
    const found = []; let head = '';
    for (const line of o.split('\n')) { if (line.startsWith('@@')) head = line.slice(2); else if (line.trim()) found.push({ file: line.trim(), commit: head }); }
    // one line per file: git log runs newest first, so keep the last (earliest) commit that added it
    const byFile = new Map(); for (const f of found) byFile.set(f.file, f);
    return [...byFile.values()];
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
