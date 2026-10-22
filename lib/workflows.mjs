// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// GitHub Actions review: in each local git repository under the given folders, list workflow files that were added
// since a date. Read-only: git log, with the repository's own config overridden wherever it could run a program
// (lib/git.mjs). It can't tell good from bad; it shows what to look at.
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { git, gitError } from './git.mjs';

export function reposUnder(roots, maxDepth = 4) {
  const out = [];
  const walk = (d, depth) => {
    if (depth < 0) return;
    if (existsSync(join(d, '.git'))) { out.push(d); return; }
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) if (e.isDirectory() && !['node_modules', '.venv', 'venv', 'Library', '.Trash'].includes(e.name) && !e.name.startsWith('.')) walk(join(d, e.name), depth - 1);
  };
  for (const r of roots) walk(resolve(r), maxDepth);
  return out;
}

export function workflowsAddedSince(repo, since) {
  try {
    // no signature checks (gpg.program), no external diff or textconv, and lib/git.mjs's overrides: nothing the
    // repository's own config names is run
    // --no-renames: rename detection reads file contents, which a blobless partial clone would have to fetch; a workflow
    // renamed into place is then listed as added, which is what a reviewer needs to see
    const o = git(repo, ['log', '--no-show-signature', '--no-ext-diff', '--no-textconv', '--no-renames', '--all', `--since=${since}`, '--diff-filter=A', '--name-only', '--format=@@%h %as %an', '--', '.github/workflows'], { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
    const found = []; let head = '';
    for (const line of o.split('\n')) { if (line.startsWith('@@')) head = line.slice(2); else if (line.trim()) found.push({ file: line.trim(), commit: head }); }
    // one line per file: git log runs newest first, so keep the last (earliest) commit that added it
    const byFile = new Map(); for (const f of found) byFile.set(f.file, f);
    return [...byFile.values()];
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
}
