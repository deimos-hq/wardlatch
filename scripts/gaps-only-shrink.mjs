#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The two lists of planted bugs no test catches only shrink: scripts/mutants-gaps.json (known test gaps) and
// scripts/mutants-allowed.json (judged equivalent). An entry comes off when a test catches it, and only the maintainer
// adds one (CLAUDE.md; to the allow list, deliberately stricter than CLAUDE.md, which takes a reason a reviewer agreed
// to). This fails (exit 1) when either list has an entry, a planted bug named by its file, operator, line text and
// occurrence (nth), that the same list at <base> doesn't have; an entry moved from one list to the other is an addition
// to the other. A reworded reason is not a new entry.
//
//   node scripts/gaps-only-shrink.mjs [<base>]    # default: where HEAD left origin/main (git merge-base HEAD origin/main)
//
// CI passes the pull request's base, or main before the push. A list that isn't at <base> is compared with the same
// list at the newest release tag (v*) in <base>'s history that has it, or, if none has it, with nothing, so every entry
// is new: deleting a list and adding a longer one fails. The maintainer's own addition fails this check on the one
// change that makes it, which is the record of it; and since a later push compares with that change, the release gate
// (scripts/release-check.mjs) checks again against the last release: every entry added since then must carry
// "approved": "maintainer, YYYY-MM-DD". Exit 2 when <base> isn't a commit, or a list isn't a JSON array.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILES = ['scripts/mutants-gaps.json', 'scripts/mutants-allowed.json'];
const die = (msg) => { console.error(msg); process.exit(2); };
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
if (process.argv.length > 3) die('usage: node scripts/gaps-only-shrink.mjs [<base commit>]');
let base = process.argv[2];
if (!base) {
  try { base = git('merge-base', 'HEAD', 'origin/main'); } catch { die('no <base> given, and no origin/main to compare with'); }
}
let sha;
try { sha = git('rev-parse', '--verify', '--quiet', `${base}^{commit}`); } catch { /* below */ }
if (!sha) die(`${base} is not a commit here`);
const at = sha.slice(0, 12);
const parse = (text, where) => {
  let l;
  try { l = JSON.parse(text); } catch (e) { die(`${where}: not JSON (${e.message})`); }
  if (!Array.isArray(l)) die(`${where}: not a JSON array`);
  return l;
};
const entries = (k) => `${k} entr${k === 1 ? 'y' : 'ies'}`;
const key = (x) => JSON.stringify([x?.file, x?.op, x?.before, x?.nth ?? 1]);
const has = (rev, file) => !!git('ls-tree', '--name-only', rev, '--', file);
// the release tags in <base>'s history, newest first
const releases = git('tag', '--merged', sha, '--list', 'v*', '--sort=-v:refname').split('\n').filter(Boolean);
let failed = false;
for (const FILE of FILES) {
  const now = parse(existsSync(join(ROOT, FILE)) ? readFileSync(join(ROOT, FILE), 'utf8') : '[]', FILE);
  // what to compare with: the list at <base>; else at the newest release that has it; else nothing
  const from = has(sha, FILE) ? sha : releases.find((t) => has(t, FILE));
  const where = from === sha ? at : from ? `${from} (not at ${at})` : `nothing (not at ${at}, nor in any release before it)`;
  const had = from ? parse(git('show', `${from}:${FILE}`), `${FILE} at ${from}`) : [];
  const known = new Set(had.map(key));
  const added = now.filter((x) => !known.has(key(x)));
  if (added.length) {
    failed = true;
    console.log(`FAIL: ${FILE} gained ${entries(added.length)} not in it at ${where}:`);
    for (const x of added) console.log(`  ${x?.file} [${x?.op}${(x?.nth ?? 1) > 1 ? ` #${x.nth}` : ''}] ${x?.before}`);
  } else console.log(`ok: ${FILE} has ${entries(now.length)}, none new since ${where} (${entries(had.length)} there)`);
}
if (failed) {
  console.log('These lists only shrink: add a test that catches each planted bug instead.\n'
    + 'Only the maintainer adds an entry, to either list: deliberately stricter than CLAUDE.md, which lets an equivalent survivor '
    + 'onto the allow list with a reason a reviewer agreed to.');
  process.exit(1);
}
