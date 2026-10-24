#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The known-test-gaps list, scripts/mutants-gaps.json, only shrinks: a gap comes off it when a test catches it, and only
// the maintainer adds one (CLAUDE.md). This fails (exit 1) when the list has an entry, a planted bug named by its file,
// operator, line text and occurrence (nth), that the list at <base> doesn't have. A reworded reason is not a new entry.
//
//   node scripts/gaps-only-shrink.mjs [<base>]    # default: where HEAD left origin/main (git merge-base HEAD origin/main)
//
// CI passes the pull request's base, or main before the push. A list that isn't at <base> at all is being introduced:
// that is said, and passes (a change that deletes the list fails the critical-mutant gate, every gap then a survivor).
// Exit 2 when <base> isn't a commit, or either list isn't a JSON array. The maintainer's own addition fails this check
// on the one change that makes it, which is the record of it.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'scripts/mutants-gaps.json';
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
const now = parse(existsSync(join(ROOT, FILE)) ? readFileSync(join(ROOT, FILE), 'utf8') : '[]', FILE);
const entries = (k) => `${k} entr${k === 1 ? 'y' : 'ies'}`;
if (!git('ls-tree', '--name-only', sha, '--', FILE)) {
  console.log(`${FILE} is not at ${at}: this change introduces it (${entries(now.length)})`);
  process.exit(0);
}
const key = (x) => JSON.stringify([x?.file, x?.op, x?.before, x?.nth ?? 1]);
const had = parse(git('show', `${sha}:${FILE}`), `${FILE} at ${at}`);
const known = new Set(had.map(key));
const added = now.filter((x) => !known.has(key(x)));
if (added.length) {
  console.log(`FAIL: ${FILE} gained ${entries(added.length)} not in it at ${at}:`);
  for (const x of added) console.log(`  ${x?.file} [${x?.op}${(x?.nth ?? 1) > 1 ? ` #${x.nth}` : ''}] ${x?.before}`);
  console.log('The list only shrinks: add a test that catches the planted bug instead. Only the maintainer adds an entry.');
  process.exit(1);
}
console.log(`ok: ${FILE} has ${entries(now.length)}, none new since ${at} (${entries(had.length)} there)`);
