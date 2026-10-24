#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release gate (docs/RELEASING.md, "Before you cut a release"). Run it on the release commit before tagging:
//
//   npm run release-check            # on the maintainer's machine: everything below
//   node scripts/release-check.mjs --ci   # in .github/workflows/release.yml: the checks that need only the checkout
//
// It refuses (exit 1) unless:
//   1. package.json's version has a dated section at the top of CHANGELOG.md, right under an empty "Unreleased";
//   2. docs/reviews/<version>/CLASS-AUDIT.md and INDEPENDENT-REVIEW.md exist, each with exactly one "Commit: <sha>"
//      line, for a commit this one descends from, and exactly one "Verdict:" line, which says READY (a line counts
//      however it is dressed: "> **Verdict:** NOT READY", "- Verdict: ..." and "Final verdict: ..." are verdicts too);
//      and nothing that runs (bin/, lib/, fix/, test/, scripts/, .github/, and package.json apart from its version)
//      changed after that commit, counting a rename as a deletion and an addition: the reviews are of the code being
//      released;
//   3. the class audit names every advisory in CHANGELOG.md, so each past advisory's kind of mistake was looked for again;
//   4. (not with --ci) the working tree is clean, on main, at origin/main, and every check GitHub ran on this commit
//      passed, every page of them, including the critical-mutant gate and the corpus report (gh, signed in, reads them).
// Releases up to 0.1.9 predate this gate and are not checked by it.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CI = process.argv.includes('--ci');
const REQUIRED_CHECKS = ['critical mutants', 'corpus (report against last release)'];   // job names in .github/workflows/ci.yml
const RUNS_CODE = /^(bin|lib|fix|test|scripts|\.github)\//;   // and package.json, apart from "version" (below)
// A verdict line however it is dressed (a quote, a list, bold, code), wherever "verdict:" stands on it, so a second
// verdict can't hide; a commit line at the start of a line, after any quote, list or emphasis marks.
const VERDICT = /\bverdict\b[\s*_`]*:(.*)$/i;
const COMMIT = /^[\s>*_`#+-]*(?:\d+[.)]\s*)?commit\b[\s*_`]*:(.*)$/i;
const plain = (s) => s.replace(/[*_`]/g, '').trim();
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const git = (...a) => execFileSync('git', ['-c', 'core.quotePath=false', ...a], { cwd: ROOT, encoding: 'utf8' }).trim();
// package.json as code: everything but the version, which is bumped after the reviews
const pkgAt = (rev) => { const p = JSON.parse(git('show', `${rev}:package.json`)); delete p.version; return JSON.stringify(p); };
const fails = [];
const ok = (msg) => console.log(`ok    ${msg}`);
const fail = (msg) => { console.log(`FAIL  ${msg}`); fails.push(msg); };

const version = JSON.parse(read('package.json')).version;
const older = (v, than) => { const a = v.split(/[.-]/).map(Number), b = than.split(/[.-]/).map(Number); for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i]; return false; };
console.log(`release gate for wardlatch ${version}${CI ? ' (--ci)' : ''}`);
if (!/^\d+\.\d+\.\d+$/.test(version)) { fail(`package.json version "${version}" is not X.Y.Z`); }
else if (older(version, '0.1.10')) {
  console.log(`${version} predates the release gate (0.1.10 and later are checked): nothing to check.`);
  process.exit(0);
}

// 1. the changelog
const log = read('CHANGELOG.md');
const heads = [...log.matchAll(/^## \[([^\]]+)\](.*)$/gm)].map((m) => ({ name: m[1], rest: m[2].trim(), at: m.index }));
if (heads[0]?.name !== 'Unreleased') fail('CHANGELOG.md: the first section is not "## [Unreleased]"');
else if (log.slice(heads[0].at, heads[1]?.at).split('\n').slice(1).some((l) => l.trim())) fail('CHANGELOG.md: "Unreleased" is not empty (move its lines under the release)');
if (heads[1]?.name !== version) fail(`CHANGELOG.md: the first release section is ${heads[1] ? `[${heads[1].name}]` : 'missing'}, not [${version}]`);
else if (!/^- \d{4}-\d{2}-\d{2}$/.test(heads[1].rest)) fail(`CHANGELOG.md: [${version}] has no date ("## [${version}] - YYYY-MM-DD")`);
else ok(`CHANGELOG.md has a dated [${version}] section under an empty Unreleased`);

// 2. the two reviews, of this code
const head = git('rev-parse', 'HEAD');
for (const name of ['CLASS-AUDIT.md', 'INDEPENDENT-REVIEW.md']) {
  const p = `docs/reviews/${version}/${name}`;
  if (!existsSync(join(ROOT, p))) { fail(`${p} is missing`); continue; }
  const text = read(p);
  const verdicts = text.split('\n').map((l) => VERDICT.exec(l)).filter(Boolean).map((m) => plain(m[1]));
  const commits = text.split('\n').map((l) => COMMIT.exec(l)).filter(Boolean).map((m) => plain(m[1]));
  if (verdicts.length !== 1) { fail(`${p} must have exactly one "Verdict:" line (found ${verdicts.length})`); continue; }
  if (verdicts[0] !== 'READY') { fail(`${p} has no line "Verdict: READY" (it says "${verdicts[0]}")`); continue; }
  if (commits.length !== 1) { fail(`${p} must have exactly one "Commit:" line (found ${commits.length})`); continue; }
  const sha = /^[0-9a-f]{7,40}$/.test(commits[0]) ? commits[0] : '';
  if (!sha) { fail(`${p}: "Commit: ${commits[0]}" is not a commit id`); continue; }
  let full;
  try { full = git('rev-parse', '--verify', `${sha}^{commit}`); } catch { fail(`${p}: commit ${sha} is not in this repository`); continue; }
  try { git('merge-base', '--is-ancestor', full, head); } catch { fail(`${p}: reviewed commit ${sha} is not an ancestor of HEAD`); continue; }
  // --no-renames: a file moved out of lib/ counts as lib/ changing; -z: names exactly as they are, never quoted
  const changed = execFileSync('git', ['diff', '--name-only', '--no-renames', '-z', `${full}..${head}`], { cwd: ROOT, encoding: 'utf8' })
    .split('\0').filter(Boolean).filter((f) => RUNS_CODE.test(f));
  let pkgChanged = false;
  try { pkgChanged = pkgAt(full) !== pkgAt(head); } catch { pkgChanged = true; }
  if (pkgChanged) changed.push('package.json (beyond its version)');
  if (changed.length) fail(`${p}: code changed after the reviewed commit ${sha}: ${changed.slice(0, 8).join(', ')}${changed.length > 8 ? ', …' : ''}`);
  else ok(`${p}: READY at ${sha}, and nothing that runs changed since`);
}

// 3. every past advisory's class looked for again
const audit = existsSync(join(ROOT, `docs/reviews/${version}/CLASS-AUDIT.md`)) ? read(`docs/reviews/${version}/CLASS-AUDIT.md`) : '';
// matched whatever their case, named as the changelog first writes them
const ghsaNames = new Map();
for (const g of log.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/gi) ?? []) if (!ghsaNames.has(g.toLowerCase())) ghsaNames.set(g.toLowerCase(), g);
const ghsas = [...ghsaNames.keys()], auditLower = audit.toLowerCase();
const missing = ghsas.filter((g) => !auditLower.includes(g)).map((g) => ghsaNames.get(g));
if (!ghsas.length) fail('CHANGELOG.md names no advisory: the pattern no longer matches it');
else if (missing.length) fail(`the class audit doesn't name ${missing.length} of the ${ghsas.length} advisories: ${missing.join(', ')}`);
else ok(`the class audit names all ${ghsas.length} advisories in CHANGELOG.md`);

// 4. the machine this is released from, and GitHub's checks on this commit
if (!CI) {
  if (git('status', '--porcelain')) fail('the working tree has changes: release from a clean checkout');
  else ok('the working tree is clean');
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
  if (branch !== 'main') fail(`on branch ${branch}, not main`);
  let upstream = '';
  try { upstream = git('rev-parse', 'origin/main'); } catch { /* no origin/main */ }
  if (upstream !== head) fail('HEAD is not origin/main: push first (git fetch, if origin/main is behind), and let CI run');
  else ok('HEAD is origin/main');
  let runs;
  try {
    const pages = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', `repos/deimos-hq/wardlatch/commits/${head}/check-runs?per_page=100`], { cwd: ROOT, encoding: 'utf8' }));
    runs = pages.flatMap((page) => page.check_runs ?? []).map(({ name, status, conclusion }) => ({ name, status, conclusion }));
  } catch (e) { fail(`couldn't read GitHub's checks for ${head.slice(0, 7)} (gh installed and signed in?): ${String(e.message).split('\n')[0]}`); }
  if (runs) {
    if (!runs.length) fail(`GitHub has no checks for ${head.slice(0, 7)} yet`);
    const bad = runs.filter((r) => r.status !== 'completed' || !['success', 'skipped', 'neutral'].includes(r.conclusion));
    if (bad.length) fail(`checks not passed on ${head.slice(0, 7)}: ${bad.map((r) => `${r.name} (${r.conclusion ?? r.status})`).join(', ')}`);
    const absent = REQUIRED_CHECKS.filter((n) => !runs.some((r) => r.name === n && r.conclusion === 'success'));
    if (absent.length) fail(`required checks didn't run or pass on ${head.slice(0, 7)}: ${absent.join(', ')}`);
    if (runs.length && !bad.length && !absent.length) ok(`all ${runs.length} GitHub checks passed on ${head.slice(0, 7)}, including ${REQUIRED_CHECKS.join(' and ')}`);
  }
}

console.log(fails.length ? `\nNOT READY: ${fails.length} problem(s). Fix each one; don't work around the gate.` : `\nREADY to tag v${version}.`);
process.exit(fails.length ? 1 : 0);
