#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The release gate (docs/RELEASING.md, "Before you cut a release"). Run it on the release commit before tagging:
//
//   npm run release-check                 # on the maintainer's machine: everything below
//   node scripts/release-check.mjs --ci   # in .github/workflows/release.yml: 4 is only "on main"
//
// It refuses (exit 1) unless:
//   1. package.json's version has a dated section at the top of CHANGELOG.md, right under an empty "Unreleased";
//   2. docs/reviews/<version>/CLASS-AUDIT.md and INDEPENDENT-REVIEW.md exist, each readable only one way: one
//      "Verdict: READY" line, the word "verdict" nowhere else, READY in capitals nowhere else, "not ready" and
//      "ready with" nowhere; one "Commit: <sha>" line, for a commit this one descends from, and nothing else labelling a
//      commit (another "Commit:", "Commit (round 1):", "Commit = ...", "Commit — ...", a table cell or heading
//      "Commit"); no HTML comment. Quote, list, heading and emphasis marks around a line don't matter, and the text is
//      read with Unicode's look-alike forms folded (NFKC) and invisible characters removed. And nothing that runs
//      (bin/, lib/, fix/, test/, scripts/, .github/, and package.json apart from its version) changed after that
//      commit, counting a rename as a deletion and an addition: the reviews are of the code being released;
//   3. the class audit names every advisory in CHANGELOG.md, so each past advisory's kind of mistake was looked for again,
//      and quotes the GATE PASSED line of the corpus gate run as root (and no GATE FAILED);
//   4. the working tree is clean, on main, at origin/main; with --ci (a tag's checkout), the tagged commit is on
//      origin/main;
//   5. every check GitHub ran on this commit passed, every page of them, including the critical-mutant gate and the
//      corpus report (gh reads them: signed in, or GH_TOKEN). With --ci the commit is GITHUB_SHA, which must be HEAD,
//      and the jobs of this workflow run itself (GITHUB_RUN_ID), still running, are left out.
//   6. the lists of planted bugs no test catches (scripts/mutants-gaps.json, scripts/mutants-allowed.json) only shrank
//      since the last release (the newest older vX.Y.Z tag in this history): each entry added since carries
//      "approved": "maintainer, YYYY-MM-DD", and each is named in the output for the maintainer to read.
// Releases 0.1.0 to 0.1.9 predate this gate: on the maintainer's machine it has nothing to check for them; with --ci (a
// tag pushed for one now) it refuses, as it does any other version older than 0.1.10, none of which was released.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CI = process.argv.includes('--ci');
const REQUIRED_CHECKS = ['critical mutants', 'corpus (report against last release)'];   // job names in .github/workflows/ci.yml
const RUNS_CODE = /^(bin|lib|fix|test|scripts|\.github)\//;   // and package.json, apart from "version" (below)
// A review is read as a person reads it, and refused if it could be read two ways. Its text: look-alike forms folded
// (a full-width colon is a colon) and invisible characters (zero-width spaces, soft hyphens) removed.
const normal = (s) => s.normalize('NFKC').replace(/\p{Cf}/gu, '');
// a line without the quote, list, heading, table and emphasis marks around it
const bare = (l) => l.replace(/^[\s>*_`#+|-]*(?:\d+[.)]\s*)?/, '').replace(/[*_`|]/g, '').trim();
// a line that labels a commit: "commit" followed by a colon, "=", a dash or "|" (after any parenthesis, as in
// "Commit (round 2):"), a table cell that says only "Commit", or a heading that does
const COMMIT_LABEL = [/\bcommit\b[\s*_`]*(?:\([^)\n]{0,40}\)[\s*_`]*)?(?:[:=|\u2012-\u2015]|\s-\s)/i,
  /\|\s*[*_`]*commit\b[\s*_`]*(?:\([^)\n]{0,40}\)[\s*_`]*)?\|/i, /^\s*#+\s*[*_`]*commit\b[\s*_`]*(?:\([^)\n]{0,40}\)[\s*_`]*)?$/i];
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const git = (...a) => execFileSync('git', ['-c', 'core.quotePath=false', ...a], { cwd: ROOT, encoding: 'utf8' }).trim();
// package.json as code: everything but the version, which is bumped after the reviews
const pkgAt = (rev) => { const p = JSON.parse(git('show', `${rev}:package.json`)); delete p.version; return JSON.stringify(p); };
const fails = [];
const ok = (msg) => console.log(`ok    ${msg}`);
const fail = (msg) => { console.log(`FAIL  ${msg}`); fails.push(msg); };

const version = JSON.parse(read('package.json')).version;
// the releases cut before this gate existed (all on npm, all tagged); every later version is checked
const BEFORE_GATE = ['0.1.0', '0.1.1', '0.1.2', '0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7', '0.1.8', '0.1.9'];
const older = (v, than) => { const a = v.split(/[.-]/).map(Number), b = than.split(/[.-]/).map(Number); for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i]; return false; };
console.log(`release gate for wardlatch ${version}${CI ? ' (--ci)' : ''}`);
if (!/^\d+\.\d+\.\d+$/.test(version)) { fail(`package.json version "${version}" is not X.Y.Z`); }
else if (older(version, '0.1.10')) {
  // Only the releases cut before the gate are let through, and only on the maintainer's machine: a tag for any of them
  // now would attest another commit under an old version, and an older version was never released at all.
  if (!CI && BEFORE_GATE.includes(version)) {
    console.log(`${version} predates the release gate (0.1.10 and later are checked): nothing to check.`);
    process.exit(0);
  }
  console.log(`FAIL  ${version} is older than the release gate (0.1.10), ${BEFORE_GATE.includes(version)
    ? 'and was released before it: a tag for it now would be a re-tag, released without reviews'
    : `and was never released (only ${BEFORE_GATE[0]} to ${BEFORE_GATE.at(-1)} were, before the gate)`}`);
  console.log('\nNOT READY: 1 problem(s). Fix each one; don\'t work around the gate.');
  process.exit(1);
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
  const text = normal(read(p)), lines = text.split('\n');
  if (text.includes('<!--')) { fail(`${p} has an HTML comment (<!--): text a reader doesn't see; take it out`); continue; }
  // the verdict: the word once in the whole file, on a line that reads "Verdict: READY"
  const said = text.match(/verdict/gi) ?? [];
  if (said.length !== 1) { fail(`${p} must have exactly one "Verdict:" line, and the word "verdict" nowhere else (found ${said.length})`); continue; }
  const vline = bare(lines.find((l) => /verdict/i.test(l)));
  const verdict = /^verdict\s*:\s*(.*)$/i.exec(vline)?.[1].trim();
  if (verdict === undefined) { fail(`${p}: the line with "verdict" on it must read "Verdict: READY" (it reads "${vline.slice(0, 80)}")`); continue; }
  if (verdict !== 'READY') { fail(`${p} has no line "Verdict: READY" (it says "${verdict.slice(0, 80)}")`); continue; }
  // and no other verdict beside it, however it is worded: READY in capitals once, "not ready" and "ready with" nowhere
  const other = (text.match(/\bREADY\b/g) ?? []).length !== 1 ? 'READY a second time' : /\bnot[\W_]*ready\b/i.exec(text)?.[0] ?? /\bready[\W_]*with\b/i.exec(text)?.[0];
  if (other) { fail(`${p} says "Verdict: READY" but also "${other.replace(/\s+/g, ' ')}": one verdict, said once (change that line; don't add another)`); continue; }
  // the commit reviewed: one line labelling a commit, "Commit: <sha>"
  const labels = lines.filter((l) => COMMIT_LABEL.some((re) => re.test(l)));
  if (labels.length !== 1) { fail(`${p} must have exactly one "Commit:" line, and no other line labelling a commit (found ${labels.length})`); continue; }
  const cline = bare(labels[0]);
  const sha = /^[0-9a-f]{7,40}$/.exec(/^commit\s*:\s*(\S+)$/i.exec(cline)?.[1] ?? '')?.[0] ?? '';
  if (!sha) { fail(`${p}: the line labelling a commit must read "Commit: <sha>" (it reads "${cline.slice(0, 80)}")`); continue; }
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

// 3b. the corpus gate, run as root with real owners before the release (docs/RELEASING.md, step 5): the class audit
// quotes its GATE PASSED line, and no GATE FAILED. A quoted line, not a proof; it makes the step one that can't be skipped
// unsaid.
{
  const said = normal(audit).split('\n').map(bare);
  if (said.some((l) => /^GATE FAILED\b/.test(l))) fail('the class audit quotes a GATE FAILED from the corpus gate: fix what it found, run it again');
  else if (!said.some((l) => /^GATE PASSED for B \S+: /.test(l))) fail('the class audit doesn\'t quote the corpus gate\'s GATE PASSED line (scripts/corpus/run.mjs ... --gate, run as root: docs/RELEASING.md, step 5)');
  else ok('the class audit quotes the corpus gate\'s GATE PASSED');
}

// 4. the machine this is released from; in the release workflow, that the tagged commit is on main (check runs from a
// pull request are attached to its head commit though they tested a merge commit: a commit never merged was never
// tested as itself)
if (CI) {
  let main = '';
  try { main = git('rev-parse', '--verify', '--quiet', 'refs/remotes/origin/main'); } catch { /* no origin/main */ }
  let onMain = false;
  if (main) try { git('merge-base', '--is-ancestor', head, main); onMain = true; } catch { /* not an ancestor */ }
  if (!main) fail('no origin/main here to tell whether the tagged commit is on main (the checkout needs fetch-depth: 0)');
  else if (!onMain) fail(`${head.slice(0, 12)} is not on main (origin/main): tag only a commit that is on main`);
  else ok(`${head.slice(0, 7)} is on main`);
} else {
  if (git('status', '--porcelain')) fail('the working tree has changes: release from a clean checkout');
  else ok('the working tree is clean');
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
  if (branch !== 'main') fail(`on branch ${branch}, not main`);
  let upstream = '';
  try { upstream = git('rev-parse', 'origin/main'); } catch { /* no origin/main */ }
  if (upstream !== head) fail('HEAD is not origin/main: push first (git fetch, if origin/main is behind), and let CI run');
  else ok('HEAD is origin/main');
}

// 5. GitHub's checks on this commit, every page of them
const checked = CI && process.env.GITHUB_SHA ? process.env.GITHUB_SHA : head;
const slug = process.env.GITHUB_REPOSITORY || 'deimos-hq/wardlatch';
// in the release workflow, its own jobs (this one among them) are still running: they are this run's, so left out
const ownRun = CI && process.env.GITHUB_RUN_ID ? `/actions/runs/${process.env.GITHUB_RUN_ID}/` : null;
if (checked !== head) fail(`GITHUB_SHA ${checked.slice(0, 12)} is not HEAD ${head.slice(0, 12)}: the checks read would be another commit's`);
else {
  let runs;
  try {
    const pages = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', `repos/${slug}/commits/${head}/check-runs?per_page=100`], { cwd: ROOT, encoding: 'utf8' }));
    runs = pages.flatMap((page) => page.check_runs ?? []).map(({ name, status, conclusion, details_url: url }) => ({ name, status, conclusion, url }));
  } catch (e) { fail(`couldn't read GitHub's checks for ${head.slice(0, 7)} (gh installed and signed in, or GH_TOKEN set?): ${String(e.message).split('\n')[0]}`); }
  if (runs && ownRun) runs = runs.filter((r) => !(typeof r.url === 'string' && r.url.includes(ownRun)));
  if (runs) {
    if (!runs.length) fail(`GitHub has no checks for ${head.slice(0, 7)} yet`);
    const bad = runs.filter((r) => r.status !== 'completed' || !['success', 'skipped', 'neutral'].includes(r.conclusion));
    if (bad.length) fail(`checks not passed on ${head.slice(0, 7)}: ${bad.map((r) => `${r.name} (${r.conclusion ?? r.status})`).join(', ')}`);
    const absent = REQUIRED_CHECKS.filter((n) => !runs.some((r) => r.name === n && r.conclusion === 'success'));
    if (absent.length) fail(`required checks didn't run or pass on ${head.slice(0, 7)}: ${absent.join(', ')}`);
    if (runs.length && !bad.length && !absent.length) ok(`all ${runs.length} GitHub checks passed on ${head.slice(0, 7)}, including ${REQUIRED_CHECKS.join(' and ')}`);
  }
}

// 6. the lists of planted bugs no test catches only shrink between releases: an entry the last release's list didn't
// have (the CI check compares one push with the one before, so an addition that failed CI once would pass after it)
// carries the maintainer's approval. Compared by file, operator, line text and occurrence, as scripts/mutate.mjs does.
const LISTS = ['scripts/mutants-gaps.json', 'scripts/mutants-allowed.json'];
const APPROVED = /^maintainer, \d{4}-\d{2}-\d{2}$/;
const entries = (k) => `${k} entr${k === 1 ? 'y' : 'ies'}`;
const last = git('tag', '--merged', head, '--list', 'v*').split('\n').filter((t) => /^v\d+\.\d+\.\d+$/.test(t) && older(t.slice(1), version))
  .sort((a, b) => (older(a.slice(1), b.slice(1)) ? 1 : -1))[0];
if (!last) fail(`no earlier release tag (older than v${version}) in this history to compare ${LISTS.join(' and ')} with (git fetch --tags)`);
else {
  const listKey = (x) => JSON.stringify([x?.file, x?.op, x?.before, x?.nth ?? 1]);
  const named = (x) => `${x?.file} [${x?.op}${(x?.nth ?? 1) > 1 ? ` #${x.nth}` : ''}] ${String(x?.before).slice(0, 70)}`;
  for (const f of LISTS) {
    let now, had;
    try {
      now = existsSync(join(ROOT, f)) ? JSON.parse(read(f)) : [];
      had = git('ls-tree', '--name-only', last, '--', f) ? JSON.parse(git('show', `${last}:${f}`)) : [];
    } catch (e) { fail(`${f}: can't be read here or at ${last} (${String(e.message).split('\n')[0]})`); continue; }
    if (!Array.isArray(now) || !Array.isArray(had)) { fail(`${f}: not a JSON array, here or at ${last}`); continue; }
    const known = new Set(had.map(listKey)), added = now.filter((x) => !known.has(listKey(x)));
    const lacking = added.filter((x) => !APPROVED.test(String(x?.approved ?? '')));
    if (lacking.length) {
      fail(`${f}: ${lacking.length} of the ${entries(added.length)} added since ${last} lack${lacking.length === 1 ? 's' : ''} the maintainer's approval `
        + `("approved": "maintainer, YYYY-MM-DD" on the entry; only the maintainer adds to this list): ${lacking.slice(0, 5).map(named).join('; ')}${lacking.length > 5 ? '; …' : ''}`);
    } else if (added.length) ok(`${f}: ${entries(added.length)} added since ${last}, each approved by the maintainer: ${added.map((x) => `${named(x)} (${x.approved})`).join('; ')}`);
    else ok(`${f}: no entry added since ${last} (${entries(now.length)} now, ${entries(had.length)} then)`);
  }
}

console.log(fails.length ? `\nNOT READY: ${fails.length} problem(s). Fix each one; don't work around the gate.` : `\nREADY to tag v${version}.`);
process.exit(fails.length ? 1 : 0);
