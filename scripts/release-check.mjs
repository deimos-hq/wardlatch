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
//   2. docs/reviews/<version>/CLASS-AUDIT.md and INDEPENDENT-REVIEW.md exist, each beginning with the block the gate
//      reads, its first four lines exactly, in ASCII: ```, "Commit: <sha>" (a commit this one descends from, in
//      lower-case hex), "Verdict: READY", ```. A fenced block at the top of a file is shown as it is written: nothing
//      before it can hide it. The rest of the file is the reviewer's, and the gate doesn't read it for meaning; but read
//      with Unicode's look-alike forms folded (NFKC) and invisible characters removed, it has no letter outside ASCII (so
//      no look-alike spells what follows), no "verdict" or "ready" in any case, even inside another word, no "commit" or
//      "commits" as a word, no word of 7 to 40 hex digits (a commit id, however it is labelled), and no HTML comment.
//      And nothing that runs (bin/, lib/, fix/, test/, scripts/, .github/, and package.json apart from its version)
//      changed after that commit, counting a rename as a deletion and an addition: the reviews are of the code being
//      released;
//   3. the class audit names every advisory in CHANGELOG.md, so each past advisory's kind of mistake was looked for again,
//      and quotes the GATE PASSED line of the corpus gate run as root on this code: the line names the SHA-256 of the
//      bin/ and lib/ it ran, which must be this commit's (and no GATE FAILED);
//   4. the working tree is clean, on main, at origin/main; with --ci (a tag's checkout), the tagged commit is on
//      origin/main;
//   5. every check GitHub ran on this commit passed, every page of them, including the critical-mutant gate and the
//      corpus report (gh reads them: signed in, or GH_TOKEN). With --ci the commit is GITHUB_SHA, which must be HEAD,
//      and the jobs of this workflow run itself (GITHUB_RUN_ID), still running, are left out.
//   6. the lists of planted bugs no test catches (scripts/mutants-gaps.json, scripts/mutants-allowed.json) only shrank
//      since the last release: the newest older vX.Y.Z tag in this history that the release workflow published a GitHub
//      release for (gh reads them), so a tag pushed by hand, or one this gate refused, is never the baseline. Each entry
//      added since carries "approved": "maintainer, YYYY-MM-DD", and each is named in the output for the maintainer to
//      read. That is deliberately stricter than CLAUDE.md, which lets an entry onto the allow list with a reason a
//      reviewer agreed to: for a release, only the maintainer adds to either list.
// Releases 0.1.0 to 0.1.9 predate this gate: on the maintainer's machine it has nothing to check for them; with --ci (a
// tag pushed for one now) it refuses, as it does any other version older than 0.1.10, none of which was released.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CI = process.argv.includes('--ci');
const REQUIRED_CHECKS = ['critical mutants', 'corpus (report against last release)'];   // job names in .github/workflows/ci.yml
const RUNS_CODE = /^(bin|lib|fix|test|scripts|\.github)\//;   // and package.json, apart from "version" (below)
// Text a person reads: look-alike forms folded (a full-width colon is a colon) and invisible characters (zero-width
// spaces, soft hyphens) removed.
const normal = (s) => s.normalize('NFKC').replace(/\p{Cf}/gu, '');
// a line without the quote, list, heading, table and emphasis marks around it
const bare = (l) => l.replace(/^[\s>*_`#+|-]*(?:\d+[.)]\s*)?/, '').replace(/[*_`|]/g, '').trim();
// A review after its block: the first line that could say the block's verdict or commit again, or hides text, and why
// (null if none). Each line is read once, by linear patterns: an HTML comment, a letter outside ASCII (or a combining
// mark), the block's words, a word of 7 to 40 hex digits.
const BLOCK_WORDS = /verdict|ready|(?<![a-z])commits?(?![a-z])/i;
const saidAgain = (lines, from) => {
  for (let i = from; i < lines.length; i++) {
    const l = normal(lines[i]), at = `line ${i + 1}`;
    if (l.includes('<!--')) return `${at} has an HTML comment (<!--): text a reader doesn't see; take it out`;
    const odd = /(?![A-Za-z])[\p{L}\p{M}]/u.exec(l)?.[0];
    if (odd) return `${at} has a letter outside ASCII ("${odd}", U+${odd.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}): a review is written in ASCII letters, so no look-alike spells a verdict or a commit`;
    const word = BLOCK_WORDS.exec(l)?.[0];
    if (word) return `${at} says "${word}" outside the block: the block says the verdict and the commit reviewed once (change it there; don't say it again)`;
    const id = l.split(/[^0-9A-Za-z]+/).find((w) => w.length >= 7 && w.length <= 40 && /^[0-9a-f]+$/i.test(w));
    if (id) return `${at} has "${id}", a commit id, outside the block: the block names the one commit reviewed (name a fix by what it changed)`;
  }
  return null;
};
// bin/ and lib/ as one SHA-256: each file's path and the SHA-256 of its content, a line each, in path order, .DS_Store
// left out. scripts/corpus/run.mjs prints the same of the code it ran, on its GATE PASSED line.
const sha256 = (x) => createHash('sha256').update(x).digest('hex');
const codeHash = (files) => sha256(files.filter(([f]) => f.split('/').at(-1) !== '.DS_Store')
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([f, body]) => `${f}\0${sha256(body)}\n`).join(''));
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

// 2. the two reviews, of this code. The gate reads one thing in each: the block its first four lines make, exactly, in
// ASCII (a fenced block at the top of a file is shown as written; nothing before it can hide it):
//   ```
//   Commit: <sha>
//   Verdict: READY
//   ```
// The rest of the file is the reviewer's, not read for meaning; it may not say the block's words again (saidAgain).
const FENCE = '```';
const head = git('rev-parse', 'HEAD');
for (const name of ['CLASS-AUDIT.md', 'INDEPENDENT-REVIEW.md']) {
  const p = `docs/reviews/${version}/${name}`;
  if (!existsSync(join(ROOT, p))) { fail(`${p} is missing`); continue; }
  const lines = read(p).split('\n'), [open, cline = '', vline = '', close] = lines;
  if (open !== FENCE || close !== FENCE || !cline.startsWith('Commit: ') || !vline.startsWith('Verdict: ')) {
    fail(`${p} must begin with the block the gate reads, its first four lines exactly: ${FENCE}, "Commit: <sha>", "Verdict: READY", ${FENCE} (docs/reviews/README.md)`); continue;
  }
  const verdict = vline.slice('Verdict: '.length);
  if (verdict !== 'READY') { fail(`${p}: the block's verdict is "${verdict.slice(0, 80)}", not READY`); continue; }
  const sha = /^Commit: ([0-9a-f]{7,40})$/.exec(cline)?.[1];
  if (!sha) { fail(`${p}: the block's commit must read "Commit: <sha>", in lower-case hex as git prints it (it reads "${cline.slice(0, 80)}")`); continue; }
  const again = saidAgain(lines, 4);
  if (again) { fail(`${p}, ${again}`); continue; }
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
// quotes its GATE PASSED line for this code, the SHA-256 of the bin/ and lib/ it ran being this commit's, and no GATE
// FAILED. A quoted line, not a proof; it makes the step one that can't be skipped unsaid, or done on other code.
{
  const said = normal(audit).split('\n').map(bare);
  const passed = said.map((l) => /^GATE PASSED for B \S+ \(bin\/ and lib\/ sha256 ([0-9a-f]{64})\): /.exec(l)?.[1]).filter(Boolean);
  const code = codeHash(execFileSync('git', ['ls-tree', '-r', '-z', head, '--', 'bin', 'lib'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(Boolean).map((e) => {
    const tab = e.indexOf('\t'), [, type, oid] = e.slice(0, tab).split(' ');
    return [e.slice(tab + 1), type === 'blob' ? execFileSync('git', ['cat-file', 'blob', oid], { cwd: ROOT }) : `${type} ${oid}`];
  }));
  if (said.some((l) => /^GATE FAILED\b/.test(l))) fail('the class audit quotes a GATE FAILED from the corpus gate: fix what it found, run it again');
  else if (!passed.length) fail('the class audit doesn\'t quote the corpus gate\'s GATE PASSED line, "GATE PASSED for B <version> (bin/ and lib/ sha256 <hash>): ..." (scripts/corpus/run.mjs ... --gate, run as root: docs/RELEASING.md, step 5)');
  else if (!passed.includes(code)) fail(`the class audit quotes a GATE PASSED for other code (bin/ and lib/ sha256 ${passed.map((h) => h.slice(0, 12)).join(', ')}), not for this commit's (${code.slice(0, 12)}): run the corpus gate on this code, and quote its line`);
  else ok(`the class audit quotes the corpus gate's GATE PASSED for this code (bin/ and lib/ sha256 ${code.slice(0, 12)})`);
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
// The last release is one that was released: its tag has a GitHub release, not a draft, that the release workflow
// published (github-actions[bot]; it publishes only after this gate passed on the tag). A tag with none, pushed by hand
// or refused here, would otherwise become the baseline and let the entries added before it through unapproved.
const LISTS = ['scripts/mutants-gaps.json', 'scripts/mutants-allowed.json'];
const APPROVED = /^maintainer, \d{4}-\d{2}-\d{2}$/;
const entries = (k) => `${k} entr${k === 1 ? 'y' : 'ies'}`;
let released;
try {
  const pages = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', `repos/${slug}/releases?per_page=100`], { cwd: ROOT, encoding: 'utf8' }));
  released = new Set(pages.flat().filter((r) => r && r.draft === false && r.author?.login === 'github-actions[bot]').map((r) => r.tag_name));
} catch (e) { fail(`couldn't read GitHub's releases, to find the last release (gh installed and signed in, or GH_TOKEN set?): ${String(e.message).split('\n')[0]}`); }
const last = released && git('tag', '--merged', head, '--list', 'v*').split('\n')
  .filter((t) => /^v\d+\.\d+\.\d+$/.test(t) && older(t.slice(1), version) && released.has(t)).sort((a, b) => (older(a.slice(1), b.slice(1)) ? 1 : -1))[0];
if (released && !last) fail(`no earlier release (a tag older than v${version} in this history, with a GitHub release the release workflow published) to compare ${LISTS.join(' and ')} with (git fetch --tags)`);
else if (last) {
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
        + `("approved": "maintainer, YYYY-MM-DD" on the entry; for a release only the maintainer adds to either list, deliberately stricter than CLAUDE.md): ${lacking.slice(0, 5).map(named).join('; ')}${lacking.length > 5 ? '; …' : ''}`);
    } else if (added.length) ok(`${f}: ${entries(added.length)} added since ${last}, each approved by the maintainer: ${added.map((x) => `${named(x)} (${x.approved})`).join('; ')}`);
    else ok(`${f}: no entry added since ${last} (${entries(now.length)} now, ${entries(had.length)} then)`);
  }
}

console.log(fails.length ? `\nNOT READY: ${fails.length} problem(s). Fix each one; don't work around the gate.` : `\nREADY to tag v${version}.`);
process.exit(fails.length ? 1 : 0);
