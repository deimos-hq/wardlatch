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
//      lower-case hex), "Verdict: READY", ```. The gate reads the verdict and the commit from that block only. The
//      rest of the file is the reviewer's, and the gate doesn't read it for meaning or render it: it refuses a review
//      that has, after the block, one of a listed set of known ways to hide or add a verdict or a commit id
//      (afterTheBlock and namesACommit, below; docs/reviews/README.md lists each). It can't prove that the page GitHub
//      shows says what the text says: the pull request into main, the maintainer's approval of the release job, and
//      the reviewers' own reading are what stand behind that. And nothing that runs (bin/, lib/, fix/, test/,
//      scripts/, .github/, and package.json apart from its version) changed after that commit, counting a rename as a
//      deletion and an addition: the reviews are of the code being released;
//   3. the class audit names every advisory in CHANGELOG.md, so each past advisory's kind of mistake was looked for again,
//      and quotes the GATE PASSED line of the corpus gate run as root on this code: the line names the SHA-256 of the
//      bin/ and lib/ it ran, which must be this commit's (and no GATE FAILED);
//   4. the working tree is clean, on main, at origin/main; with --ci (a tag's checkout), the tagged commit is on
//      origin/main;
//   5. every check GitHub ran on this commit passed, every page of them, including the critical-mutant gate and the
//      corpus report (gh reads them: signed in, or GH_TOKEN). With --ci the commit is GITHUB_SHA, which must be HEAD,
//      and the jobs of this workflow run itself (GITHUB_RUN_ID), still running, are left out.
//   6. the lists of planted bugs no test catches (scripts/mutants-gaps.json, scripts/mutants-allowed.json) only shrank
//      since the last release: the newest older vX.Y.Z tag in this history with a GitHub release (gh reads them) that
//      the gate trusts as the release workflow's (RELEASED, below), so a tag pushed by hand, one this gate refused, a
//      prerelease or a release edited after it was published is never the baseline. Each entry added since carries
//      "approved": "maintainer, YYYY-MM-DD", and each is named in the output for the maintainer to read. That is
//      deliberately stricter than CLAUDE.md, which lets an entry onto the allow list with a reason a reviewer agreed
//      to: for a release, only the maintainer adds to either list.
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
// A review after its block. The gate doesn't read it as Markdown, HTML or a browser would show it (CLAUDE.md, rule 2),
// so it can't prove the page shows what the text says. It refuses a listed set of known ways to hide or add a verdict
// or a commit id (docs/reviews/README.md lists them). Each line is read once, by linear patterns and loops, in this
// order, and the first that matches is the reason given: the patterns below, anywhere in the line; a table row with
// more cells than its header; the block's words, or "ship", again. Then git is asked about the commit ids it could see.
const AFTER_THE_BLOCK = [
  // after this one, the line is printable ASCII and tabs: no letter outside ASCII, as written or after NFKC folding (a
  // full-width letter is one), no zero-width, format or control character, no look-alike symbol, no other space
  [/[^\t\x20-\x7e]/u, (c) => `a character outside printable ASCII (${/[\p{L}\p{N}\p{P}\p{S}]/u.test(c) ? `"${c}", ` : ''}U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}), which can look like another or not show at all`],
  [/<[A-Za-z/!?]/, () => 'HTML: "<" and then a letter, "/", "!" or "?" (a tag, a comment or an autolink, which can hide text or join words)'],
  [/&[#A-Za-z]/, () => 'a character reference: "&" and then "#" or a letter (&#101; shows as e)'],
  [/\\/, () => 'a backslash (an escape: it can hide the mark after it)'],
  [/[A-Za-z0-9][*_~`]+[A-Za-z0-9]/, () => 'a mark inside a word: *, _, ~ or a backtick between letters or digits (RE*AD*Y shows as READY)'],
  [/\][ \t]*[(:]/, () => 'a link: "]" and then "(" or ":" (a link, an image or a link reference definition, which can hide text or join words)'],
  [/:[A-Za-z0-9_+-]+:/, () => 'an emoji code: letters, digits, _, + or - between two colons (GitHub shows some as letters)'],
  [/\$/, () => 'a "$" (GitHub shows text between two as math, which joins letters)'],
  [/(?:```|~~~)[ \t]*[^\s`~]/, () => 'a fence with an info string (GitHub shows some as math or a diagram)'],
  // git resolves v0.1.9-3-g0657 to the commit 0657 begins, with only 4 hex digits; refused whatever it resolves to
  [/-[0-9]+-g[0-9A-Fa-f]{4}/, () => 'a commit as git describe writes one: "-", a number, "-g" and 4 or more hex digits (v0.1.9-3-g0657 names the commit 0657 begins)'],
  // at the start of a line, after any quote marks, bullets or one-digit markers: GitHub shows 0657. as 657., and
  // numbers the items after a list's first itself, whatever is written
  [/^(?:[ \t>*+-]|[0-9][.)])*[0-9]{2,}[.)](?:[ \t]|$)/, () => 'an ordered-list marker of 2 or more digits (GitHub shows 0657. as 657., and numbers the items after the first itself: write 1. for each item)'],
];
// A table: a delimiter row (only |, :, - and spaces or tabs, with a -, after any quote marks, spaces and tabs) starts
// one, and a blank line ends it. GitHub doesn't show the cells of a row past its header's, and a header has as many as
// its delimiter row, so a row with more cells than the delimiter row is refused. Its cells are its "|"s, plus one, less
// one for a "|" at its start and one for a "|" at its end (a backslash, which could escape one, is refused above).
const QUOTED = /^[ \t>]*/;
const cells = (t) => {
  let pipes = 0, end = t.length - 1;
  for (let i = 0; i < t.length; i++) if (t[i] === '|') pipes++;
  while (end > 0 && (t[end] === ' ' || t[end] === '\t')) end--;
  return pipes + 1 - (t[0] === '|' ? 1 : 0) - (end > 0 && t[end] === '|' ? 1 : 0);
};
const delimiterRow = (t) => {
  let dash = false;
  for (const c of t) { if (c === '-') dash = true; else if (c !== '|' && c !== ':' && c !== ' ' && c !== '\t') return false; }
  return dash;
};
// The block's words said again, in any case, after a fixed fold of ASCII look-alikes (l, I, 1 and | read as i; 0 as
// o): "verdict" and "ready" anywhere, even inside another word; "commit", "commits", "ship" and "ships" as a word, its
// edges read as written (so "1ship" is one, "ownership" and "committed" are not). The fold keeps every position.
const fold = (s) => s.replace(/[lI1|]/g, 'i').replace(/0/g, 'o');
const LETTER = /[A-Za-z]/;
const blockWord = (l) => {
  const f = fold(l), re = /verdict|ready|commit|ship/gi;
  for (let m; (m = re.exec(f));) {
    let end = m.index + m[0].length;
    if (/^(?:commit|ship)$/i.test(m[0])) {
      if (f[end] === 's' || f[end] === 'S') end++;
      if (LETTER.test(l[m.index - 1] ?? '') || LETTER.test(l[end] ?? '')) continue;
    }
    return l.slice(m.index, end);
  }
  return undefined;
};
// an advisory id, as a whole word: its four words aren't read for a commit id (the class audit must name each one, and
// its groups can be hex). Nothing is taken out of the line: every other word, and the words around it, are read.
const ADVISORY = /\bGHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}\b/g;
const HEX = '0123456789abcdefABCDEF';
const isHex = (s) => { for (const c of s) if (!HEX.includes(c)) return false; return true; };
// the hex digits in a word (letters and digits between any other characters) that git could take for a commit: the
// whole word, of 4 digits or more (git's shortest abbreviation); else each run of 7 or more inside it (git's usual
// abbreviation), as git describe writes one after a "g" (v0.1.9-3-g0657ddb). Not the 4 in "sha256".
const hexIn = (w) => {
  if (w.length >= 4 && isHex(w)) return [w];
  const runs = [];
  for (let i = 0, start = -1; i <= w.length; i++) {
    const h = i < w.length && HEX.includes(w[i]);
    if (h && start < 0) start = i;
    else if (!h && start >= 0) { if (i - start >= 7) runs.push(w.slice(start, i)); start = -1; }
  }
  return runs;
};
// The first line after the block that the gate refuses, and why ({ why }); else, for git to say which name a commit,
// the hex digits in it that git could take for a commit ({ hex: Map }) and its words between spaces and tabs, exactly
// as written ({ tokens: Map }), each with the first line it is on, but the block's own commit in full (`full`).
const afterTheBlock = (lines, from, full) => {
  const hex = new Map(), tokens = new Map();
  let columns = 0;   // in a table, its header's cells; else 0
  for (let i = from; i < lines.length; i++) {
    const l = lines[i], at = `line ${i + 1}`;
    for (const [re, what] of AFTER_THE_BLOCK) {
      const m = re.exec(l);
      if (m) return { why: `${at} has ${what(m[0])}: write it plainly, in printable ASCII (docs/reviews/README.md)` };
    }
    const t = l.slice(QUOTED.exec(l)[0].length);
    if (!t.trim()) columns = 0;
    else if (columns) {
      const n = cells(t);
      if (n > columns) return { why: `${at} has a table row with ${n} cells, more than the ${columns} of its header (GitHub doesn't show the cells after the header's; a line of only |, :, - and spaces starts a table, and a blank line ends one) (docs/reviews/README.md)` };
    } else if (delimiterRow(t)) columns = cells(t);
    const word = blockWord(l);
    if (word) {
      const as = fold(word).toLowerCase() === word.toLowerCase() ? '' : ` (read as "${fold(word).toLowerCase()}")`;
      return { why: `${at} says "${word}"${as} outside the block: the block says the verdict and the commit reviewed once (change it there; don't say it again)` };
    }
    // the words of letters and digits, but the four of each advisory id: both in order, so a pass over each
    const advisories = [...l.matchAll(ADVISORY)].map((m) => [m.index, m.index + m[0].length]);
    let a = 0;
    for (const m of l.matchAll(/[0-9A-Za-z]+/g)) {
      while (a < advisories.length && advisories[a][1] <= m.index) a++;
      if (a < advisories.length && advisories[a][0] <= m.index) continue;
      for (const h of hexIn(m[0])) if (h !== full && !hex.has(h)) hex.set(h, i + 1);
    }
    for (const w of l.split(/[ \t]+/)) {
      // git takes the rest of such a word as a pattern to search the commit messages with, and one such pattern kept
      // git busy for over 20 seconds before it was stopped: refused here, never asked
      if (w.startsWith(':/') || w.includes('^{/')) return { why: `${at} has "${w.slice(0, 80)}", which git reads as a search of the commit messages (":/" at the start of a word, or "^{/" in it), to name the commit it finds: write it another way` };
      if (w && w !== full && !tokens.has(w)) tokens.set(w, i + 1);
    }
  }
  return { hex, tokens };
};
// Of these words, those git could resolve as a commit here: git cat-file, which reads a name as git rev-parse --verify
// does, is asked about each word of hex digits, as written and in lower case (by an id it begins, or a ref it names),
// and each word between spaces exactly as written (a branch, a tag, HEAD^^, @, <id>^, v0.1.9-3-g0657). A word passes
// only if git finds nothing by it, or one blob or one tree. A commit, a tag, or more than one object ("ambiguous": git
// doesn't choose, as core.disambiguate=none) is refused; when git stops on a word (@{u} with no upstream), the review
// is refused. (Not asked as <word>^{commit}: git says "missing" there for a prefix two commits share.) Returns
// [word, line] of each refused, by line.
const namesACommit = (hex, tokens) => {
  const names = [...new Set([...[...hex.keys()].flatMap((h) => [h, h.toLowerCase()]), ...tokens.keys()])];
  if (!names.length) return [];
  const input = names.map((h) => `${h}\n`).join('');
  const out = execFileSync('git', ['-c', 'core.disambiguate=none', 'cat-file', '--batch-check'], { cwd: ROOT, encoding: 'utf8', input,
    stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: input.length + 256 * names.length + 4096 }).split('\n');
  if (out.length !== names.length + 1) throw new Error(`git cat-file answered ${out.length - 1} line(s) for ${names.length} word(s)`);
  // "<word> missing", or "<id> <type> <size>" for the one object it found
  const passes = (h, line) => {
    if (line === `${h} missing`) return true;
    const [id, type, size, more] = line.split(' ');
    return more === undefined && id.length >= 40 && isHex(id) && /^\d/.test(size ?? '') && (type === 'blob' || type === 'tree');
  };
  const refused = new Set(names.filter((h, k) => !passes(h, out[k])));
  return [...[...hex].filter(([h]) => refused.has(h) || refused.has(h.toLowerCase())), ...[...tokens].filter(([w]) => refused.has(w))]
    .sort(([, a], [, b]) => a - b);
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

// 2. the two reviews, of this code. The gate reads the verdict and the commit in each from one place: the block its
// first four lines make, exactly, in ASCII (a fenced block at the very top of the file):
//   ```
//   Commit: <sha>
//   Verdict: READY
//   ```
// The rest of the file is the reviewer's, not read for meaning. The gate refuses it if it has one of the known ways
// to hide or add a verdict or a commit id that afterTheBlock and namesACommit look for; what else the page shows is
// for the people who read it.
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
  let full;
  try { full = git('rev-parse', '--verify', `${sha}^{commit}`); } catch { fail(`${p}: commit ${sha} is not in this repository`); continue; }
  const after = afterTheBlock(lines, 4, full);
  if (after.why) { fail(`${p}, ${after.why}`); continue; }
  let named;
  try { named = namesACommit(after.hex, after.tokens); } catch (e) { fail(`${p}: couldn't ask git which words in it name a commit: ${String(e.message).split('\n')[0]}`); continue; }
  if (named.length) {
    const [[first, line]] = named;
    fail(`${p}, line ${line} has "${first}", which git resolves as a commit here, or finds ambiguous${named.length > 1 ? ` (and ${named.length - 1} more)` : ''}: after the block a review names no commit but the block's, written in full (name a fix by what it changed; write a number, word, branch or tag name that git resolves another way, 0.1.9 for v0.1.9)`);
    continue;
  }
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
// The last release is one that was released: its tag has a GitHub release the gate trusts as the release workflow's
// (RELEASED): published by github-actions[bot] (the workflow publishes only after this gate passed on the tag), for a
// tag vX.Y.Z, neither a draft nor a prerelease, and either immutable (GitHub keeps an immutable release's tag and files,
// whatever is edited later) or never edited after it was published (its updated_at no later than its published_at). A field missing or of another kind is not trusted. A tag with no such release (pushed by hand,
// refused here, a prerelease, or a release edited while it could still be changed) would otherwise become the baseline
// and let the entries added before it through unapproved. For a release that isn't immutable (0.1.3 to 0.1.9, cut
// before GitHub's immutable releases were turned on), the gate takes the tag in this clone as the one released: the
// tag ruleset that lets only admins create, move or delete v* tags is what it relies on there.
const RELEASED = (r) => !!r && r.author?.login === 'github-actions[bot]' && typeof r.tag_name === 'string' && /^v\d+\.\d+\.\d+$/.test(r.tag_name)
  && r.draft === false && r.prerelease === false
  && (r.immutable === true || (typeof r.published_at === 'string' && typeof r.updated_at === 'string' && Date.parse(r.updated_at) <= Date.parse(r.published_at)));
const LISTS = ['scripts/mutants-gaps.json', 'scripts/mutants-allowed.json'];
const APPROVED = /^maintainer, \d{4}-\d{2}-\d{2}$/;
const entries = (k) => `${k} entr${k === 1 ? 'y' : 'ies'}`;
let released;
try {
  const pages = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', `repos/${slug}/releases?per_page=100`], { cwd: ROOT, encoding: 'utf8' }));
  released = new Set(pages.flat().filter(RELEASED).map((r) => r.tag_name));
} catch (e) { fail(`couldn't read GitHub's releases, to find the last release (gh installed and signed in, or GH_TOKEN set?): ${String(e.message).split('\n')[0]}`); }
// only a tag RELEASED trusts can be the last release, so only a vX.Y.Z tag
const last = released && git('tag', '--merged', head, '--list', 'v*').split('\n')
  .filter((t) => released.has(t) && older(t.slice(1), version)).sort((a, b) => (older(a.slice(1), b.slice(1)) ? 1 : -1))[0];
if (released && !last) fail(`no earlier release (a tag older than v${version} in this history, with a GitHub release the gate trusts as the release workflow's: by github-actions[bot], for a tag vX.Y.Z, neither a draft nor a prerelease, and immutable or never edited after it was published) to compare ${LISTS.join(' and ')} with (git fetch --tags)`);
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
