// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Keys committed to code (the lesson of the TiDB Cloud breach): scan the files each local git repository tracks for
// high-confidence secret formats. Read-only. A finding never prints the secret: only its type, file, line and a mask.
// Current files only; history needs a dedicated scanner (gitleaks, trufflehog), which the fix text names.
import { join } from 'node:path';
import { readCapped, readHead, pathState, eachPiece } from './files.mjs';
import { git, gitError } from './git.mjs';

export const PATTERNS = [
  { type: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { type: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { type: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'Stripe live key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
];
// two searches, one after the other: a single pattern with [\s\S]* between them backtracked on every "type" line
// (3.6 s for one planted 512 KB file in 0.1.8)
const SA_TYPE = /"type"\s{0,64}:\s{0,64}"service_account"/;
const SA_KEY = /"private_key"\s{0,64}:\s{0,64}"-----BEGIN/;
// (in a piece of a larger file, only a "type" that starts in the piece's own range counts: lib/files.mjs eachPiece)
const SA_TYPES = new RegExp(SA_TYPE.source, 'g');
const isServiceAccount = (text, minStart = 0, maxStart = Infinity) => {
  for (const m of text.matchAll(SA_TYPES)) if (m.index >= minStart && m.index < maxStart) return SA_KEY.test(text.slice(m.index));
  return false;
};
// Documentation placeholders (AWS's own example key and the like) are not findings: looked for in the match and the
// 32 characters on each side, never the whole line (one "example.com" anywhere on a minified line hid every key on it).
const PLACEHOLDER = /EXAMPLE|example|XXXXXXXX|your[_-]?key|placeholder|dummy|fake/;
const NEAR = 32, MARK_LINE = 2000, MARK_NEAR = 200;
// Lines a team has already reviewed and marked (Clockford's own marker, gitleaks', detect-secrets').
const ALLOWED = /secrets-ok|gitleaks:allow|pragma:\s*allowlist secret/;

export const mask = (s) => `${s.slice(0, 4)}…(${s.length} chars)`;

/** Findings in `text`. `minStart`/`maxStart`: count only matches that start in that range (characters into `text`),
 *  for a piece of a larger file (lib/files.mjs eachPiece). */
export function scanText(text, { minStart = 0, maxStart = Infinity } = {}) {
  const out = [];
  const lines = text.split('\n');
  const around = (line, m, n) => line.slice(Math.max(0, m.index - n), m.index + m[0].length + n);
  let at = 0;   // where the current line starts in `text`
  lines.forEach((line, i) => {
    const lineAt = at; at += line.length + 1;
    for (const p of PATTERNS) for (const m of line.matchAll(p.re)) {
      if (lineAt + m.index < minStart || lineAt + m.index >= maxStart) continue;
      if (PLACEHOLDER.test(around(line, m, NEAR))) continue;
      // a reviewed-line marker counts on its own line; on a very long (minified) line only near the match. A line a
      // piece only partly holds (it goes on into the previous or next piece) is a long line.
      const partial = (i === 0 && minStart > 0) || (i === lines.length - 1 && maxStart < Infinity);
      if (ALLOWED.test(line.length <= MARK_LINE && !partial ? line : around(line, m, MARK_NEAR))) continue;
      out.push({ type: p.type, line: i + 1, masked: p.type === 'private key' ? '-----BEGIN …PRIVATE KEY-----' : mask(m[0]) });
    }
  });
  if (isServiceAccount(text, minStart, maxStart)) out.push({ type: 'Google service-account key file', line: 1, masked: '{"type": "service_account", …}' });
  return out;
}

// A text file larger than maxBytes is scanned in pieces that end at line breaks (keys are on one line), up to MAX_TEXT:
// a tracked data file of 14 MB (a fixture, a generated JSON) made 0.1.9's first cut report UNKNOWN on clean machines.
const MAX_TEXT = 512 * 1024 * 1024;
// git's own record of each tracked file: its mode says what it is, which the working tree can't (a link that points into
// a folder that can't be opened would read as an unreadable file), and its blob id says when there is nothing to scan.
const SYMLINK = '120000', GITLINK = '160000', EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391';
export function scanRepo(repo, { maxBytes = 8 * 1024 * 1024, maxText = MAX_TEXT } = {}) {
  let entries = [];
  // git with the repository's own config overridden where it could run a program (core.fsmonitor; lib/git.mjs)
  try {
    entries = git(repo, ['ls-files', '-s', '-z'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 }).split('\0').filter(Boolean)
      .map((e) => { const tab = e.indexOf('\t'); const [mode, blob] = e.slice(0, tab).split(' '); return { mode, blob, file: e.slice(tab + 1) }; });
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
  const found = [], seen = new Set();
  // a piece scan gives each match to exactly one piece (lib/files.mjs eachPiece), so nothing is found twice
  const add = (hit) => found.push(hit);
  for (const { mode, blob, file: f } of entries) {
    // a link is stored as the text of its target, not the target's contents; a submodule is another repository, which
    // is not scanned (as in 0.1.8; the CHANGELOG's known limits); a file in a merge conflict appears once per stage
    if (mode === SYMLINK || mode === GITLINK || seen.has(f)) continue;
    seen.add(f);
    const p = join(repo, f);
    const st = pathState(p);
    if (st === 'gone' || st === 'dir') continue;                        // deleted in the working tree
    // a tracked file that can't be read was not scanned: say so (0.1.8 skipped it, and a key in it read SAFE), unless
    // git records it as empty (a .gitkeep in a folder a database container has since locked)
    const unread = (why) => { if (blob !== EMPTY_BLOB) found.push({ file: f, unread: why }); };
    if (st !== 'file') { unread('not a regular file, or a folder on the way could not be opened'); continue; }
    const head = readHead(p, 8000);
    if (!head) { unread('could not be read'); continue; }
    if (head.includes(0)) continue;                                      // binary: keys in code are text
    const buf = readCapped(p, maxBytes);
    if (buf) { for (const hit of scanText(buf.toString('utf8'))) add({ file: f, ...hit }); continue; }
    const read = eachPiece(p, maxText, (text, first, range) => { for (const hit of scanText(text, range)) add({ file: f, ...hit, line: hit.line + first - 1 }); });
    if (!read) unread(`could not be read through (a text file over ${maxText / 1024 / 1024} MB, or unreadable)`);
  }
  return found;
}
