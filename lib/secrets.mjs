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
const isServiceAccount = (text) => { const m = SA_TYPE.exec(text); return !!m && SA_KEY.test(text.slice(m.index)); };
// Documentation placeholders (AWS's own example key and the like) are not findings.
const PLACEHOLDER = /EXAMPLE|example|XXXXXXXX|your[_-]?key|placeholder|dummy|fake/;
// Lines a team has already reviewed and marked (Clockford's own marker, gitleaks', detect-secrets').
const ALLOWED = /secrets-ok|gitleaks:allow|pragma:\s*allowlist secret/;

export const mask = (s) => `${s.slice(0, 4)}…(${s.length} chars)`;

export function scanText(text) {
  const out = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    for (const p of PATTERNS) for (const m of line.matchAll(p.re)) {
      if (PLACEHOLDER.test(line) || ALLOWED.test(line)) continue;
      out.push({ type: p.type, line: i + 1, masked: p.type === 'private key' ? '-----BEGIN …PRIVATE KEY-----' : mask(m[0]) });
    }
  });
  if (isServiceAccount(text)) out.push({ type: 'Google service-account key file', line: 1, masked: '{"type": "service_account", …}' });
  return out;
}

// A text file larger than maxBytes is scanned in pieces that end at line breaks (keys are on one line), up to MAX_TEXT:
// a tracked data file of 14 MB (a fixture, a generated JSON) made 0.1.9's first cut report UNKNOWN on clean machines.
const MAX_TEXT = 512 * 1024 * 1024;
export function scanRepo(repo, { maxBytes = 8 * 1024 * 1024, maxText = MAX_TEXT } = {}) {
  let files = [];
  // git with the repository's own config overridden where it could run a program (core.fsmonitor; lib/git.mjs)
  try { files = git(repo, ['ls-files', '-z'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 }).split('\0').filter(Boolean); }
  catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
  const found = [];
  for (const f of files) {
    const p = join(repo, f);
    const st = pathState(p);
    if (st === 'gone' || st === 'dir') continue;                        // deleted in the working tree, or a submodule
    // a tracked file that can't be read was not scanned: say so (0.1.8 skipped it, and a key in it read SAFE)
    if (st !== 'file') { found.push({ file: f, unread: 'not a regular file, or a folder on the way could not be opened' }); continue; }
    const head = readHead(p, 8000);
    if (!head) { found.push({ file: f, unread: 'could not be read' }); continue; }
    if (head.includes(0)) continue;                                      // binary: keys in code are text
    const buf = readCapped(p, maxBytes);
    if (buf) { for (const hit of scanText(buf.toString('utf8'))) found.push({ file: f, ...hit }); continue; }
    const read = eachPiece(p, maxText, (text, first) => { for (const hit of scanText(text)) found.push({ file: f, ...hit, line: hit.line + first - 1 }); });
    if (!read) found.push({ file: f, unread: `could not be read through (a text file over ${maxText / 1024 / 1024} MB, or unreadable)` });
  }
  return found;
}
