// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Keys committed to code (the lesson of the TiDB Cloud breach): scan the files each local git repository tracks for
// high-confidence secret formats. Read-only. A finding never prints the secret: only its type, file, line and a mask.
// Current files only; history needs a dedicated scanner (gitleaks, trufflehog), which the fix text names.
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { readCapped } from './files.mjs';

export const PATTERNS = [
  { type: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { type: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { type: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'Stripe live key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
];
const SERVICE_ACCOUNT = /"type"\s*:\s*"service_account"[\s\S]*"private_key"\s*:\s*"-----BEGIN/;
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
  if (SERVICE_ACCOUNT.test(text)) out.push({ type: 'Google service-account key file', line: 1, masked: '{"type": "service_account", …}' });
  return out;
}

export function scanRepo(repo, { maxBytes = 512 * 1024 } = {}) {
  let files = [];
  try { files = execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8', timeout: 20000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean); }
  catch { return []; }
  const found = [];
  for (const f of files) {
    const p = join(repo, f);
    const buf = readCapped(p, maxBytes);                                    // null: not a file, too big or unreadable
    if (!buf || buf.subarray(0, 8000).includes(0)) continue;               // skipped, or binary
    for (const hit of scanText(buf.toString('utf8'))) found.push({ file: f, ...hit });
  }
  return found;
}
