// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Known-version checks: find a program on PATH, read its version, compare it with an incident's bad range or fixed
// version. Read-only: the program is only asked for its version.
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, delimiter } from 'node:path';

export const findOnPath = (name, pathEnv = process.env.PATH ?? '') =>
  pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, name)).find(existsSync);

export function versionOf(bin, args = ['--version'], re = '(\\d+\\.\\d+\\.\\d+)') {
  try { const o = execFileSync(bin, args, { encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'pipe'] }); return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
  catch (e) { const o = `${e.stdout ?? ''}${e.stderr ?? ''}`; return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
}

/** Compare dotted versions numerically: -1, 0 or 1. */
export function cmp(a, b) {
  const x = String(a).split('.').map(Number), y = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] ?? 0) - (y[i] ?? 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}

/**
 * One binary rule → null when the program isn't installed, else { status, bin, version, reason }.
 * rule: { binary, versionArgs?, versionRe?, fixedIn? , bad?: { from, to }, pendingUntil? }
 */
export function checkBinary(rule, pathEnv) {
  const bin = findOnPath(rule.binary, pathEnv);
  if (!bin) return null;
  const v = versionOf(bin, rule.versionArgs, rule.versionRe);
  if (!v) return { status: 'UNKNOWN', bin, version: '', reason: 'installed, but its version could not be read' };
  if (rule.bad && cmp(v, rule.bad.from) >= 0 && cmp(v, rule.bad.to) <= 0) return { status: 'EXPOSED', bin, version: v, reason: `version ${v} is in the affected range ${rule.bad.from} to ${rule.bad.to}` };
  if (rule.fixedIn) {
    // A list means one fix per release line (Go: 1.26.10 and 1.27.3): compare with the fix for the same major.minor.
    const fixes = [].concat(rule.fixedIn);
    const line = (x) => String(x).split('.').slice(0, 2).join('.');
    const same = fixes.find((f) => line(f) === line(v));
    const ok = same ? cmp(v, same) >= 0 : fixes.every((f) => cmp(v, f) > 0);
    if (ok) return { status: 'SAFE', bin, version: v };
    // older than every line that got a fix: an end-of-life line, with no fix coming
    const eol = !same && fixes.every((f) => cmp(line(v), line(f)) < 0);
    return { status: 'EXPOSED', bin, version: v, reason: eol ? `no fix for the ${line(v)} line (end of life): move to a supported version (${fixes.join(', ')} or later)` : `fixed in ${same ?? fixes.join(' or ')}` };
  }
  if (rule.pendingUntil) return { status: 'UNKNOWN', bin, version: v, reason: rule.pendingNote };
  return { status: 'SAFE', bin, version: v };
}
