// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Known-version checks: find a program on PATH, read its version, compare it with an incident's bad range or fixed
// version. Read-only: the program is only asked for its version, except where an incident says the program itself may be
// malware (`noExec`): then it is never run, and the file is checked by its hash and by the traces the malware leaves.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';

export const findOnPath = (name, pathEnv = process.env.PATH ?? '') =>
  pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, name)).find(existsSync);

export function versionOf(bin, args = ['--version'], re = '(\\d+\\.\\d+\\.\\d+)') {
  try { const o = execFileSync(bin, args, { encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'pipe'] }); return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
  catch (e) { const o = `${e.stdout ?? ''}${e.stderr ?? ''}`; return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
}

export const md5File = (path) => createHash('md5').update(readFileSync(path)).digest('hex');

/** Folders named like a malware's leftovers (`re`) in the temp directories: $TMPDIR, /tmp and /var/tmp. */
export function tmpTraces(re, dirs = [...new Set([tmpdir(), '/tmp', '/var/tmp'])]) {
  const out = [], rx = new RegExp(re);
  for (const d of dirs) { try { for (const n of readdirSync(d)) if (rx.test(n)) out.push(join(d, n)); } catch { /* not there or not readable */ } }
  return out;
}

/** Compare dotted versions numerically: -1, 0 or 1. Each part counts by its leading number ("1-ee" is 1, Plex's
 *  "9200-c6bbc1b53" is 9200): Number() made such parts NaN, and a NaN difference was skipped as if equal. */
export function cmp(a, b) {
  const num = (s) => String(s).split('.').map((p) => parseInt(p, 10) || 0);
  const x = num(a), y = num(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] ?? 0) - (y[i] ?? 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}

/**
 * One binary rule → null when the program isn't installed (and left no trace), else { status, bin, version, reason }.
 * rule: { binary, versionArgs?, versionRe?, fixedIn? , bad?: { from, to }, pendingUntil?,
 *         noExec?, md5Bad?: [hex], tmpTrace?: regex source, note? }
 */
export function checkBinary(rule, pathEnv, { tmpDirs } = {}) {
  // A trace in a temp directory means the malware already ran here, whether or not the program is still installed.
  const traces = rule.tmpTrace ? tmpTraces(rule.tmpTrace, tmpDirs) : [];
  const bin = findOnPath(rule.binary, pathEnv);
  if (traces.length) return { status: 'EXPOSED', bin: bin ?? traces[0], version: '', reason: `the malware ran on this machine: it left ${traces.join(', ')}` };
  if (!bin) return null;
  if (rule.noExec) {
    // never run a program that may itself be the malware: compare the file's hash with the published bad builds
    let h;
    try { h = md5File(bin); } catch (e) { return { status: 'UNKNOWN', bin, version: '', reason: `installed, but the file could not be read (${e.code ?? e.message}); it was not run` }; }
    if ((rule.md5Bad ?? []).includes(h)) return { status: 'EXPOSED', bin, version: '', reason: `this file is one of the compromised builds (MD5 ${h}). Do not run it.` };
    return { status: 'SAFE', bin, version: '', reason: rule.note ?? `not one of the compromised builds (checked by its MD5, ${h}; it was not run)` };
  }
  const v = versionOf(bin, rule.versionArgs, rule.versionRe);
  if (!v) return { status: 'UNKNOWN', bin, version: '', reason: 'installed, but its version could not be read' };
  return { bin, version: v, ...judgeVersion(v, rule) };
}

/** A version against an incident's bad range or fixed versions → { status, reason? }. Shared by programs on PATH and
 *  versions read from a product's own files (lib/installs.mjs). */
export function judgeVersion(v, rule) {
  // Judge the leading dotted number: GitLab's "19.5.1-ee" is 19.5.1, Plex's "1.41.2.9200-c6bbc1b53" is 1.41.2.9200.
  // A version that doesn't start with one can't be judged; a pre-release of a fixed version is older than the fix.
  const m = /^v?(\d+(?:\.\d+)*)(.*)$/s.exec(String(v).trim());
  if (!m) return { status: 'UNKNOWN', reason: `version "${v}" could not be compared` };
  const n = m[1], pre = /^[-.~_+]?(rc|pre|alpha|beta|dev)/i.test(m[2]);
  if (rule.bad && cmp(n, rule.bad.from) >= 0 && cmp(n, rule.bad.to) <= 0) return { status: 'EXPOSED', reason: `version ${v} is in the affected range ${rule.bad.from} to ${rule.bad.to}` };
  if (rule.fixedIn) {
    // A list means one fix per release line (Go: 1.26.10 and 1.27.3): compare with the fix for the same major.minor.
    const fixes = [].concat(rule.fixedIn);
    const line = (x) => String(x).split('.').slice(0, 2).join('.');
    const same = fixes.find((f) => line(f) === line(n));
    const ok = same ? cmp(n, same) > 0 || (cmp(n, same) === 0 && !pre) : fixes.every((f) => cmp(n, f) > 0);
    if (ok) return { status: 'SAFE' };
    // older than every line that got a fix: an end-of-life line, with no fix coming
    const eol = !same && fixes.every((f) => cmp(line(n), line(f)) < 0);
    return { status: 'EXPOSED', reason: eol ? `no fix for the ${line(n)} line (end of life): move to a supported version (${fixes.join(', ')} or later)` : `fixed in ${same ?? fixes.join(' or ')}` };
  }
  if (rule.pendingUntil) return { status: 'UNKNOWN', reason: rule.pendingNote };
  return { status: 'SAFE' };
}
