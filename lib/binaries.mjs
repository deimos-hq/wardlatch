// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Known-version checks: find a program on PATH, read its version, compare it with an incident's bad range or fixed
// version. Read-only: the program is only asked for its version, except where an incident says the program itself may be
// malware (`noExec`): then it is never run, and the file is checked by its hash and by the traces the malware leaves.
import { tmpdir, homedir } from 'node:os';
import { join, delimiter, isAbsolute } from 'node:path';
import { runSync } from './run.mjs';
import { pathState, listDir, realPath, hashFile, readText, isNativeProgram } from './files.mjs';
import { safe } from './report.mjs';

const MAX_PROGRAM = 512 * 1024 * 1024;   // hashing a program larger than this is not what an incident's hash list is for

/** Every regular file called `name` in the PATH folders, each once by its real path, in PATH order. Something of that
 *  name that isn't a regular file (a FIFO, a device) or can't be looked at goes into `odd` (when given). */
export function findAllOnPath(name, pathEnv = process.env.PATH ?? '', odd) {
  const out = [], seen = new Set();
  for (const d of pathEnv.split(delimiter).filter(Boolean)) {
    const p = join(d, name);
    const st = pathState(p);
    if (st === 'other' || st === 'denied') { odd?.push(p); continue; }
    if (st !== 'file') continue;
    const real = realPath(p) ?? p;
    if (!seen.has(real)) { seen.add(real); out.push(p); }
  }
  return out;
}

/**
 * Which copies of `name` on PATH may be run: the first (the one the shell runs, a version manager's shim included), and
 * every later one that is a compiled program (a distribution's /usr/bin/node behind an nvm one, which a service run by
 * its full path uses). A later copy that is a script is never run for the first time by Wardlatch (a console script that
 * happens to share the name): it goes into `notRun`. One rule for the trust check and the version checks; 0.1.9's
 * first cut ran only the first copy in one and every copy in the other.
 * → { run: paths, notRun: paths }
 */
export function copiesToRun(name, pathEnv = process.env.PATH ?? '', odd) {
  const run = [], notRun = [];
  findAllOnPath(name, pathEnv, odd).forEach((p, i) => (i === 0 || isNativeProgram(p) ? run : notRun).push(p));
  return { run, notRun };
}

/** The first regular file called `name` on PATH (the one a shell would run), or undefined. An absolute path is taken as
 *  given, if it is a regular file. */
export const findOnPath = (name, pathEnv) => (isAbsolute(name) ? (pathState(name) === 'file' ? name : undefined) : findAllOnPath(name, pathEnv)[0]);

/** A program's version, read by running it with an allowlisted environment (lib/run.mjs: GOTOOLCHAIN=local, no
 *  ambient settings), from /. '' when it can't be read. */
export function versionOf(bin, args = ['--version'], re = '(\\d+\\.\\d+\\.\\d+)') {
  try { const o = runSync(bin, args, { purpose: 'version', timeout: 8000 }); return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
  catch (e) { const o = `${e.stdout ?? ''}${e.stderr ?? ''}`; return (o.match(new RegExp(re)) ?? [])[1] ?? ''; }
}

/** A program file's MD5, or null when it isn't a regular file or can't be read. Never runs it; never blocks on a FIFO. */
export const md5File = (path) => hashFile(path, 'md5', MAX_PROGRAM);

/**
 * The temp folders a malware's leftovers can be in: $TMPDIR, /tmp, /var/tmp, and on macOS every per-user temp folder
 * (/private/var/folders/xx/yyyy/T) this user can list. Under sudo, cron or launchd TMPDIR is unset or root's, and the
 * person's own per-user folder, where a stealer they ran left its trace, was missed (0.1.0 to 0.1.8).
 */
export function tempDirs(platform = process.platform) {
  const dirs = [tmpdir(), '/tmp', '/var/tmp'];
  if (platform === 'darwin') {
    for (const a of listDir('/private/var/folders').entries ?? []) {
      for (const b of listDir(join('/private/var/folders', a.name)).entries ?? []) {
        const t = join('/private/var/folders', a.name, b.name, 'T');
        if (listDir(t).entries) dirs.push(t);   // another user's folder can't be listed and isn't ours to report
      }
    }
  }
  const out = [], seen = new Set();
  for (const d of dirs) { const r = realPath(d) ?? d; if (!seen.has(r)) { seen.add(r); out.push(d); } }
  return out;
}

/** Folders named like a malware's leftovers (`re`) in the temp folders. A temp folder that exists but can't be listed
 *  goes into `denied` (when given): not having looked is not the same as finding nothing. */
export function tmpTraces(re, dirs = tempDirs(), denied) {
  const out = [], rx = new RegExp(re);
  for (const d of dirs) {
    const l = listDir(d);
    if (l.denied) denied?.push(d);
    for (const e of l.entries ?? []) if (rx.test(e.name)) out.push(join(d, e.name));
  }
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
 * One binary rule → one result per copy of the program on PATH ([] when there is none and no trace), each
 * { status, bin, version, reason }. Every copy counts: a fixed one first on PATH used to hide a vulnerable one behind it.
 * A temp folder that can't be listed, and something of the program's name that isn't a regular file, are UNKNOWN rows.
 * rule: { binary, versionArgs?, versionRe?, fixedIn? , bad?: { from, to }, pendingUntil?,
 *         noExec?, md5Bad?: [hex], tmpTrace?: regex source, note? }
 */
export function checkBinaryAll(rule, pathEnv, { tmpDirs } = {}) {
  const out = [];
  // A trace in a temp directory means the malware already ran here, whether or not the program is still installed.
  if (rule.tmpTrace) {
    const denied = [];
    const traces = tmpTraces(rule.tmpTrace, tmpDirs, denied);
    if (traces.length) out.push({ status: 'EXPOSED', bin: traces[0], version: '', reason: `the malware ran on this machine: it left ${traces.join(', ')}` });
    for (const d of denied) out.push({ status: 'UNKNOWN', bin: d, version: '', reason: 'this temp folder could not be listed, so the malware\'s trace was not looked for there' });
  }
  const odd = [];
  // a noExec rule never runs any copy (each is hashed), so every copy is checked; otherwise lib/binaries.mjs copiesToRun()
  const { run, notRun } = rule.noExec ? { run: findAllOnPath(rule.binary, pathEnv, odd), notRun: [] } : copiesToRun(rule.binary, pathEnv, odd);
  for (const bin of run) out.push(checkOne(rule, bin));
  out.notRun = notRun;   // shown as a REVIEW row by bin/wardlatch.mjs (notRunRow), which never changes the exit code
  for (const p of odd) out.push({ status: 'UNKNOWN', bin: p, version: '', reason: 'something of this name is there, but it is not a regular file (or could not be looked at), so it was not checked and not run' });
  return out;
}

const RANK = { EXPOSED: 3, UNKNOWN: 2, REVIEW: 1 };
/** One binary rule → the worst of checkBinaryAll's results (EXPOSED, then UNKNOWN), or null when there is nothing. */
export function checkBinary(rule, pathEnv, opts) {
  const all = checkBinaryAll(rule, pathEnv, opts);
  return all.reduce((w, r) => ((RANK[r.status] ?? 0) > (RANK[w?.status] ?? -1) ? r : w), null);
}

function checkOne(rule, bin) {
  if (rule.noExec) {
    // never run a program that may itself be the malware: compare the file's hash with the published bad builds
    const h = md5File(bin);
    if (!h) return { status: 'UNKNOWN', bin, version: '', reason: 'installed, but the file could not be read; it was not run' };
    if ((rule.md5Bad ?? []).includes(h)) return { status: 'EXPOSED', bin, version: '', reason: `this file is one of the compromised builds (MD5 ${h}). Do not run it.` };
    return safe([bin], { bin, version: '', reason: rule.note ?? `not one of the compromised builds (checked by its MD5, ${h}; it was not run)` });
  }
  const v = versionOf(bin, rule.versionArgs, rule.versionRe);
  if (!v) return { status: 'UNKNOWN', bin, version: '', reason: 'installed, but its version could not be read' };
  const r = judge(rule, bin, v);
  if (rule.binary !== 'go') return r;
  // Go runs the toolchain GOTOOLCHAIN names (go1.26.5, go1.26.5+auto, go1.26.5+path) instead of itself, for every go
  // command the person runs. Wardlatch asks with GOTOOLCHAIN=local, so it reads the installed go; the pinned one is
  // read from the setting, without running go, and the worse of the two is reported.
  const pin = goToolchain();
  if (r.status === 'EXPOSED' || !pin || /^(local|auto|path)(\+|$)/.test(pin)) return r;
  const pv = (/^go(\d+\.\d+(?:\.\d+)?)(?:\+(?:auto|path))?$/.exec(pin) ?? [])[1];
  const p = pv ? judge(rule, bin, pv) : null;
  const why = `GOTOOLCHAIN selects ${pin}, which every go command runs instead of this go ${v}`;
  if (!p || p.status === 'UNKNOWN') return { status: 'UNKNOWN', bin, version: v, reason: `${why}; that toolchain was not checked` };
  if (p.status === 'EXPOSED') return { ...p, version: v, reason: `${why}: ${p.reason}` };
  return r;
}

/**
 * The person's GOTOOLCHAIN, read without running go: the environment variable, else the GOTOOLCHAIN= line of the file
 * `go env -w` writes (GOENV, else the OS's config folder). '' when unset.
 */
export function goToolchain(env = process.env, os = process.platform, home = homedir()) {
  if (env.GOTOOLCHAIN) return env.GOTOOLCHAIN.trim();
  const file = env.GOENV ? (env.GOENV === 'off' ? '' : env.GOENV)
    : os === 'darwin' ? join(home, 'Library', 'Application Support', 'go', 'env')
      : join(env.XDG_CONFIG_HOME || join(home, '.config'), 'go', 'env');
  if (!file) return '';
  // the last GOTOOLCHAIN= line wins, as Go reads the file
  // read like every other file: a FIFO or a huge file here can't hang or exhaust the run
  const text = readText(file, 1024 * 1024) ?? '';
  return (([...text.matchAll(/^GOTOOLCHAIN=(.*)$/gm)].pop() ?? [])[1] ?? '').trim();
}

/** One version against a rule → { status, bin, version, reason? }. */
function judge(rule, bin, v) {
  const r = judgeVersion(v, rule);
  return { bin, version: v, ...r, ...(r.searched ? { searched: [bin, ...r.searched] } : {}) };
}

/** A version against an incident's bad range or fixed versions → { status, reason? }. Shared by programs on PATH and
 *  versions read from a product's own files (lib/installs.mjs). */
export function judgeVersion(v, rule) {
  // Judge the leading dotted number: GitLab's "19.5.1-ee" is 19.5.1, Plex's "1.41.2.9200-c6bbc1b53" is 1.41.2.9200.
  // A version that doesn't start with one can't be judged; a pre-release of a fixed version is older than the fix.
  const m = /^v?(\d+(?:\.\d+)*)(.*)$/s.exec(String(v).trim());
  if (!m) return { status: 'UNKNOWN', reason: `version "${v}" could not be compared` };
  const n = m[1], pre = /^[-.~_+]?(rc|pre|alpha|beta|dev)/i.test(m[2]);
  const ok = (fields) => safe([`version ${v}`], fields);
  if (rule.affectedFrom && cmp(n, rule.affectedFrom) < 0) return ok({ reason: `older than the affected range (from ${rule.affectedFrom})` });
  if (rule.bad && cmp(n, rule.bad.from) >= 0 && cmp(n, rule.bad.to) <= 0) return { status: 'EXPOSED', reason: `version ${v} is in the affected range ${rule.bad.from} to ${rule.bad.to}` };
  // one fixed version for every line (Plex: 1.43.3.10861 and later are not affected)
  if (rule.minVersion) return cmp(n, rule.minVersion) > 0 || (cmp(n, rule.minVersion) === 0 && !pre) ? ok() : { status: 'EXPOSED', reason: `fixed in ${rule.minVersion}` };
  if (rule.fixedIn) {
    // A list means one fix per release line (Go: 1.26.10 and 1.27.3): compare with the fix for the same major.minor.
    const fixes = [].concat(rule.fixedIn);
    const line = (x) => String(x).split('.').slice(0, 2).join('.');
    const same = fixes.find((f) => line(f) === line(n));
    const fixed = same ? cmp(n, same) > 0 || (cmp(n, same) === 0 && !pre) : fixes.every((f) => cmp(n, f) > 0);
    if (fixed) return ok();
    // older than every line that got a fix: an end-of-life line, with no fix coming
    const eol = !same && fixes.every((f) => cmp(line(n), line(f)) < 0);
    return { status: 'EXPOSED', reason: eol ? `no fix for the ${line(n)} line (end of life): move to a supported version (${fixes.join(', ')} or later)` : `fixed in ${same ?? fixes.join(' or ')}` };
  }
  if (rule.pendingUntil) return { status: 'UNKNOWN', reason: rule.pendingNote };
  return ok();
}
