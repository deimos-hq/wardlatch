// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Known-version checks: find a program on PATH, read its version, compare it with an incident's bad range or fixed
// version. Read-only: the program is only asked for its version, except where an incident says the program itself may be
// malware (`noExec`): then it is never run, and the file is checked by its hash and by the traces the malware leaves.
import { tmpdir, homedir } from 'node:os';
import { join, delimiter, isAbsolute } from 'node:path';
import { runSync } from './run.mjs';
import { pathState, listDir, realPath, hashFile, readText, isNativeProgram } from './files.mjs';
import { safe, saw } from './report.mjs';

const MAX_PROGRAM = 512 * 1024 * 1024;   // hashing a program larger than this is not what an incident's hash list is for

/** Every regular file called `name` in the PATH folders, each once by its real path, in PATH order. Something of that
 *  name that isn't a regular file (a FIFO, a device) or can't be looked at goes into `odd` (when given). The folders
 *  that are there, and so were looked in, go into `listed` (when given): the receipt behind "not found on PATH". */
export function findAllOnPath(name, pathEnv = process.env.PATH ?? '', odd, listed) {
  const out = [], seen = new Set();
  for (const d of pathEnv.split(delimiter).filter(Boolean)) {
    if (pathState(d) === 'dir') listed?.push(d);
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
export function copiesToRun(name, pathEnv = process.env.PATH ?? '', odd, listed) {
  const run = [], notRun = [];
  findAllOnPath(name, pathEnv, odd, listed).forEach((p, i) => (i === 0 || isNativeProgram(p) ? run : notRun).push(p));
  return { run, notRun };
}

/** The folders a pattern names: each `*` in a segment matches one folder name (no `**`). A folder a `*` would be matched
 *  in that is there but can't be listed goes into `odd` (UNKNOWN): an admin can close /opt/cpanel, and a PHP below it
 *  must not read as absent; one that isn't there contributes nothing. */
function dirsMatching(pattern, odd) {
  let out = [pattern.startsWith('/') ? '/' : ''];
  for (const part of pattern.split('/').filter(Boolean)) {
    if (!part.includes('*')) { out = out.map((d) => join(d, part)); continue; }
    const rx = new RegExp(`^${part.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
    out = out.flatMap((d) => { const l = listDir(d); if (l.denied) odd?.push(d); return (l.entries ?? []).filter((e) => rx.test(e.name)).map((e) => join(d, e.name)); });
  }
  return out;
}

/**
 * The copies to run of every program whose name matches `names` (a pattern), on PATH and then in `extraDirs` (folders,
 * each `*` matching one folder name: Homebrew's php@8.1 keg, Remi's /opt/remi/php81, cPanel's ea-php81, Plesk's
 * /opt/plesk/php/8.1): for each name, lib/binaries.mjs copiesToRun()'s rule (the first copy of a name, and later ones
 * that are compiled programs). A file reached by two names (php pointing at php8.3 through /etc/alternatives) is counted
 * once, under the name met first; each name counts as met either way. For PHP on a server with several versions, where
 * /usr/bin/php is one of them and php8.1 and php-fpm8.1 serve the sites: 0.1.0 to 0.1.9's first cuts checked only
 * `php`, and an old php8.1 read SAFE. A folder that can't be listed is still asked for `exact` by name (a folder that
 * can be entered but not listed); one that can't be entered either makes that name an `odd` entry (UNKNOWN), as for a
 * plain name. The folders whose entries were read go into `listed` (when given): the receipt behind "not found".
 * → { run: paths, notRun: paths }
 */
export function copiesMatching(names, pathEnv = process.env.PATH ?? '', extraDirs = [], odd, exact, listed) {
  const re = new RegExp(names), run = [], notRun = [], realSeen = new Set(), nameSeen = new Set();
  const dirs = [...new Set([...pathEnv.split(delimiter).filter(Boolean), ...extraDirs.flatMap((x) => dirsMatching(x, odd))])];
  for (const d of dirs) {
    const l = listDir(d);
    if (l.entries) listed?.push(d);
    const found = l.entries ? l.entries.map((e) => e.name).filter((n) => re.test(n)).sort() : l.denied && exact ? [exact] : [];
    for (const name of found) {
      const p = join(d, name), st = pathState(p);
      if (st === 'other' || st === 'denied') { odd?.push(p); continue; }
      if (st !== 'file') continue;
      const first = !nameSeen.has(name);
      nameSeen.add(name);
      const real = realPath(p) ?? p;
      if (realSeen.has(real)) continue;
      realSeen.add(real);
      (first || isNativeProgram(p) ? run : notRun).push(p);
    }
  }
  return { run, notRun };
}

/** The first regular file called `name` on PATH (the one a shell would run), or undefined. An absolute path is taken as
 *  given, if it is a regular file. */
export const findOnPath = (name, pathEnv) => (isAbsolute(name) ? (pathState(name) === 'file' ? name : undefined) : findAllOnPath(name, pathEnv)[0]);

/** A program's version, read by running it with an allowlisted environment (lib/run.mjs: GOTOOLCHAIN=local, no
 *  ambient settings), from /. '' when it can't be read. */
export function versionOf(bin, args = ['--version'], re = '(\\d+\\.\\d+\\.\\d+)') {
  // Prefer a match at the START OF A LINE, which is where a program's own banner lives, and fall back to anywhere.
  // Taking the first match anywhere let any earlier line decide the verdict: a wrapper or shim printing
  // "policy: this host is checked against PHP 8.5.12" before the real "PHP 8.3.6 (cli)" banner made a vulnerable
  // 8.3.6 report as the fixed 8.5.12 (audit AUDIT-18). checkVersionFiles already reads its patterns with 'm' for the
  // same reason; this makes the two agree. A hostile wrapper that prints a false banner at the start of a line can
  // still mislead — nothing short of not running it can prevent that — but an ordinary chatty one no longer does.
  const pick = (o) => (o.match(new RegExp(`^${re}`, 'm')) ?? o.match(new RegExp(re)) ?? [])[1] ?? '';
  try { return pick(runSync(bin, args, { purpose: 'version', timeout: 8000 })); }
  catch (e) { return pick(`${e.stdout ?? ''}${e.stderr ?? ''}`); }
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
export function checkBinaryAll(rule, pathEnv, { tmpDirs, listed } = {}) {
  const out = [];
  // The temp directories this run actually LISTED. A rule with a tmpTrace says, in its all-clear, that no trace
  // was found in them -- so they are part of what the row rests on and belong in its receipt. Until 29 Oct 2026
  // the receipt named only the program, and the second half of that sentence could not be audited (AUDIT-12).
  // Directories that could not be listed are NOT added: each is already its own UNKNOWN row, and a receipt names
  // what was opened, never what was attempted.
  let searchedTmp = [];
  // A trace in a temp directory means the malware already ran here, whether or not the program is still installed.
  if (rule.tmpTrace) {
    const denied = [];
    const traces = tmpTraces(rule.tmpTrace, tmpDirs, denied);
    searchedTmp = (tmpDirs ?? []).filter((d) => !denied.includes(d));
    if (traces.length) out.push({ status: 'EXPOSED', bin: traces[0], version: '', reason: `the malware ran on this machine: it left ${traces.join(', ')}` });
    for (const d of denied) out.push({ status: 'UNKNOWN', bin: d, version: '', reason: 'this temp folder could not be listed, so the malware\'s trace was not looked for there' });
  }
  const odd = [];
  // a noExec rule never runs any copy (each is hashed), so every copy is checked; otherwise lib/binaries.mjs copiesToRun()
  // `binaryNames`: a rule whose program also comes under other names (php8.1, php-fpm8.1), looked for on PATH and in
  // `extraDirs` as well (lib/binaries.mjs copiesMatching)
  const { run, notRun } = rule.noExec ? { run: findAllOnPath(rule.binary, pathEnv, odd, listed), notRun: [] }
    : rule.binaryNames ? copiesMatching(rule.binaryNames, pathEnv, rule.extraDirs ?? [], odd, rule.binary, listed) : copiesToRun(rule.binary, pathEnv, odd, listed);
  for (const bin of run) out.push(checkOne(rule, bin, searchedTmp));
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

function checkOne(rule, bin, searchedTmp = []) {
  if (rule.noExec) {
    // never run a program that may itself be the malware: compare the file's hash with the published bad builds
    const h = md5File(bin);
    if (!h) return { status: 'UNKNOWN', bin, version: '', reason: 'installed, but the file could not be read; it was not run' };
    if ((rule.md5Bad ?? []).includes(h)) return { status: 'EXPOSED', bin, version: '', reason: `this file is one of the compromised builds (MD5 ${h}). Do not run it.` };
    return safe([bin, ...searchedTmp], { bin, version: '', reason: rule.note ?? `not one of the compromised builds (checked by its MD5, ${h}; it was not run)` });
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
  // A Debian/RPM epoch ("1:19.5.0-ee") is stripped before anything reads the version. Without this the regex below
  // captured "1" and nothing else: GitLab 19.5.0 packaged with an epoch compared as version 1, fell below
  // affectedFrom 7.0, and a vulnerable install read SAFE with the receipt "version 1:19.5.0-ee", which reads as though
  // the version had been understood (audit AUDIT-16). The epoch orders packages within a distribution and says nothing
  // about upstream; every affectedFrom, bad range, minVersion and fixedIn in the incident files is an upstream version,
  // so the upstream part is what must be compared.
  const m = /^v?(\d+(?:\.\d+)*)(.*)$/s.exec(String(v).trim().replace(/^\d+:/, ''));
  if (!m) return { status: 'UNKNOWN', reason: `version "${v}" could not be compared` };
  const n = m[1], pre = /^[-.~_+]?(rc|pre|alpha|beta|dev)/i.test(m[2]);
  // the version is read from a program or a file, which the caller puts at the front of this receipt (judge() here and
  // checkVersionFiles in lib/installs.mjs): the version string itself is what was compared, not a place, so it is
  // declared rather than left looking like a path
  const ok = (fields) => safe([saw(`version ${v}`)], fields);
  if (rule.affectedFrom && cmp(n, rule.affectedFrom) < 0) return ok({ reason: `older than the affected range (from ${rule.affectedFrom})` });
  if (rule.bad && cmp(n, rule.bad.from) >= 0 && cmp(n, rule.bad.to) <= 0) return { status: 'EXPOSED', reason: `version ${v} is in the affected range ${rule.bad.from} to ${rule.bad.to}` };
  // one fixed version for every line (Plex: 1.43.3.10861 and later are not affected)
  if (rule.minVersion) return cmp(n, rule.minVersion) > 0 || (cmp(n, rule.minVersion) === 0 && !pre) ? ok() : { status: 'EXPOSED', reason: `fixed in ${rule.minVersion}` };
  if (rule.fixedIn) {
    // A list means one fix per release line (Go: 1.26.10 and 1.27.3): compare with the fix for the same major.minor.
    const fixes = [].concat(rule.fixedIn);
    // The release line, read NUMERICALLY. It used to join the first two parts as text, so "8.03.36" gave the line
    // "8.03", which never equals "8.3": no fix was found for the line, the version was judged against every other
    // line instead, and a PHP that was patched read EXPOSED (audit AUDIT-17). cmp() has always read parts as numbers;
    // this reads them the same way, so the two halves of the judgement agree about what a version is.
    const line = (x) => String(x).replace(/^\d+:/, '').split('.').slice(0, 2).map((p) => parseInt(p, 10) || 0).join('.');
    const same = fixes.find((f) => line(f) === line(n));
    const fixed = same ? cmp(n, same) > 0 || (cmp(n, same) === 0 && !pre) : fixes.every((f) => cmp(n, f) > 0);
    if (fixed) return ok();
    // older than every line that got a fix: an end-of-life line, with no fix coming
    const eol = !same && fixes.every((f) => cmp(line(n), line(f)) < 0);
    return { status: 'EXPOSED', reason: eol ? `no fix for the ${line(n)} line (end of life): move to a supported version (${fixes.join(', ')} or later)` : `fixed in ${same ?? fixes.join(' or ')}` };
  }
  if (rule.pendingUntil) return { status: 'UNKNOWN', reason: rule.pendingNote };
  // Nothing to judge the version against: no affectedFrom that placed it, no bad range, no minVersion, no fixedIn, no
  // pendingUntil. Up to this fix that fell through to SAFE, so dropping one key from an incident file turned EXPOSED
  // into SAFE and exit 0, while invalid JSON failed closed at exit 2 — the data layer disagreed with itself. A version
  // read but not comparable is the same ignorance as a version that could not be read, and that is already UNKNOWN.
  return { status: 'UNKNOWN', reason: `version ${v} was read, but this check says nothing to compare it against, so it could not be judged: please report this` };
}
