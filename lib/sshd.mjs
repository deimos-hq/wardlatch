// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// SSHole, CVE-2026-123158: sshd before OpenSSH 10.6p2, on Linux with musl libc and without PAM, accepts any password of
// 257 to 1024 bytes for an account whose password field is `*` when another account has a `$5$` or `$6$` hash (the CVE
// record; Alpine's advisory of 5 Nov 2026). This module only reads files: the Alpine release, the package database,
// sshd's configuration, /etc/shadow when this user may read it (counts only, never a name, a field or a hash), and the
// start times of running processes in /proc. It never runs sshd (not even `sshd -T`), never connects to any port, and
// sends nothing.
//
// The package version is judged against Alpine's own fixed version FOR ITS BRANCH (the secdb), never against the
// upstream number alone: Alpine backported the fix, so 10.3_p1-r2 is fixed on 3.24 and 10.3_p1-r1 is not. A package
// at or above the upstream fix, 10.6_p2, is fixed on any branch.
//
// Verdicts, and what each needs (every SAFE names what it read):
//   SAFE      a condition the CVE needs is read as false where nothing can turn it back on: not Linux, not musl, no
//             sshd installed, or a fixed package with no sshd process left running older code.
//   REVIEW    an unfixed package, where something Alpine says closes the hole was read (password logins off, the PAM
//             build with UsePAM yes, no `*` account or no `$`-hash): not open now, and still to update.
//   EXPOSED   an unfixed package, and nothing read rules it out. What could not be read is named in the reason.
//   UNKNOWN   everything else: a version or branch that can't be placed, a file that can't be read, a Match block or
//             start-up option that can change the answer, a fixed package whose daemon may predate it.
import { join, dirname, basename } from 'node:path';
import { readText, pathState, listDir, modifiedAt } from './files.mjs';
import { safe, saw } from './report.mjs';

// ---- Alpine package versions --------------------------------------------------------------------------------------------
const SUFFIX = ['alpha', 'beta', 'pre', 'rc', '', 'cvs', 'svn', 'git', 'hg', 'p'];
const VERSION_RE = /^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$/;

/** An apk version split for comparing, or null when it is not one this reads (then nothing is judged by it). */
export function apkParse(v) {
  const m = VERSION_RE.exec(String(v ?? ''));
  if (!m) return null;
  const suffixes = [...m[3].matchAll(/_([a-z]+)(\d*)/g)].map((s) => [SUFFIX.indexOf(s[1]), Number(s[2] || 0)]);
  return { nums: m[1].split('.').map(Number), letter: m[2] ? m[2].charCodeAt(0) : 0, suffixes, rel: Number(m[4] ?? 0) };
}

/** -1, 0 or 1 by apk's order (numbers, then a letter, then suffixes: _alpha < _beta < _pre < _rc < none < _p, then -rN). */
export function apkCompare(a, b) {
  const x = apkParse(a), y = apkParse(b);
  if (!x || !y) throw new Error(`not an apk version: ${!x ? a : b}`);
  const s = (n) => (n < 0 ? -1 : n > 0 ? 1 : 0);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    if (x.nums[i] === undefined) return -1;
    if (y.nums[i] === undefined) return 1;
    if (x.nums[i] !== y.nums[i]) return s(x.nums[i] - y.nums[i]);
  }
  if (x.letter !== y.letter) return s(x.letter - y.letter);
  for (let i = 0; i < Math.max(x.suffixes.length, y.suffixes.length); i++) {
    const p = x.suffixes[i] ?? [SUFFIX.indexOf(''), 0], q = y.suffixes[i] ?? [SUFFIX.indexOf(''), 0];
    if (p[0] !== q[0]) return s(p[0] - q[0]);
    if (p[1] !== q[1]) return s(p[1] - q[1]);
  }
  return s(x.rel - y.rel);
}

/** The Alpine branch an /etc/alpine-release names: '3.24' for 3.24.4, 'edge' for a development snapshot, else ''. */
export function alpineBranch(text) {
  const t = String(text ?? '').trim();
  if (/^\d+\.\d+_(alpha|beta|rc)\d+$/.test(t)) return 'edge';
  const m = /^(\d+)\.(\d+)\.\d+$/.exec(t);
  return m ? `${m[1]}.${m[2]}` : '';
}

/**
 * Whether `version` is fixed on `branch`: 'fixed', 'unfixed' or 'unknown' (a branch the incident doesn't list, or a
 * version this can't read). `fixed` is the incident's { branch: version } table; `upstream` the upstream fix.
 */
export function packageState(version, branch, { fixed, upstream }) {
  if (!apkParse(version)) return 'unknown';
  if (upstream && apkCompare(version, upstream) >= 0) return 'fixed';
  const want = fixed?.[branch];
  if (!want) return 'unknown';
  return apkCompare(version, want) >= 0 ? 'fixed' : 'unfixed';
}

/** The versions of `names` in the text of /lib/apk/db/installed ({ name: version }). Stanzas are blank-line separated. */
export function installedVersions(text, names) {
  const out = {};
  for (const stanza of String(text ?? '').split(/\n\s*\n/)) {
    const p = /^P:(.+)$/m.exec(stanza)?.[1]?.trim(), v = /^V:(.+)$/m.exec(stanza)?.[1]?.trim();
    if (p && names.includes(p)) out[p] = v ?? '';
  }
  return out;
}

// ---- sshd's configuration -----------------------------------------------------------------------------------------------
export const KEYWORDS = { passwordauthentication: 'yes', usepam: 'no', permitrootlogin: 'prohibit-password', kbdinteractiveauthentication: 'yes' };
const ALIAS = { challengeresponseauthentication: 'kbdinteractiveauthentication' };

/**
 * Reads sshd_config as sshd does for the keywords this check needs: the first value outside a Match block wins, an
 * Include is read where it stands (a relative name is under /etc/ssh; a glob only in the last part of the name, sorted),
 * and a value inside a Match block (from a Match line to the end of its file) is conditional. `read(path)` → text or
 * null; `list(dir)` → names or null. → { values: { kw: { value, conditional: [values] } }, files: [paths read],
 * problems: [sentences] }. A problem makes every keyword UNKNOWN for the caller.
 */
export function readSshdConfig(main, { read, list }) {
  const values = Object.fromEntries(Object.keys(KEYWORDS).map((k) => [k, { value: undefined, conditional: [] }]));
  const files = [], problems = [];
  const visit = (file, depth, inMatch) => {
    if (depth > 16) { problems.push(`Include goes more than 16 levels deep at ${file}`); return; }
    const text = read(file);
    if (text === null || text === undefined) { problems.push(`${file} could not be read`); return; }
    files.push(file);
    let match = inMatch;
    for (const raw of text.split('\n')) {
      const line = raw.replace(/\r$/, '').trim();
      if (!line || line.startsWith('#')) continue;
      const m = /^([A-Za-z]+)(?:\s*=\s*|\s+)(.*)$/.exec(line);
      if (!m) { problems.push(`a line in ${file} could not be read as a keyword and a value`); continue; }
      const kw = m[1].toLowerCase(), arg = m[2].trim();
      if (kw === 'match') { match = true; continue; }
      if (kw === 'include') {
        for (const pat of arg.split(/\s+/).filter(Boolean)) {
          const full = pat.startsWith('/') ? pat : join('/etc/ssh', pat);
          if (/[*?[]/.test(dirname(full))) { problems.push(`Include ${pat} has a pattern in a folder name, which this does not expand`); continue; }
          if (/[*?[]/.test(basename(full))) {
            const names = list(dirname(full));
            if (names === null) { problems.push(`${dirname(full)} could not be listed for Include ${pat}`); continue; }
            const re = new RegExp(`^${basename(full).replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
            if (/\[/.test(basename(full))) { problems.push(`Include ${pat} uses a [ ] pattern, which this does not expand`); continue; }
            for (const n of names.filter((x) => re.test(x) && !x.startsWith('.')).sort()) visit(join(dirname(full), n), depth + 1, match);
          } else visit(full, depth + 1, match);
        }
        continue;
      }
      const key = ALIAS[kw] ?? kw;
      if (!values[key]) continue;
      const first = arg.split(/\s+/)[0].toLowerCase();
      if (match) values[key].conditional.push(first);
      else if (values[key].value === undefined) values[key].value = first;
    }
  };
  visit(main, 0, false);
  for (const [k, d] of Object.entries(KEYWORDS)) if (values[k].value === undefined) { values[k].value = d; values[k].defaulted = true; }
  return { values, files, problems };
}

/**
 * Whether a keyword is ON for some login: true, false, or null (unknown). `on(value)` says whether a value turns it on.
 * Off globally with a Match block that sets it to anything else is unknown, never off.
 */
export function maybeOn(entry, on) {
  if (on(entry.value)) return true;
  return entry.conditional.some((v) => v !== entry.value) ? null : false;
}

// ---- accounts -----------------------------------------------------------------------------------------------------------
/**
 * Counts from the text of /etc/shadow, never a name or a field: accounts other than root whose field is exactly `*`,
 * whether root's is, `$5$`/`$6$` hashes, and other `$`-hashes. A line that can't be split is counted as unreadable.
 */
export function shadowCounts(text) {
  const c = { star: 0, rootStar: false, sha: 0, otherHash: 0, lines: 0, unreadable: 0 };
  for (const line of String(text ?? '').split('\n')) {
    if (!line.trim()) continue;
    const f = line.split(':');
    if (f.length < 2) { c.unreadable++; continue; }
    c.lines++;
    if (f[1] === '*') { if (f[0] === 'root') c.rootStar = true; else c.star++; }
    else if (/^\$[56]\$/.test(f[1])) c.sha++;
    else if (f[1].startsWith('$')) c.otherHash++;
  }
  return c;
}

/** Whether /etc/nsswitch.conf takes passwd entries from a directory service (accounts with no shadow entry). */
export const directoryAccounts = (text) => /^\s*passwd\s*:.*\b(ldap|nslcd|winbind|sss)\b/m.test(String(text ?? ''));

// ---- running daemons ----------------------------------------------------------------------------------------------------
/**
 * The start times (ms since 1970) of running processes named sshd, from /proc: field 22 of /proc/<pid>/stat over
 * USER_HZ, plus btime from /proc/stat. USER_HZ is 100 on every architecture Alpine builds for; that is checked here on
 * this process's own start before anything is believed. → { procs: [{ pid, start }], problem? }.
 */
export function sshdProcesses({ read, list, now = Date.now(), uptime = process.uptime() }) {
  const btime = Number(/^btime (\d+)$/m.exec(read('/proc/stat') ?? '')?.[1]);
  if (!btime) return { procs: [], problem: '/proc/stat could not be read for the boot time' };
  const startOf = (stat) => {
    // the name is in parentheses and may hold spaces or parentheses: fields are counted after the last ')'
    const i = stat.lastIndexOf(')'); if (i < 0) return null;
    const rest = stat.slice(i + 2).split(' ');
    const ticks = Number(rest[19]);   // field 22 overall; fields 3.. start at rest[0]
    return Number.isFinite(ticks) ? (btime + ticks / 100) * 1000 : null;
  };
  // the control: this process's own start, read the same way, must agree with what Node says to within 2 seconds
  const self = read('/proc/self/stat');
  const mine = self ? startOf(self) : null;
  if (mine === null || Math.abs(mine - (now - uptime * 1000)) > 2000) return { procs: [], problem: 'the start time of this process, read from /proc/self/stat, did not match its real start, so process start times here cannot be trusted' };
  const pids = list('/proc');
  if (pids === null) return { procs: [], problem: '/proc could not be listed' };
  // with /proc mounted hidepid, another user's processes are not listed: pid 1 is the one every system has
  if (!pids.includes('1')) return { procs: [], problem: 'process 1 is not listed in /proc (it is mounted to hide other users\' processes), so a running sshd may not be visible' };
  const procs = [];
  for (const pid of pids.filter((p) => /^\d+$/.test(p))) {
    const stat = read(`/proc/${pid}/stat`);
    if (!stat || !/^\d+ \(sshd(?:\.pam)?\) /.test(stat)) continue;
    const start = startOf(stat);
    if (start === null) return { procs, problem: `/proc/${pid}/stat could not be read for its start time` };
    procs.push({ pid: Number(pid), start });
  }
  return { procs };
}

// ---- the check ----------------------------------------------------------------------------------------------------------
const fsRead = (p) => readText(p, 64 * 1024 * 1024);
const fsList = (d) => { const l = listDir(d); return l.entries ? l.entries.map((e) => e.name) : null; };
const SSHD_PLACES = ['/usr/sbin/sshd', '/usr/sbin/sshd.pam', '/usr/local/sbin/sshd', '/sbin/sshd'];
const SSHD_CODE = ['/usr/sbin/sshd', '/usr/sbin/sshd.pam', '/usr/lib/ssh/sshd-session', '/usr/lib/ssh/sshd-auth'];

/**
 * One row for this machine. `platform` is the OS (process.platform). The caller adds incident, kind and fix.
 */
export function checkSshole(inc, { platform = process.platform, read = fsRead, list = fsList, state = pathState, mtime = modifiedAt, procs = sshdProcesses } = {}) {
  const r = inc.sshd;
  if (platform === 'win32') return { status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' };
  if (platform !== 'linux') return safe([saw(`this system is ${platform === 'darwin' ? 'macOS' : platform}, not Linux`)], { reason: `not Linux: ${r.scope}` });

  // musl: Alpine's release file, or musl's own loader, which is always /lib/ld-musl-<arch>.so.1
  const release = read('/etc/alpine-release');
  const libNames = list('/lib');
  if (libNames === null) return { status: 'UNKNOWN', reason: '/lib could not be listed, so whether this system uses musl libc was not checked' };
  const loader = libNames.find((n) => /^ld-musl-[\w-]+\.so\.1$/.test(n));
  if (release === null && !loader) {
    if (state('/etc/alpine-release') !== 'gone') return { status: 'UNKNOWN', reason: '/etc/alpine-release is there but could not be read' };
    return safe(['/lib', saw('no /etc/alpine-release')], { reason: `not a musl system: no /etc/alpine-release and no musl loader (/lib/ld-musl-*.so.1) in /lib; ${r.scope}` });
  }

  // the package, judged on its branch
  const db = read('/lib/apk/db/installed');
  const pkgs = db === null ? null : installedVersions(db, ['openssh-server', 'openssh-server-pam']);
  const present = SSHD_PLACES.filter((p) => state(p) !== 'gone');
  if (db === null) {
    if (release !== null || state('/lib/apk/db/installed') !== 'gone') return { status: 'UNKNOWN', reason: '/lib/apk/db/installed could not be read, so the openssh package was not checked' };
    // musl, but not Alpine's package manager (Void, Chimera and others): a version can't be judged here
    if (!present.length) return safe(['/lib', ...SSHD_PLACES.map((p) => saw(`no ${p}`))], { reason: `musl libc (/lib/${loader}), and no sshd program at ${SSHD_PLACES.join(', ')}` });
    return { status: 'UNKNOWN', reason: `musl libc (/lib/${loader}) without Alpine's package database, and sshd is at ${present.join(', ')}: this check judges Alpine's packages only. Update OpenSSH to 10.6p2 or later, or your distribution's fixed package, and set PasswordAuthentication no until you have` };
  }
  const branch = alpineBranch(release);
  const names = Object.keys(pkgs);
  if (!names.length) {
    if (present.length) return { status: 'UNKNOWN', reason: `no openssh-server package in /lib/apk/db/installed, but sshd is at ${present.join(', ')}: one not installed by apk can't be judged by its version` };
    return safe(['/lib/apk/db/installed', ...SSHD_PLACES.map((p) => saw(`no ${p}`))], { reason: `neither openssh-server nor openssh-server-pam is installed (read /lib/apk/db/installed), and there is no sshd program at ${SSHD_PLACES.join(', ')}` });
  }
  const read1 = `${names.map((n) => `${n} ${pkgs[n] || '(no version)'}`).join(', ')} on ${branch ? `Alpine ${branch}` : 'an Alpine branch this can\'t name'} (${release === null ? '/etc/alpine-release could not be read' : `/etc/alpine-release: ${release.trim().slice(0, 40)}`})`;
  const states = names.map((n) => packageState(pkgs[n], branch, r));
  const want = r.fixed[branch];
  if (states.includes('unknown')) {
    return { status: 'UNKNOWN', reason: `${read1}: ${!branch || !want ? `the fixed version for this branch is not known here (Alpine lists ${Object.keys(r.fixed).join(', ')})` : 'a version this could not read'}, and below ${r.upstream} it can't be judged by the upstream number: Alpine backported the fix` };
  }

  if (states.every((s) => s === 'fixed')) {
    // a fixed package does not restart a running sshd (Alpine): any sshd process older than the program on disk still
    // runs the old code
    const p = procs({ read, list });
    if (p.problem) return { status: 'UNKNOWN', reason: `${read1}: fixed (Alpine's fix on this branch is ${want ?? r.upstream}), but ${p.problem}. Alpine says upgrading does not restart a running sshd: restart it (rc-service sshd restart)` };
    const code = SSHD_CODE.filter((f) => state(f) === 'file');
    const newest = Math.max(...code.map((f) => mtime(f) ?? NaN));
    if (p.procs.length && !(Number.isFinite(newest))) return { status: 'UNKNOWN', reason: `${read1}: fixed, but the time sshd's programs were last changed could not be read, so whether the running sshd (process ${p.procs[0].pid}) predates them was not checked` };
    const stale = p.procs.filter((x) => x.start < newest + 2000);
    if (stale.length) return { status: 'UNKNOWN', reason: `${read1}: fixed on disk, but sshd process ${stale.map((x) => x.pid).join(', ')} started before (or within 2 seconds of) the last change to ${code.join(', ')}, so it may still be running the old code. Alpine says upgrading does not restart a running sshd: restart it (rc-service sshd restart)` };
    return safe(['/lib/apk/db/installed', '/etc/alpine-release', '/proc', ...code, saw(`${names.map((n) => `${n} ${pkgs[n]}`).join(', ')}`)], { reason: `${read1}: fixed (Alpine's fix on this branch is ${want ?? r.upstream}), and ${p.procs.length ? `every running sshd (${p.procs.length}) started after its program was last changed` : 'no sshd process is running'}` });
  }

  // unfixed: what Alpine says closes the hole, read where it can be
  const why = [], notRead = [];
  const cfg = readSshdConfig('/etc/ssh/sshd_config', { read, list });
  const confd = read('/etc/conf.d/sshd');
  const startup = confd !== null && confd.split('\n').some((l) => /^\s*[A-Za-z_]+=\s*["']?[^"'\s]/.test(l));
  if (cfg.problems.length || startup) {
    notRead.push(`sshd's settings (${[...cfg.problems, ...(startup ? ['/etc/conf.d/sshd sets start-up options, which this does not read'] : [])].join('; ')})`);
  } else {
    const pw = maybeOn(cfg.values.passwordauthentication, (v) => v === 'yes');
    if (pw === false) why.push(`PasswordAuthentication is no in ${cfg.files.join(', ')}`);
    else if (pw === null) notRead.push(`PasswordAuthentication is no outside a Match block and set otherwise inside one, in ${cfg.files.join(', ')}`);
    const nonPam = names.includes('openssh-server');
    const pam = maybeOn(cfg.values.usepam, (v) => v === 'no');
    if (!nonPam && pam === false) why.push(`only openssh-server-pam is installed, and UsePAM is yes in ${cfg.files.join(', ')}`);
    const kbd = cfg.values.kbdinteractiveauthentication;
    cfg.context = `for reference, KbdInteractiveAuthentication is ${kbd.value}${kbd.defaulted ? ', the default' : ''} (Alpine's advisory names PasswordAuthentication only)`;
  }
  const shadow = read('/etc/shadow');
  if (shadow === null) notRead.push('/etc/shadow (only root can read it), so whether an account with no password (*) and one with a $5$ or $6$ hash both exist');
  else {
    const c = shadowCounts(shadow);
    const rootIn = !cfg.problems.length && !startup ? maybeOn(cfg.values.permitrootlogin, (v) => v === 'yes') : null;
    const stars = c.star + (c.rootStar && rootIn !== false ? 1 : 0);
    const directory = directoryAccounts(read('/etc/nsswitch.conf'));
    if (c.unreadable) notRead.push(`${c.unreadable} line${c.unreadable === 1 ? '' : 's'} of /etc/shadow`);
    else if (!c.sha && !c.otherHash) why.push(`no account in /etc/shadow has a $-style password hash (${c.lines} read)`);
    else if (!c.sha && c.otherHash) notRead.push(`whether the ${c.otherHash} $-style hash${c.otherHash === 1 ? '' : 'es'} in /etc/shadow that ${c.otherHash === 1 ? 'is' : 'are'} not $5$ or $6$ can serve (Alpine names $5$ and $6$)`);
    if (!stars && !directory && !c.unreadable) why.push(`no account that can log in by password has the field * in /etc/shadow${c.rootStar ? ' (root has, and PermitRootLogin is not yes)' : ''} (${c.lines} read)`);
    else if (!stars && directory) notRead.push('accounts from a directory service (/etc/nsswitch.conf), which have no shadow entry');
  }
  const context = cfg.context ? `. ${cfg.context[0].toUpperCase()}${cfg.context.slice(1)}` : '';
  if (why.length) return { status: 'REVIEW', reason: `${read1}: below Alpine's fix for this branch (${want}), but ${why.join(', and ')}, which Alpine says closes the hole. Update anyway: a later change to any of those opens it${context}` };
  return { status: 'EXPOSED', reason: `${read1}: below Alpine's fix for this branch (${want}), and nothing read here rules it out${notRead.length ? `. Not read: ${notRead.join('; ')}` : ''}${context}` };
}
