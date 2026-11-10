// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// SSHole, CVE-2026-123158: sshd before OpenSSH 10.6p2, on Linux with musl libc and without PAM, accepts a very long
// password for an account whose password field is `*` when another account has a `$5$` or `$6$` hash (Alpine's advisory
// of 5 Nov 2026 says 257 to 1024 bytes; the CVE record says "between 256 and 1024 characters"). This module only reads
// files: the Alpine release, the package database, sshd's configuration and start-up options, /etc/passwd, /etc/shadow
// when this user may read it (counts only, never a name, a field or a hash), and the start times of running processes in
// /proc. It never runs sshd (not even `sshd -T`), never connects to any port, and sends nothing.
//
// The package version is judged against Alpine's own fixed builds (the secdb, each branch's openssh secfixes), never
// against the upstream number alone: Alpine backported the fix, so on 3.24 10.3_p1-r2 is fixed and 10.3_p1-r1 is not.
// At or above the upstream fix, 10.6_p2, a build is fixed anywhere; below it only the fix of the branch
// /etc/alpine-release names counts (packageState(): revision numbers mean nothing across branches), and a branch Alpine
// lists no fix for is not fixed (Alpine: "we have published fixed packages for each release all the way back to 3.16").
//
// Verdicts, and what each needs (every SAFE names what it read):
//   SAFE      a condition the CVE needs is read as false where nothing can turn it back on: not Linux, not musl (and no
//             sshd that might be built against musl), no sshd installed, or a fixed package, no sshd program apk didn't
//             install, and no sshd process that started before the fixed programs were installed.
//   REVIEW    an unfixed package, where something Alpine's advisory says the flaw needs was read as missing (password
//             logins off, the PAM build alone with UsePAM yes, no `*` account it can use, no `$`-hash): not open now, and
//             still to update.
//   EXPOSED   an unfixed package, and nothing read rules it out. What could not be read (an unreadable file, a Match
//             block that turns a setting back on, start-up options) is named on the line.
//   UNKNOWN   a version that can't be read, a file the verdict needs that can't be read, an sshd apk didn't install, a
//             fixed package whose daemon may predate it, and anything this can't place.
import { join, dirname, basename } from 'node:path';
import { readText, readHead, pathState, listDir, changedAt, realPath, isLink } from './files.mjs';
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

const upstreamPart = (v) => String(v).replace(/-r\d+$/, '');
/**
 * Whether an Alpine build of openssh is fixed on `branch` (the one /etc/alpine-release names): 'fixed', 'unfixed' or
 * 'unknown'. At or above the upstream fix it is fixed anywhere. Below it, only the branch's own fix counts: the same
 * upstream version at or above its revision is fixed, below it (or an older upstream version) is not. Revision numbers
 * mean nothing across branches (edge built an unfixed 10.0_p1-r11 in Sep 2025, the very version string of 3.22's fixed
 * build; review, 9 Nov 2026), so a newer build from another branch is 'unknown', and on edge, on a branch Alpine lists
 * no fix for, or where the branch can't be read, below the upstream fix is not fixed ('unknown' where the string is one
 * of Alpine's fixed builds, since that can't be told apart).
 */
export function packageState(version, branch, { fixed, upstream }) {
  if (!apkParse(version)) return 'unknown';
  if (upstream && apkCompare(version, upstream) >= 0) return 'fixed';
  const own = branch && branch !== 'edge' ? fixed?.[branch] : undefined;
  if (own) {
    if (upstreamPart(own) === upstreamPart(version)) return apkCompare(version, own) >= 0 ? 'fixed' : 'unfixed';
    return apkCompare(version, own) < 0 ? 'unfixed' : 'unknown';
  }
  if (!branch && Object.values(fixed ?? {}).some((w) => upstreamPart(w) === upstreamPart(version) && apkCompare(version, w) >= 0)) return 'unknown';
  return 'unfixed';
}

/**
 * The packages `names` in the text of /lib/apk/db/installed: { name: { version, files } }, `files` the absolute paths
 * the stanza's F: (folder) and R: (file) lines say it installed. Stanzas are blank-line separated.
 */
export function installedPackages(text, names) {
  const out = {};
  for (const stanza of String(text ?? '').replace(/\r/g, '').split(/\n\s*\n/)) {
    const p = /^P:(.+)$/m.exec(stanza)?.[1]?.trim();
    if (!p || !names.includes(p) || out[p]) continue;
    const files = []; let folder = '';
    for (const line of stanza.split('\n')) {
      if (line.startsWith('F:')) folder = line.slice(2).trim();
      else if (line.startsWith('R:')) files.push(`/${folder ? `${folder}/` : ''}${line.slice(2).trim()}`);
    }
    out[p] = { version: /^V:(.+)$/m.exec(stanza)?.[1]?.trim() ?? '', files };
  }
  return out;
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
            // checked before a pattern is built from the name: a lone [ made an invalid expression and stopped the run
            if (/\[/.test(basename(full))) { problems.push(`Include ${pat} uses a [ ] pattern, which this does not expand`); continue; }
            const re = new RegExp(`^${basename(full).replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
            for (const n of names.filter((x) => re.test(x) && !x.startsWith('.')).sort()) visit(join(dirname(full), n), depth + 1, match);
          } else visit(full, depth + 1, match);
        }
        continue;
      }
      const key = ALIAS[kw] ?? kw;
      if (!values[key]) continue;
      // sshd takes a quoted word as the word: "yes" is yes
      const first = arg.split(/\s+/)[0].replace(/^"(.*)"$/, '$1').toLowerCase();
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

/**
 * From /etc/passwd (anyone may read it), counts only: accounts other than root with no shadow line whose password field
 * there is `*`, and `$`-hashes kept in /etc/passwd itself. `shadowNames` is the set of names /etc/shadow has, or null when
 * it couldn't be read (then nothing here is counted, since the field in passwd is not the one that is used).
 */
export function passwdCounts(text, shadowNames) {
  const c = { star: 0, rootStar: false, sha: 0, otherHash: 0 };
  if (!shadowNames) return c;
  for (const line of String(text ?? '').split('\n')) {
    const f = line.split(':');
    if (f.length < 2 || shadowNames.has(f[0])) continue;
    if (f[1] === '*') { if (f[0] === 'root') c.rootStar = true; else c.star++; }
    else if (/^\$[56]\$/.test(f[1])) c.sha++;
    else if (f[1].startsWith('$')) c.otherHash++;
  }
  return c;
}

/** The account names /etc/shadow has, to tell which /etc/passwd entries have no shadow line. Kept in memory, never printed. */
export const shadowNames = (text) => new Set(String(text ?? '').split('\n').map((l) => l.split(':')).filter((f) => f.length >= 2).map((f) => f[0]));

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
    if (!stat || !/^\d+ \(sshd(?:\.pam|\.krb5)?\) /.test(stat)) continue;
    const start = startOf(stat);
    if (start === null) return { procs, problem: `/proc/${pid}/stat could not be read for its start time` };
    procs.push({ pid: Number(pid), start });
  }
  return { procs };
}

// ---- the check ----------------------------------------------------------------------------------------------------------
const fsRead = (p) => readText(p, 64 * 1024 * 1024);
const fsList = (d) => { const l = listDir(d); return l.entries ? l.entries.map((e) => e.name) : null; };
// Alpine's three server builds (aports main/openssh: openssh-server, and openssh-server-pam and -krb5, both built
// --with-pam, each installing its own sshd.<flavour>); the init script picks among them by the configuration.
const PACKAGES = ['openssh-server', 'openssh-server-pam', 'openssh-server-krb5'];
const PAM_BUILDS = ['openssh-server-pam', 'openssh-server-krb5'];
const SSHD_PLACES = ['/usr/sbin/sshd', '/usr/sbin/sshd.pam', '/usr/sbin/sshd.krb5', '/usr/local/sbin/sshd', '/sbin/sshd', '/usr/bin/sshd', '/usr/local/bin/sshd'];
const SSHD_CODE = ['/usr/sbin/sshd', '/usr/sbin/sshd.pam', '/usr/sbin/sshd.krb5', ...['', '.pam', '.krb5'].flatMap((x) => [`/usr/lib/ssh/sshd-session${x}`, `/usr/lib/ssh/sshd-auth${x}`])];

/**
 * One row for this machine. `platform` is the OS (process.platform). The caller adds incident, kind and fix.
 * `changed(path)`: when the file was installed. apk sets a file's modification time from the package, so the inode's
 * change time is used, which apk cannot set (a review found the mtime made the stale-daemon check unable to fire).
 */
export function checkSshole(inc, { platform = process.platform, read = fsRead, list = fsList, state = pathState, changed = changedAt, procs = sshdProcesses, head = (p) => readHead(p, 64 * 1024), real = realPath, link = isLink } = {}) {
  const r = inc.sshd;
  if (platform === 'win32') return { status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' };
  if (platform !== 'linux') return safe([saw(`this system is ${platform === 'darwin' ? 'macOS' : platform}, not Linux`)], { reason: `not Linux: ${r.scope}` });

  // musl: Alpine's release file, or musl's own loader, which is always /lib/ld-musl-<arch>.so.1
  const release = read('/etc/alpine-release');
  const libNames = list('/lib');
  if (libNames === null) return { status: 'UNKNOWN', reason: '/lib could not be listed, so whether this system uses musl libc was not checked' };
  const loader = libNames.find((n) => /^ld-musl-[\w-]+\.so\.1$/.test(n));
  const present = SSHD_PLACES.filter((p) => state(p) !== 'gone');
  if (release === null && !loader) {
    if (state('/etc/alpine-release') !== 'gone') return { status: 'UNKNOWN', reason: '/etc/alpine-release is there but could not be read' };
    // a glibc system can still run an sshd built against musl, statically or not: each sshd program here must name
    // glibc's loader, or this can't say it isn't one
    // glibc's loader is ld-linux*.so on most architectures, ld64.so.1/.2 on s390x and ppc64, ld.so.1 on 32-bit mips/ppc
    const notGlibc = present.filter((p) => !/\/ld-linux[\w.-]*\.so|\/ld64\.so\.\d|\/lib\/ld\.so\.1/.test(head(p)?.toString('latin1') ?? ''));
    if (notGlibc.length) return { status: 'UNKNOWN', reason: `no musl loader in /lib and no /etc/alpine-release, but ${notGlibc.join(', ')} does not name glibc's loader, so it may be built against musl (statically, or for a musl loader elsewhere)` };
    return safe(['/lib', saw('no /etc/alpine-release'), ...present], { reason: `not a musl system: no /etc/alpine-release and no musl loader (/lib/ld-musl-*.so.1) in /lib${present.length ? `, and ${present.join(', ')} names glibc's loader` : ''}; ${r.scope}` });
  }

  // the package, judged as the build it is
  const db = read('/lib/apk/db/installed');
  if (db === null) {
    if (release !== null || state('/lib/apk/db/installed') !== 'gone') return { status: 'UNKNOWN', reason: '/lib/apk/db/installed could not be read, so the openssh package was not checked' };
    // musl, but not Alpine's package manager (Void, Chimera and others): a version can't be judged here
    if (!present.length) return safe(['/lib', ...SSHD_PLACES.map((p) => saw(`no ${p}`))], { reason: `musl libc (/lib/${loader}), and no sshd program at ${SSHD_PLACES.join(', ')}` });
    return { status: 'UNKNOWN', reason: `musl libc (/lib/${loader}) without Alpine's package database, and sshd is at ${present.join(', ')}. This check reads Alpine's packages only: update OpenSSH to 10.6p2 or later (or your distribution's fixed package), and set PasswordAuthentication no until you have` };
  }
  const pkgs = installedPackages(db, PACKAGES);
  const branch = alpineBranch(release);
  const names = Object.keys(pkgs);
  // every sshd program found must be one these packages installed, or its version is not the one read here
  // an sshd apk installed is one of its R: files, and still a file: a link put where apk installed a file is not apk's
  const owned = new Set(names.flatMap((n) => pkgs[n].files).filter((p) => !link(p)).map((p) => real(p) ?? p));
  const stray = present.filter((p) => !owned.has(real(p) ?? p));
  if (!names.length) {
    if (present.length) return { status: 'UNKNOWN', reason: `no openssh-server package in /lib/apk/db/installed, but there is an sshd at ${present.join(', ')}. One apk didn't install can't be judged by a version` };
    return safe(['/lib/apk/db/installed', ...SSHD_PLACES.map((p) => saw(`no ${p}`))], { reason: `no openssh server package is installed (read /lib/apk/db/installed), and there is no sshd program at ${SSHD_PLACES.join(', ')}` });
  }
  const read1 = `${names.map((n) => `${n} ${pkgs[n].version || '(no version)'}`).join(', ')} on ${branch ? `Alpine ${branch}` : 'an Alpine release this can\'t name'} (${release === null ? '/etc/alpine-release could not be read' : `/etc/alpine-release: ${release.trim().slice(0, 40)}`})`;
  const states = names.map((n) => packageState(pkgs[n].version, branch, r));
  // the fixed build of the same OpenSSH version, never the branch's own fix as a fallback: that can be older than what
  // is installed, and would point the reader at a downgrade (review, 9 Nov 2026)
  const wantOf = (v) => {
    const w = Object.values(r.fixed).find((x) => upstreamPart(x) === upstreamPart(v));
    return w ? `Alpine's fixed build is ${w}` : `Alpine lists no fixed build of OpenSSH ${upstreamPart(v)}: it published fixes back to 3.16, and the fix upstream is in 10.6p2`;
  };
  const want = [...new Set(names.map((n) => wantOf(pkgs[n].version)))].join('; ');
  if (states.includes('unknown')) return { status: 'UNKNOWN', reason: `${read1}: ${names.some((n) => !apkParse(pkgs[n].version)) ? 'a version this could not read' : 'a build that is not this release\'s own (pinned from another branch, or a release this can\'t name), and revision numbers differ between branches'}, so whether it is fixed can't be told. Update openssh (apk upgrade -U -a), or set PasswordAuthentication no` };
  if (stray.length && states.every((x) => x === 'fixed')) return { status: 'UNKNOWN', reason: `${read1}. There is also an sshd at ${stray.join(', ')} that apk didn't install, so its version can't be read and it isn't judged` };

  if (states.every((s) => s === 'fixed')) {
    // Alpine: "Upgrading the package does not restart a running sshd". Any sshd process that started before the fixed
    // programs were installed may still run the old code.
    const p = procs({ read, list });
    if (p.problem) return { status: 'UNKNOWN', reason: `${read1}: fixed (${want}), but ${p.problem}. Alpine says upgrading doesn't restart a running sshd: restart it (rc-service sshd restart)` };
    const code = SSHD_CODE.filter((f) => state(f) === 'file');
    const newest = Math.max(...code.map((f) => changed(f) ?? NaN));
    if (p.procs.length && !Number.isFinite(newest)) return { status: 'UNKNOWN', reason: `${read1}: fixed, but when sshd's programs were installed could not be read, so whether the running sshd (process ${p.procs[0].pid}) is older was not checked` };
    const stale = p.procs.filter((x) => x.start < newest + 2000);
    if (stale.length) return { status: 'UNKNOWN', reason: `${read1}: fixed on disk, but sshd (process ${stale.map((x) => x.pid).join(', ')}) was started before the fixed program was installed, so it may still run the old code. Restart it: rc-service sshd restart (Alpine: upgrading doesn't restart sshd)` };
    return safe(['/lib/apk/db/installed', '/etc/alpine-release', '/proc', ...code, saw(names.map((n) => `${n} ${pkgs[n].version}`).join(', '))], { reason: `${read1}: fixed (${want}), and ${p.procs.length ? `every running sshd (${p.procs.length}) started after its program was installed` : 'no sshd process is running'}` });
  }

  // unfixed: what Alpine's advisory says the flaw needs, read where it can be
  const why = [], notRead = [], could = [];
  if (stray.length) notRead.push(`the sshd at ${stray.join(', ')}, which apk didn't install`);
  const cfg = readSshdConfig('/etc/ssh/sshd_config', { read, list });
  // start-up options: any setting in /etc/conf.d/sshd (SSHD_OPTS, command_args, cfgfile, SSHD_BINARY ...) can change
  // what sshd reads or which program runs, and a second instance (sshd.<name>) has its own
  const confd = read('/etc/conf.d/sshd');
  const others = ['/etc/conf.d', '/etc/init.d'].flatMap((d) => (list(d) ?? []).filter((n) => /^sshd\..+/.test(n)).map((n) => `${d}/${n}`));
  const startup = [
    ...(confd !== null && confd.split('\n').some((l) => l.trim() && !l.trim().startsWith('#')) ? ['/etc/conf.d/sshd sets start-up options'] : []),
    ...(confd === null && state('/etc/conf.d/sshd') !== 'gone' ? ['/etc/conf.d/sshd could not be read'] : []),
    ...(others.length ? [`another sshd instance is set up (${others.join(', ')})`] : []),
  ];
  // an sshd started by hand or another supervisor can carry -o or -f on its command line; sshd's listener keeps it in
  // its title ("sshd: /usr/sbin/sshd -o ... [listener] ..."), which /proc/<pid>/cmdline shows to anyone
  const running = procs({ read, list });
  for (const p of running.procs ?? []) {
    const cmd = (read(`/proc/${p.pid}/cmdline`) ?? '').replace(/\0/g, ' ');
    if (/(^|\s)-[A-Za-z]*[of]/.test(cmd)) startup.push(`a running sshd (process ${p.pid}) was started with options on its command line`);
  }
  const cfgOk = !cfg.problems.length && !startup.length;
  if (!cfgOk) notRead.push(`sshd's settings (${[...cfg.problems, ...startup].join('; ')})`);
  else {
    const pw = maybeOn(cfg.values.passwordauthentication, (v) => v !== 'no');
    if (pw === false) why.push(`PasswordAuthentication is no (${cfg.files.join(', ')})`);
    else if (pw === null) could.push(`PasswordAuthentication is no, but a Match block in ${cfg.files.join(', ')} turns it on again for some logins.`);
    const pam = maybeOn(cfg.values.usepam, (v) => v !== 'yes');
    if (!names.includes('openssh-server') && pam === false) why.push(`only a PAM build is installed (${names.join(', ')}; Alpine builds openssh-server-pam and -krb5 with PAM), with UsePAM yes, and the flaw needs sshd without PAM`);
  }
  const shadow = read('/etc/shadow');
  if (shadow === null) notRead.push('/etc/shadow (usually only root can read it), so it was not checked whether there is both an account with no password (*) and one with a $5$ or $6$ hash. Run as root to check');
  else {
    const c = shadowCounts(shadow);
    const pc = passwdCounts(read('/etc/passwd'), shadowNames(shadow));
    const rootIn = cfgOk ? maybeOn(cfg.values.permitrootlogin, (v) => v === 'yes') : null;
    const stars = c.star + pc.star + ((c.rootStar || pc.rootStar) && rootIn !== false ? 1 : 0);
    const sha = c.sha + pc.sha, other = c.otherHash + pc.otherHash;
    const directory = directoryAccounts(read('/etc/nsswitch.conf'));
    if (c.unreadable) notRead.push(`${c.unreadable} line${c.unreadable === 1 ? '' : 's'} of /etc/shadow`);
    else if (directory) notRead.push('accounts from a directory service (/etc/nsswitch.conf): they have no shadow entry, and their hashes are not read here');
    else {
      if (!sha && !other) why.push(`no account has a $-style password hash (${c.lines} accounts read)`);
      else if (!sha) notRead.push(`whether the ${other} $-style hash${other === 1 ? '' : 'es'} that ${other === 1 ? 'is' : 'are'} not $5$ or $6$ can serve (Alpine names $5$ and $6$)`);
      if (!stars) why.push(`no account has the field * (${c.rootStar || pc.rootStar ? 'root does, but PermitRootLogin is not yes; ' : ''}${c.lines} accounts read)`);
    }
  }
  if (why.length) return { status: 'REVIEW', reason: `${read1}: not fixed (${want}), but ${why.join(', and ')}, and the advisories say the flaw needs that (Alpine's; the CVE record). Update anyway: if that changes later, the hole is open again` };
  return { status: 'EXPOSED', reason: `${read1}: not fixed (${want}), and nothing read here rules it out.${could.length ? ` ${could.join(' ')}` : ''}${notRead.length ? ` Not read: ${notRead.join('; ')}.` : ''}` };
}
