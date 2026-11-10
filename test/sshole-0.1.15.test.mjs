// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.15: SSHole, CVE-2026-123158 (lib/sshd.mjs, lib/incidents/sshole-2026-11.json). Each verdict branch is held here on
// a made-up machine: the file reads are handed in, so no test reads this machine's /etc, /lib or /proc, and nothing
// runs sshd or connects anywhere. The fixed versions are Alpine's secdb's, read on 9 Nov 2026 for edge and 3.16 to 3.24
// (they match the table in Alpine's advisory of 5 Nov 2026). The last tests run the command on a stand-in Linux root.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs, { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apkParse, apkCompare, alpineBranch, packageState, installedVersions, readSshdConfig, maybeOn, shadowCounts, directoryAccounts, sshdProcesses, checkSshole } from '../lib/sshd.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'sshole-2026-11.json'), 'utf8'));
// Alpine's secdb, 9 Nov 2026: the openssh secfixes entry naming CVE-2026-123158, per branch (copied by hand)
const SECDB = { edge: '10.6_p2-r0', '3.24': '10.3_p1-r2', '3.23': '10.2_p1-r1', '3.22': '10.0_p1-r11', '3.21': '9.9_p2-r1', '3.20': '9.7_p1-r6', '3.19': '9.6_p1-r3', '3.18': '9.3_p2-r4', '3.17': '9.1_p1-r7', '3.16': '9.0_p1-r6' };
// the revision before each fix, which is still vulnerable on that branch
const prior = (v) => v.replace(/-r(\d+)$/, (m, r) => `-r${Number(r) - 1}`);
const RELEASE = { edge: '3.25_alpha20261101', '3.24': '3.24.3', '3.23': '3.23.7', '3.22': '3.22.7', '3.21': '3.21.9', '3.20': '3.20.8', '3.19': '3.19.9', '3.18': '3.18.12', '3.17': '3.17.10', '3.16': '3.16.9' };

// ---- a made-up machine ----------------------------------------------------------------------------------------------
// files: { path: text | null (there, unreadable) }; dirs: { path: [names] | null (unlistable) }; a path in neither is gone.
// The reads are handed to the check; the same files are also written under a folder of the test's own, and while a check
// runs this process's statSync reads /etc, /lib, /usr, /sbin, /bin and /proc from there, so that lib/report.mjs safe()
// can hold an all-clear's receipt to places that really are there, as it does on a real machine. Without that, every
// SAFE here read UNKNOWN ("an all-clear that names ... which cannot be checked by looking"), which is the rule working.
let ROOTNOW = null;
const SYSP = /^\/(etc|lib|usr|sbin|bin|proc)(\/|$)/;
const realStat = fs.statSync;
fs.statSync = function (p, ...a) { return realStat.call(this, ROOTNOW && typeof p === 'string' && SYSP.test(p) ? ROOTNOW + p : p, ...a); };
syncBuiltinESMExports();
function machine({ files = {}, dirs = {}, mtimes = {}, procs = { procs: [] } } = {}) {
  const root = mkdtempSync(join(dir, 'm-'));
  for (const d of ['/proc', ...Object.keys(dirs)]) mkdirSync(join(root, d), { recursive: true });
  for (const [p, t] of Object.entries(files)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), t ?? ''); }
  const read = (p) => (p in files ? files[p] : null);
  const list = (d) => (d in dirs ? dirs[d] : null);
  const state = (p) => (p in files ? (files[p] === null ? 'denied' : 'file') : p in dirs ? 'dir' : 'gone');
  const asked = [];
  return { root, read: (p) => { asked.push(p); return read(p); }, list, state, mtime: (p) => mtimes[p], procs: () => procs, asked };
}
const db = (pkgs) => Object.entries(pkgs).map(([p, v]) => `C:Q1abc=\nP:${p}\nV:${v}\nA:x86_64\nS:1\nI:2\nT:t\n`).join('\n') + '\n';
const SHADOW = 'root:*::0:::::\nbin:!::0:::::\nada:$6$salt$hash:20000:0:99999:7:::\ndeploy:*:20000:0:99999:7:::\n';
function alpine({ branch = '3.24', version, pkg = 'openssh-server', extra = {}, config = 'Include /etc/ssh/sshd_config.d/*.conf\n', confd = '#SSHD_OPTS=""\n', shadow = SHADOW, dropins = {}, procs, mtimes } = {}) {
  const files = {
    '/etc/alpine-release': `${RELEASE[branch]}\n`,
    '/lib/apk/db/installed': db({ 'musl': '1.2.5-r10', [pkg]: version ?? SECDB[branch], ...extra }),
    '/etc/ssh/sshd_config': config, '/etc/conf.d/sshd': confd, '/usr/sbin/sshd': 'ELF',
    ...(shadow === undefined ? {} : { '/etc/shadow': shadow }),
  };
  for (const [n, t] of Object.entries(dropins)) files[`/etc/ssh/sshd_config.d/${n}`] = t;
  return machine({ files, dirs: { '/lib': ['ld-musl-x86_64.so.1', 'apk'], '/etc/ssh/sshd_config.d': Object.keys(dropins) }, procs, mtimes: mtimes ?? { '/usr/sbin/sshd': 1000 } });
}
const run = (m, platform = 'linux') => { ROOTNOW = m.root; try { return checkSshole(inc, { platform, ...m }); } finally { ROOTNOW = null; } };

let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-sshole-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

test('the incident\'s fixed versions are Alpine\'s secdb\'s, branch by branch, and its sources are primary', () => {
  assert.deepEqual(inc.sshd.fixed, SECDB);
  assert.equal(inc.sshd.upstream, '10.6_p2-r0');
  assert.equal(inc.sshd.cve, 'CVE-2026-123158');
  assert.equal(inc.advisory, 'https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/');
  for (const u of inc.sources) assert.match(u, /^https:\/\//);
  assert.ok(inc.sources.some((u) => u.includes('cve.org/CVERecord?id=CVE-2026-123158')));
  assert.ok(inc.sources.some((u) => u.includes('openssh.org/releasenotes.html#10.6p2')));
  // what it must not say: root by default, or that it contacted sshd
  assert.match(inc.summary, /PermitRootLogin yes/);
  assert.match(inc.summary, /never runs sshd and never connects to it/);
  assert.match(inc.fix, /apk upgrade -U -a/); assert.match(inc.fix, /rc-service sshd restart/);
  assert.match(inc.fix, /PasswordAuthentication no/);
});

test('apk versions compare as apk does, on the forms Alpine\'s openssh uses', () => {
  const lt = [['10.3_p1-r1', '10.3_p1-r2'], ['10.0_p1-r9', '10.0_p1-r11'], ['9.9_p1-r5', '9.9_p2-r1'], ['10.3_p1-r9', '10.6_p2-r0'],
    ['10.6_p1-r3', '10.6_p2-r0'], ['10.6-r0', '10.6_p1-r0'], ['10.6_rc1-r0', '10.6-r0'], ['9.6_p1', '9.6_p1-r1'], ['1.2', '1.2.1'], ['1.2a', '1.2b'], ['1.2', '1.2a']];
  for (const [a, b] of lt) { assert.equal(apkCompare(a, b), -1, `${a} < ${b}`); assert.equal(apkCompare(b, a), 1, `${b} > ${a}`); }
  assert.equal(apkCompare('10.3_p1-r2', '10.3_p1-r2'), 0);
  assert.equal(apkCompare('9.6_p1-r0', '9.6_p1'), 0);
  for (const bad of ['', '10.3p1', '10.3_p1-r', 'x', '10.3_p1-r2 ', '10.3_foo1-r1', null]) assert.equal(apkParse(bad), null, String(bad));
  assert.throws(() => apkCompare('x', '1'));
});

test('the branch is read from /etc/alpine-release, and edge from a development snapshot', () => {
  assert.equal(alpineBranch('3.24.4\n'), '3.24'); assert.equal(alpineBranch('3.16.0'), '3.16');
  assert.equal(alpineBranch('3.25_alpha20261101'), 'edge');
  for (const bad of ['', '3.24', 'edge', '3.24.4.1', 'v3.24.4', null]) assert.equal(alpineBranch(bad), '', String(bad));
});

test('each branch\'s fix is fixed, the revision before it is not, and an unlisted branch is unknown', () => {
  for (const [branch, fixed] of Object.entries(SECDB)) {
    assert.equal(packageState(fixed, branch, inc.sshd), 'fixed', `${branch} ${fixed}`);
    if (!fixed.endsWith('-r0')) assert.equal(packageState(prior(fixed), branch, inc.sshd), 'unfixed', `${branch} ${prior(fixed)}`);
  }
  // the backport trap: 10.3_p1-r1 is fixed nowhere, though 10.3 < 10.6 says nothing
  assert.equal(packageState('10.3_p1-r1', '3.24', inc.sshd), 'unfixed');
  // edge's fix is the upstream one; one below it
  assert.equal(packageState('10.6_p1-r0', 'edge', inc.sshd), 'unfixed');
  // at or above the upstream fix, on any branch, listed or not
  assert.equal(packageState('10.6_p2-r0', '3.15', inc.sshd), 'fixed');
  assert.equal(packageState('10.7_p1-r0', '', inc.sshd), 'fixed');
  // below it on a branch Alpine doesn't list: not judged
  assert.equal(packageState('8.8_p1-r9', '3.15', inc.sshd), 'unknown');
  assert.equal(packageState('10.3_p1-r9', '', inc.sshd), 'unknown');
  assert.equal(packageState('garbage', '3.24', inc.sshd), 'unknown');
});

test('the package database is read by stanza, and only the packages asked for', () => {
  const text = db({ 'openssh-server': '10.3_p1-r2', 'openssh-server-pam': '10.3_p1-r2', 'openssh-client-default': '10.3_p1-r1' });
  assert.deepEqual(installedVersions(text, ['openssh-server', 'openssh-server-pam']), { 'openssh-server': '10.3_p1-r2', 'openssh-server-pam': '10.3_p1-r2' });
  assert.deepEqual(installedVersions(db({ 'openssh-server-common': '1' }), ['openssh-server']), {});
});

test('sshd_config: first value wins, Include is read in place, a Match block is conditional', () => {
  const files = {
    '/etc/ssh/sshd_config': '# PasswordAuthentication no\nInclude sshd_config.d/*.conf\nPasswordAuthentication yes\nMatch User x\n  PasswordAuthentication yes\n',
    '/etc/ssh/sshd_config.d/10-a.conf': 'PasswordAuthentication=no\nUsePAM yes\n', '/etc/ssh/sshd_config.d/20-b.conf': 'PasswordAuthentication yes\n',
  };
  const io = { read: (p) => files[p] ?? null, list: (d) => (d === '/etc/ssh/sshd_config.d' ? ['20-b.conf', '10-a.conf', '.hidden.conf', 'x.txt'] : null) };
  const c = readSshdConfig('/etc/ssh/sshd_config', io);
  assert.deepEqual(c.problems, []);
  assert.deepEqual(c.files, ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/10-a.conf', '/etc/ssh/sshd_config.d/20-b.conf']);
  assert.equal(c.values.passwordauthentication.value, 'no');
  assert.deepEqual(c.values.passwordauthentication.conditional, ['yes']);
  assert.equal(maybeOn(c.values.passwordauthentication, (v) => v === 'yes'), null, 'off globally, on in a Match block: unknown, never off');
  assert.equal(c.values.usepam.value, 'yes');
  assert.equal(c.values.permitrootlogin.value, 'prohibit-password'); assert.equal(c.values.permitrootlogin.defaulted, true);
  // the old name of kbd-interactive is the same keyword
  assert.equal(readSshdConfig('/m', { read: () => 'ChallengeResponseAuthentication no\n', list: () => [] }).values.kbdinteractiveauthentication.value, 'no');
  // an unreadable Include, an unlistable folder and a folder pattern are problems, not silence
  assert.match(readSshdConfig('/m', { read: (p) => (p === '/m' ? 'Include /x/y.conf\n' : null), list: () => [] }).problems.join(), /\/x\/y\.conf could not be read/);
  assert.match(readSshdConfig('/m', { read: (p) => (p === '/m' ? 'Include /x/*.conf\n' : null), list: () => null }).problems.join(), /could not be listed/);
  assert.match(readSshdConfig('/m', { read: (p) => (p === '/m' ? 'Include /x/*/y.conf\n' : null), list: () => [] }).problems.join(), /pattern in a folder name/);
  assert.match(readSshdConfig('/m', { read: () => null, list: () => [] }).problems.join(), /\/m could not be read/);
  // an Include inside a Match block is conditional too
  const m = readSshdConfig('/m', { read: (p) => ({ '/m': 'Match Address 10.0.0.0/8\nInclude /i.conf\n', '/i.conf': 'PasswordAuthentication no\n' })[p] ?? null, list: () => [] });
  assert.equal(m.values.passwordauthentication.value, 'yes'); assert.deepEqual(m.values.passwordauthentication.conditional, ['no']);
  // a loop of Includes stops, as a problem
  const loop = readSshdConfig('/m', { read: () => 'Include /m\n', list: () => [] });
  assert.match(loop.problems.join(), /more than 16 levels/);
  // sshd's own limit (readconf.c, READCONF_MAX_DEPTH 16): the file itself and 16 levels of Include, then it stops
  assert.equal(loop.files.length, 17);
});

test('shadow counts carry no name, field or hash', () => {
  const c = shadowCounts(SHADOW);
  assert.deepEqual(c, { star: 1, rootStar: true, sha: 1, otherHash: 0, lines: 4, unreadable: 0 });
  assert.deepEqual(shadowCounts('a:$y$j9T$x:1\nb:$2b$xx:1\n'), { star: 0, rootStar: false, sha: 0, otherHash: 2, lines: 2, unreadable: 0 });
  assert.equal(shadowCounts('garbage\n').unreadable, 1);
  assert.equal(directoryAccounts('passwd: files ldap\n'), true); assert.equal(directoryAccounts('passwd: files\n'), false);
});

// ---- the verdicts ---------------------------------------------------------------------------------------------------
const NAMES = /\bada\b|\bdeploy\b|\$6\$salt|\$hash/;
test('every branch: the revision before the fix is EXPOSED, the fix itself is SAFE, and a SAFE names what it read', () => {
  for (const [branch, fixed] of Object.entries(SECDB)) {
    const ok = run(alpine({ branch, version: fixed }));
    assert.equal(ok.status, 'SAFE', `${branch} ${fixed}: ${ok.reason}`);
    assert.ok(ok.searched.includes('/lib/apk/db/installed') && ok.searched.includes('/etc/alpine-release'), ok.searched.join());
    assert.match(ok.reason, new RegExp(`fixed \\(Alpine's fix on this branch is ${fixed.replace(/\./g, '\\.')}\\)`));
    assert.match(ok.reason, /no sshd process is running/);
    if (fixed.endsWith('-r0')) continue;
    const bad = run(alpine({ branch, version: prior(fixed) }));
    assert.equal(bad.status, 'EXPOSED', `${branch} ${prior(fixed)}: ${bad.reason}`);
    assert.doesNotMatch(bad.reason, NAMES);
  }
});

test('an unfixed package: what Alpine says closes the hole makes REVIEW, never SAFE; anything unread stays EXPOSED', () => {
  const v = '10.3_p1-r1';
  const off = run(alpine({ version: v, dropins: { '00-no.conf': 'PasswordAuthentication no\n' } }));
  assert.equal(off.status, 'REVIEW'); assert.match(off.reason, /PasswordAuthentication is no in \/etc\/ssh\/sshd_config, \/etc\/ssh\/sshd_config\.d\/00-no\.conf/);
  // off in a drop-in, on in a Match block: not ruled out
  const match = run(alpine({ version: v, dropins: { '00-no.conf': 'PasswordAuthentication no\n' }, config: 'Include /etc/ssh/sshd_config.d/*.conf\nMatch User git\n  PasswordAuthentication yes\n' }));
  assert.equal(match.status, 'EXPOSED'); assert.match(match.reason, /set otherwise inside one/);
  // the PAM build with UsePAM yes, alone
  const pam = run(alpine({ version: v, pkg: 'openssh-server-pam', dropins: { 'pam.conf': 'UsePAM yes\n' } }));
  assert.equal(pam.status, 'REVIEW'); assert.match(pam.reason, /only openssh-server-pam is installed, and UsePAM is yes/);
  // the PAM build with UsePAM no (the default), or beside the plain build: open
  assert.equal(run(alpine({ version: v, pkg: 'openssh-server-pam' })).status, 'EXPOSED');
  assert.equal(run(alpine({ version: v, pkg: 'openssh-server-pam', extra: { 'openssh-server': v }, dropins: { 'pam.conf': 'UsePAM yes\n' } })).status, 'EXPOSED');
  // no $-hash at all, or no account with * that can log in
  assert.equal(run(alpine({ version: v, shadow: 'root:*::0:::::\ndeploy:*:1::::::\n' })).status, 'REVIEW');
  const rootOnly = run(alpine({ version: v, shadow: 'root:*::0:::::\nada:$6$s$h:1::::::\n' }));
  assert.equal(rootOnly.status, 'REVIEW'); assert.match(rootOnly.reason, /root has, and PermitRootLogin is not yes/);
  assert.equal(run(alpine({ version: v, shadow: 'root:*::0:::::\nada:$6$s$h:1::::::\n', dropins: { 'r.conf': 'PermitRootLogin yes\n' } })).status, 'EXPOSED', 'root with PermitRootLogin yes counts');
  // a directory service's accounts have no shadow entry
  const nss = alpine({ version: v, shadow: 'ada:$6$s$h:1::::::\n' }); nss.read2 = nss.read;
  const withNss = { ...nss, read: (p) => (p === '/etc/nsswitch.conf' ? 'passwd: files ldap\n' : nss.read2(p)) };
  assert.equal(run(withNss).status, 'EXPOSED');
  // a $-hash Alpine doesn't name: not ruled out
  assert.equal(run(alpine({ version: v, shadow: 'deploy:*:1::::::\nada:$y$j9T$x:1::::::\n' })).status, 'EXPOSED');
  // /etc/shadow unreadable (not root): EXPOSED, and the reason says what was not read
  const noShadow = run(alpine({ version: v, shadow: null }));
  assert.equal(noShadow.status, 'EXPOSED'); assert.match(noShadow.reason, /Not read: \/etc\/shadow \(only root can read it\)/);
  // start-up options in /etc/conf.d/sshd can change any setting: they are named as not read, and nothing is ruled out by config
  const opts = run(alpine({ version: v, confd: 'SSHD_OPTS="-o PasswordAuthentication=yes"\n', dropins: { '00-no.conf': 'PasswordAuthentication no\n' } }));
  assert.equal(opts.status, 'EXPOSED'); assert.match(opts.reason, /\/etc\/conf\.d\/sshd sets start-up options/);
  // an unreadable drop-in: the same
  const m = alpine({ version: v, dropins: { 'a.conf': 'PasswordAuthentication no\n' } });
  const lockedDrop = { ...m, read: (p) => (p === '/etc/ssh/sshd_config.d/a.conf' ? null : m.read(p)) };
  assert.equal(run(lockedDrop).status, 'EXPOSED');
  // and the counts never carry a name or a hash
  for (const r of [off, match, pam, rootOnly, noShadow, opts]) assert.doesNotMatch(r.reason, NAMES);
});

test('a fixed package with an sshd started before the program changed is UNKNOWN: restart it', () => {
  const fixed = SECDB['3.24'];
  const stale = run(alpine({ version: fixed, procs: { procs: [{ pid: 412, start: 500 }] }, mtimes: { '/usr/sbin/sshd': 1000 } }));
  assert.equal(stale.status, 'UNKNOWN'); assert.match(stale.reason, /sshd process 412 started before/); assert.match(stale.reason, /rc-service sshd restart/);
  // within two seconds is not told apart
  assert.equal(run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 2500 }] }, mtimes: { '/usr/sbin/sshd': 1000 } })).status, 'UNKNOWN');
  const fresh = run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 5000 }] }, mtimes: { '/usr/sbin/sshd': 1000 } }));
  assert.equal(fresh.status, 'SAFE'); assert.match(fresh.reason, /every running sshd \(1\) started after its program was last changed/);
  assert.equal(run(alpine({ version: fixed, procs: { procs: [], problem: 'process 1 is not listed in /proc' } })).status, 'UNKNOWN');
  assert.equal(run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 5000 }] }, mtimes: {} })).status, 'UNKNOWN', 'a program time that cannot be read');
});

test('what can\'t be placed is UNKNOWN; what is not this flaw\'s ground is SAFE with what it read', () => {
  assert.equal(run(machine(), 'win32').status, 'UNKNOWN');
  const mac = run(machine(), 'darwin'); assert.equal(mac.status, 'SAFE'); assert.match(mac.reason, /^not Linux: /); assert.deepEqual(mac.searched, ['this system is macOS, not Linux']);
  const glibc = run(machine({ dirs: { '/lib': ['x86_64-linux-gnu', 'ld-linux-x86-64.so.2'] } }));
  assert.equal(glibc.status, 'SAFE'); assert.match(glibc.reason, /^not a musl system: no \/etc\/alpine-release and no musl loader/); assert.ok(glibc.searched.includes('/lib'));
  assert.equal(run(machine({ dirs: {} })).status, 'UNKNOWN', '/lib unlistable');
  assert.equal(run(machine({ files: { '/etc/alpine-release': null }, dirs: { '/lib': [] } })).status, 'UNKNOWN', 'release file there, unreadable');
  // Alpine, the database unreadable
  const a = alpine({ version: '10.3_p1-r2' }); const noDb = { ...a, read: (p) => (p === '/lib/apk/db/installed' ? null : a.read(p)) };
  const nd = run(noDb); assert.equal(nd.status, 'UNKNOWN'); assert.match(nd.reason, /^\/lib\/apk\/db\/installed could not be read/);
  // the same with no sshd program in the usual places: the database is what would say one is installed, so still UNKNOWN
  const bare = { ...noDb, state: (p) => (p === '/usr/sbin/sshd' ? 'gone' : a.state(p)) };
  const nb = run(bare); assert.equal(nb.status, 'UNKNOWN', nb.reason); assert.match(nb.reason, /^\/lib\/apk\/db\/installed could not be read/);
  // Alpine with no openssh-server: SAFE when no sshd program is there, UNKNOWN when one is
  const none = machine({ files: { '/etc/alpine-release': '3.24.4\n', '/lib/apk/db/installed': db({ musl: '1' }) }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } });
  const noPkg = run(none); assert.equal(noPkg.status, 'SAFE'); assert.match(noPkg.reason, /neither openssh-server nor openssh-server-pam is installed/);
  const built = machine({ files: { '/etc/alpine-release': '3.24.4\n', '/lib/apk/db/installed': db({ musl: '1' }), '/usr/local/sbin/sshd': 'ELF' }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } });
  assert.equal(run(built).status, 'UNKNOWN');
  // musl without apk (Void, Chimera): sshd there → UNKNOWN; none → SAFE
  const voidSshd = machine({ files: { '/usr/sbin/sshd': 'ELF' }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } });
  assert.equal(run(voidSshd).status, 'UNKNOWN');
  assert.equal(run(machine({ dirs: { '/lib': ['ld-musl-aarch64.so.1'] } })).status, 'SAFE');
  // a branch Alpine doesn't list, below the upstream fix; a release file this can't read as a branch
  assert.equal(run(machine({ files: { '/etc/alpine-release': '3.15.11\n', '/lib/apk/db/installed': db({ 'openssh-server': '8.8_p1-r9' }) }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } })).status, 'UNKNOWN');
  assert.equal(run(machine({ files: { '/etc/alpine-release': 'weird\n', '/lib/apk/db/installed': db({ 'openssh-server': '10.3_p1-r2' }) }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } })).status, 'UNKNOWN');
  // an unreadable version in the database
  assert.equal(run(alpine({ version: '10.3p1' })).status, 'UNKNOWN');
});

test('sshdProcesses: the start-time reading is checked on this process before it is believed', () => {
  const now = 1_800_000_000_000, uptime = 5, btime = 1_799_990_000;
  const ticks = (ms) => Math.round((ms / 1000 - btime) * 100);
  const stat = (pid, name, startMs) => `${pid} (${name}) S 1 1 1 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 ${ticks(startMs)} 1000 100 18446744073709551615`;
  const files = { '/proc/stat': `cpu 1 2 3\nbtime ${btime}\n`, '/proc/self/stat': stat(77, 'node', now - uptime * 1000), '/proc/1/stat': stat(1, 'init', now - 9e6), '/proc/412/stat': stat(412, 'sshd', now - 6e6), '/proc/413/stat': stat(413, 'sshd-session', now - 1000), '/proc/414/stat': stat(414, 'my (sshd) app', now - 1000) };
  const io = (over = {}) => ({ read: (p) => ({ ...files, ...over })[p] ?? null, list: (d) => (d === '/proc' ? ['1', '412', '413', '414', 'self', 'stat'] : null), now, uptime });
  const r = sshdProcesses(io());
  assert.equal(r.problem, undefined); assert.deepEqual(r.procs.map((p) => p.pid), [412]);
  assert.ok(Math.abs(r.procs[0].start - (now - 6e6)) < 20);
  // the control: a /proc whose clock disagrees with this process's own start (USER_HZ not 100) is not believed
  assert.match(sshdProcesses(io({ '/proc/self/stat': stat(77, 'node', now - 60_000) })).problem, /did not match its real start/);
  assert.match(sshdProcesses({ ...io(), list: () => ['412'] }).problem, /process 1 is not listed/);
  assert.match(sshdProcesses(io({ '/proc/stat': 'cpu 1\n' })).problem, /boot time/);
});

// ---- the command, on a stand-in Linux root ------------------------------------------------------------------------------
// test/support/fake-root.cjs maps /etc, /lib, /usr, /sbin and /proc onto a folder of this test's and says the platform
// is linux. Nothing of this machine's system folders is read; nothing is run.
function rig(build) {
  const root = mkdtempSync(join(dir, 'root-'));
  const put = (p, t) => { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), t); };
  build(put);
  const startMs = Date.now();
  const btime = Math.floor(startMs / 1000) - 3600;
  put('/proc/stat', `cpu 1\nbtime ${btime}\n`);
  put('/proc/self/stat', `77 (node) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 ${Math.round((startMs / 1000 - btime) * 100)} 0 0`);
  put('/proc/1/stat', '1 (init) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0');
  const home = join(root, 'home-of-test'); mkdirSync(home);
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
  const go = (json) => {
    const r = spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'fake-root.cjs'), BIN, '--incident', 'sshole-2026-11', '--no-containers', ...(json ? ['--json'] : [])], { encoding: 'utf8', env: { ...env, HOME: home, WL_FAKE_ROOT: root, WL_FAKE_PLATFORM: 'linux' } });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  return go;
}
const alpineRoot = (version, extra = () => {}) => (put) => {
  put('/etc/alpine-release', '3.24.3\n'); put('/lib/ld-musl-x86_64.so.1', 'ELF');
  put('/lib/apk/db/installed', db({ musl: '1.2.5-r10', 'openssh-server': version }));
  put('/etc/ssh/sshd_config', 'Include /etc/ssh/sshd_config.d/*.conf\n'); put('/etc/ssh/sshd_config.d/.keep', '');
  put('/usr/sbin/sshd', 'ELF'); put('/etc/shadow', SHADOW);
  extra(put);
};

test('the command: an unfixed Alpine sshd is EXPOSED with exit 1, its fix is Alpine\'s, and no account leaks', () => {
  const go = rig(alpineRoot('10.3_p1-r1'));
  const j = go(true);
  assert.ok(j.out, j.err);
  const rows = JSON.parse(j.out).results.filter((r) => r.incident === 'sshole-2026-11');
  assert.equal(rows.length, 1, JSON.stringify(rows));
  assert.equal(rows[0].status, 'EXPOSED', rows[0].reason);
  assert.equal(j.code, 1);
  assert.equal(rows[0].fix, inc.fix);
  const t = go(false);
  assert.match(t.out, /EXPOSED {2}openssh-server 10\.3_p1-r1 on Alpine 3\.24/);
  assert.match(t.out, /fix: Update openssh and restart sshd/);
  assert.doesNotMatch(`${t.out}${j.out}${t.err}${j.err}`, NAMES);
});

test('the command: the fixed revision is SAFE with exit 0, and names what it read', () => {
  const go = rig(alpineRoot('10.3_p1-r2'));
  const j = go(true);
  const rows = JSON.parse(j.out).results.filter((r) => r.incident === 'sshole-2026-11');
  assert.equal(rows.length, 1); assert.equal(rows[0].status, 'SAFE', rows[0].reason);
  assert.equal(j.code, 0, j.err);
  assert.ok(rows[0].searched.length >= 3);
  // and with an sshd started an hour before the program changed: UNKNOWN, exit 2
  const stale = rig(alpineRoot('10.3_p1-r2', (put) => put('/proc/412/stat', '412 (sshd) S 1 412 412 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0')));
  const s = stale(true);
  const row = JSON.parse(s.out).results.find((r) => r.incident === 'sshole-2026-11');
  assert.equal(row.status, 'UNKNOWN', row.reason); assert.equal(s.code, 2);
});

test('no account name, password field or hash from /etc/shadow reaches any line, on every path that reads it', () => {
  // distinctive names at the top, middle and bottom of the file, so a leak of any one line's field shows
  const names = ['zqtopuser', 'zqmiduser', 'zqlastuser'];
  const shadows = [
    `${names[0]}:*:1::::::\nroot:*::0:::::\n${names[1]}:$6$zqsalt$zqhashvalue:1::::::\n${names[2]}:!:1::::::\n`,
    `${names[0]}:$6$zqsalt$zqhashvalue:1::::::\n${names[1]}:!:1::::::\n${names[2]}:!:1::::::\n`,
    `${names[0]}:*:1::::::\n${names[1]}:$y$zqsalt$zqhashvalue:1::::::\n${names[2]}:*:1::::::\n`,
    `${names[0]}\n${names[1]}:*:1::::::\n`,
  ];
  const leak = /zq/;
  const seen = new Set();
  for (const shadow of shadows) for (const version of ['10.3_p1-r1', '10.3_p1-r2']) for (const dropins of [{}, { 'r.conf': 'PermitRootLogin yes\n' }]) {
    const r = run(alpine({ version, shadow, dropins }));
    seen.add(r.status);
    assert.doesNotMatch(`${r.reason} ${JSON.stringify(r.searched ?? [])}`, leak, `${r.status}: ${r.reason}`);
  }
  // the loop reached the paths that read the file: EXPOSED, REVIEW and SAFE all came up
  assert.deepEqual([...seen].sort(), ['EXPOSED', 'REVIEW', 'SAFE']);
});
