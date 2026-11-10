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
import { apkParse, apkCompare, alpineBranch, packageState, installedPackages, readSshdConfig, maybeOn, shadowCounts, passwdCounts, directoryAccounts, sshdProcesses, checkSshole } from '../lib/sshd.mjs';

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
function machine({ files = {}, dirs = {}, changed = {}, procs = { procs: [] } } = {}) {
  const root = mkdtempSync(join(dir, 'm-'));
  for (const d of ['/proc', ...Object.keys(dirs)]) mkdirSync(join(root, d), { recursive: true });
  for (const [p, t] of Object.entries(files)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), t ?? ''); }
  const read = (p) => (p in files ? files[p] : null);
  const list = (d) => (d in dirs ? dirs[d] : null);
  const state = (p) => (p in files ? (files[p] === null ? 'denied' : 'file') : p in dirs ? 'dir' : 'gone');
  const asked = [];
  const head = (p) => (typeof files[p] === 'string' ? Buffer.from(files[p], 'latin1') : null);
  return { root, read: (p) => { asked.push(p); return read(p); }, list, state, head, real: (p) => p, changed: (p) => changed[p], procs: () => procs, asked };
}
// a stanza as apk writes it, with the files each server package installs (aports main/openssh: sshd, sshd.pam, sshd.krb5)
const OWN = { 'openssh-server': 'sshd', 'openssh-server-pam': 'sshd.pam', 'openssh-server-krb5': 'sshd.krb5' };
const db = (pkgs) => Object.entries(pkgs).map(([p, v]) => `C:Q1abc=\nP:${p}\nV:${v}\nA:x86_64\nS:1\nI:2\nT:t\n${OWN[p] ? `F:usr/sbin\nR:${OWN[p]}\nZ:Q1x=\n` : ''}`).join('\n') + '\n';
const SHADOW = 'root:*::0:::::\nbin:!::0:::::\nada:$6$salt$hash:20000:0:99999:7:::\ndeploy:*:20000:0:99999:7:::\n';
function alpine({ branch = '3.24', version, pkg = 'openssh-server', extra = {}, config = 'Include /etc/ssh/sshd_config.d/*.conf\n', confd = '#SSHD_OPTS=""\n', shadow = SHADOW, dropins = {}, procs, changed, files: more = {}, dirs: moreDirs = {} } = {}) {
  const files = {
    '/etc/alpine-release': `${RELEASE[branch]}\n`,
    '/lib/apk/db/installed': db({ 'musl': '1.2.5-r10', [pkg]: version ?? SECDB[branch], ...extra }),
    '/etc/ssh/sshd_config': config, '/etc/conf.d/sshd': confd,
    ...Object.fromEntries(Object.keys({ [pkg]: 1, ...extra }).filter((p) => OWN[p]).map((p) => [`/usr/sbin/${OWN[p]}`, 'ELF'])),
    ...(shadow === undefined ? {} : { '/etc/shadow': shadow }),
  };
  for (const [n, t] of Object.entries(dropins)) files[`/etc/ssh/sshd_config.d/${n}`] = t;
  Object.assign(files, more);
  return machine({ files, dirs: { '/lib': ['ld-musl-x86_64.so.1', 'apk'], '/etc/ssh/sshd_config.d': Object.keys(dropins), ...moreDirs }, procs, changed: changed ?? { '/usr/sbin/sshd': 1000, '/usr/sbin/sshd.pam': 1000, '/usr/sbin/sshd.krb5': 1000 } });
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
    assert.equal(packageState(fixed, inc.sshd), 'fixed', `${branch} ${fixed}`);
    if (!fixed.endsWith('-r0')) assert.equal(packageState(prior(fixed), inc.sshd), 'unfixed', `${branch} ${prior(fixed)}`);
  }
  // the backport trap: 10.3_p1-r1 is fixed nowhere, though 10.3 < 10.6 says nothing
  assert.equal(packageState('10.3_p1-r1', inc.sshd), 'unfixed');
  // edge's fix is the upstream one; one below it, of an upstream version Alpine has no fixed build of
  assert.equal(packageState('10.6_p1-r0', inc.sshd), 'unfixed');
  // at or above the upstream fix, on any branch
  assert.equal(packageState('10.6_p2-r0', inc.sshd), 'fixed');
  assert.equal(packageState('10.7_p1-r0', inc.sshd), 'fixed');
  // a later revision of a fixed build keeps the patch; an older version Alpine never fixed (3.15's 8.8) is not fixed
  assert.equal(packageState('10.3_p1-r9', inc.sshd), 'fixed');
  assert.equal(packageState('8.8_p1-r9', inc.sshd), 'unfixed');
  assert.equal(packageState('10.1_p1-r3', inc.sshd), 'unfixed', 'no fixed build of 10.1 exists');
  assert.equal(packageState('garbage', inc.sshd), 'unknown');
});

test('the package database is read by stanza, and only the packages asked for', () => {
  const text = db({ 'openssh-server': '10.3_p1-r2', 'openssh-server-pam': '10.3_p1-r2', 'openssh-client-default': '10.3_p1-r1' });
  assert.deepEqual(installedPackages(text, ['openssh-server', 'openssh-server-pam']), { 'openssh-server': { version: '10.3_p1-r2', files: ['/usr/sbin/sshd'] }, 'openssh-server-pam': { version: '10.3_p1-r2', files: ['/usr/sbin/sshd.pam'] } });
  assert.deepEqual(installedPackages(db({ 'openssh-server-common': '1' }), ['openssh-server']), {});
  // CRLF and a repeated stanza: the first wins, the line ends don't stick to the version
  assert.deepEqual(installedPackages(text.replace(/\n/g, '\r\n') + 'P:openssh-server\nV:1.0-r0\n', ['openssh-server']), { 'openssh-server': { version: '10.3_p1-r2', files: ['/usr/sbin/sshd'] } });
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
    assert.match(ok.reason, new RegExp(`fixed \\(Alpine's fixed build is ${fixed.replace(/\./g, '\\.')}\\)`));
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
  assert.equal(off.status, 'REVIEW'); assert.match(off.reason, /PasswordAuthentication is no \(\/etc\/ssh\/sshd_config, \/etc\/ssh\/sshd_config\.d\/00-no\.conf\)/);
  assert.match(off.reason, /Alpine's advisory says the flaw needs that\. Update anyway: if that changes later, the hole is open again$/);
  // off in a drop-in, on in a Match block: not ruled out
  const match = run(alpine({ version: v, dropins: { '00-no.conf': 'PasswordAuthentication no\n' }, config: 'Include /etc/ssh/sshd_config.d/*.conf\nMatch User git\n  PasswordAuthentication yes\n' }));
  assert.equal(match.status, 'EXPOSED'); assert.match(match.reason, /PasswordAuthentication is no, but a Match block in .* sets it again for some logins/);
  // the PAM build with UsePAM yes, alone
  const pam = run(alpine({ version: v, pkg: 'openssh-server-pam', dropins: { 'pam.conf': 'UsePAM yes\n' } }));
  assert.equal(pam.status, 'REVIEW'); assert.match(pam.reason, /only Alpine's PAM build is installed \(openssh-server-pam\), with UsePAM yes/);
  // the PAM build with UsePAM no (the default), or beside the plain build: open
  assert.equal(run(alpine({ version: v, pkg: 'openssh-server-pam' })).status, 'EXPOSED');
  assert.equal(run(alpine({ version: v, pkg: 'openssh-server-pam', extra: { 'openssh-server': v }, dropins: { 'pam.conf': 'UsePAM yes\n' } })).status, 'EXPOSED');
  // no $-hash at all, or no account with * that can log in
  assert.equal(run(alpine({ version: v, shadow: 'root:*::0:::::\ndeploy:*:1::::::\n' })).status, 'REVIEW');
  const rootOnly = run(alpine({ version: v, shadow: 'root:*::0:::::\nada:$6$s$h:1::::::\n' }));
  assert.equal(rootOnly.status, 'REVIEW'); assert.match(rootOnly.reason, /no account has the field \* \(root does, but PermitRootLogin is not yes\) \(2 accounts read\)/);
  assert.equal(run(alpine({ version: v, shadow: 'root:*::0:::::\nada:$6$s$h:1::::::\n', dropins: { 'r.conf': 'PermitRootLogin yes\n' } })).status, 'EXPOSED', 'root with PermitRootLogin yes counts');
  // a directory service's accounts have no shadow entry
  const nss = alpine({ version: v, shadow: 'ada:$6$s$h:1::::::\n' }); nss.read2 = nss.read;
  const withNss = { ...nss, read: (p) => (p === '/etc/nsswitch.conf' ? 'passwd: files ldap\n' : nss.read2(p)) };
  assert.equal(run(withNss).status, 'EXPOSED');
  // a $-hash Alpine doesn't name: not ruled out
  assert.equal(run(alpine({ version: v, shadow: 'deploy:*:1::::::\nada:$y$j9T$x:1::::::\n' })).status, 'EXPOSED');
  // /etc/shadow unreadable (not root): EXPOSED, and the reason says what was not read
  const noShadow = run(alpine({ version: v, shadow: null }));
  assert.equal(noShadow.status, 'EXPOSED'); assert.match(noShadow.reason, /Not read: \/etc\/shadow \(usually only root can read it\), so it was not checked whether there is both/);
  // start-up options in /etc/conf.d/sshd can change any setting: they are named as not read, and nothing is ruled out by config
  const opts = run(alpine({ version: v, confd: 'SSHD_OPTS="-o PasswordAuthentication=yes"\n', dropins: { '00-no.conf': 'PasswordAuthentication no\n' } }));
  assert.equal(opts.status, 'EXPOSED'); assert.match(opts.reason, /\/etc\/conf\.d\/sshd sets start-up options/);
  for (const confd of ['export command_args="-o PasswordAuthentication=yes"\n', 'SSHD_OPTS=" -o PasswordAuthentication=yes"\n', 'SSHD_OPTS="\n-o PasswordAuthentication=yes"\n', 'cfgfile=/etc/ssh/other_config\n']) assert.equal(run(alpine({ version: v, confd, dropins: { '00-no.conf': 'PasswordAuthentication no\n' } })).status, 'EXPOSED', confd);
  // a second instance of sshd has its own options and its own configuration
  const two = run(alpine({ version: v, dropins: { '00-no.conf': 'PasswordAuthentication no\n' }, dirs: { '/etc/conf.d': ['sshd', 'sshd.two'], '/etc/init.d': ['sshd', 'sshd.two'] } }));
  assert.equal(two.status, 'EXPOSED'); assert.match(two.reason, /another sshd instance is set up \(\/etc\/conf\.d\/sshd\.two, \/etc\/init\.d\/sshd\.two\)/);
  // an unreadable drop-in: the same
  const m = alpine({ version: v, dropins: { 'a.conf': 'PasswordAuthentication no\n' } });
  const lockedDrop = { ...m, read: (p) => (p === '/etc/ssh/sshd_config.d/a.conf' ? null : m.read(p)) };
  assert.equal(run(lockedDrop).status, 'EXPOSED');
  // and the counts never carry a name or a hash
  for (const r of [off, match, pam, rootOnly, noShadow, opts]) assert.doesNotMatch(r.reason, NAMES);
});

test('a fixed package with an sshd started before the program changed is UNKNOWN: restart it', () => {
  const fixed = SECDB['3.24'];
  const stale = run(alpine({ version: fixed, procs: { procs: [{ pid: 412, start: 500 }] }, changed: { '/usr/sbin/sshd': 1000 } }));
  assert.equal(stale.status, 'UNKNOWN'); assert.match(stale.reason, /sshd \(process 412\) was started before the fixed program was installed/); assert.match(stale.reason, /rc-service sshd restart/);
  // within two seconds is not told apart
  assert.equal(run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 2500 }] }, changed: { '/usr/sbin/sshd': 1000 } })).status, 'UNKNOWN');
  const fresh = run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 5000 }] }, changed: { '/usr/sbin/sshd': 1000 } }));
  assert.equal(fresh.status, 'SAFE'); assert.match(fresh.reason, /every running sshd \(1\) started after its program was installed/);
  assert.equal(run(alpine({ version: fixed, procs: { procs: [], problem: 'process 1 is not listed in /proc' } })).status, 'UNKNOWN');
  assert.equal(run(alpine({ version: fixed, procs: { procs: [{ pid: 9, start: 5000 }] }, changed: {} })).status, 'UNKNOWN', 'a program time that cannot be read');
  // the PAM build's program is the one that counts when it is installed
  assert.equal(run(alpine({ version: fixed, pkg: 'openssh-server-pam', procs: { procs: [{ pid: 9, start: 1500 }] }, changed: { '/usr/sbin/sshd.pam': 3000 } })).status, 'UNKNOWN');
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
  const noPkg = run(none); assert.equal(noPkg.status, 'SAFE'); assert.match(noPkg.reason, /no openssh server package is installed/);
  const built = machine({ files: { '/etc/alpine-release': '3.24.4\n', '/lib/apk/db/installed': db({ musl: '1' }), '/usr/local/sbin/sshd': 'ELF' }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } });
  assert.equal(run(built).status, 'UNKNOWN');
  // musl without apk (Void, Chimera): sshd there → UNKNOWN; none → SAFE
  const voidSshd = machine({ files: { '/usr/sbin/sshd': 'ELF' }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } });
  assert.equal(run(voidSshd).status, 'UNKNOWN');
  const voidNone = run(machine({ dirs: { '/lib': ['ld-musl-aarch64.so.1'] } }));
  assert.equal(voidNone.status, 'SAFE'); assert.match(voidNone.reason, /^musl libc \(\/lib\/ld-musl-aarch64\.so\.1\), and no sshd program at /);
  // a branch Alpine doesn't list, below the upstream fix; a release file this can't read as a branch
  // 3.15, which Alpine published no fix for: its 8.8 build is not a fixed one, so it is judged as unfixed, never SAFE
  const old = run(machine({ files: { '/etc/alpine-release': '3.15.11\n', '/lib/apk/db/installed': db({ 'openssh-server': '8.8_p1-r9' }), '/usr/sbin/sshd': 'ELF', '/etc/ssh/sshd_config': '', '/etc/shadow': SHADOW }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } }));
  assert.equal(old.status, 'EXPOSED', old.reason); assert.match(old.reason, /Alpine lists no fixed build of this OpenSSH version/);
  // a release file this can't name, with a fixed build: judged by the build
  assert.equal(run(machine({ files: { '/etc/alpine-release': 'weird\n', '/lib/apk/db/installed': db({ 'openssh-server': '10.3_p1-r2' }), '/usr/sbin/sshd': 'ELF' }, dirs: { '/lib': ['ld-musl-x86_64.so.1'] } })).status, 'SAFE');
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
  build(put, root);
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
const alpineRoot = (version, extra = () => {}) => (put, root) => {
  put('/etc/alpine-release', '3.24.3\n'); put('/lib/ld-musl-x86_64.so.1', 'ELF');
  put('/lib/apk/db/installed', db({ musl: '1.2.5-r10', 'openssh-server': version }));
  put('/etc/ssh/sshd_config', 'Include /etc/ssh/sshd_config.d/*.conf\n'); put('/etc/ssh/sshd_config.d/.keep', '');
  put('/usr/sbin/sshd', 'ELF'); put('/etc/shadow', SHADOW);
  extra(put, root);
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

// ---- the 0.1.15 review (9 Nov 2026): each of these read SAFE, or REVIEW where Alpine says exposed, or stopped the run -------
test('R1 a package pinned from another branch is judged as the build it is', () => {
  // 3.23's release file with 3.24's unfixed build read SAFE ("fixed on this branch is 10.2_p1-r1")
  const pinned = run(alpine({ branch: '3.23', version: '10.3_p1-r1' }));
  assert.equal(pinned.status, 'EXPOSED', pinned.reason); assert.match(pinned.reason, /Alpine's fixed build is 10\.3_p1-r2/);
  assert.equal(run(alpine({ branch: '3.23', version: '10.3_p1-r2' })).status, 'SAFE');
  // edge's 10.6_p1 on a 3.2x release
  assert.equal(run(alpine({ branch: '3.22', version: '10.6_p1-r1' })).status, 'EXPOSED');
});

test('R2 the Kerberos build is a PAM build: on its own with UsePAM no it is exposed, and its daemon counts', () => {
  const k = run(alpine({ version: '10.3_p1-r1', pkg: 'openssh-server-krb5', dropins: { 'k.conf': 'GSSAPIAuthentication yes\n' } }));
  assert.equal(k.status, 'EXPOSED', k.reason); assert.match(k.reason, /^openssh-server-krb5 10\.3_p1-r1 on Alpine 3\.24/);
  assert.equal(run(alpine({ version: '10.3_p1-r1', pkg: 'openssh-server-krb5', dropins: { 'k.conf': 'UsePAM yes\n' } })).status, 'REVIEW');
  // a running sshd.krb5 is a running sshd
  const now = 1_800_000_000_000, uptime = 5, btime = 1_799_990_000;
  const stat = (pid, name, ms) => `${pid} (${name}) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 ${Math.round((ms / 1000 - btime) * 100)} 0 0`;
  const files = { '/proc/stat': `btime ${btime}\n`, '/proc/self/stat': stat(7, 'node', now - uptime * 1000), '/proc/1/stat': stat(1, 'init', now - 9e6), '/proc/50/stat': stat(50, 'sshd.krb5', now - 1000), '/proc/51/stat': stat(51, 'sshd.pam', now - 1000) };
  const p = sshdProcesses({ read: (x) => files[x] ?? null, list: () => ['1', '50', '51', 'self'], now, uptime });
  assert.deepEqual(p.procs.map((x) => x.pid), [50, 51]);
});

test('R3 the stale-daemon check uses when the program was installed, not the time apk stamps on it', () => {
  // apk sets a file's mtime from the package (build time); only the inode's change time says when it was installed
  const go = rig(alpineRoot('10.3_p1-r2', (put, root) => {
    put('/proc/412/stat', `412 (sshd) S 1 412 412 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 ${(3600 - 60) * 100} 0 0`);   // started a minute ago
    const old = new Date(Date.now() - 3 * 86400e3); fs.utimesSync(join(root, 'usr/sbin/sshd'), old, old);           // "built" three days ago
  }));
  // the program was installed just now (its ctime), after the daemon started: UNKNOWN, restart it
  const row = JSON.parse(go(true).out).results.find((x) => x.incident === 'sshole-2026-11');
  assert.equal(row.status, 'UNKNOWN', row.reason); assert.match(row.reason, /was started before the fixed program was installed/);
});

test('R4 an sshd apk didn\'t install, beside a fixed package, is UNKNOWN', () => {
  const m = run(alpine({ version: '10.3_p1-r2', files: { '/usr/local/sbin/sshd': 'ELF' } }));
  assert.equal(m.status, 'UNKNOWN', m.reason); assert.match(m.reason, /an sshd apk didn't install at \/usr\/local\/sbin\/sshd/);
});

test('R5 a [ in an Include pattern is a setting not read, never a stopped run', () => {
  const r = run(alpine({ version: '10.3_p1-r1', config: 'Include /etc/ssh/sshd_config.d/*[.conf\nPasswordAuthentication no\n' }));
  assert.equal(r.status, 'EXPOSED', r.reason); assert.match(r.reason, /uses a \[ \] pattern/);
  // through the command: the row is there and the run ends as an EXPOSED run does (0.1.15's first build stopped, exit 2)
  const go = rig(alpineRoot('10.3_p1-r1', (put) => put('/etc/ssh/sshd_config', 'Include /etc/ssh/sshd_config.d/*[.conf\n')));
  const j = go(true);
  assert.ok(j.out, j.err);
  const row = JSON.parse(j.out).results.find((x) => x.incident === 'sshole-2026-11');
  assert.equal(row?.status, 'EXPOSED', j.err); assert.equal(j.code, 1);
});

test('R6 quoted values are the word inside, and only an exact no closes the hole', () => {
  const q = run(alpine({ version: '10.3_p1-r1', dropins: { 'q.conf': 'PasswordAuthentication "yes"\n' } }));
  assert.equal(q.status, 'EXPOSED', q.reason);
  assert.equal(run(alpine({ version: '10.3_p1-r1', dropins: { 'q.conf': 'PasswordAuthentication "no"\n' } })).status, 'REVIEW');
  assert.equal(run(alpine({ version: '10.3_p1-r1', pkg: 'openssh-server-pam', dropins: { 'q.conf': 'UsePAM "no"\n' } })).status, 'EXPOSED');
  assert.equal(run(alpine({ version: '10.3_p1-r1', pkg: 'openssh-server-pam', dropins: { 'q.conf': 'UsePAM maybe\n' } })).status, 'EXPOSED', 'only an exact yes turns PAM on');
  assert.equal(run(alpine({ version: '10.3_p1-r1', dropins: { 'q.conf': 'PasswordAuthentication maybe\n' } })).status, 'EXPOSED', 'a value sshd would refuse is not "no"');
});

test('R8 accounts this check can\'t see in /etc/shadow are not ruled out', () => {
  // a directory service: its accounts have no shadow line and their hashes are not read, so "no $-hash" proves nothing
  const nss = alpine({ version: '10.3_p1-r1', shadow: 'root:*::0:::::\ndeploy:*:1::::::\n' });
  const withNss = { ...nss, read: (p) => (p === '/etc/nsswitch.conf' ? 'passwd: files sss\n' : nss.read(p)) };
  const d = run(withNss); assert.equal(d.status, 'EXPOSED', d.reason); assert.match(d.reason, /directory service/);
  // a local account with * in /etc/passwd and no shadow line counts as one with no password
  const pw = alpine({ version: '10.3_p1-r1', shadow: 'root:*::0:::::\nada:$6$s$h:1::::::\n' });
  const withPw = { ...pw, read: (p) => (p === '/etc/passwd' ? 'root:x:0:0::/root:/bin/sh\nada:x:1:1::/home/ada:/bin/sh\nsvc:*:2:2::/home/svc:/bin/sh\n' : pw.read(p)) };
  assert.equal(run(withPw).status, 'EXPOSED');
  assert.deepEqual(passwdCounts('svc:*:2:2:::\nada:x:1:1:::\nold:$6$a$b:3:3:::\n', new Set(['ada'])), { star: 1, sha: 1, otherHash: 0 });
  assert.deepEqual(passwdCounts('svc:*:2:2:::\n', null), { star: 0, sha: 0, otherHash: 0 });
  // an unsplittable shadow line with no hash: not ruled out, and the reason says so
  const bad = run(alpine({ version: '10.3_p1-r1', shadow: 'garbage\ndeploy:*:1::::::\n' }));
  assert.equal(bad.status, 'EXPOSED', bad.reason); assert.match(bad.reason, /1 line of \/etc\/shadow/);
  // a $-hash Alpine doesn't name is named as not read
  assert.match(run(alpine({ version: '10.3_p1-r1', shadow: 'deploy:*:1::::::\nada:$y$j9T$x:1::::::\n' })).reason, /\$-style hash that is not \$5\$ or \$6\$/);
});

test('R9 on a glibc system, an sshd that does not name glibc\'s loader may be built against musl', () => {
  const stat = machine({ files: { '/usr/sbin/sshd': '\u007fELF static' }, dirs: { '/lib': ['ld-linux-x86-64.so.2'] } });
  const r = run(stat); assert.equal(r.status, 'UNKNOWN', r.reason); assert.match(r.reason, /does not name glibc's loader/);
  const glibc = machine({ files: { '/usr/sbin/sshd': '\u007fELF /lib64/ld-linux-x86-64.so.2 x' }, dirs: { '/lib': ['ld-linux-x86-64.so.2'] } });
  const g = run(glibc); assert.equal(g.status, 'SAFE', g.reason); assert.match(g.reason, /names glibc's loader/); assert.ok(g.searched.includes('/usr/sbin/sshd'));
});
