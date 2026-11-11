// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// --reach (lib/reach.mjs, docs/REACH.md): which guarded data and credential files this process could open. Every case
// runs on a made-up home in this test's temporary folder, never the home of whoever runs the tests. The disk is reached
// through `strict()`, a stand-in that has the four calls --reach is allowed (lstat, realpath, open to read, close) and fails
// on any other, and the command is run under test/support/reach-spy.cjs, which records every read of anything under
// that home. Each of the two is shown to be able to fail (R5, R6): a test that cannot go red has shown nothing.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, chmodSync, rmSync, readFileSync, realpathSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { measure, lines, toJson, loadItems, REAL_IO, STATES, WORDS } from '../lib/reach.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const SPY = join(ROOT, 'test', 'support', 'reach-spy.cjs');
const DATA = loadItems();
const ROOTUSER = process.getuid?.() === 0;
// what a file in the made-up home holds, a name inside a folder there, and a word in the home's own path: none of the
// three may ever be printed
const CONTENT = 'TOPSECRET-CONTENT-7f3a', INNER = 'inner-name-51c9', HOMEWORD = 'homeword-e2b4';
let dir, n = 0;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-reach-'))); });
after(() => { try { execFileSync('chmod', ['-R', 'u+rwx', dir]); } catch { /* nothing to put back */ } rmSync(dir, { recursive: true, force: true }); });

/** A made-up home → its path. `put(rel, 'file' | 'dir')` adds a place to it. */
const home = () => { const h = join(dir, `${HOMEWORD}-${++n}`, 'home'); mkdirSync(h, { recursive: true }); return h; };
const put = (h, rel, kind = 'file') => {
  const p = join(h, rel);
  if (kind === 'dir') { mkdirSync(p, { recursive: true }); writeFileSync(join(p, INNER), CONTENT); } else { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, CONTENT); }
  return p;
};

/** The disk as --reach may use it: the four calls, counted, and nothing else. Any other property is a failure. */
const strict = (over = {}) => {
  const calls = { lstat: [], realpath: [], openRead: [], close: [] };
  const io = new Proxy({}, {
    get(_, k) {
      if (!(k in calls)) throw new Error(`--reach used fs.${String(k)}: it may only lstat, realpath, open and close`);
      return (...a) => { calls[k].push(a); return (over[k] ?? REAL_IO[k])(...a); };
    },
  });
  return { io, calls };
};
const errno = (code) => Object.assign(new Error(`${code}: made up`), { code });
const run = (h, opts = {}) => { const s = strict(opts.over); const r = measure({ home: h, os: 'darwin', env: {}, uid: 501, io: s.io, ...opts.with }); return { ...r, calls: s.calls, row: (id) => r.rows.find((x) => x.id === id) }; };

/** The command → { code, out, err, spy }, in a made-up home, under the spy. */
const cli = (h, args, env = {}) => {
  const out = join(dir, `spy-${++n}.json`);
  const own = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN|SUDO_USER|[A-Z_]*CONFIG[A-Z_]*|KUBECONFIG|CARGO_HOME|AWS_[A-Z_]+|npm_config_[a-z_]+|CHROME_USER_DATA_DIR)$/.test(k)));
  const r = spawnSync(process.execPath, ['--require', SPY, BIN, ...args], { encoding: 'utf8', timeout: 120000, killSignal: 'SIGKILL', env: { ...own, HOME: h, WARDLATCH_REACH_SPY_HOME: h, WARDLATCH_REACH_SPY_OUT: out, ...env } });
  let spy = null;
  try { spy = JSON.parse(readFileSync(out, 'utf8')); } catch { /* the command died before the spy wrote */ }
  return { code: r.status, out: r.stdout, err: r.stderr, spy };
};

// ---------------------------------------------------------------------------------------------------- the data file

test('R1 the list: every place has an id, a kind, paths under the home folder, and an https page it comes from', () => {
  assert.ok(DATA.items.length >= 25);
  assert.equal(new Set(DATA.items.map((i) => i.id)).size, DATA.items.length, 'ids are unique');
  for (const i of DATA.items) {
    assert.match(i.id, /^[a-z0-9-]+$/, i.id);
    assert.ok(['file', 'dir'].includes(i.kind), i.id);
    assert.ok(i.label && i.group, i.id);
    assert.match(i.source, /^https:\/\/\S+$/, `${i.id}: source`);
    assert.ok(i.sourceSays?.length > 10, `${i.id}: what the source says`);
    const systems = Object.keys(i.paths);
    assert.ok(systems.length && systems.every((s) => ['darwin', 'linux'].includes(s)), i.id);
    for (const rel of Object.values(i.paths).flat()) {
      assert.ok(!rel.startsWith('/') && !rel.startsWith('~') && !rel.split('/').includes('..') && !rel.endsWith('/') && rel === rel.trim(), `${i.id}: ${rel}`);
    }
    // one fix line for a "reachable", with its page: the item's own, or its guard's on a Mac
    if (i.guard) assert.ok(DATA.guards[i.guard], `${i.id}: guard ${i.guard}`);
    if (!i.guard || i.paths.linux) { assert.ok(i.fix?.length > 20, `${i.id}: fix`); assert.match(i.fixSource, /^https:\/\/\S+$/, `${i.id}: fixSource`); }
    if (i.mustExist) assert.ok(i.mustExistSays?.length > 20, i.id);
    for (const k of i.moved ?? []) assert.match(k, /^[A-Za-z_][A-Za-z0-9_]*$/, i.id);
  }
  for (const [k, g] of Object.entries(DATA.guards)) for (const f of ['blocked', 'fix']) { assert.ok(g[f]?.length > 20, `${k}.${f}`); assert.match(g[`${f}Source`], /^https:\/\//, `${k}.${f}Source`); }
  // the Mac-only data is marked by having no Linux path, which is what makes it "not applicable" there
  for (const id of ['messages', 'mail', 'safari-history', 'safari-cookies', 'notes', 'tcc-db', 'keychain']) assert.equal(DATA.items.find((i) => i.id === id).paths.linux, undefined, id);
});

test('R2 wording: what is measured, never what is implied; nothing under embargo; no verdict words of the incident checks', () => {
  const text = [JSON.stringify(DATA), readFileSync(join(ROOT, 'lib', 'reach.mjs'), 'utf8'), readFileSync(join(ROOT, 'docs', 'REACH.md'), 'utf8')].join('\n');
  assert.doesNotMatch(text, /you are infected|is infected|you have been (hacked|compromised)|malware (was )?found|was stolen/i);
  assert.doesNotMatch(text, /LibreSSL|\/usr\/bin\/python3|\/usr\/bin\/ruby/);
  // the shipped strings never produce a SAFE, EXPOSED or UNKNOWN status: lib/reach.mjs has no such literal
  assert.doesNotMatch(readFileSync(join(ROOT, 'lib', 'reach.mjs'), 'utf8'), /['"`](SAFE|EXPOSED|UNKNOWN)['"`]/);
  assert.deepEqual(Object.keys(WORDS).sort(), [...STATES].sort());
});

// ------------------------------------------------------------------------------------------------------ the states

test('R3 reachable: a file and a folder that open are REVIEW lines, each with one fix line and its page', () => {
  const h = home(); put(h, '.npmrc'); put(h, '.ssh', 'dir'); put(h, 'Library/Messages/chat.db');
  const r = run(h);
  for (const id of ['npmrc', 'ssh', 'messages']) {
    const row = r.row(id);
    assert.equal(row.state, 'reachable', id); assert.equal(row.status, 'REVIEW', id);
    assert.ok(row.fix.length > 20, id); assert.match(row.fixSource, /^https:\/\//, id);
  }
  // a guarded place that opens gets the guard's fix (which setting let this app in), not a generic one
  assert.match(r.row('messages').fix, /Full Disk Access/);
  assert.equal(r.row('messages').fixSource, DATA.guards.fda.fixSource);
  assert.equal(r.counts.reachable, 3);
  // each was opened once and closed again, a folder as a folder (the flags themselves: R18)
  assert.equal(r.calls.openRead.length, 3); assert.equal(r.calls.close.length, 3);
  assert.deepEqual(r.calls.openRead.map(([p, folder]) => [p.slice(h.length), folder]).sort(), [['/.npmrc', false], ['/.ssh', true], ['/Library/Messages/chat.db', false]]);
});

test('R4 blocked by permissions: a chmod 000 file, and a file inside a chmod 000 folder, are "blocked" (EACCES), said to hold only while the permissions do', { skip: ROOTUSER && 'root is not stopped by permission bits' }, () => {
  const h = home(); chmodSync(put(h, '.npmrc'), 0o000); put(h, '.aws/credentials'); chmodSync(join(h, '.aws'), 0o000);
  const r = run(h);
  assert.deepEqual([r.row('npmrc').state, r.row('npmrc').errno, r.row('npmrc').at], ['blocked', 'EACCES', 'open']);
  assert.deepEqual([r.row('aws').state, r.row('aws').errno, r.row('aws').at], ['blocked', 'EACCES', 'lstat']);
  assert.match(r.row('npmrc').reason, /file permissions.*Whoever owns it can change them/);
  assert.match(r.row('aws').reason, /on a folder on the way/);
  assert.equal(r.row('npmrc').status, undefined, 'a blocked line is not a REVIEW line');
  assert.equal(r.row('npmrc').fix, undefined);
});

test('R5 blocked by the system: EPERM says what is known about why for a guarded place, and that it is not known for any other', () => {
  const h = home(); put(h, 'Library/Messages/chat.db'); put(h, 'Library/Application Support/Google/Chrome', 'dir'); put(h, '.npmrc');
  const refuse = { openRead: () => { throw errno('EPERM'); } };
  const r = run(h, { over: refuse });
  assert.equal(r.row('messages').state, 'blocked');
  assert.match(r.row('messages').reason, /above the file permissions \(EPERM\).*Full Disk Access.*cannot tell that protection from a sandbox/);
  assert.equal(r.row('messages').reasonSource, DATA.guards.fda.blockedSource);
  // Chrome's folder on macOS 27: what Apple says, and that it is not confirmed
  assert.match(r.row('chrome').reason, /not confirmed.*XProtect.*Apple does not name this folder/);
  assert.match(r.row('npmrc').reason, /does not know which protection/);
  // on Linux no guard's text is borrowed: the Mac's reasons are the Mac's
  const l = run(h, { over: refuse, with: { os: 'linux' } });
  put(h, '.config/google-chrome', 'dir');
  assert.match(run(h, { over: refuse, with: { os: 'linux' } }).row('chrome').reason, /does not know which protection.*SELinux/);
  assert.equal(l.row('npmrc').state, 'blocked');
});

test('R6 absent: nothing at the path is "not there", and a file where a folder on the way should be (ENOTDIR) is too', () => {
  const h = home(); put(h, '.aws');            // a file named .aws: .aws/credentials cannot exist
  const r = run(h);
  assert.deepEqual([r.row('npmrc').state, r.row('npmrc').errno], ['absent', 'ENOENT']);
  assert.deepEqual([r.row('aws').state, r.row('aws').errno], ['absent', 'ENOTDIR']);
  assert.equal(r.row('npmrc').status, undefined);
  assert.equal(r.calls.openRead.length, 0, 'nothing is opened where nothing is');
});

test('R7 could not tell, never absent: ENOENT for a place the system keeps in every account (the privacy database)', () => {
  const r = run(home());
  const row = r.row('tcc-db');
  assert.equal(row.state, 'unknown'); assert.equal(row.status, 'REVIEW'); assert.equal(row.errno, 'ENOENT');
  assert.match(row.reason, /not believed for this place.*macOS 26 and earlier.*macOS 27 Apple says/);
  assert.equal(r.counts.absent, r.rows.length - 1);
});

test('R8 could not tell, never absent: nothing at the default place while a variable the vendor documents moves it (its name is said, its value is not)', () => {
  const h = home();
  const r = run(h, { with: { env: { AWS_SHARED_CREDENTIALS_FILE: `/elsewhere/${CONTENT}`, DOCKER_CONFIG: '' } } });
  assert.equal(r.row('aws').state, 'unknown');
  assert.match(r.row('aws').reason, /AWS_SHARED_CREDENTIALS_FILE is set.*did not follow the variable/);
  assert.ok(!JSON.stringify(r.rows).includes(CONTENT), 'the value of the variable is never in a row');
  assert.equal(r.row('docker').state, 'absent', 'a variable set to nothing moves nothing');
  // and when the default place is there, it is measured as it is: the variable changes only what "not there" means
  put(h, '.aws/credentials');
  assert.equal(run(h, { with: { env: { AWS_SHARED_CREDENTIALS_FILE: '/elsewhere' } } }).row('aws').state, 'reachable');
});

test('R9 could not tell: any errno without a rule, from lstat or from open, is named; ENOENT from open (lstat saw the file) is not "absent"', () => {
  const h = home(); put(h, '.npmrc');
  for (const code of ['EIO', 'ELOOP', 'ENAMETOOLONG', 'EMFILE', 'ENXIO', 'ENOENT', 'EINTR']) {
    const row = run(h, { over: { openRead: () => { throw errno(code); } } }).row('npmrc');
    assert.deepEqual([row.state, row.errno, row.at, row.status], ['unknown', code, 'open', 'REVIEW'], code);
    assert.match(row.reason, new RegExp(`does not have a rule for \\(${code} from open\\)`));
  }
  const l = run(h, { over: { lstat: () => { throw errno('EIO'); } } }).row('npmrc');
  assert.deepEqual([l.state, l.errno, l.at], ['unknown', 'EIO', 'lstat']);
  // an error that is not an errno at all (no code, or a made-up one with a path in it) prints as fixed words
  const odd = run(h, { over: { openRead: () => { throw Object.assign(new Error(`/home/${CONTENT}`), { code: `E /${CONTENT}` }); } } }).row('npmrc');
  assert.equal(odd.errno, 'an error with no errno'); assert.ok(!JSON.stringify(odd).includes(CONTENT));
});

test('R10 links: one that stays inside the home folder is followed; one that leads outside it is not opened, and is "could not tell"', () => {
  const h = home(), outside = join(dirname(h), 'outside'); mkdirSync(outside); writeFileSync(join(outside, 'npmrc'), CONTENT); mkdirSync(join(outside, 'dotaws')); writeFileSync(join(outside, 'dotaws', 'credentials'), CONTENT);
  put(h, 'dotfiles/gitcreds'); symlinkSync(join(h, 'dotfiles', 'gitcreds'), join(h, '.git-credentials'));       // inside
  symlinkSync(join(outside, 'npmrc'), join(h, '.npmrc'));                                                        // the file, outside
  symlinkSync(join(outside, 'dotaws'), join(h, '.aws'));                                                         // a folder on the way, outside
  symlinkSync('/dev/zero', join(h, '.netrc'));                                                                   // a device
  symlinkSync(join(h, 'nothing-here'), join(h, '.pypirc'));                                                      // to nothing
  const r = run(h);
  assert.equal(r.row('git-credentials').state, 'reachable');
  for (const id of ['npmrc', 'aws', 'netrc']) {
    assert.equal(r.row(id).state, 'unknown', id); assert.equal(r.row(id).status, 'REVIEW', id);
    assert.match(r.row(id).reason, /leads outside the home folder. Wardlatch did not follow it; a program that opens this path would/, id);
  }
  assert.equal(r.row('pypirc').state, 'unknown'); assert.match(r.row('pypirc').reason, /a link whose target is not there/);
  // the only thing opened is the one inside the home folder, by its real path
  assert.deepEqual(r.calls.openRead.map(([p]) => p), [join(h, 'dotfiles', 'gitcreds')]);
  // and what is printed is the fixed path, not where the link goes
  assert.equal(r.row('git-credentials').path, '~/.git-credentials');
  assert.ok(!JSON.stringify(r.rows).includes('dotfiles') && !JSON.stringify(r.rows).includes('outside/'));
});

test('R11 a FIFO, and a folder where a file is expected, are not opened: "could not tell", and nothing waits', () => {
  const h = home();
  execFileSync('mkfifo', [join(h, '.npmrc')]);
  put(h, '.netrc', 'dir'); put(h, '.ssh');
  const t = Date.now(), r = run(h);
  assert.ok(Date.now() - t < 5000);
  assert.equal(r.row('npmrc').state, 'unknown'); assert.match(r.row('npmrc').reason, /a FIFO, socket or device\). Wardlatch did not open it/);
  assert.match(r.row('netrc').reason, /a folder is here where a file is expected/);
  assert.match(r.row('ssh').reason, /a file is here where a folder is expected/);
  assert.equal(r.calls.openRead.length, 0);
  // and a FIFO that takes a file's place between the look and the open still does not hang: the open does not block
  // (in a process of its own, with a limit: an open that waits would otherwise hang this whole file, not fail it)
  const script = join(dir, `late-fifo-${++n}.mjs`);
  writeFileSync(script, `import { lstatSync } from 'node:fs';
import { probePath, REAL_IO } from ${JSON.stringify(pathToFileURL(join(ROOT, 'lib', 'reach.mjs')).href)};
const fifo = ${JSON.stringify(join(h, '.npmrc'))}, file = ${JSON.stringify(join(h, '.ssh'))};
const io = { ...REAL_IO, lstat: (p) => lstatSync(p === fifo ? file : p) };     // the look says "a file"; a FIFO is there
console.log(JSON.stringify(probePath(fifo, 'file', ${JSON.stringify(h)}, io)));
`);
  const late = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL' });
  assert.equal(late.signal, null, 'opening a FIFO for reading waited for a writer');
  assert.equal(late.status, 0, late.stderr);
  assert.ok(['reachable', 'unknown'].includes(JSON.parse(late.stdout).state));
});

test('R12 more than one place for one thing: the answer is the strongest that is true of any, and names the place it is true of', () => {
  const h = home(); put(h, '.config/git/credentials');
  const row = run(h).row('git-credentials');
  assert.deepEqual([row.state, row.path, row.places], ['reachable', '~/.config/git/credentials', 2]);
  const h2 = home(); put(h2, '.git-credentials');
  const both = run(h2, { over: { openRead: () => { throw errno('EPERM'); } } }).row('git-credentials');
  assert.deepEqual([both.state, both.path], ['blocked', '~/.git-credentials'], 'blocked in one place and absent in the other is blocked');
});

test('R13 another system: Mac-only places are "not applicable" on Linux, never "not there"; on Windows nothing is opened and every line is "could not tell"', () => {
  const h = home(); put(h, 'Library/Messages/chat.db'); put(h, '.npmrc'); put(h, '.config/google-chrome', 'dir');
  const l = run(h, { with: { os: 'linux' } });
  for (const id of ['messages', 'mail', 'safari-history', 'safari-cookies', 'notes', 'tcc-db', 'keychain', 'brave']) { assert.equal(l.row(id).state, 'not-applicable', id); assert.equal(l.row(id).path, null); }
  assert.equal(l.row('npmrc').state, 'reachable'); assert.equal(l.row('chrome').state, 'reachable');
  assert.match(l.row('chrome').fix, /no setting in the vendor's documentation/, 'no Mac setting is offered on Linux');
  assert.equal(l.counts['not-applicable'], 8); assert.equal(l.counts.absent + l.counts.reachable + l.counts.unknown + l.counts.blocked, l.rows.length - 8);
  assert.ok(lines(l).some((x) => /^not applicable {2}Messages history$/.test(x.text)));
  const w = run(h, { with: { os: 'win32' } });
  assert.ok(w.rows.every((x) => x.state === 'unknown' && x.status === 'REVIEW' && /Windows is not supported: nothing was opened/.test(x.reason)));
  assert.deepEqual(Object.values(w.calls).map((c) => c.length), [0, 0, 0, 0]);
});

test('R14 no home folder to measure: every line is "could not tell", nothing is opened', () => {
  for (const h of [join(dir, 'no-such-home'), '', 'relative/home', undefined]) {
    const r = run(h);
    assert.ok(r.rows.every((x) => x.state === 'unknown' && /home folder could not be resolved/.test(x.reason)), String(h));
    assert.equal(r.calls.openRead.length + r.calls.lstat.length, 0);
  }
});

test('R15 it says whose reach was measured: this process, this user (or root, and what that changes), and that another app has its own', () => {
  const h = home(); put(h, '.npmrc');
  const text = (r) => lines(r).map((l) => l.text).join('\n');
  const mine = text(run(h));
  assert.match(mine, /Measured: this process only \(Node, started from this shell, as this user\)/);
  assert.match(mine, /Another terminal or app has its own\npermissions and may get other answers/);
  assert.match(mine, /not a malware scan/); assert.match(mine, /is no all-clear/);
  assert.doesNotMatch(mine, /Run as root/);
  const root = run(h, { with: { uid: 0 } });
  assert.match(text(root), /as root\)/); assert.match(text(root), /Run as root: file permissions do not stop root/);
  assert.equal(toJson(root, '0').measured.user, 'root');
});

// ---------------------------------------------------------------------------------------- it reads nothing (R16-R18)

test('R16 the stand-in can fail: a probe that reads, lists or stats through it throws', () => {
  for (const k of ['read', 'readSync', 'readFileSync', 'readdir', 'readdirSync', 'opendirSync', 'stat', 'statSync', 'fstatSync', 'createReadStream', 'readlinkSync', 'openSync']) {
    assert.throws(() => strict().io[k], /may only lstat, realpath, open and close/, k);
  }
});

test('R17 every state is reached through the four calls and no other, on a home that has one of everything', () => {
  const h = home(), outside = join(dirname(h), 'outside'); mkdirSync(outside); writeFileSync(join(outside, 'config'), CONTENT);
  for (const i of DATA.items) for (const rel of i.paths.darwin ?? []) if (!['tcc-db', 'netrc', 'pypirc', 'kube'].includes(i.id)) put(h, rel, i.kind);
  symlinkSync(outside, join(h, '.kube')); execFileSync('mkfifo', [join(h, '.netrc')]);
  const r = run(h);     // strict(): any other fs call throws, and the run fails
  assert.ok(r.counts.reachable >= 20 && r.counts.unknown >= 3 && r.counts.absent >= 1);
  assert.equal(r.calls.openRead.length, r.calls.close.length, 'everything opened was closed');
});

test('R18 the command, under a spy on every read: it opens and closes, and takes no byte and no folder entry out of the home folder; the spy is shown to see a read', () => {
  const h = home();
  for (const i of DATA.items) for (const rel of (i.paths[process.platform === 'darwin' ? 'darwin' : 'linux'] ?? []).slice(0, 1)) if (i.id !== 'tcc-db') put(h, rel, i.kind);
  const expected = DATA.items.filter((i) => i.id !== 'tcc-db' && i.paths[process.platform === 'darwin' ? 'darwin' : 'linux']).length;
  for (const args of [['--reach'], ['--reach', '--json']]) {
    const r = cli(h, args);
    assert.equal(r.code, 0, r.err);
    assert.ok(r.spy, 'the spy reported');
    // the positive control: the spy saw the opens, so it was watching the right folder
    assert.equal(r.spy.opens.length, expected, JSON.stringify(r.spy.opens));
    for (const o of r.spy.opens) {
      // read-only, cannot wait (a FIFO), cannot be led elsewhere (a link), creates and changes nothing
      assert.equal(o.flags & constants.O_ACCMODE, constants.O_RDONLY, o.path);
      assert.ok(o.flags & constants.O_NONBLOCK, o.path); assert.ok(o.flags & constants.O_NOFOLLOW, o.path);
      assert.equal(o.flags & (constants.O_CREAT | constants.O_TRUNC | constants.O_APPEND), 0, o.path);
      assert.equal(Boolean(o.flags & constants.O_DIRECTORY), DATA.items.some((i) => i.kind === 'dir' && Object.values(i.paths).flat().includes(o.path.slice(1))), o.path);
    }
    assert.deepEqual(r.spy.reads, [], 'nothing under the home folder was read or listed');
  }
  // the spy can fail: a script that opens a file there and reads one byte, and one that lists a folder, are both seen
  const out = join(dir, `spy-${++n}.json`), script = join(dir, `reader-${n}.cjs`);
  writeFileSync(script, `const fs = require('node:fs'); const fd = fs.openSync(${JSON.stringify(join(h, '.npmrc'))}, fs.constants.O_RDONLY); fs.readSync(fd, Buffer.alloc(1), 0, 1, 0); fs.closeSync(fd); fs.readdirSync(${JSON.stringify(join(h, '.ssh'))});\n`);
  const bad = spawnSync(process.execPath, ['--require', SPY, script], { encoding: 'utf8', env: { ...process.env, HOME: h, WARDLATCH_REACH_SPY_HOME: h, WARDLATCH_REACH_SPY_OUT: out } });
  assert.equal(bad.status, 0, bad.stderr);
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')).reads, ['readSync', 'readdirSync']);
});

// ---------------------------------------------------------------------------------------------- privacy of the output

test('R19 what is printed: fixed labels, ~ paths, states and counts; no home path, no content, no name from inside a folder, in text or --json', () => {
  const h = home();
  for (const i of DATA.items) for (const rel of Object.values(i.paths).flat()) if (i.id !== 'kube') put(h, rel, i.kind);
  put(h, `link-target-${INNER}/config`); symlinkSync(join(h, `link-target-${INNER}`), join(h, '.kube'));       // a link that is followed: where it goes is not said
  for (const args of [['--reach'], ['--reach', '--json']]) {
    const r = cli(h, args, { AWS_SHARED_CREDENTIALS_FILE: `/x/${CONTENT}` });
    assert.equal(r.code, 0, r.err);
    for (const secret of [CONTENT, INNER, HOMEWORD, h, dir, process.env.USER, process.env.LOGNAME].filter((s) => s && s.length > 2)) {
      assert.ok(!(r.out + r.err).includes(secret), `${args.join(' ')} printed ${secret === h ? 'the home path' : secret}`);
    }
    assert.match(r.out, /~\/\.ssh/); assert.match(r.out, /reachable\s+Kubernetes kubeconfig|"id": "kube",[^}]*"state": "reachable"/);
    // no sizes, modes, owners or times: no number in the output but the counts, the version, and those in fixed text
    const fixed = JSON.stringify(DATA) + lines(measure({ home: h, env: {} })).map((l) => l.text).join('\n');
    for (const num of r.out.match(/\d{3,}/g) ?? []) assert.ok(fixed.includes(num), `a number that is not fixed text: ${num}`);
  }
});

// ------------------------------------------------------------------------------------------------- the command (R20+)

test('R20 the command: exit 0 with reachable and could-not-tell lines; REVIEW is the only status word; --json has no results list', () => {
  const h = home(); put(h, '.npmrc'); put(h, '.ssh', 'dir'); symlinkSync('/dev/null', join(h, '.netrc'));
  const t = cli(h, ['--reach']);
  assert.equal(t.code, 0); assert.equal(t.err, '');
  assert.match(t.out, /^REVIEW {3}reachable {7}npm user config \(may hold a token\) {2}~\/\.npmrc$/m);
  assert.match(t.out, /^ {9} {4}fix: npm's documentation: .*\(https:\/\/docs\.npmjs\.com\/trusted-publishers\)$/m);
  assert.match(t.out, /^REVIEW {3}could not tell {2}\.netrc/m);
  assert.match(t.out, /^ {9}not there {7}AWS shared credentials file/m);
  assert.doesNotMatch(t.out, /^(SAFE|EXPOSED|UNKNOWN)\b/m);
  assert.doesNotMatch(t.out, /\bSAFE\b|\bEXPOSED\b/);
  assert.match(t.out, /\n\d+ reachable · \d+ blocked · \d+ not there · \d+ could not tell · \d+ not applicable here\n/);
  assert.match(t.out, /Exit code 0 whatever is above/);
  const j = JSON.parse(cli(h, ['--reach', '--json']).out);
  assert.equal(j.mode, 'reach'); assert.equal(j.results, undefined); assert.equal(j.incidents, undefined);
  assert.equal(j.reach.length, DATA.items.length);
  assert.deepEqual([...new Set(j.reach.map((x) => x.status))].sort(), ['REVIEW', undefined].sort());
  for (const x of j.reach) { assert.ok(STATES.includes(x.state)); assert.equal(x.status === 'REVIEW', ['reachable', 'unknown'].includes(x.state), x.id); }
  assert.equal(Object.values(j.counts).reduce((a, b) => a + b, 0), DATA.items.length, 'every place is counted once');
});

test('R21 --reach runs on its own: beside --incident, --paths, --list or --no-containers it is refused (exit 2), nothing measured', () => {
  const h = home(); put(h, '.npmrc');
  for (const more of [['--incident', 'chrome-2026-11'], ['--paths', h], ['--no-containers']]) {
    const r = cli(h, ['--reach', ...more]);
    assert.equal(r.code, 2, more.join(' ')); assert.match(r.err, /--reach runs on its own/); assert.equal(r.out, '');
    assert.deepEqual(r.spy.opens.filter((o) => o.path === '/.npmrc'), []);
  }
  assert.match(cli(h, ['--help']).out, /--reach /);
});

test('R22 off unless asked: a run without --reach opens none of these places and prints no reach line', () => {
  const h = home(); put(h, '.aws/credentials'); put(h, '.kube/config'); put(h, 'Library/Messages/chat.db');
  const r = cli(h, ['--incident', 'chrome-2026-11', '--no-containers', '--json', '--paths', join(h, 'nothing')]);
  assert.ok(r.spy);
  assert.deepEqual(r.spy.opens.filter((o) => /credentials|kube|chat\.db/.test(o.path)), []);
  const j = JSON.parse(r.out);
  assert.equal(j.reach, undefined); assert.equal(j.mode, undefined); assert.ok(Array.isArray(j.results));
});

test('R23 a long list: 5,000 places are measured in seconds, each opened at most once', () => {
  const h = home();
  const items = Array.from({ length: 5000 }, (_, i) => ({ id: `x${i}`, group: 'g', label: `l${i}`, kind: 'file', paths: { darwin: [`many/f${i}`], linux: [`many/f${i}`] }, source: 'https://example.com/', fix: 'f', fixSource: 'https://example.com/' }));
  mkdirSync(join(h, 'many')); for (let i = 0; i < 5000; i += 2) writeFileSync(join(h, 'many', `f${i}`), '');
  const t = Date.now(), r = run(h, { with: { data: { guards: {}, items } } });
  assert.ok(Date.now() - t < 20000, `${Date.now() - t} ms`);
  assert.deepEqual([r.counts.reachable, r.counts.absent], [2500, 2500]);
  assert.equal(r.calls.openRead.length, 2500);
});
