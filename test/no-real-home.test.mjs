// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The tests' safety net (test/support/no-real-home.cjs), tried on each route it watches (CONTRIBUTING.md, Testing
// policy, lists routes it is known not to watch). Each test has a clean twin, in the test itself or, for the fs
// functions, in the test after it: looks of the same kinds outside the home, which must stay allowed. Not every way in
// a test tries has a twin of its own, and only the spelling test's twin also looks under the start-up disk's other
// names (on macOS). Each probe runs on a made-up machine in this test's temporary folder: a home with a checkout
// inside it (as on a laptop: the net's copy loads from there), and a temporary folder beside it. A Node started as a
// test file is (the net's copy first, HOME the made-up home) tries each way in, and reports what was refused. Nothing
// here looks in a real home but for this checkout and the folder of the Node running the tests, which the net leaves
// readable: the folders probed are the made-up ones, and the one path probed in another account's home (root's, under
// sudo) has a name longer than any file system takes, so the system answers without looking there. A probe run against
// a net with a hole in it reads only the made-up folders.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import * as nodeFs from 'node:fs';
import * as nodeModule from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, symlinkSync, linkSync, readFileSync, readdirSync, realpathSync, rmSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const NET = join(ROOT, 'test', 'support', 'no-real-home.cjs');
const MAC = process.platform === 'darwin';
const J = JSON.stringify;
let dir, n = 0;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-seal-')); });
after(() => rmSync(dir, { recursive: true, force: true }));

/** A made-up machine: home/secret, home/dev/wardlatch (a checkout, with the net's copy), tmp beside home. */
const machine = (name, { checkout: co } = {}) => {
  const base = join(dir, name), home = join(base, 'home'), tmp = join(base, 'tmp'), checkout = co?.(base) ?? join(home, 'dev', 'wardlatch');
  mkdirSync(join(checkout, 'test', 'support'), { recursive: true }); mkdirSync(home, { recursive: true }); mkdirSync(tmp, { recursive: true });
  const net = join(checkout, 'test', 'support', 'no-real-home.cjs');
  copyFileSync(NET, net);
  writeFileSync(join(home, 'secret'), 'secret\n'); writeFileSync(join(tmp, 'ok'), 'ok\n');
  return { home, tmp, checkout, net };
};
/** A script in the machine's tmp → its path. */
const put = (m, name, text, mode = 0o644) => { const p = join(m.tmp, name); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, { mode }); return p; };
/** A Node script that reads `file` and prints READ. */
const reader = (m, name, file, first = '') => put(m, name, `${first}require('fs').readFileSync(${J(file)}); console.log('READ');\n`, 0o755);

/** Run `body` (CommonJS; `m` is the machine, `report(x)` prints the result) in a Node started as a test file is: the
 *  net's copy loaded first, HOME the made-up home, the working folder its tmp (or `cwd`) → { code, out, err }. */
const probe = (m, body, env = {}, cwd = m.tmp) => {
  const script = put(m, `probe-${++n}.cjs`, `require(${J(m.net)});
const m = ${J(m)};
const fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const report = (x) => fs.writeSync(1, JSON.stringify(x) + '\\n');
const tried = (f) => { try { f(); return 'not refused'; } catch (e) { return e.code === 'EREALHOME' ? 'refused' : 'not refused: ' + e.code; } };
const triedAsync = async (f) => { try { await f(); return 'not refused'; } catch (e) { return e.code === 'EREALHOME' ? 'refused' : 'not refused: ' + e.code; } };
${body}`);
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', cwd, maxBuffer: 64 * 1024 * 1024,
    env: { WARDLATCH_TEST_NO_HOME: '', HOME: m.home, TMPDIR: m.tmp, PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, LANG: 'C', ...env } });
  const last = r.stdout.trim().split('\n').pop();
  let out = null;
  try { out = JSON.parse(last); } catch { /* the probe died before it reported */ }
  return { code: r.status, out, err: r.stderr };
};
/** Every way in the probe tried (exactly `tried`, by name) was refused. */
const allRefused = (r, tried) => {
  assert.ok(r.out, `the probe reported nothing: ${r.err.slice(-4000)}`);
  assert.deepEqual(Object.entries(r.out).filter(([, v]) => v !== 'refused'), [], 'these ways in were not refused');
  assert.deepEqual(Object.keys(r.out).sort(), [...tried].sort());
};
/** Another Node binary, one the net knows by its first bytes and name, not by its path: a hard link, or a copy, of this
 *  one (a link to it would be this one) in a bin folder of its own in the machine's tmp, with the other folders of this
 *  one's install linked beside that folder, as a Node may load its own library from there (Homebrew's loads
 *  @loader_path/../lib/libnode.<n>.dylib: a copy of it alone stops before it starts, SIGABRT). The links are made by a
 *  Node that loads the net as a test file does, in this test file's environment: an install in a home is refused
 *  there, which fails that Node, not this test file, and the copy is tried without them. → { node } if it starts, else
 *  { node, skipped: why it doesn't }. */
const anotherNode = (m) => {
  const install = dirname(dirname(process.execPath)), root = join(m.tmp, 'other'), node = join(root, 'bin', 'node');
  mkdirSync(dirname(node), { recursive: true });
  try { linkSync(process.execPath, node); } catch { copyFileSync(process.execPath, node, constants.COPYFILE_FICLONE); }
  const laid = spawnSync(process.execPath, ['--require', NET, '-e', `const fs = require('fs'), path = require('path');
for (const e of fs.readdirSync(${J(install)})) if (e !== 'bin') fs.symlinkSync(path.join(${J(install)}, e), path.join(${J(root)}, e));`],
  { encoding: 'utf8', timeout: 20000, killSignal: 'SIGKILL', env: { ...process.env, WARDLATCH_TEST_NO_HOME: '' } });
  const r = spawnSync(node, ['--version'], { encoding: 'utf8', timeout: 20000, killSignal: 'SIGKILL' });
  if (r.status === 0 && r.stdout.trim() === process.version) return { node };
  const how = r.signal ?? r.error?.code ?? `exit ${r.status}`;
  return { node, skipped: `a hard link, or a copy, of this Node (${process.execPath}) doesn't start here (${how}), ${laid.status === 0
    ? `with the other folders of ${install} linked beside its bin folder` : `and the other folders of ${install} couldn't be linked beside it (${laid.signal ?? `exit ${laid.status}`})`}` };
};

test('a refusal in a process a test started fails the test file, at any depth, though nothing reads that process\'s exit code', () => {
  const m = machine('marks');
  const home = reader(m, 'g-home.cjs', join(m.home, 'secret')), ok = reader(m, 'g-ok.cjs', join(m.tmp, 'ok'));
  const mid = put(m, 'g-mid.cjs', `require('child_process').spawnSync(process.execPath, [${J(home)}]); console.log('mid');\n`);
  // a second copy of the net, loaded by the child itself (a mutation run's copy of the checkout): the first one stays
  mkdirSync(join(m.tmp, 'copy', 'test', 'support'), { recursive: true }); copyFileSync(NET, join(m.tmp, 'copy', 'test', 'support', 'no-real-home.cjs'));
  const second = `require(${J(join(m.tmp, 'copy', 'test', 'support', 'no-real-home.cjs'))});\n`;
  const twice = put(m, 'g-twice.cjs', `${second}try { require('fs').readFileSync(${J(join(m.home, 'secret'))}); } catch { /* swallowed */ }\nconsole.log('swallowed');\n`);
  const twiceOk = reader(m, 'g-twice-ok.cjs', join(m.tmp, 'ok'), second);
  const run = (script, env) => probe(m, `const r = cp.spawnSync(process.execPath, [${J(script)}], { encoding: 'utf8' }); report({ status: r.status, out: r.stdout.trim() });`, env);
  // the child's refusal is swallowed: its exit code is never looked at
  const one = run(home);
  assert.deepEqual(one.out, { status: 70, out: '' }, one.err);
  assert.equal(one.code, 1, 'the test file passed though a process it started was stopped');
  assert.match(one.err, /was stopped \(exit 70\)/);
  // two levels down, through a process that ignores it and exits 0
  const two = run(mid);
  assert.deepEqual(two.out, { status: 0, out: 'mid' }, two.err);
  assert.equal(two.code, 1, 'the test file passed though a process two levels down was stopped');
  const copy = run(twice);
  assert.deepEqual(copy.out, { status: 70, out: '' }, copy.err);
  assert.equal(copy.code, 1, copy.err);
  // ...and changes nothing in a child that looks only at its own folders (the copy is never set up a second time)
  const copyOk = run(twiceOk);
  assert.deepEqual(copyOk.out, { status: 0, out: 'READ' }, copyOk.err);
  assert.equal(copyOk.code, 0, copyOk.err);
  // a test file run by a node --test the test started (as the mutation gate's tests do): Node starts it, not the net,
  // and its refusal still reaches the test
  const inner = put(m, 'inner/home.test.cjs', `const { test } = require('node:test');
test('swallows a look at the home', () => { try { require('fs').readFileSync(${J(join(m.home, 'secret'))}); } catch { /* swallowed */ } });\n`);
  const innerOk = put(m, 'inner/ok.test.cjs', `const { test } = require('node:test');\ntest('reads its own', () => require('fs').readFileSync(${J(join(m.tmp, 'ok'))}));\n`);
  const nested = (file) => probe(m, `const r = cp.spawnSync(process.execPath, ['--test', ${J(file)}], { encoding: 'utf8' }); report({ status: r.status });`);
  const viaRunner = nested(inner);
  assert.deepEqual(viaRunner.out, { status: 1 }, viaRunner.err);
  assert.equal(viaRunner.code, 1, 'a refusal in a test file a nested node --test ran did not fail the test');
  const viaRunnerOk = nested(innerOk);
  assert.deepEqual(viaRunnerOk.out, { status: 0 }, viaRunnerOk.err);
  assert.equal(viaRunnerOk.code, 0, viaRunnerOk.err);
  // ...and when a shell starts that node --test (the net comes by NODE_OPTIONS, which the runner passes on)
  const viaShell = probe(m, `let status = 0; try { cp.execSync('node --test ' + ${J(J(inner))}, { stdio: 'pipe' }); } catch (e) { status = e.status; } report({ status });`);
  assert.deepEqual(viaShell.out, { status: 1 }, viaShell.err);
  assert.equal(viaShell.code, 1, 'a refusal in a test file a nested node --test ran (started by a shell) did not fail the test');
  // ...and a child of a test file that runner runs in its own process (--test-isolation=none): the runner keeps the
  // net's variable for the test files it starts, which is no choice of that test file's, so the child gets the net
  // (with the environment as it is, or a copy of it)
  const isolation = ['--test-isolation', '--experimental-test-isolation'].find((f) => process.allowedNodeEnvironmentFlags.has(f));
  if (isolation) {
    const starts = (script) => `const { test } = require('node:test'), cp = require('child_process');
test('starts a child and reads nothing of it', () => { cp.spawnSync(process.execPath, [${J(script)}]); cp.spawnSync(process.execPath, [${J(script)}], { env: { ...process.env } }); });\n`;
    const none = (file) => probe(m, `const r = cp.spawnSync(process.execPath, ['--test', '${isolation}=none', ${J(file)}], { encoding: 'utf8' }); report({ status: r.status });`);
    const inProcess = none(put(m, 'none/home.test.cjs', starts(home)));
    assert.deepEqual(inProcess.out, { status: 0 }, inProcess.err);
    assert.equal(inProcess.code, 1, 'a child of a test file run in the runner\'s own process looked in the home, and the test passed');
    assert.equal(inProcess.err.match(/was stopped \(exit 70\)/g)?.length, 2, inProcess.err);
    const inProcessOk = none(put(m, 'none/ok.test.cjs', starts(ok)));
    assert.deepEqual(inProcessOk.out, { status: 0 }, inProcessOk.err);
    assert.equal(inProcessOk.code, 0, inProcessOk.err);
  }
  // a test file whose temporary folder is in the home keeps its notes elsewhere: the net writes nothing there
  mkdirSync(join(m.home, 't'));
  const inHome = probe(m, `cp.spawnSync(process.execPath, [${J(home)}]); report({ left: cp.execFileSync('/bin/ls', ['-A', path.join(m.home, 't')], { encoding: 'utf8' }) });`, { TMPDIR: join(m.home, 't') });
  assert.deepEqual(inHome.out, { left: '' }, inHome.err);
  assert.equal(inHome.code, 1, inHome.err);
  // the folder for notes is made only when a test file first starts a process (one that is killed can't remove it),
  // and removed when it exits
  const quiet = join(m.tmp, 'quiet'); mkdirSync(quiet);
  const q = probe(m, `const before = fs.readdirSync(process.env.TMPDIR); cp.spawnSync(process.execPath, ['-e', '0']);
report({ before, after: fs.readdirSync(process.env.TMPDIR).map((f) => f.replace(/-[^-]*$/, '-*')) });`, { TMPDIR: quiet });
  assert.deepEqual(q.out, { before: [], after: ['wardlatch-no-home-*'] }, q.err);
  assert.equal(q.code, 0, q.err);
  assert.deepEqual(readdirSync(quiet), [], 'the folder for notes was left behind');
  // the clean twin: a child that reads only its own folders leaves no note, and the test file passes
  const clean = run(ok);
  assert.deepEqual(clean.out, { status: 0, out: 'READ' }, clean.err);
  assert.equal(clean.code, 0, clean.err);
});

test('every spelling of a path in the home is refused: relative, links followed, \'..\' after a link, a Buffer or URL, and (macOS) case and the start-up disk\'s other names, however many', () => {
  const m = machine('spellings');
  mkdirSync(join(m.home, 'inner')); mkdirSync(join(m.tmp, 'okdir')); writeFileSync(join(m.tmp, 'okdir', 'file'), 'ok\n');
  symlinkSync(m.home, join(m.tmp, 'link'));                        // a link to the home
  symlinkSync('../home', join(m.tmp, 'rel'));                      // relative
  symlinkSync(join(m.tmp, 'link'), join(m.tmp, 'chain'));           // a link to the link
  symlinkSync(join(m.home, 'inner'), join(m.tmp, 'inner-link'));    // '..' after it is the home itself, not tmp
  symlinkSync(join(m.home, 'secret'), join(m.checkout, 'escape'));  // in the readable checkout, out of it
  symlinkSync(m.tmp, join(m.home, 'out'));                         // in the home, out of it: still a look in the home
  symlinkSync(join(m.tmp, 'okdir'), join(m.tmp, 'ok-link'));
  const s = join(m.home, 'secret');
  // (macOS) the home's path through the start-up disk's link for its folder (/tmp or /var, for /private/tmp or
  // /private/var, as a temporary folder is spelt on CI's runners): /System/Volumes/Data has no such link, so with the
  // disk's other name before it the path names nothing, and the net refuses it by its text
  const viaRoot = MAC ? realpathSync(s).replace(/^\/private(?=\/(?:tmp|var)\/)/, '') : s;
  const spellings = {
    plain: s, link: join(m.tmp, 'link', 'secret'), relative: join(m.tmp, 'rel', 'secret'), chain: join(m.tmp, 'chain', 'secret'),
    dotdot: `${join(m.tmp, 'inner-link')}/../secret`, escape: join(m.checkout, 'escape'), beside: join(m.home, 'dev', 'other'),
    outLink: join(m.home, 'out', 'ok'), fromCwd: 'link/secret', upFromCwd: '../home/secret',
    ...(MAC ? {
      upper: s.toUpperCase(), data: `/System/Volumes/Data${s}`, dataTwice: `/System/Volumes/Data/System/Volumes/Data${s}`,
      volume: `/Volumes/Wardlatch Probe/System/Volumes/Data${s}`, volumeLower: `/volumes/x/volumes/y${s}`,
      dataRootLink: `/System/Volumes/Data${viaRoot}`, volumeRootLink: `/Volumes/Wardlatch Probe${viaRoot}`,
      volumeLink: `/Volumes/Wardlatch Probe${join(m.tmp, 'link', 'secret')}`,
    } : {}),
  };
  const r = probe(m, `const s = ${J(spellings)}, out = {};
for (const [k, p] of Object.entries(s)) out[k] = tried(() => fs.statSync(p));
out.buffer = tried(() => fs.statSync(Buffer.from(s.plain)));
out.uint8Array = tried(() => fs.statSync(new Uint8Array(Buffer.from(s.plain))));
out.url = tried(() => fs.statSync(require('node:url').pathToFileURL(s.plain)));
// an object fs takes as a URL where this Node does (Node 20 on: href and protocol, no auth or path; Node 18: href and
// origin). Where Node refuses that shape for a path outside the home too, it reads nothing: Node's own refusal is the
// refusal. (With auth, no Node takes it: that branch runs on every Node.)
const like = (p, more) => ({ href: 'file:///nowhere', protocol: 'file:', hostname: '', pathname: p, ...more });
const urlLike = (more) => {
  const home = tried(() => fs.statSync(like(s.plain, more)));
  return home === 'not refused: ERR_INVALID_ARG_TYPE' && tried(() => fs.statSync(like(path.join(m.tmp, 'ok'), more))) === home ? 'refused' : home;
};
out.urlLike = urlLike({});
out.urlLikeNodeRefuses = urlLike({ auth: '' });
out.chdir = tried(() => process.chdir(path.join(m.tmp, 'link', 'inner')));
// a 1 MB path is read in one pass: refused, and fast
const t0 = Date.now();
out.longDots = tried(() => fs.statSync('/.'.repeat(500000) + s.plain));
if (${MAC}) out.longVolumes = tried(() => fs.statSync('/Volumes/x'.repeat(100000) + s.plain));
if (${MAC}) out.longVolumesRootLink = tried(() => fs.statSync('/Volumes/x'.repeat(100000) + ${J(viaRoot)}));
const ms = Date.now() - t0;
report({ ...out, fast: ms < 2000 ? 'refused' : ms + ' ms' });`);
  allRefused(r, [...Object.keys(spellings), 'buffer', 'uint8Array', 'url', 'urlLike', 'urlLikeNodeRefuses', 'chdir', 'longDots',
    ...(MAC ? ['longVolumes', 'longVolumesRootLink'] : []), 'fast']);
  // a readable folder that holds a whole home (a checkout with the home inside it) opens none of it
  const wide = machine('wide', { checkout: (base) => base });
  const w = probe(wide, `report({ inside: tried(() => fs.statSync(path.join(m.home, 'secret'))) });`);
  assert.deepEqual(w.out, { inside: 'refused' }, w.err);
  // the clean twin: the same kinds of path outside the home, and the checkout inside it, stay readable; on macOS, the
  // start-up disk's other names before a path outside the home too, read by their text: /System/Volumes/Data before
  // its real path reads the file, and a /Volumes/<x> that isn't there names nothing, so the system answers ENOENT
  const real = realpathSync(join(m.tmp, 'ok'));
  const ok = { file: join(m.tmp, 'ok'), link: join(m.tmp, 'ok-link', 'file'), checkout: m.net, dotdot: `${join(m.tmp, 'ok-link')}/../ok`, fromCwd: 'ok',
    ...(MAC ? { data: `/System/Volumes/Data${real}`, volume: `/Volumes/Wardlatch Probe${real}` } : {}) };
  const c = probe(m, `const s = ${J(ok)}, out = {}; for (const [k, p] of Object.entries(s)) out[k] = tried(() => fs.readFileSync(p));
out.buffer = tried(() => fs.readFileSync(Buffer.from(s.file))); report(out);`);
  const clean = Object.fromEntries([...Object.keys(ok), 'buffer'].map((k) => [k, 'not refused']));
  assert.deepEqual(c.out, MAC ? { ...clean, volume: 'not refused: ENOENT' } : clean, c.err);
  assert.equal(c.code, 0, c.err);
});

// the fs functions that take a path, each in the forms this Node has (a Node without one has nothing to refuse)
const ONE = ['access', 'appendFile', 'chmod', 'chown', 'createReadStream', 'createWriteStream', 'exists', 'glob', 'lchmod', 'lchown', 'lstat',
  'lutimes', 'mkdir', 'mkdtemp', 'mkdtempDisposable', 'open', 'openAsBlob', 'opendir', 'readdir', 'readFile', 'readlink', 'realpath', 'rm',
  'rmdir', 'stat', 'statfs', 'truncate', 'unlink', 'utimes', 'watch', 'watchFile', 'writeFile'];
const TWO = ['copyFile', 'cp', 'link', 'rename', 'symlink'];
const forms = (fs, k) => [['callback', fs[k]], ['Sync', fs[`${k}Sync`]], ['promise', fs.promises[k]]].filter(([, f]) => typeof f === 'function');

test('every fs function that takes a path refuses one in the home: callback, Sync and promise forms, and either path of those that take two', () => {
  const m = machine('fs');
  const expected = [...ONE.flatMap((k) => forms(nodeFs, k).map(([form]) => `${k} ${form}`)),
    ...TWO.flatMap((k) => forms(nodeFs, k).flatMap(([form]) => [`${k} ${form} (first)`, `${k} ${form} (second)`])), 'realpath.native', 'realpathSync.native'];
  const r = probe(m, `const h = path.join(m.home, 'secret'), t = path.join(m.tmp, 'ok'), t2 = path.join(m.tmp, 'new'), out = {}, noop = () => {};
const forms = (k) => (${forms})(fs, k);
const run = (f, args) => tried(() => { const x = f(...args); x?.catch?.(noop); x?.close?.(); x?.destroy?.(); });
for (const k of ${J(ONE)}) for (const [form, f] of forms(k)) {
  const args = ['watch', 'watchFile'].includes(k) ? [h, { persistent: false }, noop] : form === 'callback' && !k.startsWith('create') ? [h, noop] : [h];
  out[k + ' ' + form] = run(f, args);
}
for (const k of ${J(TWO)}) for (const [form, f] of forms(k)) {
  const end = form === 'callback' ? [noop] : [];
  out[k + ' ' + form + ' (first)'] = run(f, [h, t2, ...end]);
  out[k + ' ' + form + ' (second)'] = run(f, [t, path.join(m.home, 'new'), ...end]);
}
out['realpath.native'] = run(fs.realpath.native, [h, noop]);
out['realpathSync.native'] = run(fs.realpathSync.native, [h]);
fs.unwatchFile(h);
report(out);`);
  allRefused(r, expected);
  assert.ok(expected.length >= 90, J(expected));
});

test('every fs function the net wraps still does its work on paths outside the home: callback, Sync and promise forms, both paths of those that take two', () => {
  const m = machine('fs-clean');
  // lchmod is macOS's alone (elsewhere Node has only a promise form, which says it isn't implemented)
  const ones = ONE.filter((k) => k !== 'lchmod' || MAC);
  const expected = [...[...ones, ...TWO].flatMap((k) => forms(nodeFs, k).map(([form]) => `${k} ${form}`)), 'realpath.native', 'realpathSync.native'];
  // each in a folder of its own in tmp, holding f (a file) and l (a link to it): what it should leave there or return
  const r = probe(m, `const uid = process.getuid(), gid = process.getgid();
const forms = (k) => (${forms})(fs, k);
let n = 0;
const fresh = () => { const d = path.join(m.tmp, 'w' + ++n); fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'f'), 'content'); fs.symlinkSync(path.join(d, 'f'), path.join(d, 'l')); return d; };
const at = (d, x) => path.join(d, x), text = (p) => fs.readFileSync(p, 'utf8'), names = (v) => [...v].map(String).sort().join();
const mode = (st) => st.mode & 0o777;
// an event that writing f again and again brings, within 5 s
const event = (start, d) => new Promise((resolve) => {
  const iv = setInterval(() => fs.writeFileSync(at(d, 'f'), String(Date.now())), 50);
  const t = setTimeout(() => end(false), 5000);
  const end = (v) => { clearInterval(iv); clearTimeout(t); resolve(v); };
  start(() => end(true));
});
const cases = {
  access: (d) => [[at(d, 'f')], () => true],
  appendFile: (d) => [[at(d, 'f'), '+'], () => text(at(d, 'f')) === 'content+'],
  chmod: (d) => [[at(d, 'f'), 0o600], () => mode(fs.statSync(at(d, 'f'))) === 0o600],
  chown: (d) => [[at(d, 'f'), uid, gid], () => fs.statSync(at(d, 'f')).uid === uid],
  copyFile: (d) => [[at(d, 'f'), at(d, 'g')], () => text(at(d, 'g')) === 'content'],
  cp: (d) => [[at(d, 'f'), at(d, 'g')], () => text(at(d, 'g')) === 'content'],
  exists: (d) => [[at(d, 'f')], (v) => v === true],
  glob: (d) => [['*', { cwd: d }], (v) => names(v) === 'f,l'],
  lchmod: (d) => [[at(d, 'l'), 0o700], () => mode(fs.lstatSync(at(d, 'l'))) === 0o700],
  lchown: (d) => [[at(d, 'l'), uid, gid], () => fs.lstatSync(at(d, 'l')).uid === uid],
  link: (d) => [[at(d, 'f'), at(d, 'h')], () => fs.statSync(at(d, 'h')).nlink === 2],
  lstat: (d) => [[at(d, 'l')], (v) => v.isSymbolicLink()],
  lutimes: (d) => [[at(d, 'l'), 1000, 2000], () => fs.lstatSync(at(d, 'l')).mtimeMs === 2000000],
  mkdir: (d) => [[at(d, 'new')], () => fs.statSync(at(d, 'new')).isDirectory()],
  mkdtemp: (d) => [[at(d, 't-')], (v) => v.startsWith(at(d, 't-')) && fs.statSync(v).isDirectory()],
  mkdtempDisposable: (d) => [[at(d, 't-')], async (v) => { const ok = v.path.startsWith(at(d, 't-')) && fs.statSync(v.path).isDirectory(); await v.remove(); return ok && !fs.existsSync(v.path); }],
  open: (d) => [[at(d, 'f'), 'r'], async (v) => { if (typeof v === 'number') fs.closeSync(v); else await v.close(); return true; }],
  openAsBlob: (d) => [[at(d, 'f')], async (v) => (await v.text()) === 'content'],
  opendir: (d) => [[d], (v) => { const s = []; let e; while ((e = v.readSync())) s.push(e.name); v.closeSync(); return names(s) === 'f,l'; }],
  readdir: (d) => [[d], (v) => names(v) === 'f,l'],
  readFile: (d) => [[at(d, 'f'), 'utf8'], (v) => v === 'content'],
  readlink: (d) => [[at(d, 'l')], (v) => v === at(d, 'f')],
  realpath: (d) => [[at(d, 'l')], (v) => v.endsWith('/f') && fs.statSync(v).ino === fs.statSync(at(d, 'f')).ino],
  rename: (d) => [[at(d, 'f'), at(d, 'g')], () => text(at(d, 'g')) === 'content' && !fs.existsSync(at(d, 'f'))],
  rm: (d) => [[at(d, 'f')], () => !fs.existsSync(at(d, 'f'))],
  rmdir: (d) => { fs.mkdirSync(at(d, 'e')); return [[at(d, 'e')], () => !fs.existsSync(at(d, 'e'))]; },
  stat: (d) => [[at(d, 'l')], (v) => v.isFile()],
  statfs: (d) => [[d], (v) => v.bsize > 0],
  symlink: (d) => [[at(d, 'f'), at(d, 's')], () => fs.readlinkSync(at(d, 's')) === at(d, 'f') && text(at(d, 's')) === 'content'],
  truncate: (d) => [[at(d, 'f'), 2], () => text(at(d, 'f')) === 'co'],
  unlink: (d) => [[at(d, 'f')], () => !fs.existsSync(at(d, 'f'))],
  utimes: (d) => [[at(d, 'f'), 1000, 2000], () => fs.statSync(at(d, 'f')).mtimeMs === 2000000],
  writeFile: (d) => [[at(d, 'w'), 'x'], () => text(at(d, 'w')) === 'x'],
};
const special = {
  'createReadStream callback': async (d) => { let s = ''; for await (const c of fs.createReadStream(at(d, 'f'), 'utf8')) s += c; return s === 'content'; },
  'createWriteStream callback': async (d) => { const w = fs.createWriteStream(at(d, 'w')); await new Promise((res, rej) => w.on('error', rej).on('close', res).end('x')); return text(at(d, 'w')) === 'x'; },
  'watch callback': (d) => event((done) => { const w = fs.watch(d, { persistent: false }, () => { w.close(); done(); }); }, d),
  'watch promise': async (d) => {
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), 5000), iv = setInterval(() => fs.writeFileSync(at(d, 'f'), String(Date.now())), 50);
    try { for await (const e of fs.promises.watch(d, { signal: ac.signal })) return typeof e.eventType === 'string'; } catch (e) { if (e.name !== 'AbortError') throw e; } finally { clearTimeout(t); clearInterval(iv); }
    return false;
  },
  'watchFile callback': (d) => event((done) => fs.watchFile(at(d, 'f'), { persistent: false, interval: 20 }, () => { fs.unwatchFile(at(d, 'f')); done(); }), d),
};
// a callback form gets one (exists: its only argument is the answer); openAsBlob has no callback, it returns a promise
const call = (k, form, f, args) => (form !== 'callback' || k === 'openAsBlob' ? f(...args)
  : new Promise((res, rej) => f(...args, (e, v) => (k === 'exists' ? res(e) : e ? rej(e) : res(v)))));
const collect = async (v) => { if (!v || typeof v[Symbol.asyncIterator] !== 'function' || v instanceof fs.Dir) return v; const a = []; for await (const x of v) a.push(x); return a; };
(async () => {
  const out = {};
  const run = async (name, f) => { try { out[name] = (await f()) === true ? 'works' : 'wrong result'; } catch (e) { out[name] = 'failed: ' + (e.code ?? e.message); } };
  for (const k of ${J([...ONE, ...TWO])}) {
    if (k === 'lchmod' && !${MAC}) continue;
    for (const [form, f] of forms(k)) {
      const name = k + ' ' + form;
      await run(name, async () => { if (special[name]) return special[name](fresh()); const [args, ok] = cases[k](fresh()); return ok(await collect(await call(k, form, f, args))); });
    }
  }
  await run('realpath.native', () => new Promise((res, rej) => fs.realpath.native(path.join(fresh(), 'l'), (e, v) => (e ? rej(e) : res(v.endsWith('/f'))))));
  await run('realpathSync.native', () => fs.realpathSync.native(path.join(fresh(), 'l')).endsWith('/f'));
  report(out);
})();`);
  assert.ok(r.out, `the probe reported nothing: ${r.err.slice(-4000)}`);
  assert.deepEqual(Object.entries(r.out).filter(([, v]) => v !== 'works'), [], 'these did not do their work outside the home');
  assert.deepEqual(Object.keys(r.out).sort(), [...expected].sort());
  assert.ok(expected.length >= 90, J(expected));
  assert.equal(r.code, 0, r.err);
});

test('the routes a review found open are refused: glob, the stream classes, require and import (a path, a link, a package name), a change of folder, a program, its working folder or a PATH folder there', () => {
  const m = machine('routes');
  writeFileSync(join(m.home, 'mod.cjs'), 'module.exports = 1;\n'); writeFileSync(join(m.home, 'mod.mjs'), 'export default 1;\n');
  // in the readable checkout: modules that reach out of it, by path, through a link (package.json's imports), and by
  // package name (Node looks for one in the node_modules folders up from the importing file: home/dev/node_modules)
  writeFileSync(join(m.checkout, 'package.json'), J({ imports: { '#secret': './secret-link.mjs' } }));
  symlinkSync(join(m.home, 'mod.mjs'), join(m.checkout, 'secret-link.mjs'));
  writeFileSync(join(m.checkout, 'linked.mjs'), "import '#secret';\n");
  writeFileSync(join(m.checkout, 'up.cjs'), "require('../../mod.cjs');\n");
  writeFileSync(join(m.checkout, 'up.mjs'), "import '../../mod.mjs';\n");
  writeFileSync(join(m.checkout, 'pkg.cjs'), "require('wardlatch-no-such-package');\n");
  writeFileSync(join(m.checkout, 'pkg.mjs'), "import 'wardlatch-no-such-package';\n");
  writeFileSync(join(m.checkout, 'fine.mjs'), "import 'node:path'; import './fine2.mjs';\n"); writeFileSync(join(m.checkout, 'fine2.mjs'), 'export {};\n');
  // a program found by name: through a folder of PATH in the home, or a link in PATH to the home
  mkdirSync(join(m.home, 'bin')); mkdirSync(join(m.tmp, 'lbin'));
  symlinkSync(join(m.home, 'tool'), join(m.tmp, 'lbin', 'tool')); writeFileSync(join(m.home, 'tool'), '#!/bin/sh\necho ran\n', { mode: 0o755 });
  // what this Node has: fs.glob (Node 22), import hooks (module.registerHooks, Node 22.15), fs.Utf8Stream (Node 24.6)
  const has = { glob: typeof nodeFs.globSync === 'function', hooks: typeof nodeModule.registerHooks === 'function', utf8: typeof nodeFs.Utf8Stream === 'function' };
  const r = probe(m, `const { pathToFileURL } = require('node:url'), Module = require('node:module');
const h = m.home, s = path.join(h, 'secret'), url = (p) => pathToFileURL(p).href, has = ${J(has)};
(async () => {
  const out = {
    readStream: tried(() => new fs.ReadStream(s)),
    readStreamCalled: tried(() => fs.ReadStream(s)),
    writeStream: tried(() => new fs.WriteStream(path.join(h, 'w'))),
    fileReadStream: tried(() => new fs.FileReadStream(s)),
    fileWriteStream: tried(() => new fs.FileWriteStream(path.join(h, 'w'))),
    subclass: tried(() => { class S extends fs.ReadStream {} return new S(s); }),
    symlinkToUrl: tried(() => fs.symlinkSync(pathToFileURL(s), path.join(m.tmp, 'url-link'))),
    requirePath: tried(() => require(path.join(h, 'mod.cjs'))),
    requireMissing: tried(() => require(path.join(h, 'missing.cjs'))),
    requireResolve: tried(() => require.resolve(path.join(h, 'mod.cjs'))),
    requireUp: tried(() => require(path.join(m.checkout, 'up.cjs'))),
    requirePackage: tried(() => require(path.join(m.checkout, 'pkg.cjs'))),
    requireGlobalFolders: tried(() => require('wardlatch-no-such-package')),
    resolveFilename: tried(() => Module._resolveFilename(path.join(h, 'missing.cjs'), null)),
    resolveFilenamePackage: tried(() => Module._resolveFilename('wardlatch-no-such-package', { id: 'x', filename: path.join(m.checkout, 'x.cjs'), paths: Module._nodeModulePaths(m.checkout) })),
    chdir: tried(() => process.chdir(h)),
    programThere: tried(() => cp.spawnSync(path.join(h, 'prog'))),
    programFromItsFolder: tried(() => cp.spawnSync('../../home/secret', [], { cwd: path.join(m.tmp, 'lbin') })),
    workingFolderThere: tried(() => cp.spawnSync('/bin/echo', [], { cwd: h })),
    shellWorkingFolderThere: tried(() => cp.execSync('true', { cwd: h })),
    forkThere: tried(() => cp.fork(path.join(h, 'mod.cjs'))),
    pathFolderThere: tried(() => cp.spawnSync('wardlatch-no-such-program', [], { env: { PATH: path.join(h, 'bin') + ':/usr/bin:/bin' } })),
    pathLinkThere: tried(() => cp.spawnSync('tool', [], { env: { PATH: path.join(m.tmp, 'lbin') + ':/usr/bin:/bin' } })),
  };
  if (has.glob) Object.assign(out, {
    globStart: tried(() => fs.globSync(path.join(h, '*'))),
    globCwd: tried(() => fs.globSync('*', { cwd: h })),
    globWalk: tried(() => fs.globSync(path.join(path.dirname(h), '**', 'secret'))),
    globUp: tried(() => fs.globSync(m.tmp + '/*/../../home/secret')),
    globPromise: await triedAsync(async () => { for await (const x of fs.promises.glob('*', { cwd: h })) void x; }),
  });
  if (has.hooks) Object.assign(out, {
    importPath: await triedAsync(() => import(url(path.join(h, 'mod.mjs')))),
    importMissing: await triedAsync(() => import(url(path.join(h, 'missing.mjs')))),
    importUp: await triedAsync(() => import(url(path.join(m.checkout, 'up.mjs')))),
    importLinked: await triedAsync(() => import(url(path.join(m.checkout, 'linked.mjs')))),
    importPackage: await triedAsync(() => import(url(path.join(m.checkout, 'pkg.mjs')))),
  });
  if (has.utf8) out.utf8Stream = tried(() => new fs.Utf8Stream({ dest: path.join(h, 'u'), sync: true }));
  report(out);
})();`);
  allRefused(r, [...'readStream readStreamCalled writeStream fileReadStream fileWriteStream subclass symlinkToUrl requirePath requireMissing requireResolve requireUp requirePackage requireGlobalFolders resolveFilename resolveFilenamePackage chdir programThere programFromItsFolder workingFolderThere shellWorkingFolderThere forkThere pathFolderThere pathLinkThere'.split(' '),
    ...(has.glob ? ['globStart', 'globCwd', 'globWalk', 'globUp', 'globPromise'] : []),
    ...(has.hooks ? ['importPath', 'importMissing', 'importUp', 'importLinked', 'importPackage'] : []), ...(has.utf8 ? ['utf8Stream'] : [])]);
  // the clean twin: the same routes on the test's own folders, a module in the checkout that stays in it, and a program
  // found before PATH reaches a folder in the home (a glob in a folder of its own: tmp holds a link into the home)
  mkdirSync(join(m.tmp, 'clean')); writeFileSync(join(m.tmp, 'clean', 'f'), 'f\n');
  const c = probe(m, `const { pathToFileURL } = require('node:url');
(async () => {
  const out = {
    readStream: tried(() => new fs.ReadStream(path.join(m.tmp, 'ok')).destroy()),
    require: tried(() => require('node:path')), import: await triedAsync(() => import(pathToFileURL(path.join(m.checkout, 'fine.mjs')).href)),
    chdir: tried(() => process.chdir(m.tmp)), spawn: tried(() => cp.spawnSync('/bin/echo', [], { cwd: m.tmp })),
    pathBefore: tried(() => cp.spawnSync('echo', [], { env: { PATH: '/bin:' + path.join(m.home, 'bin') } })),
  };
  if (${has.glob}) out.glob = tried(() => fs.globSync('*', { cwd: path.join(m.tmp, 'clean') }));
  report(out);
})();`);
  assert.deepEqual(c.out, { readStream: 'not refused', require: 'not refused', import: 'not refused', chdir: 'not refused', spawn: 'not refused', pathBefore: 'not refused', ...(has.glob ? { glob: 'not refused' } : {}) }, c.err);
  assert.equal(c.code, 0, c.err);
});

test('a walk that can reach the home is refused: a recursive readdir (every form) or opendir, a copy, a recursive watch or a glob below which a link leads into it, and one of those or rm from a folder that holds it; the same walks elsewhere do their work', () => {
  const m = machine('walks');
  // tmp/start/sub/link: a link to the home's folder, two folders down (a fixture that links to a home, say)
  mkdirSync(join(m.tmp, 'start', 'sub'), { recursive: true }); symlinkSync(m.home, join(m.tmp, 'start', 'sub', 'link'));
  // a link to a file in the home (readdir stats what each name leads to), and a link to tmp/start (two hops)
  mkdirSync(join(m.tmp, 'file-link')); symlinkSync(join(m.home, 'secret'), join(m.tmp, 'file-link', 'secret'));
  mkdirSync(join(m.tmp, 'hop')); symlinkSync(join(m.tmp, 'start'), join(m.tmp, 'hop', 'to-start'));
  // clean: a link that stays outside the home, a link back up (a loop), and one in a folder rm empties (rm never follows it)
  mkdirSync(join(m.tmp, 'clean', 'a'), { recursive: true }); writeFileSync(join(m.tmp, 'clean', 'a', 'f'), 'f\n');
  mkdirSync(join(m.tmp, 'elsewhere')); writeFileSync(join(m.tmp, 'elsewhere', 'g'), 'g\n');
  symlinkSync(join(m.tmp, 'elsewhere'), join(m.tmp, 'clean', 'a', 'there'));
  mkdirSync(join(m.tmp, 'loop', 'a'), { recursive: true }); symlinkSync('..', join(m.tmp, 'loop', 'a', 'up'));
  mkdirSync(join(m.tmp, 'gone')); symlinkSync(m.home, join(m.tmp, 'gone', 'link'));
  const has = { glob: typeof nodeFs.globSync === 'function' };
  // (no probe walks /, /System, /System/Volumes or /Volumes, which hold the real home: a net with a hole would walk it)
  const r = probe(m, `const s = path.join(m.tmp, 'start'), base = path.dirname(m.home), noop = () => {}, has = ${J(has)};
(async () => {
  const out = {
    readdirSync: tried(() => fs.readdirSync(s, { recursive: true })),
    readdirSyncTypes: tried(() => fs.readdirSync(s, { recursive: true, withFileTypes: true })),
    readdirCallback: tried(() => fs.readdir(s, { recursive: true }, noop)),
    readdirPromise: await triedAsync(() => fs.promises.readdir(s, { recursive: true })),
    readdirFileLink: tried(() => fs.readdirSync(path.join(m.tmp, 'file-link'), { recursive: true })),
    readdirTwoHops: tried(() => fs.readdirSync(path.join(m.tmp, 'hop'), { recursive: true })),
    opendirSync: tried(() => fs.opendirSync(s, { recursive: true }).closeSync()),
    opendirPromise: await triedAsync(async () => (await fs.promises.opendir(s, { recursive: true })).close()),
    cpSync: tried(() => fs.cpSync(s, path.join(m.tmp, 'copy-1'), { recursive: true, dereference: true })),
    cpPromise: await triedAsync(() => fs.promises.cp(s, path.join(m.tmp, 'copy-2'), { recursive: true, dereference: true })),
    watch: tried(() => fs.watch(s, { recursive: true, persistent: false }).close()),
    readdirHolds: tried(() => fs.readdirSync(base, { recursive: true })),
    cpHolds: tried(() => fs.cpSync(base, path.join(m.tmp, 'copy-3'), { recursive: true })),
    watchHolds: tried(() => fs.watch(base, { recursive: true, persistent: false }).close()),
  };
  if (has.glob) Object.assign(out, {
    glob: tried(() => fs.globSync('*/link/*', { cwd: s })),
    globPromise: await triedAsync(async () => { for await (const x of fs.promises.glob('*/link/*', { cwd: s })) void x; }),
  });
  // last: rm from a folder that holds the home would remove this whole made-up machine
  out.rmHolds = tried(() => fs.rmSync(base, { recursive: true, force: true }));
  out.rmPromiseHolds = await triedAsync(() => fs.promises.rm(base, { recursive: true, force: true }));
  report(out);
})();`);
  allRefused(r, ['readdirSync', 'readdirSyncTypes', 'readdirCallback', 'readdirPromise', 'readdirFileLink', 'readdirTwoHops', 'opendirSync', 'opendirPromise',
    'cpSync', 'cpPromise', 'watch', 'readdirHolds', 'cpHolds', 'watchHolds', ...(has.glob ? ['glob', 'globPromise'] : []), 'rmHolds', 'rmPromiseHolds']);
  // the clean twin: the same walks where every link stays outside the home, a loop, and rm of a folder with a link in it
  const c = probe(m, `const s = path.join(m.tmp, 'clean'), names = (v) => [...v].map(String).sort(), has = ${J(has)};
const p = require('node:util').promisify;
(async () => {
  const out = {
    readdirSync: names(fs.readdirSync(s, { recursive: true })),
    readdirCallback: names(await p(fs.readdir)(s, { recursive: true })),
    readdirPromise: names(await fs.promises.readdir(s, { recursive: true })),
    loop: tried(() => fs.readdirSync(path.join(m.tmp, 'loop'), { recursive: true })),
    opendirSync: (() => { const d = fs.opendirSync(s, { recursive: true }), a = []; let e; while ((e = d.readSync())) a.push(path.relative(s, path.join(e.parentPath ?? e.path ?? s, e.name))); d.closeSync(); return names(a); })(),
    cpSync: (fs.cpSync(s, path.join(m.tmp, 'copy-c'), { recursive: true, dereference: true }), fs.readFileSync(path.join(m.tmp, 'copy-c', 'a', 'there', 'g'), 'utf8')),
    watch: (() => { try { fs.watch(s, { recursive: true, persistent: false }).close(); return 'watched'; } catch (e) { return e.code; } })(),
    rm: (fs.rmSync(path.join(m.tmp, 'gone'), { recursive: true }), fs.existsSync(path.join(m.tmp, 'gone'))),
  };
  if (has.glob) out.glob = names(fs.globSync('*/there/*', { cwd: s }));
  report(out);
})();`);
  assert.ok(c.out, `the probe reported nothing: ${c.err.slice(-4000)}`);
  const { opendirSync, watch, ...rest } = c.out;
  const all = ['a', 'a/f', 'a/there', 'a/there/g'];
  assert.deepEqual(rest, { readdirSync: all, readdirCallback: all, readdirPromise: all, loop: 'not refused', cpSync: 'g\n', rm: false, ...(has.glob ? { glob: ['a/there/g'] } : {}) }, c.err);
  // a recursive opendir doesn't follow links (a Node without its recursive option lists the top only); a recursive
  // watch is Linux's from Node 20
  assert.ok([J(all.slice(0, 3)), J(['a'])].includes(J(opendirSync)), J(opendirSync));
  assert.ok(watch === 'watched' || (!MAC && watch === 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM'), watch);
  assert.equal(c.code, 0, c.err);
  assert.equal(readFileSync(join(m.home, 'secret'), 'utf8'), 'secret\n', 'rm followed the link into the home');
});

test('a call that never follows the link its path names last (lstat, readlink, unlink, rmdir, rm, lchown, lutimes) takes a link into the home as a link, as Node\'s own rm does each name below its start; through a link on the way, with a \'/\', \'.\' or \'..\' after it, or by a call that follows it, a look in the home is refused', () => {
  const m = machine('leaf');
  // tmp/<x>: links to the home's folder (one for each call that takes one away); tmp/fl: a link to a file there;
  // tmp/g<n>: a folder that holds a link to the home; tmp/via/link: one gone through; in the home, inner (a link) and sub
  for (const x of ['l', 'u1', 'u2', 'u3', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'slash']) symlinkSync(m.home, join(m.tmp, x));
  symlinkSync(join(m.home, 'secret'), join(m.tmp, 'fl'));
  for (const x of ['g1', 'g2', 'g3']) { mkdirSync(join(m.tmp, x)); symlinkSync(m.home, join(m.tmp, x, 'link')); writeFileSync(join(m.tmp, x, 'f'), 'f\n'); }
  mkdirSync(join(m.tmp, 'via')); symlinkSync(m.home, join(m.tmp, 'via', 'link'));
  mkdirSync(join(m.home, 'sub')); symlinkSync(join(m.home, 'secret'), join(m.home, 'inner'));
  const head = `const t = (x) => path.join(m.tmp, x), uid = process.getuid(), gid = process.getgid();
const cb = (f, ...a) => new Promise((res, rej) => f(...a, (e, v) => (e ? rej(e) : res(v))));
const did = async (f) => { try { return (await f()) === true ? 'works' : 'wrong result'; } catch (e) { return e.code === 'EREALHOME' ? 'refused' : 'failed: ' + e.code; } };
const gone = (...x) => { const left = fs.readdirSync(m.tmp); return x.every((y) => !left.includes(y)); };\n`;
  // the regression (CI run 40241781535: the net read lstat's and unlink's link to its end, and refused Node's own rm of
  // a folder with a link into the home in it, on Node 20 and 22, where rmSync calls the wrapped functions; fs.rm and
  // fs.promises.rm do on every Node): each such call in every form, on a link into the home, does its work
  const c = probe(m, `${head}(async () => {
  const out = {
    lstat: await did(async () => fs.lstatSync(t('l')).isSymbolicLink() && (await cb(fs.lstat, t('l'))).isSymbolicLink() && (await fs.promises.lstat(t('l'))).isSymbolicLink()
      && fs.lstatSync(t('fl')).isSymbolicLink()),
    readlink: await did(async () => fs.readlinkSync(t('l')) === m.home && await cb(fs.readlink, t('l')) === m.home && await fs.promises.readlink(t('l')) === m.home),
    lutimes: await did(async () => { fs.lutimesSync(t('l'), 1000, 2000); await cb(fs.lutimes, t('l'), 1000, 3000); await fs.promises.lutimes(t('l'), 1000, 4000); return fs.lstatSync(t('l')).mtimeMs === 4000000; }),
    lchown: await did(async () => { fs.lchownSync(t('l'), uid, gid); await cb(fs.lchown, t('l'), uid, gid); await fs.promises.lchown(t('l'), uid, gid); return fs.lstatSync(t('l')).uid === uid; }),
    // with '..' after the link, the system follows it and goes up out of the home: the folder above it
    upOut: await did(() => fs.lstatSync(t('via/link') + '/..').isDirectory() && fs.lstatSync(t('via/link') + '/..').ino === fs.lstatSync(path.dirname(m.home)).ino),
    // (macOS) the link by the start-up disk's other name, read by its text too
    ...(${MAC} ? { volume: await did(() => fs.lstatSync('/System/Volumes/Data' + fs.realpathSync(m.tmp) + '/l').isSymbolicLink()) } : {}),
    // (rmdir takes no link away: the system says so, not the net)
    rmdir: await did(() => { try { fs.rmdirSync(t('l')); } catch (e) { if (e.code === 'ENOTDIR') return true; throw e; } return false; }),
    unlink: await did(async () => { fs.unlinkSync(t('u1')); await cb(fs.unlink, t('u2')); await fs.promises.unlink(t('u3')); return gone('u1', 'u2', 'u3'); }),
    rm: await did(async () => { fs.rmSync(t('r1')); await cb(fs.rm, t('r2')); await fs.promises.rm(t('r3')); return gone('r1', 'r2', 'r3'); }),
    rmFolder: await did(async () => { fs.rmSync(t('g1'), { recursive: true }); await cb(fs.rm, t('g2'), { recursive: true }); await fs.promises.rm(t('g3'), { recursive: true }); return gone('g1', 'g2', 'g3'); }),
    rmLink: await did(async () => { fs.rmSync(t('r4'), { recursive: true }); await cb(fs.rm, t('r5'), { recursive: true, force: true }); await fs.promises.rm(t('r6'), { recursive: true }); return gone('r4', 'r5', 'r6'); }),
  };
  report(out);
})();`);
  assert.ok(c.out, `the probe reported nothing: ${c.err.slice(-4000)}`);
  assert.deepEqual(c.out, Object.fromEntries(['lstat', 'readlink', 'lutimes', 'lchown', 'upOut', ...(MAC ? ['volume'] : []), 'rmdir', 'unlink', 'rm', 'rmFolder', 'rmLink'].map((k) => [k, 'works'])), c.err);
  assert.equal(c.code, 0, c.err);
  assert.deepEqual(readdirSync(m.home).sort(), ['dev', 'inner', 'secret', 'sub'], 'a call took something in the home away');
  // the biting twin: the same calls where the system does go into the home (a link on the way, a '/', '.' or '..' after
  // the last link, a path in the home itself), and a call that follows the last link; a 1 MB path read in one pass. A
  // net with a hole would take the made-up home's files away: rm with a '/' after the link empties it
  const r = probe(m, `${head}(async () => {
  const out = {
    lstatThrough: await did(() => fs.lstatSync(t('via/link/secret'))),
    lstatThroughPromise: await did(() => fs.promises.lstat(t('via/link/secret'))),
    readlinkThrough: await did(() => fs.readlinkSync(t('via/link/inner'))),
    lutimesThrough: await did(() => fs.lutimesSync(t('via/link/inner'), 1000, 2000)),
    lchownThrough: await did(() => fs.lchownSync(t('via/link/inner'), uid, gid)),
    unlinkThrough: await did(() => fs.unlinkSync(t('via/link/inner'))),
    rmdirThrough: await did(() => fs.rmdirSync(t('via/link/sub'))),
    rmThrough: await did(() => fs.promises.rm(t('via/link/sub'), { recursive: true })),
    lstatSlash: await did(() => fs.lstatSync(t('l') + '/')),
    lstatDot: await did(() => fs.lstatSync(t('l') + '/.')),
    lstatDotDot: await did(() => fs.lstatSync(t('via/link/sub') + '/..')),
    lstatHome: await did(() => fs.lstatSync(m.home)),
    unlinkInHome: await did(() => fs.unlinkSync(path.join(m.home, 'inner'))),
    statFollows: await did(() => fs.statSync(t('l'))),
    readdirFollows: await did(() => fs.readdirSync(t('l'))),
    readFileFollows: await did(() => fs.readFileSync(t('fl'))),
    ${MAC ? "lstatVolume: await did(() => fs.lstatSync('/System/Volumes/Data' + t('via/link/secret')))," : ''}
    rmSlash: await did(() => fs.rmSync(t('slash') + '/', { recursive: true, force: true })),
    rmPromiseSlash: await did(() => fs.promises.rm(t('slash') + '/', { recursive: true, force: true })),
  };
  const t0 = Date.now();
  out.longDots = await did(() => fs.lstatSync('/.'.repeat(500000) + path.join(m.home, 'secret')));
  out.fast = Date.now() - t0 < 2000 ? 'refused' : (Date.now() - t0) + ' ms';
  report(out);
})();`);
  allRefused(r, ['lstatThrough', 'lstatThroughPromise', 'readlinkThrough', 'lutimesThrough', 'lchownThrough', 'unlinkThrough', 'rmdirThrough', 'rmThrough',
    'lstatSlash', 'lstatDot', 'lstatDotDot', 'lstatHome', 'unlinkInHome', 'statFollows', 'readdirFollows', 'readFileFollows',
    ...(MAC ? ['lstatVolume'] : []), 'rmSlash', 'rmPromiseSlash', 'longDots', 'fast']);
  assert.equal(readFileSync(join(m.home, 'secret'), 'utf8'), 'secret\n');
  assert.deepEqual(readdirSync(m.home).sort(), ['dev', 'inner', 'secret', 'sub'], 'a call took something in the home away');
});

test('the routes that open files without fs are refused: a Worker thread (its own fs, at any depth, its environment shared or not), process.loadEnvFile, and node:sqlite (a database, a backup, an extension, a file SQL attaches) however it is loaded or its class reached', () => {
  const m = machine('threads');
  writeFileSync(join(m.home, 'mod.cjs'), 'module.exports = 1;\n'); writeFileSync(join(m.home, '.env'), 'WL_FROM_ENV=home\n'); writeFileSync(join(m.tmp, '.env'), 'WL_FROM_ENV=tmp\n');
  const esm = put(m, 'esm-worker.mjs', `import { readFileSync } from 'node:fs';\nreadFileSync(${J(join(m.home, 'secret'))});\n`);
  // what this Node has, asked of a Node of its own without the net (so this test file never loads node:sqlite, and a
  // net that refused a way in tmp couldn't make it read as missing): it opens a database in tmp, nothing more
  const has = JSON.parse(execFileSync(process.execPath, ['--no-warnings', '-e', `let s = null; try { s = require('node:sqlite'); } catch {}
const opens = (p) => { try { new s.DatabaseSync(p).close(); return true; } catch { return false; } };
console.log(JSON.stringify({ loadEnvFile: typeof process.loadEnvFile === 'function', sqlite: !!s, authorizer: typeof s?.DatabaseSync.prototype.setAuthorizer === 'function',
  backup: typeof s?.backup === 'function', database: typeof s?.Database === 'function', loadExtension: typeof s?.DatabaseSync.prototype.loadExtension === 'function',
  bufferPath: !!s && opens(Buffer.from(${J(join(m.tmp, 'has.db'))})), urlPath: !!s && opens(require('node:url').pathToFileURL(${J(join(m.tmp, 'has.db'))})),
  getBuiltin: typeof process.getBuiltinModule === 'function', hooks: typeof require('node:module').registerHooks === 'function' }));`],
  { encoding: 'utf8', env: { ...process.env, WARDLATCH_TEST_NO_HOME: '' } }));
  const workers = `const { Worker, SHARE_ENV } = require('node:worker_threads');
const reads = (f) => "require('fs').readFileSync(" + JSON.stringify(f) + "); require('worker_threads').parentPort.postMessage('READ');";
const run = (code, o = {}) => new Promise((res) => {
  let w, got = null;
  try { w = new Worker(code, { eval: true, ...o }); } catch (e) { return res(e.code === 'EREALHOME' ? 'refused' : 'threw ' + e.code); }
  w.on('message', (x) => { got = x; }).on('error', (e) => res('error ' + (e.code ?? e.message))).on('exit', (c) => res(got ?? c));
});\n`;
  const s = join(m.home, 'secret');
  const w = probe(m, `${workers}(async () => report({
  worker: await run(reads(${J(s)})),
  ownEnv: await run(reads(${J(s)}), { env: { PATH: '/usr/bin:/bin' } }),
  sharedEnv: await run(reads(${J(s)}), { env: SHARE_ENV }),
  execArgv: await run(reads(${J(s)}), { execArgv: ['--no-warnings'] }),
  esm: await run(${J(esm)}, { eval: false }),
  fileThere: await run(${J(join(m.home, 'mod.cjs'))}, { eval: false }),
  nested: await run("new (require('worker_threads').Worker)(" + JSON.stringify(reads(${J(s)})) + ", { eval: true }).on('exit', (c) => require('worker_threads').parentPort.postMessage(c));"),
}))();`);
  assert.deepEqual(w.out, { worker: 70, ownEnv: 70, sharedEnv: 70, execArgv: 70, esm: 70, fileThere: 'refused', nested: 70 }, w.err);
  assert.equal(w.code, 1, w.err);
  // a refusal in a Worker whose end nothing reads still fails the test file
  const quiet = probe(m, `${workers}new Worker(reads(${J(s)}), { eval: true }).on('exit', () => report({ ended: true }));`);
  assert.deepEqual(quiet.out, { ended: true }, quiet.err);
  assert.equal(quiet.code, 1, 'the test file passed though a Worker it started was stopped');
  assert.match(quiet.err, /process \d+, thread \d+ .*was stopped \(exit 70\)/);
  // the clean twin: the same Workers reading tmp, and what one sees: its own NODE_OPTIONS, not the net's variable, and
  // SHARE_ENV still shared
  const ok = join(m.tmp, 'ok');
  const sees = "require('worker_threads').parentPort.postMessage([process.env.NODE_OPTIONS ?? null, 'WARDLATCH_TEST_NO_HOME' in process.env]);";
  const wc = probe(m, `${workers}(async () => report({
  worker: await run(reads(${J(ok)})),
  ownEnv: await run(reads(${J(ok)}), { env: { PATH: '/usr/bin:/bin' } }),
  sharedEnv: await run(reads(${J(ok)}), { env: SHARE_ENV }),
  execArgv: await run(reads(${J(ok)}), { execArgv: ['--no-warnings'] }),
  sees: await run(${J(sees)}, { env: { ...process.env, NODE_OPTIONS: '--no-deprecation' } }),
  seesUnset: await run(${J(sees)}),
  shared: (await run("process.env.WL_SHARED = 'yes';", { env: SHARE_ENV }), process.env.WL_SHARED),
}))();`);
  assert.deepEqual(wc.out, { worker: 'READ', ownEnv: 'READ', sharedEnv: 'READ', execArgv: 'READ', sees: ['--no-deprecation', false], seesUnset: [null, false], shared: 'yes' }, wc.err);
  assert.equal(wc.code, 0, wc.err);

  if (has.loadEnvFile) {
    const e = probe(m, `report({ path: tried(() => process.loadEnvFile(${J(join(m.home, '.env'))})), buffer: tried(() => process.loadEnvFile(Buffer.from(${J(join(m.home, '.env'))}))),
  url: tried(() => process.loadEnvFile(require('node:url').pathToFileURL(${J(join(m.home, '.env'))}))), fromCwd: tried(() => process.loadEnvFile()) });`, {}, m.home);
    allRefused(e, ['path', 'buffer', 'url', 'fromCwd']);
    const ec = probe(m, `process.loadEnvFile(); const a = process.env.WL_FROM_ENV; delete process.env.WL_FROM_ENV; process.loadEnvFile(${J(join(m.tmp, '.env'))}); report([a, process.env.WL_FROM_ENV]);`);
    assert.deepEqual(ec.out, ['tmp', 'tmp'], ec.err);
    assert.equal(ec.code, 0, ec.err);
  }

  if (has.sqlite) {
    const h = (x) => J(join(m.home, x)), t = (x) => J(join(m.tmp, x));
    // the database opened first by each way of loading node:sqlite, so each wraps it; and require() on a Node without
    // module.registerHooks (22.5 to 22.14), whose hook would otherwise see it first
    const older = put(m, 'older-node.cjs', 'require(\'node:module\').registerHooks = undefined;\n');
    const ways = { require: ["require('node:sqlite')"], olderRequire: ["require('node:sqlite')", { NODE_OPTIONS: `--require ${older}` }],
      ...(has.getBuiltin ? { getBuiltin: ["process.getBuiltinModule('node:sqlite')"] } : {}), ...(has.hooks ? { import: ["await import('node:sqlite')"] } : {}) };
    for (const [way, [load, env]] of Object.entries(ways)) {
      const r = probe(m, `(async () => { const { DatabaseSync } = ${load}; report({ open: tried(() => new DatabaseSync(${h('x.db')})) }); })();`, env);
      assert.deepEqual(r.out, { open: 'refused' }, `${way}: ${r.err}`);
    }
    const r = probe(m, `const sq = require('node:sqlite'), { DatabaseSync, Database } = sq, c = sq.constants, has = ${J(has)};
(async () => {
  const db = new DatabaseSync(':memory:', { allowExtension: true });
  const out = { uri: tried(() => new DatabaseSync('file:' + ${t('uri.db')})),
    // the class as its prototype and every database it makes give it
    rawConstructor: tried(() => new db.constructor(${h('x.db')})),
    prototypeConstructor: tried(() => new (Object.getPrototypeOf(db).constructor)(${h('x.db')})) };
  if (has.database) out.databaseConstructor = tried(() => new Database.prototype.constructor(${h('x.db')}));
  if (has.database) out.database = tried(() => new Database(${h('x.db')}));
  if (has.bufferPath) out.buffer = tried(() => new DatabaseSync(Buffer.from(${h('x.db')})));
  if (has.urlPath) out.url = tried(() => new DatabaseSync(require('node:url').pathToFileURL(${h('x.db')})));
  if (has.loadExtension) out.loadExtension = tried(() => db.loadExtension(${h('ext')}));
  if (has.backup) out.backup = await triedAsync(() => sq.backup(db, ${h('b.db')}));
  if (has.authorizer) Object.assign(out, {
    attach: tried(() => db.exec("ATTACH DATABASE " + ${J(`'${join(m.home, 'a.db')}'`)} + " AS a")),
    vacuumInto: tried(() => db.exec("VACUUM INTO " + ${J(`'${join(m.home, 'v.db')}'`)})),
    attachUri: tried(() => db.exec("ATTACH 'file:" + ${t('a.db')} + "' AS b")),
    attachBound: tried(() => db.prepare('ATTACH ? AS c')),
    loadExtensionSql: tried(() => db.exec("SELECT load_extension('x')")),
    afterOwn: tried(() => { db.setAuthorizer(() => c.SQLITE_OK); db.exec("ATTACH DATABASE " + ${J(`'${join(m.home, 'a.db')}'`)} + " AS d"); }),
    afterNull: tried(() => { db.setAuthorizer(null); db.exec("ATTACH DATABASE " + ${J(`'${join(m.home, 'a.db')}'`)} + " AS e"); }),
    opened: tried(() => { const d = new DatabaseSync(':memory:', { open: false }); d.open(); d.exec("ATTACH DATABASE " + ${J(`'${join(m.home, 'a.db')}'`)} + " AS f"); }),
  });
  report(out);
})();`);
    allRefused(r, ['uri', 'rawConstructor', 'prototypeConstructor', ...(has.database ? ['databaseConstructor'] : []),
      ...['database', 'buffer', 'url', 'loadExtension', 'backup'].filter((k) => has[k === 'buffer' || k === 'url' ? `${k}Path` : k]),
      ...(has.authorizer ? ['attach', 'vacuumInto', 'attachUri', 'attachBound', 'loadExtensionSql', 'afterOwn', 'afterNull', 'opened'] : [])]);
    assert.deepEqual(readdirSync(m.home).filter((f) => f.endsWith('.db')), [], 'a database was made in the home');
    // the clean twin: the same in tmp, and the test's own authorizer still has its say
    const sc = probe(m, `const sq = require('node:sqlite'), { DatabaseSync, Database } = sq, c = sq.constants, has = ${J(has)};
(async () => {
  const db = new DatabaseSync(${t('ok.db')});
  db.exec('CREATE TABLE t (x); INSERT INTO t VALUES (7)');
  const out = { read: db.prepare('SELECT x FROM t').get().x, memory: (new DatabaseSync(':memory:').close(), 'opened'),
    rawConstructor: new db.constructor(${t('ok.db')}).prepare('SELECT x FROM t').get().x, sameClass: new db.constructor(':memory:') instanceof DatabaseSync };
  if (has.database) out.database = (new Database(${t('d.db')}).close(), 'opened');
  if (has.bufferPath) out.buffer = (new DatabaseSync(Buffer.from(${t('ok.db')})).close(), 'opened');
  if (has.urlPath) out.url = new DatabaseSync(require('node:url').pathToFileURL(${t('ok.db')})).prepare('SELECT x FROM t').get().x;
  if (has.loadExtension) out.loadExtension = tried(() => new DatabaseSync(':memory:', { allowExtension: true }).loadExtension(${t('no-such-ext')}));
  if (has.backup) out.backup = (await sq.backup(db, ${t('b.db')}), new DatabaseSync(${t('b.db')}).prepare('SELECT x FROM t').get().x);
  if (has.authorizer) {
    db.exec("ATTACH DATABASE " + ${J(`'${join(m.tmp, 'a.db')}'`)} + " AS a; CREATE TABLE a.u (y); DETACH a");
    db.exec("VACUUM INTO " + ${J(`'${join(m.tmp, 'v.db')}'`)});
    out.attached = new DatabaseSync(${t('a.db')}).prepare("SELECT name FROM sqlite_master").get().name;
    out.vacuumed = new DatabaseSync(${t('v.db')}).prepare('SELECT x FROM t').get().x;
    db.setAuthorizer((action) => (action === c.SQLITE_DELETE ? c.SQLITE_DENY : c.SQLITE_OK));
    out.ownDenies = tried(() => db.exec('DELETE FROM t'));
  }
  report(out);
})();`);
    assert.ok(sc.out, `the probe reported nothing: ${sc.err.slice(-4000)}`);
    const { loadExtension, ...rest } = sc.out;
    assert.deepEqual(rest, { read: 7, memory: 'opened', rawConstructor: 7, sameClass: true, ...(has.database ? { database: 'opened' } : {}), ...(has.bufferPath ? { buffer: 'opened' } : {}),
      ...(has.urlPath ? { url: 7 } : {}), ...(has.backup ? { backup: 7 } : {}), ...(has.authorizer ? { attached: 'u', vacuumed: 7, ownDenies: 'not refused: ERR_SQLITE_ERROR' } : {}) }, sc.err);
    // (there is no extension to load: SQLite answers, not the net)
    if (has.loadExtension) assert.match(loadExtension, /^not refused: /);
    assert.equal(sc.code, 0, sc.err);
  }
});

test('a package in the checkout\'s own node_modules loads by name, by require() and import, from a checkout in the home; going on into the home\'s node_modules above it is refused, for a package name or a \'#\' name of package.json\'s imports', () => {
  // the made-up machine reached through a link, as a temporary folder is on macOS (/var/folders is /private/var/folders
  // there, as CI's runners name it), on every system: require.resolve gives a file's real path (CI run 40241781535)
  mkdirSync(join(dir, 'packages-real')); symlinkSync(join(dir, 'packages-real'), join(dir, 'packages-link'));
  const m = machine(join('packages-link', 'packages'));
  writeFileSync(join(m.checkout, 'package.json'), J({ name: 'wardlatch-probe-checkout', private: true }));
  const pkg = (dir, name, value, main = 'main.js') => {
    const d = join(dir, 'node_modules', name); mkdirSync(d, { recursive: true });
    writeFileSync(join(d, 'package.json'), J({ name, main })); writeFileSync(join(d, 'main.js'), `module.exports = ${J(value)};\n`);
  };
  pkg(m.checkout, 'wl-local', 'local'); pkg(m.checkout, '@wl/scoped', 'scoped');
  // in the home above the checkout: packages the checkout lacks, one in a scope the checkout has (import goes on up past
  // node_modules/@wl when node_modules/@wl/<name> isn't there), and ones whose main is missing, so Node finds no file
  // there and only a refusal before it looks can tell (a package found there is also refused after, where it led)
  const up = join(m.home, 'dev');
  pkg(up, 'wl-above', 'above'); pkg(up, '@wl/above', 'above'); pkg(up, 'wl-broken', 'broken', 'missing.js'); pkg(up, '@wl/broken', 'broken', 'missing.js');
  // and one linked into the checkout's node_modules from the home (as npm link makes one)
  pkg(join(m.home, 'linked'), 'wl-linked', 'linked', 'missing.js'); symlinkSync(join(m.home, 'linked', 'node_modules', 'wl-linked'), join(m.checkout, 'node_modules', 'wl-linked'));
  const mod = (name, text) => { writeFileSync(join(m.checkout, name), text); return J(pathToFileURL(join(m.checkout, name)).href); };
  const local = { cjs: mod('local.cjs', "module.exports = [require('wl-local'), require('@wl/scoped'), require('wl-local/main.js')];\n"),
    mjs: mod('local.mjs', "import a from 'wl-local'; import b from '@wl/scoped'; export default [a, b];\n") };
  const names = ['wl-above', '@wl/above', 'wl-broken', '@wl/broken', 'wl-nowhere', 'wl-linked'];
  const above = Object.fromEntries(names.flatMap((x, i) => [[`require ${x}`, JSON.parse(mod(`above-${i}.cjs`, `require(${J(x)});\n`))], [`import ${x}`, JSON.parse(mod(`above-${i}.mjs`, `import ${J(x)};\n`))]]));
  // a '#' name of package.json's imports that names a package the checkout lacks: Node looks for that package as an
  // import does, up from the folder of that package.json (each in a folder of its own in the checkout, with a
  // package.json of its own; a condition and a pattern among them)
  const hashes = { 'wl-above': 'wl-above', '@wl/above': '@wl/above', 'wl-broken': 'wl-broken', 'wl-nowhere': 'wl-nowhere',
    condition: { node: 'wl-nowhere', default: './x.js' }, pattern: 'wl-*' };
  Object.entries(hashes).forEach(([x, target], i) => {
    mkdirSync(join(m.checkout, `hash-${i}`));
    writeFileSync(join(m.checkout, `hash-${i}`, 'package.json'), J({ imports: { [x === 'pattern' ? '#p/*' : '#x']: target } }));
    const name = x === 'pattern' ? '#p/nowhere' : '#x';
    above[`require #${x}`] = JSON.parse(mod(`hash-${i}/use.cjs`, `require(${J(name)});\n`));
    above[`import #${x}`] = JSON.parse(mod(`hash-${i}/use.mjs`, `import ${J(name)};\n`));
  });
  // and one whose package.json Node reads though JSON.parse can't (Node parses only the fields it reads)
  const junk = '{"imports":{"#x":"wl-nowhere"},"junk":[1,,]}';
  mkdirSync(join(m.checkout, 'hash-junk')); writeFileSync(join(m.checkout, 'hash-junk', 'package.json'), junk);
  above['require #junk'] = JSON.parse(mod('hash-junk/use.cjs', "require('#x');\n"));
  above['import #junk'] = JSON.parse(mod('hash-junk/use.mjs', "import '#x';\n"));
  const all = [...names, ...Object.keys(hashes).map((x) => `#${x}`), '#junk'];
  const hooks = typeof nodeModule.registerHooks === 'function';
  // require() on a Node without module.registerHooks (before 22.15), whose hook would otherwise see the name first
  const older = put(m, 'older-node.cjs', 'require(\'node:module\').registerHooks = undefined;\n');
  const run = (env) => probe(m, `const { fileURLToPath } = require('node:url'), above = ${J(above)};
(async () => {
  const out = {
    resolvePathsAbove: tried(() => require.resolve('wl-above', { paths: [path.join(m.home, 'dev')] })),
    resolvePathsBroken: tried(() => require.resolve('wl-broken', { paths: [path.join(m.home, 'dev')] })),
  };
  for (const [k, u] of Object.entries(above)) {
    if (k.startsWith('require')) out[k] = tried(() => require(fileURLToPath(u)));
    else if (${hooks} && !${!!env}) out[k] = await triedAsync(() => import(u));
  }
  report(out);
})();`, env);
  allRefused(run(), ['resolvePathsAbove', 'resolvePathsBroken', ...all.map((x) => `require ${x}`), ...(hooks ? all.map((x) => `import ${x}`) : [])]);
  allRefused(run({ NODE_OPTIONS: `--require ${older}` }), ['resolvePathsAbove', 'resolvePathsBroken', ...all.map((x) => `require ${x}`)]);
  // the clean twin: the checkout's own packages, by require(), import and require.resolve's paths, and by '#' names a
  // package.json in the checkout maps to them, to a file of its own and (import) to a module of Node's
  const inner = join(m.checkout, 'inner'); mkdirSync(inner);
  writeFileSync(join(inner, 'package.json'), J({ imports: { '#local': 'wl-local', '#scoped': '@wl/scoped', '#file': './file.js', '#builtin': 'path' } }));
  writeFileSync(join(inner, 'file.js'), "module.exports = 'file';\n");
  const hashCjs = mod('inner/use.cjs', "module.exports = [require('#local'), require('#scoped'), require('#file')];\n");
  const hashMjs = mod('inner/use.mjs', "import a from '#local'; import b from '#scoped'; import c from '#file'; import { join } from '#builtin';\nexport default [a, b, c, typeof join];\n");
  // ...and such a package.json outside the home, mapping a '#' name to a file of its own: what Node makes of it is
  // Node's (Node 26 reads it; a Node that parses the whole file refuses it), the same with the net as without
  mkdirSync(join(m.tmp, 'junk'));
  writeFileSync(join(m.tmp, 'junk', 'package.json'), junk.replace('wl-nowhere', './file.js')); writeFileSync(join(m.tmp, 'junk', 'file.js'), "module.exports = 'file';\n");
  writeFileSync(join(m.tmp, 'junk', 'use.cjs'), "module.exports = require('#x');\n"); writeFileSync(join(m.tmp, 'junk', 'use.mjs'), "export { default } from '#x';\n");
  const junkLoads = `(async () => {
  const out = {}, said = (e) => 'Node: ' + (e.code ?? e.name);
  try { out.requireJunk = require(${J(join(m.tmp, 'junk', 'use.cjs'))}); } catch (e) { out.requireJunk = said(e); }
  try { out.importJunk = (await import(${J(pathToFileURL(join(m.tmp, 'junk', 'use.mjs')).href)})).default; } catch (e) { out.importJunk = said(e); }
  return out;
})()`;
  const bareJunk = JSON.parse(execFileSync(process.execPath, ['-e', `${junkLoads}.then((o) => console.log(JSON.stringify(o)));`],
    { encoding: 'utf8', env: { WARDLATCH_TEST_NO_HOME: '', PATH: '/usr/bin:/bin' } }));
  if (Number(process.versions.node.split('.')[0]) >= 26) assert.deepEqual(bareJunk, { requireJunk: 'file', importJunk: 'file' });
  const clean = (env) => probe(m, `const { fileURLToPath } = require('node:url');
(async () => report({
  require: require(fileURLToPath(${local.cjs})),
  import: (await import(${local.mjs})).default,
  resolvePaths: path.relative(fs.realpathSync(m.checkout), fs.realpathSync(require.resolve('wl-local', { paths: [m.checkout] }))),
  requireHash: require(fileURLToPath(${hashCjs})),
  importHash: (await import(${hashMjs})).default,
  ...(await ${junkLoads}),
}))();`, env);
  for (const c of [clean(), clean({ NODE_OPTIONS: `--require ${older}` })]) {
    assert.deepEqual(c.out, { require: ['local', 'scoped', 'local'], import: ['local', 'scoped'], resolvePaths: join('node_modules', 'wl-local', 'main.js'),
      requireHash: ['local', 'scoped', 'file'], importHash: ['local', 'scoped', 'file', 'function'], ...bareJunk }, c.err);
    assert.equal(c.code, 0, c.err);
  }
  // a '#' name from a checkout with no package.json: Node reads those above it, in the home, for one (the net reads
  // none there); the same outside the home finds none, and Node says so
  const bare = machine('packages-bare');
  writeFileSync(join(bare.checkout, 'use.mjs'), "import '#x';\n"); writeFileSync(join(bare.tmp, 'use.mjs'), "import '#x';\n");
  const b = probe(bare, `const { pathToFileURL } = require('node:url'), at = (d) => pathToFileURL(path.join(d, 'use.mjs')).href;
(async () => report(${hooks} ? { checkout: await triedAsync(() => import(at(m.checkout))), outside: await triedAsync(() => import(at(m.tmp))) } : {}))();`);
  assert.deepEqual(b.out, hooks ? { checkout: 'refused', outside: 'not refused: ERR_PACKAGE_IMPORT_NOT_DEFINED' } : {}, b.err);
});

test('the net goes with every Node a test starts: fork, exec, execSync, node by name, a #! script, a shell, another Node, and below the command; the child\'s own NODE_OPTIONS stay its own', (t) => {
  // a space in every path: NODE_OPTIONS must quote the net's (Node reads it as words)
  const m = machine('carry with space');
  const s = join(m.home, 'secret');
  const g = reader(m, 'g.cjs', s);
  const byEnv = reader(m, 'by-env', s, '#!/usr/bin/env node\n');
  const byEnvS = reader(m, 'by-env-s', s, '#!/usr/bin/env -S node --no-warnings\n');
  const byPath = reader(m, 'by-path', s, `#!${process.execPath}\n`);
  // another Node binary (anotherNode, above): a found Node the command runs is one. Where even its copy can't start,
  // that one case is skipped, and the test's output says why
  const other = anotherNode(m);
  if (other.skipped) t.diagnostic(`skipped one case, another Node binary: ${other.skipped}`);
  // not a program: a FIFO the net must not hang on, reading its first bytes
  const fifo = join(m.tmp, 'fifo'); execFileSync('mkfifo', [fifo]);
  // below a process the test started (as the command is), where only a Node gets the net
  const mid = put(m, 'mid.cjs', `const cp = require('child_process'), o = { stdio: 'ignore', timeout: 20000, killSignal: 'SIGKILL' }, r = {};
r.shebangEnv = cp.spawnSync(${J(byEnv)}, o).status;
r.shebangEnvS = cp.spawnSync(${J(byEnvS)}, o).status;
r.shebangPath = cp.spawnSync(${J(byPath)}, o).status;
r.byName = cp.spawnSync('node', [${J(g)}], o).status;
${other.skipped ? '' : `r.otherNode = cp.spawnSync(${J(other.node)}, [${J(g)}], o).status;\n`}r.shellOption = cp.spawnSync('node ' + ${J(J(g))}, { ...o, shell: true }).status;
try { cp.execSync('node ' + ${J(J(g))}, o); r.execSync = 0; } catch (e) { r.execSync = e.status; }
r.fifo = cp.spawnSync(${J(fifo)}, o).error?.code ?? 'ran';
cp.exec('node ' + ${J(J(g))}, o, (e) => { r.exec = e?.code ?? 0; cp.fork(${J(g)}, o).on('exit', (d) => { r.fork = d; console.log(JSON.stringify(r)); }); });
`);
  const r = probe(m, `const g = ${J(g)}, o = { encoding: 'utf8', stdio: 'pipe', timeout: 20000, killSignal: 'SIGKILL' };
const status = (f) => { try { return String(f() ?? '').includes('READ') ? 'READ' : 0; } catch (e) { return e.status ?? e.code; } };
const out = {
  execSync: status(() => cp.execSync('node ' + JSON.stringify(g), o)),
  byName: status(() => cp.execFileSync('node', [g], o)),
  shebangEnv: status(() => cp.execFileSync(${J(byEnv)}, o)),
  shebangPath: status(() => cp.execFileSync(${J(byPath)}, o)),
  shell: status(() => cp.execFileSync('/bin/sh', ['-c', 'node ' + JSON.stringify(g)], o)),
  shellOption: status(() => cp.execFileSync('node ' + JSON.stringify(g), { ...o, shell: true })),
  below: JSON.parse(cp.execFileSync(process.execPath, [${J(mid)}], o)),
};
cp.exec('node ' + JSON.stringify(g), o, (e) => {
  out.exec = e?.code ?? 0;
  cp.fork(g, { stdio: 'ignore' }).on('exit', (c) => { out.fork = c; report(out); });
});`);
  assert.deepEqual(r.out, {
    execSync: 70, byName: 70, shebangEnv: 70, shebangPath: 70, shell: 70, shellOption: 70, exec: 70, fork: 70,
    below: { shebangEnv: 70, shebangEnvS: 70, shebangPath: 70, byName: 70, ...(other.skipped ? {} : { otherNode: 70 }), shellOption: 70, execSync: 70, fifo: 'EACCES', exec: 70, fork: 70 },
  }, r.err);
  assert.equal(r.code, 1, 'the processes it started were stopped: the test file fails');

  // what the child sees: its own NODE_OPTIONS, never the net's, and not the net's variable; a shell script named node
  // that the command (a process the test started) runs gets neither (the command builds its children's environments)
  const show = put(m, 'show.cjs', 'console.log(JSON.stringify([process.env.NODE_OPTIONS ?? null, "WARDLATCH_TEST_NO_HOME" in process.env]));\n');
  const sh = put(m, 'sb/node', '#!/bin/sh\nprintf "%s|%s" "${NODE_OPTIONS-unset}" "${WARDLATCH_TEST_NO_HOME-unset}"\n', 0o755);
  const cmd = put(m, 'cmd.cjs', `process.stdout.write(require('child_process').execFileSync(${J(sh)}, { env: { PATH: '/usr/bin:/bin' } }));\n`);
  // a fork from node -e: Node takes the -e code out of the fork's execArgv, so the fork runs show.cjs, not the -e code
  // again (which, run again, would fork again: WL_DEPTH stops it at one, and it says so)
  const forker = `if (process.env.WL_DEPTH) console.log(JSON.stringify('the -e code ran again in the fork')); else require('child_process').fork(${J(show)}, { env: { ...process.env, WL_DEPTH: '1' } });`;
  const env = probe(m, `const o = { timeout: 20000, killSignal: 'SIGKILL' }, show = ${J(show)};
const run = (f) => JSON.parse(f().toString());
report({
  exec: run(() => cp.execSync('node ' + JSON.stringify(show), { ...o, env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=99' } })),
  execUnset: run(() => cp.execSync('node ' + JSON.stringify(show), o)),
  self: run(() => cp.execFileSync(process.execPath, [show], { ...o, env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=98' } })),
  fork: run(() => cp.execFileSync(process.execPath, ['-e', ${J(forker)}], o)),
  belowCommand: cp.execFileSync(process.execPath, [${J(cmd)}], o).toString(),
});`);
  assert.deepEqual(env.out, {
    exec: ['--max-old-space-size=99', false], execUnset: [null, false], self: ['--max-old-space-size=98', false], fork: [null, false],
    belowCommand: 'unset|unset',
  }, env.err);
  assert.equal(env.code, 0, env.err);
});

test('a Node a test starts with a flag that reads a file as it starts is refused when that file is in the home: --env-file, --env-file-if-exists, --experimental-config-file, --config-file, --experimental-default-config-file, by spawn, execFile, name or fork', () => {
  const m = machine('flags');
  for (const [d, v] of [[m.home, 'home'], [m.tmp, 'tmp']]) { writeFileSync(join(d, '.env'), `WL_FROM_ENV=${v}\n`); writeFileSync(join(d, 'node.config.json'), '{}\n'); }
  const show = put(m, 'show.cjs', "console.log(process.env.WL_FROM_ENV ?? 'none');\n");
  // each flag as flag=path and as flag path (a relative path is from the child's working folder, the probe's: tmp); and
  // node.config.json in that folder, which the config flags without '=' read too on Node 26 (the next word is the script)
  const flags = (d) => ({
    envFile: [`--env-file=${join(d, '.env')}`], envFileWord: ['--env-file', join(d, '.env')],
    envFileIfExists: [`--env-file-if-exists=${join(d, '.env')}`], envFileIfExistsWord: ['--env-file-if-exists', join(d, '.env')],
    envFileRelative: [`--env-file=${relative(m.tmp, join(d, '.env'))}`],
    configFile: [`--experimental-config-file=${join(d, 'node.config.json')}`], configFileWord: ['--experimental-config-file', join(d, 'node.config.json')],
    configFileStable: [`--config-file=${join(d, 'node.config.json')}`],
  });
  const defaults = { defaultConfig: ['--experimental-default-config-file'], configFileAlone: ['--experimental-config-file'], configFileStableAlone: ['--config-file'] };
  const r = probe(m, `const flags = ${J(flags(m.home))}, show = ${J(show)}, out = {};
for (const [k, f] of Object.entries(flags)) out[k] = tried(() => cp.spawnSync(process.execPath, [...f, show]));
out.execFile = tried(() => cp.execFileSync(process.execPath, [...flags.envFile, show]));
out.byName = tried(() => cp.spawnSync('node', [...flags.envFile, show]));
out.fork = tried(() => cp.fork(show, [], { execArgv: flags.envFile, stdio: 'ignore' }));
report(out);`);
  allRefused(r, [...Object.keys(flags(m.home)), 'execFile', 'byName', 'fork']);
  // node.config.json in the working folder: a probe working in the home
  const d = probe(m, `const out = {};
for (const [k, f] of Object.entries(${J(defaults)})) out[k] = tried(() => cp.spawnSync(process.execPath, [...f, ${J(show)}]));
report(out);`, {}, m.home);
  allRefused(d, Object.keys(defaults));
  // the clean twin: the same flags on tmp's files give what they give without the net (a Node without one says so)
  const said = (x) => (x.status === 0 ? x.stdout.trim() : /bad option/.test(x.stderr) ? 'no such flag' : `failed: ${x.status} ${x.stderr}`);
  const all = { ...flags(m.tmp), ...defaults };
  const bare = Object.fromEntries(Object.entries(all).map(([k, f]) => [k,
    said(spawnSync(process.execPath, [...f, show], { cwd: m.tmp, encoding: 'utf8', env: { WARDLATCH_TEST_NO_HOME: '', PATH: '/usr/bin:/bin' } }))]));
  const c = probe(m, `const all = ${J(all)}, show = ${J(show)}, out = {}, said = ${said};
(async () => {
  for (const [k, f] of Object.entries(all)) out[k] = said(cp.spawnSync(process.execPath, [...f, show], { encoding: 'utf8' }));
  out.byName = said(cp.spawnSync('node', [...all.envFile, show], { encoding: 'utf8' }));
  out.fork = await new Promise((res) => {
    const ch = cp.fork(show, [], { execArgv: all.envFile, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    let stdout = '', stderr = '';
    ch.stdout.on('data', (b) => { stdout += b; }); ch.stderr.on('data', (b) => { stderr += b; });
    ch.on('exit', (status) => res(said({ status, stdout, stderr })));
  });
  report(out);
})();`);
  assert.deepEqual(c.out, { ...bare, byName: bare.envFile, fork: bare.envFile }, c.err);
  // (from Node 20.6 the flag reads the file: the twin shows the net left it its work)
  if (Number(process.versions.node.split('.')[0]) >= 22) assert.equal(c.out.envFile, 'tmp');
  assert.equal(c.code, 0, c.err);
});

test('the PATH a test file starts with loses its folders in the home, however they are spelt; the checkout\'s stay', () => {
  const m = machine('path');
  symlinkSync(m.home, join(m.tmp, 'link'));
  const keep = [join(m.checkout, 'bin'), dirname(process.execPath), '/usr/bin', '/bin'];
  const r = probe(m, 'report({ path: process.env.PATH });', { PATH: [join(m.home, 'bin'), join(m.tmp, 'link', 'bin'), keep[0], `${m.home}/dev/../.local/bin`, ...keep.slice(1)].join(':') });
  assert.deepEqual(r.out, { path: keep.join(':') }, r.err);
});

test('under sudo, SUDO_USER\'s own home is off limits too: /Users/<name> or /home/<name>, and its home in /etc/passwd', () => {
  const m = machine('sudo');
  const theirs = join(MAC ? '/Users' : '/home', 'wardlatch-probe-user', 'x');
  // root's line in /etc/passwd stands in for a real user's: its home is named only there (/var/root on macOS, /root).
  // That home is another account's real one: the name probed in it is longer than any file system takes (255 bytes),
  // so it can never exist, and a net with a hole in it has the system answer ENAMETOOLONG without looking in the folder
  const rootHome = (readFileSync('/etc/passwd', 'utf8').split('\n').find((l) => l.startsWith('root:')) ?? '').split(':')[5];
  const never = `wardlatch-probe-${'x'.repeat(300)}`;
  const body = (p) => `report({ named: tried(() => fs.statSync(${J(theirs)})), passwd: ${p ? `tried(() => fs.statSync(${J(join(p, never))}))` : '"refused"'} });`;
  const named = probe(m, body(null), { SUDO_USER: 'wardlatch-probe-user' });
  assert.deepEqual(named.out, { named: 'refused', passwd: 'refused' }, named.err);
  if (rootHome) {
    const passwd = probe(m, body(rootHome), { SUDO_USER: 'root' });
    assert.equal(passwd.out?.passwd, 'refused', passwd.err);
  }
  // the clean twin: without sudo, that user's home is no one's here, and only the system answers
  const none = probe(m, body(null));
  assert.equal(none.out?.named, 'not refused: ENOENT', none.err);
});
