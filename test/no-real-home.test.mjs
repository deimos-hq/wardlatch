// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The tests' safety net (test/support/no-real-home.cjs), tried against every way past it a review found. Each probe
// runs on a made-up machine in this test's temporary folder: a home with a checkout inside it (as on a laptop: the
// net's copy loads from there), and a temporary folder beside it. A Node started as a test file is (the net's copy
// first, HOME the made-up home) tries each way in, and reports what was refused. Nothing here looks at the real home:
// the folders probed are the made-up ones, so a probe run against a net with a hole in it reads only those.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import * as nodeFs from 'node:fs';
import * as nodeModule from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, symlinkSync, linkSync, readFileSync, readdirSync, rmSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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
 *  net's copy loaded first, HOME the made-up home, the working folder its tmp → { code, out, err }. */
const probe = (m, body, env = {}) => {
  const script = put(m, `probe-${++n}.cjs`, `require(${J(m.net)});
const m = ${J(m)};
const fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const report = (x) => fs.writeSync(1, JSON.stringify(x) + '\\n');
const tried = (f) => { try { f(); return 'not refused'; } catch (e) { return e.code === 'EREALHOME' ? 'refused' : 'not refused: ' + e.code; } };
const triedAsync = async (f) => { try { await f(); return 'not refused'; } catch (e) { return e.code === 'EREALHOME' ? 'refused' : 'not refused: ' + e.code; } };
${body}`);
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', cwd: m.tmp, maxBuffer: 64 * 1024 * 1024,
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
  const spellings = {
    plain: s, link: join(m.tmp, 'link', 'secret'), relative: join(m.tmp, 'rel', 'secret'), chain: join(m.tmp, 'chain', 'secret'),
    dotdot: `${join(m.tmp, 'inner-link')}/../secret`, escape: join(m.checkout, 'escape'), beside: join(m.home, 'dev', 'other'),
    outLink: join(m.home, 'out', 'ok'), fromCwd: 'link/secret', upFromCwd: '../home/secret',
    ...(MAC ? {
      upper: s.toUpperCase(), data: `/System/Volumes/Data${s}`, dataTwice: `/System/Volumes/Data/System/Volumes/Data${s}`,
      volume: `/Volumes/Wardlatch Probe/System/Volumes/Data${s}`, volumeLower: `/volumes/x/volumes/y${s}`,
    } : {}),
  };
  const r = probe(m, `const s = ${J(spellings)}, out = {};
for (const [k, p] of Object.entries(s)) out[k] = tried(() => fs.statSync(p));
out.buffer = tried(() => fs.statSync(Buffer.from(s.plain)));
out.uint8Array = tried(() => fs.statSync(new Uint8Array(Buffer.from(s.plain))));
out.url = tried(() => fs.statSync(require('node:url').pathToFileURL(s.plain)));
out.urlLike = tried(() => fs.statSync({ href: 'file:///nowhere', protocol: 'file:', hostname: '', pathname: s.plain }));
out.chdir = tried(() => process.chdir(path.join(m.tmp, 'link', 'inner')));
// a 1 MB path is read in one pass: refused, and fast
const t0 = Date.now();
out.longDots = tried(() => fs.statSync('/.'.repeat(500000) + s.plain));
if (${MAC}) out.longVolumes = tried(() => fs.statSync('/Volumes/x'.repeat(100000) + s.plain));
const ms = Date.now() - t0;
report({ ...out, fast: ms < 2000 ? 'refused' : ms + ' ms' });`);
  allRefused(r, [...Object.keys(spellings), 'buffer', 'uint8Array', 'url', 'urlLike', 'chdir', 'longDots', ...(MAC ? ['longVolumes'] : []), 'fast']);
  // a readable folder that holds a whole home (a checkout with the home inside it) opens none of it
  const wide = machine('wide', { checkout: (base) => base });
  const w = probe(wide, `report({ inside: tried(() => fs.statSync(path.join(m.home, 'secret'))) });`);
  assert.deepEqual(w.out, { inside: 'refused' }, w.err);
  // the clean twin: the same kinds of path outside the home, and the checkout inside it, stay readable
  const ok = { file: join(m.tmp, 'ok'), link: join(m.tmp, 'ok-link', 'file'), checkout: m.net, dotdot: `${join(m.tmp, 'ok-link')}/../ok`, fromCwd: 'ok' };
  const c = probe(m, `const s = ${J(ok)}, out = {}; for (const [k, p] of Object.entries(s)) out[k] = tried(() => fs.readFileSync(p));
out.buffer = tried(() => fs.readFileSync(Buffer.from(s.file))); report(out);`);
  assert.deepEqual(c.out, Object.fromEntries([...Object.keys(ok), 'buffer'].map((k) => [k, 'not refused'])), c.err);
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
  // found before PATH reaches a folder in the home
  const c = probe(m, `const { pathToFileURL } = require('node:url');
(async () => {
  const out = {
    readStream: tried(() => new fs.ReadStream(path.join(m.tmp, 'ok')).destroy()),
    require: tried(() => require('node:path')), import: await triedAsync(() => import(pathToFileURL(path.join(m.checkout, 'fine.mjs')).href)),
    chdir: tried(() => process.chdir(m.tmp)), spawn: tried(() => cp.spawnSync('/bin/echo', [], { cwd: m.tmp })),
    pathBefore: tried(() => cp.spawnSync('echo', [], { env: { PATH: '/bin:' + path.join(m.home, 'bin') } })),
  };
  if (${has.glob}) out.glob = tried(() => fs.globSync('*', { cwd: m.tmp }));
  report(out);
})();`);
  assert.deepEqual(c.out, { readStream: 'not refused', require: 'not refused', import: 'not refused', chdir: 'not refused', spawn: 'not refused', pathBefore: 'not refused', ...(has.glob ? { glob: 'not refused' } : {}) }, c.err);
  assert.equal(c.code, 0, c.err);
});

test('the net goes with every Node a test starts: fork, exec, execSync, node by name, a #! script, a shell, another Node, and below the command; the child\'s own NODE_OPTIONS stay its own', () => {
  // a space in every path: NODE_OPTIONS must quote the net's (Node reads it as words)
  const m = machine('carry with space');
  const s = join(m.home, 'secret');
  const g = reader(m, 'g.cjs', s);
  const byEnv = reader(m, 'by-env', s, '#!/usr/bin/env node\n');
  const byEnvS = reader(m, 'by-env-s', s, '#!/usr/bin/env -S node --no-warnings\n');
  const byPath = reader(m, 'by-path', s, `#!${process.execPath}\n`);
  // another Node binary (a hard link, or a copy, of this one): a found Node the command runs is one
  const other = join(m.tmp, 'other', 'node'); mkdirSync(dirname(other));
  try { linkSync(process.execPath, other); } catch { copyFileSync(process.execPath, other, constants.COPYFILE_FICLONE); }
  // not a program: a FIFO the net must not hang on, reading its first bytes
  const fifo = join(m.tmp, 'fifo'); execFileSync('mkfifo', [fifo]);
  // below a process the test started (as the command is), where only a Node gets the net
  const mid = put(m, 'mid.cjs', `const cp = require('child_process'), o = { stdio: 'ignore', timeout: 20000, killSignal: 'SIGKILL' }, r = {};
r.shebangEnv = cp.spawnSync(${J(byEnv)}, o).status;
r.shebangEnvS = cp.spawnSync(${J(byEnvS)}, o).status;
r.shebangPath = cp.spawnSync(${J(byPath)}, o).status;
r.byName = cp.spawnSync('node', [${J(g)}], o).status;
r.otherNode = cp.spawnSync(${J(other)}, [${J(g)}], o).status;
r.shellOption = cp.spawnSync('node ' + ${J(J(g))}, { ...o, shell: true }).status;
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
    below: { shebangEnv: 70, shebangEnvS: 70, shebangPath: 70, byName: 70, otherNode: 70, shellOption: 70, execSync: 70, fifo: 'EACCES', exec: 70, fork: 70 },
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
  // root's line in /etc/passwd stands in for a real user's: its home is named only there (/var/root on macOS, /root)
  const rootHome = (readFileSync('/etc/passwd', 'utf8').split('\n').find((l) => l.startsWith('root:')) ?? '').split(':')[5];
  const body = (p) => `report({ named: tried(() => fs.statSync(${J(theirs)})), passwd: ${p ? `tried(() => fs.statSync(${J(join(p, 'wardlatch-probe'))}))` : '"refused"'} });`;
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
