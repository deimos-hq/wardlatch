// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Paths as the programs that read them do (round 8, rule 5): a folder from PATH, a variable or the home folder is put
// together as written and handed to the OS, never cleaned up as text first. x/sym is a link to y/deep, so x/sym/.. is y
// to the OS (and to the shell, git, curl and every C or Rust program), and x to path.join, path.resolve and Node's
// realpathSync. Each place that decides which file is read, with its clean twin. Offline: nothing outside this test's
// folder is run, and the home folder is a made-up one.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { findAllOnPath, copiesMatching, tempDirs, tmpTraces } from '../lib/binaries.mjs';
import { expand, sitePackagesDirs } from '../lib/installs.mjs';
import { scanHeaders } from '../lib/headers.mjs';
import { runtimePrograms } from '../lib/brotli.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let dir, home;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-paths-'))); home = join(dir, 'home'); mkdirSync(home); });
after(() => rmSync(dir, { recursive: true, force: true }));
const put = (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode ? { mode } : undefined); return p; };
const exe = (p, body) => put(p, `#!/bin/sh\n${body}\n`, 0o755);
/** x and y in a fresh folder, x/sym a link to y/deep: `via` (x/sym/..) is y to the OS and x as text. */
const tree = (name) => {
  const d = join(dir, name), x = join(d, 'x'), y = join(d, 'y');
  mkdirSync(join(y, 'deep'), { recursive: true }); mkdirSync(x, { recursive: true }); symlinkSync(join(y, 'deep'), join(x, 'sym'));
  return { d, x, y, via: `${x}/sym/..` };
};

test('PATH: each copy is the folder and the name as written, read once by its real path, as the shell runs it', () => {
  const { x, y, via } = tree('path');
  exe(join(y, 'bin', 'tool'), 'echo y'); exe(join(y, 'bin', 'php8.1'), 'echo y');
  // only y/bin holds the programs: the shell runs y/bin/tool; path.join looked in x/bin, where there is none
  assert.deepEqual(findAllOnPath('tool', `${via}/bin`), [`${via}/bin/tool`]);
  assert.deepEqual(copiesMatching('^php', `${via}/bin`).run, [`${via}/bin/php8.1`]);
  // x/bin holds other copies: both are there, each once (Node's realpathSync made the first x/bin/tool, the second's
  // real path, and dropped the second)
  exe(join(x, 'bin', 'tool'), 'echo x'); exe(join(x, 'bin', 'php8.1'), 'echo x');
  assert.deepEqual(findAllOnPath('tool', `${via}/bin:${join(x, 'bin')}`), [`${via}/bin/tool`, join(x, 'bin', 'tool')]);
  assert.deepEqual(copiesMatching('^php', `${via}/bin:${join(x, 'bin')}`), { run: [`${via}/bin/php8.1`], notRun: [join(x, 'bin', 'php8.1')] });
  // the clean twins: the same file by two folders is still once (each by its real path as the OS resolves it: by the
  // path as found, copiesMatching listed y/bin/php8.1 a second time, as a copy not run: round 8's mutant M5d); plain
  // folders read as before
  assert.deepEqual(findAllOnPath('tool', `${via}/bin:${join(y, 'bin')}`), [`${via}/bin/tool`]);
  assert.deepEqual(copiesMatching('^php', `${via}/bin:${join(y, 'bin')}`), { run: [`${via}/bin/php8.1`], notRun: [] });
  assert.deepEqual(findAllOnPath('tool', `${join(y, 'bin')}:${join(x, 'bin')}`), [join(y, 'bin', 'tool'), join(x, 'bin', 'tool')]);
});

test('$TMPDIR: each temp folder once by its real path as the OS resolves it, and a trace named as its folder was listed', () => {
  // TMPDIR reads /private/tmp as text and is <base>/private/tmp to the OS: Node's realpathSync took it for /tmp's real
  // folder, and /tmp, where a malware's trace may be, was dropped as looked at already
  const base = join(dir, 'tmpdirs'), depth = base.split('/').length - 1;
  const deep = join(base, ...Array(depth + 1).fill('q'));
  mkdirSync(deep, { recursive: true }); symlinkSync(deep, join(base, 'sym')); mkdirSync(join(base, 'private', 'tmp'), { recursive: true });
  const t = `${base}/sym/${'../'.repeat(depth + 1)}private/tmp`;
  assert.equal(realpathSync.native(t), join(base, 'private', 'tmp'));
  const saved = process.env.TMPDIR;
  try {
    process.env.TMPDIR = t;
    assert.deepEqual(tempDirs('linux'), [t, '/tmp', '/var/tmp']);
    // the clean twin: TMPDIR that is /tmp's real folder is the same folder as /tmp, once
    process.env.TMPDIR = realpathSync.native('/tmp');
    assert.deepEqual(tempDirs('linux'), [realpathSync.native('/tmp'), '/var/tmp']);
  } finally { if (saved === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = saved; }
  // a trace in that folder is named as written (path.join named /private/tmp/<trace>, another folder)
  mkdirSync(join(base, 'private', 'tmp', 'stealer-x1'));
  assert.deepEqual(tmpTraces('^stealer-', [t]), [`${t}/stealer-x1`]);
  assert.deepEqual(tmpTraces('^stealer-', [join(base, 'private', 'tmp')]), [join(base, 'private', 'tmp', 'stealer-x1')], 'the clean twin');
});

test('a pattern with a \'..\' (a variable, the home folder) is expanded as written, and each site-packages folder is read once by its real path', () => {
  const { x, y, via } = tree('expand');
  mkdirSync(join(y, 'sp')); mkdirSync(join(x, 'sp'));
  assert.deepEqual(expand(`${via}/s*`), [`${via}/sp`]);
  assert.deepEqual(expand(`${join(y, 's')}*`), [join(y, 'sp')], 'the clean twin');
  // two folders, y/sp (by x/sym/..) and x/sp: both read (as text, both were x/sp, once); one reached by a '..' is
  // named by its real path, so the files in it are never put together from a path a '..' is cleaned out of
  assert.deepEqual(sitePackagesDirs({ patterns: [`${via}/sp`, join(x, 'sp')], home: '' }), [join(y, 'sp'), join(x, 'sp')]);
  assert.deepEqual(sitePackagesDirs({ patterns: [`${via}/sp`, join(y, 'sp')], home: '' }), [join(y, 'sp')], 'the clean twin: one folder by two paths is read once');
  assert.deepEqual(sitePackagesDirs({ patterns: [join(y, 'sp'), `${via}/sp`], home: '' }), [join(y, 'sp')]);
});

test('discover: the curl that tests the Linux trust store, and the trusted curl, are PATH\'s first as the shell finds it, and each runtime is probed once by its real path', () => {
  const { x, y, via } = tree('discover');
  exe(join(y, 'bin', 'curl'), 'echo "curl 8.0.0"'); exe(join(x, 'bin', 'curl'), 'echo "curl 7.0.0"');
  const bundle = put(join(dir, 'discover', 'ca.crt'), '-----BEGIN CERTIFICATE-----\n');
  // in a Node of its own: Linux, the system's folders hidden, /usr/bin/curl being the file `curl` names (none when not
  // given) and the CA bundle this test's, nothing run outside this test's folder
  const preload = (curl) => put(join(dir, `discover-${curl ? 'curl' : 'none'}-${curl === join(x, 'bin', 'curl') ? 'x' : 'y'}.cjs`), `'use strict';
const fs = require('node:fs'), os = require('node:os'), cp = require('node:child_process');
const DIR = ${JSON.stringify(dir)}, MAP = ${JSON.stringify({ ...(curl ? { '/usr/bin/curl': curl } : {}), '/etc/ssl/certs/ca-certificates.crt': bundle })};
const SYS = /^\\/(?:usr|etc|opt|bin|sbin|System|Library)(?:\\/|$)/;
const where = (p) => (typeof p === 'string' && MAP[p] ? MAP[p] : p);
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const hidden = (p) => typeof p === 'string' && SYS.test(p);
const ex = fs.existsSync; fs.existsSync = (p) => !hidden(where(p)) && ex(where(p));
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => { const q = where(p); if (hidden(q)) throw gone(); return o(q, ...a); };
  if (o.native) fs[k].native = (p, ...a) => { const q = where(p); if (hidden(q)) throw gone(); return o.native(q, ...a); };
}
const guard = (o) => function (f, ...r) { if (String(f) !== process.execPath && !String(f).startsWith(DIR + '/')) throw Object.assign(new Error('not run in these tests'), { code: 'ENOENT' }); return o.call(this, f, ...r); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) cp[k] = guard(cp[k]);
os.platform = () => 'linux'; Object.defineProperty(process, 'platform', { value: 'linux' });
require('node:module').syncBuiltinESMExports();
`);
  // → each curl row as [its program, the Linux trust store's row?, the variable whose bundle it tests]
  const found = (pathEnv, { curl = join(x, 'bin', 'curl'), env = {} } = {}) => {
    const code = `const { discover } = await import(${JSON.stringify(pathToFileURL(join(ROOT, 'lib', 'discover.mjs')).href)});
console.log(JSON.stringify(discover({ roots: [], pathEnv: ${JSON.stringify(pathEnv)} }).filter((r) => r.kind === 'curl').map((r) => [r.bin, Boolean(r.system), ...(r.caVar ? [r.caVar] : [])])));`;
    const r = spawnSync(process.execPath, ['--require', preload(curl), '--input-type=module', '-e', code], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin', TMPDIR: dir, ...env } });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  };
  // PATH x/sym/../bin: the shell's curl is y/bin/curl; /usr/bin/curl (x/bin/curl here) is another file, probed too. By
  // path.join the Linux row's curl was x/bin/curl, and by Node's realpathSync y/bin/curl was x/bin/curl, so the system's
  // curl was dropped as probed already
  assert.deepEqual(found(`${via}/bin`), [[`${via}/bin/curl`, false], ['/usr/bin/curl', false], [`${via}/bin/curl`, true]]);
  // the clean twin: PATH y/bin
  assert.deepEqual(found(join(y, 'bin')), [[join(y, 'bin', 'curl'), false], ['/usr/bin/curl', false], [join(y, 'bin', 'curl'), true]]);
  // /usr/bin/curl the same file as PATH's (y/bin/curl): probed once, by its real path as the OS resolves it (by the path
  // as found, /usr/bin/curl was probed a second time: round 8's mutant M5i)
  assert.deepEqual(found(`${via}/bin`, { curl: join(y, 'bin', 'curl') }), [[`${via}/bin/curl`, false], [`${via}/bin/curl`, true]]);
  // no /usr/bin/curl: the trusted curl that tests REQUESTS_CA_BUNDLE's file is PATH's first, as written, y/bin/curl (by
  // path.join it was x/bin/curl, another program: round 8's mutant M5h); the clean twin, PATH y/bin
  const ca = { env: { REQUESTS_CA_BUNDLE: bundle }, curl: null };
  assert.deepEqual(found(`${via}/bin`, ca), [[`${via}/bin/curl`, false], [`${via}/bin/curl`, true], [`${via}/bin/curl`, false, 'REQUESTS_CA_BUNDLE']]);
  assert.deepEqual(found(join(y, 'bin'), ca), [[join(y, 'bin', 'curl'), false], [join(y, 'bin', 'curl'), true], [join(y, 'bin', 'curl'), false, 'REQUESTS_CA_BUNDLE']]);
});

test('header settings under a folder with a \'..\': read both ways, as written (git, curl, wget) and as text (npm, the Node-based agents)', () => {
  const { x, y, via } = tree('headers');
  const h = join(dir, 'headers-home');
  put(join(h, '.gitconfig'), '[user]\n\tname = Ada Lovelace\n\temail = ada.lovelace@example.org\n');
  // XDG_CONFIG_HOME x/sym/..: git reads y/git/config, which sends the email to every remote; path.join read x/git/config
  put(join(y, 'git', 'config'), '[http]\n\textraHeader = "From: ada.lovelace@example.org"\n');
  // NPM_CONFIG_USERCONFIG x/sym/../npmrc: npm resolves it as text, x/npmrc, whose user-agent carries the email; only
  // the file as written (y/npmrc, none) was read
  put(join(x, 'npmrc'), 'user-agent = "npm ada.lovelace@example.org"\n');
  const at = (env, home = h) => scanHeaders({ home, env: { PATH: '/usr/bin:/bin', ...env } }).findings.map((f) => [f.file, f.status]).sort();
  assert.deepEqual(at({ XDG_CONFIG_HOME: via, NPM_CONFIG_USERCONFIG: `${via}/npmrc` }), [[`${via}/git/config`, 'EXPOSED'], [join(x, 'npmrc'), 'REVIEW']].sort());
  // the clean twins: the same files by plain paths
  assert.deepEqual(at({ XDG_CONFIG_HOME: y, NPM_CONFIG_USERCONFIG: join(x, 'npmrc') }), [[join(y, 'git', 'config'), 'EXPOSED'], [join(x, 'npmrc'), 'REVIEW']].sort());
  // the home folder itself with a '..' (x/sym/..): git reads ~/.gitconfig and curl ~/.curlrc as written, y's, each
  // sending the email everywhere. Read as text only (x's, none there) they were missed: round 8's mutants M5k and M5m.
  // The clean twin: the home folder y
  const { y: y2, via: via2 } = tree('headers-home-dots');
  put(join(y2, '.gitconfig'), '[http]\n\textraHeader = "From: ada.lovelace@example.org"\n');
  put(join(y2, '.curlrc'), 'header = "From: ada.lovelace@example.org"\n');
  assert.deepEqual(at({}, via2), [[`${via2}/.curlrc`, 'EXPOSED'], [`${via2}/.gitconfig`, 'EXPOSED']].sort());
  assert.deepEqual(at({}, y2), [[join(y2, '.curlrc'), 'EXPOSED'], [join(y2, '.gitconfig'), 'EXPOSED']].sort());
});

test('runtimePrograms: a node found on PATH and in a version manager\'s folder is read once, by its real path as the OS resolves it (round 8\'s mutant M5w)', () => {
  const { y, via } = tree('runtimes');
  // a compiled program (a Mach-O magic is enough to tell it from a script), on PATH as x/sym/../bin/node and in a
  // version manager's folder as y/bin/node: one file, read once (by the path as found it was read twice)
  put(join(y, 'bin', 'node'), Buffer.from('cffaedfe0c000001', 'hex'), 0o755);
  assert.deepEqual(runtimePrograms('node', [join(y, 'bin', 'node')], { pathEnv: `${via}/bin` }).files, [{ file: `${via}/bin/node`, onPath: true }]);
  // the clean twin: another file in the version manager's folder is read too
  put(join(y, 'other', 'node'), Buffer.from('cffaedfe0c000001', 'hex'), 0o755);
  assert.deepEqual(runtimePrograms('node', [join(y, 'other', 'node')], { pathEnv: `${via}/bin` }).files, [{ file: `${via}/bin/node`, onPath: true }, { file: join(y, 'other', 'node'), onPath: false }]);
});
