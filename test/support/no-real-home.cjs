// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The tests' safety net: no test looks in the real home folder of the person running them, where macOS keeps
// Desktop, Documents, Downloads, Library, iCloud Drive, Photos and Mail. Every test file loads it first, and it loads
// itself into every Node process a test starts (the command, the scripts), with the same folders. Off limits: the home
// the tests were started with (os.homedir() before any test changes HOME) and the account's own (its home in the user
// database, and /Users/<name> on macOS), in every spelling macOS accepts. Inside them, this checkout and the folder of
// the Node running the tests (nvm and the like keep it there) stay readable.
// A look under them (a read, a listing, a stat, an open, a write) is never made: it throws, says so on stderr and fails
// the test file. In a process a test started, it ends that process at once (exit 70), whatever would catch the error
// (lib/files.mjs reads one as "can't be opened"). The PATH the tests were started with loses its folders under them,
// so no test, and no command a test runs with that PATH, looks for a program there (~/.local/bin, ~/.cargo/bin).
'use strict';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
const { fileURLToPath } = require('node:url');

const KEY = 'WARDLATCH_TEST_NO_HOME';   // the folders, passed from a test to the processes it starts
const MAC = process.platform === 'darwin';
// as macOS reads a path: case ignored, and the start-up disk's folders also under /System/Volumes/Data or /Volumes/<x>
const norm = (p) => { const r = path.resolve(p); return MAC ? r.replace(/^\/(?:System\/Volumes\/Data|Volumes\/[^/]+)(?=\/)/i, '').toLowerCase() : r; };
const passed = process.env[KEY];
delete process.env[KEY];
let me = {};
try { me = os.userInfo(); } catch { /* no entry in the user database */ }
const HOMES = [...new Set([...(passed ? JSON.parse(passed) : [os.homedir()]), me.homedir, MAC && me.username && `/Users/${me.username}`]
  .filter(Boolean).map(norm))].filter((h) => h !== '/');
const under = (p, d) => p === d || p.startsWith(`${d}/`);
// readable inside them: this checkout and the Node running the tests, never a folder that holds a whole home
const OPEN = [path.join(__dirname, '..', '..'), path.dirname(process.execPath)].map(norm).filter((a) => !HOMES.some((h) => under(h, a)));
const shut = (n) => HOMES.some((h) => under(n, h)) && !OPEN.some((a) => under(n, a));
if (!passed && process.env.PATH) process.env.PATH = process.env.PATH.split(path.delimiter).filter((d) => !shut(norm(d))).join(path.delimiter);

let looked = false;
const check = (p) => {
  if (p == null || typeof p === 'number') return;   // a file descriptor: its open was checked
  const s = p instanceof URL ? fileURLToPath(p) : String(p);
  if (!shut(norm(s))) return;
  const msg = `test/support/no-real-home.cjs: a test looked in the real home folder (${s}); give it a home of its own`;
  try { fs.writeSync(2, `\n${msg}\n${new Error().stack.split('\n').slice(2).join('\n')}\n`); } catch { /* stderr is gone */ }
  if (passed) process.exit(70);
  looked = true;
  throw Object.assign(new Error(msg), { code: 'EREALHOME' });
};
process.on('exit', (code) => { if (looked && !code) process.exitCode = 1; });

// every fs function that takes a path, in its callback, Sync and promise forms; these take a second path too (symlink:
// where the link points, from the link's folder)
const NAMES = ['access', 'appendFile', 'chmod', 'chown', 'copyFile', 'cp', 'createReadStream', 'createWriteStream', 'exists',
  'lchown', 'link', 'lstat', 'lutimes', 'mkdir', 'mkdtemp', 'open', 'openAsBlob', 'opendir', 'readdir', 'readFile',
  'readlink', 'realpath', 'rename', 'rm', 'rmdir', 'stat', 'statfs', 'symlink', 'truncate', 'unlink', 'utimes', 'watch',
  'watchFile', 'writeFile'];
const TWO = ['copyFile', 'cp', 'link', 'rename'];
const paths = (k, a) => (k === 'symlink' ? [path.resolve(path.dirname(String(a[1])), String(a[0])), a[1]] : TWO.includes(k) ? [a[0], a[1]] : [a[0]]);
const wrap = (o, k) => Object.assign(function (...a) { for (const p of paths(k, a)) check(p); return o.apply(this, a); }, o);
for (const k of NAMES) for (const [obj, name] of [[fs, k], [fs, `${k}Sync`], [fs.promises, k]]) if (typeof obj[name] === 'function') obj[name] = wrap(obj[name], k);
for (const f of [fs.realpath, fs.realpathSync]) f.native = wrap(f.native, 'realpath');

// a Node process a test starts gets this file first, and the same folders
const carry = (o) => function (file, ...a) {
  if (String(file) === process.execPath) {
    const args = Array.isArray(a[0]) ? a.shift() : a[0] == null && a.length ? (a.shift(), []) : [];
    const opts = a.length && (a[0] == null || typeof a[0] === 'object') ? a.shift() ?? {} : {};
    a.unshift(['--require', __filename, ...args], { ...opts, env: { ...(opts.env ?? process.env), [KEY]: JSON.stringify(HOMES) } });
  }
  return o.call(this, file, ...a);
};
for (const k of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) cp[k] = carry(cp[k]);
require('node:module').syncBuiltinESMExports();
