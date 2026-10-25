// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The tests' safety net: it catches a test that reads or writes the real home folder of the person running them (where
// macOS keeps Desktop, Documents, Downloads, Library, iCloud Drive, Photos and Mail) by accident, and fails that test.
// It is not a sandbox: code written to get past it can (CONTRIBUTING.md, Testing policy, lists the routes it doesn't
// watch). Every test file loads it first, and it goes with every Node process a test starts through child_process, and
// those they start in turn, with the same folders. Off limits: the home the tests were started with (os.homedir()
// before any test changes HOME), the account's own (its home in the user database, and /Users/<name> on macOS or
// /home/<name> elsewhere) and, under sudo, SUDO_USER's (/Users/<name> or /home/<name>, and its line in /etc/passwd).
// Inside them, this checkout and the folder of the Node running the tests (nvm and the like keep it there) stay
// readable.
// A path is compared as the system reads it: '.', '..' and links followed in order, and on macOS in any case and with
// the start-up disk's folders also spelt under /System/Volumes/Data or /Volumes/<x>, however many times (read by its
// text too, where the system would find nothing). Following a link never looks inside a home: a folder off limits is
// never looked at, but for those on the way to this checkout.
// A look under them by these routes is refused before it is made: a path given to an fs function or stream class, a
// glob, a require() or an import (of a file, a package name or a '#' name of package.json's imports), a change of
// folder, a program started there or in a working folder there, or found through a PATH folder there, a Node started
// with a flag that reads a file there as it starts (--env-file and the like); and a walk that can reach one (a
// recursive listing, copy, watch or removal of a folder that holds one, and a recursive listing, copy, watch or glob
// below which a link leads into one). It goes with each Worker thread started with worker_threads.Worker (a Worker has
// an fs of its own), and covers process.loadEnvFile and node:sqlite, which open files without fs.
// In the test it throws, says so on stderr and fails the test file. In a process a test started it ends that
// process at once (exit 70; a Worker thread, that thread), whatever would catch the error (lib/files.mjs reads one as
// "can't be opened"), and leaves a note the test file reads when it exits: a refusal anywhere below a test fails the
// test file, even when nothing checks that process's exit code.
// The PATH the tests were started with loses its folders under them, so no test, and no command a test runs with that
// PATH, looks for a program there (~/.local/bin, ~/.cargo/bin).
'use strict';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
const Module = require('node:module'), wt = require('node:worker_threads');
const { fileURLToPath, pathToFileURL } = require('node:url');

// once per process, whichever copy loads first (a test file's import, --require, NODE_OPTIONS)
const ONCE = Symbol.for('wardlatch.test.no-real-home');
if (globalThis[ONCE]) return;
globalThis[ONCE] = __filename;

// the net's own looks go to fs as it was, never through the checks below
const { lstatSync, readlinkSync, statSync, accessSync, openSync, readSync, closeSync, writeSync, writeFileSync, readFileSync,
  readdirSync, mkdtempSync, rmSync } = fs;

// what a test passes to the processes it starts, as JSON { homes, marks, nodeOptions? }: the folders, where a note
// goes, and the NODE_OPTIONS the process was given before this file was added to it. Every process deletes it from its
// own environment first, so the code under test never sees it; but a node --test runner a test started keeps it, and
// its NODE_OPTIONS, as Node starts each test file without the wrappers below, and a test file it runs is still below
// the test. A value a test gives a child itself (an empty one starts a process as a test file starts: a test of this
// file needs that) is that test's choice, for that child only (carry, below).
const KEY = 'WARDLATCH_TEST_NO_HOME';
const MAC = process.platform === 'darwin';
let given = null;
try { given = process.env[KEY] ? JSON.parse(process.env[KEY]) : null; } catch { /* not from this file: started as a test file */ }
// a Worker thread: what the thread that started it handed it, as the threads' environment data, goes before the
// variable; and the variable isn't deleted there (its environment may be that thread's own: SHARE_ENV)
if (!wt.isMainThread) { try { const d = wt.getEnvironmentData(KEY); if (typeof d === 'string') given = JSON.parse(d); } catch { /* not handed one */ } }
const child = !!given && Array.isArray(given.homes) && typeof given.marks === 'string';
const runner = child && wt.isMainThread && process.execArgv.includes('--test');
if (!runner && wt.isMainThread) delete process.env[KEY];
// NODE_OPTIONS carried this file here: put back what the process was given, so the code under test reads its own
if (child && !runner && 'nodeOptions' in given) { if (given.nodeOptions == null) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = given.nodeOptions; }

// a path's spelling for comparing: on macOS, without the start-up disk's other spellings, in lower case (one pass from
// the start, however many there are)
const VOLUME = /\/(?:System\/Volumes\/Data|Volumes\/[^/]+)(?=\/|$)/iy;
const strip = (q) => { let i = 0; for (VOLUME.lastIndex = 0; VOLUME.exec(q); VOLUME.lastIndex = i) i = VOLUME.lastIndex; return q.slice(i) || '/'; };
const key = (q) => (MAC ? strip(q).toLowerCase() : q);
const under = (p, d) => p === d || p.startsWith(d === '/' ? '/' : `${d}/`);

/** An absolute path as the system reads it: each part in order, '..' to the folder above, a link replaced by where it
 *  points. stop(prefix) true: that prefix is never looked at, and the rest is returned as written. */
function physical(abs, stop) {
  let parts = abs.split('/'), i = 0, out = '', links = 0;
  const rest = (next) => path.posix.normalize([next, ...parts.slice(i)].join('/'));
  while (i < parts.length) {
    const c = parts[i++];
    if (c === '' || c === '.') continue;
    if (c === '..') { out = out.slice(0, out.lastIndexOf('/')); continue; }
    const next = `${out}/${c}`;
    if (stop?.(next)) return rest(next);
    let st;
    try { st = lstatSync(next, { throwIfNoEntry: false }); } catch { st = undefined; }
    if (!st) return rest(next);   // not there, or not a folder on the way: the system stops here too
    if (st.isSymbolicLink()) {
      let to;
      try { to = readlinkSync(next); } catch { return rest(next); }
      if (++links > 64) return rest(next);
      parts = [...to.split('/'), ...parts.slice(i)]; i = 0;
      if (to.startsWith('/')) out = '';
      continue;
    }
    out = next;
  }
  return out || '/';
}

let me = {};
try { me = os.userInfo(); } catch { /* no entry in the user database */ }
const named = (n) => (n && !/[/\0]/.test(n) && !['.', '..'].includes(n) ? [MAC ? `/Users/${n}` : `/home/${n}`] : []);
const passwd = (n) => {
  if (!n) return [];
  try { return readFileSync('/etc/passwd', 'utf8').split('\n').filter((l) => l.startsWith(`${n}:`)).map((l) => l.split(':')[5]); } catch { return []; }
};
const sudo = process.env.SUDO_USER;
const HOMES = child ? given.homes : [...new Set([os.homedir(), me.homedir, ...named(me.username), ...named(sudo), ...passwd(sudo)]
  .filter((h) => typeof h === 'string' && path.isAbsolute(h)).map((h) => key(physical(h))))].filter((h) => h !== '/');
// readable inside them: this checkout and the Node running the tests, never a folder that holds a whole home
const OPEN = [path.join(__dirname, '..', '..'), path.dirname(process.execPath)].map((a) => key(physical(a))).filter((a) => !HOMES.some((h) => under(h, a)));
const shut = (k) => HOMES.some((h) => under(k, h)) && !OPEN.some((a) => under(k, a));
// on the way to a path: a folder off limits is never looked at, except one that holds a readable folder
const stop = (q) => { const k = key(q); return shut(k) && !OPEN.some((a) => under(a, k)); };
/** The absolute path an fs argument names, or null (a file descriptor, a FileHandle: its open was checked). */
const where = (p) => {
  let s;
  if (typeof p === 'string') s = p;
  else if (p instanceof Uint8Array) s = Buffer.from(p.buffer, p.byteOffset, p.byteLength).toString();
  // a URL, or an object fs takes as one (its pathname is the path, as fs reads it)
  else if (p && typeof p === 'object' && p.href && p.protocol && p.auth === undefined && p.path === undefined) { try { s = fileURLToPath(p); } catch { return null; } }
  else return null;
  if (!s || s.includes('\0')) return null;   // fs refuses these itself
  let cwd = '/';
  try { cwd = process.cwd(); } catch { /* the working folder is gone: a relative path opens nothing */ }
  return path.isAbsolute(s) ? s : `${cwd}/${s}`;
};
// on macOS a path is also read by its text with the start-up disk's other names taken off before any link is followed
// ('.', '..' and doubled slashes read as written): a spelling of the home under them is refused even where the system
// would find nothing (/System/Volumes/Data has no /tmp or /var: those links are the system volume's alone)
const offLimits = (abs) => {
  if (shut(key(physical(abs, stop)))) return true;
  if (!MAC) return false;
  const n = path.posix.normalize(abs), t = strip(n);
  return t !== n && shut(key(physical(t, stop)));
};

// where a process a test started leaves its note: the test file's own folder, made when it first starts a process (a
// test file that is killed can't remove it) and removed when it exits; never one in a home
let MARKS = child ? given.marks : '';
const marks = () => {
  if (child || MARKS) return MARKS;
  const t = os.tmpdir();
  try { MARKS = mkdtempSync(path.join(offLimits(where(t)) ? '/tmp' : t, 'wardlatch-no-home-')); } catch { MARKS = ''; }
  return MARKS;
};
let looked = false, notes = 0;
// (what: what the test did; a place the net doesn't read, such as a SQLite URI, is refused whole and says so)
const refuse = (s, what = 'looked in the real home folder', fix = 'give it a home of its own') => {
  const msg = `test/support/no-real-home.cjs: a test ${what} (${s}); ${fix}`;
  const text = `\n${msg}\n${new Error().stack.split('\n').slice(3).join('\n')}\n`;
  try { writeSync(2, text); } catch { /* stderr is gone */ }
  if (child) {
    const who = `process ${process.pid}${wt.isMainThread ? '' : `, thread ${wt.threadId}`}`;
    try { if (MARKS) writeFileSync(path.join(MARKS, `${process.pid}-${wt.threadId}-${++notes}`), `${who} (${process.argv.slice(1, 3).join(' ')}) was stopped (exit 70):${text}`); } catch { /* the test file has exited */ }
    process.exit(70);
  }
  looked = true;
  throw Object.assign(new Error(msg), { code: 'EREALHOME' });
};
const check = (p) => { const abs = where(p); if (abs !== null && offLimits(abs)) refuse(abs); };

if (!child) {
  if (process.env.PATH) process.env.PATH = process.env.PATH.split(path.delimiter).filter((d) => !offLimits(where(d || '.'))).join(path.delimiter);
  process.on('exit', (code) => {
    let left = [];
    try { left = MARKS ? readdirSync(MARKS).sort() : []; } catch { /* nothing was left */ }
    for (const f of left) { try { writeSync(2, `\ntest/support/no-real-home.cjs: ${readFileSync(path.join(MARKS, f), 'utf8')}`); } catch { /* stderr is gone */ } }
    try { if (MARKS) rmSync(MARKS, { recursive: true, force: true }); } catch { /* left for the system to clear */ }
    if ((looked || left.length) && !code) process.exitCode = 1;
  });
}

// A walk below a folder is refused whole when it can reach a home: a folder it enters holds one (or, on macOS, holds the
// start-up disk under another name: /System/Volumes/Data, /Volumes), or (following links) a link below it leads into
// one or to a folder that holds one. Every recursive readdir follows links to folders (Node 20.1 to 26 at least), as a
// glob does through a fixed part after a wildcard; a recursive opendir, cp, recursive watch and glob are read as
// following them too (when in doubt, refuse). rm and rmdir never follow a link: only a home below their start counts.
// The walk reads each folder with fs as it was, never one in a home, and follows each link once.
const ROOTS = MAC ? ['/system/volumes/data', '/volumes'] : [];
const holds = (k) => HOMES.some((h) => under(h, k)) || ROOTS.some((r) => under(r, k));
const reach = (start, follow, what) => {
  const seen = new Set(), todo = [start];
  while (todo.length) {
    const d = todo.pop(), k = key(d);
    if (shut(k) || holds(k)) refuse(d === start ? what : `${d}, below ${what}`);
    if (!follow || seen.has(d)) continue;
    seen.add(d);
    let list;
    try { list = readdirSync(d, { withFileTypes: true, encoding: 'buffer' }); } catch { continue; }   // not a folder, or not one it can read: nor can the walk
    for (const e of list) {
      const name = e.name.toString();
      // a name that isn't UTF-8 can't be followed by its spelling here
      if (!Buffer.from(name).equals(e.name)) refuse(`${d}/${name}, below ${what}`, 'walked a folder whose names the net can\'t read', 'walk a folder of its own');
      const p = `${d === '/' ? '' : d}/${name}`;
      if (e.isDirectory()) todo.push(p);
      else if (e.isSymbolicLink()) {
        const t = physical(p, stop), tk = key(t);
        if (shut(tk) || holds(tk)) refuse(`${p}, below ${what}`);
        let st = null;
        try { st = statSync(t); } catch { /* leads nowhere */ }
        if (st?.isDirectory()) todo.push(t);
      }
    }
  }
};
// (the options: cp's third argument, the others' second; cp copies a folder only with recursive, and is read as always)
const WALKS = new Map([['readdir', true], ['opendir', true], ['cp', true], ['watch', true], ['rm', false], ['rmdir', false]]);
const walk = (k, a) => {
  const o = a[k === 'cp' ? 2 : 1];
  if (k !== 'cp' && !(o && typeof o === 'object' && o.recursive)) return;
  const abs = where(a[0]);
  if (abs !== null) reach(physical(abs, stop), WALKS.get(k), abs);
};

// a glob looks at its fixed start and walks below it (from '/', with a '..' after a wildcard)
const MAGIC = /[*?[\]{}()!+@\\]/;
const checkGlob = (patterns, options) => {
  const cwd = (options && typeof options === 'object' && options.cwd != null ? where(options.cwd) : null) ?? where('.') ?? '/';
  for (const g of [].concat(patterns)) {
    if (typeof g !== 'string') continue;   // fs refuses it itself
    const parts = (g.startsWith('/') ? g : `${cwd}/${g}`).split('/');
    const i = parts.findIndex((x) => MAGIC.test(x));
    const start = (i < 0 ? parts : parts.slice(0, i)).join('/') || '/';
    check(start);
    if (i >= 0) reach(parts.slice(i).includes('..') ? '/' : physical(start, stop), true, g);
  }
};

// every fs function that takes a path, in its callback, Sync and promise forms (createReadStream and createWriteStream:
// the stream classes below); these take a second path too (symlink: where the link points, from the link's folder)
const NAMES = ['access', 'appendFile', 'chmod', 'chown', 'copyFile', 'cp', 'exists', 'glob', 'lchmod', 'lchown', 'link', 'lstat',
  'lutimes', 'mkdir', 'mkdtemp', 'mkdtempDisposable', 'open', 'openAsBlob', 'opendir', 'readdir', 'readFile', 'readlink',
  'realpath', 'rename', 'rm', 'rmdir', 'stat', 'statfs', 'symlink', 'truncate', 'unlink', 'utimes', 'watch', 'watchFile',
  'writeFile'];
const TWO = ['copyFile', 'cp', 'link', 'rename'];
const pointsTo = (to, link) => {
  const s = typeof to === 'string' ? to : to instanceof Uint8Array ? Buffer.from(to.buffer, to.byteOffset, to.byteLength).toString() : where(to);
  const at = where(link);
  return s == null || at == null ? s : path.resolve(path.dirname(at), s);
};
const paths = (k, a) => (k === 'symlink' ? [pointsTo(a[0], a[1]), a[1]] : TWO.includes(k) ? [a[0], a[1]] : [a[0]]);
const wrap = (o, k) => Object.assign(function (...a) {
  if (k === 'glob') checkGlob(a[0], a[1]);
  else {
    for (const p of paths(k, a)) check(p);
    if (WALKS.has(k)) walk(k, a);
  }
  return o.apply(this, a);
}, o);
for (const k of NAMES) for (const [obj, name] of [[fs, k], [fs, `${k}Sync`], [fs.promises, k]]) if (typeof obj[name] === 'function') obj[name] = wrap(obj[name], k);
for (const f of [fs.realpath, fs.realpathSync]) f.native = wrap(f.native, 'realpath');
// the stream classes, called with new or without (setting fs.ReadStream also sets the class createReadStream uses)
const guarded = (C, at) => new Proxy(C, {
  construct(t, a, nt) { check(at(a)); return Reflect.construct(t, a, nt); },
  apply(t, self, a) { check(at(a)); return Reflect.apply(t, self, a); },
});
for (const k of ['ReadStream', 'WriteStream', 'FileReadStream', 'FileWriteStream']) if (typeof fs[k] === 'function') fs[k] = guarded(fs[k], (a) => a[0]);
// (fs.Utf8Stream opens its dest with fs.open or fs.openSync, checked above)

// a change of folder
const chdir = process.chdir;
process.chdir = function (d) { check(d); return chdir.call(this, d); };

// a .env file read into the environment (Node 20.12 on: by Node's own code, not fs; './.env' when no path is given)
const loadEnvFile = process.loadEnvFile;
if (typeof loadEnvFile === 'function') process.loadEnvFile = function (...a) { check(a[0] == null ? '.env' : a[0]); return loadEnvFile.apply(this, a); };

// node:sqlite (Node 22.5 on) opens files by SQLite's own code, not fs: where a database is opened (DatabaseSync and
// Database, by new or open()), backed up to (backup) or an extension loaded from (loadExtension); and, on a Node with
// setAuthorizer, which SQLite tells of each, a file SQL attaches (ATTACH, VACUUM INTO). The net reads plain paths only:
// a place SQLite reads as a URI (file:..., whose query can name another file), a file SQL gives by a bound value and
// SQL's load_extension() are refused whole. Wrapped when a test first loads it (loading it here would print Node's
// experimental warning in every process): by require(), import (from Node 22.15) or process.getBuiltinModule.
const SQLITE = Symbol.for('wardlatch.test.no-real-home.sqlite');
const dbAt = (loc) => {
  const s = typeof loc === 'string' ? loc : loc instanceof Uint8Array ? Buffer.from(loc.buffer, loc.byteOffset, loc.byteLength).toString() : null;
  if (s === '' || s === ':memory:') return;   // no file
  if (s !== null ? /^file:/i.test(s) : !!(loc && typeof loc === 'object' && (loc.search || loc.hash))) refuse(s ?? String(loc.href), 'named a SQLite database by a URI, which the net doesn\'t read', 'name it by a plain path');
  check(loc);
};
const sqlite = (m) => {
  if (!m || typeof m !== 'object' || m[SQLITE]) return m;
  m[SQLITE] = true;
  const c = m.constants ?? {};
  const guard = (action, a1, a2) => {
    if (action === c.SQLITE_ATTACH) {
      if (typeof a1 !== 'string') refuse('ATTACH', 'attached a SQLite file by a bound value, which the net doesn\'t read', 'write its path in the SQL');
      dbAt(a1);
    } else if (action === c.SQLITE_FUNCTION && typeof a2 === 'string' && a2.toLowerCase() === 'load_extension') {
      refuse('load_extension()', 'loaded a SQLite extension from SQL, which the net doesn\'t read', 'load it with loadExtension(path)');
    }
  };
  const made = new Map();   // (Database is DatabaseSync on Node 26)
  for (const name of ['DatabaseSync', 'Database']) {
    const C = m[name];
    if (typeof C !== 'function') continue;
    if (!made.has(C)) {
      const P = C.prototype, { setAuthorizer, open, loadExtension } = P;
      let own = () => {};
      if (typeof setAuthorizer === 'function') {
        // ours first, then the test's own, which can't take ours off (null puts back ours alone)
        P.setAuthorizer = function (cb, ...a) {
          if (cb != null && typeof cb !== 'function') return setAuthorizer.call(this, cb, ...a);   // Node refuses it
          return setAuthorizer.call(this, (...x) => { guard(...x); return cb ? cb(...x) : c.SQLITE_OK ?? 0; }, ...a);
        };
        const ours = P.setAuthorizer;
        own = (db) => { try { ours.call(db, null); } catch { /* not open yet: open() sets it */ } };
      }
      if (typeof open === 'function') P.open = function (...a) { const r = open.apply(this, a); own(this); return r; };
      if (typeof loadExtension === 'function') P.loadExtension = function (p, ...a) { check(p); return loadExtension.call(this, p, ...a); };
      made.set(C, new Proxy(C, { construct(t, a, nt) { dbAt(a[0]); const db = Reflect.construct(t, a, nt); own(db); return db; } }));
      // the class its prototype and every database give (db.constructor) is that same guarded one
      const d = Object.getOwnPropertyDescriptor(P, 'constructor');
      if (d?.value === C) Object.defineProperty(P, 'constructor', { ...d, value: made.get(C) });
    }
    m[name] = made.get(C);
  }
  if (typeof m.backup === 'function') { const backup = m.backup; m.backup = function (db, p, ...a) { dbAt(p); return backup.call(this, db, p, ...a); }; }
  Module.syncBuiltinESMExports();
  return m;
};
const load = Module._load;
Module._load = function (request, ...rest) { const r = load.call(this, request, ...rest); return request === 'node:sqlite' ? sqlite(r) : r; };
const getBuiltin = process.getBuiltinModule;
if (typeof getBuiltin === 'function') process.getBuiltinModule = function (id, ...a) { const r = getBuiltin.call(this, id, ...a); return id === 'node:sqlite' ? sqlite(r) : r; };

// require() and import of a file there, checked before Node looks; then a file require() found is read through
// fs.readFileSync, checked above, and where an import led (a link into the home) is checked too, as Node's loader may
// read the file without fs. And of a package name, which Node looks for in the node_modules folders up from the
// importing file (require() then in ~/.node_modules and ~/.node_libraries too), in order: Node's own search runs up to
// the first folder in a home, so this checkout's own node_modules loads, and going on into that folder is refused.
// import is checked from Node 22.15 (module.registerHooks, which also runs for require()); on an older Node only
// require() is.
const pathLike = (s) => /^(?:\/|\.\.?(?:\/|$))/.test(s);
const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  if (typeof request === 'string' && !Module.isBuiltin(request)) {
    const from = parent?.filename ? path.dirname(parent.filename) : process.cwd();
    if (pathLike(request)) check(path.resolve(from, request));
    else if (request.startsWith('#')) hashSearch(from);
  }
  return resolveFilename.call(this, request, parent, ...rest);
};
// require()'s search for a package name (Module._findPath, as Node calls it, with require.resolve's paths too); in a
// folder it may search, the name itself is checked too (a package linked there from a home, as npm link makes one)
const findPath = Module._findPath;
Module._findPath = function (request, paths, ...rest) {
  if (typeof request === 'string' && !pathLike(request) && Array.isArray(paths)) {
    const i = paths.findIndex((d) => { const abs = where(d); return abs !== null && offLimits(abs); });
    for (const d of i < 0 ? paths : paths.slice(0, i)) if (typeof d === 'string') check(path.resolve(d, request));
    if (i >= 0) {
      const found = i > 0 ? findPath.call(this, request, paths.slice(0, i), ...rest) : false;
      if (found) return found;
      refuse(path.join(String(paths[i]), request));
    }
  }
  return findPath.call(this, request, paths, ...rest);
};
// import's search for a package name stops at the first of those folders that holds a folder of that name, found or
// not (require() goes on): one in a home before it is refused. A name read otherwise ('@scope' alone, '..') is looked
// for in every folder, so any in a home is refused.
const importSearch = (spec, from) => {
  const scoped = spec.startsWith('@'), name = spec.split('/').slice(0, scoped ? 2 : 1);
  const plain = name.length === (scoped ? 2 : 1) && name.every((x) => x && x !== '.' && x !== '..' && !/[\\%]/.test(x));
  for (const d of Module._nodeModulePaths(from)) {
    check(d);
    if (!plain) continue;
    const p = path.join(d, ...name);
    check(p);
    try { if (statSync(p).isDirectory()) return; } catch { /* not here: on up */ }
  }
};
// A '#' name (package.json's imports), by require() or import: Node reads the nearest package.json up from the
// importing file's folder (not past a node_modules folder) and, for a target that names a package, looks for that
// package as import does, up from that package.json's folder: in the checkout's own node_modules it loads, and going on
// into a home's is refused. The net doesn't work out which target Node takes: it checks that search for every package
// any target in that file's imports names (any name, condition or fallback; a pattern's '*' kept, so that name is
// looked for in every folder). A package.json in a home on the way is refused, as Node would read it; one the net
// can't read as JSON is read as naming any package.
const hashSearch = (from) => {
  for (let d = from; path.basename(d) !== 'node_modules'; d = path.dirname(d)) {
    const f = path.join(d, 'package.json');
    check(f);
    let text;
    try { text = readFileSync(f, 'utf8'); } catch { if (d === path.dirname(d)) return; continue; }   // none here: on up
    let imports;
    try { imports = JSON.parse(text.replace(/^\uFEFF/, '')).imports; } catch {
      for (const n of Module._nodeModulePaths(d)) check(n);
      return;
    }
    const todo = [imports];
    while (todo.length) {
      const v = todo.pop();
      if (v && typeof v === 'object') for (const x of Object.values(v)) todo.push(x);
      // (a target that isn't a package: './' a file of the package, a builtin; '../', '/' and a URL Node refuses)
      else if (typeof v === 'string' && !/^(?:\.?\.?\/|[a-z][a-z\d+.-]*:)/i.test(v) && !Module.isBuiltin(v)) {
        importSearch(v, d);
      }
    }
    return;
  }
};
if (typeof Module.registerHooks === 'function') {
  Module.registerHooks({
    resolve(spec, context, next) {
      if (spec === 'node:sqlite') sqlite(getBuiltin('node:sqlite'));
      if (typeof spec === 'string' && !Module.isBuiltin(spec)) {
        const parent = context?.parentURL?.startsWith('file:') ? context.parentURL : null;
        let url = null;
        try { url = /^[a-z][a-z\d+.-]*:/i.test(spec) || pathLike(spec) ? new URL(spec, parent ?? pathToFileURL(`${process.cwd()}/`)) : null; } catch { url = null; }
        const conditions = Array.isArray(context?.conditions) ? context.conditions : [];
        const from = () => (parent ? path.dirname(fileURLToPath(parent)) : process.cwd());
        if (url?.protocol === 'file:') check(url);
        else if (!url && spec.startsWith('#')) hashSearch(from());
        // (a require() goes on to Module._findPath, above)
        else if (!url && !(conditions.includes('require') && !conditions.includes('import'))) importSearch(spec, from());
      }
      const r = next(spec, context);
      if (typeof r?.url === 'string' && r.url.startsWith('file:')) check(new URL(r.url));
      return r;
    },
  });
}

// every process a test starts gets this file: a Node by its path or name (this one: --require; another, or one a #!
// line names, such as #!/usr/bin/env node: NODE_OPTIONS), a fork (NODE_OPTIONS), and a shell command (execSync, shell:
// true, and exec, which runs execFile with shell: true: NODE_OPTIONS, for any node it runs). From a test file every
// child gets NODE_OPTIONS, whatever it is (a script that runs node). Below that only a Node does: the code under test
// builds its children's environments (lib/run.mjs), and a test reads them.
const SELF = key(physical(process.execPath));
/** The program a child runs, from its working folder (cwd) and, for a name, each folder of its PATH in turn, as the
 *  system looks for it: a place in a home is refused before it is looked at. */
const locate = (file, env, cwd) => {
  const f = String(file);
  if (f.includes('/')) { check(path.resolve(cwd, f)); return path.resolve(cwd, f); }
  for (const d of String(env.PATH ?? '/usr/bin:/bin').split(path.delimiter)) {
    const p = path.resolve(cwd, d || '.', f);
    check(p);
    try { if (statSync(p).isFile()) { accessSync(p, fs.constants.X_OK); return p; } } catch { /* not here */ }
  }
  return null;
};
/** 'self' (the Node running this), 'node' (another Node, or a script a #! line runs with node), or null. */
const nodeKind = (p) => {
  if (!p) return null;
  const real = physical(p, stop);
  if (key(real) === SELF) return 'self';
  const head = Buffer.alloc(256);
  let n = 0;
  try {
    if (!statSync(real).isFile()) return null;
    const fd = openSync(real, 'r');
    try { n = readSync(fd, head, 0, 256, 0); } finally { closeSync(fd); }
  } catch { return null; }
  const text = head.subarray(0, n).toString('latin1');
  if (text.startsWith('#!')) {
    const words = text.slice(2).split('\n')[0].trim().split(/[ \t]+/);
    const prog = path.basename(words[0]) === 'env' ? words.slice(1).find((w) => !w.startsWith('-') && !w.includes('=')) : words[0];
    return prog && /^node(?:js)?[\d.]*$/.test(path.basename(prog)) ? 'node' : null;
  }
  const binary = /^(?:\x7fELF|\xcf\xfa\xed\xfe|\xce\xfa\xed\xfe|\xfe\xed\xfa\xcf|\xfe\xed\xfa\xce|\xca\xfe\xba\xbe)/.test(text);
  return binary && /^node/.test(path.basename(real)) ? 'node' : null;
};
const payload = (extra) => JSON.stringify({ homes: HOMES, marks: marks(), ...extra });
// (quoted only when it must be: a path with a space, a quote or a backslash)
const REQUIRE = `--require ${/[\s"'\\]/.test(__filename) ? JSON.stringify(__filename) : __filename}`;
const withOptions = (env) => ({ ...env, NODE_OPTIONS: `${REQUIRE}${env.NODE_OPTIONS ? ` ${env.NODE_OPTIONS}` : ''}`, [KEY]: payload({ nodeOptions: env.NODE_OPTIONS ?? null }) });
// a Node's own flags that read a file as it starts, before any code of it runs (this file's too), from its working
// folder: --env-file, --env-file-if-exists, --experimental-config-file and --config-file (flag=path, or the path as
// the next word), and --experimental-default-config-file (node.config.json; Node 26 reads the two config flags without
// '=' so too, the next word being the script: both readings are checked). Node takes none of them from NODE_OPTIONS.
// Every word of a Node's arguments (a fork's: its execArgv) is read so, a word after the script too (the script's own:
// when in doubt, refuse); a shell command's words and a #! line's are not read.
const FLAG_FILES = ['--env-file', '--env-file-if-exists', '--experimental-config-file', '--config-file'];
const DEFAULT_CONFIG = ['--experimental-default-config-file', '--experimental-config-file', '--config-file'];
const nodeFlags = (words, cwd) => {
  if (!Array.isArray(words)) return;
  words.forEach((w, i) => {
    const s = String(w);
    if (DEFAULT_CONFIG.includes(s)) check(path.join(cwd, 'node.config.json'));
    for (const f of FLAG_FILES) {
      if (s === f && i + 1 < words.length) check(path.resolve(cwd, String(words[i + 1])));
      else if (s.startsWith(`${f}=`)) check(path.resolve(cwd, s.slice(f.length + 1)));
    }
  });
};
const carry = (kind, o) => function (file, ...a) {
  const shellCmd = kind === 'execSync';
  const args = shellCmd ? null : Array.isArray(a[0]) ? a.shift() : a[0] == null && a.length ? (a.shift(), []) : [];
  const opts = a.length && (a[0] == null || typeof a[0] === 'object') ? a.shift() ?? {} : {};
  const env = opts.env ?? process.env;
  const call = (as, op) => o.call(this, file, ...(as ? [as] : []), op, ...a);
  // the test chose (a test of this file): it gave the child the variable itself. The one this process was given is no
  // choice: a node --test runner keeps it, and a test file it runs in its own process (--test-isolation=none) starts
  // its children with the net
  if (Object.prototype.hasOwnProperty.call(env, KEY) && env[KEY] !== undefined && `${env[KEY]}` !== process.env[KEY]) return call(args, opts);
  const cwd = where(opts.cwd ?? '.') ?? '/';
  if (opts.cwd != null) check(opts.cwd);
  if (kind === 'fork') {
    check(typeof file === 'string' ? path.resolve(cwd, file) : file);
    nodeFlags(opts.execArgv ?? process.execArgv, cwd);
  }
  // a fork's execArgv is left as it is: Node takes -e out of its own execArgv only when it is that same list (else a
  // fork from node -e runs the -e code again, and forks again)
  if (kind === 'fork' || shellCmd || opts.shell) return call(args, { ...opts, env: withOptions(env) });
  const how = nodeKind(locate(file, env, cwd));
  if (how) nodeFlags(args, cwd);
  if (how === 'self') return call(['--require', __filename, ...args], { ...opts, env: { ...env, [KEY]: payload() } });
  if (how === 'node' || !child) return call(args, { ...opts, env: withOptions(env) });
  return call(args, opts);
};
for (const k of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'execSync', 'fork']) cp[k] = carry(k, cp[k]);

// a Worker thread has an fs and a module loader of its own: its file is checked, and it gets this file by the
// NODE_OPTIONS of the environment it is given (a Worker reads them from one; its execArgv stay its own, and the net
// puts the NODE_OPTIONS back in its copy), or, with SHARE_ENV, by --require before the execArgv the test gave (the
// options of this thread's command line are then not passed on). What to refuse goes as the threads' environment data.
const { Worker } = wt;
wt.Worker = new Proxy(Worker, {
  construct(t, a, nt) {
    const o = a[1] && typeof a[1] === 'object' ? a[1] : {};
    if (!o.eval) check(a[0]);
    const shared = o.env === wt.SHARE_ENV, env = shared ? null : o.env ?? process.env;
    wt.setEnvironmentData(KEY, payload(shared ? {} : { nodeOptions: env.NODE_OPTIONS ?? null }));
    const opts = shared ? { ...o, execArgv: ['--require', __filename, ...(o.execArgv ?? [])] }
      : { ...o, env: { ...env, NODE_OPTIONS: `${REQUIRE}${env.NODE_OPTIONS ? ` ${env.NODE_OPTIONS}` : ''}` } };
    return Reflect.construct(t, [a[0], opts, ...a.slice(2)], nt);
  },
});
Module.syncBuiltinESMExports();
