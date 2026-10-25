// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The tests' safety net: no test looks in the real home folder of the person running them, where macOS keeps
// Desktop, Documents, Downloads, Library, iCloud Drive, Photos and Mail. Every test file loads it first, and it goes
// with every Node process a test starts, at any depth, with the same folders. Off limits: the home the tests were
// started with (os.homedir() before any test changes HOME), the account's own (its home in the user database, and
// /Users/<name> on macOS or /home/<name> elsewhere) and, under sudo, SUDO_USER's (/Users/<name> or /home/<name>, and
// its line in /etc/passwd). Inside them, this checkout and the folder of the Node running the tests (nvm and the like
// keep it there) stay readable.
// A path is compared as the system reads it: '.', '..' and links followed in order, and on macOS in any case and with
// the start-up disk's folders also spelt under /System/Volumes/Data or /Volumes/<x>, however many times. Following a
// link never looks inside a home: a folder off limits is never looked at, but for those on the way to this checkout.
// A look under them is never made: a read, a listing, a stat, an open, a write, a glob, a stream, a require() or an
// import, a change of folder, a program started there or in a working folder there, or found through a PATH folder
// there. In the test it throws, says so on stderr and fails the test file. In a process a test started it ends that
// process at once (exit 70), whatever would catch the error (lib/files.mjs reads one as "can't be opened"), and leaves
// a note the test file reads when it exits: a refusal anywhere below a test fails the test file, even when nothing
// checks that process's exit code.
// The PATH the tests were started with loses its folders under them, so no test, and no command a test runs with that
// PATH, looks for a program there (~/.local/bin, ~/.cargo/bin).
// What no net inside Node can stop: a program that isn't Node (and a Node one starts below the command), and macOS's
// own libraries reading ~/.CFUserTextEncoding as any process starts (CONTRIBUTING.md, Testing policy).
'use strict';
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
const Module = require('node:module');
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
// own environment first, so the code under test never sees it. An empty value starts a process as a test file starts
// (a test of this file needs that).
const KEY = 'WARDLATCH_TEST_NO_HOME';
const MAC = process.platform === 'darwin';
let given = null;
try { given = process.env[KEY] ? JSON.parse(process.env[KEY]) : null; } catch { /* not from this file: started as a test file */ }
delete process.env[KEY];
const child = !!given && Array.isArray(given.homes) && typeof given.marks === 'string';
// NODE_OPTIONS carried this file here: put back what the process was given, so the code under test reads its own
if (child && 'nodeOptions' in given) { if (given.nodeOptions == null) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = given.nodeOptions; }

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
const offLimits = (abs) => shut(key(physical(abs, stop)));

// where a process a test started leaves its note (a test file: a folder of its own, removed when it exits)
let MARKS = child ? given.marks : '';
if (!child) {
  const t = os.tmpdir();
  try { MARKS = mkdtempSync(path.join(offLimits(where(t)) ? '/tmp' : t, 'wardlatch-no-home-')); } catch { MARKS = ''; }
}
let looked = false, notes = 0;
const refuse = (s) => {
  const msg = `test/support/no-real-home.cjs: a test looked in the real home folder (${s}); give it a home of its own`;
  const text = `\n${msg}\n${new Error().stack.split('\n').slice(3).join('\n')}\n`;
  try { writeSync(2, text); } catch { /* stderr is gone */ }
  if (child) {
    try { if (MARKS) writeFileSync(path.join(MARKS, `${process.pid}-${++notes}`), `process ${process.pid} (${process.argv.slice(1, 3).join(' ')}) was stopped (exit 70):${text}`); } catch { /* the test file has exited */ }
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

// a glob looks at its fixed start and walks below it (anywhere, with a '..' after a wildcard): a walk that could enter
// a home is refused whole
const MAGIC = /[*?[\]{}()!+@\\]/;
const checkGlob = (patterns, options) => {
  const cwd = (options && typeof options === 'object' && options.cwd != null ? where(options.cwd) : null) ?? where('.') ?? '/';
  for (const g of [].concat(patterns)) {
    if (typeof g !== 'string') continue;   // fs refuses it itself
    const parts = (g.startsWith('/') ? g : `${cwd}/${g}`).split('/');
    const i = parts.findIndex((x) => MAGIC.test(x));
    const start = (i < 0 ? parts : parts.slice(0, i)).join('/') || '/';
    check(start);
    if (i < 0) continue;
    const from = parts.slice(i).includes('..') ? '/' : key(physical(start, stop));
    if (HOMES.some((h) => under(h, from))) refuse(g);
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
  if (k === 'glob') checkGlob(a[0], a[1]); else for (const p of paths(k, a)) check(p);
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

// require() and import of a file there, and of a package name, which Node looks for in the node_modules folders up from
// the importing file (and require() in ~/.node_modules and ~/.node_libraries too); checked before Node looks. Then a
// file require() found is read through fs.readFileSync, checked above; where an import led (a link into the home) is
// checked too, as Node's loader may read the file without fs. import is checked from Node 22.15 (module.registerHooks,
// which also runs for require()); on an older Node only require() is.
const pathLike = (s) => /^(?:\/|\.\.?(?:\/|$))/.test(s);
const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  if (typeof request === 'string' && !Module.isBuiltin(request)) {
    const from = parent?.filename ? path.dirname(parent.filename) : process.cwd();
    if (pathLike(request)) check(path.resolve(from, request));
    else for (const d of Module._resolveLookupPaths?.(request, parent) ?? Module._nodeModulePaths(from)) check(d);
  }
  return resolveFilename.call(this, request, parent, ...rest);
};
if (typeof Module.registerHooks === 'function') {
  Module.registerHooks({
    resolve(spec, context, next) {
      if (typeof spec === 'string' && !Module.isBuiltin(spec)) {
        const parent = context?.parentURL?.startsWith('file:') ? context.parentURL : null;
        let url = null;
        try { url = /^[a-z][a-z\d+.-]*:/i.test(spec) || pathLike(spec) ? new URL(spec, parent ?? pathToFileURL(`${process.cwd()}/`)) : null; } catch { url = null; }
        if (url?.protocol === 'file:') check(url);
        else if (!url && !spec.startsWith('#')) for (const d of Module._nodeModulePaths(parent ? path.dirname(fileURLToPath(parent)) : process.cwd())) check(d);
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
const payload = (extra) => JSON.stringify({ homes: HOMES, marks: MARKS, ...extra });
// (quoted only when it must be: a path with a space, a quote or a backslash)
const REQUIRE = `--require ${/[\s"'\\]/.test(__filename) ? JSON.stringify(__filename) : __filename}`;
const withOptions = (env) => ({ ...env, NODE_OPTIONS: `${REQUIRE}${env.NODE_OPTIONS ? ` ${env.NODE_OPTIONS}` : ''}`, [KEY]: payload({ nodeOptions: env.NODE_OPTIONS ?? null }) });
const carry = (kind, o) => function (file, ...a) {
  const shellCmd = kind === 'execSync';
  const args = shellCmd ? null : Array.isArray(a[0]) ? a.shift() : a[0] == null && a.length ? (a.shift(), []) : [];
  const opts = a.length && (a[0] == null || typeof a[0] === 'object') ? a.shift() ?? {} : {};
  const env = opts.env ?? process.env;
  const call = (as, op) => o.call(this, file, ...(as ? [as] : []), op, ...a);
  if (Object.prototype.hasOwnProperty.call(env, KEY)) return call(args, opts);   // the test chose (a test of this file)
  const cwd = where(opts.cwd ?? '.') ?? '/';
  if (opts.cwd != null) check(opts.cwd);
  if (kind === 'fork') check(typeof file === 'string' ? path.resolve(cwd, file) : file);
  // a fork's execArgv is left as it is: Node takes -e out of its own execArgv only when it is that same list (else a
  // fork from node -e runs the -e code again, and forks again)
  if (kind === 'fork' || shellCmd || opts.shell) return call(args, { ...opts, env: withOptions(env) });
  const how = nodeKind(locate(file, env, cwd));
  if (how === 'self') return call(['--require', __filename, ...args], { ...opts, env: { ...env, [KEY]: payload() } });
  if (how === 'node' || !child) return call(args, { ...opts, env: withOptions(env) });
  return call(args, opts);
};
for (const k of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'execSync', 'fork']) cp[k] = carry(k, cp[k]);
Module.syncBuiltinESMExports();
