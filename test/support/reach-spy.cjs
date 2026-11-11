// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// A spy for test/reach.test.mjs, loaded into the command by node --require; only a test loads it. It watches every
// way Node's fs can take content out of the folder WARDLATCH_REACH_SPY_HOME names (the test's made-up home): a read of
// a descriptor that was opened there, and any read, listing or stream by a path there. At exit it writes what it saw to
// the file WARDLATCH_REACH_SPY_OUT names: { opens: [{ path, flags }], reads: [names of the calls that took content] }.
// --reach may open and close; `reads` must stay empty. The test proves the spy can fill it (a script that reads).
'use strict';
const fs = require('node:fs');
const { syncBuiltinESMExports } = require('node:module');

const HOME = fs.realpathSync(process.env.WARDLATCH_REACH_SPY_HOME), OUT = process.env.WARDLATCH_REACH_SPY_OUT;
const write = fs.writeFileSync, real = fs.realpathSync;
const under = (p) => {
  if (typeof p !== 'string' && !Buffer.isBuffer(p) && !(p instanceof URL)) return false;
  let s = p instanceof URL ? p.pathname : String(p);
  // a path as the system reads it, as far as it exists: a link into the home counts
  try { s = real(s); } catch { /* not there: compare as written */ }
  return s === HOME || s.startsWith(`${HOME}/`);
};
const seen = { opens: [], reads: [] };
const fds = new Set();

const open = fs.openSync;
fs.openSync = function openSync(p, flags, ...rest) {
  const fd = open.call(this, p, flags, ...rest);
  if (under(p)) { fds.add(fd); seen.opens.push({ path: String(p).slice(HOME.length), flags }); }
  return fd;
};
const close = fs.closeSync;
fs.closeSync = function closeSync(fd) { fds.delete(fd); return close.call(this, fd); };

// content through a descriptor
for (const k of ['readSync', 'read', 'readvSync', 'readv']) {
  const o = fs[k];
  fs[k] = function (fd, ...rest) { if (fds.has(fd)) seen.reads.push(k); return o.call(this, fd, ...rest); };
}
// content, or a folder's entries, by a path (readFile and createReadStream also take a descriptor)
for (const k of ['readFileSync', 'readFile', 'readdirSync', 'readdir', 'opendirSync', 'opendir', 'createReadStream', 'readlinkSync', 'openAsBlob', 'cpSync', 'copyFileSync', 'open', 'watch']) {
  const o = fs[k];
  if (typeof o !== 'function') continue;
  fs[k] = function (p, ...rest) { if (fds.has(p) || under(p)) seen.reads.push(k); return o.call(this, p, ...rest); };
}
for (const k of ['readFile', 'readdir', 'opendir', 'open', 'readlink', 'cp', 'copyFile']) {
  const o = fs.promises[k];
  fs.promises[k] = function (p, ...rest) { if (under(p)) seen.reads.push(`promises.${k}`); return o.call(this, p, ...rest); };
}
syncBuiltinESMExports();
process.on('exit', () => write(OUT, JSON.stringify(seen)));
