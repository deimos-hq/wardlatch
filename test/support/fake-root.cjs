// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded (node --require) by tests that run the command on a stand-in system: every path under /etc, /lib, /usr,
// /sbin, /bin and /proc is read from the folder WL_FAKE_ROOT instead, and process.platform says WL_FAKE_PLATFORM. Nothing
// of the real system folders is read through Node's fs, and a path the stand-in doesn't hold is simply not there. No
// program is started through it: a test using it runs a check that starts none, and child_process refuses here.
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const cp = require('node:child_process');
const ROOT = process.env.WL_FAKE_ROOT;
if (!ROOT) throw new Error('fake-root.cjs: WL_FAKE_ROOT is not set');
if (process.env.WL_FAKE_PLATFORM) {
  Object.defineProperty(process, 'platform', { value: process.env.WL_FAKE_PLATFORM });
  os.platform = () => process.env.WL_FAKE_PLATFORM;
}
const SYS = /^\/(etc|lib|usr|sbin|bin|proc)(\/|$)/;
const m = (p) => (typeof p === 'string' && SYS.test(p) ? ROOT + p : p);
for (const k of ['existsSync', 'statSync', 'lstatSync', 'readdirSync', 'openSync', 'accessSync', 'readFileSync', 'opendirSync', 'readlinkSync']) {
  const o = fs[k];
  if (!o) continue;
  fs[k] = function (p, ...rest) { return o.call(this, m(p), ...rest); };
}
const rp = fs.realpathSync;
const wrapped = function (p, ...rest) { return rp.call(this, m(p), ...rest); };
wrapped.native = (p, ...rest) => rp.native(m(p), ...rest);
fs.realpathSync = wrapped;
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync', 'exec', 'execSync']) {
  cp[k] = (file) => { throw new Error(`fake-root.cjs: no program is run under a stand-in system (${file})`); };
}
require('node:module').syncBuiltinESMExports();
