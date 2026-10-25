// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// A user's home folder where the code looks for one, made of a folder in the test's own temporary folder: the code
// sees /Users/<name> on macOS (in any case, and under /System/Volumes/Data, as macOS spells it) or /home/<name>
// elsewhere, and every look at it goes to `folder`. So no test needs a real user's home, or reads one
// (test/support/no-real-home.cjs refuses that). fakeHome(name, folder) → a function that puts fs back. Used in a test,
// or loaded into the command by a test's stand-in (node --require); only a test loads it.
'use strict';
const fs = require('node:fs');
const { syncBuiltinESMExports } = require('node:module');

exports.fakeHome = (name, folder) => {
  const mac = process.platform === 'darwin', home = `${mac ? '/Users' : '/home'}/${name}`;
  const same = (a, b) => (mac ? a.toLowerCase() === b.toLowerCase() : a === b);
  const to = (p) => {
    if (typeof p !== 'string') return p;
    const q = mac ? p.replace(/^\/System\/Volumes\/Data(?=\/)/i, '') : p;
    return same(q.slice(0, home.length), home) && [undefined, '/'].includes(q[home.length]) ? folder + q.slice(home.length) : p;
  };
  const back = (p) => (typeof p === 'string' && (p === folder || p.startsWith(`${folder}/`)) ? home + p.slice(folder.length) : p);
  const saved = {};
  for (const k of ['existsSync', 'statSync', 'lstatSync', 'readdirSync', 'openSync']) { const o = saved[k] = fs[k]; fs[k] = (p, ...a) => o(to(p), ...a); }
  const rp = saved.realpathSync = fs.realpathSync;
  fs.realpathSync = (p, ...a) => back(rp(to(p), ...a));
  syncBuiltinESMExports();
  return () => { Object.assign(fs, saved); syncBuiltinESMExports(); };
};
