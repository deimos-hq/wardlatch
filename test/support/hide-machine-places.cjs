// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that run the bundled-decoder check end to end: hides the machine's own places it reads (system
// and Homebrew libraries, framework and system Pythons, the version managers' machine-wide folders, the distribution's
// package records, the dynamic loader's folder lists) and the node running the test, so a developer's Mac or a CI
// runner, with its real Pillow or Node, can't change what a test sees. HOME and PATH point into the test's own folder.
// Nothing else changes.
'use strict';
const fs = require('node:fs');
const HIDDEN = /^\/(?:usr|opt|lib|lib64|Library|System|Applications|home\/linuxbrew|var\/lib\/dpkg|etc\/os-release|etc\/ld\.so\.conf|etc\/ld\.so\.conf\.d)(?:\/|$)/;
const self = new Set([process.execPath]);
try { self.add(fs.realpathSync(process.execPath)); } catch { /* the node running this may be gone */ }
const hidden = (p) => HIDDEN.test(String(p)) || self.has(String(p));
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const exists = fs.existsSync;
fs.existsSync = (p) => !hidden(p) && exists(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => { if (hidden(p)) throw gone(); return o(p, ...a); };
}
require('node:module').syncBuiltinESMExports();
