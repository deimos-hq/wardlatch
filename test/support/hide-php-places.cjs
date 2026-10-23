// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that run the PHP check: hides the folders it searches off PATH (/usr/sbin, /usr/local, /opt), so
// a machine with PHP installed there (a CI runner, a developer's Mac) can't change what a test sees. Nothing else changes.
'use strict';
const fs = require('node:fs');
const HIDDEN = /^\/(?:usr\/sbin|usr\/local|opt)(?:\/|$)/;
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const exists = fs.existsSync;
fs.existsSync = (p) => !HIDDEN.test(String(p)) && exists(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => { if (HIDDEN.test(String(p))) throw gone(); return o(p, ...a); };
}
require('node:module').syncBuiltinESMExports();
