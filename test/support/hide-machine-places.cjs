// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that run the bundled-decoder check end to end: hides the machine's own places it reads (system
// and Homebrew libraries, framework and system Pythons, the version managers' machine-wide folders, the distribution's
// package records, the dynamic loader's folder lists, and the server folders whose virtual environments are always read:
// /srv/*/venv, /app/.venv, /var/www) and the node running the test, so a developer's Mac, a dev container or a CI runner,
// with its real Pillow or Node, can't change what a test sees. HOME and PATH point into the test's own folder. The code
// under test (the checkout's bin/, lib/ and test/, and its package.json) and the test's own folder (named in
// WARDLATCH_TEST_OWN_DIR by the test that starts the command) are never hidden, wherever they are (a dev container may
// keep them in /app or /srv); the rest of the checkout is, so /app/.venv beside a checkout at /app is too. Nothing else
// changes. What is hidden: test/support/machine-places.cjs.
'use strict';
const fs = require('node:fs');
const { resolve } = require('node:path');
const { hiddenPlaces } = require('./machine-places.cjs');
const self = [process.execPath];
try { self.push(fs.realpathSync(process.execPath)); } catch { /* the node running this may be gone */ }
const real = (d) => { try { return fs.realpathSync(d); } catch { return null; } };
const own = process.env.WARDLATCH_TEST_OWN_DIR;
delete process.env.WARDLATCH_TEST_OWN_DIR;
const hidden = hiddenPlaces({ root: resolve(__dirname, '..', '..'), own, self, real });
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const exists = fs.existsSync;
fs.existsSync = (p) => !hidden(p) && exists(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => { if (hidden(p)) throw gone(); return o(p, ...a); };
  // realpathSync.native (the OS's realpath, which lib/files.mjs realPathAsWritten uses) hides the same places
  if (o.native) fs[k].native = (p, ...a) => { if (hidden(p)) throw gone(); return o.native(p, ...a); };
}
require('node:module').syncBuiltinESMExports();
