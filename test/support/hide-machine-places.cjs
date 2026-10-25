// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that run the bundled-decoder check end to end: hides the machine's own places it reads (system
// and Homebrew libraries, framework and system Pythons, the version managers' machine-wide folders, the distribution's
// package records, the dynamic loader's folder lists, and the server folders whose virtual environments are always read:
// /srv/*/venv, /app/.venv, /var/www) and the node running the test, so a developer's Mac, a dev container or a CI runner,
// with its real Pillow or Node, can't change what a test sees. HOME and PATH point into the test's own folder. The code
// under test and the test's temporary folder are never hidden, wherever they are (a dev container may keep them in /app
// or /srv). Nothing else changes.
'use strict';
const fs = require('node:fs');
const { resolve, sep } = require('node:path');
const { tmpdir } = require('node:os');
const HIDDEN = /^\/(?:usr|opt|lib|lib64|Library|System|Applications|srv|app|var\/www|home\/linuxbrew|var\/lib\/dpkg|etc\/os-release|etc\/ld\.so\.conf|etc\/ld\.so\.conf\.d|etc\/ld-musl-[^/]*\.path)(?:\/|$)/;
const self = new Set([process.execPath]);
try { self.add(fs.realpathSync(process.execPath)); } catch { /* the node running this may be gone */ }
const kept = [resolve(__dirname, '..', '..'), tmpdir()].flatMap((d) => { try { return [d, fs.realpathSync(d)]; } catch { return [d]; } }).map((d) => (d.endsWith(sep) ? d : d + sep));
const hidden = (p) => !kept.some((k) => String(p).startsWith(k)) && (HIDDEN.test(String(p)) || self.has(String(p)));
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const exists = fs.existsSync;
fs.existsSync = (p) => !hidden(p) && exists(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => { if (hidden(p)) throw gone(); return o(p, ...a); };
}
require('node:module').syncBuiltinESMExports();
