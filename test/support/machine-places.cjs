// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// What test/support/hide-machine-places.cjs hides, as a function of where the checkout is, so a test can ask about a
// checkout anywhere (a dev container keeps it in /app or /srv, beside the server folders the check always reads).
'use strict';
const { resolve, sep } = require('node:path');

const HIDDEN = /^\/(?:usr|opt|lib|lib64|Library|System|Applications|srv|app|var\/www|home\/linuxbrew|var\/lib\/dpkg|etc\/os-release|etc\/ld\.so\.conf|etc\/ld\.so\.conf\.d|etc\/ld-musl-[^/]*\.path)(?:\/|$)/;

/**
 * → (path) => whether the preload hides it. root: the checkout; own: the test's own temporary folder (or none); self:
 * the paths of the node running the test; real: a path's real path (or null). Never hidden: the code under test (the
 * checkout's bin/, lib/ and test/, and its package.json, which the command reads its version from) and the test's own
 * folder. The rest of the checkout and of the temporary folder is hidden like any other place: a checkout at /app has
 * /app/.venv beside it, which the check always reads.
 */
exports.hiddenPlaces = ({ root, own, self = [], real = () => null }) => {
  const twice = (p) => [p, real(p) ?? p];
  const kept = [...['bin', 'lib', 'test'].map((d) => resolve(root, d)), ...(own ? [resolve(own)] : [])].flatMap(twice).map((d) => (d.endsWith(sep) ? d : d + sep));
  const files = new Set(twice(resolve(root, 'package.json')));
  const me = new Set(self);
  return (p) => { const s = String(p); return !kept.some((k) => s.startsWith(k)) && !files.has(s) && (HIDDEN.test(s) || me.has(s)); };
};
