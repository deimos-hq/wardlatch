// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that need a folder the system refuses with EPERM: the folders named in WARDLATCH_TEST_EPERM (a
// JSON list of absolute paths), and everything below them, refuse to be listed or opened with EPERM, while stat still
// answers. That is the shape an unprivileged sandbox profile's `(deny file-read-data (subpath …))` gives on macOS
// (measured 31 Oct 2026, macOS 27.2), and the shape macOS's privacy protection gives (test/support/errno-mechanisms.mjs).
// A real sandbox cannot be built inside another one (sandbox_apply: Operation not permitted, measured the same day), so
// the offline suite, which runs inside one, builds the refusal this way instead; test/independent-read.test.mjs also
// runs the real mechanism where it can. Nothing else changes.
'use strict';
const fs = require('node:fs'), path = require('node:path');
let places = [];
try { places = JSON.parse(process.env.WARDLATCH_TEST_EPERM || '[]').map((p) => path.resolve(p)); } catch { /* none */ }
const under = (p) => {
  let a; try { a = path.resolve(String(p)); } catch { return false; }
  return places.some((d) => a === d || a.startsWith(`${d}/`));
};
const refuse = (p, syscall) => Object.assign(new Error(`EPERM: operation not permitted, ${syscall} '${p}'`), { code: 'EPERM', errno: -1, syscall, path: String(p) });
for (const [k, syscall] of [['readdirSync', 'scandir'], ['opendirSync', 'opendir'], ['openSync', 'open'], ['readFileSync', 'open']]) {
  const o = fs[k];
  fs[k] = function (p, ...a) { if (typeof p !== 'number' && under(p)) throw refuse(p, syscall); return o.call(this, p, ...a); };
}
require('node:module').syncBuiltinESMExports();
