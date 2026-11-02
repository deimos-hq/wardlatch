// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Seat 6. Maps one absolute folder onto a rig folder, for a place this user cannot write (no sudo here), and logs
// every path Wardlatch asked for under it. Nothing is planted in the real place.
'use strict';
const fs = require('node:fs');
const from = process.env.S6_FROM, to = process.env.S6_TO, log = process.env.S6_LOG;
const m = (p) => {
  if (typeof p === 'string' && (p === from || p.startsWith(`${from}/`))) { try { fs.appendFileSync(log, `${p}\n`); } catch { /* */ } return to + p.slice(from.length); }
  return p;
};
for (const k of ['statSync', 'lstatSync', 'readdirSync', 'openSync', 'realpathSync']) {
  const o = fs[k];
  const w = function (p, ...r) { return o.call(this, m(p), ...r); };
  if (o.native) w.native = o.native;
  fs[k] = w;
}
require('node:module').syncBuiltinESMExports();
