#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The CISA KEV rows for every CVE our incident files name, taken from a copy of CISA's feed that you downloaded, and
// written to test/support/fixtures/kev-snapshot.json. test/kev.test.mjs then holds every incident file to it: an
// incident whose CVE is in the snapshot must carry the same `kev` row, and one that is not must carry none.
//
//   curl -sSo kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   node scripts/kev-snapshot.mjs kev.json
//
// Wardlatch itself never fetches the feed (it runs offline); this is a maintainer's step, run before a release.
// The feed is read whole or not at all: if its `count` is not the number of rows read, nothing is written, because a
// CVE "not in KEV" from a partial read is a negative from an incomplete scan.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const feedPath = process.argv[2];
if (!feedPath || process.argv.length > 3) { console.error('usage: node scripts/kev-snapshot.mjs <known_exploited_vulnerabilities.json>'); process.exit(2); }

export const CVE = /CVE-\d{4}-\d{4,}/g;
const feed = JSON.parse(readFileSync(feedPath, 'utf8'));
const rows = feed.vulnerabilities;
if (!Array.isArray(rows) || !rows.length || feed.count !== rows.length) {
  console.error(`the feed says count ${feed.count} and holds ${Array.isArray(rows) ? rows.length : 'no'} rows: not a whole catalog, nothing written`);
  process.exit(1);
}
const byId = new Map(rows.map((r) => [r.cveID, r]));
if (byId.size !== rows.length) { console.error('the feed names a CVE twice: nothing written'); process.exit(1); }

const dir = join(ROOT, 'lib', 'incidents');
const named = {};
for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
  const ids = [...new Set(readFileSync(join(dir, f), 'utf8').match(CVE) ?? [])].sort();
  if (ids.length) named[f.replace(/\.json$/, '')] = ids;
}
const listed = {}, notListed = {};
for (const [inc, ids] of Object.entries(named)) {
  for (const id of ids) {
    const r = byId.get(id);
    if (r) (listed[inc] ??= []).push({ cve: id, vendorProject: r.vendorProject, product: r.product, dateAdded: r.dateAdded, dueDate: r.dueDate });
    else (notListed[inc] ??= []).push(id);
  }
}
const out = {
  source: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, count: feed.count, read: rows.length,
  listed, notListed,
};
const target = join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json');
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`catalog ${feed.catalogVersion}: ${rows.length} of ${feed.count} rows read; ${Object.values(listed).flat().length} listed, ${Object.values(notListed).flat().length} not listed; wrote ${target}`);
