// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.16: CISA KEV rows in the incident files and in the output. The rows are copied from a whole read of CISA's feed
// (scripts/kev-snapshot.mjs → test/support/fixtures/kev-snapshot.json) and every incident file is held to that copy
// here, in both directions: an incident whose CVE CISA lists must say so, and one CISA does not list must not.
// Wardlatch itself never fetches the feed.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { kevRows, kevLines, dayOf, KEV_URL } from '../lib/kev.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const SNAP = JSON.parse(readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json'), 'utf8'));
const INC_DIR = join(ROOT, 'lib', 'incidents');
const INCIDENTS = readdirSync(INC_DIR).filter((f) => f.endsWith('.json')).map((f) => ({ file: f, text: readFileSync(join(INC_DIR, f), 'utf8'), inc: JSON.parse(readFileSync(join(INC_DIR, f), 'utf8')) }));
const PRELOAD = ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs')];
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-kev-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
const cli = (args, bin = BIN) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  const r = spawnSync(process.execPath, [...PRELOAD, bin, ...args], { encoding: 'utf8', env: { ...rest, HOME: fresh(`home-${Math.random()}`), PATH: fresh(`path-${Math.random()}`), WARDLATCH_TEST_OWN_DIR: dir }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test('K1 the snapshot is a whole read of the catalog, and current to the incident files: every CVE they name is in it, listed or not', () => {
  assert.equal(SNAP.read, SNAP.count, 'a partial read cannot say a CVE is not listed');
  assert.ok(SNAP.count > 1000, `a catalog of ${SNAP.count} rows is not CISA's`);
  const inSnap = new Set([...Object.values(SNAP.listed).flat().map((r) => r.cve), ...Object.values(SNAP.notListed).flat()]);
  const named = INCIDENTS.flatMap(({ text }) => text.match(/CVE-\d{4}-\d{4,}/g) ?? []);
  assert.ok(named.length, 'the control: the incident files name CVEs');
  for (const cve of named) assert.ok(inSnap.has(cve), `${cve} is named by an incident file but not in the snapshot: run scripts/kev-snapshot.mjs on a fresh feed`);
});

test('K2 an incident whose CVE CISA lists carries exactly that row; one CISA does not list carries none', () => {
  let carried = 0;
  for (const { file, inc } of INCIDENTS) {
    const want = SNAP.listed[inc.id] ?? [];
    const have = (inc.kev ?? []).map(({ cve, vendorProject, product, dateAdded, dueDate }) => ({ cve, vendorProject, product, dateAdded, dueDate }));
    assert.deepEqual(have, want, `${file}: its kev rows must be the catalog's`);
    carried += have.length;
  }
  // the brief named SSHole and Brotli; the rule found PHP's two and Plex's four too, and CISA listed Chrome's on 10 Nov
  assert.equal(carried, 9);
  assert.deepEqual(Object.keys(SNAP.listed).sort(), ['brotli-2026-10', 'chrome-2026-11', 'php-2026-10', 'plex-2026-10', 'sshole-2026-11']);
});

test('K3 the line names CISA\'s vendor and product (Google Brotli, not Node.js), both dates and the catalog link', () => {
  const brotli = INCIDENTS.find(({ inc }) => inc.id === 'brotli-2026-10').inc;
  assert.deepEqual(kevLines(brotli), ['CISA KEV: Google Brotli CVE-2026-111497 is known to be exploited · added 27 Oct 2026 · due date for US federal agencies 10 Nov 2026 · https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-111497']);
  const php = INCIDENTS.find(({ inc }) => inc.id === 'php-2026-10').inc;
  assert.deepEqual(kevLines(php), ['CISA KEV: PHP Group PHP CVE-2026-109618 and CVE-2026-109619 are known to be exploited · added 26 Oct 2026 · due date for US federal agencies 29 Oct 2026 · https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-109618']);
  // Plex's four rows have two due dates: two lines, each with its own CVEs
  const plex = INCIDENTS.find(({ inc }) => inc.id === 'plex-2026-10').inc;
  const lines = kevLines(plex);
  assert.equal(lines.length, 2);
  assert.match(lines[0], /CVE-2026-96652 and CVE-2026-96655 are known .* due date for US federal agencies 3 Nov 2026/);
  assert.match(lines[1], /CVE-2026-96654 and CVE-2026-96656 are known .* due date for US federal agencies 23 Oct 2026/);
  assert.deepEqual(kevLines({ id: 'x' }), []);
});

test('K4 the line is printed under the title, and --json carries the rows with their links; an incident CISA does not list prints none', () => {
  const t = cli(['--incident', 'sshole-2026-11', '--no-containers']);
  const lines = t.out.split('\n');
  const at = lines.findIndex((l) => l.startsWith('SSHole'));
  assert.ok(at >= 0, t.out + t.err);
  assert.equal(lines[at + 1], 'CISA KEV: OpenBSD OpenSSH CVE-2026-123158 is known to be exploited · added 9 Nov 2026 · due date for US federal agencies 12 Nov 2026 · https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-123158');
  const j = JSON.parse(cli(['--incident', 'sshole-2026-11', '--incident', 'gitlab-2026-10', '--no-containers', '--json']).out);
  const ss = j.incidents.find((i) => i.id === 'sshole-2026-11'), gl = j.incidents.find((i) => i.id === 'gitlab-2026-10');
  assert.deepEqual(ss.kev, [{ cve: 'CVE-2026-123158', vendorProject: 'OpenBSD', product: 'OpenSSH', dateAdded: '2026-11-09', dueDate: '2026-11-12', url: KEV_URL('CVE-2026-123158') }]);
  assert.equal(gl.kev, undefined);
  const g = cli(['--incident', 'gitlab-2026-10', '--no-containers']);
  assert.ok(g.out.includes('GitLab'), 'the control: the GitLab check ran');
  assert.doesNotMatch(g.out, /CISA KEV/);
});

test('K5 a malformed row is a broken incident file: dates, ids and fields are checked, and the command stops (exit 2) before printing a line', () => {
  assert.equal(dayOf('2026-11-09'), '9 Nov 2026');
  for (const bad of ['2026-13-01', '2026-00-10', '2026-11-32', '2026-11-00', '10 Nov 2026', '', undefined, '2026-1-10']) assert.throws(() => dayOf(bad), /not a KEV date/, String(bad));
  const ok = { cve: 'CVE-2026-1', vendorProject: 'V', product: 'P', dateAdded: '2026-11-01', dueDate: '2026-11-02' };
  assert.throws(() => kevRows({ id: 'x', kev: [{ ...ok, cve: 'CVE-2026-1' }] }), /needs cve/);
  for (const k of ['cve', 'vendorProject', 'product', 'dateAdded', 'dueDate']) { const r = { ...ok, cve: 'CVE-2026-12345' }; delete r[k]; assert.throws(() => kevRows({ id: 'x', kev: [r] }), undefined, k); }
  assert.throws(() => kevRows({ id: 'x', kev: [] }), /non-empty/);
  assert.throws(() => kevRows({ id: 'x', kev: {} }), /non-empty/);
  // end to end, on a copy of the tool whose SSHole file has a bad date
  const copy = fresh('copy');
  for (const d of ['bin', 'lib', 'package.json']) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
  const f = join(copy, 'lib', 'incidents', 'sshole-2026-11.json');
  writeFileSync(f, readFileSync(f, 'utf8').replace('"dueDate":"2026-11-12"', '"dueDate":"2026-11-31x"').replace('"dueDate": "2026-11-12"', '"dueDate": "2026-11-31x"'));
  assert.match(readFileSync(f, 'utf8'), /2026-11-31x/, 'the control: the copy was broken');
  const r = cli(['--incident', 'gitlab-2026-10', '--no-containers'], join(copy, 'bin', 'wardlatch.mjs'));
  assert.equal(r.code, 2, r.out + r.err);
  assert.doesNotMatch(r.out, /GitLab/);
});

test('K6 the snapshot script refuses a feed it did not read whole, and writes nothing', () => {
  const feed = join(fresh('feed'), 'partial.json');
  writeFileSync(feed, JSON.stringify({ catalogVersion: 'x', count: 5, vulnerabilities: [{ cveID: 'CVE-2026-111497' }] }));
  const before = readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json'), 'utf8');
  const { NODE_OPTIONS, ...env } = process.env;
  const r = spawnSync(process.execPath, [join(ROOT, 'scripts', 'kev-snapshot.mjs'), feed], { encoding: 'utf8', env });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /not a whole catalog, nothing written/);
  assert.equal(readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'kev-snapshot.json'), 'utf8'), before);
});
