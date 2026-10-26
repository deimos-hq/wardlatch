// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The incident files are data the checks trust, so they are checked like code: the shape each check reads, https
// sources only, the bundled roots are exactly the advisory's roots, and the fix commands people copy are safe to run.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib', 'incidents');
const incidents = readdirSync(DIR).filter((f) => f.endsWith('.json')).map((f) => ({ file: f, ...JSON.parse(readFileSync(join(DIR, f), 'utf8')) }));
const TYPES = ['trust', 'binaries', 'workflows', 'secrets', 'wordpress', 'installs', 'headers'];
const https = (u) => typeof u === 'string' && new URL(u).protocol === 'https:';
// the start of a date window: an explicit instant in UTC, to the second (lib/workflows.mjs windowStart reads only this)
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

test('every incident has the fields its check reads, named after its file', () => {
  assert.ok(incidents.length >= 6);
  for (const i of incidents) {
    assert.equal(`${i.id}.json`, i.file);
    assert.ok(TYPES.includes(i.type), `${i.id}: type ${i.type}`);
    assert.match(i.date, /^\d{4}-\d{2}-\d{2}$/); assert.ok(i.title && i.summary, i.id);
    assert.ok(https(i.advisory), `${i.id}: the source is an https URL`);
    for (const b of i.binaries ?? []) assert.ok(b.binary && b.fix && (b.bad || b.fixedIn || b.pendingUntil || (b.noExec && b.md5Bad?.length)), `${i.id}: ${b.binary}`);
    if (i.type === 'workflows') assert.ok(INSTANT.test(i.since) && i.fix, `${i.id}: since`);
    if (i.type === 'secrets') assert.ok(i.fix);
    if (i.type === 'installs') {
      assert.ok(i.versionFiles || i.sitePackages || i.dockerDigests, `${i.id}: something to check`);
      assert.ok(i.safeText, `${i.id}: safeText`);
      if (i.versionFiles) {
        const v = i.versionFiles; assert.ok(v.product && v.fix && v.lookedIn && (v.fixedIn || v.bad || v.minVersion) && v.files.length, `${i.id}: versionFiles`);
        for (const f of v.files) { assert.match(f.path, /^(\/|~\/)/); assert.ok(new RegExp(f.re).source.includes('('), `${i.id}: ${f.path} re captures`); if (f.reviewWhenFixed) assert.ok(i.reviewFix, `${i.id}: reviewFix for ${f.path}`); }
      }
      if (i.sitePackages) {
        assert.ok(i.sitePackages.fix);
        for (const f of i.sitePackages.iocFiles ?? []) {
          assert.ok(f.name && !f.name.includes('/') && [].concat(f.sha256).every((h) => /^[0-9a-f]{64}$/.test(h)), `${i.id}: ${f.name}`);
          assert.ok([undefined, 'EXPOSED'].includes(f.nameAlone), `${i.id}: ${f.name} nameAlone`);
          // a review line needs its own advice: the EXPOSED fix ("rotate every credential") is wrong for a legitimate file
          if (f.nameAlone !== 'EXPOSED' && f.reviewIfOther !== false) assert.ok(i.reviewFix, `${i.id}: reviewFix for ${f.name}`);
        }
      }
      if (i.tmpTrace) new RegExp(i.tmpTrace);
      for (const d of i.dockerDigests ?? []) assert.match(d, /^sha256:[0-9a-f]{64}$/);
      if (i.dockerDigests) assert.ok(i.dockerFix);
      for (const d of i.dockerDigestPrefixes ?? []) assert.match(d, /^sha256:[0-9a-f]{12,64}$/);
      for (const t of i.dockerTags ?? []) assert.match(t, /^[a-z0-9./_-]+:[A-Za-z0-9._-]+$/);
      if (i.dockerDigestPrefixes || i.dockerTags) assert.ok(i.dockerFix);
    }
    if (i.type === 'headers') assert.ok(i.fix && i.notCovered);
    if (i.type === 'wordpress') { assert.ok(INSTANT.test(i.addedSince) && i.reviewFix, `${i.id}: addedSince`); for (const r of i.rules) assert.ok(r.plugin && r.mainFile && r.fix); }
  }
  assert.equal(new Set(incidents.map((i) => i.id)).size, incidents.length, 'ids are unique');
});

test('every date window starts at an explicit UTC instant that exists, never a bare date', () => {
  // 0.1.0 to 0.1.9 gave the workflow review "2026-09-01", which git read as 1 Sep at the run's time of day in the zone
  // git ran in (up to 0.1.8 that of the TZ Wardlatch was started with, which git got too, the machine's when it was
  // unset; in 0.1.9, which gave git no TZ, the machine's), and a workflow committed on 31 Aug read SAFE. Any field
  // naming a window's start (since, addedSince, at any depth) is a full instant in UTC.
  const starts = (o, at) => (o && typeof o === 'object' ? Object.entries(o).flatMap(([k, v]) => (/since$/i.test(k) ? [[`${at}.${k}`, v]] : starts(v, `${at}.${k}`))) : []);
  const found = incidents.flatMap((i) => starts(i, i.id));
  assert.ok(found.some(([k]) => k === 'github-actions-2026-10.since') && found.some(([k]) => k === 'wordpress-plugins-2026-10.addedSince'), JSON.stringify(found));
  for (const [k, v] of found) {
    assert.match(String(v), INSTANT, k);
    assert.equal(new Date(Date.parse(v)).toISOString(), v.replace('Z', '.000Z'), `${k}: a day and time that exist`);
  }
  // the pattern itself refuses what git or Date.parse would read in a zone, or at the time of day
  for (const bad of ['2026-09-01', '2026-08-30 00:00:00', '2026-08-30T00:00:00', '2026-08-30T00:00:00+00:00', '2026-08-30T00:00Z', '2026-08-30T00:00:00.000Z']) assert.doesNotMatch(bad, INSTANT, bad);
});

test('the trust incident: unique test hosts, and the bundled roots are exactly the advisory\'s roots', () => {
  for (const i of incidents.filter((x) => x.type === 'trust')) {
    assert.ok(i.canaryHost.includes('{id}'));
    assert.equal(new Set(i.canaries).size, i.canaries.length);
    for (const id of i.canaries) assert.match(id, /^[a-z0-9-]+$/);
    // The positive control forces these roots in, so they must be the ones the advisory names, by fingerprint.
    const pems = readFileSync(join(DIR, i.rootsPem), 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    assert.deepEqual(pems.map((p) => new X509Certificate(p).fingerprint256).sort(), i.distrustedRoots.map((r) => r.sha256).sort());
    // each root's own file (its group's forced-roots control) holds exactly that root, named after the group
    const own = (i.canaryRoots ?? []).map((g) => {
      const list = readFileSync(join(DIR, g.pem), 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
      assert.equal(list.length, 1, g.pem);
      const x = new X509Certificate(list[0]);
      assert.match(x.subject, new RegExp(`^CN=${g.root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'), g.pem);
      return x.fingerprint256;
    });
    assert.deepEqual(own.sort(), i.distrustedRoots.map((r) => r.sha256).sort(), 'one file per distrusted root');
  }
});

test('regression: the copyable macOS fix runs awk with sudo, so a root-only backup cannot leave cert.pem empty', () => {
  // 0.1.2 fixed this (advisory issue #35): with a plain awk, reading a root-only backup fails, and `sudo tee` has
  // already emptied /etc/ssl/cert.pem by then.
  const texts = incidents.flatMap((i) => Object.values(i.fixes ?? {})).filter((t) => t.includes('tee /etc/ssl/cert.pem'));
  assert.ok(texts.length >= 1);
  for (const t of texts) {
    assert.match(t, /sudo cp \/etc\/ssl\/cert\.pem \/etc\/ssl\/cert\.pem\.bak && sudo awk /, 'back up first, then read the backup as root');
    assert.doesNotMatch(t, /(?<!sudo) awk '/, 'no awk without sudo');
  }
});
