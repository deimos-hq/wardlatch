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
const TYPES = ['sshd', 'trust', 'binaries', 'workflows', 'secrets', 'wordpress', 'installs', 'headers'];
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
          if (f.nameAlone !== 'EXPOSED') assert.ok(i.reviewFix, `${i.id}: reviewFix for ${f.name}`);
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

// ---- round 5: the seven other withdrawn keys (decision #38, and the compromised intermediates) -------------------
// The eMudhra incident is a compromise of eight CA keys, six of them TLS, in 12 certificates. Removing the two
// withdrawn ROOTS clears them only for a reader that insists on a chain ending at a self-signed root in the file;
// /usr/bin/curl, Apple's git and the built-in perl take every CA certificate in a --cacert file as a trust anchor, so
// one of those intermediates left in a bundle keeps trusting everything it issued, and the Mac fix said SAFE, exit 0
// (measured 1 Nov 2026 on edc4d71, for all 14 certificates). "emSign Root TLS CA - G3", which issued six of the 12,
// also exists as a SELF-SIGNED certificate, a full anchor for every reader; the owner's decision #38 was to add it.
// These tests stand in front of that gap: they fail on edc4d71, where neither the data nor the fix's list existed.
test('eMudhra: the seven other withdrawn keys are the keys their certificates hold, derived from the certificates', async () => {
  const { createHash } = await import('node:crypto');
  const ROOT = join(DIR, '..', '..');
  const inc = incidents.find((i) => i.id === 'emudhra-2026-10');
  const pem = readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'emudhra-2026-10-compromised-keys.pem'), 'utf8');
  const certs = (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((p) => new X509Certificate(p));
  assert.equal(certs.length, 14, 'the fixture holds the 12 intermediates and both emSign Root TLS CA - G3 certificates');
  assert.ok(Array.isArray(inc.withdrawnKeys) && inc.withdrawnKeys.length === 7, 'seven keys');
  // The SHA-256 of no input at all. A key hash that comes out as this one means nothing was hashed, and a check that
  // accepted it would be a check that measured nothing.
  const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const seen = new Set();
  for (const k of inc.withdrawnKeys) {
    assert.match(k.spkiSha256, /^[0-9a-f]{64}$/, k.name);
    assert.notEqual(k.spkiSha256, EMPTY, `${k.name}: the hash of no input`);
    assert.match(k.ecX, /^[0-9a-f]{96}$/, `${k.name}: the X coordinate is 48 bytes of lowercase hex`);
    assert.ok(Array.isArray(k.certificates) && k.certificates.length === 2, `${k.name}: two certificates carry this key`);
    // Every certificate the entry names is in the fixture and carries this key -- hashed here by node's own crypto,
    // a second derivation of the values the commit derived with LibreSSL 3.3.6 and OpenSSL 4.0.3.
    for (const fp of k.certificates) {
      const c = certs.find((x) => x.fingerprint256 === fp);
      assert.ok(c, `${k.name}: no certificate in the fixture has fingerprint ${fp}`);
      const spki = createHash('sha256').update(c.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
      assert.equal(spki, k.spkiSha256, `${k.name}: ${fp} carries another key`);
      // The X coordinate, from the key's own JWK, independently of how openssl prints it.
      const x = Buffer.from(c.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
      assert.equal(x, k.ecX, `${k.name}: ${fp}'s X coordinate`);
      assert.ok(!seen.has(fp), `${fp} is named by two entries`);
      seen.add(fp);
    }
  }
  // Every certificate in the fixture is covered, and no entry is there for nothing: the completeness gate. Without
  // it, six of the seven entries could be missing and every assertion above would still pass.
  assert.equal(seen.size, 14, 'the seven keys cover all 14 certificates');
  assert.equal(new Set(inc.withdrawnKeys.map((k) => k.spkiSha256)).size, 7, 'the seven keys are distinct');
  // They are keys, not the two withdrawn roots: distrustedRoots drives the probe's forced-roots control and has one
  // PEM file and one canary group per entry, so the two lists must not overlap.
  for (const k of inc.withdrawnKeys) {
    assert.ok(!inc.distrustedRoots.some((r) => r.spkiSha256 === k.spkiSha256), `${k.name} is also in distrustedRoots`);
  }
});

test('eMudhra: the Mac fix matches exactly the seven keys the incident file names, in the same order', () => {
  const ROOT = join(DIR, '..', '..');
  const inc = incidents.find((i) => i.id === 'emudhra-2026-10');
  const fix = readFileSync(join(ROOT, 'fix', 'fix-macos.sh'), 'utf8');
  // The WKEYS array, as the script declares it: one 'name|X coordinate' per line.
  const block = fix.match(/^WKEYS=\(\n([\s\S]*?)^\)$/m);
  assert.ok(block, 'fix/fix-macos.sh declares a WKEYS array');
  const got = [...block[1].matchAll(/^\s*'([^|']+)\|([0-9a-f]{96})'\s*$/gm)].map((m) => ({ name: m[1], ecX: m[2] }));
  assert.equal(got.length, 7, 'seven entries in WKEYS');
  assert.deepEqual(got, inc.withdrawnKeys.map((k) => ({ name: k.name, ecX: k.ecX })),
    "the fix's key list and the incident file have drifted apart");
});

test("eMudhra: the fixture's twelve intermediates are the twelve Apple lists, by a source that is not the fixture", () => {
  // The incident file and the fixture PEM are two copies of ONE reading -- the chains the advisory's 12 test hosts
  // served on 31 Oct 2026 -- so the tests above prove they AGREE, not that the reading was RIGHT. This one checks
  // the fixture against Apple's own published list (emudhra-2026-10-apple-ht149555.tsv, read 1 Nov 2026 from
  // support.apple.com/en-us/149555, which its header records). Nothing is derived from that file: every key value
  // is derived from certificate bytes elsewhere in this suite. Its one job is to disagree if either source is wrong.
  const ROOT = join(DIR, '..', '..');
  const F = join(ROOT, 'test', 'support', 'fixtures');
  const rows = readFileSync(join(F, 'emudhra-2026-10-apple-ht149555.tsv'), 'utf8')
    .split('\n').filter((l) => l.trim() && !l.startsWith('#'))
    .map((l) => { const [sha256, name, issuer] = l.split('\t'); return { sha256, name, issuer }; });
  assert.equal(rows.length, 12, "Apple's list is twelve certificates");
  for (const r of rows) assert.match(r.sha256, /^[0-9A-F]{64}$/, r.name);
  assert.equal(new Set(rows.map((r) => r.sha256)).size, 12, "Apple's twelve are distinct");
  const certs = (readFileSync(join(F, 'emudhra-2026-10-compromised-keys.pem'), 'utf8')
    .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((p) => new X509Certificate(p));
  assert.equal(certs.length, 14);
  const cn = (dn) => dn.split('\n').find((l) => l.startsWith('CN='))?.slice(3);
  const ours = new Map(certs.map((c) => [c.fingerprint256.replaceAll(':', ''), c]));
  // Every one of Apple's twelve is in the fixture, with the same name and the same issuer.
  for (const r of rows) {
    const c = ours.get(r.sha256);
    assert.ok(c, `${r.name}: Apple lists ${r.sha256} and the fixture does not hold it`);
    assert.equal(cn(c.subject), r.name, `${r.sha256}: the name differs from Apple's`);
    assert.equal(cn(c.issuer), r.issuer, `${r.sha256}: the issuer differs from Apple's`);
  }
  // And the fixture holds nothing beyond them but the two emSign Root TLS CA - G3 certificates of decision #38, so
  // a thirteenth certificate smuggled into the fixture would fail here rather than pass as covered.
  const extra = [...ours].filter(([fp]) => !rows.some((r) => r.sha256 === fp));
  assert.equal(extra.length, 2, 'the fixture holds exactly two certificates Apple does not list');
  for (const [fp, c] of extra) assert.equal(cn(c.subject), 'emSign Root TLS CA - G3', `unexpected extra ${fp}`);
  // Six under each issuer, as Apple's page groups them: each intermediate was issued twice.
  for (const issuer of ['emSign Root TLS CA - G3', 'AAA Certificate Services']) {
    assert.equal(rows.filter((r) => r.issuer === issuer).length, 6, `six under ${issuer}`);
  }
});

test('eMudhra: none of the seven keys is in the macOS bundle Apple ships, so refusing them costs that file nothing', async () => {
  const { createHash } = await import('node:crypto');
  const ROOT = join(DIR, '..', '..');
  const inc = incidents.find((i) => i.id === 'emudhra-2026-10');
  const apple = readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'macos-27.2-cert.pem'), 'utf8');
  const certs = (apple.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((p) => new X509Certificate(p));
  // The scan has to be complete before "absent" means anything: 128 certificates in, 128 keys hashed out.
  assert.equal(certs.length, 128, 'the vendored macOS bundle holds 128 certificates');
  const keys = certs.map((c) => createHash('sha256').update(c.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'));
  assert.equal(keys.filter((h) => /^[0-9a-f]{64}$/.test(h)).length, 128, "every certificate's key was hashed");
  for (const k of inc.withdrawnKeys) assert.ok(!keys.includes(k.spkiSha256), `${k.name} is in Apple's own bundle`);
  // The positive control for the scan: the two withdrawn roots ARE in it, and this same scan finds them. Without
  // this, a scan that read nothing would report every key absent.
  for (const r of inc.distrustedRoots) assert.ok(keys.includes(r.spkiSha256), `${r.name} was not found in Apple's bundle`);
});
