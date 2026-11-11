// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.17: the eight RSA CAs eMudhra revoked on 7 Nov 2026 (EM DV/OV/EV TLS CA - G2B/G2C, EM OV CS CA - G2B/G2C;
// cessationOfOperation; Mozilla bug 2083449, comment 82, Appendix C), the two CAs that issued them, emSign Root CA - G1
// above the six TLS ones, and the two October code-signing CAs 0.1.16 left out (EM OV CS CA - G3B and G3C, Appendices A
// and B). The owner's decision of 11 Nov 2026: REVIEW, never EXPOSED, and no word says their keys were "compromised".
// Every check here is shown able to give the other answer: each new fingerprint is found (a positive control per
// certificate), Apple's 27.2.1 file is found clean (the negative control), and Apple's 27.2 file, which ships G1, is
// not. Nothing connects; no real /etc/ssl is read.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate, createHash } from 'node:crypto';
import { bundleHolds, reviewHolds, backupRows, certPemReviewRow, appleNote } from '../lib/macos.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FX = join(ROOT, 'test', 'support', 'fixtures');
const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const G2 = readFileSync(join(FX, 'emudhra-2026-11-g2-cas.pem'), 'utf8');
const APPLE_2721 = readFileSync(join(FX, 'macos-27.2.1-cert.pem'), 'utf8');        // no eMudhra root at all
const APPLE_272 = readFileSync(join(FX, 'macos-27.2-cert.pem'), 'utf8');            // Apple's 27.2 file: G1 is in it
const HANDFIXED = readFileSync(join(FX, 'macos-27.2-handfixed-cert.pem'), 'utf8');  // the Mac fix's work: G1 still in it
const OCTOBER = readFileSync(join(FX, 'emudhra-2026-10-compromised-keys.pem'), 'utf8');
const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const certs = (G2.match(PEM) ?? []).map((p) => ({ pem: p, x: new X509Certificate(p) }));
const spkiOf = (x) => createHash('sha256').update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const cn = (dn) => dn.split('\n').find((l) => l.startsWith('CN='))?.slice(3);
const hex = (fp) => fp.replaceAll(':', '');
const RSA = inc.reviewKeys.filter((k) => k.group === 'emudhra-2026-11-rsa');
const CS3 = inc.reviewKeys.filter((k) => k.group === 'emudhra-2026-10-code-signing');
const EIGHT = ['EM DV TLS CA - G2B', 'EM DV TLS CA - G2C', 'EM OV TLS CA - G2B', 'EM OV TLS CA - G2C', 'EM EV TLS CA - G2B', 'EM EV TLS CA - G2C', 'EM OV CS CA - G2B', 'EM OV CS CA - G2C'];
const tsv = readFileSync(join(FX, 'emudhra-2026-11-bug2083449-c82.tsv'), 'utf8').split('\n').filter((l) => l.trim() && !l.startsWith('#'))
  .map((l) => { const [appendix, sha256, name, issuer, serial] = l.split('\t'); return { appendix, sha256, name, issuer, serial }; });

test('E1 the eleven RSA-group keys are the keys their certificates hold, derived here from the certificates; the scan is complete', () => {
  assert.equal(certs.length, 13, 'the fixture holds the 8 RSA CAs, both emSign Root TLS CA - G1 and both emSign Root CS CA - G2 certificates, and emSign Root CA - G1');
  assert.equal(RSA.length, 11, 'eleven RSA-group entries');
  assert.equal(CS3.length, 2, 'two October code-signing entries');
  assert.equal(inc.reviewKeys.length, 13, 'and nothing else');
  assert.deepEqual(RSA.slice(0, 8).map((k) => k.name), EIGHT);
  const seen = new Set();
  for (const k of RSA) {
    assert.match(k.spkiSha256, /^[0-9a-f]{64}$/, k.name);
    assert.notEqual(k.spkiSha256, EMPTY, `${k.name}: the hash of no input`);
    assert.ok(k.certificates.length >= 1, k.name);
    for (const fp of k.certificates) {
      const c = certs.find((y) => y.x.fingerprint256 === fp);
      assert.ok(c, `${k.name}: no certificate in the fixture has fingerprint ${fp}`);
      assert.equal(spkiOf(c.x), k.spkiSha256, `${k.name}: ${fp} carries another key`);
      assert.equal(cn(c.x.subject), k.name, `${fp}: subject`);
      if (k.issuer) assert.equal(cn(c.x.issuer), k.issuer, `${fp}: issuer`);
      if (k.serial) assert.equal(c.x.serialNumber, k.serial, `${fp}: serial`);
      assert.ok(!seen.has(fp), `${fp} named twice`); seen.add(fp);
    }
  }
  // the completeness gate: every certificate in the fixture is covered by an entry, and no entry is there for nothing
  assert.equal(seen.size, 13, 'the eleven keys cover all 13 certificates');
  assert.equal(new Set(RSA.map((k) => k.spkiSha256)).size, 11, 'eleven distinct keys');
  // the two copies of each issuing CA carry one key (a cross-sign and a self-signed certificate)
  for (const n of ['emSign Root TLS CA - G1', 'emSign Root CS CA - G2']) assert.equal(RSA.find((k) => k.name === n).certificates.length, 2, n);
  // none is an October root or key: those lists decide EXPOSED, and these must never reach them
  const october = new Set([...inc.distrustedRoots, ...inc.withdrawnKeys].map((k) => k.spkiSha256));
  for (const k of RSA) assert.ok(!october.has(k.spkiSha256), `${k.name} is also an October key`);
  // the anchor: the same certificate Apple names among the roots its update removes, byte for byte the one in Apple's 27.2 file
  const g1 = RSA.find((k) => k.name === 'emSign Root CA - G1');
  assert.deepEqual(g1.certificates, [inc.appleFix.alsoRemoved.find((r) => r.name === 'emSign Root CA - G1').sha256]);
  const g1pem = certs.find((c) => c.x.fingerprint256 === g1.certificates[0]).pem;
  assert.ok((APPLE_272.match(PEM) ?? []).includes(g1pem), "the fixture's G1 is the copy in Apple's 27.2 file");
  assert.equal(Buffer.from(new X509Certificate(g1pem).publicKey.export({ format: 'jwk' }).n, 'base64url').subarray(0, 48).toString('hex'), g1.rsaN48);
  assert.equal(g1.distrustAfter.mozilla, '2026-11-16T23:59:59Z'); assert.equal(g1.distrustAfter.chrome, '2026-11-16T23:59:59Z');
  // the eight are RSA-4096, valid 30 Apr 2025 to 28 Apr 2040, each with its revocation from the CRL
  for (const k of RSA.slice(0, 8)) {
    const c = certs.find((y) => y.x.fingerprint256 === k.certificates[0]).x;
    assert.equal(c.publicKey.asymmetricKeyDetails.modulusLength, 4096, k.name);
    assert.match(c.validFrom, /Apr 30 .* 2025 GMT/, k.name); assert.match(c.validTo, /Apr 28 .* 2040 GMT/, k.name);
    assert.match(k.revoked, /^2026-11-07T09:\d\d:\d\dZ$/, k.name);
    assert.equal(k.revocationReason, 'cessationOfOperation', k.name);
    assert.equal(k.eku, / CS CA /.test(k.name) ? 'codeSigning' : 'serverAuth, clientAuth', k.name);
  }
});

test("E2 the fixture and the record against eMudhra's own list (comment 82), a source that is neither of them", () => {
  const c = tsv.filter((r) => r.appendix === 'C');
  assert.equal(c.length, 8, 'Appendix C lists eight');
  assert.equal(new Set(c.map((r) => r.sha256)).size, 8);
  const ours = new Map(certs.map((y) => [hex(y.x.fingerprint256), y.x]));
  for (const r of c) {
    const x = ours.get(r.sha256);
    assert.ok(x, `${r.name}: eMudhra lists ${r.sha256} and the fixture does not hold it`);
    assert.equal(cn(x.subject), r.name); assert.equal(cn(x.issuer), r.issuer); assert.equal(x.serialNumber, r.serial.toUpperCase());
    assert.deepEqual(RSA.find((k) => k.name === r.name).certificates.map(hex), [r.sha256], r.name);
  }
  // the fixture holds exactly five certificates eMudhra's list doesn't: the two issuing CAs' four, and G1
  const extra = [...ours].filter(([fp]) => !c.some((r) => r.sha256 === fp)).map(([, x]) => cn(x.subject)).sort();
  assert.deepEqual(extra, ['emSign Root CA - G1', 'emSign Root CS CA - G2', 'emSign Root CS CA - G2', 'emSign Root TLS CA - G1', 'emSign Root TLS CA - G1']);
  // the October code-signing CAs: the record's four fingerprints are Appendix A's and B's, and they are not in the October fixture
  for (const k of CS3) {
    const rows = tsv.filter((r) => r.name === k.name && r.appendix !== 'C');
    assert.deepEqual(rows.map((r) => r.appendix), ['A', 'B'], k.name);
    assert.deepEqual(k.certificates.map(hex), rows.map((r) => r.sha256), k.name);
    assert.deepEqual(k.serials, rows.map((r) => r.serial), k.name);
    assert.equal(k.spkiSha256, undefined, `${k.name}: no key is claimed without the certificate's bytes`);
    for (const fp of k.certificates) assert.ok(!(OCTOBER.match(PEM) ?? []).some((p) => new X509Certificate(p).fingerprint256 === fp), `${fp} is already in the October fixture`);
  }
});

test('E3 positive controls: every new certificate, added alone to Apple\'s clean 27.2.1 file, is found under its own name, and never as an October key', () => {
  const want = new Map(RSA.flatMap((k) => k.certificates.map((fp) => [fp, k.name])));
  for (const c of certs) {
    const name = want.get(c.x.fingerprint256);
    const r = reviewHolds(`${APPLE_2721}\n${c.pem}\n`, inc);
    assert.deepEqual(r, { held: [name], read: 124, unreadable: 0 }, `${name} (${c.x.fingerprint256})`);
    // alone, and with a misleading name line above it: the match is by key
    assert.deepEqual(reviewHolds(`=== /CN=Harmless Root\n${c.pem}\n`, inc).held, [name]);
    // the EXPOSED reading does not see it: these are REVIEW only
    assert.deepEqual(bundleHolds(`${APPLE_2721}\n${c.pem}\n`, inc).held, [], `${name} reached bundleHolds`);
  }
  // all of them at once: every name, in the record's order
  assert.deepEqual(reviewHolds(`${APPLE_2721}\n${G2}`, inc).held, RSA.map((k) => k.name));
  // the October code-signing CAs are matched by fingerprint: their certificates are not here, so the matcher's
  // fingerprint path is shown with a record that names a certificate that IS here by fingerprint only, and the same
  // record with one digit changed finds nothing
  const dv = certs[1];
  const byFp = (fp) => ({ ...inc, reviewKeys: [{ name: 'by fingerprint', group: 'emudhra-2026-10-code-signing', certificates: [fp] }] });
  assert.deepEqual(reviewHolds(`${APPLE_2721}\n${dv.pem}\n`, byFp(dv.x.fingerprint256)).held, ['by fingerprint']);
  const other = dv.x.fingerprint256.replace(/^(.)/, (d) => (d === '0' ? '1' : '0'));
  assert.deepEqual(reviewHolds(`${APPLE_2721}\n${dv.pem}\n`, byFp(other)).held, []);
});

test('E4 the negative control and the instrument: Apple\'s 27.2.1 file is clean, and the same scan finds G1 in the files that hold it', () => {
  assert.deepEqual(reviewHolds(APPLE_2721, inc), { held: [], read: 123, unreadable: 0 });
  // the instrument can give the other answer: Apple's 27.2 file and the Mac fix's own cleaned file both hold G1
  assert.deepEqual(reviewHolds(APPLE_272, inc), { held: ['emSign Root CA - G1'], read: 128, unreadable: 0 });
  assert.deepEqual(reviewHolds(HANDFIXED, inc), { held: ['emSign Root CA - G1'], read: 126, unreadable: 0 });
  // and the October file: none of the new keys is in it
  assert.deepEqual(reviewHolds(OCTOBER, inc).held, []);
  // unreadable blocks are counted, never skipped
  const r = reviewHolds(`${APPLE_2721}\n-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n`, inc);
  assert.deepEqual(r, { held: [], read: 123, unreadable: 2 });
  // no record of these keys, no reading
  assert.equal(reviewHolds(APPLE_272, { ...inc, reviewKeys: undefined }), null);
});

test('E5 a copy of cert.pem holding only G1 is a REVIEW row on a release Apple names (0.1.16 gave none); October rows are unchanged', () => {
  const rows = backupRows(inc, '27.2.1', [
    { file: '/etc/ssl/cert.pem.wardlatch-20261102-124354.bak', text: HANDFIXED },
    { file: '/etc/ssl/cert.pem.bak', text: APPLE_272 },
    { file: '/etc/ssl/cert.pem.bak.1', text: APPLE_2721 },
  ]);
  assert.deepEqual(rows.map((x) => [x.file, x.status, x.heldRoots ?? null, x.reviewHeld ?? null]), [
    ['/etc/ssl/cert.pem.wardlatch-20261102-124354.bak', 'REVIEW', null, ['emSign Root CA - G1']],
    ['/etc/ssl/cert.pem.bak', 'REVIEW', ['AAA Certificate Services (Comodo, via the Sectigo cross-sign)', 'emSign ECC Root CA - G3'], null],
  ]);
  const [g1] = rows;
  assert.match(g1.reason, /^\/etc\/ssl\/cert\.pem\.wardlatch-20261102-124354\.bak \(the Mac fix's own backup\) is a copy of cert\.pem that holds none of the October withdrawn roots or keys, but holds emSign Root CA - G1\. emSign Root CA - G1: one of the eight CAs eMudhra revoked on 7 Nov 2026 \(cessationOfOperation\), or a CA or root above them, matched by key\./);
  assert.match(g1.reason, /cannot demonstrate that those CAs' keys stayed inside the HSM \(Mozilla bug 2083449, comment 82\)/);
  assert.match(g1.reason, /Apple's update removes emSign Root CA - G1 from cert\.pem \(https:\/\/support\.apple\.com\/en-us\/149555\), so don't restore this copy over it/);
  assert.match(g1.reason, /Wardlatch read it and changed nothing\.$/);
  // before Apple's release the backups are the undo: nothing is said of them, as before
  assert.deepEqual(backupRows(inc, '27.2', [{ file: '/etc/ssl/cert.pem.bak', text: HANDFIXED }]), []);
  // a record without reviewKeys (0.1.16's) gives no G1 row: the line comes from the data
  assert.deepEqual(backupRows({ ...inc, reviewKeys: undefined }, '27.2.1', [{ file: '/etc/ssl/cert.pem.bak', text: HANDFIXED }]), []);
});

test('E6 /etc/ssl/cert.pem itself: a REVIEW row whenever it holds a new key, its advice following the release; none for a clean or unread file', () => {
  const row = (v, t = APPLE_272) => certPemReviewRow(inc, v, t);
  const fixed = row('27.2.1');
  assert.deepEqual([fixed.kind, fixed.status, fixed.file, fixed.reviewHeld], ['cert-pem', 'REVIEW', '/etc/ssl/cert.pem', ['emSign Root CA - G1']]);
  assert.match(fixed.reason, /^\/etc\/ssl\/cert\.pem, the file macOS's built-in curl, git, python3 and openssl read, holds emSign Root CA - G1\. /);
  assert.match(fixed.reason, /this Mac runs 27\.2\.1: this is not the file Apple says the update installs/);
  assert.match(fixed.reason, /This is a line to review, not a finding of exposure\. Wardlatch read it and changed nothing\.$/);
  assert.match(row('27.2').reason, /Apple says updating to macOS 27\.2\.1 removes emSign Root CA - G1 from this file/);
  assert.match(row('26.7.2').reason, /Apple says updating to macOS 26\.7\.3 removes/);
  assert.match(row('14.7.1').reason, /names no update for macOS 14\. Wardlatch's Mac fix removes only the October roots and keys, not this one\./);
  assert.match(row('').reason, /Apple says macOS 27\.2\.1, 26\.7\.3 and 15\.8\.3 remove emSign Root CA - G1 from this file/);
  // negative controls: Apple's 27.2.1 file, an unread file, no record
  assert.equal(row('27.2.1', APPLE_2721), null);
  assert.equal(row('27.2.1', null), null);
  assert.equal(certPemReviewRow({ ...inc, rsaRevocation: undefined }, '27.2.1', APPLE_272), null);
  // a revoked TLS CA added by hand, without G1: named, with no G1 advice
  const dv = certs.find((c) => cn(c.x.subject) === 'EM DV TLS CA - G2C').pem;
  const ca = row('27.2.1', `${APPLE_2721}\n${dv}\n`);
  assert.deepEqual(ca.reviewHeld, ['EM DV TLS CA - G2C']);
  assert.doesNotMatch(ca.reason, /removes emSign Root CA - G1/);
  // the October code-signing group has its own words (shown with a record naming a certificate that is here)
  const cs = certPemReviewRow({ ...inc, reviewKeys: [...inc.reviewKeys, { name: 'stand-in', group: 'emudhra-2026-10-code-signing', certificates: [new X509Certificate(dv).fingerprint256] }] }, '27.2.1', `${APPLE_2721}\n${dv}\n`);
  assert.match(cs.reason, /stand-in: one of the two October code-signing CAs, whose keys eMudhra says were recoverable/);
  assert.match(cs.reason, /whether a TLS reader trusts a code-signing CA in its CA file was not measured/);
});

test('E7 the words: the RSA CAs are never called compromised, the record says what eMudhra said and where, and REVIEW is the tier', () => {
  const rr = inc.rsaRevocation;
  assert.deepEqual([rr.id, rr.status, rr.revoked, rr.date, rr.revocationReason], ['emudhra-2026-11-rsa', 'REVIEW', '2026-11-07', '2026-11-10', 'cessationOfOperation']);
  assert.ok(rr.sources.includes('https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c82'));
  assert.deepEqual(rr.crls.map((c) => c.thisUpdate), ['2026-11-07T09:43:43Z', '2026-11-07T09:44:31Z']);
  const rsaLine = inc.reviewGroups.find((g) => g.id === 'emudhra-2026-11-rsa').line;
  const texts = [rr.title, rr.summary, rsaLine, ...RSA.flatMap((k) => [k.why ?? '', k.note ?? '']),
    certPemReviewRow(inc, '27.2.1', APPLE_272).reason, certPemReviewRow(inc, '14.7.1', APPLE_272).reason,
    backupRows(inc, '27.2.1', [{ file: '/etc/ssl/cert.pem.bak', text: HANDFIXED }])[0].reason];
  for (const t of texts) assert.doesNotMatch(t, /compromis/i, t.slice(0, 120));
  assert.match(rsaLine, /eMudhra says it cannot demonstrate that those CAs' keys stayed inside the HSM \(Mozilla bug 2083449, comment 82\)/);
  assert.match(rr.summary, /never EXPOSED/);
  // the October summary now says the eight RSA CAs are a separate matter
  assert.match(inc.summary, /Separately, on 7 Nov 2026 eMudhra revoked eight RSA CAs \(G2B and G2C\) for another reason, and those are REVIEW lines here, not EXPOSED/);
  // and appleNote no longer says G1 changes no result, on any release
  for (const v of ['27.2.1', '27.2', '14.7.1']) {
    const n = appleNote(inc, { version: v, certText: HANDFIXED }).join(' ');
    assert.match(n, /emSign Root CA - G1 is the root above the six RSA TLS CAs eMudhra revoked on 7 Nov 2026: see the REVIEW line for \/etc\/ssl\/cert\.pem\./, v);
    assert.doesNotMatch(n, /G1[^.]*change(s)? no result/, v);
  }
  // what is not covered is said: certifi, Node.js and Linux bundles are not read for these
  assert.match(inc.notCovered, /looked for only in \/etc\/ssl on a Mac \(REVIEW lines\): certifi, Node\.js and Linux bundles still hold emSign Root CA - G1/);
});
