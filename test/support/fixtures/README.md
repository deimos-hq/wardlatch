<!-- SPDX-License-Identifier: Apache-2.0 -->
# Test fixtures

## `macos-27.2-cert.pem`

Apple's shipped `/etc/ssl/cert.pem`, copied from a Mac running macOS 27.2 on 29 October 2026, **before** the
eMudhra fix was applied. 333,483 bytes, 128 certificates,
sha256 `9dae8d76e55cb08991f2b672d58999ea15560d910759c16b544f843bdffbb994`.

**Why it is here.** The harnesses that test the Mac fix used to read `/etc/ssl/cert.pem` live, and
`mojave-shapes.sh` built its "both roots present" case from it. That made the tests require the person running
them to leave their own machine unfixed — a test whose green depends on something other than the thing it
measures, which is the defect class this project spent 29 October removing from its own tools.

**Provenance, and why vendoring it is safe.** This file is a byte-identical copy of OpenBSD
`src/lib/libcrypto/cert.pem` revision **1.22.2.1** (2021-09-30, tag `OPENBSD_6_9`), which is public and
BSD-licensed. Verify for yourself:

    curl -s 'https://cvsweb.openbsd.org/src/lib/libcrypto/cert.pem?rev=1.22.2.1&content-type=text/plain' \
      | shasum -a 256

It should print the same digest. Apple ships this revision verbatim; it tracked OpenBSD's 6.9-stable branch
rather than trunk, so it never received rev 1.23 (11 June 2021), which removed the AC Camerfirma, GeoTrust and
VeriSign Universal roots.

**It contains both withdrawn roots** — `AAA Certificate Services` (`D7:A7:A0:FB…`) and `emSign ECC Root CA - G3`
(`86:A1:EC:BA…`) — on purpose. That is what makes it a usable subject for the fix's tests.

## `emudhra-2026-10-compromised-keys.pem`

The 14 **public** certificates of the eMudhra incident that are not either withdrawn root: the two
`emSign Root TLS CA - G3` certificates (the self-signed one, `7D:D7:8D:5F…`, and the one cross-signed by
`emSign ECC Root CA - G3`, `30:94:02:57…`) and the 12 compromised intermediates. Between them they carry seven
keys — six intermediate keys, each issued twice (once under `emSign Root TLS CA - G3`, once under
`AAA Certificate Services`), and `emSign Root TLS CA - G3`'s own.

**Why it is here.** The cases that show a bundle holding one of these reads EXPOSED, and that the Mac fix removes
it, need the certificates themselves, and they must run offline and in CI. Nothing here is secret: every one is a
CA certificate that was served publicly, and each entry carries its subject, issuer, SHA-256 fingerprint and the
SHA-256 of its SubjectPublicKeyInfo as comment lines above it. No private key is in this repository.

**Provenance.** Read on 31 October 2026 from the chains the advisory's own 12 test hosts serve (one
`openssl s_client -showcerts` each, read-only) and, for the self-signed `emSign Root TLS CA - G3`, from crt.sh
entry 12478656984. The 12 fingerprints are the 12 Apple lists in HT149555: compared on 31 October as raw bytes on
both sides, the certificates the hosts served against the published list, rather than through a summariser; and
compared again on 1 November against Apple's page as it reads today, through
`emudhra-2026-10-apple-ht149555.tsv` below, whose own header says that side came through a summariser.

**Three derivations, and which is which.** Each key value in `lib/incidents/emudhra-2026-10.json`'s `withdrawnKeys`
was derived from these certificates **twice by hand** — LibreSSL 3.3.6 and OpenSSL 4.0.3, independent builds, both
giving `emSign Root TLS CA - G3` a 120-byte SubjectPublicKeyInfo hashing to `c619e478…ac792fe9` for the self-signed
and the cross-signed certificate alike — and a **third time on every run** by `test/incidents.test.mjs`, which uses
node's own `crypto` and takes the X coordinate from the key's JWK rather than from the way `openssl` prints it. So
"twice" is the author's two and "three ways" below counts the test's as well; they are the same seven keys, not two
different claims.

sha256 `489d8e0e1632412a960cbf126e1f54f9aa287c6e40d4be6250cc2f3b3ec7525c`, 14 certificates.

## `emudhra-2026-10-apple-ht149555.tsv`

Apple's own published list of the twelve blocked eMudhra intermediates — fingerprint, name, issuer — with its
source, the page's published date and the date it was read in the file's own header.

**Why it is here.** `lib/incidents/emudhra-2026-10.json`'s `withdrawnKeys` and the PEM above are two copies of *one*
reading: the chains the advisory's twelve test hosts served on 31 October 2026. A test that the two agree therefore
proves only that they agree — the fixture was its own witness. This file is a second source for the same twelve, so
`test/incidents.test.mjs` can check the fixture against something other than itself.

**It is for comparison only.** These values came through a summariser rather than from raw bytes, which is the
weakness INTEL's V58 named, so nothing derives a value from this file. Every key in the incident file is derived
from certificate bytes three ways (LibreSSL 3.3.6, OpenSSL 4.0.3, node's `crypto`). A summariser can drop a row or
mangle a digit; it cannot make a wrong value agree with bytes measured three other ways — and if Apple's list and
our bytes ever disagree in a fingerprint, a name or an issuer, that test says which.

## `macos-27.2-handfixed-cert.pem` and `macos-27.2.1-cert.pem`

`/etc/ssl/cert.pem` on one Mac, copied before and after its update from macOS 27.2 (26B123) to 27.2.1 (26B131) on
10 November 2026, read-only.

- **Before:** sha256 `6bddc1e2bc758979a309b9932ef676f9e166903a27313609bad3a777c0577083`, 328,989 bytes, 126
  certificates: the 27.2 file above with the two withdrawn roots taken out by hand on 2 November (the Mac fix). It
  still held emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3.
- **After:** sha256 `a386d6cea5dc81a00217d48873a56c843511e05c60c203465aab85df34565bd5`, 322,786 bytes, 123
  certificates, dated 5 November 21:22 by Apple's installer: no eMudhra or emSign root at all.

**What it shows, and no more:** on this one Mac, the update replaced a `cert.pem` changed by hand with Apple's new
file. Other Macs, and the 26.7.3 and 15.8.3 updates, were not measured. The two backups in `/etc/ssl` on that Mac
(`cert.pem.bak`, 27 October, and `cert.pem.wardlatch-20261102-124354.bak`) were left in place and are both
byte-identical to `macos-27.2-cert.pem` above, so the tests use that file for them. The built-in tools kept their
versions (curl 8.7.1, LibreSSL 3.3.6, Python 3.9.6, git 2.54.0 Apple Git-157). Public root certificates only, kept
byte for byte (they are listed in `test/conventions.test.mjs`'s VERBATIM).
