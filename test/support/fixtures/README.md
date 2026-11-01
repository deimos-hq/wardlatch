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
entry 12478656984. The 12 fingerprints are the 12 Apple lists in HT149555, compared as raw bytes rather than
through a summariser. Each key value in `lib/incidents/emudhra-2026-10.json`'s `withdrawnKeys` was re-derived from
these certificates twice, with LibreSSL 3.3.6 and with OpenSSL 4.0.3.

sha256 `489d8e0e1632412a960cbf126e1f54f9aa287c6e40d4be6250cc2f3b3ec7525c`, 14 certificates.
