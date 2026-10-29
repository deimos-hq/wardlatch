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
