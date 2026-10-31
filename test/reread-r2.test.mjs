// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The three independent re-reads of fix/false-safes at 03d95c9 (31 Oct 2026) all said NOT READY. Each test here stands
// in front of one of their lib and bin findings, or of the escaper finding of the same day's red-team pass (W1), is
// named after it, and failed at 03d95c9 for the reason its name gives (or, for a test that could not fail there, fails
// on the mutant named in its comment). Offline: no test reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let dir;
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-reread-r2-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

// ---- the eMudhra fix text named the 28 Sep releases as the newest ------------------------------------------------------
// The macOS curl fix said no macOS release had updated /etc/ssl/cert.pem, "the newest, 27.0.1, 26.7.1 and 15.8.1,
// shipped on 28 Sep 2026". macOS 27.2, 26.7.2 and 15.8.2 shipped on 26 Oct 2026. MEASURED on 27.2 (build 26B123), 31 Oct
// 2026: its /etc/ssl/cert.pem holds 128 certificates, both withdrawn roots among them, byte-identical to
// test/support/fixtures/macos-27.2-cert.pem, so the sentence's claim still holds and only its "newest" was stale. Apple's
// page on the incident (support.apple.com/en-us/149555, published 29 Oct 2026) names no version; it says the file will be
// updated in a future macOS update.
test('the eMudhra macOS fix names the releases of 26 Oct 2026 as the newest, not those of 28 Sep', () => {
  const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
  const text = inc.fixes['curl:/usr/bin/curl:darwin'];
  assert.doesNotMatch(text, /27\.0\.1|26\.7\.1|15\.8\.1|28 Sep/, text);
  assert.match(text, /27\.2, 26\.7\.2 and 15\.8\.2, shipped on 26 Oct 2026/, text);
  assert.match(text, /future macOS update/, 'what Apple says of the file, as Apple says it');
});
