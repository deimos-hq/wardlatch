// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026. The receipt rule (lib/report.mjs) is the one thing standing between an UNKNOWN and a
// SAFE, and it tests only that `searched` is a non-empty list of non-blank strings. It cannot tell what was opened from
// what someone believes is there, so these receipts get past it:
//   - a hand-written English sentence (`versionFiles.lookedIn`, pushed into the receipt at bin/wardlatch.mjs:376),
//     naming folders that are not on this machine and were never opened;
//   - a receipt that covers less than its own row's reason claims (lib/binaries.mjs:184 with the OVHcloud note);
//   - and no all-clear names the --paths folder the person asked about, so a reader cannot tell it was searched.
// These tests fail on 0.1.10.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBinaryAll } from '../lib/binaries.mjs';
import { hasReceipt, safe, withdrawUnreceipted } from '../lib/report.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-rcpt-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-audit-rcpt-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
const rows = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, '--json', ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
  assert.ok(r.stdout, `no output (exit ${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout).results;
};

test('AUDIT-10 an all-clear\'s receipt can be a sentence about folders that are not on this machine', () => {
  const empty = join(dir, 'empty-10'); mkdirSync(empty, { recursive: true });
  // the incidents' own words, pushed into the receipt whatever expand() found
  assert.equal(incident('gitlab-2026-10').versionFiles.lookedIn, 'GitLab\'s version files under /opt/gitlab and /home/git/gitlab');
  // identity-headers is the clearest of the three: "0 header settings found in 0 files", receipt ["the environment"]
  for (const id of ['identity-headers-2026-10', 'gitlab-2026-10', 'plex-2026-10']) {
    const safeRows = rows(['--incident', id, '--no-containers', '--paths', empty]).filter((r) => r.status === 'SAFE');
    assert.ok(safeRows.length, `${id}: expected an all-clear on a machine without it`);
    for (const r of safeRows) for (const entry of r.searched) {
      // a receipt says what was LOOKED AT: each entry names one thing that was opened, so it is a path that is there
      assert.ok(isAbsolute(String(entry)) && existsSync(String(entry)),
        `${id}: the receipt entry ${JSON.stringify(entry)} is not a place that was opened, so the SAFE above it rests on nothing: ${JSON.stringify(r.searched)}`);
    }
  }
});

test('AUDIT-11 no all-clear names the --paths folder the person asked about, so a reader cannot tell it was searched', () => {
  const asked = join(dir, 'asked-11');
  mkdirSync(join(asked, 'project'), { recursive: true });
  for (const id of ['litellm-2026-10', 'gitlab-2026-10', 'plex-2026-10']) {
    const safeRows = rows(['--incident', id, '--no-containers', '--paths', asked]).filter((r) => r.status === 'SAFE');
    assert.ok(safeRows.length, `${id}: expected an all-clear`);
    assert.ok(safeRows.some((r) => r.searched.some((s) => String(s).includes(asked))),
      `${id}: the folder given with --paths (${asked}) is nowhere in the all-clear's receipt: ${JSON.stringify(safeRows.map((r) => r.searched))}`);
  }
});

test('AUDIT-12 a SAFE row\'s reason claims more than its receipt covers: the OVHcloud row says the temp folders are clean and names only the program', () => {
  const bin = join(dir, 'ovh-12'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'ovhcloud'), 'a clean build, never run\n', { mode: 0o755 });
  for (const t of ['temp-12-a', 'temp-12-b']) mkdirSync(join(dir, t), { recursive: true });
  const rule = incident('ovhcloud-cli-2026-10').binaries[0];
  const out = checkBinaryAll(rule, bin, { tmpDirs: [join(dir, 'temp-12-a'), join(dir, 'temp-12-b')] });
  const row = out.find((r) => r.status === 'SAFE');
  assert.ok(row, `expected a SAFE row: ${JSON.stringify(out)}`);
  assert.match(row.reason, /temp directories/, 'premise: the reason claims the temp folders were looked at');
  // the claim covers two things; the receipt covers one. The CLI's own all-clear for a MISSING ovhcloud does list
  // tempDirs() (bin/wardlatch.mjs:350), so the tool is inconsistent with itself.
  assert.ok(row.searched.some((s) => String(s).includes('temp-12-')),
    `the receipt names only the program, so the "no envchecker folder in the temp directories" half cannot be audited: ${JSON.stringify(row.searched)}`);
});

// AUDIT-13, rewritten 30 Oct 2026, and this is why rather than a tidy-up. The original test took the defect it was
// written to find as its PREMISES: its first two lines asserted that safe() returns SAFE for a made-up receipt and
// that hasReceipt() says yes to a prose sentence, in those words ("premise: any non-blank string is a receipt"), and
// only its third line was the finding. A test built that way cannot pass after any correct fix -- once the gate
// refuses a made-up receipt the premises are false, so it goes red for the right reason and stays red for ever, and a
// suite with a permanent red in it is a suite nobody reads. 00b6332 fixed the gate on this branch; the finding is now
// asserted the way round that survives it. What AUDIT-13 found is that the rule standing between an UNKNOWN and a
// SAFE tested the SHAPE of a receipt and never its truth, and that the second enforcement on the way out called the
// same shape-only test and so could catch nothing. Both are asserted here as refusals.
test('AUDIT-13 the receipt gate refuses a made-up receipt, in safe() and again in withdrawUnreceipted()', () => {
  const prose = 'I had a thorough look around';
  const nowhere = '/no/such/folder/anywhere';
  assert.ok(!existsSync(nowhere), 'this case needs a path that is not on this machine');

  // safe() must not hand back an all-clear for a receipt naming a path that is not there and a sentence about
  // looking. It comes back UNKNOWN rather than throwing, because a folder read a moment ago can be gone by the time
  // the rule runs, and the iron law's answer to that is UNKNOWN and never SAFE.
  const madeUp = safe([nowhere, prose], { kind: 'audit13', reason: 'nothing found here' });
  assert.equal(madeUp.status, 'UNKNOWN',
    `a receipt naming ${nowhere} and a prose sentence still yielded ${madeUp.status}: ${JSON.stringify(madeUp)}`);
  assert.match(madeUp.reason, /cannot be checked by looking/, 'the withdrawal has to say why, not just change the status');
  // both failing entries named, so a reader can see which part of the receipt did not hold
  assert.ok(madeUp.reason.includes(nowhere), `the made-up path is not named in the reason: ${madeUp.reason}`);
  assert.ok(madeUp.reason.includes(prose), `the prose entry is not named in the reason: ${madeUp.reason}`);

  // hasReceipt() is the rule itself, and it must say no to the same thing whoever assembled the row.
  assert.equal(hasReceipt({ status: 'SAFE', searched: [nowhere, prose] }), false,
    'hasReceipt() still accepts any non-blank string, so the shape-only test is still the rule');

  // withdrawUnreceipted() is the second enforcement, and it has to catch a row safe() never made: lib/binaries.mjs
  // and lib/installs.mjs push the file they read onto the front of a receipt after the fact, so the row that reaches
  // the way out is not the object safe() returned. It changes the row in place and returns the ones it changed.
  const row = { status: 'SAFE', kind: 'audit13', reason: 'nothing found here', searched: [nowhere, prose] };
  const withdrawn = withdrawUnreceipted([row]);
  assert.equal(withdrawn.length, 1, `withdrawUnreceipted() let a made-up receipt through: ${JSON.stringify(row)}`);
  assert.equal(withdrawn[0], row, 'it should return the row it was given, changed in place');
  assert.equal(row.status, 'UNKNOWN');
  assert.match(row.reason, /cannot be checked by looking/);

  // And the gate is not simply refusing everything, which would pass every assertion above and be a different
  // defect: a receipt naming a place that IS on this machine still yields SAFE, and is left alone on the way out.
  const real = safe([dir], { kind: 'audit13', reason: 'nothing found here' });
  assert.equal(real.status, 'SAFE', `an existing folder is not a receipt any more: ${JSON.stringify(real)}`);
  assert.deepEqual(real.searched, [dir]);
  assert.ok(real.searched.every((s) => isAbsolute(String(s)) && existsSync(String(s))));
  assert.equal(hasReceipt(real), true);
  assert.deepEqual(withdrawUnreceipted([{ ...real }]), [], 'the way out withdrew an all-clear whose receipt holds');
});
