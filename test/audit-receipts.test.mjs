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
import { hasReceipt, safe } from '../lib/report.mjs';

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

test('AUDIT-13 withdrawUnreceipted() cannot catch any of this: it checks the shape of a receipt, never its truth', () => {
  const madeUp = safe(['/no/such/folder/anywhere', 'I had a thorough look around']);
  assert.equal(madeUp.status, 'SAFE');
  assert.equal(hasReceipt(madeUp), true, 'premise: any non-blank string is a receipt');
  assert.ok(madeUp.searched.every((s) => isAbsolute(String(s)) && existsSync(String(s))),
    `lib/report.mjs lets a SAFE through whose receipt names nothing that exists: ${JSON.stringify(madeUp.searched)}`);
});
