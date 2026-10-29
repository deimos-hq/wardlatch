// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026. judgeVersion() (lib/binaries.mjs:227) decides every version verdict, for programs on
// PATH and for versions read from a product's own files. Four ways it gets one wrong:
//   - it ends in `return ok()`: a rule with nothing to compare against calls every version SAFE (fail open). The
//     invariant that stops that today lives in test/incidents.test.mjs:27 and :34, not in the code;
//   - it judges the leading dotted number, so a Debian epoch ("1:19.5.0-ee") is judged as version 1, which
//     `affectedFrom` then calls older than the affected range: SAFE;
//   - it picks a release line by comparing `line()` as a STRING while comparing versions numerically, so "8.03.36"
//     and "8.3.36" are not the same line;
//   - versionOf() (lib/binaries.mjs:94) matches the version regex unanchored and takes the FIRST match in the output,
//     while checkVersionFiles() uses the 'm' flag: a line before the real banner decides the verdict.
// And the PHP rule's own versionRe throws away a distribution's revision, so a backported, patched package is reported
// as plain upstream and EXPOSED, with a fix naming a version that distribution never shipped.
// These tests fail on 0.1.10.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeVersion, versionOf } from '../lib/binaries.mjs';
import { checkVersionFiles } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
const PHP_FIXES = { fixedIn: ['8.2.35', '8.3.36', '8.4.27', '8.5.12'] };
let dir;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-judge-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

test('AUDIT-14 judgeVersion() fails open: a rule with nothing to compare against calls every version SAFE', () => {
  // the shipped incident files all carry one of bad/fixedIn/minVersion, held by test/incidents.test.mjs, not by the
  // code. A rule that loses the field in an edit, a merge or a hand-patched lib/incidents/*.json reads SAFE for every
  // machine, with a receipt, and withdrawUnreceipted() cannot see it.
  for (const v of ['0.0.1', '8.3.6', '1.107.0', '3.0.123']) {
    assert.notEqual(judgeVersion(v, {}).status, 'SAFE', `a rule with no bad/fixedIn/minVersion called ${v} SAFE`);
    assert.notEqual(judgeVersion(v, { product: 'Thing', fix: 'update it' }).status, 'SAFE', `a rule with only prose called ${v} SAFE`);
  }
});

test('AUDIT-15 judgeVersion() fails open through a whole version file too', () => {
  const f = join(dir, 'VERSION'); writeFileSync(f, '19.5.0-ee\n');
  const rule = { product: 'Thing', fix: 'update it', lookedIn: 'here', files: [{ path: f, re: '^(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.]+)?)' }] };
  const out = checkVersionFiles(rule);
  assert.equal(out.length, 1);
  assert.notEqual(out[0].status, 'SAFE', `a version file read against a rule with nothing to compare against: ${JSON.stringify(out[0])}`);
});

test('AUDIT-27 end to end: deleting one key from an incident file turns EXPOSED into SAFE, while invalid JSON fails closed', () => {
  // the incident files ship in the npm package and are read at run time. A packager's patch, a vendored copy, a
  // hand-applied hotfix or a half-written download can lose a key. Invalid JSON stops the run (exit 2, fail closed);
  // a missing key reads SAFE (fail open). Only test/incidents.test.mjs holds the invariant, and it never runs here.
  const copy = join(dir, 'copy');
  for (const d of ['lib', 'bin']) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
  cpSync(join(ROOT, 'package.json'), join(copy, 'package.json'));
  const bin = join(dir, 'phpbin'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'php'), '#!/bin/sh\necho "PHP 8.3.6 (cli)"\n', { mode: 0o755 });
  const own = join(dir, 'home-27'); mkdirSync(own, { recursive: true });
  const run = () => {
    const r = spawnSync(process.execPath, [join(copy, 'bin', 'wardlatch.mjs'), '--incident', 'php-2026-10', '--paths', own],
      { encoding: 'utf8', maxBuffer: 1 << 26, env: { ...process.env, PATH: bin, HOME: own, TMPDIR: own } });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const file = join(copy, 'lib', 'incidents', 'php-2026-10.json');
  const shipped = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(run().code, 1, 'premise: as shipped, PHP 8.3.6 is EXPOSED');
  const stripped = JSON.parse(JSON.stringify(shipped));
  delete stripped.binaries[0].fixedIn;
  writeFileSync(file, JSON.stringify(stripped, null, 2));
  const open = run();
  writeFileSync(file, '{ not json');
  const closed = run();
  assert.equal(closed.code, 2, 'premise: invalid JSON stops the run');
  assert.notEqual(open.code, 0, `one key removed from the incident file and PHP 8.3.6 reads:\n${open.out}`);
  assert.doesNotMatch(open.out, /SAFE {5}php 8\.3\.6/, 'an all-clear for a version nothing was compared against');
});

test('AUDIT-16 a Debian epoch makes a vulnerable version read SAFE through affectedFrom', () => {
  const rule = incident('gitlab-2026-10').versionFiles;      // affectedFrom 7.0, fixedIn up to 19.5.1
  assert.equal(judgeVersion('19.5.0-ee', rule).status, 'EXPOSED', 'premise: 19.5.0 is affected');
  const r = judgeVersion('1:19.5.0-ee', rule);
  assert.notEqual(r.status, 'SAFE', `an epoch-prefixed 19.5.0 read ${r.status}: ${JSON.stringify(r)}`);
  // and the receipt it would carry says only "version 1:19.5.0-ee", which reads like the version was understood
  assert.notDeepEqual(r.searched, ['version 1:19.5.0-ee']);
});

test('AUDIT-17 release lines are matched as strings while versions compare numerically: a zero-padded fix reads EXPOSED', () => {
  assert.equal(judgeVersion('8.3.36', PHP_FIXES).status, 'SAFE', 'premise: 8.3.36 is the fix for the 8.3 line');
  // 8.03.36 is the same version: cmp() reads both parts numerically, but line() compares "8.03" with "8.3" as text,
  // so no fix is found for the line and the version is judged against every other line instead
  assert.equal(judgeVersion('8.03.36', PHP_FIXES).status, 'SAFE', `8.03.36 read ${JSON.stringify(judgeVersion('8.03.36', PHP_FIXES))}`);
  assert.equal(judgeVersion('8.03.40', PHP_FIXES).status, 'SAFE', `8.03.40 read ${JSON.stringify(judgeVersion('8.03.40', PHP_FIXES))}`);
});

test('AUDIT-18 versionOf() takes the first match anywhere in the output, so a line printed before the real banner decides the verdict', () => {
  const bin = join(dir, 'two'); mkdirSync(bin, { recursive: true });
  const php = join(bin, 'php');
  // a wrapper or shim that prints a line of its own first (checkVersionFiles anchors with 'm'; versionOf does not)
  writeFileSync(php, '#!/bin/sh\necho "policy: this host is checked against PHP 8.5.12"\necho "PHP 8.3.6 (cli) (built: Oct 1 2026) (NTS)"\n', { mode: 0o755 });
  const re = incident('php-2026-10').binaries[0].versionRe;
  assert.equal(versionOf(php, ['-n', '-v'], re), '8.3.6',
    'the version read was the one on an earlier line, not the program\'s own banner');
});

test('AUDIT-19 a distribution\'s revision is thrown away at capture, so a backported patched package is reported as plain upstream', () => {
  const bin = join(dir, 'ub'); mkdirSync(bin, { recursive: true });
  const php = join(bin, 'php');
  // Ubuntu 24.04 LTS ships php8.3 as 8.3.6-0ubuntu0.24.04.x and backports the October fixes into that revision
  writeFileSync(php, '#!/bin/sh\necho "PHP 8.3.6-0ubuntu0.24.04.6 (cli) (built: Oct 22 2026) (NTS)"\n', { mode: 0o755 });
  const re = incident('php-2026-10').binaries[0].versionRe;
  const v = versionOf(php, ['-n', '-v'], re);
  assert.equal(v, '8.3.6-0ubuntu0.24.04.6',
    `the row shows "${v}", so a reader cannot see this is a distribution build; the verdict is EXPOSED with "fixed in 8.3.36", a version that distribution never shipped`);
});
