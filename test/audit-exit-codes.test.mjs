// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026. The iron law is that not having looked is UNKNOWN, and UNKNOWN exits 2. Two places turn
// "I did not check this" into a REVIEW line, which leaves the exit code at 0:
//   - a later copy of a program on PATH that is a script is not run, so its version is not judged
//     (lib/binaries.mjs:39, reported by bin/wardlatch.mjs notRunRow() as REVIEW). The same ignorance, when the program
//     IS run and will not say its version, is UNKNOWN (lib/binaries.mjs:187);
//   - a folder under a searched root that cannot be opened and is owned by a service account is a REVIEW line
//     (bin/wardlatch.mjs:181 through lib/owners.mjs), although a site or a repository in it went unread.
// In both cases the summary line reads "0 could not be tested" and a pipeline passes.
// These tests fail on 0.1.10.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
// the PHP check also searches folders off PATH: hidden, so PHP on the machine cannot change what these tests see
const HIDE_PHP = ['--require', join(ROOT, 'test', 'support', 'hide-php-places.cjs')];
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-exit-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-audit-exit-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [...HIDE_PHP, BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const script = (d, name, body) => { mkdirSync(d, { recursive: true }); writeFileSync(join(d, name), body, { mode: 0o755 }); return d; };

test('AUDIT-20 a later copy of php on PATH that is a script is never run, and the run reads SAFE, exit 0, with a vulnerable PHP installed', () => {
  const fixed = script(join(dir, 'first'), 'php', '#!/bin/sh\necho "PHP 8.5.12 (cli) (built: Oct 21 2026) (NTS)"\n');
  const vulnerable = script(join(dir, 'second'), 'php', '#!/bin/sh\necho "PHP 8.3.6 (cli) (built: Mar 1 2026) (NTS)"\n');
  // the control: with the vulnerable copy first, the same two programs read EXPOSED
  const control = run(['--incident', 'php-2026-10', '--paths', dir], { PATH: `${vulnerable}:${fixed}` });
  assert.equal(control.code, 1, `premise: a vulnerable php first on PATH is EXPOSED:\n${control.out}`);
  const r = run(['--incident', 'php-2026-10', '--paths', dir], { PATH: `${fixed}:${vulnerable}` });
  assert.match(r.out, /copies on PATH not run/, 'premise: the later copy is named as not run');
  assert.notEqual(r.code, 0, `PHP 8.3.6 is installed and its version was never read, and the run exits 0:\n${r.out}`);
  assert.doesNotMatch(r.out, /0 could not be tested/, 'a copy whose version was not judged is something that could not be tested');
});

test('AUDIT-26 the all-clear fires beside a "folders not searched" line: SAFE, exit 0, over a folder the run could not open', () => {
  // bin/wardlatch.mjs counted() (:147) leaves kind 'skipped' out, so every() at :416 and the !counted().length tests
  // at :443, :461 and :479 see an empty list and the all-clear fires. The folder here is private by its place (a
  // dot-folder below the root, lib/wordpress.mjs:120), which is a REVIEW line whoever owns it; on a server the same
  // line covers every root- or service-owned folder under /srv, /opt and /var/www when the run is not under sudo
  // (checked on this Mac with --paths "/Library/Application Support": SAFE, exit 0, beside the same REVIEW line).
  // test/contract-0.1.9.test.mjs:436 asserts exactly this scenario is "UNKNOWN (exit 2), never SAFE" with the folder
  // named `locked`. Renaming it `.staging` flips the verdict, because the name decides which list it lands in.
  // And lib/wordpress.mjs:110 says dot-folders are searched like any other, "a staging copy in .staging is a
  // site" — so a .staging that CAN be opened is a site, and one that cannot is "private by its place", exit 0.
  // (test/release-0.1.9.test.mjs:274-277 blesses exit 0 for a locked dot-folder, but its fixture holds no site.)
  const root = join(dir, 'webroot-26');
  const closed = join(root, '.staging');
  const site = join(closed, 'live');
  mkdirSync(join(site, 'wp-includes'), { recursive: true });
  writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  writeFileSync(join(site, 'wp-config.php'), '<?php\n');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  mkdirSync(plugin, { recursive: true });
  writeFileSync(join(plugin, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.123\n*/\n');
  chmodSync(closed, 0o000);
  try {
    const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', root]);
    // either wording is a valid premise: before the fix the folder landed in `privateDot` and was only ever REVIEW,
    // after it goes to `denied` and gaps() makes it UNKNOWN because the person running owns it. What the rest of this
    // test checks — no all-clear, non-zero exit — is the same either way.
    assert.match(r.out, /REVIEW {3}folders not searched|could not be opened, so it was not searched/, 'premise: the run says it could not open a folder');
    assert.doesNotMatch(r.out, /SAFE {5}no WordPress installs found/,
      `an all-clear printed beside a line saying a folder went unsearched, with the backdoored plugin inside it:\n${r.out}`);
    assert.notEqual(r.code, 0, `exit 0 with a folder under the searched root unread:\n${r.out}`);
  } finally { chmodSync(closed, 0o755); }
});

test('AUDIT-21 --json carries the same verdict: one SAFE row, no UNKNOWN, with a vulnerable copy unchecked', () => {
  const fixed = script(join(dir, 'j-first'), 'php', '#!/bin/sh\necho "PHP 8.5.12 (cli)"\n');
  const vulnerable = script(join(dir, 'j-second'), 'php', '#!/bin/sh\necho "PHP 8.3.6 (cli)"\n');
  const r = run(['--incident', 'php-2026-10', '--json', '--paths', dir], { PATH: `${fixed}:${vulnerable}` });
  const results = JSON.parse(r.out).results;
  const notRun = results.find((x) => x.kind === 'not-run');
  assert.ok(notRun, `premise: a not-run row is reported: ${JSON.stringify(results)}`);
  assert.equal(notRun.status, 'UNKNOWN', `a copy that was not run and not judged is reported as ${notRun.status}: ${JSON.stringify(notRun)}`);
});
