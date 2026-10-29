// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026: the test-coverage half. A mutation campaign planted 59 deliberate bugs in lib/ and bin/
// one at a time and ran the suite (`npm test`) against each. 55 were caught. Four were not:
//   M45 lib/owners.mjs:42  delete `if (uid === 0) return false;`      — an EQUIVALENT mutant, not a gap: the line is
//       dead (a run as root returns true at `uid === self` above it, and otherwise 0 is below the uid floor below it).
//   M60 bin/wardlatch.mjs:33  keep relative PATH entries              — nothing watches the PATH hardening.
//   M69 lib/wordpress.mjs:143  read only .php, not .js or .inc        — nothing watches which files the indicator
//       search reads (the other half of this is audit-blind-spots.test.mjs AUDIT-24).
//   M70 lib/workflows.mjs:14  reposUnder's default maxDepth 4 -> 1   — EQUIVALENT too: every caller passes the depth
//       (bin/wardlatch.mjs:427, :448 and lib/headers.mjs:277), so the default is dead. Mutating the call sites
//       instead: :427 and :448 are caught, and so are the WordPress (:466), installs and discover depths, but
//   M76 lib/headers.mjs:277  the header check's repository depth 4 -> 1 — SURVIVES. The per-repository settings the
//       header check reads (.mcp.json, .claude/settings.json, .cursor/mcp.json, .vscode/mcp.json) could stop being
//       found below the first level and nothing would fail.
// Unlike the other audit-* files, these four PASS on 0.1.10. They exist to close the gaps, so the next edit that
// weakens one of these is caught.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reposUnder } from '../lib/workflows.mjs';
import { checkSite } from '../lib/wordpress.mjs';
import { scanHeaders } from '../lib/headers.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const HIDE_PHP = ['--require', join(ROOT, 'test', 'support', 'hide-php-places.cjs')];
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-cov-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-audit-cov-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));

test('M60 a relative PATH entry is dropped, so a program in the folder the command was started from is never run', () => {
  // npx puts a project's node_modules/.bin first on PATH, and an empty or relative entry makes a bare name resolve in
  // the current folder. bin/wardlatch.mjs:33 keeps only absolute entries. A php on PATH as an absolute entry stands
  // beside it, so dropping the relative one cannot fall through to /usr/bin:/bin and find the machine's own php.
  const rel = 'relbin';
  mkdirSync(join(dir, rel), { recursive: true });
  writeFileSync(join(dir, rel, 'php'), '#!/bin/sh\necho "PHP 8.3.6 (cli)"\n', { mode: 0o755 });   // vulnerable
  const abs = join(dir, 'absbin');
  mkdirSync(abs, { recursive: true });
  writeFileSync(join(abs, 'php'), '#!/bin/sh\necho "PHP 8.5.12 (cli)"\n', { mode: 0o755 });        // fixed
  const r = spawnSync(process.execPath, [...HIDE_PHP, BIN, '--incident', 'php-2026-10', '--json', '--paths', dir],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, cwd: dir, env: { ...ownEnv(), PATH: `${rel}:${abs}`, HOME: home, TMPDIR: home } });
  const php = JSON.parse(r.stdout).results.filter((x) => x.kind === 'binary');
  assert.deepEqual(php.map((x) => [x.status, x.version]), [['SAFE', '8.5.12']],
    `the relative PATH entry was used: ${JSON.stringify(php)}`);
  assert.equal(r.status, 0);
});

test('M70 a repository is found four levels under a searched folder, and not five', () => {
  const at = (n) => {
    const root = join(dir, `depth-${n}`);
    const repo = join(root, ...Array.from({ length: n - 1 }, (_, i) => `L${i}`), 'repo');
    mkdirSync(join(repo, '.git'), { recursive: true });
    return { root, repo };
  };
  for (const n of [1, 2, 3, 4]) { const { root, repo } = at(n); assert.deepEqual(reposUnder([root], 4, []), [repo], `${n} level(s) under the root`); }
  const five = at(5);
  assert.deepEqual(reposUnder([five.root], 4, []), [], 'five levels under the root is past the cap (the CHANGELOG\'s known limits)');
});

test('M76 the header check reads a repository\'s own settings four levels under a searched folder', () => {
  // the only depth the suite does not watch: lib/headers.mjs:277. A repository two to four levels down holds the
  // same .mcp.json and .claude/settings.json as one at the top.
  const email = 'ada.lovelace@example.org';
  for (const n of [1, 4]) {
    const root = join(dir, `hdr-${n}`);
    const repo = join(root, ...Array.from({ length: n - 1 }, (_, i) => `L${i}`), 'app');
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(join(repo, '.mcp.json'), JSON.stringify({ mcpServers: { x: { url: 'https://x.example', headers: { 'X-Operator': email } } } }));
    const own = join(dir, `hdr-home-${n}`); mkdirSync(own, { recursive: true });
    const h = scanHeaders({ home: own, env: { PATH: process.env.PATH, GIT_AUTHOR_EMAIL: email }, roots: [root] });
    assert.ok(h.findings.some((f) => f.file === join(repo, '.mcp.json')),
      `a repository ${n} level(s) under the root: its .mcp.json header was not read: ${JSON.stringify({ findings: h.findings, files: h.files })}`);
  }
});

test('M69 the WordPress indicator search reads .js and .inc, not only .php', () => {
  const site = join(dir, 'site-m69');
  mkdirSync(join(site, 'wp-includes'), { recursive: true });
  writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  writeFileSync(join(site, 'wp-config.php'), '<?php\n');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  mkdirSync(plugin, { recursive: true });
  writeFileSync(join(plugin, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.124\n*/\n');
  const rules = [{ plugin: 'seo-by-rank-math-pro', mainFile: 'rank-math-pro.php', bad: ['3.0.123'], indicator: 'rank1cdn', fix: 'x' }];
  for (const name of ['loader.php', 'loader.js', 'loader.inc', 'LOADER.PHP', 'loader.JS']) {
    writeFileSync(join(plugin, name), 'var u = "https://rank1cdn.example/x";\n');
    const out = checkSite(site, rules);
    rmSync(join(plugin, name));
    assert.ok(out.some((f) => f.status === 'EXPOSED' && String(f.what).includes(name)), `${name}: the indicator in it was not found: ${JSON.stringify(out.map((f) => [f.status, f.what]))}`);
  }
});
