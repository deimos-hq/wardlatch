// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Hostile audit, October 2026. Two checks decline to read a file and say nothing, so "nothing found" covers files that
// were never looked at:
//   - lib/secrets.mjs:185 (`if (!enc) continue;`): a tracked file with one NUL byte in its first 8 KB is "binary" and
//     dropped WITHOUT the unread() row every other skip in that same loop records. One byte hides every key in a file,
//     and the all-clear still counts the repository as read;
//   - lib/wordpress.mjs:143: the indicator search reads only .php, .js and .inc, and `skipped` reports only size,
//     depth and the file cap — never "there were files here I do not read". A backdoor in a .phtml, a .php5 or a file
//     with no extension is invisible and unmentioned.
// These tests fail on 0.1.10.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo, encodingOf } from '../lib/secrets.mjs';
import { checkSite } from '../lib/wordpress.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const KEY = `${'AKIA'}Q1W2E3R4T5Y6U7I8`;      // the shape lib/secrets.mjs matches, built so this file carries no key
let dir, home;

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-audit-blind-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-audit-blind-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
function keyRepo(path, body) {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env: { ...process.env, HOME: home, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q');
  writeFileSync(join(path, 'deploy.sh'), body);
  g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add');
  return path;
}

test('AUDIT-22 one NUL byte in a tracked file hides every key in it, with no row saying the file was not read', () => {
  assert.equal(encodingOf(Buffer.from('a text file\n')), 'utf8', 'premise');
  assert.equal(encodingOf(Buffer.concat([Buffer.from('#\0\n'), Buffer.from('text\n')])), null, 'premise: one NUL makes it binary');
  const plain = keyRepo(join(dir, 'plain', 'app'), `AWS_ACCESS_KEY_ID=${KEY}\n`);
  assert.equal(scanRepo(plain).length, 1, 'premise: the same file without the NUL byte is found');
  const nulled = keyRepo(join(dir, 'nulled', 'app'), Buffer.concat([Buffer.from('#\0\n'), Buffer.from(`AWS_ACCESS_KEY_ID=${KEY}\n`)]));
  const hits = scanRepo(nulled);
  // every other skip in that loop records an unread row; this one records nothing
  assert.ok(hits.length, `the file was neither scanned nor reported as unscanned: ${JSON.stringify(hits)}`);
});

test('AUDIT-23 the same file reads SAFE through the command, and the all-clear still counts the repository as read', () => {
  const root = join(dir, 'cli-nulled');
  keyRepo(join(root, 'app'), Buffer.concat([Buffer.from('#\0\n'), Buffer.from(`AWS_ACCESS_KEY_ID=${KEY}\n`)]));
  const r = run(['--incident', 'committed-keys-2026-10', '--paths', root]);
  assert.doesNotMatch(r.out, /SAFE {5}no committed keys found in the files of 1 local repository/,
    `an all-clear that says it read the repository, over a tracked file it declined to read:\n${r.out}`);
});

test('AUDIT-24 the WordPress indicator search reads only .php, .js and .inc, and never says which files it skipped', () => {
  const site = join(dir, 'site');
  mkdirSync(join(site, 'wp-includes'), { recursive: true });
  writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.7";\n');
  writeFileSync(join(site, 'wp-config.php'), '<?php\n');
  const plugin = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  mkdirSync(plugin, { recursive: true });
  // a version that is NOT the compromised release, so only the indicator search can find anything
  writeFileSync(join(plugin, 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math PRO\nVersion: 3.0.124\n*/\n');
  const rules = [{ plugin: 'seo-by-rank-math-pro', mainFile: 'rank-math-pro.php', bad: ['3.0.123'], indicator: 'rank1cdn', fix: 'x' }];
  // the control: the indicator in a .php file is found
  writeFileSync(join(plugin, 'loader.php'), '<?php $u = "https://rank1cdn.example/x";\n');
  assert.ok(checkSite(site, rules).some((f) => f.status === 'EXPOSED'), 'premise: the indicator in a .php file is found');
  rmSync(join(plugin, 'loader.php'));
  // the same indicator in the file names a PHP server will also execute or serve
  for (const name of ['loader.phtml', 'loader.php5', 'loader.inc.html', 'loader']) {
    writeFileSync(join(plugin, name), '<?php $u = "https://rank1cdn.example/x";\n');
    const out = checkSite(site, rules);
    rmSync(join(plugin, name));
    const found = out.some((f) => f.status === 'EXPOSED');
    const said = out.some((f) => f.status === 'UNKNOWN' && /indicator/.test(String(f.what)));
    assert.ok(found || said, `${name}: the indicator was neither found nor reported as unsearched: ${JSON.stringify(out.map((f) => [f.status, f.what, f.reason]))}`);
  }
});
