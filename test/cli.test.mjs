// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The command itself, end to end, offline: every incident here is checked against stand-ins built in a temporary
// folder (fake programs on a private PATH, throwaway git repositories, a fake WordPress site). The eMudhra trust
// check is not run here because it needs the advisory's public test hosts; its logic is covered in wardlatch.test.mjs.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const VERSION = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
let dir;

/** Run the CLI → { code, out, err }. Output is piped, as in CI, so stdout is not a TTY and carries no colour. */
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const gitRepo = (path) => {
  mkdirSync(path, { recursive: true });
  const g = (...a) => execFileSync('git', ['-C', path, ...a], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } });
  g('init', '-q');
  return { commit: () => { g('add', '-A'); g('-c', 'commit.gpgsign=false', 'commit', '-qm', 'add'); } };
};

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-cli-')); });

test('--help and --list answer without checking anything', () => {
  const help = run(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, new RegExp(`wardlatch ${VERSION.replace(/\./g, '\\.')}`));
  assert.match(help.out, /Exit code: 0 all safe/);
  const list = run(['--list']);
  assert.equal(list.code, 0);
  const ids = readdirSync(join(ROOT, 'lib', 'incidents')).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5));
  for (const id of ids) assert.match(list.out, new RegExp(`^${id}  `, 'm'));
});

test('an unknown incident is refused with exit code 2, never a SAFE', () => {
  const r = run(['--incident', 'no-such-incident']);
  assert.equal(r.code, 2);
  assert.match(r.err, /unknown incident "no-such-incident"/);
  assert.doesNotMatch(r.out, /SAFE/);
});

test('a known-bad tool version is EXPOSED (exit 1); a missing tool is SAFE (exit 0); --json is complete', () => {
  const bin = join(dir, 'ovh'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'ovhcloud'), '#!/bin/sh\necho "ovhcloud 0.13.0"\n', { mode: 0o755 });
  const bad = run(['--incident', 'ovhcloud-cli-2026-10', '--json', '--paths', dir], { PATH: bin });
  assert.equal(bad.code, 1);
  const j = JSON.parse(bad.out);
  assert.equal(j.tool, 'wardlatch'); assert.equal(j.version, VERSION);
  assert.deepEqual(j.incidents.map((i) => i.id), ['ovhcloud-cli-2026-10']);
  assert.equal(j.results.length, 1);
  assert.equal(j.results[0].status, 'EXPOSED'); assert.equal(j.results[0].version, '0.13.0'); assert.ok(j.results[0].fix);
  const text = run(['--incident', 'ovhcloud-cli-2026-10', '--paths', dir], { PATH: bin });
  assert.match(text.out, /EXPOSED {2}ovhcloud 0\.13\.0/); assert.match(text.out, /fix: Install v0\.16\.0/);
  const none = run(['--incident', 'ovhcloud-cli-2026-10', '--paths', dir], { PATH: join(dir, 'empty-path') });
  assert.equal(none.code, 0); assert.match(none.out, /SAFE {5}ovhcloud not installed/);
});

test('workflow files added to a local repository are listed to REVIEW, and do not fail the exit code', () => {
  const root = join(dir, 'wf'); const repo = gitRepo(join(root, 'app'));
  mkdirSync(join(root, 'app', '.github', 'workflows'), { recursive: true });
  writeFileSync(join(root, 'app', '.github', 'workflows', 'build.yml'), 'on: push\n'); repo.commit();
  const r = run(['--incident', 'github-actions-2026-10', '--paths', root]);
  assert.equal(r.code, 0);
  assert.match(r.out, /REVIEW {2}.*app\/\.github\/workflows\/build\.yml/);
  assert.match(r.out, /1 to review/);
  const clean = run(['--incident', 'github-actions-2026-10', '--paths', join(dir, 'nothing-here')]);
  assert.equal(clean.code, 0); assert.match(clean.out, /SAFE {5}no workflow files added since 2026-09-01 in 0 local repositories/);
});

test('a committed key is reported by type, file and line, and the key itself is never printed', () => {
  const root = join(dir, 'keys'); const repo = gitRepo(join(root, 'svc'));
  const key = 'AKIA' + 'Q7RZ' + 'M2LP' + 'X9TB' + 'K4WD';            // built at runtime so this file holds no key literal
  writeFileSync(join(root, 'svc', 'config.js'), `const region = "us-east-1";\nconst k = "${key}";\n`); repo.commit();
  for (const json of [false, true]) {
    const r = run(['--incident', 'committed-keys-2026-10', '--paths', root, ...(json ? ['--json'] : [])]);
    assert.equal(r.code, 0, 'a review line informs; it does not fail a pipeline');
    assert.ok(!r.out.includes(key), 'the key never appears in the output');
    if (json) assert.deepEqual(JSON.parse(r.out).results.map((x) => [x.file, x.line, x.type]), [['config.js', 2, 'AWS access key']]);
    else assert.match(r.out, /REVIEW {2}.*svc\/config\.js:2 {2}AWS access key AKIA…\(20 chars\)/);
  }
});

test('regression: long --json output arrives complete through a pipe (0.1.1 fixed it being cut off)', () => {
  // process.exit() could end the process before a large write to a pipe had drained; on macOS, where pipe writes are
  // asynchronous, the JSON came out truncated. 300 findings make the output far larger than a pipe buffer.
  const root = join(dir, 'many'); const repo = gitRepo(join(root, 'big'));
  const lines = Array.from({ length: 300 }, (_, i) => `k${i} = "AKIA${'Q7RZM2LPX9TB'}${String(i).padStart(4, '0')}"`);
  writeFileSync(join(root, 'big', 'keys.txt'), `${lines.join('\n')}\n`); repo.commit();
  const r = run(['--incident', 'committed-keys-2026-10', '--json', '--paths', root]);
  assert.ok(r.out.length > 128 * 1024, `output is ${r.out.length} bytes`);
  assert.equal(JSON.parse(r.out).results.length, 300);
});

test('WordPress: a compromised plugin is EXPOSED with its fix (exit 1); no site found is SAFE', () => {
  const site = join(dir, 'wp', 'shop'); const pl = join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro');
  mkdirSync(join(site, 'wp-includes'), { recursive: true }); writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php $wp_version = "6.8";');
  mkdirSync(pl, { recursive: true }); writeFileSync(join(pl, 'rank-math-pro.php'), '<?php\n/**\n * Plugin Name: Rank Math PRO\n * Version: 3.0.123\n */\n');
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(dir, 'wp')]);
  assert.equal(r.code, 1);
  assert.match(r.out, /EXPOSED {2}.*shop · seo-by-rank-math-pro 3\.0\.123/);
  assert.match(r.out, /fix: /);
  const none = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(dir, 'nothing-here')]);
  assert.equal(none.code, 0); assert.match(none.out, /SAFE {5}no WordPress installs found/);
});
