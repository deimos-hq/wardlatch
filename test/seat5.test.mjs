// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The rest of seat 5's review of 2 Nov 2026: what read SAFE and shouldn't have. Each failed on integrate/r5 at 8c7f203.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseGitConfig, headersInToml } from '../lib/headers.mjs';
import { checkImages } from '../lib/installs.mjs';
import { versionOf } from '../lib/binaries.mjs';
import { discover } from '../lib/discover.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
let dir, home, n = 0;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-s5-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-s5-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

const fresh = () => { const d = join(dir, `t${++n}`); mkdirSync(d, { recursive: true }); return d; };
const put = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); return p; };
const exe = (p, body) => { put(p, `#!/bin/sh\n${body}\n`); spawnSync('/bin/chmod', ['755', p]); return p; };
const cli = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, '--json', ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...ownEnv(), PATH: '/usr/bin:/bin', HOME: home, TMPDIR: home, ...env } });
  assert.ok(r.stdout, `no output (exit ${r.status}): ${r.stderr}`);
  return { code: r.status, results: JSON.parse(r.stdout).results };
};
const git = (cwd, env, ...args) => { const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', ...env } }); assert.equal(r.status, 0, r.stderr); };

const HEADER = 'X-User: ada@example.invalid';

test('F5 the git config forms git reads: a section and key on one line, a continued value, a ; inside quotes', () => {
  const one = parseGitConfig(`[http] extraHeader = ${HEADER}\n`);
  assert.deepEqual(one.headers.map((h) => h.value), [HEADER]);
  const cont = parseGitConfig(`[http]\n\textraHeader = X-User: \\\nada@example.invalid\n`);
  assert.deepEqual(cont.headers.map((h) => h.value), ['X-User: ada@example.invalid']);
  const quoted = parseGitConfig(`[http]\n\textraHeader = "X-Team: core ; ${HEADER}"\n`);
  assert.deepEqual(quoted.headers.map((h) => h.value), [`X-Team: core ; ${HEADER}`]);
  // the controls: comments outside quotes still go, and a subsection header still parses
  assert.equal(parseGitConfig('[user]\n\temail = a@example.invalid ; a comment\n').email, 'a@example.invalid');
  assert.equal(parseGitConfig('[user]\n\temail = a@example.invalid;a comment\n').email, 'a@example.invalid');
  assert.equal(parseGitConfig('[http "https://x.example"]\n\textraHeader = a\n').headers[0].everywhere, false);
});

test('F11 a TOML args array carries a header the way a JSON one does, on one line or several', () => {
  const single = headersInToml(`[mcp_servers.x]\nargs = ["mcp-remote", "--header", "${HEADER}"]\n`);
  assert.deepEqual(single.map((h) => h.value), [HEADER]);
  const many = headersInToml(`[mcp_servers.x]\nargs = [\n  "mcp-remote",\n  "--header",\n  "${HEADER}",\n]\n`);
  assert.deepEqual(many.map((h) => h.value), [HEADER]);
  assert.deepEqual(headersInToml(`args = ["--header=${HEADER}"]\n`).map((h) => h.value), [HEADER]);
  assert.deepEqual(headersInToml('[mcp_servers.x]\nargs = ["mcp-remote", "--port", "80"]\n'), [], 'the control: other args are not headers');
});

const site = (root) => { put(join(root, 'wp-includes', 'version.php'), "<?php $wp_version = '6.6';\n"); mkdirSync(join(root, 'wp-content', 'plugins'), { recursive: true }); return root; };
const bad = (d, version = '3.0.123') => put(join(d, 'rank-math-pro.php'), `<?php\n/*\n * Version: ${version}\n */\n`);
const wp = (root) => cli(['--incident', 'wordpress-plugins-2026-10', '--no-containers', '--paths', root]);

test('F7 a compromised copy under a folder beside a core is checked', () => {
  const r1 = fresh(); site(r1); bad(join(r1, 'old', 'plugins', 'seo-by-rank-math-pro'));
  assert.equal(wp(r1).code, 1);
  const r2 = fresh(); site(join(r2, 'wp')); bad(join(r2, 'backup', 'plugins', 'seo-by-rank-math-pro'));
  assert.equal(wp(r2).code, 1);
});

test('F8 a plugin in a folder with another name is checked', () => {
  const a = fresh(); site(a); bad(join(a, 'wp-content', 'plugins', 'seo-by-rank-math-pro-3.0.123'));
  assert.equal(wp(a).code, 1, 'versioned folder name');
  const b = fresh(); site(b); bad(join(b, 'wp-content', 'plugins.bak', 'seo-by-rank-math-pro'));
  assert.equal(wp(b).code, 1, 'plugins.bak');
  const c = fresh(); site(c); bad(join(c, 'wp-content', 'old-plugins', 'seo-by-rank-math-pro'));
  assert.equal(wp(c).code, 1, 'old-plugins');
  const d = fresh(); site(d); put(join(d, 'wp-content', 'plugins', 'seo-by-rank-math-pro-extra', 'readme.txt'), 'x');
  assert.equal(wp(d).code, 0, 'the control: a folder with the prefix and no main file is not the plugin');
});

test('F15 a single-file plugin added in the window is a REVIEW line', () => {
  const r = fresh(); site(r);
  put(join(r, 'wp-content', 'plugins', 'door.php'), '<?php\n');
  assert.ok(wp(r).results.some((x) => x.status === 'REVIEW' && /door\.php/.test(x.what)));
  const q = fresh(); site(q);
  put(join(q, 'wp-content', 'plugins', 'index.php'), '<?php\n');
  assert.ok(!wp(q).results.some((x) => x.status === 'REVIEW' && /index\.php/.test(x.what ?? '')), 'the control: the index.php WordPress ships');
});

test('F16 a version written with a trailing .0 is the same version', () => {
  const r = fresh(); site(r); bad(join(r, 'wp-content', 'plugins', 'seo-by-rank-math-pro'), '3.0.123.0');
  assert.equal(wp(r).code, 1);
});

const engine = (body) => { const d = fresh(); exe(join(d, 'docker'), `if [ "$1" = images ]; then ${body}; fi\nexit 0`); return `${d}:/usr/bin:/bin`; };
const images = (PATH) => cli(['--incident', 'litellm-2026-10'], { PATH });

test('F9 a dangling image carrying a known-bad digest is EXPOSED', () => {
  const d = incident('litellm-2026-10').dockerDigests[0];
  assert.equal(images(engine(`echo '<none>:<none>@${d}'`)).code, 1);
  assert.equal(images(engine("echo '<none>:<none>@<none>'")).code, 0, 'the control: one with nothing to match is left out');
});

test('F19 an engine that answers with lines that can\'t be read is could-not-be-tested, not "0 images"', () => {
  assert.equal(images(engine("echo 'something else entirely'")).code, 2);
  assert.equal(images(engine(':')).code, 0, 'the control: an empty answer is no images');
});

test('F10 every tag the rule\'s own text names is at least a REVIEW line when its digest is not listed', () => {
  const rule = incident('litellm-2026-10');
  for (const ref of ['ghcr.io/berriai/litellm:main-stable', 'docker.io/litellm/litellm:latest', 'litellm/litellm-database:v1.107.0']) {
    const [row] = checkImages(rule, { docker: [`${ref}@sha256:${'0'.repeat(64)}`] });
    assert.equal(row?.status, 'REVIEW', ref);
  }
  assert.deepEqual(checkImages(rule, { docker: [`ghcr.io/berriai/litellm:v1.106.2@sha256:${'0'.repeat(64)}`] }), [], 'the control: an earlier version');
  assert.equal(checkImages(rule, { docker: [`ghcr.io/berriai/litellm:latest@${rule.dockerDigests[0]}`] })[0].status, 'EXPOSED', 'a listed digest stays EXPOSED');
});

test('F12 a bare repository is read by the workflow review', () => {
  const src = fresh();
  git(src, {}, 'init', '-q');
  put(join(src, '.github', 'workflows', 'x.yml'), 'on: push\n');
  git(src, {}, 'add', '-A');
  const when = '2026-10-01T00:00:00Z';
  git(src, { GIT_AUTHOR_DATE: when, GIT_COMMITTER_DATE: when }, 'commit', '-q', '-m', 'x');
  const root = fresh();
  git(root, {}, 'clone', '-q', '--bare', src, join(root, 'mirror.git'));
  const { results } = cli(['--incident', 'github-actions-2026-10', '--no-containers', '--paths', root]);
  assert.ok(results.some((r) => r.status !== 'SAFE'), JSON.stringify(results));
});

test('F13 a pip --target folder is checked as a package folder', () => {
  const root = fresh();
  put(join(root, 'package', 'litellm-1.107.0.dist-info', 'METADATA'), 'Name: litellm\nVersion: 1.107.0\n');
  put(join(root, 'package', 'cook.pth'), 'import os\n');
  assert.equal(cli(['--incident', 'litellm-2026-10', '--no-containers', '--paths', root]).code, 1);
  const plain = fresh(); put(join(plain, 'package', 'requests-2.0.dist-info', 'METADATA'), 'Name: requests\n');
  assert.equal(cli(['--incident', 'litellm-2026-10', '--no-containers', '--paths', plain]).code, 0, 'the control: another package');
});

test('F14 .mcp.json in a project with no .git is read', () => {
  const h = fresh(); put(join(h, '.gitconfig'), '[user]\n\tname = Ada Example\n\temail = ada@example.invalid\n');
  const root = fresh();
  put(join(root, 'proj', '.mcp.json'), JSON.stringify({ mcpServers: { x: { headers: { 'X-User': 'ada@example.invalid' } } } }));
  const { results } = cli(['--incident', 'identity-headers-2026-10', '--no-containers', '--paths', root], { HOME: h, TMPDIR: h });
  assert.ok(results.some((r) => ['REVIEW', 'EXPOSED'].includes(r.status)), JSON.stringify(results));
});

test('F17 a version in a warning from a program that failed is not its version', () => {
  const warn = exe(join(fresh(), 'php'), 'echo "Warning: 8.5.12 is recommended" >&2; exit 1');
  assert.equal(versionOf(warn), '');
  const banner = exe(join(fresh(), 'php'), 'echo "8.1.2 (cli)"; exit 1');
  assert.equal(versionOf(banner), '8.1.2', 'the control: a failing program that printed its own banner');
});

test('F18 a venv with only bin/python3 is probed, and a FIFO where the bundle should be is a gap', () => {
  const lists = () => ({ denied: [], found: [], notRun: [], untested: [], links: [], deep: [] });
  const root = fresh(), v = join(root, 'v');
  put(join(v, 'pyvenv.cfg'), 'home = /usr/bin\n');
  exe(join(v, 'bin', 'python3'), 'exit 0');
  put(join(v, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), 'x\n');
  const l = lists();
  const rows = discover({ roots: [root], pathEnv: '/nonexistent', ...l });
  assert.ok([...rows, ...l.untested].length > 0, 'the venv left no row');
  const r2 = fresh(), v2 = join(r2, 'v');
  put(join(v2, 'pyvenv.cfg'), 'home = /usr/bin\n');
  exe(join(v2, 'bin', 'python'), 'exit 0');
  const cert = join(v2, 'lib', 'python3.12', 'site-packages', 'certifi');
  mkdirSync(cert, { recursive: true });
  spawnSync('/usr/bin/mkfifo', [join(cert, 'cacert.pem')]);
  const m = lists();
  discover({ roots: [r2], pathEnv: '/nonexistent', ...m });
  assert.ok(m.found.length > 0, 'a FIFO in place of the bundle left no gap');
});
