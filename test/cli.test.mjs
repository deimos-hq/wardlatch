// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The command itself, end to end, offline: every incident here is checked against stand-ins built in a temporary
// folder (fake programs on a private PATH, throwaway git repositories, a fake WordPress site). The eMudhra trust
// check runs here only with an offline stand-in (no test host answers), for what it says when it can't test; its
// probes need the advisory's public test hosts, so they are covered in wardlatch.test.mjs against a local one.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const VERSION = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
let dir;

/** Run the CLI → { code, out, err }. Output is piped, as in CI, so stdout is not a TTY and carries no colour. */
const run = (args, env = {}, nodeArgs = [], cwd = undefined) => {
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 64 * 1024 * 1024, cwd });
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
  assert.ok(help.out.startsWith(`wardlatch ${VERSION}: `));
  assert.match(help.out, /Exit code: 0 all safe/);
  assert.match(help.out, /Sends nothing anywhere except TLS connections to the incidents' public test hosts and two control sites/);
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
  const bin = join(dir, 'php'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'php'), '#!/bin/sh\necho "PHP 8.4.26 (cli)"\n', { mode: 0o755 });
  const bad = run(['--incident', 'php-2026-10', '--json', '--paths', dir], { PATH: bin });
  assert.equal(bad.code, 1);
  const j = JSON.parse(bad.out);
  assert.equal(j.tool, 'wardlatch'); assert.equal(j.version, VERSION);
  assert.deepEqual(j.incidents.map((i) => i.id), ['php-2026-10']);
  assert.equal(j.results.length, 1);
  assert.equal(j.results[0].status, 'EXPOSED'); assert.equal(j.results[0].version, '8.4.26'); assert.ok(j.results[0].fix);
  const text = run(['--incident', 'php-2026-10', '--paths', dir], { PATH: bin });
  assert.match(text.out, /EXPOSED {2}php 8\.4\.26/); assert.match(text.out, /fix: Update PHP to 8\.5\.12/);
  const none = run(['--incident', 'php-2026-10', '--paths', dir], { PATH: join(dir, 'empty-path') });
  assert.equal(none.code, 0); assert.match(none.out, /SAFE {5}php not installed/);
});

test('the OVHcloud CLI is never run: a clean file is SAFE, the stealer\'s temp folder is EXPOSED (exit 1)', () => {
  const bin = join(dir, 'ovh'), ran = join(dir, 'ovh-ran'), tmp = join(dir, 'ovh-tmp');
  mkdirSync(bin, { recursive: true }); mkdirSync(tmp, { recursive: true });
  writeFileSync(join(bin, 'ovhcloud'), `#!/bin/sh\ntouch "${ran}"\necho "ovhcloud 0.13.0"\n`, { mode: 0o755 });
  const clean = run(['--incident', 'ovhcloud-cli-2026-10', '--json', '--paths', dir], { PATH: bin, TMPDIR: tmp });
  const j = JSON.parse(clean.out);
  assert.equal(j.results[0].status, 'SAFE'); assert.match(j.results[0].reason, /it was not run/);
  mkdirSync(join(tmp, 'envchecker-1234567890'));
  const hit = run(['--incident', 'ovhcloud-cli-2026-10', '--paths', dir], { PATH: bin, TMPDIR: tmp });
  assert.equal(hit.code, 1);
  assert.match(hit.out, /EXPOSED/); assert.match(hit.out, /envchecker-1234567890/); assert.match(hit.out, /fix: Do not run an ovhcloud binary/);
  assert.equal(existsSync(ran), false, 'wardlatch ran the ovhcloud program');
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

test('options are checked: an unknown option or a missing value is refused with exit code 2, before anything runs', () => {
  for (const [args, msg] of [[['--jsn'], /unknown option "--jsn"/], [['--paths'], /--paths needs a value/], [['--incident', '--json'], /--incident needs a value/], [['extra'], /unknown option "extra"/]]) {
    const r = run(args);
    assert.equal(r.code, 2, args.join(' '));
    assert.match(r.err, msg);
    assert.doesNotMatch(r.err, /TypeError|at file:/, 'a message, not a stack trace');
    assert.equal(r.out, '', 'nothing was checked');
  }
});

test('names from the disk are printed with control characters escaped, so a planted name cannot rewrite the screen', () => {
  // A backdoor plugin folder named to erase its own line ("\x1b[2K" clears the line, "\r" returns to its start).
  const site = join(dir, 'wp2', 'blog'); const evil = 'cache\x1b[2K\r';
  mkdirSync(join(site, 'wp-includes'), { recursive: true }); writeFileSync(join(site, 'wp-includes', 'version.php'), '<?php');
  mkdirSync(join(site, 'wp-content', 'plugins', evil), { recursive: true });
  const r = run(['--incident', 'wordpress-plugins-2026-10', '--paths', join(dir, 'wp2')]);
  assert.match(r.out, /REVIEW {2}.*blog · plugin folder cache\\x1b\[2K\\x0d/);
  assert.ok(!/[\x00-\x09\x0b-\x1f\x7f]/.test(r.out), 'no raw control character reaches the terminal');
  assert.equal(JSON.parse(run(['--incident', 'wordpress-plugins-2026-10', '--json', '--paths', join(dir, 'wp2')]).out).results[0].what, `plugin folder ${evil}`, 'JSON keeps the real name, escaped by JSON itself');
});

test('a repository\'s own .git/config never makes git run a program: fsmonitor, signature checks, diff drivers, filters, hooks', () => {
  // A repository unpacked from an archive or copied from elsewhere keeps its .git/config. This one names a program for
  // every setting that could run one, and each program leaves a marker named after its setting if it ever runs.
  const root = join(dir, 'hostile'), path = join(root, 'repo'), ran = join(dir, 'hostile-ran');
  mkdirSync(ran, { recursive: true }); mkdirSync(join(path, '.github', 'workflows'), { recursive: true });
  const prog = (name) => { const p = join(dir, `hostile-${name}`); writeFileSync(p, `#!/bin/sh\ntouch "${join(ran, name)}"\nexit 1\n`, { mode: 0o755 }); return p; };
  const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' };
  const g = (args, input) => execFileSync('git', ['-C', path, ...args], { env, input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
  const repo = gitRepo(path);
  writeFileSync(join(path, '.gitattributes'), '* diff=planted filter=planted\n');
  writeFileSync(join(path, '.github', 'workflows', 'build.yml'), 'on: push\n'); writeFileSync(join(path, 'app.js'), 'x = 1\n'); repo.commit();
  // a commit carrying a gpgsig header that adds a workflow file, so `git log` shows it and, with log.showSignature,
  // would check its signature with gpg.program
  writeFileSync(join(path, '.github', 'workflows', 'signed.yml'), 'on: push\n'); g(['add', '-A']);
  const now = Math.floor(Date.now() / 1000);
  const body = `tree ${g(['write-tree'])}\nparent ${g(['rev-parse', 'HEAD'])}\nauthor t <t@x> ${now} +0000\ncommitter t <t@x> ${now} +0000\n`
    + 'gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n';
  g(['update-ref', 'HEAD', g(['hash-object', '-t', 'commit', '-w', '--stdin'], body)]);
  for (const [key, name] of [['core.fsmonitor', 'fsmonitor'], ['gpg.program', 'gpg'], ['gpg.ssh.program', 'gpg-ssh'], ['gpg.x509.program', 'gpg-x509'],
    ['diff.external', 'diff-external'], ['diff.planted.command', 'diff-command'], ['diff.planted.textconv', 'textconv'],
    ['filter.planted.clean', 'filter-clean'], ['filter.planted.smudge', 'filter-smudge'], ['core.pager', 'pager']]) g(['config', key, prog(name)]);
  g(['config', 'log.showSignature', 'true']);
  for (const h of ['post-index-change', 'reference-transaction', 'post-checkout', 'pre-auto-gc', 'post-rewrite', 'fsmonitor-watchman']) writeFileSync(join(path, '.git', 'hooks', h), `#!/bin/sh\ntouch "${join(ran, `hook-${h}`)}"\n`, { mode: 0o755 });
  // the test means something: git as 0.1.6 ran it does start the planted programs
  try { execFileSync('git', ['-C', path, 'ls-files', '-z'], { stdio: 'ignore' }); } catch { /* the marker is what counts */ }
  try { execFileSync('git', ['-C', path, 'log', '--all', '--since=2026-09-01', '--diff-filter=A', '--name-only', '--format=@@%h %as %an', '--', '.github/workflows'], { stdio: 'ignore' }); } catch { /* as above */ }
  assert.ok(existsSync(join(ran, 'fsmonitor')), 'ls-files runs core.fsmonitor unless told not to');
  assert.ok(existsSync(join(ran, 'gpg')), 'log runs gpg.program on a signed commit with log.showSignature, unless told not to');
  for (const m of readdirSync(ran)) rmSync(join(ran, m));
  // the real checks over it: they still work, and nothing the config names runs
  const wf = run(['--incident', 'github-actions-2026-10', '--json', '--paths', root]);
  assert.deepEqual(JSON.parse(wf.out).results.map((x) => x.file).sort(), ['.github/workflows/build.yml', '.github/workflows/signed.yml']);
  const keys = run(['--incident', 'committed-keys-2026-10', '--paths', root]);
  assert.match(keys.out, /SAFE {5}no committed keys found in the files of 1 local repository/);
  assert.deepEqual(readdirSync(ran), [], 'a program named in the repository\'s config was run');
});

test('a partial clone is never fetched from: git log would run the program its config names to fetch with', () => {
  // A partial clone fetches missing objects from the remote in its config when a command needs them. A config can make
  // that fetch run a program (remote.<name>.uploadpack here; core.sshCommand for ssh), and any fetch sends a request.
  const srv = join(dir, 'lazy-srv'), root = join(dir, 'lazy'), clone = join(root, 'pc'), marker = join(dir, 'lazy-ran');
  const s = gitRepo(srv);
  for (const n of [1, 2, 3]) { mkdirSync(join(srv, '.github', 'workflows'), { recursive: true }); writeFileSync(join(srv, '.github', 'workflows', `w${n}.yml`), `on: push # ${n}\n`); mkdirSync(join(srv, `d${n}`), { recursive: true }); writeFileSync(join(srv, `d${n}`, 'f'), `${n}\n`); s.commit(); }
  execFileSync('git', ['-C', srv, 'config', 'uploadpack.allowFilter', 'true']);
  execFileSync('git', ['-c', 'protocol.file.allow=always', 'clone', '-q', '--no-local', '--filter=tree:0', `file://${srv}`, clone], { stdio: 'ignore' });
  writeFileSync(join(dir, 'lazy-uploadpack'), `#!/bin/sh\ntouch "${marker}"\nexit 1\n`, { mode: 0o755 });
  execFileSync('git', ['-C', clone, 'config', 'remote.origin.uploadpack', join(dir, 'lazy-uploadpack')]);
  // the test means something: git log as 0.1.6 ran it fetches the older trees, and runs the program to do it
  try { execFileSync('git', ['-C', clone, 'log', '--all', '--since=2026-09-01', '--diff-filter=A', '--name-only', '--format=@@%h', '--', '.github/workflows'], { stdio: 'ignore' }); } catch { /* the fetch fails; the marker is what counts */ }
  assert.ok(existsSync(marker), 'git log fetches missing objects through the configured program'); rmSync(marker);
  const r = run(['--incident', 'github-actions-2026-10', '--json', '--paths', root]);
  assert.equal(existsSync(marker), false, 'wardlatch made git fetch from the partial clone\'s remote');
  // what git can't read without fetching is UNKNOWN, never a clean result (exit 2), and the repository is named
  assert.equal(r.code, 2, r.err);
  assert.deepEqual(JSON.parse(r.out).results.map((x) => [x.kind, x.status, x.repo]), [['workflow', 'UNKNOWN', clone]]);
  assert.match(JSON.parse(r.out).results[0].reason, /^git could not read this repository \(/);
  assert.doesNotMatch(run(['--incident', 'github-actions-2026-10', '--paths', root]).out, /SAFE/);
});

test('a blobless partial clone is read without fetching, and a workflow renamed within the folder is listed', () => {
  // Rename detection compares file contents, which a blobless clone lacks, so with lazy fetching off git log would fail
  // on a workflow renamed and edited in .github/workflows. With --no-renames nothing has to be fetched, and the renamed
  // file is listed as added.
  const srv = join(dir, 'blobless-srv'), root = join(dir, 'blobless'), clone = join(root, 'bc');
  const s = gitRepo(srv), wf = join(srv, '.github', 'workflows');
  mkdirSync(wf, { recursive: true }); writeFileSync(join(wf, 'old.yml'), `on: push\n${'# filler line\n'.repeat(40)}`); s.commit();
  execFileSync('git', ['-C', srv, 'mv', '.github/workflows/old.yml', '.github/workflows/new.yml']);
  writeFileSync(join(wf, 'new.yml'), `on: [push, pull_request]\n${'# filler line\n'.repeat(40)}`); s.commit();
  execFileSync('git', ['-C', srv, 'config', 'uploadpack.allowFilter', 'true']);
  execFileSync('git', ['-c', 'protocol.file.allow=always', 'clone', '-q', '--no-local', '--filter=blob:none', '--no-checkout', `file://${srv}`, clone], { stdio: 'ignore' });
  const r = run(['--incident', 'github-actions-2026-10', '--json', '--paths', root]);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(JSON.parse(r.out).results.map((x) => [x.status, x.file]).sort(), [['REVIEW', '.github/workflows/new.yml'], ['REVIEW', '.github/workflows/old.yml']]);
});

test('npx\'s project folders are dropped from PATH: a project\'s node_modules/.bin git or python3 never runs', () => {
  // npx puts the current project's node_modules/.bin first on PATH; a hostile project could ship its own git.
  const nm = join(dir, 'npxproj', 'node_modules', '.bin'), marker = join(dir, 'npx-ran'); mkdirSync(nm, { recursive: true });
  for (const b of ['git', 'python3', 'node', 'curl']) writeFileSync(join(nm, b), `#!/bin/sh\ntouch "${marker}-${b}"\nexit 1\n`, { mode: 0o755 });
  const root = join(dir, 'npxpath'); const repo = gitRepo(join(root, 'app'));
  mkdirSync(join(root, 'app', '.github', 'workflows'), { recursive: true }); writeFileSync(join(root, 'app', '.github', 'workflows', 'ci.yml'), 'on: push\n'); repo.commit();
  const r = run(['--incident', 'github-actions-2026-10', '--json', '--paths', root], { PATH: `${nm}:relative/bin:${process.env.PATH}` });
  assert.deepEqual(JSON.parse(r.out).results.map((x) => [x.status, x.file]), [['REVIEW', '.github/workflows/ci.yml']], 'the real git ran');
  const { offline } = preloads();
  run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', join(dir, 'nothing-here')], { PATH: `${nm}:${join(dir, 'empty-path')}` }, ['--require', offline]);
  assert.deepEqual(readdirSync(dir).filter((f) => f.startsWith('npx-ran')), [], 'a program from node_modules/.bin ran');
});

test('programs are run from /, with Go\'s toolchain switching off, and PHP without its php.ini or extensions', () => {
  // From a project folder, `go version` reads go.mod and can download and run the newer Go it names; `php -v` loads
  // every extension its php.ini lists. A project folder is where npx usually starts.
  const bin = join(dir, 'recorders'), log = join(dir, 'recorded'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'go'), `#!/bin/sh\necho "go cwd=$(pwd) toolchain=$GOTOOLCHAIN args=$*" >> "${log}"\necho 'go version go1.27.3 darwin/arm64'\n`, { mode: 0o755 });
  writeFileSync(join(bin, 'php'), `#!/bin/sh\necho "php cwd=$(pwd) args=$*" >> "${log}"\necho 'PHP 8.4.27 (cli)'\n`, { mode: 0o755 });
  const project = join(dir, 'a-project'); mkdirSync(project, { recursive: true }); writeFileSync(join(project, 'go.mod'), 'module x\n\ngo 1.99\n\ntoolchain go1.99.0\n');
  const { offline } = preloads();
  run(['--incident', 'emudhra-2026-10', '--no-containers', '--paths', join(dir, 'nothing-here')], { PATH: bin }, ['--require', offline], project);
  run(['--incident', 'php-2026-10', '--paths', join(dir, 'nothing-here')], { PATH: bin }, [], project);
  const lines = readFileSync(log, 'utf8').trim().split('\n');
  assert.ok(lines.some((l) => l.startsWith('go ')), 'go was asked its version'); assert.ok(lines.some((l) => l.startsWith('php ')), 'php was asked its version');
  for (const l of lines) assert.match(l, /^\S+ cwd=\/ /, l);
  for (const l of lines.filter((x) => x.startsWith('go '))) assert.match(l, /toolchain=local /, l);
  for (const l of lines.filter((x) => x.startsWith('php '))) assert.match(l, /args=-n -v$/, l);
});

/**
 * Stand-ins loaded into the command before it starts (node --require), for the checks that would otherwise look at this
 * machine or the network. offline: the Unix paths discover() looks at are missing, and no test host answers, so nothing
 * leaves the machine. win32: offline, on a platform that says win32.
 */
const preloads = () => {
  const offline = join(dir, 'offline.cjs'), win32 = join(dir, 'win32.cjs');
  writeFileSync(offline, `const fs = require('node:fs'), tls = require('node:tls'), { EventEmitter } = require('node:events');
const exists = fs.existsSync;
fs.existsSync = (p) => !/^\\/(usr|etc|opt|bin)\\//.test(String(p)) && exists(p);
tls.connect = () => { const s = new EventEmitter(); s.end = s.destroy = () => {}; process.nextTick(() => s.emit('error', new Error('offline'))); return s; };
require('node:module').syncBuiltinESMExports();
`);
  writeFileSync(win32, `require(${JSON.stringify(offline)});
Object.defineProperty(process, 'platform', { value: 'win32' });
require('node:os').platform = () => 'win32';
require('node:module').syncBuiltinESMExports();
`);
  return { offline, win32 };
};

test('Windows (not supported): the trust check is UNKNOWN, never a silent all-clear, and so are the program checks (exit 2)', () => {
  // On Windows discover() finds nothing to test: it looks for `node`, `curl` and `python3`, and Windows has node.exe,
  // curl.exe and python.exe. Up to 0.1.6 the eMudhra check then printed nothing and exited 0.
  const { offline, win32 } = preloads();
  const env = { PATH: join(dir, 'empty-path') }, where = ['--no-containers', '--paths', join(dir, 'nothing-here')];
  const trust = run(['--incident', 'emudhra-2026-10', '--json', ...where], env, ['--require', win32]);
  assert.equal(trust.code, 2, trust.err);
  assert.deepEqual(JSON.parse(trust.out).results, [{ incident: 'emudhra-2026-10', kind: 'runtimes', status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' }]);
  assert.match(run(['--incident', 'emudhra-2026-10', ...where], env, ['--require', win32]).out, /UNKNOWN {2}not checked on Windows yet \(Windows is not supported\)/);
  for (const id of ['php-2026-10', 'ovhcloud-cli-2026-10']) {
    const r = run(['--incident', id, '--json', ...where], env, ['--require', win32]);
    assert.equal(r.code, 2, id); assert.deepEqual(JSON.parse(r.out).results.map((x) => [x.status, x.reason]), [['UNKNOWN', 'not checked on Windows yet (Windows is not supported)']], id);
  }
  // a container found on Windows must not hide that the machine's own runtimes were not checked
  const eng = join(dir, 'win-engine'); mkdirSync(eng, { recursive: true });
  writeFileSync(join(eng, 'docker'), '#!/bin/sh\nif [ "$1" = ps ]; then printf "abc123\\tweb\\tnginx:latest\\n"; exit 0; fi\nexit 3\n', { mode: 0o755 });
  const withC = run(['--incident', 'emudhra-2026-10', '--json', '--paths', join(dir, 'nothing-here')], { PATH: eng }, ['--require', win32]);
  assert.equal(withC.code, 2, withC.err);
  const wr = JSON.parse(withC.out).results;
  assert.ok(wr.some((x) => x.kind === 'container'), 'the container was checked');
  assert.deepEqual(wr.filter((x) => x.kind === 'runtimes').map((x) => [x.status, x.reason]), [['UNKNOWN', 'the runtimes on this machine were not checked: Windows is not supported yet']]);
  // the OVHcloud stealer's temp folder still reads EXPOSED on Windows: the temp directory is read there too
  const tmpd = join(dir, 'wintmp'); mkdirSync(join(tmpd, 'envchecker-1760900000'), { recursive: true });
  const traced = run(['--incident', 'ovhcloud-cli-2026-10', '--json', ...where], { ...env, TMPDIR: tmpd, TMP: tmpd, TEMP: tmpd }, ['--require', win32]);
  assert.equal(traced.code, 1, traced.err);
  assert.deepEqual(JSON.parse(traced.out).results.map((x) => x.status), ['EXPOSED']);
  // elsewhere, finding no runtime at all is UNKNOWN too, with its own reason
  const none = run(['--incident', 'emudhra-2026-10', '--json', ...where], env, ['--require', offline]);
  assert.equal(none.code, 2, none.err);
  assert.deepEqual(JSON.parse(none.out).results.map((x) => [x.kind, x.status, x.reason]), [['runtimes', 'UNKNOWN', 'no runtime was found to test']]);
});

test('a container engine that hangs or fails is UNKNOWN (exit 2), never "not running"; a stopped daemon stays a note', () => {
  // Up to 0.1.6 every failure but "permission denied" read as "not running", so a hung Docker Desktop let the eMudhra
  // check end all SAFE (exit 0) with its running containers never checked.
  const { offline } = preloads();
  const engine = (name, body) => { const d = join(dir, `engine-${name}`); mkdirSync(d, { recursive: true }); writeFileSync(join(d, 'docker'), `#!/bin/sh\n${body}\n`, { mode: 0o755 }); return d; };
  const trust = (path, json = true) => run(['--incident', 'emudhra-2026-10', ...(json ? ['--json'] : []), '--paths', join(dir, 'nothing-here')], { PATH: path }, ['--require', offline]);
  const rows = (r) => JSON.parse(r.out).results.filter((x) => x.kind === 'containers').map((x) => [x.engine, x.status, x.reason]);
  const hung = trust(engine('hung', 'exec /bin/sleep 30'));
  assert.equal(hung.code, 2); assert.deepEqual(rows(hung), [['docker', 'UNKNOWN', 'did not answer within 10 seconds: restart it and run again, or pass --no-containers to skip running containers']]);
  const failing = trust(engine('failing', 'echo \'error during connect: Get "http://%2F%2F.%2Fpipe%2Fdocker_engine/v1.47/containers/json": EOF\' >&2; exit 1'));
  assert.equal(failing.code, 2); assert.match(rows(failing)[0]?.[2] ?? '', /^could not list its containers \(error during connect: Get /);
  const stopped = engine('stopped', "echo 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?' >&2; exit 1");
  assert.deepEqual(rows(trust(stopped)), [], 'a daemon that is not running has no containers to check');
  assert.match(trust(stopped, false).out, /docker: not running, so no running containers to check/);
});
