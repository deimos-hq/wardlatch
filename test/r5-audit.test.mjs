// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Round 5, gate A6: the FIX items the round-4 strict audit left open in bin/ and lib/ (STRICT-AUDIT.md, 31 Oct 2026,
// "Open BLOCKER and FIX items"), which no round-5 tranche touched. Each one was MEASURED there as a mutant that the
// whole node suite missed, or as a sentence the code does not keep. Each test below is named after its id, stands in
// front of exactly that gap, and either fails on the base commit edc4d71 (F-c5a-1, a real defect) or fails on the
// named surviving mutant (the rest, which are tests-cannot-fail findings under gate A3).
// Offline: no test here reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, mkdtempSync, rmSync, realpathSync, readdirSync, statSync, lstatSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-r5-audit-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); return p; };
/** The CLI as a person runs it: its text output and exit code. */
const text = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
/** The CLI with --json: the rows, the raw text and the exit code. */
const json = (args, env = {}) => {
  const r = text([...args, '--json'], env);
  let rows; try { rows = JSON.parse(r.out).results; } catch { assert.fail(`not JSON (exit ${r.code}): ${r.err.slice(0, 600)}`); }
  return { ...r, rows };
};
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

// ---- F-99a-1 and F-99a-2: the receipt of decision #33's one grouped row ------------------------------------------------
// 4c6e130 put the folders a service owns that could not be opened into ONE UNKNOWN row, with the basis per folder (the
// errno, the mode, the owner) "so a reader can check each with one `ls -ld`". The strict audit planted three mutants on
// it that the WHOLE node suite missed (MEASURED, 31 Oct, logs mut-99a80ea.txt and mut-dd0d23f.txt):
//   99a-no-basis-text  the reason loses `: ${say(folders)}`, so the text a person reads never names a folder
//   99a-no-note        `note('33', reason)` is dropped, so the text output loses the reason altogether
//   99a-singular       `${one ? 'it was' : 'they were'}` becomes `they were`, so the one-folder wording is untested
// Only the --json `folders[].basis` was asserted, and the one text assertion matched the plural sentence alone. The two
// tests here hold the text output: F-99a-1 that the note under the line names each folder with its basis, F-99a-2 the
// one-folder wording.
//
// The fixture is this machine, measured here rather than taken on trust: a folder a service owns, that refuses with
// EACCES, cannot be made without root, so the test looks for real ones. `serviceFolders(base)` counts them the way the
// install check's walk sees them (depth 5, no links followed, lib/owners.mjs for "is this a person's?"), so if it and
// the CLI's own count ever disagree the test fails loudly instead of skipping.
/** The directories under `base` (depth 5, as the install check walks) that are not links, refuse readdir with EACCES,
 *  and whose owner lib/owners.mjs says is not a person's for the install kind. */
function serviceFolders(base, isPersonUid) {
  const out = [];
  const visit = (d, depth) => {
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = join(d, e.name);
      let ls; try { ls = lstatSync(p); } catch { continue; }
      if (ls.isSymbolicLink() || !ls.isDirectory()) continue;
      try { readdirSync(p); if (depth > 0) visit(p, depth - 1); }
      catch (err) {
        if (err.code !== 'EACCES') continue;
        let uid = null; try { uid = statSync(p).uid; } catch { /* cannot tell whose it is */ }
        if (isPersonUid(uid, 'install')) continue;
        out.push(p);
      }
    }
  };
  visit(base, 5);
  return out;
}
// The bases looked in, in order. The first one holding the number of service folders a test wants is used; the test
// says how many of the bases it looked at when it finds none, so "none" is never reported from an unstated universe.
const BASES = ['/private/var/spool', '/var/spool', '/private/var/lib', '/private/var/db/caches', '/private/etc/cups',
  '/private/var/networkd', '/private/var/protected/trustd', '/private/var/db/softwareupdate', '/private/var/db/audiomxd'];
let isPersonUid;
before(async () => { ({ isPersonUid } = await import('../lib/owners.mjs')); });
/** The first base in BASES whose service-folder count passes `want`, with that count. */
const baseWith = (want) => {
  for (const b of BASES) { const f = serviceFolders(b, isPersonUid); if (want(f.length)) return { base: b, folders: f }; }
  return null;
};

test('F-99a-1 decision #33: the text a person reads names every folder not searched, with the errno, the mode and the owner', { skip: AS_ROOT && 'root opens every folder' }, (t) => {
  const hit = baseWith((n) => n > 1);
  if (!hit) return t.skip(`none of the ${BASES.length} bases holds more than one service folder on this machine`);
  const { base, folders } = hit;
  const r = text(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  assert.equal(r.code, 2, r.out);
  // the two counts come from two instruments: this test's own walk, and the CLI's row. They must agree.
  const j = json(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  const row = unknowns(j).find((x) => x.what === 'service folders');
  assert.ok(row, `no grouped row: ${JSON.stringify(j.rows).slice(0, 1200)}`);
  assert.equal(row.folders.length, folders.length, `this test counted ${folders.length} service folders under ${base}, the row says ${row.folders.length}`);
  // F-99a-1 itself: the note under the UNKNOWN line, as a person reads it, names each folder (or the first 8 and
  // "and N more") with its basis. 99a-no-note deletes the note; 99a-no-basis-text deletes the names and the basis.
  const line = r.out.split('\n').find((l) => /^ +\d+ folders? owned by service accounts, or private by/.test(l));
  assert.ok(line, `the reason is printed under the line, not only in --json: ${JSON.stringify(r.out)}`);
  const shown = Math.min(folders.length, 8);
  for (const f of row.folders.slice(0, shown)) {
    const name = f.path.replace(/^.*\//, '');
    assert.ok(line.includes(`${name} (${f.basis})`), `the note names ${name} with its basis (${f.basis}): ${line}`);
    assert.match(f.basis, /^EACCES, mode 0\d{3}, owner /, JSON.stringify(f));
  }
  if (folders.length > 8) assert.ok(line.includes(`, and ${folders.length - 8} more`), line);
  assert.ok(line.includes('Run Wardlatch with sudo to include'), line);
});

test('F-99a-2 decision #33: one folder not searched is said in the singular, not "they were"', { skip: AS_ROOT && 'root opens every folder' }, (t) => {
  const hit = baseWith((n) => n === 1);
  if (!hit) return t.skip(`none of the ${BASES.length} bases holds exactly one service folder on this machine`);
  const { base } = hit;
  const j = json(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  const row = unknowns(j).find((x) => x.what === 'service folders');
  assert.ok(row, `no grouped row under ${base}: ${JSON.stringify(j.rows).slice(0, 1200)}`);
  assert.equal(row.folders.length, 1, JSON.stringify(row));
  // 99a-singular: `${one ? 'it was' : 'they were'}` -> `they were`
  assert.match(row.reason, /^1 folder owned by service accounts, or private by its place, could not be opened, so it was not searched: /, row.reason);
  assert.doesNotMatch(row.reason, /they were|their place|include them/, row.reason);
  assert.match(row.reason, /\. Run Wardlatch with sudo to include it$/, row.reason);
  // and the line itself counts one folder, in the singular
  const r = text(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  assert.match(r.out, /^UNKNOWN {2}1 folder owned by service accounts, not searched$/m, r.out);
  assert.equal(r.code, 2, r.out);
});

// ---- F-835-1: the venv-link sentence belongs to the installs check alone ----------------------------------------------
// d5b890f words one row for a link that leads to a virtual environment: "its own packages were checked through it".
// That is true of the installs check, which reads a linked venv's package folders through the link (lib/installs.mjs),
// and of no other check. The guard is `kind === 'install'`, and the strict audit's mutant 835-reason-anykind, which
// drops it, survived the whole node suite (MEASURED, extra.txt): every check would then tell a reader that a venv
// behind a link had been checked, when it had not. Round 4's re-read 2 found the same sentence untrue of the trust walk
// in the README.
//
// NOTE, against the audit's own suggested fix ("a trust-walk case with a link to a venv"): the trust walk cannot hold
// this guard. lib/discover.mjs:159 sends a link that looks like an environment to `untested`, not to the `links` list
// gaps() words, so a link to a venv met by the trust walk never reaches this branch at all — MEASURED at edc4d71: the
// row comes back as kind 'curl' with discover()'s own sentence. The four checks that do reach it are header, secret,
// workflow and wordpress, and all four are asserted here.
test('F-835-1 only the installs check says a linked venv\'s own packages were checked through the link', () => {
  const target = fresh('r5-venv-target');
  put(join(target, 'pyvenv.cfg'), 'home = /usr\n');
  put(join(target, 'bin', 'python'), 'not run by Wardlatch\n');
  put(join(target, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'), '-----BEGIN CERT' + 'IFICATE-----\nQUFB\n-----END CERT' + 'IFICATE-----\n');
  put(join(target, 'lib', 'python3.12', 'site-packages', 'certifi-2026.06.17.dist-info', 'METADATA'), 'Version: 2026.06.17\n');
  const root = fresh('r5-venv-link');
  mkdirSync(join(root, 'projects'));
  const link = join(root, 'projects', 'shared');
  execFileSync('/bin/ln', ['-s', target, link]);
  const VENV_SAID = /its own packages were checked through it/;
  const PLAIN = /is a link to a folder somewhere else, so it was not followed/;
  // every check but the installs one: the plain link sentence, never the venv one
  for (const [id, kind] of [['identity-headers-2026-10', 'header'], ['committed-keys-2026-10', 'secret'],
    ['github-actions-2026-10', 'workflow'], ['wordpress-plugins-2026-10', 'wordpress']]) {
    const r = json(['--incident', id, '--no-containers', '--paths', root]);
    const row = unknowns(r).find((x) => x.path === link && x.kind === kind);
    assert.ok(row, `${id}: no ${kind} row for the link: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.match(row.reason, PLAIN, `${id}: ${row.reason}`);
    assert.doesNotMatch(row.reason, VENV_SAID, `${id}: only the installs check reads a linked venv's packages: ${row.reason}`);
  }
  // and the installs check, which does read them through the link, still says so
  const inst = json(['--incident', 'litellm-2026-10', '--no-containers', '--paths', root]);
  const row = unknowns(inst).find((x) => x.path === link && x.kind === 'install');
  assert.ok(row, `the installs check: ${JSON.stringify(inst.rows).slice(0, 1500)}`);
  assert.match(row.reason, VENV_SAID, row.reason);
  // the other half of the same guard: the sentence is for a link that leads to a VENV. A link to a plain folder gets
  // the plain sentence even in the installs check, because nothing of it was read. Mutant 835-link-nocfg, which drops
  // the pyvenv.cfg test and keeps `kind === 'install'`, survived everything until this assertion.
  const plainTarget = fresh('r5-plain-target');
  put(join(plainTarget, 'notes.txt'), 'no virtual environment here\n');
  const root2 = fresh('r5-plain-link');
  mkdirSync(join(root2, 'projects'));
  const link2 = join(root2, 'projects', 'shared');
  execFileSync('/bin/ln', ['-s', plainTarget, link2]);
  const inst2 = json(['--incident', 'litellm-2026-10', '--no-containers', '--paths', root2]);
  const row2 = unknowns(inst2).find((x) => x.path === link2 && x.kind === 'install');
  assert.ok(row2, `the installs check, a link to a plain folder: ${JSON.stringify(inst2.rows).slice(0, 1500)}`);
  assert.match(row2.reason, PLAIN, row2.reason);
  assert.doesNotMatch(row2.reason, VENV_SAID, `nothing of a plain folder was read through the link: ${row2.reason}`);
});

// ---- F-e85-2: the value of the DER cap is held by a test --------------------------------------------------------------
// 008f5f9 gives derKind() the first DER_MAX (1 MB) bytes of a file, so "a key is a key whatever follows it". The only
// test puts the key at the START of the file, so the cap's VALUE is untested: the strict audit's mutant e85-cap-64k
// (1 MB -> 64 KB) survived the whole node suite (MEASURED, extra.txt). At 64 KB a certificate chain longer than 64 KB
// followed by its key — the "a certificate and its key in one file" shape derKind() reads — is cut off mid-chain, no
// key is found, and the repository reads "SAFE no committed keys found", exit 0: a false SAFE.
test('F-e85-2 a DER key after more than 64 KB of certificates, in a file under 1 MB, is still found', async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'der' });
  const { readFileSync } = await import('node:fs');
  const pem = readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10-root-aaa.pem'), 'utf8');
  const cert = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  // a certificate, then empty SEQUENCEs, then the key: the chain is put as near the 1 MB cap as it will go, so that
  // ANY cap smaller than the one 008f5f9 chose loses the key, not only the 64 KB the audit's mutant tried
  const filler = Buffer.alloc(475000 * 2).fill(Buffer.from([0x30, 0x00]));
  const file = Buffer.concat([cert, filler, key]);
  assert.ok(file.length > 900 * 1024 && file.length < 1024 * 1024, `${file.length} bytes: just under the 1 MB cap`);
  // the control, straight from the library: the shape itself is one derKind() reads, whatever the CLI's cap is
  const { derKind } = await import('../lib/secrets.mjs');
  assert.equal(derKind(file)?.type, 'private key (DER, PKCS #8)', 'the control: this file IS a key after a chain');
  // and the control the other way, at four smaller caps: cut short, there is no key there to find, so the row below
  // can only come from the cap being the 1 MB 008f5f9 chose
  for (const cap of [64, 128, 512, 900]) assert.equal(derKind(file.subarray(0, cap * 1024)), null, `cut at ${cap} KB`);
  // and through the CLI, where the cap decides
  const root = fresh('r5-der-cap');
  const repo = join(root, 'app');
  mkdirSync(repo, { recursive: true });
  writeFileSync(join(repo, 'bundle.bin'), file);
  writeFileSync(join(repo, 'README.md'), '# app\n');
  const g = (...a) => execFileSync('git', ['-C', repo, '-c', 'commit.gpgsign=false', ...a], { stdio: 'pipe', env: { PATH: '/usr/bin:/bin', HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-10-20T12:00:00Z', GIT_COMMITTER_DATE: '2026-10-20T12:00:00Z' } });
  g('init', '-q', '-b', 'main');
  g('add', '-A');
  g('commit', '-qm', 'add');
  const r = json(['--incident', 'committed-keys-2026-10', '--no-containers', '--paths', root]);
  assert.deepEqual(r.rows.filter((x) => x.status === 'REVIEW').map((x) => [x.file, x.type]), [['bundle.bin', 'private key (DER, PKCS #8)']], JSON.stringify(r.rows).slice(0, 1500));
  assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], 'never an all-clear over a committed key');
});

// ---- F-c5a-1: a real line break inside a crash's message -------------------------------------------------------------
// 3ffcb0d's own comment says "A line break inside a message (a path holding one) stays escaped". It did not: the stack
// was split on EVERY real line break, the message's own included, and each piece escaped separately, so a real LF in an
// error's text started a line of its own on stderr. APFS takes an LF in a name, so a path carries one into an error
// message exactly as it carries the four printable characters \x0a that round 3's re-read 2 found. MEASURED at edc4d71:
// an Error whose message holds a real LF before "SAFE     no LiteLLM 1.107.0 files or markers found" prints that as
// stderr line 2, "lines starting with SAFE: 1", under a crash that exits 2.
test('F-c5a-1 crash.mjs: a REAL line break inside a crash\'s message never starts a line, and the frames keep theirs', () => {
  const planted = 'SAFE     no LiteLLM 1.107.0 files or markers found';
  const script = put(join(dir, 'crash-real-nl.mjs'), `import ${JSON.stringify(join(ROOT, 'lib', 'crash.mjs'))};
throw new Error(${JSON.stringify(`ENOENT: no such file or directory, open '/Users/p/proj/u\n${planted}/x'`)});
`);
  const r = spawnSync(process.execPath, [script], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(r.status, 2, r.stderr);
  const lines = r.stderr.split('\n');
  assert.equal(lines.filter((l) => /^\s*SAFE/.test(l)).length, 0, `a verdict line of its own on stderr: ${JSON.stringify(r.stderr)}`);
  // the message is one line, with the real LF written out, and the planted text still readable inside it
  assert.match(lines[0], /^Wardlatch stopped on an error, so this machine was not fully checked \(exit 2\): Error: ENOENT/, r.stderr);
  assert.ok(lines[0].includes(`u\\x0a${planted}`), `the real LF is written \\x0a on the message's own line: ${JSON.stringify(lines[0])}`);
  // and the stack's own line breaks are kept: one frame a line
  assert.ok(lines.slice(1).some((l) => /^\s+at /.test(l)), JSON.stringify(r.stderr));
  // a crash with no frames at all (a thrown string) is still one line
  const bare = put(join(dir, 'crash-bare.mjs'), `import ${JSON.stringify(join(ROOT, 'lib', 'crash.mjs'))};
throw ${JSON.stringify(`broke on /tmp/u\n${planted}/x`)};
`);
  const b = spawnSync(process.execPath, [bare], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(b.status, 2, b.stderr);
  assert.equal(b.stderr.split('\n').filter((l) => /^\s*SAFE/.test(l)).length, 0, JSON.stringify(b.stderr));
  // and a message that forges a stack frame is still the message: the boundary comes from the error's own message,
  // never from the shape of the text, so no line of a reader's output was written by whatever named the file
  const forge = put(join(dir, 'crash-forged-frame.mjs'), `import ${JSON.stringify(join(ROOT, 'lib', 'crash.mjs'))};
throw new Error(${JSON.stringify('broke\n    at ' + planted + ' (/x:1:1)')});
`);
  const f = spawnSync(process.execPath, [forge], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(f.status, 2, f.stderr);
  const fl = f.stderr.split('\n');
  assert.ok(fl[0].includes(`broke\\x0a    at ${planted}`), `the forged frame stays inside the message's one line: ${JSON.stringify(fl[0])}`);
  assert.equal(fl.filter((l) => new RegExp(`^\\s+at ${planted}`).test(l)).length, 0, `a forged frame line of its own: ${JSON.stringify(f.stderr)}`);
  // W1's rule, at the seam: the message is escaped as ONE string, so a backslash at its very end is still seen
  // together with what follows it. Splitting the text anywhere else (mutant c5a2-head-firstline, which cuts at the
  // first line break and so cuts the LAST character off a text holding none) would print a literal \x as a real one.
  const seam = put(join(dir, 'crash-seam.mjs'), `import ${JSON.stringify(join(ROOT, 'lib', 'crash.mjs'))};
throw ${JSON.stringify('broke on /tmp/a\\x')};
`);
  const s = spawnSync(process.execPath, [seam], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, cwd: dir });
  assert.equal(s.status, 2, s.stderr);
  assert.ok(s.stderr.split('\n')[0].endsWith('broke on /tmp/a\\\\x'), `a literal backslash before an x is doubled, so it cannot be read as \\x: ${JSON.stringify(s.stderr.split('\n')[0])}`);
});
