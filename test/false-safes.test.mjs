// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// THE RULE THAT DISCRIMINATES, 29 October 2026.
//
// On one Mac, `--incident wordpress-plugins-2026-10 --paths ~` reported 311 folders as untested and 0 safe, and
// `--incident github-actions-2026-10 --paths ~` reported 50. Measured: 310 of the 311 were links that every one
// resolve into a tree the same run had already walked, and 49 of the 50 were READABLE folders (~/.config, ~/.ssh,
// ~/.claude, ~/.local, ~/.gnupg) that lib/workflows.mjs chose not to walk and then reported through the channel whose
// consumers print "could not be opened, so it was not searched: run Wardlatch with sudo" — a sentence that was false
// and an instruction that could not work. The real gaps were buried under 359 false ones, which is how UNKNOWN becomes
// the footnote nobody reads and a tool that always exits 2 teaches people `|| true`.
//
// The fix replaces four name lists with one measured predicate (lib/files.mjs mandatoryRefusal; the measurement is
// test/support/errno-mechanisms.mjs). Its whole value is that it DISCRIMINATES, so these three tests are the ones that
// matter most: each stands in front of a named past failure, and each fails on the shape before the fix.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, readdirSync, statSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mandatoryRefusal, fileId, realPath } from '../lib/files.mjs';
import { isPersonUid } from '../lib/owners.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
const locked = [], acls = [];
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-false-safes-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => {
  for (const p of acls) { try { execFileSync('chmod', ['-N', p], { stdio: 'pipe' }); } catch { /* gone, or no ACL */ } }
  for (const p of locked) { try { chmodSync(p, 0o755); } catch { /* gone */ } }
  rmSync(dir, { recursive: true, force: true });
});

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const lock = (p) => { chmodSync(p, 0o000); locked.push(p); };
const run = (args, env = {}) => {
  const r = spawnSync(process.execPath, [BIN, ...args, '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
  let rows; try { rows = JSON.parse(r.stdout).results; } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stderr.slice(0, 600)}`); }
  return { code: r.status, rows };
};
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');
const skippedRow = (r) => r.rows.find((x) => x.kind === 'skipped');

// ---- 1. the hiding place stays caught --------------------------------------------------------------------------------
// FAILS ON THE OLD SHAPE. `.Trash` was on lib/workflows.mjs's TOOL_CACHES list, so the workflow and key checks stepped
// over it without a word, whatever was inside and whatever its permissions: `mkdir .Trash` in a project hid a whole
// tree from both, and the run read SAFE, exit 0. That is AUDIT-5 half fixed — the name gate came out of
// isSystemFolder() and stayed in workflows.mjs. Both lists are gone, and a chmod 000 folder is EACCES: a lock the
// owner chose, which anyone can set, so it is NOT a mandatory refusal and must stay could-not-be-tested.
test('a chmod 000 folder the person owns is could-not-be-tested and exits 2, under a dot-name or a plain one',
  { skip: AS_ROOT && 'root opens every folder' }, () => {
    const root = fresh('h1-root');
    const dot = join(root, '.Trash'), plain = join(root, 'shut');
    for (const p of [dot, plain]) { put(join(p, 'inside', 'keep.txt'), 'x'); lock(p); }
    for (const id of ['github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
      const r = run(['--incident', id, '--paths', root]);
      for (const p of [dot, plain]) {
        assert.ok(unknowns(r).some((x) => x.path === p), `${id}: ${p} is EACCES and must be UNKNOWN: ${JSON.stringify(r.rows)}`);
        assert.ok(!skippedRow(r)?.paths?.includes(p), `${id}: ${p} must not ride in the channel that keeps the exit code at 0`);
      }
      assert.equal(r.code, 2, id);
    }
    // and the predicate itself refuses it, whatever errno it is handed
    assert.equal(mandatoryRefusal(dot, 'EACCES'), false);
    assert.equal(mandatoryRefusal(plain, 'EACCES'), false);
  });

// ---- 2. a deny ACL is not macOS's refusal ----------------------------------------------------------------------------
// The subtle forgery, and the reason the rule cannot be read off the mode bits alone: a deny ACL shuts a folder while
// leaving its mode looking open, so `ls -ld` shows 0755 and the read still fails. Measured on this machine (see
// test/support/errno-mechanisms.mjs): it gives EACCES, not EPERM. If it gave EPERM the whole rule would be unsound,
// because then an attacker could put their own folder into the channel that does not change the exit code.
// FAILS ON THE OLD SHAPE for the same reason as test 1: under the name `.Trash` the workflow check never looked.
test('a folder shut with a deny ACL (mode still 0755) is could-not-be-tested and exits 2',
  { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS, as a user' }, (t) => {
    const root = fresh('h2-root'), shut = join(root, '.Trash');
    put(join(shut, 'inside', 'keep.txt'), 'x');
    const who = execFileSync('id', ['-un'], { encoding: 'utf8' }).trim();
    // `deny read,list,search` and NOT readattr: measured on this machine to deny readdir while leaving stat working,
    // so the mode bits a reader would check still say 0755 while the folder cannot be listed. That is the whole point
    // of this test — the rule cannot be read off the mode bits alone, and must turn on the errno.
    try { execFileSync('chmod', ['+a', `${who} deny read,list,search`, shut], { stdio: 'pipe' }); } catch { return t.skip('this file system does not take ACLs'); }
    acls.push(shut); locked.push(shut);
    let code = null; try { readdirSync(shut); } catch (e) { code = e.code; }
    if (code === null) return t.skip('the ACL did not deny the read on this file system');
    // the premise, stated: the mode bits look open, and the errno is NOT the one that cannot be forged
    assert.equal(statSync(shut).mode & 0o777, 0o755, 'premise: the mode still looks open');
    assert.equal(code, 'EACCES', 'premise: an ACL denial is EACCES, not EPERM');
    assert.equal(mandatoryRefusal(shut, code), false, 'an ACL anyone can set is not macOS protecting a folder');
    const r = run(['--incident', 'github-actions-2026-10', '--paths', root]);
    assert.ok(unknowns(r).some((x) => x.path === shut), JSON.stringify(r.rows));
    assert.ok(!skippedRow(r)?.paths?.includes(shut), 'a forgeable denial must not keep the exit code at 0');
    assert.equal(r.code, 2);
  });

// ---- 3. the real article: a refusal from above the permission bits is could-not-be-tested ----------------------------
// REVERSED 31 Oct 2026 by owner decision #32 ("Yes, UNKNOWN"): any folder Wardlatch could not open, EPERM included, is
// UNKNOWN with exit 2, never SAFE. This test demanded the opposite — a stated gap in the REVIEW line beside the
// all-clear, exit 0 — on the claim that EPERM cannot be forged without root. The independent read of da8f5c2 built
// that EPERM with an unprivileged sandbox-exec profile and turned a real EXPOSED ×2, exit 1 into SAFE, exit 0 with it.
// The fixture is kept: a REAL folder on this machine that the system refuses with EPERM (on this Mac, one System
// Integrity Protection guards under /private/var/db), found at run time and skipped when there is none, in the style
// of serviceLockedRoot() in test/release-0.1.9.test.mjs. Not the real ~/Pictures/*.photoslibrary: the tests' safety
// net (support/no-real-home.cjs) refuses to let a test read the real home, correctly. test/independent-read.test.mjs
// builds the same refusal with a sandbox profile, the way the independent read did.
const mandatoryRefusalRoot = () => {
  // mirrors reposUnder(root, 4): a parent whose subtree holds at least one mandatory refusal, no person-owned denial
  // (which would be UNKNOWN and exit 2) and no link leaving what the walk listed (likewise UNKNOWN)
  const assess = (root) => {
    const mandatory = [], person = [], listed = new Set(), links = [];
    const GONE = ['ENOENT', 'ENOTDIR', 'ENAMETOOLONG', 'ELOOP'];
    const walk = (d, depth) => {
      if (depth < 0) return;
      let ents;
      try { ents = readdirSync(d, { withFileTypes: true }); } catch (e) {
        if (GONE.includes(e.code) || d === root) { if (!GONE.includes(e.code)) person.push(d); return; }
        if (mandatoryRefusal(d, e.code)) { mandatory.push(d); return; }
        let uid = null; try { uid = statSync(d).uid; } catch { /* cannot tell */ }
        if (isPersonUid(uid, 'workflow')) person.push(d);
        return;
      }
      const id = fileId(d); if (id) listed.add(id);
      for (const e of ents) {
        const p = join(d, e.name);
        if (e.isSymbolicLink()) { let st; try { st = statSync(p); } catch { continue; } if (st.isDirectory()) links.push(p); continue; }
        if (e.isDirectory()) walk(p, depth - 1);
      }
    };
    walk(root, 4);
    const escaping = links.filter((p) => { const id = fileId(realPath(p) ?? p); return !(id && listed.has(id)); });
    return { mandatory, clean: mandatory.length > 0 && person.length === 0 && escaping.length === 0 };
  };
  for (const base of ['/private/var/protected', '/private/var/db', '/private/var', '/Library']) {
    let ents; try { ents = readdirSync(base, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const p = join(base, e.name);
      let a; try { a = assess(p); } catch { continue; }
      if (a.clean) return { root: p, gap: a.mandatory[0] };
    }
  }
  return null;
};

test('a folder the system refuses with EPERM is could-not-be-tested with its basis, exit 2, never a stated gap beside an all-clear',
  { skip: (process.platform !== 'darwin' || AS_ROOT) && 'macOS, as a user (root is never refused by DAC)' }, (t) => {
    const found = mandatoryRefusalRoot();
    if (!found) return t.skip('no folder macOS refuses, without a person-owned denial beside it, on this machine');
    const { root, gap } = found;
    const r = run(['--incident', 'github-actions-2026-10', '--paths', root]);

    // its own UNKNOWN row, never the channel that keeps the exit code at 0
    const row = unknowns(r).find((x) => x.path === gap);
    assert.ok(row, `expected an UNKNOWN row for ${gap}: ${JSON.stringify(r.rows)}`);
    assert.ok(!skippedRow(r)?.paths?.includes(gap), `${gap} must not ride in the stated-gap line: ${JSON.stringify(skippedRow(r))}`);

    // THE BASIS: the errno and the mode, which a reader checks with one `ls -ld`, in --json and in the sentence
    assert.equal(row.code, 'EPERM');
    assert.match(row.basis, /^EPERM, mode 0[0-7]{3}, owner /, `the basis must be checkable: ${row.basis}`);
    assert.match(row.reason, /EPERM, mode 0[0-7]{3}, owner /, 'and it is in the reason, not only in --json');
    // and it never claims to know what refused: a sandbox around the run gives the same EPERM
    assert.doesNotMatch(row.reason, /macOS is protecting|sudo cannot open/, row.reason);

    // no all-clear beside a folder that was not searched, and exit 2
    assert.deepEqual(r.rows.filter((x) => x.status === 'SAFE'), [], `no all-clear: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 2);

    // and a root given with --paths is NEVER a stated gap, whatever its errno: the person asked about it by name
    const direct = run(['--incident', 'github-actions-2026-10', '--paths', gap]);
    assert.ok(unknowns(direct).some((x) => x.path === gap), `a --paths root that cannot be opened is UNKNOWN: ${JSON.stringify(direct.rows)}`);
    assert.equal(direct.code, 2);
  });

// ---- 4. the 359 false gaps, held down ---------------------------------------------------------------------------------
// The two measurements this branch exists for, as fixtures rather than as one machine's home folder.
test('a link into a folder the same walk already listed is not a gap', () => {
  const root = fresh('h4-root');
  mkdirSync(join(root, 'store', 'thing'), { recursive: true });
  writeFileSync(join(root, 'store', 'thing', 'f.txt'), 'x');
  // the shape of ~/.cache/uv/wheels-vN -> ~/.cache/uv/archive-v0: a tree of links into a tree we walk
  mkdirSync(join(root, 'links'), { recursive: true });
  for (let i = 0; i < 5; i++) execFileSync('ln', ['-s', join(root, 'store', 'thing'), join(root, 'links', `l${i}`)]);
  // and one that leaves the walked set, which must still be reported
  const outside = fresh('h4-outside'); writeFileSync(join(outside, 'f.txt'), 'x');
  execFileSync('ln', ['-s', outside, join(root, 'links', 'away')]);
  for (const id of ['github-actions-2026-10', 'wordpress-plugins-2026-10']) {
    const r = run(['--incident', id, '--paths', root]);
    const paths = unknowns(r).map((x) => x.path);
    for (let i = 0; i < 5; i++) assert.ok(!paths.includes(join(root, 'links', `l${i}`)), `${id}: a link into a folder this walk listed is not a gap: ${JSON.stringify(paths)}`);
    assert.ok(paths.includes(join(root, 'links', 'away')), `${id}: a link that leaves the walked set is still a gap: ${JSON.stringify(paths)}`);
  }
});

test('a readable dot-folder is walked, and never reported as one that could not be opened', () => {
  // the 49: ~/.config, ~/.ssh, ~/.claude, ~/.local, ~/.gnupg are all readable, and lib/workflows.mjs reported every
  // one of them through the "could not be opened ... run Wardlatch with sudo" channel without trying to open it
  const root = fresh('h5-root');
  for (const name of ['.config', '.ssh', '.claude', '.local', '.gnupg', '.worktrees']) writeFileSync(join(fresh(`h5-root/${name}`), 'f.txt'), 'x');
  for (const id of ['github-actions-2026-10', 'committed-keys-2026-10']) {
    const r = run(['--incident', id, '--paths', root]);
    assert.equal(unknowns(r).length, 0, `${id}: a readable folder must produce no row at all: ${JSON.stringify(r.rows)}`);
    assert.ok(!skippedRow(r), `${id}: nor a review line: ${JSON.stringify(r.rows)}`);
    assert.equal(r.code, 0, id);
  }
  // and a repository in a dot-folder is now FOUND, where the name list hid it (AUDIT-4)
  const repo = join(root, '.worktrees', 'app');
  mkdirSync(repo, { recursive: true });
  for (const [k, v] of [['user.email', 'nobody@example.invalid'], ['user.name', 'Test'], ['commit.gpgsign', 'false']]) {
    execFileSync('git', ['init', '-q', '-b', 'main', repo], { stdio: 'pipe' });
    execFileSync('git', ['-C', repo, 'config', k, v], { stdio: 'pipe' });
  }
  writeFileSync(join(repo, 'k.py'), 'k = "AKIA' + 'IOSFODNN7ZXAMPLQ"\n');
  execFileSync('git', ['-C', repo, 'add', '-A'], { stdio: 'pipe' });
  execFileSync('git', ['-C', repo, 'commit', '-qm', 'one'], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_DATE: '2026-10-10T00:00:00Z', GIT_COMMITTER_DATE: '2026-10-10T00:00:00Z' } });
  const r = run(['--incident', 'committed-keys-2026-10', '--paths', root]);
  assert.ok(r.rows.some((x) => x.status === 'REVIEW' && x.repo === repo), `a repository in a dot-folder must be read, not skipped by its name: ${JSON.stringify(r.rows)}`);
});
