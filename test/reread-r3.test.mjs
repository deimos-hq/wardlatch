// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Round 3's three independent re-reads of fix/false-safes at f62f9ba (31 Oct 2026) all said NOT READY, and the owner
// decided #33 the same day. Each test here stands in front of one of their lib and bin findings, of the lib mutants
// round 3's re-read planted that no test caught, or of decision #33, is named after it, and failed at f62f9ba for the
// reason its name gives (or, for a test that could not fail there, fails on the mutant named in its comment). Offline:
// no test reaches a network host.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, mkdtempSync, rmSync, realpathSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const AS_ROOT = process.getuid?.() === 0;
let dir, home;
before(() => { dir = mkdtempSync(join(realpathSync(tmpdir()), 'wardlatch-reread-r3-')); home = join(dir, 'home'); mkdirSync(home); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

const fresh = (n) => { const d = join(dir, n); mkdirSync(d, { recursive: true }); return d; };
const put = (p, text) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
/** The CLI as a person runs it: its text output and exit code. */
const text = (args, env = {}, nodeArgs = []) => {
  const r = spawnSync(process.execPath, [...nodeArgs, BIN, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...env }, cwd: dir, timeout: 180000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
/** The CLI with --json: the raw text, the rows and the exit code. */
const json = (args, env = {}, nodeArgs = []) => {
  const r = text([...args, '--json'], env, nodeArgs);
  let rows; try { rows = JSON.parse(r.out).results; } catch { assert.fail(`not JSON (exit ${r.code}): ${r.err.slice(0, 600)}`); }
  return { ...r, rows };
};
const unknowns = (r) => r.rows.filter((x) => x.status === 'UNKNOWN');

// ---- owner decision #33: a service's folder that could not be opened is UNKNOWN, grouped in one row ------------------
// "UNKNOWN too" (owner, 31 Oct 2026): a folder Wardlatch could not open because it belongs to a system service (EACCES)
// is could-not-be-tested, exit 2, never a REVIEW line beside SAFE, and such folders are grouped into one line. This
// supersedes the 22 Oct one-review-line rule and extends decision #32 (EPERM). At f62f9ba, MEASURED by the round-3
// re-read and again here: `--incident litellm-2026-10 --paths /private/var/spool` printed "REVIEW folders not searched"
// for 15 folders root and _postfix own, then "SAFE no LiteLLM 1.107.0 files or markers found", exit 0.
/** A folder on this machine below which every folder that can't be listed is a service's and refuses with EACCES,
 *  none with EPERM, none a person's, and with no link out of it: /private/var/spool on macOS, /var/spool on Linux. */
const spool = () => {
  const { isPersonUid } = OWNERS;
  for (const base of ['/private/var/spool', '/var/spool']) {
    let service = 0, bad = false;
    const walk = (d, depth) => {
      let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { bad = true; return; }
      for (const e of ents) {
        const p = join(d, e.name);
        if (e.isSymbolicLink()) { try { if (statSync(p).isDirectory()) bad = true; } catch { /* a link to nothing */ } continue; }
        if (!e.isDirectory()) continue;
        try { readdirSync(p); } catch (err) {
          let uid = null; try { uid = statSync(p).uid; } catch { /* cannot tell */ }
          if (err.code !== 'EACCES' || isPersonUid(uid, 'install')) bad = true; else service++;
          continue;
        }
        if (depth > 0) walk(p, depth - 1);
      }
    };
    walk(base, 4);
    if (!bad && service > 1) return base;
  }
  return null;
};
let OWNERS;
before(async () => { OWNERS = await import('../lib/owners.mjs'); });

test('#33 the folders a service owns that could not be opened are UNKNOWN, in one row, exit 2, with no all-clear beside them', { skip: AS_ROOT && 'root opens every folder' }, (t) => {
  const base = spool(); if (!base) return t.skip('no spool folder of that shape on this machine');
  for (const id of ['litellm-2026-10', 'github-actions-2026-10', 'committed-keys-2026-10', 'wordpress-plugins-2026-10']) {
    const r = json(['--incident', id, '--no-containers', '--paths', base]);
    assert.ok(!r.rows.some((x) => x.status === 'REVIEW'), `${id}: never a REVIEW line for a folder not opened: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    const grouped = unknowns(r).filter((x) => x.what === 'service folders');
    assert.equal(grouped.length, 1, `${id}: one row for them all: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.ok(grouped[0].paths.length > 1 && grouped[0].folders.length === grouped[0].paths.length, JSON.stringify(grouped[0]));
    for (const f of grouped[0].folders) assert.match(f.basis, /^EACCES, mode 0\d{3}, owner /, JSON.stringify(f));
    assert.match(grouped[0].reason, /could not be opened, so they were not searched/, grouped[0].reason);
    assert.ok(!r.rows.some((x) => x.status === 'SAFE'), `${id}: no all-clear beside folders not searched: ${JSON.stringify(r.rows).slice(0, 1500)}`);
    assert.equal(r.code, 2, id);
  }
  // as a person reads it: one UNKNOWN line for the group, and the last line counts it
  const t2 = text(['--incident', 'litellm-2026-10', '--no-containers', '--paths', base]);
  assert.equal(t2.out.split('\n').filter((l) => /^UNKNOWN +\d+ folders owned by service accounts/.test(l)).length, 1, t2.out);
  assert.doesNotMatch(t2.out, /^(REVIEW|SAFE) /m, t2.out);
  assert.match(t2.out, /0 safe · 0 exposed · 1 could not be tested\n/, t2.out);
  assert.equal(t2.code, 2);
});
