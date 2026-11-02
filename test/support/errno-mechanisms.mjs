// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// THE MEASUREMENT behind lib/files.mjs mandatoryRefusal() — run by hand, not by `npm test`.
//
// What it measures, since owner decision #32 (31 Oct 2026). Up to then a "stated gap" rule rested on one claim: that
// EPERM from readdir cannot be produced without root, so a folder refusing with EPERM could ride beside an all-clear
// with exit 0. That claim was false: an unprivileged sandbox profile gives exactly that EPERM (claim 3 below measures
// it), and the owner reversed the rule: every folder Wardlatch could not open, EPERM included, is UNKNOWN. What still
// rests on this file is the sentence such a row prints: that an EPERM on a folder whose permission bits would let the
// run in came from something above them (macOS's privacy protection, a sandbox), while chmod 000 and a deny ACL give
// EACCES. A claim that a row prints is not allowed to live only in a comment, so it lives here, runnable.
//
// It is NOT in the `test/*.test.mjs` glob on purpose, for the same reason test/support/repro-receipt-truth.mjs is not:
// the TCC half can only be measured against folders macOS actually protects, which are in the real home, and the
// tests' own safety net (test/support/no-real-home.cjs) correctly refuses to let a test look there. This script is
// read-only — it attempts readdir and stat, nothing else, and its own fixtures live in a mkdtemp folder it removes —
// and it is the one place allowed to ask the real home a question.
//
// Run:  node test/support/errno-mechanisms.mjs
// Exit: 0 when every claim was measured, twice, and held; 1 when a claim was measured and did not hold; 2 when none
//       broke but something could not be measured here (a setup that could not be applied — no chmod +a, no chflags,
//       a sandbox inside a sandbox — or no folder macOS protects to measure). Up to 31 Oct 2026 a claim whose setup
//       failed counted as holding, and a run that measured no TCC folder at all exited 0 (independent read, M2 and
//       WV-18): an exit 0 that confirmed nothing. 2 is the tool's own "could not be tested".
//
// MEASURED on macOS 27.2 (Darwin 27.2.0), 29 October 2026, uid 501:
//   ~/.Trash                                EPERM  mode 0700  owner you
//   ~/Library/Mail                          EPERM  mode 0700  owner you
//   ~/Pictures/Photo Booth Library          EPERM  mode 0755  owner you
//   ~/Pictures/Photos Library.photoslibrary EPERM  mode 0755  owner you
//   chmod 000                               EACCES
//   chmod +a "<user> deny read,list,search,readattr"   EACCES
//   chflags uchg | hidden | opaque          no effect at all — the folder still lists
// and on 31 October 2026, the same Mac, without root:
//   sandbox-exec, (deny file-read-data (subpath <folder>))   EPERM  mode 0755  owner you
import { readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { mandatoryRefusal } from '../../lib/files.mjs';

const H = homedir();
const short = (p) => p.replace(H, '~');
let held = 0, broken = 0, unmeasured = 0;

/** A claim that could not be measured here: said, counted, and never mistaken for one that holds. */
const unmeasurable = (what, why) => { unmeasured += 1; console.log(`  UNMEASURED ${what}\n             -> ${why}`); return null; };

/** Assert a claim TWICE, from two independent attempts: a one-off must not be mistaken for a measurement. `measure`
 *  returns null when its setup could not be applied: then the claim is UNMEASURED, not held. */
function claim(what, measure, holds) {
  const attempt = () => { try { return { ok: true, v: measure() }; } catch (e) { return { ok: false, e }; } };
  const runs = [attempt(), attempt()];
  if (runs.some((r) => r.ok && r.v === null)) return unmeasurable(what, 'its setup could not be applied on this machine, so nothing was measured');
  const results = runs.map((r) => (r.ok ? (() => { try { return holds(r.v); } catch (e) { return `threw: ${e.message}`; } })() : `measuring threw: ${r.e.message}`));
  if (results.every((r) => r === true)) { held += 1; console.log(`  HOLDS x2   ${what}`); return true; }
  broken += 1; console.log(`  BROKEN     ${what}\n             -> ${JSON.stringify(results)}`); return false;
}

/** The errno readdir gives for `p`, or null when it lists. */
const code = (p) => { try { readdirSync(p); return null; } catch (e) { return e.code; } };
const bits = (p) => { try { const s = statSync(p); return { mode: s.mode & 0o777, uid: s.uid }; } catch { return null; } };
const sh = (cmd, args) => { try { execFileSync(cmd, args, { stdio: 'pipe' }); return true; } catch { return false; } };
const MAC = process.platform === 'darwin';

console.log(`uid ${process.getuid?.()} on ${process.platform}\n`);

// ---- 1. the folders macOS protects: EPERM, and mandatoryRefusal() accepts each one -------------------------------
console.log('macOS TCC-protected folders (skipped where absent, or where this terminal has Full Disk Access):');
const tcc = MAC ? [join(H, '.Trash'), join(H, 'Library', 'Mail'), join(H, 'Pictures', 'Photo Booth Library')] : [];
try { for (const e of MAC ? readdirSync(join(H, 'Pictures')) : []) if (e.endsWith('.photoslibrary')) tcc.push(join(H, 'Pictures', e)); } catch { /* no Pictures, or it is itself protected */ }
let sawTcc = 0;
for (const p of tcc) {
  if (!existsSync(p)) { console.log(`  absent     ${short(p)}`); continue; }
  const c = code(p);
  if (c === null) { console.log(`  readable   ${short(p)} (this terminal has Full Disk Access: nothing to measure here)`); continue; }
  sawTcc += 1;
  const b = bits(p);
  claim(`${short(p)} refuses with EPERM (mode 0${(b?.mode ?? 0).toString(8)}, ${b?.uid === process.getuid?.() ? 'owner you' : `uid ${b?.uid}`}) and its bits would let this user in`,
    () => ({ c: code(p) }), ({ c: got }) => got === 'EPERM' && mandatoryRefusal(p, got) === true);
}
if (!sawTcc) unmeasurable('the TCC half: a folder macOS protects refuses with EPERM', MAC ? 'none to measure on this machine (absent, or readable with Full Disk Access)' : 'not macOS');

// ---- 2. the unprivileged ways to deny a read on one's own folder ---------------------------------------------------
console.log('\nthe unprivileged denial mechanisms:');
const tmp = mkdtempSync(join(tmpdir(), 'wardlatch-errno-'));
const made = [];
const mk = (name) => { const d = join(tmp, name); mkdirSync(d); writeFileSync(join(d, 'inside'), 'x'); made.push(d); return d; };
try {
  // chmod 000 — the obvious hiding place, and the one test fixtures build
  claim('chmod 000 gives EACCES, and mandatoryRefusal() refuses it', () => {
    const d = mk(`chmod000-${made.length}`); chmodSync(d, 0o000); return d;
  }, (d) => code(d) === 'EACCES' && mandatoryRefusal(d, code(d)) === false);

  // a deny ACL — the subtle one: it denies a read without changing the mode bits a reader would check
  if (MAC) {
    const who = (() => { try { return execFileSync('id', ['-un'], { encoding: 'utf8' }).trim(); } catch { return ''; } })();
    if (!who) unmeasurable('a deny ACL gives EACCES, and mandatoryRefusal() refuses it', 'this user\'s name could not be learned (`id -un` did not run), so no ACL could be written');
    else {
      claim('a deny ACL gives EACCES, and mandatoryRefusal() refuses it', () => {
        const d = mk(`denyacl-${made.length}`);
        if (!sh('chmod', ['+a', `${who} deny read,list,search,readattr`, d])) return null;
        return d;
      }, (d) => code(d) === 'EACCES' && mandatoryRefusal(d, code(d)) === false);
    }
    // chflags — measured to do nothing at all to a readdir, which is worth recording so nobody re-tries it
    for (const fl of ['uchg', 'hidden', 'opaque']) {
      claim(`chflags ${fl} does not deny the read at all (the folder still lists)`, () => {
        const d = mk(`flag-${fl}-${made.length}`);
        return sh('chflags', [fl, d]) ? d : null;
      }, (d) => code(d) === null);
    }

    // ---- 3. the claim decision #32 rests on: an unprivileged sandbox gives the same EPERM ----------------------------
    // So EPERM alone cannot tell macOS's privacy protection from a sandbox the run is inside (the kind coding agents
    // run tools in), and a row may never say which it was. A sandbox cannot be applied inside another one: then this
    // is UNMEASURED, never held.
    claim('an unprivileged sandbox profile gives EPERM on a folder of mode 0755 owned by this user, and its bits would let this user in', () => {
      const d = mk(`sandbox-${made.length}`); chmodSync(d, 0o755);
      const profile = join(tmp, `sandbox-${made.length}.sb`), probe = join(tmp, `sandbox-${made.length}.cjs`);
      writeFileSync(profile, `(version 1)\n(allow default)\n(deny network*)\n(deny file-read-data (subpath ${JSON.stringify(d)}))\n`);
      writeFileSync(probe, 'try { require("node:fs").readdirSync(process.argv[2]); console.log("LISTS"); } catch (e) { console.log(e.code); }\n');
      const r = spawnSync('/usr/bin/sandbox-exec', ['-f', profile, process.execPath, probe, d], { encoding: 'utf8', timeout: 30000 });
      if (r.status !== 0 || /sandbox_apply/.test(r.stderr ?? '')) return null;
      return { d, got: r.stdout.trim() };
    }, ({ d, got }) => got === 'EPERM' && mandatoryRefusal(d, 'EPERM') === true);
  } else console.log('  (not macOS: the ACL, chflags and sandbox-exec mechanisms are macOS\'s, and are not measured here)');

  // ---- 4. the control: the rule must not accept everything ------------------------------------------------------
  console.log('\ncontrol — mandatoryRefusal() must say no to anything that is not EPERM:');
  claim('a folder that lists fine is not a refusal', () => mk(`open-${made.length}`), (d) => mandatoryRefusal(d, code(d)) === false);
  claim('a path that cannot be stat-ed claims nothing', () => join(tmp, 'no-such-folder-anywhere'), (p) => mandatoryRefusal(p, 'EPERM') === false);
} finally {
  for (const d of made) { try { chmodSync(d, 0o755); } catch { /* gone */ } if (MAC) { sh('chmod', ['-N', d]); sh('chflags', ['nouchg,nohidden,noopaque', d]); } }
  rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n${held} claim(s) hold, ${broken} broken, ${unmeasured} unmeasured.`);
if (broken) { console.error('FAILED: a claim behind mandatoryRefusal() no longer holds on this machine.'); process.exit(1); }
if (!held) { console.error('FAILED RUN: nothing was measured, so nothing was confirmed.'); process.exit(2); }
if (unmeasured) { console.error(`NOT CONFIRMED: ${unmeasured} claim(s) could not be measured on this machine, so this run confirms only the ones that hold.`); process.exit(2); }
process.exit(0);
