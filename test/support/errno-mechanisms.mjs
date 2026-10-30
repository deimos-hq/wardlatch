// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// THE MEASUREMENT behind lib/files.mjs mandatoryRefusal() — run by hand, not by `npm test`.
//
// Why this file exists. The whole stated-gap rule rests on one claim about this operating system: that EPERM from
// readdir cannot be produced by an unprivileged attacker, while every way they CAN deny a read on their own folder
// gives something else. If that claim is wrong, a folder an attacker locked becomes a REVIEW line that does not change
// the exit code, which is the failure the iron law exists to prevent. A claim that load-bearing is not allowed to live
// only in a comment, so it lives here, runnable, and the comment cites it by name.
//
// It is NOT in the `test/*.test.mjs` glob on purpose, for the same reason test/support/repro-receipt-truth.mjs is not:
// the TCC half can only be measured against folders macOS actually protects, which are in the real home, and the
// tests' own safety net (test/support/no-real-home.cjs) correctly refuses to let a test look there. This script is
// read-only — it attempts readdir and stat, nothing else, and its own fixtures live in a mkdtemp folder it removes —
// and it is the one place allowed to ask the real home a question.
//
// Run:  node test/support/errno-mechanisms.mjs
// Exit: 0 if the rule still holds on this machine, 1 if any load-bearing claim has stopped holding.
//
// MEASURED on macOS 27.2 (Darwin 27.2.0), 29 October 2026, uid 501:
//   ~/.Trash                                EPERM  mode 0700  owner you
//   ~/Library/Mail                          EPERM  mode 0700  owner you
//   ~/Pictures/Photo Booth Library          EPERM  mode 0755  owner you
//   ~/Pictures/Photos Library.photoslibrary EPERM  mode 0755  owner you
//   chmod 000                               EACCES
//   chmod +a "<user> deny read,list,search,readattr"   EACCES
//   chflags uchg | hidden | opaque          no effect at all — the folder still lists
import { readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { mandatoryRefusal } from '../../lib/files.mjs';

const H = homedir();
const short = (p) => p.replace(H, '~');
let held = 0, broken = 0;

/** Assert a claim TWICE, from two independent attempts: a one-off must not be mistaken for a measurement. */
function claim(what, measure, holds) {
  const attempt = () => { try { return { ok: true, v: measure() }; } catch (e) { return { ok: false, e }; } };
  const runs = [attempt(), attempt()];
  const results = runs.map((r) => (r.ok ? (() => { try { return holds(r.v); } catch (e) { return `threw: ${e.message}`; } })() : `measuring threw: ${r.e.message}`));
  if (results.every((r) => r === true)) { held += 1; console.log(`  HOLDS x2   ${what}`); return true; }
  broken += 1; console.log(`  BROKEN     ${what}\n             -> ${JSON.stringify(results)}`); return false;
}

/** The errno readdir gives for `p`, or null when it lists. */
const code = (p) => { try { readdirSync(p); return null; } catch (e) { return e.code; } };
const bits = (p) => { try { const s = statSync(p); return { mode: s.mode & 0o777, uid: s.uid }; } catch { return null; } };
const sh = (cmd, args) => { try { execFileSync(cmd, args, { stdio: 'pipe' }); return true; } catch { return false; } };

console.log(`uid ${process.getuid?.()} on ${process.platform}\n`);

// ---- 1. the folders macOS protects: EPERM, and mandatoryRefusal() accepts each one -------------------------------
console.log('macOS TCC-protected folders (skipped where absent, or where this terminal has Full Disk Access):');
const tcc = [join(H, '.Trash'), join(H, 'Library', 'Mail'), join(H, 'Pictures', 'Photo Booth Library')];
try { for (const e of readdirSync(join(H, 'Pictures'))) if (e.endsWith('.photoslibrary')) tcc.push(join(H, 'Pictures', e)); } catch { /* no Pictures, or it is itself protected */ }
let sawTcc = 0;
for (const p of tcc) {
  if (!existsSync(p)) { console.log(`  absent     ${short(p)}`); continue; }
  const c = code(p);
  if (c === null) { console.log(`  readable   ${short(p)} (this terminal has Full Disk Access: nothing to measure here)`); continue; }
  sawTcc += 1;
  const b = bits(p);
  claim(`${short(p)} refuses with EPERM (mode 0${(b?.mode ?? 0).toString(8)}, ${b?.uid === process.getuid?.() ? 'owner you' : `uid ${b?.uid}`}) and is a mandatory refusal`,
    () => ({ c: code(p) }), ({ c: got }) => got === 'EPERM' && mandatoryRefusal(p, got) === true);
}
if (!sawTcc) console.log('  (none to measure on this machine: the TCC half of the rule is unverified here)');

// ---- 2. the three ways an unprivileged attacker can deny a read on their own folder ------------------------------
console.log('\nthe three unprivileged denial mechanisms — none of them may produce EPERM:');
const tmp = mkdtempSync(join(tmpdir(), 'wardlatch-errno-'));
const made = [];
const mk = (name) => { const d = join(tmp, name); mkdirSync(d); writeFileSync(join(d, 'inside'), 'x'); made.push(d); return d; };
try {
  // chmod 000 — the obvious hiding place, and the one test fixtures build
  claim('chmod 000 gives EACCES, and mandatoryRefusal() refuses it', () => {
    const d = mk(`chmod000-${made.length}`); chmodSync(d, 0o000); return d;
  }, (d) => code(d) === 'EACCES' && mandatoryRefusal(d, code(d)) === false);

  // a deny ACL — the subtle one: it denies a read without changing the mode bits a reader would check
  const who = (() => { try { return execFileSync('id', ['-un'], { encoding: 'utf8' }).trim(); } catch { return ''; } })();
  if (process.platform === 'darwin' && who) {
    claim('a deny ACL gives EACCES, and mandatoryRefusal() refuses it', () => {
      const d = mk(`denyacl-${made.length}`);
      if (!sh('chmod', ['+a', `${who} deny read,list,search,readattr`, d])) return null;
      return d;
    }, (d) => d === null || (code(d) === 'EACCES' && mandatoryRefusal(d, code(d)) === false));
  } else console.log('  skipped    deny ACL (macOS only)');

  // chflags — measured to do nothing at all to a readdir, which is worth recording so nobody re-tries it
  if (process.platform === 'darwin') {
    for (const fl of ['uchg', 'hidden', 'opaque']) {
      claim(`chflags ${fl} does not deny the read at all (the folder still lists)`, () => {
        const d = mk(`flag-${fl}-${made.length}`);
        return sh('chflags', [fl, d]) ? d : null;
      }, (d) => d === null || code(d) === null);
    }
  }

  // ---- 3. the control: the rule must not accept everything ------------------------------------------------------
  console.log('\ncontrol — mandatoryRefusal() must say no to anything that is not EPERM:');
  claim('a folder that lists fine is not a refusal', () => mk(`open-${made.length}`), (d) => mandatoryRefusal(d, code(d)) === false);
  claim('a path that cannot be stat-ed claims nothing', () => join(tmp, 'no-such-folder-anywhere'), (p) => mandatoryRefusal(p, 'EPERM') === false);
} finally {
  for (const d of made) { try { chmodSync(d, 0o755); } catch { /* gone */ } try { sh('chmod', ['-N', d]); } catch { /* no ACL */ } try { sh('chflags', ['nouchg,nohidden,noopaque', d]); } catch { /* no flags */ } }
  rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n${held} claim(s) hold, ${broken} broken.`);
if (broken) { console.error('FAILED: a load-bearing claim behind mandatoryRefusal() no longer holds on this machine.'); process.exit(1); }
if (!held) { console.error('FAILED RUN: nothing was measured, so nothing was confirmed.'); process.exit(1); }
process.exit(0);
