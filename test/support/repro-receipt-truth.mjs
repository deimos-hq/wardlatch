// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// REGRESSION ARTEFACT — the receipt gate must check a receipt's TRUTH, not only its SHAPE.
//
// WHAT THIS FILE ORIGINALLY FOUND, and why it was written. AUDIT-10 through AUDIT-13 in
// test/audit-receipts.test.mjs were red on branch fix/false-safes and described one root cause between them: the
// rule standing between an UNKNOWN and a SAFE (lib/report.mjs) tested that `searched` was a non-empty list of
// non-blank strings and never asked whether any entry referred to anything. The owner's rule (29 Oct 2026) is that
// a bug found once is a hypothesis: it has to be reproduced and minimised before anyone acts on it, or the next
// session goes round the same circle. This file was that minimisation — standalone, no test framework, every case
// asserted TWICE from independently constructed inputs so a one-off could not be mistaken for a defect. It
// reproduced four defects, and this is the record of them as they were measured, which is kept because it is the
// only account of what the gate actually did:
//
//   R-1  safe(['I had a thorough look around'])                  -> SAFE, hasReceipt() true.
//        A sentence naming nothing stood behind an all-clear.
//   R-2  safe(['/no/such/folder/anywhere-xxxxxxxx'])              -> SAFE, hasReceipt() true.
//        A path on no machine stood behind an all-clear. This is AUDIT-10's shape: that is how "GitLab's version
//        files under /opt/gitlab and /home/git/gitlab" came to be the receipt for an all-clear on a machine with
//        neither folder.
//   R-3  safe(['x'])                                             -> SAFE, hasReceipt() true.
//        One character satisfied the iron law, which made the law a formality.
//   R-4  withdrawUnreceipted([safe(['/no/such/folder/anywhere', 'I had a thorough look around'])])
//                                                                -> withdrew nothing, row still SAFE.
//        The second enforcement, on the way out in bin/wardlatch.mjs, could catch none of the above because it
//        called the same shape-only predicate.
//   C-1  safe([])        and
//   C-2  safe(['   ', '\t\n'])
//        the half of the gate that already worked: both correctly refused. They were kept so the file could not
//        become all-fail and therefore meaningless, and they are kept now for the same reason, from the other side.
//
// 00b6332 (29 Oct 2026) fixed the gate: a receipt entry is now either an absolute path that is on this machine, or
// an observation declared by the check with saw(), and anything else is prose, so the row comes back UNKNOWN with
// the failing entry named. From that commit none of the six reproduces, and this file said "FAILED RUN: nothing
// reproduced" and exited 1 — backwards, because by then nothing reproducing was the correct state of the world.
//
// So it is inverted (30 Oct 2026). It is no longer a reproduction: it is the regression artefact for those six.
// NONE of them may come back. What it used to call success is now the failure it reports.
//
// Run:  env -i PATH=/usr/local/bin:/usr/bin:/bin node test/support/repro-receipt-truth.mjs
// Exit: 0 if none of the six reproduces AND the gate is still reachable (the liveness checks at the end).
//       Non-zero if any of them comes back, or if the liveness checks stop holding — because six cases that
//       cannot reproduce for want of reaching the gate at all would otherwise be a green run proving nothing.
import { safe, hasReceipt, withdrawUnreceipted } from '../../lib/report.mjs';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

// A folder that is certainly on this machine, because this file is in it. The liveness checks need a receipt that
// must hold, and anything derived from the environment could be absent under `env -i`.
const HERE = fileURLToPath(new URL('.', import.meta.url));

let back = 0, stayedFixed = 0, unreachable = 0;

/** Two independently constructed attempts at the same thing; a build that throws is an answer, not a crash. */
function twice(build, holds) {
  const attempt = () => { try { return { ok: true, v: build() }; } catch (e) { return { ok: false, e }; } };
  return [attempt(), attempt()].map((r) => {
    if (!r.ok) return `the gate refused it: ${r.e.message}`;
    try { return holds(r.v); } catch (e) { return `threw: ${e.message}`; }
  });
}

/**
 * Assert a defect is still GONE, twice, from independently constructed inputs.
 *
 * build() is wrapped as well as holds(), because the way one of these comes back may well be that the gate stops
 * throwing on an input it used to refuse. The first version of this file guarded only holds(), so the moment the
 * fix worked the throw escaped and crashed the harness — a tool that cannot survive the bug being fixed reports a
 * fix as a crash, and the same mistake in reverse would report a regression as a crash.
 */
function mustNotReproduce(id, what, build, reproduces) {
  const results = twice(build, reproduces);
  if (results.every((r) => r === false)) { stayedFixed += 1; console.log(`  still fixed x2  ${id}  ${what}`); return; }
  if (results.every((r) => r === true)) {
    back += 1;
    console.log(`  CAME BACK x2    ${id}  ${what}`);
    return;
  }
  // One of the two attempts said something other than a plain yes or no: a throw from holds(), or two attempts
  // disagreeing. Either way this case measured nothing, which is not a pass.
  unreachable += 1;
  console.log(`  NOT MEASURED    ${id}  ${what}\n                  -> ${JSON.stringify(results)}`);
}

/** A positive fact about the gate that must hold, so that six silent cases cannot pass for a working harness. */
function live(id, what, holds) {
  const results = twice(() => null, holds);
  if (results.every((r) => r === true)) { console.log(`  holds x2        ${id}  ${what}`); return; }
  unreachable += 1;
  console.log(`  BROKEN          ${id}  ${what}\n                  -> ${JSON.stringify(results)}`);
}

console.log('receipt gate: a SAFE needs a TRUE receipt. None of these six may come back.\n');

// 1. The core defect. A sentence is not a receipt: nothing in it refers to anything a reader could open.
mustNotReproduce('R-1', 'a sentence that names nothing is a valid receipt',
  () => safe(['I had a thorough look around']),
  (row) => row.status === 'SAFE' && hasReceipt(row) === true);

// 2. A path that does not exist is not a receipt. AUDIT-10's shape.
mustNotReproduce('R-2', 'a path that does not exist is a valid receipt',
  () => safe(['/no/such/folder/anywhere-' + 'x'.repeat(8)]),
  (row) => row.status === 'SAFE' && hasReceipt(row) &&
           !row.searched.every((s) => isAbsolute(String(s)) && existsSync(String(s))));

// 3. The smallest possible receipt. If one character satisfies the iron law, the law is a formality.
mustNotReproduce('R-3', 'a single character satisfies the iron law', () => safe(['x']),
  (row) => row.status === 'SAFE' && hasReceipt(row) === true);

// 4. withdrawUnreceipted(), the second enforcement on the way out in bin/wardlatch.mjs. It is given the row
//    directly rather than one from safe(), because safe() no longer makes one: lib/binaries.mjs and
//    lib/installs.mjs assemble a row's receipt after the fact, so this is the shape that really reaches it.
mustNotReproduce('R-4', 'withdrawUnreceipted() withdraws nothing from a made-up receipt',
  () => { const rows = [{ status: 'SAFE', kind: 'repro', reason: 'nothing found', searched: ['/no/such/folder/anywhere', 'I had a thorough look around'] }];
          return { rows, withdrawn: withdrawUnreceipted(rows) }; },
  ({ rows, withdrawn }) => withdrawn.length === 0 && rows[0].status === 'SAFE');

// 5. The half of the gate that already worked when this file was written, and must go on working: a blank or empty
//    receipt is refused. If either of these ever comes back the gate is gone entirely, which is a worse finding
//    than the four above.
console.log('\nand the half of the gate that already worked, which must also not come back:');
mustNotReproduce('C-1', 'an empty receipt is accepted', () => { try { return safe([]); } catch (e) { return e; } },
  (r) => !(r instanceof Error));
mustNotReproduce('C-2', 'a whitespace-only receipt is accepted', () => { try { return safe(['   ', '\t\n']); } catch (e) { return e; } },
  (r) => !(r instanceof Error));

// Liveness. Six cases that cannot reproduce because this file no longer reaches the gate would read exactly like
// six cases that cannot reproduce because the gate works. The old file caught that with "a run that reproduces
// nothing is a FAILED run"; inverted, that guard has to become positive facts about the gate instead.
console.log('\nliveness — this file still reaches a gate that is doing something:');
live('L-1', 'a receipt naming a folder that is on this machine is an all-clear',
  () => { const row = safe([HERE], { kind: 'repro', reason: 'nothing found' }); return row.status === 'SAFE' && hasReceipt(row) === true; });
live('L-2', 'a receipt naming prose is withdrawn, and the prose is named in the reason',
  () => { const row = safe(['I had a thorough look around'], { kind: 'repro', reason: 'nothing found' });
          return row.status === 'UNKNOWN' && String(row.reason).includes('I had a thorough look around'); });
live('L-3', 'an all-clear whose receipt holds is left alone on the way out',
  () => withdrawUnreceipted([safe([HERE], { kind: 'repro', reason: 'nothing found' })]).length === 0);

console.log(`\n${back} defect(s) came back, ${stayedFixed} still fixed, ${unreachable} not measured.`);
if (back) {
  console.error(`\nREGRESSION: ${back} of the six ${back === 1 ? 'is' : 'are'} back. lib/report.mjs is accepting a receipt whose truth it has not checked.`);
  process.exit(1);
}
if (unreachable) {
  console.error(`\nFAILED RUN: ${unreachable} case(s) measured nothing, so this file is not holding the gate to anything.`);
  process.exit(1);
}
console.log('None of the six reproduces, and the gate is still reachable. This is the state this file now asserts.');
process.exit(0);
