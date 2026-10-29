// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// MINIMAL REPRODUCTION — the receipt gate checks a receipt's SHAPE, never its TRUTH.
//
// Why this file exists. AUDIT-10 through AUDIT-13 in test/audit-receipts.test.mjs are red on branch
// fix/false-safes and describe one root cause between them. The owner's rule (29 Oct) is that a bug found once
// is a hypothesis: it has to be reproduced and minimised before anyone acts on it, or the next session goes
// round the same circle. This is that minimisation — standalone, no test framework, every case asserted TWICE
// so a one-off cannot be mistaken for a defect.
//
// Run:  env -i PATH=/usr/local/bin:/usr/bin:/bin node test/support/repro-receipt-truth.mjs
// Exit: 0 if every defect still reproduces (i.e. nothing is fixed yet), 1 if any has stopped reproducing.
import { safe, hasReceipt, withdrawUnreceipted } from '../../lib/report.mjs';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';

let reproduced = 0, gone = 0;

/**
 * Assert a defect STILL EXISTS, twice, from independently constructed inputs.
 *
 * build() is wrapped as well as holds(), because the most likely way a defect stops reproducing is that the gate
 * starts THROWING on the input that used to sail through. The first version of this file guarded only holds(),
 * so the moment the fix worked the throw escaped and crashed the harness — a repro tool that cannot survive the
 * bug being fixed reports a fix as a crash.
 */
function defect(id, what, build, holds) {
  const attempt = () => { try { return { ok: true, v: build() }; } catch (e) { return { ok: false, e }; } };
  const runs = [attempt(), attempt()];
  const results = runs.map((r) => {
    if (!r.ok) return `gate refused it: ${r.e.message}`;
    try { return holds(r.v); } catch (e) { return `threw: ${e.message}`; }
  });
  const both = results.every((r) => r === true);
  if (both) { reproduced += 1; console.log(`  REPRODUCED x2  ${id}  ${what}`); }
  else { gone += 1; console.log(`  NO LONGER      ${id}  ${what}\n                 -> ${JSON.stringify(results)}`); }
}

console.log('receipt gate: does a SAFE need a TRUE receipt, or only a non-blank one?\n');

// 1. The core defect. A sentence is a receipt. Nothing in the gate asks whether it refers to anything.
defect('R-1', 'a sentence that names nothing is a valid receipt', () => safe(['I had a thorough look around']),
  (row) => row.status === 'SAFE' && hasReceipt(row) === true);

// 2. A path that does not exist is a valid receipt. This is AUDIT-10's shape: an all-clear whose receipt is
//    about folders that are not on this machine.
defect('R-2', 'a path that does not exist is a valid receipt',
  () => safe(['/no/such/folder/anywhere-' + 'x'.repeat(8)]),
  (row) => row.status === 'SAFE' && hasReceipt(row) &&
           !row.searched.every((s) => isAbsolute(String(s)) && existsSync(String(s))));

// 3. The smallest possible receipt. If one character satisfies the iron law, the law is a formality.
defect('R-3', 'a single character satisfies the iron law', () => safe(['x']),
  (row) => row.status === 'SAFE' && hasReceipt(row) === true);

// 4. withdrawUnreceipted() is the second line of defence, enforced on the way out in bin/wardlatch.mjs.
//    It cannot catch any of the above, because it calls the same shape-only predicate.
defect('R-4', 'withdrawUnreceipted() withdraws nothing from a made-up receipt',
  () => { const rows = [safe(['/no/such/folder/anywhere', 'I had a thorough look around'])];
          return { rows, withdrawn: withdrawUnreceipted(rows) }; },
  ({ rows, withdrawn }) => withdrawn.length === 0 && rows[0].status === 'SAFE');

// 5. The boundary that IS enforced, kept here so this file cannot become all-fail and therefore meaningless:
//    a blank or empty receipt is still correctly refused. If this one ever "reproduces", the gate is gone
//    entirely and that is a far worse finding.
console.log('\ncontrol — the half of the gate that DOES work (must say NO LONGER):');
defect('C-1', 'an empty receipt is refused', () => { try { return safe([]); } catch (e) { return e; } },
  (r) => !(r instanceof Error));
defect('C-2', 'a whitespace-only receipt is refused', () => { try { return safe(['   ', '\t\n']); } catch (e) { return e; } },
  (r) => !(r instanceof Error));

console.log(`\n${reproduced} defect(s) reproduced, ${gone} no longer reproducing.`);
console.log('Expected while fix/false-safes is unfinished: R-1..R-4 REPRODUCED, C-1..C-2 NO LONGER.');
// A run that reproduces nothing is a FAILED run, not a pass: it means this file stopped reaching the gate.
if (reproduced === 0) { console.error('\nFAILED RUN: nothing reproduced. This file no longer reaches the gate.'); process.exit(1); }
process.exit(0);
