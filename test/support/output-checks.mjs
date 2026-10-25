// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Two checks every test helper that runs the command makes on what it printed, whatever the test itself asserts.
// T0, the safety net never fires: the receipt rule (bin/wardlatch.mjs, withdrawUnreceipted) turns a SAFE row that names
// nothing it looked at into UNKNOWN on the way out, and says so with "internal error: a SAFE result without a receipt".
// In a correct run no such row is ever made, so those words never appear, in --json or on screen. A bug that makes a
// SAFE row with no receipt (a planted 'UNKNOWN' -> 'SAFE') is repaired by the rule, and a test that reads only the
// status, the exit code or words of the reason still passes on it: this one doesn't.
// T1, the lines add up: on screen, every result is printed exactly once, on a line starting with its status, so the
// lines starting with SAFE, EXPOSED, UNKNOWN and REVIEW match the counts on the summary line ("2 safe · 0 exposed · 1
// could not be tested · 3 to review"). A bug in a screen line alone (the --json row is a separate line of code) shows
// here and nowhere else. A run with no summary line (help, a refused option, a crash, a kill) is not counted.
import assert from 'node:assert/strict';

export const NET_FIRED = 'a SAFE result without a receipt';
const SUMMARY = /^(\d+) safe · (\d+) exposed · (\d+) could not be tested(?: · (\d+) to review)?$/gm;
const STATUS = /^(SAFE|EXPOSED|UNKNOWN|REVIEW) {2,}/;

/** T0: neither stream holds the receipt rule's internal-error words. */
export function netNeverFires(out, err = '') {
  for (const [name, s] of [['stdout', out], ['stderr', err]]) {
    const text = String(s ?? ''), at = text.indexOf(NET_FIRED);
    assert.ok(at < 0, `T0: the receipt rule withdrew a SAFE result (a SAFE row was made without a receipt), in ${name}: …${text.slice(Math.max(0, at - 300), at + 200)}…`);
  }
}

/** T1: the status lines on screen match the summary line's counts. Text output only; nothing to count without a summary. */
export function linesAddUp(out) {
  const text = String(out ?? '');
  const sums = [...text.matchAll(SUMMARY)];
  if (!sums.length) return;
  assert.equal(sums.length, 1, `T1: ${sums.length} summary lines`);
  const [, safe, exposed, unknown, review = '0'] = sums[0];
  const want = { SAFE: Number(safe), EXPOSED: Number(exposed), UNKNOWN: Number(unknown), REVIEW: Number(review) };
  const got = { SAFE: 0, EXPOSED: 0, UNKNOWN: 0, REVIEW: 0 };
  for (const line of text.slice(0, sums[0].index).split('\n')) { const m = STATUS.exec(line); if (m) got[m[1]]++; }
  assert.deepEqual(got, want, `T1: the status lines don't add up to the summary line "${sums[0][0]}":\n${text}`);
}

/** Both, on one run of the command: T1 only when it printed text (no --json among its arguments). */
export function outputChecks(args, out, err) {
  netNeverFires(out, err);
  if (!args.includes('--json')) linesAddUp(out);
}

/** outputChecks on a spawnSync result, given the command's own arguments (--json among them or not). → the result */
export const checked = (args, r) => { outputChecks(args, r.stdout, r.stderr); return r; };
