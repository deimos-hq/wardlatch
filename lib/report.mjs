// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// SAFE needs a receipt. This is the one place a SAFE result is made, and it can't be made without saying what was
// looked at: up to 0.1.8 a check could print SAFE having looked at nothing (a --paths that didn't exist, a folder it
// couldn't open, a test host that never answered), and nothing in the code could tell. test/conventions and the 0.1.9
// contract hold every other file to comparing with SAFE, never producing it.

/**
 * A SAFE result: { status, searched, ...fields }. `searched` is what was looked at, a non-empty list of non-empty
 * strings (files, folders, programs, test hosts). Throws without one: a SAFE that can't say what it saw is a bug.
 */
export function safe(searched, fields = {}) {
  const list = [].concat(searched ?? []).map(String).filter((s) => s.trim());
  if (!list.length) throw new Error('a SAFE result needs a receipt: what was looked at');
  return { ...fields, status: 'SAFE', searched: list };
}

/** A receipt is a non-empty list with at least one non-blank entry. */
export const hasReceipt = (row) => Array.isArray(row.searched) && row.searched.some((s) => String(s).trim());

/**
 * The receipt rule, enforced once more on the way out (bin/wardlatch.mjs): every SAFE row without a receipt, however it
 * was made, becomes UNKNOWN in place. → the rows withdrawn, for the CLI to say so under the lines it already printed.
 */
export function withdrawUnreceipted(rows) {
  const out = [];
  for (const r of rows) {
    if (r.status !== 'SAFE' || hasReceipt(r)) continue;
    Object.assign(r, { status: 'UNKNOWN', reason: `internal error: a SAFE result without a receipt (${r.reason ?? r.kind}): please report this` });
    out.push(r);
  }
  return out;
}
