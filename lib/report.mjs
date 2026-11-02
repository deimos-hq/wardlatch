// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// SAFE needs a receipt, and the receipt has to be one a reader can check. This is the one place a SAFE result is made,
// and it can't be made without saying what was looked at: up to 0.1.8 a check could print SAFE having looked at nothing
// (a --paths that didn't exist, a folder it couldn't open, a test host that never answered), and nothing in the code
// could tell. test/conventions and the 0.1.9 contract hold every other file to comparing with SAFE, never producing it.
//
// Up to 0.1.10 the rule tested the SHAPE of a receipt — a non-empty list of non-blank strings — and never its truth, so
// any sentence passed it, and the second enforcement on the way out called the same shape-only test and could catch
// nothing (AUDIT-13; test/support/repro-receipt-truth.mjs reproduced it four times over and stays as a script run by
// hand against those four coming back: it is in no suite, and test/audit-receipts.test.mjs's AUDIT-13 test is what
// CI runs). That is how "GitLab's version files under /opt/gitlab and /home/git/gitlab" came to
// stand behind an all-clear on a machine with neither folder (AUDIT-10), and
// how the php all-clear came to name thirteen folders that are not on this machine and five glob patterns that are not
// paths at all. A receipt entry is now one of exactly two things, and anything else is prose:
//   - a place on disk: an absolute path that is there now, which a reader can go and open themselves;
//   - an observation that is not a place, declared by the check that made it with saw(): a test host that refused the
//     connection, the environment, a version read from a file the same receipt already names. The rule cannot verify
//     these by looking, so the check has to say it means one. The point is that nothing reaches a receipt by accident.
import { isAbsolute } from 'node:path';
import { pathState } from './files.mjs';

/**
 * Evidence that is not a place on disk, for a receipt: saw('the environment'), saw(`version ${v}`), saw(host). A reader
 * cannot open it, so the rule below cannot check it the way it checks a path; declaring it is the check taking
 * responsibility for it, in one visible word at the call site. An entry that is neither this nor a path on this machine
 * is refused.
 */
export const saw = (what) => ({ saw: String(what) });

// "gone" and "denied" are different answers (lib/files.mjs): a folder that is there but closed to this user was still
// there to be opened, and the question here is whether the place a receipt names exists, not who may read it.
const isPlace = (s) => isAbsolute(s) && pathState(s) !== 'gone';

/**
 * The entries of a row's receipt that neither name a place on this machine nor were declared with saw(). Empty for a
 * receipt that holds. Exported for the enforcement on the way out, and for tests.
 */
export function unchecked(row) {
  const declared = [].concat(row.notOnDisk ?? []).map(String);
  return (Array.isArray(row.searched) ? row.searched : []).map(String).filter((s) => !(declared.includes(s) ? s.trim() : isPlace(s)));
}

/**
 * A SAFE result: { status, searched, gaps?, notOnDisk?, ...fields }. `searched` is the receipt: what was looked at, a
 * non-empty list of places on this machine (files, folders, programs) and observations declared with saw(), which are
 * repeated in `notOnDisk` so a reader of --json can tell which entries they cannot open. Throws without a receipt: a
 * SAFE that can't say what it saw is a bug in the check. → UNKNOWN instead of SAFE when the receipt does not hold.
 *
 * `gaps`: the number of folders this run could not open and did not hold against the exit code, recorded beside
 * `searched` because it belongs to the same sentence. Zero is left out. Nothing passes it since owner decision #33 (31
 * Oct 2026): every folder the run could not open is UNKNOWN now, a service account's included, so no all-clear stands
 * beside one. From 22 Oct to #33 bin/wardlatch.mjs passed the count of a service's folders here, with a REVIEW line
 * beside the all-clear and exit 0. It is kept so that a caller that passes it still gets the field it asked for.
 */
export function safe(searched, fields = {}) {
  const given = [].concat(searched ?? []).filter((e) => String(e?.saw ?? e).trim());
  const list = given.map((e) => String(e?.saw ?? e));
  const notOnDisk = given.filter((e) => e?.saw !== undefined).map((e) => String(e.saw));
  // an empty call is a mistake in the code, not something the disk can cause: a check that gets here has looked at
  // something and must name it
  if (!list.length) throw new Error('a SAFE result needs a receipt: what was looked at');
  const { gaps, ...rest } = fields;
  const row = { ...rest, status: 'SAFE', searched: list, ...(gaps ? { gaps } : {}), ...(notOnDisk.length ? { notOnDisk } : {}) };
  // A receipt that does not hold is not thrown, because a folder read a moment ago can be gone by the time this runs,
  // and the answer to that is the one the iron law gives: not having looked, or no longer being able to show what was
  // looked at, is UNKNOWN. Never a crash, and never SAFE.
  return unchecked(row).length ? { ...rest, ...withdrawn(row) } : row;
}

/** The UNKNOWN a row becomes when its receipt does not hold, with the entries that failed named. */
function withdrawn(row) {
  const bad = unchecked(row);
  const what = bad.length ? `names ${bad.map((s) => JSON.stringify(s)).join(', ')}, which cannot be checked by looking` : 'has no receipt';
  return { status: 'UNKNOWN', reason: `internal error: an all-clear that ${what} (${row.reason ?? row.kind}): please report this` };
}

/** A receipt is a non-empty list, and every entry in it is a place on this machine or an observation declared with saw(). */
export const hasReceipt = (row) => Array.isArray(row.searched) && row.searched.some((s) => String(s).trim()) && !unchecked(row).length;

/**
 * The receipt rule, enforced once more on the way out (bin/wardlatch.mjs): every SAFE row whose receipt does not hold,
 * however it was made, becomes UNKNOWN in place. → the rows withdrawn, for the CLI to say so under the lines it already
 * printed. Checked again here, and not only in safe(), because the disk can change under a long run and because a row
 * assembled from a result (lib/binaries.mjs, lib/installs.mjs add the file they read to the front of the receipt) is
 * not the object safe() returned.
 */
export function withdrawUnreceipted(rows) {
  const out = [];
  for (const r of rows) {
    if (r.status !== 'SAFE' || hasReceipt(r)) continue;
    Object.assign(r, withdrawn(r));
    out.push(r);
  }
  return out;
}
