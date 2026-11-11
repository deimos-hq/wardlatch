// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// CISA's Known Exploited Vulnerabilities (KEV) catalog rows an incident file carries (`kev`), as the lines Wardlatch
// prints under the incident's title and the objects it puts in --json. Wardlatch never fetches the catalog: the rows are
// copied into the incident file before a release (scripts/kev-snapshot.mjs) and test/kev.test.mjs holds them to that
// copy. A row is printed as CISA files it (vendor and product as CISA names them: Brotli's is "Google Brotli", not Node.js).

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const ISO = /^(\d{4})-(\d{2})-(\d{2})$/;
export const KEV_URL = (cve) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${cve}`;

/** "2026-10-27" → "27 Oct 2026"; anything else throws (a malformed date is a broken incident file, not a line to print). */
export function dayOf(iso) {
  const m = ISO.exec(iso ?? '');
  const month = m ? Number(m[2]) : 0, day = m ? Number(m[3]) : 0;
  // a real calendar day (review 1: 2026-02-31 passed): the date built from the parts must give the same parts back
  const d = m ? new Date(Date.UTC(Number(m[1]), month - 1, day)) : null;
  if (!m || month < 1 || month > 12 || day < 1 || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) throw new Error(`not a KEV date: ${JSON.stringify(iso)}`);
  return `${day} ${MONTHS[month - 1]} ${m[1]}`;
}

const ROW = /^CVE-\d{4}-\d{4,}$/;
/** The incident's KEV rows, checked: each has a CVE id, vendor, product and both dates. [] when the file has none. */
export function kevRows(inc) {
  if (inc.kev === undefined) return [];
  if (!Array.isArray(inc.kev) || !inc.kev.length) throw new Error(`${inc.id}: kev must be a non-empty list`);
  return inc.kev.map((r) => {
    if (!ROW.test(r?.cve ?? '') || !r.vendorProject || !r.product) throw new Error(`${inc.id}: a kev row needs cve, vendorProject and product: ${JSON.stringify(r)}`);
    dayOf(r.dateAdded); dayOf(r.dueDate);
    if (r.dueDate < r.dateAdded) throw new Error(`${inc.id}: ${r.cve}'s due date is before the date it was added`);
    return { cve: r.cve, vendorProject: r.vendorProject, product: r.product, dateAdded: r.dateAdded, dueDate: r.dueDate, url: KEV_URL(r.cve) };
  });
}

const and = (xs) => (xs.length < 3 ? xs.join(' and ') : `${xs.slice(0, -1).join(', ')} and ${xs.at(-1)}`);

/** One line per product and pair of dates, e.g. "CISA KEV: Google Brotli CVE-2026-111497 is known to be exploited ·
 * added 27 Oct 2026 · due date for US federal agencies 10 Nov 2026 · <link>". */
export function kevLines(inc) {
  const groups = new Map();
  for (const r of kevRows(inc)) {
    const key = [r.vendorProject, r.product, r.dateAdded, r.dueDate].join('\0');
    if (!groups.has(key)) groups.set(key, { ...r, cves: [] });
    groups.get(key).cves.push(r.cve);
  }
  return [...groups.values()].map((g) => `CISA KEV: ${g.vendorProject} ${g.product} ${and(g.cves)} ${g.cves.length === 1 ? 'is' : 'are'} known to be exploited · added ${dayOf(g.dateAdded)} · due date for US federal agencies ${dayOf(g.dueDate)} · ${KEV_URL(g.cves[0])}`);
}
