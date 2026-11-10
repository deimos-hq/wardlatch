// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// What Apple's own fix for /etc/ssl/cert.pem means for this Mac. Apple's page on the eMudhra incident
// (support.apple.com/en-us/149555, as of 9 Nov 2026) says macOS 27.2.1, 26.7.3 and 15.8.3 remove the two withdrawn
// roots from /etc/ssl/cert.pem, "along with three other eMudhra root CA certificates", and that on those releases the
// built-in command-line tools stop accepting the 12 compromised certificates ("Starting in macOS 27.2.1 [...] macOS
// 26.7.3 and macOS 15.8.3 also include this protection").
//
// None of this decides a verdict. The trust check's verdict is what the runtime itself does when it is asked to
// connect to the test hosts (lib/probe.mjs); a version number says what Apple shipped, not what is in the file now,
// and nobody has measured what an update to one of those releases does to a cert.pem changed by hand. The macOS
// version chooses only which fix text an EXPOSED row carries, and the three other roots are a note, never a status.
import { X509Certificate, createHash } from 'node:crypto';
import { readText } from './files.mjs';
import { safe } from './report.mjs';

export const SYSTEM_VERSION_PLIST = '/System/Library/CoreServices/SystemVersion.plist';

/** ProductVersion from the text of SystemVersion.plist, or '' when it isn't there in a form read here. */
export function productVersion(text) {
  const m = /<key>\s*ProductVersion\s*<\/key>\s*<string>\s*(\d+(?:\.\d+){0,3})\s*<\/string>/.exec(String(text ?? ''));
  return m ? m[1] : '';
}

/** This Mac's macOS version, read from the file (no program is run), or '' when it can't be read. */
export const readMacosVersion = (file = SYSTEM_VERSION_PLIST) => productVersion(readText(file, 64 * 1024));

const parts = (v) => String(v).split('.').map(Number);
// -1, 0 or 1; a missing part counts as 0 (27.2 is 27.2.0)
function compare(a, b) {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Where `version` stands against the releases Apple names as removing the roots (`releases`, one per major version,
 * newest first: ['27.2.1', '26.7.3', '15.8.3']):
 *   'fixed'       at or past the release Apple names for its major version, or a major version newer than all of them
 *                 (Apple: "Starting in macOS 27.2.1")
 *   'before-fix'  a major version Apple names, below its release: updating within it gets the fix
 *   'no-release'  a major version older than every one Apple names (macOS 14 and earlier): Apple names no update for it
 *   'unknown'     no version, or not one this table can place (16 to 25 were never macOS versions)
 */
export function appleFixState(version, releases) {
  const v = String(version ?? '');
  if (!/^\d+(\.\d+){0,3}$/.test(v) || !Array.isArray(releases) || !releases.length) return 'unknown';
  const major = parts(v)[0];
  const majors = releases.map((r) => parts(r)[0]);
  const named = releases.find((r) => parts(r)[0] === major);
  if (named) return compare(v, named) >= 0 ? 'fixed' : 'before-fix';
  if (major > Math.max(...majors)) return 'fixed';
  if (major < Math.min(...majors)) return 'no-release';
  return 'unknown';
}

/**
 * The fix text for an EXPOSED trust row. `appleFix` is the incident's record of Apple's fix ({ fixKeys, releases });
 * `macos` the version read on this Mac. Off macOS, and for every runtime Apple's fix does not cover, it is the text it
 * always was. The macOS version is put into the text where it says {macos}.
 */
export function trustFix(inc, rt, { os, macos = '' } = {}) {
  if (rt.fixKey) return inc.fixes[rt.fixKey];
  if (rt.kind === 'macos-system') return inc.fixes['macos-system'];
  if (rt.system) return inc.fixes['curl:linux'];
  const key = inc.fixes[`${rt.kind}:${rt.bin}:${os}`] !== undefined ? `${rt.kind}:${rt.bin}:${os}` : '';
  if (key && os === 'darwin' && inc.appleFix?.fixKeys?.includes(key)) {
    const state = appleFixState(macos, inc.appleFix.releases);
    const text = inc.fixes[`${key}:${state}`] ?? inc.fixes[key];
    return text.replaceAll('{macos}', macos || 'unknown');
  }
  return inc.fixes[key] ?? inc.fixes[`${rt.kind}:${os}`] ?? inc.fixes[rt.kind];
}

// Each block from a BEGIN line to its END line, read line by line (a regex over the whole file went quadratic on a
// BEGIN line with no END, a stall a review measured at 2 s for 512 KB). `trusted`: a BEGIN TRUSTED CERTIFICATE block,
// which LibreSSL loads as a trust anchor too and node:crypto does not read; it is counted as unreadable, never skipped.
function pemBlocks(text) {
  const out = []; let cur = null;
  for (const line of String(text ?? '').split(/\r?\n/)) {
    // TRUSTED and the old X509 label are loaded as certificates by LibreSSL and OpenSSL, and node:crypto reads neither
    const begin = /^-----BEGIN (TRUSTED |X509 )?CERTIFICATE-----\s*$/.exec(line);
    if (begin) { if (cur) out.push({ ...cur, broken: true }); cur = { lines: [line], trusted: !!begin[1] }; continue; }
    if (!cur) continue;
    cur.lines.push(line);
    if (/^-----END (TRUSTED |X509 )?CERTIFICATE-----\s*$/.test(line)) { out.push({ text: cur.lines.join('\n'), trusted: cur.trusted }); cur = null; }
  }
  if (cur) out.push({ ...cur, broken: true });
  return out;
}
const hex = (fp) => String(fp).replace(/:/g, '').toUpperCase();

/**
 * Which of `roots` ({ name, sha256 }) the PEM text holds, by SHA-256 fingerprint, with how many certificates were read
 * and how many could not be: { held: [names], read, unreadable }. A note only (see the top of this file).
 */
export function rootsHeld(text, roots) {
  const want = new Map(roots.map((r) => [hex(r.sha256), r.name]));
  const held = new Set(); let read = 0, unreadable = 0;
  for (const block of pemBlocks(text)) {
    let fp;
    if (block.trusted || block.broken) { unreadable++; continue; }
    try { fp = hex(new X509Certificate(block.text).fingerprint256); } catch { unreadable++; continue; }
    read++;
    if (want.has(fp)) held.add(want.get(fp));
  }
  return { held: roots.map((r) => r.name).filter((n) => held.has(n)), read, unreadable };
}

/**
 * What a CA bundle vouches for, judged by KEY, not by name or by fingerprint alone: the SHA-256 of each certificate's
 * public key (SPKI) against the incident's two withdrawn roots (`distrustedRoots`) and the seven withdrawn keys
 * (`withdrawnKeys`). A cross-sign or re-issue of a withdrawn key carries the same key and is caught; a relabelled name
 * line changes nothing (GHSA-66g2-c367-j933 was matching by names). → { held: [names], read, unreadable }.
 * A block that can't be read (TRUSTED, cut short, not a certificate) is counted, never skipped: the caller must not
 * call a file with any unreadable block clean.
 */
export function bundleHolds(text, inc) {
  const want = new Map([...(inc.distrustedRoots ?? []), ...(inc.withdrawnKeys ?? [])].map((k) => [String(k.spkiSha256).toLowerCase(), k.name]));
  if (!want.size) throw new Error(`${inc.id}: no withdrawn roots or keys to look for`);
  const held = new Set(); let read = 0, unreadable = 0;
  for (const block of pemBlocks(text)) {
    if (block.trusted || block.broken) { unreadable++; continue; }
    let spki;
    try { spki = createHash('sha256').update(new X509Certificate(block.text).publicKey.export({ type: 'spki', format: 'der' })).digest('hex'); } catch { unreadable++; continue; }
    read++;
    if (want.has(spki)) held.add(want.get(spki));
  }
  return { held: [...want.values()].filter((n, i, a) => held.has(n) && a.indexOf(n) === i), read, unreadable };
}

/**
 * The note printed once under the eMudhra trust check on a Mac: the macOS version and what Apple says of it, and
 * whether /etc/ssl/cert.pem still holds the three other roots Apple's update removes. Every clause names what it read.
 * `version` and `certText` are passed in (the caller reads them), so the wording is testable without a Mac.
 */
export function appleNote(inc, { version, certText, certFile = '/etc/ssl/cert.pem' }) {
  const f = inc.appleFix; if (!f) return [];
  const out = [];
  const state = appleFixState(version, f.releases);
  const named = f.releases.join(', ').replace(/, ([^,]*)$/, ' and $1');
  const said = `Apple says macOS ${named} (${f.date}) remove the withdrawn roots from ${certFile} (${f.source})`;
  if (state === 'fixed') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}, and this is one of them or later. A version says what Apple shipped, not what is in the file now: the rows above are what this Mac's own tools did.`);
  else if (state === 'before-fix') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}. This Mac doesn't have that update yet.`);
  else if (state === 'no-release') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}. Apple names no update for macOS ${parts(version)[0]}: if this Mac can run macOS 15 or later, updating to 15.8.3 or later is Apple's fix, and if not, the Mac fix is.`);
  else if (version) out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}) is not a release this can place against Apple's list, so this run can't say whether this Mac has Apple's update. ${said}.`);
  else out.push(`the macOS version could not be read from ${SYSTEM_VERSION_PLIST}, so this run can't say whether this Mac has Apple's update. ${said}.`);
  if (certText === null || certText === undefined) out.push(`${certFile} could not be read, so whether it holds the three other roots Apple's update removes was not checked.`);
  else {
    const r = rootsHeld(certText, f.alsoRemoved);
    if (r.held.length) {
      const one = r.held.length === 1;
      out.push(`${certFile} holds ${r.held.join(', ')}: Apple's update removes ${one ? 'this root' : 'these roots'} as well. Apple did not say ${one ? 'its key was' : 'their keys were'} compromised, so ${one ? 'it changes' : 'they change'} no result here.`
        + (state === 'fixed' ? ` On this release Apple says ${one ? 'it is' : 'they are'} gone from the file, so this file is not what Apple says the update installs: the update did not replace it (we measured one Mac on 10 Nov 2026 whose update from 27.2 to 27.2.1 replaced a hand-changed file with Apple's; other Macs and releases weren't measured), or an older copy was put back after it, such as a backup (Apple says not to restore a backup made before the update).` : ''));
    }
    if (!r.read) out.push(`no certificate in ${certFile} could be read here${r.unreadable ? ` (${r.unreadable} block${r.unreadable === 1 ? '' : 's'} could not be)` : ''}, so whether it holds the three other roots Apple's update removes was not checked.`);
    else if (r.unreadable) out.push(`${r.unreadable} certificate${r.unreadable === 1 ? '' : 's'} in ${certFile} could not be read, so whether ${r.unreadable === 1 ? 'it is' : 'they are'} among the three other roots Apple's update removes was not checked (${r.read} read).`);
  }
  return out;
}

/**
 * macOS's own copy of a library Apple fixed in an update (the Brotli incident's `appleSystem`: Apple's security notes
 * of 9 Nov 2026 list CVE-2026-111497 under "brotli" for macOS 27.2.1, 26.7.3 and 15.8.3). That copy is inside the
 * system, not a file Wardlatch can read as one, so the macOS version and Apple's own notes are all there is, and the
 * row says exactly that. `version` is read by the caller from SystemVersion.plist. → one row:
 *   at or past the release Apple names for this macOS → SAFE, its receipt the file the version was read from
 *   a macOS Apple names, before that release        → EXPOSED, fix: update macOS
 *   macOS 14 or older                               → UNKNOWN (Apple names no update; its notes don't say it is unaffected)
 *   no version, or one this can't place             → UNKNOWN
 */
export function appleSystemRow(inc, version) {
  const a = inc.appleSystem;
  if (!a) return null;
  const state = appleFixState(version, a.releases);
  const named = a.releases.join(', ').replace(/, ([^,]*)$/, ' and $1');
  const said = `Apple's security notes of ${a.date} list ${a.cve} under "${a.component}" for macOS ${named} (${a.sources.join(', ')})`;
  const base = { what: 'macOS', label: a.label, version: version || '', file: SYSTEM_VERSION_PLIST };
  if (state === 'fixed') return safe([SYSTEM_VERSION_PLIST], { ...base, reason: `macOS ${version}, read from ${SYSTEM_VERSION_PLIST}: ${said}, and this is one of them or later. Apple's copy is inside the system and is not read here: this rests on the version and Apple's notes` });
  if (state === 'before-fix') {
    const want = a.releases.find((r) => parts(r)[0] === parts(version)[0]);
    return { ...base, status: 'EXPOSED', reason: `macOS ${version}, read from ${SYSTEM_VERSION_PLIST}: ${said}, and this Mac doesn't have that update yet`, fix: a.fix.replaceAll('{release}', want) };
  }
  if (state === 'no-release') return { ...base, status: 'UNKNOWN', reason: `macOS ${version}, read from ${SYSTEM_VERSION_PLIST}: ${said}, and none for macOS ${parts(version)[0]}. Apple's notes don't say whether this release is affected` };
  return { ...base, status: 'UNKNOWN', reason: version ? `macOS ${version}, read from ${SYSTEM_VERSION_PLIST}, is not a release this can place: ${said}` : `the macOS version could not be read from ${SYSTEM_VERSION_PLIST}, so whether this Mac has Apple's fix is not known: ${said}` };
}

/**
 * The copies of cert.pem left in /etc/ssl (W6, W7; measured on one Mac on 10 Nov 2026: the update to 27.2.1 replaced
 * cert.pem and left cert.pem.bak and the Mac fix's own cert.pem.wardlatch-<date>.bak, both holding all five eMudhra
 * roots). On a release Apple names, each one that holds a withdrawn root or key is a REVIEW row: it is the file Apple
 * says not to put back. Read, never changed. One that can't be read is a REVIEW row too, never passed over. `backups`:
 * [{ file, text }] (text null when it couldn't be read). Before Apple's release nothing is said: they are the undo.
 */
export function backupRows(inc, version, backups) {
  const f = inc.appleFix;
  if (!f || appleFixState(version, f.releases) !== 'fixed') return [];
  const dont = `Don't restore it, even if a program stops connecting after the update: Apple says not to restore a backup made before the update, and to delete it once you have updated (${f.source}). Programs that read /etc/ssl/cert.pem themselves (the Pythons uv installs among them, measured on one Mac) would trust the withdrawn roots again if it were put back. Wardlatch read it and changed nothing.`;
  const rows = [];
  for (const b of backups) {
    const ours = /^cert\.pem\.wardlatch-\d{8}-\d{6}\.bak$/.test(b.file.split('/').pop()) ? " (the Mac fix's own backup)" : '';
    if (b.text === null || b.text === undefined) { rows.push({ kind: 'backup', status: 'REVIEW', file: b.file, reason: `${b.file}${ours} could not be read here, so whether it holds the withdrawn roots was not checked. If it is a copy of cert.pem from before the update: ${dont}` }); continue; }
    const r = bundleHolds(b.text, inc);
    if (r.held.length) rows.push({ kind: 'backup', status: 'REVIEW', file: b.file, heldRoots: r.held, reason: `${b.file}${ours} is a copy of cert.pem that still holds ${r.held.join(' and ')} (by key). ${dont}` });
    else if (r.unreadable) rows.push({ kind: 'backup', status: 'REVIEW', file: b.file, reason: `${b.file}${ours}: ${r.unreadable} of ${r.read + r.unreadable} certificate${r.read + r.unreadable === 1 ? '' : 's'} could not be read here, so whether it holds the withdrawn roots was not checked. If it is a copy of cert.pem from before the update: ${dont}` });
  }
  return rows;
}

/**
 * When the trust check may read a file in place of the forced-roots control (lib/probe.mjs fileVerdict): on a Mac
 * running a release Apple names (27.2.1, 26.7.3, 15.8.3 or later), for the built-in curl or python3 (the file is
 * /etc/ssl/cert.pem) or the built-in curl testing a named bundle (certifi's, REQUESTS_CA_BUNDLE's: that file).
 * → { fileCheck } to use, { skipped: reason } when the tool could be reading another file than the one named, or {}.
 * Settings that point the tool elsewhere (SSL_CERT_FILE, SSL_CERT_DIR, a .curlrc) keep the row UNKNOWN, with why.
 */
export function appleFileCheck(inc, rt, { os, macos = '', env = {}, home = '', exists = () => false, certsDir = 0 } = {}) {
  if (os !== 'darwin' || !inc.appleFix || appleFixState(macos, inc.appleFix.releases) !== 'fixed') return {};
  if (!['/usr/bin/curl', '/usr/bin/python3'].includes(rt.bin)) return {};
  const args = rt.args ?? [];
  if (rt.bin === '/usr/bin/curl' && args.length === 2 && args[0] === '--cacert' && args[1]) return { fileCheck: { file: args[1], kind: 'bundle', inc, macos } };
  if (args.length || rt.env) return {};
  // set at all, even empty (an empty SSL_CERT_FILE makes LibreSSL load no file); CURL_CA_BUNDLE moves curl (review 1)
  const set = ['SSL_CERT_FILE', 'SSL_CERT_DIR', ...(rt.bin === '/usr/bin/curl' ? ['CURL_CA_BUNDLE'] : [])].filter((k) => env[k] !== undefined);
  if (set.length) return { skipped: `${set.join(set.length > 2 ? ', ' : ' and ')} ${set.length === 1 ? 'is' : 'are'} set, so this tool may read another file than /etc/ssl/cert.pem, and the file was not read in place of the control` };
  if (rt.bin === '/usr/bin/curl') {
    const rcs = [...new Set([env.CURL_HOME && `${env.CURL_HOME}/.curlrc`, env.XDG_CONFIG_HOME && `${env.XDG_CONFIG_HOME}/.curlrc`, home && `${home}/.curlrc`].filter(Boolean))].filter((p) => exists(p));
    if (rcs.length) return { skipped: `${rcs.join(', ')} can point curl at another file than /etc/ssl/cert.pem, so the file was not read in place of the control` };
  }
  // Apple's python3 also reads the folder /etc/ssl/certs (its capath): the file stands in only when that folder holds
  // nothing (review 1); `certsDir` is how many entries it has, -1 when it can't be listed
  if (rt.bin === '/usr/bin/python3' && certsDir !== 0) return { skipped: `/etc/ssl/certs ${certsDir < 0 ? 'could not be listed' : `holds ${certsDir} file${certsDir === 1 ? '' : 's'}`}, and python3 reads that folder as well as /etc/ssl/cert.pem, so the file was not read in place of the control` };
  return { fileCheck: { file: '/etc/ssl/cert.pem', kind: 'system', inc, macos } };
}

/**
 * A line for an UNKNOWN row of the built-in curl or python3 on a release Apple says blocks the 12 certificates in its
 * command-line tools: that block can make the forced-roots control fail too, which nobody here has measured. It changes
 * no status; it says why the row may be UNKNOWN on an updated Mac. '' when it doesn't apply.
 */
export function appleUnknownNote(inc, rt, row, { os, macos = '' } = {}) {
  if (os !== 'darwin' || row?.status !== 'UNKNOWN' || !inc.appleFix || !/^positive control failed/.test(row.reason ?? '') || !/a certificate error/.test(row.reason ?? '')) return '';
  if (!['/usr/bin/curl', '/usr/bin/python3'].includes(rt.bin) || rt.args?.length || rt.env) return '';
  if (appleFixState(macos, inc.appleFix.releases) !== 'fixed') return '';
  return `on macOS ${macos} Apple says the built-in command-line tools themselves stop accepting the 12 compromised certificates (${inc.appleFix.source}), and that makes this control fail too (measured on one Mac updated to 27.2.1, 10 Nov 2026). The file this tool reads was not read in its place here, so this row says only that this tool could not be tested this way.`;
}
