// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// What Apple's own fix for /etc/ssl/cert.pem means for this Mac. Apple's page on the eMudhra incident
// (support.apple.com/en-us/149555, as of 9 Nov 2026) says macOS 27.2.1, 26.7.3 and 15.8.3 remove the two withdrawn
// roots from /etc/ssl/cert.pem, "along with three other eMudhra root CA certificates", and that "Starting in macOS
// 27.2.1" the built-in command-line tools stop accepting the 12 compromised certificates.
//
// None of this decides a verdict. The trust check's verdict is what the runtime itself does when it is asked to
// connect to the test hosts (lib/probe.mjs); a version number says what Apple shipped, not what is in the file now,
// and nobody has measured what an update to one of those releases does to a cert.pem changed by hand. The macOS
// version chooses only which fix text an EXPOSED row carries, and the three other roots are a note, never a status.
import { X509Certificate } from 'node:crypto';
import { readText } from './files.mjs';

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

const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const hex = (fp) => String(fp).replace(/:/g, '').toUpperCase();

/**
 * Which of `roots` ({ name, sha256 }) the PEM text holds, by SHA-256 fingerprint, with how many certificates were read
 * and how many could not be: { held: [names], read, unreadable }. A note only (see the top of this file).
 */
export function rootsHeld(text, roots) {
  const want = new Map(roots.map((r) => [hex(r.sha256), r.name]));
  const held = new Set(); let read = 0, unreadable = 0;
  for (const block of String(text ?? '').match(PEM) ?? []) {
    let fp;
    try { fp = hex(new X509Certificate(block).fingerprint256); } catch { unreadable++; continue; }
    read++;
    if (want.has(fp)) held.add(want.get(fp));
  }
  return { held: roots.map((r) => r.name).filter((n) => held.has(n)), read, unreadable };
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
  if (state === 'fixed') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}, and this is one of them or later. A version says what Apple shipped, not what is in the file now: the curl and python3 lines above are what this Mac's own tools did.`);
  else if (state === 'before-fix') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}. This Mac doesn't have that update yet.`);
  else if (state === 'no-release') out.push(`macOS ${version} (read from ${SYSTEM_VERSION_PLIST}): ${said}. Apple names no update for macOS ${parts(version)[0]}, so on this Mac the file stays as it is unless it is fixed by hand.`);
  else out.push(`the macOS version could not be read from ${SYSTEM_VERSION_PLIST}, so this run can't say whether this Mac has Apple's update. ${said}.`);
  if (certText === null || certText === undefined) out.push(`${certFile} could not be read, so whether it holds the three other roots Apple's update removes was not checked.`);
  else {
    const r = rootsHeld(certText, f.alsoRemoved);
    if (r.held.length) {
      const one = r.held.length === 1;
      out.push(`${certFile} holds ${r.held.join(', ')}: Apple's update removes ${one ? 'this root' : 'these roots'} as well. Apple did not say ${one ? 'its key was' : 'their keys were'} compromised, so ${one ? 'it changes' : 'they change'} no result here.`
        + (state === 'fixed' ? ` On this release Apple says ${one ? 'it is' : 'they are'} gone from the file, so this file is not what Apple says the update installs: the update did not replace it (we haven't measured what an update does to a file changed by hand), or an older copy was put back after it, such as a backup (Apple says not to restore a backup made before the update).` : ''));
    }
    if (r.unreadable) out.push(`${r.unreadable} certificate${r.unreadable === 1 ? '' : 's'} in ${certFile} could not be read, so the note above covers the ${r.read} that could.`);
  }
  return out;
}
