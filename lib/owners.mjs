// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Who a folder Wardlatch couldn't open belongs to (owner, 22 Oct 2026): a person, whose folders could hold their projects
// or sites, so not having looked is UNKNOWN; or a service (root, a database, a container, certbot), whose folders hold
// that service's data, so they are listed in one REVIEW line. bin/wardlatch.mjs gaps() is the one place it is applied.
import { platform } from 'node:os';
import { readText, ownerOf } from './files.mjs';

// the web server's accounts: for the WordPress check they count as people, since they own websites
const WEB_ACCOUNTS = ['www-data', 'apache', 'nginx', 'wwwrun', 'http', '_www'];
// "nobody" (and its 32-bit forms): never a person
const NOBODY = [65534, 4294967294, 4294967295];

/** uid → account name, from /etc/passwd (macOS's _www, uid 70, is added: its accounts live in Directory Services). */
export function accounts(passwd = readText('/etc/passwd', 4 * 1024 * 1024) ?? '', os = platform()) {
  const names = new Map([[0, 'root']]);
  for (const line of passwd.split('\n')) { const f = line.split(':'); if (f.length > 3 && /^\d+$/.test(f[2])) names.set(Number(f[2]), f[0]); }
  if (os === 'darwin' && !names.has(70)) names.set(70, '_www');
  return names;
}

/** The uid ranges handed to rootless containers (/etc/subuid, /etc/subgid): a container's files, a service's. */
export function subuidRanges(text = `${readText('/etc/subuid', 1024 * 1024) ?? ''}\n${readText('/etc/subgid', 1024 * 1024) ?? ''}`) {
  const out = [];
  for (const line of text.split('\n')) { const [, start, count] = line.split(':'); if (/^\d+$/.test(start ?? '') && /^\d+$/.test(count ?? '')) out.push([Number(start), Number(start) + Number(count) - 1]); }
  return out;
}

let cache;
const defaults = () => (cache ??= { self: process.getuid?.(), os: platform(), names: accounts(), subuids: subuidRanges() });

/**
 * Whether a folder owned by `uid` is a person's. An owner that can't be told (null) counts as a person's: not having
 * looked must not read as a service's data. A person is this user, or any login account: uid 1000 and up on Linux, 501
 * and up on macOS, with no upper limit (a company directory's accounts have uids in the hundreds of millions), except
 * "nobody" and the uids handed to rootless containers. For WordPress (`kind`), the web server's accounts count too.
 */
export function isPersonUid(uid, kind, opts = {}) {
  const { self, os, names, subuids } = { ...defaults(), ...opts };
  // on Windows a file's owner can't be read this way (Node reports uid 0 for every file): never told, so a person's
  if (os === 'win32' || uid === null || uid === undefined || uid === self) return true;
  if (uid === 0) return false;
  if (kind === 'wordpress' && WEB_ACCOUNTS.includes(names.get(uid))) return true;
  if (NOBODY.includes(uid) || subuids.some(([a, b]) => uid >= a && uid <= b)) return false;
  return uid >= (os === 'darwin' ? 501 : 1000);
}

/** Whether the folder at `path` is a person's (isPersonUid on its owner). */
export const ownedByPerson = (path, kind, opts) => isPersonUid(ownerOf(path), kind, opts);

/** An owner's name for the review line. */
export const ownerName = (path) => { const uid = ownerOf(path); return defaults().names.get(uid) ?? `uid ${uid}`; };
