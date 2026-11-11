// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// --reach (docs/REACH.md): for a fixed list of places a credential stealer goes for (lib/reach/items.json, each with the
// vendor page that names it), can THIS process open the place for reading? It answers one question: if a program ran in
// this terminal or CI job now, what could it open. It is not a malware scan, has no signatures, and says nothing about
// whether anything was taken.
//
// What it does to each place, and nothing else:
//   lstat      what is at the path (a file, a folder, a link, something else), without following a link
//   realpath   only to learn whether a link on the way leads outside the home folder
//   open       O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY (and O_DIRECTORY for a folder), then close at once
// It never reads a byte, never lists a folder, never stats what is inside one, and opens no network connection. The
// four functions above are the whole of `io` below: test/reach.test.mjs runs it against a stand-in that fails on any
// other call, and a spy in a child process that fails when a descriptor opened under the home folder is read.
//
// Five states, and what each errno means here (Apple's DTS, https://developer.apple.com/forums/thread/678819: blocked by
// BSD permissions or ACLs is EACCES; blocked "by something else" is EPERM):
//   reachable       the open succeeded. A fact about this process, now.
//   blocked         EACCES (permission bits or an ACL, on the place or on a folder on the way) or EPERM (the system
//                   refused above the permission bits: on macOS its privacy protection, or a sandbox the run is inside;
//                   on Linux a security module or a sandbox). Never said for any other errno.
//   absent          ENOENT or ENOTDIR from lstat (nothing at that path, or a file where a folder on the way should be),
//                   and only when neither rule below turns it into "could not tell".
//   could not tell  everything else, named: any other errno (ELOOP, ENAMETOOLONG, EIO, ENXIO, EMFILE, ...); ENOENT for a
//                   place the system keeps in every account (items.json `mustExist`: a refusal can look like that);
//                   ENOENT when a variable the vendor documents says the tool keeps it elsewhere (`moved`; only the
//                   variable's name is looked at, never its value, and the other place is not followed); ENOENT from
//                   open after lstat saw the file; a link that leads outside the home folder (not followed), or to
//                   nothing; a FIFO, socket or device, or a file where a folder is expected (not opened: opening a
//                   FIFO for reading waits for a writer); no home folder; an operating system this does not support.
//   not applicable  the place does not exist on this operating system (Messages on Linux). Not "absent".
// Nothing here is SAFE, EXPOSED or UNKNOWN: those belong to the incident checks, and --reach runs none of them. A
// "reachable" and a "could not tell" are REVIEW lines; the exit code is 0 whatever is found (bin/wardlatch.mjs).
//
// Privacy of the output: the labels and paths printed are the fixed ones from items.json with the home folder written
// as ~, plus a state, an errno name and counts. No user name, no real path, no size or time, nothing from inside a
// file, and no value of an environment variable.
import { readText, OPEN_CLOSE } from './files.mjs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The four calls --reach makes on the disk (lib/files.mjs OPEN_CLOSE, where the open's flags are). A test passes its
 *  own; nothing else in this file touches a file under the home folder. */
export const REAL_IO = OPEN_CLOSE;

export const STATES = Object.freeze(['reachable', 'blocked', 'absent', 'unknown', 'not-applicable']);
/** A state as printed. `unknown` is "could not tell": it is not the incident checks' UNKNOWN and does not set exit 2. */
export const WORDS = Object.freeze({ reachable: 'reachable', blocked: 'blocked', absent: 'not there', unknown: 'could not tell', 'not-applicable': 'not applicable' });

/** The item list and the guards' texts, from lib/reach/items.json (Wardlatch's own file, not one under the home folder). */
export function loadItems(file = join(dirname(fileURLToPath(import.meta.url)), 'reach', 'items.json')) {
  const text = readText(file, 4 * 1024 * 1024);
  if (text === null) throw new Error('lib/reach/items.json could not be read');
  return JSON.parse(text);
}

// an errno name as Node gives it, and nothing else: what is printed never comes from a message, which can carry a path
const errnoName = (e) => (typeof e?.code === 'string' && /^E[A-Z0-9]{1,24}$/.test(e.code) ? e.code : 'an error with no errno');
const REFUSED = { EACCES: 'permissions', EPERM: 'system' };
const refusal = (e, at) => (REFUSED[e?.code] ? { state: 'blocked', by: REFUSED[e.code], errno: e.code, at } : null);
const unknown = (why, errno, at) => ({ state: 'unknown', why, ...(errno ? { errno } : {}), ...(at ? { at } : {}) });

/**
 * One path, opened and closed → { state, by?, why?, errno?, at? }. `abs` is `realHome` + the item's fixed relative path,
 * so the only links realpath can find on the way are ones inside that relative path.
 */
export function probePath(abs, kind, realHome, io = REAL_IO) {
  let st;
  try { st = io.lstat(abs); } catch (e) {
    // nothing at the path (ENOENT), or a file where a folder on the way should be (ENOTDIR): nothing a program could
    // open by this name. EACCES and EPERM are a refusal on a folder on the way. Anything else is not understood.
    if (e?.code === 'ENOENT' || e?.code === 'ENOTDIR') return { state: 'absent', errno: e.code };
    return refusal(e, 'lstat') ?? unknown('errno', errnoName(e), 'lstat');
  }
  let target = abs;
  let real;
  try { real = io.realpath(abs); } catch (e) {
    // lstat saw something here, so "no such file" now is a link to nothing, or a place that changed under the run
    if (e?.code === 'ENOENT' || e?.code === 'ENOTDIR') return unknown('link-to-nothing', e.code, 'realpath');
    return refusal(e, 'realpath') ?? unknown('errno', errnoName(e), 'realpath');
  }
  if (real !== abs) {
    // A link (or, on a file system that ignores case, another spelling). Inside the home folder it is followed: a
    // dotfiles folder linked into place is the same credential. Outside it, it is not: --reach promises to touch only
    // these places under the home folder, and a link can point at a device, a network share or another account. A
    // program that opens the path would follow it, so this is "could not tell", never "blocked" or "absent".
    if (real !== realHome && !real.startsWith(`${realHome}/`)) return unknown('link-outside');
    try { st = io.lstat(real); } catch (e) { return refusal(e, 'lstat') ?? unknown('errno', errnoName(e), 'lstat'); }
    target = real;
  }
  // Only a regular file (or, for a folder item, a folder) is opened. A FIFO opened for reading waits for a writer, a
  // device can do anything, and a folder where a file is expected is not the thing the item names.
  if (kind === 'dir' ? !st.isDirectory() : !st.isFile()) return unknown(st.isFile() || st.isDirectory() ? 'wrong-kind' : 'not-regular');
  let fd;
  try {
    // read-only, and it cannot wait or be led elsewhere: a FIFO put there between lstat and now returns at once
    // (O_NONBLOCK), a link put there fails (O_NOFOLLOW, ELOOP)
    fd = io.openRead(target, kind === 'dir');
  } catch (e) {
    // ENOENT here is not "absent": lstat saw the file a moment ago
    return refusal(e, 'open') ?? unknown('errno', errnoName(e), 'open');
  }
  try { io.close(fd); } catch { /* it opened: that is the answer; a failed close changes nothing about it */ }
  return { state: 'reachable' };
}

// one answer for an item with more than one place: the strongest claim that is true of any of them
const RANK = ['reachable', 'unknown', 'blocked', 'absent'];

/**
 * Measure every item → { context, rows, counts }. `home` is the home folder to measure (bin/wardlatch.mjs gives the
 * person's under sudo); `os` is process.platform; `env` is read only for whether a `moved` variable is set; `uid` is
 * the effective user id, or undefined where there is none.
 */
export function measure({ data = loadItems(), home, os = process.platform, env = process.env, uid = process.geteuid?.(), io = REAL_IO } = {}) {
  const sys = os === 'darwin' ? 'darwin' : os === 'win32' ? null : 'linux';   // another Unix keeps the same dotfiles as Linux
  let realHome = null, homeErrno = null;
  if (sys && typeof home === 'string' && home.startsWith('/')) {
    try { realHome = io.realpath(home); } catch (e) { homeErrno = errnoName(e); }
  }
  const rows = data.items.map((item) => {
    const base = { id: item.id, group: item.group, label: item.label, kind: item.kind, source: item.source };
    const rels = sys ? item.paths?.[sys] : undefined;
    // a "could not tell" before anything was opened: the same REVIEW line, with its reason, as one found by opening
    const early = (path, res) => ({ ...base, path, ...res, reason: unknownWhy(res, item, 1), status: 'REVIEW' });
    if (!sys) return early(null, unknown('unsupported-os'));
    if (!rels?.length) return { ...base, path: null, state: 'not-applicable' };
    if (!realHome) return early(`~/${rels[0]}`, unknown('no-home', homeErrno));
    const tried = rels.map((rel) => ({ rel, ...probePath(join(realHome, rel), item.kind, realHome, io) }));
    const best = tried.slice().sort((a, b) => RANK.indexOf(a.state) - RANK.indexOf(b.state))[0];
    let { rel, ...res } = best;
    if (res.state === 'absent') {
      // "absent" is only said from a complete look. Two things make it incomplete:
      const moved = (item.moved ?? []).filter((k) => typeof env[k] === 'string' && env[k] !== '');
      if (item.mustExist?.includes(sys)) res = unknown('must-exist', res.errno);
      else if (moved.length) res = { ...unknown('moved', res.errno), moved };
    }
    const guard = sys === 'darwin' && item.guard ? data.guards[item.guard] : null;
    const row = { ...base, path: `~/${rel}`, ...res, ...(rels.length > 1 ? { places: rels.length } : {}) };
    if (res.state === 'reachable') {
      // one fix line, from the data file: the guard's on a Mac (which setting lets this app in), else the item's own
      const fix = guard ?? item;
      Object.assign(row, { fix: fix.fix, fixSource: fix.fixSource });
    }
    if (res.state === 'blocked') Object.assign(row, blockedWhy(res, guard, sys, uid));
    if (res.state === 'unknown') row.reason = unknownWhy(res, item, rels.length);
    if (res.state === 'reachable' || res.state === 'unknown') row.status = 'REVIEW';
    return row;
  });
  const counts = Object.fromEntries(STATES.map((s) => [s, rows.filter((r) => r.state === s).length]));
  return { context: { os: sys ?? 'unsupported', root: uid === 0, home: realHome ? '~' : null, items: rows.length }, rows, counts };
}

/** What is known about why a place is blocked, or that it is not known. */
function blockedWhy(res, guard, sys, uid) {
  const where = res.at === 'open' ? '' : ' on a folder on the way';
  if (res.by === 'permissions') {
    return { reason: `file permissions or an access list${where} (EACCES). Whoever owns it can change them, so this holds only while they stay as they are${uid === 0 ? '' : '; a program running as root is not stopped by them'}` };
  }
  if (guard) return { reason: `the system refused it${where}, above the file permissions (EPERM). Why: ${guard.blocked}`, reasonSource: guard.blockedSource };
  return { reason: `the system refused it${where}, above the file permissions (EPERM). Wardlatch does not know which protection did: ${sys === 'darwin'
    ? 'macOS\'s privacy protection, or a sandbox this run is inside' : 'a sandbox this run is inside, or a security module (SELinux, AppArmor)'}` };
}

/** Why an answer is "could not tell", in words. Fixed sentences: nothing from the disk is in them but an errno name. */
function unknownWhy(res, item, places) {
  const at = res.at ? ` (${res.errno} from ${res.at})` : res.errno ? ` (${res.errno})` : '';
  switch (res.why) {
    case 'unsupported-os': return 'Windows is not supported: nothing was opened';
    case 'no-home': return `the home folder could not be resolved${at}: nothing was opened`;
    case 'must-exist': return `the system said there is no file here${at}, which is not believed for this place. ${item.mustExistSays}`;
    case 'moved': return `nothing at the default place${places > 1 ? 's' : ''}${at}, but ${res.moved.join(' and ')} ${res.moved.length > 1 ? 'are' : 'is'} set, which tells the tool to keep it somewhere else. Wardlatch looks only at the default place${places > 1 ? 's' : ''} and did not follow the variable`;
    case 'link-outside': return 'a link that leads outside the home folder. Wardlatch did not follow it; a program that opens this path would';
    case 'link-to-nothing': return `a link whose target is not there, or a place that changed during the run${at}`;
    case 'not-regular': return 'something other than a file or folder is here (a FIFO, socket or device). Wardlatch did not open it';
    case 'wrong-kind': return `a ${item.kind === 'dir' ? 'file is here where a folder' : 'folder is here where a file'} is expected. Wardlatch did not open it`;
    default: return `an answer Wardlatch does not have a rule for${at}`;
  }
}

/** The lines of the text report → [{ review, text, tone, row }]: `row` lines sit in the result column, `review` puts
 *  REVIEW in the status column of one, `tone` is 'head', 'plain' or 'dim'. bin/wardlatch.mjs prints them; every string is fixed text from here or from items.json. */
export function lines(result) {
  const { context, rows, counts } = result;
  const out = [];
  const say = (text, tone = 'plain', review = false, row = false) => out.push({ review, text, tone, row });
  say('Reach: what a program started from this terminal could open right now', 'head');
  say(`Measured: this process only (Node, started from this shell, as ${context.root ? 'root' : 'this user'}), by opening each place below for reading and`, 'dim');
  say('closing it at once. Nothing was read, no folder was listed, nothing was sent. Another terminal or app has its own', 'dim');
  say('permissions and may get other answers. This is not a malware scan: "reachable" means this process can open it,', 'dim');
  say('not that anything has. A "blocked" or "not there" line is about this process and these paths, and is no all-clear.', 'dim');
  if (context.root) say('Run as root: file permissions do not stop root, so this is what root can open, not what your own account can.', 'dim');
  let group = null;
  for (const r of rows) {
    if (r.group !== group) { group = r.group; say(''); say(group, 'head'); }
    const where = r.path ? `  ${r.path}${r.places > 1 ? ` (${r.places} places tried)` : ''}` : '';
    say(`${WORDS[r.state].padEnd(15)} ${r.label}${r.state === 'not-applicable' ? '' : where}`, 'plain', r.status === 'REVIEW', true);
    if (r.state === 'reachable') say(`    fix: ${r.fix} (${r.fixSource})`, 'dim', false, true);
    else if (r.state === 'blocked') say(`    why: ${r.reason}${r.reasonSource ? ` (${r.reasonSource})` : ''}`, 'dim', false, true);
    else if (r.state === 'unknown') say(`    why: ${r.reason}`, 'dim', false, true);
    else if (r.state === 'not-applicable') say(`    this place is not on ${context.os === 'linux' ? 'Linux' : 'this system'}`, 'dim', false, true);
  }
  say('');
  say(`${counts.reachable} reachable · ${counts.blocked} blocked · ${counts.absent} not there · ${counts.unknown} could not tell · ${counts['not-applicable']} not applicable here`);
  say('Exit code 0 whatever is above: these lines are for review. --reach runs no incident check and is no part of their result.', 'dim');
  say('Where each place and each fix comes from, and what this does not cover: docs/REACH.md', 'dim');
  return out;
}

/** The --json form. No `results`: a reader of the incident checks' output must not take this for one of theirs. */
export function toJson(result, version) {
  return {
    tool: 'wardlatch', version, mode: 'reach',
    measured: { process: 'this process only', user: result.context.root ? 'root' : 'this user', os: result.context.os, home: result.context.home, how: 'open for reading, then close; nothing read, no folder listed, nothing sent' },
    exitCode: 'always 0: review lines only, no incident check was run',
    counts: result.counts,
    reach: result.rows.map(({ kind, ...r }) => r),
  };
}
