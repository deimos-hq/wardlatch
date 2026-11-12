// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// npm packages a project pins, read from its lockfile and nothing else: package-lock.json and npm-shrinkwrap.json
// (npm), yarn.lock (Yarn classic and Berry) and pnpm-lock.yaml (pnpm). The file is read as text. Nothing in the project
// is run or imported, node_modules is not opened, and no registry is asked: a lockfile says what an install would
// fetch, which is what this reports, and all it reports.
//
// A lockfile that can't be read, or isn't one, or holds an entry this reader does not understand, is UNKNOWN for the
// whole file: a reader that skips what it can't parse reads a pinned package as absent (the shape of the 128
// certificates in, 1 decoded: a passing control beside an incomplete scan). So every parser here counts the entries
// it met and the entries it understood, and the two must agree.
import { join } from 'node:path';
import { readCapped, listDir, pathState, mayBeFolder, isSystemFolder, fileId, holdsMore, gapLists, walkedTo, unwalkedLinks } from './files.mjs';
import { cmp } from './binaries.mjs';
import { safe, saw } from './report.mjs';

// Folders this walk never enters, by name: a package's own files (node_modules holds the lockfiles of other people's
// packages, which pin nothing this project installs) and git's store. Said under every all-clear that rests on it.
export const NOT_WALKED = ['node_modules', '.git'];
// How deep the walk goes below each folder searched. Deeper than the other walks (4 or 5): a lockfile sits at a
// project's top, but a project's own folders run deep (src/app/components/…), and a floor at 5 would end almost every
// run on a developer's machine in "folders past the depth limit". A folder below the floor that holds more is still
// could-not-be-tested (holdsMore()).
export const LOCK_DEPTH = 10;
const MAX = 64 * 1024 * 1024;

/** Lockfile names → the reader for each. Bun's are found and named, never read: no reader for them here yet. */
export const LOCK_NAMES = { 'package-lock.json': 'npm', 'npm-shrinkwrap.json': 'npm', 'yarn.lock': 'yarn', 'pnpm-lock.yaml': 'pnpm', 'bun.lock': 'bun', 'bun.lockb': 'bun' };

/**
 * Every lockfile under `roots` → [{ path, kind }], kind as in LOCK_NAMES. Links to folders are recorded in `links`,
 * never followed; a folder that can't be opened goes to `denied`; a folder at the depth floor that holds more goes to
 * `deep`. An entry of a lockfile's name that is not a file this run can see as one (a folder is passed over; a link
 * that leads nowhere readable, a FIFO) is still returned, so the caller says UNKNOWN of it.
 */
export function lockfilesUnder(roots, maxDepth = LOCK_DEPTH, denied, links = denied, { deep } = {}) {
  // none of the gap lists is opt-in: one left out that the walk has something for makes it throw (lib/files.mjs gapLists())
  const gap = gapLists('lockfilesUnder()', { denied, links, deep });
  ({ denied, links, deep } = gap);
  const out = [];
  const listed = new Map(), maybeLinks = [];
  const walk = (d, depth) => {
    const l = listDir(d);
    if (l.denied) { denied?.push(d); return; }
    walkedTo(listed, d, depth);
    for (const e of l.entries ?? []) {
      const p = join(d, e.name);
      if (Object.hasOwn(LOCK_NAMES, e.name) && !e.isDirectory() && pathState(p) !== 'dir') { out.push({ path: p, kind: LOCK_NAMES[e.name] }); continue; }
      if (NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)) continue;
      if (e.isDirectory()) {
        // the floor: this folder's own files were listed above (a lockfile in it is found); the folders in it are not opened
        if (depth === 0) continue;
        walk(p, depth - 1);
        continue;
      }
      // a link to a folder is recorded, never followed: a project behind one would be passed over in silence otherwise
      if (e.isSymbolicLink() && mayBeFolder(p)) maybeLinks.push({ path: p, need: depth - 1 });
    }
    if (depth === 0 && deep && holdsMore(d, NOT_WALKED)) deep.push(d);
  };
  // one folder, one walk, however many names lead to it (lib/wordpress.mjs, AUDIT-25)
  const walked = new Set();
  for (const r of roots) {
    const id = fileId(r);
    if (id && walked.has(id)) continue;
    if (id) walked.add(id);
    walk(r, maxDepth);
  }
  if (links) links.push(...unwalkedLinks(maybeLinks, listed).map((c) => c.path));
  gap.done();
  return out;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The package a spec names: "react@^19.0.0" → react, "@scope/x@npm:1.0.0" → @scope/x; null when it names none. */
const specName = (spec) => { const at = spec.indexOf('@', 1); return at > 0 ? spec.slice(0, at) : null; };

/** npm's lockfile (lockfileVersion 1, 2 or 3) → { pins: [{ name, version }], entries } or { error }. */
function readNpm(text, names) {
  let j;
  try { j = JSON.parse(text); } catch { return { error: 'is not valid JSON, so it could not be read as an npm lockfile' }; }
  if (!isObj(j) || !Number.isInteger(j.lockfileVersion) || j.lockfileVersion < 1 || j.lockfileVersion > 3) return { error: 'is not an npm lockfile this check reads (lockfileVersion 1, 2 or 3)' };
  const pins = []; let entries = 0;
  if (j.packages !== undefined) {
    // lockfileVersion 2 and 3: one entry per installed path; the name is the entry's own (an alias) or the path's end
    if (!isObj(j.packages)) return { error: 'is an npm lockfile whose packages list could not be read' };
    for (const [key, e] of Object.entries(j.packages)) {
      if (key === '') continue;
      entries++;
      if (!isObj(e)) return { error: `is an npm lockfile with an entry that could not be read (${key.slice(0, 80)})` };
      if (e.link === true) continue;   // a workspace link: the package it points at has an entry of its own
      const name = typeof e.name === 'string' ? e.name : key.includes('node_modules/') ? key.slice(key.lastIndexOf('node_modules/') + 13) : null;
      if (name && names.includes(name)) pins.push({ name, version: typeof e.version === 'string' ? e.version : '' });
    }
    return { pins, entries };
  }
  // lockfileVersion 2 without a packages list is not what npm writes: its dependencies tree is a copy kept for old npms
  if (j.lockfileVersion !== 1) return { error: 'is an npm lockfile with no packages list' };
  if (j.dependencies !== undefined && !isObj(j.dependencies)) return { error: 'is an npm lockfile whose dependencies could not be read' };
  let bad = null;
  const tree = (deps) => {
    for (const [key, e] of Object.entries(deps ?? {})) {
      entries++;
      if (!isObj(e)) { bad ??= key; continue; }
      // an alias: "version": "npm:real-name@1.2.3"
      const alias = typeof e.version === 'string' && e.version.startsWith('npm:') ? e.version.slice(4) : null;
      const name = alias ? specName(alias) : key;
      const version = alias ? alias.slice((name ?? '').length + 1) : e.version;
      if (name && names.includes(name)) pins.push({ name, version: typeof version === 'string' ? version : '' });
      if (e.dependencies !== undefined) { if (isObj(e.dependencies)) tree(e.dependencies); else bad ??= key; }
    }
  };
  tree(j.dependencies);
  return bad ? { error: `is an npm lockfile with an entry that could not be read (${bad.slice(0, 80)})` } : { pins, entries };
}

/** yarn.lock, classic (v1) or Berry → { pins, entries } or { error }. An entry is a block: a line at the left margin
 *  ending in a colon that lists the specs it answers, then indented lines, one of them the version. */
function readYarn(text, names) {
  const classic = /^# yarn lockfile v1\s*$/m.test(text), berry = /^__metadata:\s*$/m.test(text);
  if (!classic && !berry) return { error: 'is not a yarn.lock this check reads (neither Yarn 1\'s header nor Yarn 2+\'s __metadata)' };
  const pins = []; let entries = 0, block = null, bad = null;
  const close = () => {
    if (!block) return;
    // the package a block installs: the names its specs carry, and the one its resolution names (an alias)
    const found = new Set(block.names);
    if (block.resolution) found.add(block.resolution);
    for (const name of found) if (names.includes(name)) pins.push({ name, version: block.version ?? '' });
    block = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || line.startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      close();
      if (!line.endsWith(':')) { bad ??= line; continue; }
      if (line === '__metadata:') { block = { names: [], meta: true }; continue; }
      entries++;
      const specs = line.slice(0, -1).split(',').map((s) => s.trim().replace(/^"|"$/g, '').trim()).filter(Boolean);
      const got = specs.map(specName);
      if (!specs.length || got.includes(null)) { bad ??= line; continue; }
      block = { names: got };
      continue;
    }
    if (!block) { bad ??= line; continue; }
    // "  version "1.2.3"" (classic) or "  version: 1.2.3" (Berry); Berry's "  resolution: "name@npm:1.2.3""; classic's
    // "  resolved "https://registry…/name/-/name-1.2.3.tgz#…"", which names the real package behind an alias
    const v = /^ {2}version:? "?([^"\s]+)"?\s*$/.exec(line);
    if (v && !block.meta) block.version = v[1];
    const r = /^ {2}resolution: "?((?:@[^/@\s]+\/)?[^/@\s]+)@/.exec(line);
    if (r && !block.meta) block.resolution = r[1];
    // the registry path before /-/ ends in the package's name, with its scope before it when it has one: taken from the
    // end, so "@acme/react-server-dom-webpack" is not read as the package it merely ends in
    const u = /^ {2}resolved "[a-z]+:\/\/[^/"]+\/([^"]*?)\/-\/[^/"]+\.tgz/.exec(line);
    if (u && !block.meta) { const parts = u[1].split('/'); block.resolution = parts.at(-2)?.startsWith('@') ? `${parts.at(-2)}/${parts.at(-1)}` : parts.at(-1); }
  }
  close();
  return bad ? { error: `is a yarn.lock with a line this check could not read (${bad.slice(0, 80)})` } : { pins, entries };
}

/** pnpm-lock.yaml → { pins, entries } or { error }. The packages (and, from lockfileVersion 9, snapshots) sections hold
 *  one key per installed package: name@1.2.3, /name@1.2.3(peers), or /name/1.2.3_peers in old lockfiles. */
function readPnpm(text, names) {
  if (!/^lockfileVersion:/m.test(text)) return { error: 'is not a pnpm lockfile (no lockfileVersion)' };
  const pins = new Map(); let entries = 0, section = null, bad = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const top = /^([A-Za-z][\w-]*):/.exec(line);
    if (top) { section = top[1]; continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    // an entry's key: indented two spaces exactly; what is deeper belongs to the entry before it
    if (!/^ {2}\S/.test(line)) continue;
    entries++;
    // the key: quoted, or plain up to the colon that ends it (a plain key may hold a colon that no space follows)
    const body = line.slice(2), q = body[0] === '\'' || body[0] === '"' ? body.indexOf(body[0], 1) : -1;
    const key = q > 0 ? (/^:(?:\s|$)/.test(body.slice(q + 1)) ? body.slice(1, q) : null) : (/^(.*?):(?:\s|$)/.exec(body)?.[1] ?? null);
    const id = (key ?? '').replace(/^\//, '').replace(/\(.*$/, '');
    const m = /^((?:@[^/@]+\/)?[^/@]+)[@/](.+)$/.exec(id);
    if (!m) { bad ??= line; continue; }
    const name = m[1], version = m[2].split('_')[0];
    if (names.includes(name)) pins.set(`${name}@${version}`, { name, version });
    // the oldest lockfiles put the registry's host in front (registry.npmjs.org/name/1.2.3), so the name read above is
    // the host: a listed package behind one is here, and its version is not taken from a key this reader half reads
    const hosted = /^[^/@]+\.[^/@]+\/((?:@[^/@]+\/)?[^/@]+)\//.exec(id)?.[1];
    if (hosted && names.includes(hosted)) pins.set(`${hosted}@`, { name: hosted, version: '' });
  }
  return bad ? { error: `is a pnpm lockfile with an entry this check could not read (${bad.trim().slice(0, 80)})` } : { pins: [...pins.values()], entries };
}

const READERS = { npm: readNpm, yarn: readYarn, pnpm: readPnpm };

/** The pinned versions of the packages `names` in a lockfile's text → { pins: [{ name, version }], entries } with each
 *  name and version once, or { error } when the text is not a lockfile of that kind read to its end. */
export function pinnedIn(kind, text, names) {
  const r = READERS[kind]?.(text, names);
  if (!r) return { error: 'is a lockfile this check has no reader for' };
  if (r.error) return r;
  const once = new Map(r.pins.map((p) => [`${p.name}@${p.version}`, p]));
  return { pins: [...once.values()], entries: r.entries };
}

/**
 * A pinned version against a package's rule: { name, ranges: [{ introduced, fixed } | { introduced, lastAffected,
 * fixed }], source, fix }. Only a plain release (1.2.3) is judged: the advisories name releases, and a canary,
 * experimental or pre-release build, a tarball or a git commit is none of them. Judging "0.0.0-experimental-…" by its
 * number would read a build of last week as older than every affected version: SAFE, from a number that says nothing.
 * `searched`: the receipt a SAFE carries (lib/report.mjs safe(), the one place a SAFE is made): the lockfile and the
 * pin, from checkLockfile(); the pin alone when a caller has only that.
 * → { status: 'EXPOSED' | 'SAFE' | 'UNKNOWN', reason }
 */
export function judgePinned(version, rule, searched = [saw(`${rule.name} ${version}`)]) {
  if (!/^\d+\.\d+\.\d+$/.test(String(version))) {
    return { status: 'UNKNOWN', reason: version ? `${rule.name} is pinned to ${version}, which is not a plain release (a canary, experimental or pre-release build, or a file or repository): ${rule.source} names releases only, so it could not be judged` : `${rule.name} is in this lockfile with no version that could be read` };
  }
  for (const r of rule.ranges) {
    const upTo = r.lastAffected !== undefined ? cmp(version, r.lastAffected) <= 0 : cmp(version, r.fixed) < 0;
    if (cmp(version, r.introduced) >= 0 && upTo) return { status: 'EXPOSED', reason: `${rule.name} ${version} is in the affected range ${r.introduced} to ${r.lastAffected ?? `before ${r.fixed}`} (${rule.source}); fixed in ${r.fixed}` };
  }
  return safe(searched, { reason: `${rule.name} ${version} is in none of the affected ranges (${rule.ranges.map((r) => `${r.introduced} to ${r.lastAffected ?? `before ${r.fixed}`}`).join(', ')}; ${rule.source})` });
}

/**
 * One lockfile against an incident's rule: { packages: [{ name, ranges, source, fix }], bunNote }.
 * → { read, rows: [{ status, what, name?, version?, reason, fix?, searched? }] }. `read`: the file was read to its end
 * as a lockfile (so "pins none of the packages" is a statement about all of it). A row per package and version pinned;
 * none when the file was read and pins none of them (the caller's all-clear names the file).
 */
export function checkLockfile({ path, kind }, rule) {
  const unknown = (reason) => ({ read: false, rows: [{ status: 'UNKNOWN', what: 'lockfile', reason }] });
  if (kind === 'bun') return unknown(rule.bunNote ?? 'is Bun\'s lockfile, which this check does not read');
  const state = pathState(path);
  if (state !== 'file') return unknown(state === 'denied' ? 'found, but it could not be read (permission denied, or a link this run could not follow)' : 'found, but it is not a file (a link that leads nowhere, or a device), so it was not read');
  const buf = readCapped(path, MAX);
  if (!buf) return unknown('found, but it could not be read (or is larger than 64 MB)');
  const names = rule.packages.map((p) => p.name);
  const got = pinnedIn(kind, buf.toString('utf8'), names);
  if (got.error) return unknown(`${got.error}, so what it pins is not known`);
  const rows = got.pins.map(({ name, version }) => {
    const pkg = rule.packages.find((p) => p.name === name);
    const what = `${name} ${version || '(no version)'}`;
    const r = judgePinned(version, pkg, [path, saw(what)]);
    return { name, version, what, ...r, ...(r.status === 'EXPOSED' ? { fix: pkg.fix } : {}) };
  });
  return { read: true, rows };
}
