// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Installed software checked by reading files only, never by running anything it finds:
//   - a product's version, read from a file the product itself writes (GitLab's version files, Plex's Info.plist);
//   - the files a malicious package release drops into Python's site-packages, matched by SHA-256 (LiteLLM 1.107.0);
//   - container images already on this machine whose digest is a published bad one (listed by the engine; never pulled
//     or run).
import { createHash } from 'node:crypto';
import { runSync } from './run.mjs';
import { join, dirname, basename, relative } from 'node:path';
import { homedir, platform } from 'node:os';
import { readCapped, listDir, pathState, mayBeFolder, entriesByMetadata, realPath, isSystemFolder, unwalkedLinks, walkedTo, holdsMore, openErrno, refusedOr, isSiteName, venvOfPackages, venvPackages, gapLists, realPathAsWritten, hasDotDot, SITE_NAMES } from './files.mjs';
import { judgeVersion, findOnPath } from './binaries.mjs';
import { HOST_NOT_FOLLOWED, ENGINE_DENIED, engineHost, engineFailure } from './containers.mjs';

const MAX = 4 * 1024 * 1024; // version files and dropped scripts are small; anything larger isn't what we look for
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const DENIED = 'could not look here (permission denied): run Wardlatch with sudo to check it';
/** Why a folder this check could not look in was not looked at: DENIED, unless the system refused it with EPERM, which
 *  sudo may not lift (lib/files.mjs refusedOr). Up to this fix every such row said DENIED (R2-N5). */
const deniedReason = (p, code = openErrno(p)) => (code === 'EPERM' ? `could not look here: ${refusedOr(p, DENIED, code)}` : DENIED);
// Folders this walk never enters, by name. Not hidden: every all-clear that rests on this walk names them
// (bin/wardlatch.mjs allClear(), `notSearched`), since `mkdir node_modules` is a hiding place like any other (WV-4).
export const NOT_WALKED = ['node_modules', '.git'];

/**
 * Expand a path pattern whose segments may contain `*` (no `**`), against the disk. `~` is the home folder.
 * A folder that is there but can't be opened is not "nothing here": its path goes into `denied` (when given), so the
 * caller can say UNKNOWN instead of reading the product as absent.
 * Where the walk got to goes into `reached` (when given): for each candidate, the deepest folder on the way to it that
 * is actually there. When the product is not installed nothing is returned, and `reached` is then the only true thing
 * the caller can put in a receipt (AUDIT-10: a SAFE row stood on a sentence from the incident file naming folders that
 * were not on this machine, because the code that looked had nothing to hand back).
 * A pattern with a '..' in it (from a variable, or the home folder) is put together as written, never cleaned up as
 * text, so the OS takes the '..' after the link before it, as the program that reads the folder does.
 */
export function expand(pattern, denied, reached) {
  const raw = pattern.replace(/^~(?=\/|$)/, homedir()), parts = raw.split('/');
  const at = hasDotDot(raw) ? (base, part) => (base.endsWith('/') ? `${base}${part}` : `${base}/${part}`) : join;
  let paths = [parts[0] === '' ? '/' : parts[0]];
  for (const part of parts.slice(1)) {
    if (!part) continue;
    const next = [];
    for (const base of paths) {
      if (!part.includes('*')) { next.push(at(base, part)); continue; }
      const rx = new RegExp(`^${part.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
      const l = listDir(base);
      if (l.denied) { denied?.push(base); continue; }
      // a folder whose entries were read is a place this run opened, whether or not anything in it matched
      if (l.entries) reached?.push(base);
      for (const e of l.entries ?? []) if (rx.test(e.name)) next.push(at(base, e.name));
    }
    paths = next;
  }
  const out = paths.filter((p) => {
    const st = pathState(p);
    if (st === 'denied') denied?.push(p);
    return st !== 'gone' && st !== 'denied';
  });
  // The deepest folder on the way to each candidate that is there: /opt exists, /opt/gitlab does not, so /opt is where
  // the walk stopped and the only place it can honestly claim. A denied one is left out — it is already its own UNKNOWN
  // row, and a receipt names what was opened, never what was attempted (lib/binaries.mjs says the same of temp folders).
  for (const p of reached ? paths : []) {
    let d = p;
    while (d !== dirname(d) && pathState(d) === 'gone') d = dirname(d);
    if (['dir', 'file'].includes(pathState(d))) reached.push(d);
  }
  return out;
}

/**
 * A version read from the product's own files. rule: { product, files: [{ path, re, label?, group?, maxBytes?,
 * reviewWhenFixed?, presentRe? }], fixedIn | bad | minVersion, affectedFrom?, fix }. `presentRe`: a shared file (dpkg's
 * status) speaks for the product only when it matches; otherwise the product isn't installed and nothing is reported. `path` may contain `*` segments. Files that
 * share a `group` describe one install: the first one that yields a version answers for it (Linux-package GitLab has
 * several). `reviewWhenFixed` turns SAFE into REVIEW with that reason (a source install that also needs its own patch).
 * → [{ status, path, version, label?, reason? }] (empty when the product isn't there). The real places the walk got to
 * go into `reached` (when given), for the all-clear's receipt (AUDIT-10): an out-parameter, as `denied` is, because a
 * property on the returned array would change what `deepEqual(rows, [])` sees.
 */
export function checkVersionFiles(rule, { root = '', reached } = {}) {
  const out = []; const seen = new Set(); const answered = new Set();
  for (const f of rule.files) {
    if (f.group && answered.has(f.group)) continue;
    const denied = [];
    const found = expand(root + f.path, denied, reached);
    for (const path of denied) out.push({ group: f.group, status: 'UNKNOWN', path, version: '', label: f.label, reason: deniedReason(path) });
    for (const path of found) {
      if (seen.has(path)) continue; seen.add(path);
      const buf = readCapped(path, f.maxBytes ?? MAX);
      if (!buf) { out.push({ group: f.group, status: 'UNKNOWN', path, version: '', label: f.label, reason: 'found, but the file could not be read (or is larger than expected)' }); continue; }
      const text = buf.toString('utf8');
      if (f.presentRe && !new RegExp(f.presentRe, 'm').test(text)) continue;
      const v = (text.match(new RegExp(f.re, 'm')) ?? [])[1] ?? '';
      if (!v) { out.push({ group: f.group, status: 'UNKNOWN', path, version: '', label: f.label, reason: 'found, but no version could be read from it' }); continue; }
      let r = judgeVersion(v, rule);
      if (r.status === 'SAFE' && f.reviewWhenFixed) r = { status: 'REVIEW', reason: f.reviewWhenFixed };
      out.push({ group: f.group, path, version: v, label: f.label, ...r, ...(r.searched ? { searched: [path, ...r.searched] } : {}) });
      if (f.group) answered.add(f.group);
    }
  }
  // an install whose first file couldn't be read but another one answered keeps just the answer
  return out.filter((r) => !(r.status === 'UNKNOWN' && r.group && answered.has(r.group))).map(({ group, ...r }) => r);
}

// Where Python keeps installed packages: system and framework Pythons, Homebrew, per-user installs, pyenv, conda,
// pipx and uv. Virtual environments under the folders searched are added by sitePackagesDirs.
export const SITE_PATTERNS = [
  '/usr/lib/python3*/site-packages', '/usr/lib/python3/dist-packages', '/usr/lib64/python3*/site-packages',
  '/usr/local/lib/python3*/site-packages', '/usr/local/lib/python3*/dist-packages',
  '/opt/homebrew/lib/python3*/site-packages', '/opt/homebrew/opt/python*/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages',
  '/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages',
  // Apple's own Python: where `sudo pip3` installs, and the Command Line Tools' and Xcode's. site.getsitepackages() on
  // /usr/bin/python3 names these, and until 2 Nov 2026 none was here, so a stealer in one read SAFE (seat 6's hypothesis 1).
  '/Library/Python/3*/site-packages',
  '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/lib/python3*/site-packages',
  '/Applications/Xcode*.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*/lib/python3*/site-packages',
  '~/Library/Python/3*/lib/python/site-packages', '~/.local/lib/python3*/site-packages',
  '~/.pyenv/versions/*/lib/python3*/site-packages',
  '~/miniconda3/lib/python3*/site-packages', '~/miniconda3/envs/*/lib/python3*/site-packages',
  '~/anaconda3/lib/python3*/site-packages', '~/anaconda3/envs/*/lib/python3*/site-packages',
  '~/miniforge3/lib/python3*/site-packages', '~/miniforge3/envs/*/lib/python3*/site-packages',
  '~/.conda/envs/*/lib/python3*/site-packages',
  '~/.local/pipx/venvs/*/lib/python3*/site-packages', '~/.local/share/pipx/venvs/*/lib/python3*/site-packages',
  '~/.local/share/uv/tools/*/lib/python3*/site-packages', '~/.local/share/uv/python/*/lib/python3*/site-packages',
  '/opt/venv/lib/python3*/site-packages', '/app/.venv/lib/python3*/site-packages',
  // uv's run/uvx environments, Poetry, Pipenv, virtualenvwrapper, pipx on macOS, conda's other homes, Homebrew formula
  // environments, asdf and mise, and the usual server folders
  '~/.cache/uv/archive-v0/*/lib/python3*/site-packages',
  '~/Library/Caches/pypoetry/virtualenvs/*/lib/python3*/site-packages', '~/.cache/pypoetry/virtualenvs/*/lib/python3*/site-packages',
  '~/.local/share/virtualenvs/*/lib/python3*/site-packages', '~/.virtualenvs/*/lib/python3*/site-packages',
  '~/Library/Application Support/pipx/venvs/*/lib/python3*/site-packages',
  '~/opt/anaconda3/lib/python3*/site-packages', '~/opt/anaconda3/envs/*/lib/python3*/site-packages',
  '~/opt/miniconda3/lib/python3*/site-packages', '~/opt/miniconda3/envs/*/lib/python3*/site-packages',
  '~/mambaforge/lib/python3*/site-packages', '~/mambaforge/envs/*/lib/python3*/site-packages', '~/micromamba/envs/*/lib/python3*/site-packages',
  '/opt/conda/lib/python3*/site-packages', '/opt/conda/envs/*/lib/python3*/site-packages',
  '/opt/miniconda3/lib/python3*/site-packages', '/opt/anaconda3/lib/python3*/site-packages',
  '/opt/homebrew/Caskroom/mini*/base/lib/python3*/site-packages', '/opt/homebrew/Caskroom/mini*/base/envs/*/lib/python3*/site-packages',
  '/opt/homebrew/Cellar/*/*/libexec/lib/python3*/site-packages', '/usr/local/Cellar/*/*/libexec/lib/python3*/site-packages',
  '/home/linuxbrew/.linuxbrew/lib/python3*/site-packages', '/home/linuxbrew/.linuxbrew/Cellar/*/*/libexec/lib/python3*/site-packages',
  '~/.asdf/installs/python/*/lib/python3*/site-packages', '~/.local/share/mise/installs/python/*/lib/python3*/site-packages',
  '/usr/local/lib64/python3*/site-packages',
  '/opt/*/venv/lib/python3*/site-packages', '/opt/*/.venv/lib/python3*/site-packages', '/srv/*/venv/lib/python3*/site-packages', '/srv/*/.venv/lib/python3*/site-packages',
];

/** Every site-packages folder on this machine that Wardlatch knows to look in, plus those of virtual environments
 *  (a folder with pyvenv.cfg) under `roots` and near the top of the home folder. Each folder once, however many links
 *  lead to it (a Linux venv's lib64 -> lib; Homebrew's opt/python, python3, python@3 aliases). Nothing in them is run.
 *  Folders on the known paths that exist but can't be opened go into `denied` (when given); the site-packages of a found
 *  virtual environment that can't be read go into `found` (always UNKNOWN: bin/wardlatch.mjs gaps()). Each of `roots`
 *  that was opened and walked goes into `walked` (when given): a folder the person asked about and in which no
 *  environment was found leaves nothing behind otherwise, so the all-clear could not say it had been searched
 *  (AUDIT-11). The folders below a root are not listed there — a receipt a reader cannot read through is no better
 *  than one they cannot check — and the roots are what was asked for. */
// `deep`: the folders below `roots` the depth cap stopped at that hold more to walk (holdsMore()); the
// quick look round the home folder reports none, as it reports no folder it cannot open.
// Where macOS keeps what it protects, relative to the home folder. A path and an errno, not a name: only EPERM, the refusal
// nobody can lift with chmod, at exactly these places. Round 6 tested the folder's NAME at any depth, so a locked
// ~/Documents/clients.photoslibrary holding a stealer read SAFE and the same folder called work read UNKNOWN (seat 6's R2).
const MAC_KEEPS = /^(?:\.Trash|Pictures\/(?:Photo Booth Library|[^/]*\.photoslibrary))$/;

// not .env: that is a file of secrets, and a link to one in a locked folder is no environment (seat 9's P2)
const VENV_NAME = /^(\.?venv|virtualenv|env)$/i;

export function sitePackagesDirs({ roots = [], maxDepth = 5, patterns = SITE_PATTERNS, home = homedir(), homeDepth = 3, denied, found = denied, links = denied, walked, kept, deep } = {}) {
  // none of the gap lists is opt-in: one left out that the walk has something for makes it throw (lib/files.mjs gapLists(); R2-N9)
  const gap = gapLists('sitePackagesDirs()', { denied, found, links, deep });
  ({ denied, found, links, deep } = gap);
  const dirs = new Map();
  const listed = new Map(), maybeLinks = [];
  // each once by its real path as the OS resolves it (a pattern's folder may hold a '..' after a link: expand); such a
  // folder is named by that real path, so the files in it are put together from a path with no '..' left in it
  const add = (d) => { const real = realPathAsWritten(d) ?? d; if (!dirs.has(real)) dirs.set(real, hasDotDot(d) ? real : d); };
  // the known places (~/.local/lib/python3*/site-packages and the like) are where an install would be: a part that can't
  // be opened is a found place not looked at, always UNKNOWN, whoever owns it
  for (const p of patterns) for (const d of expand(p, found)) add(d);
  // report: whether a folder that can't be opened is a gap to report (under the searched folders) or not (the quick look
  // round the home folder, where macOS keeps folders it protects)
  // → whether `d` itself was opened, which the caller of a root needs for the receipt (the recursive calls ignore it)
  // A virtual environment's own package folders are checked (venvPackages()) and not walked, so they leave nothing
  // unsearched at the depth floor (holdsMore()'s `checked`); every other folder in a venv is walked like any folder.
  // `inVenv`: `d` is a venv this walk met, or inside one (holdsMore()).
  // `linked`: the quick look reached `d` through a link (below).
  const walk = (d, depth, report, skip = new Set(), inVenv = false, linked = false) => {
    if (depth < 0) { if (report && deep && holdsMore(d, NOT_WALKED, { checked: (p) => dirs.has(realPath(p) ?? p), inVenv })) deep.push(d); return false; }
    const l = listDir(d);
    // a folder under the searched ones that can't be opened: a virtual environment in it was not looked at
    // The quick look round the home folder reports it too: a stealer in ~/Documents read SAFE on any terminal without
    // access to it, against owner decision #33 (seat 5, 2 Nov 2026). What macOS keeps to itself on every Mac is left out
    // (MAC_KEEPS), measured on one Mac on 2 Nov 2026: reported, it makes every healthy run exit 2.
    // What is left out is still said: `kept` goes under the all-clear (seat 7's D13). One whose metadata says it holds
    // nothing is no gap, so an emptied Trash is proven and not merely skipped.
    // Through a link the place can be anywhere, so the path can't decide: EPERM behind a link on a Mac is kept too, which
    // is the shape of ~/OneDrive -> a folder macOS protects (WV-13), and anything else is UNKNOWN like a folder.
    if (l.denied) {
      const place = linked ? realPath(d) ?? d : d;
      if (!report && l.code === 'EPERM' && (linked ? platform() === 'darwin' : MAC_KEEPS.test(relative(home, d)))) { if (entriesByMetadata(place) !== 0 && !kept?.includes(place)) kept?.push(place); } else denied?.push(d);
      return false;
    }
    // only the walks of the searched folders count as having read a link's target: the quick look round the home folder
    // goes two levels and says nothing about what it cannot open, so its listing covered nothing (WV-3)
    if (report) walkedTo(listed, d, depth);
    for (const e of l.entries ?? []) {
      // pip install --target leaves a package folder with any name: a .dist-info in it is what marks it
      if (e.isDirectory() && e.name.endsWith('.dist-info')) add(d);
      // a link to a folder is looked at (a .venv that points elsewhere) but never walked into, so a loop can't trap it
      if (!(e.isDirectory() || e.isSymbolicLink()) || NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)) continue;
      const p = join(d, e.name);
      if (skip.has(p)) continue;
      // An environment is checked (its own package folders), so a link to it from elsewhere in a searched folder is no
      // gap (WV-9), and it is walked, all but its own package folders: up to R2-N4's fix it was not walked, so a venv
      // inside a project made with `python3 -m venv .` was never seen, and from 2ce50f0 to this fix its bin, include,
      // lib, share and etc were not (round 3's re-reads).
      // A LINK to one has its packages checked through it, and is not walked, as links never are: it is a link not
      // followed (bin/wardlatch.mjs gaps() says its packages were checked), unless this walk walked its target as deep.
      // Up to this fix the link marked its target as walked whole, so a venv inside the linked venv was never looked for
      // and had no row, and the run read SAFE (round 3's re-read 2).
      // The quick look reports no link and says nothing of most folders, but a place that says it is an environment and
      // can't be read is one: ~/app/.venv as a link to a locked target, or a folder of mode 0644, which lists but can't be
      // entered, read SAFE until 2 Nov 2026 (seat 7's D8). Only those: ~/OneDrive -> a protected folder is WV-13's.
      const cfg = pathState(join(p, 'pyvenv.cfg'));
      // A name that isn't valid UTF-8 can't be asked for at all, on Linux: at the floor nothing else would open it, and a
      // venv of that name read SAFE (seat 15's F1). \uFFFD is what such a name comes back as (lib/files.mjs isGone()).
      if (!report && cfg === 'denied' && (e.isDirectory() ? listDir(p).entries || e.name.includes('\uFFFD') : VENV_NAME.test(e.name))) { denied?.push(p); continue; }
      if (cfg === 'file') {
        for (const sp of venvPackages(p, found)) add(sp);
        if (e.isDirectory()) { if (report) walkedTo(listed, p, Infinity); walk(p, depth - 1, report, skip, true, linked); }
        else if (report) maybeLinks.push({ path: p, need: depth - 1 });
      } else if (isSiteName(e.name, d) && pathState(p) === 'dir') {
        // a site-packages folder below a folder given with --paths (--paths .venv/lib): checked, as one inside a venv is.
        // A venv's own is not walked (VENV_PACKAGES_SAID); any other is a folder like any other,
        // walked, and a link of the name is a link not followed. From 53c3029 to this fix the name alone stopped the
        // walk, and let a link escape the link rule: a venv behind either read SAFE (R2-N2).
        add(p);
        if (venvOfPackages(p)) continue;
        if (e.isDirectory()) walk(p, depth - 1, report, skip, inVenv, linked);
        else if (report) maybeLinks.push({ path: p, need: depth - 1 });
      } else if (e.isDirectory()) walk(p, depth - 1, report, skip, inVenv, linked);
      // a link to a folder that is not itself an environment is recorded, never followed: an environment deeper inside
      // it was passed over in silence before, and the run still read SAFE.
      else if (report && e.isSymbolicLink() && mayBeFolder(p)) maybeLinks.push({ path: p, need: depth - 1 });
      // The quick look has no gap list for links, so it goes through one as it goes into a folder, no deeper, which the
      // depth keeps from looping: ~/app/proj as a link to a project read SAFE, reachable or locked (F7), and a row per
      // link made every run exit 2 (WV-13: ~/OneDrive -> ~/Library/CloudStorage/OneDrive-Personal). Only one that leads
      // to a folder: past a locked folder a link can't be told from a link to a file, which is seat 9's P2 (~/app/.env).
      else if (!report && e.isSymbolicLink() && pathState(p) === 'dir') walk(p, depth - 1, false, skip, inVenv, true);
    }
    return true;
  };
  // A folder given with --paths that IS an environment, or a site-packages folder, is checked itself. Up to this fix only
  // its entries were tested for pyvenv.cfg, so `--paths <the venv>` (what the trust check's advice for a linked venv
  // told people to do) read SAFE with the venv named in the receipt and the stealer's install record inside it (WV-1).
  // Every folder given with --paths is walked; one that is an environment is walked past its own package folders (R2-N1).
  for (const r of roots) {
    const isEnv = pathState(join(r, 'pyvenv.cfg')) === 'file';
    if (isEnv) for (const sp of venvPackages(r, found)) add(sp);
    else if (isSiteName(basename(r), dirname(r)) && pathState(r) === 'dir') add(r);
    if (walk(r, maxDepth, true, undefined, isEnv || Boolean(venvOfPackages(r)))) walked?.push(r);
  }
  // virtual environments outside the folders searched (~/Desktop/x/venv, ~/project/.venv), a few levels deep only,
  // through a link as through a folder
  if (home) walk(home, homeDepth - 1, false, new Set(roots));
  // a link into a folder this walk already listed is not a gap: its bytes were read (lib/files.mjs unwalkedLinks)
  if (links) links.push(...unwalkedLinks(maybeLinks, listed).map((c) => c.path));
  gap.done();
  return [...dirs.values()];
}

/**
 * The files a malicious release drops into site-packages. rule: { iocFiles: [{ name, sha256 }], distInfo?: [names] }.
 * A file whose name and SHA-256 both match is EXPOSED; a dropped-file name with other contents is REVIEW (a variant, or
 * a file of the same name: sitecustomize.py has legitimate uses); the bad release's install record is EXPOSED.
 * No rule can silence that REVIEW: the option that did read a stealer changed by one byte as SAFE (owner, 2 Nov 2026).
 * → [{ status, dir, what, reason }]
 */
export function checkSitePackages(rule, dirs, denied = []) {
  const out = denied.map((dir) => ({ status: 'UNKNOWN', dir, what: 'folder', reason: deniedReason(dir) }));
  for (const dir of dirs) {
    // one listing per folder: a folder that can't be read is UNKNOWN, never an empty one
    const l = listDir(dir);
    if (l.denied) { out.push({ status: 'UNKNOWN', dir, what: 'folder', reason: deniedReason(dir, l.code) }); continue; }
    const names = new Set((l.entries ?? []).map((e) => e.name));
    for (const ioc of rule.iocFiles ?? []) {
      // Python runs these at start as it does the file: the package, and either compiled with no source beside it
      // (seat 7's D12; seat 9's P1, Apple's Python 3.9.6 ran each). They can't be matched against the published file.
      const stem = ioc.name.endsWith('.py') ? ioc.name.slice(0, -3) : null;
      if (stem) for (const form of [`${stem}/__init__.py`, `${stem}/__init__.pyc`, `${stem}.pyc`]) {
        if (pathState(join(dir, form)) !== 'gone') out.push({ status: 'REVIEW', dir, what: form, reason: `Python runs this each time it starts, as it does ${ioc.name}, and it isn't the published file` });
      }
      if (!names.has(ioc.name)) continue;
      const buf = readCapped(join(dir, ioc.name), MAX);
      const h = buf ? sha256(buf) : '';
      if (h && [].concat(ioc.sha256).includes(h)) out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: `${ioc.name} is the malicious file (SHA-256 ${h})` });
      // a name nothing legitimate puts in site-packages (cook.pth): a variant, a padded copy or an unreadable one is
      // still the malware, so the name alone is EXPOSED, not a review line that leaves the exit code at 0
      else if (ioc.nameAlone === 'EXPOSED') out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: buf ? `${ioc.name} is a variant of the malicious file (SHA-256 ${h}); nothing legitimate installs a file of this name` : `${ioc.name} is there (it could not be read to compare); nothing legitimate installs a file of this name` });
      // a file of a name with legitimate uses (sitecustomize.py) that couldn't be compared was not looked at
      else if (!buf) out.push({ status: 'UNKNOWN', dir, what: ioc.name, reason: `${ioc.name} is there but could not be read (or is larger than 4 MB), so it was not compared` });
      else out.push({ status: 'REVIEW', dir, what: ioc.name, reason: `a ${ioc.name} that isn't the known malicious one (SHA-256 ${h}); check what put it there` });
    }
    for (const name of rule.distInfo ?? []) {
      if (names.has(name)) out.push({ status: 'EXPOSED', dir, what: name, reason: `the compromised release is installed here (${name})` });
    }
  }
  return out;
}

/** Every local image of a container engine as `repository:tag@digest` (the digest may be `<none>`). Read from the
 *  engine's own list; nothing is pulled or run. → [] when the engine isn't there, null when its daemon isn't running,
 *  { error } when it is there but couldn't be asked (permission, no answer, too much output): that is not "no images". */
export function localImageDigests(engine) {
  const bin = findOnPath(engine);
  if (!bin) return [];
  try {
    const out = runSync(bin, ['images', '--digests', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}@{{.Digest}}'], { purpose: 'engine', env: engineHost().env, timeout: 15000, maxBuffer: 64 * 1024 * 1024 });
    // an image loaded with `docker load` or tagged locally has no repo digest (`@<none>`): kept, so its tag is still checked
    // a dangling image with no digest (`<none>:<none>@<none>`) has nothing to match and is left out
    // A row with a digest is kept whatever its name: a dangling image can be the compromised one.
    const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
    if (lines.length && !lines.some((l) => l.includes('@'))) return { error: 'gave a list of images that could not be read' };
    return lines.filter((l) => l.includes('@') && !(l.startsWith('<none>') && l.endsWith('@<none>')));
  } catch (e) {
    // lib/containers.mjs engineFailure(): the same rule as for running containers
    const err = String(e.stderr ?? '');
    const why = engineFailure(e);
    if (why === 'missing') return [];
    if (why === 'denied') return { error: ENGINE_DENIED };
    if (why === 'not-running') return engineHost().refused.some((k) => k.endsWith('_HOST')) ? { error: HOST_NOT_FOLLOWED } : null;
    if (why === 'timeout') return { error: 'did not answer within 15 seconds' };
    if (why === 'too-much') return { error: 'listed more images than could be read' };
    return { error: `could not list its images (${(err.trim().split('\n')[0] || e.code || e.message).slice(0, 160)})` };
  }
}

/** Local images whose digest is one of the published bad ones. rule: { dockerDigests: [sha256:…] } */
export function checkImages(rule, digestsByEngine) {
  const bad = new Set(rule.dockerDigests ?? []);
  const prefixes = rule.dockerDigestPrefixes ?? [];                  // where the vendor published only a short digest
  const badTags = new Set((rule.dockerTags ?? []).map((t) => t.toLowerCase())); // repository:tag that only ever named the bad image
  // Tags that named the bad image only for a while: one pulled then is compromised, one pulled since is not, and a local
  // list doesn't say when. So a tag here with an unlisted digest is a question, not a finding.
  const movedTags = new Set((rule.dockerTagsMoved ?? []).map((t) => t.toLowerCase()));
  const out = [];
  for (const [engine, list] of Object.entries(digestsByEngine)) {
    for (const ref of list ?? []) {
      const at = ref.lastIndexOf('@'), d = ref.slice(at + 1), name = ref.slice(0, at);
      if (bad.has(d) || prefixes.some((p) => d.startsWith(p))) out.push({ status: 'EXPOSED', engine, what: ref, reason: `this image is the compromised one (${d})` });
      else if (badTags.has(name.replace(/^docker\.io\//, '').toLowerCase())) out.push({ status: 'EXPOSED', engine, what: ref, reason: `${name} only ever named the compromised image` });
      else if (movedTags.has(name.replace(/^docker\.io\//, '').toLowerCase())) out.push({ status: 'REVIEW', engine, what: ref, reason: `${name} named the compromised image for a while, and this digest is not on the published list: check when this image was pulled` });
    }
  }
  return out;
}

