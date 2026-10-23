// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Installed software checked by reading files only, never by running anything it finds:
//   - a product's version, read from a file the product itself writes (GitLab's version files, Plex's Info.plist);
//   - the files a malicious package release drops into Python's site-packages, matched by SHA-256 (LiteLLM 1.107.0);
//   - container images already on this machine whose digest is a published bad one (listed by the engine; never pulled
//     or run).
import { createHash } from 'node:crypto';
import { runSync } from './run.mjs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { readCapped, listDir, pathState, realPath, isSystemFolder } from './files.mjs';
import { judgeVersion, findOnPath } from './binaries.mjs';
import { HOST_NOT_FOLLOWED, engineHost } from './containers.mjs';

const MAX = 4 * 1024 * 1024; // version files and dropped scripts are small; anything larger isn't what we look for
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const DENIED = 'could not look here (permission denied): run Wardlatch with sudo to check it';

/**
 * Expand a path pattern whose segments may contain `*` (no `**`), against the disk. `~` is the home folder.
 * A folder that is there but can't be opened is not "nothing here": its path goes into `denied` (when given), so the
 * caller can say UNKNOWN instead of reading the product as absent.
 */
export function expand(pattern, denied) {
  const parts = pattern.replace(/^~(?=\/|$)/, homedir()).split('/');
  let paths = [parts[0] === '' ? '/' : parts[0]];
  for (const part of parts.slice(1)) {
    if (!part) continue;
    const next = [];
    for (const base of paths) {
      if (!part.includes('*')) { next.push(join(base, part)); continue; }
      const rx = new RegExp(`^${part.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
      const l = listDir(base);
      if (l.denied) { denied?.push(base); continue; }
      for (const e of l.entries ?? []) if (rx.test(e.name)) next.push(join(base, e.name));
    }
    paths = next;
  }
  return paths.filter((p) => {
    const st = pathState(p);
    if (st === 'denied') denied?.push(p);
    return st !== 'gone' && st !== 'denied';
  });
}

/**
 * A version read from the product's own files. rule: { product, files: [{ path, re, label?, group?, maxBytes?,
 * reviewWhenFixed?, presentRe? }], fixedIn | bad | minVersion, affectedFrom?, fix }. `presentRe`: a shared file (dpkg's
 * status) speaks for the product only when it matches; otherwise the product isn't installed and nothing is reported. `path` may contain `*` segments. Files that
 * share a `group` describe one install: the first one that yields a version answers for it (Linux-package GitLab has
 * several). `reviewWhenFixed` turns SAFE into REVIEW with that reason (a source install that also needs its own patch).
 * → [{ status, path, version, label?, reason? }] (empty when the product isn't there).
 */
export function checkVersionFiles(rule, { root = '' } = {}) {
  const out = []; const seen = new Set(); const answered = new Set();
  for (const f of rule.files) {
    if (f.group && answered.has(f.group)) continue;
    const denied = [];
    const found = expand(root + f.path, denied);
    for (const path of denied) out.push({ group: f.group, status: 'UNKNOWN', path, version: '', label: f.label, reason: DENIED });
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
const SITE_PATTERNS = [
  '/usr/lib/python3*/site-packages', '/usr/lib/python3/dist-packages', '/usr/lib64/python3*/site-packages',
  '/usr/local/lib/python3*/site-packages', '/usr/local/lib/python3*/dist-packages',
  '/opt/homebrew/lib/python3*/site-packages', '/opt/homebrew/opt/python*/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages',
  '/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages',
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
 *  virtual environment that can't be read go into `found` (always UNKNOWN: bin/wardlatch.mjs gaps()). */
export function sitePackagesDirs({ roots = [], maxDepth = 5, patterns = SITE_PATTERNS, home = homedir(), homeDepth = 3, denied, found = denied } = {}) {
  const dirs = new Map();
  const add = (d) => { const real = realPath(d) ?? d; if (!dirs.has(real)) dirs.set(real, d); };
  for (const p of patterns) for (const d of expand(p, denied)) add(d);
  // report: whether a folder that can't be opened is a gap to report (under the searched folders) or not (the quick look
  // round the home folder, where macOS keeps folders it protects)
  const walk = (d, depth, report, skip = new Set()) => {
    if (depth < 0) return;
    const l = listDir(d);
    // a folder under the searched ones that can't be opened: a virtual environment in it was not looked at
    if (l.denied) { if (report) denied?.push(d); return; }
    for (const e of l.entries ?? []) {
      // a link to a folder is looked at (a .venv that points elsewhere) but never walked into, so a loop can't trap it
      if (!(e.isDirectory() || e.isSymbolicLink()) || ['node_modules', '.git'].includes(e.name) || isSystemFolder(e.name, d)) continue;
      const p = join(d, e.name);
      if (skip.has(p)) continue;
      if (pathState(join(p, 'pyvenv.cfg')) === 'file') { for (const sp of expand(`${p}/lib*/python3*/site-packages`, found)) add(sp); }
      else if (e.isDirectory()) walk(p, depth - 1, report, skip);
    }
  };
  for (const r of roots) walk(r, maxDepth, true);
  // virtual environments outside the folders searched (~/Desktop/x/venv, ~/project/.venv), a few levels deep only
  if (home) walk(home, homeDepth - 1, false, new Set(roots));
  return [...dirs.values()];
}

/**
 * The files a malicious release drops into site-packages. rule: { iocFiles: [{ name, sha256 }], distInfo?: [names] }.
 * A file whose name and SHA-256 both match is EXPOSED; a dropped-file name with other contents is REVIEW (a variant, or
 * a file of the same name: sitecustomize.py has legitimate uses); the bad release's install record is EXPOSED.
 * → [{ status, dir, what, reason }]
 */
export function checkSitePackages(rule, dirs, denied = []) {
  const out = denied.map((dir) => ({ status: 'UNKNOWN', dir, what: 'folder', reason: DENIED }));
  for (const dir of dirs) {
    // one listing per folder: a folder that can't be read is UNKNOWN, never an empty one
    const l = listDir(dir);
    if (l.denied) { out.push({ status: 'UNKNOWN', dir, what: 'folder', reason: DENIED }); continue; }
    const names = new Set((l.entries ?? []).map((e) => e.name));
    for (const ioc of rule.iocFiles ?? []) {
      if (!names.has(ioc.name)) continue;
      const buf = readCapped(join(dir, ioc.name), MAX);
      const h = buf ? sha256(buf) : '';
      if (h && [].concat(ioc.sha256).includes(h)) out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: `${ioc.name} is the malicious file (SHA-256 ${h})` });
      // a name nothing legitimate puts in site-packages (cook.pth): a variant, a padded copy or an unreadable one is
      // still the malware, so the name alone is EXPOSED, not a review line that leaves the exit code at 0
      else if (ioc.nameAlone === 'EXPOSED') out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: buf ? `${ioc.name} is a variant of the malicious file (SHA-256 ${h}); nothing legitimate installs a file of this name` : `${ioc.name} is there (it could not be read to compare); nothing legitimate installs a file of this name` });
      // a file of a name with legitimate uses (sitecustomize.py) that couldn't be compared was not looked at
      else if (!buf) out.push({ status: 'UNKNOWN', dir, what: ioc.name, reason: `${ioc.name} is there but could not be read (or is larger than 4 MB), so it was not compared` });
      else if (ioc.reviewIfOther !== false) out.push({ status: 'REVIEW', dir, what: ioc.name, reason: `a ${ioc.name} that isn't the known malicious one (SHA-256 ${h}); check what put it there` });
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
    // a dangling image (`<none>:<none>@<none>`) has nothing to match and is left out
    return out.split('\n').map((l) => l.trim()).filter((l) => l.includes('@') && !l.startsWith('<none>'));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    const err = String(e.stderr ?? '');
    if (/cannot connect to (the )?(docker|podman)|is the docker daemon running|failed to connect to the docker API|unable to connect to podman/i.test(err)) return engineHost().refused.some((k) => k.endsWith('_HOST')) ? { error: HOST_NOT_FOLLOWED } : null;
    if (e.code === 'ETIMEDOUT') return { error: 'did not answer within 15 seconds' };
    if (e.code === 'ENOBUFS') return { error: 'listed more images than could be read' };
    if (/permission denied/i.test(err)) return { error: 'permission denied: run with sudo, or add this user to the docker group' };
    return { error: `could not list its images (${(err.trim().split('\n')[0] || e.code || e.message).slice(0, 160)})` };
  }
}

/** Local images whose digest is one of the published bad ones. rule: { dockerDigests: [sha256:…] } */
export function checkImages(rule, digestsByEngine) {
  const bad = new Set(rule.dockerDigests ?? []);
  const prefixes = rule.dockerDigestPrefixes ?? [];                  // where the vendor published only a short digest
  const badTags = new Set((rule.dockerTags ?? []).map((t) => t.toLowerCase())); // repository:tag that only ever named the bad image
  const out = [];
  for (const [engine, list] of Object.entries(digestsByEngine)) {
    for (const ref of list ?? []) {
      const at = ref.lastIndexOf('@'), d = ref.slice(at + 1), name = ref.slice(0, at);
      if (bad.has(d) || prefixes.some((p) => d.startsWith(p))) out.push({ status: 'EXPOSED', engine, what: ref, reason: `this image is the compromised one (${d})` });
      else if (badTags.has(name.replace(/^docker\.io\//, '').toLowerCase())) out.push({ status: 'EXPOSED', engine, what: ref, reason: `${name} only ever named the compromised image` });
    }
  }
  return out;
}

