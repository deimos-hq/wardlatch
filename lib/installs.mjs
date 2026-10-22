// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Installed software checked by reading files only, never by running anything it finds:
//   - a product's version, read from a file the product itself writes (GitLab's version files, Plex's Info.plist);
//   - the files a malicious package release drops into Python's site-packages, matched by SHA-256 (LiteLLM 1.107.0);
//   - container images already on this machine whose digest is a published bad one (listed by the engine; never pulled
//     or run).
import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { readCapped } from './files.mjs';
import { judgeVersion } from './binaries.mjs';

const MAX = 4 * 1024 * 1024; // version files and dropped scripts are small; anything larger isn't what we look for
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** Expand a path pattern whose segments may contain `*` (no `**`), against the disk. `~` is the home folder. */
export function expand(pattern) {
  const parts = pattern.replace(/^~(?=\/|$)/, homedir()).split('/');
  let paths = [parts[0] === '' ? '/' : parts[0]];
  for (const part of parts.slice(1)) {
    if (!part) continue;
    const next = [];
    for (const base of paths) {
      if (!part.includes('*')) { next.push(join(base, part)); continue; }
      const rx = new RegExp(`^${part.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
      let names; try { names = readdirSync(base); } catch { continue; }
      for (const n of names) if (rx.test(n)) next.push(join(base, n));
    }
    paths = next;
  }
  return paths.filter((p) => existsSync(p));
}

/**
 * A version read from the product's own files. rule: { product, files: [{ path, re, label? }], fixedIn | bad, fix }.
 * `path` may contain `*` segments. → [{ status, path, version, label?, reason? }] (empty when the product isn't there).
 */
export function checkVersionFiles(rule, { root = '' } = {}) {
  const out = []; const seen = new Set();
  for (const f of rule.files) {
    for (const path of expand(root + f.path)) {
      if (seen.has(path)) continue; seen.add(path);
      const buf = readCapped(path, MAX);
      if (!buf) { out.push({ status: 'UNKNOWN', path, version: '', label: f.label, reason: 'found, but the file could not be read' }); continue; }
      const v = (buf.toString('utf8').match(new RegExp(f.re, 'm')) ?? [])[1] ?? '';
      if (!v) { out.push({ status: 'UNKNOWN', path, version: '', label: f.label, reason: 'found, but no version could be read from it' }); continue; }
      out.push({ path, version: v, label: f.label, ...judgeVersion(v, rule) });
    }
  }
  return out;
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
 *  lead to it (a Linux venv's lib64 -> lib; Homebrew's opt/python, python3, python@3 aliases). Nothing in them is run. */
export function sitePackagesDirs({ roots = [], maxDepth = 5, patterns = SITE_PATTERNS, home = homedir(), homeDepth = 3 } = {}) {
  const dirs = new Map();
  const add = (d) => { let real; try { real = realpathSync(d); } catch { real = d; } if (!dirs.has(real)) dirs.set(real, d); };
  for (const p of patterns) for (const d of expand(p)) add(d);
  const walk = (d, depth, skip = new Set()) => {
    if (depth < 0) return;
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      // a link to a folder is looked at (a .venv that points elsewhere) but never walked into, so a loop can't trap it
      if (!(e.isDirectory() || e.isSymbolicLink()) || ['node_modules', '.git', 'Library', '.Trash'].includes(e.name)) continue;
      const p = join(d, e.name);
      if (skip.has(p)) continue;
      if (existsSync(join(p, 'pyvenv.cfg'))) { for (const sp of expand(`${p}/lib*/python3*/site-packages`)) add(sp); }
      else if (e.isDirectory()) walk(p, depth - 1, skip);
    }
  };
  for (const r of roots) walk(r, maxDepth);
  // virtual environments outside the folders searched (~/Desktop/x/venv, ~/project/.venv), a few levels deep only
  if (home) walk(home, homeDepth - 1, new Set(roots));
  return [...dirs.values()];
}

/**
 * The files a malicious release drops into site-packages. rule: { iocFiles: [{ name, sha256 }], distInfo?: [names] }.
 * A file whose name and SHA-256 both match is EXPOSED; a dropped-file name with other contents is REVIEW (a variant, or
 * a file of the same name: sitecustomize.py has legitimate uses); the bad release's install record is EXPOSED.
 * → [{ status, dir, what, reason }]
 */
export function checkSitePackages(rule, dirs) {
  const out = [];
  for (const dir of dirs) {
    for (const ioc of rule.iocFiles ?? []) {
      const path = join(dir, ioc.name);
      if (!existsSync(path)) continue;
      const buf = readCapped(path, MAX);
      const h = buf ? sha256(buf) : '';
      if (h && [].concat(ioc.sha256).includes(h)) out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: `${ioc.name} is the malicious file (SHA-256 ${h})` });
      // a name nothing legitimate puts in site-packages (cook.pth): a variant, a padded copy or an unreadable one is
      // still the malware, so the name alone is EXPOSED, not a review line that leaves the exit code at 0
      else if (ioc.nameAlone === 'EXPOSED') out.push({ status: 'EXPOSED', dir, what: ioc.name, reason: buf ? `${ioc.name} is a variant of the malicious file (SHA-256 ${h}); nothing legitimate installs a file of this name` : `${ioc.name} is there (it could not be read to compare); nothing legitimate installs a file of this name` });
      else if (ioc.reviewIfOther !== false) out.push({ status: 'REVIEW', dir, what: ioc.name, reason: buf ? `a ${ioc.name} that isn't the known malicious one (SHA-256 ${h}); check what put it there` : `${ioc.name} is there but could not be read` });
    }
    for (const name of rule.distInfo ?? []) {
      if (existsSync(join(dir, name))) out.push({ status: 'EXPOSED', dir, what: name, reason: `the compromised release is installed here (${name})` });
    }
  }
  return out;
}

/** Image digests on this machine for a container engine: `repository@sha256:…` for every local image. Read from the
 *  engine's own list; nothing is pulled or run. → [] when the engine isn't there, null when its daemon isn't running,
 *  { error } when it is there but couldn't be asked (permission, no answer, too much output): that is not "no images". */
export function localImageDigests(engine) {
  try {
    const out = execFileSync(engine, ['images', '--digests', '--format', '{{.Repository}}@{{.Digest}}'], { encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    return out.split('\n').map((l) => l.trim()).filter((l) => /@sha256:[0-9a-f]{64}$/.test(l));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    const err = String(e.stderr ?? '');
    if (/cannot connect to (the )?(docker|podman)|is the docker daemon running|failed to connect to the docker API|unable to connect to podman/i.test(err)) return null;
    if (e.code === 'ETIMEDOUT') return { error: 'did not answer within 15 seconds' };
    if (e.code === 'ENOBUFS') return { error: 'listed more images than could be read' };
    if (/permission denied/i.test(err)) return { error: 'permission denied: run with sudo, or add this user to the docker group' };
    return { error: `could not list its images (${(err.trim().split('\n')[0] || e.code || e.message).slice(0, 160)})` };
  }
}

/** Local images whose digest is one of the published bad ones. rule: { dockerDigests: [sha256:…] } */
export function checkImages(rule, digestsByEngine) {
  const bad = new Set(rule.dockerDigests ?? []);
  const out = [];
  for (const [engine, list] of Object.entries(digestsByEngine)) {
    for (const ref of list ?? []) { const d = ref.slice(ref.indexOf('@') + 1); if (bad.has(d)) out.push({ status: 'EXPOSED', engine, what: ref, reason: `this image is the compromised one (${d})` }); }
  }
  return out;
}

