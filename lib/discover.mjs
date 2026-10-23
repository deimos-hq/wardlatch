// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Find the TLS-capable runtimes on this machine: the first node, curl and python3 on PATH, the OS built-ins, and Python
// virtual environments under the folders you name. Nothing is changed; this only looks.
import { join, delimiter, resolve } from 'node:path';
import { homedir } from 'node:os';
import { readText, pathState, listDir, realPath, isSystemFolder } from './files.mjs';
import { runSync } from './run.mjs';
import { copiesToRun } from './binaries.mjs';

// asked for its version with lib/run.mjs's allowlisted environment, from /
const version = (bin, args, re) => { try { return (runSync(bin, args, { purpose: 'version', timeout: 5000 }).match(re) ?? [])[1] ?? ''; } catch { return ''; } };
// A virtual environment found on disk is never executed: a cloned repository can ship a fake bin/python. Its certifi
// bundle is read as a file instead (version from the dist-info, or certifi/__init__.py) and tested by a curl this
// machine already trusts (/usr/bin/curl, else the first curl on PATH) with --cacert, the same way as a Linux system bundle.
// A folder on the way that can't be opened goes into `found`: an environment is there, and its certifi bundle wasn't seen
// (27cdfbd dropped it with no row). Always UNKNOWN, whoever owns it (bin/wardlatch.mjs gaps()).
function certifiIn(env, found) {
  for (const libdir of ['lib', 'lib64']) {
    const l = listDir(join(env, libdir));
    if (l.denied) { found?.push(join(env, libdir)); continue; }
    const pys = (l.entries ?? []).map((e) => e.name).filter((n) => /^python\d/.test(n));
    for (const py of pys) {
      const sp = join(env, libdir, py, 'site-packages');
      const bundle = join(sp, 'certifi', 'cacert.pem');
      const st = pathState(bundle);
      if (st === 'denied') { found?.push(sp); continue; }
      if (st !== 'file') continue;
      // read like every other file (lib/files.mjs): a planted FIFO here blocked the open and hung the whole run
      const text = (f) => readText(f, 1024 * 1024) ?? '';
      const dist = (listDir(sp).entries ?? []).map((e) => e.name).find((n) => /^certifi-.*\.dist-info$/.test(n));
      let version = dist ? (text(join(sp, dist, 'METADATA')).match(/^Version:\s*(\S+)/m) ?? [])[1] ?? '' : '';
      if (!version) version = (text(join(sp, 'certifi', '__init__.py')).match(/__version__\s*=\s*["']([^"']+)/) ?? [])[1] ?? '';
      return { bundle, version };
    }
  }
  return null;
}

/**
 * The runtimes to probe: the node, curl and python3 on PATH that lib/binaries.mjs copiesToRun() allows (the first, the
 * one the person's shell runs, and later ones that are compiled programs; a later script goes into `notRun`), the
 * system's own curl and python3, and the OS's trust. A folder under `roots` that can't be opened goes into `denied`; a
 * found environment whose own folders can't be read goes into `found`.
 */
export function discover({ roots = [], pathEnv = process.env.PATH ?? '', maxDepth = 5, denied, found, notRun, untested } = {}) {
  // Windows isn't supported: its runtimes are node.exe, curl.exe and python.exe in places this doesn't look. Nothing is
  // found, and the caller says so (UNKNOWN), rather than testing whatever a Unix-style path happens to hold
  if (process.platform === 'win32') return [];
  const out = []; const seen = new Set();
  const add = (kind, bin, extra = {}) => {
    if (!bin || pathState(bin) !== 'file') return;
    const real = realPath(bin) ?? bin;
    const key = `${kind}:${extra.env ?? real}`; if (seen.has(key)) return; seen.add(key);
    const v = kind === 'node' ? version(bin, ['-v'], /v?([\d.]+)/) : kind === 'curl' ? version(bin, ['--version'], /curl ([\d.]+)/) : version(bin, ['-V'], /Python ([\d.]+)/);
    out.push({ kind, bin, version: v, ...extra });
  };
  // the copies lib/binaries.mjs copiesToRun() allows: the first on PATH, and later ones that are compiled programs
  for (const [kind, name] of [['node', 'node'], ['curl', 'curl'], ['python', 'python3']]) {
    const c = copiesToRun(name, pathEnv);
    for (const bin of c.run) add(kind, bin);
    notRun?.push(...c.notRun);
  }
  for (const b of ['/usr/bin/curl', '/usr/bin/python3']) add(b.endsWith('curl') ? 'curl' : 'python', b);
  // The operating system's own trust: macOS's networking stack (Safari, Apple's apps), or a Linux distribution's bundle.
  if (process.platform === 'darwin' && pathState('/usr/bin/nscurl') === 'file') {
    out.push({ kind: 'macos-system', bin: '/usr/bin/nscurl', version: version('/usr/bin/sw_vers', ['-productVersion'], /([\d.]+)/), label: 'macOS system (Safari and Apple apps)' });
  }
  if (process.platform === 'linux') {
    const bundle = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem'].find((f) => pathState(f) === 'file');
    const curl = pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, 'curl')).find((f) => pathState(f) === 'file');
    if (bundle && curl) out.push({ kind: 'curl', bin: curl, args: ['--cacert', bundle], version: version(curl, ['--version'], /curl ([\d.]+)/), label: `Linux system trust store (${bundle})`, system: true });
  }
  const walk = (d, depth) => {
    if (depth < 0) return;
    const l = listDir(d);
    if (l.denied) { denied?.push(d); return; }
    for (const e of l.entries ?? []) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name === '.git' || isSystemFolder(e.name, d)) continue;
      const p = join(d, e.name);
      if (pathState(join(p, 'bin', 'python')) !== 'gone' && pathState(join(p, 'pyvenv.cfg')) === 'file') {
        // never run p/bin/python: test the environment's certifi bundle, as a file, with a trusted curl
        const c = certifiIn(p, found);
        const key = `certifi:${p}`;
        if (c && trustedCurl && !seen.has(key)) {
          seen.add(key);
          out.push({ kind: 'curl', bin: trustedCurl, args: ['--cacert', c.bundle], version: '', env: p, certifi: c.version,
            label: `certifi ${c.version || '(version unknown)'}  ${p.replace(homedir(), '~')}`, fixKey: 'python-certifi' });
        }
        // found, but no curl on this machine to test it with: never dropped (a Linux machine without curl read SAFE)
        else if (c && !trustedCurl && !seen.has(key)) { seen.add(key); untested?.push({ env: p, certifi: c.version, bundle: c.bundle }); }
        // without certifi the environment uses its base Python's trust, and that Python is checked above
      } else walk(p, depth - 1);
    }
  };
  const trustedCurl = ['/usr/bin/curl', ...pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, 'curl'))].find((f) => pathState(f) === 'file');
  // absolute, so a found bundle's path still means the same file to a curl run from /
  for (const r of roots) walk(resolve(r), maxDepth);
  // REQUESTS_CA_BUNDLE replaces certifi's list for requests and pip, and Python's own probe (urllib) never reads it: the
  // file it names is tested like a certifi bundle (up to b03e7be it went untested). bin/wardlatch.mjs made it absolute.
  const caFile = process.env.REQUESTS_CA_BUNDLE;
  if (caFile && pathState(caFile) === 'file') {
    const label = `REQUESTS_CA_BUNDLE (requests, pip)  ${caFile.replace(homedir(), '~')}`;
    if (trustedCurl) out.push({ kind: 'curl', bin: trustedCurl, args: ['--cacert', caFile], version: '', caVar: 'REQUESTS_CA_BUNDLE', bundle: caFile, label, fixKey: 'requests-ca-bundle' });
    else untested?.push({ caVar: 'REQUESTS_CA_BUNDLE', bundle: caFile, label });
  }
  return out;
}
