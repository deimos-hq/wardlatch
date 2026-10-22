// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Find the TLS-capable runtimes on this machine: the first node, curl and python3 on PATH, the OS built-ins, and Python
// virtual environments under the folders you name. Nothing is changed; this only looks.
import { join, delimiter, resolve } from 'node:path';
import { homedir } from 'node:os';
import { readText, pathState, listDir, realPath, isSystemFolder } from './files.mjs';
import { runSync } from './run.mjs';

// asked for its version with lib/run.mjs's allowlisted environment, from /
const version = (bin, args, re) => { try { return (runSync(bin, args, { purpose: 'version', timeout: 5000 }).match(re) ?? [])[1] ?? ''; } catch { return ''; } };
// A virtual environment found on disk is never executed: a cloned repository can ship a fake bin/python. Its certifi
// bundle is read as a file instead (version from the dist-info, or certifi/__init__.py) and tested by a curl this
// machine already trusts (/usr/bin/curl, else the first curl on PATH) with --cacert, the same way as a Linux system bundle.
// A folder on the way that can't be opened goes into `denied`: the environment may have a certifi bundle that wasn't seen
// (27cdfbd dropped it with no row).
function certifiIn(env, denied) {
  for (const libdir of ['lib', 'lib64']) {
    const l = listDir(join(env, libdir));
    if (l.denied) { denied?.push(join(env, libdir)); continue; }
    const pys = (l.entries ?? []).map((e) => e.name).filter((n) => /^python\d/.test(n));
    for (const py of pys) {
      const sp = join(env, libdir, py, 'site-packages');
      const bundle = join(sp, 'certifi', 'cacert.pem');
      const st = pathState(bundle);
      if (st === 'denied') { denied?.push(sp); continue; }
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
 * The runtimes to probe: the first node, curl and python3 on PATH (the ones the person's shell runs), the system's own
 * curl and python3, and the OS's trust. A later copy on PATH is never run: it is never what the shell runs, and a
 * script of that name further down (a pip --user console script, say) would have run for the first time here
 * (0.1.0 to 0.1.8 ran every copy). A folder under `roots` that can't be opened goes into `denied`.
 */
export function discover({ roots = [], pathEnv = process.env.PATH ?? '', maxDepth = 5, denied } = {}) {
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
  const first = (name) => pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, name)).find((f) => pathState(f) === 'file');
  add('node', first('node')); add('curl', first('curl')); add('python', first('python3'));
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
        const c = certifiIn(p, denied);
        const key = `certifi:${p}`;
        if (c && trustedCurl && !seen.has(key)) {
          seen.add(key);
          out.push({ kind: 'curl', bin: trustedCurl, args: ['--cacert', c.bundle], version: '', env: p, certifi: c.version,
            label: `certifi ${c.version || '(version unknown)'}  ${p.replace(homedir(), '~')}`, fixKey: 'python-certifi' });
        }
        // without certifi the environment uses its base Python's trust, and that Python is checked above
      } else walk(p, depth - 1);
    }
  };
  const trustedCurl = ['/usr/bin/curl', ...pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, 'curl'))].find((f) => pathState(f) === 'file');
  // absolute, so a found bundle's path still means the same file to a curl run from /
  for (const r of roots) walk(resolve(r), maxDepth);
  return out;
}
