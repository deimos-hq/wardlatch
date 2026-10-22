// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Find the TLS-capable runtimes on this machine: every node, curl and python3 on PATH, the OS built-ins, and Python
// virtual environments under the folders you name. Nothing is changed; this only looks.
import { existsSync, readdirSync, realpathSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, delimiter, resolve } from 'node:path';
import { homedir } from 'node:os';
import { RUN_ENV } from './binaries.mjs';

// run from / with Go's toolchain switching off, like every program Wardlatch runs (lib/binaries.mjs)
const version = (bin, args, re) => { try { const o = execFileSync(bin, args, { encoding: 'utf8', timeout: 5000, cwd: '/', env: RUN_ENV(), stdio: ['ignore', 'pipe', 'pipe'] }); return (o.match(re) ?? [])[1] ?? ''; } catch { return ''; } };
// A virtual environment found on disk is never executed: a cloned repository can ship a fake bin/python. Its certifi
// bundle is read as a file instead (version from the dist-info, or certifi/__init__.py) and tested by a curl this
// machine already trusts (/usr/bin/curl, else the first curl on PATH) with --cacert, the same way as a Linux system bundle.
function certifiIn(env) {
  for (const libdir of ['lib', 'lib64']) {
    let pys; try { pys = readdirSync(join(env, libdir)).filter((n) => /^python\d/.test(n)); } catch { continue; }
    for (const py of pys) {
      const sp = join(env, libdir, py, 'site-packages');
      const bundle = join(sp, 'certifi', 'cacert.pem');
      if (!existsSync(bundle)) continue;
      let version = '';
      try {
        const dist = readdirSync(sp).find((n) => /^certifi-.*\.dist-info$/.test(n));
        if (dist) version = (readFileSync(join(sp, dist, 'METADATA'), 'utf8').match(/^Version:\s*(\S+)/m) ?? [])[1] ?? '';
        if (!version) version = (readFileSync(join(sp, 'certifi', '__init__.py'), 'utf8').match(/__version__\s*=\s*["']([^"']+)/) ?? [])[1] ?? '';
      } catch { /* the bundle is still tested without a version */ }
      return { bundle, version };
    }
  }
  return null;
}

export function discover({ roots = [], pathEnv = process.env.PATH ?? '', maxDepth = 5 } = {}) {
  const out = []; const seen = new Set();
  const add = (kind, bin, extra = {}) => {
    if (!existsSync(bin)) return;
    let real; try { real = realpathSync(bin); } catch { real = bin; }
    const key = `${kind}:${extra.env ?? real}`; if (seen.has(key)) return; seen.add(key);
    const v = kind === 'node' ? version(bin, ['-v'], /v?([\d.]+)/) : kind === 'curl' ? version(bin, ['--version'], /curl ([\d.]+)/) : version(bin, ['-V'], /Python ([\d.]+)/);
    out.push({ kind, bin, version: v, ...extra });
  };
  for (const dir of pathEnv.split(delimiter).filter(Boolean)) { add('node', join(dir, 'node')); add('curl', join(dir, 'curl')); add('python', join(dir, 'python3')); }
  for (const b of ['/usr/bin/curl', '/usr/bin/python3']) add(b.endsWith('curl') ? 'curl' : 'python', b);
  // The operating system's own trust: macOS's networking stack (Safari, Apple's apps), or a Linux distribution's bundle.
  if (process.platform === 'darwin' && existsSync('/usr/bin/nscurl')) {
    out.push({ kind: 'macos-system', bin: '/usr/bin/nscurl', version: version('/usr/bin/sw_vers', ['-productVersion'], /([\d.]+)/), label: 'macOS system (Safari and Apple apps)' });
  }
  if (process.platform === 'linux') {
    const bundle = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem'].find(existsSync);
    const curl = pathEnv.split(delimiter).map((d) => join(d, 'curl')).find(existsSync);
    if (bundle && curl) out.push({ kind: 'curl', bin: curl, args: ['--cacert', bundle], version: version(curl, ['--version'], /curl ([\d.]+)/), label: `Linux system trust store (${bundle})`, system: true });
  }
  const walk = (d, depth) => {
    if (depth < 0) return;
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name === '.git' || e.name === 'Library') continue;
      const p = join(d, e.name);
      const py = join(p, 'bin', 'python');
      if (existsSync(py) && existsSync(join(p, 'pyvenv.cfg'))) {
        // never run p/bin/python: test the environment's certifi bundle, as a file, with a trusted curl
        const c = certifiIn(p);
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
  const trustedCurl = ['/usr/bin/curl', ...pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, 'curl'))].find(existsSync);
  // absolute, so a found bundle's path still means the same file to a curl run from /
  for (const r of roots) walk(resolve(r), maxDepth);
  return out;
}
