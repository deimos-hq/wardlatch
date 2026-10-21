// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Find the TLS-capable runtimes on this machine: every node, curl and python3 on PATH, the OS built-ins, and Python
// virtual environments under the folders you name. Nothing is changed; this only looks.
import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, delimiter } from 'node:path';

const version = (bin, args, re) => { try { const o = execFileSync(bin, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }); return (o.match(re) ?? [])[1] ?? ''; } catch { return ''; } };
const hasCertifi = (py) => { try { return execFileSync(py, ['-I', '-c', 'import certifi;print(certifi.__version__)'], { encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; } };

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
        const cv = hasCertifi(py);
        if (cv) add('python-certifi', py, { env: p, certifi: cv }); else add('python', py, { env: p });
      } else walk(p, depth - 1);
    }
  };
  for (const r of roots) walk(r, maxDepth);
  return out;
}
