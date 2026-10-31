// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Find the TLS-capable runtimes on this machine: the first node, curl and python3 on PATH, the OS built-ins, and Python
// virtual environments under the folders you name. Nothing is changed; this only looks.
import { join, delimiter, resolve } from 'node:path';
import { homedir } from 'node:os';
import { readText, pathState, listDir, realPath, isSystemFolder, unwalkedLinks, walkedTo, holdsMore, VENV_OWN, venvOfPackages, gapLists } from './files.mjs';
import { runSync } from './run.mjs';
import { copiesToRun } from './binaries.mjs';

// Folders this walk never enters, by name. Not hidden: the trust check names them under its rows
// (bin/wardlatch.mjs), since `mkdir node_modules` is a hiding place like any other (WV-4).
export const NOT_WALKED = ['node_modules', '.git'];

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
// `deep`: the folders the depth cap stopped at that hold more to walk (lib/files.mjs holdsMore()). `links`: every link
// to a folder that does not look like an environment (those go to `untested`) and whose target this walk did not walk
// as deep. None of the lists is opt-in: one left out that the walk has something for makes it throw (lib/files.mjs
// gapLists(); R2-N9).
export function discover({ roots = [], pathEnv = process.env.PATH ?? '', maxDepth = 5, denied, found, notRun, untested, links, deep } = {}) {
  // Windows isn't supported: its runtimes are node.exe, curl.exe and python.exe in places this doesn't look. Nothing is
  // found, and the caller says so (UNKNOWN), rather than testing whatever a Unix-style path happens to hold
  if (process.platform === 'win32') return [];
  const gap = gapLists('discover()', { denied, found, notRun, untested, links, deep });
  ({ denied, found, notRun, untested, links, deep } = gap);
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
    // with no curl, a python3 tests the same bundle (its default context reads it); with neither, it isn't tested:
    // UNKNOWN, never dropped (owner, 23 Oct 2026)
    else if (bundle && !out.some((r) => r.kind === 'python')) untested?.push({ fields: { system: true, bundle }, label: `Linux system trust store (${bundle})`, reason: 'there is neither curl nor python3 on this machine to test the distribution\'s CA bundle with: install curl and run again' });
  }
  // A link is judged only once the walk is over: its target is often listed after it is met, and a link into a folder
  // this walk already opened is not a gap at all (lib/files.mjs unwalkedLinks). `listed` is fileId() per folder listed;
  // `maybeLinks` buffers the candidates with what the row would say, so neither `links` nor `untested` gets a row for a
  // link that leads nowhere new.
  const listed = new Map(), maybeLinks = [];
  // `env`: `d` is a virtual environment, whose own folders (lib/files.mjs VENV_OWN) were probed with it and are not walked
  const walk = (d, depth, env = false) => {
    if (depth < 0) { if (deep && holdsMore(d, env ? [...NOT_WALKED, ...VENV_OWN] : NOT_WALKED)) deep.push(d); return; }
    const l = listDir(d);
    if (l.denied) { denied?.push(d); return; }
    walkedTo(listed, d, depth);
    for (const e of l.entries ?? []) {
      if (NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d) || (env && VENV_OWN.includes(e.name))) continue;
      // A link to a folder is NOT followed — one can point at a folder it sits inside, and following invites a loop —
      // and every one is REPORTED: a link that looks like an environment as an untested environment (`untested`), any
      // other as a link not followed (`links`, which the caller makes UNKNOWN: bin/wardlatch.mjs gaps()). Up to this
      // fix only the first kind was reported: a link to a folder that HOLDS environments (~/Development/work ->
      // /Volumes/Work, with app/.venv in it) went to `links`, which the caller never read, and had no row (WV-5).
      if (!e.isDirectory()) {
        const lp = join(d, e.name);
        if (e.isSymbolicLink() && pathState(lp) === 'dir') {
          const looksLikeEnv = pathState(join(lp, 'pyvenv.cfg')) === 'file'
            || pathState(join(lp, 'bin', 'python')) !== 'gone'
            || /^\.?(venv|env|virtualenv)$/i.test(e.name);
          maybeLinks.push({ path: lp, need: depth - 1, looksLikeEnv });
        }
        continue;
      }
      const p = join(d, e.name);
      // a virtual environment is probed AND walked, past its own folders: up to this fix it was only probed, so a venv
      // inside a project made with `python3 -m venv .` was never seen (R2-N1, R2-N4)
      if (isEnv(p)) { probeEnv(p); walk(p, depth - 1, true); continue; }
      // a venv's own site-packages, met by walking its lib (--paths .venv/lib): that venv is probed, as it is when its
      // own folder is met (RR-5), and its packages are not walked, as they are not then
      const owner = venvOfPackages(p);
      if (owner && isEnv(owner)) { probeEnv(owner); continue; }
      walk(p, depth - 1);
    }
  };
  // a virtual environment: never run p/bin/python; test its certifi bundle, as a file, with a trusted curl
  const isEnv = (p) => pathState(join(p, 'bin', 'python')) !== 'gone' && pathState(join(p, 'pyvenv.cfg')) === 'file';
  const probeEnv = (p) => {
    // an environment is probed whole, so a link to it from elsewhere in the walk is no gap (WV-9)
    walkedTo(listed, p, Infinity);
    const c = certifiIn(p, found);
    const key = `certifi:${p}`;
    if (c && trustedCurl && !seen.has(key)) {
      seen.add(key);
      out.push({ kind: 'curl', bin: trustedCurl, args: ['--cacert', c.bundle], version: '', env: p, certifi: c.version,
        label: `certifi ${c.version || '(version unknown)'}  ${p.replace(homedir(), '~')}`, fixKey: 'python-certifi' });
    }
    // found, but no curl on this machine to test it with: never dropped (a Linux machine without curl read SAFE)
    else if (c && !trustedCurl && !seen.has(key)) { seen.add(key); untested?.push({ fields: { env: p, certifi: c.version }, label: `certifi ${c.version || '(version unknown)'}  ${p.replace(homedir(), '~')}`, reason: 'this virtual environment\'s certifi bundle was found, but there is no curl on this machine to test it with: install curl and run again' }); }
    // without certifi the environment uses its base Python's trust, and that Python is checked above
  };
  const trustedCurl = ['/usr/bin/curl', ...pathEnv.split(delimiter).filter(Boolean).map((d) => join(d, 'curl'))].find((f) => pathState(f) === 'file');
  // absolute, so a found bundle's path still means the same file to a curl run from /
  // A folder given with --paths is always walked. One that IS an environment is probed too (up to d4d4c71, the WV-1 fix,
  // only its entries were looked at, so following the advice below for a linked venv, `--paths <it>`, made its row
  // vanish), and walked past its own folders; from d4d4c71 to this fix it was probed INSTEAD of walked, and every venv
  // inside it vanished (R2-N1). One that is a venv's own site-packages probes that venv (RR-5: --paths .venv/lib/python3.12/
  // site-packages examined nothing).
  for (const r of roots) {
    const a = resolve(r);
    if (isEnv(a)) { probeEnv(a); walk(a, maxDepth, true); continue; }
    const owner = venvOfPackages(a);
    if (owner && isEnv(owner)) probeEnv(owner);
    walk(a, maxDepth);
  }
  // now the links, with the ones that lead into a folder this walk already walked as deep dropped: a link is not a gap
  // when its bytes were read under another name (lib/files.mjs unwalkedLinks)
  for (const { path: lp, looksLikeEnv } of unwalkedLinks(maybeLinks, listed)) {
    if (!looksLikeEnv) { links?.push(lp); continue; }
    if (seen.has(`link:${lp}`)) continue;
    seen.add(`link:${lp}`);
    untested?.push({ fields: { env: lp, link: true },
      label: `linked folder  ${lp.replace(homedir(), '~')}`,
      reason: `${lp.replace(homedir(), '~')} is a link to a folder. Wardlatch does not follow links, because one can point back at a folder it is inside, so whatever is behind this link was not tested. Give it to --paths directly to have it checked.` });
  }
  // REQUESTS_CA_BUNDLE replaces certifi's list for requests and pip, and Python's own probe (urllib) never reads it: the
  // file it names is tested like a certifi bundle (up to b03e7be it went untested). bin/wardlatch.mjs made it absolute.
  // A folder there (requests reads it as a folder of certificates) is not tested: UNKNOWN, never dropped.
  const caFile = process.env.REQUESTS_CA_BUNDLE, caState = caFile ? pathState(caFile) : 'gone';
  const label = `REQUESTS_CA_BUNDLE (requests, pip)  ${(caFile ?? '').replace(homedir(), '~')}`;
  if (caState === 'file' && trustedCurl) out.push({ kind: 'curl', bin: trustedCurl, args: ['--cacert', caFile], version: '', caVar: 'REQUESTS_CA_BUNDLE', bundle: caFile, label, fixKey: 'requests-ca-bundle' });
  const caGap = (why) => untested?.push({ fields: { caVar: 'REQUESTS_CA_BUNDLE', bundle: caFile }, label, reason: `REQUESTS_CA_BUNDLE names ${caFile}, which was not tested: ${why}` });
  if (caState === 'file' && !trustedCurl) caGap('there is no curl on this machine to test it with: install curl and run again');
  else if (caState === 'denied') caGap('it could not be opened');
  else if (caState !== 'gone' && caState !== 'file') caGap('it is not a file (requests reads a folder as a folder of certificates), and Wardlatch tests only a bundle file');
  gap.done();
  return out;
}
