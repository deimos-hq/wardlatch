#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Wardlatch: does the wrong key still turn? Checks whether the runtimes on this machine still trust a compromised
// certificate authority, by asking each one to connect to public test hosts signed with the compromised keys.
// Runs locally. Sends nothing anywhere except TLS connections to those test hosts and two control sites. Changes nothing.
// A free tool from Deimos AI LLC · Apache-2.0
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { discover } from '../lib/discover.mjs';
import { check, reachable } from '../lib/probe.mjs';
import { checkBinary, findOnPath, tmpTraces } from '../lib/binaries.mjs';
import { checkVersionFiles, sitePackagesDirs, checkSitePackages, localImageDigests, checkImages } from '../lib/installs.mjs';
import { listContainers, checkContainer } from '../lib/containers.mjs';
import { reposUnder, workflowsAddedSince } from '../lib/workflows.mjs';
import { scanRepo } from '../lib/secrets.mjs';
import { wordpressUnder, checkSite } from '../lib/wordpress.mjs';

const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const VERSION = JSON.parse(readFileSync(join(LIB, '..', 'package.json'), 'utf8')).version;
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
// Names shown come from the disk, git and container engines, and can carry terminal control characters (a planted
// plugin folder could try to erase its own line). They are printed escaped, never interpreted.
const clean = (s) => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, (ch) => `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`);

// Every option is a known one, and an option that takes a value has one: a typo is refused, not quietly ignored.
const FLAGS = ['-h', '--help', '--list', '--json', '--no-containers'];
const VALUED = ['--paths', '--incident'];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (VALUED.includes(a)) {
    if (args[i + 1] === undefined || args[i + 1].startsWith('-')) { console.error(`${a} needs a value (try --help)`); process.exit(2); }
    i++;
  } else if (!FLAGS.includes(a)) { console.error(`unknown option "${clean(a)}" (try --help)`); process.exit(2); }
}

if (flag('-h') || flag('--help')) {
  console.log(`wardlatch ${VERSION}: does the wrong key still turn?

  npx wardlatch                    check this machine against every current incident
  npx wardlatch --paths ~/code     where to look for Python environments, git repositories and WordPress sites (repeatable)
  npx wardlatch --incident <id>    one incident only (--list shows them)
  npx wardlatch --json             machine-readable output
  npx wardlatch --no-containers    skip running Docker and Podman containers

Exit code: 0 all safe · 1 something is exposed · 2 something could not be tested ("review" lines don't change it).
Runs locally. Sends nothing anywhere except TLS connections to the incidents' public test hosts and two control sites.
Changes nothing.`);
  process.exit(0);
}
const incidents = readdirSync(join(LIB, 'incidents')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(LIB, 'incidents', f), 'utf8'))).sort((a, b) => b.date.localeCompare(a.date));
if (flag('--list')) { for (const i of incidents) console.log(`${i.id}  ${i.date}  ${i.title}`); process.exit(0); }
const chosen = val('--incident') ? incidents.filter((i) => i.id === val('--incident')) : incidents;
if (!chosen.length) { console.error(`unknown incident "${clean(val('--incident'))}" (try --list)`); process.exit(2); }

const json = flag('--json');
const roots = []; args.forEach((a, i) => { if (a === '--paths') roots.push(args[i + 1].replace(/^~/, homedir())); });
if (!roots.length) { for (const d of ['Development', 'code', 'src', 'projects', 'Projects', 'dev', 'work', 'Sites']) roots.push(join(homedir(), d)); roots.push('/var/www'); }

const tty = process.stdout.isTTY && !json;
const c = (code, s) => (tty ? `\x1b[${code}m${clean(s)}\x1b[0m` : clean(s));
const STATUS = { SAFE: c('32', 'SAFE   '), EXPOSED: c('31;1', 'EXPOSED'), UNKNOWN: c('33', 'UNKNOWN'), REVIEW: c('33', 'REVIEW ') };
const short = (p) => p.replace(homedir(), '~');
const print = (status, what, extra = '') => { if (!json) console.log(`${STATUS[status]}  ${clean(what)}${extra}`); };
const note = (code, text) => { if (!json) console.log(c(code, `         ${text}`)); };
const all = [];

if (!json) {
  console.log(`${c('1', 'Wardlatch')} ${VERSION} · ${chosen.length} incident${chosen.length > 1 ? 's' : ''} · runs locally, sends nothing but test connections, changes nothing`);
}

for (const inc of chosen) {
  if (!json) console.log(`\n${c('1', inc.title)} ${c('2', `(${inc.date})`)}`);
  const results = [];
  // Windows is not supported yet: these checks look only in macOS and Linux places (no .exe names, no Windows Python
  // folders), so on Windows they would read SAFE without having looked. Say so instead (README).
  if (platform() === 'win32' && ['binaries', 'installs'].includes(inc.type)) {
    results.push({ incident: inc.id, kind: inc.type === 'binaries' ? 'binary' : 'install', status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' });
    print('UNKNOWN', 'not checked on Windows yet'); note('33', 'this check looks only in macOS and Linux locations; Windows is not supported yet');
    all.push(...results); if (!json) console.log(c('2', `Source: ${inc.advisory}`)); continue;
  }

  if (inc.type === 'trust') {
    if (!json) console.log(c('2', `Asks each runtime to connect to ${inc.canaries.length} test hosts signed with the compromised keys.`));
    const fixFor = (rt) => {
      const os = platform();
      if (rt.fixKey) return inc.fixes[rt.fixKey];
      if (rt.kind === 'macos-system') return inc.fixes['macos-system'];
      if (rt.system) return inc.fixes['curl:linux'];
      return inc.fixes[`${rt.kind}:${rt.bin}:${os}`] ?? inc.fixes[`${rt.kind}:${os}`] ?? inc.fixes[rt.kind];
    };
    const canaries = await Promise.all(inc.canaries.map(async (id) => { const host = inc.canaryHost.replace('{id}', id); return { id, host, url: `https://${host}/`, up: await reachable(host) }; }));
    const rootsPem = join(LIB, 'incidents', inc.rootsPem);
    for (const rt of discover({ roots })) {
      const r = await check(rt, canaries, { rootsPem, controlUrl: inc.advisory });
      const row = { incident: inc.id, ...rt, ...r, fix: r.status === 'EXPOSED' ? fixFor(rt) : undefined };
      results.push(row);
      const what = rt.label ? `${rt.label} ${rt.version}` : rt.kind === 'python-certifi' ? `certifi ${rt.certifi}  ${short(rt.env)}` : `${rt.kind} ${rt.version}  ${short(rt.bin)}${rt.env ? `  (${short(rt.env)})` : ''}`;
      print(r.status, what, r.status === 'EXPOSED' ? c('31', `  trusts ${r.trusted.length}/${r.tested}`) : '');
      if (r.status === 'UNKNOWN') note('33', r.reason);
      if (r.note) note('2', r.note);
      if (row.fix) note('2', `fix: ${row.fix}`);
    }
    // Running containers keep their image's trust list, whatever the host has.
    for (const engine of flag('--no-containers') ? [] : ['docker', 'podman'].filter((e) => findOnPath(e))) {
      const list = listContainers(engine);
      if (list === null) { note('2', `${engine}: not running, so no running containers to check`); continue; }
      if (list.error) { results.push({ incident: inc.id, kind: 'containers', engine, status: 'UNKNOWN', reason: list.error }); print('UNKNOWN', `${engine} containers`); note('33', list.error); continue; }
      for (const ct of list) {
        const r = await checkContainer(engine, ct, canaries, { controlUrl: inc.advisory });
        const row = { incident: inc.id, kind: 'container', engine, container: ct.name, image: ct.image, ...r, fix: r.status === 'EXPOSED' ? inc.fixes.container : undefined };
        results.push(row);
        print(r.status, `${engine} ${ct.name}  ${ct.image}${r.tool ? `  (via ${r.tool})` : ''}`, r.status === 'EXPOSED' ? c('31', `  trusts ${r.trusted.length}/${r.tested}`) : '');
        if (r.status === 'UNKNOWN') note('33', r.reason);
        if (row.fix) note('2', `fix: ${row.fix}`);
      }
      if (!list.length) note('2', `${engine}: no running containers (images that aren't running aren't checked: rebuild them before you start them)`);
    }
    const down = canaries.filter((x) => !x.up).length;
    if (down) note('33', `${down} of ${canaries.length} test hosts did not answer`);
  }

  for (const rule of inc.binaries ?? []) {
    const r = checkBinary(rule);
    if (!r) continue;
    const row = { incident: inc.id, kind: 'binary', binary: rule.binary, ...r, fix: r.status !== 'SAFE' ? rule.fix : undefined };
    results.push(row);
    print(r.status, `${rule.binary} ${r.version}  ${short(r.bin)}`);
    if (r.reason) note({ EXPOSED: '31', SAFE: '2' }[r.status] ?? '33', r.reason);
    if (r.status === 'EXPOSED') note('2', `fix: ${rule.fix}`);
  }
  if (inc.type === 'binaries' && !results.length) print('SAFE', `${inc.binaries.map((b) => b.binary).join(', ')} not installed`);

  if (inc.type === 'installs') {
    // Read-only: versions from the product's own files, dropped files in site-packages by hash, local image digests.
    // Nothing found is run (lib/installs.mjs).
    const show = (r, what, fix) => {
      results.push({ incident: inc.id, kind: 'install', ...r, fix: r.status === 'EXPOSED' ? fix : r.status === 'REVIEW' ? inc.reviewFix : undefined });
      print(r.status, what);
      if (r.reason) note({ EXPOSED: '31', SAFE: '2' }[r.status] ?? '33', r.reason);
      if (r.status === 'EXPOSED') note('2', `fix: ${fix}`);
      else if (r.status === 'REVIEW' && inc.reviewFix) note('2', `check: ${inc.reviewFix}`);
    };
    const looked = [];
    if (inc.versionFiles) {
      const v = inc.versionFiles;
      for (const r of checkVersionFiles(v)) show(r, `${v.product}${r.label ? ` (${r.label})` : ''} ${r.version}  ${short(r.path)}`, v.fix);
      looked.push(v.lookedIn);
    }
    if (inc.sitePackages) {
      const dirs = sitePackagesDirs({ roots });
      for (const r of checkSitePackages(inc.sitePackages, dirs)) show(r, `${r.what}  ${short(r.dir)}`, inc.sitePackages.fix);
      // say where: a SAFE that only gives a count reads as "everywhere"
      looked.push(`${dirs.length} Python package folder${dirs.length === 1 ? '' : 's'}: the system's, Homebrew, user, pyenv, conda, pipx, uv, Poetry and Pipenv installs, and virtual environments near the top of ~ and under ${roots.map(short).join(', ')}`);
    }
    if (inc.tmpTrace) {
      for (const t of tmpTraces(inc.tmpTrace)) show({ status: 'EXPOSED', path: t, reason: 'the malware ran on this machine: it leaves this marker each time it runs' }, short(t), inc.tmpFix ?? inc.sitePackages?.fix);
      looked.push('the temp folders');
    }
    if (inc.dockerDigests && flag('--no-containers')) looked.push('no container images (--no-containers)');
    if (inc.dockerDigests && !flag('--no-containers')) {
      const byEngine = {};
      for (const e of ['docker', 'podman'].filter((x) => findOnPath(x))) {
        const list = localImageDigests(e);
        if (list === null) { note('2', `${e}: not running, so its local images were not checked`); looked.push(`no ${e} images (not running)`); continue; }
        // permission denied, no answer, too much output: the images exist but weren't seen, which is not SAFE
        if (list.error) { show({ status: 'UNKNOWN', engine: e, reason: `${list.error}, so its local images were not checked` }, `${e} images`); continue; }
        byEngine[e] = list; looked.push(`${list.length} ${e} image${list.length === 1 ? '' : 's'}`);
      }
      for (const r of checkImages(inc, byEngine)) show(r, `${r.engine} image ${r.what}`, inc.dockerFix);
    }
    // the parts that could be checked found nothing: say so, even when an engine couldn't be asked (its own UNKNOWN line
    // stays, and keeps the exit code at 2); never when a part found something or a file couldn't be read
    if (results.every((r) => r.status === 'UNKNOWN' && r.engine)) print('SAFE', `${inc.safeText ?? 'nothing found'} (looked in ${looked.filter(Boolean).join('; ')})${inc.sitePackages ? '. Pass --paths for a folder elsewhere' : ''}`);
  }

  if (inc.type === 'workflows') {
    let repos = 0;
    for (const repo of reposUnder(roots)) {
      repos++;
      const added = workflowsAddedSince(repo, inc.since);
      for (const w of added) {
        results.push({ incident: inc.id, kind: 'workflow', status: 'REVIEW', repo, ...w, fix: inc.fix });
        print('REVIEW', `${short(repo)}/${w.file}`, c('2', `  added ${w.commit}`));
      }
    }
    if (!results.length) print('SAFE', `no workflow files added since ${inc.since} in ${repos} local repositor${repos === 1 ? 'y' : 'ies'}`);
    else note('2', `check: ${inc.fix}`);
  }
  if (inc.type === 'secrets') {
    let repos = 0;
    for (const repo of reposUnder(roots)) {
      repos++;
      for (const h of scanRepo(repo)) {
        results.push({ incident: inc.id, kind: 'secret', status: 'REVIEW', repo, file: h.file, line: h.line, type: h.type, masked: h.masked, fix: inc.fix });
        print('REVIEW', `${short(repo)}/${h.file}:${h.line}`, c('2', `  ${h.type} ${h.masked}`));
      }
    }
    if (!results.length) print('SAFE', `no committed keys found in the files of ${repos} local repositor${repos === 1 ? 'y' : 'ies'} (current files; history needs gitleaks or trufflehog)`);
    else note('2', `check: ${inc.fix}`);
  }
  if (inc.type === 'wordpress') {
    const sites = wordpressUnder(roots);
    for (const site of sites) for (const f of checkSite(site, inc.rules, inc.addedSince)) {
      results.push({ incident: inc.id, kind: 'wordpress', ...f, fix: f.fix ?? (f.status === 'REVIEW' ? inc.reviewFix : undefined) });
      print(f.status, `${short(site)} · ${f.what}`, f.reason ? c('2', `  ${f.reason}`) : '');
      if (f.status === 'EXPOSED') note('2', `fix: ${f.fix}`);
    }
    if (!sites.length) print('SAFE', 'no WordPress installs found in the folders searched (run it on the server, or pass --paths)');
    else if (results.some((r) => r.status === 'REVIEW')) note('2', `check: ${inc.reviewFix}`);
  }
  all.push(...results);
  if (!json) console.log(c('2', `Source: ${inc.advisory}`));
}

const n = (s) => all.filter((r) => r.status === s).length;
if (json) console.log(JSON.stringify({ tool: 'wardlatch', version: VERSION, incidents: chosen.map((i) => ({ id: i.id, title: i.title, advisory: i.advisory })), results: all }, null, 1));
else {
  console.log(`\n${n('SAFE')} safe · ${n('EXPOSED')} exposed · ${n('UNKNOWN')} could not be tested${n('REVIEW') ? ` · ${n('REVIEW')} to review` : ''}`);
  const trust = chosen.find((i) => i.type === 'trust');
  if (trust) console.log(c('2', `Not covered here: ${trust.notCovered}`));
  console.log(c('2', 'Wardlatch, a free tool from Deimos AI LLC · https://www.deimoscore.com/wardlatch/'));
}
process.exitCode = n('EXPOSED') ? 1 : n('UNKNOWN') ? 2 : 0;   // REVIEW lines inform; they don't fail a pipeline. exitCode, not exit(): long output must finish writing
