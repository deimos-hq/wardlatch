#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Wardlatch: does the wrong key still turn? Checks whether the runtimes on this machine still trust a compromised
// certificate authority, by asking each one to connect to public test hosts signed with the compromised keys.
// Runs locally. Sends nothing anywhere except TLS connections to those test hosts and two control sites. Changes nothing.
// A free tool from Deimos AI LLC · Apache-2.0
import '../lib/crash.mjs';
import { join, dirname, delimiter, isAbsolute, resolve } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { discover } from '../lib/discover.mjs';
import { check, reachable } from '../lib/probe.mjs';
import { droppedNodeOptions } from '../lib/run.mjs';
import { checkBinaryAll, findOnPath, tmpTraces, tempDirs } from '../lib/binaries.mjs';
import { checkVersionFiles, sitePackagesDirs, checkSitePackages, localImageDigests, checkImages } from '../lib/installs.mjs';
import { listContainers, checkContainer, engineHost } from '../lib/containers.mjs';
import { reposUnder, workflowsAddedSince } from '../lib/workflows.mjs';
import { scanRepo } from '../lib/secrets.mjs';
import { wordpressUnder, checkSite } from '../lib/wordpress.mjs';
import { scanHeaders } from '../lib/headers.mjs';
import { pathState, readText, listDir } from '../lib/files.mjs';
import { ownedByPerson, ownerName } from '../lib/owners.mjs';
import { safe, withdrawUnreceipted } from '../lib/report.mjs';

// npx puts the current project's node_modules/.bin, and each parent folder's, first on PATH. Wardlatch finds git,
// python3, node, curl, php, go and the container engines on PATH and runs some of them, so a project could otherwise
// have it run the project's own programs. Those folders, and any relative entry, are dropped before anything runs.
// npx also starts Wardlatch with the project's own node_modules/.bin/node if it has one, and applies the project's
// .npmrc, before any of this runs; nothing here can undo either: run it from your home folder, as the README says.
// When nothing is left (PATH unset, or made only of dropped entries), PATH is /usr/bin:/bin, as Node itself assumes for
// an unset PATH. An empty PATH would make a bare program name resolve in the current folder.
const kept = (process.env.PATH ?? '').split(delimiter).filter((d) => d && isAbsolute(d) && !/[\\/]node_modules[\\/]\.bin[\\/]?$/.test(d));
process.env.PATH = kept.length ? kept.join(delimiter) : ['/usr/bin', '/bin'].join(delimiter);
// Programs run from /, so a relative CA file or folder in the person's own environment is made absolute first, against
// the folder Wardlatch was started from, as their own programs would read it.
for (const k of ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'REQUESTS_CA_BUNDLE']) {
  if (!process.env[k]) continue;
  // SSL_CERT_DIR may be a list of folders
  process.env[k] = k === 'SSL_CERT_DIR' ? process.env[k].split(delimiter).map((d) => (d && !isAbsolute(d) ? resolve(d) : d)).join(delimiter)
    : isAbsolute(process.env[k]) ? process.env[k] : resolve(process.env[k]);
}

const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const VERSION = JSON.parse(readText(join(LIB, '..', 'package.json'), 1024 * 1024)).version;
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

  npx wardlatch@latest             check this machine against every current incident
  npx wardlatch@latest --paths ~/code   where to look for Python environments, git repositories and WordPress sites (repeatable)
  npx wardlatch@latest --incident <id>  one incident only (--list shows them)
  npx wardlatch@latest --json      machine-readable output
  npx wardlatch@latest --no-containers  skip Docker and Podman (running containers and local images)

Run it from your home folder, not inside a project: npx also starts Wardlatch with the project's own
node_modules/.bin/node if it has one, and applies its .npmrc; Wardlatch can't undo either.
Exit code: 0 all safe · 1 something is exposed · 2 something could not be tested ("review" lines don't change it).
Runs locally. Sends nothing anywhere except TLS connections to the incidents' public test hosts and two control sites
(and what your container engine sends, if your docker context points at a remote one; a remote DOCKER_HOST is not followed,
a local socket is). Changes nothing.`);
  process.exit(0);
}
const incidents = (listDir(join(LIB, 'incidents')).entries ?? []).map((e) => e.name).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readText(join(LIB, 'incidents', f), 4 * 1024 * 1024))).sort((a, b) => b.date.localeCompare(a.date));
if (flag('--list')) { for (const i of incidents) console.log(`${i.id}  ${i.date}  ${i.title}`); process.exit(0); }
const chosen = val('--incident') ? incidents.filter((i) => i.id === val('--incident')) : incidents;
if (!chosen.length) { console.error(`unknown incident "${clean(val('--incident'))}" (try --list)`); process.exit(2); }

const json = flag('--json');
// absolute before anything runs: programs run from /, where a relative folder would mean something else
// Whose files to look at: under sudo (which Wardlatch's own messages suggest for folders it can't open), the person who
// ran sudo, not root. $HOME is root's there, and every default folder below pointed at root's empty home.
// A sudo user whose home isn't in the usual place leaves root's home searched: said in an UNKNOWN row per incident.
let sudoHomeMissing = '';
const HOME = (() => {
  const u = process.env.SUDO_USER;
  // root running sudo (SUDO_USER=root) is root's own home
  if (u && u !== 'root' && process.getuid?.() === 0) {
    // a name with a slash or .. can't be a home folder's name (a directory user can be ada@corp.example)
    const h = /^[\w.@-]+$/.test(u) && !u.includes('..') ? (platform() === 'darwin' ? `/Users/${u}` : `/home/${u}`) : '';
    if (h && pathState(h) === 'dir') return h;
    sudoHomeMissing = `run under sudo by ${clean(u)}, whose home folder was not found${h ? ` at ${h}` : ''}: root's home (${homedir()}) was searched instead. Run Wardlatch without sudo, or pass --paths`;
  }
  return homedir();
})();
// every module that resolves ~ (os.homedir() reads $HOME) then searches the same home: under sudo, the person's
process.env.HOME = HOME;
const explicitPaths = args.includes('--paths');
const roots = []; args.forEach((a, i) => { if (a === '--paths') roots.push(resolve(args[i + 1].replace(/^~/, HOME))); });
if (!roots.length) { for (const d of ['Development', 'code', 'src', 'projects', 'Projects', 'dev', 'work', 'Sites']) roots.push(join(HOME, d)); roots.push('/var/www', '/srv/www', '/Library/WebServer/Documents'); }
// which of them exist and can be searched; one that exists but can't be opened is a gap, reported per check
const searchable = roots.filter((r) => pathState(r) === 'dir');
const lockedRoots = roots.filter((r) => pathState(r) === 'denied');
// a folder given with --paths that isn't there, or isn't a folder (a file, a FIFO), was not searched: an UNKNOWN row of
// its own, even beside others that are
const missingRoots = explicitPaths ? roots.filter((r) => ['gone', 'file', 'other'].includes(pathState(r))) : [];

const tty = process.stdout.isTTY && !json;
const c = (code, s) => (tty ? `\x1b[${code}m${clean(s)}\x1b[0m` : clean(s));
const STATUS = { SAFE: c('32', 'SAFE   '), EXPOSED: c('31;1', 'EXPOSED'), UNKNOWN: c('33', 'UNKNOWN'), REVIEW: c('33', 'REVIEW ') };
const short = (p) => p.replace(HOME, '~');
// an EXPOSED line sets the exit code as it is printed, so a crash after it can't turn it into "could not be tested"
const print = (status, what, extra = '') => { if (status === 'EXPOSED') process.exitCode = 1; if (!json) console.log(`${STATUS[status]}  ${clean(what)}${extra}`); };
const note = (code, text) => { if (!json) console.log(c(code, `         ${text}`)); };
const all = [];
// SAFE needs a receipt (lib/report.mjs). Every summary all-clear goes through here: it is a result row too (0.1.8
// printed it but left it out of --json, so a reader couldn't tell "clean" from "not checked"), it names what it
// searched, and when nothing could be searched it is UNKNOWN instead (a typo in --paths, a different HOME under sudo).
// With no --paths and none of the usual folders there (a fresh server, a CI runner), there is nothing of the kind to look
// in: SAFE, and the receipt lists the folders looked for (owner, 22 Oct; 0.1.9's first cut said UNKNOWN, exit 2, and
// whether a machine passed depended on whether an empty ~/Development happened to exist).
function allClear(results, inc, kind, text, searched) {
  if (searched.length) { const row = { incident: inc.id, kind, ...safe(searched), reason: text }; results.push(row); print(row.status, text); return; }
  if (!explicitPaths) {
    const reason = `none of the usual folders exist here (${roots.map(short).join(', ')}), so there was nothing to search: pass --paths for a folder elsewhere`;
    const row = { incident: inc.id, kind, ...safe(roots.map((r) => `looked for ${r}`)), reason }; results.push(row); print(row.status, reason); return;
  }
  const reason = `none of the folders given with --paths exist (${roots.map(short).join(', ')}), so nothing was searched`;
  results.push({ incident: inc.id, kind, status: 'UNKNOWN', reason });
  print('UNKNOWN', reason);
}
// The machine's own runtime rows, counted by name (an allowlist: any other kind of row, a skipped-folders line, a
// container, must never stand in for them)
const RUNTIME_KINDS = ['node', 'curl', 'python', 'macos-system'];
const hostRowsOf = (results) => results.filter((r) => RUNTIME_KINDS.includes(r.kind)).length;
// rows that count for a summary line: a skipped-folders or not-run line is information beside it, never instead of it
const counted = (results) => results.filter((r) => !['skipped', 'not-run'].includes(r.kind));
// later copies on PATH that are scripts, and so were not run (lib/binaries.mjs copiesToRun): a REVIEW line, in --json
// too, so a reader can tell a copy went unchecked; it doesn't change the exit code
function notRunRow(results, inc, what, paths) {
  if (!paths.length) return;
  const reason = `${what}: ${paths.length === 1 ? 'a later copy' : 'later copies'} on PATH ${paths.length === 1 ? 'is a script' : 'are scripts'}, not ${paths.length === 1 ? 'a program' : 'programs'}, so Wardlatch did not run ${paths.length === 1 ? 'it' : 'them'} and ${paths.length === 1 ? 'its' : 'their'} version was not checked: ${paths.map(short).join(', ')}`;
  results.push({ incident: inc.id, kind: 'not-run', status: 'REVIEW', paths, reason });
  print('REVIEW', 'copies on PATH not run'); note('2', reason);
}

// Folders that couldn't be opened: the one rule for every check (owner, 22 Oct 2026). Every source of them comes here.
//   - a searched root (a --paths folder, or a usual folder that exists) that can't be opened: UNKNOWN;
//   - `found`: something already found whose own folders can't be read (a virtual environment's lib): UNKNOWN;
//   - a folder below a root, owned by a person (this user, or a login account), could hold that person's projects or
//     sites: UNKNOWN; owned by a service (root, a database, a container, certbot), it holds that service's data: one
//     REVIEW line per check listing them, which doesn't change the exit code (lib/owners.mjs says which is which).
//   - `review`: folders a check knows to be private by their place (a locked dot-folder under a web root: www-data's
//     .ssh), listed in the REVIEW line whoever owns them.
// Up to e0e1c35 every locked folder was UNKNOWN, and any server with docker or certbot exited 2.
// `searchesRoots`: whether this check searches the --paths folders at all (Plex's and GitLab's look only in their own
// install places: a --paths folder that isn't there is nothing to them)
function gaps(results, inc, kind, dirs, { found = [], searchesRoots = true, review = [] } = {}) {
  for (const d of searchesRoots ? missingRoots : []) {
    const reason = `given with --paths, but ${pathState(d) === 'gone' ? 'not there' : 'not a folder'}, so it was not searched`;
    results.push({ incident: inc.id, kind, status: 'UNKNOWN', path: d, reason });
    print('UNKNOWN', short(d)); note('33', reason);
  }
  // on macOS a folder can be closed by privacy protection (Desktop, Documents, Downloads, iCloud), which sudo doesn't open
  const how = platform() === 'darwin' ? 'run Wardlatch with sudo if it belongs to another user, or allow your terminal Full Disk Access (System Settings → Privacy & Security) if macOS is protecting it' : 'run Wardlatch with sudo to include it';
  const unknown = (d, reason) => { results.push({ incident: inc.id, kind, status: 'UNKNOWN', path: d, reason }); print('UNKNOWN', short(d)); note('33', reason); };
  const skipped = [];
  for (const d of [...new Set(found)]) unknown(d, `found, but could not be read, so it was not checked: ${how}`);
  // a searched root itself (a --paths folder, or /var/www) that can't be opened is always UNKNOWN: it was asked for
  for (const d of [...new Set(dirs)].filter((x) => !found.includes(x))) {
    if (lockedRoots.includes(d) || roots.includes(d) || ownedByPerson(d, kind)) unknown(d, `could not be opened, so it was not searched: ${how}`);
    else skipped.push(d);
  }
  skipped.push(...review.filter((d) => !skipped.includes(d)));
  if (skipped.length) {
    const list = skipped.slice(0, 8).map((d) => `${short(d)} (${ownerName(d)})`).join(', ') + (skipped.length > 8 ? `, and ${skipped.length - 8} more` : '');
    const reason = `${skipped.length} folder${skipped.length === 1 ? '' : 's'} owned by service accounts, or private by ${skipped.length === 1 ? 'its' : 'their'} place, could not be opened and ${skipped.length === 1 ? 'was' : 'were'} not searched: ${list}. Run Wardlatch with sudo to include ${skipped.length === 1 ? 'it' : 'them'}`;
    results.push({ incident: inc.id, kind: 'skipped', status: 'REVIEW', paths: skipped, reason });
    print('REVIEW', 'folders not searched'); note('2', reason);
  }
}

// NODE_OPTIONS words a probe doesn't need to measure trust, and that change no trust: memory, warnings, traces
// (Node takes either spelling of a name, --max_old_space_size too)
const BENIGN_NODE_OPTION_RE = /^--(?:max-old-space-size|max-semi-space-size|max-http-header-size|stack-size|stack-trace-limit|no-warnings|no-deprecation|enable-source-maps|trace-warnings|trace-deprecation|trace-uncaught|unhandled-rejections|dns-result-order|openssl-legacy-provider|disable-warning|experimental-vm-modules)(?:=[\w.-]*)?$/;
const benignNodeOption = (w) => { const i = w.indexOf('='); return BENIGN_NODE_OPTION_RE.test((i < 0 ? w : w.slice(0, i)).replace(/_/g, '-') + (i < 0 ? '' : w.slice(i))); };
// A DOCKER_HOST or the like that isn't followed (lib/containers.mjs engineHost(): anything but a local socket the person
// or root owns): the engine it names was not checked, whatever answers locally. Every check that asks an engine (running
// containers, local images) says so in an UNKNOWN row.
// (a local socket DOCKER_HOST names is followed: lib/containers.mjs engineHost(); the row appears only when an engine is
// installed, since without one there is nothing it could have named to check)
const hostVars = engineHost().refused;
function hostVarsRow(results, inc, what) {
  if (!hostVars.length || flag('--no-containers') || !['docker', 'podman'].some((e) => findOnPath(e))) return;
  const reason = `${hostVars.join(', ')} ${hostVars.length === 1 ? 'is' : 'are'} set, and not followed (whoever starts Wardlatch can point ${hostVars.length === 1 ? 'it' : 'them'} at any host): the ${what} there were not checked. Select the engine with \`docker context use\` instead, or pass --no-containers`;
  results.push({ incident: inc.id, kind: 'containers', engine: hostVars.join(','), status: 'UNKNOWN', reason });
  print('UNKNOWN', `${what} named by the environment`); note('33', reason);
}

if (!json) {
  console.log(`${c('1', 'Wardlatch')} ${VERSION} · ${chosen.length} incident${chosen.length > 1 ? 's' : ''} · runs locally, sends nothing but test connections, changes nothing`);
}

for (const inc of chosen) {
  if (!json) console.log(`\n${c('1', inc.title)} ${c('2', `(${inc.date})`)}`);
  const results = [];
  // only where the home folder is read: the trust check (the probes' ~/.curlrc, the go env file, the engine's config),
  // installs and headers always; the folder checks only when their usual folders, in the home, are the ones searched;
  // never the version checks, which read PATH
  const readsHome = ['trust', 'installs', 'headers'].includes(inc.type) || (['workflows', 'secrets', 'wordpress'].includes(inc.type) && !explicitPaths);
  if (sudoHomeMissing && readsHome) { results.push({ incident: inc.id, kind: 'home', status: 'UNKNOWN', reason: sudoHomeMissing }); print('UNKNOWN', 'home folder'); note('33', sudoHomeMissing); }
  // Windows is not supported yet: the program checks look only for macOS and Linux names (no .exe), so on Windows they
  // would read SAFE without having looked. Say so instead (README). A malware's temp-folder trace still counts: the
  // temp directory is read on Windows too.
  if (platform() === 'win32' && inc.type === 'binaries') {
    let traced = 0;
    for (const rule of inc.binaries) {
      const t = rule.tmpTrace ? tmpTraces(rule.tmpTrace) : [];
      if (!t.length) continue;
      traced++;
      results.push({ incident: inc.id, kind: 'binary', binary: rule.binary, status: 'EXPOSED', bin: t[0], version: '', reason: `the malware ran on this machine: it left ${t.join(', ')}`, fix: rule.fix });
      print('EXPOSED', `${rule.binary}  ${short(t[0])}`); note('31', `the malware ran on this machine: it left ${t.join(', ')}`); note('2', `fix: ${rule.fix}`);
    }
    if (traced < inc.binaries.length) {
      results.push({ incident: inc.id, kind: 'binary', status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' });
      print('UNKNOWN', 'not checked on Windows yet'); note('33', 'this check looks only in macOS and Linux locations; Windows is not supported yet');
    }
    all.push(...results); if (!json) console.log(c('2', `Source: ${inc.advisory}`)); continue;
  }
  // installed software is looked for only in macOS and Linux places (no Windows Python folders or install paths)
  if (platform() === 'win32' && inc.type === 'installs') {
    results.push({ incident: inc.id, kind: 'install', status: 'UNKNOWN', reason: 'not checked on Windows yet (Windows is not supported)' });
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
    // a test host counts as up only when it presents the compromised chain's issuer: a TLS-inspecting firewall or a DNS
    // filter answering in its place would otherwise make every refusal look like the runtime's own (0.1.4 to 0.1.8)
    const issuerOk = (issuer) => !inc.canaryIssuer || new RegExp(inc.canaryIssuer).test(issuer);
    const canaries = await Promise.all(inc.canaries.map(async (id) => {
      const host = inc.canaryHost.replace('{id}', id);
      const r = await reachable(host);
      // which distrusted root this host's chain ends at: a runtime is only SAFE when each root had a host to test
      const g = inc.canaryRoots?.find((x) => x.canaries.includes(id));
      return { id, host, url: `https://${host}/`, root: g?.root, pem: g?.pem ? join(LIB, 'incidents', g.pem) : undefined, up: r.up && issuerOk(r.issuer), impostor: r.up && !issuerOk(r.issuer) ? r.issuer : '' };
    }));
    // the probes get only what changes trust or the route to a host (lib/run.mjs); say what of the person's own
    // settings they did not get, since a probe without it can measure less trust than the person's programs have
    // An UNKNOWN row (in --json too), not only a note: a CA added through NODE_OPTIONS --require (mac-ca, syswide-cas)
    // is trust the person's Node has and the probe doesn't, and d59e114 read SAFE, exit 0 with one in place.
    const notPassed = [
      ...(droppedNodeOptions().filter((w) => !benignNodeOption(w)).length ? [`NODE_OPTIONS (${droppedNodeOptions().join(' ').slice(0, 120)})`] : []),
      ...(process.env.OPENSSL_CONF ? ['OPENSSL_CONF'] : []),
    ];
    if (notPassed.length) {
      const reason = `${notPassed.join(', ')}: set in this environment and not given to the probes, since ${notPassed.length === 1 ? 'it' : 'they'} can load code or point a program at files the caller chose. Trust added that way was not tested`;
      results.push({ incident: inc.id, kind: 'environment', status: 'UNKNOWN', reason });
      print('UNKNOWN', 'settings not given to the probes'); note('33', reason);
    }
    const impostors = canaries.filter((x) => x.impostor);
    if (impostors.length) note('33', `${impostors.length} test host${impostors.length === 1 ? '' : 's'} answered with a certificate from "${impostors[0].impostor}", not the compromised chain: something on this network (a TLS-inspecting firewall, a DNS filter) is in the way, and those hosts were not used`);
    const rootsPem = join(LIB, 'incidents', inc.rootsPem);
    const deniedVenvs = [...lockedRoots], foundUnread = [], notRun = [];
    for (const rt of discover({ roots: searchable, denied: deniedVenvs, found: foundUnread, notRun })) {
      const r = await check(rt, canaries, { rootsPem, controlUrl: inc.advisory });
      const row = { incident: inc.id, ...rt, ...r, fix: r.status === 'EXPOSED' ? fixFor(rt) : undefined };
      results.push(row);
      const what = rt.label ? `${rt.label} ${rt.version}` : `${rt.kind} ${rt.version}  ${short(rt.bin)}${rt.env ? `  (${short(rt.env)})` : ''}`;
      print(r.status, what, r.status === 'EXPOSED' ? c('31', `  trusts ${r.trusted.length}/${r.tested}`) : '');
      if (r.status === 'UNKNOWN') note('33', r.reason);
      if (r.note) note('2', r.note);
      if (row.fix) note('2', `fix: ${row.fix}`);
    }
    gaps(results, inc, 'search', deniedVenvs, { found: foundUnread });
    notRunRow(results, inc, 'trust', notRun);
    // the test hosts' certificates expire: after that a container (which has no forced-roots control) would read every
    // refusal as SAFE, so containers are UNKNOWN once the incident's notAfter has passed
    const expired = inc.canaryNotAfter && Date.now() > Date.parse(inc.canaryNotAfter);
    if (expired) note('33', `the test hosts' certificates expired on ${inc.canaryNotAfter}: containers can't be tested against them`);
    hostVarsRow(results, inc, 'containers');
    // Running containers keep their image's trust list, whatever the host has.
    for (const engine of flag('--no-containers') ? [] : ['docker', 'podman'].filter((e) => findOnPath(e))) {
      const list = listContainers(engine);
      if (list === null) { note('2', `${engine}: not running, so no running containers to check`); continue; }
      if (list.error) { results.push({ incident: inc.id, kind: 'containers', engine, status: 'UNKNOWN', reason: list.error }); print('UNKNOWN', `${engine} containers`); note('33', list.error); continue; }
      for (const ct of list) {
        const r = expired ? { status: 'UNKNOWN', trusted: [], tested: 0, reason: `the test hosts' certificates expired on ${inc.canaryNotAfter}, so a refusal here would prove nothing` } : await checkContainer(engine, ct, canaries, { controlUrl: inc.advisory });
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
  // A trust check that found nothing to test is not an all-clear: possible anywhere, and always so for the machine itself
  // on Windows, whose program names discover() doesn't look for (a container row must not hide that). Up to 0.1.6
  // nothing was printed here, and the exit code could be 0.
  // Counted from the host's own runtime rows: a container row used to stand in for them (0.1.8: one container SAFE,
  // nothing tested on the machine, exit 0).
  if (inc.type === 'trust' && (platform() === 'win32' || !hostRowsOf(results))) {
    const reason = platform() !== 'win32' ? 'no runtime was found to test'
      : results.some((r) => r.kind === 'container') ? 'the runtimes on this machine were not checked: Windows is not supported yet' : 'not checked on Windows yet (Windows is not supported)';
    results.push({ incident: inc.id, kind: 'runtimes', status: 'UNKNOWN', reason });
    print('UNKNOWN', reason);
  }

  // every copy of each program on PATH (a fixed one first used to hide a vulnerable one behind it); a program that
  // isn't there gets its own receipt row naming PATH (go and cloudflared in the trust incident used to get none)
  // on Windows (not supported) program checks look in macOS and Linux places only: not checked, never "not found"
  for (const rule of platform() === 'win32' ? [] : inc.binaries ?? []) {
    const rows = checkBinaryAll(rule);
    notRunRow(results, inc, rule.binary, rows.notRun ?? []);
    for (const r of rows) {
      const row = { incident: inc.id, kind: 'binary', binary: rule.binary, ...r, fix: r.status !== 'SAFE' ? rule.fix : undefined };
      results.push(row);
      print(r.status, `${rule.binary} ${r.version}  ${short(r.bin)}`);
      if (r.reason) note({ EXPOSED: '31', SAFE: '2' }[r.status] ?? '33', r.reason);
      if (r.status === 'EXPOSED') note('2', `fix: ${rule.fix}`);
    }
    if (!rows.length) allClear(results, inc, 'binary', `${rule.binary} not found on PATH (searched: ${short(process.env.PATH ?? '')})`, [`PATH: ${process.env.PATH ?? ''}`, ...(rule.tmpTrace ? tempDirs() : [])]);
  }

  // A repository git could not read (a partial clone missing what git would have to fetch, an ownership refusal, a
  // timeout) is UNKNOWN with git's reason, and is left out of the count in the SAFE line: it was not looked at.
  const unread = (kind, repo, error) => {
    results.push({ incident: inc.id, kind, status: 'UNKNOWN', repo, reason: `git could not read this repository (${error})` });
    print('UNKNOWN', short(repo)); note('33', `git could not read it: ${error}`);
  };
  const repoCount = (n) => `${n} local repositor${n === 1 ? 'y' : 'ies'}`;

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
    // what was looked at, for the all-clear's receipt; folders that couldn't be opened, for UNKNOWN rows
    const searched = [], denied = [], foundUnread = [];
    if (inc.versionFiles) {
      const v = inc.versionFiles;
      for (const r of checkVersionFiles(v)) show(r, `${v.product}${r.label ? ` (${r.label})` : ''} ${r.version}  ${short(r.path)}`, v.fix);
      searched.push(v.lookedIn);
    }
    if (inc.sitePackages) {
      // an explicit --paths that doesn't exist is a search of nothing: UNKNOWN, not an all-clear for that part
      if (explicitPaths && !searchable.length) show({ status: 'UNKNOWN', reason: `none of the folders given with --paths exist (${roots.map(short).join(', ')}), so no virtual environment there was searched` }, 'folders given with --paths');
      denied.push(...lockedRoots);
      const dirs = sitePackagesDirs({ roots: searchable, denied, found: foundUnread });
      for (const r of checkSitePackages(inc.sitePackages, dirs)) show(r, `${r.what}  ${short(r.dir)}`, inc.sitePackages.fix);
      searched.push(...dirs);
    }
    if (inc.tmpTrace) {
      const temps = tempDirs();
      // a temp folder that can't be listed is a known place the marker would be: always UNKNOWN, and not in the receipt
      const tempsDenied = [];
      for (const t of tmpTraces(inc.tmpTrace, temps, tempsDenied)) show({ status: 'EXPOSED', path: t, reason: 'the malware ran on this machine: it leaves this marker each time it runs' }, short(t), inc.tmpFix ?? inc.sitePackages?.fix);
      foundUnread.push(...tempsDenied);
      searched.push(...temps.filter((t) => !tempsDenied.includes(t)));
    }
    if (inc.dockerDigests && !flag('--no-containers')) {
      hostVarsRow(results, inc, 'images');
      const byEngine = {};
      for (const e of ['docker', 'podman'].filter((x) => findOnPath(x))) {
        const list = localImageDigests(e);
        if (list === null) { note('2', `${e}: not running, so its local images were not checked`); continue; }
        // permission denied, no answer, too much output: the images exist but weren't seen, which is not SAFE
        if (list.error) { show({ status: 'UNKNOWN', engine: e, reason: `${list.error}, so its local images were not checked` }, `${e} images`); continue; }
        byEngine[e] = list; searched.push(`${list.length} ${e} image${list.length === 1 ? '' : 's'}`);
      }
      for (const r of checkImages(inc, byEngine)) show(r, `${r.engine} image ${r.what}`, inc.dockerFix);
    }
    gaps(results, inc, 'install', denied, { found: foundUnread, searchesRoots: Boolean(inc.sitePackages) });
    // nothing found in any part that could be looked at: the all-clear names every folder it searched. An engine that
    // couldn't be asked keeps its own UNKNOWN row (and the exit code at 2) beside it; a finding or another gap doesn't.
    const onlyEngineGaps = counted(results).every((r) => r.status === 'UNKNOWN' && r.engine);
    if (onlyEngineGaps) allClear(results, inc, 'install', `${inc.safeText ?? 'nothing found'} (looked in ${searched.length} place${searched.length === 1 ? '' : 's'}${inc.sitePackages ? '; pass --paths for a folder elsewhere' : ''})`, searched.filter(Boolean));
  }

  if (inc.type === 'workflows') {
    let repos = 0;
    const denied = [...lockedRoots];
    for (const repo of reposUnder(searchable, 4, denied)) {
      const added = workflowsAddedSince(repo, inc.since);
      if (added.error) { unread('workflow', repo, added.error); continue; }
      repos++;
      for (const w of added) {
        results.push({ incident: inc.id, kind: 'workflow', status: 'REVIEW', repo, ...w, fix: inc.fix });
        print('REVIEW', `${short(repo)}/${w.file}`, c('2', `  added ${w.commit}`));
      }
    }
    gaps(results, inc, 'workflow', denied);
    if (counted(results).some((r) => r.status === 'REVIEW')) note('2', `check: ${inc.fix}`);
    else if (!counted(results).length) allClear(results, inc, 'workflow', `no workflow files added since ${inc.since} in ${repoCount(repos)}`, searchable);
  }
  if (inc.type === 'secrets') {
    let repos = 0;
    const denied = [...lockedRoots];
    for (const repo of reposUnder(searchable, 4, denied)) {
      const hits = scanRepo(repo);
      if (hits.error) { unread('secret', repo, hits.error); continue; }
      repos++;
      for (const h of hits) {
        if (h.unread) { results.push({ incident: inc.id, kind: 'secret', status: 'UNKNOWN', repo, file: h.file, reason: h.unread }); print('UNKNOWN', `${short(repo)}/${h.file}`); note('33', h.unread); continue; }
        results.push({ incident: inc.id, kind: 'secret', status: 'REVIEW', repo, file: h.file, line: h.line, type: h.type, masked: h.masked, fix: inc.fix });
        print('REVIEW', `${short(repo)}/${h.file}:${h.line}`, c('2', `  ${h.type} ${h.masked}`));
      }
    }
    gaps(results, inc, 'secret', denied);
    if (counted(results).some((r) => r.status === 'REVIEW')) note('2', `check: ${inc.fix}`);
    else if (!counted(results).length) allClear(results, inc, 'secret', `no committed keys found in the files of ${repoCount(repos)} (current files; history needs gitleaks or trufflehog)`, searchable);
  }
  if (inc.type === 'wordpress') {
    const denied = [...lockedRoots];
    const privateDot = [];
    const sites = wordpressUnder(searchable, 5, denied, privateDot);
    for (const site of sites) for (const f of checkSite(site, inc.rules, inc.addedSince)) {
      results.push({ incident: inc.id, kind: 'wordpress', ...f, fix: f.fix ?? (f.status === 'REVIEW' ? inc.reviewFix : undefined) });
      print(f.status, `${short(site)} · ${f.what}`, f.reason ? c('2', `  ${f.reason}`) : '');
      if (f.status === 'EXPOSED') note('2', `fix: ${f.fix}`);
    }
    gaps(results, inc, 'wordpress', denied, { review: privateDot });
    if (!counted(results).length) allClear(results, inc, 'wordpress', `no WordPress installs found in ${searchable.length} folder${searchable.length === 1 ? '' : 's'} searched (run it on the server, or pass --paths)`, searchable);
    else if (counted(results).some((r) => r.status === 'REVIEW')) note('2', `check: ${inc.reviewFix}`);
  }
  if (inc.type === 'headers') {
    // your name and email are read from this machine to compare against; they are never printed or sent
    const h = scanHeaders({ home: HOME, roots: searchable });
    for (const u of h.unread) {
      results.push({ incident: inc.id, kind: 'header', status: 'UNKNOWN', file: u.file, reason: u.reason });
      print('UNKNOWN', short(u.file)); note('33', `could not read it: ${u.reason}`);
    }
    for (const f of h.findings) {
      results.push({ incident: inc.id, kind: 'header', status: f.status, file: f.file, where: f.where, carries: f.carries, to: f.to, fix: inc.fix });
      print(f.status, `${short(f.file)} · ${f.where}`, c('2', `  carries ${f.carries}, ${f.to}`));
    }
    gaps(results, inc, 'header', [...lockedRoots, ...h.denied]);
    if (h.findings.length) note('2', `fix: ${inc.fix}`);
    else if (!counted(results).length) allClear(results, inc, 'header', `no name or email in the ${h.settings} header setting${h.settings === 1 ? '' : 's'} found in ${h.read} file${h.read === 1 ? '' : 's'} and the environment`, [...h.files, 'the environment']);
    if (h.notUsed.length) note('2', `${h.notUsed.length} settings file${h.notUsed.length === 1 ? '' : 's'} this user can't open (so its tools can't read ${h.notUsed.length === 1 ? 'it' : 'them'} either): ${h.notUsed.slice(0, 4).map(short).join(', ')}${h.notUsed.length > 4 ? ', …' : ''}`);
    if (!h.id.name && !h.id.email) note('2', 'no git name or email is set, so only email-shaped values were looked for');
    note('2', `not covered: ${inc.notCovered}`);
  }
  all.push(...results);
  if (!json) console.log(c('2', `Source: ${inc.advisory}`));
}

// The receipt rule, enforced once more on the way out: a SAFE row that can't say what it looked at is not printed as one,
// however it was made (lib/report.mjs's safe() is the only intended way; this catches any other)
// (the text line was printed already: a correction line follows it)
for (const r of withdrawUnreceipted(all)) { print('UNKNOWN', `the SAFE line for ${r.kind} above is withdrawn`); note('33', r.reason); }
const count = { SAFE: 0, EXPOSED: 0, UNKNOWN: 0, REVIEW: 0 };
for (const r of all) if (r.status in count) count[r.status]++;
const n = (s) => count[s];
// JSON.stringify escapes control characters below 0x20 but passes DEL and C1 (0x7f-0x9f) through; names from the disk can
// carry them, so they are escaped too, as the text output does
if (json) console.log(JSON.stringify({ tool: 'wardlatch', version: VERSION, incidents: chosen.map((i) => ({ id: i.id, title: i.title, advisory: i.advisory })), results: all }, null, 1)
  .replace(/[\u007f-\u009f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`));
else {
  console.log(`\n${count.SAFE} safe · ${n('EXPOSED')} exposed · ${n('UNKNOWN')} could not be tested${n('REVIEW') ? ` · ${n('REVIEW')} to review` : ''}`);
  const trust = chosen.find((i) => i.type === 'trust');
  if (trust) console.log(c('2', `Not covered here: ${trust.notCovered}`));
  console.log(c('2', 'Wardlatch, a free tool from Deimos AI LLC · https://www.deimoscore.com/wardlatch/'));
}
process.exitCode = n('EXPOSED') ? 1 : n('UNKNOWN') ? 2 : 0;   // REVIEW lines inform; they don't fail a pipeline. exitCode, not exit(): long output must finish writing
