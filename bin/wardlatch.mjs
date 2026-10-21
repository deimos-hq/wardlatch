#!/usr/bin/env node
// Wardlatch: does the wrong key still turn? Checks whether the runtimes on this machine still trust a compromised
// certificate authority, by asking each one to connect to public test hosts signed with the compromised keys.
// Runs locally. Sends nothing anywhere except TLS handshakes to those test hosts. Changes nothing.
// A free tool from Deimos AI LLC · Apache-2.0
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { discover } from '../lib/discover.mjs';
import { check, reachable } from '../lib/probe.mjs';
import { checkBinary } from '../lib/binaries.mjs';
import { reposUnder, workflowsAddedSince } from '../lib/workflows.mjs';
import { scanRepo } from '../lib/secrets.mjs';
import { wordpressUnder, checkSite } from '../lib/wordpress.mjs';

const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const VERSION = JSON.parse(readFileSync(join(LIB, '..', 'package.json'), 'utf8')).version;
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

if (flag('-h') || flag('--help')) {
  console.log(`wardlatch ${VERSION}: does the wrong key still turn?

  npx wardlatch                    check this machine against every current incident
  npx wardlatch --paths ~/code     where to look for Python environments, git repositories and WordPress sites (repeatable)
  npx wardlatch --incident <id>    one incident only (--list shows them)
  npx wardlatch --json             machine-readable output

Exit code: 0 all safe · 1 something is exposed · 2 something could not be tested ("review" lines don't change it).
Runs locally. Sends nothing anywhere except TLS handshakes to the incidents' public test hosts. Changes nothing.`);
  process.exit(0);
}
const incidents = readdirSync(join(LIB, 'incidents')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(LIB, 'incidents', f), 'utf8'))).sort((a, b) => b.date.localeCompare(a.date));
if (flag('--list')) { for (const i of incidents) console.log(`${i.id}  ${i.date}  ${i.title}`); process.exit(0); }
const chosen = val('--incident') ? incidents.filter((i) => i.id === val('--incident')) : incidents;
if (!chosen.length) { console.error(`unknown incident "${val('--incident')}" (try --list)`); process.exit(2); }

const json = flag('--json');
const roots = []; args.forEach((a, i) => { if (a === '--paths') roots.push(args[i + 1].replace(/^~/, homedir())); });
if (!roots.length) { for (const d of ['Development', 'code', 'src', 'projects', 'Projects', 'dev', 'work', 'Sites']) roots.push(join(homedir(), d)); roots.push('/var/www'); }

const tty = process.stdout.isTTY && !json;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const STATUS = { SAFE: c('32', 'SAFE   '), EXPOSED: c('31;1', 'EXPOSED'), UNKNOWN: c('33', 'UNKNOWN'), REVIEW: c('33', 'REVIEW ') };
const short = (p) => p.replace(homedir(), '~');
const print = (status, what, extra = '') => { if (!json) console.log(`${STATUS[status]}  ${what}${extra}`); };
const note = (code, text) => { if (!json) console.log(c(code, `         ${text}`)); };
const all = [];

if (!json) {
  console.log(`${c('1', 'Wardlatch')} ${VERSION} · ${chosen.length} incident${chosen.length > 1 ? 's' : ''} · runs locally, sends nothing but test connections, changes nothing`);
}

for (const inc of chosen) {
  if (!json) console.log(`\n${c('1', inc.title)} ${c('2', `(${inc.date})`)}`);
  const results = [];

  if (inc.type === 'trust') {
    if (!json) console.log(c('2', `Asks each runtime to connect to ${inc.canaries.length} test hosts signed with the compromised keys.`));
    const fixFor = (rt) => {
      const os = platform();
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
      if (row.fix) note('2', `fix: ${row.fix}`);
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
    if (r.reason) note(r.status === 'EXPOSED' ? '31' : '33', r.reason);
    if (r.status === 'EXPOSED') note('2', `fix: ${rule.fix}`);
  }
  if (inc.type === 'binaries' && !results.length) print('SAFE', `${inc.binaries.map((b) => b.binary).join(', ')} not installed`);

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
