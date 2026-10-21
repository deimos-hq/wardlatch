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

const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const VERSION = JSON.parse(readFileSync(join(LIB, '..', 'package.json'), 'utf8')).version;
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

if (flag('-h') || flag('--help')) {
  console.log(`wardlatch ${VERSION}: does the wrong key still turn?

  npx wardlatch                    check this machine against the latest incident
  npx wardlatch --paths ~/code     also look for Python virtual environments under these folders (repeatable)
  npx wardlatch --incident <id>    a specific incident (--list shows them)
  npx wardlatch --json             machine-readable output

Exit code: 0 all safe · 1 something is exposed · 2 something could not be tested.
Runs locally. Sends nothing anywhere except TLS handshakes to the incident's public test hosts. Changes nothing.`);
  process.exit(0);
}
const incidents = readdirSync(join(LIB, 'incidents')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(LIB, 'incidents', f), 'utf8'))).sort((a, b) => b.date.localeCompare(a.date));
if (flag('--list')) { for (const i of incidents) console.log(`${i.id}  ${i.date}  ${i.title}`); process.exit(0); }
const inc = val('--incident') ? incidents.find((i) => i.id === val('--incident')) : incidents[0];
if (!inc) { console.error(`unknown incident "${val('--incident')}" (try --list)`); process.exit(2); }

const json = flag('--json');
const roots = []; args.forEach((a, i) => { if (a === '--paths') roots.push(args[i + 1].replace(/^~/, homedir())); });
if (!roots.length) for (const d of ['Development', 'code', 'src', 'projects', 'Projects', 'dev', 'work']) roots.push(join(homedir(), d));

const tty = process.stdout.isTTY && !json;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const STATUS = { SAFE: c('32', 'SAFE   '), EXPOSED: c('31;1', 'EXPOSED'), UNKNOWN: c('33', 'UNKNOWN') };
const short = (p) => p.replace(homedir(), '~');
const fixFor = (rt) => {
  const os = platform();
  return inc.fixes[`${rt.kind}:${rt.bin}:${os}`] ?? inc.fixes[`${rt.kind}:${os}`] ?? inc.fixes[rt.kind];
};

if (!json) {
  console.log(`${c('1', 'Wardlatch')} ${VERSION} · ${inc.title} (${inc.date})`);
  console.log(c('2', `Asks each runtime on this machine to connect to ${inc.canaries.length} test hosts signed with the compromised keys.`));
  console.log(c('2', 'Runs locally; sends nothing except TLS handshakes to those hosts; changes nothing.\n'));
}
const canaries = await Promise.all(inc.canaries.map(async (id) => { const host = inc.canaryHost.replace('{id}', id); return { id, host, url: `https://${host}/`, up: await reachable(host) }; }));
const runtimes = discover({ roots });
const rootsPem = join(LIB, 'incidents', inc.rootsPem);
const results = [];
for (const rt of runtimes) {
  const r = await check(rt, canaries, { rootsPem });
  const row = { ...rt, ...r, fix: r.status === 'EXPOSED' ? fixFor(rt) : undefined };
  results.push(row);
  if (!json) {
    const what = rt.kind === 'python-certifi' ? `certifi ${rt.certifi}  ${short(rt.env)}` : `${rt.kind} ${rt.version}  ${short(rt.bin)}${rt.env ? `  (${short(rt.env)})` : ''}`;
    console.log(`${STATUS[r.status]}  ${what}${r.status === 'EXPOSED' ? c('31', `  trusts ${r.trusted.length}/${r.tested}`) : ''}`);
    if (r.status === 'UNKNOWN') console.log(c('33', `         ${r.reason}`));
    if (row.fix) console.log(c('2', `         fix: ${row.fix}`));
  }
}
const n = (s) => results.filter((r) => r.status === s).length;
const down = canaries.filter((x) => !x.up).length;
if (json) console.log(JSON.stringify({ tool: 'wardlatch', version: VERSION, incident: { id: inc.id, title: inc.title, advisory: inc.advisory }, testHostsDown: down, results }, null, 1));
else {
  console.log(`\n${n('SAFE')} safe · ${n('EXPOSED')} exposed · ${n('UNKNOWN')} could not be tested${down ? ` · ${down} of ${canaries.length} test hosts did not answer` : ''}`);
  console.log(c('2', `Not covered here: ${inc.notCovered}`));
  console.log(c('2', `Advisory: ${inc.advisory} · Wardlatch, a free tool from Deimos AI LLC.`));
}
process.exit(n('EXPOSED') ? 1 : n('UNKNOWN') ? 2 : 0);
