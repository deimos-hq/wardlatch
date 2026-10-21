// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { cmp } from './binaries.mjs';

export function wordpressUnder(roots, maxDepth = 5) {
  const out = [];
  const walk = (d, depth) => {
    if (depth < 0) return;
    if (existsSync(join(d, 'wp-includes', 'version.php')) && existsSync(join(d, 'wp-content'))) { out.push(d); return; }
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) if (e.isDirectory() && !['node_modules', '.git', '.venv', 'Library'].includes(e.name)) walk(join(d, e.name), depth - 1);
  };
  for (const r of roots) walk(r, maxDepth);
  return out;
}

/** The Version: header of a plugin's main file. */
export function pluginVersion(dir, mainFile) {
  try { return (readFileSync(join(dir, mainFile), 'utf8').match(/^\s*\*?\s*Version:\s*([\d.]+)/mi) ?? [])[1] ?? ''; } catch { return ''; }
}

function grepDir(dir, needle, maxFiles = 4000) {
  const hits = []; let n = 0;
  const walk = (d) => {
    let ents; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (n > maxFiles) return;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(php|js|inc)$/i.test(e.name)) { n++; try { if (statSync(p).size < 2e6 && readFileSync(p, 'utf8').includes(needle)) hits.push(p); } catch { /* skip */ } }
    }
  };
  walk(dir); return hits;
}

/**
 * rules: [{ plugin, mainFile, bad?: [versions], fixedIn?, fixedInMajor?: { "2": "2.26.13" }, indicator?, fix }]
 * → findings: { site, status, what, reason, fix }
 */
export function checkSite(site, rules, addedSince) {
  const plugins = join(site, 'wp-content', 'plugins'); const out = [];
  for (const r of rules) {
    const dir = join(plugins, r.plugin);
    if (!existsSync(dir)) continue;
    const v = pluginVersion(dir, r.mainFile);
    const fixFor = r.fixedInMajor?.[String(v).split('.')[0]] ?? r.fixedIn;
    if (r.bad?.includes(v)) out.push({ site, status: 'EXPOSED', what: `${r.plugin} ${v}`, reason: `version ${v} is the compromised release`, fix: r.fix });
    else if (fixFor && v && cmp(v, fixFor) < 0) out.push({ site, status: 'EXPOSED', what: `${r.plugin} ${v}`, reason: `fixed in ${fixFor}`, fix: r.fix });
    else out.push({ site, status: 'SAFE', what: `${r.plugin} ${v || '(version unreadable)'}` });
    if (r.indicator) for (const f of grepDir(dir, r.indicator)) out.push({ site, status: 'EXPOSED', what: `${r.plugin}: ${f.slice(dir.length + 1)}`, reason: `contains the attack's indicator "${r.indicator}"`, fix: r.fix });
  }
  if (addedSince) {
    const since = Date.parse(addedSince);
    let ents = []; try { ents = readdirSync(plugins, { withFileTypes: true }); } catch { /* none */ }
    for (const e of ents) {
      if (!e.isDirectory()) continue;
      try { const t = statSync(join(plugins, e.name)).birthtimeMs || statSync(join(plugins, e.name)).ctimeMs; if (t >= since) out.push({ site, status: 'REVIEW', what: `plugin folder ${e.name}`, reason: `added ${new Date(t).toISOString().slice(0, 10)}` }); } catch { /* skip */ }
    }
  }
  return out;
}
