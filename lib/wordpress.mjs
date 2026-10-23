// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { join, basename, dirname, isAbsolute } from 'node:path';
import { cmp } from './binaries.mjs';
import { readCapped, listDir, pathState, createdAt, isSystemFolder, realPath } from './files.mjs';
import { safe } from './report.mjs';

/** PHP source with its comments (line comments and block comments) blanked, strings kept: a commented-out define is not
 *  a define. */
function phpCode(text) {
  let out = '', i = 0, q = '';
  while (i < text.length) {
    const ch = text[i], nx = text[i + 1];
    if (q) { out += ch; if (ch === '\\') { out += nx ?? ''; i += 2; continue; } if (ch === q) q = ''; i++; continue; }
    if (ch === '"' || ch === "'") { q = ch; out += ch; i++; continue; }
    if ((ch === '/' && nx === '/') || ch === '#') { const e = text.indexOf('\n', i); i = e < 0 ? text.length : e; out += ' '; continue; }
    if (ch === '/' && nx === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? text.length : e + 2; out += ' '; continue; }
    out += ch; i++;
  }
  return out;
}

// define('WP_CONTENT_DIR' | 'WP_PLUGIN_DIR', <value>); anywhere in the code (on any line, in any case, inside an if),
// with a bounded value
const DEFINE = /\bdefine\s*\(\s*(['"])(WP_CONTENT_DIR|WP_PLUGIN_DIR)\1\s*,\s*([^;]{1,400}?)\s*\)\s*;/gi;
/** A define's value as a folder, for the forms sites use: an absolute 'path', __DIR__ . '/x', dirname(__FILE__) . '/x',
 *  ABSPATH . 'x'. null for anything else (a constant, getenv(), dirname(__DIR__)): it can't be followed. */
function definedPath(expr, cfgDir, core) {
  let m;
  if ((m = /^['"]([^'"]+)['"]$/.exec(expr))) return isAbsolute(m[1]) ? m[1] : null;
  if ((m = /^(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*['"]([^'"]*)['"]$/i.exec(expr))) return join(cfgDir, m[1]);
  if ((m = /^ABSPATH\s*\.\s*['"]([^'"]*)['"]$/.exec(expr))) return join(core, m[1]);
  return null;
}

/**
 * Where a config file moves the content or plugins folder → { content: [folders], plugins: [folders], unfollowed:
 * [reasons] }. A positive rule: every mention of WP_CONTENT_DIR or WP_PLUGIN_DIR in its code is either a define this
 * follows or a `defined(...)` test; anything else, or a file there that can't be read, is unfollowed (UNKNOWN). Up to
 * 66621a5 a define in another form (on the <?php line, over several lines, inside an if, in capitals) or a wp-config.php
 * this user can't read was taken for "no move", SAFE about a leftover folder.
 */
function movesIn(cfg, core) {
  const res = { content: [], plugins: [], unfollowed: [] };
  const st = pathState(cfg);
  if (st === 'gone') return res;
  const text = st === 'file' ? readCapped(cfg, 1e6)?.toString('utf8') : null;
  if (text == null) { res.unfollowed.push(`${cfg} could not be read, so a moved plugins folder can't be ruled out (run Wardlatch with sudo)`); return res; }
  const code = phpCode(text), used = [];
  for (const m of code.matchAll(DEFINE)) {
    const dir = definedPath(m[3].trim(), dirname(cfg), core);
    if (!dir) { res.unfollowed.push(`${cfg} sets ${m[2].toUpperCase()} to ${m[3].trim().slice(0, 80)}, which Wardlatch can't follow`); continue; }
    used.push([m.index, m.index + m[0].length]);
    if (/content/i.test(m[2])) { res.content.push(dir); res.plugins.push(join(dir, 'plugins')); } else res.plugins.push(dir);
  }
  for (const m of code.matchAll(/WP_(?:CONTENT|PLUGIN)_DIR/gi)) {
    if (used.some(([f, t]) => m.index >= f && m.index < t) || /\bdefined\s*\(\s*['"]$/i.test(code.slice(Math.max(0, m.index - 40), m.index))) continue;
    if (!res.unfollowed.length) res.unfollowed.push(`${cfg} uses ${m[0].toUpperCase()} in a way Wardlatch can't follow`);
  }
  return res;
}

/** Whether `d` is a WordPress core folder (the one rule, for the search and for pluginDirs()). */
const isCore = (d) => pathState(join(d, 'wp-includes', 'version.php')) === 'file';

/**
 * Every plugins folder a WordPress core folder can be using, and leftover ones beside it (a plugin's files left on a web
 * server can still be reached directly) → { dirs, unfollowed, found }:
 * - wp-content beside the core, as WordPress ships;
 * - wp-content one level up (WordPress in its own directory) and Bedrock's app/ one level up (core in web/wp, plugins in
 *   web/app/plugins), where "one level up" counts only when that folder is not a WordPress core itself (a blog in
 *   public_html/blog doesn't use public_html's plugins);
 * - what WP_CONTENT_DIR and WP_PLUGIN_DIR are set to in wp-config.php (in the core, or one level up, where WordPress
 *   looks) and Bedrock's CONTENT_DIR in config/application.php;
 * every one that exists, not only the first (a core still holding its bundled wp-content beside the live one read SAFE
 * about the wrong plugins up to 558eaef). What can't be followed is in `unfollowed` (UNKNOWN). Up to b03e7be only the
 * first place was looked in, and a Bedrock site with a compromised plugin read "no WordPress installs found", SAFE.
 */
export function pluginDirs(core) {
  const up = isCore(dirname(core)) ? null : dirname(core);
  const content = [join(core, 'wp-content'), ...(up ? [join(up, 'wp-content'), join(up, 'app')] : [])];
  const plugins = content.map((c) => join(c, 'plugins')), unfollowed = [];
  for (const cfg of [join(core, 'wp-config.php'), ...(up ? [join(up, 'wp-config.php')] : [])]) {
    const r = movesIn(cfg, core);
    content.push(...r.content); plugins.push(...r.plugins); unfollowed.push(...r.unfollowed);
  }
  // Bedrock: config/application.php beside the web root sets CONTENT_DIR (under the web root, '/app' by default)
  const bedrock = up ? join(dirname(up), 'config', 'application.php') : null;
  if (bedrock && pathState(bedrock) !== 'gone') {
    const code = pathState(bedrock) === 'file' ? phpCode(readCapped(bedrock, 1e6)?.toString('utf8') ?? '') : null;
    const m = code && /Config::define\s*\(\s*(['"])CONTENT_DIR\1\s*,\s*(['"])(\/[^'"]*)\2\s*\)/.exec(code);
    if (m) { content.push(join(up, m[3])); plugins.push(join(up, m[3], 'plugins')); }
    else if (code === null || /CONTENT_DIR/.test(code)) unfollowed.push(`${bedrock} sets the content folder in a way Wardlatch can't follow`);
  }
  // the ones that are there (or can't be opened, which checkSite() reports); one folder reached two ways is checked once
  const seen = new Set(), dirs = [];
  for (const d of plugins) {
    if (pathState(d) === 'gone') continue;
    const real = realPath(d) ?? d;
    if (!seen.has(real)) { seen.add(real); dirs.push(d); }
  }
  return { dirs, unfollowed, found: content.some((c) => pathState(c) === 'dir') || dirs.length > 0 || unfollowed.length > 0 };
}

/** WordPress installs under `roots` (their core folders). A folder that can't be opened goes into `denied` (when given),
 *  except a dot-folder below a root (www-data's .ssh under /var/www), which goes into `privateDot`: private by its place,
 *  listed for review whoever owns it. Dot-folders are searched like any other (a staging copy in .staging is a site). A
 *  core with no content or plugins folder in any place pluginDirs() knows goes into `coreOnly`: a site whose plugins
 *  weren't found, UNKNOWN. The search goes on inside a site (a blog in public_html/blog, or a staging copy inside
 *  wp-content, is a site of its own; up to 558eaef the search stopped at the first one). */
export function wordpressUnder(roots, maxDepth = 5, denied, privateDot = denied, coreOnly) {
  const out = [];
  const walk = (d, depth, isRoot) => {
    if (depth < 0) return;
    if (isCore(d)) { if (pluginDirs(d).found) out.push(d); else coreOnly?.push(d); }
    const l = listDir(d);
    if (l.denied) { (isRoot || !basename(d).startsWith('.') ? denied : privateDot)?.push(d); return; }
    for (const e of l.entries ?? []) if (e.isDirectory() && !['node_modules', '.git', '.venv'].includes(e.name) && !isSystemFolder(e.name, d)) walk(join(d, e.name), depth - 1, false);
  };
  for (const r of roots) walk(r, maxDepth, true);
  return out;
}

/** The Version: header of a plugin's main file. */
export function pluginVersion(dir, mainFile) {
  return (readCapped(join(dir, mainFile), 2e6)?.toString('utf8').match(/^\s*\*?\s*Version:\s*([\d.]+)/mi) ?? [])[1] ?? '';
}

/** Files under `dir` (.php, .js, .inc) containing `needle`, depth- and count-capped → { hits, skipped }. Folders that
 *  can't be opened go into `denied`; `skipped` says what a cap left unsearched (27cdfbd stopped silently: a backdoor in
 *  a file over 2 MB, past 4,000 files or 12 folders deep read as SAFE). */
function grepDir(dir, needle, denied, maxFiles = 4000, maxDepth = 12, maxBytes = 2e6) {
  const hits = [], big = []; let n = 0, deep = 0, more = false;
  const walk = (d, depth) => {
    const l = listDir(d);
    if (l.denied) { denied.push(d); return; }
    for (const e of l.entries ?? []) {
      const p = join(d, e.name);
      if (e.isDirectory()) { if (depth > 0) walk(p, depth - 1); else deep++; }
      else if (/\.(php|js|inc)$/i.test(e.name)) {
        if (n >= maxFiles) { more = true; return; }
        n++;
        const buf = readCapped(p, maxBytes);
        if (!buf) big.push(p); else if (buf.toString('utf8').includes(needle)) hits.push(p);
      }
    }
  };
  walk(dir, maxDepth);
  const skipped = [];
  if (big.length) skipped.push(`${big.length} file${big.length === 1 ? '' : 's'} over ${maxBytes / 1e6} MB or unreadable (${big.slice(0, 3).map((f) => f.slice(dir.length + 1)).join(', ')}${big.length > 3 ? ', …' : ''})`);
  if (deep) skipped.push(`${deep} folder${deep === 1 ? '' : 's'} deeper than ${maxDepth} levels`);
  if (more) skipped.push(`files past the first ${maxFiles}`);
  return { hits, skipped };
}

/**
 * rules: [{ plugin, mainFile, bad?: [versions], fixedIn?, fixedInMajor?: { "2": "2.26.13" }, indicator?, fix }]
 * → findings: { site, status, what, reason, fix }
 */
export function checkSite(site, rules, addedSince) {
  const { dirs, unfollowed } = pluginDirs(site); const out = [];
  for (const reason of unfollowed) out.push({ site, status: 'UNKNOWN', what: 'plugins folder', reason: `${reason}, so the plugins there were not checked` });
  // with more than one plugins folder, each row says which one it is about
  for (const plugins of dirs) out.push(...checkPlugins(site, plugins, rules, addedSince, dirs.length > 1 ? plugins : undefined));
  return out;
}

function checkPlugins(site, plugins, rules, addedSince, which) {
  const out = [];
  for (const r of rules) {
    const dir = join(plugins, r.plugin);
    const st = pathState(dir);
    if (st === 'denied') { out.push({ site, status: 'UNKNOWN', what: r.plugin, reason: 'the plugins folder could not be opened, so this plugin was not checked: run Wardlatch with sudo' }); continue; }
    if (st === 'gone') continue;
    const v = pluginVersion(dir, r.mainFile);
    const fixFor = r.fixedInMajor?.[String(v).split('.')[0]] ?? r.fixedIn;
    if (r.bad?.includes(v)) out.push({ site, status: 'EXPOSED', what: `${r.plugin} ${v}`, reason: `version ${v} is the compromised release`, fix: r.fix });
    else if (fixFor && v && cmp(v, fixFor) < 0) out.push({ site, status: 'EXPOSED', what: `${r.plugin} ${v}`, reason: `fixed in ${fixFor}`, fix: r.fix });
    // A version that can't be read is not a safe one: without it, the check can't have seen a bad release.
    else if (!v) out.push({ site, status: 'UNKNOWN', what: `${r.plugin} (version unreadable)`, reason: `no Version: header could be read in ${r.mainFile}, so the version could not be checked` });
    else out.push({ site, ...safe([join(dir, r.mainFile)]), what: `${r.plugin} ${v}` });
    const denied = [];
    if (r.indicator) {
      const { hits, skipped } = grepDir(dir, r.indicator, denied);
      for (const f of hits) out.push({ site, status: 'EXPOSED', what: `${r.plugin}: ${f.slice(dir.length + 1)}`, reason: `contains the attack's indicator "${r.indicator}"`, fix: r.fix });
      if (skipped.length) out.push({ site, status: 'UNKNOWN', what: `${r.plugin}: indicator search`, reason: `not searched for "${r.indicator}": ${skipped.join('; ')}` });
    }
    for (const d of denied) out.push({ site, status: 'UNKNOWN', what: `${r.plugin}: ${d.slice(dir.length + 1) || '.'}`, reason: 'this folder could not be opened, so the indicator was not searched for in it: run Wardlatch with sudo' });
  }
  if (addedSince) {
    const since = Date.parse(addedSince);
    const l = listDir(plugins);
    if (l.denied) out.push({ site, status: 'UNKNOWN', what: 'plugins folder', reason: 'could not be opened, so new plugin folders were not looked for: run Wardlatch with sudo' });
    for (const e of l.entries ?? []) {
      if (!e.isDirectory()) continue;
      const t = createdAt(join(plugins, e.name));
      if (t !== null && t >= since) out.push({ site, status: 'REVIEW', what: `plugin folder ${e.name}`, reason: `added ${new Date(t).toISOString().slice(0, 10)}` });
    }
  }
  return which ? out.map((r) => ({ ...r, plugins: which })) : out;
}
