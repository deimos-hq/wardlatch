// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { join, basename, dirname, isAbsolute } from 'node:path';
import { cmp } from './binaries.mjs';
import { readCapped, listDir, pathState, createdAt, isSystemFolder, realPath } from './files.mjs';
import { safe } from './report.mjs';

/** Whether `d` is a WordPress core folder (the one rule, for the search and for pluginDirs()). */
const isCore = (d) => pathState(join(d, 'wp-includes', 'version.php')) === 'file';

// wp-config.php can move the content or plugins folder: define('WP_CONTENT_DIR', ...) / define('WP_PLUGIN_DIR', ...).
// Read line by line (a bounded pattern on lines of at most 2,000 characters), skipping commented-out lines.
const DEFINE = /^\s*define\s*\(\s*['"](WP_CONTENT_DIR|WP_PLUGIN_DIR)['"]\s*,\s*(.{1,400}?)\s*\)\s*;/;
/** A define's value as a folder, for the forms sites use: an absolute 'path', __DIR__ . '/x', dirname(__FILE__) . '/x',
 *  ABSPATH . 'x'. null for anything else (a constant, a function call): it can't be followed. */
function definedPath(expr, cfgDir, core) {
  let m;
  if ((m = /^['"]([^'"]+)['"]$/.exec(expr))) return isAbsolute(m[1]) ? m[1] : null;
  if ((m = /^(?:__DIR__|dirname\(\s*__FILE__\s*\))\s*\.\s*['"]([^'"]*)['"]$/.exec(expr))) return join(cfgDir, m[1]);
  if ((m = /^ABSPATH\s*\.\s*['"]([^'"]*)['"]$/.exec(expr))) return join(core, m[1]);
  return null;
}

/**
 * Every plugins folder a WordPress core folder can be using → { dirs, unfollowed }. Each candidate that exists is
 * checked, not only the first (a core that still holds its bundled wp-content beside the live one read SAFE about the
 * wrong plugins up to 558eaef):
 * - wp-content beside the core, as WordPress ships;
 * - wp-content one level up (WordPress in its own directory);
 * - Bedrock's app/ one level up (core in web/wp, plugins in web/app/plugins);
 * - the folders WP_CONTENT_DIR and WP_PLUGIN_DIR name in a wp-config.php (in the core or one level up, where WordPress
 *   looks);
 * where "one level up" counts only when that folder is not a WordPress core itself.
 * A define whose value can't be followed is in `unfollowed` (UNKNOWN). Up to b03e7be only the first place was looked
 * in, and a Bedrock site with a compromised plugin read "no WordPress installs found", SAFE.
 */
export function pluginDirs(core) {
  // one level up only when that folder isn't a WordPress install itself (as WordPress decides for wp-config.php): a blog
  // in public_html/blog doesn't use public_html's plugins
  const up = isCore(dirname(core)) ? null : dirname(core);
  const content = [join(core, 'wp-content'), ...(up ? [join(up, 'wp-content')] : [])].filter((c) => pathState(c) === 'dir');
  if (up && pathState(join(up, 'app', 'plugins')) === 'dir') content.push(join(up, 'app'));
  const plugins = content.map((c) => join(c, 'plugins')), unfollowed = [];
  for (const cfg of [join(core, 'wp-config.php'), ...(up ? [join(up, 'wp-config.php')] : [])]) {
    const text = readCapped(cfg, 1e6)?.toString('utf8');
    if (!text) continue;
    for (const line of text.split('\n')) {
      if (line.length > 2000 || /^\s*(\/\/|#|\*|\/\*)/.test(line)) continue;
      const m = DEFINE.exec(line);
      if (!m) continue;
      const dir = definedPath(m[2].trim(), dirname(cfg), core);
      if (!dir) { unfollowed.push(`${cfg} sets ${m[1]} to ${m[2].trim().slice(0, 80)}, which Wardlatch can't follow`); continue; }
      plugins.push(m[1] === 'WP_CONTENT_DIR' ? join(dir, 'plugins') : dir);
      if (m[1] === 'WP_CONTENT_DIR' && pathState(dir) === 'dir') content.push(dir);
    }
  }
  // one folder reached two ways is checked once
  const seen = new Set(), dirs = [];
  for (const d of plugins) { const real = realPath(d) ?? d; if (!seen.has(real)) { seen.add(real); dirs.push(d); } }
  return { dirs, unfollowed, found: content.length > 0 || unfollowed.length > 0 || dirs.some((d) => pathState(d) === 'dir') };
}

/** WordPress installs under `roots` (their core folders). A folder that can't be opened goes into `denied` (when given),
 *  except a dot-folder below a root (www-data's .ssh under /var/www), which goes into `privateDot`: private by its place,
 *  listed for review whoever owns it. Dot-folders are searched like any other (a staging copy in .staging is a site). A
 *  core with no content or plugins folder in any place pluginDirs() knows goes into `coreOnly`: a site whose plugins
 *  weren't found, UNKNOWN. The search goes on inside a site (a blog in public_html/blog is a site of its own; up to
 *  558eaef the search stopped at the first one), except into the core's own wp-admin, wp-includes and wp-content. */
export function wordpressUnder(roots, maxDepth = 5, denied, privateDot = denied, coreOnly) {
  const out = [];
  const walk = (d, depth, isRoot) => {
    if (depth < 0) return;
    const core = isCore(d);
    if (core) { if (pluginDirs(d).found) out.push(d); else coreOnly?.push(d); }
    const l = listDir(d);
    if (l.denied) { (isRoot || !basename(d).startsWith('.') ? denied : privateDot)?.push(d); return; }
    for (const e of l.entries ?? []) {
      if (!e.isDirectory() || ['node_modules', '.git', '.venv'].includes(e.name) || isSystemFolder(e.name, d)) continue;
      if (core && ['wp-admin', 'wp-includes', 'wp-content'].includes(e.name)) continue;
      walk(join(d, e.name), depth - 1, false);
    }
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
