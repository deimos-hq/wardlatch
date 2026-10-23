// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { join, basename, dirname } from 'node:path';
import { cmp } from './binaries.mjs';
import { readCapped, readHead, listDir, pathState, createdAt, isSystemFolder, realPath } from './files.mjs';
import { safe } from './report.mjs';

/** Whether `d` is a WordPress core folder (the one rule, for the search and for pluginDirs()). */
const isCore = (d) => pathState(join(d, 'wp-includes', 'version.php')) === 'file';

// Wardlatch doesn't read PHP (owner, 23 Oct 2026: copying PHP's rules missed forms in four checks in a row). A config
// file that names one of the settings that move the content or plugins folder, anywhere in its text (a define, a
// comment, a string), may move it: UNKNOWN, as is one that can't be read.
const MOVES = /WP_CONTENT_DIR|WP_PLUGIN_DIR/i;
// in Bedrock's config, its own CONTENT_DIR moves the folder too
const BEDROCK_MOVES = /CONTENT_DIR|WP_PLUGIN_DIR/i;
// Bedrock's own lines that set its default content folder, web/app (any other mention of CONTENT_DIR may move it)
const BEDROCK_STOCK = [
  /^\s*(?:<\?php\s+)?(?:Config::)?define\(\s*(['"])CONTENT_DIR\1\s*,\s*(['"])\/app\2\s*\)\s*;\s*$/i,
  /^\s*(?:<\?php\s+)?(?:Config::)?define\(\s*(['"])WP_CONTENT_DIR\1\s*,\s*\$webroot_dir\s*\.\s*(?:Config::get\(\s*(['"])CONTENT_DIR\2\s*\)|CONTENT_DIR)\s*\)\s*;\s*$/i,
  /^\s*(?:<\?php\s+)?(?:Config::)?define\(\s*(['"])WP_CONTENT_URL\1\s*,(?![^;]*(?:WP_CONTENT_DIR|WP_PLUGIN_DIR))[^;]{0,200}\)\s*;\s*$/i,
];
/** The doubt a file or folder leaves when it can't be read (`why`). */
const unread = (path, why) => `${path} ${why}, so a moved plugins folder can't be ruled out`;
const CANT_OPEN = 'could not be opened (run Wardlatch with sudo)';
/** Why `file` leaves where the plugins are in doubt (it can't be read, or `moves(text)` says it may move them), or
 *  null. A file that isn't there leaves no doubt. */
function doubtIn(file, moves) {
  const st = pathState(file);
  if (st === 'gone') return null;
  const text = st === 'file' ? readCapped(file, 1e6)?.toString('utf8') : null;
  if (text == null) return unread(file, st === 'denied' || (st === 'file' && !readHead(file, 1)) ? CANT_OPEN : st === 'file' ? 'is over 1 MB, which is not read' : 'is not a regular file');
  return moves(text) ? `${file} names a setting that moves the plugins folder, and Wardlatch doesn't read PHP, so where this site's plugins are can't be told` : null;
}

/**
 * Every plugins folder on disk a WordPress core folder can be using, and leftover ones beside it (a plugin's files left
 * on a web server can still be reached directly) → { dirs, unfollowed, found }:
 * - wp-content/plugins beside the core, as WordPress ships;
 * - wp-content/plugins one level up (WordPress in its own directory) and Bedrock's app/plugins one level up (core in
 *   web/wp), where "one level up" counts only when that folder is not a WordPress core itself (a blog in public_html/blog
 *   doesn't use public_html's plugins);
 * each one that is there, not only the first (a core still holding its bundled wp-content beside the live one read SAFE
 * about the wrong plugins up to 558eaef; up to b03e7be a Bedrock site read "no WordPress installs found", SAFE).
 * `unfollowed`: why the plugins may be elsewhere (doubtIn()): the wp-config.php WordPress reads (wp-load.php: the
 * core's own, or only when there is none, the one a level up unless that folder holds a wp-settings.php of its own), and
 * Bedrock's config/application.php (past its stock lines) and config/environments/*.php.
 */
export function pluginDirs(core) {
  const up = isCore(dirname(core)) ? null : dirname(core);
  // Bedrock's app/ counts when it holds plugins/ or Bedrock's config/application.php is there (an app/ folder of
  // another program beside the core is not one)
  const bedrockApp = up && (pathState(join(up, 'app', 'plugins')) !== 'gone' || pathState(join(dirname(up), 'config', 'application.php')) !== 'gone');
  const content = [join(core, 'wp-content'), ...(up ? [join(up, 'wp-content')] : []), ...(bedrockApp ? [join(up, 'app')] : [])];
  const own = join(core, 'wp-config.php');
  const configs = pathState(own) !== 'gone' ? [own] : up && pathState(join(up, 'wp-settings.php')) === 'gone' ? [join(up, 'wp-config.php')] : [];
  const unfollowed = configs.map((cfg) => doubtIn(cfg, (t) => MOVES.test(t)));
  if (up) {
    const conf = join(dirname(up), 'config');
    unfollowed.push(doubtIn(join(conf, 'application.php'), (t) => t.split('\n').some((l) => !BEDROCK_STOCK.some((re) => re.test(l)) && BEDROCK_MOVES.test(l))));
    // its environment files; a folder of them that can't be opened or listed leaves the same doubt
    const envDir = join(conf, 'environments'), envState = pathState(envDir), envList = envState === 'dir' ? listDir(envDir) : null;
    if (envState === 'denied' || envList?.denied) unfollowed.push(unread(envDir, CANT_OPEN));
    for (const e of envList?.entries ?? []) if (e.name.endsWith('.php')) unfollowed.push(doubtIn(join(envDir, e.name), (t) => BEDROCK_MOVES.test(t)));
  }
  // the plugins folders that are there (or can't be opened, which checkSite() reports); one reached two ways once
  const seen = new Set(), dirs = [];
  for (const d of content.map((c) => join(c, 'plugins'))) {
    if (pathState(d) === 'gone') continue;
    const real = realPath(d) ?? d;
    if (!seen.has(real)) { seen.add(real); dirs.push(d); }
  }
  const reasons = unfollowed.filter(Boolean);
  return { dirs, unfollowed: reasons, found: content.some((c) => pathState(c) === 'dir') || reasons.length > 0 };
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
  for (const reason of unfollowed) out.push({ site, status: 'UNKNOWN', what: 'plugins folder', reason });
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
