// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { join, basename, dirname, isAbsolute } from 'node:path';
import { cmp } from './binaries.mjs';
import { readCapped, readHead, listDir, pathState, createdAt, isSystemFolder, realPath } from './files.mjs';
import { safe } from './report.mjs';

/** PHP source with its comments blanked (a line comment ends at the line's end or at ?>, as PHP ends it), and the text
 *  of heredocs and nowdocs blanked too; quoted strings kept. A commented-out define is not a define, and neither is one
 *  inside a heredoc. */
function phpCode(text) {
  let out = '', i = 0, q = '';
  while (i < text.length) {
    const ch = text[i], nx = text[i + 1];
    if (q) { out += ch; if (ch === '\\') { out += nx ?? ''; i += 2; continue; } if (ch === q) q = ''; i++; continue; }
    if (ch === '"' || ch === "'") { q = ch; out += ch; i++; continue; }
    if ((ch === '/' && nx === '/') || ch === '#') {
      const nl = text.indexOf('\n', i), close = text.indexOf('?>', i);
      i = [nl, close].filter((x) => x >= 0).reduce((x, y) => Math.min(x, y), text.length); out += ' '; continue;
    }
    if (ch === '/' && nx === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? text.length : e + 2; out += ' '; continue; }
    const doc = ch === '<' ? /^<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1\r?\n/.exec(text.slice(i, i + 80)) : null;
    if (doc) {
      // ends at a line holding its name (indented or not) followed by something that can't be part of a name
      const end = new RegExp(`\\n[ \\t]*${doc[2]}(?![A-Za-z0-9_])`, 'g'); end.lastIndex = i + doc[0].length - 1;
      const e = end.exec(text); i = e ? e.index + e[0].length : text.length; out += ' ""'; continue;
    }
    out += ch; i++;
  }
  return out;
}

// A define of WP_CONTENT_DIR or WP_PLUGIN_DIR: define('NAME', <value>); in any case, with a bounded value
const DEFINE = /^define\s*\(\s*(['"])(WP_CONTENT_DIR|WP_PLUGIN_DIR)\1\s*,\s*([^;]{1,400}?)\s*\)\s*;?$/i;
/** A define's value as a folder, for the forms sites use: an absolute 'path', __DIR__ . '/x', dirname(__FILE__) . '/x',
 *  ABSPATH . 'x'. null for anything else (a constant, getenv(), dirname(__DIR__), a "double-quoted $variable"): it can't
 *  be followed. */
function definedPath(expr, cfgDir, core) {
  const lit = (q, v) => (q === '"' && v.includes('$') ? null : v);
  let m;
  if ((m = /^(['"])([^'"]+)\1$/.exec(expr))) { const v = lit(m[1], m[2]); return v && isAbsolute(v) ? v : null; }
  if ((m = /^(?:__DIR__|dirname\s*\(\s*__FILE__\s*\))\s*\.\s*(['"])([^'"]*)\1$/i.exec(expr))) { const v = lit(m[1], m[2]); return v === null ? null : join(cfgDir, v); }
  if ((m = /^ABSPATH\s*\.\s*(['"])([^'"]*)\1$/.exec(expr))) { const v = lit(m[1], m[2]); return v === null ? null : join(core, v); }
  return null;
}

/**
 * Where a config file moves the content or plugins folder → { content: [folders], plugins: [folders], unfollowed:
 * [reasons] }. A positive rule over what can move them: every define(...) call whose arguments name WP_CONTENT_DIR or
 * WP_PLUGIN_DIR is one this follows, or it is unfollowed (UNKNOWN); so is a `const WP_CONTENT_DIR = ...`, and a file
 * there that can't be read. A plain use of the constant moves nothing. Up to 66621a5 a define in another form (on the
 * <?php line, over several lines, inside an if, in capitals) or a wp-config.php this user can't read was taken for "no
 * move", SAFE about a leftover folder.
 */
function movesIn(cfg, core) {
  const res = { content: [], plugins: [], unfollowed: [] };
  const st = pathState(cfg);
  if (st === 'gone') return res;
  const text = st === 'file' ? readCapped(cfg, 1e6)?.toString('utf8') : null;
  if (text == null) {
    const why = st === 'denied' || (st === 'file' && !readHead(cfg, 1)) ? 'could not be opened (run Wardlatch with sudo)' : st === 'file' ? 'is over 1 MB, which is not read' : 'is not a regular file';
    res.unfollowed.push(`${cfg} ${why}, so a moved plugins folder can't be ruled out`); return res;
  }
  const code = phpCode(text);
  for (const d of code.matchAll(/\bdefine\s*\(/gi)) {
    const end = code.indexOf(';', d.index), call = code.slice(d.index, end < 0 ? d.index + 600 : Math.min(end + 1, d.index + 600));
    if (!/WP_(?:CONTENT|PLUGIN)_DIR/i.test(call)) continue;
    const m = DEFINE.exec(call.trim());
    const dir = m && definedPath(m[3].trim(), dirname(cfg), core);
    if (!dir) { res.unfollowed.push(`${cfg} sets ${m ? m[2].toUpperCase() : 'WP_CONTENT_DIR or WP_PLUGIN_DIR'} with ${call.trim().slice(0, 100)}, which Wardlatch can't follow, so the plugins there were not checked`); continue; }
    if (/content/i.test(m[2])) { res.content.push(dir); res.plugins.push(join(dir, 'plugins')); } else res.plugins.push(dir);
  }
  if (/\bconst\s+WP_(?:CONTENT|PLUGIN)_DIR\b/i.test(code)) res.unfollowed.push(`${cfg} sets WP_CONTENT_DIR or WP_PLUGIN_DIR with const, which Wardlatch doesn't follow, so the plugins there were not checked`);
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
  // the wp-config.php WordPress reads (wp-load.php): the core's own; only when there is none, the one a level up, unless
  // that folder holds a wp-settings.php of its own
  const own = join(core, 'wp-config.php');
  const configs = pathState(own) !== 'gone' ? [own] : up && pathState(join(up, 'wp-settings.php')) === 'gone' ? [join(up, 'wp-config.php')] : [];
  for (const cfg of configs) {
    const r = movesIn(cfg, core);
    content.push(...r.content); plugins.push(...r.plugins); unfollowed.push(...r.unfollowed);
  }
  // Bedrock: config/application.php beside the web root sets CONTENT_DIR (under the web root, '/app' by default); one it
  // sets in another way (env('CONTENT_DIR')) is unfollowed
  const bedrock = up ? join(dirname(up), 'config', 'application.php') : null;
  if (bedrock && pathState(bedrock) !== 'gone') {
    const code = pathState(bedrock) === 'file' ? phpCode(readCapped(bedrock, 1e6)?.toString('utf8') ?? '') : null;
    // Config::define (Bedrock 1.9 and later) or a plain define (earlier Bedrock)
    const m = code && /\b(?:Config::)?define\s*\(\s*(['"])CONTENT_DIR\1\s*,\s*'(\/[^']*)'|\b(?:Config::)?define\s*\(\s*(['"])CONTENT_DIR\3\s*,\s*"(\/[^"$]*)"/i.exec(code);
    const dir = m && (m[2] ?? m[4]);
    if (dir) { content.push(join(up, dir)); plugins.push(join(up, dir, 'plugins')); }
    else if (code === null || /CONTENT_DIR/.test(code)) unfollowed.push(`${bedrock} sets the content folder in a way Wardlatch can't follow, so the plugins there were not checked`);
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
