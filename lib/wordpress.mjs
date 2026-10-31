// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// WordPress plugin incidents (October 2026): find WordPress installs under the given folders and read plugin headers.
// Read-only. It flags known-bad versions and an indicator string, and lists plugin folders added since a date.
import { join, basename, dirname } from 'node:path';
import { cmp } from './binaries.mjs';
import { readCapped, readHead, listDir, pathState, createdAt, isSystemFolder, realPath, fileId, unwalkedLinks, walkedTo, holdsMore, openErrno, refusedOr, gapLists } from './files.mjs';
import { safe } from './report.mjs';

// Folders this walk never enters, by name. Not hidden: every all-clear that rests on this walk names them
// (bin/wardlatch.mjs allClear(), `notSearched`), since `mkdir node_modules` is a hiding place like any other (WV-4).
export const NOT_WALKED = ['node_modules', '.git', '.venv'];

/** Whether `d` is a WordPress core folder (the one rule, for the search and for pluginDirs()). */
const isCore = (d) => pathState(join(d, 'wp-includes', 'version.php')) === 'file';

// Wardlatch doesn't read PHP (owner, 23 Oct 2026: copying PHP's rules missed forms in four checks in a row). A config
// file that names one of the settings that move the content or plugins folder, anywhere in its text (a define, a
// comment, a string), may move it: UNKNOWN, as is one that can't be read.
const MOVES = /WP_CONTENT_DIR|WP_PLUGIN_DIR/i;
// in Bedrock's config, its own CONTENT_DIR moves the folder too
const BEDROCK_MOVES = /CONTENT_DIR|WP_PLUGIN_DIR/i;
// a PHP file name, in any case (PHP loads production.PHP on a case-insensitive disk)
const PHP_FILE = /\.php$/i;
// Bedrock's own lines that set its default content folder, each in the layout that shipped it (any other mention of
// CONTENT_DIR may move it). `webroot`: Bedrock 1.1 and later, config/ beside the web root (web/wp, web/app).
// `core`: Bedrock 1.0.0 (2014), config/ beside the core (wp/, app/ and config/ in one folder). $root_dir means a
// different folder in each, so a 1.0.0 line in a 1.1+ config moves the content folder: never stock there.
const CONTENT_APP = /^\s*(?:<\?php\s+)?(?:Config::)?define\(\s*(['"])CONTENT_DIR\1\s*,\s*(['"])\/app\2\s*\)\s*;\s*$/i;
const BEDROCK_STOCK = {
  webroot: [
    CONTENT_APP,
    /^\s*(?:<\?php\s+)?(?:Config::)?define\(\s*(['"])WP_CONTENT_DIR\1\s*,\s*\$webroot_dir\s*\.\s*(?:Config::get\(\s*(['"])CONTENT_DIR\2\s*\)|CONTENT_DIR)\s*\)\s*;\s*$/i,
    // the URL line only in its exact stock forms: anything more on it could set a folder (a define written any of the
    // ways PHP allows: 'define'(…), call_user_func('define', …), define/**/(…))
    /^\s*(?:<\?php\s+)?Config::define\(\s*(['"])WP_CONTENT_URL\1\s*,\s*Config::get\(\s*(['"])WP_HOME\2\s*\)\s*\.\s*Config::get\(\s*(['"])CONTENT_DIR\3\s*\)\s*\)\s*;\s*$/i,
    /^\s*(?:<\?php\s+)?define\(\s*(['"])WP_CONTENT_URL\1\s*,\s*WP_HOME\s*\.\s*CONTENT_DIR\s*\)\s*;\s*$/i,
  ],
  core: [
    CONTENT_APP,
    /^\s*(?:<\?php\s+)?define\(\s*(['"])WP_CONTENT_DIR\1\s*,\s*\$root_dir\s*\.\s*CONTENT_DIR\s*\)\s*;\s*$/i,
    // its URL built from the request's host
    /^\s*(?:<\?php\s+)?define\(\s*(['"])WP_CONTENT_URL\1\s*,\s*(['"])http:\/\/\2\s*\.\s*\$_SERVER\[\s*(['"])HTTP_HOST\3\s*\]\s*\.\s*CONTENT_DIR\s*\)\s*;\s*$/i,
  ],
};
/** The doubt a file or folder leaves when it can't be read (`why`). */
const unread = (path, why) => `${path} ${why}, so a moved plugins folder can't be ruled out`;
const CANT_OPEN = 'could not be opened (run Wardlatch with sudo)';
/** CANT_OPEN, or for a path the system refused with EPERM the words that are true of that (lib/files.mjs refusedOr):
 *  up to this fix every row here said "run Wardlatch with sudo" whatever the errno (R2-N5). */
const cantOpen = (path) => { const code = openErrno(path); return code === 'EPERM' ? `could not be opened (${refusedOr(path, '', code)})` : CANT_OPEN; };
/** The end of a row's reason for a folder that could not be opened: ": run Wardlatch with sudo", or the EPERM words. */
const sudoOr = (path) => `: ${refusedOr(path, 'run Wardlatch with sudo')}`;
/** Why `file` leaves where the plugins are in doubt (it can't be read, or `moves(text)` says it may move them), or
 *  null. A file that isn't there leaves no doubt. */
function doubtIn(file, moves) {
  const st = pathState(file);
  if (st === 'gone') return null;
  const text = st === 'file' ? readCapped(file, 1e6)?.toString('utf8') : null;
  if (text == null) return unread(file, st === 'denied' || (st === 'file' && !readHead(file, 1)) ? cantOpen(file) : st === 'file' ? 'is over 1 MB, which is not read' : 'is not a regular file');
  return moves(text) ? `${file} names a setting that moves the plugins folder, and Wardlatch doesn't read PHP, so where this site's plugins are can't be told` : null;
}

/** Whether `c` is Bedrock's config folder: Bedrock's own PHP is there (application.php, or a .php file in
 *  environments/). A Rails app's config/application.rb and environments/*.rb is not, unless its environments/ can't be
 *  opened or listed, which leaves the same doubt (reported by pluginDirs()); a missing one doesn't. */
const isBedrockConf = (c) => {
  if (pathState(join(c, 'application.php')) !== 'gone') return true;
  const env = join(c, 'environments'), st = pathState(env), l = st === 'dir' ? listDir(env) : null;
  return st === 'denied' || Boolean(l?.denied) || (l?.entries ?? []).some((e) => PHP_FILE.test(e.name));
};

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
  // Bedrock's config folder: beside the web root (Bedrock 1.1 and later: web/wp, config/), or beside the core itself
  // (Bedrock 1.0.0: wp/, app/ and config/ in one folder); one counts as Bedrock's by isBedrockConf()
  // ([folder, layout]; isBedrockConf() below)
  const confs = up ? [[join(dirname(up), 'config'), 'webroot'], [join(up, 'config'), 'core']].filter(([c]) => isBedrockConf(c)) : [];
  // Bedrock's app/ counts when it holds plugins/ or a Bedrock config folder is there (an app/ folder of another
  // program beside the core is not one)
  const bedrockApp = up && (pathState(join(up, 'app', 'plugins')) !== 'gone' || confs.length > 0);
  const content = [join(core, 'wp-content'), ...(up ? [join(up, 'wp-content')] : []), ...(bedrockApp ? [join(up, 'app')] : [])];
  const own = join(core, 'wp-config.php');
  const configs = pathState(own) !== 'gone' ? [own] : up && pathState(join(up, 'wp-settings.php')) === 'gone' ? [join(up, 'wp-config.php')] : [];
  const unfollowed = configs.map((cfg) => doubtIn(cfg, (t) => MOVES.test(t)));
  for (const [conf, layout] of confs) {
    unfollowed.push(doubtIn(join(conf, 'application.php'), (t) => t.split('\n').some((l) => !BEDROCK_STOCK[layout].some((re) => re.test(l)) && BEDROCK_MOVES.test(l))));
    // its environment files; a folder of them that can't be opened or listed leaves the same doubt
    const envDir = join(conf, 'environments'), envState = pathState(envDir), envList = envState === 'dir' ? listDir(envDir) : null;
    if (envState === 'denied' || envList?.denied) unfollowed.push(unread(envDir, cantOpen(envDir)));
    for (const e of envList?.entries ?? []) if (PHP_FILE.test(e.name)) unfollowed.push(doubtIn(join(envDir, e.name), (t) => BEDROCK_MOVES.test(t)));
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
 *  a dot-folder below a root (www-data's .ssh under /var/www) included; nothing goes into `privateDot` now, which gaps()
 *  would put in its one row for a service's folders whoever owns it. Dot-folders are searched like any other (a staging copy in .staging is a site). A
 *  core with no content or plugins folder in any place pluginDirs() knows goes into `coreOnly`: a site whose plugins
 *  weren't found, UNKNOWN. The search goes on inside a site (a blog in public_html/blog, or a staging copy inside
 *  wp-content, is a site of its own; up to 558eaef the search stopped at the first one). */
// `links = denied`: recording a link we did not follow must NOT be opt-in. AUDIT-3 calls this without a links array,
// and the gap vanished — a caller who forgets the argument got silence, which is the behaviour this was meant to end.
// It falls back to the channel every caller already passes, the same way privateDot does.
// `loose` (when given): plugins folders with no WordPress core that uses them — one given with --paths
// (--paths <site>/wp-content/plugins, or <site>/wp-content), or a wp-content/plugins the walk meets with no core beside
// it (a copy of a site's content folder). Up to this fix nothing looked in them: the plugins folder that holds the
// backdoored release, named directly, read "SAFE no WordPress installs found in 1 folder searched" (WV-1).
// A Bedrock app/plugins with no core yet (a checkout before `composer install`: config/ beside web/, web/app/plugins, no
// web/wp) is one of these too, as is an app/plugins holding a folder named as a listed plugin (`names`) (R2-N7). And
// so is a folder named plugins under any other parent that holds a listed plugin's folder, when no WordPress core was
// found in the folder that holds that parent (`named`): up to round 4 none was, so a copy outside any site (a backup's
// content/plugins) holding the compromised release read "SAFE no WordPress installs found" (round 3's re-read 2). One
// inside a found site's folder that is not where that site keeps its plugins is not this: a site whose config moves its
// content folder (Skeleton's content/) is UNKNOWN already, and a leftover beside a stock site is not read, as before.
// A plugins folder of another program, with no listed plugin's folder in it, is not a WordPress folder.
// `deep` (when given): the folders the depth cap stopped at that hold more to walk (lib/files.mjs holdsMore()).
export function wordpressUnder(roots, maxDepth = 5, denied, privateDot = denied, coreOnly, links = denied, { loose, deep, names = [] } = {}) {
  // none of the gap lists is opt-in: one left out that the walk has something for makes it throw (lib/files.mjs gapLists(); R2-N9)
  const gap = gapLists('wordpressUnder()', { denied, privateDot, coreOnly, links, loose, deep });
  ({ denied, privateDot, coreOnly, links, loose, deep } = gap);
  const out = [];
  const listed = new Map(), maybeLinks = [], plugins = [], named = [];
  // Bedrock's app/ folder: its config/ beside it (Bedrock 1.0.0) or beside its web root (1.1 and later)
  const bedrockApp = (app) => basename(app) === 'app' && [join(dirname(app), 'config'), join(dirname(dirname(app)), 'config')].some(isBedrockConf);
  const holdsListed = (d) => names.some((n) => pathState(join(d, n)) === 'dir');
  const pluginsFolder = (d, isRoot) => basename(d) === 'plugins' && (isRoot || basename(dirname(d)) === 'wp-content'
    || (basename(dirname(d)) === 'app' && (bedrockApp(dirname(d)) || holdsListed(d))));
  const walk = (d, depth, isRoot) => {
    if (depth < 0) { if (deep && holdsMore(d, NOT_WALKED)) deep.push(d); return; }
    if (isCore(d)) { if (pluginDirs(d).found) out.push(d); else coreOnly?.push(d); }
    if (pluginsFolder(d, isRoot)) plugins.push(d);
    else if (basename(d) === 'plugins' && holdsListed(d)) named.push(d);
    const l = listDir(d);
    // Every folder that can't be opened goes to `denied`, dot-folder or not, and gaps() lays out its row from who owns
    // it: one owned by a service account (www-data's .ssh under /var/www) goes in the check's one UNKNOWN row for a
    // service's folders (owner decision #33; up to it, a REVIEW line), one owned by the person running is an UNKNOWN row
    // of its own. Up to this fix a dot-folder below a root always went to `privateDot` and so was only
    // ever REVIEW, which never changes the exit code — so `.staging` at mode 0 holding a backdoored plugin printed
    // "folders not searched" and an all-clear side by side and exited 0, while the same folder named `locked` was
    // UNKNOWN and exit 2 (test/contract-0.1.9.test.mjs:436). The name a folder carries decided the verdict.
    if (l.denied) { denied?.push(d); return; }
    walkedTo(listed, d, depth);
    for (const e of l.entries ?? []) {
      if (NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)) continue;
      const p = join(d, e.name);
      if (e.isDirectory()) { walk(p, depth - 1, false); continue; }
      // a link to a folder is never followed (it can loop, or leave the tree asked for), but it is recorded, so the
      // run says so instead of passing over a site behind it in silence
      if (e.isSymbolicLink() && pathState(p) === 'dir') maybeLinks.push({ path: p, need: depth - 1 });
    }
  };
  // ONE FOLDER, ONE WALK. Two spellings of the same directory — a link and its target, /tmp/x and /private/tmp/x,
  // /x and /System/Volumes/Data/x — were each walked, so one site was reported as two and the count a person
  // reads was wrong in the alarming direction. sitePackagesDirs() has always deduped (lib/installs.mjs); these
  // walks deduped by nothing. fileId() is device:inode, the only identity that catches links, firmlinks and bind
  // mounts alike — comparing path strings catches none of them. A root whose id cannot be read is still walked:
  // refusing to look is worse than looking twice (AUDIT-25).
  const walked = new Set();
  for (const r of roots) {
    const id = fileId(r);
    if (id && walked.has(id)) continue;
    if (id) walked.add(id);
    walk(r, maxDepth, true);
  }
  // A link whose target this walk already listed is not a gap: the bytes were read (lib/files.mjs unwalkedLinks). This
  // is where the 310 of 311 came from — ~/.cache/uv/wheels-vN/ is a tree of links into ~/.cache/uv/archive-v0/, which
  // the same walk opens.
  if (links) links.push(...unwalkedLinks(maybeLinks, listed).map((c) => c.path));
  // the plugins folders no found core uses (one a core uses is checked with its site), and those under another parent
  // that are in no found site's folder (the folder holding its core, or the core's own: `named` above)
  if (loose) {
    const used = new Set(out.flatMap((c) => pluginDirs(c).dirs.map((p) => fileId(p) ?? p)));
    // a site's folder: its core's, or the one holding its core (WordPress in its own directory, Bedrock 1.0.0)
    const sites = new Set([...out, ...(coreOnly ?? [])].flatMap((c) => [c, dirname(c)]));
    const inSite = (p) => sites.has(dirname(dirname(p)));
    for (const p of [...plugins, ...named.filter((x) => !inSite(x))]) if (!used.has(fileId(p) ?? p) && !loose.includes(p)) loose.push(p);
  }
  gap.done();
  return out;
}

/** The listed plugins in a plugins folder that no WordPress core was found to use, checked as a site's are (version,
 *  indicator, new plugin folders) → findings, each with `site` set to the plugins folder. */
export function checkPluginsFolder(plugins, rules, addedSince) {
  return checkPlugins(plugins, plugins, rules, addedSince);
}

/** The Version: header of a plugin's main file. */
export function pluginVersion(dir, mainFile) {
  return (readCapped(join(dir, mainFile), 2e6)?.toString('utf8').match(/^\s*\*?\s*Version:\s*([\d.]+)/mi) ?? [])[1] ?? '';
}

/** Files under `dir` containing `needle`, every one but those INERT names, depth- and count-capped → { hits, skipped }.
 *  Folders that can't be opened go into `denied`; `skipped` says what a cap left unsearched (27cdfbd stopped silently:
 *  a backdoor in a file over 2 MB, past 4,000 files or 12 folders deep read as SAFE). */
// What a PHP server will execute or serve as code. `.php` alone was too narrow: a server configured for `.phtml`
// or `.php5` runs those too, and a backdoor is named by whoever planted it, not by our regex (AUDIT-24).
const CODE = /\.(php|phtml|php[3-8]|phps|inc|js|cgi)$/i;
// Files it is honest to pass over without saying so: there is no interpreter behind a PNG. Everything else is READ and
// searched, CODE or not. A backdoor in `loader.inc.html`, or in a file with no extension at all, used to be skipped in
// silence; then every such file was reported as unread instead, and every clean Rank Math PRO install, which ships
// ordinary files such as readme.txt, a .pot and .json files, read UNKNOWN for ever (WV-11). A small text file the
// search could read is not a gap: it is now read.
const INERT = /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|woff2?|ttf|eot|otf|css|less|scss|map|zip|gz|tgz|bz2|xz|rar|7z|mp[34]|mov|avi|webm|ogg|wav|pdf|docx?|xlsx?|pptx?|psd|mo|po|lock|min\.js)$/i;

function grepDir(dir, needle, denied, maxFiles = 4000, maxDepth = 12, maxBytes = 2e6) {
  const hits = [], big = []; let n = 0, deep = 0, more = false;
  const walk = (d, depth) => {
    const l = listDir(d);
    if (l.denied) { denied.push(d); return; }
    for (const e of l.entries ?? []) {
      const p = join(d, e.name);
      if (e.isDirectory()) { if (depth > 0) walk(p, depth - 1); else deep++; }
      else if (CODE.test(e.name) || !INERT.test(e.name)) {
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
    if (st === 'denied') { out.push({ site, status: 'UNKNOWN', what: r.plugin, reason: `the plugins folder could not be opened, so this plugin was not checked${sudoOr(dir)}` }); continue; }
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
    for (const d of denied) out.push({ site, status: 'UNKNOWN', what: `${r.plugin}: ${d.slice(dir.length + 1) || '.'}`, reason: `this folder could not be opened, so the indicator was not searched for in it${sudoOr(d)}` });
  }
  if (addedSince) {
    const since = Date.parse(addedSince);
    const l = listDir(plugins);
    if (l.denied) out.push({ site, status: 'UNKNOWN', what: 'plugins folder', reason: `could not be opened, so new plugin folders were not looked for${sudoOr(plugins)}` });
    for (const e of l.entries ?? []) {
      if (!e.isDirectory()) continue;
      const t = createdAt(join(plugins, e.name));
      if (t !== null && t >= since) out.push({ site, status: 'REVIEW', what: `plugin folder ${e.name}`, reason: `added ${new Date(t).toISOString().slice(0, 10)}` });
    }
  }
  return which ? out.map((r) => ({ ...r, plugins: which })) : out;
}
