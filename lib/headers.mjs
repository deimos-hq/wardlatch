// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Agents that tell websites who you are: find your own name or email (or any email address) in the header settings your
// tools send with their requests: curl's and wget's start-up files, git's http.extraHeader and http.userAgent, npm's
// user-agent, the headers in coding agents' and MCP clients' config files, and *_HEADERS / *_USER_AGENT variables in the
// environment. Read-only: files are read, nothing is run, and nothing is sent. A finding never prints the header's value:
// only where it is, the header's name, and what it carries ("your email").
// What this can't see: an agent that adds the header itself, in the moment, because a page asked it to.
import { join, isAbsolute } from 'node:path';
import { platform } from 'node:os';
import { readCapped, readHead, pathState, realPath } from './files.mjs';
import { reposUnder } from './workflows.mjs';

const MAX = 16 * 1024 * 1024;   // ~/.claude.json grows with history; a header file larger than this is not a config file
const REPO_MAX = 1024 * 1024;   // a repository's own config is small; a planted 16 MB .mcp.json took 1.4 GB to walk in 0.1.8
// bounded pieces: an unbounded [\w.+-]+ before the @ made a long token (a 200 KB bearer token) take quadratic time
const EMAIL = /[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){0,10}\.[a-z]{2,24}/i;

// ---- who you are, from this machine only ---------------------------------------------------------------------------

const unquote = (v) => v.trim().replace(/^"(.*)"$/, '$1').replace(/\\"/g, '"');

/** A git config file, read as text (never through git, so nothing it names is run). includes are not followed, and a
 *  `#` or `;` inside a quoted value is taken as the start of a comment (rare in names and headers). */
export function parseGitConfig(text) {
  const out = { name: '', email: '', headers: [] };
  let section = '', sub = '';
  for (const raw of text.split('\n')) {
    const line = raw.replace(/(^|\s)[#;].*$/, '').trim();
    if (!line) continue;
    const s = line.match(/^\[\s*([\w.-]+)(?:\s+"(.*)")?\s*\]$/);
    if (s) { section = s[1].toLowerCase(); sub = s[2] ?? ''; continue; }
    const kv = line.match(/^([\w-]+)\s*=\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1].toLowerCase(), val = unquote(kv[2]);
    if (section === 'user' && key === 'name') out.name = val;
    else if (section === 'user' && key === 'email') out.email = val;
    else if (section === 'http' && (key === 'extraheader' || key === 'useragent')) {
      out.headers.push({ where: `http${sub ? ` "${sub}"` : ''}.${kv[1]}`, value: val, everywhere: !sub });
    }
  }
  return out;
}

function gitFiles(home, env) {
  // GIT_CONFIG_GLOBAL names the file git reads in place of ~/.gitconfig and the XDG one
  if (env.GIT_CONFIG_GLOBAL) return [env.GIT_CONFIG_GLOBAL];
  return [join(home, '.gitconfig'), join(env.XDG_CONFIG_HOME || join(home, '.config'), 'git', 'config')];
}

/** Your name and email as your own tools know them: git's global config and the usual variables. Never sent. */
export function identityFrom(home, env = process.env) {
  const id = { name: env.GIT_AUTHOR_NAME || env.GIT_COMMITTER_NAME || '', email: env.GIT_AUTHOR_EMAIL || env.GIT_COMMITTER_EMAIL || env.EMAIL || '' };
  for (const f of gitFiles(home, env)) {
    const buf = readCapped(f, MAX);
    if (!buf) continue;
    const g = parseGitConfig(buf.toString('utf8'));
    id.name ||= g.name; id.email ||= g.email;
  }
  return id;
}

/** What a header value gives away, or null. Names count only when long enough not to match by chance. */
export function carries(value, id) {
  const v = String(value);
  if (id.email && v.toLowerCase().includes(id.email.toLowerCase())) return 'your email';
  const name = id.name.trim();
  if (name.length >= 6 || name.includes(' ')) {
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
    if (new RegExp(`(^|[^\\p{L}])${esc}($|[^\\p{L}])`, 'iu').test(v)) return 'your name';
  }
  const local = id.email.split('@')[0] ?? '';
  if (local.length >= 6 && v.toLowerCase().includes(local.toLowerCase())) return 'your email\'s user name';
  if (EMAIL.test(v)) return 'an email address';
  return null;
}

// ---- reading the settings -----------------------------------------------------------------------------------------

/** Where the next character that isn't white space or inside a comment is, from `j` (text.length when there is none). */
function nextToken(text, j) {
  for (;;) {
    while (j < text.length && ' \n\t\r'.includes(text[j])) j++;
    if (text[j] === '/' && text[j + 1] === '/') { const e = text.indexOf('\n', j); if (e < 0) return text.length; j = e; continue; }
    if (text[j] === '/' && text[j + 1] === '*') { const e = text.indexOf('*/', j + 2); if (e < 0) return text.length; j = e + 2; continue; }
    return j;
  }
}

/** JSON with comments and trailing commas (VS Code's settings), made plain JSON. Text inside strings is never changed. */
export function stripJsonc(text) {
  // copies runs of text in slices, not one character at a time (a 16 MB file grew memory by over 600 MB)
  const parts = []; let i = 0, from = 0, str = false;
  const cut = (to, skipTo) => { if (to > from) parts.push(text.slice(from, to)); from = skipTo; };
  while (i < text.length) {
    const ch = text[i], nx = text[i + 1];
    if (str) { if (ch === '\\') { i += 2; continue; } if (ch === '"') str = false; i++; continue; }
    if (ch === '"') { str = true; i++; continue; }
    if (ch === '/' && nx === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? text.length : e; cut(i, end); i = end; continue; }
    if (ch === '/' && nx === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? text.length : e + 2; cut(i, end); i = end; continue; }
    // a trailing comma: the next thing that isn't white space or a comment closes the object or array (VS Code writes
    // a commented-out last setting after one: up to b03e7be that file read as invalid, UNKNOWN)
    if (ch === ',') { const j = nextToken(text, i + 1); if (text[j] === '}' || text[j] === ']') { cut(i, i + 1); i++; continue; } }
    i++;
  }
  cut(text.length, text.length);
  return parts.join('');
}

const HEADERISH = /header|user[-_]?agent/i;
const MAX_DEPTH = 64, MAX_ITEMS = 200000;   // a planted config can't exhaust the stack or the clock
/** Header-like strings anywhere in a parsed config: a string whose own key, or the key right above it, names headers or
 *  the user agent, and the value after --header / -H in an args list (mcp-remote and similar bridges take
 *  headers that way). Walked with an explicit stack, depth- and size-capped. */
export function headersInJson(root) {
  const out = [];
  const stack = [{ node: root, path: [] }];
  let items = 0;
  // past either cap the file is not read through: the caller reports it UNKNOWN (dropping the rest silently let a
  // header after 200,000 items, or nested 70 deep, read as SAFE)
  const push = (x) => { if (++items > MAX_ITEMS) throw new RangeError('more items than are read through'); stack.push(x); };
  while (stack.length) {
    const { node, path } = stack.pop();
    if (typeof node === 'string') {
      // its own key or the key right above it (a "headers" object, an array's name): never a key further up, or a
      // project folder called request-headers would make every prompt in its history a "header"
      if ([path.at(-1), path.at(-2)].some((k) => typeof k === 'string' && HEADERISH.test(k))) out.push({ where: path.join('.'), value: node });
      continue;
    }
    if (!node || typeof node !== 'object') continue;
    if (path.length >= MAX_DEPTH) throw new RangeError('nested deeper than is read through');
    if (Array.isArray(node)) {
      node.forEach((v, i) => {
        if (typeof v === 'string' && ['--header', '-H'].includes(v) && typeof node[i + 1] === 'string') out.push({ where: `${path.join('.')}[${i + 1}]`, value: node[i + 1] });
        else if (typeof v === 'string' && v.startsWith('--header=')) out.push({ where: `${path.join('.')}[${i}]`, value: v.slice(9) });
        else if (v && typeof v === 'object') push({ node: v, path: [...path, i] });
        else if (typeof v === 'string') push({ node: v, path: [...path, i] });
      });
    } else {
      for (const [k, v] of Object.entries(node)) push({ node: v, path: [...path, k] });
    }
  }
  return out;
}

// curl options that send a header or user agent (to every site, or to the proxy; each also as curl 8.3's expand-
// form), and the two that bring in more: config (-K) and variable
const CURL_SENDS = ['header', 'user-agent', 'proxy-header'];
/** A curl value with its backslash escapes undone, everywhere (curl undoes them inside quotes): \t \n \r \v are white
 *  space, any other \x is x. On the safe side, so `jo\@example.com` reads as the address curl sends. */
const unescape = (v) => v.replace(/\\([\s\S])/g, (_, ch) => ({ t: '\t', n: '\n', r: '\r', v: '\v' })[ch] ?? ch);
/**
 * One .curlrc line → { kind: 'header' | 'config' | 'variable', value, raw } or null (`value` without its enclosing quotes
 * and with escapes undone, `raw` as written). Read on the safe side of curl, not as its parser reads it (owner, 23 Oct
 * 2026: copying curl's parser missed forms in four checks in a row): the option is the first word (up to white space,
 * and for one without dashes also up to '=' or ':'); for an option that sends a header or user agent, the value is the
 * whole rest of the line, so your name or email anywhere after it counts. A cluster of short options counts when H or A
 * is in it (-sH, -svA); -K brings in a config file with the file attached (-K/path) or as the cluster's last letter (-K
 * file, -sK file). Long names
 * are matched without regard to case (older curl did). So a line curl itself refuses, or reads only in part (an
 * unquoted value is cut at its first space; a later -A replaces an earlier one), is still reported: fix or remove it.
 */
export function curlLine(line) {
  const dashed = line[0] === '-';
  const m = (dashed ? /^[^ \t\n\v\f\r]+/ : /^[^ \t\n\v\f\r=:]+/).exec(line);
  if (!m) return null;
  const word = m[0];
  let rest = line.slice(word.length).replace(dashed ? /^[ \t\n\v\f\r]+/ : /^[ \t\n\v\f\r=:]+/, '').replace(/[ \t\n\v\f\r]+$/, '');
  // `file`: what a header or config value names as a file, read exactly as curl reads it (fileName())
  const out = (kind, raw, option, attached = false) => ({ kind, value: unescape(unquote(raw)), raw, option, file: fileName(raw, attached) });
  if (!dashed || word.startsWith('--')) {
    // --header=x: curl refuses the '=', but it is read here, on the safe side
    const [opt, ...glued] = word.replace(/^--/, '').split('=');
    const long = opt.toLowerCase();
    if (glued.length) rest = [glued.join('='), rest].filter(Boolean).join(' ');
    // curl 8.3's expand- prefix works on any option (expand-config reads a file too): the option is what follows it
    const name = long.replace(/^expand-/, ''), expand = name !== long;
    if (CURL_SENDS.includes(name)) return { ...out('header', rest, name, glued.length > 0), expand };
    if (name === 'config' || name === 'variable') return { ...out(name, rest, name, glued.length > 0), expand };
    return null;
  }
  // -K with its file attached (-K/path), or as the cluster's last letter with the file next (-K file, -sK file)
  if (word.startsWith('-K') && word.length > 2) return out('config', [word.slice(2), rest].filter(Boolean).join(' '), 'config', true);
  if (word.endsWith('K')) return out('config', rest, 'config');
  const k = word.slice(1).search(/[HA]/) + 1;
  return k ? out('header', [word.slice(k + 1), rest].filter(Boolean).join(' '), word[k] === 'H' ? 'header' : 'user-agent', word.length > k + 1) : null;
}

/** The file name a curl value gives, as curl reads it: a value attached to its option (-K/path, -H@file) or not quoted
 *  is its first word exactly as written (curl undoes no escapes there: a file named a\b is a\b); a quoted one is the
 *  quoted string with its escapes undone (\" is a quote, \t white space, \x is x). */
function fileName(raw, attached) {
  if (attached || raw[0] !== '"') return raw.split(/[ \t\n\v\f\r]/)[0];
  let name = '';
  for (let i = 1; i < raw.length && raw[i] !== '"'; i++) name += raw[i] === '\\' && i + 1 < raw.length ? unescape(raw.slice(i, ++i + 1)) : raw[i];
  return name;
}
// the files a curl config brings in (header files, config files): small, read once per use, and at most this many
const CURL_FILE_MAX = 1024 * 1024, CURL_FILES = 32;

/** curl's and wget's start-up files: header and user-agent lines. Lines may end in CRLF. Parsed by hand, not with a
 *  regex that can backtrack: a planted line of thousands of spaces took 22 seconds in 0.1.8. wget reads command names
 *  without regard to case, dashes or underscores (useragent, user_agent, UserAgent); curl's lines go through
 *  curlLine(), and carry its kind (a header, a config file to bring in, a variable). */
export function headersInRc(text, kind) {
  const out = [];
  text.replace(/^﻿/, '').split(/\r?\n/).forEach((raw, n) => {
    // leading ASCII white space only, as curl skips it (a line that starts with a no-break space is not an option)
    const line = raw.replace(/^[ \t\n\v\f\r]+/, '');
    if (!line || line.startsWith('#')) return;
    if (kind === 'wget') {
      const eq = line.indexOf('=');
      if (eq > 0 && ['header', 'useragent'].includes(line.slice(0, eq).trim().toLowerCase().replace(/[-_]/g, ''))) out.push({ where: `line ${n + 1}`, value: unquote(line.slice(eq + 1).trim()) });
      return;
    }
    const c = curlLine(line);
    if (c) out.push({ where: `line ${n + 1}`, ...c });
  });
  return out;
}

/** TOML (Codex's config.toml): a key that names headers, or any key = value under a [table] whose name names headers
 *  ([mcp_servers.x.http_headers]). Parsed by hand: no regex can backtrack on a planted line. */
export function headersInToml(text) {
  const out = [];
  let inHeaders = false;
  text.split(/\r?\n/).forEach((raw, n) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    if (line.startsWith('[')) { const end = line.lastIndexOf(']'); inHeaders = end > 0 && /header/i.test(line.slice(1, end)); return; }
    const eq = line.indexOf('=');
    if (eq <= 0) return;
    if (inHeaders || /header/i.test(line.slice(0, eq))) out.push({ where: `line ${n + 1}`, value: line });
  });
  return out;
}

/** npm's .npmrc: the user-agent line. */
function headersInLines(text, re) {
  const out = [];
  text.split('\n').forEach((line, n) => { if (!/^\s*[#;]/.test(line) && re.test(line)) out.push({ where: `line ${n + 1}`, value: line }); });
  return out;
}

const headerName = (h) => {
  const m = String(h.value).match(/^\s*([A-Za-z][\w-]{0,60})\s*:/);
  if (m) return `header "${m[1]}"`;
  // { "headers": { "X-Name": "value" } }: the key is the header's name, and the path before it says which server
  const k = h.where.match(/^(?:(.*)\.)?headers\.([^.]+)$/i);
  return k ? `${k[1] ? `${k[1]} ` : ''}header "${k[2]}"` : h.where;
};

/** The places headers are set, each with who receives them. */
export function places(home, env = process.env, roots = [], denied) {
  const os = platform();
  const appSupport = os === 'darwin' ? join(home, 'Library', 'Application Support') : os === 'win32' ? (env.APPDATA || join(home, 'AppData', 'Roaming')) : (env.XDG_CONFIG_HOME || join(home, '.config'));
  const every = 'sent to every site that program opens';
  const one = 'sent to the service or MCP server it names';
  const list = [
    // every place a curl version looks for its start-up file: $CURL_HOME (and its .config/curlrc), the home folder, and
    // the XDG folder (curl 8.7.1 reads fewer of these; reading one it skips is on the safe side)
    ...[env.CURL_HOME && join(env.CURL_HOME, '.curlrc'), env.CURL_HOME && join(env.CURL_HOME, '.config', 'curlrc'), join(home, '.curlrc'), join(env.XDG_CONFIG_HOME || join(home, '.config'), 'curlrc'), join(env.XDG_CONFIG_HOME || join(home, '.config'), '.curlrc')]
      .filter(Boolean).map((file) => ({ file, kind: 'curl', to: every, everywhere: true })),
    { file: env.WGETRC || join(home, '.wgetrc'), kind: 'wget', to: every, everywhere: true },
    ...gitFiles(home, env).map((file) => ({ file, kind: 'git' })),
    { file: env.NPM_CONFIG_USERCONFIG || join(home, '.npmrc'), kind: 'npmrc', to: 'sent to the npm registry' },
    { file: join(home, '.codex', 'config.toml'), kind: 'toml', to: one },
    ...[
      join(home, '.claude.json'), join(home, '.claude', 'settings.json'), join(home, '.claude', 'settings.local.json'),
      join(home, '.cursor', 'mcp.json'), join(home, '.codeium', 'windsurf', 'mcp_config.json'), join(home, '.gemini', 'settings.json'),
      join(appSupport, 'Claude', 'claude_desktop_config.json'), join(appSupport, 'Code', 'User', 'mcp.json'), join(appSupport, 'Code', 'User', 'settings.json'),
    ].map((file) => ({ file, kind: 'json', to: one })),
  ];
  for (const repo of reposUnder(roots, 4, denied)) {
    for (const f of ['.mcp.json', join('.claude', 'settings.json'), join('.claude', 'settings.local.json'), join('.cursor', 'mcp.json'), join('.vscode', 'mcp.json'), join('.gemini', 'settings.json')]) {
      list.push({ file: join(repo, f), kind: 'json', to: one, max: REPO_MAX });
    }
  }
  return list;
}

/** The header settings in one file, by its kind → [{ h, status, to }]. Throws on a file it can't parse. */
function settingsIn(p, text) {
  const as = (list, status, to) => list.map((h) => ({ h, status, to }));
  if (p.kind === 'git') return parseGitConfig(text).headers.map((h) => ({ h, status: h.everywhere ? 'EXPOSED' : 'REVIEW', to: h.everywhere ? 'sent to every git remote' : 'sent to the remote it names' }));
  if (p.kind === 'wget') return as(headersInRc(text, p.kind), 'EXPOSED', p.to);
  if (p.kind === 'npmrc') return as(headersInLines(text, /^\s*user-agent\s*=/i), 'REVIEW', p.to);
  if (p.kind === 'toml') return as(headersInToml(text), 'REVIEW', p.to);
  return as(headersInJson(JSON.parse(stripJsonc(text))), 'REVIEW', p.to);
}

/** Every header setting that gives you away. → { findings, unread, read, settings, id, files, denied, notUsed } (denied:
 *  folders under `roots` that couldn't be opened, so their repositories' settings were not read; notUsed: settings files
 *  this user can't open, which their own tools can't use either) */
export function scanHeaders({ home, env = process.env, roots = [] }) {
  const id = identityFrom(home, env);
  const findings = [], unread = [], files = [], denied = [], notUsed = [];
  let read = 0, settings = 0;
  const add = (file, h, status, to) => {
    settings++;
    const what = carries(h.value, id);
    if (what) findings.push({ status, file, where: headerName(h), carries: what, to });
  };
  // One rule for every file a tool reads its settings or headers from. Gone: nothing in it is sent. One this user can't
  // open (or a folder in its place) can't be read by their git, curl or npm either, so nothing in it is sent (0.1.9's first cut said UNKNOWN: a
  // ~/.config left root-owned by an earlier sudo made the check exit 2; curl exits 26 for a header file it can't read).
  // /dev/null is how CI and test setups switch one off (GIT_CONFIG_GLOBAL=/dev/null): empty. → a Buffer, or null when
  // the file was gone, not used (recorded) or not read through (recorded as unread)
  const readSetting = (file, max) => {
    const st = pathState(file);
    if (st === 'gone') return null;
    if (st === 'denied' || st === 'dir') { notUsed.push(file); return null; }
    const buf = st === 'other' && realPath(file) === '/dev/null' ? Buffer.alloc(0) : readCapped(file, max);
    if (!buf && st === 'file' && !readHead(file, 1)) { notUsed.push(file); return null; }
    if (!buf) { unread.push({ file, reason: `not a regular file under ${max / 1024 / 1024} MB` }); return null; }
    return buf;
  };
  // A curl config file (curlLine()): each header line is checked; the file a header line names with @file is read in its
  // place (up to b03e7be the name itself was checked, and the headers in it never were), and a config/-K line's file is
  // read as curl config too. Each brought-in file is read once per use, at most CURL_FILES of them and CURL_FILE_MAX each: past
  // that, UNKNOWN (planted files that bring each other in hung the scan at 486ef49). A file named by a relative path is
  // read from whatever folder curl runs in: UNKNOWN. curl variables (a variable line, or {{name}} in an expand-* line)
  // can build a header from pieces, which Wardlatch doesn't put together: UNKNOWN.
  const brought = new Set();
  const curlSettings = (file, text, to) => {
    // each kind of doubt once per file: a planted file of 50,000 such lines makes one row, not 50,000
    const doubts = new Set();
    const doubt = (kind, reason) => { if (!doubts.has(kind)) { doubts.add(kind); unread.push({ file, reason }); } };
    // a file is read once as config and once as headers at most (one file brought in both ways is read both ways)
    const bring = (l, f, as) => {
      if (!isAbsolute(f)) { doubt('relative', `${l.where} names a file by a relative path (${f}), which curl reads from the folder it runs in`); return null; }
      if (brought.has(`${as}:${f}`)) return null;
      if (brought.size >= CURL_FILES) { doubt('many', `${l.where} brings in more files than the ${CURL_FILES} Wardlatch reads`); return null; }
      brought.add(`${as}:${f}`);
      const b = readSetting(f, CURL_FILE_MAX);
      if (b) files.push(f);
      return b?.toString('utf8') ?? null;
    };
    let variables = false;
    for (const l of headersInRc(text, 'curl')) {
      // the file a value names (fileName()); - is standard input, never a file
      const first = l.file;
      if (l.kind === 'variable' || (l.expand && l.value.includes('{{'))) { variables = true; continue; }
      if (l.kind === 'config') { const t = first && first !== '-' ? bring(l, first, 'config') : null; if (t !== null) curlSettings(first, t, to); continue; }
      // only a header option reads @file (curl sends a user agent's value as it is, @ and all)
      if (['header', 'proxy-header'].includes(l.option) && first.startsWith('@') && first !== '@-') {
        const t = bring(l, first.slice(1), 'headers');
        for (const line of (t ?? '').split(/\r?\n/)) if (line.trim()) add(file, { where: `${l.where} (${first.slice(1)})`, value: line }, 'EXPOSED', to);
        continue;
      }
      add(file, { where: l.where, value: l.value }, 'EXPOSED', to);
    }
    if (variables) doubt('variables', 'uses curl variables (a variable line, or {{name}} in an expand- line), which can build a header from pieces Wardlatch does not put together');
  };
  for (const p of places(home, env, roots, denied)) {
    const buf = readSetting(p.file, p.max ?? MAX);
    if (!buf) continue;
    files.push(p.file);
    read++;
    const text = buf.toString('utf8');
    if (p.kind === 'curl') { brought.add(`config:${p.file}`); curlSettings(p.file, text, p.to); continue; }
    // one malformed or hostile file never ends the run: it is UNKNOWN, and the scan goes on
    let found;
    try { found = settingsIn(p, text); } catch (e) { unread.push({ file: p.file, reason: e instanceof SyntaxError ? 'not valid JSON' : `could not be read through (${e.name})` }); read--; files.pop(); continue; }
    for (const { h, status, to } of found) add(p.file, h, status, to);
  }
  for (const [k, v] of Object.entries(env)) {
    if (!/(^|_)HEADERS?$|USER_?AGENT$/i.test(k) || typeof v !== 'string') continue;
    // ANTHROPIC_CUSTOM_HEADERS holds one "Name: value" per line; OTEL_*_HEADERS holds name=value pairs
    for (const value of v.split(/\n|,(?=\s*[\w-]+\s*[=:])/)) add(`$${k}`, { where: `$${k}`, value }, 'REVIEW', 'sent by the program that reads this variable');
  }
  return { findings, unread, read, settings, id, files, denied, notUsed };
}
