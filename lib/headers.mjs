// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Agents that tell websites who you are: find your own name or email (or any email address) in the header settings your
// tools send with their requests: curl's and wget's start-up files, git's http.extraHeader and http.userAgent, npm's
// user-agent, the headers in coding agents' and MCP clients' config files, and *_HEADERS / *_USER_AGENT variables in the
// environment. Read-only: files are read, nothing is run, and nothing is sent. A finding never prints the header's value:
// only where it is, the header's name, and what it carries ("your email").
// What this can't see: an agent that adds the header itself, in the moment, because a page asked it to.
import { join } from 'node:path';
import { platform } from 'node:os';
import { readCapped, pathState } from './files.mjs';
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
    // a trailing comma: the next thing that isn't white space closes the object or array
    if (ch === ',') { let j = i + 1; while (j < text.length && (text[j] === ' ' || text[j] === '\n' || text[j] === '\t' || text[j] === '\r')) j++; if (text[j] === '}' || text[j] === ']') { cut(i, i + 1); i++; continue; } }
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
  // past the cap the file is not read through: the caller reports it UNKNOWN (dropping the rest silently let a header
  // after 200,000 items read as SAFE)
  const push = (x) => { if (++items > MAX_ITEMS) throw new RangeError('more items than are read through'); stack.push(x); };
  while (stack.length) {
    const { node, path } = stack.pop();
    if (typeof node === 'string') {
      // its own key or the key right above it (a "headers" object, an array's name): never a key further up, or a
      // project folder called request-headers would make every prompt in its history a "header"
      if ([path.at(-1), path.at(-2)].some((k) => typeof k === 'string' && HEADERISH.test(k))) out.push({ where: path.join('.'), value: node });
      continue;
    }
    if (!node || typeof node !== 'object' || path.length >= MAX_DEPTH) continue;
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

/** curl's and wget's start-up files: header and user-agent lines. Lines may end in CRLF. Parsed by hand, not with a
 *  regex that can backtrack: a planted line of thousands of spaces took 22 seconds in 0.1.8. wget reads command names
 *  without regard to case, dashes or underscores (useragent, user_agent, UserAgent); curl's short options are
 *  case-sensitive (-a is --append). */
export function headersInRc(text, kind) {
  const out = [];
  text.split(/\r?\n/).forEach((raw, n) => {
    const line = raw.trimStart();
    if (!line || line.startsWith('#')) return;
    let value = null;
    if (kind === 'wget') {
      const eq = line.indexOf('=');
      if (eq > 0 && ['header', 'useragent'].includes(line.slice(0, eq).trim().toLowerCase().replace(/[-_]/g, ''))) value = line.slice(eq + 1).trim();
    } else {
      // the option is the first word, ended by white space, '=' or ':'
      let i = 0;
      while (i < line.length && !' \t=:'.includes(line[i])) i++;
      const opt = line.slice(0, i), bare = opt.replace(/^--?/, '');
      if (opt === '-H' || opt === '-A' || (opt === bare || opt.startsWith('--')) && ['header', 'user-agent'].includes(bare.toLowerCase())) {
        while (i < line.length && ' \t=:'.includes(line[i])) i++;
        value = line.slice(i).trimEnd();
      }
    }
    if (value !== null) out.push({ where: `line ${n + 1}`, value: unquote(value) });
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
export function places(home, env = process.env, roots = []) {
  const os = platform();
  const appSupport = os === 'darwin' ? join(home, 'Library', 'Application Support') : os === 'win32' ? (env.APPDATA || join(home, 'AppData', 'Roaming')) : (env.XDG_CONFIG_HOME || join(home, '.config'));
  const every = 'sent to every site that program opens';
  const one = 'sent to the service or MCP server it names';
  const list = [
    // every place curl looks for its start-up file: $CURL_HOME, the home folder, and the XDG folder (curlrc, no dot)
    ...[env.CURL_HOME && join(env.CURL_HOME, '.curlrc'), join(home, '.curlrc'), join(env.XDG_CONFIG_HOME || join(home, '.config'), 'curlrc'), join(env.XDG_CONFIG_HOME || join(home, '.config'), '.curlrc')]
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
  for (const repo of reposUnder(roots)) {
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
  if (p.kind === 'curl' || p.kind === 'wget') return as(headersInRc(text, p.kind), 'EXPOSED', p.to);
  if (p.kind === 'npmrc') return as(headersInLines(text, /^\s*user-agent\s*=/i), 'REVIEW', p.to);
  if (p.kind === 'toml') return as(headersInToml(text), 'REVIEW', p.to);
  return as(headersInJson(JSON.parse(stripJsonc(text))), 'REVIEW', p.to);
}

/** Every header setting that gives you away. → { findings, unread, read, settings, id } */
export function scanHeaders({ home, env = process.env, roots = [] }) {
  const id = identityFrom(home, env);
  const findings = [], unread = [], files = [];
  let read = 0, settings = 0;
  const add = (file, h, status, to) => {
    settings++;
    const what = carries(h.value, id);
    if (what) findings.push({ status, file, where: headerName(h), carries: what, to });
  };
  for (const p of places(home, env, roots)) {
    const st = pathState(p.file);
    if (st === 'gone') continue;
    if (st === 'denied') { unread.push({ file: p.file, reason: 'a folder on the way could not be opened' }); continue; }
    const buf = readCapped(p.file, p.max ?? MAX);
    if (!buf) { unread.push({ file: p.file, reason: `not a readable file under ${(p.max ?? MAX) / 1024 / 1024} MB` }); continue; }
    files.push(p.file);
    read++;
    const text = buf.toString('utf8');
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
  return { findings, unread, read, settings, id, files };
}
