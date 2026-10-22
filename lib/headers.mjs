// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Agents that tell websites who you are: find your own name or email (or any email address) in the header settings your
// tools send with their requests: curl's and wget's start-up files, git's http.extraHeader and http.userAgent, npm's
// user-agent, the headers in coding agents' and MCP clients' config files, and *_HEADERS / *_USER_AGENT variables in the
// environment. Read-only: files are read, nothing is run, and nothing is sent. A finding never prints the header's value:
// only where it is, the header's name, and what it carries ("your email").
// What this can't see: an agent that adds the header itself, in the moment, because a page asked it to.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { platform } from 'node:os';
import { readCapped } from './files.mjs';
import { reposUnder } from './workflows.mjs';

const MAX = 16 * 1024 * 1024;   // ~/.claude.json grows with history; a header file larger than this is not a config file
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/i;

// ---- who you are, from this machine only ---------------------------------------------------------------------------

const unquote = (v) => v.trim().replace(/^"(.*)"$/, '$1').replace(/\\"/g, '"');

/** A git config file, read as text (never through git, so nothing it names is run). includes are not followed. */
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

/** JSON with comments and trailing commas (VS Code's settings), made plain JSON. Strings are left alone. */
export function stripJsonc(text) {
  let out = '', i = 0, str = false;
  while (i < text.length) {
    const ch = text[i], nx = text[i + 1];
    if (str) { out += ch; if (ch === '\\') { out += nx ?? ''; i += 2; continue; } if (ch === '"') str = false; i++; continue; }
    if (ch === '"') { str = true; out += ch; i++; continue; }
    if (ch === '/' && nx === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (ch === '/' && nx === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; continue; }
    out += ch; i++;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

const HEADERISH = /header|user[-_]?agent/i;
/** Header-like strings anywhere in a parsed config: values under a key that names headers or the user agent, and the
 *  value after --header / -H in an args list (mcp-remote and similar bridges take headers that way). */
export function headersInJson(node, path = []) {
  const out = [];
  if (typeof node === 'string') {
    if (path.some((p) => HEADERISH.test(String(p)))) out.push({ where: path.join('.'), value: node });
  } else if (Array.isArray(node)) {
    node.forEach((v, i) => {
      if (typeof v === 'string' && ['--header', '-H'].includes(v) && typeof node[i + 1] === 'string') out.push({ where: `${path.join('.')}[${i + 1}]`, value: node[i + 1] });
      else if (typeof v === 'string' && v.startsWith('--header=')) out.push({ where: `${path.join('.')}[${i}]`, value: v.slice(9) });
      else out.push(...headersInJson(v, [...path, i]));
    });
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) out.push(...headersInJson(v, [...path, k]));
  }
  return out;
}

/** curl's and wget's start-up files: header and user-agent lines. */
export function headersInRc(text, kind) {
  const out = [];
  const re = kind === 'wget' ? /^\s*(header|user_agent)\s*=\s*(.*)$/i : /^\s*(?:-H|--header|header|-A|--user-agent|user-agent)\s*[=:\s]\s*(.*)$/i;
  text.split('\n').forEach((line, n) => {
    if (/^\s*#/.test(line)) return;
    const m = line.match(re);
    if (m) out.push({ where: `line ${n + 1}`, value: unquote(m[m.length - 1]) });
  });
  return out;
}

/** npm's .npmrc: the user-agent line. TOML (Codex): any line whose key names headers. */
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
    { file: join(home, '.curlrc'), kind: 'curl', to: every, everywhere: true },
    { file: join(env.XDG_CONFIG_HOME || join(home, '.config'), '.curlrc'), kind: 'curl', to: every, everywhere: true },
    { file: join(home, '.wgetrc'), kind: 'wget', to: every, everywhere: true },
    ...gitFiles(home, env).map((file) => ({ file, kind: 'git' })),
    { file: join(home, '.npmrc'), kind: 'npmrc', to: 'sent to the npm registry' },
    { file: join(home, '.codex', 'config.toml'), kind: 'toml', to: one },
    ...[
      join(home, '.claude.json'), join(home, '.claude', 'settings.json'), join(home, '.claude', 'settings.local.json'),
      join(home, '.cursor', 'mcp.json'), join(home, '.codeium', 'windsurf', 'mcp_config.json'), join(home, '.gemini', 'settings.json'),
      join(appSupport, 'Claude', 'claude_desktop_config.json'), join(appSupport, 'Code', 'User', 'mcp.json'), join(appSupport, 'Code', 'User', 'settings.json'),
    ].map((file) => ({ file, kind: 'json', to: one })),
  ];
  for (const repo of reposUnder(roots)) {
    for (const f of ['.mcp.json', join('.claude', 'settings.json'), join('.claude', 'settings.local.json'), join('.cursor', 'mcp.json'), join('.vscode', 'mcp.json'), join('.gemini', 'settings.json')]) {
      list.push({ file: join(repo, f), kind: 'json', to: one });
    }
  }
  return list;
}

/** Every header setting that gives you away. → { findings, unread, read, settings, id } */
export function scanHeaders({ home, env = process.env, roots = [] }) {
  const id = identityFrom(home, env);
  const findings = [], unread = [];
  let read = 0, settings = 0;
  const add = (file, h, status, to) => {
    settings++;
    const what = carries(h.value, id);
    if (what) findings.push({ status, file, where: headerName(h), carries: what, to });
  };
  for (const p of places(home, env, roots)) {
    if (!existsSync(p.file)) continue;
    const buf = readCapped(p.file, MAX);
    if (!buf) { unread.push({ file: p.file, reason: 'not a readable file under 16 MB' }); continue; }
    read++;
    const text = buf.toString('utf8');
    if (p.kind === 'git') {
      for (const h of parseGitConfig(text).headers) add(p.file, h, h.everywhere ? 'EXPOSED' : 'REVIEW', h.everywhere ? 'sent to every git remote' : 'sent to the remote it names');
    } else if (p.kind === 'curl' || p.kind === 'wget') {
      for (const h of headersInRc(text, p.kind)) add(p.file, h, 'EXPOSED', p.to);
    } else if (p.kind === 'npmrc') {
      for (const h of headersInLines(text, /^\s*user-agent\s*=/i)) add(p.file, h, 'REVIEW', p.to);
    } else if (p.kind === 'toml') {
      for (const h of headersInLines(text, /^\s*[\w."-]*header[\w."-]*\s*=/i)) add(p.file, h, 'REVIEW', p.to);
    } else {
      let parsed;
      try { parsed = JSON.parse(stripJsonc(text)); } catch { unread.push({ file: p.file, reason: 'not valid JSON' }); read--; continue; }
      for (const h of headersInJson(parsed)) add(p.file, h, 'REVIEW', p.to);
    }
  }
  for (const [k, v] of Object.entries(env)) {
    if (!/(^|_)HEADERS?$|USER_?AGENT$/i.test(k) || typeof v !== 'string') continue;
    // ANTHROPIC_CUSTOM_HEADERS holds one "Name: value" per line; OTEL_*_HEADERS holds name=value pairs
    for (const value of v.split(/\n|,(?=\s*[\w-]+\s*[=:])/)) add(`$${k}`, { where: `$${k}`, value }, 'REVIEW', 'sent by the program that reads this variable');
  }
  return { findings, unread, read, settings, id };
}
