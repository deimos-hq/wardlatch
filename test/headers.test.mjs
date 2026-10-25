// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Agents that tell websites who you are: header settings that carry your name or email are found, by file and header
// name, and the value is never printed. Everything runs against a made-up home folder; nothing is sent.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync as mkdtempRaw, mkdirSync, writeFileSync, rmSync } from 'node:fs';
// every temp folder this file makes is removed when it ends
const made = [];
const mkdtempSync = (p) => { const d = mkdtempRaw(p); made.push(d); return d; };
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checked } from './support/output-checks.mjs';
import { carries, parseGitConfig, headersInJson, headersInRc, headersInToml, stripJsonc, scanHeaders, identityFrom } from '../lib/headers.mjs';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'wardlatch.mjs');
// the command, with T0 and T1 checked on what it printed (test/support/output-checks.mjs)
const cli = (args, env) => checked(args, spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env }));
const ID = { name: 'Ada Lovelace', email: 'ada.lovelace@example.org' };
const CLEAN = { PATH: process.env.PATH };   // no inherited *_HEADERS, GIT_AUTHOR_* or EMAIL variables
let home;
const put = (rel, text) => { const p = join(home, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };

before(() => {
  home = mkdtempSync(join(tmpdir(), 'wardlatch-headers-'));
  put('.gitconfig', '[user]\n\tname = Ada Lovelace\n\temail = ada.lovelace@example.org\n[http]\n\textraHeader = "From: ada.lovelace@example.org"\n[http "https://git.example.com/"]\n\textraHeader = X-Requested-By: Ada Lovelace\n');
  put('.curlrc', '# mine\nheader = "X-Contact: Ada Lovelace"\nuser-agent = "curl-ok"\n');
  put('.claude/settings.json', JSON.stringify({ env: { ANTHROPIC_CUSTOM_HEADERS: 'X-User: ada.lovelace@example.org' } }));
  put('.cursor/mcp.json', JSON.stringify({ mcpServers: { tools: { command: 'npx', args: ['mcp-remote', 'https://mcp.example.com', '--header', 'Authorization: Bearer abc123'] }, other: { url: 'https://x.example', headers: { 'X-Operator': 'someone@elsewhere.net' } } } }));
  put('.codeium/windsurf/mcp_config.json', '{ not json');
});

test('who you are comes from git\'s own file, read as text', () => {
  assert.deepEqual(identityFrom(home, CLEAN), ID);
  const g = parseGitConfig('[http "https://a.example/"]\n  extraheader = X: 1 ; note\n[include]\n  path = ~/x\n');
  assert.deepEqual(g.headers, [{ where: 'http "https://a.example/".extraheader', value: 'X: 1', everywhere: false }]);
});

test('what a value carries: your email, your name, your email\'s user name, any email, or nothing', () => {
  assert.equal(carries('From: ADA.LOVELACE@example.org', ID), 'your email');
  assert.equal(carries('X: ada  lovelace', ID), 'your name');
  assert.equal(carries('X: adalovelacex', ID), null, 'a name inside another word is not a match');
  assert.equal(carries('X: ada.lovelace', ID), 'your email\'s user name');
  assert.equal(carries('X: bob@corp.io', ID), 'an email address');
  assert.equal(carries('Authorization: Bearer abc123', ID), null);
  assert.equal(carries('X: Ada', { name: 'Ada', email: '' }), null, 'a short single name is too common to count');
});

test('headers are found in JSON (keys and --header args), in rc files, and through comments', () => {
  const j = headersInJson({ a: { headers: { X: 'v' } }, args: ['--header', 'Y: w', '--header=Z: q'], env: { USER_AGENT: 'u' }, other: 'no' });
  assert.deepEqual(j.map((h) => h.value).sort(), ['Y: w', 'Z: q', 'u', 'v']);
  assert.deepEqual(headersInRc('-H "A: b"\n# header = "no"\n--user-agent x\n', 'curl').map((h) => h.value), ['A: b', 'x']);
  assert.deepEqual(headersInRc('header = C: d\n', 'wget').map((h) => h.value), ['C: d']);
  assert.deepEqual(JSON.parse(stripJsonc('{ // c\n "u": "http://x", /* b */ "h": [1,],\n}')), { u: 'http://x', h: [1] });
});

test('the scan: global headers are EXPOSED, scoped ones REVIEW, a broken file UNKNOWN, a plain token nothing', () => {
  const r = scanHeaders({ home, env: CLEAN });
  const by = Object.fromEntries(r.findings.map((f) => [`${f.file.replace(home, '~')} ${f.where}`, `${f.status} ${f.carries}`]));
  assert.deepEqual(by, {
    '~/.gitconfig header "From"': 'EXPOSED your email',
    '~/.gitconfig header "X-Requested-By"': 'REVIEW your name',
    '~/.curlrc header "X-Contact"': 'EXPOSED your name',
    '~/.claude/settings.json header "X-User"': 'REVIEW your email',
    '~/.cursor/mcp.json mcpServers.other header "X-Operator"': 'REVIEW an email address',
  });
  assert.deepEqual(r.unread.map((u) => u.file.replace(home, '~')), ['~/.codeium/windsurf/mcp_config.json']);
});

test('header variables in the environment are read too', () => {
  const r = scanHeaders({ home: mkdtempSync(join(tmpdir(), 'wardlatch-empty-')), env: { OTEL_EXPORTER_OTLP_HEADERS: 'a=1,x-user=ada.lovelace@example.org', GIT_AUTHOR_EMAIL: ID.email } });
  assert.deepEqual(r.findings.map((f) => [f.file, f.carries]), [['$OTEL_EXPORTER_OTLP_HEADERS', 'your email']]);
});

test('the command: EXPOSED exits 1, names the file and header, and never prints the value or who you are', () => {
  const r = cli(['--incident', 'identity-headers-2026-10', '--paths', home], { ...CLEAN, HOME: home });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /EXPOSED  ~\/\.gitconfig · header "From"  carries your email, sent to every git remote/);
  assert.match(r.stdout, /UNKNOWN  ~\/\.codeium\/windsurf\/mcp_config\.json/);
  assert.doesNotMatch(r.stdout, /lovelace|Lovelace|someone@|abc123/);
  const j = cli(['--incident', 'identity-headers-2026-10', '--json', '--paths', home], { ...CLEAN, HOME: home });
  assert.doesNotMatch(j.stdout, /lovelace|Lovelace|someone@|abc123/);
  assert.ok(JSON.parse(j.stdout).results.some((x) => x.status === 'EXPOSED' && x.carries === 'your email'));
});

test('a home with no header settings is SAFE and says what it could not cover', () => {
  // --paths names an empty folder: one that isn't there is UNKNOWN (test/review2-0.1.9.test.mjs, M3)
  const r = cli(['--incident', 'identity-headers-2026-10', '--paths', mkdtempSync(join(tmpdir(), 'wardlatch-none-root-'))], { ...CLEAN, HOME: mkdtempSync(join(tmpdir(), 'wardlatch-none-')) });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /SAFE     no name or email in the 0 header settings/);
  assert.match(r.stdout, /no git name or email is set/);
  assert.match(r.stdout, /not covered: an agent that adds your details itself/);
});

// ---- from the 0.1.8 chief-engineer review (22 Oct 2026) ------------------------------------------------------------

test('a hostile config can\'t crash or stall the scan: deep nesting, a huge array, a 2 MB token', () => {
  const h = mkdtempSync(join(tmpdir(), 'wardlatch-hostile-'));
  const repo = join(h, 'code', 'app'); mkdirSync(join(repo, '.git'), { recursive: true });
  writeFileSync(join(repo, '.mcp.json'), '['.repeat(20000) + ']'.repeat(20000));
  mkdirSync(join(h, '.cursor'), { recursive: true });
  writeFileSync(join(h, '.cursor', 'mcp.json'), JSON.stringify({ headers: Array(300000).fill('x'), mcpServers: { a: { headers: { Authorization: `Bearer ${'A'.repeat(2_000_000)}` } } } }));
  writeFileSync(join(h, '.curlrc'), 'header = "From: ada.lovelace@example.org"\n');
  const t = Date.now();
  const r = scanHeaders({ home: h, env: { ...CLEAN, GIT_AUTHOR_EMAIL: ID.email }, roots: [join(h, 'code')] });
  assert.ok(Date.now() - t < 10000, 'the scan took too long');
  assert.ok(r.findings.some((f) => f.where === 'header "From"'), 'the files after the hostile ones are still scanned');
});

test('wget spells its commands any way (useragent, user-agent, UserAgent), and Codex puts headers in a [..._headers] table', () => {
  assert.deepEqual(headersInRc('useragent = a@b.co\nuser-agent = c\nUserAgent=d\nHEADER = X: e\nother = f\n', 'wget').map((x) => x.value), ['a@b.co', 'c', 'd', 'X: e']);
  const t = headersInToml('[mcp_servers.x.http_headers]\n"X-Email" = "ada.lovelace@example.org"\n\n[mcp_servers.x]\ncommand = "npx"\n');
  assert.deepEqual(t.map((x) => x.where), ['line 2']);
});

test('curl\'s short options are case-sensitive: -a (--append) and -h (--help) are not headers', () => {
  assert.deepEqual(headersInRc('-a x@y.com\n-h\n-H "X: 1"\n-A agent\n--HEADER "Y: 2"\n', 'curl').map((x) => x.value), ['X: 1', 'agent', 'Y: 2']);
});

test('only a value\'s own key, or the key right above it, makes it a header: a project folder named request-headers does not', () => {
  const j = headersInJson({ projects: { '/x/request-headers': { history: [{ display: 'mail bob@corp.com' }] } }, mcpServers: { a: { headers: { 'X-Op': 'v' } } } });
  assert.deepEqual(j.map((x) => x.where), ['mcpServers.a.headers.X-Op']);
  assert.equal(stripJsonc('{"a": "x,}", "b": [1,],}'), '{"a": "x,}", "b": [1]}', 'text inside strings is never changed');
});
