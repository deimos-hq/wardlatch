// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The coding standard in CONTRIBUTING.md, checked by machine wherever a rule can be. Most rules are the README's
// promises in code form: Wardlatch sends nothing but test connections, changes nothing, never turns certificate
// checking off except to see whether a test host is up, starts no shell on the host, and has no dependencies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => {
  if (['.git', 'node_modules'].includes(e.name)) return [];
  const p = join(d, e.name);
  return e.isDirectory() ? walk(p) : [relative(ROOT, p)];
});
const FILES = walk(ROOT);
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
const SHIPPED = FILES.filter((f) => /^(bin|lib)\/[^/]+\.mjs$/.test(f));        // the code users run
const SOURCE = FILES.filter((f) => /\.(mjs|sh|ya?ml)$/.test(f) && f !== 'fix/fix-macos.sh');
const VERBATIM = ['LICENSE', 'LICENSES/Apache-2.0.txt'];                       // licence texts stay exactly as published
const TEXT = FILES.filter((f) => (/\.(mjs|sh|ya?ml|md|json|toml|txt|pem)$/.test(f) || ['NOTICE', '.gitignore'].includes(f)) && !VERBATIM.includes(f));
const imports = (src) => [...src.matchAll(/^\s*import\b[^'"]*?from\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/gm)].map((m) => m[1] ?? m[2]);
const named = (src, mod) => [...src.matchAll(new RegExp(`import\\s*\\{([^}]*)\\}\\s*from\\s*'${mod}'`, 'g'))].flatMap((m) => m[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0]).filter(Boolean));

test('every source file opens with its licence and copyright (fix/fix-macos.sh is covered by REUSE.toml instead)', () => {
  assert.ok(SOURCE.length >= 12);
  for (const f of SOURCE) {
    const head = read(f).split('\n').slice(0, 4).join('\n');
    // REUSE-IgnoreStart (a pattern, not this file's licence)
    assert.match(head, /SPDX-License-Identifier: Apache-2\.0/, f);
    // REUSE-IgnoreEnd
    assert.match(head, /Copyright 2026 Deimos AI LLC/, f);
  }
  assert.match(read('REUSE.toml'), /path = "fix\/fix-macos\.sh"/);
});

test('zero dependencies: package.json declares none, and code imports only Node built-ins and its own files', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const k of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) assert.equal(pkg[k], undefined, k);
  for (const f of FILES.filter((x) => x.endsWith('.mjs'))) for (const m of imports(read(f))) assert.match(m, /^(node:|\.\.?\/)/, `${f} imports ${m}`);
});

test('child processes get an argument list, never a host shell', () => {
  for (const f of SHIPPED) {
    const src = read(f);
    for (const fn of named(src, 'node:child_process')) assert.ok(['execFile', 'execFileSync'].includes(fn), `${f} imports ${fn}`);
    assert.doesNotMatch(src, /\bshell\s*:\s*true/, f);
    assert.doesNotMatch(src, /\beval\s*\(|\bnew Function\s*\(/, f);
  }
});

test('changes nothing: the shipped code imports no function that writes, moves or deletes files', () => {
  const WRITES = /^(write|writev|writeFile|appendFile|mkdir|mkdtemp|rm|rmdir|unlink|rename|copyFile|cp|chmod|lchmod|fchmod|chown|lchown|fchown|symlink|link|truncate|ftruncate|utimes|lutimes|futimes)(Sync)?$|^createWriteStream$/;
  for (const f of SHIPPED) {
    const src = read(f);
    assert.doesNotMatch(src, /from\s*'node:fs\/promises'|from\s*'fs'|require\(\s*'fs'\s*\)\.(write|append|rm|unlink)/, f);
    for (const fn of named(src, 'node:fs')) assert.doesNotMatch(fn, WRITES, `${f} imports ${fn}`);
    // A file may be opened, but only to read: O_RDONLY, and no flag that writes or creates.
    for (const [, flags] of src.matchAll(/\bopen(?:Sync)?\(([^)]*)\)/g)) {
      assert.match(flags, /O_RDONLY/, `${f}: open(${flags})`);
      assert.doesNotMatch(flags, /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND|['"][^'"]*[wa+][^'"]*['"]/, `${f}: open(${flags})`);
    }
  }
});

test('sends nothing but test connections: only lib/probe.mjs opens network connections', () => {
  for (const f of SHIPPED.filter((x) => x !== 'lib/probe.mjs')) {
    const src = read(f);
    for (const m of imports(src)) assert.doesNotMatch(m, /^node:(http|https|http2|tls|net|dgram|dns)$/, `${f} imports ${m}`);
    assert.doesNotMatch(src, /\bfetch\s*\(|\bWebSocket\b|XMLHttpRequest/, f);
  }
});

test('certificate checking is never switched off, except the one reachability handshake that sends nothing', () => {
  const all = SHIPPED.map((f) => [f, read(f)]);
  const off = all.flatMap(([f, src]) => (src.match(/rejectUnauthorized\s*:\s*false/g) ?? []).map(() => f));
  assert.deepEqual(off, ['lib/probe.mjs'], 'exactly one: reachable() in lib/probe.mjs');
  assert.match(read('lib/probe.mjs'), /export function reachable[\s\S]*?rejectUnauthorized: false[\s\S]*?s\.end\(\); res\(\{ up: true/);
  for (const [f, src] of all) {
    assert.doesNotMatch(src, /NODE_TLS_REJECT_UNAUTHORIZED|--insecure|['"\s]-k['"\s]|--no-check-certificate|CERT_NONE|_create_unverified_context|verify\s*=\s*False|check_hostname\s*=\s*False/, f);
  }
});

test('layout: UTF-8 text with LF line ends, no tabs, no trailing spaces, a final newline', () => {
  assert.ok(TEXT.length >= 20);
  for (const f of TEXT) {
    const src = read(f);
    assert.ok(!src.includes('\r'), `${f}: CR`);
    assert.ok(!src.includes('\uFFFD'), `${f}: not UTF-8`);
    assert.ok(src.endsWith('\n'), `${f}: final newline`);
    src.split('\n').forEach((line, i) => {
      assert.ok(!line.includes('\t'), `${f}:${i + 1}: tab`);
      assert.ok(!/ +$/.test(line), `${f}:${i + 1}: trailing space`);
    });
  }
});
