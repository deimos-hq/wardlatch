// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// A differential of 0.1.12's third draft against 0.1.11, 2 Nov 2026 (seat 10): about 250,000 generated cases, and each of
// these had a row on 0.1.11 and read SAFE there. Nothing a released version found may go. Nothing connects.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { chmodSync } from 'node:fs';
import { join } from 'node:path';
import { fresh, put, cli, NEW, KEYS, WP, HDR, repoWith, brief, has, safeOnly } from './support/seat7-lib.mjs';
import { headersInToml, parseGitConfig, carries } from '../lib/headers.mjs';

const M = 'ada@example.org', H = `[h.headers]\nk = "${M}"\n`;
const found = (t) => headersInToml(t).some((h) => h.value.includes(M));

test('one bad line does not cost the headers after it', () => {
  assert.ok(found(H), 'the control');
  for (const [name, text] of Object.entries({
    'a no-break space before a table': `\u00a0${H}`,
    'a byte-order mark mid-file, two files joined': `a = 1\n\ufeff${H}`,
    'an array never closed': `args = ["a",\n  "b"\n\n${H}`,
    'a stray bracket in a value': `x = a[\n${H}`,
    'a string never closed in an array': `x = ["a", "b]\n${H}`,
    'an inline table holding an array never closed': `x = { a = [1\n${H}`,
    'a key missing a quote': `[h.headers]\n"k = "${M}"\n`,
    'a path that ends in a backslash': `path = "C:\\temp\\\n${H}`,
    'a # inside a key': `x-header# = "${M}"\n`,
  })) assert.ok(found(text), name);
});

test('escapes and line breaks in args', () => {
  for (const v of [`X: ada\\t@example.org`, `X:\\n ${M}`]) assert.ok(headersInToml(`args = ["-H", "${v}"]\n`).length, v);
  assert.ok(found(`args = ['-H', 'X: ${M}']\n`));
});

test('git: a value is matched as git reads it and as the file says it', () => {
  assert.ok(parseGitConfig(`[http]\n\textraHeader = ada\\t@example.org\n`).headers[0].value.includes('ada\\t@example.org'));
  assert.equal(parseGitConfig(`[http]\n\textraHeader = "X: ${M}"\n`).headers[0].value, `X: ${M}`, 'the control: no second form where they agree');
  const g = parseGitConfig('[user]\n\tname = Ada "Ace" Lovelace\n');
  const id = { name: g.name, email: '', raw: g.raw };
  assert.equal(carries('Ada Ace Lovelace', id), 'your name');
  assert.equal(carries('by Ada "Ace" Lovelace', id), 'your name');
});

test('an RSA public key followed by a private key has a row: cat pub.der key.der, which OpenSSL 3 loads', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pub = publicKey.export({ type: 'pkcs1', format: 'der' }), key = privateKey.export({ type: 'pkcs1', format: 'der' });
  const scan = (body) => cli(NEW, [...KEYS, '--paths', repoWith(join(fresh('k'), 'r'), { 'k.bin': body })]);
  assert.equal(scan(pub).code, 0, 'the control: the public key alone is quiet');
  const r = scan(Buffer.concat([pub, key]));
  assert.ok(!safeOnly(r), brief(r));
});

const plugin = (d, main, v) => put(join(d, main), `<?php\n/*\n * Version: ${v}\n */\n`);
test('a folder holding both listed plugins\' main files is checked as both', () => {
  const p = join(fresh('both'), 'plugins'), f = join(p, 'updraftplus-seo-by-rank-math-pro');
  plugin(f, 'updraftplus.php', '1.0.0'); plugin(f, 'rank-math-pro.php', '3.0.122');
  const r = cli(NEW, [...WP, '--paths', p]);
  assert.ok(has(r, 'EXPOSED'), brief(r));
});

test('a plugins folder that can be entered and not listed still answers for a listed name', { skip: process.getuid?.() === 0 }, () => {
  const root = fresh('x'), p = join(root, 'backup', 'plugins'); plugin(join(p, 'seo-by-rank-math-pro'), 'rank-math-pro.php', '3.0.123');
  chmodSync(p, 0o311);
  const r = cli(NEW, [...WP, '--paths', root]);
  chmodSync(p, 0o755);
  assert.ok(has(r, 'EXPOSED'), brief(r));
});
