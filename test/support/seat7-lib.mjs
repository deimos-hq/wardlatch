// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// test/seat7.test.mjs's rig. Nothing here connects. Each CLI run gets a fresh HOME, a fixed PATH and the rig's TMPDIR.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync, chmodSync, utimesSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
export const NEW = fileURLToPath(new URL('../..', import.meta.url));
export const RIG = mkdtempSync(join(tmpdir(), 'wl-seat7-'));
mkdirSync(join(RIG, 'tmp'), { recursive: true });
let n = 0;
export const fresh = (name) => { const d = join(RIG, `${String(++n).padStart(3, '0')}-${name}`); mkdirSync(d, { recursive: true }); return d; };
export const put = (p, body = '') => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); return p; };
export const cli = (tree, args, { home, env = {}, cwd } = {}) => {
  const h = home ?? fresh('home');
  const r = spawnSync(process.execPath, [join(tree, 'bin', 'wardlatch.mjs'), '--json', ...args], { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000, env: { HOME: h, PATH: '/usr/bin:/bin', LANG: 'C', TMPDIR: join(RIG, 'tmp'), ...env } });
  if (!r.stdout) throw new Error(`CONTROL no output, exit ${r.status}: ${r.stderr.slice(0, 400)}`);
  return { code: r.status, rows: JSON.parse(r.stdout).results };
};
export const brief = (r) => `exit ${r.code}: ` + r.rows.map((x) => `${x.status}:${x.kind}:${String(x.what ?? x.file ?? x.path ?? x.dir ?? x.type ?? '').slice(-46)}`).join(' | ');
export const has = (r, s) => r.rows.some((x) => x.status === s);
export const safeOnly = (r) => r.code === 0 && r.rows.length > 0 && r.rows.every((x) => x.status === 'SAFE');
export const gitIn = (cwd, ...args) => {
  const g = spawnSync('/usr/bin/git', args, { cwd, encoding: 'utf8', env: { HOME: join(RIG, 'tmp'), PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' } });
  if (g.status !== 0) throw new Error(`CONTROL git ${args[0]}: ${g.stderr}`);
  return g.stdout;
};
export const repoWith = (d, files) => { mkdirSync(d, { recursive: true }); gitIn(d, 'init', '-q'); for (const [f, b] of Object.entries(files)) put(join(d, f), b); gitIn(d, 'add', '-A'); gitIn(d, 'commit', '-q', '-m', 'x'); return d; };
export const old = (p, when = new Date('2026-01-01T00:00:00Z')) => { utimesSync(p, when, when); return p; };
export const KEYS = ['--incident', 'committed-keys-2026-10', '--no-containers'];
export const WP = ['--incident', 'wordpress-plugins-2026-10', '--no-containers'];
export const LITELLM = ['--incident', 'litellm-2026-10', '--no-containers'];
export const HDR = ['--incident', 'identity-headers-2026-10', '--no-containers'];
export const WF = ['--incident', 'github-actions-2026-10', '--no-containers'];
// DER builders
export const lenBytes = (n) => { if (n < 0x80) return Buffer.from([n]); const b = []; for (let x = n; x; x = Math.floor(x / 256)) b.unshift(x & 255); return Buffer.from([0x80 | b.length, ...b]); };
export const tlv = (tag, body) => Buffer.concat([Buffer.from(Array.isArray(tag) ? tag : [tag]), lenBytes(body.length), body]);
export const kids = (buf) => { // the elements of one DER SEQUENCE, as raw TLVs
  let at = 0; const hdr = (p) => (buf[p + 1] < 0x80 ? [2, buf[p + 1]] : (() => { const m = buf[p + 1] & 0x7f; let l = 0; for (let i = 0; i < m; i++) l = l * 256 + buf[p + 2 + i]; return [2 + m, l]; })());
  const [h0, l0] = hdr(0); at = h0; const out = [];
  while (at < h0 + l0) { const [h, l] = hdr(at); out.push(buf.subarray(at, at + h + l)); at += h + l; }
  return out;
};
