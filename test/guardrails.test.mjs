// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The guardrails' own wiring, read as text: the workflows give each job only the token it needs and the concurrency the
// release gate relies on. These files never touch bin/ or lib/, so the mutation copies don't run this test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
// a workflow's jobs: { id: { text, permissions: { scope: level }, needs } }, read from its two-space job keys
const jobs = (f) => {
  const src = read(f), at = src.indexOf('\njobs:\n');
  assert.ok(at >= 0, `${f} has no jobs`);
  const out = {};
  for (const part of src.slice(at + 7).split(/\n(?= {2}[\w-]+:\n)/)) {
    const id = /^ {2}([\w-]+):/.exec(part)?.[1];
    if (!id) continue;
    const perms = /\n {4}permissions:\n((?: {6}.*\n)+)/.exec(`${part}\n`)?.[1] ?? '';
    const permissions = Object.fromEntries([...perms.matchAll(/^ {6}([\w-]+): (\w+)/gm)].map((m) => [m[1], m[2]]));
    out[id] = { text: part, permissions, needs: /\n {4}needs: \[?([\w-, ]+)\]?/.exec(part)?.[1].split(',').map((s) => s.trim()) ?? [] };
  }
  return out;
};

test('release.yml: the release gate runs in a job of its own with a read-only token; the job that can write and sign needs it', () => {
  const all = jobs('.github/workflows/release.yml');
  const gates = Object.entries(all).filter(([, j]) => /release-check\.mjs --ci/.test(j.text));
  assert.equal(gates.length, 1, 'one job runs the release gate');
  const [gate, g] = gates[0];
  assert.deepEqual(g.permissions, { contents: 'read', checks: 'read' }, 'the gate reads the code and the checks, nothing more');
  assert.doesNotMatch(g.text, /id-token|attest|gh release/, 'the gate job neither signs nor publishes');
  for (const [id, j] of Object.entries(all)) {
    if (id === gate) continue;
    if (Object.values(j.permissions).includes('write')) {
      assert.ok(j.needs.includes(gate), `${id} can write, so it runs only after the gate passed (needs: ${gate})`);
      assert.equal(j.permissions.checks, undefined, `${id} doesn't need to read the checks`);
      assert.doesNotMatch(j.text, /release-check/, `${id} doesn't run the gate itself with its token`);
    }
  }
});
