// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The guardrails' own wiring, read as text: the workflows give each job only the token it needs and the concurrency the
// release gate relies on, and the documents say what the gates do, no more. Nothing here touches bin/ or lib/, so the
// mutation copies don't run this test.
import './support/no-real-home.cjs';
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

test('ci.yml: on main every commit keeps its own critical-mutants run (the release gate needs it on the release commit); a pull request\'s new push cancels its last', () => {
  const j = jobs('.github/workflows/ci.yml')['critical-mutants'];
  assert.ok(j, 'the critical-mutants job');
  const c = /\n {4}concurrency:\n {6}group: (.*)\n {6}cancel-in-progress: (.*)\n/.exec(j.text);
  assert.ok(c, 'it has a concurrency group');
  // a group keeps one running and one pending run, and a newly queued one cancels the pending one: on a push the group
  // must be the commit itself, or a commit pushed between two others could end cancelled
  assert.match(c[1], /^critical-mutants-\$\{\{ github\.event_name == 'pull_request' && github\.ref \|\| github\.sha \}\}$/);
  assert.equal(c[2], "${{ github.event_name == 'pull_request' }}");
});

// ---- what the documents say about the gates --------------------------------------------------------------------------
const DOCS = ['README.md', 'CONTRIBUTING.md', 'GOVERNANCE.md', 'ASSURANCE_CASE.md', 'CHANGELOG.md', 'docs/ARCHITECTURE.md', 'docs/RELEASING.md'];
// a document's sentences: its paragraphs and list items, lines folded, split after "." or ";" before a capital; of
// CHANGELOG.md only what is not released yet (a past release's entry records what was said then)
const text = (f) => (f === 'CHANGELOG.md' ? read(f).split(/\n## \[(?!Unreleased)/)[0] : read(f));
const sentences = (f) => text(f).split(/\n\s*\n|\n\s*(?:[-*]|\d+\.) /).flatMap((p) => p.replace(/\s*\n\s*/g, ' ').split(/(?<=[.;])\s+(?=[A-Z`(*[])/));

test('CONTRIBUTING says which files the mutation gate plants in, as scripts/mutate.mjs chooses them', () => {
  assert.match(read('scripts/mutate.mjs'), /^const all = \[\.\.\.readdirSync\(join\(REPO, 'lib'\)\)\.filter\(\(f\) => f\.endsWith\('\.mjs'\)\)\.map\(\(f\) => `lib\/\$\{f\}`\), 'bin\/wardlatch\.mjs'\];$/m,
    'top-level lib/*.mjs and bin/wardlatch.mjs: not lib/incidents/, not other files in bin/');
  const critical = read('CONTRIBUTING.md').replace(/\s*\n\s*/g, ' ').split(' - **').find((p) => p.startsWith('Critical mutants**'));
  assert.ok(critical, 'the Critical mutants item');
  assert.match(critical, /in `bin\/wardlatch\.mjs` and `lib\/\*\.mjs`/);
  assert.doesNotMatch(critical, /in `bin\/` and `lib\/`/);
});

test('no document says CI runs on every push (it runs on pull requests and pushes to main), or lists OpenSSF Scorecard among the checks on every pull request (it runs on pushes to main and weekly)', () => {
  assert.match(read('.github/workflows/ci.yml'), /^on:\n {2}push: \{ branches: \[main\] \}\n {2}pull_request:\n[^ ]/m, 'ci.yml runs on pushes to main and pull requests only');
  const on = read('.github/workflows/scorecard.yml');
  assert.doesNotMatch(on.slice(0, on.indexOf('\njobs:')), /pull_request/, 'scorecard.yml runs on no pull request');
  for (const f of DOCS) {
    for (const s of sentences(f)) {
      assert.doesNotMatch(s, /\b(?:every|each) push and pull request/, `${f}: ${s.slice(0, 300)}`);
      if (/every pull request/.test(s)) assert.doesNotMatch(s, /Scorecard/, `${f}: ${s.slice(0, 300)}`);
    }
  }
});

test('no document says the release workflow repeats the release gate\'s checks without saying what it does instead of the clean checkout of main', () => {
  let seen = 0;
  for (const f of DOCS) {
    for (const s of sentences(f)) {
      if (!/release workflow repeats/.test(s)) continue;
      seen++;
      assert.match(s, /on `main` instead of the clean checkout of `main`/, `${f}: ${s.slice(0, 300)}`);
    }
  }
  assert.ok(seen >= 3, `the claim is made in CHANGELOG.md, GOVERNANCE.md and docs/RELEASING.md (seen ${seen})`);
});
