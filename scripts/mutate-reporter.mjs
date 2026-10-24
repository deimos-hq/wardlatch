// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The test reporter scripts/mutate.mjs runs the suite with (node --test --test-reporter=<this file>): one JSON line per
// test that passed or failed, with the file it is in, so the script can tell a named failing test from a crash and run
// that one test again on its own. Nothing else is printed. Each line carries "wardlatch-mutate": 1, so nothing a test
// prints can pass for one.
import { relative } from 'node:path';

export default async function* report(source) {
  for await (const { type, data } of source) {
    if (type !== 'test:pass' && type !== 'test:fail') continue;
    yield `${JSON.stringify({
      'wardlatch-mutate': 1,
      ev: type === 'test:pass' ? 'pass' : 'fail',
      name: String(data.name),
      nesting: data.nesting,
      file: data.file ? relative(process.cwd(), data.file) : null,
      todo: data.todo !== undefined && data.todo !== false,
      skip: data.skip !== undefined && data.skip !== false,
    })}\n`;
  }
}
