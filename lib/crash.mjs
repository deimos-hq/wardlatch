// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Imported first by bin/wardlatch.mjs. A crash inside Wardlatch means the machine was not fully checked: exit 2 ("could
// not be tested"), never Node's default 1, which the exit-code contract reads as "something is exposed", unless an
// EXPOSED line was already printed (the CLI sets process.exitCode to 1 as it prints one), which a crash must not hide.
// A file of Wardlatch's own that fails to load still exits 1: nothing of Wardlatch's runs before that.
// An error's message can carry a path from the disk: it is escaped like everything else printed (lib/escape.mjs), a
// line at a time, so the stack keeps its own line breaks and nothing in the text can make one. Up to round 4 the whole
// stack was escaped and every \x0a in the result turned back into a line break, which also turned the four printable
// characters \x0a in a path into one: a folder named u\x0aSAFE ... printed "SAFE ..." as a line of its own on stderr,
// under a crash that exits 2 (round 3's re-read 2). A line break inside a message (a path holding one) stays escaped.
import { escapeHidden } from './escape.mjs';

const crashed = (e) => {
  const code = process.exitCode === 1 ? 1 : 2;
  const text = String(e?.stack ?? e).split('\n').map(escapeHidden).join('\n');
  process.stderr.write(`Wardlatch stopped on an error, so this machine was not fully checked (exit ${code}): ${text}\n`);
  process.exit(code);
};
process.on('uncaughtException', crashed);
process.on('unhandledRejection', crashed);
