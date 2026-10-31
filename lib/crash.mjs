// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Imported first by bin/wardlatch.mjs. A crash inside Wardlatch means the machine was not fully checked: exit 2 ("could
// not be tested"), never Node's default 1, which the exit-code contract reads as "something is exposed", unless an
// EXPOSED line was already printed (the CLI sets process.exitCode to 1 as it prints one), which a crash must not hide.
// A file of Wardlatch's own that fails to load still exits 1: nothing of Wardlatch's runs before that.
// An error's message can carry a path from the disk: it is escaped like everything else printed (lib/escape.mjs).
import { escapeHidden } from './escape.mjs';

const crashed = (e) => {
  const code = process.exitCode === 1 ? 1 : 2;
  process.stderr.write(`Wardlatch stopped on an error, so this machine was not fully checked (exit ${code}): ${escapeHidden(e?.stack ?? e).replace(/\\x0a/g, '\n')}\n`);
  process.exit(code);
};
process.on('uncaughtException', crashed);
process.on('unhandledRejection', crashed);
