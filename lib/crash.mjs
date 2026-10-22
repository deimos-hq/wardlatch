// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Imported first by bin/wardlatch.mjs. A crash inside Wardlatch means the machine was not checked: exit 2 ("could not be
// tested"), never Node's default 1, which the exit-code contract reads as "something is exposed".
const crashed = (e) => {
  process.stderr.write(`Wardlatch stopped on an error, so this machine was not checked (exit 2): ${e?.stack ?? e}\n`);
  process.exit(2);
};
process.on('uncaughtException', crashed);
process.on('unhandledRejection', crashed);
