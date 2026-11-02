// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Imported first by bin/wardlatch.mjs. A crash inside Wardlatch means the machine was not fully checked: exit 2 ("could
// not be tested"), never Node's default 1, which the exit-code contract reads as "something is exposed", unless an
// EXPOSED line was already printed (the CLI sets process.exitCode to 1 as it prints one), which a crash must not hide.
// A file of Wardlatch's own that fails to load still exits 1: nothing of Wardlatch's runs before that.
// An error's message can carry a path from the disk: it is escaped like everything else printed (lib/escape.mjs). Up to
// round 4 the whole stack was escaped and every \x0a in the result turned back into a line break, which also turned the
// four printable characters \x0a in a path into one: a folder named u\x0aSAFE ... printed "SAFE ..." as a line of its
// own on stderr, under a crash that exits 2 (round 3's re-read 2). c5ad2a9 escaped the stack a line at a time instead
// and said a line break inside a message stayed escaped; it did not, because the split took the message's own line
// breaks too, and a REAL line break in a path (APFS takes one in a name) started a verdict line of its own just the
// same (F-c5a-1, round 4's strict audit, MEASURED).
// So the message and the frames are escaped apart. The message is ONE string, taken from the error itself and never
// guessed from the text, so every line break inside it is written \x0a and none of it can start a line; the frames,
// which Wardlatch's own code and Node write, keep their line breaks, one frame a line.
import { escapeHidden } from './escape.mjs';

// A stack frame as Node writes one: leading blank space, then "at ". Nothing from the disk reaches the start of a line
// here, so this is the one shape a line break is kept in front of.
const FRAME = /^\s+at /;
/** The stack text split into the message part and the rest, using the error's OWN message to find the end: a message
 *  holding "\n    at " cannot move the boundary. With no message to go by (a thrown string, an error with none) the
 *  whole text is the rest, and every line break in it is then decided by the frame shape alone. */
const parts = (e) => {
  const raw = String(e?.stack ?? e);
  const msg = typeof e?.message === 'string' && e.message ? e.message : '';
  const at = msg ? raw.indexOf(msg) : -1;
  const end = at === -1 ? 0 : at + msg.length;
  return [raw.slice(0, end), raw.slice(end)];
};
/** `rest` escaped, keeping a line break only where the line after it is a frame; any other line break is written
 *  \x0a, so a path carried into the text cannot start a line of its own. */
const after = (rest) => {
  const lines = rest.split('\n');
  let out = escapeHidden(lines[0]);
  for (let i = 1; i < lines.length; i++) out += (FRAME.test(lines[i]) ? '\n' : '\\x0a') + escapeHidden(lines[i]);
  return out;
};

const crashed = (e) => {
  const code = process.exitCode === 1 ? 1 : 2;
  const [head, rest] = parts(e);
  const text = escapeHidden(head) + after(rest);
  process.stderr.write(`Wardlatch stopped on an error, so this machine was not fully checked (exit ${code}): ${text}\n`);
  process.exit(code);
};
process.on('uncaughtException', crashed);
process.on('unhandledRejection', crashed);
