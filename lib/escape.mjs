// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The one escaper. Every name, path, version and value Wardlatch prints comes from somewhere it does not control: a
// folder or file name on disk, a git author, a container's name, a version string read from a file, the incident data.
// What it prints is read by a person, and as often by the person's AI agent, which acts on a "Next step". So no
// character that a reader cannot see, or that changes how the rest of the line reads, reaches either raw.
//
// Up to this fix the escaper (then bin/wardlatch.mjs clean()) took C0 and C1 control characters and nothing else, and
// --json took DEL and C1 only (W1, red-team pass of 31 Oct 2026). A folder named with U+2028 (LINE SEPARATOR) started
// a line of its own in many renderers and in every language model, U+202E reversed what followed it, U+200B hid inside
// a word, and the tag block (U+E0000-U+E007F) is invisible on screen and read as ASCII by a language model: the person
// saw "proj", an agent reading the same line read an order. APFS accepts every one of these names.
//
// Escaped, by Unicode general category: Cc (controls), Cf (format: bidi overrides and isolates, zero-width characters,
// the byte-order mark, soft hyphen, the tag characters), Cs (a lone surrogate), Co (private use), Cn (unassigned: a
// character this Node does not know cannot be shown to be visible), Zl and Zp (the line and paragraph separators), and
// the whole tag block, its unassigned code points included. Printable text from the disk is printed as it is, so a name
// can still say anything a name can say in plain letters (a look-alike slash, U+2215, is printable): the escaper makes
// the hidden visible; it cannot make a planted sentence untrue.
const HIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\u{E0000}-\u{E007F}]/gu;

/** `s` with every hidden character written out: \x1b for one up to U+00FF (as since 0.1.4), \u{202e} for any other. */
export const escapeHidden = (s) => String(s).replace(HIDDEN, (ch) => {
  const cp = ch.codePointAt(0);
  return cp <= 0xff ? `\\x${cp.toString(16).padStart(2, '0')}` : `\\u{${cp.toString(16)}}`;
});

/** A JSON text with every hidden character inside its strings written as a JSON escape ( ; a character past
 *  U+FFFF as its two \u escapes). JSON.parse gives the same value back, so a path field still names the real file, and
 *  the text a reader or an agent is given holds no hidden character. Hidden characters only ever sit inside strings
 *  (JSON's own syntax is ASCII), except the line breaks and tabs JSON.stringify lays its text out with: it escapes
 *  those inside a string itself, so a raw one is layout, and is kept. */
export const escapeJsonHidden = (text) => String(text).replace(HIDDEN, (ch) => (ch === '\n' || ch === '\r' || ch === '\t' ? ch
  : [...Array(ch.length).keys()].map((i) => `\\u${ch.charCodeAt(i).toString(16).padStart(4, '0')}`).join('')));
