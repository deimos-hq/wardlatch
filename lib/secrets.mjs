// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Keys committed to code (the lesson of the TiDB Cloud breach): scan the files each local git repository tracks for
// high-confidence secret formats. Read-only. A finding never prints the secret: only its type, file, line and a mask.
// Current files only; history needs a dedicated scanner (gitleaks, trufflehog), which the fix text names.
import { join } from 'node:path';
import { readCapped, readHead, pathState, eachPiece } from './files.mjs';
import { git, gitError, ownGitDir } from './git.mjs';

export const PATTERNS = [
  { type: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { type: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { type: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'Stripe live key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
];
// two searches, one after the other: a single pattern with [\s\S]* between them backtracked on every "type" line
// (3.6 s for one planted 512 KB file in 0.1.8)
// Names that say "this is text". A tracked file with one of these that reads as binary is an anomaly worth a row:
// either something corrupted it, or a NUL was put at the front to hide what is below it from a text scan.
const TEXT_BY_NAME = /(?:^|\/)(?:\.env[^/]*|[^/]*\.(?:sh|bash|zsh|env|ya?ml|json|jsonc|js|mjs|cjs|ts|tsx|jsx|py|rb|php|pl|go|rs|java|cs|sql|tf|tfvars|ini|cfg|conf|toml|properties|txt|md|xml|csv|pem|key|crt|service|dockerfile|gradle|lock)|Dockerfile|Makefile|Procfile|Gemfile|Rakefile|\.npmrc|\.netrc|\.pypirc|\.gitconfig|\.htpasswd)$/i;
const SA_TYPE = /"type"\s{0,64}:\s{0,64}"service_account"/;
const SA_KEY = /"private_key"\s{0,64}:\s{0,64}"-----BEGIN/;
// (in a piece of a larger file, only a "type" that starts in the piece's own range counts: lib/files.mjs eachPiece)
const SA_TYPES = new RegExp(SA_TYPE.source, 'g');
const isServiceAccount = (text, minStart = 0, maxStart = Infinity) => {
  for (const m of text.matchAll(SA_TYPES)) if (m.index >= minStart && m.index < maxStart) return SA_KEY.test(text.slice(m.index));
  return false;
};
// Documentation placeholders (AWS's own example key and the like) are not findings: looked for in the match and the
// 32 characters on each side, never the whole line (one "example.com" anywhere on a minified line hid every key on it).
const PLACEHOLDER = /EXAMPLE|example|XXXXXXXX|your[_-]?key|placeholder|dummy|fake/;
const NEAR = 32, MARK_LINE = 2000, MARK_NEAR = 200;
// Lines a team has already reviewed and marked (Clockford's own marker, gitleaks', detect-secrets').
const ALLOWED = /secrets-ok|gitleaks:allow|pragma:\s*allowlist secret/;

export const mask = (s) => `${s.slice(0, 4)}…(${s.length} chars)`;

// ---- DER: the binary encoding of keys and certificates ----------------------------------------------------------------
// A private key committed in DER (`openssl rsa -outform der`, a .der, .key or .p8 file, or any name) is binary, and up
// to this fix every binary file was skipped: a committed DER private key under a name not in TEXT_BY_NAME was passed
// over with no row and the repository read SAFE. derKind() reads the structure, not the name: one DER element that is
// the whole file, whose fields have the shape of a private key (PKCS #1 RSA, PKCS #8, encrypted PKCS #8, SEC1 EC,
// OpenSSL's DSA) or of a PKCS #12 key store, is a finding; one with the shape of an X.509 certificate is not a secret.
/** One element at `at` → { tag, start, end, next, ber? } (its contents are buf[start, end); the next element starts at
 *  `next`), or null where it isn't one. An indefinite length (0x80: BER, never DER) is read too, for a constructed
 *  element: its contents are elements up to an end-of-contents (00 00), and `ber` is set. Up to this fix it was refused,
 *  and a PKCS #12 store with an indefinite outer length, which openssl reads, was skipped with no row (R2-N3). */
// `clip`: the bytes are the HEAD of a longer file (derPastEnd() below), so an element whose declared length runs past
// them is read as far as the bytes go, with `clipped` set, instead of being refused. Only derPastEnd() sets it.
function derAt(buf, at, nest = 0, clip = false) {
  if (at + 2 > buf.length || nest > 32) return null;
  const tag = buf[at];
  let len = buf[at + 1], hdr = 2;
  if (len === 0x80) {
    if (!(tag & 0x20)) return null;   // a primitive element never has an indefinite length
    for (let p = at + 2; p + 2 <= buf.length;) {
      if (buf[p] === 0 && buf[p + 1] === 0) return { tag, start: at + 2, end: p, next: p + 2, ber: true };
      const k = derAt(buf, p, nest + 1);
      if (!k) return null;
      p = k.next;
    }
    return null;
  }
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || at + 2 + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[at + 2 + i];
    hdr = 2 + n;
  }
  if (at + hdr + len <= buf.length) return { tag, start: at + hdr, end: at + hdr + len, next: at + hdr + len };
  return clip && at + hdr <= buf.length ? { tag, start: at + hdr, end: buf.length, next: buf.length, clipped: true } : null;
}
/** The elements inside a constructed one, or null when they don't fill it exactly. Inside a clipped element (derPastEnd())
 *  the last child may itself be clipped, and then it ends exactly where the bytes do, so the rule below is unchanged:
 *  the children still fill the element. That is enough to tell a PKCS #12 store or a PKCS #8 key from its head, where
 *  everything that names it sits. A child whose own header is cut in half by the cap gives null, and derPastEnd() then
 *  says UNKNOWN rather than naming it: an extra rule for that case would be one no file reaches and no test could hold. */
function derKids(buf, el) {
  const out = [];
  let at = el.start;
  while (at < el.end) { const k = derAt(buf, at, 0, Boolean(el.clipped)); if (!k) return null; out.push(k); at = k.next; }
  return at === el.end ? out : null;
}
const INT = 0x02, OCTETS = 0x04, BITS = 0x03, OID = 0x06, SEQ = 0x30;
const small = (buf, el) => (el.tag === INT && el.end - el.start === 1 ? buf[el.start] : -1);
const oidHex = (buf, el) => (el?.tag === OID ? buf.subarray(el.start, el.end).toString('hex') : '');
const algOid = (buf, el) => { const k = el?.tag === SEQ ? derKids(buf, el) : null; return k?.length ? oidHex(buf, k[0]) : ''; };
// password-based encryption: PKCS #5 (1.2.840.113549.1.5.*) and PKCS #12 (1.2.840.113549.1.12.1.*)
const PBE = /^2a864886f70d0105|^2a864886f70d010c01/;
const PKCS7 = /^2a864886f70d01070[12]$/;   // pkcs7-data, pkcs7-signedData: a PKCS #12 file's content
/** The shape of one SEQUENCE element → { type, key: true } for a private key or a key store, { type: 'certificate' }, or
 *  null for a shape this does not know. */
function shapeOf(buf, top) {
  const k = derKids(buf, top);
  if (!k?.length) return null;
  const v = small(buf, k[0]);
  // a key store whose encoding uses an indefinite length anywhere it is read here is named BER, which it is
  const enc = top.ber || k.some((x) => x.ber) ? 'BER' : 'DER';
  if (k.length === 3 && k[0].tag === SEQ && k[1].tag === SEQ && k[2].tag === BITS && derKids(buf, k[0])) return { type: 'certificate' };
  if ((v === 0 || v === 1) && k.length >= 3 && k[1].tag === SEQ && algOid(buf, k[1]) && k[2].tag === OCTETS) return { type: `private key (${enc}, PKCS #8)`, key: true };
  if (k.length === 2 && k[0].tag === SEQ && PBE.test(algOid(buf, k[0])) && k[1].tag === OCTETS) return { type: `encrypted private key (${enc}, PKCS #8)`, key: true };
  if ((v === 0 || v === 1) && k.length >= 9 && k.every((x) => x.tag === INT)) return { type: `RSA private key (${enc})`, key: true };
  if (v === 0 && k.length === 6 && k.every((x) => x.tag === INT)) return { type: `DSA private key (${enc})`, key: true };
  if (v === 1 && k.length >= 2 && k[1].tag === OCTETS && k.slice(2).every((x) => x.tag === 0xa0 || x.tag === 0xa1)) return { type: `EC private key (${enc})`, key: true };
  if (v === 3 && k[1]?.tag === SEQ && PKCS7.test(algOid(buf, k[1]))) return { type: `PKCS #12 key store (${enc})`, key: true };
  return null;
}
/** Where the bytes of `buf` from `from` on stop being anything but line ends: buf.length less its trailing CR and LF. */
const bodyEnd = (buf, from) => { let end = buf.length; while (end > from && (buf[end - 1] === 0x0a || buf[end - 1] === 0x0d)) end--; return end; };
/** What a DER (or BER) file is → { type, key: true } for a private key or a key store, { type: 'certificate' }, or null
 *  when its first element is not of a shape this knows (then nothing is claimed). A key is a key whatever follows it:
 *  openssl loads a DER key with a trailing byte (`openssl pkey -inform DER`, LibreSSL 3.3.6 and OpenSSL 4.0.3, measured
 *  31 Oct 2026), and up to this fix only line ends were allowed after it, so one trailing NUL or space turned the key
 *  into a binary file skipped with no row (R2-N3). After a certificate, the elements that follow are read too, and a key
 *  among them is a key (a certificate and its key in one file); a certificate followed by anything else claims nothing,
 *  as before. */
export function derKind(buf) {
  if (!buf || buf[0] !== SEQ) return null;
  const top = derAt(buf, 0);
  if (!top) return null;
  const kind = shapeOf(buf, top);
  // the end of what follows, less trailing line ends, found once: 81b267d tested "only line ends left?" before each
  // element by copying the rest, and a certificate followed by 16,000 empty elements took 2.9 s (quadratic)
  const end = bodyEnd(buf, top.next);
  if (kind?.key || end === top.next) return kind;
  if (kind?.type !== 'certificate') return null;
  for (let at = top.next; at < end;) {
    const el = buf[at] === SEQ ? derAt(buf, at) : null;
    if (!el) return null;
    const next = shapeOf(buf, el);
    if (next?.key) return next;
    at = el.next;
  }
  return null;
}
// A key or a certificate is a few KB: derKind() is given at most the first DER_MAX bytes of a file, never the whole of a
// larger one, and a key in them is a key whatever follows it. Up to round 4 a file over DER_MAX was not read as DER at
// all (readCapped() gives nothing past its cap), so a DER key followed by more than 1 MB of other bytes, which openssl
// loads, was skipped with no row, in the working tree and from git's index (round 3's re-read 2).
const DER_MAX = 1024 * 1024;
export const DER_MAX_MB = DER_MAX / 1024 / 1024;
/** The end the first element of `buf` declares, or null where `buf` does not begin a SEQUENCE of a stated length. An
 *  indefinite length states none, so it is null here too, and derPastEnd() reads that case from the bytes instead:
 *  returning null for it meant derPastEnd() dropped a BER store over the cap in silence (F2). */
function declaredEnd(buf) {
  if (!buf || buf.length < 2 || buf[0] !== SEQ) return null;
  let len = buf[1], hdr = 2;
  if (len === 0x80) return null;
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || 2 + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[2 + i];
    hdr = 2 + n;
  }
  return hdr + len;
}
/**
 * What a file whose FIRST DER element runs past the bytes read is → { type, key: true } where its head names it,
 * { unread: true } where it does not, or null where the first element is read through inside the bytes (derKind() has
 * already had it) or does not begin a SEQUENCE.
 *
 * 008f5f9 gave derKind() the first DER_MAX bytes so that a key followed by more than a megabyte of other bytes is still
 * found. A store whose OWN outer element is longer than DER_MAX was still skipped, because derAt() refuses an element
 * whose declared length runs past the buffer, and a skip in that loop says nothing: MEASURED at edc4d71 (p12-probe.sh,
 * 1 Nov 2026), a 1,866,487-byte PKCS #12 holding one RSA key -- `openssl pkcs12 -nocerts -nodes` reads the key out of
 * it -- read "SAFE no committed keys found in the files of 1 local repository", exit 0 (B-e85-1, strict audit, BLOCKER).
 * A PKCS #12's version and its authSafe content OID, and a PKCS #8 key's version and algorithm, are in the first few
 * dozen bytes, so reading the head as a clipped element names most of them outright. What it cannot name is UNKNOWN:
 * the bytes were not read, and a file not read is never part of an all-clear.
 *
 * That closed the STATED length only. An indefinite length (0x80: BER, never DER) declares no end at all, so
 * declaredEnd() gave null and this function returned before its clipped read -- and the one length encoding this
 * project had already found a reader for (R2-N3) went back to being skipped in silence over the cap. MEASURED at
 * eccae50 (F2-DER-INDEFINITE.md, 1 Nov 2026): the SAME 1,866,487-byte store, re-wrapped `30 80 ... 00 00` and nothing
 * else changed, read "SAFE no committed keys found in the files of 1 local repository", exit 0, with no row of any
 * kind, while the other three cells of {stated, indefinite} x {under the cap, over it} were all named and both
 * LibreSSL 3.3.6 and OpenSSL 4.0.3 (-legacy) take the same private key out of all four (round-5 re-read #1, F2).
 * For an indefinite length the question "does the element run past the bytes read?" is not asked of a number but of
 * the bytes: the element ends at the end-of-contents (00 00) that derAt() walks the children to find. Where derAt()
 * finds it, every byte of the element was read and derKind() has already had it, so nothing is claimed here -- an
 * unrecognised shape inside bytes that were all read claims nothing, exactly as a stated length under the cap claims
 * nothing. Where derAt() cannot -- the terminator is past the cap, the cap cut it in half, or a child's own header or
 * nested terminator is past it -- the element runs past the bytes read just as an overlong stated length does, and
 * takes the same clipped read, with the same UNKNOWN behind it.
 */
export function derPastEnd(buf) {
  if (!buf || buf.length < 2 || buf[0] !== SEQ) return null;
  const indefinite = buf[1] === 0x80;
  if (indefinite) { if (derAt(buf, 0)) return null; }
  else { const end = declaredEnd(buf); if (end === null || end <= buf.length) return null; }
  const hdr = indefinite ? 2 : buf[1] > 0x80 ? 2 + (buf[1] & 0x7f) : 2;
  const kind = shapeOf(buf, { tag: SEQ, start: hdr, end: buf.length, next: buf.length, clipped: true, ber: indefinite });
  return kind?.key ? kind : { unread: true };
}
const derFinding = (file, kind) => ({ file, type: kind.type, line: 1, masked: `(binary ${/\(BER/.test(kind.type) ? 'BER' : 'DER'}, not shown)` });

// one test per line before the per-pattern work: most lines hold no key at all
const ANY = new RegExp(PATTERNS.map((p) => p.re.source).join('|'));
/** `line` with every match in `hits` replaced by spaces (overlapping matches blanked once). */
function blanked(line, hits) {
  const spans = hits.map(({ m }) => [m.index, m.index + m[0].length]).sort((x, y) => x[0] - y[0]);
  let out = '', at = 0;
  for (const [from, to] of spans) { const f = Math.max(from, at), t = Math.max(to, at); out += line.slice(at, f) + ' '.repeat(t - f); at = t; }
  return out + line.slice(at);
}

/** Findings in `text`. `minStart`/`maxStart`: count only matches that start in that range (characters into `text`),
 *  for a piece of a larger file (lib/files.mjs eachPiece). */
export function scanText(text, { minStart = 0, maxStart = Infinity } = {}) {
  const out = [];
  const lines = text.split('\n');
  const around = (line, m, n) => line.slice(Math.max(0, m.index - n), m.index + m[0].length + n);
  let at = 0;   // where the current line starts in `text`
  lines.forEach((line, i) => {
    const lineAt = at; at += line.length + 1;
    if (!ANY.test(line)) return;
    const hits = PATTERNS.flatMap((p) => [...line.matchAll(p.re)].map((m) => ({ p, m })));
    // every other key on the line, of any kind, is blanked before looking for a placeholder near this one: the docs'
    // example key in a comment beside a real one hid the real one up to b03e7be
    const others = hits.length > 1 ? blanked(line, hits) : line;
    for (const { p, m } of hits) {
      if (lineAt + m.index < minStart || lineAt + m.index >= maxStart) continue;
      const end = m.index + m[0].length;
      if (PLACEHOLDER.test(`${others.slice(Math.max(0, m.index - NEAR), m.index)}${m[0]}${others.slice(end, end + NEAR)}`)) continue;
      // a reviewed-line marker counts on its own line; on a very long (minified) line only near the match. A line a
      // piece only partly holds (it goes on into the previous or next piece) is a long line.
      const partial = (i === 0 && minStart > 0) || (i === lines.length - 1 && maxStart < Infinity);
      if (ALLOWED.test(line.length <= MARK_LINE && !partial ? line : around(line, m, MARK_NEAR))) continue;
      out.push({ type: p.type, line: i + 1, masked: p.type === 'private key' ? '-----BEGIN …PRIVATE KEY-----' : mask(m[0]) });
    }
  });
  if (isServiceAccount(text, minStart, maxStart)) out.push({ type: 'Google service-account key file', line: 1, masked: '{"type": "service_account", …}' });
  return out;
}

/** How a file's text is encoded, from its first bytes (`head`, up to 8,000, as git decides): 'utf8', 'utf16le' or
 *  'utf16be' (UTF-16 that starts with its byte-order mark, as PowerShell 5's Out-File and `>` write it: up to b03e7be it
 *  was skipped as binary), or null for binary, which keys in code are not: a zero byte in the head, or a zero character
 *  in a head that starts with a byte-order mark. One rule: scanRepo() asks it once per file, and textIn() decodes by it. */
export function encodingOf(head) {
  const bom = head[0] === 0xff && head[1] === 0xfe ? 'utf16le' : head[0] === 0xfe && head[1] === 0xff ? 'utf16be' : null;
  if (!bom) return head.subarray(0, 8000).includes(0) ? null : 'utf8';
  return textIn(head.subarray(0, 8000), bom).includes('\0') ? null : bom;
}
/** `buf` decoded as `enc` (encodingOf()), without its byte-order mark. */
export function textIn(buf, enc) {
  if (enc === 'utf8') return buf.toString('utf8');
  const b = buf.subarray(2, buf.length - (buf.length % 2));
  return (enc === 'utf16be' ? Buffer.from(b).swap16() : b).toString('utf16le');
}
// a tracked file deleted in the working tree is read from git's index, up to this size
const MAX_INDEXED = 64 * 1024 * 1024;

/** `git cat-file --batch` output → [{ blob, body } or { blob, missing: true }]. Each object is "<id> blob <size>\n", its
 *  bytes and "\n"; one git no longer has is "<id> missing\n" with no bytes (gone since the size check), and the rest
 *  are still read past it. */
export function parseBatch(out) {
  const objects = [];
  for (let at = 0; at < out.length;) {
    const nl = out.indexOf(0x0a, at);
    if (nl < 0) break;
    const [blob, type, size] = out.subarray(at, nl).toString('latin1').split(' ');
    if (type !== 'blob') { objects.push({ blob, missing: true }); at = nl + 1; continue; }
    objects.push({ blob, body: out.subarray(nl + 1, nl + 1 + Number(size)) });
    at = nl + 1 + Number(size) + 1;
  }
  return objects;
}

/** Tracked files deleted in the working tree ([{ file, blob }]), read from git's store in a few git runs, not one per
 *  file (that took 40 s for 3,000 deletions): `cat-file --batch-check` for their sizes, then `cat-file --batch` for the
 *  text of those up to `max` bytes, one run per `max` bytes of text. One that git doesn't have, or that is larger, is
 *  UNKNOWN. Findings and gaps go into `found`. */
// True for bytes shaped like a private key that derKind() could not read: an outer SEQUENCE whose first element is an
// INTEGER, the version every unencrypted key format and PKCS #12 begin with. Certificates, public keys and signatures
// begin with a SEQUENCE or an OID, so they stay quiet. 30 80 is left out: an indefinite element read to its end is
// derPastEnd()'s to judge, and calling every such file unread is what test/reread-r4.test.mjs's control forbids.
// An ENCRYPTED PKCS #8 key written with non-minimal lengths begins with a SEQUENCE and is not caught here.
const unreadDer = (head, der, enc) => {
  if (!head || head[0] !== SEQ || der || head[1] === 0x80) return false;
  const first = head[1] < 0x80 ? 2 : 2 + (head[1] & 0x7f);
  return head[first] === 2 && (!enc || head[1] >= 0x80);
};
const DER_UNREAD = 'is shaped like a private key in DER, but not one Wardlatch can read, so what it holds was not scanned';

function scanIndexed(repo, parked, found, max) {
  if (!parked.length) return;
  const blobs = [...new Set(parked.map((x) => x.blob))];
  const filesOf = (b) => parked.filter((x) => x.blob === b).map((x) => x.file);
  const gap = (b, why) => { for (const file of filesOf(b)) found.push({ file, unread: `deleted in the working tree, and git's copy ${why}` }); };
  let sizes;
  try {
    sizes = new Map(git(repo, ['cat-file', '--batch-check'], { input: `${blobs.join('\n')}\n`, timeout: 20000 }).split('\n').filter(Boolean)
      .map((l) => l.split(' ')).map(([b, type, size]) => [b, type === 'blob' ? Number(size) : -1]));
  } catch (e) { for (const b of blobs) gap(b, `could not be read (${gitError(e)})`); return; }
  const batches = [[]]; let total = 0;
  for (const b of blobs) {
    const size = sizes.get(b) ?? -1;
    if (size < 0) { gap(b, 'is not in this repository\'s store'); continue; }
    if (size > max) { gap(b, `is over ${max / 1024 / 1024} MB`); continue; }
    if (total + size > max && batches.at(-1).length) { batches.push([]); total = 0; }
    batches.at(-1).push(b); total += size;
  }
  for (const batch of batches.filter((x) => x.length)) {
    let out;
    try { out = git(repo, ['cat-file', '--batch'], { input: `${batch.join('\n')}\n`, timeout: 20000, maxBuffer: max + batch.length * 128, encoding: 'buffer' }); } catch (e) { for (const b of batch) gap(b, `could not be read (${gitError(e)})`); continue; }
    for (const o of parseBatch(out)) {
      if (o.missing) { gap(o.blob, 'is not in this repository\'s store'); continue; }
      const head = o.body[0] === SEQ ? o.body.subarray(0, DER_MAX) : null;
      const der = head ? derKind(head) : null;
      if (der?.key) { for (const file of filesOf(o.blob)) found.push(derFinding(file, der)); continue; }
      // a store or key whose own outer element is longer than the bytes read: named from its head where it can be,
      // and UNKNOWN where it cannot, never skipped in silence (B-e85-1)
      const past = head && !der ? derPastEnd(head) : null;
      if (past?.key) { for (const file of filesOf(o.blob)) found.push(derFinding(file, past)); continue; }
      if (past?.unread) { gap(o.blob, `begins a DER or BER element that runs past the bytes read (at most ${DER_MAX_MB} MB), so what it holds was not read`); continue; }
      const enc = encodingOf(o.body.subarray(0, 8000));
      if (unreadDer(head, der, enc)) { gap(o.blob, DER_UNREAD); continue; }
      if (enc) for (const hit of scanText(textIn(o.body, enc))) for (const file of filesOf(o.blob)) found.push({ file, ...hit });
    }
  }
}

// A text file larger than maxBytes is scanned in pieces that end at line breaks (keys are on one line), up to MAX_TEXT:
// a tracked data file of 14 MB (a fixture, a generated JSON) made 0.1.9's first cut report UNKNOWN on clean machines.
const MAX_TEXT = 512 * 1024 * 1024;
// git's own record of each tracked file: its mode says what it is, which the working tree can't (a link that points into
// a folder that can't be opened would read as an unreadable file), and its blob id says when there is nothing to scan.
const SYMLINK = '120000', GITLINK = '160000', EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391';
export function scanRepo(repo, { maxBytes = 8 * 1024 * 1024, maxText = MAX_TEXT, maxIndexed = MAX_INDEXED } = {}) {
  let entries = [];
  // git with the repository's own config overridden where it could run a program (core.fsmonitor; lib/git.mjs). -t tags
  // each entry: S is a file a sparse checkout leaves out of the working tree on purpose
  try {
    // a .git folder git reads some other repository through (a commondir file, or one git doesn't take as a
    // repository): UNKNOWN, as in the workflow review (lib/git.mjs ownGitDir)
    const elsewhere = ownGitDir(repo);
    if (elsewhere) return { error: `${elsewhere}, so its files were not scanned`, own: true };
    entries = git(repo, ['ls-files', '-s', '-t', '-z'], { timeout: 20000, maxBuffer: 64 * 1024 * 1024 }).split('\0').filter(Boolean)
      .map((e) => { const tab = e.indexOf('\t'); const [tag, mode, blob] = e.slice(0, tab).split(' '); return { tag, mode, blob, file: e.slice(tab + 1) }; });
  } catch (e) { return { error: gitError(e) }; }   // not read: UNKNOWN, never an empty (clean) list
  const found = [], seen = new Set(), parked = [];
  // a piece scan gives each match to exactly one piece (lib/files.mjs eachPiece), so nothing is found twice
  const add = (hit) => found.push(hit);
  for (const { tag, mode, blob, file: f } of entries) {
    // a link is stored as the text of its target, not the target's contents; a submodule is another repository, which
    // is not scanned (as in 0.1.8; the CHANGELOG's known limits); a file in a merge conflict appears once per stage
    if (mode === SYMLINK || mode === GITLINK || seen.has(f)) continue;
    seen.add(f);
    // a tracked file that can't be read was not scanned: say so (0.1.8 skipped it, and a key in it read SAFE), unless
    // git records it as empty (a .gitkeep in a folder a database container has since locked)
    const unread = (why) => { if (blob !== EMPTY_BLOB) found.push({ file: f, unread: why }); };
    const p = join(repo, f);
    const st = pathState(p);
    // skip-worktree (S) and not on disk: a file a sparse checkout leaves out (in a partial clone not even in git's
    // store), not scanned, as in 0.1.8 (the known limits). One that is on disk (a config marked with update-index
    // --skip-worktree) is scanned like any other.
    if (tag === 'S' && st === 'gone') continue;
    // deleted (or replaced by a folder) in the working tree but still tracked: its text is still in the index, in HEAD
    // and in every push, so git's own copy is scanned, all of them in one batch below (up to b03e7be they were skipped)
    if (st === 'gone' || st === 'dir') { if (blob !== EMPTY_BLOB) parked.push({ file: f, blob }); continue; }
    if (st !== 'file') { unread('not a regular file, or a folder on the way could not be opened'); continue; }
    const head = readHead(p, 8000);
    if (!head) { unread('could not be read'); continue; }
    const enc = encodingOf(head);
    // DER, by its structure and whatever the name: a private key is a finding; a certificate is not a secret, and is
    // not "a text file that reads as binary" either (a DER .crt was UNKNOWN with that false sentence: WV-12)
    const derHead = head[0] === SEQ ? readHead(p, DER_MAX) : null;
    const der = derHead ? derKind(derHead) : null;
    if (der?.key) { add(derFinding(f, der)); continue; }
    // a store or key whose own outer element is longer than the bytes read: named from its head where it can be, and
    // UNKNOWN where it cannot, never skipped in silence (B-e85-1)
    const past = derHead && !der ? derPastEnd(derHead) : null;
    if (past?.key) { add(derFinding(f, past)); continue; }
    if (past?.unread) { unread(`begins a DER or BER element that runs past the bytes read (at most ${DER_MAX_MB} MB), so what it holds was not read`); continue; }
    if (der && !enc) continue;
    // Binary: keys in code are text, so a picture or a compiled asset is rightly skipped and saying so for every one
    // would bury the output. But encodingOf() calls a file binary on ONE NUL byte in the first 8 KB, so a tracked
    // deploy.sh beginning "#\0" was dropped with no row at all — the only skip in this loop that recorded nothing —
    // while the all-clear still counted the repository as read. A file whose NAME says text and whose bytes say binary
    // is the anomalous case, and that one is reported.
    // A file that begins as a DER element and was not read as one is not a picture: LibreSSL reads a key whose lengths
    // are written the long way, which derKind() does not, and until 2 Nov 2026 such a key read SAFE, exit 0, with no row.
    if (unreadDer(head, der, enc)) { unread(DER_UNREAD); continue; }
    if (!enc) { if (TEXT_BY_NAME.test(f)) unread('its name is one a text file usually has, but it reads as binary (a NUL byte in its first 8 KB) and is not a DER key or certificate Wardlatch recognises, so it was not scanned'); continue; }
    const buf = readCapped(p, maxBytes);
    if (buf) { for (const hit of scanText(textIn(buf, enc))) add({ file: f, ...hit }); continue; }
    // pieces are read as UTF-8: a UTF-16 file this large was not scanned
    if (enc !== 'utf8') { unread(`a UTF-16 text file over ${maxBytes / 1024 / 1024} MB, which is not read in pieces`); continue; }
    const read = eachPiece(p, maxText, (text, first, range) => { for (const hit of scanText(text, range)) add({ file: f, ...hit, line: hit.line + first - 1 }); });
    if (!read) unread(`could not be read through (a text file over ${maxText / 1024 / 1024} MB, or unreadable)`);
  }
  scanIndexed(repo, parked, found, maxIndexed);
  return found;
}
