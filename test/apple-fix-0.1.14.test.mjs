// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.14: Apple shipped its fix for /etc/ssl/cert.pem on 9 Nov 2026. Apple's page (support.apple.com/en-us/149555, as
// fetched 9 Nov 2026) says: "Starting in macOS 27.2.1, macOS also blocks these 12 certificates in the command-line tools
// [...] It also removes the two root CA certificates that the 12 certificates chain to from /etc/ssl/cert.pem, along
// with three other eMudhra root CA certificates. macOS 26.7.3 and macOS 15.8.3 also include this protection." From that
// day Wardlatch's "no macOS release has fixed it yet" was false. These tests hold lib/macos.mjs and the incident's new
// fix texts to what Apple's page says and to nothing it doesn't: the macOS version picks a fix text, never a status, and
// the three other roots are a note. Nothing connects; no real /etc/ssl/cert.pem is read or written.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { productVersion, appleFixState, trustFix, rootsHeld, appleNote, readMacosVersion, appleUnknownNote } from '../lib/macos.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
const APPLE_272 = readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'macos-27.2-cert.pem'), 'utf8');
const RELEASES = ['27.2.1', '26.7.3', '15.8.3'];
// Apple's table "Root CA certificates removed from /etc/ssl/cert.pem", copied by hand from the page on 9 Nov 2026
const APPLE_REMOVED = {
  'emSign ECC Root CA - G3': '86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B',
  'AAA Certificate Services': 'D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4',
  'emSign Root CA - G1': '40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367',
  'emSign Root CA - C1': '125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F',
  'emSign ECC Root CA - C3': 'BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3',
};
const hex = (s) => s.replace(/:/g, '').toUpperCase();
const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const fp = (block) => new X509Certificate(block).fingerprint256.replace(/:/g, '');
// Apple's 27.2 file with every root Apple's update removes taken out: the shape Apple says 27.2.1 ships. Not measured on
// an updated Mac (none here has updated): built from Apple's table, which is what the wording says too.
const cleaned = () => (APPLE_272.match(PEM) ?? []).filter((b) => !Object.values(APPLE_REMOVED).includes(fp(b))).join('\n') + '\n';

const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n\t<key>BuildID</key>\n\t<string>X</string>\n\t<key>ProductBuildVersion</key>\n\t<string>26B123</string>\n\t<key>ProductCopyright</key>\n\t<string>1983-2026 Apple Inc.</string>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductUserVisibleVersion</key>\n\t<string>${v}</string>\n\t<key>ProductVersion</key>\n\t<string>${v}</string>\n</dict>\n</plist>\n`;

let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-apple-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

test('the incident names the five roots Apple removes, by the fingerprints on Apple\'s page', () => {
  assert.equal(inc.appleFix.source, 'https://support.apple.com/en-us/149555');
  assert.equal(inc.appleFix.date, '2026-11-09');
  assert.deepEqual(inc.appleFix.releases, RELEASES);
  assert.match(inc.appleFix.said, /^Starting in macOS 27\.2\.1, /);
  assert.match(inc.appleFix.said, /along with three other eMudhra root CA certificates/);
  const all = [...inc.distrustedRoots, ...inc.appleFix.alsoRemoved];
  assert.deepEqual(Object.fromEntries(all.map((r) => [r.name.replace(/ \(.*$/, ''), hex(r.sha256)])), APPLE_REMOVED);
  // the three are a note: none of them is a distrusted root or a withdrawn key, so nothing can make one EXPOSED
  const verdictFps = new Set([...inc.distrustedRoots.map((r) => hex(r.sha256)), ...inc.withdrawnKeys.flatMap((k) => (k.certificates ?? []).map(hex))]);
  for (const r of inc.appleFix.alsoRemoved) assert.ok(!verdictFps.has(hex(r.sha256)), r.name);
});

test('rootsHeld: Apple\'s 27.2 file holds all three other roots, a file cleaned by Apple\'s table holds none (128 read)', () => {
  // positive control first: a file known to hold them (this Mac's own 27.2 file, vendored 29 Oct 2026)
  const before = rootsHeld(APPLE_272, inc.appleFix.alsoRemoved);
  assert.deepEqual(before, { held: ['emSign Root CA - G1', 'emSign Root CA - C1', 'emSign ECC Root CA - C3'], read: 128, unreadable: 0 });
  const after = rootsHeld(cleaned(), inc.appleFix.alsoRemoved);
  assert.deepEqual(after, { held: [], read: 123, unreadable: 0 });
  // a block that isn't a certificate is counted, never silently skipped
  const bad = rootsHeld(`${APPLE_272}\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n`, inc.appleFix.alsoRemoved);
  assert.equal(bad.unreadable, 1); assert.equal(bad.read, 128);
  // a TRUSTED CERTIFICATE block (LibreSSL takes it as an anchor) and a block with no END line are counted, not skipped
  assert.deepEqual(rootsHeld('-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n', inc.appleFix.alsoRemoved), { held: [], read: 0, unreadable: 1 });
  assert.equal(rootsHeld(`${APPLE_272}-----BEGIN CERTIFICATE-----\nAAAA\n`, inc.appleFix.alsoRemoved).unreadable, 1);
  // the old X509 CERTIFICATE label, which OpenSSL and LibreSSL load: counted as unreadable, never skipped
  const relabelled = APPLE_272.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '-----$1 X509 CERTIFICATE-----');
  assert.deepEqual(rootsHeld(relabelled, inc.appleFix.alsoRemoved), { held: [], read: 0, unreadable: 128 });
  // and many BEGIN lines with no END are read in linear time (a whole-file regex took 2 s for 512 KB)
  const t0 = Date.now(); rootsHeld('-----BEGIN CERTIFICATE-----\nAAAA\n'.repeat(120000), inc.appleFix.alsoRemoved);
  assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
});

test('productVersion reads ProductVersion, and nothing else, from SystemVersion.plist', () => {
  assert.equal(productVersion(plist('27.2.1')), '27.2.1');
  assert.equal(productVersion(plist('15.8')), '15.8');
  assert.equal(productVersion('<key>ProductVersion</key>\n  <string> 26.7.3 </string>'), '26.7.3');
  // ProductUserVisibleVersion alone is not ProductVersion
  assert.equal(productVersion('<key>ProductUserVisibleVersion</key><string>27.2.1</string>'), '');
  assert.equal(productVersion('<key>ProductVersion</key><string>27.2.1 beta</string>'), '');
  assert.equal(productVersion(''), ''); assert.equal(productVersion(null), '');
  // a missing file is '', never a version
  assert.equal(readMacosVersion(join(dir, 'no-such.plist')), '');
  const f = join(dir, 'SystemVersion.plist'); writeFileSync(f, plist('26.7.2'));
  assert.equal(readMacosVersion(f), '26.7.2');
});

test('appleFixState: each release Apple names, the one before it, and what Apple does not name', () => {
  const table = {
    '27.2.1': 'fixed', '27.2.2': 'fixed', '27.3': 'fixed', '27.2.1.1': 'fixed', '28.0': 'fixed', '28': 'fixed',
    '27.2': 'before-fix', '27.2.0': 'before-fix', '27.1.9': 'before-fix', '27': 'before-fix', '27.0.1': 'before-fix',
    '26.7.3': 'fixed', '26.8': 'fixed', '26.7.2': 'before-fix', '26.7': 'before-fix', '26.0': 'before-fix',
    '15.8.3': 'fixed', '15.9': 'fixed', '15.8.2': 'before-fix', '15.0': 'before-fix',
    '14.7.1': 'no-release', '10.14.6': 'no-release',
    '16.0': 'unknown', '25.1': 'unknown', '': 'unknown', 'x': 'unknown', '27.2.1 beta': 'unknown', '27..1': 'unknown',
  };
  for (const [v, want] of Object.entries(table)) assert.equal(appleFixState(v, RELEASES), want, v);
  assert.equal(appleFixState('27.2.1', []), 'unknown');
  assert.equal(appleFixState('27.2.1', undefined), 'unknown');
});

const usrCurl = { kind: 'curl', bin: '/usr/bin/curl' };
const ADVISORY_CMD = "sudo cp /etc/ssl/cert.pem /etc/ssl/cert.pem.bak && sudo awk";
test('trustFix: the built-in curl\'s text follows the macOS release; every other text is what it was', () => {
  const before = trustFix(inc, usrCurl, { os: 'darwin', macos: '27.2' });
  const fixed = trustFix(inc, usrCurl, { os: 'darwin', macos: '27.2.1' });
  const old = trustFix(inc, usrCurl, { os: 'darwin', macos: '14.7.1' });
  const unknown = trustFix(inc, usrCurl, { os: 'darwin', macos: '' });
  assert.equal(before, inc.fixes['curl:/usr/bin/curl:darwin']);
  assert.equal(unknown, inc.fixes['curl:/usr/bin/curl:darwin'], 'an unread version gets the general text, which tells the reader to update');
  assert.match(before, /update macOS/);
  assert.match(fixed, /^Apple's update should have removed the withdrawn roots from \/etc\/ssl\/cert\.pem, but the built-in curl still accepted the test hosts\. This Mac runs macOS 27\.2\.1, /);
  assert.doesNotMatch(fixed, /\{macos\}/);
  assert.match(fixed, /not to restore a backup made before the update/);
  assert.match(fixed, /we haven't measured what an update does to a file changed by hand/);
  assert.match(old, /Apple names none for macOS 14\.7\.1/);
  for (const t of [before, fixed, old]) {
    assert.ok(t.includes(ADVISORY_CMD), 'the advisory\'s own command is still given');
    assert.ok(t.includes('www.deimoscore.com/wardlatch/#mac'));
    assert.match(t, /support\.apple\.com\/en-us\/149555/);
  }
  // off macOS, and for every other runtime, the version changes nothing
  assert.equal(trustFix(inc, usrCurl, { os: 'linux', macos: '27.2.1' }), inc.fixes['curl:linux']);
  assert.equal(trustFix(inc, { kind: 'python', bin: '/usr/bin/python3' }, { os: 'linux', macos: '27.2.1' }), inc.fixes['python:linux']);
  // the built-in python3 follows the release as curl does, and its text stands on its own (no "see the curl line")
  const py = (v) => trustFix(inc, { kind: 'python', bin: '/usr/bin/python3' }, { os: 'darwin', macos: v });
  assert.equal(py('26.7.2'), inc.fixes['python:/usr/bin/python3:darwin']);
  assert.match(py('26.7.3'), /^Apple's update should have removed the withdrawn roots from \/etc\/ssl\/cert\.pem, but Apple's built-in Python still accepted the test hosts\. This Mac runs macOS 26\.7\.3, /);
  assert.match(py('13.6'), /Apple names none for macOS 13\.6/);
  for (const v of ['26.7.2', '26.7.3', '13.6']) { assert.doesNotMatch(py(v), /see the curl line/); assert.ok(py(v).includes(ADVISORY_CMD)); assert.match(py(v), /support\.apple\.com\/en-us\/149555/); }
  assert.equal(trustFix(inc, { kind: 'macos-system', bin: '/usr/bin/nscurl' }, { os: 'darwin', macos: '27.2.1' }), inc.fixes['macos-system']);
  assert.equal(trustFix(inc, { kind: 'curl', bin: '/opt/homebrew/bin/curl' }, { os: 'darwin', macos: '27.2.1' }), inc.fixes.curl);
  assert.equal(trustFix(inc, { kind: 'curl', bin: '/usr/bin/curl', fixKey: 'requests-ca-bundle' }, { os: 'darwin', macos: '27.2.1' }), inc.fixes['requests-ca-bundle']);
  assert.equal(trustFix(inc, { kind: 'curl', bin: '/usr/bin/curl', system: true }, { os: 'linux' }), inc.fixes['curl:linux']);
  assert.equal(trustFix(inc, { kind: 'node', bin: '/x/node' }, { os: 'darwin', macos: '27.2.1' }), inc.fixes.node);
});

test('no text says a macOS release has not fixed the file, or that an update always replaces a changed file', () => {
  const texts = Object.entries(inc.fixes);
  for (const [k, t] of texts) {
    assert.doesNotMatch(t, /no macOS release|future macOS update|does not fix it yet|after every update|after a system update/i, k);
    assert.doesNotMatch(t, /always (replaces|puts)|guarantee/i, k);
  }
  // what is measured is said as measured, what isn't as Apple's word
  assert.match(inc.fixes['macos-system'], /updates to 26\.7\.2 on 27 Oct and 27\.2 on 28 Oct did, as we measured/);
  assert.match(inc.fixes['macos-system'], /We haven't measured what an update to 27\.2\.1, 26\.7\.3 or 15\.8\.3 does to a file already changed by hand/);
  // and nothing claims the three other roots were compromised
  for (const [k, t] of texts) assert.doesNotMatch(t, /G1|C1|ECC Root CA - C3/, k);
});

test('appleNote: one line per state, each naming what it read, and the three roots as a note', () => {
  const at = (version, certText) => appleNote(inc, { version, certText });
  const fixedClean = at('27.2.1', cleaned());
  assert.equal(fixedClean.length, 1, fixedClean.join('\n'));
  assert.match(fixedClean[0], /^macOS 27\.2\.1 \(read from \/System\/Library\/CoreServices\/SystemVersion\.plist\): Apple says macOS 27\.2\.1, 26\.7\.3 and 15\.8\.3 \(2026-11-09\) remove/);
  assert.match(fixedClean[0], /A version says what Apple shipped, not what is in the file now/);
  const fixedOld = at('27.2.1', APPLE_272);
  assert.equal(fixedOld.length, 2);
  assert.match(fixedOld[1], /holds emSign Root CA - G1, emSign Root CA - C1, emSign ECC Root CA - C3: Apple's update removes these roots as well\. Apple did not say their keys were compromised, so they change no result here\./);
  assert.match(fixedOld[1], /is not what Apple says the update installs/);
  const before = at('27.2', APPLE_272);
  assert.match(before[0], /This Mac doesn't have that update yet\./);
  assert.doesNotMatch(before[1], /not what Apple says the update installs/, 'on 27.2 the roots are expected');
  assert.match(at('14.7.1', APPLE_272)[0], /Apple names no update for macOS 14: if this Mac can run macOS 15 or later, updating to 15\.8\.3 or later is Apple's fix, and if not, the Mac fix is\./);
  assert.doesNotMatch(at('14.7.1', APPLE_272)[0], /stays as it is/);
  // a version that was read but can't be placed is not called unread
  assert.match(at('16.0', APPLE_272)[0], /^macOS 16\.0 \(read from \/System\/Library\/CoreServices\/SystemVersion\.plist\) is not a release this can place/);
  // a file from which no certificate could be read is not a file without the three roots
  assert.match(at('27.2.1', '')[1], /^no certificate in \/etc\/ssl\/cert\.pem could be read here, so whether it holds the three other roots Apple's update removes was not checked\./);
  const trusted = APPLE_272.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '-----$1 TRUSTED CERTIFICATE-----');
  assert.match(at('27.2.1', trusted)[1], /^no certificate in \/etc\/ssl\/cert\.pem could be read here \(128 blocks could not be\)/);
  assert.match(at('27.2.1', `${cleaned()}-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n`)[1], /^1 certificate in \/etc\/ssl\/cert\.pem could not be read, so whether it is among the three other roots Apple's update removes was not checked \(123 read\)\./);
  assert.match(at('', APPLE_272)[0], /^the macOS version could not be read from \/System\/Library\/CoreServices\/SystemVersion\.plist/);
  const unread = at('27.2', null);
  assert.match(unread[1], /^\/etc\/ssl\/cert\.pem could not be read, so whether it holds the three other roots Apple's update removes was not checked\./);
  // one of the three only
  const one = (APPLE_272.match(PEM) ?? []).filter((b) => fp(b) === APPLE_REMOVED['emSign Root CA - C1']).join('\n');
  assert.match(at('26.7.2', `${cleaned()}${one}\n`)[1], /holds emSign Root CA - C1: Apple's update removes this root as well\. Apple did not say its key was compromised, so it changes no result here\./);
  // no incident record, no note
  assert.deepEqual(appleNote({ ...inc, appleFix: undefined }, { version: '27.2.1', certText: '' }), []);
});

test('appleUnknownNote: why the built-in tools\' control may fail on an updated Mac, and only there', () => {
  const unk = { status: 'UNKNOWN', reason: 'positive control failed: with the compromised roots forced in, this runtime still could not connect' };
  const o = { os: 'darwin', macos: '27.2.1' };
  assert.match(appleUnknownNote(inc, usrCurl, unk, o), /^on macOS 27\.2\.1 Apple says the built-in command-line tools themselves stop accepting the 12 compromised certificates \(https:\/\/support\.apple\.com\/en-us\/149555\)/);
  assert.match(appleUnknownNote(inc, usrCurl, unk, o), /We haven't measured it on an updated Mac/);
  assert.notEqual(appleUnknownNote(inc, { kind: 'python', bin: '/usr/bin/python3' }, unk, o), '');
  // not before the fix, not off macOS, not for another curl, a bundle given with --cacert, a venv, another reason or status
  assert.equal(appleUnknownNote(inc, usrCurl, unk, { os: 'darwin', macos: '27.2' }), '');
  assert.equal(appleUnknownNote(inc, usrCurl, unk, { os: 'linux', macos: '27.2.1' }), '');
  assert.equal(appleUnknownNote(inc, { kind: 'curl', bin: '/opt/homebrew/bin/curl' }, unk, o), '');
  assert.equal(appleUnknownNote(inc, { ...usrCurl, args: ['--cacert', '/x.pem'] }, unk, o), '');
  assert.equal(appleUnknownNote(inc, { ...usrCurl, env: '/v' }, unk, o), '');
  assert.equal(appleUnknownNote(inc, usrCurl, { status: 'UNKNOWN', reason: 'no test host answered' }, o), '');
  assert.equal(appleUnknownNote(inc, usrCurl, { status: 'EXPOSED', reason: 'positive control failed' }, o), '');
  assert.equal(appleUnknownNote({ ...inc, appleFix: undefined }, usrCurl, unk, o), '');
});

// ---- the command, on a stand-in Mac ------------------------------------------------------------------------------------
// process.platform says darwin; /System/Library/CoreServices/SystemVersion.plist, /etc/ssl/cert.pem and /usr/bin/curl are
// mapped onto this test's own files, every other system path is hidden, every test host "answers" with the compromised
// chain's issuer and no real connection is made. The stand-in curl connects to everything (EXPOSED), or with
// `refuses` only when roots are forced in with --cacert (the positive control passes, every test host is refused: SAFE).
// `baseline`: the incident is read without its appleFix record, as 0.1.13 had it, so a row or an exit code that the new
// code adds or removes shows against it.
const INCIDENT = join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json');
function standIn({ version, pem, refuses = false, fails = false, baseline = false }) {
  const d = mkdtempSync(join(dir, 'mac-'));
  const files = { plist: join(d, 'SystemVersion.plist'), pem: join(d, 'cert.pem'), curl: join(d, 'curl'), log: join(d, 'asked'), inc: join(d, 'emudhra-2026-10.json') };
  if (version !== undefined) writeFileSync(files.plist, plist(version));
  if (pem !== undefined) writeFileSync(files.pem, pem);
  writeFileSync(files.inc, JSON.stringify({ ...inc, appleFix: undefined }));
  writeFileSync(files.curl, `#!/bin/sh\ncase "$1" in --version) echo "curl 8.7.1 (x86_64-apple-darwin27.0)"; exit 0;; esac\n${fails ? 'exit 60\n' : refuses ? 'for a in "$@"; do [ "$a" = --cacert ] && exit 0; done\nexit 60\n' : 'exit 0\n'}`, { mode: 0o755 });
  const pre = join(d, 'mac.cjs');
  const map = { '/System/Library/CoreServices/SystemVersion.plist': files.plist, '/etc/ssl/cert.pem': files.pem, '/usr/bin/curl': files.curl, ...(baseline ? { [INCIDENT]: files.inc } : {}) };
  writeFileSync(pre, `const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), http = require('node:http'), https = require('node:https');
const cp = require('node:child_process'), { EventEmitter } = require('node:events');
Object.defineProperty(process, 'platform', { value: 'darwin' });
require('node:os').platform = () => 'darwin';
const MAP = ${JSON.stringify(map)};
const SYS = /^\\/(usr|etc|opt|bin|sbin|System|Library)(\\/|$)/;
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const m = (p) => { const s = String(p); if (MAP[s]) { fs.appendFileSync(${JSON.stringify(files.log)}, s + '\\n'); return MAP[s]; } if (SYS.test(s)) throw gone(); return p; };
const exists = fs.existsSync; fs.existsSync = (p) => { try { return exists(m(p)); } catch { return false; } };
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync', 'accessSync', 'readFileSync']) { const o = fs[k]; const w = function (p, ...a) { return typeof p === 'number' ? o.call(this, p, ...a) : o.call(this, m(p), ...a); }; if (o.native) w.native = (p, ...a) => o.native(m(p), ...a); fs[k] = w; }
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
http.request = http.get = https.request = https.get = () => { throw new Error('no network in these tests'); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) { const o = cp[k]; cp[k] = function (file, ...rest) { const f = String(file) === process.execPath ? file : m(file); if (f === file && String(file) !== process.execPath && !String(file).startsWith(${JSON.stringify(d)})) throw new Error('not run in these tests: ' + file); return o.call(this, f, ...rest); }; }
tls.connect = (...a) => { const cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s; s.getPeerCertificate = () => ({ issuer: { CN: 'EM DV TLS CA - G3B' } }); process.nextTick(() => cb && cb()); return s; };
require('node:module').syncBuiltinESMExports();
`);
  const empty = join(d, 'empty-path'); mkdirSync(empty);
  const home = join(d, 'home'); mkdirSync(home);
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS|NODE_OPTIONS)$/.test(k)));
  const go = (json) => {
    const r = spawnSync(process.execPath, ['--require', pre, BIN, '--incident', 'emudhra-2026-10', '--no-containers', ...(json ? ['--json'] : [])], { encoding: 'utf8', env: { ...env, HOME: home, PATH: empty }, maxBuffer: 64 * 1024 * 1024 });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  return { go, files };
}
const shape = (o) => o.results.map((r) => [r.incident, r.kind, r.bin ?? null, r.status]);
function runAll(setups, want) {
  const runs = {};
  for (const [name, setup] of Object.entries(setups)) {
    const s = standIn({ ...setup, refuses: want === 'SAFE', fails: want === 'UNKNOWN' });
    const j = s.go(true);
    assert.ok(j.out, j.err);
    const out = JSON.parse(j.out);
    const curl = out.results.find((r) => r.bin === '/usr/bin/curl');
    // positive precondition: the stand-in curl was really the one tested, with the status the stand-in makes
    assert.ok(curl, `${name}: no row for /usr/bin/curl: ${j.out.slice(0, 600)} ${j.err}`);
    assert.equal(curl.status, want, `${name}: ${JSON.stringify(curl)}`);
    runs[name] = { out, curl, code: j.code, text: s.go(false).out, asked: readFileSync(s.files.log, 'utf8') };
  }
  return runs;
}

test('the command on a stand-in Mac: the built-in curl\'s fix follows the release, and no status moves with it', () => {
  const runs = runAll({ fixed: { version: '27.2.1', pem: APPLE_272 }, before: { version: '27.2', pem: APPLE_272 }, unread: {}, baseline: { version: '27.2.1', pem: APPLE_272, baseline: true } }, 'EXPOSED');
  assert.match(runs.fixed.curl.fix, /^Apple's update should have removed the withdrawn roots/);
  assert.match(runs.fixed.curl.fix, /This Mac runs macOS 27\.2\.1, /);
  assert.equal(runs.before.curl.fix, inc.fixes['curl:/usr/bin/curl:darwin']);
  assert.equal(runs.unread.curl.fix, inc.fixes['curl:/usr/bin/curl:darwin']);
  // the version was read from the file, and the file is where the note says it was read
  for (const n of ['fixed', 'before', 'unread']) assert.match(runs[n].asked, /^\/System\/Library\/CoreServices\/SystemVersion\.plist$/m);
  assert.deepEqual(runs.fixed.out.macos, { version: '27.2.1', appleFix: 'fixed', source: 'https://support.apple.com/en-us/149555', notes: runs.fixed.out.macos.notes });
  assert.equal(runs.fixed.out.macos.notes.length, 2);
  assert.equal(runs.unread.out.macos.appleFix, 'unknown');
  assert.match(runs.unread.text, /could not be read, so whether it holds the three other roots Apple's update removes was not checked/);
  assert.match(runs.fixed.text, /Apple did not say their keys were compromised, so they change no result here/);
  // the baseline is what 0.1.13 would have done with this machine: no note, no macos field
  assert.equal(runs.baseline.out.macos, undefined);
  assert.doesNotMatch(runs.baseline.text, /SystemVersion\.plist/);
  // invariance against the baseline: the same rows, the same statuses and the same exit code in every state
  for (const n of ['fixed', 'before', 'unread']) {
    assert.deepEqual(shape(runs[n].out), shape(runs.baseline.out), n);
    assert.equal(runs[n].code, runs.baseline.code, n);
  }
  assert.equal(runs.baseline.code, 1);
});

test('the command on a stand-in Mac where curl refuses: SAFE, and the note adds no row and keeps the exit code', () => {
  const runs = runAll({ fixed: { version: '27.2.1', pem: cleaned() }, held: { version: '27.2.1', pem: APPLE_272 }, before: { version: '27.2', pem: APPLE_272 }, old: { version: '14.7.1', pem: APPLE_272 }, unread: {}, baseline: { version: '27.2.1', pem: APPLE_272, baseline: true } }, 'SAFE');
  for (const n of Object.keys(runs)) {
    assert.deepEqual(shape(runs[n].out), shape(runs.baseline.out), n);
    assert.equal(runs[n].code, runs.baseline.code, n);
    assert.equal(runs[n].curl.fix, undefined, `${n}: a SAFE row carries no fix`);
  }
  // exit 0 needs every row SAFE: say so, so the comparison above is about a run that could reach 0
  assert.ok(runs.baseline.out.results.every((r) => r.status === 'SAFE'), JSON.stringify(shape(runs.baseline.out)));
  assert.equal(runs.baseline.code, 0);
  assert.match(runs.held.text, /is not what Apple says the update installs/);
  assert.doesNotMatch(runs.fixed.text, /holds emSign/);
  assert.match(runs.old.text, /Apple names no update for macOS 14: if this Mac can run macOS 15 or later/);
});

test('the command on a stand-in Mac whose curl refuses even with the roots forced in: UNKNOWN, and on a fixed release it says why it may be', () => {
  const runs = runAll({ fixed: { version: '27.2.1', pem: cleaned() }, before: { version: '27.2', pem: APPLE_272 }, baseline: { version: '27.2.1', pem: cleaned(), baseline: true } }, 'UNKNOWN');
  assert.match(runs.fixed.curl.reason, /^positive control failed/);
  assert.match(runs.fixed.curl.appleNote, /^on macOS 27\.2\.1 Apple says the built-in command-line tools themselves stop accepting/);
  assert.match(runs.fixed.text, /We haven't measured it on an updated Mac, so this row says only that this tool could not be tested this way/);
  // and the reason beside it no longer says the error was not a block, which is unmeasured there
  assert.doesNotMatch(runs.fixed.curl.reason, /not the runtime's block/); assert.match(runs.fixed.curl.reason, /which on this release may be Apple's own block \(see below\)/);
  assert.match(runs.before.curl.reason, /a certificate error that is not the runtime's block of these keys/, 'unchanged before the fix');
  assert.equal(runs.before.curl.appleNote, undefined);
  assert.equal(runs.baseline.curl.appleNote, undefined);
  for (const n of ['fixed', 'before']) { assert.deepEqual(shape(runs[n].out), shape(runs.baseline.out), n); assert.equal(runs[n].code, runs.baseline.code, n); }
  assert.equal(runs.baseline.code, 2);
});
