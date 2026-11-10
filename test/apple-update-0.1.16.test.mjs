// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.16: after Apple's update. MEASURED on one Mac, 10 Nov 2026 (macOS 27.2 26B123 → 27.2.1 26B131): the update replaced
// a cert.pem changed by hand (6bddc1e2…, 126 roots) with Apple's new file (a386d6ce…, 123 roots, no eMudhra root), left
// two older backups holding both withdrawn roots in /etc/ssl, and kept the built-in tools at the same versions (curl
// 8.7.1, LibreSSL 3.3.6, Python 3.9.6). Wardlatch 0.1.14 then read the built-in curl, the built-in python3 and a venv's
// certifi (tested through the built-in curl) as UNKNOWN: with the compromised roots forced in they still refused, which
// is Apple's own block of the 12 certificates in those tools ("Starting in macOS 27.2.1, macOS also blocks these 12
// certificates in the command-line tools", support.apple.com/en-us/149555). These tests hold the file check that now
// stands in for that control (lib/probe.mjs fileVerdict, lib/macos.mjs appleFileCheck, bundleHolds) and the backup
// note. The two cert.pem files are the measured ones (test/support/fixtures/README.md). Nothing connects; no real
// /etc/ssl is read.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundleHolds, appleFileCheck, appleNote, backupRows } from '../lib/macos.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const FX = join(ROOT, 'test', 'support', 'fixtures');
const inc = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
const APPLE_2721 = readFileSync(join(FX, 'macos-27.2.1-cert.pem'), 'utf8');        // measured after the update
const HANDFIXED = readFileSync(join(FX, 'macos-27.2-handfixed-cert.pem'), 'utf8');  // measured before it
const APPLE_272 = readFileSync(join(FX, 'macos-27.2-cert.pem'), 'utf8');            // Apple's 27.2 file = both backups
const KEYS = readFileSync(join(FX, 'emudhra-2026-10-compromised-keys.pem'), 'utf8');
const PEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const AAA = 'AAA Certificate Services (Comodo, via the Sectigo cross-sign)', G3 = 'emSign ECC Root CA - G3';
const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductVersion</key>\n\t<string>${v}</string>\n</dict>\n</plist>\n`;

let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-update-'))); });
after(() => { try { chmodSync(join(dir), 0o755); } catch {} rmSync(dir, { recursive: true, force: true }); });

test('U1 bundleHolds judges by key: the measured files, both backups, the withdrawn keys, a relabelled copy and an unreadable block', () => {
  assert.deepEqual(bundleHolds(APPLE_2721, inc), { held: [], read: 123, unreadable: 0 });
  assert.deepEqual(bundleHolds(HANDFIXED, inc), { held: [], read: 126, unreadable: 0 });
  // the positive control: Apple's 27.2 file, which both measured backups are, holds both roots
  assert.deepEqual(bundleHolds(APPLE_272, inc), { held: [AAA, G3], read: 128, unreadable: 0 });
  // the withdrawn keys, not only the roots: the self-signed emSign Root TLS CA - G3 (first block of the keys fixture)
  const tlsG3 = KEYS.match(PEM)[0];
  assert.deepEqual(bundleHolds(`${APPLE_2721}\n${tlsG3}\n`, inc).held, ['emSign Root TLS CA - G3']);
  // a name line relabelled to something harmless changes nothing (GHSA-66g2-c367-j933 matched by names)
  const aaa = (APPLE_272.match(PEM) ?? []).find((b) => bundleHolds(b, inc).held.length === 1 && bundleHolds(b, inc).held[0] === AAA);
  assert.ok(aaa, 'the AAA root is in Apple\'s 27.2 file');
  assert.deepEqual(bundleHolds(`=== /CN=Harmless Root\n${aaa}\n`, inc).held, [AAA]);
  // a TRUSTED block, a block cut short and one that is not a certificate are counted, never skipped
  const r = bundleHolds(`${APPLE_2721}\n-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB\n`, inc);
  assert.deepEqual(r, { held: [], read: 123, unreadable: 3 });
  assert.throws(() => bundleHolds(APPLE_2721, { id: 'x' }), /no withdrawn roots or keys/);
});

test('U2 appleFileCheck: only on a release Apple names, only for the built-in tools, and never when settings point them elsewhere', () => {
  const o = { os: 'darwin', macos: '27.2.1', env: {}, home: '/h', exists: () => false };
  const curl = { kind: 'curl', bin: '/usr/bin/curl' }, py = { kind: 'python', bin: '/usr/bin/python3' };
  assert.deepEqual(appleFileCheck(inc, curl, o).fileCheck, { file: '/etc/ssl/cert.pem', kind: 'system', inc, macos: '27.2.1' });
  assert.equal(appleFileCheck(inc, py, o).fileCheck.file, '/etc/ssl/cert.pem');
  for (const v of ['26.7.3', '15.8.3', '27.3', '28.0']) assert.ok(appleFileCheck(inc, curl, { ...o, macos: v }).fileCheck, v);
  for (const v of ['27.2', '26.7.2', '15.8.2', '14.7.1', '', 'x']) assert.deepEqual(appleFileCheck(inc, curl, { ...o, macos: v }), {}, v);
  assert.deepEqual(appleFileCheck(inc, curl, { ...o, os: 'linux' }), {});
  assert.deepEqual(appleFileCheck({ ...inc, appleFix: undefined }, curl, o), {});
  assert.deepEqual(appleFileCheck(inc, { kind: 'curl', bin: '/opt/homebrew/opt/curl/bin/curl' }, o), {});
  assert.deepEqual(appleFileCheck(inc, { kind: 'python', bin: '/opt/homebrew/bin/python3' }, o), {});
  // a named bundle tested through the built-in curl: that file
  assert.deepEqual(appleFileCheck(inc, { ...curl, args: ['--cacert', '/v/certifi/cacert.pem'], env: '/v' }, o).fileCheck, { file: '/v/certifi/cacert.pem', kind: 'bundle', inc, macos: '27.2.1' });
  assert.deepEqual(appleFileCheck(inc, { ...curl, args: ['--cacert'] }, o), {});
  assert.deepEqual(appleFileCheck(inc, { ...curl, args: ['-k', '--cacert', '/x'] }, o), {});
  // settings that point the tool at another file: said, never read in place of the control
  assert.match(appleFileCheck(inc, curl, { ...o, env: { SSL_CERT_FILE: '/x.pem' } }).skipped, /^SSL_CERT_FILE is set/);
  assert.match(appleFileCheck(inc, py, { ...o, env: { SSL_CERT_DIR: '/d', SSL_CERT_FILE: '/x' } }).skipped, /^SSL_CERT_FILE and SSL_CERT_DIR are set/);
  assert.match(appleFileCheck(inc, curl, { ...o, exists: (p) => p === '/h/.curlrc' }).skipped, /\/h\/\.curlrc can point curl at another file/);
  assert.match(appleFileCheck(inc, curl, { ...o, env: { CURL_HOME: '/c' }, exists: (p) => p === '/c/.curlrc' }).skipped, /\/c\/\.curlrc/);
  // python3 doesn't read .curlrc
  assert.ok(appleFileCheck(inc, py, { ...o, exists: () => true }).fileCheck);
});

// ---- the command, on a stand-in updated Mac --------------------------------------------------------------------------
// process.platform says darwin; SystemVersion.plist, the folder /etc/ssl and /usr/bin/curl are this test's own; every
// other system path is hidden; every test host "answers" with the compromised chain's issuer and nothing connects.
// The stand-in curl does what the measured one did: it refuses every test host (60), forced roots or not, and opens the
// normal site (the advisory's own page). `accepts` names a test host it connects to; `errors` one it fails on another way;
// `noControl` makes it fail the normal site too.
function standIn({ version = '27.2.1', pem = APPLE_2721, backups = {}, accepts = '', errors = '', noControl = false, env = {}, curlrc = false, venvPem, curl } = {}) {
  const d = mkdtempSync(join(dir, 'mac-'));
  const ssl = join(d, 'etc-ssl'); mkdirSync(ssl);
  if (pem !== null) writeFileSync(join(ssl, 'cert.pem'), pem);   // null: no cert.pem at all
  for (const [n, text] of Object.entries(backups)) { writeFileSync(join(ssl, n), text ?? ''); if (text === null) chmodSync(join(ssl, n), 0); }
  const files = { plist: join(d, 'SystemVersion.plist'), curl: join(d, 'curl') };
  writeFileSync(files.plist, plist(version));
  writeFileSync(files.curl, curl ?? `#!/bin/sh\ncase "$1" in --version) echo "curl 8.7.1 (x86_64-apple-darwin26.0)"; exit 0;; esac\nfor u; do :; done\ncase "$u" in\n  ${JSON.stringify(inc.advisory)}) ${noControl ? 'exit 60' : 'exit 0'};;\n  ${accepts ? `*${accepts}*) exit 0;;` : ''}\n  ${errors ? `*${errors}*) exit 7;;` : ''}\nesac\nexit 60\n`, { mode: 0o755 });
  const home = join(d, 'home'); mkdirSync(home);
  if (curlrc) writeFileSync(join(home, '.curlrc'), 'cacert = /somewhere/else.pem\n');
  const roots = [];
  if (venvPem !== undefined) {
    const sp = join(home, 'Development', 'app', '.venv', 'lib', 'python3.12', 'site-packages');
    mkdirSync(join(sp, 'certifi'), { recursive: true }); mkdirSync(join(sp, 'certifi-2026.10.19.dist-info'));
    writeFileSync(join(home, 'Development', 'app', '.venv', 'pyvenv.cfg'), 'home = /usr/bin\n');
    // a venv is one with a bin/python3 beside its pyvenv.cfg (lib/discover.mjs isEnv); it is never run
    mkdirSync(join(home, 'Development', 'app', '.venv', 'bin')); writeFileSync(join(home, 'Development', 'app', '.venv', 'bin', 'python3'), '');
    writeFileSync(join(sp, 'certifi', 'cacert.pem'), venvPem); writeFileSync(join(sp, 'certifi', '__init__.py'), '__version__ = "2026.10.19"\n');
    writeFileSync(join(sp, 'certifi-2026.10.19.dist-info', 'METADATA'), 'Name: certifi\nVersion: 2026.10.19\n');
    roots.push('--paths', join(home, 'Development'));
  }
  const pre = join(d, 'mac.cjs');
  writeFileSync(pre, `const fs = require('node:fs'), tls = require('node:tls'), net = require('node:net'), http = require('node:http'), https = require('node:https');
const cp = require('node:child_process'), { EventEmitter } = require('node:events');
Object.defineProperty(process, 'platform', { value: 'darwin' });
require('node:os').platform = () => 'darwin';
const MAP = ${JSON.stringify({ '/System/Library/CoreServices/SystemVersion.plist': files.plist, '/usr/bin/curl': files.curl })};
const SSL = ${JSON.stringify(ssl)};
const SYS = /^\\/(usr|etc|opt|bin|sbin|System|Library|Applications)(\\/|$)/;
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const m = (p) => { const s = String(p); if (MAP[s]) return MAP[s]; if (s === '/etc/ssl' || s.startsWith('/etc/ssl/')) return SSL + s.slice(8); if (SYS.test(s)) throw gone(); return p; };
const exists = fs.existsSync; fs.existsSync = (p) => { try { return exists(m(p)); } catch { return false; } };
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync', 'accessSync', 'readFileSync', 'opendirSync']) { const o = fs[k]; if (!o) continue; const w = function (p, ...a) { return typeof p === 'number' ? o.call(this, p, ...a) : o.call(this, m(p), ...a); }; if (o.native) w.native = (p, ...a) => o.native(m(p), ...a); fs[k] = w; }
net.connect = net.createConnection = () => { throw new Error('no network in these tests'); };
http.request = http.get = https.request = https.get = () => { throw new Error('no network in these tests'); };
for (const k of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) { const o = cp[k]; cp[k] = function (file, ...rest) { const f = String(file) === process.execPath ? file : m(file); if (f === file && String(file) !== process.execPath && !String(file).startsWith(${JSON.stringify(d)}) && !/^\\/bin\\/(sh|bash)$/.test(String(file))) throw new Error('not run in these tests: ' + file); return o.call(this, f, ...rest); }; }
tls.connect = (...a) => { const cb = a.find((x) => typeof x === 'function'), s = new EventEmitter(); s.end = s.destroy = () => s; s.getPeerCertificate = () => ({ issuer: { CN: 'EM DV TLS CA - G3B' } }); process.nextTick(() => cb && cb()); return s; };
require('node:module').syncBuiltinESMExports();
`);
  const empty = join(d, 'empty-path'); mkdirSync(empty);
  const base = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|CURL_HOME|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS|NODE_OPTIONS)$/.test(k)));
  const go = (json = true) => {
    const r = spawnSync(process.execPath, ['--require', pre, BIN, '--incident', 'emudhra-2026-10', '--no-containers', ...roots, ...(json ? ['--json'] : [])], { encoding: 'utf8', env: { ...base, HOME: home, PATH: empty, ...env }, maxBuffer: 64 * 1024 * 1024 });
    if (!json) return { code: r.status, out: r.stdout, err: r.stderr };
    let out; try { out = JSON.parse(r.stdout); } catch { assert.fail(`not JSON (exit ${r.status}): ${r.stdout.slice(0, 800)} ${r.stderr.slice(0, 800)}`); }
    return { code: r.status, out, err: r.stderr, curl: out.results.find((x) => x.bin === '/usr/bin/curl' && !x.args?.length), certifi: out.results.find((x) => x.certifi) };
  };
  return { go };
}

test('U3 the measured updated Mac: Apple\'s new file and Apple\'s block give SAFE, naming the file read and every host refused', () => {
  const r = standIn().go();
  assert.ok(r.curl, JSON.stringify(r.out.results).slice(0, 800));
  assert.equal(r.curl.status, 'SAFE', JSON.stringify(r.curl));
  assert.deepEqual(r.curl.fileRead, { file: '/etc/ssl/cert.pem', certificates: 123 });
  assert.equal(r.curl.searched[0], '/etc/ssl/cert.pem');
  // in --json a receipt is a string: the file, then each host it refused
  assert.deepEqual(r.curl.searched.slice(1).sort(), inc.canaries.map((id) => inc.canaryHost.replace('{id}', id)).sort(), 'every test host it refused');
  assert.equal(r.curl.tested, 12);
  assert.match(r.curl.note, /^refused all 12 test hosts, opens a normal site, and \/etc\/ssl\/cert\.pem holds none of the withdrawn roots or keys \(by key, 123 certificates, all read\)/);
  assert.equal(r.code, 0, JSON.stringify(r.out.results.map((x) => [x.bin ?? x.what, x.status])));
  // the hand-fixed file measured before the update holds neither withdrawn root (only the three Apple also removes): SAFE too
  assert.equal(standIn({ pem: HANDFIXED }).go().curl.status, 'SAFE');
});

test('U4 every outcome the file check can meet: an accepted host is EXPOSED on this path too, and every doubt is UNKNOWN', () => {
  // EXPOSED is never gated: a host the tool connects to, with Apple's file in place
  const x = standIn({ accepts: 'dv-g3b-emudhra' }).go();
  assert.equal(x.curl.status, 'EXPOSED'); assert.deepEqual(x.curl.trusted, ['dv-g3b']); assert.equal(x.code, 1);
  const e = standIn({ errors: 'ov-g3c-emudhra' }).go();
  assert.equal(e.curl.status, 'UNKNOWN'); assert.match(e.curl.reason, /^1 of 12 test connections failed for a reason other than a certificate refusal/);
  const n = standIn({ noControl: true }).go();
  assert.equal(n.curl.status, 'UNKNOWN'); assert.match(n.curl.reason, /could not open a normal site either, so its refusals prove nothing$/);
  // cert.pem still holds the roots on a release Apple says removes them: not Apple's file, UNKNOWN, never SAFE
  const h = standIn({ pem: APPLE_272 }).go();
  assert.equal(h.curl.status, 'UNKNOWN'); assert.deepEqual(h.curl.heldRoots, [AAA, G3]); assert.match(h.curl.reason, /this is not the file Apple ships with it/);
  const u = standIn({ pem: null }).go();
  assert.equal(u.curl.status, 'UNKNOWN'); assert.match(u.curl.reason, /\/etc\/ssl\/cert\.pem could not be read here$/);
  const b = standIn({ pem: `${APPLE_2721}\n-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n` }).go();
  assert.equal(b.curl.status, 'UNKNOWN'); assert.match(b.curl.reason, /1 certificate in \/etc\/ssl\/cert\.pem could not be read here \(123 read\)/);
  const z = standIn({ pem: 'no certificates here\n' }).go();
  assert.equal(z.curl.status, 'UNKNOWN'); assert.match(z.curl.reason, /no certificate in \/etc\/ssl\/cert\.pem could be read here$/);
});

test('U5 the file check is used only where Apple says the tools block the certificates, and never past a setting that moves them', () => {
  // before the update (27.2): the control's failure is what it always was, UNKNOWN, and the file is not read for it
  const old = standIn({ version: '27.2' }).go();
  assert.equal(old.curl.status, 'UNKNOWN'); assert.match(old.curl.reason, /^positive control failed/); assert.equal(old.curl.fileRead, undefined);
  for (const [name, setup, said] of [['SSL_CERT_FILE', { env: { SSL_CERT_FILE: '/elsewhere.pem' } }, /SSL_CERT_FILE is set/], ['.curlrc', { curlrc: true }, /\.curlrc can point curl at another file/]]) {
    const r = standIn(setup).go();
    assert.equal(r.curl.status, 'UNKNOWN', name); assert.match(r.curl.reason, /^positive control failed/, name);
    assert.match(r.curl.fileCheckSkipped, said, name);
    assert.match(standIn(setup).go(false).out, said, `${name}: said in the text too`);
  }
});

test('U6 a venv\'s certifi tested through the built-in curl: read by key, SAFE when clean and EXPOSED when it holds a root', () => {
  const clean = standIn({ venvPem: APPLE_2721 }).go();
  assert.ok(clean.certifi, JSON.stringify(clean.out.results.map((x) => [x.label ?? x.bin, x.status])));
  assert.equal(clean.certifi.status, 'SAFE', JSON.stringify(clean.certifi));
  assert.match(clean.certifi.fileRead.file, /certifi\/cacert\.pem$/);
  const bad = standIn({ venvPem: APPLE_272 }).go();
  assert.equal(bad.certifi.status, 'EXPOSED'); assert.deepEqual(bad.certifi.heldRoots, [AAA, G3]);
  assert.match(bad.certifi.reason, /any program given this bundle trusts the compromised chain/);
  assert.ok(bad.certifi.fix, 'an EXPOSED row carries its fix');
  assert.equal(bad.code, 1);
  assert.match(standIn({ venvPem: APPLE_272 }).go(false).out, /EXPOSED +certifi 2026\.10\.19 .* holds AAA Certificate Services/);
});

test('U7 a backup in /etc/ssl that still holds a withdrawn root is a REVIEW row, with Apple\'s words; read, never changed; only on a release Apple names', () => {
  const backups = { 'cert.pem.bak': APPLE_272, 'cert.pem.wardlatch-20261102-124354.bak': APPLE_272, 'cert.pem.bak.1': APPLE_2721, 'cert.pem.orig': null, 'other.pem': APPLE_272 };
  const r = standIn({ backups }).go();
  const rows = r.out.results.filter((x) => x.kind === 'backup');
  assert.deepEqual(rows.map((x) => [x.file, x.status]), [['/etc/ssl/cert.pem.bak', 'REVIEW'], ['/etc/ssl/cert.pem.orig', 'REVIEW'], ['/etc/ssl/cert.pem.wardlatch-20261102-124354.bak', 'REVIEW']]);
  const [bak, orig, ours] = rows;
  assert.deepEqual(bak.heldRoots, [AAA, G3]);
  assert.match(bak.reason, /^\/etc\/ssl\/cert\.pem\.bak is a copy of cert\.pem that still holds AAA Certificate Services .* and emSign ECC Root CA - G3 \(by key\)\. Don't restore it, even if a program stops connecting after the update: Apple says not to restore a backup made before the update, and to delete it once you have updated/);
  assert.match(bak.reason, /Wardlatch read it and changed nothing\.$/);
  assert.match(ours.reason, /^\/etc\/ssl\/cert\.pem\.wardlatch-20261102-124354\.bak \(the Mac fix's own backup\) is a copy/);
  assert.match(orig.reason, /could not be read here/);
  // a clean copy and a file that isn't a copy of cert.pem: nothing
  assert.ok(!rows.some((x) => /bak\.1|other\.pem/.test(x.file)));
  // REVIEW rows never move the exit code
  assert.equal(r.code, standIn().go().code);
  assert.match(standIn({ backups }).go(false).out, /^REVIEW +\/etc\/ssl\/cert\.pem\.bak$/m);
  // before the update the backups are the person's undo: nothing is said of them
  assert.deepEqual(standIn({ version: '27.2', backups }).go().out.results.filter((x) => x.kind === 'backup'), []);
  assert.deepEqual(backupRows(inc, '27.2.1', [{ file: '/etc/ssl/cert.pem.bak', text: 'nothing\n' }]), []);
  assert.deepEqual(backupRows({ ...inc, appleFix: undefined }, '27.2.1', [{ file: '/etc/ssl/cert.pem.bak', text: APPLE_272 }]), []);
});

test('U8 a failed forced-roots control never hides a connection: a host the tool opens with nothing forced in is EXPOSED, on any release', () => {
  // macOS 27.2 (no file check): the stand-in refuses every host but one, forced roots or not, so the control fails for
  // the other root; up to 0.1.15 that returned UNKNOWN before any host was probed plainly, and the connection was lost
  const r = standIn({ version: '27.2', accepts: 'dv-g3b-emudhra' }).go();
  assert.equal(r.curl.status, 'EXPOSED', JSON.stringify(r.curl));
  assert.deepEqual(r.curl.trusted, ['dv-g3b']);
  assert.match(r.curl.note, /the forced-roots control failed, but this runtime connected to these test hosts with nothing forced in/);
  assert.equal(r.code, 1);
  // the control for the same release: nothing accepted, still UNKNOWN for the control
  assert.equal(standIn({ version: '27.2' }).go().curl.status, 'UNKNOWN');
});

// ---- W1, W2, W9 (the 10 Nov inspection of the updated Mac) ------------------------------------------------------------
import { outcome } from '../lib/probe.mjs';
// A stand-in curl that reports its verification result as curl's -w %{ssl_verify_result} does. It reads the LAST
// --cacert, as curl does. `blockForced`: with a withdrawn root forced in, it answers 23 (certificate revoked), as macOS
// 27.2.1's curl does, offline too; `binding`: with only the negative control's certificate it can't open a normal site
// (as a curl that keeps to its CA file does); without it, it opens it anyway (Apple's keychain fallback, measured).
const measuredCurl = ({ blockForced = true, binding = false } = {}) => `#!/bin/sh
case "$1" in --version) echo "curl 8.7.1 (x86_64-apple-darwin26.0)"; exit 0;; esac
ca=""; prev=""; for a; do [ "$prev" = --cacert ] && ca="$a"; prev="$a"; u="$a"; done
case "$ca" in *negative-control.pem) [ "$u" = ${JSON.stringify(inc.advisory)} ] && { ${binding ? 'printf 20; exit 60' : 'printf 0; exit 0'}; };; esac
[ "$u" = ${JSON.stringify(inc.advisory)} ] && { printf 0; exit 0; }
case "$ca" in *emudhra-2026-10-root-*) ${blockForced ? 'printf 23; exit 60' : 'printf 0; exit 0'};; esac
printf 20; exit 60
`;

test('W1 the exit code alone never says "blocked": curl\'s 60 is a block only with verify result 23; python\'s probe exits 4 for it', () => {
  const e = (code) => ({ code });
  assert.equal(outcome('curl', e(60), '23'), 'blocked');
  assert.equal(outcome('curl', e(60), '23\n'), 'blocked');
  for (const v of ['20', '', '2', '230', '0']) assert.equal(outcome('curl', e(60), v), 'refused', v);
  assert.equal(outcome('curl', e(7), '23'), 'error');
  assert.equal(outcome('curl', null, ''), 'ok');
  assert.equal(outcome('python', e(4)), 'blocked'); assert.equal(outcome('python', e(1)), 'refused'); assert.equal(outcome('python', e(3)), 'error');
  assert.equal(outcome('node', e(4)), 'blocked');
});

test('W1 Apple\'s curl answering "certificate revoked" with the roots forced in is SAFE by its own block, on the fixed release and before it', () => {
  for (const version of ['27.2.1', '27.2']) {
    const r = standIn({ version, curl: measuredCurl() }).go();
    assert.equal(r.curl.status, 'SAFE', `${version}: ${JSON.stringify(r.curl)}`);
    assert.equal(r.curl.note, 'blocks the compromised keys themselves, even with their roots trusted', version);
    assert.equal(r.curl.fileRead, undefined, `${version}: the tool's own answer, not the file`);
  }
  // the control: a curl that gives 20 with the roots forced in is not blocked; on 27.2.1 the file decides (fileVerdict)
  const r = standIn({ curl: measuredCurl({ blockForced: false }) }).go();
  assert.notEqual(r.curl.note, 'blocks the compromised keys themselves, even with their roots trusted');
});

test('W2/W9 a venv\'s certifi tested through a curl that doesn\'t keep to its CA file is read by key, on any release; a curl that does is tested as before', () => {
  for (const version of ['27.2.1', '27.2']) {
    const clean = standIn({ version, venvPem: APPLE_2721, curl: measuredCurl() }).go();
    assert.equal(clean.certifi.status, 'SAFE', `${version}: ${JSON.stringify(clean.certifi)}`);
    assert.match(clean.certifi.note, /Read by key because this curl does not keep to a CA file it is given/);
    const bad = standIn({ version, venvPem: APPLE_272, curl: measuredCurl() }).go();
    assert.equal(bad.certifi.status, 'EXPOSED', version); assert.deepEqual(bad.certifi.heldRoots, [AAA, G3]);
    // Apple's curl blocks the keys and refuses every host, but that is Apple's trust, not certifi's: never SAFE here
    assert.notEqual(bad.certifi.note, 'blocks the compromised keys themselves, even with their roots trusted');
  }
  // a curl that keeps to its file and blocks the keys itself: the block says nothing of the bundle, which is read by key
  const blk = standIn({ venvPem: APPLE_272, curl: measuredCurl({ binding: true }) }).go();
  assert.equal(blk.certifi.status, 'EXPOSED'); assert.match(blk.certifi.reason, /holds AAA/);
  // a curl that keeps to its file and does not block: the test hosts decide, as before 0.1.16 (no file read)
  const lin = standIn({ version: '27.2', venvPem: APPLE_2721, curl: measuredCurl({ binding: true, blockForced: false }) }).go();
  assert.equal(lin.certifi.status, 'SAFE', JSON.stringify(lin.certifi)); assert.equal(lin.certifi.fileRead, undefined);
});

import { pipListRows } from '../lib/probe.mjs';
test('W4 pip\'s own list, read by key: a REVIEW row when it holds a withdrawn root or can\'t be read; nothing when clean or absent', () => {
  const site = (name, text) => { const d = join(dir, 'w4', name, 'site-packages'); mkdirSync(join(d, 'pip', '_vendor', 'certifi'), { recursive: true }); if (text !== undefined) writeFileSync(join(d, 'pip', '_vendor', 'certifi', 'cacert.pem'), text); return d; };
  const held = site('held', APPLE_272), clean = site('clean', APPLE_2721), none = site('none'), broken = site('broken', `${APPLE_2721}\n-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n`);
  const locked = site('locked', APPLE_272); chmodSync(join(locked, 'pip', '_vendor', 'certifi', 'cacert.pem'), 0);
  const rows = pipListRows(inc, [held, clean, none, broken, locked]);
  assert.deepEqual(rows.map((r) => [r.file.split('/w4/')[1], r.status]), [['held/site-packages/pip/_vendor/certifi/cacert.pem', 'REVIEW'], ['broken/site-packages/pip/_vendor/certifi/cacert.pem', 'REVIEW'], ['locked/site-packages/pip/_vendor/certifi/cacert.pem', 'REVIEW']]);
  assert.deepEqual(rows[0].heldRoots, [AAA, G3]);
  assert.match(rows[0].reason, /pip uses this list only when run with --use-deprecated=legacy-certs/);
  assert.match(rows[0].reason, /a compromised test host of the emSign family \(the AAA family was refused/);
  assert.match(rows[1].reason, /1 of 124 certificates could not be read here/);
  assert.match(rows[2].reason, /could not be read here, so whether it holds the withdrawn roots was not checked/);
  assert.ok(rows.every((r) => r.kind === 'pip-list' && r.status === 'REVIEW'), 'never SAFE or EXPOSED: it takes a flag to be used');
  chmodSync(join(locked, 'pip', '_vendor', 'certifi', 'cacert.pem'), 0o644);
});

test('W8 the Go rebuild advice says it is for Linux and containers, and what was measured on a Mac', () => {
  // only what Go documents and Apple says: the first inspection's Go measurement was not independently verified
  assert.match(inc.notCovered, /rebuild Go programs with Go 1\.27\.3 or 1\.26\.10 \(on Linux and in containers: on a Mac, Go checks certificates through Apple's own trust, which Apple says blocks the 12 for apps that use it\);/);
});

import { appCertifiRows } from '../lib/probe.mjs';
test('W3 the certifi an app\'s own Python carries (Blender, Unity) is read by key: REVIEW when it holds a withdrawn root, with what was and wasn\'t shown', () => {
  assert.deepEqual(inc.appPythons, ['/Applications/*.app/Contents/Resources/*/python/lib/python3*/site-packages', '~/Applications/*.app/Contents/Resources/*/python/lib/python3*/site-packages', '/Applications/Unity/Hub/Editor/*/PlaybackEngines/*/BuildTools/Emscripten/python/lib/python3*/site-packages']);
  const site = (name, text) => { const d = join(dir, 'w3', name); mkdirSync(join(d, 'certifi'), { recursive: true }); if (text !== undefined) writeFileSync(join(d, 'certifi', 'cacert.pem'), text); return d; };
  const both = site('unity-like', APPLE_272), clean = site('clean', APPLE_2721), empty = site('empty');
  const emsignOnly = site('blender-like', (APPLE_272.match(PEM) ?? []).filter((b) => !bundleHolds(b, inc).held.includes(AAA)).join('\n') + '\n');
  const rows = appCertifiRows(inc, [both, clean, empty, emsignOnly]);
  assert.deepEqual(rows.map((r) => [r.file.split('/w3/')[1], r.status, r.heldRoots]), [['unity-like/certifi/cacert.pem', 'REVIEW', [AAA, G3]], ['blender-like/certifi/cacert.pem', 'REVIEW', [G3]]]);
  assert.match(rows[0].reason, /Whether the app itself connects that way is not known/);
  assert.match(rows[0].reason, /its plain ssl default reads no list/);
});
