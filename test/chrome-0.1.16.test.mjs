// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.16: Google Chrome, CVE-2026-125350 (chrome-2026-11). Google's stable update of 9 Nov 2026 (157.0.8103.50/.51 for
// Mac and Windows, .50 for Linux) fixes it, and Google's post says "Google is aware that an exploit for CVE-2026-125350
// exists in the wild". The check reads the installed version from the app's Info.plist or dpkg's record and never
// starts Chrome. A fixed install is REVIEW, not SAFE: one left open since the update runs the old version until it
// restarts, which no file says. On the Mac this was written on, Chrome was 157.0.8103.40.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'chrome-2026-11.json'), 'utf8'));
// the two system-wide places only: the ~/Applications one is read through HOME, in the command's test below
const RULE = { ...INC.versionFiles, files: INC.versionFiles.files.filter((f) => !f.path.startsWith('~')) };
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-chrome-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
// an Info.plist as Chrome's has it (keys around the version included, so the regex has to find the right one)
const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>CFBundleExecutable</key>\n\t<string>Google Chrome</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>CFBundleVersion</key>\n\t<string>8103.40</string>\n\t<key>KSVersion</key>\n\t<string>${v}</string>\n</dict>\n</plist>\n`;
const mac = (root, text) => { const f = join(root, 'Applications', 'Google Chrome.app', 'Contents', 'Info.plist'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
const stanza = (pkg, v) => `Package: ${pkg}\nStatus: install ok installed\nPriority: optional\nSection: web\nInstalled-Size: 360000\nMaintainer: Chrome Linux Team <chromium-dev@chromium.org>\nArchitecture: amd64\nVersion: ${v}\nDescription: The web browser from Google\n\n`;
const dpkg = (root, text) => { const f = join(root, 'var', 'lib', 'dpkg', 'status'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
const judge = (root) => checkVersionFiles(RULE, { root });

test('C1 the facts are Google\'s and the CVE record\'s: the fixed version, the source and Google\'s own sentence', () => {
  assert.equal(INC.versionFiles.minVersion, '157.0.8103.50');
  assert.equal(INC.advisory, 'https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_018223192.html');
  assert.match(INC.summary, /Google's post says: "Google is aware that an exploit for CVE-2026-125350 exists in the wild\."/);
  assert.match(INC.summary, /CISA had not listed it/);
  assert.equal(INC.kev, undefined, 'not in KEV (test/kev.test.mjs holds this to the snapshot)');
});

test('C2 the Mac app: below the fix is EXPOSED, at or past it is REVIEW (it may still be running the old one), and an unread version is UNKNOWN', () => {
  for (const [v, want] of [['157.0.8103.40', 'EXPOSED'], ['157.0.8103.49', 'EXPOSED'], ['156.0.8075.120', 'EXPOSED'], ['120.0.6099.71', 'EXPOSED'],
    ['157.0.8103.50', 'REVIEW'], ['157.0.8103.51', 'REVIEW'], ['157.0.8104.1', 'REVIEW'], ['158.0.8200.0', 'REVIEW']]) {
    const root = fresh(`mac-${v}`); mac(root, plist(v));
    const rows = judge(root);
    assert.equal(rows.length, 1, `${v}: ${JSON.stringify(rows)}`);
    assert.equal(rows[0].status, want, v); assert.equal(rows[0].version, v);
    if (want === 'REVIEW') assert.match(rows[0].reason, /Wardlatch can't see which version is running/);
    if (want === 'EXPOSED') assert.equal(rows[0].reason, 'fixed in 157.0.8103.50');
  }
  // CFBundleShortVersionString is read, not the first version-looking string (KSVersion here holds a newer one)
  const r = fresh('mac-ks'); mac(r, plist('157.0.8103.40').replace('<key>KSVersion</key>\n\t<string>157.0.8103.40', '<key>KSVersion</key>\n\t<string>157.0.8103.51'));
  assert.equal(judge(r)[0].status, 'EXPOSED');
  const nokey = fresh('mac-nokey'); mac(nokey, plist('157.0.8103.50').replace('CFBundleShortVersionString', 'CFBundleOther'));
  assert.equal(judge(nokey)[0].status, 'UNKNOWN'); assert.match(judge(nokey)[0].reason, /no version could be read/);
  const locked = fresh('mac-locked'); chmodSync(mac(locked, plist('157.0.8103.50')), 0);
  assert.equal(judge(locked)[0].status, 'UNKNOWN');
  // no Chrome at all: nothing here (the command's all-clear names where it looked)
  assert.deepEqual(judge(fresh('mac-none')), []);
});

test('C3 Debian and Ubuntu: dpkg\'s google-chrome-stable stanza, whatever is around it', () => {
  const r = (text) => { const root = fresh(`dpkg-${Math.random()}`); dpkg(root, text); return judge(root); };
  assert.equal(r(stanza('libc6', '2.41-6') + stanza('google-chrome-stable', '157.0.8103.40-1'))[0].status, 'EXPOSED');
  assert.equal(r(stanza('google-chrome-stable', '157.0.8103.50-1') + stanza('zlib1g', '1:1.3.dfsg-3'))[0].status, 'REVIEW');
  // a beta beside it is not stable's version: stable's stanza is the one read
  assert.equal(r(stanza('google-chrome-beta', '158.0.8150.10-1') + stanza('google-chrome-stable', '157.0.8103.40-1'))[0].status, 'EXPOSED');
  // no stable package: nothing
  assert.deepEqual(r(stanza('google-chrome-beta', '158.0.8150.10-1') + stanza('libc6', '2.41-6')), []);
});

test('C4 the command: a Chrome in ~/Applications is read, EXPOSED is exit 1 with Google\'s fix, and "not covered" is said', () => {
  const home = fresh('cli-home'); mac(home, plist('157.0.8103.40'));
  const { NODE_OPTIONS, ...rest } = process.env;
  const go = (args) => spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'chrome-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh(`p-${Math.random()}`), WARDLATCH_TEST_OWN_DIR: dir } });
  const t = go([]);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +Google Chrome \(Mac app\) 157\.0\.8103\.40 +~\/Applications\/Google Chrome\.app\/Contents\/Info\.plist$/m);
  assert.match(t.stdout, /fix: Update Chrome to 157\.0\.8103\.50 or later/);
  assert.match(t.stdout, /not covered: Other browsers built on Chromium \(Edge, Brave, Opera, Vivaldi, Arc\)/);
  // the machine's own /Applications is hidden by the preload, so only the test's Chrome is seen
  const j = JSON.parse(go(['--json']).stdout);
  assert.deepEqual(j.results.map((x) => [x.status, x.version]), [['EXPOSED', '157.0.8103.40']]);
  // the clean twin: no Chrome anywhere it reads is one receipted all-clear, exit 0
  const none = spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'chrome-2026-11', '--json'], { encoding: 'utf8', env: { ...rest, HOME: fresh('cli-empty'), PATH: fresh('p-empty'), WARDLATCH_TEST_OWN_DIR: dir } });
  assert.equal(none.status, 0, none.stdout);
  const rows = JSON.parse(none.stdout).results;
  assert.equal(rows.length, 1); assert.equal(rows[0].status, 'SAFE'); assert.ok(rows[0].searched.length, 'it names where it looked');
});
