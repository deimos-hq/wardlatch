// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Fortinet FortiClient for Mac, CVE-2026-121529 (forticlient-2026-11). Fortinet's advisory FG-IR-26-194 of 10 Nov 2026
// lists FortiClientMac 7.4.0 through 7.4.7 as affected ("Upgrade to 7.4.8 or above") and FortiClientMac 8.0 and 7.2 as
// "Not affected"; it names no older line. The check reads the installed version from the app's Info.plist and never
// starts FortiClient. A version on a line Fortinet does not name is UNKNOWN, never SAFE. No FortiClient was installed
// on the Mac this was written on: the Info.plist here is written to Apple's format, not copied from a real bundle.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';
import { judgeVersion } from '../lib/binaries.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'forticlient-2026-11.json'), 'utf8'));
// the system-wide place only: the ~/Applications one is read through HOME, in the command's tests below
const RULE = { ...INC.versionFiles, files: INC.versionFiles.files.filter((f) => !f.path.startsWith('~')) };
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-forticlient-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, name); mkdirSync(d, { recursive: true }); return d; };
// an Info.plist as an app bundle has it: the build number and the minimum macOS beside the version, so the pattern has
// to find the right key
const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>CFBundleExecutable</key>\n\t<string>FortiClient</string>\n\t<key>CFBundleIdentifier</key>\n\t<string>com.fortinet.FortiClient</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>CFBundleVersion</key>\n\t<string>1790</string>\n\t<key>LSMinimumSystemVersion</key>\n\t<string>11.0</string>\n</dict>\n</plist>\n`;
const app = (root, text) => { const f = join(root, 'Applications', 'FortiClient.app', 'Contents', 'Info.plist'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
const judge = (root) => checkVersionFiles(RULE, { root });
const cli = (home, args = []) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'forticlient-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh(`p-${Math.random()}`), WARDLATCH_TEST_OWN_DIR: dir } });
};

test('F1 the facts are Fortinet\'s: the affected range, the fix, the lines it names, its own sentence, and nothing about exploitation it did not say', () => {
  const v = INC.versionFiles;
  assert.equal(INC.advisory, 'https://fortiguard.fortinet.com/psirt/FG-IR-26-194');
  assert.deepEqual([v.affectedFrom, v.bad, v.minVersion, v.notNamedBelow], ['7.4.0', { from: '7.4.0', to: '7.4.7' }, '7.4.8', '7.2']);
  assert.deepEqual(v.files.map((f) => f.path), ['/Applications/FortiClient.app/Contents/Info.plist', '~/Applications/FortiClient.app/Contents/Info.plist']);
  assert.ok(v.notNamedNote, 'a line the advisory does not name needs its own sentence');
  assert.match(INC.summary, /in Fortinet's words "may allow an unauthorized remote attacker to execute unauthorized code or commands\. Successful exploitation requires interaction with the victim\."/);
  assert.match(v.fix, /Fortinet: "Upgrade to 7\.4\.8 or above"/);
  // CISA does not list it (catalog 2026.11.10; test/kev.test.mjs holds that to the snapshot), and Fortinet's page says
  // "Known Exploited: No": the file carries no KEV row and no word that says otherwise
  assert.equal(INC.kev, undefined);
  assert.match(INC.summary, /Fortinet's page says Known Exploited: No, and CISA's Known Exploited Vulnerabilities catalog \(version 2026\.11\.10\) does not list it/);
  assert.doesNotMatch(JSON.stringify(INC), /in the wild|actively exploited|is exploited|being exploited/i);
  // every claim in the summary that has a date carries it
  assert.match(INC.summary, /on 10 November 2026/); assert.match(INC.summary, /As read on 11 November 2026/);
});

test('F2 the Mac app: 7.4.0 to 7.4.7 is EXPOSED, 7.4.8 and later, 7.2 and 8.0 are SAFE with a receipt, and a line Fortinet does not name is UNKNOWN', () => {
  for (const [v, want] of [['7.4.0', 'EXPOSED'], ['7.4.1', 'EXPOSED'], ['7.4.7', 'EXPOSED'], ['7.4.3.1790', 'EXPOSED'], ['7.4.7.1811', 'EXPOSED'],
    ['7.4.8', 'SAFE'], ['7.4.8.1820', 'SAFE'], ['7.4.10', 'SAFE'], ['7.2.0', 'SAFE'], ['7.2.14', 'SAFE'], ['8.0.0', 'SAFE'], ['8.0.2', 'SAFE'],
    ['7.0.14', 'UNKNOWN'], ['6.4.10', 'UNKNOWN'], ['7.1.9', 'UNKNOWN']]) {
    const root = fresh(`mac-${v}`); const f = app(root, plist(v));
    const rows = judge(root);
    assert.equal(rows.length, 1, `${v}: ${JSON.stringify(rows)}`);
    assert.equal(rows[0].status, want, `${v}: ${JSON.stringify(rows[0])}`); assert.equal(rows[0].version, v);
    if (want === 'SAFE') assert.deepEqual(rows[0].searched, [f, `version ${v}`], 'a SAFE names the file it read and the version it compared');
    if (want === 'UNKNOWN') assert.equal(rows[0].reason, INC.versionFiles.notNamedNote);
  }
  // the reasons a reader is given
  const reason = (v) => { const root = fresh(`why-${v}`); app(root, plist(v)); return judge(root)[0].reason; };
  assert.equal(reason('7.4.3'), 'version 7.4.3 is in the affected range 7.4.0 to 7.4.7');
  assert.equal(reason('7.4.7.1811'), 'fixed in 7.4.8');
  assert.equal(reason('7.2.14'), 'older than the affected range (from 7.4.0)');
});

test('F3 a version that cannot be read is UNKNOWN, never SAFE and never left out: no key, a binary plist, a file that cannot be opened', () => {
  // the control: the same bundle with a readable version is judged
  const ok = fresh('read-ok'); app(ok, plist('7.4.3'));
  assert.equal(judge(ok)[0].status, 'EXPOSED');
  const nokey = fresh('read-nokey'); app(nokey, plist('7.4.3').replace('CFBundleShortVersionString', 'CFBundleOther'));
  assert.deepEqual(judge(nokey).map((r) => [r.status, r.reason]), [['UNKNOWN', 'found, but no version could be read from it']]);
  // CFBundleVersion (the build, 1790) is not the version: it must not be read in its place
  const build = fresh('read-build'); app(build, plist('7.4.3').replace('<key>CFBundleShortVersionString</key>\n\t<string>7.4.3</string>\n', ''));
  assert.equal(judge(build)[0].status, 'UNKNOWN');
  const bin = fresh('read-binary'); app(bin, Buffer.concat([Buffer.from('bplist00'), Buffer.from([0xd1, 0x01, 0x02, 0x5f, 0x10, 0x1a]), Buffer.from('CFBundleShortVersionString'), Buffer.from([0x55]), Buffer.from('7.4.3')]));
  assert.equal(judge(bin)[0].status, 'UNKNOWN');
  const locked = fresh('read-locked'); chmodSync(app(locked, plist('7.4.8')), 0);
  assert.deepEqual(judge(locked).map((r) => r.status), ['UNKNOWN']);
  // a bundle folder that cannot be entered: there, and not looked into
  const shut = fresh('read-shut'); const f = app(shut, plist('7.4.8')); chmodSync(dirname(f), 0);
  try { assert.deepEqual(judge(shut).map((r) => r.status), ['UNKNOWN']); } finally { chmodSync(dirname(f), 0o755); }
  // no FortiClient at all: nothing here (the command's all-clear names where it looked)
  assert.deepEqual(judge(fresh('read-none')), []);
});

test('F4 notNamedBelow: without it a line the source never mentions reads SAFE; with it, UNKNOWN (and every other rule is unchanged)', () => {
  const { notNamedBelow, notNamedNote, ...without } = INC.versionFiles;
  assert.equal(judgeVersion('7.0.14', without).status, 'SAFE', 'the control: this is the false SAFE the key exists to prevent');
  assert.equal(judgeVersion('7.0.14', INC.versionFiles).status, 'UNKNOWN');
  assert.equal(judgeVersion('7.0.14', { ...without, notNamedBelow }).reason, 'version 7.0.14 is on a release line the source does not name (older than 7.2), so it could not be judged');
  // at the line itself and past it the key says nothing
  for (const v of ['7.2', '7.2.0', '7.4.3', '7.4.8', '8.0.0']) assert.equal(judgeVersion(v, INC.versionFiles).status, judgeVersion(v, without).status, v);
  // a rule that has no such key is judged as before (GitLab's, Chrome's)
  assert.equal(judgeVersion('1.0.0', { minVersion: '2.0.0' }).status, 'EXPOSED');
  assert.equal(judgeVersion('1.0.0', { affectedFrom: '2.0.0', minVersion: '3.0.0' }).status, 'SAFE');
});

test('F5 the command: a FortiClient in ~/Applications is read; EXPOSED is exit 1 with Fortinet\'s fix, a fixed one exit 0 with a receipt, an unnamed line exit 2', () => {
  const home = fresh('cli-exposed'); app(home, plist('7.4.3'));
  const t = cli(home);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +FortiClient \(Mac app\) 7\.4\.3 +~\/Applications\/FortiClient\.app\/Contents\/Info\.plist$/m);
  assert.match(t.stdout, /fix: Update FortiClient to 7\.4\.8 or later \(Fortinet: "Upgrade to 7\.4\.8 or above"\)/);
  assert.match(t.stdout, /not covered: FortiClient for Windows and FortiClient Windows PAM/);
  assert.match(t.stdout, /^Source: https:\/\/fortiguard\.fortinet\.com\/psirt\/FG-IR-26-194$/m);
  // CISA does not list it: no KEV line under the title, no kev in --json
  assert.doesNotMatch(t.stdout, /CISA KEV/);
  const j = JSON.parse(cli(home, ['--json']).stdout);
  assert.deepEqual(j.results.map((x) => [x.status, x.version]), [['EXPOSED', '7.4.3']]);
  assert.equal(j.incidents[0].kev, undefined);
  // the fixed twin
  const fixed = fresh('cli-fixed'); const f = app(fixed, plist('7.4.8'));
  const s = cli(fixed, ['--json']);
  assert.equal(s.status, 0, s.stdout + s.stderr);
  assert.deepEqual(JSON.parse(s.stdout).results.map((x) => [x.status, x.version, x.searched]), [['SAFE', '7.4.8', [f, 'version 7.4.8']]]);
  // a line Fortinet does not name: could not be tested
  const old = fresh('cli-old'); app(old, plist('7.0.14'));
  const u = cli(old, ['--json']);
  assert.equal(u.status, 2, u.stdout + u.stderr);
  assert.deepEqual(JSON.parse(u.stdout).results.map((x) => x.status), ['UNKNOWN']);
  // no FortiClient anywhere it reads: one receipted all-clear, exit 0
  const none = cli(fresh('cli-none'), ['--json']);
  assert.equal(none.status, 0, none.stdout + none.stderr);
  const rows = JSON.parse(none.stdout).results;
  assert.equal(rows.length, 1); assert.equal(rows[0].status, 'SAFE'); assert.ok(rows[0].searched.length, 'it names where it looked');
  assert.match(rows[0].reason, /^no FortiClient found in the places this check reads/);
});

test('F6 FortiClient is never started: a program in the bundle that would leave a mark leaves none', () => {
  const home = fresh('cli-norun'); const f = app(home, plist('7.4.3'));
  const mark = join(home, 'ran');
  const exe = join(dirname(f), 'MacOS', 'FortiClient'); mkdirSync(dirname(exe), { recursive: true });
  writeFileSync(exe, `#!/bin/sh\necho ran > '${mark}'\n`, { mode: 0o755 });
  // the control: the program does leave its mark when it is run
  spawnSync(exe, [], { encoding: 'utf8' });
  assert.ok(existsSync(mark), 'the control: the fake FortiClient marks when started');
  rmSync(mark);
  const t = cli(home);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.ok(!existsSync(mark), 'Wardlatch started the program in the bundle');
});
