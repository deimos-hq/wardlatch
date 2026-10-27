#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# Runs fix/fix-macos.sh on COPIES of this Mac's /etc/ssl/cert.pem, never on the real file (which is only read):
# the original, a second run, undo from the backup, an empty file, a truncated file and a missing file. Off macOS it
# checks that the fix refuses to run. CI runs it on macos-latest and ubuntu-latest; it is safe on your own Mac too.
# On a Mac that is already fixed, pass a copy of Apple's original as the first argument (for example the backup the
# fix made) to exercise the removal itself: bash test/fix-macos.check.sh /etc/ssl/cert.pem.wardlatch-<date>.bak
# The fix re-tests against the advisory's public test host, so this needs the network (the unit tests do not).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fix="$root/fix/fix-macos.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
BAD='^=== .*/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$'
source=${1:-/etc/ssl/cert.pem}

fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok: $*"; }
count() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }
bad() { grep -E -c "$BAD" "$1" || true; }
backups() { find "$work" -name "$(basename "$1").wardlatch-*.bak" | wc -l | tr -d ' '; }
# Runs the fix on one file; sets $code and $out.
run() {
  code=0
  out=$(WARDLATCH_CERT_FILE="$1" bash "$fix" 2>&1) || code=$?
  printf '%s\n' "$out" | sed 's/^/    | /'
}

if [ "$(uname -s)" != Darwin ]; then
  run "$work/cert.pem"
  [ "$code" -eq 2 ] || fail "off macOS the fix should exit 2, got $code"
  grep -q 'This fix is for macOS' <<<"$out" || fail "off macOS the fix should say it is for macOS"
  ok "refuses to run off macOS"
  exit 0
fi

cp "$source" "$work/original.pem"
chmod 644 "$work/original.pem"
total=$(count "$work/original.pem")
found=$(bad "$work/original.pem")
echo "$source: $total certificates, $found of the two roots"

# A missing file: refused, nothing created.
run "$work/missing.pem"
if [ "$code" -ne 2 ] || [ -e "$work/missing.pem" ]; then fail "missing file: expected exit 2 and no file, got $code"; fi
ok "missing file refused"

# An empty file: refused as damaged, left as it was, no backup.
: >"$work/empty.pem"
run "$work/empty.pem"
if [ "$code" -ne 2 ] || [ -s "$work/empty.pem" ] || [ "$(backups "$work/empty.pem")" -ne 0 ]; then fail "empty file: expected exit 2, unchanged, no backup"; fi
ok "empty file refused, unchanged"

# A truncated file: refused as damaged, byte for byte unchanged, no backup.
head -c 20000 "$work/original.pem" >"$work/truncated.pem"
cp "$work/truncated.pem" "$work/truncated.before"
run "$work/truncated.pem"
if [ "$code" -ne 2 ] || ! cmp -s "$work/truncated.pem" "$work/truncated.before" || [ "$(backups "$work/truncated.pem")" -ne 0 ]; then
  fail "truncated file: expected exit 2, unchanged, no backup"
fi
ok "truncated file refused, unchanged"

# The real file's contents.
cp "$work/original.pem" "$work/cert.pem"
run "$work/cert.pem"
[ "$code" -eq 0 ] || fail "first run: expected exit 0, got $code"
if [ "$found" -gt 0 ]; then
  [ "$(bad "$work/cert.pem")" -eq 0 ] || fail "first run: a root is still there"
  [ "$(count "$work/cert.pem")" -eq $((total - found)) ] || fail "first run: expected $((total - found)) certificates, got $(count "$work/cert.pem")"
  [ "$(stat -f %Lp "$work/cert.pem")" = 644 ] || fail "first run: mode is not 644"
  [ "$(backups "$work/cert.pem")" -eq 1 ] || fail "first run: expected one backup"
  backup=$(find "$work" -name 'cert.pem.wardlatch-*.bak')
  cmp -s "$backup" "$work/original.pem" || fail "first run: the backup is not the original"
  ok "fixed: removed $found roots, kept $((total - found)) certificates, 644, backup identical to the original"
else
  cmp -s "$work/cert.pem" "$work/original.pem" || fail "first run on a clean file changed it"
  ok "$source is already clean; the fix changed nothing"
fi

# A second run: nothing changes, no second backup.
cp "$work/cert.pem" "$work/cert.after-first"
run "$work/cert.pem"
if [ "$code" -ne 0 ] || ! grep -q 'Nothing changed' <<<"$out"; then fail "second run: expected exit 0 and 'Nothing changed'"; fi
cmp -s "$work/cert.pem" "$work/cert.after-first" || fail "second run changed the file"
if [ "$found" -gt 0 ] && [ "$(backups "$work/cert.pem")" -ne 1 ]; then fail "second run made another backup"; fi
ok "second run changed nothing"

# Undo, as the script prints it: the backup puts the original back exactly.
if [ "$found" -gt 0 ]; then
  cp -p "$backup" "$work/cert.pem"
  cmp -s "$work/cert.pem" "$work/original.pem" || fail "undo did not restore the original"
  ok "undo restores the original byte for byte"
fi

# The same file without its "=== " name lines (some managed Macs ship it that way): the roots are found by fingerprint.
# Before this, the fix removed nothing here and, with the test site unreachable, printed SAFE (exit 0) for a file that
# still trusted the leaked keys.
if [ "$found" -gt 0 ]; then
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}' "$work/original.pem" >"$work/nolabel.pem"
  cp "$work/nolabel.pem" "$work/nolabel-offline.pem"
  run "$work/nolabel.pem"
  [ "$code" -eq 0 ] || fail "no name lines: expected exit 0, got $code"
  [ "$(count "$work/nolabel.pem")" -eq $((total - found)) ] || fail "no name lines: expected $((total - found)) certificates, got $(count "$work/nolabel.pem")"
  ok "no name lines: removed $found roots by fingerprint"

  # The test site unreachable (a proxy on a closed port): the file must still be fixed, never called SAFE as it was.
  code=0
  out=$(https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 WARDLATCH_CERT_FILE="$work/nolabel-offline.pem" bash "$fix" 2>&1) || code=$?
  printf '%s\n' "$out" | sed 's/^/    | /'
  [ "$code" -eq 0 ] || fail "no name lines, offline: expected exit 0, got $code"
  [ "$(count "$work/nolabel-offline.pem")" -eq $((total - found)) ] || fail "no name lines, offline: the file was not fixed but the fix exited 0"
  ok "no name lines, test site unreachable: fixed in the file, not a false SAFE"
fi

# A certificate the fix can't read: refused, unchanged, no backup (a file it can't fully check is never called clean).
awk 'BEGIN{d=0} /-----BEGIN CERTIFICATE-----/ && !d {print; getline; print "!!!!" substr($0, 5); d=1; next} {print}' "$work/original.pem" >"$work/garbled.pem"
cp "$work/garbled.pem" "$work/garbled.before"
run "$work/garbled.pem"
if [ "$code" -ne 2 ] || ! cmp -s "$work/garbled.pem" "$work/garbled.before" || [ "$(backups "$work/garbled.pem")" -ne 0 ]; then
  fail "unreadable certificate: expected exit 2, unchanged, no backup"
fi
ok "unreadable certificate refused, unchanged"
