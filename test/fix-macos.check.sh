#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# Runs fix/fix-macos.sh on COPIES of a certificate bundle, never on the real /etc/ssl/cert.pem: the original, a
# second run, undo from the backup, an empty file, a truncated file and a missing file. Off macOS it checks that the
# fix refuses to run. CI runs it on macos-latest and ubuntu-latest; it is safe on your own Mac too.
#
# The bundle it works from defaults to the vendored UNFIXED fixture, test/support/fixtures/macos-27.2-cert.pem, for
# the reason test/support/fixtures/README.md gives: every removal case and every network case here needs a bundle
# that still holds the two withdrawn roots, so reading the runner's live /etc/ssl/cert.pem made this suite's green
# depend on the runner being unfixed. On an already-fixed Mac -- or on CI's macos-latest the day Apple ships a fixed
# bundle -- the cases skipped with a NOTE and the suite stayed green. They now cannot skip: a source holding neither
# root is a failure here, and the run prints how many cases it ran. Pass a path to test a different bundle,
# including the live one: bash test/fix-macos.check.sh /etc/ssl/cert.pem
# The fix re-tests against the advisory's public test host, so this needs the network (the unit tests do not).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fix="$root/fix/fix-macos.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
source=${1:-"$root/test/support/fixtures/macos-27.2-cert.pem"}
# Every case that reports ok counts itself, and the end of the run checks the total: a case that stops running
# because the bundle under test no longer has the shape it needs must not pass as silence. Bump this when you add
# a case, and the run tells you the number to put here.
expect_cases=24

fail() { echo "FAIL: $*"; exit 1; }
cases=0
ok() { cases=$((cases + 1)); echo "ok: $*"; }
count() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }
# How many of the two roots a file holds, by SHA-256 fingerprint (name lines or not).
bad() {
  local n=0 d; d=$(mktemp -d)
  awk -v d="$d" '/-----BEGIN CERTIFICATE-----/{k++; f=d "/" k ".pem"} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$1"
  for c in "$d"/*.pem; do
    [ -e "$c" ] || continue
    case "$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null)" in
      *D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4|*86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B) n=$((n + 1)) ;;
    esac
  done
  rm -rf "$d"; echo "$n"
}
backups() { find "$work" -name "$(basename "$1").wardlatch-*.bak" | wc -l | tr -d ' '; }
# Runs the fix on one file; sets $code and $out.
# Extra VAR=value arguments after the file are set for that run only (e.g. a proxy, to make the test site unreachable).
# Each run gets its own TMPDIR, which must be empty afterwards, and must print nothing on stderr.
# $script is the script it runs: the shipped one, except in the network cases at the end, which point it at a copy
# whose one network command is a stub (no real network can be made to answer those ways on demand).
script=$fix
run() {
  local file=$1; shift
  code=0
  rm -rf "$work/tmp"; mkdir "$work/tmp"
  out=$(env "$@" TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$file" bash "$script" 2>"$work/stderr") || code=$?
  printf '%s\n' "$out" | sed 's/^/    | /'
  [ ! -s "$work/stderr" ] || { sed 's/^/    ! /' "$work/stderr"; fail "the fix wrote to stderr"; }
  left=$(find "$work/tmp" -mindepth 1 -maxdepth 1 -exec basename {} \; | tr '\n' ' ')
  [ -z "$left" ] || fail "the fix left temporary files behind: $left"
}

if [ "$(uname -s)" != Darwin ]; then
  run "$work/cert.pem"
  [ "$code" -eq 2 ] || fail "off macOS the fix should exit 2, got $code"
  grep -q 'This fix is for macOS' <<<"$out" || fail "off macOS the fix should say it is for macOS"
  ok "refuses to run off macOS"
  echo "$cases cases ran (off macOS, where the fix refuses to run)"
  exit 0
fi

cp "$source" "$work/original.pem"
chmod 644 "$work/original.pem"
total=$(count "$work/original.pem")
found=$(bad "$work/original.pem")
echo "$source: $total certificates, $found of the two roots"
# Not a NOTE. Everything this suite is for -- the removal, the undo, the shapes with no name lines, and every case
# about what the fix does with an answer from the network -- needs a bundle that still holds a withdrawn root. On a
# bundle that holds neither, those cases cannot run, and a green run would be saying only that they did not.
[ "$found" -gt 0 ] || fail "$source holds neither withdrawn root, so the removal and network cases cannot run and this suite can prove nothing. The default source is the vendored unfixed fixture test/support/fixtures/macos-27.2-cert.pem; give that, or another bundle that still holds a root, or no argument at all."

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

# A symlinked cert.pem: refused, the link left as a link, the file it points at untouched, no backup. This fix
# replaces the file it is given, so on a link it would leave the bundle the Mac actually reads exactly as it was.
# The one-line fix on the page has refused a symbolic link since CL-42, and the download had no -L test at all.
cp "$work/original.pem" "$work/link-target.pem"
chmod 644 "$work/link-target.pem"
ln -s "$work/link-target.pem" "$work/cert-link.pem"
run "$work/cert-link.pem"
[ "$code" -eq 2 ] || fail "symbolic link: expected exit 2, got $code"
grep -q 'symbolic link' <<<"$out" || fail "symbolic link: it did not say the file is a symbolic link"
[ -L "$work/cert-link.pem" ] || fail "symbolic link: the link itself was replaced"
cmp -s "$work/link-target.pem" "$work/original.pem" || fail "symbolic link: the file the link points at was changed"
[ "$(backups "$work/cert-link.pem")" -eq 0 ] || fail "symbolic link: it made a backup beside the link"
[ "$(backups "$work/link-target.pem")" -eq 0 ] || fail "symbolic link: it made a backup beside the target"
# Proof the refusal is what stops it: the same run on a copy of the script with that one line removed must leave
# either the link replaced or its target rewritten. If it leaves both alone, this case proves nothing.
grep -v '^\[ ! -L "\$FILE" \]' "$fix" >"$work/nolink.sh"
cmp -s "$fix" "$work/nolink.sh" && fail "symbolic link: the refusal line was not found, so this case proves nothing"
cp "$work/original.pem" "$work/link-target2.pem"
chmod 644 "$work/link-target2.pem"
ln -s "$work/link-target2.pem" "$work/cert-link2.pem"
script=$work/nolink.sh
run "$work/cert-link2.pem"
script=$fix
if cmp -s "$work/link-target2.pem" "$work/original.pem" && [ -L "$work/cert-link2.pem" ]; then
  fail "symbolic link: the case does not discriminate -- with the refusal removed, the link and its target were both left alone"
fi
ok "a symbolic link is refused, and the file it points at is left alone"

# The real file's contents.
cp "$work/original.pem" "$work/cert.pem"
run "$work/cert.pem"
[ "$code" -eq 0 ] || fail "first run: expected exit 0, got $code"
if [ "$found" -gt 0 ]; then
  [ "$(bad "$work/cert.pem")" -eq 0 ] || fail "first run: a root is still there"
  [ "$(count "$work/cert.pem")" -eq $((total - found)) ] || fail "first run: expected $((total - found)) certificates, got $(count "$work/cert.pem")"
  [ "$(stat -f %Lp "$work/cert.pem")" = 644 ] || fail "first run: mode is not 644"
  [ "$(backups "$work/cert.pem")" -eq 1 ] || fail "first run: expected one backup"
  # The byte-for-byte comparison with the advisory's own removal. It is doubly conditional, so it says out loud
  # when it does not happen: a comparison that silently did not run, inside a case that still reports ok, is the
  # shape of defect this suite spent 29 Oct 2026 removing from itself.
  if ! grep -q '^=== ' "$work/original.pem"; then
    echo "    - not compared with the advisory's removal: this bundle has no \"=== \" name lines for it to work on"
  else
    awk '/^(###|===) /{skip=0} /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1} !skip' "$work/original.pem" >"$work/advisory.pem"
    # (The advisory's awk only works on LF files; on others it removes nothing, so there's nothing to compare.)
    if [ "$(count "$work/advisory.pem")" -ne $((total - found)) ]; then
      echo "    - not compared with the advisory's removal: its awk left $(count "$work/advisory.pem") certificates, not $((total - found)), so it removed nothing here"
    else
      cmp -s "$work/cert.pem" "$work/advisory.pem" || fail "first run: not byte for byte the advisory's removal"
      echo "    - and byte for byte the advisory's own removal"
    fi
  fi
  cp "$work/cert.pem" "$work/cleaned.pem"
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
  run "$work/nolabel-offline.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
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

# A block curl also trusts but the fix doesn't read (BEGIN TRUSTED CERTIFICATE): refused, online and offline, never
# SAFE. Before this, a cleaned file with an emSign root appended in that form read SAFE (exit 0) when the test site was
# unreachable.
if [ "$found" -gt 0 ]; then
  awk '/-----BEGIN CERTIFICATE-----/{k++; p=1} p{print > ("'"$work"'/one-" k ".pem")} /-----END CERTIFICATE-----/{p=0}' "$work/original.pem"
  emsign=
  for c in "$work"/one-*.pem; do
    case "$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null)" in *86:A1:EC:BA:08:9C:4A:8D*) emsign=$c ;; esac
  done
  # A bundle holding AAA but not emSign satisfies the guard above, and this case needs the emSign root to build
  # its TRUSTED CERTIFICATE block from. Without this the suite died with "emsign: unbound variable" on exactly the
  # Mojave-era shape test/support/mojave-shapes.sh exists for.
  [ -n "$emsign" ] || fail "a BEGIN TRUSTED CERTIFICATE block: $source holds no emSign ECC Root CA - G3 to build the block from, so this case cannot run. Give a bundle that holds it, or no argument at all."
  cp "$work/cleaned.pem" "$work/trusted.pem"
  /usr/bin/openssl x509 -in "$emsign" -trustout -addtrust serverAuth >>"$work/trusted.pem"
  cp "$work/trusted.pem" "$work/trusted.before"
  for net in online offline; do
    if [ "$net" = offline ]; then run "$work/trusted.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9; else run "$work/trusted.pem"; fi
    if [ "$code" -ne 2 ] || ! cmp -s "$work/trusted.pem" "$work/trusted.before"; then fail "TRUSTED CERTIFICATE block, $net: expected exit 2, unchanged, got $code"; fi
  done
  ok "a BEGIN TRUSTED CERTIFICATE block is refused, online and offline"
fi

# What the fix does while it is replacing the file. These cases drive copies of the script with one step changed,
# because a disk that writes a short file, a write that fails, and a signal arriving in the middle of a copy cannot
# be arranged on demand. Everything else in each copy is the shipped script, byte for byte.
#
# Most of them rewrite replace(), the one function in the script that writes to $FILE, by name rather than by line,
# so they keep working when the lines around it move. body() prints the script with replace()'s body replaced by
# the lines given; prefix() prints it with lines added at the top of that body.
# (awk -v cannot carry a newline, so the lines go through a file.)
body() {   # $1 = out file, rest = lines to use as replace()'s whole body
  local out=$1; shift
  printf '%s\n' "$@" >"$work/body.txt"
  awk -v bf="$work/body.txt" '
    /^replace\(\) \{$/ { inside = 1; print; while ((getline l < bf) > 0) print l; close(bf); next }
    inside { if ($0 == "}") { inside = 0; print } ; next }
    { print }' "$fix" >"$out"
  cmp -s "$fix" "$out" && fail "replace() was not found in $fix, so the cases about the write prove nothing"
  return 0
}
prefix() {   # $1 = out file, rest = lines to put at the top of replace()'s body
  local out=$1; shift
  printf '%s\n' "$@" >"$work/body.txt"
  awk -v bf="$work/body.txt" '
    { print }
    /^replace\(\) \{$/ { while ((getline l < bf) > 0) print l; close(bf) }' "$fix" >"$out"
  cmp -s "$fix" "$out" && fail "replace() was not found in $fix, so the cases about the write prove nothing"
  return 0
}

if [ "$found" -gt 0 ]; then
  # A backup that isn't the file it came from: nothing is replaced, and the bad backup is named. The fix prints an
  # Undo line pointing at that backup and the content-mismatch restore uses it, so an unchecked backup makes both
  # a lie. Up to 29 Oct 2026 the backup was written with `cp -p` and never compared.
  awk '{ print }
       /^\$SUDO cp -p "\$FILE" "\$backup" \|\|/ { print "echo tampered >> \"$backup\"" }' "$fix" >"$work/badbackup.sh"
  cmp -s "$fix" "$work/badbackup.sh" && fail "a bad backup: the backup step was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/badbackup.pem"
  script=$work/badbackup.sh
  run "$work/badbackup.pem"
  script=$fix
  [ "$code" -eq 2 ] || fail "a bad backup: expected exit 2, got $code"
  grep -q "couldn't be used to undo" <<<"$out" || fail "a bad backup: it did not say the backup is unusable"
  grep -q "Bad backup: $work/badbackup.pem.wardlatch-" <<<"$out" || fail "a bad backup: it did not name the backup it wrote"
  cmp -s "$work/badbackup.pem" "$work/original.pem" || fail "a bad backup: the file was replaced anyway"
  # Proof it discriminates: with the comparison taken out, the same run replaces the file and prints an Undo line
  # naming a backup that is not the original.
  awk '/^cmp -s "\$FILE" "\$backup" \|\| \{$/ { drop = 1 } drop { if ($0 == "}") drop = 0; next } { print }' \
    "$work/badbackup.sh" >"$work/badbackup-nocheck.sh"
  cmp -s "$work/badbackup.sh" "$work/badbackup-nocheck.sh" && fail "a bad backup: the comparison was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/badbackup2.pem"
  script=$work/badbackup-nocheck.sh
  run "$work/badbackup2.pem"
  script=$fix
  cmp -s "$work/badbackup2.pem" "$work/original.pem" && fail "a bad backup: the case does not discriminate -- with the comparison removed the file was not replaced either"
  b2=$(find "$work" -name 'badbackup2.pem.wardlatch-*.bak')
  [ -n "$b2" ] || fail "a bad backup: the run with the comparison removed wrote no backup"
  cmp -s "$b2" "$work/original.pem" && fail "a bad backup: the case does not discriminate -- the backup it trusted was the original after all"
  grep -q 'Undo:' <<<"$out" || fail "a bad backup: the run with the comparison removed printed no Undo line to be wrong about"
  ok "a backup that isn't the file it came from stops the fix before anything is replaced"

  # A signal in the middle of the write. The copy into the file beside the bundle is replaced by a short write and
  # a TERM to the script itself, because a Ctrl-C landing inside a copy, a sudo timeout and a power cut cannot be
  # arranged on demand. The bundle must be left exactly as it was: the replacement is a rename, which the kernel
  # either did or didn't do.
  body "$work/interrupted.sh" \
    '  new="$(dirname "$FILE")/.wardlatch-new.$$"' \
    '  head -c 500 "$1" > "$new"; kill -TERM $$'
  cp "$work/original.pem" "$work/interrupted.pem"
  script=$work/interrupted.sh
  run "$work/interrupted.pem"
  script=$fix
  cmp -s "$work/interrupted.pem" "$work/original.pem" ||
    fail "an interrupted write: the bundle is neither the old file nor the new one ($(count "$work/interrupted.pem") certificates)"
  [ -z "$(find "$work" -name '.wardlatch-new.*' -print -quit)" ] || fail "an interrupted write: the half-written file was left beside the bundle"
  [ "$(backups "$work/interrupted.pem")" -eq 1 ] || fail "an interrupted write: expected the backup to have been written already"
  # Proof it discriminates: the same interruption in the shape this script had until 29 Oct 2026, which copied
  # straight into the bundle and so truncated it first, must leave a stump. That is the defect.
  body "$work/inplace.sh" '  head -c 500 "$1" > "$FILE"; kill -TERM $$'
  cp "$work/original.pem" "$work/inplace.pem"
  script=$work/inplace.sh
  run "$work/inplace.pem"
  script=$fix
  cmp -s "$work/inplace.pem" "$work/original.pem" &&
    fail "an interrupted write: the case does not discriminate -- interrupting a copy straight into the bundle left it whole too"
  [ "$(count "$work/inplace.pem")" -lt 50 ] ||
    fail "an interrupted write: the case does not discriminate -- the in-place write left a usable bundle"
  ok "a signal during the write leaves the bundle whole, never half-written"

  # A write that fails: a full disk, a read-only volume, an expired sudo timestamp, SIP. All of those are "couldn't
  # tell", which is exit 2 with a printed line. Unchecked, `set -e` ended the run with the failing command's own
  # status, which is 1 -- the code the published table reads as EXPOSED, meaning this Mac still trusts the
  # compromised keys -- and the EXIT trap printed nothing, so there was no line to read either.
  body "$work/writefails.sh" '  return 1'
  cp "$work/original.pem" "$work/writefails.pem"
  script=$work/writefails.sh
  run "$work/writefails.pem"
  script=$fix
  [ "$code" -eq 2 ] || fail "a failed write: expected exit 2, got $code"
  grep -q '^UNKNOWN' <<<"$out" || fail "a failed write: expected UNKNOWN, got no line to read"
  grep -q "Couldn't replace" <<<"$out" || fail "a failed write: it did not say the write failed"
  cmp -s "$work/writefails.pem" "$work/original.pem" || fail "a failed write: the bundle changed anyway"
  # And the same for the backup, which is the first write of the run.
  sed 's#^\$SUDO cp -p "\$FILE" "\$backup" ||#false ||#' "$fix" >"$work/backupfails.sh"
  cmp -s "$fix" "$work/backupfails.sh" && fail "a failed write: the backup step was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/backupfails.pem"
  script=$work/backupfails.sh
  run "$work/backupfails.pem"
  script=$fix
  [ "$code" -eq 2 ] || fail "a failed backup: expected exit 2, got $code"
  grep -q "Couldn't write the backup" <<<"$out" || fail "a failed backup: it did not say the backup could not be written"
  cmp -s "$work/backupfails.pem" "$work/original.pem" || fail "a failed backup: the bundle changed anyway"
  [ "$(backups "$work/backupfails.pem")" -eq 0 ] || fail "a failed backup: it left a backup behind"
  # Proof both discriminate: with the checks taken off those two writes, the run exits 1 with nothing printed.
  for t in writefails backupfails; do
    case "$t" in
      writefails) sed 's#^replace "\$tmp" || .*$#replace "$tmp"#' "$work/$t.sh" >"$work/$t-nocheck.sh" ;;
      backupfails) sed 's#^false || { echo "UNKNOWN  Couldn.t write the backup.*$#false#' "$work/$t.sh" >"$work/$t-nocheck.sh" ;;
    esac
    cmp -s "$work/$t.sh" "$work/$t-nocheck.sh" && fail "a failed write: the check on $t was not found, so this case proves nothing"
    cp "$work/original.pem" "$work/$t-nocheck.pem"
    script=$work/$t-nocheck.sh
    run "$work/$t-nocheck.pem"
    script=$fix
    [ "$code" -eq 1 ] || fail "a failed write: the case does not discriminate -- unchecked, $t exited $code, not the EXPOSED code 1"
    [ -z "$out" ] || fail "a failed write: the case does not discriminate -- unchecked, $t printed something: $out"
  done
  ok "a write that fails is UNKNOWN with a line to read, not a silent EXPOSED"

  # The content-mismatch restore: the one path left in this script that puts the original back, and the only kind
  # of reason there can be for one -- the bytes now in the file are not the bytes the script built and checked, so
  # what every TLS client on the Mac reads is a file nobody has checked, and the backup is the only file in the run
  # that has been. The CHANGELOG said a case for it was here. It was not. This copy's write puts something else in
  # the file afterwards, because nothing else can make that happen on demand.
  # First, that the reason the script declares is the reason this case is about. replace() is the only thing in the
  # script that writes to the file; nothing outside it may, there are exactly two calls, and the one that puts the
  # backup back must declare why immediately above it. A write added anywhere else, or a second restore, or a
  # restore on another reason, fails here and needs a case of its own.
  awk '/^replace\(\) \{$/ { inside = 1 } inside { if ($0 == "}") inside = 0; next } { print }' "$fix" >"$work/outside-replace.sh"
  stray=$(grep -cE '\b(cp|mv|install|tee|dd|ln)\b[^;|]*"\$FILE"[[:space:]]*(;|\||$)|>[[:space:]]*"\$FILE"' "$work/outside-replace.sh" || true)
  [ "$stray" -eq 0 ] || fail "content mismatch: $stray line(s) outside replace() write to \$FILE, so they are not covered by the cases above and need their own"
  calls=$(grep -c 'replace "' "$fix" || true)
  [ "$calls" -eq 2 ] || fail "content mismatch: replace() is called $calls time(s), expected 2 (the fix and the restore); a third needs a declared reason and a case here"
  declared=$(grep -B1 '\breplace "\$backup"' "$fix" | sed -n 's/^ *# *wardlatch:revert-reason=//p')
  [ "$declared" = content-mismatch ] || fail "content mismatch: the restore declares '$declared', expected 'content-mismatch'"
  awk '{ print } /^replaced=1$/ { print "echo tampered >> \"$FILE\"" }' "$fix" >"$work/mismatch.sh"
  cmp -s "$fix" "$work/mismatch.sh" && fail "content mismatch: the write step was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/mismatch.pem"
  script=$work/mismatch.sh
  run "$work/mismatch.pem"
  script=$fix
  [ "$code" -eq 1 ] || fail "content mismatch: expected exit 1, got $code"
  grep -q '^EXPOSED' <<<"$out" || fail "content mismatch: expected EXPOSED"
  grep -q "isn't the file this built and checked" <<<"$out" || fail "content mismatch: it did not say what was wrong"
  grep -q 'Backup:' <<<"$out" || fail "content mismatch: it did not name the backup it restored from"
  cmp -s "$work/mismatch.pem" "$work/original.pem" || fail "content mismatch: the original was not put back"
  [ "$(bad "$work/mismatch.pem")" -eq "$found" ] || fail "content mismatch: what was put back is not the bundle that holds the withdrawn roots"
  # Proof it discriminates: the same tamper on a copy that cannot put the original back must leave the tampered
  # bytes in the file. If the original comes back there too, this case is not testing the restore.
  prefix "$work/mismatch-norestore.sh" '  case "$1" in *.bak) return 1 ;; esac'
  awk '{ print } /^replaced=1$/ { print "echo tampered >> \"$FILE\"" }' "$work/mismatch-norestore.sh" >"$work/mismatch-norestore2.sh"
  cp "$work/original.pem" "$work/mismatch2.pem"
  script=$work/mismatch-norestore2.sh
  run "$work/mismatch2.pem"
  script=$fix
  cmp -s "$work/mismatch2.pem" "$work/original.pem" &&
    fail "content mismatch: the case does not discriminate -- with the restore refused the original came back anyway"
  # And a restore that cannot be made is UNKNOWN with the command to run by hand, not a silent exit 1 leaving
  # unchecked bytes in the file with nothing said.
  [ "$code" -eq 2 ] || fail "content mismatch: a restore that failed should exit 2, got $code"
  grep -q "couldn't be put" <<<"$out" || fail "content mismatch: a restore that failed did not say so"
  grep -q "sudo cp -p '$work/mismatch2.pem.wardlatch-" <<<"$out" || fail "content mismatch: a restore that failed did not give the command to put it back"
  ok "a file that isn't the one the script built brings the original back, declaring content-mismatch as the reason"

  # The restore is a rename too. Interrupted, it must leave the file whole -- the unchecked bytes or the original,
  # never a stump. Up to this change the restore copied the backup over the file in place, which is the very defect
  # the forward write was redesigned to remove, still live on the one path that runs when something has gone wrong.
  prefix "$work/restore-cut.sh" \
    '  case "$1" in *.bak) new="$(dirname "$FILE")/.wardlatch-new.$$"; head -c 500 "$1" > "$new"; kill -TERM $$ ;; esac'
  awk '{ print } /^replaced=1$/ { print "echo tampered >> \"$FILE\"" }' "$work/restore-cut.sh" >"$work/restore-cut2.sh"
  cp "$work/original.pem" "$work/restorecut.pem"
  script=$work/restore-cut2.sh
  run "$work/restorecut.pem"
  script=$fix
  [ "$(count "$work/restorecut.pem")" -ge 50 ] ||
    fail "an interrupted restore: the bundle was left a stump of $(count "$work/restorecut.pem") certificates"
  [ -z "$(find "$work" -name '.wardlatch-new.*' -print -quit)" ] || fail "an interrupted restore: the half-written file was left beside the bundle"
  # Proof it discriminates: the same interruption of a restore that copies straight over the file leaves a stump.
  prefix "$work/restore-inplace.sh" \
    '  case "$1" in *.bak) head -c 500 "$1" > "$FILE"; kill -TERM $$ ;; esac'
  awk '{ print } /^replaced=1$/ { print "echo tampered >> \"$FILE\"" }' "$work/restore-inplace.sh" >"$work/restore-inplace2.sh"
  cp "$work/original.pem" "$work/restoreinplace.pem"
  script=$work/restore-inplace2.sh
  run "$work/restoreinplace.pem"
  script=$fix
  [ "$(count "$work/restoreinplace.pem")" -lt 50 ] ||
    fail "an interrupted restore: the case does not discriminate -- restoring straight over the file left it usable too"
  ok "an interrupted restore leaves the bundle whole, never half-written"

  # An interrupt while the fix is running, delivered just before the write. macOS's /bin/bash is 3.2.57, and with
  # a trap on EXIT alone a SIGINT that reaches this script while it is waiting on a plain foreground command is
  # swallowed: bash carries on to the NEXT line, `set -euo pipefail` and all. So an interrupt during the backup
  # copy -- or during any of the copies, on a slow disk or a busy Mac -- left the script to go on and replace
  # /etc/ssl/cert.pem, then print SAFE and exit 0, about a run the person had cancelled. (bash does stop if the
  # interrupt lands in a command substitution, which is why this has to be landed on a plain command to be seen at
  # all; the run is put in its own process group so the signal reaches bash and nothing else.)
  prefix "$work/atwrite.sh" '  touch "$WL_AT_THE_WRITE"; /bin/sleep 3'
  sed "s|^trap stopped HUP INT TERM\$|# (the old shape: a trap on EXIT alone)|" "$work/atwrite.sh" >"$work/atwrite-exitonly.sh"
  cmp -s "$work/atwrite.sh" "$work/atwrite-exitonly.sh" && fail "an interrupt: the signal trap was not found, so this case proves nothing"
  interrupt() {   # $1 = script copy, $2 = bundle. Interrupts it at the write; sets $code and $out.
    local pid i
    rm -rf "$work/tmp"; mkdir "$work/tmp"
    rm -f "$work/at-the-write"
    set -m
    env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$2" WL_AT_THE_WRITE="$work/at-the-write" \
      bash "$1" >"$work/interrupt.out" 2>&1 &
    pid=$!
    set +m
    for i in $(seq 1 200); do [ -e "$work/at-the-write" ] && break; /bin/sleep 0.1; done
    [ -e "$work/at-the-write" ] || fail "an interrupt: the run never reached the write, so there was nothing to interrupt"
    kill -INT "$pid" 2>/dev/null || true
    code=0; wait "$pid" || code=$?
    out=$(cat "$work/interrupt.out")
    printf '%s\n' "$out" | sed 's/^/    | /'
  }
  cp "$work/original.pem" "$work/atwrite.pem"
  interrupt "$work/atwrite.sh" "$work/atwrite.pem"
  # Exit 2 exactly, not merely non-zero: the Mac page publishes an exit-code table that fleet policies are built
  # on, and it lists 0, 1 and 2. An interrupted run reached no verdict, which is what 2 means there.
  [ "$code" -eq 2 ] || fail "an interrupt: expected exit 2, got $code"
  cmp -s "$work/atwrite.pem" "$work/original.pem" || fail "an interrupt: the bundle was replaced after the run was interrupted"
  grep -qE '^(SAFE|EXPOSED)' <<<"$out" && fail "an interrupt: it printed a verdict about a run that was interrupted"
  [ -z "$(find "$work" -name '.wardlatch-new.*' -print -quit)" ] || fail "an interrupt: the file beside the bundle was left behind"
  [ -z "$(find "$work/tmp" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail "an interrupt: temporary files were left in TMPDIR"
  # Proof it discriminates: with the trap back on EXIT alone the same interrupt must fail to stop the run, so the
  # bundle is replaced and a verdict printed about it. If it stops there too, this case is proving nothing.
  cp "$work/original.pem" "$work/atwrite2.pem"
  interrupt "$work/atwrite-exitonly.sh" "$work/atwrite2.pem"
  cmp -s "$work/atwrite2.pem" "$work/original.pem" &&
    fail "an interrupt: the case does not discriminate -- with a trap on EXIT alone the interrupt stopped the run too"
  grep -qE '^(SAFE|EXPOSED)' <<<"$out" ||
    fail "an interrupt: the case does not discriminate -- with a trap on EXIT alone no verdict was printed either"
  [ "$code" -eq 0 ] || fail "an interrupt: the case does not discriminate -- with a trap on EXIT alone the run exited $code, not 0"
  rm -rf "$work/tmp"; mkdir "$work/tmp"
  ok "an interrupt stops the fix, where a trap on EXIT alone replaced the file and printed SAFE anyway"

  # An interrupt AFTER the file has been replaced. Exit 2 means "read the printed line", so a run stopped once the
  # file was already changed has to say that it was, and name the way back. The window is the two probes, up to 15
  # seconds each, which is exactly when somebody decides the script has hung and stops it.
  sed 's|^control() { local r=0; |control() { local r=0; touch "$WL_AT_THE_WRITE"; /bin/sleep 3; |' "$fix" >"$work/afterwrite.sh"
  cmp -s "$fix" "$work/afterwrite.sh" && fail "an interrupt after the write: control() was not found, so this case proves nothing"
  sed 's#^  \[ -z "\$replaced" \] || {$#  [ -n "$replaced" ] || {#' "$work/afterwrite.sh" >"$work/afterwrite-silent.sh"
  cmp -s "$work/afterwrite.sh" "$work/afterwrite-silent.sh" && fail "an interrupt after the write: the report was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/afterwrite.pem"
  # the baseline control pauses too, so the first interrupt chance is before the write; let that one pass by
  # waiting for the SECOND touch of the sentinel, which is the control read after the file was replaced.
  interrupt_after() {   # $1 = script copy, $2 = bundle. Sets $code and $out.
    local pid i
    rm -rf "$work/tmp"; mkdir "$work/tmp"
    rm -f "$work/at-the-write"
    set -m
    env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$2" WL_AT_THE_WRITE="$work/at-the-write" \
      bash "$1" >"$work/interrupt.out" 2>&1 &
    pid=$!
    set +m
    for i in $(seq 1 400); do
      [ -e "$work/at-the-write" ] && [ "$(count "$2")" -ne "$total" ] && break
      /bin/sleep 0.1
    done
    kill -INT "$pid" 2>/dev/null || true
    code=0; wait "$pid" || code=$?
    out=$(cat "$work/interrupt.out")
    printf '%s\n' "$out" | sed 's/^/    | /'
  }
  interrupt_after "$work/afterwrite.sh" "$work/afterwrite.pem"
  [ "$code" -eq 2 ] || fail "an interrupt after the write: expected exit 2, got $code"
  [ "$(count "$work/afterwrite.pem")" -eq $((total - found)) ] || fail "an interrupt after the write: the bundle is not the fixed file"
  grep -q 'had already been replaced' <<<"$out" || fail "an interrupt after the write: it did not say the file had been replaced"
  grep -q "Backup: $work/afterwrite.pem.wardlatch-" <<<"$out" || fail "an interrupt after the write: it did not name the backup"
  grep -q 'Undo:' <<<"$out" || fail "an interrupt after the write: it did not give the way back"
  # Proof it discriminates: with that report taken out, the same interrupt prints nothing at all about a file it
  # had already changed -- exit 2 telling the reader to read a line that does not exist.
  cp "$work/original.pem" "$work/afterwrite2.pem"
  interrupt_after "$work/afterwrite-silent.sh" "$work/afterwrite2.pem"
  [ -z "$out" ] ||
    fail "an interrupt after the write: the case does not discriminate -- without the report it still printed: $out"
  rm -rf "$work/tmp"; mkdir "$work/tmp"
  ok "an interrupt after the file was replaced says so, and names the way back"

  # The exit code a stopped or refused run reports, which the EXIT trap can quietly change. Measured on
  # /bin/bash 3.2.57: with `set -e`, a failing command inside the EXIT trap ends the trap AND overrides the exit
  # status, so one failed `rm` in the cleanup turned exit 2 ("couldn't tell") into exit 1, which the published
  # table reads as EXPOSED -- this Mac still trusts the compromised keys. `return 0` at the end does not help:
  # errexit ends the function before reaching it. Every command in clean() ends in `|| true` for that reason.
  sed 's#^clean() { rm -f "\$snap" "\$tmp" || true; #clean() { /usr/bin/false || true; #' "$fix" >"$work/cleanfails.sh"
  cmp -s "$fix" "$work/cleanfails.sh" && fail "the cleanup's exit code: clean() was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/cleanfails.pem"
  : >"$work/cleanfails-empty.pem"
  script=$work/cleanfails.sh
  run "$work/cleanfails-empty.pem"
  script=$fix
  [ "$code" -eq 2 ] || fail "the cleanup's exit code: a refused run should exit 2 whatever the cleanup does, got $code"
  # Proof it discriminates: without the `|| true`, the same failing cleanup turns that 2 into 1.
  sed 's#^clean() { rm -f "\$snap" "\$tmp" || true; #clean() { /usr/bin/false; #' "$fix" >"$work/cleanfails-bare.sh"
  cmp -s "$fix" "$work/cleanfails-bare.sh" && fail "the cleanup's exit code: clean() was not found, so this case proves nothing"
  script=$work/cleanfails-bare.sh
  run "$work/cleanfails-empty.pem"
  script=$fix
  [ "$code" -eq 1 ] ||
    fail "the cleanup's exit code: the case does not discriminate -- with a bare failing cleanup the run exited $code, not 1"
  ok "a failing cleanup cannot turn UNKNOWN into EXPOSED"
fi

# What the fix does with what the network says. These cases drive a copy of the script whose one network command is
# a stub standing in for /usr/bin/curl, because no real network can be made to answer these ways on demand. They are
# about control flow, not about curl: everything else in the copy is the shipped script, byte for byte.
if [ "$found" -gt 0 ]; then
  sed 's|/usr/bin/curl|"${WARDLATCH_CURL:-/usr/bin/curl}"|g' "$fix" >"$work/stubbed.sh"
  cmp -s "$fix" "$work/stubbed.sh" && fail "the network cases: the stub replaced nothing, so they would test the real network"
  # EVERY call site, not merely one. With one left behind these cases would still reach the real network on that
  # path and pass for the wrong reason, which is exactly how test/support/mojave-shapes.sh came to claim it was
  # offline while every one of its shapes made live requests. Counted by occurrence, not by line.
  curls=$(grep -o '/usr/bin/curl' "$fix" | wc -l | tr -d ' ')
  [ "$curls" -ge 2 ] || fail "the network cases: expected at least 2 /usr/bin/curl call sites in the script, found $curls"
  behind=$(grep -o 'WARDLATCH_CURL:-/usr/bin/curl' "$work/stubbed.sh" | wc -l | tr -d ' ')
  allcurl=$(grep -o '/usr/bin/curl' "$work/stubbed.sh" | wc -l | tr -d ' ')
  [ "$behind" -eq "$curls" ] && [ "$allcurl" -eq "$curls" ] ||
    fail "the network cases: the script has $curls /usr/bin/curl call site(s), and the stubbed copy has $allcurl of which $behind are behind the stub; every one must be, or those paths reach the real network"
  cat >"$work/curl-stub" <<'STUB'
#!/bin/bash
# Stands in for /usr/bin/curl: $STUB_TEST for the advisory's test host, $STUB_CONTROL for anything else. Prints
# nothing and exits with that code, as curl -s -o /dev/null does.
case "$*" in
  *we-have-a-problem.com*) exit "${STUB_TEST:?}" ;;
  *) exit "${STUB_CONTROL:?}" ;;
esac
STUB
  chmod +x "$work/curl-stub"
  script=$work/stubbed.sh

  # A network that accepts everything: the test host answers AND is trusted, after the two roots were removed from
  # the file. The fix must be KEPT and the Mac reported exposed, never reverted: putting the original back would
  # hand both withdrawn roots to a Mac whose network is already answering for someone else, which is the one Mac
  # that could then never be fixed. Up to 29 Oct 2026 this case restored the backup and exited 1.
  cp "$work/original.pem" "$work/lying.pem"
  run "$work/lying.pem" WARDLATCH_CURL="$work/curl-stub" STUB_CONTROL=0 STUB_TEST=0
  [ "$code" -eq 1 ] || fail "a network that accepts everything: expected exit 1, got $code"
  grep -q '^EXPOSED' <<<"$out" || fail "a network that accepts everything: expected EXPOSED"
  [ "$(bad "$work/lying.pem")" -eq 0 ] || fail "a network that accepts everything: the fix was reverted, so the roots are back"
  [ "$(count "$work/lying.pem")" -eq $((total - found)) ] || fail "a network that accepts everything: the file is not the fixed file"
  # And it names the two ordinary causes. "Something other than this file is trusting the compromised keys" is a
  # misdiagnosis for both of them, and sends an admin hunting the wrong thing on their own Mac.
  grep -q 'TLS-inspecting proxy' <<<"$out" || fail "a network that accepts everything: it did not name a TLS-inspecting proxy's root in the file as a cause"
  grep -q "re-issued its certificate" <<<"$out" || fail "a network that accepts everything: it did not name the test site re-issuing its certificate as a cause"
  ok "a network that accepts everything: EXPOSED, exit 1, the fix kept, and the two ordinary causes named"

  # A network where nothing answers, but the test host's silence arrives as curl 60 and so looks like a refusal.
  # The fix must not read a verdict out of it: the file is fixed, and the output must not say the Mac now refuses
  # the compromised keys, because nothing was tested. Up to 29 Oct 2026 this case printed exactly that.
  cp "$work/original.pem" "$work/nocontrol.pem"
  run "$work/nocontrol.pem" WARDLATCH_CURL="$work/curl-stub" STUB_CONTROL=7 STUB_TEST=60
  [ "$code" -eq 0 ] || fail "no control: expected exit 0, got $code"
  [ "$(count "$work/nocontrol.pem")" -eq $((total - found)) ] || fail "no control: the file was not fixed"
  grep -q 'refuses the compromised keys' <<<"$out" && fail "no control: it claimed a re-test on a network that answered nothing"
  grep -q "didn't load before this change (curl 7) or after it (curl 7)" <<<"$out" ||
    fail "no control: it did not give both readings of the control, before the change and after it"
  ok "no control before or after the change: fixed in the file, and no online verdict claimed"

  # The control read BEFORE anything is written, and again after: three readings where there were two. These cases
  # need a control that answers differently on the two calls, so they use a second stub that takes its control
  # answers from a list, one per call.
  cat >"$work/curl-stub-ba" <<'STUB'
#!/bin/bash
# Stands in for /usr/bin/curl where the control has to answer differently before and after the write. The test host
# always gets $STUB_TEST. Control calls take their answer from $STUB_CONTROLS, one per call in the order given, the
# last repeating; the call number is kept in $STUB_STATE.
case "$*" in
  *we-have-a-problem.com*) exit "${STUB_TEST:?}" ;;
esac
n=$(cat "${STUB_STATE:?}" 2>/dev/null || echo 0)
n=$((n + 1)); printf '%s' "$n" >"$STUB_STATE"
i=1; last=0
for a in ${STUB_CONTROLS:?}; do
  last=$a
  [ "$i" = "$n" ] && exit "$a"
  i=$((i + 1))
done
exit "$last"
STUB
  chmod +x "$work/curl-stub-ba"

  # The control loads before the change and not after it. This is the one reading here that is about the change and
  # not about the network, and it must not revert: the two files differ by exactly the two withdrawn roots, so a
  # revert on this reading is a revert on what the network answered, through a side door -- a MITM presenting a
  # certificate issued under AAA Certificate Services for the control host produces precisely this pair of
  # readings. Up to 29 Oct 2026 the control was read only AFTER the write, so this and "nothing on this network
  # answers" were the same reading, and both printed "SAFE Fixed in the file" and exited 0.
  cp "$work/original.pem" "$work/brokeafter.pem"
  printf '0' >"$work/ba-state"
  run "$work/brokeafter.pem" WARDLATCH_CURL="$work/curl-stub-ba" STUB_STATE="$work/ba-state" \
    STUB_CONTROLS="0 60" STUB_TEST=60
  [ "$code" -eq 2 ] || fail "the control broke with the change: expected exit 2, got $code"
  grep -q '^UNKNOWN' <<<"$out" || fail "the control broke with the change: expected UNKNOWN"
  grep -q '^SAFE' <<<"$out" && fail "the control broke with the change: it called the run safe"
  grep -q 'loaded through the old file (curl 0)' <<<"$out" || fail "the control broke with the change: it did not give the reading before the change"
  grep -q "doesn't load through the new one (curl 60)" <<<"$out" || fail "the control broke with the change: it did not give the reading after the change"
  [ "$(bad "$work/brokeafter.pem")" -eq 0 ] || fail "the control broke with the change: the fix was reverted, so the withdrawn roots are back"
  [ "$(count "$work/brokeafter.pem")" -eq $((total - found)) ] || fail "the control broke with the change: the file is not the fixed file"
  grep -q 'Undo:' <<<"$out" || fail "the control broke with the change: it did not name the way back"
  # Proof it fails on the old shape: with the baseline forced to a value no reading produced, the decision falls to
  # the reading after the write alone, which is the control flow the script had. The run must then end in SAFE and
  # exit 0 -- an all-clear for a Mac whose ordinary certificate validation stopped working with the change.
  sed 's|^c0=\$(control "\$snap")$|c0=7   # (the old shape: no baseline was taken)|' "$work/stubbed.sh" >"$work/nobaseline.sh"
  cmp -s "$work/stubbed.sh" "$work/nobaseline.sh" && fail "the control broke with the change: the baseline was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/brokeafter2.pem"
  printf '0' >"$work/ba-state"
  script=$work/nobaseline.sh
  run "$work/brokeafter2.pem" WARDLATCH_CURL="$work/curl-stub-ba" STUB_STATE="$work/ba-state" \
    STUB_CONTROLS="60" STUB_TEST=60
  script=$work/stubbed.sh
  [ "$code" -eq 0 ] ||
    fail "the control broke with the change: the case does not discriminate -- with no baseline the run exited $code, not 0"
  grep -q '^SAFE' <<<"$out" ||
    fail "the control broke with the change: the case does not discriminate -- with no baseline it did not print SAFE"
  ok "the control loading before the change but not after: UNKNOWN, exit 2, the fix kept and nothing reverted"

  # The control loads both times, so it is meaningful and the test host's answer can be read. The third reading,
  # and the only one that ends in a verdict about the compromised keys.
  cp "$work/original.pem" "$work/bothcontrols.pem"
  printf '0' >"$work/ba-state"
  run "$work/bothcontrols.pem" WARDLATCH_CURL="$work/curl-stub-ba" STUB_STATE="$work/ba-state" \
    STUB_CONTROLS="0 0" STUB_TEST=60
  [ "$code" -eq 0 ] || fail "the control loads both times: expected exit 0, got $code"
  grep -q 'now refuses the compromised keys' <<<"$out" || fail "the control loads both times: it did not read the test host"
  [ "$(count "$work/bothcontrols.pem")" -eq $((total - found)) ] || fail "the control loads both times: the file was not fixed"
  [ "$(bad "$work/bothcontrols.pem")" -eq 0 ] || fail "the control loads both times: a withdrawn root is still there"
  ok "the control loading before and after: the test host is read, and the verdict is the test host's"

  script=$fix
fi

# A file the fix can't read: UNKNOWN (exit 2), unchanged, nothing on stderr.
cp "$work/original.pem" "$work/unreadable.pem"
chmod 000 "$work/unreadable.pem"
if [ ! -r "$work/unreadable.pem" ]; then
  run "$work/unreadable.pem"
  [ "$code" -eq 2 ] || fail "unreadable file: expected exit 2, got $code"
  chmod 644 "$work/unreadable.pem"
  cmp -s "$work/unreadable.pem" "$work/original.pem" || fail "unreadable file: it changed"
  ok "unreadable file refused, unchanged"
else
  chmod 644 "$work/unreadable.pem"
  echo "NOTE: running as root, so a file can't be made unreadable; skipped."
  cases=$((cases + 1))   # counted, so the total below still means every case was reached
fi

# The count, printed and checked. Showing it is the point: a case that silently stopped running is what made this
# suite green on a bundle it could prove nothing about.
echo "$cases cases ran against $source ($total certificates, $found of the two roots)"
[ "$cases" -eq "$expect_cases" ] || fail "$cases cases ran, expected $expect_cases. If you added or removed a case, set expect_cases to $cases; otherwise a case stopped running."
