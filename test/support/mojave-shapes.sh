#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# THE CASE NO TEST COVERED: one withdrawn root present, the other already absent.
#
# Every existing case assumes a bundle holds BOTH roots or NEITHER. On 29 Oct 2026 a Mid-2013 MacBook Air
# running macOS 10.14.6 was measured with its owner's consent, and its /etc/ssl/cert.pem (OpenBSD rev 1.15,
# 2017-02-24, 77 certificates) held `AAA Certificate Services` and did NOT hold `emSign ECC Root CA - G3`:
# Apple added emSign after Mojave shipped. So the one-present shape is not hypothetical, it is what every
# un-updated Mac of that era looks like, and the fix had never been run against it.
#
# Shapes exercised here, built from this machine's own bundle so no one else's file is needed:
#   A  both roots present        (current macOS)
#   B  AAA only, emSign removed  (THE MOJAVE SHAPE)
#   C  emSign only, AAA removed  (the mirror, to catch logic that only handles the first entry)
#   D  neither root present      (an already-fixed machine)
#   E  a bundle too small for the floor at the top of the script, holding neither root (refused, nothing changed,
#      and since 30 Oct 2026 not called damaged and not sent back to a backup)
#
# Shape E has never reached the SECOND floor the script carried, on the rebuilt file: 12 certificates are refused
# at the top, so that branch stayed untested, and on 30 Oct 2026 it turned out to be unreachable by anything except
# a correct result -- it is gone, and fix/fix-macos.sh says why above the checks on the cleaned file. The case that
# does reach that arithmetic is a 50-certificate bundle, in test/fix-macos.check.sh.
#
# Offline and deterministic: a stub curl that exits 7 stands in for every probe, so no request leaves this machine
# and the "an ordinary website didn't load" branch is what gets exercised -- which is also the real branch on a
# machine with no network. WARDLATCH_CERT_FILE keeps every write inside a temp folder under TMPDIR; /etc/ssl is never
# touched and sudo is never invoked (the file and its folder are writable, so the fix sets SUDO empty). CI runs this
# on macOS since 31 Oct 2026; until then it ran nowhere but by hand.
#
# The stub is reached through WARDLATCH_CURL in a COPY of the script, the way test/fix-macos.check.sh does it.
# Until 29 Oct 2026 this put a `curl` on PATH instead -- which the fix never consulted, because it calls
# /usr/bin/curl by absolute path on purpose. So the stub was dead code, every shape made live requests to
# www.apple.com and to the advisory's test host, each shape's result depended on what the network answered that
# minute, and the branch this header claimed to exercise was not the branch taken. Shape A printing "now refuses
# the compromised keys" was the proof: that line cannot be reached with a curl that exits 7.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
FIX="$REPO/fix/fix-macos.sh"
# The bundle under test. Defaults to the vendored UNFIXED fixture so this harness does not require
# the machine running it to be vulnerable. Pass a path to test a different bundle, including the live one.
SRC=${1:-"$REPO/test/support/fixtures/macos-27.2-cert.pem"}
AAA='D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4'
EMS='86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B'

# Under TMPDIR, like everything else the tests make. Until 31 Oct 2026 this was a hard-coded /tmp, so a run whose
# TMPDIR was its own scratch folder still wrote here.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mojave-shapes.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
printf '#!/bin/sh\nexit 7\n' > "$WORK/bin/curl"   # no probe ever answers, deterministically
chmod +x "$WORK/bin/curl"
# The copy under test: the shipped script with its one network command behind WARDLATCH_CURL, and nothing else
# changed. If the substitution matches nothing, say so and stop rather than quietly test the real network.
RUN="$WORK/fix-stubbed.sh"
sed 's|/usr/bin/curl|"${WARDLATCH_CURL:-/usr/bin/curl}"|g' "$FIX" > "$RUN"
if cmp -s "$FIX" "$RUN"; then
  echo "FAIL: no /usr/bin/curl call site found in $FIX, so these shapes would reach the real network. Nothing run."
  exit 2
fi

# Split the bundle into one file per certificate. `inblock` matters: cert.pem carries each certificate's name
# and a full openssl text dump BETWEEN blocks, and printing those reopens a closed handle -- the bug that made
# the Mojave run report an absence from 17 of 77 certificates.
split_certs() {
  awk -v d="$1" '/BEGIN CERTIFICATE/ { n++; f = sprintf("%s/c%04d.pem", d, n); inblock = 1 }
                 inblock { print >> f }
                 /END CERTIFICATE/ { if (inblock) { close(f); inblock = 0 } }' "$SRC"
}

# Rebuild a bundle, dropping any certificate whose fingerprint is in $2, and keeping at most $3 of the rest.
build() { # $1 = out file, $2 = fingerprints to drop (newline separated), $3 = max certs or "all"
  local out=$1 drop=$2 cap=$3 d kept=0
  d=$(mktemp -d "$WORK/split.XXXXXX"); split_certs "$d"
  : > "$out"
  for c in "$d"/c*.pem; do
    [ -e "$c" ] || continue
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
    case "$drop" in *"$fp"*) [ -n "$fp" ] && continue ;; esac
    [ "$cap" = all ] || [ "$kept" -lt "$cap" ] || continue
    cat "$c" >> "$out"; kept=$((kept+1))
  done
  rm -rf "$d"
  echo "$kept"
}

has() { # does bundle $1 contain fingerprint $2
  local d found=no
  d=$(mktemp -d "$WORK/chk.XXXXXX")
  awk -v d="$d" '/BEGIN CERTIFICATE/ { n++; f = sprintf("%s/c%04d.pem", d, n); inblock = 1 }
                 inblock { print >> f }
                 /END CERTIFICATE/ { if (inblock) { close(f); inblock = 0 } }' "$1"
  for c in "$d"/c*.pem; do
    [ -e "$c" ] || continue
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
    [ "$fp" = "$2" ] && found=yes
  done
  rm -rf "$d"; echo "$found"
}

fails=0
shape() { # $1 = label, $2 = bundle, $3 = expected exit, $4 = expected text fragment
  local f="$WORK/run-$1.pem"
  cp "$2" "$f"
  out=$(cd "$WORK" && WARDLATCH_CERT_FILE="$f" WARDLATCH_CURL="$WORK/bin/curl" /bin/bash "$RUN" 2>&1); code=$?
  local certs_after; certs_after=$(grep -c 'BEGIN CERTIFICATE' "$f")
  local still_aaa still_ems
  still_aaa=$(has "$f" "$AAA"); still_ems=$(has "$f" "$EMS")
  local verdict=PASS
  [ "$code" = "$3" ] || verdict="FAIL exit=$code want=$3"
  case "$out" in *"$4"*) ;; *) verdict="FAIL text" ;; esac
  # whatever the fix claims, NEITHER root may remain in a bundle it reports as fixed
  if [ "$code" = 0 ] && { [ "$still_aaa" = yes ] || [ "$still_ems" = yes ]; }; then
    verdict="FAIL a root survived a run that exited 0"
  fi
  [ "$verdict" = PASS ] || fails=$((fails+1))
  printf '  %-26s exit=%-2s certs=%-4s AAA=%-4s emSign=%-4s %s\n' "$1" "$code" "$certs_after" "$still_aaa" "$still_ems" "$verdict"
  printf '      %s\n' "$out"
}

echo "building shapes from $SRC ($(grep -c 'BEGIN CERTIFICATE' "$SRC") certificates)"
n_both=$(build "$WORK/both.pem"   ""                all)
n_aaa=$( build "$WORK/aaaonly.pem" "$EMS"           all)
n_ems=$( build "$WORK/emsonly.pem" "$AAA"           all)
n_none=$(build "$WORK/none.pem"    "$AAA
$EMS"                                               all)
n_tiny=$(build "$WORK/tiny.pem"    ""               12)
echo "  both=$n_both  AAA-only=$n_aaa  emSign-only=$n_ems  neither=$n_none  tiny=$n_tiny"
echo

echo "A  both roots present (current macOS):"
shape both "$WORK/both.pem" 0 "removed both withdrawn roots"
# The fix names the root it removed and says this FILE did not hold the other. Until 31 Oct 2026 it said "the other
# was already absent from this Mac", a claim about a Mac that one file cannot show, and these two shapes asserted it.
echo "B  AAA only, emSign already absent  <-- THE MOJAVE SHAPE:"
shape aaa-only "$WORK/aaaonly.pem" 0 "removed AAA Certificate Services (this file did not hold the other withdrawn root, emSign ECC Root CA - G3)"
echo "C  emSign only, AAA already absent (the mirror):"
shape ems-only "$WORK/emsonly.pem" 0 "removed emSign ECC Root CA - G3 (this file did not hold the other withdrawn root, AAA Certificate Services)"
echo "D  neither root present (already fixed):"
# "no longer holds the two roots", not "neither": shape() writes the bundle to $WORK/run-neither.pem and the fix
# echoes that path in every line, so the old expected fragment "neither" matched the FILENAME and the assertion
# could not fail whatever the script printed.
shape neither "$WORK/none.pem" 0 "no longer holds the two roots"
echo "E  a bundle under the 50-certificate floor, holding neither root:"
# The floor's own words for THIS branch, not merely "UNKNOWN": the fix prints UNKNOWN on a dozen other paths, so
# matching that alone would have passed for almost any refusal, however it was reached or explained. Since
# 30 Oct 2026 the floor's two branches say different things, and this bundle holds neither withdrawn root, so the
# words to expect are the ones that say so. "fewer than the 50 this expects" was matched here until then and is
# not enough on its own any more: the floor said that while also calling the file damaged and telling the reader
# to put a backup back, which on this branch means reverting a correct result to a file holding both roots.
shape tiny "$WORK/tiny.pem" 2 "It holds neither"

echo
if [ "$fails" = 0 ]; then
  echo "all shapes behaved as expected -- which for this file means the EXPECTATIONS need challenging,"
  echo "not that the fix is proven. A run that finds nothing has not confirmed anything."
  exit 0
else
  echo "$fails shape(s) did not behave as expected. Each is a finding."
  # Non-zero, so this can gate something. It exited 0 whatever happened until 29 Oct 2026, which made it a
  # report nobody could act on automatically.
  exit 1
fi
