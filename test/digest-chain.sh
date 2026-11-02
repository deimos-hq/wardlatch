#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# The digest chain, checked mechanically: fix/fix-macos.sh's own SHA-256, the pin CI runs in
# .github/workflows/ci.yml, and the digest SECURITY.md prints to the reader must all be one string.
#
# Why this exists. Until 1 Nov 2026 CI compared the script to one number typed in one file, and every other copy
# of that number was unguarded prose. The chain drifted twice in forty-eight hours: bb4f9b8 (31 Oct) fixed
# SECURITY.md after it printed the round-3 digest, and by 1 Nov it was wrong again -- fb4001a and b749850 moved
# the script and the pin and SECURITY.md did not move with them, so the file hashed 464e3bbe..., CI pinned
# 464e3bbe... and SECURITY.md told the reader d8a4bffd..., a digest that belonged to neither. Four reviewers were
# reading that tree at the time. A hand-coordinated invariant with a one-way check is not a mechanism; this is.
#
# It runs offline, reads nothing but these three files, and writes nothing.
# Usage: bash test/digest-chain.sh [root]      (root defaults to this repository; a copy is for the self-test)
set -euo pipefail

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
f=$root/fix/fix-macos.sh
ci=$root/.github/workflows/ci.yml
sec=$root/SECURITY.md

bad=0
fail() { echo "FAIL: $*"; bad=1; }

for p in "$f" "$ci" "$sec"; do
  [ -r "$p" ] || { echo "FAIL: $p is not readable, so the chain cannot be checked"; exit 1; }
done

# The instrument first. A digest read as the empty string, or shasum failing without saying so, would make every
# comparison below pass for the wrong reason -- the class of defect this repository has found eleven times.
actual=$(shasum -a 256 "$f" | awk '{print $1}')
case "$actual" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "FAIL: shasum did not give a 64-digit hex digest for $f (got '$actual'), so nothing below means anything"; exit 1 ;;
esac

# The pin, taken from the line CI actually runs rather than from anywhere in the file: a digest in a comment is
# not what CI compares against. Exactly one such line, carrying exactly one digest, or this says so -- "they
# agree" read off an empty set is the failure this file exists to prevent.
pinlines=$(grep -c 'shasum -a 256 -c -' "$ci" || true)
[ "$pinlines" -eq 1 ] || fail "$ci has $pinlines lines running 'shasum -a 256 -c -', expected exactly 1: this check cannot tell which digest CI pins"
pin=$(grep 'shasum -a 256 -c -' "$ci" | grep -o '[0-9a-f]\{64\}' || true)
[ "$(printf '%s\n' "$pin" | grep -c .)" -eq 1 ] || fail "the pin line in $ci carries $(printf '%s\n' "$pin" | grep -c .) 64-digit digests, expected exactly 1"

# And the digest SECURITY.md prints. Its universe is stated: every 64-digit hex string in the whole file, which
# must be exactly one, so that "the printed digest" is not a choice this check makes quietly. If a second digest
# ever belongs in SECURITY.md, this fails until someone teaches it which one is the Mac fix's -- deliberately.
secall=$(grep -o '[0-9a-f]\{64\}' "$sec" || true)
secn=$(printf '%s\n' "$secall" | grep -c . || true)
if [ "$secn" -ne 1 ]; then
  fail "$sec prints $secn 64-digit hex digests, and this check needs exactly one so that 'the digest SECURITY.md prints' is unambiguous. If another digest now belongs there, teach this check which one is the Mac fix's."
  sec_digest=''
else
  sec_digest=$secall
fi

[ "$pin" = "$actual" ] || fail "the pin in $ci is $pin and fix/fix-macos.sh hashes $actual"
if [ -n "$sec_digest" ]; then
  [ "$sec_digest" = "$actual" ] || fail "SECURITY.md prints $sec_digest and fix/fix-macos.sh hashes $actual"
  [ "$sec_digest" = "$pin" ] || fail "SECURITY.md prints $sec_digest and the pin in $ci is $pin"
fi

# Mode travels with the digest: a download published with a checksum and no execute bit is still a broken
# instruction ("run bash ~/Downloads/..."), and gate A8 names it.
mode=$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f")
[ "$mode" = 755 ] || fail "fix/fix-macos.sh is mode $mode, expected 755"

if [ "$bad" -ne 0 ]; then
  echo "The digest chain is out of step. The script, the pin CI runs and the digest SECURITY.md prints move together or not at all."
  exit 1
fi
echo "ok: the digest chain agrees -- fix/fix-macos.sh, the ci.yml pin and SECURITY.md all say $actual (mode $mode)"
