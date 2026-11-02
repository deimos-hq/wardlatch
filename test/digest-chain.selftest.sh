#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Deimos AI LLC
#
# The positive control and the mutants for test/digest-chain.sh. A check nobody has shown can fail is not a
# check: this repository has found eleven measuring instruments broken in a day, and the commonest disguise for
# a blind one is a green run. So this builds a throwaway copy of the three files the chain is made of, makes
# them agree (the control: the check must say ok), and then plants one defect at a time -- each a defect that
# has actually happened here, or the next one of its kind -- and requires the check to FAIL on every one.
#
# Offline. Writes only inside its own mktemp directory. Never reads or writes /etc/ssl/cert.pem.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
chk=$root/test/digest-chain.sh
work=$(mktemp -d "${TMPDIR:-/tmp}/digest-chain-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT

cases=0 oks=0
ok() { cases=$((cases + 1)); oks=$((oks + 1)); echo "ok: $*"; }
fail() { echo "FAIL: $*"; exit 1; }

# A throwaway root whose four files agree. The script copy is a stand-in, not the real one: this is about the
# check, not about the fix, and a copy keeps the real digest out of the expected values.
# CHANGELOG.md is here because the check reads it. It is built holding a historical digest that is NOT the
# file's, on a line that says nothing about ci.yml -- which is what a real changelog looks like and what the
# changelog leg must tolerate, so the control proves the leg is about staleness and not about digests existing.
build() {
  rm -rf "$work/r"; mkdir -p "$work/r/fix" "$work/r/.github/workflows"
  printf '#!/bin/bash\n# a stand-in for fix/fix-macos.sh\necho hello\n' >"$work/r/fix/fix-macos.sh"
  chmod 755 "$work/r/fix/fix-macos.sh"
  d=$(shasum -a 256 "$work/r/fix/fix-macos.sh" | awk '{print $1}')
  {
    printf 'jobs:\n  fix:\n    steps:\n'
    printf '      - name: The Mac fix is the published file\n'
    printf '        run: echo "%s  fix/fix-macos.sh" | shasum -a 256 -c -\n' "$d"
  } >"$work/r/.github/workflows/ci.yml"
  printf 'Some prose.\n\nSHA-256 (`%s`). CI pins that hash.\n' "$d" >"$work/r/SECURITY.md"
  printf '# Changelog\n\n- an older release shipped `%s`, kept published because a download has no update channel.\n' \
    1111111111111111111111111111111111111111111111111111111111111111 >"$work/r/CHANGELOG.md"
}

# Runs the check on the throwaway root. Sets $code and $out.
# sed -i differs between macOS and Linux, and cat keeps the file's mode.
sub() { sed "$1" "$2" >"$2.new" && cat "$2.new" >"$2" && rm -f "$2.new"; }
chk() { code=0; out=$(bash "$chk" "$work/r" 2>&1) || code=$?; printf '%s\n' "$out" | sed 's/^/    | /'; }

# ---- POSITIVE CONTROL. Without this the mutants below prove only that the check always fails.
build; chk
[ "$code" -eq 0 ] || fail "the control: three files that agree must pass, got exit $code"
grep -q '^ok: the digest chain agrees' <<<"$out" || fail "the control: it did not say the chain agrees"
ok "CONTROL: a chain whose three files agree passes, so a FAIL below means something"

# ---- M1. SECURITY.md's digest off by one hex digit. This is the live defect of 1 Nov 2026, and of 31 Oct
# before it (bb4f9b8): the script and the pin moved and the printed digest did not.
build; sub "s/\`$d\`/\`${d%?}0\`/" "$work/r/SECURITY.md"; chk
[ "$code" -ne 0 ] || fail "M1: SECURITY.md printing another digest passed"
grep -q 'SECURITY.md prints' <<<"$out" || fail "M1: the failure did not name SECURITY.md's digest"
ok "M1 CAUGHT: SECURITY.md printing a digest that is not the file's"

# ---- M2. The ci.yml pin off by one hex digit: the leg CI already had, kept under this check too.
build; sub "s/$d/${d%?}0/" "$work/r/.github/workflows/ci.yml"; chk
[ "$code" -ne 0 ] || fail "M2: a wrong pin passed"
grep -q 'the pin in' <<<"$out" || fail "M2: the failure did not name the pin"
ok "M2 CAUGHT: the ci.yml pin not matching the file"

# ---- M3. The script edited, both copies of the digest left behind: the ordinary way this drifts.
build; printf '# one more comment\n' >>"$work/r/fix/fix-macos.sh"; chk
[ "$code" -ne 0 ] || fail "M3: an edited script with a stale pin and a stale printed digest passed"
grep -q 'the pin in' <<<"$out" && grep -q 'SECURITY.md prints' <<<"$out" || fail "M3: it did not name both stale copies"
ok "M3 CAUGHT: the script edited while the pin and the printed digest stayed, named on both legs"

# ---- M4. A second 64-digit digest in SECURITY.md. The completeness gate: with two, "the printed digest" is a
# choice, and a check that picks one quietly can pick the right one while the reader is shown the wrong one.
build; printf '\nAnd another hash: `%s`.\n' "$(printf 'a%.0s' $(seq 1 64))" >>"$work/r/SECURITY.md"; chk
[ "$code" -ne 0 ] || fail "M4: two printed digests passed"
grep -q 'needs exactly one' <<<"$out" || fail "M4: the failure did not say why one digest is required"
ok "M4 CAUGHT: SECURITY.md printing more than one digest, with the reason stated"

# ---- M5. The pin line gone. A check that reads a missing line as a match is the grep-read-as-no-match class
# this repository has already been bitten by twice.
build; sub '/shasum -a 256 -c -/d' "$work/r/.github/workflows/ci.yml"; chk
[ "$code" -ne 0 ] || fail "M5: ci.yml with no pin line at all passed"
grep -q 'expected exactly 1' <<<"$out" || fail "M5: it did not say the pin line is missing"
ok "M5 CAUGHT: ci.yml with no 'shasum -a 256 -c -' line"

# ---- M6. The execute bit off, everything else right: a download published with a checksum that cannot be run
# the way the page says to run it (gate A8).
build; chmod 644 "$work/r/fix/fix-macos.sh"; chk
[ "$code" -ne 0 ] || fail "M6: mode 644 passed"
grep -q 'mode 644' <<<"$out" || fail "M6: it did not name the mode"
ok "M6 CAUGHT: fix/fix-macos.sh not mode 755"

# ---- M7. shasum itself broken. The instrument check at the top of digest-chain.sh, driven directly: a stand-in
# that prints nothing must stop the run rather than compare an empty string with an empty string.
build
mkdir -p "$work/shim"
printf '#!/bin/bash\nexit 0\n' >"$work/shim/shasum"; chmod 755 "$work/shim/shasum"
code=0; out=$(PATH="$work/shim:$PATH" bash "$chk" "$work/r" 2>&1) || code=$?
printf '%s\n' "$out" | sed 's/^/    | /'
[ "$code" -ne 0 ] || fail "M7: a shasum that prints nothing passed"
grep -q 'did not give a 64-digit hex digest' <<<"$out" || fail "M7: it did not name the broken instrument"
ok "M7 CAUGHT: a shasum that prints nothing fails closed instead of comparing two empty strings"

# ---- M8. CHANGELOG.md naming a stale digest as the pinned one. The live defect of 2 Nov 2026: the round-5
# merge moved the script, the pin and SECURITY.md to a new digest and left one changelog entry saying the OLD
# one was "pinned in `ci.yml` in the same commit". That entry also tells the publisher to move the site's hash
# together with it, so a stale digest there is a wrong published hash waiting to happen -- and this check
# reported no failure, because its universe was three files and CHANGELOG.md was not one of them.
build; printf '\n- the fix is `%s`, pinned in `ci.yml` in the same commit.\n' \
  0000000000000000000000000000000000000000000000000000000000000000 >>"$work/r/CHANGELOG.md"; chk
[ "$code" -ne 0 ] || fail "M8: a changelog naming a stale digest as the pinned one passed"
grep -q 'CHANGELOG.md names' <<<"$out" || fail "M8: the failure did not name CHANGELOG.md"
ok "M8 CAUGHT: CHANGELOG.md calling a digest the pinned one when it is not the file's"

# ---- M8b. M8's control, and the reason the leg is written the way it is. SECURITY.md promises every digest
# the Mac fix has ever had stays published, so old digests belong in old entries forever. A leg that merely
# banned digests from the changelog would forbid that. The CORRECT digest beside the same words must pass.
build; printf '\n- the fix is `%s`, pinned in `ci.yml` in the same commit.\n' "$d" >>"$work/r/CHANGELOG.md"; chk
[ "$code" -eq 0 ] || fail "M8b: the correct digest beside those words was rejected, so the leg forbids the history SECURITY.md requires: $out"
ok "M8b CONTROL: the correct digest on a ci.yml line is accepted, so the leg is about staleness, not about digests existing"

echo "$cases cases ran; $oks said ok"
[ "$cases" -eq "$oks" ] || fail "a case was counted without saying ok"
[ "$cases" -eq 10 ] || fail "$cases cases ran, expected 10 (1 control + 7 mutants + M8 and its control M8b). If you added one, change this number."
