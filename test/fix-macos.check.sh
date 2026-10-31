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
# With the network, the shipped script's own probes reach the advisory's test host and www.apple.com. Every case also
# runs, and must pass, with no network at all: the cases about what the network says use a stub, and that is how this
# is run offline (inside sandbox-exec with outbound network denied). Until 31 Oct 2026 this line said the harness
# needs the network, and it never did.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
fix="$root/fix/fix-macos.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/fix-macos-check.XXXXXX")
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
source=${1:-"$root/test/support/fixtures/macos-27.2-cert.pem"}
# Every case that reports ok counts itself, and the end of the run checks the total: a case that stops running
# because the bundle under test no longer has the shape it needs must not pass as silence. Bump this when you add
# a case, and the run tells you the number to put here.
expect_cases=94
# Cases that could not run on this machine, by name, each with a NOTE where it was skipped. Only two things put a
# case here: running as root (a file can't be made unreadable to root) and running inside another sandbox
# (sandbox-exec can't apply a second profile), and the second only when WL_NESTED_SANDBOX=1 says so.
notrun=''

fail() { echo "FAIL: $*"; exit 1; }
cases=0
# oks counts the "ok:" lines printed; only ok() adds to either count, and the end of the run checks they agree, so a
# case cannot be counted as run without saying ok (the third read's M7: a skipped case did exactly that, under root).
oks=0
ok() { cases=$((cases + 1)); oks=$((oks + 1)); echo "ok: $*"; }
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
# Each run gets its own TMPDIR, which must be empty afterwards, and must print nothing on stderr. Since 31 Oct 2026
# the fix makes its temporary files where TMPDIR says, so that check watches the folder they are really in.
# On macOS every run must also print a line that starts with SAFE, EXPOSED or UNKNOWN, whatever it exits with: the
# page publishes that each run does, and an exit 2 with no line tells the reader to read a line that is not there.
# Three flags relax one check each, for a run that is about something else: stderr_ok (the case reads $work/stderr
# itself), leak_ok (a copy whose cleanup is broken on purpose), silent_ok (a copy with a check taken out, which must
# end silently to prove the check is what printed the line).
# $script is the script it runs: the shipped one, except in the network cases at the end, which point it at a copy
# whose one network command is a stub (no real network can be made to answer those ways on demand).
script=$fix
stderr_ok='' leak_ok='' silent_ok=''
run() {
  local file=$1; shift
  code=0
  rm -rf "$work/tmp"; mkdir "$work/tmp"
  out=$(env "$@" TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$file" bash "$script" 2>"$work/stderr") || code=$?
  printf '%s\n' "$out" | sed 's/^/    | /'
  if [ -z "$stderr_ok" ] && [ -s "$work/stderr" ]; then sed 's/^/    ! /' "$work/stderr"; fail "the fix wrote to stderr"; fi
  if [ -z "$leak_ok" ]; then
    left=$(find "$work/tmp" -mindepth 1 -maxdepth 1 -exec basename {} \; | tr '\n' ' ')
    [ -z "$left" ] || fail "the fix left temporary files behind: $left"
  fi
  if [ "$(uname -s)" = Darwin ] && [ -z "$silent_ok" ] && ! printf '%s\n' "$out" | grep -qE '^(SAFE|EXPOSED|UNKNOWN) '; then
    fail "the fix exited $code and printed no line starting SAFE, EXPOSED or UNKNOWN"
  fi
  return 0
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

# The entry floor's OLD shape, for the three cases below that have to fail on it: the floor as it stood until
# 30 Oct 2026, put back where it stood -- immediately after the snapshot, before anything in the file had been
# read. It fires there and exits, so nothing after it runs, which is exactly the behaviour it had.
cat >"$work/oldentry.txt" <<'OLDENTRY'
if [ "$(certs "$snap")" -lt 50 ]; then
  echo "UNKNOWN  $FILE holds only $(certs "$snap") certificates, fewer than the 50 this expects of a trust store, so it"
  echo "         looks damaged. Nothing changed."
  echo "         Put a backup back (ls $FILE*.bak; sudo cp -p <backup> $FILE), then run this again."
  exit 2
fi
OLDENTRY
awk -v bf="$work/oldentry.txt" '
  { print }
  /^cp "\$FILE" "\$snap" 2>\/dev\/null/ { while ((getline l < bf) > 0) print l; close(bf) }' "$fix" >"$work/oldentry.sh"
cmp -s "$fix" "$work/oldentry.sh" && fail "the entry floor: the snapshot line was not found in $fix, so the floor cases below prove nothing"

# ---- r2: setup
# What the cases added on 31 Oct 2026 share, after an independent read found defects the cases above could not see.
# Each of those cases (marked "r2 case") stands on this setup alone, so it can be run by itself -- and shown failing
# on the script as it was. They need a bundle in Apple's shape holding both withdrawn roots, which the default
# fixture is.
if [ "$found" -ne 2 ] || ! grep -q '^=== ' "$work/original.pem"; then
  fail "the cases below need a bundle in Apple's shape holding both withdrawn roots (the default fixture is one); $source holds $found and no '=== ' name lines"
fi
r2=$work/r2
mkdir "$r2"
# Files a run left beside a bundle: the fix's own temporary names there, which must never outlive a run.
beside() { find "$(dirname "$1")" -maxdepth 1 -name '.wardlatch-*' -exec basename {} \; | tr '\n' ' '; }
# Dated backups beside one bundle (backups() above searches all of $work by name, and these cases share names).
baks() { find "$(dirname "$1")" -maxdepth 1 -name "$(basename "$1").wardlatch-*.bak" | wc -l | tr -d ' '; }
# Certificates as LibreSSL counts them: lines that START with the marker (count() above matches it anywhere).
certs_in() { grep -c '^-----BEGIN CERTIFICATE-----' "$1" || true; }
# The two withdrawn roots and one ordinary certificate, PEM only, picked out of the bundle by fingerprint.
mkdir "$r2/split"
awk -v d="$r2/split" '/^-----BEGIN CERTIFICATE-----/{k++; f=sprintf("%s/%05d.pem", d, k)} f{print > f} /^-----END CERTIFICATE-----/{close(f); f=""}' "$work/original.pem"
for c in "$r2/split"/*.pem; do
  case "$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null)" in
    *=D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4) cp "$c" "$r2/aaa.pem" ;;
    *=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B) cp "$c" "$r2/ems.pem" ;;
  esac
done
cp "$r2/split/00001.pem" "$r2/other.pem"
if [ ! -s "$r2/aaa.pem" ] || [ ! -s "$r2/ems.pem" ]; then fail "setup: the two withdrawn roots were not found by fingerprint"; fi
# A line of each certificate's base64 that no other certificate in the bundle has: how a stand-in recognises it.
aaa_line=$(sed -n 2p "$r2/aaa.pem"); other_line=$(sed -n 2p "$r2/other.pem")
if [ "$(grep -cF -- "$aaa_line" "$work/original.pem")" -ne 1 ] || [ "$(grep -cF -- "$other_line" "$work/original.pem")" -ne 1 ]; then
  fail "setup: a certificate's second line is not unique in the bundle"
fi
# AAA Certificate Services as Apple's file carries it: its "=== " name line, the text dump, and the certificate.
awk '/^=== .*\/CN=AAA Certificate Services$/{p=1} p{print} p && /^-----END CERTIFICATE-----/{exit}' "$work/original.pem" >"$r2/aaa-entry.pem"
grep -q '^SHA256 Fingerprint=D7:A7:A0:FB' "$r2/aaa-entry.pem" || fail "setup: AAA Certificate Services's entry was not found"
# An ordinary root of our own, standing for the corporate TLS-inspection root an administrator appends to this file.
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout "$r2/corp.key" -out "$r2/corp.pem" -days 30 \
  -subj "/CN=Example Corp TLS Inspection Root" >/dev/null 2>&1 || fail "setup: openssl could not make a certificate"
# The advisory's own removal, which is the file every successful run on this bundle must leave; and the two one-root
# shapes, each Apple's file with one root's whole entry taken out (the Mojave shape, and its mirror).
adv() { awk -v re="$1" '/^(###|===) /{skip=0} $0 ~ re {skip=1} !skip' "$work/original.pem"; }
adv '^=== .*/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$' >"$r2/P.pem"
adv '^=== .*/CN=emSign ECC Root CA - G3$' >"$r2/aaaonly.pem"
adv '^=== .*/CN=AAA Certificate Services$' >"$r2/emsonly.pem"
if [ "$(count "$r2/P.pem")" -ne $((total - 2)) ] || [ "$(bad "$r2/P.pem")" -ne 0 ]; then
  fail "setup: the advisory's removal did not leave $((total - 2)) certificates and no root"
fi
if [ "$(count "$r2/aaaonly.pem")" -ne $((total - 1)) ] || [ "$(count "$r2/emsonly.pem")" -ne $((total - 1)) ]; then
  fail "setup: a one-root shape has the wrong count"
fi
# Copies of the script with one command behind a stand-in, and nothing else changed: the network (curl), as in the
# network cases below, and the fingerprinting (openssl). Every call site must be behind it, or that path would reach
# the real command and pass for the wrong reason.
behind() {   # $1 = absolute path of the command, $2 = variable, $3 = out file, $4 = the fewest call sites there can be
  sed "s|$1|\"\${$2:-$1}\"|g" "$fix" >"$3"
  [ "$(grep -o "$1" "$fix" | wc -l | tr -d ' ')" -ge "$4" ] || fail "setup: $1 has fewer than $4 call sites in $fix"
  [ "$(grep -o "$2:-$1" "$3" | wc -l | tr -d ' ')" -eq "$(grep -o "$1" "$fix" | wc -l | tr -d ' ')" ] ||
    fail "setup: not every $1 call site in $fix is behind \$$2"
  return 0
}
behind /usr/bin/curl WARDLATCH_CURL "$r2/net.sh" 2
behind /usr/bin/openssl WARDLATCH_OPENSSL "$r2/ossl.sh" 1
cat >"$r2/curl" <<'STUB'
#!/bin/bash
# Stands in for /usr/bin/curl. The advisory's test host gets $STUB_TEST. A control call gets $STUB_CONTROL, or, when
# $STUB_CONTROLS is set, the next of its answers, one per call, the last repeating (counted in $STUB_STATE). With
# STUB_HOLD=1 the first control call touches $WL_MARK and waits, so a case can stop the run there.
# r4: STUB_ONLY_FILE=1: a call whose --cacert is not $WARDLATCH_CERT_FILE itself gets 77, an answer nothing expects.
# STUB_MARK_TEST=1: the call to the test host touches $WL_MARK first (the last reading a run takes).
if [ -n "${STUB_ONLY_FILE:-}" ]; then prev=''; for a in "$@"; do if [ "$prev" = --cacert ] && [ "$a" != "$WARDLATCH_CERT_FILE" ]; then exit 77; fi; prev=$a; done; fi
case "$*" in *we-have-a-problem.com*) [ -z "${STUB_MARK_TEST:-}" ] || : >"$WL_MARK" ;; esac
case "$*" in *we-have-a-problem.com*) exit "${STUB_TEST:?}" ;; esac
n=$(cat "${STUB_STATE:-/dev/null}" 2>/dev/null); n=$(( ${n:-0} + 1 ))
[ -z "${STUB_STATE:-}" ] || printf '%s' "$n" >"$STUB_STATE"
if [ "${STUB_HOLD:-}" = 1 ] && [ "$n" = 1 ]; then : >"$WL_MARK"; /bin/sleep 3; fi
[ -n "${STUB_CONTROLS:-}" ] || exit "${STUB_CONTROL:?}"
i=1; last=0
for a in $STUB_CONTROLS; do last=$a; [ "$i" = "$n" ] && exit "$a"; i=$((i + 1)); done
exit "$last"
STUB
cat >"$r2/openssl" <<'STUB'
#!/bin/bash
# Stands in for /usr/bin/openssl. `x509` on the one certificate whose PEM holds $STUB_MATCH prints $STUB_OUT (nothing
# at all when it is empty) and exits 0, as an openssl that failed without saying so would. Anything else is the real
# openssl, given the same input (from -in, or from stdin).
[ "$1" = x509 ] || exec /usr/bin/openssl "$@"
in=''; prev=''
for a in "$@"; do [ "$prev" = -in ] && in=$a; prev=$a; done
if [ -n "$in" ]; then pem=$(cat "$in"); else pem=$(cat); fi
case "$pem" in *"$STUB_MATCH"*) [ -z "${STUB_OUT:-}" ] || printf '%s\n' "$STUB_OUT"; exit 0 ;; esac
printf '%s\n' "$pem" | /usr/bin/openssl "$@"
STUB
# Stand-ins for cp, mv, mktemp, chmod and sudo, first on PATH for the cases that need a copy, a rename or a temporary
# file to fail, stop, race or be tampered with -- none of which a real disk or a real person can do on demand. With
# no WL_ variable set, each passes straight through to the real command, except sudo, which always refuses: no case
# here may run the real sudo.
shims=$r2/shims
mkdir "$shims"
cat >"$shims/cp" <<'SHIM'
#!/bin/bash
# The fix copies in three ways: the snapshot (cp FILE snap), the backup (cp -p FILE x), and the file it is about to
# rename into place (cp SRC <dir>/.wardlatch-new.*, or, in a copy that writes in place, cp SRC FILE), whose source is
# the cleaned file -- or the backup, *.bak, for the restore.
src=''; dst=''
for a in "$@"; do src=$dst; dst=$a; done
file=${WARDLATCH_CERT_FILE:-}
bk=''; [ "$1" = -p ] && [ "$src" = "$file" ] && bk=1
fwd=''
case "$dst" in */.wardlatch-new.*) fwd=1 ;; esac
[ "$dst" = "$file" ] && fwd=1
case "$src" in *.bak) fwd='' ;; esac
[ "$src" = "$file" ] && fwd=''
rs=''; case "$src" in *.bak) case "$dst" in */.wardlatch-new.*) rs=1 ;; esac ;; esac
case "${WL_CP:-}" in
  tamper-backup) if [ -n "$bk" ]; then /bin/cp "$@" || exit; echo tampered >>"$dst"; exit 0; fi ;;
  partial-backup) if [ -n "$bk" ]; then head -c 100000 "$src" >"$dst"; exit 1; fi ;;
  race-before-backup) if [ -n "$bk" ]; then cat "$WL_CORP" >>"$src"; exec /bin/cp "$@"; fi ;;
  race-after-backup) if [ -n "$bk" ]; then /bin/cp "$@"; r=$?; cat "$WL_CORP" >>"$src"; exit "$r"; fi ;;
  sig-backup) if [ -n "$bk" ]; then head -c 100000 "$src" >"$dst"; : >"$WL_MARK"; /bin/sleep 3; exit 1; fi ;;
  partial-new) if [ -n "$fwd" ]; then head -c 1000 "$src" >"$dst"; exit 1; fi ;;
  kill-in-new) if [ -n "$fwd" ]; then head -c 500 "$src" >"$dst"; kill -TERM "$PPID"; /bin/sleep 1; exit 1; fi ;;
  tamper-new-append) if [ -n "$fwd" ]; then cat "$WL_TAMPER" >>"$src"; exec /bin/cp "$@"; fi ;;
  tamper-new-swap)
    if [ -n "$fwd" ]; then
      awk -v t="$WL_TAMPER" 'BEGIN { while ((getline l < t) > 0) rep = rep l "\n" }
        /^-----BEGIN CERTIFICATE-----/ && !done { skip = 1 }
        skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0; done = 1 }; next }
        { print }' "$src" >"$src.swap" && /bin/mv "$src.swap" "$src"
      exec /bin/cp "$@"
    fi ;;
  sig-restore-cp) if [ -n "$rs" ]; then : >"$WL_MARK"; /bin/sleep 3; exec /bin/cp "$@"; fi ;;
  # r3: the snapshot copy (cp FILE <TMPDIR file>, no -p) failing on a full temporary folder.
  full-snap) if [ -z "$bk" ] && [ "$src" = "$file" ]; then head -c 1000 "$src" >"$dst"; echo "cp: $dst: No space left on device" >&2; exit 1; fi ;;
  # r3: the snapshot in the invoking user's temporary folder swapped for $WL_VARIANT by a same-user process -- at the
  # copy itself (swap-early), or at the first grep that reads it (swap-late, done by the grep stand-in) -- and put back
  # just before the backup copy, so the backup and the snapshot compare equal again.
  swap-early|swap-late)
    if [ -z "$bk" ] && [ "$src" = "$file" ]; then
      printf '%s' "$dst" >"$WL_SWAP_STATE"
      [ "$WL_CP" = swap-late ] || exec /bin/cp "$WL_VARIANT" "$dst"
      exec /bin/cp "$@"
    fi
    if [ -n "$bk" ] && [ -s "$WL_SWAP_STATE" ]; then /bin/cp "$file" "$(cat "$WL_SWAP_STATE")"; exec /bin/cp "$@"; fi ;;
  # r3: the cleaned file in the temporary folder has one certificate swapped for $WL_TAMPER while the backup is copied
  # (after the cleaned file was built and its SHA-256 taken, before it is copied beside the bundle).
  tamper-tmp-at-backup)
    if [ -n "$bk" ]; then
      for t in "${TMPDIR:-/tmp}"/wardlatch.*; do
        cmp -s "$t" "$file" && continue
        awk -v t="$WL_TAMPER" 'BEGIN { while ((getline l < t) > 0) rep = rep l "\n" }
          /^-----BEGIN CERTIFICATE-----/ && !done { skip = 1 }
          skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0; done = 1 }; next }
          { print }' "$t" >"$t.swap" && /bin/mv "$t.swap" "$t"
      done
      exec /bin/cp "$@"
    fi ;;
  # r3: another backup appears under the dated name between the script's check that the name is free and its link.
  take-bak-name) if [ -n "$bk" ]; then /bin/cp "$@" || exit; echo 'an earlier backup' >"$file.wardlatch-$WL_DATE.bak"; exit 0; fi ;;
esac
exec /bin/cp "$@"
SHIM
cat >"$shims/mv" <<'SHIM'
#!/bin/bash
# The fix renames one thing into place: <dir>/.wardlatch-new.* over the bundle, forward and, for the restore, again.
src=''; dst=''
for a in "$@"; do src=$dst; dst=$a; done
into=''
if [ "$dst" = "${WARDLATCH_CERT_FILE:-}" ]; then case "$src" in */.wardlatch-new.*) into=1 ;; esac; fi
[ -n "$into" ] || exec /bin/mv "$@"
n=$(cat "${WL_MV_STATE:-/dev/null}" 2>/dev/null); n=$(( ${n:-0} + 1 ))
[ -z "${WL_MV_STATE:-}" ] || printf '%s' "$n" >"$WL_MV_STATE"
case "${WL_MV:-}" in
  fail) exit 1 ;;
  sig-forward) /bin/mv "$@"; r=$?; : >"$WL_MARK"; /bin/sleep 3; exit "$r" ;;
  mismatch) /bin/mv "$@"; r=$?; [ "$n" != 1 ] || echo '# another writer' >>"$dst"; exit "$r" ;;
  mismatch-sig-restore)
    /bin/mv "$@"; r=$?
    if [ "$n" = 1 ]; then echo '# another writer' >>"$dst"; else : >"$WL_MARK"; /bin/sleep 3; fi
    exit "$r" ;;
esac
exec /bin/mv "$@"
SHIM
cat >"$shims/mktemp" <<'SHIM'
#!/bin/bash
# Fails the WL_MKTEMP_FAIL-th call (counted in WL_MKTEMP_STATE), as a full or unwritable folder would;
# WL_MKTEMP_LOG records the path of every file it makes. WL_MKTEMP_ORPHAN=new or backup makes the file beside the
# bundle of that kind and then fails without printing its name, as when a signal stops mktemp before the name
# reaches the script.
n=$(cat "${WL_MKTEMP_STATE:-/dev/null}" 2>/dev/null); n=$(( ${n:-0} + 1 ))
[ -z "${WL_MKTEMP_STATE:-}" ] || printf '%s' "$n" >"$WL_MKTEMP_STATE"
if [ "$n" = "${WL_MKTEMP_FAIL:-0}" ]; then echo "mktemp: mkstemp failed on $*: No space left on device" >&2; exit 1; fi
# r3: WL_MKTEMP_HOLD=1 makes the first file, then touches $WL_MARK and waits before printing its name, so a case can
# send a signal while the name has not yet reached the script.
if [ "${WL_MKTEMP_HOLD:-}" = 1 ] && [ "$n" = 1 ]; then p=$(/usr/bin/mktemp "$@") || exit; : >"$WL_MARK"; /bin/sleep 3; echo "$p"; exit 0; fi
# r4: WL_MKTEMP_ORPHAN=tmp does the same for a file in TMPDIR (wardlatch.*).
if [ "${WL_MKTEMP_ORPHAN:-}" = tmp ]; then
  for a in "$@"; do case "$a" in "${TMPDIR:-/tmp}"/wardlatch.*) /usr/bin/mktemp "$@" >/dev/null; exit 1 ;; esac; done
fi
if [ -n "${WL_MKTEMP_ORPHAN:-}" ]; then
  for a in "$@"; do case "$a" in */.wardlatch-"$WL_MKTEMP_ORPHAN".*) /usr/bin/mktemp "$@" >/dev/null; exit 1 ;; esac; done
fi
p=$(/usr/bin/mktemp "$@") || exit
[ -z "${WL_MKTEMP_LOG:-}" ] || echo "$p" >>"$WL_MKTEMP_LOG"
echo "$p"
SHIM
cat >"$shims/chmod" <<'SHIM'
#!/bin/bash
if [ "${WL_CHMOD:-}" = fail-new ]; then for a in "$@"; do case "$a" in */.wardlatch-new.*) exit 1 ;; esac; done; fi
# r3: race-new appends $WL_CORP to the bundle while the new file is being made beside it, after the backup was taken.
if [ "${WL_CHMOD:-}" = race-new ]; then for a in "$@"; do case "$a" in */.wardlatch-new.*) cat "$WL_CORP" >>"$WARDLATCH_CERT_FILE" ;; esac; done; fi
exec /bin/chmod "$@"
SHIM
cat >"$shims/sudo" <<'SHIM'
#!/bin/bash
# A refused password, three times, or no answer in time. Never the real sudo. r3: with WL_SUDO=grant it grants every
# call (runs the command as this user; `-v` succeeds) except the WL_SUDO_REFUSE-th, counted in WL_SUDO_STATE, which it
# refuses in sudo's own words.
if [ "${WL_SUDO:-}" = grant ]; then
  n=$(cat "$WL_SUDO_STATE" 2>/dev/null); n=$(( ${n:-0} + 1 )); printf '%s' "$n" >"$WL_SUDO_STATE"
  if [ "$n" = "${WL_SUDO_REFUSE:-0}" ]; then echo 'sudo: 3 incorrect password attempts' >&2; exit 1; fi
  # r4: WL_SUDO_LOG records each granted command, so a case can see what root was asked to open.
  [ -z "${WL_SUDO_LOG:-}" ] || printf '%s\n' "$*" >>"$WL_SUDO_LOG"
  # r4: WL_SUDO_SECRET names a file of mode 000, which this user can't read and root can: each granted command runs with
  # it readable, as root would, and it is unreadable again after. At -v, where the run waits for the password, the
  # cleaned file in TMPDIR (a wardlatch.* file holding something other than the bundle) becomes a symbolic link to it,
  # as a process running as this user could make it. Afterwards, a file beside the bundle holding the secret's first
  # line is recorded in WL_SUDO_LEAK.
  if [ "$1" = -v ]; then
    if [ -n "${WL_SUDO_SECRET:-}" ]; then
      for t in "${TMPDIR:-/tmp}"/wardlatch.*; do
        if [ -s "$t" ] && ! cmp -s "$t" "$WARDLATCH_CERT_FILE"; then /bin/rm -f "$t"; ln -s "$WL_SUDO_SECRET" "$t"; fi
      done
    fi
    exit 0
  fi
  [ -n "${WL_SUDO_SECRET:-}" ] || exec "$@"
  /bin/chmod 600 "$WL_SUDO_SECRET"; "$@"; r=$?; /bin/chmod 000 "$WL_SUDO_SECRET"
  for f in "$(dirname "$WARDLATCH_CERT_FILE")"/.wardlatch-*; do
    if [ -f "$f" ] && /usr/bin/grep -qF 'root-only secret' "$f" 2>/dev/null; then echo "$f" >>"$WL_SUDO_LEAK"; fi
  done
  exit "$r"
fi
exit 1
SHIM
# r3: stand-ins for grep, rm, uname and date. With no WL_ variable set, each is the real command.
cat >"$shims/grep" <<'SHIM'
#!/bin/bash
# WL_GREP=swap: the first grep that reads the snapshot (its name is in $WL_SWAP_STATE, written by the cp stand-in)
# first replaces the snapshot's contents with $WL_VARIANT, as a same-user process could at any moment.
if [ "${WL_GREP:-}" = swap ] && [ -s "${WL_SWAP_STATE:-}" ] && [ ! -e "$WL_SWAP_STATE.done" ]; then
  s=$(cat "$WL_SWAP_STATE"); last=''
  for a in "$@"; do last=$a; done
  if [ "$last" = "$s" ]; then : >"$WL_SWAP_STATE.done"; /bin/cp "$WL_VARIANT" "$s"; fi
fi
# r4: WL_GREP_TMP=<file>: the first grep that reads the cleaned file (a wardlatch.* file in TMPDIR holding something,
# not the snapshot and not a copy of the bundle) first keeps its contents in $WL_STASH, and its name in $WL_STASH.path,
# and puts <file>'s contents in its place: the checks on the cleaned file then read what a same-user process chose.
if [ -n "${WL_GREP_TMP:-}" ] && [ ! -e "$WL_STASH.path" ]; then
  last=''
  for a in "$@"; do last=$a; done
  case "$last" in
    "${TMPDIR:-/tmp}"/wardlatch.*)
      if [ -s "$last" ] && [ "$last" != "$(cat "${WL_SWAP_STATE:-/dev/null}" 2>/dev/null)" ] && ! cmp -s "$last" "$WARDLATCH_CERT_FILE"; then
        /bin/cp "$last" "$WL_STASH"; printf '%s' "$last" >"$WL_STASH.path"; /bin/cp "$WL_GREP_TMP" "$last"
      fi ;;
  esac
fi
# r4: WL_GREP_NEW=race: the first grep that reads the new file beside the bundle (.wardlatch-new.*, which built() checks)
# first appends $WL_CORP to the bundle, as an administrator could at that moment. Once: $WL_GREP_NEW_STATE.
if [ "${WL_GREP_NEW:-}" = race ] && [ ! -e "$WL_GREP_NEW_STATE" ]; then
  last=''
  for a in "$@"; do last=$a; done
  case "$last" in */.wardlatch-new.*) : >"$WL_GREP_NEW_STATE"; cat "$WL_CORP" >>"$WARDLATCH_CERT_FILE" ;; esac
fi
exec /usr/bin/grep "$@"
SHIM
cat >"$shims/rm" <<'SHIM'
#!/bin/bash
# WL_RM=hold: the first rm that names a file in $TMPDIR (the cleanup when the script exits) touches $WL_MARK and waits,
# so a case can send a signal while the cleanup runs. Once only: $WL_RM_STATE records it.
if [ "${WL_RM:-}" = hold ] && [ ! -e "$WL_RM_STATE" ]; then
  for a in "$@"; do case "$a" in "${TMPDIR:-/tmp}"/wardlatch.*) : >"$WL_RM_STATE"; : >"$WL_MARK"; /bin/sleep "${WL_HOLD:-3}"; break ;; esac; done
fi
exec /bin/rm "$@"
SHIM
cat >"$shims/uname" <<'SHIM'
#!/bin/bash
# WL_UNAME=hold: touches $WL_MARK and waits (r4: WL_HOLD seconds, 3 if unset), so a case can send a signal at the very start.
if [ "${WL_UNAME:-}" = hold ]; then : >"$WL_MARK"; /bin/sleep "${WL_HOLD:-3}"; fi
exec /usr/bin/uname "$@"
SHIM
cat >"$shims/date" <<'SHIM'
#!/bin/bash
# WL_DATE pins the stamp the fix puts in its backup's name.
if [ -n "${WL_DATE:-}" ] && [ "${1:-}" = +%Y%m%d-%H%M%S ]; then echo "$WL_DATE"; exit 0; fi
# r4: WL_STASH: the first date call (the backup's name, after the checks on the cleaned file) puts back what the grep
# stand-in kept, so the cleaned file is again the one the fix built.
if [ -n "${WL_STASH:-}" ] && [ -e "$WL_STASH.path" ] && [ ! -e "$WL_STASH.back" ]; then
  : >"$WL_STASH.back"; /bin/cp "$WL_STASH" "$(cat "$WL_STASH.path")"
fi
exec /bin/date "$@"
SHIM
cat >"$shims/awk" <<'SHIM'
#!/bin/bash
# WL_AWK=tamper-tmp: once, right after the first awk that leaves a temporary file of the fix's (a wardlatch.* file in
# $TMPDIR that is not a copy of the bundle) holding something -- that is, as soon as the cleaned file is written --
# one certificate of that file is swapped for $WL_TAMPER, as a same-user process could, before its SHA-256 is taken.
# r4: WL_AWK=restore-snap: the first awk after the grep stand-in swapped the snapshot (the cleaned file being built) first
# puts the bundle's bytes back in it, so what was read and what is built from differ, as a same-user process can make them.
if [ "${WL_AWK:-}" = restore-snap ] && [ -e "$WL_SWAP_STATE.done" ] && [ ! -e "$WL_SWAP_STATE.back" ]; then
  : >"$WL_SWAP_STATE.back"; /bin/cp "$WARDLATCH_CERT_FILE" "$(cat "$WL_SWAP_STATE")"
fi
# r4: WL_AWK=hold-strip: the first awk that strip() runs (it alone sets WL_STRIP=1) -- the cleaned file being written --
# touches $WL_MARK and waits first, so a case can send a signal while the cleaned file is built. Once: $WL_AWK_STATE.
if [ "${WL_AWK:-}" = hold-strip ] && [ "${WL_STRIP:-}" = 1 ] && [ ! -e "$WL_AWK_STATE" ]; then
  : >"$WL_AWK_STATE"; : >"$WL_MARK"; /bin/sleep 3
fi
/usr/bin/awk "$@"; r=$?
if [ "${WL_AWK:-}" = tamper-tmp ] && [ ! -e "$WL_AWK_STATE" ]; then
  for t in "${TMPDIR:-/tmp}"/wardlatch.*; do
    [ -s "$t" ] || continue
    cmp -s "$t" "$WARDLATCH_CERT_FILE" && continue
    : >"$WL_AWK_STATE"
    /usr/bin/awk -v t="$WL_TAMPER" 'BEGIN { while ((getline l < t) > 0) rep = rep l "\n" }
      /^-----BEGIN CERTIFICATE-----/ && !done { skip = 1 }
      skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0; done = 1 }; next }
      { print }' "$t" >"$t.swap" && /bin/mv "$t.swap" "$t"
  done
fi
exit "$r"
SHIM
cat >"$shims/link" <<'SHIM'
#!/bin/bash
# r4: WL_LINK=reswap: just after the backup gets its dated name, the snapshot (its name in $WL_SWAP_STATE) is swapped for
# $WL_VARIANT again, as a same-user process could, so the backup and the snapshot differ from then on.
/bin/link "$@"; r=$?
if [ "${WL_LINK:-}" = reswap ] && [ -s "${WL_SWAP_STATE:-}" ]; then /bin/cp "$WL_VARIANT" "$(cat "$WL_SWAP_STATE")"; fi
exit "$r"
SHIM
cat >"$shims/tee" <<'SHIM'
#!/bin/bash
# r4: the file to be renamed into place may be made by `tee <dir>/.wardlatch-new.* <source` rather than by cp, so that
# root writes it without opening any path of the user's. WL_CP's new-file modes act on it as they act on cp: the
# forward copy is the one made before any rename into place (WL_MV_STATE absent or 0), the restore's the one after.
dst=''
for a in "$@"; do dst=$a; done
case "$dst" in */.wardlatch-new.*) ;; *) exec /usr/bin/tee "$@" ;; esac
n=$(cat "${WL_MV_STATE:-/dev/null}" 2>/dev/null); fwd=''; [ "${n:-0}" != 0 ] || fwd=1
case "${WL_CP:-}" in
  partial-new) if [ -n "$fwd" ]; then head -c 1000 >"$dst"; exit 1; fi ;;
  # r4: full-new: the copy fails part-way on a full disk, in tee's own words.
  full-new) if [ -n "$fwd" ]; then head -c 1000 >"$dst"; echo "tee: $dst: No space left on device" >&2; exit 1; fi ;;
  kill-in-new) if [ -n "$fwd" ]; then head -c 500 >"$dst"; kill -TERM "$PPID"; /bin/sleep 1; exit 1; fi ;;
  tamper-new-append) if [ -n "$fwd" ]; then { cat; cat "$WL_TAMPER"; } >"$dst"; exit 0; fi ;;
  tamper-new-swap)
    if [ -n "$fwd" ]; then
      /usr/bin/awk -v t="$WL_TAMPER" 'BEGIN { while ((getline l < t) > 0) rep = rep l "\n" }
        /^-----BEGIN CERTIFICATE-----/ && !done { skip = 1 }
        skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0; done = 1 }; next }
        { print }' >"$dst"
      exit 0
    fi ;;
  sig-restore-cp) if [ -z "$fwd" ]; then : >"$WL_MARK"; /bin/sleep 3; fi ;;
esac
exec /usr/bin/tee "$@"
SHIM
chmod +x "$r2/curl" "$r2/openssl" "$shims"/*
# r4: a case that sends the fix a signal needs the fix to start with that signal's default action, as it does from a
# terminal. A harness started with a signal ignored passes the ignore on (a script's background job ignores INT and
# QUIT; some parents ignore PIPE), and bash can't trap a signal that was ignored when it started, so until r4 such a case
# failed and blamed the fix (the round-3 re-read: 'an interrupt' under `( ... & )`, 13 runs of 13). Any such signal is
# found here, and then each run that is signalled is started through perl, which sets them all back to their defaults.
reset=()
for s in HUP INT QUIT TERM ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2; do
  [ "$(/bin/bash -c "trap 'echo y' $s; kill -$s \$\$" 2>/dev/null)" != y ] || continue
  [ -x /usr/bin/perl ] || fail "this harness was started with SIG$s ignored, which the signal cases need not to be, and there is no /usr/bin/perl to set it back: run it in the foreground"
  # shellcheck disable=SC2016
  reset=(/usr/bin/perl -e '$SIG{$_} = "DEFAULT" for qw(HUP INT QUIT TERM ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2); exec @ARGV or die "exec: $!\n"' --)
  echo "NOTE: this harness was started with SIG$s ignored, so each run it signals is started with every signal's default set back."
  break
done
# Runs $1 on bundle $2 in the background, in its own process group, with the VAR=value arguments after them; waits
# for a stand-in to touch $WL_MARK, then sends INT to the script itself, as a Ctrl-C would reach it (another signal
# when $sigrun_sig names one). Sets $code and $out, and checks what run() checks: nothing on stderr but the
# stand-in's, nothing left in TMPDIR, a line to read.
sigrun_sig=INT
sigrun() {
  local s=$1 f=$2 pid i
  shift 2
  rm -rf "$work/tmp"; mkdir "$work/tmp"; rm -f "$r2/mark"
  set -m
  ${reset[@]+"${reset[@]}"} env "$@" WL_MARK="$r2/mark" TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$f" bash "$s" >"$r2/sig.out" 2>"$r2/sig.err" &
  pid=$!
  set +m
  for i in $(seq 1 300); do [ -e "$r2/mark" ] && break; /bin/sleep 0.1; done
  if [ ! -e "$r2/mark" ]; then kill -KILL "$pid" 2>/dev/null || true; fail "a stopped run: the run never reached the point it is stopped at"; fi
  kill -"$sigrun_sig" "$pid" 2>/dev/null || true
  code=0; wait "$pid" || code=$?
  out=$(cat "$r2/sig.out")
  printf '%s\n' "$out" | sed 's/^/    | /'
  [ ! -s "$r2/sig.err" ] || sed 's/^/    ! /' "$r2/sig.err"
  left=$(find "$work/tmp" -mindepth 1 -maxdepth 1 -exec basename {} \; | tr '\n' ' ')
  [ -z "$left" ] || fail "a stopped run left temporary files behind: $left"
  printf '%s\n' "$out" | grep -qE '^(SAFE|EXPOSED|UNKNOWN) ' || fail "a stopped run exited $code and printed no line starting SAFE, EXPOSED or UNKNOWN"
}
offline='https_proxy=http://127.0.0.1:9'
OFFLINE='HTTPS_PROXY=http://127.0.0.1:9'
# ---- r2: end of setup
# ---- r2: end of prologue

# A missing file: refused, nothing created.
run "$work/missing.pem"
if [ "$code" -ne 2 ] || [ -e "$work/missing.pem" ]; then fail "missing file: expected exit 2 and no file, got $code"; fi
ok "missing file refused"

# An empty file: refused as damaged, left as it was, no backup.
: >"$work/empty.pem"
run "$work/empty.pem"
if [ "$code" -ne 2 ] || [ -s "$work/empty.pem" ] || [ "$(backups "$work/empty.pem")" -ne 0 ]; then fail "empty file: expected exit 2, unchanged, no backup"; fi
ok "empty file refused, unchanged"

# A truncated file: refused, byte for byte unchanged, no backup -- and refused for the right reason, which is what
# this case asserts since 30 Oct 2026. Until then it asserted exit 2, unchanged and no backup and nothing else,
# and the floor's old wording satisfied all three while telling the reader the file "looks damaged" and to "put a
# backup back". This bundle holds NEITHER withdrawn root (the truncation lands inside a certificate's text dump, so
# the certificates in it are whole and readable), so there is nothing here for this fix to remove, nothing it can
# honestly call damage, and no copy of this file it can send the reader back to: the only backup it could name is
# the one it writes itself, a copy of the file as it was before the removal, which holds the withdrawn roots.
head -c 20000 "$work/original.pem" >"$work/truncated.pem"
cp "$work/truncated.pem" "$work/truncated.before"
run "$work/truncated.pem"
if [ "$code" -ne 2 ] || ! cmp -s "$work/truncated.pem" "$work/truncated.before" || [ "$(backups "$work/truncated.pem")" -ne 0 ]; then
  fail "truncated file: expected exit 2, unchanged, no backup"
fi
[ "$(bad "$work/truncated.pem")" -eq 0 ] || fail "truncated file: it holds a withdrawn root, so this case is measuring the other branch of the floor and not the one it describes"
grep -q "has $(count "$work/truncated.pem") certificates, fewer than the 50 this expects" <<<"$out" ||
  fail "truncated file: it did not name the count it found"
grep -q 'It holds neither' <<<"$out" || fail "truncated file: it did not say the file holds neither withdrawn root"
grep -q 'nothing to remove' <<<"$out" || fail "truncated file: it did not say this fix has nothing to remove"
grep -qi 'looks damaged' <<<"$out" && fail "truncated file: it called a file holding neither withdrawn root damaged"
grep -qi 'backup back\|\.bak' <<<"$out" && fail "truncated file: it sent the reader to a backup, which holds the withdrawn roots"
grep -q '^SAFE' <<<"$out" && fail "truncated file: it claimed this Mac is safe"
# Proof it fails on the old shape: the entry floor as it stood, on the same bytes.
cp "$work/truncated.before" "$work/truncated-old.pem"
script=$work/oldentry.sh
run "$work/truncated-old.pem"
script=$fix
grep -qi 'looks damaged' <<<"$out" || fail "truncated file: the case does not discriminate -- the old floor did not call the file damaged"
grep -q 'Put a backup back' <<<"$out" || fail "truncated file: the case does not discriminate -- the old floor did not advise restoring a backup"
ok "truncated file refused as holding neither root, where the old floor called it damaged and advised a backup"

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

  # Content that follows a removed root and is not a header line. A certificate's block ends at its END CERTIFICATE
  # line; until 30 Oct 2026 the fix cleared its skip only at the next "###" or "=== " line, so everything after a
  # removed root went with it as far as the next header -- an administrator's note, a trailing comment, a line naming
  # what follows. Content that is not a certificate does not change the count, so `after == before - found` still
  # matched, and the run printed a verdict and exited 0 with that content silently gone, which is the false SAFE
  # SECURITY.md puts first. Apple's own file has a "=== " line above every certificate, so it was never live there;
  # it was live on any hand-concatenated bundle, which is the ordinary case -- a corporate TLS-inspection root is
  # appended to this file precisely because curl ignores the keychain.
  # The bundle here carries one note line after every certificate, so the count of notes left is the measurement:
  # every one of them must still be there, not $total minus the roots removed.
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}' "$work/original.pem" >"$work/notes.src"
  awk '{ print } /-----END CERTIFICATE-----/ { print "# note: the certificate above was appended by hand" }' \
    "$work/notes.src" >"$work/notes.built"
  [ "$(grep -c '^# note' "$work/notes.built")" -eq "$total" ] || fail "a note after a removed root: the bundle was built with $(grep -c '^# note' "$work/notes.built") notes, not $total, so this case would measure nothing"
  cp "$work/notes.built" "$work/notes.pem"
  run "$work/notes.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  [ "$code" -eq 0 ] || fail "a note after a removed root: expected exit 0, got $code"
  [ "$(count "$work/notes.pem")" -eq $((total - found)) ] || fail "a note after a removed root: expected $((total - found)) certificates, got $(count "$work/notes.pem")"
  [ "$(bad "$work/notes.pem")" -eq 0 ] || fail "a note after a removed root: a withdrawn root is still there"
  [ "$(grep -c '^# note' "$work/notes.pem")" -eq "$total" ] || fail "a note after a removed root: $(( total - $(grep -c '^# note' "$work/notes.pem") )) note line(s) were deleted with the roots"
  # Proof it fails on the old shape: a copy of the script carrying the strip() this replaced, whose skip ran from a
  # removed certificate to the next header line. It must lose exactly the notes that followed the removed roots, and
  # it must do it while still exiting 0 with a verdict printed -- the silence is the defect, not the deletion.
  cat >"$work/oldstrip.txt" <<'OLDSTRIP'
  awk -v list="$2" '
    BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) drop[a[i] + 0] = 1 }
    NR == FNR {
      if ($0 ~ /^=== /) name = FNR
      if ($0 ~ /-----BEGIN CERTIFICATE-----/) { k++; start[name ? name : FNR] = k; name = 0 }
      if ($0 ~ /-----END CERTIFICATE-----/) name = 0
      next
    }
    FNR in start { skip = (start[FNR] in drop) }
    !(FNR in start) && /^(###|===) / { skip = 0 }
    !skip' "$1" "$1"
OLDSTRIP
  awk -v bf="$work/oldstrip.txt" '
    /^strip\(\) \{$/ { inside = 1; print; while ((getline l < bf) > 0) print l; close(bf); next }
    inside { if ($0 == "}") { inside = 0; print } ; next }
    { print }' "$fix" >"$work/oldstrip.sh"
  cmp -s "$fix" "$work/oldstrip.sh" && fail "a note after a removed root: strip() was not found in $fix, so this case proves nothing"
  cp "$work/notes.built" "$work/notes-old.pem"
  script=$work/oldstrip.sh
  run "$work/notes-old.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  script=$fix
  [ "$code" -eq 0 ] || fail "a note after a removed root: the case does not discriminate -- with the old strip() the run exited $code, not 0"
  grep -q '^SAFE' <<<"$out" || fail "a note after a removed root: the case does not discriminate -- with the old strip() no verdict was printed, so the loss was not silent"
  [ "$(count "$work/notes-old.pem")" -eq $((total - found)) ] || fail "a note after a removed root: the case does not discriminate -- with the old strip() the count was wrong too, so the loss was not silent"
  [ "$(grep -c '^# note' "$work/notes-old.pem")" -eq $((total - found)) ] ||
    fail "a note after a removed root: the case does not discriminate -- with the old strip() $(grep -c '^# note' "$work/notes-old.pem") notes survived, expected $((total - found))"
  ok "a note after a removed root survives, where the old strip() deleted it and still exited 0"

  # The 50-certificate bundle, which is the only arithmetic that ever reached the second floor. The check at the top
  # of the script refuses a bundle of fewer than 50 certificates before it reads anything out of it, so a run that
  # gets as far as the rebuild started at 50 or more and removed 1 or 2: 50-1, 50-2 and 51-2 are the only results
  # below 50, and every one of them is exactly before-minus-found, which the count check has already proved right.
  # So the floor could only ever fire on a correct result, report it as "didn't come out as expected (50 before, 48
  # after)" without mentioning a floor at all, and leave that Mac with no way to be fixed. No test had ever reached
  # the branch.
  : >"$work/floor-roots.pem"; : >"$work/floor-rest.pem"
  rm -rf "$work/floorsplit"; mkdir "$work/floorsplit"
  awk -v d="$work/floorsplit" '/-----BEGIN CERTIFICATE-----/{k++; f=sprintf("%s/%05d.pem", d, k)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$work/original.pem"
  for c in "$work/floorsplit"/*.pem; do
    case "$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null)" in
      *D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4|*86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B)
        cat "$c" >>"$work/floor-roots.pem" ;;
      *) cat "$c" >>"$work/floor-rest.pem" ;;
    esac
  done
  cp "$work/floor-roots.pem" "$work/floor.built"
  awk -v want=$((50 - found)) '/-----BEGIN CERTIFICATE-----/{k++} k <= want { print }' "$work/floor-rest.pem" >>"$work/floor.built"
  [ "$(count "$work/floor.built")" -eq 50 ] || fail "a 50-certificate bundle: built $(count "$work/floor.built") certificates, not 50, so this case would measure nothing"
  [ "$(bad "$work/floor.built")" -eq "$found" ] || fail "a 50-certificate bundle: built it with $(bad "$work/floor.built") of the withdrawn roots, not $found"
  cp "$work/floor.built" "$work/floor.pem"
  run "$work/floor.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  [ "$code" -eq 0 ] || fail "a 50-certificate bundle: expected exit 0, got $code"
  [ "$(count "$work/floor.pem")" -eq $((50 - found)) ] || fail "a 50-certificate bundle: expected $((50 - found)) certificates, got $(count "$work/floor.pem")"
  [ "$(bad "$work/floor.pem")" -eq 0 ] || fail "a 50-certificate bundle: a withdrawn root is still there"
  grep -q 'Fixed' <<<"$out" || fail "a 50-certificate bundle: it did not say the file was fixed"
  # Proof it fails on the old shape: a copy carrying the floor this replaced, inserted where it stood. It must refuse
  # the right answer, report it as arithmetic, and leave the bundle as it was.
  cat >"$work/oldfloor.txt" <<'OLDFLOOR'
if [ "$after" -lt 50 ]; then
  echo "UNKNOWN  The cleaned file didn't come out as expected ($before certificates before, $after after). Nothing changed."
  exit 2
fi
OLDFLOOR
  awk -v bf="$work/oldfloor.txt" '
    { print }
    /^left=\$\(roots "\$tmp"\) \|\| left=unreadable$/ { while ((getline l < bf) > 0) print l; close(bf) }' "$fix" >"$work/oldfloor.sh"
  cmp -s "$fix" "$work/oldfloor.sh" && fail "a 50-certificate bundle: the check on the cleaned file was not found, so this case proves nothing"
  cp "$work/floor.built" "$work/floor2.pem"
  script=$work/oldfloor.sh
  run "$work/floor2.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  script=$fix
  [ "$code" -eq 2 ] || fail "a 50-certificate bundle: the case does not discriminate -- with the floor back the run exited $code, not 2"
  grep -q "didn't come out as expected (50 certificates before, $((50 - found)) after)" <<<"$out" ||
    fail "a 50-certificate bundle: the case does not discriminate -- with the floor back it did not report the correct result as an arithmetic failure"
  grep -qi 'floor\|fewer than' <<<"$out" && fail "a 50-certificate bundle: the case does not discriminate -- the old message mentioned a floor after all"
  cmp -s "$work/floor2.pem" "$work/floor.built" || fail "a 50-certificate bundle: the case does not discriminate -- with the floor back the file was fixed anyway"
  [ "$(backups "$work/floor2.pem")" -eq 0 ] || fail "a 50-certificate bundle: the run that refused it wrote a backup"
  ok "a 50-certificate bundle is fixed, where the second floor called 50-minus-$found an arithmetic failure and refused"

  # A small bundle correctly fixed, then run again. With the post-strip floor gone (the case above), the first run
  # fixes a bundle of 49-plus-$found certificates down to 49 -- and until 30 Oct 2026 the SECOND run then hit the
  # ENTRY floor, which told the operator the file "looks damaged" and to "put a backup back". That backup is the one
  # the first run wrote: a copy of the file as it was, holding the withdrawn root(s). So a correct result was
  # reported as damage and the advice was to revert to the compromised file -- the same defect class as the
  # network-triggered revert this branch removed on 29 Oct 2026, in a script people run as root. The size is
  # 49 + $found so the fixed file is 49 whatever the bundle held: 50 or 51 before, 49 after, under the floor either
  # way, and the Mojave-era one-root shape is covered rather than skipped.
  cp "$work/floor-roots.pem" "$work/small.built"
  awk -v want=49 '/-----BEGIN CERTIFICATE-----/{k++} k <= want { print }' "$work/floor-rest.pem" >>"$work/small.built"
  [ "$(count "$work/small.built")" -eq $((49 + found)) ] || fail "a small bundle run twice: built $(count "$work/small.built") certificates, not $((49 + found)), so this case would measure nothing"
  [ "$(bad "$work/small.built")" -eq "$found" ] || fail "a small bundle run twice: built it with $(bad "$work/small.built") of the withdrawn roots, not $found"
  cp "$work/small.built" "$work/small.pem"
  run "$work/small.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  [ "$code" -eq 0 ] || fail "a small bundle run twice: the first run should fix it, got exit $code"
  [ "$(count "$work/small.pem")" -eq 49 ] || fail "a small bundle run twice: the first run left $(count "$work/small.pem") certificates, not 49"
  [ "$(bad "$work/small.pem")" -eq 0 ] || fail "a small bundle run twice: the first run left a withdrawn root in it"
  [ "$(backups "$work/small.pem")" -eq 1 ] || fail "a small bundle run twice: the first run wrote $(backups "$work/small.pem") backups, not 1"
  smallbackup=$(find "$work" -name 'small.pem.wardlatch-*.bak')
  [ "$(bad "$smallbackup")" -eq "$found" ] || fail "a small bundle run twice: the first run's backup holds $(bad "$smallbackup") withdrawn root(s), not $found -- that it holds them is why advising a restore is the defect"
  cp "$work/small.pem" "$work/small.after-first"
  run "$work/small.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  [ "$code" -eq 2 ] || fail "a small bundle run twice: the second run should be UNKNOWN (exit 2), got $code"
  cmp -s "$work/small.pem" "$work/small.after-first" || fail "a small bundle run twice: the second run changed the file"
  [ "$(backups "$work/small.pem")" -eq 1 ] || fail "a small bundle run twice: the second run wrote another backup"
  grep -q 'has 49 certificates, fewer than the 50 this expects' <<<"$out" || fail "a small bundle run twice: the second run did not name the count it found"
  grep -q 'It holds neither' <<<"$out" || fail "a small bundle run twice: the second run did not say the file holds neither withdrawn root"
  grep -q 'nothing to remove' <<<"$out" || fail "a small bundle run twice: the second run did not say this fix has nothing to remove"
  grep -qi 'looks damaged' <<<"$out" && fail "a small bundle run twice: the second run called a correctly fixed file damaged"
  grep -qi 'backup back\|\.bak' <<<"$out" && fail "a small bundle run twice: the second run sent the reader to the backup, which holds the withdrawn root(s)"
  grep -q '^SAFE' <<<"$out" && fail "a small bundle run twice: the second run claimed this Mac is safe"
  # Proof it fails on the old shape: the entry floor as it stood, on the file the first run produced.
  cp "$work/small.after-first" "$work/small-old.pem"
  script=$work/oldentry.sh
  run "$work/small-old.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  script=$fix
  [ "$code" -eq 2 ] || fail "a small bundle run twice: the case does not discriminate -- with the old floor back the run exited $code, not 2"
  grep -qi 'looks damaged' <<<"$out" || fail "a small bundle run twice: the case does not discriminate -- the old floor did not call the fixed file damaged"
  grep -q 'Put a backup back' <<<"$out" || fail "a small bundle run twice: the case does not discriminate -- the old floor did not advise restoring the backup that holds the roots"
  ok "a small bundle correctly fixed is UNKNOWN on the next run, where the old entry floor called it damaged and sent the reader back to the roots"

  # The other branch of the floor: a small bundle that DOES still hold a withdrawn root keeps today's refusal -- but
  # not today's advice. There is no copy of this file the script can honestly send the reader back to either, for
  # the same reason: the only backup it writes is a copy of the file as it was, roots and all.
  cp "$work/floor-roots.pem" "$work/tinyroot.built"
  awk -v want=10 '/-----BEGIN CERTIFICATE-----/{k++} k <= want { print }' "$work/floor-rest.pem" >>"$work/tinyroot.built"
  [ "$(bad "$work/tinyroot.built")" -eq "$found" ] || fail "a small bundle holding a root: built it with $(bad "$work/tinyroot.built") of the withdrawn roots, not $found"
  [ "$(count "$work/tinyroot.built")" -lt 50 ] || fail "a small bundle holding a root: built $(count "$work/tinyroot.built") certificates, which is not under the floor, so this case would measure nothing"
  cp "$work/tinyroot.built" "$work/tinyroot.pem"
  run "$work/tinyroot.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  [ "$code" -eq 2 ] || fail "a small bundle holding a root: expected exit 2, got $code"
  cmp -s "$work/tinyroot.pem" "$work/tinyroot.built" || fail "a small bundle holding a root: the file was changed"
  [ "$(backups "$work/tinyroot.pem")" -eq 0 ] || fail "a small bundle holding a root: it wrote a backup"
  grep -q 'still holds a withdrawn root' <<<"$out" || fail "a small bundle holding a root: it did not say the file still holds one"
  grep -qi 'backup back\|\.bak' <<<"$out" && fail "a small bundle holding a root: it sent the reader to a backup, which holds the withdrawn root(s) too"
  cp "$work/tinyroot.built" "$work/tinyroot-old.pem"
  script=$work/oldentry.sh
  run "$work/tinyroot-old.pem" https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
  script=$fix
  grep -q 'Put a backup back' <<<"$out" || fail "a small bundle holding a root: the case does not discriminate -- the old floor did not advise restoring a backup"
  ok "a small bundle still holding a withdrawn root is refused without being sent back to a backup that holds it"

  # The three reasons the cleaned file may not be used, each said in its own words. They were one condition and one
  # line reporting all three as arithmetic ("didn't come out as expected (N before, M after)"), which is a
  # misdiagnosis for two of them: a withdrawn root surviving the rebuild, and a certificate in the rebuilt file that
  # cannot be read, are not count problems and the count printed beside them was right. Nothing had ever reached any
  # of the three. Each copy below changes the rebuild, and nothing else, in the one way that reaches its reason.
  for reason in root unreadable count; do
    case "$reason" in
      # a rebuild that removes nothing: both withdrawn roots are still in the cleaned file, and the count is right
      root)       sed 's|^strip "\$snap" .*|cat "$snap" > "$tmp"|' "$fix" >"$work/reason.sh"
                  want="still holds a withdrawn root" ;;
      # one certificate in the cleaned file made unreadable: the count is right and a root is gone, but it was not
      # fully checked
      unreadable) awk '{ print } /^strip "\$snap" / { print "sed -i \"\" \"s/^MII/!!!/\" \"$tmp\"" }' "$fix" >"$work/reason.sh"
                  want="couldn't be read" ;;
      # one extra certificate lost from the cleaned file: the only one of the three that is about the count
      count)      awk '{ print } /^strip "\$snap" / { print "sed -i \"\" \"1,/-----END CERTIFICATE-----/d\" \"$tmp\"" }' "$fix" >"$work/reason.sh"
                  want="not the $((total - found)) there should be" ;;
    esac
    cmp -s "$fix" "$work/reason.sh" && fail "the three reasons ($reason): the rebuild was not found in $fix, so this case proves nothing"
    cp "$work/original.pem" "$work/reason.pem"
    script=$work/reason.sh
    run "$work/reason.pem"
    script=$fix
    [ "$code" -eq 2 ] || fail "the three reasons ($reason): expected exit 2, got $code"
    grep -q "^UNKNOWN" <<<"$out" || fail "the three reasons ($reason): expected UNKNOWN"
    grep -q "$want" <<<"$out" || fail "the three reasons ($reason): it did not say \"$want\", so it reported the wrong reason"
    cmp -s "$work/reason.pem" "$work/original.pem" || fail "the three reasons ($reason): the file was replaced anyway"
    [ "$(backups "$work/reason.pem")" -eq 0 ] || fail "the three reasons ($reason): it wrote a backup before refusing"
    # and it does not report one reason in another's words: the line names this reason and no other
    for other in "still holds a withdrawn root" "couldn't be read" "there should be"; do
      case "$want" in *"$other"*) continue ;; esac
      grep -q "$other" <<<"$out" && fail "the three reasons ($reason): it also said \"$other\", so the line does not name one reason"
    done
    rm -f "$work/reason.pem"
  done
  ok "each of the three reasons the cleaned file is refused is reported in its own words, not as arithmetic"
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
  # A backup that isn't the file it came from: nothing is replaced, and nothing is left under the dated backup name.
  # The fix prints an Undo line pointing at that name and the content-mismatch restore uses it, so a backup that
  # isn't the file makes both a lie. Up to 29 Oct 2026 the backup was written with `cp -p` and never compared. Until
  # 31 Oct 2026 the bad copy stayed under the dated name ("Bad backup: ..."), and this case asserted that it did;
  # a copy that is not the file this run checked now never gets that name. The copy is spoiled by the stand-in for
  # cp that the cases below share (WL_CP=tamper-backup appends a line to it), so this does not depend on how the
  # script spells its backup step.
  cp "$work/original.pem" "$work/badbackup.pem"
  run "$work/badbackup.pem" PATH="$shims:$PATH" WL_CP=tamper-backup
  [ "$code" -eq 2 ] || fail "a bad backup: expected exit 2, got $code"
  grep -qE "backup( copy)? isn't" <<<"$out" || fail "a bad backup: it did not say the backup isn't the file"
  [ "$(backups "$work/badbackup.pem")" -eq 0 ] || fail "a bad backup: a copy that isn't the file was left under the dated backup name"
  [ -z "$(beside "$work/badbackup.pem")" ] || fail "a bad backup: it left $(beside "$work/badbackup.pem") beside the bundle"
  cmp -s "$work/badbackup.pem" "$work/original.pem" || fail "a bad backup: the file was replaced anyway"
  # Proof it discriminates: with the comparison taken out, the same run replaces the file and prints an Undo line
  # naming a backup that is not the original. (Either shape of the comparison: the one that compared with $FILE until
  # 31 Oct 2026, or the one that compares the copy with the snapshot. And the backup's own check, checkbackup, which
  # since r3 also refuses a backup that isn't the file the run read: a test of the comparison has to take out every
  # check that catches the same thing, or it shows only that some other check caught it.)
  awk '/^(cmp -s "\$FILE" "\$backup"|checkbackup) \|\| \{$/ { drop = 1 } drop { if ($0 == "}") drop = 0; next }
       /^cmp -s "\$bnew" "\$snap" \|\| / { next } { print }' "$fix" >"$work/badbackup-nocheck.sh"
  cmp -s "$fix" "$work/badbackup-nocheck.sh" && fail "a bad backup: the comparison was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/badbackup2.pem"
  script=$work/badbackup-nocheck.sh
  run "$work/badbackup2.pem" PATH="$shims:$PATH" WL_CP=tamper-backup
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
  # And the same for the backup, which is the first write of the run -- failing part-way, as a full disk makes it,
  # which is what the stand-in for cp does with WL_CP=partial-backup. Until 31 Oct 2026 this case made the copy fail
  # with `false`, which never makes a file, so "it left a backup behind" could not fail; and the shipped script did
  # leave one, truncated, under exactly the name of a good backup.
  cp "$work/original.pem" "$work/backupfails.pem"
  run "$work/backupfails.pem" PATH="$shims:$PATH" WL_CP=partial-backup
  [ "$code" -eq 2 ] || fail "a failed backup: expected exit 2, got $code"
  grep -q "the backup" <<<"$out" || fail "a failed backup: it did not say the backup could not be written"
  cmp -s "$work/backupfails.pem" "$work/original.pem" || fail "a failed backup: the bundle changed anyway"
  [ "$(backups "$work/backupfails.pem")" -eq 0 ] || fail "a failed backup: it left a backup behind"
  [ -z "$(beside "$work/backupfails.pem")" ] || fail "a failed backup: it left $(beside "$work/backupfails.pem") beside the bundle"
  # Proof both discriminate: with the checks taken off those two writes, the run exits 1 with nothing printed. (The
  # backup copy in either shape: as a bare command, or, since r3, with its words kept for the line that reports it.
  # And, since r4, with the exit-code guard at exit -- `ended "$r"` in the EXIT trap, which turns any exit 1 that no
  # EXPOSED line asked for into 2 -- taken out too: it catches the same failure, so a test of either check has to take
  # out both, or it shows only that the other one caught it.)
  for t in writefails backupfails; do
    case "$t" in
      writefails) base=$work/$t.sh; sed -e 's#^replace "\$tmp" || .*$#replace "$tmp"#' -e "s#; ended \"\\\$r\"' EXIT\$#' EXIT#" "$base" >"$work/$t-nocheck.sh" ;;
      backupfails) base=$fix; sed -e 's#^\(\$SUDO cp -p "\$FILE" "\$b[a-z]*"\) ||.*$#\1#' \
                                  -e 's#^\(why=\$(\$SUDO cp -p "\$FILE" "\$b[a-z]*" 2>&1)\) ||.*$#\1#' \
                                  -e "s#; ended \"\\\$r\"' EXIT\$#' EXIT#" "$base" >"$work/$t-nocheck.sh" ;;
    esac
    cmp -s "$base" "$work/$t-nocheck.sh" && fail "a failed write: the check on $t was not found, so this case proves nothing"
    cp "$work/original.pem" "$work/$t-nocheck.pem"
    script=$work/$t-nocheck.sh
    silent_ok=1
    if [ "$t" = backupfails ]; then run "$work/$t-nocheck.pem" PATH="$shims:$PATH" WL_CP=partial-backup; else run "$work/$t-nocheck.pem"; fi
    silent_ok=''
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
  # It names the backup and says what it holds, and prints NO command to put it back: the backup holds the withdrawn
  # roots, and "Put it back yourself, now: sudo cp -p ..." was advice to revert to them. Until 31 Oct 2026 this
  # asserted that the command was printed.
  grep -q "Backup: $work/mismatch2.pem.wardlatch-" <<<"$out" || fail "content mismatch: a restore that failed did not name the backup"
  grep -q 'sudo cp -p' <<<"$out" && fail "content mismatch: a restore that failed printed a command to put back a copy that holds the withdrawn roots"
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
    ${reset[@]+"${reset[@]}"} env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$2" WL_AT_THE_WRITE="$work/at-the-write" \
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
  # And a line to read: exit 2 means "read the printed line". Until 31 Oct 2026 a run stopped before the file was
  # replaced printed nothing at all.
  grep -q '^UNKNOWN' <<<"$out" || fail "an interrupt: it exited 2 and printed no line to read"
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
  # (Either shape of the report: the flag test it had until 31 Oct 2026, or the SHA-256 test it has now.)
  sed -e 's#^  \[ -z "\$replaced" \] || {$#  [ -n "$replaced" ] || {#' \
      -e 's#^  if \[ -n "\$want" \] && \[ "\$now" = "\$want" \]; then$#  if false; then#' \
      "$work/afterwrite.sh" >"$work/afterwrite-silent.sh"
  cmp -s "$work/afterwrite.sh" "$work/afterwrite-silent.sh" && fail "an interrupt after the write: the report was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/afterwrite.pem"
  # the baseline control pauses too, so the first interrupt chance is before the write; let that one pass by
  # waiting for the SECOND touch of the sentinel, which is the control read after the file was replaced.
  interrupt_after() {   # $1 = script copy, $2 = bundle. Sets $code and $out.
    local pid i
    rm -rf "$work/tmp"; mkdir "$work/tmp"
    rm -f "$work/at-the-write"
    set -m
    ${reset[@]+"${reset[@]}"} env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$2" WL_AT_THE_WRITE="$work/at-the-write" \
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
  # Proof it discriminates: with that report taken out, the same interrupt does not say that the file it had already
  # changed was replaced. (Until 31 Oct 2026 this asserted that it then printed nothing at all. Every stopped run now
  # prints a line, so what the report adds is the statement that the file was replaced, and that is what is tested.)
  cp "$work/original.pem" "$work/afterwrite2.pem"
  interrupt_after "$work/afterwrite-silent.sh" "$work/afterwrite2.pem"
  grep -q 'had already been replaced' <<<"$out" &&
    fail "an interrupt after the write: the case does not discriminate -- without the report it still said the file was replaced"
  rm -rf "$work/tmp"; mkdir "$work/tmp"
  ok "an interrupt after the file was replaced says so, and names the way back"

  # The exit code a stopped or refused run reports, which the EXIT trap can quietly change. Measured on
  # /bin/bash 3.2.57: with `set -e`, a failing command inside the EXIT trap ends the trap AND overrides the exit
  # status, so one failed `rm` in the cleanup turned exit 2 ("couldn't tell") into exit 1, which the published
  # table reads as EXPOSED -- this Mac still trusts the compromised keys. `return 0` at the end does not help:
  # errexit ends the function before reaching it. Every command in clean() ends in `|| true` for that reason.
  # (clean()'s first command in either shape: removing both temporary files at once, or, since r3, the snapshot alone
  # when it has a name -- the traps are now set before the temporary files are made, so it can run before they are.)
  sed -e 's#^clean() { rm -f "\$snap" "\$tmp" || true; #clean() { /usr/bin/false || true; #' \
      -e 's#^clean() { \[ -z "\$snap" \] || rm -f "\$snap" || true; #clean() { /usr/bin/false || true; #' "$fix" >"$work/cleanfails.sh"
  cmp -s "$fix" "$work/cleanfails.sh" && fail "the cleanup's exit code: clean() was not found, so this case proves nothing"
  cp "$work/original.pem" "$work/cleanfails.pem"
  : >"$work/cleanfails-empty.pem"
  # (leak_ok: this copy's cleanup is broken on purpose, so its temporary files are left in TMPDIR, where run() now
  # sees them.)
  script=$work/cleanfails.sh
  leak_ok=1
  run "$work/cleanfails-empty.pem"
  leak_ok=''
  script=$fix
  [ "$code" -eq 2 ] || fail "the cleanup's exit code: a refused run should exit 2 whatever the cleanup does, got $code"
  # Proof it discriminates: without the `|| true`, the same failing cleanup turns that 2 into 1.
  sed -e 's#^clean() { rm -f "\$snap" "\$tmp" || true; #clean() { /usr/bin/false; #' \
      -e 's#^clean() { \[ -z "\$snap" \] || rm -f "\$snap" || true; #clean() { /usr/bin/false; #' "$fix" >"$work/cleanfails-bare.sh"
  cmp -s "$fix" "$work/cleanfails-bare.sh" && fail "the cleanup's exit code: clean() was not found, so this case proves nothing"
  script=$work/cleanfails-bare.sh
  leak_ok=1
  run "$work/cleanfails-empty.pem"
  leak_ok=''
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
  # And no Undo line: such a network produces this reading at will, and the command would put the withdrawn roots back.
  grep -q 'Undo:' <<<"$out" && fail "a network that accepts everything: it printed an Undo line, a revert to the withdrawn roots, on a reading such a network produces at will"
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
  grep -q "Backup: $work/brokeafter.pem.wardlatch-" <<<"$out" || fail "the control broke with the change: it did not name the backup"
  # And no Undo line. This is the reading a man in the middle holding a withdrawn root's key produces, and a command
  # that puts the withdrawn roots back is not a way back from it. Until 31 Oct 2026 this asserted the opposite: that
  # the run "named the way back", in a line placed under "Decide it yourself from the two lines below".
  grep -q 'Undo:' <<<"$out" && fail "the control broke with the change: it printed an Undo line, a revert to the withdrawn roots, on a reading an attacker can produce"
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

# ---- r2 case: mktemp
# mktemp failing -- a full or unwritable temporary folder, or the folder beside the bundle -- is "couldn't tell":
# exit 2 with a line, the bundle unchanged, nothing left behind, and mktemp's own complaint not passed to stderr.
# Until 31 Oct 2026 the first two calls were unchecked, so `set -e` ended the run with mktemp's status, 1 -- the
# published table's EXPOSED, about a Mac whose file the run had not even read -- and printed nothing.
d=$r2/mktemp; mkdir "$d"
for at in 1 2 3 4; do
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
  stderr_ok=1
  run "$d/cert.pem" PATH="$shims:$PATH" WL_MKTEMP_FAIL="$at" WL_MKTEMP_STATE="$d/state" "$offline" "$OFFLINE"
  stderr_ok=''
  [ "$code" -eq 2 ] || fail "mktemp failing at its call $at: expected UNKNOWN, exit 2, got $code"
  [ ! -s "$work/stderr" ] || fail "mktemp failing at its call $at: its complaint reached stderr: $(cat "$work/stderr")"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "mktemp failing at its call $at: the bundle changed"
  [ -z "$(beside "$d/cert.pem")" ] || fail "mktemp failing at its call $at: it left $(beside "$d/cert.pem") beside the bundle"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "mktemp failing at any of its calls is UNKNOWN with a line, exit 2, and nothing is changed or left behind"
# ---- r2 end case

# ---- r2 case: tmpdir
# The fix's own temporary files are made where TMPDIR says, so run()'s "left temporary files behind" check watches
# the folder they are really in; the only other place it makes files is beside the bundle. `mktemp -t` on macOS
# ignores TMPDIR for the per-user folder, so until 31 Oct 2026 that check watched a folder the fix never wrote to,
# and could not fail.
d=$r2/tmpdir; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"; : >"$d/log"
run "$d/cert.pem" PATH="$shims:$PATH" WL_MKTEMP_LOG="$d/log" "$offline" "$OFFLINE"
[ "$code" -eq 0 ] || fail "temporary files: expected the run to fix the bundle, exit 0, got $code"
[ "$(grep -c . "$d/log")" -ge 2 ] || fail "temporary files: the fix made $(grep -c . "$d/log") file(s) with mktemp, fewer than its two temporary files"
elsewhere=$(grep -v -e "^$work/tmp/" -e "^$d/\.wardlatch-" "$d/log" || true)
[ -z "$elsewhere" ] || fail "temporary files: the fix made files outside TMPDIR ($work/tmp) and outside the bundle's folder: $elsewhere"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "the fix makes its temporary files in TMPDIR, where the check for leftovers looks"
# ---- r2 end case

# ---- r2 case: heredoc
# No here-string and no here-document anywhere in the fix. macOS's /bin/bash 3.2 writes each one to a file in
# /private/var/tmp whatever TMPDIR says, and the fingerprint comparison was one: where that write failed (a sandbox, an
# endpoint agent's policy, a full disk), the comparison failed, the failure read as "no match", and the run said
# SAFE with both roots still in the file.
hd=$(grep -n '<<' "$fix" | grep -v '^[0-9]*:[[:space:]]*#' || true)
[ -z "$hd" ] || fail "the fix has here-strings or here-documents, which bash 3.2 writes to /private/var/tmp: $hd"
ok "the fix has no here-string and no here-document"
# ---- r2 end case

# ---- r2 case: heredoc-trigger
# The same, run for real: the shipped script under a profile that refuses every write to /private/var/tmp (and all
# network but loopback). Until 31 Oct 2026 it printed SAFE, exit 0, with both roots still in the file. sandbox-exec
# cannot apply a profile inside another one; only WL_NESTED_SANDBOX=1 lets this case be skipped for that reason, and
# then it is named at the end as not run.
if /usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>/dev/null; then
  d=$r2/vartmp; mkdir "$d"
  printf '%s\n' '(version 1)' '(allow default)' '(deny network-outbound)' '(allow network-outbound (remote ip "localhost:*"))' \
    '(deny file-write* (regex #"^/private/var/tmp/"))' >"$d/profile.sb"
  # shellcheck disable=SC2016
  printf '%s\n' '#!/bin/bash' 'exec /usr/bin/sandbox-exec -f "$WL_SB" /bin/bash "$WL_REAL"' >"$d/wrap.sh"
  cp "$work/original.pem" "$d/cert.pem"
  script=$d/wrap.sh
  stderr_ok=1
  run "$d/cert.pem" WL_SB="$d/profile.sb" WL_REAL="$fix" "$offline" "$OFFLINE"
  stderr_ok=''
  script=$fix
  if grep -q '^SAFE' <<<"$out" && [ "$(bad "$d/cert.pem")" -ne 0 ]; then
    fail "/private/var/tmp refused: it printed SAFE with $(bad "$d/cert.pem") withdrawn root(s) still in the file"
  fi
  [ "$code" -eq 0 ] || fail "/private/var/tmp refused: expected the run to fix the bundle as it does anywhere else, exit 0, got $code"
  [ "$(bad "$d/cert.pem")" -eq 0 ] || fail "/private/var/tmp refused: a withdrawn root is still in the file"
  [ ! -s "$work/stderr" ] || fail "/private/var/tmp refused: it wrote to stderr: $(head -3 "$work/stderr")"
  rm -f "$d"/cert.pem.wardlatch-*.bak
  ok "with every write to /private/var/tmp refused, the fix still finds and removes both roots"
elif [ "${WL_NESTED_SANDBOX:-}" = 1 ]; then
  echo "NOTE: sandbox-exec can't apply a profile here (this run is inside another sandbox), so heredoc-trigger did not run."
  notrun="$notrun heredoc-trigger"
else
  fail "/private/var/tmp refused: sandbox-exec could not apply a profile, so this case cannot run (inside another sandbox, WL_NESTED_SANDBOX=1 names it as not run instead)"
fi
# ---- r2 end case

# ---- r2 case: fp-empty
# An openssl that prints nothing and exits 0 for AAA Certificate Services. A certificate whose fingerprint could not
# be read is not "not a withdrawn root": every certificate must give a fingerprint, or the run is UNKNOWN and changes
# nothing. Until 31 Oct 2026 the empty answer matched neither root, and the run removed emSign, kept AAA, and said
# SAFE, exit 0.
d=$r2/fpempty; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
script=$r2/ossl.sh
run "$d/cert.pem" WARDLATCH_OPENSSL="$r2/openssl" STUB_MATCH="$aaa_line" STUB_OUT= "$offline" "$OFFLINE"
script=$fix
[ "$code" -eq 2 ] || fail "an empty fingerprint for a withdrawn root: expected UNKNOWN, exit 2, got $code"
grep -q '^SAFE' <<<"$out" && fail "an empty fingerprint for a withdrawn root: it said SAFE"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "an empty fingerprint for a withdrawn root: the bundle changed"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "an empty fingerprint for a withdrawn root: it wrote a backup"
ok "a withdrawn root whose fingerprint comes back empty makes the run UNKNOWN, and nothing changes"
# ---- r2 end case

# ---- r2 case: fp-garbage
# The same for an ordinary certificate whose fingerprint comes back as something that is not a fingerprint. That
# certificate could be anything, so the file has not been fully checked, and the completeness gate (fingerprints read
# against certificates counted) makes it UNKNOWN. Until 31 Oct 2026 it counted as "not a withdrawn root".
d=$r2/fpgarbage; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
script=$r2/ossl.sh
run "$d/cert.pem" WARDLATCH_OPENSSL="$r2/openssl" STUB_MATCH="$other_line" STUB_OUT='SHA256 Fingerprint=this is not a fingerprint' "$offline" "$OFFLINE"
script=$fix
[ "$code" -eq 2 ] || fail "a fingerprint that isn't one: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a fingerprint that isn't one: the bundle changed"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a fingerprint that isn't one: it wrote a backup"
ok "a certificate whose fingerprint isn't one makes the run UNKNOWN, and nothing changes"
# ---- r2 end case

# ---- r2 case: marker-comment
# A comment that mentions the BEGIN marker after other text stops the run: UNKNOWN, exit 2, nothing changed, and the
# line says why. Until the morning of 31 Oct 2026 the fix counted the marker anywhere in a line and called this bundle
# unreadable ("a certificate can't be read"); r2 then counted only markers at the start of a line, on the model that
# LibreSSL reads a certificate from nowhere else, and this case expected the bundle fixed. That model is untrue:
# LibreSSL reads the file 253 bytes at a time, so a marker at byte 253, 506, ... of a long line starts a certificate it
# trusts (OpenSSL 3.6.4 at byte 254), and a withdrawn root hidden that way stayed in the file under SAFE, exit 0 (the
# r3 case begin-mid-line). The fix now refuses a marker anywhere but at the start of a line, this comment's included,
# because it cannot know which reader of the file sees which; refusing is UNKNOWN, never a false SAFE.
d=$r2/marker; mkdir "$d"
note='# Corporate additions. Paste each certificate below, from its -----BEGIN CERTIFICATE----- line to its -----END CERTIFICATE----- line.'
{ cat "$work/original.pem"; printf '%s\n' "$note"; cat "$r2/corp.pem"; } >"$d/cert.pem"
cp "$d/cert.pem" "$d/cert.before"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a comment naming the marker: expected UNKNOWN, exit 2, got $code"
grep -q '^UNKNOWN' <<<"$out" || fail "a comment naming the marker: expected UNKNOWN"
grep -q 'BEGIN comes after other text' <<<"$out" || fail "a comment naming the marker: it did not say a line holds the marker after other text"
cmp -s "$d/cert.pem" "$d/cert.before" || fail "a comment naming the marker: the bundle changed"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a comment naming the marker: it wrote a backup"
ok "a comment that mentions the BEGIN marker after other text stops the run, and nothing changes"
# ---- r2 end case

# ---- r2 case: strip-own-lines
# Only each withdrawn root's own lines go: its certificate block; its name lines when they are directly above it and
# name that root (Apple's "=== .../CN=<name>" with the text dump ending in its own SHA-256 line, or mk-ca-bundle's
# name and "=" underline); and the one empty line after it. Everything else stays, byte for byte. Until 31 Oct 2026 an
# administrator's own "=== " line above a root they had appended, and every line between, went with the root; so did
# every empty line after it; and the run said SAFE, exit 0. The expected file is built here from the same parts.
d=$r2/strip; mkdir "$d"
# Apple's entry for AAA with an administrator's note inside the description: no longer that root's description and
# nothing else, so only the certificate block goes and the note, the name line and the description stay.
awk 'NR == 2 { print; print "# IT: checked against the vendor list on 2026-10-01"; next } { print }' "$r2/aaa-entry.pem" >"$d/noted-entry.pem"
awk '/^-----BEGIN CERTIFICATE-----/ { exit } { print }' "$d/noted-entry.pem" >"$d/noted-kept.pem"
{
  cat "$r2/emsonly.pem"
  cat "$d/noted-entry.pem"; echo
  printf '%s\n' '=== Added by IT on 2026-10-01: compatibility root and our proxy root below' '# Contact: it-pki@example.invalid'
  cat "$r2/aaa.pem"; echo
  echo '=== Pasted by IT, with its description'
  cat "$r2/aaa-entry.pem"; echo
  echo; echo 'AAA Certificate Services'; echo '========================'
  cat "$r2/aaa.pem"; echo
  cat "$r2/aaa.pem"; echo; echo; echo '# kept: of the two empty lines above, one is the separator and one is not'
  echo 'AAA Certificate Services'; echo '# pasted from the vendor portal'
  cat "$r2/aaa.pem"
  cat "$r2/corp.pem"
} >"$d/cert.pem"
{
  cat "$r2/P.pem"
  cat "$d/noted-kept.pem"
  printf '%s\n' '=== Added by IT on 2026-10-01: compatibility root and our proxy root below' '# Contact: it-pki@example.invalid'
  echo '=== Pasted by IT, with its description'
  echo
  echo; echo '# kept: of the two empty lines above, one is the separator and one is not'
  echo 'AAA Certificate Services'; echo '# pasted from the vendor portal'
  cat "$r2/corp.pem"
} >"$d/expected.pem"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 0 ] || fail "lines around removed roots: expected the bundle fixed, exit 0, got $code"
if ! cmp -s "$d/cert.pem" "$d/expected.pem"; then
  diff "$d/expected.pem" "$d/cert.pem" >"$d/diff" || true
  head -20 "$d/diff" | sed 's/^/    > /'
  fail "lines around removed roots: the file is not the bundle with only the withdrawn roots' own lines removed"
fi
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "only each withdrawn root's own lines are removed; an administrator's lines around them stay"
# ---- r2 end case

# ---- r2 case: symlink-advice
# A linked cert.pem is refused, for the true reason, with advice that can be followed: the command it prints, run as
# printed, fixes the file the link points to and leaves the link alone. Until 31 Oct 2026 the reason given was that
# the Mac would go on reading the old file (replacing the link gives $FILE a cleaned file of its own), and the advice
# was "run this against that file instead", without how.
d=$r2/link; mkdir "$d"
cp "$work/original.pem" "$d/target.pem"; chmod 644 "$d/target.pem"
ln -s target.pem "$d/cert.pem"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a linked bundle: expected UNKNOWN, exit 2, got $code"
grep -q "is a symbolic link to $d/target.pem" <<<"$out" || fail "a linked bundle: it did not say which file the link points to"
grep -q 'actually reads as it is' <<<"$out" && fail "a linked bundle: it gave the old reason, which is untrue"
named=$(sed -n "s/.*WARDLATCH_CERT_FILE='\([^']*\)' bash .*/\1/p" <<<"$out")
[ -n "$named" ] || fail "a linked bundle: it printed no command to fix the file the link points to"
[ "$named" = "$d/target.pem" ] || fail "a linked bundle: its command names $named, not the file the link points to"
run "$named" "$offline" "$OFFLINE"
[ "$code" -eq 0 ] || fail "a linked bundle: the printed command did not fix the file it names, exit $code"
[ "$(bad "$d/target.pem")" -eq 0 ] || fail "a linked bundle: after the printed command, a withdrawn root is still in the file"
[ -L "$d/cert.pem" ] || fail "a linked bundle: the link is no longer a link"
[ "$(readlink "$d/cert.pem")" = target.pem ] || fail "a linked bundle: the link points somewhere else now"
rm -f "$d"/target.pem.wardlatch-*.bak
ok "a linked bundle is refused for the true reason, and the command it prints fixes the file the link points to"
# ---- r2 end case

# ---- r2 case: dangling-new
# A symbolic link to nothing at the name the fix used for its new file until 31 Oct 2026 (.wardlatch-new.<pid>)
# passed `[ ! -e ]`: cp wrote through it, and mv put the link itself where the bundle was. The new file is now made by
# mktemp, which refuses anything at its name, under a name nobody can take in advance.
d=$r2/dangling; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' \
  '# Takes .wardlatch-new.<pid> beside the bundle as a link to a file that does not exist, then runs the fix in this' \
  '# same process, so the pid -- and the name -- is the one taken.' \
  'ln -s "$WL_ELSEWHERE" "$(dirname "$WARDLATCH_CERT_FILE")/.wardlatch-new.$$"' \
  'exec bash "$WL_REAL"' >"$d/take.sh"
script=$d/take.sh
run "$d/cert.pem" WL_ELSEWHERE="$d/elsewhere.pem" WL_REAL="$fix" "$offline" "$OFFLINE"
script=$fix
[ ! -L "$d/cert.pem" ] || fail "a link at the new file's name: the bundle is now a symbolic link to $(readlink "$d/cert.pem")"
[ ! -e "$d/elsewhere.pem" ] || fail "a link at the new file's name: the fix wrote through it"
[ "$code" -eq 0 ] || fail "a link at the new file's name: expected the bundle fixed, exit 0, got $code"
[ "$(bad "$d/cert.pem")" -eq 0 ] || fail "a link at the new file's name: a withdrawn root is still there"
rm -f "$d"/.wardlatch-new.* "$d"/cert.pem.wardlatch-*.bak
ok "a link planted at the new file's name is never written through, and the bundle stays a file"
# ---- r2 end case

# ---- r2 case: tamper-new
# The cleaned file changed in the temporary folder after it was checked and before root copied it beside the bundle
# -- a withdrawn root appended, or one ordinary certificate swapped for another (same count, no withdrawn root).
# What is renamed into place is now checked beside the bundle, byte for byte against the cleaned file's SHA-256, so
# neither lands. Until 31 Oct 2026 the checked copy was the one in the invoking user's temporary folder, and both
# landed under SAFE, exit 0.
d=$r2/tamper; mkdir "$d"
for how in append swap; do
  cp "$work/original.pem" "$d/cert.pem"
  if [ "$how" = append ]; then tw=$r2/aaa.pem; else tw=$r2/corp.pem; fi
  run "$d/cert.pem" PATH="$shims:$PATH" WL_CP="tamper-new-$how" WL_TAMPER="$tw" "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "the cleaned file changed before it was copied ($how): expected UNKNOWN, exit 2, got $code"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "the cleaned file changed before it was copied ($how): the bundle was replaced with a file nobody checked"
  [ -z "$(beside "$d/cert.pem")" ] || fail "the cleaned file changed before it was copied ($how): it left $(beside "$d/cert.pem") beside the bundle"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a cleaned file changed after its check never lands: the file beside the bundle is what is checked"
# ---- r2 end case

# ---- r2 case: changed-before-backup
# The bundle changes during the backup step -- where the interactive run waits for the password -- here, an
# administrator's root appended just before the copy. The backup is compared with the snapshot, so the run stops and
# the change stays. Until 31 Oct 2026 the "changed while this ran" check came before that step and the backup was
# compared with the live file: both passed, the cleaned OLD snapshot replaced the file, and the appended root was
# gone from it, under SAFE, exit 0.
d=$r2/racebefore; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"; cat "$work/original.pem" "$r2/corp.pem" >"$d/expected.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=race-before-backup WL_CORP="$r2/corp.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a change during the backup step: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$d/expected.pem" || fail "a change during the backup step: the change was thrown away ($(certs_in "$d/cert.pem") certificates left)"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a change during the backup step: a copy that is not the file this run checked was kept as the backup"
[ -z "$(beside "$d/cert.pem")" ] || fail "a change during the backup step: it left $(beside "$d/cert.pem") beside the bundle"
ok "a change made during the backup step stops the run, and the change is kept"
# ---- r2 end case

# ---- r2 case: changed-after-backup
# The bundle changes after the backup is taken. The file is compared with the snapshot again immediately before the
# replacement, so the run stops, the change stays, and the backup is the file the run read.
d=$r2/raceafter; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"; cat "$work/original.pem" "$r2/corp.pem" >"$d/expected.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=race-after-backup WL_CORP="$r2/corp.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a change after the backup: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$d/expected.pem" || fail "a change after the backup: the change was thrown away ($(certs_in "$d/cert.pem") certificates left)"
b=$(find "$d" -maxdepth 1 -name 'cert.pem.wardlatch-*.bak')
[ -n "$b" ] || fail "a change after the backup: no backup was kept"
cmp -s "$b" "$work/original.pem" || fail "a change after the backup: the backup is not the file this run read"
[ -z "$(beside "$d/cert.pem")" ] || fail "a change after the backup: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$b"
ok "a change made after the backup stops the run before the replacement, and the change is kept"
# ---- r2 end case

# ---- r2 case: partial-backup
# The backup copy fails part-way (a full disk). Nothing is left under the dated backup name, and the line says what
# happened. Until 31 Oct 2026 the copy went straight to the dated name, and a truncated file was left under exactly
# the name of a good backup.
d=$r2/partialbackup; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=partial-backup "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a backup copy that failed part-way: expected UNKNOWN, exit 2, got $code"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a backup copy that failed part-way: a truncated copy was left under the dated backup name"
[ -z "$(beside "$d/cert.pem")" ] || fail "a backup copy that failed part-way: it left $(beside "$d/cert.pem") beside the bundle"
grep -q 'no backup was kept' <<<"$out" || fail "a backup copy that failed part-way: the line did not say that no backup was kept"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a backup copy that failed part-way: the bundle changed"
ok "a backup copy that fails part-way leaves nothing under the backup's name, and says so"
# ---- r2 end case

# ---- r2 case: sig-backup
# A Ctrl-C during the backup copy. Nothing is left under the dated backup name, and the run prints a line. Until
# 31 Oct 2026 it left a truncated copy under that name and printed nothing.
d=$r2/sigbackup; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_CP=sig-backup "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a run stopped during the backup copy: expected exit 2, got $code"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a run stopped during the backup copy: a partial copy was left under the dated backup name"
[ -z "$(beside "$d/cert.pem")" ] || fail "a run stopped during the backup copy: it left $(beside "$d/cert.pem") beside the bundle"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a run stopped during the backup copy: the bundle changed"
grep -q 'Stopped' <<<"$out" || fail "a run stopped during the backup copy: it did not say it was stopped"
ok "a run stopped during the backup copy leaves no partial backup, and says it was stopped"
# ---- r2 end case

# ---- r2 case: sig-forward
# A Ctrl-C between the rename that replaces the bundle and the line after it. The file has changed, so the run must
# say so. Until 31 Oct 2026 the report went by a flag set after the rename returned: the file was replaced, the run
# exited 2, and printed nothing.
d=$r2/sigforward; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MV=sig-forward "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a run stopped just after the rename: expected exit 2, got $code"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "a run stopped just after the rename: the bundle is not the cleaned file"
grep -q 'had already been replaced with the cleaned file' <<<"$out" || fail "a run stopped just after the rename: it did not say the file had been replaced"
grep -q "Backup: $d/cert.pem.wardlatch-" <<<"$out" || fail "a run stopped just after the rename: it did not name the backup"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a run stopped just after the rename says the file was replaced, and names the backup"
# ---- r2 end case

# ---- r2 case: sig-restore
# A Ctrl-C just after the content-mismatch restore put the original back. The line must say what the file holds --
# the file the run read, with both withdrawn roots. Until 31 Oct 2026 it said the file "had already been replaced
# with the cleaned file (removed both withdrawn roots ...). It is whole".
d=$r2/sigrestore; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MV=mismatch-sig-restore WL_MV_STATE="$d/state" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a run stopped after the restore: expected exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a run stopped after the restore: the bundle is not the original"
grep -q 'replaced with the cleaned file' <<<"$out" && fail "a run stopped after the restore: it said the file holds the cleaned file; it holds $(bad "$d/cert.pem") withdrawn root(s)"
grep -q 'still holds' <<<"$out" || fail "a run stopped after the restore: it did not say the file still holds the withdrawn roots"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a run stopped after the restore says the file is the original, with the withdrawn roots"
# ---- r2 end case

# ---- r2 case: sig-restore-cp
# A Ctrl-C during the restore's copy, before its rename: the file holds the mismatched bytes nobody checked, and the
# line must say that. Until 31 Oct 2026 it said "replaced with the cleaned file ... It is whole" here too.
d=$r2/sigrestorecp; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MV=mismatch WL_CP=sig-restore-cp WL_MV_STATE="$d/state" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a run stopped during the restore's copy: expected exit 2, got $code"
[ "$(tail -n 1 "$d/cert.pem")" = '# another writer' ] || fail "a run stopped during the restore's copy: the bundle is not the mismatched file this case expects"
grep -q 'replaced with the cleaned file' <<<"$out" && fail "a run stopped during the restore's copy: it said the file holds the cleaned file; it holds bytes nothing checked"
grep -q "didn't build or check" <<<"$out" || fail "a run stopped during the restore's copy: it did not say the file holds bytes this run didn't build or check"
[ -z "$(beside "$d/cert.pem")" ] || fail "a run stopped during the restore's copy: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a run stopped during the restore's copy says the file holds bytes nothing checked"
# ---- r2 end case

# ---- r2 case: stopped-prints
# A Ctrl-C before anything is written (here, during the control read before the change). Exit 2 means "read the
# printed line", so there must be one. Until 31 Oct 2026 a run stopped before the file was replaced printed nothing.
d=$r2/stopped; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$r2/net.sh" "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_HOLD=1 STUB_STATE="$d/state" STUB_CONTROL=7 STUB_TEST=60
[ "$code" -eq 2 ] || fail "a run stopped before any write: expected exit 2, got $code"
grep -q 'Stopped before this changed anything' <<<"$out" || fail "a run stopped before any write: it did not say nothing was changed"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a run stopped before any write: the bundle changed"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a run stopped before any write: it wrote a backup"
ok "a run stopped before any write says so"
# ---- r2 end case

# ---- r2 case: sudo-refused
# sudo refusing (a wrong password three times, no answer in time) is reported as sudo refusing. Until 31 Oct 2026 the
# first sudo call was the backup copy, and its failure was reported as a disk with no room (df -h /).
if [ "$(id -u)" -eq 0 ]; then
  echo "NOTE: running as root, so the fix never calls sudo; sudo-refused did not run."
  notrun="$notrun sudo-refused"
else
  d=$r2/sudo; mkdir "$d"
  cp "$work/original.pem" "$d/cert.pem"; chmod 644 "$d/cert.pem"
  chmod 555 "$d"
  run "$d/cert.pem" PATH="$shims:$PATH" "$offline" "$OFFLINE"
  chmod 755 "$d"
  [ "$code" -eq 2 ] || fail "a refused sudo: expected UNKNOWN, exit 2, got $code"
  grep -q 'sudo' <<<"$out" || fail "a refused sudo: it did not say sudo refused"
  grep -qi 'disk\|df -h' <<<"$out" && fail "a refused sudo: it blamed the disk"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a refused sudo: the bundle changed"
  [ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a refused sudo: it wrote a backup"
  ok "a refused sudo is reported as sudo refusing, not as a full disk"
fi
# ---- r2 end case

# ---- r2 case: network-stopped
# The control loads before the change and then fails after it. A name that didn't resolve (6), a connection not made
# (7) or no answer in time (28) is a network that stopped answering, not a certificate refused: UNKNOWN, the fix kept,
# and no attack diagnosed. Only a refused certificate (60) gets the reading about the change or the network, attack
# included; any other code is reported without a reading. Until 31 Oct 2026 every one of them got the attack reading.
d=$r2/netstop; mkdir "$d"
script=$r2/net.sh
for c in 6 7 28; do
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
  run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_STATE="$d/state" STUB_CONTROLS="0 $c" STUB_TEST=60
  [ "$code" -eq 2 ] || fail "the network stopped answering (curl $c): expected UNKNOWN, exit 2, got $code"
  grep -q 'stopped answering' <<<"$out" || fail "the network stopped answering (curl $c): it did not say the network stopped answering"
  grep -qi 'attack' <<<"$out" && fail "the network stopped answering (curl $c): it diagnosed an attack from a network that did not answer"
  grep -q "(curl $c" <<<"$out" || fail "the network stopped answering (curl $c): it did not give the reading"
  cmp -s "$d/cert.pem" "$r2/P.pem" || fail "the network stopped answering (curl $c): the file is not the fixed file"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_STATE="$d/state" STUB_CONTROLS="0 60" STUB_TEST=60
[ "$code" -eq 2 ] || fail "a certificate refused after the change: expected UNKNOWN, exit 2, got $code"
grep -q "doesn't load through the new one (curl 60" <<<"$out" || fail "a certificate refused after the change: it did not give the reading"
grep -q 'attack' <<<"$out" || fail "a certificate refused after the change: it did not give the reading an attack would produce"
rm -f "$d"/cert.pem.wardlatch-*.bak
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_STATE="$d/state" STUB_CONTROLS="0 35" STUB_TEST=60
[ "$code" -eq 2 ] || fail "another failure after the change (curl 35): expected UNKNOWN, exit 2, got $code"
grep -qi 'attack' <<<"$out" && fail "another failure after the change (curl 35): it diagnosed an attack"
grep -q 'reads nothing into it' <<<"$out" || fail "another failure after the change (curl 35): it did not say it reads nothing into it"
rm -f "$d"/cert.pem.wardlatch-*.bak
script=$fix
ok "after the change, a network that stopped answering is not read as a certificate refused or as an attack"
# ---- r2 end case

# ---- r2 case: no-revert-advice
# On the readings a network -- or an attacker holding a withdrawn root's key -- can produce, and when the restore
# itself fails, the run names its backup and what it holds, and prints no command that puts a withdrawn root back.
# Until 31 Oct 2026 each of these printed one: an Undo line, under "Decide it yourself from the two lines below" on
# the control reading, and "Put it back yourself, now: sudo cp -p ..." on the failed restore.
d=$r2/norevert; mkdir "$d"
script=$r2/net.sh
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_STATE="$d/state" STUB_CONTROLS="0 60" STUB_TEST=60
grep -q 'Undo:' <<<"$out" && fail "a certificate refused after the change: it printed an Undo line"
grep -q 'Decide it yourself' <<<"$out" && fail "a certificate refused after the change: it put the revert in front of the reader as their decision"
grep -q "Backup: $d/cert.pem.wardlatch-" <<<"$out" || fail "a certificate refused after the change: it did not name the backup"
rm -f "$d"/cert.pem.wardlatch-*.bak
cp "$work/original.pem" "$d/cert.pem"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=0
[ "$code" -eq 1 ] || fail "a network that accepts everything: expected EXPOSED, exit 1, got $code"
grep -q 'Undo:' <<<"$out" && fail "a network that accepts everything: it printed an Undo line"
rm -f "$d"/cert.pem.wardlatch-*.bak
script=$fix
awk '{ print } /^replace\(\) \{$/ { print "  case \"$1\" in *.bak) return 1 ;; esac" }' "$fix" |
  awk '{ print } /^replaced=1$/ { print "echo tampered >> \"$FILE\"" }' >"$d/norestore.sh"
[ "$(wc -l <"$d/norestore.sh")" -eq $(($(wc -l <"$fix") + 2)) ] || fail "a failed restore: replace() or the line after the write was not found, so this proves nothing"
cp "$work/original.pem" "$d/cert.pem"
script=$d/norestore.sh
run "$d/cert.pem" "$offline" "$OFFLINE"
script=$fix
[ "$code" -eq 2 ] || fail "a failed restore: expected UNKNOWN, exit 2, got $code"
grep -q 'sudo cp -p' <<<"$out" && fail "a failed restore: it printed a command to put back a copy that holds the withdrawn roots"
grep -q "Backup: $d/cert.pem.wardlatch-" <<<"$out" || fail "a failed restore: it did not name the backup"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "no command that puts a withdrawn root back is printed on a network reading or a failed restore"
# ---- r2 end case

# ---- r2 case: one-root-wording
# What the run says it removed is what it removed, by name, and nothing about the Mac that one file cannot show: on
# the one-root shapes (every Mac from before emSign was added holds one), on two copies of one root, and in the
# reading after a refused certificate. Until 31 Oct 2026: "the other was already absent from this Mac", "removed both
# withdrawn roots" for two copies of AAA, and "issued under AAA Certificate Services" on a file that never held it.
d=$r2/oneroot; mkdir "$d"
script=$r2/net.sh
for shape in aaaonly emsonly; do
  if [ "$shape" = aaaonly ]; then
    want='removed AAA Certificate Services (this file did not hold the other withdrawn root, emSign ECC Root CA - G3)'
  else
    want='removed emSign ECC Root CA - G3 (this file did not hold the other withdrawn root, AAA Certificate Services)'
  fi
  cp "$r2/$shape.pem" "$d/cert.pem"
  run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=60
  [ "$code" -eq 0 ] || fail "one root ($shape): expected SAFE, exit 0, got $code"
  grep -qF "$want" <<<"$out" || fail "one root ($shape): it did not say \"$want\""
  grep -q 'already absent' <<<"$out" && fail "one root ($shape): it said the other root is absent from this Mac, which one file cannot show"
  grep -q 'removed both' <<<"$out" && fail "one root ($shape): it said both roots were removed"
  [ "$(bad "$d/cert.pem")" -eq 0 ] || fail "one root ($shape): the root is still there"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
cat "$r2/aaaonly.pem" "$r2/aaa.pem" >"$d/cert.pem"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=60
grep -qF 'removed 2 copies of AAA Certificate Services (this file did not hold the other withdrawn root, emSign ECC Root CA - G3)' <<<"$out" ||
  fail "two copies of one root: it did not say it removed two copies of AAA Certificate Services"
grep -q 'removed both' <<<"$out" && fail "two copies of one root: it said both withdrawn roots were removed"
rm -f "$d"/cert.pem.wardlatch-*.bak
cp "$r2/emsonly.pem" "$d/cert.pem"; rm -f "$d/state"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_STATE="$d/state" STUB_CONTROLS="0 60" STUB_TEST=60
grep -q 'issued under AAA' <<<"$out" && fail "a refused certificate on an emSign-only file: it named AAA Certificate Services, which the file never held"
grep -qF 'differ only by emSign ECC Root CA - G3' <<<"$out" || fail "a refused certificate on an emSign-only file: it did not name what the two files differ by"
rm -f "$d"/cert.pem.wardlatch-*.bak
script=$fix
ok "what the run says it removed is what this file held, by name"
# ---- r2 end case

# ---- r2 case: already-clean
# A bundle that already holds neither root, beside the backup a first run left (which holds both). The branch for it
# had no case: an EXPOSED that exited 0, a flipped control and a revert to that backup all passed. Every reading,
# and the file and the backup untouched by each.
d=$r2/clean; mkdir "$d"
cp "$r2/P.pem" "$d/cert.pem"; cp "$work/original.pem" "$d/cert.pem.wardlatch-20261030-000000.bak"
script=$r2/net.sh
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=0
[ "$code" -eq 1 ] || fail "already clean, test site trusted: expected EXPOSED, exit 1, got $code"
grep -q '^EXPOSED.*holds neither root but still trusts the test site' <<<"$out" || fail "already clean, test site trusted: expected EXPOSED"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "already clean, test site trusted: the file changed (put back to the backup?)"
cmp -s "$d/cert.pem.wardlatch-20261030-000000.bak" "$work/original.pem" || fail "already clean, test site trusted: the backup changed"
[ "$(baks "$d/cert.pem")" -eq 1 ] || fail "already clean, test site trusted: it wrote another backup"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=60
[ "$code" -eq 0 ] || fail "already clean, test site refused: expected SAFE, exit 0, got $code"
grep -q 'already refuses the compromised keys' <<<"$out" || fail "already clean, test site refused: it did not give the test site's answer"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=7 STUB_TEST=60
[ "$code" -eq 0 ] || fail "already clean, no control: expected SAFE, exit 0, got $code"
grep -q "no longer holds the two roots" <<<"$out" || fail "already clean, no control: expected the no-roots line"
grep -q "didn't load either (curl 7)" <<<"$out" || fail "already clean, no control: it did not say the control didn't load"
grep -q 'already refuses' <<<"$out" && fail "already clean, no control: it read the test site with no control"
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=28
[ "$code" -eq 0 ] || fail "already clean, test site silent: expected SAFE, exit 0, got $code"
grep -q "didn't answer (curl 28)" <<<"$out" || fail "already clean, test site silent: it did not say the test site didn't answer"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "already clean: a run changed the file"
[ "$(baks "$d/cert.pem")" -eq 1 ] || fail "already clean: a run wrote another backup"
script=$fix
ok "an already-clean bundle: each reading in its own words and exit code, the file and the backup untouched"
# ---- r2 end case

# ---- r2 case: stray-writes
# Nothing outside replace() writes to $FILE, whatever command does it and however the line ends. The guard in the
# content-mismatch case above looks only for a write whose last word is "$FILE"; a revert added as
# `$SUDO cp -p "$b" "$FILE" 2>/dev/null || true` ends in something else, and passed it. Quoted text is blanked
# first, so the words of a message are not read as commands, and "$FILE" becomes @FILE@ so it survives that. A cp
# that READS $FILE into a file of its own (the snapshot, the backup copy) is the one shape allowed.
awk '/^replace\(\) \{$/ { inside = 1 } inside { if ($0 == "}") inside = 0; next } { print }' "$fix" |
  grep -v '^[[:space:]]*#' |
  sed -e 's/"\$FILE"/@FILE@/g' -e 's/"\${FILE}"/@FILE@/g' -e 's/"[^"]*"/""/g' -e "s/'[^']*'/''/g" >"$r2/outside.sh" || true
redir=$(grep -nE '>>?[[:space:]]*(@FILE@|\$\{?FILE\b)' "$r2/outside.sh" || true)
[ -z "$redir" ] || fail "a redirection into \$FILE outside replace(): $redir"
cmds=$(grep -nE '(^|[[:space:];&|({])(cp|mv|install|tee|dd|ln|link|rsync|ditto|sed|perl|truncate|rm|chmod|chown|touch|cat)([[:space:]]|$)' "$r2/outside.sh" |
  grep -E '@FILE@|\$\{?FILE\b' | grep -vE 'cp (-p )?@FILE@ ""' || true)
[ -z "$cmds" ] || fail "a command outside replace() that can write, with \$FILE among its words: $cmds"
ok "nothing outside replace() writes to the bundle"
# ---- r2 end case

# ---- r2 case: fixed-test-silent
# Fixed, the control loads after the change, and the test site does not answer: SAFE in the file, exit 0, with that
# said. No case reached this branch before 31 Oct 2026; an `exit 2` added to it passed.
d=$r2/testsilent; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
script=$r2/net.sh
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=28
script=$fix
[ "$code" -eq 0 ] || fail "the test site silent after the change: expected SAFE, exit 0, got $code"
grep -q '^SAFE     Fixed in the file' <<<"$out" || fail "the test site silent after the change: expected SAFE, fixed in the file"
grep -q '(curl 28)' <<<"$out" || fail "the test site silent after the change: it did not give the test site's reading"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "the test site silent after the change: the file is not the fixed file"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "the test site silent after the change: SAFE in the file, exit 0, and the reading given"
# ---- r2 end case

# ---- r2 case: replace-fails
# replace()'s own failure path, reached through the shipped body -- a copy that fails part-way, a chmod that fails, a
# rename that fails -- not through a rewritten replace(). UNKNOWN, exit 2, the bundle as it was, nothing beside it.
# No case ran this path before 31 Oct 2026: removing its cleanup, or making it return success, passed.
d=$r2/replacefails; mkdir "$d"
for how in WL_CP=partial-new WL_CHMOD=fail-new WL_MV=fail; do
  cp "$work/original.pem" "$d/cert.pem"
  run "$d/cert.pem" PATH="$shims:$PATH" "$how" "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "a write that fails ($how): expected UNKNOWN, exit 2, got $code"
  grep -q "Couldn't replace" <<<"$out" || fail "a write that fails ($how): it did not say the replacement failed"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a write that fails ($how): the bundle changed"
  [ -z "$(beside "$d/cert.pem")" ] || fail "a write that fails ($how): it left $(beside "$d/cert.pem") beside the bundle"
  b=$(find "$d" -maxdepth 1 -name 'cert.pem.wardlatch-*.bak')
  if [ -z "$b" ] || ! cmp -s "$b" "$work/original.pem"; then fail "a write that fails ($how): the backup is not the original"; fi
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a copy, chmod or rename that fails inside replace() is UNKNOWN, and leaves nothing beside the bundle"
# ---- r2 end case

# ---- r2 case: kill-in-replace
# A TERM during the copy into the new file, reached through the shipped replace(): the bundle must stay whole and a
# line must be printed. The interrupt cases above rewrite replace()'s body, so a replace() that copied straight into
# the bundle passed them all.
d=$r2/killreplace; mkdir "$d"
cp "$work/original.pem" "$d/cert.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=kill-in-new "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a signal during the copy into the new file: expected exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a signal during the copy into the new file: the bundle is neither the old file nor the new one ($(certs_in "$d/cert.pem") certificates)"
[ -z "$(beside "$d/cert.pem")" ] || fail "a signal during the copy into the new file: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a signal during the copy into the new file leaves the bundle whole, and a line to read"
# ---- r2 end case

# ---- r2 case: empty-wording
# A file of 0 certificates is reported as holding none, by the floor's own words. Until 31 Oct 2026 nothing checked
# the words: a roots() that called an empty file unreadable passed.
d=$r2/empty; mkdir "$d"
: >"$d/cert.pem"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "an empty file: expected UNKNOWN, exit 2, got $code"
grep -q 'has 0 certificates, fewer than the 50' <<<"$out" || fail "an empty file: it did not say it holds 0 certificates"
grep -q 'It holds neither' <<<"$out" || fail "an empty file: it did not say it holds neither withdrawn root"
grep -q "couldn't be read" <<<"$out" && fail "an empty file: it said a certificate couldn't be read"
ok "an empty file is reported as holding no certificates and neither root"
# ---- r2 end case

# ---- r2 case: orphan-temp
# A file mktemp made beside the bundle whose name never reached the script -- a signal while mktemp ran, before it
# printed the name -- is still removed: the cleanup looks for this run's own names there. The stand-in makes the
# file and fails without printing its name. Added after a mutant that took out replace()'s own removal survived
# because this cleanup removes the same file at exit, and no case reached the cleanup itself.
d=$r2/orphan; mkdir "$d"
for which in new backup tmp; do
  cp "$work/original.pem" "$d/cert.pem"
  run "$d/cert.pem" PATH="$shims:$PATH" WL_MKTEMP_ORPHAN="$which" "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "a $which file whose name never reached the script: expected UNKNOWN, exit 2, got $code"
  [ -z "$(beside "$d/cert.pem")" ] || fail "a $which file whose name never reached the script: it was left beside the bundle: $(beside "$d/cert.pem")"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a $which file whose name never reached the script: the bundle changed"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a file made beside the bundle whose name never reached the script is removed all the same"
# ---- r2 end case

# ---- r2 case: header
# The header people read before running this with sudo says what the script does. Until 31 Oct 2026 one sentence
# had words missing ("an interruption leaves or the new one") and another ("never tells you to restore a backup")
# was contradicted by the script's own "Put it back yourself" line.
hdr=$(awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); printf "%s ", $0; next } NR > 1 { exit }' "$fix" | tr -s ' ')
grep -qF 'so an interruption leaves the old file or the new one' <<<"$hdr" || fail "the header: the sentence about an interruption does not say what is left"
grep -qF 'never tells you to restore a backup' <<<"$hdr" && fail "the header: it still says the script never tells you to restore a backup"
ok "the header's sentences about interruption and backups say what the script does"
# ---- r2 end case

# ---- r3 cases
# Added on 31 Oct 2026 after a third independent read. Like the r2 cases, each stands on the setup above alone.

# ---- r3 case: mode
# The fix is executable, as the site serves it: `./fix/fix-macos.sh` in a clone must run. fbed337 (31 Oct 2026) took the
# bit away (100755 to 100644) without saying so, and nothing here could see it. In a git checkout the mode git records
# is what a clone gets, so that is what is checked; elsewhere, the file's own bit.
if m=$(git -C "$root" ls-files -s -- fix/fix-macos.sh 2>/dev/null) && [ -n "$m" ]; then
  [ "${m%% *}" = 100755 ] || fail "the fix is mode ${m%% *} in git, not 100755, so ./fix/fix-macos.sh in a clone says Permission denied"
else
  [ -x "$fix" ] || fail "the fix is not executable"
fi
ok "fix/fix-macos.sh is executable (100755)"
# ---- r3 end case

# ---- r3 case: begin-mid-line
# A withdrawn root whose BEGIN marker is not at the start of its line. LibreSSL reads the file 253 bytes at a time, so a
# marker at byte 253, 506, ... of a long line starts a certificate it trusts; until 31 Oct 2026 the fix counted only
# markers at the start of a line, and a root hidden that way stayed in the file under SAFE, exit 0. A marker after other
# text anywhere now stops the run: UNKNOWN, exit 2, nothing changed. Each shape that LibreSSL reads is first shown to be
# read by it (otherwise the case would measure nothing): in each of the three labels it trusts, after ASCII padding and
# after bytes that are not UTF-8, which macOS's grep does not match at all in a UTF-8 locale, so that shape runs in one.
d=$work/r3/midline; mkdir -p "$d"
libre() { /usr/bin/openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | /usr/bin/openssl pkcs7 -print_certs 2>/dev/null | grep -c '^-----BEGIN CERTIFICATE-----' || true; }
aaa_body=$(sed '1d;$d' "$r2/aaa.pem")
for shape in 253-cert 506-cert 253-trusted 253-x509 253-ff 60-cert plus-253; do
  pad=${shape%%-*}; label=${shape#*-}; base=$r2/P.pem
  case "$label" in
    cert|ff) blk=$(cat "$r2/aaa.pem") ;;
    trusted) blk=$(/usr/bin/openssl x509 -in "$r2/aaa.pem" -trustout -addtrust serverAuth) ;;
    x509) blk=$(printf -- '-----BEGIN X509 CERTIFICATE-----\n%s\n-----END X509 CERTIFICATE-----' "$aaa_body") ;;
    253) pad=253; base=$work/original.pem; blk=$(cat "$r2/aaa.pem") ;;   # plus-253: the whole file, plus a hidden copy
  esac
  if [ "$label" = ff ]; then fill='\377'; else fill='#'; fi
  p=$(printf '%*s' "$pad" '' | LC_ALL=C tr ' ' "$fill")
  { cat "$base"; printf '%s%s\n' "$p" "$blk"; } >"$d/$shape.pem"
  cp "$d/$shape.pem" "$d/$shape.before"
  seen=$(libre "$d/$shape.pem"); plain=$(libre "$base")
  if [ "$pad" = 60 ]; then
    [ "$seen" -eq "$plain" ] || fail "a marker after other text ($shape): LibreSSL read the hidden block after all, so this shape is not the one it describes"
  else
    [ "$seen" -eq $((plain + 1)) ] || fail "a marker after other text ($shape): LibreSSL reads $seen certificates, not $((plain + 1)), so this case would measure nothing"
  fi
  run "$d/$shape.pem" LC_ALL=en_US.UTF-8 "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "a marker after other text ($shape): expected UNKNOWN, exit 2, got $code"
  grep -q '^UNKNOWN.*BEGIN comes after other text' <<<"$out" || fail "a marker after other text ($shape): it did not say a line holds the marker after other text"
  cmp -s "$d/$shape.pem" "$d/$shape.before" || fail "a marker after other text ($shape): the bundle changed"
  [ "$(baks "$d/$shape.pem")" -eq 0 ] || fail "a marker after other text ($shape): it wrote a backup"
done
ok "a BEGIN marker after other text on its line stops the run, in every label LibreSSL trusts and after any bytes"
# ---- r3 end case

# ---- r3 case: labels
# A withdrawn root at the start of a line under another label LibreSSL trusts as a certificate: X509 CERTIFICATE, and
# TRUSTED CERTIFICATE (which LibreSSL 3.3.6 trusts even when its trust settings reject serverAuth; measured 31 Oct
# 2026). The fix reads only the CERTIFICATE label, so a file holding any other block is UNKNOWN, exit 2, unchanged:
# it cannot be checked, so it is never called clean. The TRUSTED CERTIFICATE case above uses emSign on the cleaned file;
# this one uses AAA, each label, and shows LibreSSL reads the block first.
d=$work/r3/labels; mkdir -p "$d"
libre() { /usr/bin/openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | /usr/bin/openssl pkcs7 -print_certs 2>/dev/null | grep -c '^-----BEGIN CERTIFICATE-----' || true; }
for label in x509 trusted trusted-reject; do
  case "$label" in
    x509) { cat "$r2/P.pem"; printf -- '-----BEGIN X509 CERTIFICATE-----\n%s\n-----END X509 CERTIFICATE-----\n' "$(sed '1d;$d' "$r2/aaa.pem")"; } >"$d/$label.pem" ;;
    trusted) { cat "$r2/P.pem"; /usr/bin/openssl x509 -in "$r2/aaa.pem" -trustout -addtrust serverAuth; } >"$d/$label.pem" ;;
    trusted-reject) { cat "$r2/P.pem"; /usr/bin/openssl x509 -in "$r2/aaa.pem" -trustout -addreject serverAuth; } >"$d/$label.pem" ;;
  esac
  [ "$(libre "$d/$label.pem")" -eq $(($(libre "$r2/P.pem") + 1)) ] || fail "another label ($label): LibreSSL does not read the block, so this case would measure nothing"
  cp "$d/$label.pem" "$d/$label.before"
  run "$d/$label.pem" "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "another label ($label): expected UNKNOWN, exit 2, got $code"
  grep -q "^UNKNOWN.*aren't plain certificates" <<<"$out" || fail "another label ($label): it did not say the file holds blocks that aren't plain certificates"
  cmp -s "$d/$label.pem" "$d/$label.before" || fail "another label ($label): the bundle changed"
  [ "$(baks "$d/$label.pem")" -eq 0 ] || fail "another label ($label): it wrote a backup"
done
ok "a withdrawn root under another label LibreSSL trusts (X509 CERTIFICATE, TRUSTED CERTIFICATE) is UNKNOWN, unchanged"
# ---- r3 end case

# ---- r3 case: same-key
# A copy of a withdrawn root with one bit of its signature flipped has another SHA-256 fingerprint and the same public
# key, and LibreSSL trusts it as the root (it does not check a trust anchor's own signature; measured 31 Oct 2026). A
# root re-issued with the same key is the same. Until 31 Oct 2026 the fix matched fingerprints only, so such a copy
# stayed in the file under SAFE, exit 0. It is now found by its key and removed, and named as what it is.
d=$work/r3/samekey; mkdir -p "$d"
libre() { /usr/bin/openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | /usr/bin/openssl pkcs7 -print_certs 2>/dev/null | grep -c '^-----BEGIN CERTIFICATE-----' || true; }
flip() {   # $1 = certificate, $2 = out: the same certificate with the low bit of its last byte (in the signature) flipped
  local h
  h=$(/usr/bin/openssl x509 -in "$1" -outform DER | xxd -p | tr -d '\n')
  printf '%s%02x' "${h:0:${#h}-2}" $(( 0x${h: -2} ^ 1 )) | xxd -r -p | /usr/bin/openssl x509 -inform DER -out "$2" ||
    fail "a same-key copy: openssl could not read the flipped copy, so this case would measure nothing"
  [ "$(/usr/bin/openssl x509 -in "$2" -noout -fingerprint -sha256)" != "$(/usr/bin/openssl x509 -in "$1" -noout -fingerprint -sha256)" ] ||
    fail "a same-key copy: the flipped copy has the root's fingerprint, so this case would measure nothing"
  [ "$(/usr/bin/openssl x509 -in "$2" -noout -pubkey)" = "$(/usr/bin/openssl x509 -in "$1" -noout -pubkey)" ] ||
    fail "a same-key copy: the flipped copy does not carry the root's key"
}
flip "$r2/aaa.pem" "$d/aaa-flipped.pem"; flip "$r2/ems.pem" "$d/ems-flipped.pem"
for shape in aaa-alone ems-alone with-both; do
  case "$shape" in
    aaa-alone) cat "$r2/P.pem" "$d/aaa-flipped.pem" >"$d/$shape.pem"; copy=$d/aaa-flipped.pem
               want='removed a certificate with the key of AAA Certificate Services (this file did not hold the other withdrawn root, emSign ECC Root CA - G3)' ;;
    ems-alone) cat "$r2/P.pem" "$d/ems-flipped.pem" >"$d/$shape.pem"; copy=$d/ems-flipped.pem
               want='removed a certificate with the key of emSign ECC Root CA - G3 (this file did not hold the other withdrawn root, AAA Certificate Services)' ;;
    with-both) cat "$work/original.pem" "$d/aaa-flipped.pem" >"$d/$shape.pem"; copy=$d/aaa-flipped.pem
               want='removed both withdrawn roots (AAA Certificate Services and 1 other certificate with its key and emSign ECC Root CA - G3)' ;;
  esac
  [ "$(libre "$d/$shape.pem")" -eq "$(certs_in "$d/$shape.pem")" ] || fail "a same-key copy ($shape): LibreSSL does not read every certificate, so this case would measure nothing"
  run "$d/$shape.pem" "$offline" "$OFFLINE"
  [ "$code" -eq 0 ] || fail "a same-key copy ($shape): expected the file fixed, exit 0, got $code"
  grep -qF -- "$(sed -n 2p "$copy")" "$d/$shape.pem" && fail "a same-key copy ($shape): the copy carrying a withdrawn root's key is still in the file"
  [ "$(bad "$d/$shape.pem")" -eq 0 ] || fail "a same-key copy ($shape): a withdrawn root is still in the file"
  [ "$(certs_in "$d/$shape.pem")" -eq $((total - 2)) ] || fail "a same-key copy ($shape): expected $((total - 2)) certificates, got $(certs_in "$d/$shape.pem")"
  grep -qF -- "$want" <<<"$out" || fail "a same-key copy ($shape): it did not say \"$want\""
  rm -f "$d"/"$shape".pem.wardlatch-*.bak
done
ok "a copy of a withdrawn root with a bit changed (same key, another fingerprint) is found by its key and removed"
# ---- r3 end case

# ---- r3 case: key-constants
# The key bytes the fix matches are the withdrawn roots' own: AAA_N is the first 48 bytes of the modulus of AAA
# Certificate Services in lib/incidents/, EMS_X the X coordinate of emSign ECC Root CA - G3's point there (the incident's
# roots, which test/incidents.test.mjs ties to its distrusted fingerprints); and the SHA-256 the script's comment gives
# for each is the SHA-256 of that root's SubjectPublicKeyInfo. (Until r4 the fix matched the base64 of the whole
# SubjectPublicKeyInfo, AAA_KEY and EMS_KEY, which missed the same key in another encoding: the r4 case samekey-enc.)
for r in aaa:AAA_N emsign:EMS_X; do
  pem=$root/lib/incidents/emudhra-2026-10-root-${r%%:*}.pem
  [ -s "$pem" ] || fail "the keys: $pem is not there"
  if [ "${r%%:*}" = aaa ]; then
    real=$(/usr/bin/openssl x509 -in "$pem" -noout -modulus | sed 's/^Modulus=//' | tr 'A-F' 'a-f'); real=${real:0:96}
  else
    real=$(/usr/bin/openssl x509 -in "$pem" -noout -pubkey | /usr/bin/openssl pkey -pubin -outform DER | xxd -p | tr -d '\n')
    # P-384, named curve, uncompressed point: the X coordinate is the 48 bytes after this header
    [ "${real:0:48}" = 3076301006072a8648ce3d020106052b8104002203620004 ] || fail "the keys: $pem is not the P-384 key this expects"
    real=${real:48:96}
  fi
  [ "${#real}" -eq 96 ] || fail "the keys: could not read 48 bytes of the key of $pem"
  inscript=$(sed -n "s/^${r#*:}='\\([0-9a-f]*\\)'\$/\\1/p" "$fix")
  [ -n "$inscript" ] || fail "the keys: ${r#*:} was not found in $fix"
  [ "$inscript" = "$real" ] || fail "the keys: ${r#*:} in the script is not the key of $pem"
  spki=$(/usr/bin/openssl x509 -in "$pem" -noout -pubkey | /usr/bin/openssl pkey -pubin -outform DER | /usr/bin/openssl dgst -sha256 | sed 's/.* //')
  grep -qE "^#   .* $spki\$" "$fix" || fail "the keys: the script's comment does not give $spki, the SHA-256 of the SubjectPublicKeyInfo of $pem"
done
ok "the keys the fix matches are the withdrawn roots' own, and the SHA-256 its comment gives for each is right"
# ---- r3 end case

# ---- r3 case: snapshot-swap
# The F1 class: the snapshot is in the invoking user's temporary folder, so a process running as that user can change
# it while the fix reads it, and put it back before the backup is compared with it. Until 31 Oct 2026 the checks and
# the cleaned file came from the snapshot alone, and a swapped certificate landed in the bundle under SAFE, exit 0
# (the third read: 4 runs of 4). The cp and grep stand-ins swap it at the copy (before its SHA-256 is taken) or at the
# first read after that, and put it back just before the backup copy. Each run must be UNKNOWN, exit 2, with the
# bundle byte for byte as it was. The variants: one ordinary certificate swapped for an attacker's root; one swapped
# for a copy of AAA Certificate Services (so the run would remove an ordinary certificate as a "copy" of it); and the
# whole snapshot swapped for the cleaned file (so a bundle holding both roots would read as already clean).
d=$work/r3/swap; mkdir -p "$d"
nth() {   # $1 = bundle, $2 = which certificate, $3 = the certificate to put in its place
  awk -v k="$2" -v t="$3" 'BEGIN { while ((getline l < t) > 0) rep = rep l "\n" }
    /^-----BEGIN CERTIFICATE-----/ { n++; if (n == k) { skip = 1 } }
    skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0 }; next }
    { print }' "$1"
}
nth "$work/original.pem" 10 "$r2/corp.pem" >"$d/evil.pem"
nth "$work/original.pem" 10 "$r2/aaa.pem" >"$d/extra-aaa.pem"
{ [ "$(certs_in "$d/evil.pem")" -eq "$total" ] && [ "$(bad "$d/evil.pem")" -eq 2 ] && grep -qF -- "$(sed -n 2p "$r2/corp.pem")" "$d/evil.pem"; } ||
  fail "the snapshot swapped: the attacker's variant was not built as described"
[ "$(bad "$d/extra-aaa.pem")" -eq 3 ] || fail "the snapshot swapped: the variant with an extra AAA was not built as described"
for how in early:evil late:evil late:extra-aaa late:P; do
  v=$d/${how#*:}.pem; [ "${how#*:}" != P ] || v=$r2/P.pem
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state" "$d/state.done"
  run "$d/cert.pem" PATH="$shims:$PATH" WL_CP="swap-${how%%:*}" WL_GREP=swap WL_SWAP_STATE="$d/state" WL_VARIANT="$v" "$offline" "$OFFLINE"
  [ -s "$d/state" ] || fail "the snapshot swapped ($how): the stand-in never saw the snapshot copy, so this case would measure nothing"
  [ "${how%%:*}" = early ] || [ -e "$d/state.done" ] || fail "the snapshot swapped ($how): the stand-in never swapped it, so this case would measure nothing"
  [ "$code" -eq 2 ] || fail "the snapshot swapped ($how): expected UNKNOWN, exit 2, got $code"
  grep -q '^UNKNOWN' <<<"$out" || fail "the snapshot swapped ($how): expected UNKNOWN"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "the snapshot swapped ($how): the bundle changed ($(certs_in "$d/cert.pem") certificates, $(bad "$d/cert.pem") withdrawn roots)"
  [ -z "$(beside "$d/cert.pem")" ] || fail "the snapshot swapped ($how): it left $(beside "$d/cert.pem") beside the bundle"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a snapshot changed by another process while the fix read it never lands, and is never called clean"
# ---- r3 end case

# ---- r3 case: changed-in-replace
# The bundle changes while the new file is being made and checked beside it -- after the backup, and after every
# comparison the fix made until 31 Oct 2026, which came before replace(); built() alone, every certificate fingerprinted
# again, took 0.6 s between that comparison and the rename. A change there (here, an administrator's root appended when
# the new file is chmod-ed) was thrown away from the bundle and was not in the backup either, under SAFE, exit 0 (the
# third read). The comparison is now made immediately before the rename: UNKNOWN, exit 2, the change kept, the backup
# the file the run read, nothing beside.
d=$work/r3/inreplace; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"; cat "$work/original.pem" "$r2/corp.pem" >"$d/expected.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CHMOD=race-new WL_CORP="$r2/corp.pem" "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a change while the new file was made: expected UNKNOWN, exit 2, got $code"
grep -q '^UNKNOWN.*changed while this ran' <<<"$out" || fail "a change while the new file was made: it did not say the file changed while it ran"
cmp -s "$d/cert.pem" "$d/expected.pem" || fail "a change while the new file was made: the change was thrown away ($(certs_in "$d/cert.pem") certificates left)"
b=$(find "$d" -maxdepth 1 -name 'cert.pem.wardlatch-*.bak')
{ [ -n "$b" ] && cmp -s "$b" "$work/original.pem"; } || fail "a change while the new file was made: the backup is not the file this run read"
[ -z "$(beside "$d/cert.pem")" ] || fail "a change while the new file was made: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a change made while the new file is built and checked stops the run at the rename, and the change is kept"
# ---- r3 end case

# ---- r3 case: sudo-refused-later
# sudo granting `sudo -v` and refusing a later call -- with `Defaults timestamp_timeout=0`, a hardening setting, every
# call asks for the password again. The run must say that sudo refused, in sudo's own words, and blame nothing else.
# Until 31 Oct 2026 a refusal at the backup's mktemp was "Check the disk has room (df -h /)" with sudo's words sent to
# /dev/null, and the copy and the write said the same (the third read). The sudo stand-in (WL_SUDO=grant) runs every
# other call as this user; the bundle is read-only to it, so the fix uses sudo, and its folder is writable, so the
# granted calls work. Calls: 1 -v, 2 the backup's mktemp, 3 its copy, 4 its link, 6 the new file's mktemp, 7 its copy,
# 8 its chmod, 9 the rename (5, removing the copy after the link, may fail without harm, so it is not one of them).
d=$work/r3/sudolater; mkdir -p "$d"
for n in 2 3 4 6 7 8 9; do
  rm -f "$d"/cert.pem "$d"/cert.pem.wardlatch-*.bak "$d/state"
  cp "$work/original.pem" "$d/cert.pem"; chmod 444 "$d/cert.pem"
  stderr_ok=1
  run "$d/cert.pem" PATH="$shims:$PATH" WL_SUDO=grant WL_SUDO_REFUSE="$n" WL_SUDO_STATE="$d/state" "$offline" "$OFFLINE"
  stderr_ok=''
  [ "$(cat "$d/state")" -ge "$n" ] || fail "sudo refused at call $n: the run made only $(cat "$d/state") sudo calls, so this case would measure nothing"
  [ "$code" -eq 2 ] || fail "sudo refused at call $n: expected UNKNOWN, exit 2, got $code"
  grep -q '^UNKNOWN' <<<"$out" || fail "sudo refused at call $n: expected UNKNOWN"
  grep -qF 'sudo: 3 incorrect password attempts' <<<"$out" || fail "sudo refused at call $n: the line did not give sudo's own words"
  grep -qi 'disk\|df -h' <<<"$out" && fail "sudo refused at call $n: it blamed the disk"
  [ ! -s "$work/stderr" ] || fail "sudo refused at call $n: sudo's words went to stderr instead of the line: $(cat "$work/stderr")"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "sudo refused at call $n: the bundle changed"
  [ -z "$(beside "$d/cert.pem")" ] || fail "sudo refused at call $n: it left $(beside "$d/cert.pem") beside the bundle"
done
chmod 644 "$d/cert.pem"
ok "sudo refusing a later call is reported in sudo's own words, and nothing is blamed on the disk"
# ---- r3 end case

# ---- r3 case: early-signal
# A signal before the script's traps were set: during uname (the first command), and while mktemp makes the snapshot
# and has not yet printed its name. Until 31 Oct 2026 the traps came after both temporary files, so such a run exited
# 143, 130 or 129 with no line and left the snapshot in TMPDIR (the third read; the window is milliseconds in a real
# run, and the stand-ins hold it open). Each must print a line, exit 2, change nothing and leave nothing behind (sigrun
# checks TMPDIR and the line).
d=$work/r3/early; mkdir -p "$d"
for how in uname:TERM uname:INT uname:HUP mktemp:INT mktemp:TERM; do
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
  sigrun_sig=${how#*:}
  if [ "${how%%:*}" = uname ]; then
    sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_UNAME=hold "$offline" "$OFFLINE"
  else
    sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MKTEMP_HOLD=1 WL_MKTEMP_STATE="$d/state" "$offline" "$OFFLINE"
  fi
  sigrun_sig=INT
  [ "$code" -eq 2 ] || fail "a signal before the traps ($how): expected exit 2, got $code"
  grep -q '^UNKNOWN  Stopped before this changed anything' <<<"$out" || fail "a signal before the traps ($how): it did not say it stopped before changing anything"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a signal before the traps ($how): the bundle changed"
  { [ -z "$(beside "$d/cert.pem")" ] && [ "$(baks "$d/cert.pem")" -eq 0 ]; } || fail "a signal before the traps ($how): it left something beside the bundle"
done
ok "a signal at the very start of a run, or while the snapshot is being made, prints a line and leaves nothing"
# ---- r3 end case

# ---- r3 case: sigquit
# Ctrl-\ sends QUIT. Until 31 Oct 2026 it was not trapped: the run ended with 131 and no line, and left what it was
# making beside the bundle (the third read). During the backup copy and just after the rename, as the INT cases do,
# a QUIT must give the same: exit 2, a true line, nothing left in TMPDIR or beside the bundle.
d=$work/r3/quit; mkdir -p "$d"
sigrun_sig=QUIT
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_CP=sig-backup "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "QUIT during the backup copy: expected exit 2, got $code"
grep -q '^UNKNOWN  Stopped' <<<"$out" || fail "QUIT during the backup copy: it did not say it was stopped"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "QUIT during the backup copy: the bundle changed"
{ [ -z "$(beside "$d/cert.pem")" ] && [ "$(baks "$d/cert.pem")" -eq 0 ]; } || fail "QUIT during the backup copy: it left $(beside "$d/cert.pem") beside the bundle"
cp "$work/original.pem" "$d/cert.pem"
sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MV=sig-forward "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "QUIT just after the rename: expected exit 2, got $code"
grep -q 'had already been replaced with the cleaned file' <<<"$out" || fail "QUIT just after the rename: it did not say the file had been replaced"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "QUIT just after the rename: the bundle is not the cleaned file"
[ -z "$(beside "$d/cert.pem")" ] || fail "QUIT just after the rename: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
sigrun_sig=INT
ok "a Ctrl-\\ (QUIT) stops the run with a true line and exit 2, and leaves nothing behind"
# ---- r3 end case

# ---- r3 case: signal-at-exit
# A signal while the cleanup at exit runs, after the verdict line was printed. Until 31 Oct 2026 it ran stopped(), which
# printed a second line under the verdict ("SAFE  Fixed ..." then "UNKNOWN  Stopped before this could re-test") and
# turned the exit code into 2 (the third read). The rm stand-in holds the cleanup's removal of the temporary files once;
# TERM goes to the script then. After a SAFE that fixed the file, a SAFE about a file already clean, and an UNKNOWN
# refusal, the run must print exactly one line starting SAFE, EXPOSED or UNKNOWN, keep its exit code, and say nothing
# about being stopped.
d=$work/r3/atexit; mkdir -p "$d"
sigrun_sig=TERM
for how in fixed:0 clean:0 empty:2; do
  case "${how%%:*}" in
    fixed) cp "$work/original.pem" "$d/cert.pem" ;;
    clean) cp "$r2/P.pem" "$d/cert.pem" ;;
    empty) : >"$d/cert.pem" ;;
  esac
  rm -f "$d/rmstate"
  sigrun "$r2/net.sh" "$d/cert.pem" PATH="$shims:$PATH" WL_RM=hold WL_RM_STATE="$d/rmstate" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=60
  [ "$code" -eq "${how#*:}" ] || fail "a signal during the cleanup at exit (${how%%:*}): expected exit ${how#*:}, got $code"
  [ "$(grep -cE '^(SAFE|EXPOSED|UNKNOWN) ' <<<"$out")" -eq 1 ] || fail "a signal during the cleanup at exit (${how%%:*}): it printed more than one verdict line"
  grep -q 'Stopped' <<<"$out" && fail "a signal during the cleanup at exit (${how%%:*}): it said it was stopped after it had finished"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
sigrun_sig=INT
ok "a signal during the cleanup at exit leaves the verdict alone: one line, its own exit code"
# ---- r3 end case

# ---- r3 case: indent-note
# An administrator's indented line inside a withdrawn root's Apple entry, between "Certificate:" and the fingerprint
# lines. Until 31 Oct 2026 any indented line there counted as part of openssl's text dump, so the note went with the
# root, under SAFE, exit 0 (the third read: F3's residual). The entry is now removed only when it is exactly what this
# Mac's openssl prints for that root; otherwise every line above the certificate stays, and only its block and the
# empty line after it go. Also checked: the unedited entry, beside it, still goes whole.
d=$work/r3/indent; mkdir -p "$d"
note='    # IT note: AAA kept for the legacy SCEP server until 2027 (ticket 4411)'
awk -v n="$note" 'NR == 2 { print; print n; next } { print }' "$r2/aaa-entry.pem" >"$d/noted-entry.pem"
grep -qxF -- "$note" "$d/noted-entry.pem" || fail "an indented note: the entry was not built with the note in it"
{ cat "$r2/emsonly.pem"; cat "$d/noted-entry.pem"; echo; } >"$d/cert.pem"
{ cat "$r2/P.pem"; awk '/^-----BEGIN CERTIFICATE-----/ { exit } { print }' "$d/noted-entry.pem"; } >"$d/expected.pem"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 0 ] || fail "an indented note: expected the bundle fixed, exit 0, got $code"
[ "$(bad "$d/cert.pem")" -eq 0 ] || fail "an indented note: a withdrawn root is still there"
grep -qxF -- "$note" "$d/cert.pem" || fail "an indented note: the administrator's note was deleted with the root"
if ! cmp -s "$d/cert.pem" "$d/expected.pem"; then
  diff "$d/expected.pem" "$d/cert.pem" | head -10 | sed 's/^/    > /'
  fail "an indented note: the file is not the bundle with only the certificate (and emSign's whole entry) removed"
fi
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "an indented line an administrator added inside a withdrawn root's entry is kept; only the certificate goes"
# ---- r3 end case

# ---- r3 case: admin-heading
# An administrator's own "=== " heading directly above Apple's text dump of a withdrawn root, in place of Apple's
# "=== .../CN=<name>" line. The heading is theirs, not the root's name, so it stays, and with it the dump under it; only
# the certificate goes. No case held this until 31 Oct 2026: with the test that the "=== " line names the root taken
# out, every other case passed while the heading and the dump went with the root, under SAFE (the third read, MJ).
d=$work/r3/heading; mkdir -p "$d"
heading='=== Added by IT on 2026-10-01: legacy SCEP root, keep until 2027'
awk -v h="$heading" 'NR == 1 { print h; next } { print }' "$r2/aaa-entry.pem" >"$d/entry.pem"
{ cat "$r2/emsonly.pem"; cat "$d/entry.pem"; echo; } >"$d/cert.pem"
{ cat "$r2/P.pem"; awk '/^-----BEGIN CERTIFICATE-----/ { exit } { print }' "$d/entry.pem"; } >"$d/expected.pem"
run "$d/cert.pem" "$offline" "$OFFLINE"
[ "$code" -eq 0 ] || fail "an administrator's heading: expected the bundle fixed, exit 0, got $code"
[ "$(bad "$d/cert.pem")" -eq 0 ] || fail "an administrator's heading: a withdrawn root is still there"
grep -qxF -- "$heading" "$d/cert.pem" || fail "an administrator's heading: the heading was deleted with the root"
if ! cmp -s "$d/cert.pem" "$d/expected.pem"; then
  diff "$d/expected.pem" "$d/cert.pem" | head -10 | sed 's/^/    > /'
  fail "an administrator's heading: the file is not the bundle with only the certificate (and emSign's whole entry) removed"
fi
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "an administrator's own heading above a withdrawn root's dump stays, with the dump; only the certificate goes"
# ---- r3 end case

# ---- r3 case: tmpdir-full
# The snapshot copy into TMPDIR failing because the folder is full. The bundle is readable, so "Can't read" is the
# wrong reason; until 31 Oct 2026 that is what the run said (the third read, on a 2 MB disk image). The cp stand-in
# writes 1000 bytes and fails with ENOSPC. UNKNOWN, exit 2, the true reason, nothing changed and nothing left behind.
d=$work/r3/tmpfull; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=full-snap "$offline" "$OFFLINE"
[ "$code" -eq 2 ] || fail "a full TMPDIR: expected UNKNOWN, exit 2, got $code"
grep -q "Can't read" <<<"$out" && fail "a full TMPDIR: it said the bundle can't be read"
grep -q "^UNKNOWN  Couldn't write a copy of $d/cert.pem into $work/tmp" <<<"$out" || fail "a full TMPDIR: it did not say the copy into the temporary folder failed"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a full TMPDIR: the bundle changed"
{ [ -z "$(beside "$d/cert.pem")" ] && [ "$(baks "$d/cert.pem")" -eq 0 ]; } || fail "a full TMPDIR: it left something beside the bundle"
ok "a temporary folder with no room is reported as that, not as a bundle that can't be read"
# ---- r3 end case

# ---- r3 case: backup-guards
# "Keeps a dated backup and never overwrites an earlier one." Two guards hold that: the dated name is checked to be free
# before anything is written, and the backup gets the name by link(2), which refuses if anything is there by then.
# No case reached either until 31 Oct 2026: with both taken out, every case passed while a run overwrote an earlier
# backup under SAFE (the third read, BKBOTH). The date stand-in pins the stamp so the name is known. First, a backup is
# already at the name: the run must stop before writing anything, saying so. Then one appears at the name while the
# backup is being copied (the cp stand-in puts it there): the link must refuse it. Either way the earlier backup is
# untouched, the bundle unchanged, and nothing is left beside it.
d=$work/r3/bak; mkdir -p "$d"
stamp=20261031-120000
for how in exists meanwhile; do
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d"/cert.pem.wardlatch-*.bak
  if [ "$how" = exists ]; then
    echo 'an earlier backup' >"$d/cert.pem.wardlatch-$stamp.bak"
    run "$d/cert.pem" PATH="$shims:$PATH" WL_DATE="$stamp" "$offline" "$OFFLINE"
    grep -q "^UNKNOWN  $d/cert.pem.wardlatch-$stamp.bak already exists. Nothing changed" <<<"$out" || fail "an earlier backup at the name: it did not stop, before writing anything, saying the name is taken"
  else
    run "$d/cert.pem" PATH="$shims:$PATH" WL_DATE="$stamp" WL_CP=take-bak-name "$offline" "$OFFLINE"
    grep -q "^UNKNOWN  Couldn't give the backup its dated name, $d/cert.pem.wardlatch-$stamp.bak" <<<"$out" || fail "a backup taking the name meanwhile: it did not say the dated name could not be given"
  fi
  [ "$code" -eq 2 ] || fail "a backup at the dated name ($how): expected UNKNOWN, exit 2, got $code"
  [ "$(cat "$d/cert.pem.wardlatch-$stamp.bak")" = 'an earlier backup' ] || fail "a backup at the dated name ($how): the earlier backup was overwritten"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a backup at the dated name ($how): the bundle changed"
  [ -z "$(beside "$d/cert.pem")" ] || fail "a backup at the dated name ($how): it left $(beside "$d/cert.pem") beside the bundle"
done
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "an earlier backup at the dated name is never overwritten, whether it was there first or arrived meanwhile"
# ---- r3 end case

# ---- r3 case: digest-from-rebuild
# The SHA-256 the new file must have is taken from the rebuild itself, not from the cleaned file in the user's
# temporary folder, which anything running as that user can change. No case held that until 31 Oct 2026: with
# `want=$(sha "$tmp")` in its place every case passed (the third read, RR-4, mutant WANT), and a change to the cleaned
# file between its writing and its digest would have been renamed into place. The awk stand-in swaps one ordinary
# certificate of the cleaned file for another root as soon as it is written. UNKNOWN, exit 2, the bundle unchanged.
d=$work/r3/digest; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
run "$d/cert.pem" PATH="$shims:$PATH" WL_AWK=tamper-tmp WL_AWK_STATE="$d/state" WL_TAMPER="$r2/corp.pem" "$offline" "$OFFLINE"
[ -e "$d/state" ] || fail "the cleaned file changed after it was written: the stand-in never changed it, so this case would measure nothing"
[ "$code" -eq 2 ] || fail "the cleaned file changed after it was written: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "the cleaned file changed after it was written: the bundle changed ($(grep -cF -- "$(sed -n 2p "$r2/corp.pem")" "$d/cert.pem") copies of the other root in it)"
[ -z "$(beside "$d/cert.pem")" ] || fail "the cleaned file changed after it was written: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "the new file's SHA-256 comes from the rebuild, so a cleaned file changed after it was written never lands"
# ---- r3 end case

# ---- r4 cases
# Added on 31 Oct 2026 after the round-3 re-reads. Like the r2 and r3 cases, each stands on the setup above alone.

# ---- r4 case: samekey-enc
# A copy of a withdrawn root that carries its key in another valid encoding: emSign ECC Root CA - G3's EC point
# compressed or hybrid, or its curve given by explicit parameters instead of by name (and both at once); AAA Certificate
# Services' RSA key labelled RSA-PSS. Each copy keeps the root's own signature bytes. LibreSSL trusts a root re-encoded
# in each of these ways (shown below on throwaway roots of the same kinds, each with a leaf it signed; and measured with
# /usr/bin/curl on 31 Oct 2026), and `openssl x509 -pubkey` prints each in its own encoding, so the round-3 comparison
# of that text with the root's missed every one: the copy stayed in the file under SAFE, exit 0. The key is now compared
# by its own bytes as openssl decodes them, so each copy must be found, removed, and named as a certificate with that
# root's key.
d=$work/r4/samekeyenc; mkdir -p "$d"
libre() { /usr/bin/openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | /usr/bin/openssl pkcs7 -print_certs 2>/dev/null | grep -c '^-----BEGIN CERTIFICATE-----' || true; }
spkihex() { /usr/bin/openssl x509 -in "$1" -noout -pubkey | /usr/bin/openssl pkey -pubin -outform DER 2>/dev/null | xxd -p | tr -d '\n'; }
derlen() { if [ "$1" -lt 128 ]; then printf '%02x' "$1"; elif [ "$1" -lt 256 ]; then printf '81%02x' "$1"; else printf '82%04x' "$1"; fi; }
derhdr() {   # $1 = hex starting at a SEQUENCE: prints the header's length in hex digits and the content's in bytes
  local b=$((0x${1:2:2}))
  if [ "$b" -lt 128 ]; then echo "4 $b"; elif [ "$b" -eq 129 ]; then echo "6 $((0x${1:4:2}))"; elif [ "$b" -eq 130 ]; then echo "8 $((0x${1:4:4}))"; else echo "0 0"; fi
}
respki() {   # $1 = certificate, $2 = SubjectPublicKeyInfo (DER hex), $3 = out: the certificate with that key, its signature kept
  local h old oh ol t th tl tbs after inner
  h=$(/usr/bin/openssl x509 -in "$1" -outform DER | xxd -p | tr -d '\n'); old=$(spkihex "$1")
  read -r oh ol <<<"$(derhdr "$h")"; t=${h:$oh}; read -r th tl <<<"$(derhdr "$t")"
  { [ "$oh" -gt 0 ] && [ "$th" -gt 0 ]; } || fail "a key in another encoding: $1 is not a certificate this can rebuild"
  tbs=${t:$th:$((tl * 2))}; after=${t:$((th + tl * 2))}
  case "$tbs" in *"$old"*"$old"*) fail "a key in another encoding: the key is in $1 twice" ;; *"$old"*) ;; *) fail "a key in another encoding: the key was not found in $1" ;; esac
  tbs=${tbs/"$old"/"$2"}
  inner="30$(derlen $(( ${#tbs} / 2 )))$tbs$after"
  printf '%s' "30$(derlen $(( ${#inner} / 2 )))$inner" | xxd -r -p | /usr/bin/openssl x509 -inform DER -out "$3" ||
    fail "a key in another encoding: openssl could not read the rebuilt $3"
}
reenc() {    # $1 = certificate, $2 = how, $3 = out
  local k bits
  case "$2" in
    compressed|hybrid) k=$(/usr/bin/openssl x509 -in "$1" -noout -pubkey | /usr/bin/openssl ec -pubin -conv_form "$2" -outform DER 2>/dev/null | xxd -p | tr -d '\n') ;;
    explicit) k=$(/usr/bin/openssl x509 -in "$1" -noout -pubkey | /usr/bin/openssl ec -pubin -param_enc explicit -outform DER 2>/dev/null | xxd -p | tr -d '\n') ;;
    explicit-compressed) k=$(/usr/bin/openssl x509 -in "$1" -noout -pubkey | /usr/bin/openssl ec -pubin -param_enc explicit -conv_form compressed -outform DER 2>/dev/null | xxd -p | tr -d '\n') ;;
    pss) k=$(spkihex "$1"); bits=${k#30820122300d06092a864886f70d0101010500}
         [ "$bits" != "$k" ] || fail "a key in another encoding: $1 is not a 2048-bit RSA key in the usual encoding"
         k=30820120300b06092a864886f70d01010a$bits ;;
  esac
  [ -n "$k" ] || fail "a key in another encoding: openssl could not re-encode the key of $1 ($2)"
  respki "$1" "$k" "$3"
}
# LibreSSL trusts each encoding: a throwaway root of the same kind, re-encoded the same way, still verifies a leaf it
# signed (for RSA-PSS, a leaf signed with PSS, which the key labelled that way is for).
{ /usr/bin/openssl ecparam -name secp384r1 -genkey -noout -out "$d/ec.key" 2>/dev/null &&
  /usr/bin/openssl req -x509 -new -key "$d/ec.key" -sha384 -days 30 -subj /CN=Throwaway-P384 -out "$d/ec.pem" 2>/dev/null &&
  /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout "$d/rsa.key" -sha256 -days 30 -subj /CN=Throwaway-RSA -out "$d/rsa.pem" 2>/dev/null &&
  /usr/bin/openssl req -newkey rsa:2048 -nodes -keyout "$d/leaf.key" -subj /CN=leaf.example -out "$d/leaf.csr" 2>/dev/null &&
  /usr/bin/openssl x509 -req -in "$d/leaf.csr" -CA "$d/ec.pem" -CAkey "$d/ec.key" -set_serial 2 -days 30 -sha384 -out "$d/ec-leaf.pem" 2>/dev/null &&
  /usr/bin/openssl x509 -req -in "$d/leaf.csr" -CA "$d/rsa.pem" -CAkey "$d/rsa.key" -set_serial 3 -days 30 -sha256 \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out "$d/rsa-leaf.pem" 2>/dev/null; } ||
  fail "a key in another encoding: openssl could not make the throwaway roots"
for how in compressed hybrid explicit explicit-compressed pss; do
  if [ "$how" = pss ]; then t=rsa; else t=ec; fi
  reenc "$d/$t.pem" "$how" "$d/$t-$how.pem"
  [ "$(/usr/bin/openssl verify -purpose sslserver -CAfile "$d/$t-$how.pem" "$d/$t-leaf.pem" 2>&1)" = "$d/$t-leaf.pem: OK" ] ||
    fail "a key in another encoding ($how): LibreSSL does not trust a root re-encoded this way, so this case would measure nothing"
done
for shape in ems:compressed ems:hybrid ems:explicit ems:explicit-compressed aaa:pss both:compressed emsplus:pss; do
  r=${shape%%:*}; how=${shape#*:}; copy=$d/$r-$how.pem
  case "$r" in aaa|emsplus) src=$r2/aaa.pem ;; *) src=$r2/ems.pem ;; esac
  reenc "$src" "$how" "$copy"
  [ "$(/usr/bin/openssl x509 -in "$copy" -noout -pubkey)" != "$(/usr/bin/openssl x509 -in "$src" -noout -pubkey)" ] ||
    fail "a key in another encoding ($shape): openssl prints the copy's key as the root's, so this case would measure nothing"
  case "$r" in
    ems) cat "$r2/P.pem" "$copy" >"$d/cert.pem"
         want='removed a certificate with the key of emSign ECC Root CA - G3 (this file did not hold the other withdrawn root, AAA Certificate Services)' ;;
    aaa) cat "$r2/P.pem" "$copy" >"$d/cert.pem"
         want='removed a certificate with the key of AAA Certificate Services (this file did not hold the other withdrawn root, emSign ECC Root CA - G3)' ;;
    both) cat "$work/original.pem" "$copy" >"$d/cert.pem"
          want='removed both withdrawn roots (AAA Certificate Services and emSign ECC Root CA - G3 and 1 other certificate with its key)' ;;
    # (r4, the round-3 mutant M14: emSign itself and only a key copy of AAA. "removed both withdrawn roots" alone would
    # say AAA itself was there.)
    emsplus) cat "$r2/emsonly.pem" "$copy" >"$d/cert.pem"
             want='removed both withdrawn roots (a certificate with the key of AAA Certificate Services and emSign ECC Root CA - G3)' ;;
  esac
  [ "$(libre "$d/cert.pem")" -eq "$(certs_in "$d/cert.pem")" ] || fail "a key in another encoding ($shape): LibreSSL does not read every certificate, so this case would measure nothing"
  run "$d/cert.pem" "$offline" "$OFFLINE"
  [ "$code" -eq 0 ] || fail "a key in another encoding ($shape): expected the file fixed, exit 0, got $code"
  cmp -s "$d/cert.pem" "$r2/P.pem" || fail "a key in another encoding ($shape): the file is not the advisory's removal ($(certs_in "$d/cert.pem") certificates): the copy carrying a withdrawn root's key is still in it"
  grep -qF -- "$want" <<<"$out" || fail "a key in another encoding ($shape): it did not say \"$want\""
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a withdrawn root's key in another encoding (EC point compressed or hybrid, explicit curve, RSA-PSS) is found and removed"
# ---- r4 end case

# ---- r4 case: root-reads
# Root never opens a path in the invoking user's temporary folder. Until r4 the fix had root copy the cleaned file there
# into a file beside the bundle (`sudo cp $tmp <new>`), which follows a symbolic link, and make that file world-readable
# before its digest was checked: a process running as the user that turned the cleaned file into a link to a root-only
# file, while the run waited for the password, got root to copy that file beside the bundle as mode 644 (round-3
# re-read 0, with a stand-in sudo). The sudo stand-in grants every call as this user and records it; the bundle is
# read-only to this user, so the fix uses sudo. First, an ordinary run: fixed, and no privileged command names a path in
# TMPDIR. Then the attack: the cleaned file becomes a link to a mode-000 secret at `sudo -v`; the secret must never reach
# a file beside the bundle, and the run must change nothing.
if [ "$(id -u)" -eq 0 ]; then
  echo "NOTE: running as root, so the fix never calls sudo and no file is unreadable to it; root-reads did not run."
  notrun="$notrun root-reads"
else
  d=$work/r4/rootreads; mkdir -p "$d"
  rm -f "$d"/cert.pem "$d/state" "$d/log"
  cp "$work/original.pem" "$d/cert.pem"; chmod 444 "$d/cert.pem"
  run "$d/cert.pem" PATH="$shims:$PATH" WL_SUDO=grant WL_SUDO_STATE="$d/state" WL_SUDO_LOG="$d/log" "$offline" "$OFFLINE"
  [ "$code" -eq 0 ] || fail "root reads: an ordinary run through sudo: expected the bundle fixed, exit 0, got $code"
  cmp -s "$d/cert.pem" "$r2/P.pem" || fail "root reads: an ordinary run through sudo: the bundle is not the advisory's removal"
  [ -s "$d/log" ] || fail "root reads: the sudo stand-in recorded no command, so this case would measure nothing"
  inuser=$(grep -F -- "$work/tmp/" "$d/log" || true)
  [ -z "$inuser" ] || fail "root reads: root was given a path in the user's temporary folder: $inuser"
  rm -f "$d"/cert.pem "$d"/cert.pem.wardlatch-*.bak "$d/state" "$d/leak"
  printf '%s\n' 'root-only secret' >"$d/secret"; chmod 000 "$d/secret"
  cp "$work/original.pem" "$d/cert.pem"; chmod 444 "$d/cert.pem"
  stderr_ok=1
  run "$d/cert.pem" PATH="$shims:$PATH" WL_SUDO=grant WL_SUDO_STATE="$d/state" WL_SUDO_SECRET="$d/secret" WL_SUDO_LEAK="$d/leak" "$offline" "$OFFLINE"
  stderr_ok=''
  chmod 600 "$d/secret"
  [ "$(cat "$d/state")" -ge 2 ] || fail "root reads: the run made only $(cat "$d/state") sudo calls, so this case would measure nothing"
  [ ! -s "$d/leak" ] || fail "root reads: a root-only file reached the bundle's folder: $(sort -u "$d/leak" | tr '\n' ' ')"
  [ "$code" -eq 2 ] || fail "root reads: the cleaned file swapped for a link: expected UNKNOWN, exit 2, got $code"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "root reads: the cleaned file swapped for a link: the bundle changed"
  [ -z "$(beside "$d/cert.pem")" ] || fail "root reads: it left $(beside "$d/cert.pem") beside the bundle"
  chmod 644 "$d/cert.pem"; rm -f "$d"/cert.pem.wardlatch-*.bak
  ok "root never opens a path in the user's temporary folder: a link put there never brings a root-only file beside the bundle"
fi
# ---- r4 end case

# ---- r4 case: hide-root
# A withdrawn root hidden from what the fix reads in the user's temporary folder. A same-user process swaps the snapshot,
# while it is read, for a copy with AAA Certificate Services' certificate replaced by another root, and puts it back
# before the cleaned file is built from it; and swaps the cleaned file, while it is checked, for one built from that
# copy, and puts it back before the backup. So the removal list names emSign alone, every check made in the temporary
# folder passes, and the cleaned file holds AAA. Until r4 the backup was checked only for each certificate on that list,
# not for being the whole list, and the one thing left to stop AAA landing was built() on the new file (the round-3
# re-read: with built() taken out, SAFE "removed emSign ECC Root CA - G3", with AAA left). The backup, which only the
# bundle's owner can change, must now read exactly as the snapshot did: the same withdrawn roots and copies, at the same
# places, and nothing else uncheckable. The run must stop there, with nothing built beside the bundle.
d=$work/r4/hide; mkdir -p "$d"
awk -v t="$r2/corp.pem" -v l="$aaa_line" 'BEGIN { while ((getline x < t) > 0) rep = rep x "\n" }
  /^-----BEGIN CERTIFICATE-----/ { held = $0; next }
  held != "" { if ($0 == l) { skip = 1; printf "%s", rep } else print held; held = "" }
  skip { if ($0 ~ /^-----END CERTIFICATE-----/) skip = 0; next }
  { print }' "$work/original.pem" >"$d/hidden.pem"
awk '/^(###|===) /{skip=0} /^=== .*\/CN=emSign ECC Root CA - G3$/{skip=1} !skip' "$d/hidden.pem" >"$d/hidden-clean.pem"
{ [ "$(bad "$d/hidden.pem")" -eq 1 ] && [ "$(certs_in "$d/hidden.pem")" -eq "$total" ] && [ "$(bad "$d/hidden-clean.pem")" -eq 0 ] &&
  [ "$(certs_in "$d/hidden-clean.pem")" -eq $((total - 1)) ]; } || fail "a hidden root: the copies were not built as described"
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d"/state* "$d"/stash*
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=swap-late WL_GREP=swap WL_SWAP_STATE="$d/state" WL_VARIANT="$d/hidden.pem" WL_AWK=restore-snap \
  WL_GREP_TMP="$d/hidden-clean.pem" WL_STASH="$d/stash" "$offline" "$OFFLINE"
{ [ -e "$d/state.done" ] && [ -e "$d/state.back" ] && [ -e "$d/stash.path" ] && [ -e "$d/stash.back" ]; } ||
  fail "a hidden root: a stand-in did not do its part ($(cd "$d" && ls state* stash* 2>/dev/null | tr '\n' ' ')), so this case would measure nothing"
[ "$code" -eq 2 ] || fail "a hidden root: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a hidden root: the bundle changed ($(certs_in "$d/cert.pem") certificates, $(bad "$d/cert.pem") withdrawn roots)"
grep -q "^UNKNOWN  The backup of $d/cert.pem doesn't bear out" <<<"$out" || fail "a hidden root: it was not stopped by the backup's check, before anything was built beside the bundle"
[ -z "$(beside "$d/cert.pem")" ] || fail "a hidden root: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a withdrawn root hidden from the reads in the temporary folder is caught by the backup's own reading, before anything is built"
# ---- r4 end case

# ---- r4 case: built-last
# built() is the check made on the very file renamed into place, beside the bundle, where only its owner can change it:
# the right number of certificates and no withdrawn root. Every other check of the cleaned file is made in the user's
# temporary folder, or on what strip() makes of the backup, so a regression in strip() that left a withdrawn root in,
# met with a same-user process feeding the temporary-folder checks a correct file, is stopped by built() alone. No case
# held it until r4: with built() a no-op every case passed (the round-3 re-read's BUILT). A copy of the script whose
# strip() keeps AAA Certificate Services stands for the regression; the grep stand-in swaps the cleaned file for the
# advisory's removal while it is checked and the date stand-in puts it back. The run must stop at built(), UNKNOWN,
# exit 2, with the bundle as it was.
d=$work/r4/builtlast; mkdir -p "$d"
sed 's/drop\[p\[1\] + 0\] = p\[2\] }/if (p[2] != "AAA") drop[p[1] + 0] = p[2] }/' "$fix" >"$d/keeps-aaa.sh"
cmp -s "$fix" "$d/keeps-aaa.sh" && fail "built() last: strip()'s removal list was not found in $fix, so this case proves nothing"
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d"/stash*
script=$d/keeps-aaa.sh
run "$d/cert.pem" PATH="$shims:$PATH" WL_GREP_TMP="$r2/P.pem" WL_STASH="$d/stash" "$offline" "$OFFLINE"
script=$fix
{ [ -e "$d/stash.path" ] && [ -e "$d/stash.back" ]; } || fail "built() last: the stand-ins did not swap the cleaned file and put it back, so this case would measure nothing"
[ "$(bad "$d/stash")" -eq 1 ] || fail "built() last: the cleaned file the copy built holds $(bad "$d/stash") withdrawn roots, not 1, so this case would measure nothing"
[ "$code" -eq 2 ] || fail "built() last: a cleaned file still holding a withdrawn root: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "built() last: the bundle changed ($(certs_in "$d/cert.pem") certificates, $(bad "$d/cert.pem") withdrawn roots)"
grep -q "^UNKNOWN  The file built beside $d/cert.pem isn't the cleaned file this checked" <<<"$out" || fail "built() last: it was not stopped by the check on the file beside the bundle"
[ -z "$(beside "$d/cert.pem")" ] || fail "built() last: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a cleaned file that still holds a withdrawn root is stopped by the check on the file beside the bundle, whatever the earlier checks read"
# ---- r4 end case

# ---- r4 case: sig-in-strip
# A signal while the cleaned file is being written. The fix writes it with `strip ... >"$tmp"`, and until r4 a signal
# then ran stopped() with its standard output still sent into $tmp: its line went into the file that clean() deletes,
# and the run ended exit 2 with no line at all (round-3 re-read 0: TERM, INT, QUIT and HUP at all four calls there).
# The awk stand-in holds strip()'s own awk; each signal must give exit 2, the line, and nothing left.
d=$work/r4/sigstrip; mkdir -p "$d"
for sig in TERM INT HUP QUIT; do
  cp "$work/original.pem" "$d/cert.pem"; rm -f "$d/state"
  sigrun_sig=$sig
  sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_AWK=hold-strip WL_AWK_STATE="$d/state" "$offline" "$OFFLINE"
  sigrun_sig=INT
  [ "$code" -eq 2 ] || fail "$sig while the cleaned file is written: expected exit 2, got $code"
  grep -q '^UNKNOWN  Stopped before this changed anything' <<<"$out" || fail "$sig while the cleaned file is written: it did not say it stopped before changing anything"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "$sig while the cleaned file is written: the bundle changed"
  { [ -z "$(beside "$d/cert.pem")" ] && [ "$(baks "$d/cert.pem")" -eq 0 ]; } || fail "$sig while the cleaned file is written: it left something beside the bundle"
done
ok "a signal while the cleaned file is written prints its line, not into the file being written"
# ---- r4 end case

# ---- r4 case: link-name
# The symbolic-link refusal prints a command to run, with the link's target in it. Until r4 the target went in raw,
# inside single quotes: a target holding a single quote broke out of them, so the printed command ran a command of the
# link maker's choosing and then the fix without WARDLATCH_CERT_FILE (round-3 re-read 0, ATTACK-WILD W1's class); and a
# target holding U+202E or U+2028 reached the terminal raw. A name with anything but plain characters is now never
# printed, in the command or in the line; a plain one still is (the r2 case symlink-advice runs that command).
d=$work/r4/linkname; mkdir -p "$d"
for how in quote bidi; do
  rm -f "$d/cert.pem"
  if [ "$how" = quote ]; then tgt="real.pem'; touch $d/PWNED; X='"; else tgt=$(printf 'real\342\200\256mep.pem\342\200\250next'); fi
  ln -s "$tgt" "$d/cert.pem"
  run "$d/cert.pem" "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "a link whose target's name is not plain ($how): expected UNKNOWN, exit 2, got $code"
  grep -q '^UNKNOWN.*is a symbolic link' <<<"$out" || fail "a link whose target's name is not plain ($how): it did not say the file is a symbolic link"
  grep -qF "touch $d/PWNED" <<<"$out" && fail "a link whose target's name is not plain ($how): the line holds the command hidden in the name"
  LC_ALL=C grep -q $'\342\200[\256\250]' <<<"$out" && fail "a link whose target's name is not plain ($how): U+202E or U+2028 reached the output raw"
  grep -qF -- "$tgt" <<<"$out" && fail "a link whose target's name is not plain ($how): the name was printed raw"
  [ -L "$d/cert.pem" ] || fail "a link whose target's name is not plain ($how): the link itself was replaced"
done
[ ! -e "$d/PWNED" ] || fail "a link whose target's name is not plain: something ran the command hidden in the name"
ok "a link whose target's name is not plain is refused without printing the name, in the command or the line"
# ---- r4 end case

# ---- r4 case: stdout-fails
# Standard output that can't be written. The verdict line was an echo under `set -e`, so a write that failed ended the
# run with echo's status, 1 -- the published table's EXPOSED -- after the file was fixed (round-3 re-read 0: a closed
# stdout, and a log file on a full volume). The line can't be read, so the run ends UNKNOWN's code, 2. Here the run's
# standard output is a pipe whose reader has gone, with SIGPIPE ignored, as a parent process can leave it: each write
# fails with EPIPE (the same failed echo as on a full volume). And a run started with standard output closed ends 2,
# before it reads or writes anything.
d=$work/r4/stdout; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"; rm -rf "$work/tmp"; mkdir "$work/tmp"
set +e
env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$d/cert.pem" "$offline" "$OFFLINE" \
  /bin/bash -c 'trap "" PIPE; exec /bin/bash "$0"' "$fix" 2>"$d/stderr" | true
code=${PIPESTATUS[0]}
set -e
grep -q 'write error' "$d/stderr" || fail "standard output that can't be written: no write failed ($(head -2 "$d/stderr")), so this case would measure nothing"
[ "$code" -eq 2 ] || fail "standard output that can't be written: expected exit 2, got $code"
[ -z "$(find "$work/tmp" -mindepth 1 -print -quit)" ] || fail "standard output that can't be written: it left temporary files behind"
rm -f "$d"/cert.pem.wardlatch-*.bak
cp "$work/original.pem" "$d/cert.pem"
code=0; env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$d/cert.pem" "$offline" "$OFFLINE" /bin/bash "$fix" >&- 2>"$d/stderr" || code=$?
[ "$code" -eq 2 ] || fail "standard output closed: expected exit 2, got $code"
{ cmp -s "$d/cert.pem" "$work/original.pem" && [ "$(baks "$d/cert.pem")" -eq 0 ]; } || fail "standard output closed: the run changed something it could not report"
ok "standard output that can't be written ends the run with 2, never the EXPOSED code"
# ---- r4 end case

# ---- r4 case: floor-swap
# The 50-certificate floor, judged from the snapshot in the user's temporary folder alone until r4: a same-user process
# that swapped the snapshot for a small bundle holding neither root made the run say "It holds neither withdrawn root,
# so this fix has nothing to remove" about a file holding both (round-3 re-read 0). Still UNKNOWN, exit 2, nothing
# changed -- but the line was untrue. What the floor says about the file is now read again from the file itself, and
# when the two readings differ the line says so instead.
d=$work/r4/floorswap; mkdir -p "$d"
awk '/^-----BEGIN CERTIFICATE-----/{k++} k <= 12 { print }' "$r2/P.pem" >"$d/small.pem"
{ [ "$(certs_in "$d/small.pem")" -eq 12 ] && [ "$(bad "$d/small.pem")" -eq 0 ]; } || fail "a swapped floor: the small bundle was not built as described"
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d"/state*
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=swap-late WL_GREP=swap WL_SWAP_STATE="$d/state" WL_VARIANT="$d/small.pem" "$offline" "$OFFLINE"
[ -e "$d/state.done" ] || fail "a swapped floor: the stand-in never swapped the snapshot, so this case would measure nothing"
[ "$code" -eq 2 ] || fail "a swapped floor: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a swapped floor: the bundle changed"
grep -q 'holds neither' <<<"$out" && fail "a swapped floor: it said a file holding both withdrawn roots holds neither"
grep -q 'fewer than the 50' <<<"$out" && fail "a swapped floor: it described the swapped copy's size as the file's"
grep -q "doesn't read the same way now" <<<"$out" || fail "a swapped floor: it did not say the file reads differently from the copy"
ok "the floor's line about the file is read from the file itself, never from a copy another process changed"
# ---- r4 end case

# ---- r4 case: every-signal
# Every signal a process can catch whose default action ends it, other than the fault signals the header names, must
# end the run with a line and exit 2. Until r4 only HUP, INT, QUIT and TERM were trapped: USR1, ALRM and XCPU (and the
# rest) ended the run with 158, 142 or 152 and no line, after the rename too (round-3 re-read 2), though the published
# contract says a signal it can catch exits 2. ALRM is what the usual timeout wrapper sends, and XCPU what a CPU limit
# sends. Each signal at the first command (the uname stand-in holds it), and USR1, ALRM and PIPE just after the rename.
d=$work/r4/everysig; mkdir -p "$d"
for sig in HUP INT QUIT TERM ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2; do
  cp "$work/original.pem" "$d/cert.pem"
  sigrun_sig=$sig
  sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_UNAME=hold WL_HOLD=1 "$offline" "$OFFLINE"
  sigrun_sig=INT
  [ "$code" -eq 2 ] || fail "$sig at the first command: expected exit 2, got $code"
  grep -q '^UNKNOWN  Stopped before this changed anything' <<<"$out" || fail "$sig at the first command: it did not say it stopped before changing anything"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "$sig at the first command: the bundle changed"
done
for sig in USR1 ALRM PIPE; do
  cp "$work/original.pem" "$d/cert.pem"
  sigrun_sig=$sig
  sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_MV=sig-forward "$offline" "$OFFLINE"
  sigrun_sig=INT
  [ "$code" -eq 2 ] || fail "$sig just after the rename: expected exit 2, got $code"
  grep -q 'had already been replaced with the cleaned file' <<<"$out" || fail "$sig just after the rename: it did not say the file had been replaced"
  cmp -s "$d/cert.pem" "$r2/P.pem" || fail "$sig just after the rename: the bundle is not the cleaned file"
  [ -z "$(beside "$d/cert.pem")" ] || fail "$sig just after the rename: it left $(beside "$d/cert.pem") beside the bundle"
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "every signal that ends a process and is not a fault ends the run with a line and exit 2, before the change and after it"
# ---- r4 end case

# ---- r4 case: locale
# The fix reads the bundle in bytes (LC_ALL=C, exported), because in a UTF-8 locale macOS's grep does not match a line
# holding a byte that is not UTF-8 at all, and a BEGIN marker after such bytes then went uncounted (round 3, NEW-1). The
# round-3 cases ran that shape with LC_ALL=en_US.UTF-8, which bash imports as exported, so `LC_ALL=C` without `export`
# still reached grep and every case passed (round-3 re-read 2's M01); in Terminal's default, LANG=en_US.UTF-8 and
# LC_ALL unset, that one word makes a hidden root read SAFE. And a pad ending in "-" before the marker: the inline
# pattern '.-----BEGIN' must count it, where '[^-]-----BEGIN' would not (M02). Each shape is first shown to hide a
# certificate LibreSSL reads.
d=$work/r4/locale; mkdir -p "$d"
libre() { /usr/bin/openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | /usr/bin/openssl pkcs7 -print_certs 2>/dev/null | grep -c '^-----BEGIN CERTIFICATE-----' || true; }
for shape in ff dash; do
  if [ "$shape" = ff ]; then p=$(printf '%*s' 253 '' | LC_ALL=C tr ' ' '\377'); else p="$(printf '%*s' 252 '' | tr ' ' '#')-"; fi
  { cat "$r2/P.pem"; printf '%s%s\n' "$p" "$(cat "$r2/aaa.pem")"; } >"$d/$shape.pem"
  cp "$d/$shape.pem" "$d/$shape.before"
  [ "$(libre "$d/$shape.pem")" -eq $(($(libre "$r2/P.pem") + 1)) ] || fail "a marker after other text ($shape): LibreSSL does not read the hidden certificate, so this case would measure nothing"
  if [ "$shape" = ff ]; then
    [ "$(env -u LC_ALL LANG=en_US.UTF-8 /usr/bin/grep -c -- '.-----BEGIN' "$d/$shape.pem" || true)" -eq 0 ] ||
      fail "a marker after other text ($shape): grep matches it in en_US.UTF-8 after all, so this case would measure nothing"
    run "$d/$shape.pem" -u LC_ALL LANG=en_US.UTF-8 "$offline" "$OFFLINE"
  else
    run "$d/$shape.pem" "$offline" "$OFFLINE"
  fi
  [ "$code" -eq 2 ] || fail "a marker after other text ($shape): expected UNKNOWN, exit 2, got $code"
  grep -q '^UNKNOWN.*BEGIN comes after other text' <<<"$out" || fail "a marker after other text ($shape): it did not say a line holds the marker after other text"
  cmp -s "$d/$shape.pem" "$d/$shape.before" || fail "a marker after other text ($shape): the bundle changed"
done
ok "a marker after bytes that aren't UTF-8 is found in Terminal's own locale, and after a pad that ends in -"
# ---- r4 end case

# ---- r4 case: exit-signals
# A signal while the cleanup at exit runs, after an UNKNOWN line: the cleanup ignores every signal the run traps, so the
# line stays the only one and the code stays 2. The r3 case signal-at-exit sends TERM alone, and with QUIT dropped from
# the cleanup's list every case passed (round-3 re-read 2's M04): a QUIT there then ran stopped() and printed a second line.
d=$work/r4/exitsig; mkdir -p "$d"
for sig in HUP INT QUIT TERM ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2; do
  : >"$d/cert.pem"; rm -f "$d/rmstate"
  sigrun_sig=$sig
  sigrun "$fix" "$d/cert.pem" PATH="$shims:$PATH" WL_RM=hold WL_HOLD=1 WL_RM_STATE="$d/rmstate" "$offline" "$OFFLINE"
  sigrun_sig=INT
  [ -e "$d/rmstate" ] || fail "$sig during the cleanup at exit: the rm stand-in never held the cleanup, so this case would measure nothing"
  [ "$code" -eq 2 ] || fail "$sig during the cleanup at exit: expected exit 2, got $code"
  [ "$(grep -cE '^(SAFE|EXPOSED|UNKNOWN) ' <<<"$out")" -eq 1 ] || fail "$sig during the cleanup at exit: it printed more than one verdict line"
  grep -q 'Stopped' <<<"$out" && fail "$sig during the cleanup at exit: it said it was stopped after it had finished"
done
ok "any signal the run traps, arriving while the cleanup at exit runs, leaves the one line and the code as they were"
# ---- r4 end case

# ---- r4 case: changed-in-built
# The bundle changes while built() checks the new file beside it, which takes as long as fingerprinting every certificate.
# The comparison with the bundle must come after built() and immediately before the rename: the r3 case changed-in-replace
# makes its change at the chmod, before built(), so with the comparison moved above built() it still passed, and a
# change made during built() was lost under SAFE (round-3 re-read 2's M05). Here the grep stand-in appends an
# administrator's root when built() first reads the new file.
d=$work/r4/inbuilt; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"; cat "$work/original.pem" "$r2/corp.pem" >"$d/expected.pem"; rm -f "$d/state"
run "$d/cert.pem" PATH="$shims:$PATH" WL_GREP_NEW=race WL_GREP_NEW_STATE="$d/state" WL_CORP="$r2/corp.pem" "$offline" "$OFFLINE"
[ -e "$d/state" ] || fail "a change while built() checks the new file: the stand-in never made it, so this case would measure nothing"
[ "$code" -eq 2 ] || fail "a change while built() checks the new file: expected UNKNOWN, exit 2, got $code"
grep -q '^UNKNOWN.*changed while this ran' <<<"$out" || fail "a change while built() checks the new file: it did not say the file changed while it ran"
cmp -s "$d/cert.pem" "$d/expected.pem" || fail "a change while built() checks the new file: the change was thrown away ($(certs_in "$d/cert.pem") certificates left)"
[ -z "$(beside "$d/cert.pem")" ] || fail "a change while built() checks the new file: it left $(beside "$d/cert.pem") beside the bundle"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a change made while the new file is checked is caught at the rename, and kept"
# ---- r4 end case

# ---- r4 case: clean-reads-file
# A bundle already clean: what it says is read from the bundle itself, the network through it too (--cacert the bundle,
# not the copy in the temporary folder, which another process can change). With the control and the re-test sent
# through the copy instead, every case passed (round-3 re-read 2's M06). The curl stub answers 77 to any call whose
# --cacert is not the bundle.
d=$work/r4/cleanfile; mkdir -p "$d"
cp "$r2/P.pem" "$d/cert.pem"
script=$r2/net.sh
run "$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_ONLY_FILE=1 STUB_CONTROL=0 STUB_TEST=60
script=$fix
[ "$code" -eq 0 ] || fail "already clean, read through the bundle: expected SAFE, exit 0, got $code"
grep -q '^SAFE.*already refuses the compromised keys' <<<"$out" || fail "already clean, read through the bundle: the control or the re-test did not go through the bundle itself"
cmp -s "$d/cert.pem" "$r2/P.pem" || fail "already clean, read through the bundle: the bundle changed"
ok "a bundle found clean is re-tested through itself, not through the copy in the temporary folder"
# ---- r4 end case

# ---- r4 case: disk-advice
# "Check the disk has room (df -h /)" is printed when the failing command's own words are about a full disk, and only
# then. The r3 case sudo-refused-later holds the "only then"; nothing held the first half, and with room() emptied every
# case passed (round-3 re-read 2's M07). The tee stand-in fails the new file's copy part-way in tee's own words: no
# space left. And, failing with no words at all, no advice about the disk.
d=$work/r4/disk; mkdir -p "$d"
for how in full-new partial-new; do
  cp "$work/original.pem" "$d/cert.pem"
  run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=$how "$offline" "$OFFLINE"
  [ "$code" -eq 2 ] || fail "a write that fails ($how): expected UNKNOWN, exit 2, got $code"
  cmp -s "$d/cert.pem" "$work/original.pem" || fail "a write that fails ($how): the bundle changed"
  if [ "$how" = full-new ]; then
    grep -q 'No space left on device' <<<"$out" || fail "a full disk: the line did not give the command's own words"
    grep -q 'Check the disk has room (df -h /)' <<<"$out" || fail "a full disk: it gave no advice about the disk"
  else
    grep -q 'Check the disk' <<<"$out" && fail "a write that failed without a word about the disk: it advised checking the disk"
  fi
  rm -f "$d"/cert.pem.wardlatch-*.bak
done
ok "a full disk gets the advice about disk space, and a failure that says nothing about the disk does not"
# ---- r4 end case

# ---- r4 case: reswap-after-link
# The backup bears out what was read only if it is compared as itself: checkbackup() cleans the BACKUP and compares the
# digest. With the snapshot cleaned there instead, every case passed (round-3 re-read 2's M15), because the r3 case
# snapshot-swap swaps the snapshot once. Here it is swapped while it is read (one ordinary certificate for an attacker's
# root), put back for the backup copy, and swapped again just after the backup gets its name (the link stand-in).
d=$work/r4/reswap; mkdir -p "$d"
awk -v t="$r2/corp.pem" 'BEGIN { while ((getline x < t) > 0) rep = rep x "\n" }
  /^-----BEGIN CERTIFICATE-----/ { n++; if (n == 10) skip = 1 }
  skip { if ($0 ~ /^-----END CERTIFICATE-----/) { printf "%s", rep; skip = 0 }; next }
  { print }' "$work/original.pem" >"$d/evil.pem"
{ [ "$(certs_in "$d/evil.pem")" -eq "$total" ] && grep -qF -- "$(sed -n 2p "$r2/corp.pem")" "$d/evil.pem"; } || fail "a second swap: the attacker's copy was not built as described"
cp "$work/original.pem" "$d/cert.pem"; rm -f "$d"/state*
run "$d/cert.pem" PATH="$shims:$PATH" WL_CP=swap-late WL_GREP=swap WL_LINK=reswap WL_SWAP_STATE="$d/state" WL_VARIANT="$d/evil.pem" "$offline" "$OFFLINE"
[ -e "$d/state.done" ] || fail "a second swap: the stand-in never swapped the snapshot, so this case would measure nothing"
[ "$code" -eq 2 ] || fail "a second swap: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a second swap: the bundle changed ($(grep -cF -- "$(sed -n 2p "$r2/corp.pem")" "$d/cert.pem") copies of the attacker's root in it)"
rm -f "$d"/cert.pem.wardlatch-*.bak
ok "a snapshot swapped again after the backup is named still never lands: the backup itself is what is cleaned and compared"
# ---- r4 end case

# ---- r4 case: other-runs-files
# The cleanup removes this run's own temporary files and no one else's: each name carries the run's process id, and
# strays() looks only for that. With strays() matching every wardlatch.* in TMPDIR every case passed (round-3 re-read 2's
# M17), and a run would delete a concurrent run's snapshot. A file named as another run's is put in TMPDIR first.
d=$work/r4/others; mkdir -p "$d"
: >"$d/cert.pem"; rm -rf "$work/tmp"; mkdir "$work/tmp"; : >"$work/tmp/wardlatch.1.AbCdEf"
code=0; out=$(env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$d/cert.pem" "$offline" "$OFFLINE" bash "$fix" 2>"$d/stderr") || code=$?
[ "$code" -eq 2 ] || fail "another run's file in TMPDIR: expected UNKNOWN, exit 2, got $code"
[ -e "$work/tmp/wardlatch.1.AbCdEf" ] || fail "another run's file in TMPDIR: this run's cleanup deleted it"
[ "$(find "$work/tmp" -mindepth 1 | wc -l | tr -d ' ')" -eq 1 ] || fail "another run's file in TMPDIR: this run left its own files behind"
rm -rf "$work/tmp"; mkdir "$work/tmp"
ok "the cleanup removes this run's own temporary files and leaves another run's alone"
# ---- r4 end case

# ---- r4 case: settled
# Once the last reading is in, the run ignores the signals it traps while it prints its verdict (settled()). With
# settled() emptied, every case passed (round-3 re-read 2's M18, judged out of reach of a stand-in, since only builtins
# run there). The verdict's own write can be held: standard output is a FIFO whose buffer is already full, so the echo
# waits until it is read, and TERM goes to the run while it waits (the curl stub marks the last reading). The run must
# still print its one verdict and keep its code, 0.
d=$work/r4/settled; mkdir -p "$d"
cp "$r2/P.pem" "$d/cert.pem"; rm -f "$d/fifo" "$r2/mark"; mkfifo "$d/fifo"; rm -rf "$work/tmp"; mkdir "$work/tmp"
exec 7<>"$d/fifo"
head -c 70000 /dev/zero >&7 &
filler=$!
${reset[@]+"${reset[@]}"} env TMPDIR="$work/tmp" WARDLATCH_CERT_FILE="$d/cert.pem" WARDLATCH_CURL="$r2/curl" STUB_CONTROL=0 STUB_TEST=60 \
  STUB_MARK_TEST=1 WL_MARK="$r2/mark" bash "$r2/net.sh" >"$d/fifo" 2>"$d/stderr" &
pid=$!
for i in $(seq 1 300); do [ -e "$r2/mark" ] && break; /bin/sleep 0.1; done
if [ ! -e "$r2/mark" ]; then kill -KILL "$pid" "$filler" 2>/dev/null || true; exec 7>&-; fail "a signal while the verdict is written: the run never reached its last reading"; fi
/bin/sleep 1
kill -TERM "$pid" 2>/dev/null || true
exec 8<"$d/fifo"; exec 7>&-
cat <&8 >"$d/drained" &
drain=$!
exec 8<&-
code=0; wait "$pid" || code=$?
wait "$filler" || true; wait "$drain" || true
out=$(LC_ALL=C tr -d '\000' <"$d/drained")
printf '%s\n' "$out" | sed 's/^/    | /'
[ "$code" -eq 0 ] || fail "a signal while the verdict is written: expected SAFE's exit 0, got $code"
[ "$(grep -cE '^(SAFE|EXPOSED|UNKNOWN) ' <<<"$out")" -eq 1 ] || fail "a signal while the verdict is written: expected one verdict line"
grep -q '^SAFE.*already refuses the compromised keys' <<<"$out" || fail "a signal while the verdict is written: the verdict is not the one the readings gave"
[ -z "$(find "$work/tmp" -mindepth 1 -print -quit)" ] || fail "a signal while the verdict is written: it left temporary files behind"
ok "a signal while the verdict is being written leaves the verdict and its code alone"
# ---- r4 end case

# ---- r4 case: key-undecoded
# A certificate whose fingerprint openssl prints, but not its key decoded ("pub" or "Modulus" and the key's bytes), can't
# be compared with the withdrawn roots' keys, so it is not counted, and the completeness gate makes the run UNKNOWN. The
# openssl stand-in prints only the right fingerprint line for one ordinary certificate, as an openssl that could not
# decode its key and said nothing would.
d=$work/r4/undecoded; mkdir -p "$d"
cp "$work/original.pem" "$d/cert.pem"
fp=$(/usr/bin/openssl x509 -in "$r2/other.pem" -noout -fingerprint -sha256)
case "$fp" in 'SHA256 Fingerprint='??:*) ;; *) fail "a key not decoded: openssl gave no fingerprint for the ordinary certificate" ;; esac
script=$r2/ossl.sh
run "$d/cert.pem" WARDLATCH_OPENSSL="$r2/openssl" STUB_MATCH="$other_line" STUB_OUT="$fp" "$offline" "$OFFLINE"
script=$fix
[ "$code" -eq 2 ] || fail "a key not decoded: expected UNKNOWN, exit 2, got $code"
cmp -s "$d/cert.pem" "$work/original.pem" || fail "a key not decoded: the bundle changed"
[ "$(baks "$d/cert.pem")" -eq 0 ] || fail "a key not decoded: it wrote a backup"
ok "a certificate whose key openssl does not decode is not counted, so the run is UNKNOWN and nothing changes"
# ---- r4 end case

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
  # Not run, and named as not run. Until 31 Oct 2026 this branch counted the case as run ("counted, so the total
  # below still means every case was reached"), so a run as root printed "N cases ran" with one in the N that had
  # not run, the silence this count exists to catch (the third read, M7).
  chmod 644 "$work/unreadable.pem"
  echo "NOTE: this run can read a file of mode 000 (as root can), so no file can be made unreadable to it; unreadable did not run."
  notrun="$notrun unreadable"
fi

# The count, printed and checked. Showing it is the point: a case that silently stopped running is what made this
# suite green on a bundle it could prove nothing about.
echo "$cases cases ran against $source ($total certificates, $found of the two roots)"
skipped=$(echo "$notrun" | wc -w | tr -d ' ')
[ "$skipped" -eq 0 ] || echo "NOT RUN on this machine ($skipped):$notrun -- each has a NOTE above saying why."
[ $((cases + skipped)) -eq "$expect_cases" ] || fail "$cases cases ran and $skipped could not, expected $expect_cases. If you added or removed a case, set expect_cases; otherwise a case stopped running."
[ "$cases" -eq "$oks" ] || fail "$cases cases are counted as run but $oks said ok: a case was counted without running"
