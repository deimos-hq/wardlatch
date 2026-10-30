#!/bin/bash
# Wardlatch Mac fix · a free tool from Deimos AI LLC · Apache-2.0 · https://www.deimoscore.com/wardlatch/#mac
#
# Removes the two roots tied to the compromised eMudhra keys (AAA Certificate Services, emSign ECC Root CA - G3) from
# /etc/ssl/cert.pem, the file macOS's built-in curl, git, python3 and openssl read. No macOS release has fixed it yet,
# and a macOS update puts Apple's original file back (26.7.2 did): run this again after every update.
# The removal is the advisory's (emudhra.we-have-a-problem.com); this script adds the safety around it:
#   - finds the two roots by their SHA-256 fingerprints, not by the name lines some copies of the file don't have,
#     and refuses a file it can't fully check (a certificate it can't read, or a block that isn't a plain certificate);
#   - refuses a $FILE that is a symbolic link, because replacing it would replace the link and leave the file the
#     Mac actually reads untouched and still trusting the compromised keys;
#   - works on a snapshot of the file and refuses to replace it if it changed meanwhile;
#   - changes nothing if the file is already clean;
#   - keeps a dated backup, never overwrites an earlier one, and compares that backup with the file it came from
#     before replacing anything, because the Undo line it prints names that backup;
#   - writes a new file and checks it (every other certificate still there, only the two removed) before replacing;
#   - replaces the file by renaming the new one over it, in one step, so an interruption leaves either the old file
#     or the new one and never half of either, and removes its temporary files on a Ctrl-C or a shutdown too;
#   - keeps the file readable by everyone, as macOS ships it;
#   - checks that what landed in the file is the file it built, and puts the original back if it isn't -- the one
#     reason it ever puts the original back, because the original is the file that trusts the compromised keys;
#   - reads a control -- an ordinary website, through this same file -- both before and after the change, so that
#     "this network answers nothing" and "this change broke certificate validation on this Mac" are two readings
#     and not one, and re-tests against the advisory's test site only when the control loads; no network result
#     undoes the fix.
# Safe to run twice. Run it in Terminal (it asks for your Mac's password) or as root from Jamf, Kandji or Intune.
# Copy it from the Wardlatch page in Safari. Don't fetch it with the Mac's own curl: that curl is what's exposed.
set -euo pipefail

FILE="${WARDLATCH_CERT_FILE:-/etc/ssl/cert.pem}"   # the override exists for testing on a copy
TEST_URL="https://dv-g3b-emudhra.we-have-a-problem.com/"
# The control host for every online verdict: an ordinary website on no compromised chain. Apple's, the same host the
# one-line test on the page uses, so the two tests answer about the same network.
CONTROL_URL="https://www.apple.com/"
# SHA-256 fingerprints: AAA Certificate Services, emSign ECC Root CA - G3
ROOTS='D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4
86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B'

[ "$(uname -s)" = Darwin ] || { echo "This fix is for macOS. On Linux, update the ca-certificates package."; exit 2; }
# Before anything else, and before the -f test, which is true for a symbolic link to a regular file: this fix
# replaces the file it is given, so on a link it would replace the link and leave the bundle the Mac actually
# reads exactly as it was. The one-line fix on the page has refused a link since CL-42; this script had no test.
[ ! -L "$FILE" ] || { echo "UNKNOWN  $FILE is a symbolic link. Replacing it would replace the link and leave the file your Mac"; echo "         actually reads as it is. Nothing changed. Run this against that file instead (readlink $FILE)."; exit 2; }
[ -f "$FILE" ] || { echo "UNKNOWN  $FILE not found. Nothing changed."; exit 2; }
SUDO=sudo; if [ "$(id -u)" -eq 0 ] || { [ -w "$FILE" ] && [ -w "$(dirname "$FILE")" ]; }; then SUDO=; fi

# 0 = trusts the compromised keys, 60 = refuses them, anything else = the test site didn't answer
# (-q: ignore ~/.curlrc, whose settings could change the answer)
trust() { local r=0; /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$TEST_URL" || r=$?; echo "$r"; }
# The control, read before any verdict is taken from trust(). 0 = an ordinary website loaded through this same file,
# so the network answers and the file still validates ordinary certificates; anything else and there is no online
# verdict to be had here -- without this, "the test site refused" and "nothing on this network answered" are the
# same reading, and the Mac that most needs this fix is the one whose network is under someone else's control.
control() { local r=0; /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$CONTROL_URL" || r=$?; echo "$r"; }
certs() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }
# Prints the position (1, 2, ...) of each certificate in the file whose fingerprint is one of ROOTS, one per line.
# Fails if any certificate can't be read, so a file we can't fully check is never called clean.
# It runs in $( ), so its EXIT trap removes the temporary folder however it ends. The trap names the folder itself,
# because it runs after the function's locals are gone.
roots() {
  local d c fp
  d=$(mktemp -d -t wardlatch) || return 1
  # shellcheck disable=SC2064
  trap "rm -rf '$d'" EXIT
  awk -v d="$d" '/-----BEGIN CERTIFICATE-----/{k++; f=sprintf("%s/%05d.pem", d, k)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$1" || return 1
  [ "$(find "$d" -name '*.pem' | wc -l | tr -d ' ')" -eq "$(certs "$1")" ] || return 1
  for c in "$d"/*.pem; do
    fp=$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null) || return 1
    if grep -qxF "${fp#*=}" <<<"$ROOTS"; then c=${c##*/}; c=${c%.pem}; echo $((10#$c)); fi
  done
}
# Writes $1 without the certificates listed in $2. A certificate's block starts at its "=== " name line when it has
# one (the advisory's removal, byte for byte) and at its BEGIN line when it doesn't; it runs to the next block.
strip() {
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
}

# Everything below reads this snapshot, so the checks and the change are about the same bytes. $new is the file
# beside $FILE that the replacement is built in; it is empty until there is one.
# HUP, INT and TERM as well as EXIT, which is what the one-line fix on the page traps. An interrupt has to STOP
# this script, and on EXIT alone it did not: measured on 29 Oct 2026 under macOS's /bin/bash 3.2.57, a SIGINT
# arriving while bash waits on a plain foreground command is swallowed, and bash carries on to the next line with
# `set -euo pipefail` in force. Interrupted just before the write, the script went on to replace the file and
# printed SAFE, exit 0, about a run that had been cancelled. (bash does stop if the signal lands inside a command
# substitution, so the old shape failed only some of the time, which is worse.)
new=
clean() { rm -f "$snap" "$tmp"; [ -z "$new" ] || $SUDO rm -f "$new"; }
snap=$(mktemp -t wardlatch); tmp=$(mktemp -t wardlatch)
trap clean EXIT
trap 'clean; exit 130' HUP INT TERM
cp "$FILE" "$snap" 2>/dev/null || { echo "UNKNOWN  Can't read $FILE. Nothing changed."; exit 2; }

if [ "$(certs "$snap")" -lt 50 ]; then
  echo "UNKNOWN  $FILE holds only $(certs "$snap") certificates, so it looks damaged. Nothing changed."
  echo "         Put a backup back (ls $FILE*.bak; sudo cp -p <backup> $FILE), then run this again."
  exit 2
fi
# curl also trusts other PEM blocks (BEGIN TRUSTED CERTIFICATE, BEGIN X509 CERTIFICATE), which this fix doesn't read.
if [ "$(grep -c -- '-----BEGIN ' "$snap" || true)" -ne "$(grep -c -- '-----BEGIN CERTIFICATE-----' "$snap" || true)" ]; then
  echo "UNKNOWN  $FILE holds blocks that aren't plain certificates (such as BEGIN TRUSTED CERTIFICATE), which curl also"
  echo "         trusts and this fix can't check. Nothing changed. Run npx wardlatch@latest to test the Mac's tools."
  exit 2
fi
list=$(roots "$snap") || { echo "UNKNOWN  A certificate in $FILE couldn't be read, so it wasn't checked. Nothing changed."; exit 2; }
found=$(grep -c . <<<"$list" || true)
if [ "$found" -eq 0 ]; then
  c=$(control "$snap")
  if [ "$c" -ne 0 ]; then
    echo "SAFE     $FILE no longer holds the two roots. Nothing changed."
    echo "         (An ordinary website didn't load either (curl $c), so nothing was re-tested online.)"
  else
    r=$(trust "$snap")
    case "$r" in
      60) echo "SAFE     $FILE already refuses the compromised keys. Nothing changed." ;;
      0)  echo "EXPOSED  $FILE holds neither root but still trusts the test site. Nothing changed; please report this."; exit 1 ;;
      *)  echo "SAFE     $FILE no longer holds the two roots. Nothing changed. (An ordinary website loaded but the test site"
          echo "         didn't answer (curl $r), so this wasn't re-tested online.)" ;;
    esac
  fi
  exit 0
fi

# How many of the two withdrawn roots this bundle actually held, in English. Apple added emSign ECC Root CA - G3
# after Mojave, so every Mac of that era holds ONE of the two: the published page says the fix "removes the two
# roots", and on those machines it removes one. Saying which, and that the other was already absent, is the
# difference between a reader trusting the result and wondering whether it half-worked.
# It does NOT name which root was missing. roots() returns certificate INDEX numbers, not fingerprints, so
# naming it would mean a second pass over every certificate -- more work and more code in a script that edits
# the file every TLS client on the Mac reads. The count and the fact that the other was already absent is what
# a reader needs; which one it was is on the page.
# It takes the count and nothing else. Every call site used to pass $list after it, which this never read.
removed_phrase() {
  if [ "$1" -eq 1 ]; then
    echo "removed 1 of the 2 withdrawn roots; the other was already absent from this Mac"
  else
    echo "removed both withdrawn roots"
  fi
}

before=$(certs "$snap")
strip "$snap" "$(tr '\n' ' ' <<<"$list")" > "$tmp"
after=$(certs "$tmp")
left=$(roots "$tmp") || left=unreadable
if [ -n "$left" ] || [ "$after" -ne $((before - found)) ] || [ "$after" -lt 50 ]; then
  echo "UNKNOWN  The cleaned file didn't come out as expected ($before certificates before, $after after). Nothing changed."
  exit 2
fi

# The control, read BEFORE anything is written, through the file as it is. Without this baseline, the control read
# after the write answers two questions at once -- "does this network answer anything?" and "did the change I just
# made break certificate validation on this Mac?" -- and the script printed SAFE for both, exit 0. That is the same
# two-readings-collapsed-into-one error the control was added to remove, one step further down the script.
c0=$(control "$snap")

backup="$FILE.wardlatch-$(date +%Y%m%d-%H%M%S).bak"
[ ! -e "$backup" ] || { echo "UNKNOWN  $backup already exists. Nothing changed; run again in a second."; exit 2; }
cmp -s "$FILE" "$snap" || { echo "UNKNOWN  $FILE changed while this ran. Nothing changed; run it again."; exit 2; }
$SUDO cp -p "$FILE" "$backup"
# A backup nobody checked makes the Undo line below a promise this script can't keep: it names that file as the way
# back, and the content-mismatch restore further down uses it as the only file here that has been checked. The
# one-line fix on the page has compared the two since CL-42, and CL-43 was already a correction about this
# instruction; the download wrote the backup and trusted it. Nothing is replaced until the backup is the file it
# came from.
cmp -s "$FILE" "$backup" || {
  echo "UNKNOWN  The backup isn't the same file as $FILE, so it couldn't be used to undo this and nothing was"
  echo "         replaced. Don't restore from it. Check the disk has room (df -h /), delete that file and run"
  echo "         this again.  Bad backup: $backup"
  exit 2
}
# The replacement is built in a file beside $FILE and renamed over it, so $FILE is never a half-written bundle: a
# rename within one directory is one step the kernel either did or didn't do. Copying into $FILE in place truncated
# it first, so a Ctrl-C, a sudo timeout or a power cut during that copy left every built-in TLS client on the Mac
# -- curl, git, python3, openssl -- reading a stump of a certificate file, with the check below never reached,
# until somebody ran this again. The file is made beside $FILE, not in $TMPDIR, because a rename only works within
# one filesystem; it is made with the same $SUDO as the write, so it belongs to whoever owns $FILE.
new=$($SUDO mktemp "$(dirname "$FILE")/.wardlatch-new.XXXXXX") || { echo "UNKNOWN  Can't make a temporary file beside $FILE. Nothing changed."; exit 2; }
$SUDO cp "$tmp" "$new"
$SUDO chmod 644 "$new"
$SUDO mv "$new" "$FILE"
new=   # renamed into place, so there is nothing beside $FILE left to remove

# The only path here that puts the original back, and the only kind of reason there may be for one: the bytes now in
# $FILE are not the bytes this script built and checked, so what every TLS client on this Mac reads is a file nobody
# has checked, and the backup is the only file here that has been. It compares two local files and reads nothing
# else; no probe result reaches it. A revert on a network reading would mean the one Mac that can never be fixed is
# the one already under attack, because putting the original back puts both withdrawn roots back.
if ! cmp -s "$tmp" "$FILE"; then
  # wardlatch:revert-reason=content-mismatch
  $SUDO cp -p "$backup" "$FILE"
  echo "EXPOSED  What was written to $FILE isn't the file this built and checked, so the original was put back and this"
  echo "         Mac still trusts the compromised keys. Nothing else was changed. Run it again; please report this."
  echo "         Backup: $backup"
  exit 1
fi

# Three readings, not two, because there is now a baseline to compare with.
c=$(control "$FILE")
if [ "$c" -eq 0 ]; then
  # The control loads through the new file: this network answers, and the new file still validates ordinary
  # certificates. So the test host's answer is about the test host, and there is a verdict to be had.
  r=$(trust "$FILE")
  case "$r" in
    60) echo "SAFE     Fixed. $FILE now refuses the compromised keys: $(removed_phrase "$found"), kept $after." ;;
    0)  echo "EXPOSED  Fixed in the file ($(removed_phrase "$found"), kept $after), but the advisory's test site is"
        echo "         still trusted. Two ordinary things look exactly like this, and both are likelier than"
        echo "         anything stranger. A TLS-inspecting proxy's own root may have been added to this file (or to"
        echo "         whichever file your tools read): the proxy then signs everything, and that site loads"
        echo "         whatever this file holds. Or the test site may have re-issued its certificate from an"
        echo "         ordinary CA, in which case it now loads for everyone and tests nothing. Rule those two out"
        echo "         before you go looking for something else on this Mac that trusts the compromised keys. The"
        echo "         fix was kept either way: putting the original back would put both withdrawn roots back."
        echo "         Please report this."
        echo "         Backup: $backup"
        echo "         Undo:   sudo cp -p '$backup' '$FILE'"
        exit 1 ;;
    *)  echo "SAFE     Fixed in the file: $(removed_phrase "$found"), kept $after. (The test site didn't answer"
        echo "         (curl $r), though an ordinary website loaded, so this wasn't re-tested online.)" ;;
  esac
elif [ "$c0" -ne 0 ]; then
  # Nothing loaded before the change either, so this reading is about the network and not about the file. Report,
  # keep the fix, claim nothing online.
  echo "SAFE     Fixed in the file: $(removed_phrase "$found"), kept $after."
  echo "         (An ordinary website didn't load before this change (curl $c0) or after it (curl $c), so nothing"
  echo "         was re-tested online.)"
else
  # The one reading here that is about the change and not about the network: an ordinary website loaded through the
  # file as it was and does not load through the file this wrote. Those two files differ by exactly the two
  # withdrawn roots, so either that site's certificate chain needs one of them, or something on this network
  # answered the two requests differently -- and that second reading is what an attack on this Mac looks like.
  # Both say the same thing about what to do, which is why there is no revert here and no revert-reason for one:
  # eMudhra's private keys are computable from certificates eMudhra published, so putting one of those roots back
  # to make a page load is not a repair, and on the second reading it would hand both withdrawn roots to a Mac
  # already under attack -- the door this script closed on 29 Oct 2026, which a before/after revert would reopen
  # from the side. UNKNOWN and exit 2, because this is a thing to look at, not an all-clear.
  echo "UNKNOWN  Fixed in the file ($(removed_phrase "$found"), kept $after), but an ordinary website that"
  echo "         loaded through the old file (curl $c0) doesn't load through the new one (curl $c). Those two files"
  echo "         differ only by the two withdrawn roots, so either that site's certificate is issued under AAA"
  echo "         Certificate Services, or something on this network is presenting one that is -- and the second is"
  echo "         what an attack on this Mac would look like. The fix was kept either way: those private keys can be"
  echo "         computed from published certificates, so trusting that root again to make a page load would not be"
  echo "         a repair. Decide it yourself from the two lines below. Please report this."
  echo "         Backup: $backup"
  echo "         Undo:   sudo cp -p '$backup' '$FILE'"
  exit 2
fi
echo "         Backup: $backup"
echo "         Undo:   sudo cp -p '$backup' '$FILE'"
echo "         This covers the built-in curl, git, python3 and openssl: the four we measured. Apple's pip3 keeps its"
echo "         own copy, and we have not measured the built-in perl or ruby. The page has both."
echo "         For everything else: npx wardlatch@latest"
echo "         A macOS update puts Apple's original file back: run this again after every update."
