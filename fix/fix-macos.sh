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
#   - refuses a bundle too small to be a trust store, and never tells you to restore a backup: the only backup it
#     could name is the one it writes, which holds the withdrawn roots, so on a small bundle holding neither root it
#     reports what it found and advises nothing;
#   - keeps a dated backup, never overwrites an earlier one, and compares that backup with the file it came from
#     before replacing anything, because the Undo line it prints names that backup;
#   - writes a new file and checks it (every other certificate still there, only the two removed) before replacing;
#   - makes every change to the file by renaming a finished file over it, in one step, so an interruption leaves
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

FILE="${WARDLATCH_CERT_FILE:-/etc/ssl/cert.pem}"   # the override exists for testing on a copy, and for a linked bundle
TEST_URL="https://dv-g3b-emudhra.we-have-a-problem.com/"
# The control host for every online verdict: an ordinary website on no compromised chain. Apple's, the same host the
# one-line test on the page uses, so the two tests answer about the same network.
CONTROL_URL="https://www.apple.com/"
# SHA-256 fingerprints, and the names the two roots go by
AAA='D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4'
EMS='86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B'
AAA_NAME='AAA Certificate Services'
EMS_NAME='emSign ECC Root CA - G3'

[ "$(uname -s)" = Darwin ] || { echo "This fix is for macOS. On Linux, update the ca-certificates package."; exit 2; }
# Before anything else, and before the -f test, which is true for a symbolic link to a regular file. This fix replaces
# the file it is given by renaming a new file over it, and a rename over a link replaces the LINK: $FILE would become
# a file of this script's own, stop following whatever the link points to (an administrator set that link up for a
# reason), and the file it points to would be left exactly as it was. Until 31 Oct 2026 the refusal said the Mac
# would go on reading the old bundle, which is not what happens, and told the reader to run this "against that file"
# without saying how. The way is WARDLATCH_CERT_FILE, so the refusal now prints the command, with the file in it.
linked() {
  local to me
  to=$(readlink "$FILE" 2>/dev/null) || to=
  case "$to" in /*|'') ;; *) to="$(dirname "$FILE")/$to" ;; esac
  case "$0" in *.sh) me=$0 ;; *) me='<this script>' ;; esac
  echo "UNKNOWN  $FILE is a symbolic link${to:+ to $to}. Nothing changed. Replacing it would replace the link with a"
  echo "         file of this run's own: $FILE would stop following the file it points to, and that file would be left"
  echo "         as it is. To fix the file it points to, run this again with that file named:"
  echo "         WARDLATCH_CERT_FILE='${to:-<the file the link points to>}' bash '$me'"
  exit 2
}
[ ! -L "$FILE" ] || linked
[ -f "$FILE" ] || { echo "UNKNOWN  $FILE not found. Nothing changed."; exit 2; }
SUDO=sudo; if [ "$(id -u)" -eq 0 ] || { [ -w "$FILE" ] && [ -w "$(dirname "$FILE")" ]; }; then SUDO=; fi
DIR=$(dirname "$FILE")

# 0 = trusts the compromised keys, 60 = refuses them, anything else = the test site didn't answer
# (-q: ignore ~/.curlrc, whose settings could change the answer)
trust() { local r=0; /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$TEST_URL" || r=$?; echo "$r"; }
# The control, read before any verdict is taken from trust(). 0 = an ordinary website loaded through this same file,
# so the network answers and the file still validates ordinary certificates; anything else and there is no online
# verdict to be had here -- without this, "the test site refused" and "nothing on this network answered" are the
# same reading, and the Mac that most needs this fix is the one whose network is under someone else's control.
control() { local r=0; /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$CONTROL_URL" || r=$?; echo "$r"; }
# How many lines of $2 match $1. Fails, rather than print a number, if grep could not read the file: a count that
# came back empty was compared as if it were one, and `[` reading "" as a number is an error, not a no.
count() { local n r=0; n=$(grep -c -- "$1" "$2" 2>/dev/null) || r=$?; if [ "$r" -gt 1 ] || [ -z "$n" ]; then return 1; fi; echo "$n"; }
# Certificates are lines that START with the BEGIN marker, which is all LibreSSL reads as one. Until 31 Oct 2026 the
# marker counted anywhere in a line, so a comment that mentioned it ("paste each certificate from its -----BEGIN
# CERTIFICATE----- line ...") made a bundle LibreSSL reads without complaint unfixable, as "a certificate can't be read".
certs() { count '^-----BEGIN CERTIFICATE-----' "$1"; }
# The SHA-256 of the file $1, or of stdin when $1 is "-": 64 hex digits, or a failure, never anything else.
# (LibreSSL prints "(stdin)= <digest>" in some versions and "<digest>" in others; the last word is the digest in both.)
sha() {
  local o
  if [ "$1" = - ]; then o=$(/usr/bin/openssl dgst -sha256 2>/dev/null) || return 1
  else o=$(/usr/bin/openssl dgst -sha256 2>/dev/null <"$1") || return 1; fi
  o=${o##* }
  case "$o" in *[!0-9a-f]*|'') return 1 ;; esac
  [ "${#o}" -eq 64 ] || return 1
  echo "$o"
}
# Prints one line for each certificate in $1 that is a withdrawn root: its position (1, 2, ...) and which root it is,
# AAA or EMS. Fails -- so the caller says UNKNOWN and changes nothing -- if any certificate can't be read, if anything
# openssl printed isn't a fingerprint, or if the number of fingerprints read isn't the number of certificates
# counted: a file this can't fully check is never called clean. That last test is the completeness gate, and it is
# what makes a failure that says nothing count as a failure.
# It reads the file itself, line by line, and hands each certificate to openssl through a pipe: no temporary files and
# no here-strings. Until 31 Oct 2026 the comparison was `grep -qxF <fingerprint> <<<"$ROOTS"`, and macOS's
# /bin/bash 3.2 writes a here-string to a file in /private/var/tmp whatever TMPDIR says. When it couldn't (a sandbox,
# an endpoint agent, a full disk), the grep failed, its failure read as "no match", and every certificate was "not a
# withdrawn root": measured, the run printed SAFE and exited 0 with both roots still in the file.
roots() {
  local n l blk='' inblk='' k=0 nfp=0 fp
  n=$(certs "$1") || return 1
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in
      -----BEGIN\ CERTIFICATE-----*)
        [ -z "$inblk" ] || return 1                     # a certificate with no END before the next one
        inblk=1; k=$((k + 1)); blk=$l ;;
      -----END\ CERTIFICATE-----*)
        [ -n "$inblk" ] || continue
        blk="$blk
$l"
        inblk=''
        fp=$(printf '%s\n' "$blk" | /usr/bin/openssl x509 -noout -fingerprint -sha256 2>/dev/null) || return 1
        fp=${fp#*=}
        # Not a fingerprint: not counted, so the gate below fails. 32 pairs of hex digits joined by colons.
        case "$fp" in *[!0-9A-F:]*|'') continue ;; esac
        [ "${#fp}" -eq 95 ] || continue
        nfp=$((nfp + 1))
        if [ "$fp" = "$AAA" ]; then echo "$k AAA"; elif [ "$fp" = "$EMS" ]; then echo "$k EMS"; fi ;;
      *)
        [ -z "$inblk" ] || blk="$blk
$l" ;;
    esac
  done <"$1" || return 1
  [ -z "$inblk" ] && [ "$k" -eq "$n" ] && [ "$nfp" -eq "$n" ]
}
# Writes $1 without the certificates listed in $2 ("position:root ..." as roots() found them). For each one it
# removes exactly these lines, and every other line in the file is kept, whatever it says:
#   - its own block, from its -----BEGIN CERTIFICATE----- line to its own -----END CERTIFICATE----- line;
#   - its name, when the name is directly above the block and is that root's: Apple's shape ("=== /.../CN=<name>",
#     then "Certificate:", the openssl text dump of the certificate, and its own "SHA256 Fingerprint=" line directly
#     above BEGIN -- every line of it indented, empty, or one of those three) or mk-ca-bundle's (the name, then a line
#     of "=" exactly as long, directly above BEGIN);
#   - the one empty line directly after the block, the separator Apple writes between blocks. That and Apple's name
#     shape are why this is still byte for byte the advisory's removal on Apple's file.
# Until 31 Oct 2026 a "=== " line anywhere above a removed root started its block, so an administrator's own "=== "
# line above a root they had appended, and every line between it and the certificate, went with the root, and the
# count check could not see it (it counts certificates). Every empty line after a removed root went too, not one.
strip() {
  awk -v list="$2" -v aaa="$AAA" -v ems="$EMS" -v aname="$AAA_NAME" -v ename="$EMS_NAME" '
    BEGIN {
      n = split(list, a, " ")
      for (i = 1; i <= n; i++) { split(a[i], p, ":"); drop[p[1] + 0] = p[2] }
    }
    NR == FNR {
      L[FNR] = $0; last = FNR
      if ($0 ~ /^-----BEGIN CERTIFICATE-----/) { k++; B[k] = FNR }
      else if ($0 ~ /^-----END CERTIFICATE-----/ && k && !(k in E) && B[k] < FNR) E[k] = FNR
      next
    }
    FNR == 1 {
      for (c in drop) {
        if (!(c in B) || !(c in E) || ((c + 1) in B && B[c + 1] < E[c])) { broken = 1; exit 1 }
        for (j = B[c]; j <= E[c]; j++) gone[j] = 1
        if (E[c] < last && L[E[c] + 1] == "") gone[E[c] + 1] = 1
        name = (drop[c] == "AAA") ? aname : ename
        fp = (drop[c] == "AAA") ? aaa : ems
        b = B[c]
        # mk-ca-bundle: the name, then a line of "=" as long as it, directly above the block
        if (b > 2 && L[b - 1] ~ /^=+$/ && L[b - 2] == name && length(L[b - 1]) == length(name)) {
          gone[b - 1] = 1; gone[b - 2] = 1
        }
        # Apple: "=== .../CN=<name>", "Certificate:", the dump, "SHA256 Fingerprint=<this root>", directly above
        if (b > 1 && L[b - 1] == "SHA256 Fingerprint=" fp) {
          for (s = b - 1; s >= 1; s--) {
            if (L[s] ~ /^=== /) break
            if (L[s] !~ /^(Certificate:$|SHA1 Fingerprint=|SHA256 Fingerprint=|[ \t]|$)/) { s = 0; break }
          }
          tail = "/CN=" name
          if (s >= 1 && L[s + 1] == "Certificate:" && length(L[s]) >= length(tail) && substr(L[s], length(L[s]) - length(tail) + 1) == tail) {
            for (j = s; j < b; j++) gone[j] = 1
          }
        }
      }
    }
    !(FNR in gone) { print }
    END { if (broken) exit 1 }' "$1" "$1"
}

# Everything below reads this snapshot, so the checks and the change are about the same bytes. $new is the file
# beside $FILE that the replacement is built in; it is empty until there is one.
# HUP, INT and TERM as well as EXIT, which is what the one-line fix on the page traps. An interrupt has to STOP
# this script, and on EXIT alone it did not: measured on 29 Oct 2026 under macOS's /bin/bash 3.2.57, a SIGINT
# arriving while bash waits on a plain foreground command is swallowed, and bash carries on to the next line with
# `set -euo pipefail` in force. Interrupted just before the write, the script went on to replace the file and
# printed SAFE, exit 0, about a run that had been cancelled. (bash does stop if the signal lands inside a command
# substitution, so the old shape failed only some of the time, which is worse.)
new=        # the file beside $FILE, while there is one
bnew=''       # the file beside $FILE the backup is copied into, until it has its dated name
replaced=   # set once $FILE has been replaced, so a run stopped after that can say so
# Every command here ends in `|| true`, and that is load-bearing rather than tidy. Measured on /bin/bash 3.2.57:
# with `set -e` in force, a failing command inside the EXIT trap ends the trap AND overrides the script's exit
# status, so one failed `rm` turned `exit 2` ("couldn't tell") into `exit 1`, which the published exit-code table
# reads as EXPOSED. `return 0` at the end does not help -- errexit ends the function before reaching it.
# strays() is for a file made beside $FILE whose name was not yet known when the signal came: mktemp chooses it.
clean() { rm -f "$snap" "$tmp" || true; [ -z "$new" ] || $SUDO rm -f "$new" || true; new=''; [ -z "$bnew" ] || $SUDO rm -f "$bnew" || true; bnew=''; strays || true; }
strays() {
  local f
  for f in "$DIR"/.wardlatch-new.$$.* "$DIR"/.wardlatch-backup.$$.*; do
    if [ -e "$f" ] || [ -L "$f" ]; then $SUDO rm -f "$f" || true; fi
  done
}
# A signal. Exit 2, not the conventional 130: 2 is this script's "couldn't tell, read the printed line", and an
# interrupted run reached no verdict, which is the same thing to a fleet tool. The page publishes an exit-code
# table that Jamf, Kandji and Intune policies are built on, and a fourth code in it would be one no policy has a
# branch for. If $FILE has already been replaced by then, this says so and names the way back: exit 2 tells the
# reader to read the printed line, and a stopped run that changed the file and printed nothing left them with
# neither a line nor a clue.
stopped() {
  clean
  [ -z "$replaced" ] || {
    echo "UNKNOWN  Stopped before this could re-test, and $FILE had already been replaced with the cleaned file"
    echo "         ($(removed_phrase), kept $after). It is whole, not half-written. Run this again."
    echo "         Backup: $backup"
    echo "         Undo:   sudo cp -p '$backup' '$FILE'"
  }
  exit 2
}
# Puts the bytes of $1 into $FILE in one step, and the ONLY thing in this script that writes to $FILE: a copy into
# a file beside it, then a rename over it. A rename within one directory is one step the kernel either did or
# didn't do, so whatever stops the script, $FILE holds either the old bundle or the new one and never half of
# either. Copying into $FILE in place truncated it first, so a Ctrl-C, a sudo timeout or a power cut during that
# copy left every built-in TLS client on the Mac -- curl, git, python3, openssl -- reading a stump of a certificate
# file until somebody ran this again. The file is made beside $FILE, not in $TMPDIR, because a rename only works
# within one filesystem, and with the same $SUDO as the write, so it belongs to whoever owns $FILE.
# It is made by mktemp, which creates a new file and fails if anything at all is at the name, a symbolic link
# included. Until 31 Oct 2026 the name was fixed (.wardlatch-new.<pid>) and the guard was `[ ! -e ]`, which is true
# for a link to nothing: cp wrote through the link and mv put the link itself where $FILE was.
# What it renames into place is checked there, beside $FILE, where only the owner of $FILE can change it: it must be
# byte for byte the file expected (the cleaned file's SHA-256, or the snapshot's for the restore), and the cleaned
# file must pass the checks again -- the right number of certificates, every one readable, no withdrawn root.
# Until 31 Oct 2026 the checks were made on the copy in the invoking user's temporary folder, and root copied it
# later. Returns 1 with $FILE untouched if a step fails, 3 if the copy beside $FILE is not the file expected.
replace() {
  local got expect
  if [ "$1" = "$tmp" ]; then expect=$want; else expect=$orig; fi
  new=$($SUDO mktemp "$DIR/.wardlatch-new.$$.XXXXXX" 2>/dev/null) || { new=''; return 1; }
  if $SUDO cp "$1" "$new" && $SUDO chmod 644 "$new"; then
    got=$(sha "$new") || got=''
    if [ "$got" != "$expect" ] || { [ "$1" = "$tmp" ] && ! built "$new"; }; then
      $SUDO rm -f "$new" || true
      new=''
      return 3
    fi
    $SUDO mv "$new" "$FILE" && { new=''; return 0; }
  fi
  $SUDO rm -f "$new" || true
  new=''
  return 1
}
# The checks the cleaned file passed, made again on the file that is about to be renamed into place.
built() { local n l; n=$(certs "$1") && [ "$n" -eq "$after" ] && l=$(roots "$1") && [ -z "$l" ]; }
# The backup copy failed or isn't the file this run checked: the partial copy is removed and the dated name is never
# used, and the line says which of those happened. Until 31 Oct 2026 the copy was made straight to the dated name,
# so a copy that failed part-way (a full disk, a Ctrl-C) left a truncated file under exactly the name of a good backup.
nobackup() {
  local left=''
  if [ -n "$bnew" ]; then
    if $SUDO rm -f "$bnew" 2>/dev/null; then bnew=''; else left=$bnew; fi
  fi
  echo "UNKNOWN  $1, so nothing was replaced and no backup was kept."
  if [ -n "$left" ]; then
    echo "         A partial copy is left at $left: it is not a backup. Delete it."
  else
    echo "         Nothing is left beside $FILE, and this run did not change it."
  fi
  exit 2
}

snap=$(mktemp "${TMPDIR:-/tmp}/wardlatch.XXXXXX" 2>/dev/null) || {
  echo "UNKNOWN  Couldn't make a temporary file in ${TMPDIR:-/tmp} (mktemp failed), so $FILE wasn't read. Nothing changed."
  exit 2
}
tmp=$(mktemp "${TMPDIR:-/tmp}/wardlatch.XXXXXX" 2>/dev/null) || {
  rm -f "$snap" || true
  echo "UNKNOWN  Couldn't make a temporary file in ${TMPDIR:-/tmp} (mktemp failed), so $FILE wasn't read. Nothing changed."
  exit 2
}
# The temporary files go where TMPDIR says. `mktemp -t` on macOS ignores TMPDIR for the per-user folder, so until
# 31 Oct 2026 the harness's "no temporary files left behind" check watched a folder this script never wrote to.
# Both are checked: unchecked, `set -e` ended the run with mktemp's own status, 1 -- the published table's EXPOSED.
trap clean EXIT
trap stopped HUP INT TERM
cp "$FILE" "$snap" 2>/dev/null || { echo "UNKNOWN  Can't read $FILE. Nothing changed."; exit 2; }
orig=$(sha "$snap") || { echo "UNKNOWN  Couldn't take the SHA-256 of $FILE (openssl failed), so it wasn't checked. Nothing changed."; exit 2; }

# curl also trusts other PEM blocks (BEGIN TRUSTED CERTIFICATE, BEGIN X509 CERTIFICATE), which this fix doesn't read.
# This is read before the floor below, and the fingerprints after it, because the floor now has to say whether the
# file holds a withdrawn root: a block this fix cannot read could hold one, so "it holds neither" would otherwise be
# a claim about bytes nobody checked.
if ! blocks=$(count '^-----BEGIN ' "$snap") || ! before=$(certs "$snap"); then
  echo "UNKNOWN  Couldn't read the copy of $FILE this run took, so it wasn't checked. Nothing changed."
  exit 2
fi
if [ "$blocks" -ne "$before" ]; then
  echo "UNKNOWN  $FILE holds blocks that aren't plain certificates (such as BEGIN TRUSTED CERTIFICATE), which curl also"
  echo "         trusts and this fix can't check. Nothing changed. Run npx wardlatch@latest to test the Mac's tools."
  exit 2
fi
spec=$(roots "$snap") || {
  echo "UNKNOWN  A certificate in $FILE couldn't be read and fingerprinted, so the file wasn't fully checked."
  echo "         Nothing changed."
  exit 2
}
drop='' naaa=0 nems=0
# Split on purpose: roots() prints "position root" pairs, digits and AAA or EMS only.
# shellcheck disable=SC2086
set -f; set -- $spec; set +f
while [ "$#" -ge 2 ]; do
  case "$2" in
    AAA) naaa=$((naaa + 1)) ;;
    EMS) nems=$((nems + 1)) ;;
    *) echo "UNKNOWN  The fingerprint check returned something this doesn't recognise. Nothing changed; please report this."; exit 2 ;;
  esac
  drop="${drop:+$drop }$1:$2"
  shift 2
done
[ "$#" -eq 0 ] || { echo "UNKNOWN  The fingerprint check returned something this doesn't recognise. Nothing changed; please report this."; exit 2; }
found=$((naaa + nems))

# The one floor in this script, and the only place a number like this belongs: a judgement about the file as it was
# found, made before anything is written into it. It names the number, because "it looks damaged" on its own tells
# the reader a verdict and not the reason for it -- and what it says next depends on what is IN the file, not on how
# small the file is.
# Until 30 Oct 2026 it said the file looked damaged and told the reader to "put a backup back" whatever the file
# held. On a small bundle holding NEITHER withdrawn root that is wrong twice over. The file may be perfectly fine
# and simply short -- a hand-built bundle, a minimal store copied out of a container image -- and this fix has
# nothing to remove from it, so there is nothing here to call damage. And the backup it pointed at is the one this
# script writes, which is a copy of the file as it was BEFORE the removal and therefore holds the withdrawn roots:
# on a small bundle correctly fixed by a first run, a second run reached this floor and advised a revert to the
# compromised file. Advising a revert to a known-compromised state is the same defect as the network-triggered
# revert this branch removed on 29 Oct 2026, in a script people run as root. So that case is now UNKNOWN with the
# facts, no claim that the Mac is safe, and no advice to restore anything.
if [ "$before" -lt 50 ]; then
  if [ "$found" -eq 0 ]; then
    echo "UNKNOWN  $FILE has $before certificates, fewer than the 50 this expects of a trust store. It holds neither"
    echo "         withdrawn root, so this fix has nothing to remove. Something else may be wrong with it; nothing"
    echo "         was changed. Run npx wardlatch@latest to test what this Mac's tools actually trust."
  else
    echo "UNKNOWN  $FILE holds only $before certificates, fewer than the 50 this expects of a trust store, so it"
    echo "         looks damaged -- and it still holds a withdrawn root. This fix rebuilds the file it is given and"
    echo "         will not rebuild one that small. Nothing changed."
    echo "         Don't put an older copy of this file back: a copy from before this fix ran holds the withdrawn"
    echo "         roots too. A macOS update restores Apple's own cert.pem -- run this again after one."
  fi
  exit 2
fi
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

# The names of the withdrawn roots this file held, from what roots() found in it. Copies are counted.
held() {
  local a=$AAA_NAME e=$EMS_NAME
  [ "$naaa" -le 1 ] || a="$naaa copies of $AAA_NAME"
  [ "$nems" -le 1 ] || e="$nems copies of $EMS_NAME"
  if [ "$naaa" -gt 0 ] && [ "$nems" -gt 0 ]; then echo "$a and $e"
  elif [ "$naaa" -gt 0 ]; then echo "$a"
  else echo "$e"; fi
}
# What this run removed, by name, and nothing it did not establish. Apple added emSign ECC Root CA - G3 after Mojave,
# so every Mac of that era holds ONE of the two, and this says which one was removed and that this FILE did not hold
# the other. Until 31 Oct 2026 it said "removed both withdrawn roots" whenever it removed two certificates -- two
# copies of AAA Certificate Services included -- and "the other was already absent from this Mac", which is a claim
# about a Mac drawn from one file.
removed_phrase() {
  if [ "$naaa" -gt 0 ] && [ "$nems" -gt 0 ]; then
    if [ "$found" -eq 2 ]; then echo "removed both withdrawn roots"; else echo "removed both withdrawn roots ($(held))"; fi
  elif [ "$naaa" -gt 0 ]; then
    echo "removed $(held) (this file did not hold the other withdrawn root, $EMS_NAME)"
  else
    echo "removed $(held) (this file did not hold the other withdrawn root, $AAA_NAME)"
  fi
}

strip "$snap" "$drop" >"$tmp" || { echo "UNKNOWN  Couldn't build the cleaned file, so nothing was changed. Please report this."; exit 2; }
# The SHA-256 of the cleaned file, taken from the rebuild itself rather than from the copy in the temporary folder:
# replace() will rename into place only a file with exactly this digest that passes the checks below again.
want=$(strip "$snap" "$drop" | sha -) || { echo "UNKNOWN  Couldn't take the SHA-256 of the cleaned file, so nothing was changed. Please report this."; exit 2; }
after=$(certs "$tmp") || after=-1
left=$(roots "$tmp") || left=unreadable
# Three separate reasons the cleaned file may not be used, each saying which one it is. Until 30 Oct 2026 they were
# one condition and one line that reported all three as arithmetic ("didn't come out as expected (N before, M
# after)"), and the third of them was a second 50-certificate floor.
# That floor is gone, and this is why. The floor above refuses a bundle holding fewer than 50 certificates before
# anything is written to it, so `before` is 50 or more here, and `found` is 1 or 2; the only arithmetic that could
# reach a floor on `after` was 50-1, 50-2 and 51-2, every one of which is exactly `before - found` and so exactly
# right. It could not fire on a mangled rebuild, because a rebuild that lost or kept a certificate is caught by the
# count check, and one that changed no count would not be caught by a floor either. So all it could ever do was
# refuse a correctly cleaned 50- or 51-certificate bundle, call the right answer an arithmetic failure, and leave
# that Mac with no way to be fixed at all. The count check and the fingerprint re-read below it are the whole of
# what there is to check here.
if [ "$left" = unreadable ]; then
  echo "UNKNOWN  A certificate in the cleaned file couldn't be read, so the cleaned file wasn't fully checked and"
  echo "         was not used. Nothing changed; $FILE is as it was. Please report this."
  exit 2
elif [ -n "$left" ]; then
  echo "UNKNOWN  The cleaned file still holds a withdrawn root, so it was not used. Nothing changed; $FILE is as it"
  echo "         was. Please report this."
  exit 2
elif [ "$after" -ne $((before - found)) ]; then
  echo "UNKNOWN  The cleaned file holds $after certificates, not the $((before - found)) there should be ($before before, $found removed),"
  echo "         so it was not used. Nothing changed; $FILE is as it was. Please report this."
  exit 2
fi

# The control, read BEFORE anything is written, through the file as it is. Without this baseline, the control read
# after the write answers two questions at once -- "does this network answer anything?" and "did the change I just
# made break certificate validation on this Mac?" -- and the script printed SAFE for both, exit 0. That is the same
# two-readings-collapsed-into-one error the control was added to remove, one step further down the script.
c0=$(control "$snap")

backup="$FILE.wardlatch-$(date +%Y%m%d-%H%M%S).bak"
{ [ ! -e "$backup" ] && [ ! -L "$backup" ]; } || { echo "UNKNOWN  $backup already exists. Nothing changed; run again in a second."; exit 2; }
# The first thing that needs privilege, asked for on its own: in the interactive run this is where sudo asks for the
# password, and a refusal there (a wrong password three times, no answer in time) is not a full disk. Until 31 Oct
# 2026 it happened inside the backup copy, and the line blamed disk space (df -h /).
if [ -n "$SUDO" ] && ! $SUDO -v; then
  echo "UNKNOWN  sudo didn't give this run the privilege to write $FILE (sudo -v failed), so nothing was changed."
  echo "         Run this again; it asks for your Mac's password."
  exit 2
fi
# The backup. Copied under a name of its own beside $FILE, compared with the SNAPSHOT -- the file every check above
# was made on -- and only then given its dated name, which link(2) refuses if anything at all is already there.
# Until 31 Oct 2026 the backup was compared with $FILE, and the "changed while this ran" check came BEFORE the backup
# step, which is where the interactive run waits for the password: a change made during that wait was in the backup
# and in $FILE, both comparisons passed, and the cleaned OLD snapshot was renamed over it. Measured: an
# administrator's root appended meanwhile was gone from the file, kept only in the backup, and the run said SAFE.
bnew=$($SUDO mktemp "$DIR/.wardlatch-backup.$$.XXXXXX" 2>/dev/null) || { bnew=''; nobackup "Couldn't make a file beside $FILE for the backup (mktemp failed). Check the disk has room (df -h /)"; }
$SUDO cp -p "$FILE" "$bnew" || nobackup "Couldn't copy $FILE to make the backup (cp failed). Check the disk has room (df -h /)"
cmp -s "$bnew" "$snap" || nobackup "The backup copy isn't the file this run checked: $FILE changed while this ran, or the copy went wrong"
$SUDO link "$bnew" "$backup" 2>/dev/null || nobackup "Couldn't give the backup its dated name, $backup"
if $SUDO rm -f "$bnew"; then bnew=''; fi
# And once more, immediately before the replacement: the file must still be the snapshot the cleaned file was built
# from, or the replacement would throw away whatever changed it.
cmp -s "$FILE" "$snap" || {
  echo "UNKNOWN  $FILE changed while this ran, after the backup was taken, so it was not replaced. Run this again."
  echo "         Backup: $backup (the file as this run read it)"
  exit 2
}
replace "$tmp" || { r=$?; if [ "$r" -eq 3 ]; then echo "UNKNOWN  The file built beside $FILE isn't the cleaned file this checked, so it was not used and"; echo "         $FILE was not changed. Please report this.  Backup: $backup"; else echo "UNKNOWN  Couldn't replace $FILE, so nothing was changed. Check the disk has room (df -h /)"; echo "         and that this ran with enough privilege.  Backup: $backup"; fi; exit 2; }
replaced=1

# The only path here that puts the original back, and the only kind of reason there may be for one: the bytes now in
# $FILE are not the bytes this script built and checked, so what every TLS client on this Mac reads is a file nobody
# has checked, and the backup is the only file here that has been. It compares $FILE's SHA-256 with the one the
# cleaned file was checked against, beside $FILE, and reads nothing else; no probe result reaches it. A revert on a
# network reading would mean the one Mac that can never be fixed is the one already under attack, because putting
# the original back puts the withdrawn roots back.
landed=$(sha "$FILE") || landed=''
if [ "$landed" != "$want" ]; then
  # Through replace(), like the forward write: an interrupted restore left $FILE a stump when it copied the backup
  # over it in place, which is the defect the forward write was redesigned to remove and this path still had.
  # The declaration goes immediately above the call, and the harness checks that it is there.
  # wardlatch:revert-reason=content-mismatch
  if replace "$backup"; then
    echo "EXPOSED  What was written to $FILE isn't the file this built and checked, so the original was put back and this"
    echo "         Mac still trusts the compromised keys. Nothing else was changed. Run it again; please report this."
    echo "         Backup: $backup"
    exit 1
  fi
  # No command to put the backup back by hand: it holds the withdrawn roots, and this says what each file holds
  # rather than advise a revert. Until 31 Oct 2026 it printed "Put it back yourself, now: sudo cp -p ...".
  echo "UNKNOWN  What was written to $FILE isn't the file this built and checked, AND the original couldn't be put"
  echo "         back, so $FILE now holds bytes nothing has checked. Backup: $backup (the file as this run read it; it"
  echo "         holds $(held)). Find what else is writing to $FILE, then run this again; please report this."
  exit 2
fi

# Four readings, because there is a baseline to compare with, and a failure after the change is either a certificate
# refused (60: about the change, or about the network) or a network that stopped answering (6, 7, 28: about neither).
c=$(control "$FILE")
if [ "$c" -eq 0 ]; then
  # The control loads through the new file: this network answers, and the new file still validates ordinary
  # certificates. So the test host's answer is about the test host, and there is a verdict to be had.
  r=$(trust "$FILE")
  case "$r" in
    60) echo "SAFE     Fixed. $FILE now refuses the compromised keys: $(removed_phrase), kept $after." ;;
    0)  echo "EXPOSED  Fixed in the file ($(removed_phrase), kept $after), but the advisory's test site is"
        echo "         still trusted. Two ordinary things look exactly like this, and both are likelier than"
        echo "         anything stranger. A TLS-inspecting proxy's own root may have been added to this file (or to"
        echo "         whichever file your tools read): the proxy then signs everything, and that site loads"
        echo "         whatever this file holds. Or the test site may have re-issued its certificate from an"
        echo "         ordinary CA, in which case it now loads for everyone and tests nothing. Rule those two out"
        echo "         before you go looking for something else on this Mac that trusts the compromised keys. The"
        echo "         fix was kept either way: putting the original back would put"
        echo "         $(held) back. Please report this."
        echo "         Backup: $backup (the file as it was; it holds $(held))"
        exit 1 ;;
    *)  echo "SAFE     Fixed in the file: $(removed_phrase), kept $after. (The test site didn't answer"
        echo "         (curl $r), though an ordinary website loaded, so this wasn't re-tested online.)" ;;
  esac
elif [ "$c0" -ne 0 ]; then
  # Nothing loaded before the change either, so this reading is about the network and not about the file. Report,
  # keep the fix, claim nothing online.
  echo "SAFE     Fixed in the file: $(removed_phrase), kept $after."
  echo "         (An ordinary website didn't load before this change (curl $c0) or after it (curl $c), so nothing"
  echo "         was re-tested online.)"
else
  case "$c" in
    6|7|28)
      # A name that didn't resolve, a connection that wasn't made, or no answer in time: the network stopped
      # answering between the two reads. None of those is a certificate refused, so there is nothing here about the
      # change and no attack to diagnose. Until 31 Oct 2026 this got the certificate reading below, attack and all.
      case "$c" in 6) why="the name didn't resolve" ;; 7) why="no connection was made" ;; *) why="no answer in time" ;; esac
      echo "UNKNOWN  Fixed in the file ($(removed_phrase), kept $after), but this network stopped answering:"
      echo "         an ordinary website loaded through the old file (curl 0), then not through the new one (curl $c:"
      echo "         $why). That is not a certificate being refused, so it says nothing about the change, and nothing"
      echo "         was re-tested online. Run this again to re-test."
      echo "         Backup: $backup"
      exit 2 ;;
    60)
      # The one reading here that is about the change or about the network, and cannot tell which: an ordinary
      # website's certificate verified through the file as it was and is refused through the file this wrote, and
      # the certificates in those two files differ only by the withdrawn roots removed. So either that site's chain
      # needs one of them, or something on this network answered the two requests differently -- and that second
      # reading is what an attack on this Mac looks like. Both say the same thing about what to do, which is why there
      # is no revert here, no revert-reason for one, and no Undo line: putting a withdrawn root back to make a page
      # load is not a repair, and on the second reading it would hand it back to a Mac already under attack. Until
      # 31 Oct 2026 this printed the Undo command under "Decide it yourself from the two lines below".
      echo "UNKNOWN  Fixed in the file ($(removed_phrase), kept $after), but an ordinary website that"
      echo "         loaded through the old file (curl 0) doesn't load through the new one (curl 60), which means its"
      echo "         certificate was refused. The certificates in the two files differ only by $(held), so"
      echo "         either that website's certificate chain needs what was removed, or this network answered the two"
      echo "         requests differently -- and the second is what an attack on this Mac would look like. The fix was"
      echo "         kept either way: this does not put a withdrawn root back on a network reading. Please report this."
      echo "         Backup: $backup (the file as it was; it holds $(held))"
      exit 2 ;;
    *)
      echo "UNKNOWN  Fixed in the file ($(removed_phrase), kept $after), but an ordinary website that"
      echo "         loaded through the old file (curl 0) failed through the new one with curl $c, which is neither a"
      echo "         certificate refused (60) nor a network that stopped answering (6, 7, 28). This run"
      echo "         reads nothing into it, and re-tested nothing online. Please report this."
      echo "         Backup: $backup"
      exit 2 ;;
  esac
fi
echo "         Backup: $backup"
echo "         Undo:   sudo cp -p '$backup' '$FILE'"
echo "         This covers the built-in curl, git, python3 and openssl: the four we measured. Apple's pip3 keeps its"
echo "         own copy, and we have not measured the built-in perl or ruby. The page has both."
echo "         For everything else: npx wardlatch@latest"
echo "         A macOS update puts Apple's original file back: run this again after every update."
