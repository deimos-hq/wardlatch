#!/bin/bash
# Wardlatch Mac fix · a free tool from Deimos AI LLC · Apache-2.0 · https://www.deimoscore.com/wardlatch/#mac
#
# Removes the two roots tied to the leaked eMudhra keys (AAA Certificate Services, emSign ECC Root CA - G3) from
# /etc/ssl/cert.pem, the file macOS's built-in curl, git, python3 and openssl read. No macOS release has fixed it yet,
# and a macOS update puts Apple's original file back (26.7.2 did): run this again after every update.
# The removal is the advisory's (emudhra.we-have-a-problem.com); this script adds the safety around it:
#   - finds the two roots by their SHA-256 fingerprints, not by the name lines some copies of the file don't have,
#     and refuses a file it can't fully check (a certificate it can't read, or a block that isn't a plain certificate);
#   - works on a snapshot of the file and refuses to replace it if it changed meanwhile;
#   - changes nothing if the file is already clean;
#   - keeps a dated backup and never overwrites an earlier one;
#   - writes a new file and checks it (every other certificate still there, only the two removed) before replacing;
#   - keeps the file readable by everyone, as macOS ships it;
#   - re-tests against the advisory's test site, and puts the original back if the result is wrong.
# Safe to run twice. Run it in Terminal (it asks for your Mac's password) or as root from Jamf, Kandji or Intune.
# Copy it from the Wardlatch page in Safari. Don't fetch it with the Mac's own curl: that curl is what's exposed.
set -euo pipefail

FILE="${WARDLATCH_CERT_FILE:-/etc/ssl/cert.pem}"   # the override exists for testing on a copy
TEST_URL="https://dv-g3b-emudhra.we-have-a-problem.com/"
# SHA-256 fingerprints: AAA Certificate Services, emSign ECC Root CA - G3
ROOTS='D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4
86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B'

[ "$(uname -s)" = Darwin ] || { echo "This fix is for macOS. On Linux, update the ca-certificates package."; exit 2; }
[ -f "$FILE" ] || { echo "UNKNOWN  $FILE not found. Nothing changed."; exit 2; }
SUDO=sudo; if [ "$(id -u)" -eq 0 ] || { [ -w "$FILE" ] && [ -w "$(dirname "$FILE")" ]; }; then SUDO=; fi

# 0 = trusts the leaked keys, 60 = refuses them, anything else = the test site didn't answer
# (-q: ignore ~/.curlrc, whose settings could change the answer)
trust() { local r=0; /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$TEST_URL" || r=$?; echo "$r"; }
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

# Everything below reads this snapshot, so the checks and the change are about the same bytes.
snap=$(mktemp -t wardlatch); tmp=$(mktemp -t wardlatch); trap 'rm -f "$snap" "$tmp"' EXIT
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
  r=$(trust "$snap")
  case "$r" in
    60) echo "SAFE     $FILE already refuses the leaked keys. Nothing changed." ;;
    0)  echo "EXPOSED  $FILE holds neither root but still trusts the test site. Nothing changed; please report this."; exit 1 ;;
    *)  echo "SAFE     $FILE no longer holds the two roots. Nothing changed. (The test site didn't answer, so this wasn't re-tested online.)" ;;
  esac
  exit 0
fi

before=$(certs "$snap")
strip "$snap" "$(tr '\n' ' ' <<<"$list")" > "$tmp"
after=$(certs "$tmp")
left=$(roots "$tmp") || left=unreadable
if [ -n "$left" ] || [ "$after" -ne $((before - found)) ] || [ "$after" -lt 50 ]; then
  echo "UNKNOWN  The cleaned file didn't come out as expected ($before certificates before, $after after). Nothing changed."
  exit 2
fi

backup="$FILE.wardlatch-$(date +%Y%m%d-%H%M%S).bak"
[ ! -e "$backup" ] || { echo "UNKNOWN  $backup already exists. Nothing changed; run again in a second."; exit 2; }
cmp -s "$FILE" "$snap" || { echo "UNKNOWN  $FILE changed while this ran. Nothing changed; run it again."; exit 2; }
$SUDO cp -p "$FILE" "$backup"
$SUDO cp "$tmp" "$FILE"
$SUDO chmod 644 "$FILE"

r=$(trust "$FILE")
case "$r" in
  60) echo "SAFE     Fixed. $FILE now refuses the leaked keys: removed $found root certificates, kept $after." ;;
  0)  $SUDO cp -p "$backup" "$FILE"
      echo "EXPOSED  The file still trusts the test site after the change, so the original was put back. Please report this."
      exit 1 ;;
  *)  echo "SAFE     Fixed in the file: removed $found root certificates, kept $after. (The test site didn't answer, so this wasn't re-tested online.)" ;;
esac
echo "         Backup: $backup"
echo "         Undo:   sudo cp -p '$backup' '$FILE'"
echo "         This covers the built-in curl, git, python3, openssl, perl and ruby. Apple's pip3 has its own copy: see the page."
echo "         For everything else: npx wardlatch@latest"
echo "         A macOS update puts Apple's original file back: run this again after every update."
