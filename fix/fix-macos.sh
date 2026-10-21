#!/bin/bash
# Wardlatch Mac fix · a free tool from Deimos AI LLC · Apache-2.0 · https://www.deimoscore.com/wardlatch/#mac
#
# Removes the two roots tied to the leaked eMudhra keys (AAA Certificate Services, emSign ECC Root CA - G3) from
# /etc/ssl/cert.pem, the file macOS's built-in curl, git, python3 and openssl read. No macOS release has updated it yet.
# The removal is the advisory's (emudhra.we-have-a-problem.com); this script adds the safety around it:
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
BAD='^=== .*/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$'

[ "$(uname -s)" = Darwin ] || { echo "This fix is for macOS. On Linux, update the ca-certificates package."; exit 2; }
[ -f "$FILE" ] || { echo "UNKNOWN  $FILE not found. Nothing changed."; exit 2; }
SUDO=sudo; if [ "$(id -u)" -eq 0 ] || { [ -w "$FILE" ] && [ -w "$(dirname "$FILE")" ]; }; then SUDO=; fi

# 0 = trusts the leaked keys, 60 = refuses them, anything else = the test site didn't answer
trust() { local r=0; /usr/bin/curl -s -o /dev/null --max-time 15 --cacert "$1" "$TEST_URL" || r=$?; echo "$r"; }
certs() { grep -c 'BEGIN CERTIFICATE' "$1" || true; }
bad()   { grep -E -c "$BAD" "$1" || true; }

if [ "$(certs "$FILE")" -lt 50 ]; then
  echo "UNKNOWN  $FILE holds only $(certs "$FILE") certificates, so it looks damaged. Nothing changed."
  echo "         Put a backup back (ls $FILE*.bak; sudo cp -p <backup> $FILE), then run this again."
  exit 2
fi
found=$(bad "$FILE")
if [ "$found" -eq 0 ]; then
  r=$(trust "$FILE")
  case "$r" in
    60) echo "SAFE     $FILE already refuses the leaked keys. Nothing changed." ;;
    0)  echo "EXPOSED  $FILE has neither root but still trusts the test site. Nothing changed; please report this."; exit 1 ;;
    *)  echo "SAFE     $FILE no longer holds the two roots. Nothing changed. (The test site didn't answer, so this wasn't re-tested online.)" ;;
  esac
  exit 0
fi

before=$(certs "$FILE")
tmp=$(mktemp -t wardlatch); trap 'rm -f "$tmp"' EXIT
awk '/^(###|===) /{skip=0} /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1} !skip' "$FILE" > "$tmp"
after=$(certs "$tmp")
if [ "$(bad "$tmp")" -ne 0 ] || [ "$after" -ne $((before - found)) ] || [ "$after" -lt 50 ]; then
  echo "UNKNOWN  The cleaned file didn't come out as expected ($before certificates before, $after after). Nothing changed."
  exit 2
fi

backup="$FILE.wardlatch-$(date +%Y%m%d-%H%M%S).bak"
[ ! -e "$backup" ] || { echo "UNKNOWN  $backup already exists. Nothing changed; run again in a second."; exit 2; }
$SUDO cp -p "$FILE" "$backup"
$SUDO cp "$tmp" "$FILE"
$SUDO chmod 644 "$FILE"

r=$(trust "$FILE")
case "$r" in
  60) echo "SAFE     Fixed. $FILE now refuses the leaked keys: removed $found roots, kept $after certificates." ;;
  0)  $SUDO cp -p "$backup" "$FILE"
      echo "EXPOSED  The file still trusts the test site after the change, so the original was put back. Please report this."
      exit 1 ;;
  *)  echo "SAFE     Fixed in the file: removed $found roots, kept $after certificates. (The test site didn't answer, so this wasn't re-tested online.)" ;;
esac
echo "         Backup: $backup"
echo "         Undo:   sudo cp -p '$backup' '$FILE'"
echo "         This covers curl, git, python3 and openssl. For everything else: npx wardlatch"
