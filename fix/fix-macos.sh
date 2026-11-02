#!/bin/bash
# Wardlatch Mac fix · a free tool from Deimos AI LLC · Apache-2.0 · https://www.deimoscore.com/wardlatch/#mac
#
# Removes the two roots tied to the compromised eMudhra keys (AAA Certificate Services, emSign ECC Root CA - G3) from
# /etc/ssl/cert.pem, the file macOS's built-in curl, git, python3 and openssl read. No macOS release has fixed it yet,
# and a macOS update puts Apple's original file back (26.7.2 did): run this again after every update.
# The removal is the advisory's (emudhra.we-have-a-problem.com); this script adds the safety around it:
#   - finds the two roots by their SHA-256 fingerprints, not by the name lines some copies of the file don't have,
#     and by their public keys too, compared as openssl decodes them whatever encoding a certificate stores them in,
#     so a copy with a bit changed, a root re-issued with the same key, or the key re-encoded is removed;
#     and refuses a file it can't fully check: a certificate it can't read, a block that isn't a plain certificate,
#     a -----BEGIN marker anywhere but at the start of a line, a NUL byte anywhere in the file (LibreSSL reads the
#     file in 253-byte pieces and cuts each at its NUL, so it reads bytes no line-based reader sees, and a withdrawn
#     root can be hidden in a block that way), or fewer fingerprints read than certificates counted;
#   - refuses a $FILE that is a symbolic link: replacing it would put a file of this script's own where the link is,
#     so $FILE would stop following the file the link points to, and that file would be left as it is;
#   - works on a snapshot of the file and refuses to replace it if it changed meanwhile: the backup it takes is
#     compared with that snapshot, and the file is compared with it again, by SHA-256, after the new file has been
#     built and checked and immediately before the rename (a change in the moment between that test and the rename
#     is the one it cannot see);
#   - and because that snapshot is in your temporary folder, where anything running as you can change it, nothing
#     read from it is taken on trust but one reading: before replacing anything, the backup (beside the file, where
#     only the file's owner can change it) must have the snapshot's SHA-256, read exactly as the snapshot did -- every
#     certificate readable, the same withdrawn roots and copies at the same places and no others -- and give byte for
#     byte the cleaned file when cleaned the same way; a file found clean, or too small to fix, is read again from the
#     file itself. The one reading nothing bears out is the control before the change, made through the snapshot: a
#     process running as you that made it fail would turn an UNKNOWN after the change into SAFE "Fixed in the file",
#     with nothing claimed online;
#   - changes nothing if the file is already clean;
#   - refuses a bundle too small to be a trust store, and never advises putting back a copy that holds a withdrawn
#     root: the only way back it ever names is its own backup, in the Undo line under a SAFE result or under a run
#     stopped after the file was fixed;
#   - keeps a dated backup and never overwrites an earlier one; the copy is made under a temporary name and compared
#     with the snapshot first, so the dated name only ever holds a complete copy of the file this run checked;
#   - removes only each withdrawn root's own lines -- its certificate, the name and description lines directly above
#     it when they are that root's exactly as openssl prints them, and the one empty line after it -- and nothing
#     else in the file;
#   - writes the new file beside the old one and checks THAT file -- byte for byte the file it built, every other
#     certificate still there, no withdrawn root left -- before replacing anything; root writes it from what your own
#     shell hands it, and never opens a file in your temporary folder;
#   - makes every change to the file by renaming a finished file over it, in one step, so an interruption leaves the
#     old file or the new one and never half of either, and removes its temporary files on a Ctrl-C or a shutdown too;
#   - keeps the file readable by everyone, as macOS ships it;
#   - checks that what landed in the file is the file it checked, and puts the original back if it isn't -- the one
#     reason it ever puts the original back, because the original is the file that trusts the compromised keys;
#   - reads a control -- an ordinary website, through this same file -- both before and after the change, and tells
#     a certificate refused after the change apart from a network that stopped answering; it re-tests against the
#     advisory's test site only when the control loads, and no network result undoes the fix;
#   - on macOS, prints a line that starts with SAFE, EXPOSED or UNKNOWN whenever it exits, from its first command on
#     (before that, bash has only read the script), and exits 2 after any signal it can catch whose default is to end
#     a process: a Ctrl-C (INT), a Ctrl-\ (QUIT), HUP, TERM, ABRT, PIPE, ALRM (a timeout), XCPU (a CPU limit), XFSZ,
#     VTALRM, PROF, USR1 and USR2. Not the fault signals, ILL, TRAP, EMT, FPE, BUS, SEGV and SYS: when bash itself
#     raises one, a trap on it would run on top of the fault, so they keep their default, and any of them, or SIGKILL,
#     ends the run with no line;
#   - exits 0 only after a SAFE line and 1 only after an EXPOSED one: a line that can't be written ends it with 2.
# Safe to run twice. Run it in Terminal (it asks for your Mac's password) or as root from Jamf, Kandji or Intune.
# Copy it from the Wardlatch page in Safari. Don't fetch it with the Mac's own curl: that curl is what's exposed.
set -euo pipefail
# Bytes, not characters, as LibreSSL reads the file. In a UTF-8 locale macOS's grep does not match a line holding a
# byte that isn't valid UTF-8 at all, so a marker after such bytes went uncounted (measured 31 Oct 2026).
export LC_ALL=C

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
# And their public keys. A certificate carrying one of these keys is trusted to sign for it whatever else it says: a
# copy with one bit of its signature flipped, or a root re-issued with the same key, has another fingerprint and the
# same key, and LibreSSL, OpenSSL 3.6.4 and Apple's python3 trust it (measured 31 Oct 2026). SHA-256 of each root's
# SubjectPublicKeyInfo as it ships:
#   AAA Certificate Services  bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3
#   emSign ECC Root CA - G3   8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782
# The same key can be stored in other encodings, and LibreSSL and /usr/bin/curl trust a root stored in each of them
# (measured 31 Oct 2026 on throwaway roots, each verifying a leaf it signed): an EC point compressed or hybrid, the curve
# given by explicit parameters instead of its name, an RSA key labelled RSA-PSS. `openssl x509 -pubkey` prints each in
# its own encoding, so comparing that text -- as this did until then -- missed all of them, and the copy stayed under
# SAFE. So the key is compared by its own bytes as openssl decodes and prints them (-text): every encoding of an EC point
# carries its X coordinate, and every encoding of an RSA key its modulus, byte for byte. These are emSign's X coordinate
# (48 bytes) and the first 48 bytes of AAA's modulus, in lowercase hex as openssl prints them.
AAA_N='be409df46ee1ea76871c4d45448ebe46c883069dc12afe181f8ee402faf3ab5d508a16310b9a06d0c57022cd492d5463'
EMS_X='23a50cb82d12f528f3b1b2dde20212809e395f494d9fc925345974ecbb061ce7c072afe8ae2fe141548714a84ab2e87c'
# The seven OTHER keys of this incident, which this file must not hold either. Removing the two roots above works
# because the compromised intermediates then chain to nothing -- but only for a reader that insists on a chain
# ending at a self-signed root in the file. /usr/bin/curl 8.7.1 does not: like curl since 7.68 on OpenSSL-style
# backends it takes EVERY CA certificate in a --cacert file as a trust anchor, and Apple's git goes through the same
# libcurl, as does the built-in perl. So a cert.pem holding one of the compromised intermediates keeps trusting
# everything that intermediate issued after both roots are gone, and until 1 Nov 2026 this script looked only for
# the two roots and said SAFE, exit 0 (the swarm's B-tls-2; measured here on 99a7f7d, and MEASURED again with
# `openssl verify -partial_chain`: the advisory's ov-g3c leaf verifies through the cleaned file plus that one
# intermediate, and fails through the cleaned file alone).
#   - Six of them are the compromised TLS intermediate keys. There are 12 compromised intermediate certificates and
#     six keys, because each intermediate was issued twice: once under emSign Root TLS CA - G3 and once under AAA
#     Certificate Services (Sectigo's cross-sign). Matching by key covers both issues of each with one entry.
#   - The seventh is emSign Root TLS CA - G3's own key. No root programme calls that key compromised, and it is not
#     one of the eight: it is here because that CA vouches for six of the 12, so in a file curl reads it is an anchor
#     for all of them. It exists as TWO certificates -- the one the advisory's hosts serve, cross-signed by emSign ECC
#     Root CA - G3 (30:94:02:57...), and a SELF-SIGNED copy (7D:D7:8D:5F...), which is a full anchor for every reader,
#     python3 and the openssl CLI included, with no partial chain needed. Both carry this one key (MEASURED: the same
#     X coordinate), so one entry covers both. The owner's decision #38, 31 Oct 2026: "Yes, add it."
# Each value is the X coordinate of the key's EC point, 48 bytes in lowercase hex as `openssl x509 -text` prints it,
# the same form as EMS_X above, so every encoding of the point matches (compressed, hybrid, explicit parameters).
# Each was derived from the certificate twice, with LibreSSL 3.3.6 and with OpenSSL 4.0.3, and refused if it came out
# as the hash of no input. Apple's file holds none of the seven (MEASURED: no key match among its 128).
# The names are for the lines this prints; the keys are what it matches on.
WKEYS=(
  'emSign Root TLS CA - G3|5f0fdc3fab5716c4be83f5b3061fa090e2efa0015e8637db3e3f0431f41978842fb4894f103a4f2658efd1c17432d740'
  'EM DV TLS CA - G3B|e79ed9c04a9773c4735e51111da85ac2bd5e64ab374b80e12cbc2038ec1e4f0e3b812fc9859e1e67afb04e2f8bc97f74'
  'EM DV TLS CA - G3C|3a7a7862c8c44d324ddd69033a6782c0efeefe4055e68a123fa0371ba3bd9194514ee172a433e3630f02bd188037d9e5'
  'EM OV TLS CA - G3B|73897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cde'
  'EM OV TLS CA - G3C|138251cd52ac9298c1c8aad977321deb97e709bd0b4ca0aca55dc8ad51dcfc9d1589a1597e3a5120e1efd631c63e1835'
  'EM EV TLS CA - G3B|25dba85a64d397da0b1052e9ea546e487befea9c9d9d68a0c5eadcfeef75a69bb5d6fc01f42bfbca6eb40bcd64c0767e'
  'EM EV TLS CA - G3C|2d56e829a6fb82c64a4697d960af951e9067ae91f926d34306da48a8aaeb7869b6a67e6d27426e0442aa03b36e1988df'
)
# Everything of -text but the public key.
KEYTEXT=no_header,no_version,no_serial,no_signame,no_validity,no_subject,no_issuer,no_extensions,no_sigdump,no_aux
# Nothing below runs a command until the traps are set, after the functions: see "The traps" further down.

# The symbolic-link check, before the -f test, which is true for a symbolic link to a regular file. This fix replaces
# the file it is given by renaming a new file over it, and a rename over a link replaces the LINK: $FILE would become
# a file of this script's own, stop following whatever the link points to (an administrator set that link up for a
# reason), and the file it points to would be left exactly as it was. Until 31 Oct 2026 the refusal said the Mac
# would go on reading the old bundle, which is not what happens, and told the reader to run this "against that file"
# without saying how. The way is WARDLATCH_CERT_FILE, so the refusal now prints the command, with the file in it.
# The link's target is named only when every character of it is plain: letters, digits, space and / . _ + @ , : = ~ % -.
# Whoever made the link chose that name, and until r4 it went raw into the command printed below, inside single
# quotes: a name holding a single quote broke out of them, so the command a reader pasted ran something of the link
# maker's choosing, then this fix without WARDLATCH_CERT_FILE; and U+202E or U+2028 in a name reached the terminal
# raw (the round-3 re-read). The script's own path is printed on the same terms.
plain() { case "$1" in ''|*[!A-Za-z0-9\ /._+@,:=~%-]*) return 1 ;; esac; }
linked() {
  local to me
  # The target's bytes, exactly. Until this fix the line and the command below named the WRONG FILE when the target's
  # name ended in a line break: `to=$(readlink "$FILE")` reported a link to "real.pem<LF>" as a link to real.pem, and
  # told the reader to run this again on real.pem -- a decoy sitting beside it (F-6b0-1, round 4's strict audit; only
  # whoever can make the link can do this, which for /etc/ssl is root).
  # readlink cannot be fixed with a sentinel, which is what that finding proposed: MEASURED on this macOS, `readlink`
  # prints a target that does not end in a line break WITH one added and a target that does end in one WITHOUT, so
  # "real.pem" and "real.pem<LF>" both come out as the same 9 bytes. The information is gone inside readlink.
  # /usr/bin/stat -nf '%Y' adds nothing (`-n`: no newline forced), so the two differ by their real byte (8 and 9,
  # MEASURED), and `printf x` holds the end against the command substitution, which drops every trailing line break.
  # `&&` keeps stat's own exit status when it fails, so an unreadable link still gives the empty $to the branches below
  # expect, and nothing false is named. plain() then sees whatever the name really holds.
  to=$(/usr/bin/stat -nf '%Y' "$FILE" 2>/dev/null && printf x) || to=
  to=${to%x}
  case "$to" in /*|'') ;; *) to="$(dirname "$FILE")/$to" ;; esac
  me='<this script>'; case "$0" in *.sh) ! plain "$0" || me=$0 ;; esac
  if [ -z "$to" ] || plain "$to"; then
    echo "UNKNOWN  $FILE is a symbolic link${to:+ to $to}. Nothing changed. Replacing it would replace the link with a"
    echo "         file of this run's own: $FILE would stop following the file it points to, and that file would be left"
    echo "         as it is. To fix the file it points to, run this again with that file named:"
    echo "         WARDLATCH_CERT_FILE='${to:-<the file the link points to>}' bash '$me'"
  else
    echo "UNKNOWN  $FILE is a symbolic link, to a file whose name holds characters this doesn't print. Nothing changed."
    echo "         Replacing it would replace the link with a file of this run's own: $FILE would stop following the"
    echo "         file it points to, and that file would be left as it is. To fix the file it points to, run this again"
    echo "         with WARDLATCH_CERT_FILE set to that file, once you have checked its name (ls -l shows it)."
  fi
  exit 2
}

# 0 = trusts the compromised keys, 60 = refuses them, anything else = the test site didn't answer
# (-q: ignore ~/.curlrc, whose settings could change the answer)
# CURL_SSL_BACKEND=openssl: /usr/bin/curl 8.7.1 is built with BOTH LibreSSL and SecureTransport, and that variable
# picks one at run time. -q keeps ~/.curlrc out; nothing kept the environment out, and these runs happen as the
# person who typed the command, with their environment. Under SecureTransport the --cacert anchors are judged by
# Apple's Security framework, which blocks the eMudhra certificates (19 and 23 Oct 2026) whatever file it is given,
# so the answer stops being about this file at all: MEASURED 31 Oct 2026, a copy of the cleaned file plus
# emSign Root TLS CA - G3 read EXPOSED by default and SAFE with CURL_SSL_BACKEND=secure-transport, while the default
# curl through that same file still loaded the test site. An unknown backend name lands on SecureTransport too, so
# the right value has to be named rather than the variable merely unset. MEASURED here: =openssl selects LibreSSL
# (the handshake reads CAfile: /etc/ssl/cert.pem). The proxy variables are deliberately left alone: they decide how
# the network is reached, not which library judges the chain.
trust() { local r=0; CURL_SSL_BACKEND=openssl /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$TEST_URL" || r=$?; echo "$r"; }
# The advisory's test leaves expire 3 May 2027 01:04:36 UTC (dv-g3b; ov-g3c 01:04:37, ev-g3c-aaa 02:27:42), and
# curl's 60 is CURLE_PEER_FAILED_VERIFICATION, which an expired leaf gives too -- MEASURED on a throwaway pair: an
# expired leaf gives 60 both through a file that trusts its root and through one that does not, the two readings
# this test exists to tell apart. So from that date a 60 would say nothing, and every unfixed Mac would read SAFE
# (the swarm's F-tls-3).
#
# What that argument does NOT cover, and what this date was wrongly used for until 1 Nov 2026: curl's 0. Exit 0
# means the chain verified, and an expired leaf cannot verify -- MEASURED on a loopback CA of our own, four
# readings, one fresh server each: a valid leaf gives 0 through a bundle that trusts its CA and 60 through one
# that does not, and an EXPIRED leaf gives 60 through BOTH. So expiry poisons the 60 and leaves the 0 exactly as
# sound as it ever was, and a 0 from the test site proves exposure on any date whatsoever. Until 1 Nov 2026 this
# date stopped both readings, so a Mac that WAS exposed read SAFE, exit 0, from 3 May 2027 -- and today, on any
# Mac whose clock is dead or years fast, because a date this cannot read counts as past it.
#
# So the date now decides one thing in one place: whether a 60 from the test site may be read as a refusal on the
# already-clean path, which is the one path where no control for the canary's liveness can be built (see there).
# Everywhere else a probe of the file as it WAS is the control, and it does not expire. Nothing anywhere gates
# the 0.
CANARY_EXPIRES=20270503
# Today in UTC as yyyymmdd, or a failure. Nothing but eight digits is accepted: a date command that printed a word
# would otherwise be compared as a number, which `[` reads as an error and `set -e` turns into a silent exit.
today() { local d; d=$(/bin/date -u +%Y%m%d 2>/dev/null) || return 1; case "$d" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) echo "$d" ;; *) return 1 ;; esac; }
# 0 when the test site's own certificate is still valid, so its refusal means something; 1 when it is not, or when
# this Mac's date can't be read. The published one-line test on the Wardlatch page fails the same way, by reading
# an unreadable date as 99999999, and prints UNKNOWN there; it has no file verdict to fall back on, and this does.
canary_live() { local d; d=$(today) || return 1; [ "$d" -lt "$CANARY_EXPIRES" ]; }
# The one line that says why no online reading was taken. $1 is what the file's own state already established.
expired_note() {
  echo "         (The advisory's test site has its own certificate, and that expires on 3 May 2027; this Mac's date"
  echo "         reads $(today 2>/dev/null || echo 'as something this cannot use'), so a refusal there would prove nothing and nothing was read from it.)"
}
# The control, read before any verdict is taken from trust(). 0 = an ordinary website loaded through this same file,
# so the network answers and the file still validates ordinary certificates; anything else and there is no online
# verdict to be had here -- without this, "the test site refused" and "nothing on this network answered" are the
# same reading, and the Mac that most needs this fix is the one whose network is under someone else's control.
# The same library is pinned here as in trust(), for the same reason: a control judged by Apple's Security framework
# and a test judged by LibreSSL would not be about the same thing.
control() { local r=0; CURL_SSL_BACKEND=openssl /usr/bin/curl -q -s -o /dev/null --max-time 15 --cacert "$1" "$CONTROL_URL" || r=$?; echo "$r"; }
# How many lines of $2 match $1. Fails, rather than print a number, if grep could not read the file: a count that
# came back empty was compared as if it were one, and `[` reading "" as a number is an error, not a no.
count() { local n r=0; n=$(grep -c -- "$1" "$2" 2>/dev/null) || r=$?; if [ "$r" -gt 1 ] || [ -z "$n" ]; then return 1; fi; echo "$n"; }
# Certificates are the lines that START with the BEGIN marker. A marker anywhere else in a line stops the run before
# anything is read out of the file (see the checks after the snapshot): LibreSSL reads the file 253 bytes at a time, so
# a marker at byte 253, 506, ... of a longer line starts a certificate it trusts (OpenSSL 3.6.4: byte 254), and this
# script would not see it. Measured 31 Oct 2026, after an earlier change that day (6a36187) counted only markers at the
# start of a line on the model that LibreSSL reads nothing else: a root hidden that way stayed trusted, under SAFE.
certs() { count '^-----BEGIN CERTIFICATE-----' "$1"; }
# How many NUL bytes are in the file $1, counted on BYTES and not on lines, or a failure. Every line-based reader this
# script has cuts a line at its first NUL and drops the rest: macOS's /bin/bash 3.2 `read` ("ab\0cd" comes back as
# "ab", length 2) and awk alike (measured 1 Nov 2026). LibreSSL does not: it reads the file with BIO_gets in 253-byte
# pieces and cuts EACH PIECE at its first NUL, so on a line longer than 253 bytes it reads every piece after the
# first. A certificate block can therefore carry base64 that curl, git, ruby, perl and openssl decode and this script
# never sees, and until 1 Nov 2026 a withdrawn root hidden that way stayed trusted under SAFE, exit 0 (the swarm's
# B-tls-1, reproduced here on 99a7f7d). No earlier check sees it: the BEGIN marker still only ever starts a line, the
# counts agree, and every certificate this does read has a fingerprint and a key, so the completeness gate passes too.
# A length check cannot stand in for this, because awk measures the cut line: on such a file `awk 'length($0)>252'`
# reports no line at all. So the count is taken with tr, on bytes. Apple's own file holds no NUL byte, so refusing
# one costs it nothing.
nuls() { local n r=0; n=$(LC_ALL=C /usr/bin/tr -cd '\000' <"$1" 2>/dev/null | wc -c) || r=$?; n=${n// /}; if [ "$r" -ne 0 ] || [ -z "$n" ]; then return 1; fi; case "$n" in *[!0-9]*) return 1 ;; esac; echo "$n"; }
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
# Reads one certificate (PEM, in $1) and sets $kind: AAA or EMS when it is that withdrawn root, byte for byte by its
# SHA-256 fingerprint; AAA-KEY or EMS-KEY when it is another certificate carrying that root's public key; - for any
# other certificate. One openssl call prints both the fingerprint and the key, decoded: its "pub:" (EC) or "Modulus:"
# (RSA) bytes in hex, which are compared with AAA_N and EMS_X. Returns 1 when openssl couldn't read the certificate, and 2 when what it printed isn't a
# fingerprint and a decoded key -- a key openssl can't decode can't be compared -- so the caller doesn't count it.
classify() {
  local o f k i w
  kind=''
  # Spaces, tabs, colons and line breaks taken out by tr, so the dump's hex digits are joined up, the fingerprint is
  # 64 hex digits, and what follows it is "SubjectPublicKeyInfo...". (Taking them out in bash instead is quadratic in
  # bash 3.2: 26 s for the 128 certificates of macOS 27.2's file, measured 31 Oct 2026.)
  o=$(printf '%s\n' "$1" | /usr/bin/openssl x509 -noout -fingerprint -sha256 -text -certopt "$KEYTEXT" 2>/dev/null | tr -d ' \t\n:') || return 1
  case "$o" in SHA256Fingerprint=*) ;; *) return 2 ;; esac
  f=${o#SHA256Fingerprint=}; k=${f:64}; f=${f:0:64}
  case "$f" in *[!0-9A-F]*) return 2 ;; esac
  [ "${#f}" -eq 64 ] || return 2
  # The key, decoded: "pub" (EC) or "Modulus" (RSA) and its bytes. Nothing else that is printed holds either word.
  case "$k" in SubjectPublicKeyInfo*pub[0-9a-f]*|SubjectPublicKeyInfo*Modulus[0-9a-f]*) ;; *) return 2 ;; esac
  if [ "$f" = "${AAA//:/}" ]; then kind=AAA
  elif [ "$f" = "${EMS//:/}" ]; then kind=EMS
  else
    case "$k" in
      *"$AAA_N"*) kind=AAA-KEY ;;
      *"$EMS_X"*) kind=EMS-KEY ;;
      *) kind=-
         # One of the seven other withdrawn keys (WKEYS): WKEY1 is the first entry, WKEY2 the second, and so on, so
         # the kind carries which key it was without a space or a colon in it -- roots() prints these kinds in a
         # space-separated list and strip() splits that list on spaces and colons.
         i=0
         for w in "${WKEYS[@]}"; do
           i=$((i + 1))
           case "$k" in *"${w#*|}"*) kind="WKEY$i"; break ;; esac
         done ;;
    esac
  fi
}
# The name of WKEYS entry $1 (1, 2, ...), or the empty string if there is no such entry.
wname() { local w=${WKEYS[$(($1 - 1))]:-}; [ -n "$w" ] || return 1; echo "${w%%|*}"; }
# Prints one line for each certificate in $1 that carries a withdrawn root's key: its position (1, 2, ...) and what
# classify() found it to be, AAA, EMS, AAA-KEY or EMS-KEY. Fails -- so the caller says UNKNOWN and changes nothing --
# if any certificate can't be read, if anything openssl printed isn't a fingerprint and a public key, or if the number
# of certificates read that way isn't the number counted: a file this can't fully check is never called clean. That
# last test is the completeness gate, and it is what makes a failure that says nothing count as a failure.
# It reads the file itself, line by line, and hands each certificate to openssl through a pipe: no temporary files and
# no here-strings. Until 31 Oct 2026 the comparison was `grep -qxF <fingerprint> <<<"$ROOTS"`, and macOS's
# /bin/bash 3.2 writes a here-string to a file in /private/var/tmp whatever TMPDIR says. When it couldn't (a sandbox,
# an endpoint agent, a full disk), the grep failed, its failure read as "no match", and every certificate was "not a
# withdrawn root": measured, the run printed SAFE and exited 0 with both roots still in the file.
roots() {
  local n l blk='' inblk='' k=0 nfp=0 r z
  # Before a single line is read: a NUL byte anywhere in the file (see nuls()). Every path that reads this file for
  # withdrawn roots comes through here -- inspect() for the snapshot, the backup in checkbackup() and the re-reads
  # from $FILE, built(), and the `left=$(roots "$tmp")` check on the cleaned file -- so one test here covers them all.
  # Returns 5, which inspect() passes on, so the run can say which refusal this is.
  z=$(nuls "$1") || return 1
  [ "$z" -eq 0 ] || return 5
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
        r=0; classify "$blk" || r=$?
        [ "$r" -ne 1 ] || return 1
        # Not a fingerprint and a key: not counted, so the gate below fails.
        [ "$r" -eq 0 ] || continue
        nfp=$((nfp + 1))
        [ "$kind" = - ] || echo "$k $kind" ;;
      *)
        [ -z "$inblk" ] || blk="$blk
$l" ;;
    esac
  done <"$1" || return 1
  [ -z "$inblk" ] && [ "$k" -eq "$n" ] && [ "$nfp" -eq "$n" ]
}
# Reads $1 as the trust store this run is about, and sets $blocks, $before, $inline and $spec. Returns 0 when it could
# be fully checked; 1 when it couldn't be read; 2 when a line holds -----BEGIN after other text; 3 when a block isn't
# a plain certificate; 4 when a certificate couldn't be read with its fingerprint and key; 5 when the file holds a
# NUL byte, which roots() refuses before it reads a line (nuls()).
inspect() {
  local rr=0
  blocks=$(count '^-----BEGIN ' "$1") && before=$(certs "$1") && inline=$(count '.-----BEGIN' "$1") || return 1
  [ "$inline" -eq 0 ] || return 2
  [ "$blocks" -eq "$before" ] || return 3
  spec=$(roots "$1") || rr=$?
  [ "$rr" -eq 0 ] || { [ "$rr" -eq 5 ] && return 5; return 4; }
}
# The $2-th certificate of $1, from its BEGIN line to its END line, as roots() hands it to openssl.
block() { awk -v k="$2" '/^-----BEGIN CERTIFICATE-----/ { n++ } n == k { print } n == k && /^-----END CERTIFICATE-----/ { exit }' "$1"; }
# Apple's entry for the $2-th certificate of $1 (a withdrawn root; $3 is AAA or EMS) as this Mac's openssl prints it:
# "=== <subject>", the text dump without the key, the signature or the issuer, then the SHA-1 and SHA-256 fingerprint
# lines. Measured on 31 Oct 2026: byte for byte the entry above each of the 128 certificates in macOS 27.2's cert.pem
# (LibreSSL 3.3.6). Where the file's lines are not this -- another openssl's way of printing, or a line someone
# added -- strip() keeps every line above the certificate.
entry() {
  local t r
  t=$(block "$1" "$2") || return 1
  r=$(printf '%s\n' "$t" | /usr/bin/openssl x509 -noout -subject -text -certopt no_pubkey,no_sigdump,no_issuer -sha1 -fingerprint 2>/dev/null) || return 1
  case "$r" in 'subject= '*) ;; *) return 1 ;; esac
  if [ "$3" = AAA ]; then t=$AAA; else t=$EMS; fi
  printf '=== %s\nSHA256 Fingerprint=%s' "${r#subject= }" "$t"
}
# Writes $1 without the certificates listed in $2 ("position:kind ..." as roots() found them). For each one it
# removes exactly these lines, and every other line in the file is kept, whatever it says -- which is true because a
# file holding a NUL byte never reaches here: awk cuts a record at its first NUL, so before 1 Nov 2026 a rewrite cut
# every line that held one, and the sentence below was untrue of exactly those lines (the swarm's F-tls-1; measured:
# Apple's file plus "# admin note: keep\0 this whole line" came out cut short, under a SAFE that said it had removed
# only the roots). roots() now refuses any NUL byte, before anything is written.
#   - its own block, from its -----BEGIN CERTIFICATE----- line to its own -----END CERTIFICATE----- line;
#   - for the root itself (not a certificate found by its key alone),
#     its name, when the name is directly above the block and is that root's: Apple's shape -- "=== <subject>",
#     "Certificate:", the openssl text dump, "SHA1 Fingerprint=" and "SHA256 Fingerprint=", directly above BEGIN --
#     when those lines are, every one of them and nothing else, what this Mac's openssl prints for that certificate
#     (entry()), or mk-ca-bundle's (the name, then a line of "=" exactly as long, directly above BEGIN);
#   - the one empty line directly after the block, the separator Apple writes between blocks. That and Apple's name
#     shape are why this is still byte for byte the advisory's removal on Apple's file.
# Until 31 Oct 2026 a "=== " line anywhere above a removed root started its block, so an administrator's own "=== "
# line above a root they had appended, and every line between it and the certificate, went with the root, and the
# count check could not see it (it counts certificates). Every empty line after a removed root went too, not one.
# After that, until a third read the same day, any indented line between "Certificate:" and the fingerprint lines
# counted as the dump, so an administrator's indented note inside a withdrawn root's entry went with it, under SAFE.
strip() {
  local p e envs
  envs=(WL_STRIP=1)
  # Split on purpose: $2 is "position:kind" pairs, digits, colons, AAA, EMS and -KEY only.
  # shellcheck disable=SC2086
  set -f; set -- "$1" $2; set +f
  for p in "${@:2}"; do
    case "${p#*:}" in AAA|EMS) e=$(entry "$1" "${p%%:*}" "${p#*:}") || e=''; envs+=("WL_ENTRY_${p%%:*}=$e") ;; esac
  done
  # The list again, as one word for awk.
  p="${*:2}"
  env "${envs[@]}" awk -v list="$p" -v aaa="$AAA" -v ems="$EMS" -v aname="$AAA_NAME" -v ename="$EMS_NAME" '
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
        # A certificate found by its key alone is not that root, so no name or description above it names that root.
        if (drop[c] != "AAA" && drop[c] != "EMS") continue
        name = (drop[c] == "AAA") ? aname : ename
        fp = (drop[c] == "AAA") ? aaa : ems
        b = B[c]
        # mk-ca-bundle: the name, then a line of "=" as long as it, directly above the block
        if (b > 2 && L[b - 1] ~ /^=+$/ && L[b - 2] == name && length(L[b - 1]) == length(name)) {
          gone[b - 1] = 1; gone[b - 2] = 1
        }
        # Apple: from the nearest "=== " line above to "SHA256 Fingerprint=<this root>" directly above BEGIN, when
        # those lines are exactly the entry this Mac openssl prints for it (from entry(), in the environment).
        want = ENVIRON["WL_ENTRY_" c]
        if (want != "" && b > 1 && L[b - 1] == "SHA256 Fingerprint=" fp) {
          for (s = b - 1; s >= 1; s--) {
            if (L[s] ~ /^=== /) break
            if (L[s] ~ /^-----(BEGIN|END) /) { s = 0; break }
          }
          if (s >= 1) {
            got = L[s]
            for (j = s + 1; j < b; j++) got = got "\n" L[j]
            if (got == want) for (j = s; j < b; j++) gone[j] = 1
          }
        }
      }
    }
    !(FNR in gone) { print }
    END { if (broken) exit 1 }' "$1" "$1"
}

# The run's state, and the traps' handlers. The checks and the change are made on a snapshot of $FILE, so that they
# are about the same bytes, and the backup must bear the snapshot out (checkbackup()) before anything is replaced.
# HUP, INT and TERM as well as EXIT, which is what the one-line fix on the page traps. An interrupt has to STOP
# this script, and on EXIT alone it did not: measured on 29 Oct 2026 under macOS's /bin/bash 3.2.57, a SIGINT
# arriving while bash waits on a plain foreground command is swallowed, and bash carries on to the next line with
# `set -euo pipefail` in force. Interrupted just before the write, the script went on to replace the file and
# printed SAFE, exit 0, about a run that had been cancelled. (bash does stop if the signal lands inside a command
# substitution, so the old shape failed only some of the time, which is worse.)
new=''        # the file beside $FILE a replacement is built in, while there is one
bnew=''       # the file beside $FILE the backup is copied into, until it has its dated name
writing=''    # set just BEFORE the first file is made beside $FILE: until then this run has written nothing there
published=''  # set once the backup has its dated name
replaced=''   # set once the cleaned file has been renamed over $FILE
orig='' want='' after='' backup='' naaa=0 nems=0 kaaa=0 kems=0 found=0 kind='' why='' step='' meant=''
nwkey=0 wseen='' todrop=0 n=''   # certificates carrying one of the seven other withdrawn keys, which WKEYS they were
snap='' tmp=''  # the two temporary files, once mktemp has named them
SUDO='' DIR=''  # set once $FILE is known to be a file
# The signals the traps below catch (stopped()), and that the run ignores once its answer is in (settled(), stopped()
# itself, and the cleanup at exit). Kept in one place: until r4 three lists of four, and the round-3 re-read found the
# cleanup's list could lose one and no case would see it.
SIGNALS='HUP INT QUIT TERM ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2'
# Every command here ends in `|| true`, and that is load-bearing rather than tidy. Measured on /bin/bash 3.2.57:
# with `set -e` in force, a failing command inside the EXIT trap ends the trap AND overrides the script's exit
# status, so one failed `rm` turned `exit 2` ("couldn't tell") into `exit 1`, which the published exit-code table
# reads as EXPOSED. `return 0` at the end does not help -- errexit ends the function before reaching it.
# strays() is for a file made beside $FILE, or in TMPDIR, whose name was not yet known when the signal came: mktemp
# chooses it, so each carries this run's process id. The traps are set before either temporary file is made, so
# clean() can run before they have names.
clean() { [ -z "$snap" ] || rm -f "$snap" || true; [ -z "$tmp" ] || rm -f "$tmp" || true; [ -z "$new" ] || $SUDO rm -f "$new" || true; new=''; [ -z "$bnew" ] || $SUDO rm -f "$bnew" || true; bnew=''; strays || true; }
strays() {
  local f
  for f in "${TMPDIR:-/tmp}"/wardlatch.$$.*; do
    if [ -e "$f" ] || [ -L "$f" ]; then rm -f "$f" || true; fi
  done
  [ -n "$DIR" ] || return 0
  for f in "$DIR"/.wardlatch-new.$$.* "$DIR"/.wardlatch-backup.$$.*; do
    if [ -e "$f" ] || [ -L "$f" ]; then $SUDO rm -f "$f" || true; fi
  done
}
# A signal. Exit 2, not the conventional 130: 2 is this script's "couldn't tell, read the printed line", and an
# interrupted run reached no verdict, which is the same thing to a fleet tool. The page publishes an exit-code
# table that Jamf, Kandji and Intune policies are built on, and a fourth code in it would be one no policy has a
# branch for. It ALWAYS prints a line, because exit 2 tells the reader to read one.
# What it says about $FILE it reads from $FILE, by SHA-256, against the two files this run knows: the file it read
# and the file it built. Until 31 Oct 2026 it went by a flag set after the rename returned, so a signal between the
# rename and the flag left the file changed and nothing printed, and a signal during the content-mismatch restore
# said "replaced with the cleaned file (removed both withdrawn roots)" about a file holding both of them again.
stopped() {
  local now
  # shellcheck disable=SC2086
  trap '' $SIGNALS
  exec >&3
  clean
  if [ -z "$writing" ]; then
    echo "UNKNOWN  Stopped before this changed anything: nothing was written to $FILE or beside it. Run this again."
    exit 2
  fi
  now=$(sha "$FILE") || now=''
  if [ -n "$want" ] && [ "$now" = "$want" ]; then
    echo "UNKNOWN  Stopped before this could re-test, and $FILE had already been replaced with the cleaned file"
    echo "         ($(removed_phrase), kept $after). It is whole, not half-written. Run this again."
    if [ -n "$published" ]; then
      echo "         Backup: $backup"
      echo "         Undo:   sudo cp -p '$backup' '$FILE'"
    fi
  elif [ -n "$orig" ] && [ "$now" = "$orig" ]; then
    echo "UNKNOWN  Stopped. $FILE is the file this run read, and still holds $(held). Run this again."
    [ -z "$replaced" ] || echo "         This run had replaced it; it holds the original again."
    [ -z "$published" ] || echo "         Backup: $backup (the same file)"
  else
    echo "UNKNOWN  Stopped, and $FILE holds bytes this run didn't build or check: it is neither the file this run read"
    echo "         nor the cleaned file. Find what else wrote to it, then run this again; please report this."
    [ -z "$published" ] || echo "         Backup: $backup (the file as this run read it; it holds $(held))"
  fi
  exit 2
}
# Called once the last reading is in, just before the verdict is printed: from here the run has its answer, and a
# signal is ignored rather than stop it half-way through saying so. Until 31 Oct 2026 a signal here, or during the
# cleanup at exit, ran stopped(), which printed "UNKNOWN  Stopped ..." under the verdict and turned exit 0 or 1 into 2.
# shellcheck disable=SC2086
settled() { trap '' $SIGNALS; }
# The last thing the EXIT trap does, with the status the run was ending with: 0 comes only from a SAFE line and 1 only
# from an EXPOSED one, which sets $meant just before its `exit 1`; every other status is 2. Until r4 a verdict line that
# could not be written (standard output closed, a log file on a full volume) failed under `set -e` and ended the run
# with echo's status, 1, which the published table reads as EXPOSED, after the file was fixed (the round-3 re-read);
# now the line that could not be read ends it with 2, and so does any other command that fails unchecked.
ended() { if { [ "$1" -eq 1 ] && [ "$meant" != 1 ]; } || [ "$1" -gt 2 ]; then exit 2; fi; }
# What this file held of one withdrawn root: $1 copies of the root itself and $2 other certificates with its key, $3
# its name. A certificate found by the key alone is named as that, not as the root: it is not byte for byte the root.
one() {
  local s=$3
  if [ "$1" -eq 0 ]; then
    if [ "$2" -le 1 ]; then echo "a certificate with the key of $3"; else echo "$2 certificates with the key of $3"; fi
    return 0
  fi
  [ "$1" -le 1 ] || s="$1 copies of $3"
  if [ "$2" -eq 1 ]; then s="$s and 1 other certificate with its key"; elif [ "$2" -gt 1 ]; then s="$s and $2 other certificates with its key"; fi
  echo "$s"
}
# The certificates this file held that this fix removes, by name, from what roots() found in it. Copies are counted,
# and so are the certificates found by one of the seven other withdrawn keys: before 1 Nov 2026 this was only ever
# called where at least one withdrawn root had been found, and with neither it would have named emSign ECC Root CA -
# G3 for a file that did not hold it.
held() {
  local s=''
  if [ "$naaa" -gt 0 ]; then s=$(one $((naaa - kaaa)) "$kaaa" "$AAA_NAME"); fi
  if [ "$nems" -gt 0 ]; then s="${s:+$s and }$(one $((nems - kems)) "$kems" "$EMS_NAME")"; fi
  if [ "$nwkey" -gt 0 ]; then s="${s:+$s and }$(wheld)"; fi
  echo "$s"
}
# What this run removed, by name, and nothing it did not establish. Apple added emSign ECC Root CA - G3 after Mojave,
# so every Mac of that era holds ONE of the two, and this says which one was removed and that this FILE did not hold
# the other. Until 31 Oct 2026 it said "removed both withdrawn roots" whenever it removed two certificates -- two
# copies of AAA Certificate Services included -- and "the other was already absent from this Mac", which is a claim
# about a Mac drawn from one file.
wheld() {
  local n s=''
  for n in $wseen; do s="${s:+$s, }$(wname "$n")"; done
  if [ "$nwkey" -eq 1 ]; then echo "a certificate with the key of $s"; else echo "$nwkey certificates with the keys of $s"; fi
}
removed_phrase() {
  if [ "$found" -eq 0 ]; then
    # Nothing but certificates found by one of the seven other withdrawn keys. No withdrawn root was in the file, so
    # this must not say it removed one.
    echo "removed $(held) (this file did not hold either withdrawn root)"
  elif [ "$naaa" -gt 0 ] && [ "$nems" -gt 0 ]; then
    if [ "$found" -eq 2 ] && [ "$((kaaa + kems + nwkey))" -eq 0 ]; then echo "removed both withdrawn roots"; else echo "removed both withdrawn roots ($(held))"; fi
  elif [ "$naaa" -gt 0 ]; then
    echo "removed $(held) (this file did not hold the other withdrawn root, $EMS_NAME)"
  else
    echo "removed $(held) (this file did not hold the other withdrawn root, $AAA_NAME)"
  fi
}
# What a run that could take no online reading did NOT check, as a sentence of its own, directly under the verdict
# and BEFORE the reason. Until 1 Nov 2026 the three uncorroborated SAFE lines said only why no reading was taken
# ("a refusal there would prove nothing", "so nothing was re-tested online") and never what the reading was for.
# That is the only part a reader who is not a TLS engineer needs, and the old wording's defect was its sequencing
# and its subject rather than its truthfulness: a parenthesis indented under a left-aligned verdict, in a block of
# five to seven other indented lines, three of which are housekeeping, tells the eye it may stop reading -- and it
# was the one line that most needed reading (the 1 Nov 2026 review, panel 3).
notchecked() { echo "         Not checked: whether anything else on this Mac still trusts the compromised keys."; }
# What every headline that is NOT SAFE must carry once the file HAS been fixed. A reader who takes a warning for a
# failure and puts the backup back has undone the fix, and that backup holds the withdrawn roots this run removed:
# SECURITY.md names exactly that a vulnerability ("putting the original back puts back the withdrawn roots it
# held"). Until 1 Nov 2026 two of the three UNKNOWN headlines on this path named the backup and said nothing about
# leaving it alone, and the third said only that the script would not revert -- which is about the script, not
# about the reader (the 1 Nov 2026 review, and the owner's instruction of that day).
kept_say() {
  echo "         The file was still fixed. Don't put the backup back: it holds $(held), which is what this removed."
  echo "         Backup: $backup (the file as it was; it holds $(held))"
  trailer UNKNOWN not-tested "$tre" "$todrop" "$after"
}
# How far any verdict here reaches. Until 1 Nov 2026 the already-clean path exited before these four lines, so the
# single answer reached by a user who is ASKING ("am I safe?") rather than fixing -- on a Mac Apple has updated, on
# a Mac they already fixed, on every second run -- was the only answer in the script with no scope at all, while
# every answer reached by changing something carried all four (the 1 Nov 2026 review, panel 2).
scope_lines() {
  echo "         This covers the built-in curl, git, python3 and openssl: the four we measured. Apple's pip3 keeps its"
  echo "         own copy, and we have not measured the built-in perl or ruby. The page has both."
  echo "         For everything else: npx wardlatch@latest"
  echo "         A macOS update puts Apple's original file back: run this again after every update."
}
# One machine-readable line, last, so a fleet can tell a corroborated verdict from an uncorroborated one by choice
# instead of by exit code. The exit-code table is published, on the page whose own section tells administrators to
# wire these codes into Jamf, Kandji or Intune, and it names the no-corroboration cases as 0; moving them would be
# a breaking change to a machine interface. Three distinguishable states were being squeezed through a field whose
# three values are already spoken for, so this adds a channel rather than repurposing that one.
# THE FIELD NAMES AND THE VALUES BELOW ARE A CONTRACT. New values may be added; none may be renamed or reused.
#   verdict  SAFE | EXPOSED | UNKNOWN -- the same word the line starts with
#   scope    file         no online reading was taken, so the verdict is about this file and nothing else
#            file+online  an online reading was taken and is part of the verdict
#   online   refused      the test site refused this file, with a live canary behind that refusal
#            trusted      the test site was accepted through this file
#            not-tested   no online reading was taken
#   reason   why none was taken, or - when one was:
#            control-<n>        an ordinary website did not load through this file (curl <n>)
#            control-<n>-both   ... and did not load before the change either
#            test-<n>           the test site did not answer (curl <n>)
#            canary-dead        the test site refused the file as it WAS, so its refusal proves nothing
#            canary-expired     past the test site's own certificate expiry, where no control can be built
#            clock-unreadable   this Mac's date could not be read, so the expiry cannot be judged
#            revert-content-mismatch   the original was put back; nothing online was read
#   removed  certificates this run took out of the file (0 when it changed nothing)
#   kept     certificates the file holds now
# Printed with every SAFE and every EXPOSED line, and with every UNKNOWN that reached an online reading. An
# UNKNOWN with no trailer is a run that never got as far as a verdict about the file.
trailer() {
  local scope=file
  [ "$2" = not-tested ] || scope=file+online
  echo "         wardlatch: verdict=$1 scope=$scope online=$2 reason=$3 removed=$4 kept=$5"
}
# The reason no online reading could be judged when the control failed. A control exit of 60 is NOT "the network
# didn't answer": it is an ordinary website's certificate REFUSED through the very file this verdict is about,
# which is what a network inspecting TLS looks like. Until 1 Nov 2026 that reading got the same words as a dropped
# connection on both paths, while a network that starts intercepting between the two reads gets exit 2 and a
# paragraph of attack language -- so the permanent interceptor was read more charitably than the transient one
# (the 1 Nov 2026 review, panel 2). The exit codes still differ, and defensibly: a 60 that appeared across the
# write may be about the change this run made, and one that was there all along cannot be. The words no longer do.
# $1 = the control's exit code; $2 = the one before the change, or empty when there was none.
control_note() {
  if [ "$1" -eq 60 ] && { [ -z "$2" ] || [ "$2" -eq 60 ]; }; then
    if [ -n "$2" ]; then
      echo "         (An ordinary website's certificate was refused through this file both before the change (curl $2)"
      echo "         and after it (curl $1). That is not the network failing to answer: something signed that website's"
    else
      echo "         (An ordinary website's certificate was refused through this file (curl $1). That is not the network"
      echo "         failing to answer: something signed that website's"
    fi
    echo "         certificate with a root this file doesn't hold, which is what a network inspecting TLS looks like."
    echo "         Worth finding out what, because it judges every site this Mac visits. Nothing was read from the"
    echo "         advisory's test site.)"
  elif [ -n "$2" ] && { [ "$1" -eq 60 ] || [ "$2" -eq 60 ]; }; then
    # One read refused a certificate and the other did not get that far, so neither "refused" nor "didn't load"
    # describes both. Said as the two readings rather than as one word for them.
    echo "         (An ordinary website's certificate was refused through this file on one of the two reads"
    echo "         (curl 60) and it didn't load at all on the other (curl $([ "$1" -eq 60 ] && echo "$2" || echo "$1")),"
    echo "         so nothing was re-tested online.)"
  elif [ -n "$2" ]; then
    echo "         (An ordinary website didn't load before this change (curl $2) or after it (curl $1), so nothing"
    echo "         was re-tested online.)"
  else
    echo "         (An ordinary website didn't load either (curl $1), so nothing was re-tested online.)"
  fi
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
# later. Returns 1 with $FILE untouched if a step fails, 3 if the copy beside $FILE is not the file expected, 4 if
# $FILE changed (below).
replace() {
  local got expect now
  if [ "$1" = "$tmp" ]; then expect=$want; else expect=$orig; fi
  step=mktemp; new=$($SUDO mktemp "$DIR/.wardlatch-new.$$.XXXXXX" 2>&1) || { why=$new; new=''; return 1; }
  case "$new" in "$DIR"/.wardlatch-new.$$.*) ;; *) why=$new; new=''; return 1 ;; esac
  # The bytes go in through tee's standard input, which this run's own shell opens, as the invoking user: root writes
  # the file it just made and opens nothing else. Until 31 Oct 2026 root copied $1 itself (`sudo cp`), and $1 is the
  # cleaned file in the invoking user's temporary folder: a process running as that user that turned it into a link to
  # a root-only file while the run waited for the password got root to copy that file here and make it readable by
  # everyone (chmod 644, below) before the digest check removed it (the round-3 re-read, with a stand-in sudo). Now a
  # link to a file the user can't read fails here, as the user, and what is made readable is only what the user could
  # already read.
  if step=tee && why=$($SUDO tee "$new" 2>&1 <"$1" >/dev/null) && step=chmod && why=$($SUDO chmod 644 "$new" 2>&1); then
    got=$(sha "$new") || got=''
    if [ "$got" != "$expect" ] || { [ "$1" = "$tmp" ] && ! built "$new"; }; then
      $SUDO rm -f "$new" || true
      new=''
      return 3
    fi
    # The forward write replaces only the file this run read: $FILE's SHA-256 must still be the snapshot's (which the
    # backup has been shown to have), taken here, after the new file is built and checked and immediately before the
    # rename, so what is left between them is this test and the start of mv. Until 31 Oct 2026 the comparison came
    # before this function, and built() alone -- every certificate fingerprinted again, 0.6 s -- lay between it and
    # the rename: a change to $FILE in that time was lost from it and from the backup, under SAFE (the third read).
    # Returns 4, with $FILE untouched.
    if [ "$1" = "$tmp" ]; then
      now=$(sha "$FILE") || now=''
      if [ "$now" != "$orig" ]; then $SUDO rm -f "$new" || true; new=''; return 4; fi
    fi
    step=mv; why=$($SUDO mv "$new" "$FILE" 2>&1) && { new=''; return 0; }
  fi
  $SUDO rm -f "$new" || true
  new=''
  return 1
}
# What a failed command said, for the line that reports it: its own words from stderr ($why), on one line -- sudo's
# when it was sudo that refused ("sudo: 3 incorrect password attempts"), the command's own otherwise -- and, from
# room(), advice about disk space only when those words are about disk space. Until 31 Oct 2026 every failure after
# `sudo -v` was reported with "Check the disk has room (df -h /)", a password refused at a later prompt included, and
# the backup mktemp's words, sudo's among them, went to /dev/null (the third read).
told() {
  local w
  w=$(printf '%s' "$why" | tr '\n' ' '); w=${w% }
  if [ -n "$w" ]; then echo "$1 said: $w"; else echo "$1 failed and said nothing"; fi
}
room() { case "$why" in *'No space left on device'*) echo " Check the disk has room (df -h /)." ;; esac; }
# The checks the cleaned file passed, made again on the file that is about to be renamed into place.
built() { local n l; n=$(certs "$1") && [ "$n" -eq "$after" ] && l=$(roots "$1") && [ -z "$l" ]; }
# Everything above the backup step -- the counts, which certificates are withdrawn roots, and the cleaned file and its
# SHA-256 -- was read from the snapshot in the invoking user's temporary folder, which anything running as that user
# can change between one read and the next. The backup is a copy of $FILE beside it, which only the owner of $FILE can
# change, so before the replacement the backup has to bear all of that out: its SHA-256 is the one the snapshot had
# when it was taken; each certificate this run is about to remove is, in the backup, what roots() found it to be; and
# the backup cleaned the same way is byte for byte the file this run built and checked. Until 31 Oct 2026 nothing did:
# a same-user process that swapped one certificate of the snapshot while it was read, and put the snapshot back before
# the backup was compared with it, landed its own root in $FILE under SAFE, exit 0 (the F1 class; measured by the third
# read, 4 runs of 4). Fails if any of the three doesn't hold.
# The second is the whole reading, made again on the backup: every certificate read, no marker after other text, no
# other kind of block, and exactly the withdrawn roots and copies the snapshot showed, at the same places. Until r4 it
# was each certificate on the removal list, so a root hidden from the reads of the snapshot was never on the list, the
# backup bore the list out, and the one thing left to stop it landing was built() on the new file (the round-3 re-read:
# with built() taken out, SAFE with AAA Certificate Services left in $FILE).
checkbackup() {
  local s=$spec b=$before
  [ "$(sha "$backup")" = "$orig" ] || return 1
  inspect "$backup" || return 1
  { [ "$spec" = "$s" ] && [ "$before" -eq "$b" ]; } || return 1
  [ "$(strip "$backup" "$drop" | sha -)" = "$want" ]
}
# The backup copy failed or isn't the file this run checked: the partial copy is removed and the dated name is never
# used, and the line says which of those happened. Until 31 Oct 2026 the copy was made straight to the dated name,
# so a copy that failed part-way (a full disk, a Ctrl-C) left a truncated file under exactly the name of a good backup.
nobackup() {
  local left=''
  if [ -n "$bnew" ]; then
    if $SUDO rm -f "$bnew" 2>/dev/null; then bnew=''; else left=$bnew; fi
  fi
  echo "UNKNOWN  $1, so nothing was replaced and no backup was kept.$(room)"
  if [ -n "$left" ]; then
    echo "         A partial copy is left at $left: it is not a backup. Delete it."
  else
    echo "         Nothing is left beside $FILE, and this run did not change it."
  fi
  exit 2
}
# The snapshot copy failed. Whether the reading or the writing failed is measured rather than guessed: if $FILE reads
# in full into nothing, the copy failed writing into TMPDIR -- a full or unwritable temporary folder. Until 31 Oct 2026
# every failure here said "Can't read $FILE", a TMPDIR with no room included (the third read, on a 2 MB disk image).
nosnap() {
  if sha "$FILE" >/dev/null; then
    echo "UNKNOWN  Couldn't write a copy of $FILE into ${TMPDIR:-/tmp} ($FILE itself reads in full), so it wasn't"
    echo "         checked. That folder may be full, or not writable by this run. Nothing changed."
  else
    echo "UNKNOWN  Can't read $FILE. Nothing changed."
  fi
  exit 2
}

# The traps, before any command runs: before uname, readlink, id and dirname, and before either temporary file is made.
# Until 31 Oct 2026 they were set after all of those, so a signal in that time -- milliseconds in a real run -- ended
# the run with 130, 143 or 129 and no line, and left the snapshot in TMPDIR (the third read). Between bash starting and
# this line only assignments and function definitions run.
# The cleanup at exit ignores the signals first: it runs after the verdict line, and a signal during it ran stopped(),
# which printed a second line contradicting the first and turned exit 0 or 1 into 2 (the third read). settled() does
# the same from the moment the last reading is in, for the lines of the verdict itself.
# File descriptor 3 is the standard output this run started with, where stopped() writes its line: a signal can arrive
# while standard output is sent somewhere else, as it is into the cleaned file while that is written (`strip ...
# >"$tmp"`), and until r4 the line went into that file, which clean() then deletes, and the run ended with no line (the
# round-3 re-read). A run whose standard output is closed has nowhere to print a line, and ends here, changing nothing.
exec 3>&1 || exit 2
trap 'r=$?; trap "" $SIGNALS; clean; ended "$r"' EXIT
trap stopped HUP INT TERM
# And QUIT, which Ctrl-\ sends: untrapped, it ended the run with 131 and no line, and left a .wardlatch-new.<pid>.*
# file beside $FILE -- root's, in a real run -- that a later run's strays() never removes (the third read).
trap stopped QUIT
# And every other signal whose default is to end a process, except the fault signals (see the header): until r4 USR1,
# ALRM -- what the usual timeout wrapper sends -- and XCPU, among others, ended the run with 158, 142 or 152 and no line,
# after the rename too (the round-3 re-read).
trap stopped ABRT PIPE ALRM XCPU XFSZ VTALRM PROF USR1 USR2

[ "$(uname -s)" = Darwin ] || { echo "This fix is for macOS. On Linux, update the ca-certificates package."; exit 2; }
# The symbolic-link check comes before the -f test, which is true for a link to a file (see linked()).
[ ! -L "$FILE" ] || linked
[ -f "$FILE" ] || { echo "UNKNOWN  $FILE not found. Nothing changed."; exit 2; }
SUDO=sudo; if [ "$(id -u)" -eq 0 ] || { [ -w "$FILE" ] && [ -w "$(dirname "$FILE")" ]; }; then SUDO=; fi
DIR=$(dirname "$FILE")

# The temporary files go where TMPDIR says. `mktemp -t` on macOS ignores TMPDIR for the per-user folder, so until
# 31 Oct 2026 the harness's "no temporary files left behind" check watched a folder this script never wrote to.
# Both are checked: unchecked, `set -e` ended the run with mktemp's own status, 1 -- the published table's EXPOSED.
# Each name carries this run's process id, so strays() can remove one whose name never reached the script.
snap=$(mktemp "${TMPDIR:-/tmp}/wardlatch.$$.XXXXXX" 2>/dev/null) || {
  snap=''
  echo "UNKNOWN  Couldn't make a temporary file in ${TMPDIR:-/tmp} (mktemp failed), so $FILE wasn't read. Nothing changed."
  exit 2
}
tmp=$(mktemp "${TMPDIR:-/tmp}/wardlatch.$$.XXXXXX" 2>/dev/null) || {
  tmp=''
  echo "UNKNOWN  Couldn't make a temporary file in ${TMPDIR:-/tmp} (mktemp failed), so $FILE wasn't read. Nothing changed."
  exit 2
}
cp "$FILE" "$snap" 2>/dev/null || nosnap
orig=$(sha "$snap") || { echo "UNKNOWN  Couldn't take the SHA-256 of $FILE (openssl failed), so it wasn't checked. Nothing changed."; exit 2; }

# curl also trusts other PEM blocks (BEGIN TRUSTED CERTIFICATE, BEGIN X509 CERTIFICATE), which this fix doesn't read.
# This is read before the floor below, and the fingerprints after it, because the floor now has to say whether the
# file holds a withdrawn root: a block this fix cannot read could hold one, so "it holds neither" would otherwise be
# a claim about bytes nobody checked.
r=0; inspect "$snap" || r=$?
case "$r" in
  0) ;;
  1) echo "UNKNOWN  Couldn't read the copy of $FILE this run took, so it wasn't checked. Nothing changed."
     exit 2 ;;
  # A marker after other text on its line. LibreSSL (curl, git, python3, openssl) starts a certificate there when the
  # marker falls at byte 253, 506, ... of the line, OpenSSL 3.6.4 at byte 254, and other readers may differ again, so
  # this fails closed on the marker anywhere but at the start of a line rather than guess which readers see it.
  2) echo "UNKNOWN  $FILE has $inline line(s) where -----BEGIN comes after other text. curl, git, python3 and openssl can"
     echo "         read a certificate from such a line, depending on where the marker falls in it, and this fix can't"
     echo "         check it. Nothing changed. Edit those lines so that -----BEGIN only ever starts a line, then run"
     echo "         this again; or run npx wardlatch@latest to test what this Mac's tools trust."
     exit 2 ;;
  3) echo "UNKNOWN  $FILE holds blocks that aren't plain certificates (such as BEGIN TRUSTED CERTIFICATE), which curl also"
     echo "         trusts and this fix can't check. Nothing changed. Run npx wardlatch@latest to test the Mac's tools."
     exit 2 ;;
  # A NUL byte. curl, git, python3, ruby, perl and openssl read this file 253 bytes at a time and cut each piece at
  # its first NUL, so they read bytes that a reader working line by line -- this script, and awk -- never sees. A
  # withdrawn root can be hidden inside an ordinary-looking certificate block that way, and this fix would call the
  # file clean. Apple's own file holds no NUL byte.
  5) echo "UNKNOWN  $FILE holds a NUL byte, so this fix can't check it. Nothing changed. curl, git, python3, ruby, perl"
     echo "         and openssl read this file 253 bytes at a time and cut each piece at its first NUL, so they can read"
     echo "         a certificate out of bytes that a reader working line by line never sees -- which is how a withdrawn"
     echo "         root can be hidden in a block that looks ordinary. Apple's own file holds no NUL byte. Take them out"
     echo "         and run this again; or run npx wardlatch@latest to test what this Mac's tools trust."
     exit 2 ;;
  *) echo "UNKNOWN  A certificate in $FILE couldn't be read and fingerprinted, so the file wasn't fully checked."
     echo "         Nothing changed."
     exit 2 ;;
esac
drop=''
# Split on purpose: roots() prints "position kind" pairs, digits and AAA, EMS, AAA-KEY, EMS-KEY or WKEY<n> only.
# shellcheck disable=SC2086
set -f; set -- $spec; set +f
while [ "$#" -ge 2 ]; do
  case "$2" in
    AAA) naaa=$((naaa + 1)) ;;
    EMS) nems=$((nems + 1)) ;;
    AAA-KEY) naaa=$((naaa + 1)); kaaa=$((kaaa + 1)) ;;
    EMS-KEY) nems=$((nems + 1)); kems=$((kems + 1)) ;;
    # One of the seven other withdrawn keys. Counted apart from the roots, because what this run says it did has to
    # say which: these are not roots any root programme listed, and most of them are intermediates.
    WKEY[1-9]|WKEY[1-9][0-9])
      n=${2#WKEY}
      wname "$n" >/dev/null || { echo "UNKNOWN  The fingerprint check named a key this doesn't know. Nothing changed; please report this."; exit 2; }
      nwkey=$((nwkey + 1))
      case " $wseen " in *" $n "*) ;; *) wseen="${wseen:+$wseen }$n" ;; esac ;;
    *) echo "UNKNOWN  The fingerprint check returned something this doesn't recognise. Nothing changed; please report this."; exit 2 ;;
  esac
  drop="${drop:+$drop }$1:$2"
  shift 2
done
[ "$#" -eq 0 ] || { echo "UNKNOWN  The fingerprint check returned something this doesn't recognise. Nothing changed; please report this."; exit 2; }
found=$((naaa + nems))
# Everything this run has to remove: the withdrawn roots and the certificates carrying one of the other seven keys.
todrop=$((found + nwkey))

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
  # What this says about $FILE is read from $FILE: the snapshot is in the invoking user's temporary folder, and until r4 a
  # same-user process that swapped it for a small clean bundle made this say "It holds neither withdrawn root" about a
  # file that held both (the round-3 re-read). Still UNKNOWN then, but the line was untrue.
  sb=$before; ss=$spec; r=0; inspect "$FILE" || r=$?
  if [ "$r" -ne 0 ] || [ "$spec" != "$ss" ] || [ "$before" -ne "$sb" ]; then
    echo "UNKNOWN  The copy of $FILE this run read has $sb certificates, but $FILE itself doesn't read the same way now:"
    echo "         it changed while this ran, or something changed the copy in ${TMPDIR:-/tmp}. Nothing changed. Run this again."
    exit 2
  fi
  if [ "$todrop" -eq 0 ]; then
    echo "UNKNOWN  $FILE has $before certificates, fewer than the 50 this expects of a trust store. It holds neither"
    echo "         withdrawn root and no certificate with a compromised key, so this fix has nothing to remove."
    echo "         Something else may be wrong with it; nothing was changed. Run npx wardlatch@latest to test what"
    echo "         this Mac's tools actually trust."
  elif [ "$found" -gt 0 ]; then
    echo "UNKNOWN  $FILE holds only $before certificates, fewer than the 50 this expects of a trust store, so it"
    echo "         looks damaged -- and it still holds a withdrawn root. This fix rebuilds the file it is given and"
    echo "         will not rebuild one that small. Nothing changed."
    echo "         Don't put an older copy of this file back: a copy from before this fix ran holds the withdrawn"
    echo "         roots too. A macOS update restores Apple's own cert.pem -- run this again after one."
  else
    # Small, no withdrawn root, but a certificate carrying one of the other seven keys: a corporate or hand-built
    # bundle, most likely, so this does not call it damaged. It still must not read SAFE.
    echo "UNKNOWN  $FILE holds $(wheld)."
    echo "         curl, git and the built-in perl take such a certificate as a trust anchor for everything that key"
    echo "         signed. It has only $before certificates, fewer than the 50 this expects of a trust store, so this"
    echo "         fix will not rebuild it, and nothing was changed. Take those certificates out of the file"
    echo "         yourself, then run npx wardlatch@latest to test what this Mac trusts."
  fi
  exit 2
fi
if [ "$todrop" -eq 0 ]; then
  # That the file holds neither root is read again from $FILE itself, and the network through $FILE, not through the
  # snapshot: the snapshot is in the invoking user's temporary folder, where anything running as that user can change
  # it between one read and the next, and $FILE is what this verdict is about. Until 31 Oct 2026 a snapshot swapped
  # for a clean copy while it was read made a file holding both roots read SAFE, nothing changed (the F1 class).
  sb=$before; r=0; inspect "$FILE" || r=$?
  if [ "$r" -ne 0 ] || [ -n "$spec" ] || [ "$before" -ne "$sb" ]; then
    echo "UNKNOWN  The copy of $FILE this run read held neither withdrawn root, but $FILE itself doesn't read the same"
    echo "         way now: it changed while this ran, or something changed the copy in ${TMPDIR:-/tmp}. Nothing changed."
    echo "         Run this again."
    exit 2
  fi
  # This is the ONE path in this script where the canary's liveness cannot be controlled for, and so the one place
  # the expiry date still decides anything. The fix path takes its receipt from the file as it was, which still
  # held a withdrawn root and so had to be accepted by the test site; here the file holds neither root and neither
  # does the snapshot, so there is nothing in this run's hands that the test site should accept and nothing to
  # read a control from. Checked and rejected: the script carries the roots' SHA-256 fingerprints and the seven
  # withdrawn public keys, not certificate bytes, so it cannot build a bundle the test site would accept; a
  # previous run's .bak may not exist and is a file this run has established nothing about; and reading the test
  # site's own notAfter is circular, because it is judged against the clock that may be the broken thing. So this
  # is the genuine canaryNotAfter case -- the same position bin/wardlatch.mjs puts a container in, for the same
  # stated reason, that it "has no forced-roots control".
  #
  # The date therefore stays here, and governs the 60 ALONE. Curl's 0 is read on every date, because 0 means the
  # chain verified and an expired leaf cannot verify: it needs no control, it cannot go stale, and until
  # 1 Nov 2026 this path threw it away with the 60 and called an exposed Mac SAFE, exit 0.
  tre='-' tos=not-tested
  c=$(control "$FILE")
  if [ "$c" -ne 0 ]; then
    settled
    tre=control-$c
    echo "SAFE     $FILE no longer holds the two roots. Nothing changed."
    notchecked
    control_note "$c" ''
  else
    r=$(trust "$FILE")
    settled
    case "$r" in
      60) if canary_live; then
            tos=refused
            echo "SAFE     $FILE already refuses the compromised keys. Nothing changed."
          else
            # Past the expiry, or with no readable clock, a 60 here could be the test site's own certificate having
            # expired just as easily as a refusal, and nothing on this path can tell the two apart.
            if today >/dev/null 2>&1; then tre=canary-expired; else tre=clock-unreadable; fi
            echo "SAFE     $FILE holds neither withdrawn root and no certificate with a compromised key. Nothing changed."
            notchecked
            expired_note
          fi ;;
      0)  tos=trusted
          echo "EXPOSED  $FILE holds neither root but still trusts the test site. Nothing changed; please report this."
          trailer EXPOSED trusted - 0 "$before"
          meant=1; exit 1 ;;
      *)  tre=test-$r
          echo "SAFE     $FILE no longer holds the two roots. Nothing changed."
          notchecked
          echo "         (An ordinary website loaded but the test site didn't answer (curl $r), so this wasn't"
          echo "         re-tested online.)" ;;
    esac
  fi
  # And the scope every other SAFE in this script carries. Until 1 Nov 2026 this path exited above these lines, so
  # the answer given to someone ASKING whether their Mac is safe -- after a macOS update, or on a second run -- was
  # the only answer here with no scope, no "for everything else", and no "run this again after every update".
  scope_lines
  trailer SAFE "$tos" "$tre" 0 "$before"
  exit 0
fi

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
elif [ "$after" -ne $((before - todrop)) ]; then
  echo "UNKNOWN  The cleaned file holds $after certificates, not the $((before - todrop)) there should be ($before before, $todrop removed),"
  echo "         so it was not used. Nothing changed; $FILE is as it was. Please report this."
  exit 2
fi

# The control, read BEFORE anything is written, through the file as it is. Without this baseline, the control read
# after the write answers two questions at once -- "does this network answer anything?" and "did the change I just
# made break certificate validation on this Mac?" -- and the script printed SAFE for both, exit 0. That is the same
# two-readings-collapsed-into-one error the control was added to remove, one step further down the script.
c0=$(control "$snap")
# And the POSITIVE CONTROL for the test site itself, read the same way: through the file as it was, which still
# holds what this run is about to remove. The test site's chain anchors in a withdrawn root, so a file that still
# holds one must be accepted -- curl 0 -- and curl 0 is the one answer nothing but a verified chain can produce. So
# a 0 here establishes, at once, that the host answered, that its own certificate is still valid, that nothing is
# answering for it, and that this probe can still tell a file that trusts the compromised keys from one that does
# not. That is a receipt, and unlike a date it cannot go stale: the control is re-earned on every run.
#
# It replaces a dated gate. Until 1 Nov 2026 this path stopped reading the test site altogether from 3 May 2027,
# the day the advisory's leaves expire, because curl's 60 is CURLE_PEER_FAILED_VERIFICATION and an expired leaf
# gives 60 too -- true, and only half the problem. An expired leaf can never give 0 (MEASURED on a throwaway CA on
# loopback: a valid leaf through a trusting bundle gives 0, an expired leaf through the same bundle gives 60), so
# the gate threw away the reading that survives expiry along with the one that doesn't, and a Mac that WAS exposed
# read SAFE, exit 0, from that date -- and from today, because a date this Mac cannot read counted as past it. The
# library uses a date for containers precisely because a container "has no forced-roots control" (bin/wardlatch.mjs);
# here there is one, in hand, for the price of one probe.
#
# What the control gates is the 60 and nothing else. The 0 through the cleaned file is read as EXPOSED on every
# date whatever this says: gating a self-certifying reading is the defect above, and a dead canary is reachable on
# a Mac that is genuinely exposed (a file holding a certificate with one of the seven other withdrawn keys and
# neither root has no anchor for the test site's chain, so its 0 would be suppressed by its own control).
t0=$(trust "$snap")

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
# and in $FILE, both comparisons passed, and the cleaned old snapshot was renamed over it. Measured: an
# administrator's root appended meanwhile was gone from the file, kept only in the backup, and the run said SAFE.
writing=1
# Each privileged step keeps its own words, sudo's among them, for the line that reports it (told(), room()).
bnew=$($SUDO mktemp "$DIR/.wardlatch-backup.$$.XXXXXX" 2>&1) || { why=$bnew; bnew=''; nobackup "Couldn't make a file beside $FILE for the backup ($(told mktemp))"; }
case "$bnew" in "$DIR"/.wardlatch-backup.$$.*) ;; *) why=$bnew; bnew=''; nobackup "Couldn't make a file beside $FILE for the backup ($(told mktemp))" ;; esac
why=$($SUDO cp -p "$FILE" "$bnew" 2>&1) || nobackup "Couldn't copy $FILE to make the backup ($(told cp))"
cmp -s "$bnew" "$snap" || nobackup "The backup copy isn't the file this run checked: $FILE changed while this ran, or the copy went wrong"
why=$($SUDO link "$bnew" "$backup" 2>&1) || nobackup "Couldn't give the backup its dated name, $backup ($(told link))"
published=1
if $SUDO rm -f "$bnew"; then bnew=''; fi
checkbackup || {
  echo "UNKNOWN  The backup of $FILE doesn't bear out what this run read from its copy in ${TMPDIR:-/tmp}: that copy"
  echo "         changed while it was read, or $FILE changed. Nothing was replaced. Run this again."
  echo "         Backup: $backup (a copy of $FILE as it was when the backup was taken)"
  exit 2
}
# And once more, immediately before the rename, inside replace(): the file must still be the file the cleaned file was
# built from, or the replacement would throw away whatever changed it (4).
replace "$tmp" || { r=$?; if [ "$r" -eq 4 ]; then echo "UNKNOWN  $FILE changed while this ran, after the backup was taken, so it was not replaced. Run this again."; echo "         Backup: $backup (the file as this run read it)"; elif [ "$r" -eq 3 ]; then echo "UNKNOWN  The file built beside $FILE isn't the cleaned file this checked, so it was not used and"; echo "         $FILE was not changed. Please report this.  Backup: $backup"; else echo "UNKNOWN  Couldn't replace $FILE ($(told "$step")), so nothing was changed.$(room)"; echo "         Backup: $backup"; fi; exit 2; }
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
    settled
    echo "EXPOSED  What was written to $FILE isn't the file this built and checked, so the original was put back and this"
    echo "         Mac still trusts the compromised keys. Nothing else was changed. Run it again; please report this."
    echo "         Backup: $backup"
    trailer EXPOSED not-tested revert-content-mismatch 0 "$before"
    meant=1; exit 1
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
# There is no date gate on this path any more; t0 above is the control that replaced it, and what it gates is the
# 60 alone. $tre is the reason the trailer prints, $tos what it says about the online reading.
tre='-' tos=not-tested
if c=$(control "$FILE") && [ "$c" -eq 0 ]; then
  # The control loads through the new file: this network answers, and the new file still validates ordinary
  # certificates. So the test host's answer is about the test host, and there is a verdict to be had.
  r=$(trust "$FILE")
  settled
  case "$r" in
    60) if [ "$t0" -eq 0 ]; then
          tos=refused
          echo "SAFE     Fixed. $FILE now refuses the compromised keys: $(removed_phrase), kept $after."
        else
          # The test site refused the file as it WAS -- the file whose withdrawn roots anchor its own chain, which
          # it had to accept for this probe to mean anything. It did not, so this run has not shown the probe can
          # tell the two files apart, and the 60 it gave through the new file is not a refusal anyone has earned.
          # It is the 3 May 2027 case, and also every other way the probe can go quiet while still answering 60.
          tre=canary-dead
          echo "SAFE     Fixed in the file: $(removed_phrase), kept $after."
          notchecked
          echo "         (The advisory's test site answered curl 60 through the new file -- but it answered curl $t0"
          echo "         through the file as it was, which still held $(held) and so"
          echo "         should have been accepted. Its own certificate expires on 3 May 2027, and it may have, or"
          echo "         something may be answering for it. Nothing here shows the test site can still tell a file"
          echo "         that trusts the compromised keys from one that refuses them, so nothing was read from it.)"
        fi ;;
    0)  tos=trusted
        echo "EXPOSED  Fixed in the file ($(removed_phrase), kept $after), but the advisory's test site is"
        echo "         still trusted. Two ordinary things look exactly like this, and both are likelier than"
        echo "         anything stranger. A TLS-inspecting proxy's own root may have been added to this file (or to"
        echo "         whichever file your tools read): the proxy then signs everything, and that site loads"
        echo "         whatever this file holds. Or the test site may have re-issued its certificate from an"
        echo "         ordinary CA, in which case it now loads for everyone and tests nothing. Rule those two out"
        echo "         before you go looking for something else on this Mac that trusts the compromised keys. The"
        echo "         fix was kept either way: putting the original back would put"
        echo "         $(held) back. Please report this."
        echo "         Backup: $backup (the file as it was; it holds $(held))"
        trailer EXPOSED trusted - "$todrop" "$after"
        meant=1; exit 1 ;;
    *)  tre=test-$r
        echo "SAFE     Fixed in the file: $(removed_phrase), kept $after."
        notchecked
        echo "         (The test site didn't answer (curl $r), though an ordinary website loaded, so this wasn't"
        echo "         re-tested online.)" ;;
  esac
elif [ "$c0" -ne 0 ]; then
  settled
  # Nothing loaded before the change either, so this reading is about the network and not about the file. Report,
  # keep the fix, claim nothing online.
  if [ "$c" -eq 60 ] && [ "$c0" -eq 60 ]; then tre=control-60-both; else tre=control-$c0; fi
  echo "SAFE     Fixed in the file: $(removed_phrase), kept $after."
  notchecked
  control_note "$c" "$c0"
else
  settled
  tre=control-$c
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
      kept_say
      exit 2 ;;
    60)
      # The one reading here that is about the change or about the network, and cannot tell which: an ordinary
      # website's certificate verified through the file as it was and is refused through the file this wrote, and
      # the certificates in those two files differ only by the withdrawn roots removed. So either that site's chain
      # needs one of them, or something on this network answered the two requests differently -- and that second
      # reading is what an attack on this Mac looks like. Both say the same thing about what to do, which is why there
      # is no revert here, no revert-reason for one, and no Undo line: putting a withdrawn root back to make a page
      # load is not a repair, and on the second reading it would hand it back to a Mac already under attack.
      echo "UNKNOWN  Fixed in the file ($(removed_phrase), kept $after), but an ordinary website that"
      echo "         loaded through the old file (curl 0) doesn't load through the new one (curl 60), which means its"
      echo "         certificate was refused. The certificates in the two files differ only by $(held), so"
      echo "         either that website's certificate chain needs what was removed, or this network answered the two"
      echo "         requests differently -- and the second is what an attack on this Mac would look like. The fix was"
      echo "         kept either way: this does not put a withdrawn root back on a network reading. Please report this."
      kept_say
      exit 2 ;;
    *)
      echo "UNKNOWN  Fixed in the file ($(removed_phrase), kept $after), but an ordinary website that"
      echo "         loaded through the old file (curl 0) failed through the new one with curl $c, which is neither a"
      echo "         certificate refused (60) nor a network that stopped answering (6, 7, 28). This run"
      echo "         reads nothing into it, and re-tested nothing online. Please report this."
      kept_say
      exit 2 ;;
  esac
fi
echo "         Backup: $backup"
echo "         Undo:   sudo cp -p '$backup' '$FILE'"
scope_lines
trailer SAFE "$tos" "$tre" "$todrop" "$after"
