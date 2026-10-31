# Changelog

What changed in each release of the `wardlatch` package on npm, newest first, written to help you decide whether to
update. Run `npx wardlatch@latest` to get the latest release: a bare `npx wardlatch` runs any copy already installed
globally or in the current project, whatever its version (and npm older than 9.6.5 also reuses a copy npx cached
earlier).

Every release has a signed tag (`v0.1.0` onwards; 0.1.0 to 0.1.2 were tagged afterwards at the commit npm recorded as
each one's `gitHead`), and 0.1.3 onwards were built and attested by the release workflow. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

We found every defect under Security below ourselves, in reviews of our own work from 29 to 31 October 2026, and
each entry ends with the day it was found, the day it was fixed and the fixing commit (dates in US Pacific time, as
the commits record them). None has shipped yet: the last release is 0.1.10, of 27 October, and the Mac fix download
changes only when the site serves the new script and its digest together (SECURITY.md, step 4). The advisories
SECURITY.md promises for them are not open yet; the release that ships them states the day it shipped.

### Security

- **The Mac fix undid itself on what the network said.** After writing the cleaned `/etc/ssl/cert.pem`, it re-tested
  against the advisory's test host and, if that host answered and was trusted (`curl` exit 0), copied the backup back
  over the file. The backup is Apple's original: it holds both withdrawn roots. Anything that can answer for
  `dv-g3b-emudhra.we-have-a-problem.com` on the Mac's network — a transparent proxy, a captive portal, or anyone
  holding the compromised eMudhra keys, which is anyone at all, since they were computed from published certificates —
  could therefore make the fix hand both roots back to the Mac it had just fixed, and that Mac is the one that could
  then never be fixed. The re-test now reports and never reverts: a still-trusted test host prints EXPOSED (exit 1)
  with the fix left in place and the backup named, because the cleaned file holds strictly fewer roots than the
  original and is never the worse of the two. (Until 31 Oct 2026 that line also printed the undo command, which puts
  the withdrawn roots back; it no longer does: below.) The only restore left compares the file it wrote with the file
  it built (`cmp`) and restores the backup when they differ — two local files, no probe result — and declares itself
  in the script as `# wardlatch:revert-reason=content-mismatch`. `test/fix-macos.check.sh` gains a case for each of
  those two, and until 29 Oct 2026 this entry claimed one that did not exist. *For the re-test:* a copy of the script
  whose one network command is a stub, because no real network can be made to answer this way on demand — a network
  that accepts everything must leave the fix in place, and it fails on the 0.1.10 script, which puts both roots back
  on the file. *For the restore:* a copy whose write puts something other than the file the script built into
  `/etc/ssl/cert.pem`, because nothing else can make that happen on demand — the original has to come back, byte for
  byte, with EXPOSED and exit 1 and the backup named. That case also checks that the restore the script declares is
  the only one in it and that `content-mismatch` is the only reason declared, so a revert added later without a
  declaration fails until it has a case of its own. It fails on a copy of the script with the restore line removed,
  which leaves the unchecked bytes in the file. *Found and fixed 29 Oct 2026 (8f10ea4; the restore's case, 6f28ddb).*
- **A verdict was read out of the test host with no control.** `curl` exit 60 was taken as "the host refused us" and
  anything else as "the host didn't answer", when on a network where nothing answers at all both readings are
  worthless; for five days the npm command had a control for every row and the Mac fix had none. It now fetches
  `$CONTROL_URL` (`https://www.apple.com/`, the host the one-line test on the page already uses) through the same
  certificate file first, and reads the test host only if that loads. If it doesn't, a cleaned file is reported as
  fixed *in the file*, with the control's `curl` code, and no online claim is made. A second stubbed case in
  `test/fix-macos.check.sh` covers it: a network where nothing answers must not be read as a refusal. On the 0.1.10
  script it prints "now refuses the compromised keys" about a test nothing performed. *Found and fixed 29 Oct 2026
  (0eba036).*
- **And the control was read only *after* the file had been replaced,** so the same error survived one step further
  down: "this network answers nothing" and "the change I have just made broke certificate validation on this Mac"
  arrived as the same `curl` code, and that branch printed `SAFE Fixed in the file` and exited 0 for both. The
  control is now read through the file as it is, before anything is written, and again after, which makes three
  readings. The control failing both times is the network, reported with both codes and no online claim. The control
  loading both times means the test host's answer is about the test host, and is read as before. The control loading
  before the change and not after it is the one reading that is about the change: it prints UNKNOWN (exit 2) with
  both codes, keeps the fix and reverts nothing. **It deliberately does not revert**, and there is no second
  `wardlatch:revert-reason` for one. The two files differ by exactly the withdrawn roots removed, so either the
  control host's certificate really is issued under one of them, or something on the network is presenting one
  that is — and the second is a MITM producing that pair of readings on purpose, which is the reverting-on-the-
  network door this release closed, re-opened from the side. Both readings say the same thing about what to do:
  eMudhra's private keys are computable from certificates eMudhra published, so trusting that root again to make a
  page load is not a repair. (Since 31 Oct 2026 only a refused certificate, curl 60, gets this reading; a network
  that stopped answering, curl 6, 7 or 28, is read as that, with no word about an attack: below.) Three stubbed cases
  in `test/fix-macos.check.sh` cover the three readings, using a stub whose control answers differ between the two
  calls. On the script before this change, the before-but-not-after case prints `SAFE Fixed in the file` and exits 0.
  *Found and fixed 29 Oct 2026 (86786d7).*
- **The Mac fix rewrote `/etc/ssl/cert.pem` in place, and an interrupt did not stop it.** Two defects in the same
  three lines of a script people run with `sudo`. The write was `cp "$tmp" "$FILE"`, which truncates the file and
  then rewrites it, so a Ctrl-C, a `SIGTERM`, a `sudo` timeout or a power cut during the copy left a partially
  written bundle — and the content-mismatch check below it never ran, because the same interruption ended the
  script. The Mac's built-in `curl`, `git`, `python3` and `openssl` then all read a stump of a certificate file,
  with no TLS working at all, until somebody ran the script again. The replacement is now built in a file beside
  `/etc/ssl/cert.pem` and renamed over it, so an interruption leaves either the old bundle or the new one and never
  half of either. Separately, the script's `trap` was on `EXIT` alone, and — measured under macOS's own
  `/bin/bash` 3.2.57 — that does not stop it: a `SIGINT` arriving while bash waits on a plain foreground command is
  swallowed, and bash carries on to the next line with `set -euo pipefail` in force. Interrupted just before the
  write, the old script went on to replace the file and printed `SAFE … now refuses the compromised keys`, exit 0,
  about a run that had been cancelled. (It stops if the signal lands in a command substitution, so it failed only
  some of the time.) The trap is now `EXIT HUP INT TERM`, which is what the one-line fix on the page has trapped
  since 28 Oct 2026, and it removes the file beside `/etc/ssl/cert.pem` too. (Until 31 Oct this entry said the
  one-liner "has always trapped" it. It had not: from 21 to 28 Oct the page's one-line fix, then the advisory's own
  command, wrote the file through `tee` with no trap.) A run stopped that way exits 2, the code this script already
  uses for "couldn't tell", because an interrupted run reached no verdict and because the exit-code table the Mac
  page publishes for Jamf, Kandji and Intune lists 0, 1 and 2 — a fourth code would be one no fleet policy has a
  branch for. That table's exit-2 row now also names the symbolic link, the unverified backup and the interrupted
  run, and says that some exits 2 follow a change to the file. (Until 31 Oct this entry and the table said one case
  did. There were three: a run stopped after the file was replaced, a restore that could not be made, and a control
  that loaded before the change and not after. The table now names each.) Two cases in `test/fix-macos.check.sh`
  drive copies of the script, because a power cut and an interrupt landing inside a copy cannot be arranged on
  demand: on the script before this change the first leaves a bundle under 50 certificates and the second exits 0
  with a SAFE line. *Found and fixed 29 Oct 2026 (913d1a6).*
- **The Mac fix wrote through a symlinked `/etc/ssl/cert.pem`.** There was no `-L` test in it anywhere, and
  `[ -f "$FILE" ]` is true for a symbolic link to a regular file. On a Mac whose `cert.pem` is a link, the fix
  edited whatever it pointed at, put its dated backup beside the link rather than beside the file, and printed
  SAFE; with the atomic replacement above it would instead have replaced the link and left the Mac's real bundle
  untouched and still trusting the compromised keys. The one-line fix on the page refuses a symbolic link, and the
  site's Record names that refusal as a safety property of ours (CL-42) — the download people run with `sudo` did
  not have it. It now refuses one, names the file to run against instead, changes nothing and exits 2. (Since 31 Oct
  2026 it also gives the true reason and prints the command that fixes that file: below.) *Found and fixed 29 Oct
  2026 (367cf9d).*
- **The Mac fix never checked the backup it told you to restore from.** `cp -p "$FILE" "$backup"` was not verified.
  The script then replaced the file and printed an `Undo:` command naming that backup, and the content-mismatch
  restore uses the same file as the only checked file in the run — so a short or failed backup write made both the
  instruction and the restore wrong, silently. CL-43 was already a correction about that instruction. The backup is
  now compared (`cmp`) with the file it came from before anything is replaced: UNKNOWN, exit 2, nothing changed.
  (Until 31 Oct 2026 the bad copy stayed under the dated backup's name, named in the line with "don't restore from
  it"; since then it is compared with the file the run checked, and a copy that fails or differs is removed, so the
  dated name only ever holds a complete, checked copy: below.) *Found and fixed 29 Oct 2026 (bf9ab0a).*
- **Not every write to `/etc/ssl/cert.pem` was the one-step one, and none of them was checked.** Two defects an
  independent review found in the lines the atomic-write correction above had just rewritten. The
  content-mismatch restore still copied the backup over the file **in place** — the very defect the forward write
  had been redesigned to remove, left live on the one path that runs when something has already gone wrong;
  interrupted mid-restore it left whatever part of the file it had copied by then, and exited 2 printing nothing at
  all. (Until 31 Oct 2026 this entry said "a 500-byte stump of 0 certificates": 500 bytes is where the harness's case
  cuts the file to stand for an interrupt, not something the old script was measured to leave.) And none
  of the writes — the backup, the copy, the chmod, the rename, the restore — was checked, so `set -e` ended the run
  with the failing command's own status, which is **1**, the code the published exit-code table reads as EXPOSED,
  with nothing printed: a full disk, a read-only volume, an expired `sudo` timestamp, a user who is not a sudoer or
  SIP each reported "this Mac still trusts the compromised keys" and gave no line to read. On the restore path the
  failure skipped the EXPOSED block entirely, so the file kept bytes nobody had checked and the backup was never
  named. There is now one function, `replace()`, that writes to the file and is the only thing in the script that
  does: a copy into a file beside it, then a rename over it, every step checked, the file removed and
  `/etc/ssl/cert.pem` untouched if any step fails. The forward write and the restore both go through it, and a
  restore that cannot be made is UNKNOWN (exit 2). The temporary file's name was fixed and recorded before it was
  made, so a signal in that gap no longer stranded one beside the bundle for ever. (Since 31 Oct 2026: a restore that
  cannot be made names the backup and what it holds, and no command to put it back; and the file beside the bundle
  is made by `mktemp`, with a file made before its name reached the script removed by `strays()`: below.) Four
  cases cover it, all rewriting `replace()` by name so they survive the lines around it moving, and each one goes
  red on the shape it replaces. *Found 29 Oct, fixed 30 Oct 2026 (28e07f2).*
- **A run stopped after the file had been replaced said nothing about it.** Exit 2 means "couldn't tell, read the
  printed line", and an interrupt landing in either probe — up to 15 seconds each, which is exactly when somebody
  decides the script has hung — exited 2 with no line at all, after the file had already been changed. The signal
  handler now says the file was replaced, what was removed, and names the backup and the undo command. (It went by
  a flag set after the rename, and on 31 Oct 2026 that turned out to leave a window with no line, and a wrong line
  during a restore: below.) *Found 29 Oct, fixed 30 Oct 2026 (28e07f2).*
- **A failing cleanup could turn UNKNOWN into EXPOSED.** Measured on macOS's own `/bin/bash` 3.2.57: with `set -e`
  in force, a command that fails inside the `EXIT` trap ends the trap *and* overrides the script's exit status. One
  failed `rm` in the cleanup therefore turned `exit 2` into `exit 1` — the code a Jamf, Kandji or Intune policy
  reads as "this Mac still trusts the compromised keys". `return 0` at the end of the function does not help,
  because errexit ends the function before reaching it; every command in the cleanup now ends in `|| true`, which
  is load-bearing and not tidiness. A case asserts a refused run still exits 2 with a deliberately failing
  cleanup, and goes red without the `|| true`. *Found 29 Oct, fixed 30 Oct 2026 (28e07f2).*
- **The Mac fix deleted whatever followed a removed root, printed SAFE and exited 0.** `strip()` set its skip when a
  dropped certificate's block began and cleared it only at the next `###` or `=== ` line, so everything after a
  removed root went with it as far as the next header: a trailing comment, an administrator's note, a line naming
  what follows. None of that is a certificate, so the count of certificates in the rebuilt file still came out at
  exactly `before - found`, the check comparing the counts passed, and the run printed SAFE, exit 0, with those lines
  gone and nothing said about them — damage to `/etc/ssl/cert.pem`, which SECURITY.md puts in scope ("intact or
  correctly cleaned"), under a SAFE line, in the file every built-in TLS client on the Mac reads. (Until 31 Oct 2026
  this entry called it "the false SAFE SECURITY.md puts first". It is the scope's fourth item, damage to the file;
  the roots the SAFE line reported removed had been removed.) Apple's shipped file has a `=== ` line above every
  certificate, so it was never live there; it was live on any hand-concatenated bundle, which is the ordinary case,
  because an administrator appends a corporate
  TLS-inspection root to `/etc/ssl/cert.pem` precisely because `curl` ignores the keychain. A certificate's block
  ends at its `-----END CERTIFICATE-----` line, so that is where the skip is cleared now. It cannot leave part of a
  dropped certificate behind, which would be worse: a block's start line is its own BEGIN line, or the `=== ` line
  above it with no END line in between, so the first END line at or after the start is that certificate's own. The
  one thing after it that may still go is the single empty separator Apple writes between blocks, and only empty
  lines are taken there, which is why the output on Apple's own file is still byte for byte the advisory's removal.
  It also no longer under-skips: a stray `###` line between a dropped root's name line and its BEGIN line cleared
  the old skip mid-block and left that root in the output, which the count check then refused rather than removing
  it (measured on a built bundle before the change). The case in `test/fix-macos.check.sh` is a bundle of all 128
  certificates with a note line after every one of them: all 128 notes must still be there afterwards. Against the
  script as it stood it loses exactly the two that followed the withdrawn roots and still exits 0 with SAFE printed,
  which is the whole defect, so the case asserts that too and cannot pass for the wrong reason. (On 31 Oct 2026 this
  turned out not to be the whole of it: a `=== ` line an administrator wrote above a root they had appended, every
  line between it and the root, and every empty line after a root, not just one, still went with it: below.)
  *Found and fixed 30 Oct 2026 (fe58828).*
- **The second 50-certificate floor could only ever refuse a correct answer, and left those Macs with no way to be
  fixed.** The check on the rebuilt file was one condition — a withdrawn root still in it, a count that does not
  match, or fewer than 50 certificates — behind one line that reported all three as arithmetic: "The cleaned file
  didn't come out as expected (N certificates before, M after)". Two of those three are not count problems, and the
  count printed beside them was right. The floor was the worse one: the check at the top of the script already
  refuses a bundle of fewer than 50 certificates before anything is read out of it, so a run reaching the rebuild
  started at 50 or more and removed 1 or 2 roots, and 50−1, 50−2 and 51−2 are the only results under 50 — every one
  of them exactly `before - found`, which the count check had already proved right. So it could fire only on an
  arithmetically correct rebuild. On a 51-certificate bundle holding both roots it refused 49, the right answer, said
  the arithmetic had failed when it had not, never mentioned a floor, and left that Mac unfixable. It could not have
  caught a mangled rebuild either: one that lost or kept a certificate is caught by the count check, and one that
  changed no count would not be caught by a floor. The floor is gone; the count check and the fingerprint re-read of
  the rebuilt file are the whole of what is checked there, now as three separate reasons, each naming the one thing
  it found and nothing it did not. Three cases, where nothing had reached the branch at all: a 50-certificate bundle
  built from the fixture (which the floor refuses, as arithmetic, with the floor put back); the three reasons, each
  on a copy of the script whose rebuild is changed in the one way that reaches one of them; and
  `test/support/mojave-shapes.sh` shape E, which now matches a floor's own words rather than "UNKNOWN", which almost
  any refusal would have satisfied. *Found and fixed 30 Oct 2026 (9bde951).*
- **A correctly fixed Mac was told to put the withdrawn roots back.** With the floor above gone, a small bundle is
  fixed properly on the first run — 51 certificates holding both roots become 49 — and the second run then hit the
  *entry* floor, fewer than 50 certificates, which said the file "looks damaged" and gave one instruction:
  `Put a backup back (ls $FILE*.bak; sudo cp -p <backup> $FILE)`. That backup is the only one this script ever
  writes: a copy of the file as it was, taken immediately before the removal, holding both withdrawn roots. So the
  one piece of advice a correctly fixed Mac was given was to restore the compromised file, in a script people run as
  root, with nothing said about what that would restore — the same defect as the network-triggered revert removed
  above, reached by another route. It also called a file damaged on no evidence: a 49-certificate bundle may simply
  be short, and this fix has nothing to remove from one that holds neither root. The floor now reads the file before
  it says anything about it. Under the floor and holding **neither** root, with every certificate readable, it
  reports UNKNOWN (exit 2), changes nothing, and gives the facts only: the count it found, that the file holds
  neither withdrawn root so this fix has nothing to remove, and that something else may be wrong with it. It does
  not say the file looks damaged, does not name a backup, and claims nothing about whether the Mac is safe. Under the
  floor and **still holding** a root, it keeps the refusal it had, minus the advice: it says a root is still in the
  file and that an older copy of the file holds the withdrawn roots too, and names the one route that does work (a
  macOS update restores Apple's own `cert.pem`, after which this can be run again). Under the floor with a
  certificate that **cannot be read**, the existing "a certificate in this file couldn't be read" refusal applies,
  which never advised a backup. The BEGIN-TRUSTED-CERTIFICATE check and the fingerprint pass now run before the
  floor, because the floor has to be able to say whether a withdrawn root is in the file and a block this fix cannot
  read could hold one. Three cases in `test/fix-macos.check.sh`, all failing against a copy of the script with the
  floor put back where it stood: a small bundle run twice (the first run's backup is asserted to hold the roots,
  because that is why the old advice was a defect); a small bundle still holding a root; and the existing truncated-
  file case, which asserted only exit 2, the file unchanged and no backup written — all three of which the old
  wording satisfied while telling the reader a file holding neither root looked damaged and sending them to a backup
  holding both. It now also asserts the count is named, that the file holds neither root, and that the output does
  not say "looks damaged", does not name a backup, and does not print SAFE. That took the harness from 27 cases to
  29; it ran 60 at 03d95c9 (31 Oct 2026), and runs 76 after the third read of that day (below). *Found and fixed 30
  Oct 2026 (ab95c59).*

The rest of this section was found by an independent read of this release as it stood on 30 Oct (da8f5c2): five
readers with different lenses, then a refuter for each, who reproduced every finding in a scratch copy before it
counted. Each fix below has a test that fails on da8f5c2 and passes after it.

- **A folder the system refused with EPERM read SAFE, exit 0. Owner decision #32 makes it could-not-be-tested,
  exit 2, whoever owns it.** Commit 6bf0555 (29 Oct, in no release) made an EPERM on a folder whose mode would let the
  run in a "stated gap": a REVIEW line beside the all-clear, outside the counts, exit 0, printed as "1 folder macOS is
  protecting was not searched … sudo cannot open it". Its basis was that EPERM is macOS's privacy protection and
  cannot be forged without root. That was false. An ordinary unprivileged sandbox gives exactly that EPERM —
  `sandbox-exec` with `(deny file-read-data (subpath …))`, the kind coding agents run tools in — and so may a Linux
  security module, fanotify or a FUSE file system, where the same macOS sentence was printed. Measured on macOS 27.2:
  a virtual environment holding the LiteLLM 1.107.0 stealer's install record and `cook.pth`, inside a folder an
  unprivileged profile refuses, read SAFE, exit 0, where the same environment read EXPOSED twice, exit 1, with
  nothing refused. The owner decided on 31 Oct 2026, in his words "Yes, UNKNOWN": any folder Wardlatch could not
  open, EPERM included, is UNKNOWN with exit 2, never SAFE. The reason is the rule the tool exists to keep: a folder
  nobody opened is a folder nobody tested, whoever refused it, and could-not-be-tested is never rounded up to SAFE.
  The row now says the system refused it, with the errno, the mode and the owner (`code` and `basis` in `--json`),
  and whether the folder's own permission bits would have let this run in. On macOS it says that privacy protection
  is a common cause, which allowing the terminal Full Disk Access may lift, and that a sandbox the run is inside, or a
  security tool, refuses the same way and sudo may not lift it; it never claims to know which. Off macOS it names a
  sandbox, a security module or a FUSE mount. A service's folders that refuse with EACCES keep the rule of 22 Oct
  2026, one review line. The cost, judged: on a Mac whose searched folders include ones macOS protects, a run now
  exits 2 until the terminal has Full Disk Access or those folders are left out. Tests in
  `test/independent-read.test.mjs`: the LiteLLM case through an EPERM the test makes, the row's words, and a real
  unprivileged `sandbox-exec` run, which skips and says why when it is already inside a sandbox; the three tests that
  held the stated-gap design were changed for the new rule in a commit of their own, with no code. *Found and fixed
  31 Oct 2026 (3a2660b; the tests, 0663905).*
- **A folder whose full path was too long to open read as "not there", and a site in it read SAFE.**
  `lib/files.mjs` counted ENAMETOOLONG as gone. A folder past PATH_MAX (1,024 bytes on macOS) is there — the walk
  listed its name — and only can't be opened by that path: Rank Math PRO 3.0.123 in a site under four 251-byte
  folders read "SAFE no WordPress installs found in 1 folder searched", exit 0. It is now could-not-be-tested
  whoever owns it, with the path's length and no sudo or Full Disk Access advice, since neither helps. *Found and
  fixed 31 Oct 2026 (8de4832).*
- **A virtual environment, its `site-packages` or a WordPress plugins folder given with `--paths` was never examined,
  and read SAFE.** Every walker tested only the folders inside the one it was given, never that folder itself:
  `--incident litellm-2026-10 --paths <the venv>` read SAFE, exit 0, with `litellm-1.107.0.dist-info` inside it and the
  venv named in the receipt — and giving the venv to `--paths` is what the trust check's own advice for a linked venv
  says to do. `--paths <site>/wp-content/plugins` holding Rank Math PRO 3.0.123 read "SAFE no WordPress installs
  found". A folder given that is a venv, a `site-packages` or `dist-packages` folder, a plugins folder, a
  `wp-content`, or one listed plugin's own folder is now checked as one found below a searched folder is. *Found and
  fixed 31 Oct 2026 (d4d4c71).*
- **A link counted as covered when its target had only been listed, which reopened AUDIT-8 in the default run.** A
  listing is not a walk: a target listed at a walk's depth limit has folders nobody opened, and the installs check's
  quick look round the home folder lists two levels and says nothing about what it can't open. `~/Development/x`
  linking to `~/clients`, with `litellm-1.107.0.dist-info` in `~/clients/client/app/.venv`, read SAFE, exit 0, in a
  run with no `--paths`. A link is now covered only when the same walk went through its target at least as deep as
  following the link would have, and the quick look round the home folder covers nothing. *Found and fixed 31 Oct
  2026 (993688a).*
- **The walkers' depth limits were silent: a site, a venv or a repository one level past one read SAFE.** Each walk
  stops at a depth — 5 levels for WordPress, virtual environments and the trust check, 4 for repositories (the
  workflow, key and header checks) — and said nothing: Rank Math PRO 3.0.123 six levels down read "SAFE no WordPress
  installs found in 1 folder searched", exit 0. Each folder a limit stopped at that holds more to walk (a folder, a
  link or a `.git`) now goes into one UNKNOWN row per check, "N folders are deeper than this check walks (5 levels
  below the folders searched) … Pass --paths with a folder nearer to them", with the folders in `--json` as `paths`;
  there is no all-clear beside it, and the exit code is 2. Judged: on a developer's machine the WordPress and trust
  checks will exit 2 more often, since a project folder often runs deeper than 5 levels outside any repository; that
  is the true answer while the limits stand. *Found and fixed 31 Oct 2026 (4c9bec8).*
- **Folder names hid whole trees with no word, while the documents said no name decides a walk.** The walkers skip
  folders by name — WordPress: `node_modules`, `.git` and `.venv`; repositories: `node_modules`, `.venv` and `venv`;
  virtual environments and the trust check: `node_modules` and `.git` — and an all-clear resting on such a walk never
  said so: Rank Math PRO 3.0.123 under `node_modules/site`, `.venv/site` or `.git/site`, and a workflow under
  `venv/repo`, each read SAFE, exit 0. (The skips predate this release; `docs/ARCHITECTURE.md`'s "no other name …
  decides a walk", and 6bf0555's title, came with it.) The names are still not walked. Every all-clear that rests on
  such a walk now names them on the line under it ("folders named node_modules, .git or .venv, and macOS's own Library
  folders, are not searched") and in `--json` as `notSearched`, and the trust check says the same under its rows. The
  SAFE sentence itself is unchanged, so a script that reads it still does. *Found and fixed 31 Oct 2026 (9ea2375).*
- **The trust check dropped a link to a folder that holds environments, with no row.** It reported a link it
  declined only when the link's name or contents looked like an environment; any other went nowhere: `root/work`
  linking to a volume with a certifi venv in `app/.venv` gave no row of any kind, exit 0. Every other link whose
  target the walk did not walk as deep is now an UNKNOWN row, as in the other checks. *Found and fixed 31 Oct 2026
  (9b0e30c).*
- **A private key committed in DER was skipped with no row, and the repository read SAFE.** The key scan skipped every
  binary file, so a key saved with `openssl rsa -outform der` under a name that isn't a text file's was passed over:
  a repository holding `deploy-key.der` read "SAFE no committed keys found in the files of 1 local repository". A file
  of one DER element (up to 1 MB) is now read by its structure, whatever its name: the shape of a PKCS #1 RSA,
  PKCS #8, encrypted PKCS #8, SEC1 EC or OpenSSL DSA private key, or of a PKCS #12 key store, is a REVIEW finding of
  that type on line 1, shown as "(binary DER, not shown)", never the key. *Found and fixed 31 Oct 2026 (eb357ff).*
- **The header check let a link to a folder root owns ride beside SAFE, and told the person to use sudo for a link to
  their own folder.** It called the repository walk with no list for links, so links fell into the list of folders it
  could not open: a link to a folder root owns went into the service review line beside SAFE, exit 0, while every
  other check makes a link it did not follow UNKNOWN; and a link to a readable folder of the person's own was
  "could not be opened … run Wardlatch with sudo …, or allow your terminal Full Disk Access", which is false twice.
  Both are now link rows, "is a link to a folder somewhere else, so it was not followed". *Found and fixed 31 Oct
  2026 (41c5014).*
- **The Mac fix could print SAFE, exit 0, with both withdrawn roots still in the file.** `roots()` compared each
  fingerprint with `grep -qxF "$fp" <<<"$ROOTS"`, and macOS's `/bin/bash` 3.2 writes every here-string to a file in
  `/private/var/tmp`, whatever `TMPDIR` says. Where that write fails — a sandbox, an endpoint agent's policy, a full
  disk — `grep` fails, and a failure read as "no match": every certificate was "not a withdrawn root". The count of
  roots found came from another here-string, came back empty, and was taken as 0. Measured on the unchanged script
  under a profile refusing writes to `/private/var/tmp`: SAFE, exit 0, on a byte-identical file holding both roots. A
  fingerprint that came back empty or garbled counted as "not a withdrawn root" too. `roots()` now reads the file
  itself and pipes each certificate to `openssl`, with no temporary file and no here-string, and fails — UNKNOWN,
  exit 2, nothing changed — if a certificate can't be read, a block has no END before the next BEGIN, or the
  number of valid fingerprints read is not the number of certificates counted. That last test is the completeness
  gate: it makes an `openssl` that fails without saying so a failure. *Found and fixed 31 Oct 2026 (84d38c2).*
- **A change made while the Mac fix waited for the password was lost, and the run said SAFE.** The "changed while
  this ran" check compared the file with the snapshot *before* the backup step, which is where the interactive run
  waits for the password, and the backup was then compared with the file, not with the snapshot. Measured: an
  administrator's root appended during the wait was gone from the file, kept only in the backup, and the run printed
  SAFE, exit 0. The backup is now compared with the snapshot, and the file with the snapshot again immediately
  before the replacement; a change at either point stops the run, says which, and replaces nothing. *Found and fixed
  31 Oct 2026 (f9b8cc6).*
- **The Mac fix checked the cleaned file in the user's temporary folder, and root copied it into place later.** A
  process running as the same user could change that copy in between — append a withdrawn root, or swap a certificate
  — and the check after the rename compared the file with that same copy, so either landed under SAFE, exit 0. (The
  refuter who checked it judged it defence in depth: such a process can already reach the script's `PATH`.) The cleaned
  file's SHA-256 is now taken from the rebuild itself, and `replace()` checks the file it made beside the bundle, in
  a folder only the bundle's owner can write, before the rename: that digest, and the count and fingerprint checks
  again. *Found and fixed 31 Oct 2026 (5a0c8ff).*
- **A symbolic link planted at the new file's name made the bundle itself a link.** `replace()` built the new file at
  a fixed name, `.wardlatch-new.<pid>`, guarded by `[ ! -e ]`, which is true for a link to nothing: `cp` wrote
  through the link, `mv` put the link where the bundle was, and the run said SAFE, exit 0. It needs write access to
  `/etc/ssl` and a guessed process ID. `mktemp` now makes the file, refusing anything at the name, and `strays()`
  removes a file of this run's made before its name reached the script. *Found and fixed 31 Oct 2026 (24e0145).*
- **The Mac fix removed lines that were not a withdrawn root's own.** `strip()` started a removed root's block at the
  nearest `=== ` line above it, whatever that line was, so an administrator's own `=== ` line above a root they had
  appended, and every line between it and the certificate, went with the root, under SAFE, exit 0; after the END
  line it took every empty line, not the one separator. It now removes exactly each root's own BEGIN-to-END block,
  its name lines only when they sit directly above the block and are that root's (Apple's shape, ending in that
  root's own `SHA256 Fingerprint=` line, or mk-ca-bundle's), and the one empty line after it, and keeps every other
  line. On Apple's own file the result is still byte for byte the advisory's removal. *Found and fixed 31 Oct 2026
  (fbed337).*
- **A backup copy that failed part-way left a truncated file under the backup's dated name.** Measured: a
  245,760-byte stump of the 333,483-byte file, cut mid-certificate, beside "Couldn't write the backup"; and a backup
  that failed the comparison stayed under the dated name too. The copy is now made under a temporary name beside
  the bundle, compared with the snapshot, and only then linked to its dated name, which `link` refuses if anything
  already has it; if any step fails the copy is removed and the line says no backup was kept. *Found and fixed 31 Oct
  2026 (2327680).*
- **A failed `mktemp` ended the Mac fix with exit 1 — EXPOSED, in the published table — and no line.** The two
  `mktemp` calls ran unchecked under `set -e`, before any trap, so a full or unwritable temporary folder ended the
  run with `mktemp`'s own status. Each is now checked: UNKNOWN, "Couldn't make a temporary file … Nothing changed",
  exit 2. *Found and fixed 31 Oct 2026 (a38ee79).*
- **A stopped run could print nothing, or say the file held the cleaned file when it held the original.** The signal
  handler chose its words by a flag set after `replace()` returned, so a signal between the rename and the flag left
  the file replaced, exit 2 and no line; a signal during the content-mismatch restore printed "had already been
  replaced with the cleaned file … It is whole" about a file holding the original, both roots included; and a run
  stopped before it changed anything printed nothing, though exit 2 means "read the printed line". It now always
  prints one, and reads what the file holds from its SHA-256: the cleaned file (with the backup and the undo line),
  the file the run read, or bytes the run did not build or check (with the backup named and no command to put it
  back). (Not always, as a third read the same day found: a signal before the traps were set, or a Ctrl-\, still
  ended the run with no line, and a signal after the verdict added a second one. Since then it prints exactly one
  from its first command on: below.) *Found and fixed 31 Oct 2026 (b6cb1b2).*
- **The Mac fix printed a command that puts the withdrawn roots back, on readings a network can produce.** After a
  certificate refused once the change was made — a reading someone on the network holding a compromised key can
  produce at will — it argued against reverting and then printed an `Undo:` line; with the test site still trusted
  after the fix, another such reading, it did the same; and after a restore that failed it said "Put it back
  yourself, now: sudo cp -p …". Each now names the backup and what it holds, and prints no command to restore it.
  The undo line stays under a SAFE result and under a run stopped after the file was fixed. *Found and fixed 31 Oct
  2026 (3acabb2).*

### Fixed
- **359 of the 361 folders a run called "could not be tested" on one Mac were not gaps at all, and the two
  sentences printed about them were false.** Measured there: `--incident wordpress-plugins-2026-10 --paths ~` gave
  311 could-not-be-tested, 0 safe, exit 2; `--incident github-actions-2026-10 --paths ~` gave 50. Of the 311, **310**
  were symbolic links under `~/.cache/uv/wheels-vN/` that every one resolve into `~/.cache/uv/archive-v0/` — a tree
  the same run had already walked, so the bytes had been read — and every walker pushed every link it declined into
  the gap channel unconditionally. Of the 50, **49** were folders that are perfectly **readable** (`~/.config`,
  `~/.ssh`, `~/.claude`, `~/.local`, `~/.gnupg`): `lib/workflows.mjs` chose not to walk any dot-folder outside a list
  of tool-cache names, and then reported that choice through the channel whose consumers print *"could not be opened,
  so it was not searched: run Wardlatch with sudo"*. The walk never tried to open them, so the sentence was untrue and
  the advice could not work. "I chose not to look" was being written into the channel reserved for "I could not look",
  and the real gaps on that machine were buried under 359 false ones — which is how could-not-be-tested becomes the
  footnote nobody reads, and how a tool that always exits 2 teaches people to write `|| true`.
  Three things changed. **A link whose target the same walk already walked is not a gap** and is dropped
  (`lib/files.mjs` `unwalkedLinks`, compared by `fileId()` — device and inode, the identity that survives links,
  firmlinks and macOS's two spellings of the start-up disk, as AUDIT-25 already uses for roots). Identity, not a path
  prefix: a walk skips `node_modules` and stops at a depth cap, so a target merely *inside* a searched folder may
  never have been opened. (Until 31 Oct 2026 a target the walk had only *listed* counted, which reopened AUDIT-8 in
  the default run; it now has to have been walked as deep as following the link would have: see Security.)
  **Dot-folders are walked like any other folder**, and the `TOOL_CACHES` name list is gone with the `denied?.push()`
  that fed on it; they are almost all readable, so walking them costs a walk and produces no row. That list also held
  `.Trash` and `.Trashes`, so until now `mkdir .Trash` in a project still hid a repository from the workflow and key
  checks — AUDIT-5 only half fixed. And **a folder skipped by its name alone now gets a row when it refuses**, below.
- **A folder macOS is protecting was reported as one that "could not be opened", with advice that cannot work, or
  skipped by its name with nothing recorded at all.** `isSystemFolder()` skipped `.Trash`, `.Trashes`,
  `Photo Booth Library` and `*.photoslibrary` by name, which made `mkdir .Trashes` a hiding place from every walk
  (AUDIT-5) — and it was wrong about the real article too: measured 29 Oct 2026, a modern `*.photoslibrary` has **no
  `Contents` directory**, so the bundle-marker gate returned false for the Photos library and true for Photo Booth
  Library only by accident. Those arms are deleted, and so is the parent gate behind them: those folders are walked
  like any other, and one that refuses is read for what it is. A folder the system refuses with **EPERM** is
  could-not-be-tested, exit 2, whoever owns it (owner decision #32, under Security), and its row carries **a basis a
  reader can check with one `ls -ld`** — the errno, the mode and the owner, in the printed reason and in `--json` —
  and, on macOS, the remedy that may work: privacy protection is a common cause, which allowing the terminal Full
  Disk Access may lift, and a sandbox the run is inside refuses the same way, so the row never claims to know which.
  (From 6bf0555 until 31 Oct 2026 this entry described a different rule, which never shipped: an EPERM on a folder
  whose mode would let the run in was a "stated gap", a REVIEW line beside the all-clear with exit 0, on the claim
  that EPERM "cannot be forged without root". That claim was false, and decision #32 replaced the rule: see
  Security.) Everything else is as it was: a person-owned EACCES stays could-not-be-tested and exit 2, and a
  service's EACCES folder is one review line.
- **An all-clear that sits beside folders a service owns, which it couldn't open, now records how many,** as `gaps`
  next to `searched` in its receipt, so exit 0 reads "I opened these, could not open 3, here they are and here is
  what would open them" rather than listing only what was opened and leaving the reader to assume the rest was
  nothing. *On the Mac that was measured, on 29 Oct 2026:* the first command went from 311 could-not-be-tested to
  **10**, the second from 50 to **11**, and three folders macOS protects (`~/.Trash` and the two photo libraries)
  were stated in one review line. Those figures were measured under the stated-gap rule that decision #32 replaced,
  and before the link, depth-limit and skipped-name corrections under Security; they have not been measured again,
  and they would differ: those three folders are now could-not-be-tested rows, a link whose target was only listed
  now counts, and so does a folder past a depth limit.
- **`test/support/mojave-shapes.sh` was testing the live network while saying it was offline, and one of its cases
  could not fail.** Its stub `curl` was dead code: it put one on `PATH`, but the fix calls `/usr/bin/curl` by
  absolute path on purpose, so `PATH` could never shadow it. All five shapes made live requests to
  `www.apple.com` and to the advisory's test host, each shape's result depended on what the network answered that
  minute, and the branch the file's header claimed to exercise was not the branch taken — shape A printing "now
  refuses the compromised keys" was the proof, since that line cannot be reached through a `curl` that exits 7. It
  now drives a copy of the script with the network command behind `WARDLATCH_CURL`, as
  `test/fix-macos.check.sh` does, and stops with a message if that substitution matches nothing. Shape D looked
  for the fragment `neither` in the output while `shape()` writes its bundle to `run-neither.pem`, which the fix
  echoes in every line: the assertion matched the *filename* and would have passed for any output at all. It now
  looks for what the script prints. And the harness exited 0 however many shapes failed, so it could gate nothing;
  it exits 1 now. Until 31 Oct 2026 it ran in no CI job; it now runs in the mac-fix job on macOS (below).
- **Three more in `test/fix-macos.check.sh`,** landed with the write-path commit above and recorded here.
  `$emsign` was assigned only if a certificate matched the emSign fingerprint, inside a block guarded by "this
  bundle holds a withdrawn root" — which an AAA-only bundle satisfies — so on exactly the Mojave-era shape the
  sibling harness exists for, the suite died with `emsign: unbound variable` instead of reporting; it now says
  which root the bundle is missing and why the case cannot run. The byte-for-byte comparison with the advisory's
  own removal sits behind two conditions and could silently not run inside a case that still printed ok; it now
  says when it is skipped and why. And the guard on the curl stub only asserted that the substitution had changed
  *something*, so it would have passed with one call site left reaching the real network — which is how the
  sibling harness came to be wrong; it now counts every occurrence and requires all of them behind the stub.
- **The Mac fix's own harness read the machine's live `/etc/ssl/cert.pem`,** so its green depended on the Mac
  running it being unfixed. `test/fix-macos.check.sh` took its bundle from `${1:-/etc/ssl/cert.pem}` while every
  removal case and every network case sits inside `if [ "$found" -gt 0 ]`: on an already-fixed Mac, or on CI's
  `macos-latest` the day Apple ships a fixed bundle, six of its cases skipped with a NOTE and the suite still
  exited 0. It now defaults to the vendored unfixed fixture `test/support/fixtures/macos-27.2-cert.pem`, which
  `test/support/mojave-shapes.sh` was moved to in this same release for the same reason; a bundle holding neither
  withdrawn root is a failure rather than a NOTE, every case counts itself, and the run prints and checks the
  total, so a case that stops running cannot pass as silence. It counted 20 cases when this landed, 60 at 03d95c9 (31
  Oct 2026), and 76 after the third read of that day (below).
- **"Something other than this file is trusting the compromised keys" misdiagnosed the two likeliest causes.** When
  the fix has removed both roots and the advisory's test host is still trusted, two ordinary things look exactly
  like that: a TLS-inspecting proxy's own root added to the certificate file, which makes the proxy sign everything
  including that host; or the test host re-issuing its certificate from an ordinary CA, which makes it load for
  everyone and test nothing. The old wording sent an administrator hunting for something else on their own Mac. It
  now names both and says to rule them out first; the verdict, the exit code and the rule that the fix is kept are
  unchanged. `removed_phrase()` also took an argument it never read, at five call sites, and no longer does.


- **The Mac fix told the user it covers `perl` and `ruby`.** Its last lines named "the built-in curl, git, python3,
  openssl, perl and ruby", while the Wardlatch Mac FAQ says in as many words that we tested the first four and treat
  perl and ruby as unmeasured by us. The advisory named them on 21 Oct 2026 and has since narrowed its macOS section
  back. The script is the artefact people run with `sudo`, so it is the worst place to carry an assurance we disclaim
  elsewhere: it now names the four we measured and says the other two are not among them.

These were found by the same independent read of 31 Oct 2026, and each fix has a test that fails on da8f5c2:

- **`mandatoryRefusal()` misread a folder's permission bits, and its test of them could be deleted with no test
  failing.** The others' bits counted for the folder's owner, whom the system judges by the owner's bits alone, so a
  folder of mode 0005 that its owner cannot list was said to be one whose "permission bits would let this run in";
  and every test handed it EACCES, which returns before the mode is read, so replacing the test with `return true`
  left the whole suite green. It now reads the bits the system applies — the owner's for the owner, the group's for a
  member of the group, the others' for everyone else (ACLs are not read) — and since decision #32 it decides only
  whether a row says that clause, never the exit code. (be137cb)
- **A DER certificate was could-not-be-tested for ever, as "a text file that reads as binary".** A tracked `.crt`,
  `.pem` or `.key` holding a NUL byte in its first 8 KB was UNKNOWN with "it is named as a text file but reads as
  binary", so a repository with a DER fixture exited 2 with no way to clear it, and the sentence was untrue. A file
  with an X.509 certificate's DER shape holds no secret and now makes no row; a binary file under a text file's name
  that is neither a DER key nor a certificate is still UNKNOWN, with a true sentence. (a2480f1)
- **A link to a repository or a virtual environment the same walk had checked was could-not-be-tested, and the
  advice printed could not clear it.** A found repository and a probed environment were never recorded as walked,
  so `current` linking to `proj` was "a link to a folder somewhere else" beside `proj`'s own clean row, exit 2, and
  passing both to `--paths`, as the line advised, changed nothing. A found repository, a probed environment and a
  venv the installs check reads from a searched folder now count as walked whole. (8e13a0b)
- **Every clean Rank Math PRO install read could-not-be-tested: the indicator search would not read a `readme.txt`.**
  It read only code files, skipped pictures, fonts and archives, and reported every other file — `readme.txt`, a
  `.pot`, `.json`, `LICENSE` — as not searched, so a clean site read SAFE for the plugin and UNKNOWN for the search,
  exit 2, with no remedy. Every file that isn't a picture, font, style sheet, source map (`.map`), archive, media
  file, document, translation file (`.mo`, `.po`) or `.lock` file is now searched (a `.min.js` file is searched, as
  code), within the same caps (4,000 files of under 2 MB, 12 levels deep; what a cap leaves out is still UNKNOWN).
  The files of those kinds are passed over with no row. (1c6a8cd)
- **The installs check's quick look round the home folder made every link it declined could-not-be-tested.** That
  look says nothing about a folder it can't open, by design, but reported every link: `~/OneDrive` linking into
  `~/Library/CloudStorage`, as cloud-drive clients make it, made every LiteLLM run exit 2, whatever `--paths` named.
  It now reports no link, as it reports no folder it can't open; a link below a searched folder is reported as
  before. (e586fb2)
- **The Mac fix gave a network that stopped answering the reading for an attack.** When the control loaded before
  the change and not after it, every failure got the reading for a refused certificate — the two files differ only
  by the withdrawn roots, so the site's certificate needs one, or someone is presenting one, "and the second is what
  an attack on this Mac would look like". curl 6 (a name that didn't resolve), 7 (no connection) and 28 (no answer
  in time) fail before or without any certificate being refused. Those three now print "this network stopped
  answering", with what each code means and nothing said about the change; only curl 60 gets the certificate
  reading; any other code is given as it is, and the run says it reads nothing into it. All exit 2 with the fix
  kept. (eefd67b)
- **What the Mac fix said it removed was not what the file held.** On a bundle holding one root, as every Mac of the
  Mojave era does, it said "removed 1 of the 2 withdrawn roots; the other was already absent from this Mac", a claim
  about a Mac drawn from one file; it said "removed both withdrawn roots" for two copies of AAA Certificate Services;
  and its reading of a refused certificate named AAA Certificate Services on a file that never held it. It now names
  what it removed, copies counted — "removed AAA Certificate Services (this file did not hold the other withdrawn
  root, emSign ECC Root CA - G3)", and the mirror — and the other readings name what the file held. (af351db)
- **A comment that mentions the BEGIN marker made a bundle the Mac fix could never fix.** A line such as "paste each
  certificate from its -----BEGIN CERTIFICATE----- line …" counted as a certificate that couldn't be read, so the run
  said UNKNOWN, exit 2, on a bundle the Mac's LibreSSL reads without complaint. A certificate now begins only at a line
  that starts with the marker, which is all LibreSSL reads as one. (6a36187)
- **The Mac fix's refusal of a symlinked `/etc/ssl/cert.pem` gave an untrue reason, and advice with no way to follow
  it.** It said replacing the link would leave the file the Mac reads as it is; in fact the rename would replace the
  link with a file of the script's own, so `/etc/ssl/cert.pem` would stop following the file an administrator linked
  it to, and that file would be left as it was. And it said to run the fix against that file without saying how. It
  now gives that reason, names the file the link points to, and prints the command:
  `WARDLATCH_CERT_FILE='<that file>' bash '<this script>'`. (ca51288)
- **A refused `sudo` was reported as a full disk.** The first `sudo` call was the backup copy, where the interactive
  run asks for the password, so a wrong password three times or no answer in time printed "Couldn't write the
  backup … Check the disk has room". The fix now asks for the privilege on its own first (`sudo -v`), and if that
  fails says so: "sudo didn't give this run the privilege to write <file> (sudo -v failed), so nothing was changed",
  exit 2. (419ab68)
- **The Mac fix made its temporary files where macOS chose, not where `TMPDIR` says.** `mktemp -t` on macOS uses the
  per-user temporary folder and ignores `TMPDIR`, so the harness's check that no temporary file was left behind,
  which watches the `TMPDIR` it sets, watched a folder the fix never wrote to and could not fail. They are now made
  with `mktemp "${TMPDIR:-/tmp}/wardlatch.XXXXXX"`. (bd82282)
- **The Mac fix's header said things the script did not do.** It had a sentence with words missing ("so an
  interruption leaves or the new one"), said the script "never tells you to restore a backup" while it printed
  "Put it back yourself, now", gave the old reason for refusing a link, said it refuses to replace a file that changed
  meanwhile on a path where it did not, and promised two network readings that curl 6, 7 and 28 merged. It now says
  what the script does, including that every exit on macOS prints a SAFE, EXPOSED or UNKNOWN line (which held from
  the script's first command on only once the fixes for the third read of 31 Oct set the traps first: below). (e9036f8)

### Development (no code in the package changes)

- **`test/fix-macos.check.sh` ran 60 cases at 03d95c9 (31 Oct 2026), where it ran 29** (76 after the third read of
  that day: below). Thirty new cases for what the
  independent read found in the Mac fix, and one for `strays()`; stand-ins for `cp`, `mv`, `mktemp`, `chmod` and
  `sudo` on `PATH` make a copy fail part-way, a rename pause or a file change in mid run (the real `sudo` never runs).
  Every run on macOS must now print a line starting SAFE, EXPOSED or UNKNOWN. Assertions that were wrong were
  corrected, among them ones that required a command putting the withdrawn roots back.
  One case, `heredoc-trigger`, applies a sandbox profile of its own, so when the harness itself runs inside a sandbox
  (`WL_NESTED_SANDBOX=1`) it is named NOT RUN rather than counted. The header no longer says the harness needs the
  network: it never did, and every case passes with none. (67741a7, 37ef37e)
- **`test/support/mojave-shapes.sh` runs in CI**, in the mac-fix job on macOS, offline, and fails if any shape
  misbehaves; it writes under `TMPDIR`, not a fixed `/tmp`, and shapes B and C assert the root removed by name instead
  of "the other was already absent". CI pinned the Mac fix's SHA-256 after this round,
  `7d0640b49b63b5964cb96aecca474446d4cac5884cb10f147eb627beb7f66cd1`, and pins
  `98f8d58cadcdde8802451f3993e3030c5dad24a65d25777956593220b572bc39` since the third read (below). (67741a7, 2f060fc)
- **`test/support/errno-mechanisms.mjs` exited 0 without measuring, and counted a failed setup as a claim that
  holds.** Its exit code is its verdict, and a run that found no folder macOS protects said the half of the rule about
  them was unverified and still exited 0. A claim whose setup could not be applied is now UNMEASURED, counted apart,
  and so is the half about folders macOS protects when there are none to measure; it exits 0 only when every claim
  was measured and held, 1 when one
  broke, and 2 when nothing broke but something was not measured. Since decision #32 it also measures the claim that
  decision rests on: an unprivileged `sandbox-exec` profile gives EPERM on a folder of mode 0755 owned by the person
  running (UNMEASURED inside another sandbox, where a profile can't be applied). (10604ca)
- **A test now holds the "not found on PATH" all-clear when a `PATH` folder no longer exists.** A planted bug that
  dropped the filter keeping a missing folder out of the receipt turned that all-clear into "UNKNOWN internal error",
  and no test failed. The code was right; the test was missing. (e7f89a8)
- **Two test comments said nothing unprivileged could produce an EPERM.** An unprivileged `sandbox-exec` profile
  does, which is why decision #32 was needed; the comments now say so. (36aaf86)

## [0.1.10] - 2026-10-27

### Security

- **The Mac fix (`fix/fix-macos.sh`) could say SAFE for a file that still trusted the leaked eMudhra keys.** It found
  the two roots by their `=== …/CN=` name lines. Some copies of `/etc/ssl/cert.pem` (on some managed Macs) have no
  name lines, so it found neither root and removed nothing. If the advisory's test site then answered, it printed
  EXPOSED (exit 1) and changed nothing; if the site didn't answer, it printed "SAFE … no longer holds the two roots"
  (exit 0) for a file that still trusted the keys. It now finds the two roots by their SHA-256 fingerprints, removes
  them whether or not the file has name lines (on Apple's file, byte for byte the advisory's removal, as before), and
  refuses a file with a certificate it can't read (UNKNOWN, exit 2, nothing changed). It also refuses a file holding
  blocks curl trusts but the fix doesn't read (`BEGIN TRUSTED CERTIFICATE`, `BEGIN X509 CERTIFICATE`): an emSign root
  appended in that form would otherwise have read SAFE with the test site unreachable. It works on a snapshot of the
  file and won't replace it if it changed meanwhile, it refuses a file it can't read, and its re-test ignores
  `~/.curlrc` (`curl -q`). `test/fix-macos.check.sh` gains the cases, counts the roots by fingerprint, and checks
  that each run prints nothing on stderr and leaves no temporary files; the new cases fail on the old script. The
  download on www.deimoscore.com changes with it (SHA-256 `50e1e41d…21b1`). The advisory's own one-line command has
  the same blind spot: on a file with no name lines it removes nothing.
- The Mac fix now says that a macOS update puts Apple's original file back (macOS 26.7.2 did, on 27 Oct 2026), so it
  should be run again after every update; its last line says `npx wardlatch@latest`, and it names the tools the file
  covers (the built-in curl, git, python3, openssl, perl and ruby) and that Apple's `pip3` has its own copy.

### Fixed

- **The workflow review read SAFE without having read every workflow in the window, in two ways (0.1.0 to 0.1.9).**
  Both came from giving git the window's start with `git log --since`.
  - *The start was a bare date.* The `github-actions-2026-10` incident gave the window's start as `2026-09-01`, passed
    to git as it was, and git reads a bare date as that day at the current time of day, in the zone git runs in: up
    to 0.1.8 the zone of the `TZ` Wardlatch was started with (the machine's when `TZ` was unset), which git got with
    the rest of the caller's environment, and in 0.1.9, which gives git no `TZ`, the machine's. So the window began on
    1 Sep at the hour the check ran: a workflow committed on 31 Aug, or on 1 Sep before that hour, was not read, and
    with nothing else found the review said "no workflow files added since 2026-09-01", SAFE, exit code 0. The sources
    say to check from 31 Aug (The Hacker News and StepSecurity, with no time zone), and GitGuardian reports a commit
    through the same compromised account at 00:30 UTC on 30 Aug. No test had a commit near the start of the window.
  - *git stopped reading at a back-dated commit.* Given `--since`, git stops following a line of history at the first
    commit dated before the start (its walk drops that commit before queueing its parents; only `--since-as-filter`,
    git 2.37 and later, doesn't). Whoever makes a commit sets its date, so one commit dated before the window, on top
    of a branch, hid every workflow added beneath it, however those were dated: on 0.1.9's code with git 2.54, a
    workflow committed on 10 Oct with a commit dated 1 Jan 2025 on top read SAFE, exit code 0; one beneath a
    back-dated commit with another workflow above it was left out; and a workflow on a side branch behind a
    back-dated commit, merged inside the window and the branch deleted, read SAFE. 0.1.9's known limits named this
    only for a later commit made on a machine with a wrong clock.
  - Also found while fixing this, each checked on 0.1.9's code with git 2.54. A commit whose committer date git can't
    read, on top of a workflow, did the same as a back-dated one (git takes it as 1970): SAFE. A workflow added on a
    side branch and removed again before the merge, all inside the window, read SAFE: given a path, `git log` follows
    only the parent a merge's files match and passed the side branch by. In a shallow clone cut inside the window, a
    workflow added and removed again below the cut was never seen (SAFE), and a workflow still there at the cut was
    listed as added by the cut commit, at that commit's date. Not a miss in 0.1.9: a replace ref (`refs/replace/`)
    couldn't put another commit in place of a workflow's commit (`GIT_NO_REPLACE_OBJECTS=1`, since 0.1.7; the commit
    the ref points to is read as one more commit), and a `.git/info/grafts` file wasn't read
    (`GIT_GRAFT_FILE=/dev/null`, in 0.1.9); both still hold.
  - The window now starts at 30 Aug 2026 00:00 UTC (`"since": "2026-08-30T00:00:00Z"`, with its sources in
    `sinceSource`). The review takes only an explicit UTC instant (`YYYY-MM-DDTHH:MM:SSZ`); anything else is
    UNKNOWN, never SAFE.
  - git gets no date at all. `git log --all --format='%H %ct'` lists every commit any branch, tag or other ref leads
    to, with its committer time in seconds since 1970, and the review keeps those on or after the start by comparing
    whole numbers in its own code. Then `git log --no-walk=unsorted --stdin` lists the workflow files that exactly
    those commits added: no walk, so no side branch is passed by, and only those commits are compared with their
    parents (a treeless partial clone with nothing in the window needs no tree, and reads SAFE as before).
    A committer time git prints that isn't a plain whole number (git prints none for a date it can't read) makes the
    repository UNKNOWN, never a commit left out. `--since-as-filter` would have kept the date in git, but needs git
    2.37, and Ubuntu 22.04 ships 2.34.1: every repository there would have read UNKNOWN.
  - A shallow repository is UNKNOWN, wherever its history is cut: "its history is cut (a shallow repository; the
    newest cut is commit …, dated 10 Oct 2026 12:00 UTC), so workflows added below the cut can't be seen: run git
    fetch --unshallow, then run again". Shallow means `git rev-parse --is-shallow-repository` says `true`, or the
    shallow file git reads (`git rev-parse --git-path shallow`) is there and not empty; one Wardlatch can't read is
    UNKNOWN too. A cut commit's date is no sign that the window is all there, because whoever makes a commit sets its
    date: an earlier cut of this fix read a history cut before the start as whole, so a `--depth 1` clone of a tip
    dated 2025, over a workflow committed on 5 Sep 2026, read SAFE, exit code 0, with the workflow file in the clone's
    own tree. A shallow file can also be written into a full repository, and git then reads nothing below the commits
    it names.
  - The SAFE line names the instant and the date it compares: "no workflow files added in commits dated on or after
    30 Aug 2026 00:00 UTC (committer date) in N local repositories". The date a review line shows is the commit's
    committer date in UTC, the date of the time the review compares: a commit made at 30 Aug 2026 00:00 UTC from
    UTC-7, where it was still 29 Aug, shows 2026-08-30. Up to 0.1.9 the line showed the author date, and an earlier cut
    of this fix the committer date in the commit's own zone.
  - The WordPress check's `addedSince` was already an explicit UTC instant; a test now holds the start of every
    incident's window to one.
  - *A file added more than once was listed at one commit (0.1.0 to 0.1.9, and this fix up to 3cff5c5).* The review
    kept one line per workflow file, at the earliest commit in the window that added it. A file added, deleted and
    added again with other contents was listed once, at the first commit: Alice adds `.github/workflows/ci.yml` on
    5 Sep and deletes it the next day, Mallory adds `ci.yml` again on 8 Oct, and the review showed only "added …
    2026-09-05 Alice". It now lists every commit in the window that added each workflow file, one REVIEW line (and one
    `--json` row, with the same `file` and `commit` fields) per file and commit, newest first: "added 4123d9f
    2026-10-08 Mallory", then "added 3fc2679 2026-09-05 Alice". With nothing added in the window, the SAFE line is
    unchanged.
  - Still not covered: a workflow whose own commit is dated before 30 Aug 2026 isn't listed, because whoever makes a
    commit sets its date (ASSURANCE_CASE.md, section 4). And a change to a workflow file that already existed isn't
    listed; the check lists added files, as the campaign added them: a commit that only changes a workflow committed
    before the window reads SAFE.
  - **What to do:** if 0.1.0 to 0.1.9 said SAFE for `github-actions-2026-10`, run a release with this fix again, or
    paste this line at the top folder of each repository, in a POSIX shell such as bash or zsh (it doesn't run as
    pasted in PowerShell or cmd). It has no date in it (given one, git stops reading a branch at the first commit
    dated before it) and reads what the review reads, in one command:
    `TZ=UTC GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL=none git --no-pager --work-tree=. --no-replace-objects -c core.commitGraph=false -c advice.graftFileDeprecated=true log --all --full-history --root --no-renames --diff-merges=combined --diff-filter=A --name-only --no-show-signature --date=iso-strict-local --format='%h %ct %cd %an' -- .github/workflows`
    It lists every workflow file that any commit of any branch, tag or other ref added, each under its commit's hash,
    committer time in seconds since 1970 (`%ct`), committer date in UTC (for convenience only) and author, whatever
    the date; a file added, deleted and added again is listed under each commit that added it, as the review lists
    it. **Review every line whose number (the commit time, in seconds) is 1788048000 or more, or isn't a plain
    number.** 1788048000 is the start, 2026-08-30T00:00:00Z. Compare that one integer and ignore the date text: for
    committer times too far in the future for git to turn into a date, git prints 1970-01-01T00:00:00Z or even a
    negative year, and those commits are in the window too. A line with no number and no date (three spaces after
    its hash) has a committer date git can't read: count it as in the window as well (the review reads the second
    kind UNKNOWN). As in the review, paths are read from the top of the folder the line runs in (`--work-tree=.`),
    whatever the repository's own `core.worktree` says (set to a folder above the repository, it made git read
    `.github/workflows` from the repository's place inside that folder, and the line up to ffacde4 listed nothing),
    a replace ref doesn't put another commit in a commit's place, a commit-graph
    file isn't used, a side branch a merge brings in is read, a root commit's files are listed whatever
    `log.showRoot` says, a workflow that only a merge commit adds is listed, one renamed into or within
    `.github/workflows` is listed as added, and nothing a repository's own config names is run: no signature is
    checked (the config can name the program that checks one), no pager is started (`core.pager`, `pager.log`), and
    nothing is fetched (in a partial clone, a fetch runs what the config names for the remote:
    `GIT_NO_LAZY_FETCH=1` stops it, and `GIT_ALLOW_PROTOCOL=none` refuses every transport for a git too old to know
    that; a partial clone without a tree the line needs stops with an error, where the review reads
    UNKNOWN). Five things the line can't get past: a `.git/info/grafts` file makes it unreliable (git follows the
    file, and no git option turns that off; the review doesn't read it; git's "hint: Support for
    <GIT_DIR>/info/grafts is deprecated" is the sign that one is there, and the line asks git to always show it); a
    `commondir` file in a `.git` folder makes git read the history of the repository it names instead (git puts one
    only in a linked worktree's folder under `.git/worktrees`; `ls .git/commondir` shows one, and the review reads
    that repository UNKNOWN); a `.git` file names the repository git reads, whichever it is (`cat .git` shows it;
    the review follows it too); a `GIT_DIR` set in the shell points git at that repository instead (`unset GIT_DIR`
    first; a `GIT_COMMON_DIR` or `GIT_OBJECT_DIRECTORY` there makes git stop with an error); and in a shallow clone
    what is below the cut isn't there to list (run `git fetch --unshallow` first).
  - Tests (`test/workflows.test.mjs`), each with a clean twin a second before the window or without the trick:
    workflows committed just inside the window (00:00:01 UTC on 30 Aug, 05:00 on 31 Aug at UTC+8, 09:00 UTC on 1 Sep,
    and the advisory's own file names, `github_actions_security.yml` and `security-audit.yml`, on 31 Aug) are listed
    with the command run under `TZ=Pacific/Kiritimati` and `TZ=America/Los_Angeles`; one committed at the start's own
    second, 30 Aug 00:00:00 UTC, from UTC-7, is listed with the date 2026-08-30 (that test runs once, with no `TZ`
    set); a back-dated commit on top, between two workflows, and on a merged and deleted side branch hides nothing; a
    workflow added and removed on a side branch is listed; a replace ref and a grafts file (cutting the history, or
    re-parenting the commit) hide nothing; a shallow repository is UNKNOWN wherever it is cut (inside the window or
    before it, at a back-dated tip over a workflow committed on 5 Sep, or by a shallow file written into a full
    repository, empty or not, even under a git that says the repository isn't shallow, or says it is with no shallow
    file), and so is one whose shallow file can't be read, while the same history cloned whole is read; partial
    clones whose remote is gone are read with nothing fetched (blobless: listed; treeless: UNKNOWN with commits in the
    window, SAFE without); a commit whose committer date git can't read, and a git that prints a committer time that
    isn't a plain whole number (empty, `x`, `-5`, `1.5`, `+1790000000`, ...), are UNKNOWN; a committer time past what
    a date can hold is listed; a start that isn't an explicit UTC instant (a bare date, another form, a day or hour
    that doesn't exist, a year past 9999 or before 0) is UNKNOWN; a git that writes down its arguments gets no
    `--since`, `--after`, `--until`, `--before`, `--max-age`, `--min-age` or `--since-as-filter`. And the "What to
    do" line above, found in this file wherever it is (a release moves it under its version's heading, and none or
    two fails) and run as written, must list every workflow the review lists, at the same commit and UTC date, in
    repositories with a replace ref, a crafted commit-graph file, a workflow only a merge commit adds, a root commit
    under `log.showRoot=false`, renames, a commit at the start's own second from UTC-7, one authored before the window
    and committed inside it, a workflow only on a branch that isn't checked out, a side branch that added and removed
    one, a signed commit under a config that names a `gpg.program` (which must not run), and a blobless partial clone
    whose remote is gone (nothing fetched); in a treeless one it must stop with an error, with nothing fetched; with a
    grafts file it must list them only before the window, as the line's own warning says; and for a commit whose
    committer date git can't read it must show no date. A git that writes down what it gets must get `--no-pager`,
    `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=none` from it (no run through a pipe can see the pager, and on git
    2.54 either setting alone stops the fetch). Its clean twins: a workflow committed a second before the window from
    UTC-7, and one authored inside the window but committed a second before it, aren't in the review, and the line
    shows each dated 2026-08-29T23:59:59Z, which a reader can tell is outside it. Far-future committer times (2^63-1,
    9223372036854775807, which git shows as 1970-01-01T00:00:00Z, and 67768000000000000 with the ends of its band,
    67767976233532800 and 67768036191676799, where git 2.54 shows a negative year such as -2147482895-02-16T20:26:40Z)
    are listed by the review and the line, and a reader who compares only the line's `%ct` number with 1788048000
    counts every one of them, while a commit at 1788047999 is skipped. The line an earlier cut of this
    entry gave fails that test, and so does this one with any one of its options left out but `--diff-filter=A`
    (without which it lists more). A workflow file added, deleted and added again inside the window is listed at both
    commits, newest first, by the review and by the line; its clean twins: two different files each added once are
    one line each, and a file added before the window, deleted, and added again inside it is listed only at the
    commit inside it. A workflow file only changed inside the window reads SAFE, and a test holds this entry,
    ASSURANCE_CASE.md and README.md to the sentence that says so.
  - Run on older code with this CHANGELOG, 23 of the 24 tests in `test/workflows.test.mjs` fail on 0.1.9's code (the
    24th reads only this file), 17 on this fix's first cut, which still gave git the start (44bb10f), and 10 on its
    second (865d0d1, the code at 3dbf26b: shallow repositories, the UTC date a line shows, the git calls made, and the
    hand check). Each planted bug fails at least one: the start given to git, as `--since` or `--since-as-filter`;
    the start's own second left out; the start's form not checked; no shallow check; a cut dated before the start
    taken as the window all there; git's answer or the shallow file alone taken as the sign; any committer time
    accepted; replace refs, grafts or a commit-graph file followed; one walk instead of two calls; the date in the
    commit's own zone; the hand check looked for only under `[Unreleased]`, or showing the author date. Those counts
    are of the 24 tests before the fix for a file added more than once; at 3cff5c5, with this CHANGELOG, the
    re-added file's test and the hand check's test fail (the review listed one commit), and so does the test of the
    documented limit without its sentence, while the two clean twins pass.
- **A repository's own config could make the workflow review (0.1.0 to 0.1.9) and the committed-keys check (0.1.1 to
  0.1.9) read SAFE without having read it.** A repository's `.git/config`, or its `.git/config.worktree` with
  `extensions.worktreeConfig`, can name another working folder: `core.worktree`. Set to a folder above the repository
  (`/tmp` for one under `/tmp`, or `../..`), git took the repository's folder as a subfolder of that one and read
  every path from there: `git log` found nothing under `.github/workflows` and `git ls-files` listed nothing. A full
  repository with a workflow committed on 5 Sep 2026 read "SAFE … in 1 local repository", exit code 0, and so did one
  with a committed key; the hand line above, as this entry gave it up to ffacde4, printed nothing. Setting it takes
  write access to the repository's `.git` folder; a clone can't carry it. Found by an independent check of this
  release with `core.worktree=/tmp`. Wardlatch now gives git the working folder on the command line,
  `--work-tree=<the folder it found>`, which wins over `core.worktree`, `core.bare` and `GIT_WORK_TREE`, so paths are
  read from that folder's top; the hand line gets `--work-tree=.`.
  - The same class, each checked with git 2.54 on 0.1.9's code and on ffacde4, with a workflow committed on 5 Sep: a
    `commondir` file written into a `.git` folder makes git read the refs and commits of the repository it names, and
    one naming an empty repository read SAFE. git writes a `commondir` file only in a linked worktree's own folder
    under `.git/worktrees`, and a linked worktree's `.git` is a file, so a `.git` folder whose history git reads from
    anywhere else is now UNKNOWN, for the workflow review and the committed-keys check ("git reads its history from
    …, which a commondir file in its .git folder names …"), and so is a `.git` folder git doesn't take as the
    repository at all (an empty one inside another repository, where git reads the outer one; an earlier cut of this
    fix, 7bdca07, had the keys check list the outer repository's files under the inner folder, files that aren't
    there). The `.git` folder is compared with git's by what it is on disk (device and inode), not by how its path
    is spelled: on macOS, `--paths` in another case, or in NFC for a name stored as NFD, names the same folder while
    git prints the name on disk, and 7bdca07, which compared the strings, read such a clean repository UNKNOWN.
  - Not a miss before, on either: `core.worktree` naming a folder that isn't above the repository, or set through
    `include.path`, `includeIf` or `-c` (git takes it only from `.git/config` and `config.worktree`); `core.bare=true`
    in the `.git` folder of a repository with its files beside it (but see the bare layout below);
    `diff.relative`, `log.follow`, `diff.noprefix`, `log.diffMerges`, `diff.renames`, `core.ignoreCase` and
    `core.precomposeUnicode`, each on its own (`diff.relative` and `log.follow` hid a workflow only together with a
    `core.worktree` above the repository, which hid it anyway); and, from the caller's environment, `GIT_DIR`,
    `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_SHALLOW_FILE`, `GIT_OBJECT_DIRECTORY`,
    `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_LITERAL_PATHSPECS`, `GIT_GLOB_PATHSPECS`, `GIT_NOGLOB_PATHSPECS`,
    `GIT_ICASE_PATHSPECS`, `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`, none of which git gets (`lib/run.mjs`'s
    allowlist). `GIT_CONFIG_GLOBAL`, which git does get, names the person's own config, and `core.worktree` there is
    not used either.
  - Not covered, before or now: a workflow under a folder whose name differs only in case, such as
    `.GitHub/Workflows`, isn't listed, whatever `core.ignoreCase` says (git compares each commit's paths exactly).
    Whether GitHub runs a workflow from such a folder hasn't been checked. A `.git` file is followed as git follows
    it, whatever repository it names: one naming an empty repository reads SAFE for both checks (0.1.9, ffacde4 and
    now), and so does, for the workflow review, one naming a folder whose `commondir` file names an empty
    repository. No rule based on the layout tells those apart from clean ones: `git clone --separate-git-dir`
    writes a `.git` file naming a repository that has no pointer back to it, and the pointer back a linked worktree's
    folder holds is a file anyone who can write the `.git` file can write too (and a worktree moved by hand has a stale
    one). A check that compares the workflow files on disk with the tree of the commit checked out could, and is
    planned for a later release. `cat .git` shows which repository a `.git` file names. This case is out of scope
    because whoever can write to a repository's `.git` can hide a workflow without any trick of layout, for example
    by deleting the branch ref that leads to it, and every version reads SAFE then. And in the
    bare-repository-with-worktrees layout (a `.bare` folder,
    a `.git` file saying `gitdir: ./.bare`, and each worktree in a subfolder), the search stops at the outer folder,
    as for any repository: the workflow review reads its history, but the committed-keys check scans no worktree's
    files and reads SAFE (as in 0.1.9). Pass a worktree's own folder with `--paths` to scan it.
  - Tests. `test/workflows.test.mjs`: a workflow committed on 5 Sep in a repository whose `core.worktree` names the
    folder above it (absolute, as `../..`, in `config.worktree`, and with `diff.relative` and `log.follow` on top) is
    listed, and so with `core.bare=true`; each but `core.bare` first shows that git as it runs by default lists
    nothing, and each has a clean twin, the same setting with the workflow a second before the window, which reads
    SAFE, not UNKNOWN. A linked worktree and a submodule's own folder (where git sets `core.worktree` itself) are
    listed as before. A `commondir` file naming an empty repository is UNKNOWN, and so is an empty `.git` folder
    inside another repository; without the file the repository is listed, and the outer one reads SAFE. On a file
    system that takes them as one folder (macOS), `--paths` in another case (`casedir` for `CaseDir`) and in NFC for
    a name stored as NFD lists the workflow, from the folder above and from the repository's own; clean twins, SAFE.
    Every git call gets `--work-tree=` the folder it gets as `-C`. The hand line must list the workflow in three
    `core.worktree` repositories too (above the repository, in `config.worktree`, and with `diff.relative` and
    `log.follow`). `test/cli.test.mjs`: a committed key under `core.worktree` (in `.git/config` and in
    `config.worktree`) is found, clean twin SAFE; a `commondir` file naming an empty repository and an empty `.git`
    folder inside another repository are UNKNOWN for the keys check, and without the file, and from the outer
    folder, the key is found; `--paths` in another case or in NFC for NFD finds the key, clean twins SAFE. Run with
    this CHANGELOG: on ffacde4's code 6 of these tests fail (both `core.worktree` tests, both `commondir` tests, the
    git-arguments test and the hand check's, which compares with the review), while the linked-worktree, submodule
    and spelling tests pass; on 7bdca07's, 3 (the keys `commondir` test, the workflow spelling test, and the
    workflow `commondir` test for its reason's wording); with `--work-tree` left out of `lib/git.mjs`, 4; with the
    own-`.git` check comparing path strings, both spelling tests; with it left out of the keys check, the keys
    `commondir` test; with it left out of both, those two `commondir` tests and the git-arguments test; and with
    `--work-tree=.` left out of the hand line, the hand check's test.

### Changed

- **A shallow clone reads UNKNOWN for the workflow review, exit code 2.** That includes the usual CI checkout:
  `actions/checkout` fetches a single commit (`fetch-depth: 1`) unless told otherwise. 0.1.9 read a shallow clone as
  if its history began at the cut. To check a repository in CI, check it out with `fetch-depth: 0`; on your own
  machine, run `git fetch --unshallow` in it first.
- **The workflow review reads each repository's whole history on every run.** On the maintainer's Mac (Apple M5 Pro,
  git 2.54), the whole command on one repository took 0.5 s for 100,000 commits (0.06 s when 0.1.9 stopped at the
  start), 0.8 s for 100,000 commits with 9,800 workflow files added over time (0.4 s before), and 7 s for 1.56 million
  commits (0.1 s before); an independent check measured 0.44 s and 7.1 s for the first and last. The list of commits
  takes about 52 bytes each, and up to 256 MB is read (about 5 million commits; 0.1.9's first cut read 64 MB and so
  lost its findings past about 1.3 million). Each git call stops after 20 seconds: a repository with millions of
  commits on a slower machine can reach that, and then reads UNKNOWN ("git did not finish in time"), never SAFE; one
  that prints more than that is UNKNOWN too ("git wrote more than could be read").

### Development (no code in the package changes)

- The tests never look in the home folder of the person running them (where macOS keeps Desktop, Documents, Downloads,
  Library, Photos and Mail): every test file loads `test/support/no-real-home.cjs` first, which refuses any look there
  by Node (fs in every form, globs, streams, `require()` and, from Node 22.15, `import` (of a file, a package name or a
  `#` name), a change of folder, a program, working folder or `PATH` folder there, a `.env` file `process.loadEnvFile`
  reads, a `node:sqlite` database there, a Node started with `--env-file` or a config-file flag naming a file there, and
  a walk that can reach it), in the test, in every Node process it starts at any depth and in each Worker thread they
  start; a refusal in a process the test started fails the test even when nothing reads that process's exit code. It is
  not a sandbox: code written to get past it can. Paths are compared as the system reads them (links and `..` followed,
  but the link a path names last for `lstat`, `readlink`, `unlink`, `rmdir`, `rm`, `lchown` and `lutimes`, and on macOS
  in any case and under the start-up disk's other names, by their text too), and under sudo SUDO_USER's home is off
  limits too. It drops the home's folders from the `PATH` the tests start with. The sudo test and the two tests of
  macOS's own Library build a `/Users/<name>` home of their own (`test/support/fake-home.cjs`); `test/cli.test.mjs`
  gives the command an empty HOME of its own and none of the runner's `XDG_*`, `GOENV` or `GOTOOLCHAIN` (on a CI runner
  `XDG_CONFIG_HOME` sent the go check into the runner's home), and the version test gives the go check one.
  `test/no-real-home.test.mjs` tries each route the net watches on a made-up home. What it can't
  stop: a program that isn't Node (and a Node one starts below the command), and macOS's own read of
  `~/.CFUserTextEncoding` as any process starts (CONTRIBUTING.md, Testing policy).

## [0.1.9] - 2026-10-23

A fixes-only release: no new incident checks. Every item below was found by a root-cause audit of all releases from
0.1.0 to 0.1.8, and each kind of mistake is now held back by a rule the test suite enforces, not just by the fix.

### Security

- Advisories: [GHSA-766p-78h4-77gr](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-766p-78h4-77gr) (forced-roots refusal read as a block, 0.1.4–0.1.8),
  [GHSA-gxqr-jm2v-mcm8](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-gxqr-jm2v-mcm8) (container failures read as refusals, 0.1.2–0.1.8) and
  [GHSA-9m5q-pvx5-fp26](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-9m5q-pvx5-fp26) (parts not examined left out, 0.1.0–0.1.8).
- **A forced-roots refusal for any reason read as the runtime's own block, the strongest SAFE.** Since 0.1.4 a runtime
  that couldn't connect with the compromised roots forced in, but could open a normal site, was reported as blocking the
  compromised keys itself. A TLS-inspecting firewall, a DNS filter answering for the test hosts, a hostname mismatch or
  an expired test certificate made every runtime read SAFE. Now only Node's own block (`CERT_REVOKED`, which Node
  26.12.1, 24.22.1 and 22.23.4 give for these keys) counts; any other failure is UNKNOWN, and curl, which has no block
  of its own, never counts. The test hosts must also present the compromised chain's issuer (`EM DV/OV/EV TLS CA -
  G3B/G3C`), so something answering in their place is reported, not tested. macOS's own stack: a certificate date error
  (-1201, -1204) is no longer read as a refusal.
- **Inside containers, any failure counted as a refusal.** The probe script exited 1 for a timeout or a DNS failure as
  for a certificate refusal, so a container that couldn't reach the test hosts read SAFE (the host probe stopped doing
  this in 0.1.7). Now only curl 60, Python's certificate error and wget 5 are refusals; anything else is UNKNOWN.
- **Folders Wardlatch couldn't open were skipped silently, and nothing searched still read SAFE.** A folder it couldn't
  open is now reported by who owns it, one rule for every check (`lib/owners.mjs`): one a person owns (it could hold
  their projects or sites: this user, or any login account, uid 1000 and up on Linux and 501 and up on macOS, a company
  directory's included; for WordPress, the web server's account too) is UNKNOWN; one a service owns (root, a database,
  "nobody", a rootless container's uids) is named in one REVIEW line, which doesn't change the exit code. A searched
  folder itself (a `--paths` folder, `/var/www`), or something already found or known (a virtual environment's own
  folders, `~/.local/lib`, a temp folder), that can't be opened is always UNKNOWN. For WordPress, a locked dot-folder
  below a root (www-data's `.ssh`) is listed for review whoever owns it. A `--paths` folder that doesn't exist is UNKNOWN (exit 2), not "SAFE, 0 repositories"; with no `--paths`
  and none of the usual folders on the machine (a fresh server, a CI runner), the check is SAFE and lists the folders
  it looked for.
- **Environment allowlist.** Every program Wardlatch runs gets an environment built for its purpose from an allowlist
  (`lib/run.mjs`), not the caller's environment: `DEVELOPER_DIR` still redirected macOS's `/usr/bin/git` shim after
  0.1.8's `GIT_*` fix, and `NODE_OPTIONS --require` ran inside the trust probes. `DOCKER_HOST` and `CONTAINER_HOST`
  are followed only to a local socket the person or root owns (Colima, Podman, rootless Docker); a remote one, and
  `DOCKER_CONTEXT`, `DOCKER_CONFIG` and `CONTAINER_CONNECTION`, are not, and when one is set and an engine is installed
  an UNKNOWN row says so. Since the second review a trust
  probe's environment is an allowlist too: the first cut still dropped a list of names, and `OPENSSL_CONF` loaded a
  module into the probe, and `SHELLOPTS` with `PS4` ran a command inside a version manager's bash shim.
- **A container that stopped mid-check read SAFE.** `docker exec` itself exits 1 when the container has stopped, the
  code the probe used for a refusal. The result is now read from a line the probe prints, never the exit code.
- **A runtime that trusted only one of the two roots read SAFE when that root's test hosts were down.** Each test host
  now names the root its chain ends at, the forced-roots control runs on a host for each root with only that root
  forced in (with both, a chain could finish at the other root), and a runtime or container is SAFE only when every
  root had a host that answered.
- **A trust setting the probe doesn't get could leave a SAFE that wasn't tested.** A CA added through `NODE_OPTIONS
  --require` (mac-ca, syswide-cas) or `OPENSSL_CONF` is now an UNKNOWN row (options that add no trust, such as
  `--max-old-space-size` in either spelling, don't count). A trust probe also gets `NIX_SSL_CERT_FILE`, and the
  person's `CURL_HOME` and `XDG_CONFIG_HOME`, so the probe's curl reads the start-up file the person's curl reads.
  The person's own `NODE_TLS_REJECT_UNAUTHORIZED` reaches the Node probe, so a Node run with checking off reads
  EXPOSED.
- **A `DOCKER_HOST` not followed, while a local engine answered, read SAFE in the LiteLLM image check**, which never
  looked at the engine it named. It is UNKNOWN there too.

### Fixed

- Temp markers: the macOS per-user temp folder is searched even when `TMPDIR` is unset (sudo, cron, launchd), and under
  sudo the person's own home folder is searched, not root's.
- Copies of a program on `PATH`, one rule for the trust check and the version checks: the first (the one the shell
  runs) and every later copy that is a compiled program are run and judged (a fixed php first no longer hides a
  vulnerable one); a later copy that is a script is named in a REVIEW line (in `--json` too), never run for the first time
  by Wardlatch.
  "Not installed" now says it searched `PATH`.
- The workflow review lists a workflow that only a merge commit adds (git's combined view: merging main into an old
  branch doesn't list main's workflows again), ignores grafts and the commit-graph file, and never shows git's own
  hints as the reason a repository couldn't be read.
- The header check reads more of the files curl and git read: CRLF files, `$CURL_HOME/.curlrc`, `$CURL_HOME/.config/curlrc`, `~/.config/curlrc`, the
  file `GIT_CONFIG_GLOBAL` names, `WGETRC`, `NPM_CONFIG_USERCONFIG` (not all of them: see Known limits).
- Three false SAFEs found in the last checks before release, all in 0.1.8 too: a Plex Media Server in any dpkg state
  but plain "installed" (held with `apt-mark hold`, marked for removal, unpacked, half-configured, waiting on triggers)
  read as not installed, though its files were on disk (half-installed is now UNKNOWN); a PHP release candidate or `-dev` build of
  a fixed version (`8.4.27RC1`, older than the fix) read as fixed; and a virtual environment's certifi bundle on a
  machine with no curl to test it with was dropped without a line (now UNKNOWN). A fourth, from the same checks: the PHP
  check judged only the program called `php`, so on a server with several PHP versions an old `php8.1`, and the
  `php-fpm8.1` serving the sites, read SAFE; versioned `php`, `php-fpm` and `php-cgi` programs on `PATH`, in the `sbin`
  folders and in macOS Homebrew's `php@*`, Remi, cPanel and Plesk install folders are now each judged (one file reached by two
  names, once; a later copy of a name that is a script is not run).
- Bounded work: hand-written parsers instead of patterns that backtracked (a planted line took 22 s), a capped JSON walk
  and a 1 MB cap on a repository's config files (a planted 16 MB `.mcp.json` took 1.4 GB), every file read through one
  reader that never blocks on a FIFO, and every program killed with SIGKILL at its timeout.
- Every SAFE line is a result row in `--json` too, with the list of what it searched (`searched`). A SAFE row without one
  becomes UNKNOWN in `--json` and the exit code, however it was made, and a line under the output withdraws it.
- The header check: a missing `--paths` folder, a folder it couldn't open, or a config nested deeper than it reads is
  UNKNOWN, not SAFE. A settings file this user can't open (so their own tools can't read it either) is not used, and
  one set to `/dev/null` (CI's way of switching it off) is empty. A `--paths` entry that is a file is UNKNOWN in every
  check that searches folders.
- A virtual environment whose `lib` folder couldn't be opened is an UNKNOWN row, not dropped.
- The WordPress indicator search says what its caps left unsearched (files over 2 MB, past 4,000 files, deeper than 12
  levels): UNKNOWN, not SAFE.
- Under sudo, git keeps `SUDO_UID`, so the person's own repositories aren't refused as "dubious ownership"; a sudo user
  whose home folder isn't found (including a directory name such as `ada@corp.example`) is an UNKNOWN row, not a silent
  search of root's home, in the checks that read the home folder.
- A crash inside Wardlatch exits 2 (could not be tested), not 1 (exposed), unless an EXPOSED line was already printed.
  A container's probe output counts only with exactly one result line.
- File reads are capped by what is read, not only by the size reported at open.
- The key scan reads every tracked text file up to 512 MB (0.1.8 skipped files over 512 KB, and unreadable ones, without
  a word): past 8 MB in overlapping pieces that end at line breaks, so a key is never cut in two and each match is
  counted in exactly one piece. A placeholder word (`example`, `fake`) counts only right next to a key, never anywhere on
  its line (one `example.com` on a minified line hid every key on it). It reads git's own record of each file: a
  committed link is not followed (git stores the target's name, not its contents), and an empty tracked file in a folder
  that can't be opened (a `.gitkeep`) is not reported.
- macOS's own folders (its Library at `/`, in `/System` and in a home folder, the Trash, the Photos libraries) are never
  searched; any other folder named Library is (0.1.8 skipped every Library folder). A trust probe also gets `CURL_SSL_BACKEND`, which picks macOS
  curl's trust store.
- From the bug hunt before release (a red team's 75 scenario tests and 614 planted bugs; `test/bughunt-0.1.9.test.mjs`):
  - **False SAFEs:**
    - Podman refusing its socket (permission denied) read as "not running" in the image check, so the run could end SAFE.
      One rule now classifies engine failures for running containers and local images alike.
    - A Bedrock site (core in `web/wp`, plugins in `web/app/plugins`), or WordPress in its own directory with
      `wp-content` one level up, was never found: "no WordPress installs found". Every plugins folder a site can use,
      and leftover ones beside it, is checked now, not only the first found (a core still holding its bundled
      `wp-content` beside the live one read SAFE about the wrong plugins). Wardlatch doesn't read PHP (owner, 23 Oct):
      when the wp-config.php WordPress reads names `WP_CONTENT_DIR` or `WP_PLUGIN_DIR` anywhere, when Bedrock's
      `config/application.php` (past its stock lines) or `config/environments/*.php` names `CONTENT_DIR` or
      `WP_PLUGIN_DIR`, or
      when one of those files can't be read, the site is UNKNOWN: its plugins may be elsewhere. So is a core with no
      content folder in any of those places.
    - A site inside another site's folder (`public_html/blog`) was never searched: the search stopped at the first.
    - A key in a tracked file deleted from the working tree (still in the index, HEAD and every push) was skipped. git's
      own copy is scanned now, in a few git runs however many there are. A file marked skip-worktree that is on disk is
      scanned like any other.
    - A key in a UTF-16 file with a byte-order mark (PowerShell 5's `Out-File`) was skipped as binary.
    - A real key with an example key (of any kind) beside it on the same line was taken for a placeholder.
    - curl's `-H @file` (`header = "@file"`, `-H@file`) was checked as a file name, never as the headers in the file.
      The file is read now; one named by a relative path is UNKNOWN, and one curl couldn't read either sends nothing.
    - `.curlrc` lines with short options in a cluster (`-sH "From: …"`, `-sA …`) or an attached value (`-HFrom:…`),
      `proxy-header`, curl 8.3's `expand-` forms, and the config files a `config =`, `expand-config` or `-K` line
      brings in (`-K file`, `-K/file`, `-sK file`) were not read. They are now, on the safe side (owner, 23 Oct): your name or email anywhere after a header
      option counts, with backslash escapes undone. curl variables (a `variable` line, or `{{name}}` in an `expand-`
      line), which can build a header from pieces, are UNKNOWN. Brought-in files are read once per use, at most 32 of 1 MB.
      File names are read as curl reads them: split only at ASCII white space (a no-break or narrow space is part of
      the name), with escapes undone only inside quotes.
    - The bundle `REQUESTS_CA_BUNDLE` names (what requests and pip trust in place of certifi) was never tested. It is
      tested now, and is UNKNOWN when there is no curl to test it with, when it names a folder, or when it can't be
      opened.
  - **Not tested, now said:**
    - Docker Desktop or a Podman machine stopped: its local images couldn't be listed, and only a note said so. It is a
      REVIEW line now (owner, 23 Oct; the exit code doesn't change, since a quit Docker Desktop is normal on a laptop).
    - On Linux with neither curl nor python3, the distribution's CA bundle went untested without a line: UNKNOWN now
      (owner, 23 Oct). With python3 there, python3 tests that bundle.
  - **False UNKNOWNs:**
    - `DOCKER_HOST` naming a local socket that is gone (Colima or a Podman machine stopped) read as an unfollowed host.
      It is "not running" now, when the socket's folder is there, is this user's or root's, and no one else can write
      to it.
    - A JSON-with-comments file whose last setting is commented out after a trailing comma (VS Code writes these) read
      as invalid.
  - **Options and wording:**
    - `--paths ""` and `--incident ""` (an unset variable in a script) are refused, exit 2: an empty `--paths` searched
      the current folder.
    - `--incident` can be given more than once: 0.1.8 checked only the first.
    - A WordPress site found with none of the listed plugins said "no WordPress installs found"; it now says how many
      were found.
    - A README sentence about the operating system's trust was cut off.

### Known limits

- The issuer check compares the issuer's common name, not a fingerprint: something on the network that copies the name
  gets past it (the forced-roots control still catches it for curl, Node and Python, not for macOS's own stack or
  containers).
- The workflow review reads commits dated on or after the incident's date: a commit given an earlier date isn't seen,
  and git stops reading a branch at a commit dated before it, so a correctly dated workflow behind a later commit from a
  machine with a wrong clock can be missed too. (0.1.9's first cut read the whole history to catch that, and lost its
  findings on repositories past about 1.3 million commits; taken out, owner, 22 Oct.)
- The key scan and the workflow review stop at the first repository they find, as 0.1.8 did: a repository nested inside
  another one, a git worktree placed inside one, and submodules are not read.
- A later copy of a program on `PATH` that is a script, not a compiled program, is not run, so its version isn't judged.
- A folder that can't be opened and whose owner can't be read counts as a person's: UNKNOWN.
- A PHP install folder that is closed (an admin's locked `/opt/remi`) is UNKNOWN once for each pattern that reaches it
  (bin and sbin: two lines for one folder), with the reason written for a program file.
- A locked folder on the way to a known install place (a vendor's folder under `/opt` or `/srv`, a `python3.X`, a
  `git` user's home holding `/home/git/gitlab`) is UNKNOWN whoever owns it, and the line names the place Wardlatch was
  looking for, which may lie below the locked folder. On a server with a `git` user whose home is closed, the GitLab
  check reads UNKNOWN even with no GitLab installed: run it with sudo.
- The header check doesn't read git's system config (`/etc/gitconfig`, `GIT_CONFIG_SYSTEM`), files a git config
  includes (`include.path`, `includeIf`), or `/etc/wgetrc`: a header set only there isn't seen. The SAFE line's receipt
  lists the files it read.
- A site folder owned by root that this user can't open (a hardened `root:www-data 750`) is a service's by the rule:
  listed for review, not UNKNOWN; run Wardlatch with sudo on a web server to include such sites.
- A file of Wardlatch's own that fails to load (a broken install) exits 1, before anything of Wardlatch's runs.
- Runtimes are run from `/` with the person's default selection: a version chosen per shell or per project
  (`PYENV_VERSION`, `.nvmrc`, `.tool-versions`) is not followed, so the runtime tested can differ from the one a project
  uses.
- The engine is the one the person's own docker or podman configuration selects (their home folder's config), which can
  name a remote host, or a local socket `DOCKER_HOST` names; a remote `DOCKER_HOST` and the like are not followed.
- Inside containers, a refusal of the test hosts can't be told from a DNS filter or TLS-inspecting proxy on the
  containers' network that answers for them with its own certificate (the issuer check covers the host's network only).
- Searches don't reach: PyPy environments (`lib/pypy3.x`); OpenLiteSpeed's `lsphp` and DirectAdmin's `/usr/local/php*`
  installs; repositories in hidden folders, more than 4 levels down, or linked in by a symbolic link; and a site linked
  into a web root by a symbolic link. A `~` written literally in `PATH` (which the shell expands) is dropped with the
  other relative entries.
- A UTF-16 file without a byte-order mark is skipped as binary, and a UTF-16 file over 8 MB is UNKNOWN (it isn't read
  in pieces). Files a sparse checkout leaves out of the working tree (skip-worktree, not on disk) are not scanned, as in
  0.1.8.
- WordPress: a site whose wp-config.php names `WP_CONTENT_DIR` or `WP_PLUGIN_DIR` anywhere (even in a comment, or to
  use it rather than move it) is UNKNOWN, since Wardlatch doesn't read PHP; so is a Bedrock site whose config names
  `CONTENT_DIR` beyond its stock lines (even an environment file setting `/app` again; its `WP_CONTENT_URL` line counts
  as stock only in the exact forms Bedrock shipped, 1.0.0 to today). A move made outside the files
  read is not seen: in a file wp-config.php brings in with `require` or `include` (a `wp-config-local.php`), through
  `eval` (the Docker image's `WORDPRESS_CONFIG_EXTRA`) or PHP's `auto_prepend_file`, with a changed Bedrock
  `$webroot_dir` or `$root_dir`, or under a constant name built from pieces. A `config/` folder beside a core that can't
  be opened, or whose `environments/` can't be opened or listed, is a doubt even when it isn't Bedrock's (UNKNOWN). A wp-config.php over 1 MB is UNKNOWN. Must-use plugins
  (`mu-plugins`) are not checked, and the indicator search doesn't enter a linked folder inside a plugin. Leftover plugins folders beside a site are checked too, so a stale copy of a
  plugin can read EXPOSED: its files are still on the web server.
- `.curlrc` is read on the safe side, not as curl parses it: a line with a header option and your name or email after
  it is EXPOSED even when curl refuses the line or sends only part of it (an unquoted value is cut at its first space;
  `--header=x` and an attached value followed by another word are refused; a later `-A` replaces an earlier one; long
  names in capitals are refused by curl 8.7 but were taken by older curl). Fix or remove such a line. Abbreviated long
  option names (`user-agen`, which older curl took) are not read; `cookie` and `referer` lines are outside this check;
  a `-K` inside a cluster with its file attached (`-sKfile`) is not followed. Start-up files some curl versions read
  and 8.7.1 doesn't (`$XDG_CONFIG_HOME/curlrc`) are read too, on the safe side.
- `DOCKER_HOST` naming a socket whose folder is gone too (a stopped Podman machine's after a reboot) is not followed:
  UNKNOWN, as for a remote host. Start the engine, or pass `--no-containers`.
- A later copy of a program on `PATH` that can be run but not read (mode 111) is taken for a script: named for review,
  not run.
- `--paths` given for a folder and a folder inside it reports a finding in the inner one twice, and `--list --json`
  prints text.

### Changed (rules the tests now enforce)

- Only `lib/run.mjs` starts programs; only `lib/files.mjs` touches the file system; only `lib/report.mjs` makes a SAFE,
  and only with a receipt. `test/contract-0.1.9.test.mjs` (written before the fixes, independently) holds all three.

## [0.1.8] - 2026-10-22

### Added

- **GitLab CVE-2026-110264** (`gitlab-2026-10`): the version read from GitLab's own files, judged per release line;
  18.10 and older have no patch; a fixed self-compiled install is REVIEW (it also needs GitLab's Ruby patch).
- **LiteLLM 1.107.0** (`litellm-2026-10`): the release record and the files it drops in site-packages (`cook.pth` and
  `cook.py` by name, `sitecustomize.py` by SHA-256) across system, Homebrew, user, pyenv, conda, pipx, uv, Poetry and
  Pipenv installs and virtual environments; the stealer's markers in the temp folders; local images by digest, by the
  published digest prefixes or by the `v1.107.0` tag. Python is never started for this.
- **Plex Media Server** (`plex-2026-10`): the version from the Debian package record or the macOS app; 1.43.3.10861 and
  later are fixed.
- The `installs` check type (`lib/installs.mjs`): installed software is read, never run.
- `identity-headers-2026-10`: agents that tell websites who you are. Finds your name or email, or any email address, in the header settings your tools send (curl and wget start-up files, git's http.extraHeader and http.userAgent, npm's user-agent, coding-agent and MCP client configs, `*_HEADERS` variables). Read-only; values are never printed.

### Security

- Advisory: [GHSA-84hq-29mv-c9fj](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-84hq-29mv-c9fj).
- **A git environment variable could point the git checks at another repository, and they read SAFE.** Run where
  `GIT_DIR` or `GIT_WORK_TREE` is set (inside a git hook, or a CI step that sets them), 0.1.0 to 0.1.7 ran every
  `git log` and `git ls-files` against that one repository instead of each repository found, so the GitHub Actions
  review and the committed-key scan reported a repository clean without having read it (exit code 0). Other `GIT_*`
  variables (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_EXEC_PATH` and the like) could set config or name
  programs the `-c` overrides don't cover. 0.1.8 drops every `GIT_*` variable before running git, except the three that
  only choose your own global and system config files and `GIT_TEST_ASSUME_DIFFERENT_OWNER`, which can only make git
  refuse a repository. Found by a new test in our own review; a test sets `GIT_DIR`
  and `GIT_CONFIG_PARAMETERS` and expects the real repository to be read and nothing to run.

### Fixed

- A version with a suffix (`19.4.2-ee`, Plex's `1.43.3.10861-07dfddaeb`) is compared by its leading number; such a
  part used to compare as equal, which could read a vulnerable version as SAFE. A pre-release of a fixed version is
  older than the fix.
- On Windows, which is not supported yet, the installed-software checks report UNKNOWN instead of SAFE.
- From the release review: a folder Wardlatch can't open (another user's home, a root-owned virtual environment, a
  locked site-packages) and a `sitecustomize.py` it can't read are UNKNOWN, never "not installed"; a planted config
  that is deeply nested, huge or holds a very long value can no longer crash or stall the header check (iterative
  walk, depth and size caps, a bounded email pattern, and one bad file is UNKNOWN while the rest are still read); wget
  settings are read in any spelling (`useragent`, `user-agent`), Codex's `[..._headers]` tables are read, curl's `-a`
  and `-h` are no longer taken for headers, and only a value's own key or the key right above it makes it a header; a
  local image without a repository digest is still matched by its tag. Each has a regression test.
- From the red-team audit (also in 0.1.7 and earlier): a planted FIFO as a virtual environment's certifi `METADATA`
  or `__init__.py` hung the run (those two files are now read like every other, regular files under a size cap only);
  `--json` now escapes DEL and C1 control characters from names on disk, as the text output already did.
- OVHcloud's temp-folder marker is matched with any number of digits.
- Release: the workflow checks the attestation bundle (present, one bundle, and `gh attestation verify` for both files,
  bound to this workflow) before it publishes a release, so a change in the attest action can't ship a release without it.
- Tests for branches the suite didn't reach: GOTOOLCHAIN's last line winning and `GOENV=off`; each folder in
  `SSL_CERT_DIR` made absolute; Python and curl failures that aren't certificate refusals; `sitecustomize.py` never run
  (skipped where the distribution's own sitecustomize is imported first, as on CI's Ubuntu); `.` and empty `PATH` entries; `core.fsmonitor` through `include.path`, `includeIf` and
  the worktree config; a program whose version or file can't be read.

## [0.1.7] - 2026-10-22

### Security

- Advisory: [GHSA-xcqr-prh6-6g8w](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-xcqr-prh6-6g8w).
- **Wardlatch no longer runs Python's start-up files.** At start-up Python runs every `.pth` file and any
  `sitecustomize.py` in its site-packages, and a malicious package can put code there: LiteLLM 1.107.0, compromised on
  PyPI on 21 October 2026, ships `cook.pth` and a `sitecustomize.py`. The eMudhra check started each `python3` on `PATH`
  and `/usr/bin/python3` with `-I`, which does not stop this. So with 0.1.0 to 0.1.6, if that interpreter's own
  site-packages held a malicious `.pth` (in an activated virtual environment, a conda environment, a pyenv version or
  Homebrew's Python, for example), running Wardlatch ran it. 0.1.0 to 0.1.2 also started the `bin/python` of each
  virtual environment found under the searched folders, which ran that environment's `.pth` files. That `bin/python` did not have to be
  Python: any program a cloned repository put there was run (fixed in 0.1.3; [GHSA-383w-hfwc-vx2h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-383w-hfwc-vx2h)). 0.1.2 to 0.1.6 ran
  `python3` without `-I` inside running containers that had no `curl`, which ran the `.pth` files of the image's
  Python, its user site-packages included; a running container from LiteLLM's own images (pulled on 21 October
  between 11:46 and 14:20 UTC) would be such a case if it had no `curl`. On the host, a copy installed with `pip install --user` was not run, because `-I` leaves out
  the user's site-packages. 0.1.7 runs `python3 -I -S`, on the host and in containers: `-S` skips the `site` module,
  and with it every `.pth` file and `sitecustomize.py`. A container's `python3` older than 3.4, which has no `-I`, is
  UNKNOWN. Found in our own review; a test plants a marker `.pth` in a real virtual environment and fails if the probe
  runs it. If one of those Pythons held LiteLLM 1.107.0, every start of it ran the stealer, Wardlatch's included:
  follow LiteLLM's advisory.
  The trade-off: a `.pth` file or `sitecustomize.py` that changes how Python trusts certificates (pip-system-certs, for
  example) no longer applies to the probe, and, as before, the `certifi` in the own site-packages of a Python on `PATH` is
  not tested yet (a virtual environment's is). A Python whose code uses an old `certifi` that way can read SAFE here; the
  certifi check for those is planned.
- Advisory: [GHSA-x8rh-w6q6-4r3h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x8rh-w6q6-4r3h).
- **A repository's own git config can no longer make Wardlatch run a program, and git never fetches.** The workflow
  review runs `git log` (since 0.1.0) and the committed-key scan runs `git ls-files` (since 0.1.1) in each repository
  under the searched folders, and git reads that repository's `.git/config`. With 0.1.1 to 0.1.6, a repository whose
  config set `core.fsmonitor` had that program run by `git ls-files`; with 0.1.0 to 0.1.6, one whose config set
  `log.showSignature` and
  `gpg.program` (or `gpg.ssh.program` or `gpg.x509.program`), with a signed commit that added a workflow file since 1
  September 2026, had that program run by `git log`. In a partial clone (`--filter=tree:0`, or `blob:none` when a
  workflow renamed within the folder needed its contents), `git log` fetched the missing objects from the clone's own
  remote, such as github.com, with your usual SSH key or credential helper, and wrote what it fetched into that
  repository's `.git/objects`: a request and a change Wardlatch promises never to make, and ones that needed no crafted
  config. The fetch also ran the repository's own `reference-transaction` hook (in `.git/hooks`, or wherever
  `core.hooksPath` points), which needs no config at all, and `core.alternateRefsCommand` when the repository has
  `objects/info/alternates`. A crafted config could also make that fetch run a program (`core.sshCommand`,
  `remote.<name>.uploadpack`, a credential helper, an `ext::` remote). A cloned repository carries no such config and
  no hooks, but one unpacked from an archive or copied from elsewhere can. 0.1.7 runs git by its full path, from `/`,
  as `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c log.showRoot=true`, `log` with
  `--no-show-signature --no-ext-diff --no-textconv --no-renames`, and lazy fetching off (`GIT_NO_LAZY_FETCH=1`, and
  `GIT_ALLOW_PROTOCOL` for older git). Tests plant
  programs for `core.fsmonitor`, `gpg.program`, diff drivers, filters, the pager and hooks, and a partial clone whose
  fetch would run one, and fail if any of them runs.
- Advisory: [GHSA-x4qj-7j53-r4cv](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x4qj-7j53-r4cv) (this item and the `log.showRoot` one under Fixed).
- **A Node.js older than 18 is tested, and only a certificate refusal reads as "does not trust".** 0.1.0 to 0.1.6
  reported any Node.js older than 18 on `PATH` as SAFE without testing it: the probe used `fetch()`, which Node 17 and
  older lack, so it failed, and every failure counted as a refusal once the forced-roots control (which used
  `https.get`) had passed. Node's bundled roots include Comodo's AAA Certificate Services (Node 10 to 17; 12 to 17 also emSign ECC Root CA - G3),
  so such a Node really is exposed. 0.1.7 probes with `https.get`, and on the host counts a failure as a refusal only when it is a
  certificate-verification error (curl exit 60, a Node certificate error code, Python's `SSLCertVerificationError`, macOS's NSURLErrorDomain -1201 to -1204);
  any other failure, when no test host connected, is UNKNOWN. Found by the critic of the 0.1.7 review; a test runs a
  Node with `fetch` removed against a trusting local test host and expects EXPOSED.
- **Hardening: programs found from the place you started Wardlatch.** From 0.1.0 to 0.1.6, run with npx from inside a
  project, Wardlatch could run that project's own programs: npx puts the project's `node_modules/.bin` first on `PATH`,
  where Wardlatch looks up `git`, `python3`, `node`, `curl`, `php`, `go` and the container engines. And `go version`,
  run from a project whose `go.mod` asks for a newer Go, can download and run that Go (a request to the Go module
  proxy, which Wardlatch promises never to make). 0.1.7 drops every `node_modules/.bin` folder and any relative entry
  from `PATH` before anything runs (and uses `/usr/bin:/bin` when nothing is left), runs git by its full path, runs
  every program from `/` (with `--paths` folders and relative CA settings such as `SSL_CERT_FILE` made absolute
  first), sets `GOTOOLCHAIN=local`, and reads PHP's version with `php -n -v`, which loads no `php.ini` and no
  extension. A Go you pinned with `GOTOOLCHAIN` (for example `go1.26.5`) is read from that setting without running go,
  and judged too. npx also starts Wardlatch with the project's own `node_modules/.bin/node` if it has one, and applies
  its `.npmrc`; Wardlatch can't undo either: run it from your home folder. Found in an independent review.

### Fixed

- **No silent all-clear when the eMudhra check has nothing to test.** When it found no runtime to test (always the
  case for the machine itself on Windows, and possible elsewhere), it printed nothing for it, and the run could exit 0.
  Now it prints one UNKNOWN line ("not checked on Windows yet (Windows is not supported)" on Windows, or "the runtimes
  on this machine were not checked: Windows is not supported yet" when containers were checked; "no runtime was found
  to test" elsewhere; `kind` `runtimes` in `--json`), so the exit code
  is 2. On Windows the OVHcloud CLI and PHP checks say UNKNOWN too, instead of SAFE: they look only for macOS and Linux
  program names. The OVHcloud stealer's temp folder is still found there, and still EXPOSED.
- **A container engine that can't be asked is UNKNOWN, not "not running".** From 0.1.2 to 0.1.6, any failure of
  `docker ps` or `podman ps` other than "permission denied" read as "not running", so a hung Docker Desktop, or one
  answering "error during connect", let the eMudhra check end all SAFE (exit 0) with its running containers never
  checked. Now only an engine that isn't installed, or says it can't connect to its daemon, counts as not running. A
  hang (killed after 10 seconds), more output than can be read, or any other failure is an UNKNOWN line with the reason
  and what to do. A pipeline whose engine is installed but stuck now exits 2 where it exited 0; `--no-containers` skips
  running containers. The `docker exec` or `podman exec` command Wardlatch starts is now killed with SIGKILL, not
  SIGTERM, if it outlives its timeout. Found in an independent review.
- **A repository git can't read is UNKNOWN, not clean.** Up to 0.1.6, when `git log` or `git ls-files` failed in a
  repository (a git refusing a folder owned by another user, a timeout), the workflow review and the committed-key
  scan left it out without a word and still counted it in their SAFE line. Now each such repository is an UNKNOWN line
  with git's reason, and the SAFE line counts only what git could read. Since git no longer fetches, a treeless partial
  clone (`--filter=tree:0`) is one of them.
- **A workflow renamed within `.github/workflows` is listed.** The workflow review now runs `git log --no-renames`, so a
  workflow file renamed into place is listed as added, and a blobless partial clone needs nothing fetched.
- **A workflow added in a repository's first commit is listed, whatever `log.showRoot` says.** Up to 0.1.6, with
  `log.showRoot=false` in the repository's config or your own, `git log` showed no files for a root commit, so a
  workflow added there was missed and the review could read SAFE ([GHSA-x4qj-7j53-r4cv](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x4qj-7j53-r4cv)). git now runs with `-c log.showRoot=true`, and with
  `GIT_NO_REPLACE_OBJECTS=1`, so `refs/replace/` can't swap one commit for another. Found in an independent review.
- **A Python environment found through a relative `--paths` folder is tested.** Since every program runs from `/`, a
  relative folder would have given curl a bundle path it couldn't open, and the environment would have read SAFE.
  Folders are made absolute first, and a curl row whose own bundle can't be found is UNKNOWN. No release had this:
  it was found in the review of 0.1.7 before release.

## [0.1.6] - 2026-10-21

### Security

- Advisory: [GHSA-23m2-fmmq-w3pr](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-23m2-fmmq-w3pr).
- **The OVHcloud CLI check no longer runs the program.** 0.1.0 to 0.1.5 read its version with `ovhcloud --version`.
  On a machine that still held one of the compromised builds, that would have run the credential stealer, which
  OVHcloud's advisory warns against. 0.1.6 never runs it: it compares the file's MD5 with the five compromised builds
  OVHcloud published (GHSA-862f-55f5-vmvw), and looks in `$TMPDIR`, `/tmp` and `/var/tmp` for the `envchecker-NNNNNNNNN`
  folder the stealer leaves every time it runs, so a machine where it already ran is EXPOSED even if the binary is
  gone, while that folder is still in the temp directory (a reboot or temp cleanup can remove it; a SAFE result does
  not clear a machine that installed or updated the CLI in the window). A clean copy reads SAFE whatever its version: OVHcloud says only downloads from the 94-minute window were
  affected, so 0.1.0 to 0.1.5 flagged every copy of v0.11.0 to v0.15.0, wrongly. Found in our own review while updating to the
  advisory. If you ran an earlier Wardlatch with a compromised `ovhcloud` installed, treat every secret the machine held then as
  exposed and replace it, whatever Wardlatch reports now (the advisory has the details).
- Rules can now mark a program as possible malware (`noExec`, `md5Bad`, `tmpTrace`); a test plants a program that
  would leave a marker file and fails if it ever runs.

### Changed

- The OVHcloud fix lists what the stealer took, from OVHcloud's advisory: cloud, SSH, Kubernetes, Docker, npm and
  Terraform credentials, `.netrc` and git credentials, and the histories of AI coding tools.


## [0.1.5] - 2026-10-21

### Changed

- **A second maintainer with full access.** @mlimano5 is an admin of the repository and an owner of the npm package
  ([GOVERNANCE.md](GOVERNANCE.md#continuity)).
- **The repository moved to the Deimos AI organization:** [github.com/deimos-hq/wardlatch](https://github.com/deimos-hq/wardlatch).
  Old links and `git clone` URLs redirect. 0.1.3 and 0.1.4 still verify under the earlier name
  ([docs/RELEASING.md](docs/RELEASING.md#verifying-a-release)).
- PHP's fix text for 8.1 and older now says the PHP project published minimal source backports for 7.4, 8.0 and 8.1, for
  people who build PHP themselves.

## [0.1.4] - 2026-10-21

### Fixed

- **A runtime that blocks the compromised keys outright now reads SAFE, not UNKNOWN.** Node.js 26.12.1, 24.22.1 and
  22.23.4 reject chains through the compromised keys even when their roots are trusted, so Wardlatch's positive control
  (forcing those roots in) could no longer connect, and 0.1.3 reported "positive control failed". Now, when the forced
  roots are refused, Wardlatch opens a normal site: if that works, the refusal is the runtime's own block, and the result
  is SAFE with the note "blocks the compromised keys themselves". If the normal site fails too, it stays UNKNOWN.

### Changed

- The Node.js fix now names the fixed releases: 26.12.1, 24.22.1 and 22.23.4, published on 21 October 2026.

## [0.1.3] - 2026-10-21

### Changed

- **PHP's fixed versions are in.** PHP released 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 21 October 2026, fixing
  CVE-2026-109618 and CVE-2026-109619 (unauthenticated remote code execution). A `php` older than its branch's fix is
  EXPOSED; 8.1 and older are reported as end of life (the PHP project ships them no fix; use a vendor backport or
  move to a supported branch). The "waiting for the release" state is gone.

### Security

- **A found Python virtual environment's own interpreter is never run.** Up to 0.1.2, Wardlatch ran the `bin/python`
  of each environment it found under the searched folders, so a repository cloned from a stranger could ship a fake
  interpreter that would run as you ([GHSA-383w-hfwc-vx2h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-383w-hfwc-vx2h), recorded on 22 October). Now it reads the environment's certifi bundle and version as files and tests the
  bundle with a curl the machine already trusts (`--cacert`). An environment without certifi uses its base Python's
  trust, which is checked through `PATH`. Found by this project's own review; no report of it being exploited.

### Added

- `fix/fix-macos.sh`, the Mac fix: removes the two roots tied to the leaked eMudhra keys from `/etc/ssl/cert.pem`
  with checks around the advisory's change (no change on a fixed Mac, a dated backup it never overwrites, a check of
  the new file before it replaces the old one, permissions kept at 644, a re-test, and a restore on a wrong result).
  It is the same file as the download on www.deimoscore.com (SHA-256 `22153b4a…6a86`). The README documents it.
- Project documents: [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) (sign-off under the DCO, a test
  for every behaviour change), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [GOVERNANCE.md](GOVERNANCE.md),
  [ROADMAP.md](ROADMAP.md), [ASSURANCE_CASE.md](ASSURANCE_CASE.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
  [docs/RELEASING.md](docs/RELEASING.md), and this file.
- Continuous integration on every push and pull request: the tests on Node 18, 20 and 22 on Linux and macOS,
  `node --check` on every module, ShellCheck, the Mac fix's checksum and a run on copies of the certificate file,
  REUSE licence and DCO sign-off checks, CodeQL, OpenSSF Scorecard. A release workflow attests the source archive and
  npm package with Sigstore.
- Tests for the command end to end, the incident data and the coding standard: 36 tests, up from 15.
- A licence and copyright header on every source file, and [REUSE.toml](REUSE.toml) for the rest.

### Changed

- The macOS curl fix text points to the Mac fix download first.
- An unknown option, or `--paths` or `--incident` without a value, is refused with exit code 2 and a message before
  anything runs. Before, an unknown option was ignored and the full check ran, and a trailing `--paths` crashed.
- Names that come from the disk, git or a container engine (file and folder names, plugin folders, authors) are
  printed with control characters escaped, so a planted name can't erase or rewrite its own line on the screen.
  `--json` output was already escaped.
- `--help` and the README name the two control sites (the advisory's page, and a self-signed test site for
  containers) among the connections Wardlatch makes; they mentioned only the test hosts. The README documents every
  option, the statuses, the exit codes and the `--json` fields.
- `package.json` links the GitHub repository, homepage and issue tracker, and adds `npm run coverage`.

### Fixed

- A WordPress plugin whose version header can't be read is "could not be tested" (UNKNOWN, exit code 2), not SAFE.
- The committed-key scan and the WordPress checks check a file's size and read it through one read-only file
  descriptor, so a file swapped in between (for a huge file, a device or a pipe) can't stall or exhaust the run. The
  plugin version header is read under the same 2 MB cap. Found by CodeQL.
- `npm test` runs on Node 22: it passed the `test/` folder, which Node 22's test runner reads as a file name.

## [0.1.2] - 2026-10-21

Published 07:53 UTC. npm `gitHead`: `bcf739c`.

### Added

- Running Docker and Podman containers are checked from inside, with the image's own `curl`, `python3` or `wget`.
  Two controls come first: a normal site must open, and a self-signed one must be refused. Images with no tool
  (distroless) and tools that don't verify certificates say "could not be tested". `--no-containers` skips them.
  Nothing is written into a container.

### Changed

- Fixes that come per release line (PHP, Go) say plainly when your line is end of life and gets no fix.
- eMudhra fix texts: macOS's `/etc/ssl/cert.pem` is read by the built-in curl, git, python3 and openssl, and no macOS
  release has updated it (the current ones date from 28 September 2026); Node's fix is merged and awaiting a release.
  The container fix text points to the home-server section of the page.

### Fixed

- The copyable macOS fix command runs `awk` with `sudo`. With a plain `awk`, a root-only backup could not be read and
  `/etc/ssl/cert.pem` was left empty (advisory issue #35).

## [0.1.1] - 2026-10-21

Published 05:57 UTC. npm `gitHead`: `49ea20c`.

### Added

- `committed-keys-2026-10`: the files your local git repositories track are scanned for high-confidence key shapes
  (cloud keys, private keys, service-account files, GitHub, npm, Slack and Stripe tokens). A finding shows the type,
  file and line, never the key. Lines marked `secrets-ok`, `gitleaks:allow` or `pragma: allowlist secret` are skipped.
- `wordpress-plugins-2026-10`: WordPress installs under the folders searched (and `/var/www`, `~/Sites`) are checked
  for Rank Math PRO 3.0.123 and the attack's indicator, UpdraftPlus before 1.26.13 / 2.26.13, and plugin folders added
  since 18 October to review.

### Fixed

- Long output is no longer cut off when it goes to a pipe: Wardlatch sets its exit code and lets the output finish,
  instead of exiting at once.

## [0.1.0] - 2026-10-21

Published 05:14 UTC. npm `gitHead`: `4d4f295`. The first release.

### Added

- `emudhra-2026-10`: does each runtime on this machine still trust the compromised eMudhra intermediates? Real,
  verified TLS connections to the advisory's 12 test hosts from every `node`, `curl` and `python3` on `PATH`, Python
  virtual environments and their `certifi`, macOS's own networking stack and the Linux distribution's trust store.
  Each host is first checked for reachability, and each runtime first proves it can see exposure (the positive
  control); otherwise the line says "could not be tested", never "safe". cloudflared (fixed in 2026.10.2) and Go
  (1.27.3 / 1.26.10) are checked by version.
- `ovhcloud-cli-2026-10` (OVHcloud CLI 0.11.0 to 0.15.0), `php-2026-10` (pending PHP's fixed versions) and
  `github-actions-2026-10` (workflow files added since 1 September, to review; review lines don't change the exit
  code).
- `--json`, `--list`, `--incident`, `--paths`; exit code 0 safe, 1 exposed, 2 could not be tested.

npm also lists `0.0.0-stage` (21 October, 05:13 UTC), a 331-byte, two-file placeholder from npm's staged publishing,
described on npm as a "Temporary package placeholder". It is not a release and holds none of Wardlatch's code.

[Unreleased]: https://github.com/deimos-hq/wardlatch/compare/v0.1.10...main
[0.1.10]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.10
[0.1.9]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.9
[0.1.8]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.8
[0.1.7]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.7
[0.1.6]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.6
[0.1.5]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.5
[0.1.4]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.4
[0.1.3]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.3
[0.1.2]: https://github.com/deimos-hq/wardlatch/tree/bcf739c318dd60397a76360ac68e04138fd532bd
[0.1.1]: https://github.com/deimos-hq/wardlatch/tree/49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e
[0.1.0]: https://github.com/deimos-hq/wardlatch/tree/4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d
