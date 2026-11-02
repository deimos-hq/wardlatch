# Security policy

Wardlatch is a security tool, so a flaw in it can do harm in a particular way: it can tell someone they are safe
when they are not. That is the first thing in scope below.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/deimos-hq/wardlatch/security/advisories/new) for this
repository. Only the maintainers can see an advisory. Do not open a public issue for a suspected vulnerability.

**You will hear back within 72 hours**, and get a first assessment within 7 days. If you do not, escalate by
messaging Deimos AI LLC on [LinkedIn](https://www.linkedin.com/company/deimoshq/); we will move you to a private
channel. The same route is described at <https://www.deimoscore.com/security/#report>.

Please include what you ran (the command, `wardlatch --help` for the version, the operating system), what Wardlatch
reported, and what was actually true.

## What is in scope

- **A false SAFE.** Any machine state, environment, input or output that makes Wardlatch report SAFE (or makes a
  REVIEW or EXPOSED line disappear) when the thing checked is exposed, including a control that fails without the
  result turning into "could not be tested".
- **Anything that sends data about the user.** Wardlatch's only network traffic is TLS connections to the incident's
  public test hosts and its two control sites (and what your own container engine sends, wherever the current docker
  context points, or a local socket `DOCKER_HOST` names; a remote `DOCKER_HOST` is not followed; `--no-containers` skips it), made through your proxy by a runtime that uses one (the probes are given `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`, in either case, as your own programs are, and the curl probe uses a proxy your curl start-up file names, so a runtime that uses one connects to the proxy, not to the test host), carrying nothing beyond what any request from the runtime being tested
  carries: the machine's address, the runtime's default User-Agent and, for curl, whatever your curl start-up file
  adds to every request. The curl probe reads that file (`~/.curlrc`, or the one `CURL_HOME` or `XDG_CONFIG_HOME`
  points to) as your own curl does, on purpose: a line in it can change what curl trusts (`insecure`, `cacert`), and a
  probe that skipped it could report SAFE for a curl that accepts any certificate. So a header or User-Agent you set
  there goes to the test hosts with the probe's request, as it goes with every request your curl makes; the
  `identity-headers-2026-10` check looks for your name or email in it. Wardlatch itself adds nothing to any request.
  Telemetry, results, paths, names, environment variables, keys or any other detail of the machine leaving it, by any
  route other than your own curl start-up file as just described, is a vulnerability.
- **Anything that modifies the system outside `fix/fix-macos.sh`.** The command changes nothing: no file, setting,
  package or container is written. A path that writes, deletes or changes anything is a vulnerability.
- **The Mac fix damaging `/etc/ssl/cert.pem`.** `fix/fix-macos.sh` must leave the file intact or correctly cleaned:
  never empty, truncated or unparseable, never missing certificates other than the withdrawn roots it removes and
  any certificate carrying one of their keys, readable by
  everyone (644) as macOS ships it, with an earlier backup never overwritten, and the original restored only when
  what landed in the file is not what the script built and checked. **A revert a network can trigger is a
  vulnerability**: putting the original back puts back the withdrawn roots it held (both, or on a Mojave-era Mac the
  one), so a Mac whose network answers for someone else would be the one Mac that could never be fixed. The re-test may report, never revert.
- **Code execution from what Wardlatch reads**: file contents, file and folder names, git output, plugin headers or
  container output that make Wardlatch run something it did not intend to.
- **A secret printed.** A committed-key finding shows the type, file, line and a mask, never the key.

## What is not

- **Trust assumptions the assurance case already states**, such as running the programs on your `PATH`. See
  [ASSURANCE_CASE.md](ASSURANCE_CASE.md#4-what-is-not-defended). A report showing a way to exploit one of them that
  the assurance case does not describe is in scope.
- **Flaws in what Wardlatch checks**: Node, curl, Python, Docker, macOS. Report those to their projects.
- **The advisories' own facts and test hosts.** A wrong fixed version or a test host that is down is a bug in the
  incident data: open a public issue, or tell the advisory's authors.
- **An attacker who already controls your user account or your `PATH`.** They can run anything as you already.

## How a report is handled

1. **Acknowledged** within 72 hours, through the advisory.
2. **Assessed** within 7 days: reproduced, scoped, and given a severity (CVSS). If it is not a vulnerability, you are
   told why, and it may move to a public issue with your agreement.
3. **Fixed** in private, in the advisory's temporary fork, with a test that fails without the fix
   ([CONTRIBUTING.md](CONTRIBUTING.md#testing-policy)).
4. **Released.** A flaw in the command ships as a new version on npm. `fix/fix-macos.sh` is **not** in the npm
   package: it is a download, so a flaw in it ships when four things move together — the file served at
   www.deimoscore.com, its published SHA-256, the source on `main` that the page links, and the site's changelog
   record. Every SHA-256 this file has ever had stays published, because a download has no update channel: a copy
   already on someone's disk is never notified, and the only way they can tell which one they hold is to hash it and
   look the result up. The place that chain lives is the site's **Record**, not the download page: each Record entry
   that changes the file prints the file's new digest and names the entry holding the one before it, back to the
   first. The page prints exactly one digest, the file it is serving now, and the site's build fails on any other
   digest written as 64 lowercase hex digits in a Wardlatch page's `<main>`, the form the pages print — so a
   superseded checksum written that way can't sit beside the current one where a reader could take either for the
   file they have just downloaded. The guard reads only that form: the same digest in capitals, or split by a tag,
   passes it.
5. **Disclosed**: the advisory is published (with a CVE requested through GitHub when the flaw warrants one), and
   [CHANGELOG.md](CHANGELOG.md) names it under the release that fixes it. The fix is reachable before it is
   described: an advisory naming a trigger, while the download still carries the flaw, tells an attacker how to
   use it against people who cannot yet act on it.

**A defect we find ourselves is a report filed at the moment we find it, and runs on the same clock as yours.**
Every deadline above used to bind us only to someone else. That is the wrong way round: we read this code more
than anyone, so most defects in it will be found by us, and the ones we find are the ones no outside clock is
counting. A defect we find in our own tools gets the same 72 hours, the same 7 days, the same advisory and the
same changelog entry, and the dates we found it and shipped it are stated. If we hold one longer than that, the
record says for how long and why. Where this stands on 2 Nov 2026: the defects under Security in 0.1.11 in
[CHANGELOG.md](CHANGELOG.md), which we found ourselves from 29 October, each say the day they were found. None has an
advisory yet, draft or published. The 72 hours passed on 1 Nov for those found on 29 Oct, because
the work of fixing them ran ahead of the paperwork and a posting freeze held every release; that is the reason, and it
is not a good one. The defects under Security in 0.1.12, found on 2 Nov, have the same clock: 72 hours is 5 Nov.

If a fix is not possible or not worth its risk, the advisory says so and explains the workaround, rather than staying
quiet.

## Credit

Reporters are credited by name or handle in the advisory and in the changelog, unless they ask not to be. Say in the
report how you would like to be credited.

## Supported versions

Only the latest release on npm. Run `npx wardlatch@latest` from your home folder (npx also starts Wardlatch with the
current project's own `node_modules/.bin/node` if it has one, and applies its `.npmrc`; Wardlatch can't undo either): a bare `npx wardlatch` runs any copy already installed
globally or in the current project, whatever its version (and npm older than 9.6.5 also reuses a copy npx cached
earlier). Fixes are not backported.

## Verifying what you run

Releases 0.1.0 to 0.1.2 were published to npm from the maintainer's machine and carry no signature of the project's
own (npm's registry signature shows only that npm serves what was uploaded). A release cut from a tag now goes
through the release workflow, which attaches a Sigstore attestation of its source archive and npm package to the
GitHub release; 0.1.3 and every release since went through it. How to check one:
[docs/RELEASING.md](docs/RELEASING.md#verifying-a-release).

`fix/fix-macos.sh` in this repository has SHA-256
`c8bba160a8a9c30f2f850cd8987429b297612ea580e77404fddbbfe7ddc167a6`. CI pins that hash and also checks that the
hash printed here, the pin and the file itself are one string, so a change to the script fails CI until all
three move together (`test/digest-chain.sh`).

www.deimoscore.com has served this file since 2 Nov 2026, the Record's CL-55. When a change ships, the download, the
page's hash, a new entry in the site's public record naming its predecessor, the changelog, the pin and this line all
move together.
