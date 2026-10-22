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
  public test hosts and its two control sites (and what your own container engine sends, wherever `DOCKER_HOST` or the
  current docker context points; `--no-containers` skips it), carrying nothing beyond what any request from the runtime being tested
  carries (the machine's address and the runtime's default User-Agent). Telemetry, results, paths, names, environment
  variables, keys or any other detail of the machine leaving it, by any route, is a vulnerability.
- **Anything that modifies the system outside `fix/fix-macos.sh`.** The command changes nothing: no file, setting,
  package or container is written. A path that writes, deletes or changes anything is a vulnerability.
- **The Mac fix damaging `/etc/ssl/cert.pem`.** `fix/fix-macos.sh` must leave the file intact or correctly cleaned:
  never empty, truncated or unparseable, never missing certificates other than the two it removes, readable by
  everyone (644) as macOS ships it, with an earlier backup never overwritten, and the original restored when the
  re-test says the change did not work.
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
4. **Released** as a new version on npm. If the flaw is in `fix/fix-macos.sh`, the download on
   www.deimoscore.com, its published SHA-256 and the site's changelog record change in the same release.
5. **Disclosed**: the advisory is published (with a CVE requested through GitHub when the flaw warrants one), and
   [CHANGELOG.md](CHANGELOG.md) names it under the release that fixes it.

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

`fix/fix-macos.sh` in this repository is byte-identical to the download on www.deimoscore.com, whose page prints its
SHA-256 (`22153b4acaaa8675f9b4a87390a06cae077f9b5c8f748945ff6b886e400f6a86`). CI pins that hash, so a change to the
script fails CI until the pin, the download and the printed checksum change together.
