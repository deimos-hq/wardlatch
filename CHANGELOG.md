# Changelog

What changed in each release of the `wardlatch` package on npm, newest first, written to help you decide whether to
update. Running `npx wardlatch` always fetches the latest release, so for most people updating means running it again.

Releases are not yet tagged in git. Each entry names the commit npm recorded when it was published (`gitHead`); a pack
of that commit matches the published package's file count and size. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.3] - 2026-10-21

### Changed

- **PHP's fixed versions are in.** PHP released 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 21 October 2026, fixing
  CVE-2026-109618 and CVE-2026-109619 (unauthenticated remote code execution). A `php` older than its branch's fix is
  EXPOSED; 8.1 and older are reported as end of life (the PHP project ships them no fix; use a vendor backport or
  move to a supported branch). The "waiting for the release" state is gone.

### Security

- **A found Python virtual environment's own interpreter is never run.** Up to 0.1.2, Wardlatch ran the `bin/python`
  of each environment it found under the searched folders, so a repository cloned from a stranger could ship a fake
  interpreter that would run as you. Now it reads the environment's certifi bundle and version as files and tests the
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

[Unreleased]: https://github.com/thearchitect0x-glitch/wardlatch/compare/v0.1.3...main
[0.1.3]: https://github.com/thearchitect0x-glitch/wardlatch/releases/tag/v0.1.3
[0.1.2]: https://github.com/thearchitect0x-glitch/wardlatch/tree/bcf739c318dd60397a76360ac68e04138fd532bd
[0.1.1]: https://github.com/thearchitect0x-glitch/wardlatch/tree/49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e
[0.1.0]: https://github.com/thearchitect0x-glitch/wardlatch/tree/4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d
