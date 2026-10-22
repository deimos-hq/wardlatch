# Changelog

What changed in each release of the `wardlatch` package on npm, newest first, written to help you decide whether to
update. Run `npx wardlatch@latest` to get the latest release: a bare `npx wardlatch` runs any copy already installed
globally or in the current project, whatever its version (and npm older than 9.6.5 also reuses a copy npx cached
earlier).

Every release has a signed tag (`v0.1.0` onwards; 0.1.0 to 0.1.2 were tagged afterwards at the commit npm recorded as
each one's `gitHead`), and 0.1.3 onwards were built and attested by the release workflow. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.8] - unreleased

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

- **A git environment variable could point the git checks at another repository, and they read SAFE.** Run where
  `GIT_DIR` or `GIT_WORK_TREE` is set (inside a git hook, or a CI step that sets them), 0.1.0 to 0.1.7 ran every
  `git log` and `git ls-files` against that one repository instead of each repository found, so the GitHub Actions
  review and the committed-key scan reported a repository clean without having read it (exit code 0). Other `GIT_*`
  variables (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_EXEC_PATH` and the like) could set config or name
  programs the `-c` overrides don't cover. 0.1.8 drops every `GIT_*` variable before running git, except the ones that
  only choose your own global and system config files. Found by a new test in our own review; a test sets `GIT_DIR`
  and `GIT_CONFIG_PARAMETERS` and expects the real repository to be read and nothing to run.

### Fixed

- A version with a suffix (`19.4.2-ee`, Plex's `1.43.3.10861-07dfddaeb`) is compared by its leading number; such a
  part used to compare as equal, which could read a vulnerable version as SAFE. A pre-release of a fixed version is
  older than the fix.
- On Windows, which is not supported yet, the installed-software checks report UNKNOWN instead of SAFE.
- OVHcloud's temp-folder marker is matched with any number of digits.
- Release: the workflow checks the attestation bundle (present, one bundle, and `gh attestation verify` for both files,
  bound to this workflow) before it publishes a release, so a change in the attest action can't ship a release without it.
- Tests for branches the suite didn't reach: GOTOOLCHAIN's last line winning and `GOENV=off`; each folder in
  `SSL_CERT_DIR` made absolute; Python and curl failures that aren't certificate refusals; `sitecustomize.py` and
  `usercustomize.py` never run; `.` and empty `PATH` entries; `core.fsmonitor` through `include.path`, `includeIf` and
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

[Unreleased]: https://github.com/deimos-hq/wardlatch/compare/v0.1.7...main
[0.1.7]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.7
[0.1.6]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.6
[0.1.5]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.5
[0.1.4]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.4
[0.1.3]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.3
[0.1.2]: https://github.com/deimos-hq/wardlatch/tree/bcf739c318dd60397a76360ac68e04138fd532bd
[0.1.1]: https://github.com/deimos-hq/wardlatch/tree/49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e
[0.1.0]: https://github.com/deimos-hq/wardlatch/tree/4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d
