# Wardlatch

[![CI](https://github.com/deimos-hq/wardlatch/actions/workflows/ci.yml/badge.svg)](https://github.com/deimos-hq/wardlatch/actions/workflows/ci.yml)
[![CodeQL](https://github.com/deimos-hq/wardlatch/actions/workflows/codeql.yml/badge.svg)](https://github.com/deimos-hq/wardlatch/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15757/badge)](https://www.bestpractices.dev/projects/15757)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/deimos-hq/wardlatch/badge)](https://scorecard.dev/viewer/?uri=github.com/deimos-hq/wardlatch)
[![npm](https://img.shields.io/npm/v/wardlatch)](https://www.npmjs.com/package/wardlatch)

**Does the wrong key still turn?**

When a certificate authority's keys leak, browsers update within hours. The rest of your machine doesn't. curl, Node,
Python and every project's own certificate bundle each keep their own list of who to trust, and each has to be fixed
on its own. Wardlatch tells you which ones still trust the leaked keys, and checks this week's other leaks too.

```
npx wardlatch@latest
```

Run it from your home folder (`cd ~` first), not from inside a project: npx also starts Wardlatch with the current
project's own `node_modules/.bin/node` if it has one, and applies its `.npmrc`; Wardlatch can't undo either. Use `@latest`: a bare `npx wardlatch` runs any copy already installed globally or in the current project, whatever its version (and npm older than 9.6.5 also reuses a copy npx cached earlier). If you installed Wardlatch, update that copy too (`npm install -g wardlatch@latest` for a global copy, `npm install wardlatch@latest` in the project), or remove it. `wardlatch --help` prints the version without running any check.

Runs on macOS and Linux, tested on both in CI. **Windows is not supported yet:** some checks don't look in Windows
locations, so a Windows run can miss what it should find. The trust check and the program checks say UNKNOWN there.

```
SAFE     node 26.12.0  /opt/homebrew/bin/node
EXPOSED  node 26.12.0  /usr/local/bin/node  trusts 6/12
         fix: update Node.js to 26.12.1, 24.22.1 or 22.23.4 or later ...
SAFE     curl 8.7.1  /usr/bin/curl
SAFE     certifi 2026.10.19  ~/Development/app/.venv

11 safe · 1 exposed · 0 could not be tested
```

## How it works

It doesn't compare version numbers. It asks each runtime to open a real, verified TLS connection to public test hosts
whose certificates are signed with the compromised keys, the way your own code would, with your own environment.
If a runtime connects, it still trusts them. Two exceptions keep it from running what it checks: Python is started
with `-I -S`, so a `.pth` file or `sitecustomize.py` that changes its trust (pip-system-certs, for example) is not
applied, and, as before, the `certifi` in the own site-packages of a Python on your `PATH` is not tested yet (a
virtual environment's is); and every program runs from `/`, so a version manager picks your default, not the current project's.

Two checks keep the answer honest:

- **Is the test host up?** Each host is first reached with verification off. If none answers, the result is
  *could not be tested*, never *safe*.
- **Could this check have failed?** Each runtime is first run once with the compromised roots forced in. If it can't
  connect even then, the probe can't see exposure on that runtime, and the result is *could not be tested*, never
  *safe*.

## What it looks at

- every `node`, `curl` and `python3` on your `PATH` (except in `node_modules/.bin` folders and relative entries, which
  are dropped so a project can't have Wardlatch run its programs), plus the operating system's own
- Python virtual environments (and their `certifi`) under `~/Development`, `~/code`, `~/src`, `~/projects`, `~/Projects`,
  `~/dev`, `~/work`, `~/Sites` and `/var/www`, or the folders you give with `--paths`
- every running Docker or Podman container, checked from inside with the image's own curl, python3 or wget. Two
  controls come first: a normal site must open, and a self-signed one must be refused, or the result is "couldn't
  test". `--no-containers` skips them. Nothing is written into a container.

Compiled programs (Go, Rust, Electron) carry the trust list of the toolchain that built them; Wardlatch prints what to
rebuild them with. Check your browser on the advisory's own page.

## The Mac fix

`fix/fix-macos.sh` removes the two roots tied to the leaked eMudhra keys from `/etc/ssl/cert.pem` (the advisory's
change) with checks around it: no change on a fixed Mac, a dated backup it never overwrites, a check of the new file
before it replaces the old one, a re-test, and a restore on a wrong result. Download it in Safari from
https://www.deimoscore.com/wardlatch/#mac and run `bash ~/Downloads/wardlatch-fix-macos.sh`, or deploy it as a root
script from Jamf, Kandji or Intune.

## Privacy

Wardlatch runs on your machine. It sends nothing anywhere: no telemetry, no results, no machine details. The only
network traffic is TLS connections to the incident's public test hosts and two control sites (the advisory's own
page, and a self-signed test site for containers), and your own container engine, wherever `DOCKER_HOST` or the
current docker context points (`--no-containers` skips it). It changes nothing on your system; each result comes with the fix
for you to apply. What it can and can't promise, and why: [ASSURANCE_CASE.md](ASSURANCE_CASE.md).

## Reference

| Option | |
|---|---|
| *(none)* | Check this machine against every current incident. |
| `--incident <id>` | One incident only. `--list` prints the ids. |
| `--paths <folder>` | Where to look for Python environments, git repositories and WordPress sites; repeat it for several. Default: `~/Development`, `~/code`, `~/src`, `~/projects`, `~/Projects`, `~/dev`, `~/work`, `~/Sites` and `/var/www`. |
| `--no-containers` | Skip Docker and Podman: running containers, and the local image list. |
| `--json` | Machine-readable output instead of lines (below). |
| `--list` | The incidents it knows: id, date, title. |
| `-h`, `--help` | Usage. |

An unknown option, or `--paths` or `--incident` without a value, stops with exit code 2 before anything runs.

Each line starts with a status: `SAFE`, `EXPOSED` (with the fix under it), `UNKNOWN` (could not be tested, with the
reason) or `REVIEW` (something to look at, such as a new workflow file). The exit code is **1** if anything is
exposed, otherwise **2** if anything could not be tested, otherwise **0**. Review lines never change it.

`--json` prints one object: `{ tool, version, incidents: [{ id, title, advisory }], results: [...] }`. Each result
has `incident`, `status` and `kind` (`node`, `curl`, `python`, `macos-system`, `container`,
`containers` when an engine can't be asked, `runtimes` when a trust check found nothing to test, `binary`,
`install`, `header`, `workflow`, `secret` or `wordpress`; a virtual environment's certifi is kind `curl` with `certifi` and `env`), the fields of that kind (such as `bin`, `version`, `trusted` and `tested` for a
trust probe, or `file`, `line`, `type` and `masked` for a key), `reason` when it is UNKNOWN, and `fix` when there is
something to do.

```
npx wardlatch@latest --json          # for CI and scripts
npx wardlatch@latest --incident emudhra-2026-10 --no-containers
npx wardlatch@latest --paths ~/code --paths /srv/www
```

## Feedback, contributing, security

- Bugs, wrong results and ideas: [issues](https://github.com/deimos-hq/wardlatch/issues).
- Changes: [CONTRIBUTING.md](CONTRIBUTING.md) (pull requests, sign-off, a test with every change).
- A vulnerability: report it privately, as [SECURITY.md](SECURITY.md) explains, not in an issue.
- How it works inside: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). What changed: [CHANGELOG.md](CHANGELOG.md).
  Where it is going: [ROADMAP.md](ROADMAP.md). Who decides: [GOVERNANCE.md](GOVERNANCE.md).
  [Code of conduct](CODE_OF_CONDUCT.md).

To work on it: `git clone`, then `npm test`. Nothing to install.

## Incidents

`npx wardlatch@latest` checks all of them; `--incident <id>` checks one.

- `emudhra-2026-10`: eMudhra intermediate CA compromise, 20 Oct 2026 ([advisory](https://emudhra.we-have-a-problem.com/)). Real TLS probes per runtime, plus cloudflared (fixed in 2026.10.2) and the Go toolchain (1.27.3 / 1.26.10).
- `ovhcloud-cli-2026-10`: OVHcloud CLI v0.11.0 to v0.15.0 swapped for a secret-stealer on 19 Oct ([OVHcloud's advisory](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw)). Never runs the program: compares the installed file with the five compromised builds OVHcloud published, and looks for the `envchecker-` folder the stealer leaves in the temp directory.
- `php-2026-10`: two critical PHP flaws (CVE-2026-109618 and CVE-2026-109619), fixed on 21 Oct in 8.5.12, 8.4.27, 8.3.36 and 8.2.35 ([report](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)). Flags an installed PHP older than its line's fix, or on a line with no fix.
- `github-actions-2026-10`: credential-stealing workflow files planted in tens of thousands of repositories since 7 Oct ([report](https://thehackernews.com/2026/10/credential-stealing-github-actions.html)). Lists workflow files added to your local repositories since 1 Sep, to review. Review lines don't change the exit code.

- `committed-keys-2026-10`: keys committed to code, the lesson of the TiDB Cloud breach ([PingCAP](https://www.pingcap.com/trust-hub/security/security-update-october-2026/)). Scans the files your local git repositories track for cloud keys, private keys, service-account files and GitHub, npm, Slack and Stripe tokens. A finding shows the type, file and line, never the key. Lines marked `secrets-ok`, `gitleaks:allow` or `pragma: allowlist secret` are skipped. Current files only: for history, use gitleaks or trufflehog.

- `wordpress-plugins-2026-10`: Rank Math PRO 3.0.123 shipped with a backdoor (15 to 16 Oct; clean 3.0.124) and stolen UpdraftCentral keys were used to plant backdoor plugins from 18 Oct ([Patchstack](https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/)). Finds WordPress installs under the folders searched (and `/var/www`), flags Rank Math PRO 3.0.123 and the attack's indicator, UpdraftPlus before 1.26.13 / 2.26.13, and lists plugin folders added since 18 Oct to review. Run it on the server.
- `gitlab-2026-10`: GitLab CVE-2026-110264, unauthenticated code execution on self-managed GitLab, fixed 21 Oct in 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10 and 18.11.13 ([GitLab](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/)). Reads the version from GitLab's own version files; never runs GitLab. Docker and Kubernetes installs aren't checked yet.
- `litellm-2026-10`: LiteLLM 1.107.0 on PyPI and Docker shipped a credential stealer on 21 Oct ([LiteLLM](https://docs.litellm.ai/blog/security-incident-oct-21-2026)). Looks in Python's site-packages for the release record and the files it drops (by SHA-256), in the temp folders for its markers, and at local image digests and tags; never starts Python for this.
- `plex-2026-10`: Plex Media Server, four chained flaws exploited since 16 Oct, fixed in 1.43.3.10861 ([Plex](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319)). Reads the version from the Debian package record or the macOS app; never runs Plex.

When the next one happens, it gets added here.

---

A free tool from Deimos AI LLC. Apache-2.0.
