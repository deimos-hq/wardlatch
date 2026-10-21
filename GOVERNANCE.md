# Governance

Who decides, and what happens if they stop. Everything here is true as of 21 October 2026, evening; where something is only
planned, it says so.

## Model

Wardlatch is a single-maintainer project published by Deimos AI LLC. The maintainer makes the final decision on
every change, release and incident, after discussion in the open: issues and pull requests on GitHub, with the reason
for a decision written in the commit message, the pull request or the changelog. Anyone may propose anything through
an issue or a pull request ([CONTRIBUTING.md](CONTRIBUTING.md)). A disagreement is settled by the maintainer, who says
why on the thread.

## Roles

| Role | Holder | Responsibilities |
|---|---|---|
| **Maintainer** | [@thearchitect0x-glitch](https://github.com/thearchitect0x-glitch) | Reviews and merges changes; keeps the incident data current as advisories change; answers issues; triages security reports within the times in [SECURITY.md](SECURITY.md); cuts and publishes releases ([docs/RELEASING.md](docs/RELEASING.md)); keeps CI green; keeps `fix/fix-macos.sh` and the copy served on www.deimoscore.com identical; owns the roadmap and these documents. Admin of this repository and an owner of the `wardlatch` package on npm, as is the successor. |
| **Successor** | [@mlimano5](https://github.com/mlimano5) | Named on 21 October 2026. Would take on every maintainer duty if the maintainer cannot continue. **Admin of this repository** since 21 October 2026: he can merge changes, manage issues and settings, and push release tags. **An owner of the `wardlatch` package on npm** since 21 October 2026. See "Continuity" below. |
| **Security contact** | The maintainer, through [SECURITY.md](SECURITY.md) | Receives private vulnerability reports, acknowledges them within 72 hours, and runs the response process. |
| **Contributors** | Anyone | Propose changes under the DCO and the testing policy in [CONTRIBUTING.md](CONTRIBUTING.md). |

## Review

Today the maintainer commits to `main` directly and there is no second reviewer. CI runs on every push and pull
request (tests on Node 18, 20 and 22 on Linux and macOS, ShellCheck, the Mac fix's checksum and a run on copies of
the certificate file, licence and sign-off checks, CodeQL, OpenSSF Scorecard). Requiring an approving review from
someone other than the author, as Deimos's Crimp and Ratchet do, needs a second person with access first; it is on
the [roadmap](ROADMAP.md).

## Continuity

**Status: access in place, not yet rehearsed.** Since 21 October 2026 a second person holds admin access to this
repository and owns the npm package with the maintainer, so either of them can merge changes, manage issues and
settings, and publish a release without the other. Until the successor has done the rehearsal below, that is an access
list, not yet something known to work.

What the project needs to continue without the maintainer is small. There is no service, no database and no secret:
the source in this repository is the whole product, there is no build, and a release is `npm publish` by an owner of
the package. So continuity comes down to two accesses held by a second person:

| Step | Status |
|---|---|
| A named successor with a published role | **Done**, 21 October 2026: @mlimano5, listed above |
| Admin access to this repository for the successor | **Done**, 21 October 2026. The repository moved from the maintainer's personal account to the Deimos AI organization, [deimos-hq](https://github.com/deimos-hq), the same day, so that a second person could hold admin rather than write access. Old links redirect |
| Owner of the `wardlatch` npm package for the successor | **Done**, 21 October 2026: `npm owner ls wardlatch` lists `architect.0x` and `mlimano` |
| A rehearsal: the successor merges a change and publishes a release without the maintainer | **Not done** |

A release tag he pushes would be signed with his own key, so [docs/RELEASING.md](docs/RELEASING.md)'s verification
step would list his signing key next to the maintainer's.

The rehearsal in the last row is what turns the access list into something known to work, and it should be done and
written up here once rather than assumed.

Outside this repository: the Mac fix download and the page at www.deimoscore.com/wardlatch/ are served from Deimos AI
LLC's website, which has its own access and is not covered here. If the site were unavailable, `fix/fix-macos.sh` in
this repository is the source, and its SHA-256 is fixed in CI.

## Changing this file

By a commit or pull request from the maintainer. If the rehearsal row still says "not done" a year from now,
that is information about the project's real risk, and it belongs in the README rather than buried here.
