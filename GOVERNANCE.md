# Governance

Who decides, and what happens if they stop. Everything here is true as of 21 October 2026; where something is only
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
| **Maintainer** | [@thearchitect0x-glitch](https://github.com/thearchitect0x-glitch) | Reviews and merges changes; keeps the incident data current as advisories change; answers issues; triages security reports within the times in [SECURITY.md](SECURITY.md); cuts and publishes releases ([docs/RELEASING.md](docs/RELEASING.md)); keeps CI green; keeps `fix/fix-macos.sh` and the copy served on www.deimoscore.com identical; owns the roadmap and these documents. Holds the only admin access to this repository and is the only owner of the `wardlatch` package on npm. |
| **Proposed successor** | [@mlimano5](https://github.com/mlimano5) | Pending. Would take on every maintainer duty if the maintainer cannot continue. **Has no access yet**: not a collaborator on this repository and not an owner of the npm package. See "Continuity" below. |
| **Security contact** | The maintainer, through [SECURITY.md](SECURITY.md) | Receives private vulnerability reports, acknowledges them within 72 hours, and runs the response process. |
| **Contributors** | Anyone | Propose changes under the DCO and the testing policy in [CONTRIBUTING.md](CONTRIBUTING.md). |

## Review

Today the maintainer commits to `main` directly and there is no second reviewer. CI runs on every push and pull
request (tests on Node 18, 20 and 22 on Linux and macOS, ShellCheck, the Mac fix's checksum and a run on copies of
the certificate file, licence and sign-off checks, CodeQL, OpenSSF Scorecard). Requiring an approving review from
someone other than the author, as Deimos's Crimp and Ratchet do, needs a second person with access first; it is on
the [roadmap](ROADMAP.md).

## Continuity

**Status: not in place. The bus factor is 1.** If the maintainer stopped today, nobody else could merge a change,
close an issue as a maintainer, or publish a release on npm.

What the project needs to continue without the maintainer is small. There is no service, no database and no secret:
the source in this repository is the whole product, there is no build, and a release is `npm publish` by an owner of
the package. So continuity comes down to two accesses held by a second person:

| Step | Status |
|---|---|
| A named successor with a published role | **Proposed**: @mlimano5, listed above; pending the steps below |
| Admin access to this repository for the successor | **Not done** |
| Owner of the `wardlatch` npm package for the successor | **Not done** |
| A rehearsal: the successor merges a change and publishes a release without the maintainer | **Not done** |

What the maintainer has to do to close the first three:

1. Add @mlimano5 as a collaborator with the **Admin** role: GitHub, Settings, Collaborators, "Add people", or
   `gh api -X PUT repos/thearchitect0x-glitch/wardlatch/collaborators/mlimano5 -f permission=admin`. He accepts the
   invitation.
2. Add him as an owner of the npm package, once he has an npm account with two-factor authentication:
   `npm owner add <his npm username> wardlatch`. Check with `npm owner ls wardlatch`.
3. Update this file in the same week: the successor row loses "proposed", the table says "Done" with the date, and
   the status line changes.

Then either person can create and close issues, accept changes and publish a release without the other. The rehearsal
in the last row is what turns that from an access list into something known to work, and it should be done and
written up here once rather than assumed.

Outside this repository: the Mac fix download and the page at www.deimoscore.com/wardlatch/ are served from Deimos AI
LLC's website, which has its own access and is not covered here. If the site were unavailable, `fix/fix-macos.sh` in
this repository is the source, and its SHA-256 is fixed in CI.

## Changing this file

By a commit or pull request from the maintainer. If the successor row still says "proposed" a year from now, that is
information about the project's real risk, and it belongs in the README rather than buried here.
