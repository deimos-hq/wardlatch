# Roadmap

What Wardlatch intends to do, and not do, over the next year. Written 21 October 2026, the day after the first
incident it covers, and reviewed when it stops being true rather than on a schedule.

Wardlatch answers one question for the machine it runs on: does a key that leaked this week still open anything here?
Everything below is judged against whether the answer stays honest (never SAFE without a control), local (nothing
sent, nothing changed) and quick to act on (a fix on every line).

## Now: shipped and tested

- Trust probes for a compromised certificate authority (eMudhra, October 2026): every `node`, `curl` and `python3` on
  `PATH`, Python virtual environments and their `certifi`, the macOS networking stack, the Linux distribution's trust
  store, and running Docker and Podman containers, each behind a reachability control and a positive control.
- Version rules for tools with a bad range or a fixed version (OVHcloud CLI, cloudflared, Go, PHP, one fix per
  release line), file checks for committed keys and WordPress plugins, and a review list of new GitHub workflow files.
- `--json` and exit codes for CI; a fix text on every exposed line.
- `fix/fix-macos.sh`, the Mac fix with checks around the advisory's change.

## Next: the coming months

- **Keep the current incidents current.** Done so far: PHP's fixed versions (0.1.3), Node's fixed releases (0.1.4),
  OVHcloud's published hashes (0.1.6). Next: any macOS update that replaces `/etc/ssl/cert.pem` changes the Mac fix
  text. Each change gets a dated changelog line.
- **New incidents as they happen**, when there is a public source and something checkable on a machine. That is the
  reason the tool exists, and it outranks everything else on this list.
- **Retiring incidents.** Decide, and write down, when an incident stops being checked by default (for example once
  the fixed versions are widely deployed) so the default run stays fast and relevant. Retired incidents stay
  available with `--incident`.
- ~~Narrow the Python trust assumption.~~ Done after 0.1.2: a found environment's interpreter is never run; its
  certifi bundle is read as a file and tested with a trusted curl (see [ASSURANCE_CASE.md](ASSURANCE_CASE.md)).
- ~~Signed releases and tags.~~ Done: 0.1.3 onwards are attested by the release workflow from signed tags, and 0.1.0
  to 0.1.2 have signed tags at the commits npm recorded.
- **A second maintainer**, then required review: see [GOVERNANCE.md](GOVERNANCE.md#continuity). The successor has
  had admin access and co-owned the npm package since 21 October 2026; next is a rehearsed release. Then every change to `main` goes through a pull
  request approved by someone other than its author.
- **Windows.** Not supported yet, and the README says so. Next: Windows paths for the installed-software checks, a
  Windows CI job, then support.

## Later: under consideration, not committed

- **Browsers.** Each browser keeps its own trust decisions; today the README sends you to the advisory's own check
  page. A local browser check would need to drive a browser, which is a different kind of tool.
- **Git history for committed keys.** Today only current files are scanned, and the fix text points to gitleaks or
  trufflehog for history. Doing it here would duplicate tools that do it well.
- **Localisation** of the output. The status words and exit codes are stable for scripts; the prose is English only.

## Explicitly not doing

These are decisions, not omissions.

- **Telemetry, accounts or any upload.** Wardlatch sends nothing about the machine anywhere, and will not, including
  "anonymous" statistics.
- **Changing the system from the command.** The command reports and gives the fix; applying it is the person's
  decision. The one exception is the separate, opt-in Mac fix script.
- **Guessing from version numbers where a real test is possible.** A trust check opens a real connection; a version
  table can be wrong in ways nobody notices.
- **A SAFE without a control.** If a check cannot show it could have seen exposure, it says "could not be tested".
- **Runtime dependencies.** Node's built-in modules only, so a supply-chain incident can't arrive through the tool
  meant to find one.
- **A score.** Each line says what was checked and what was found; there is no blended number to hide that behind.

## How this changes

By the maintainer when reality moves, or by pull request. If something here has been "Next" for a year, it belongs in
"Later" or in "Not doing", and moving it is more honest than leaving it.
