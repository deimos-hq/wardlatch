# Contributing

Bug reports, corrections to incident data, new incidents and code are all welcome.

- **A bug, a wrong fix text, or an idea**: open an [issue](https://github.com/deimos-hq/wardlatch/issues).
  For a wrong result, paste what Wardlatch printed (remove anything private) and what was actually true.
- **A new incident**: open an issue with the advisory's link. An incident needs a public source and something on a
  machine that can be checked locally; see "Incidents" below.
- **A change**: open a pull request against `main`. CI runs on every pull request; the maintainer reviews and
  merges. Small, focused pull requests are easier to review than large ones.
- **A security vulnerability**: not an issue. See [SECURITY.md](SECURITY.md).

How decisions are made is in [GOVERNANCE.md](GOVERNANCE.md); expected behaviour is in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Certificate of origin

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/) 1.1:

    git commit -s

The `Signed-off-by:` line certifies that you wrote the change, or otherwise have the right to submit it under this
project's Apache-2.0 licence, and that you understand the contribution is public. CI checks every commit a push or
pull request adds, and fails on one without it (Dependabot's commits, made by a bot, are exempt). The first 13
commits on `main`, up to 21 October 2026, predate this rule and carry no sign-off.

## What an acceptable contribution looks like

1. **The tests pass**: `npm test` (that is, `node --test test/*.test.mjs`) on Node 18.17 or later. CI runs it on Node 18, 20
   and 22, on Linux and macOS.
2. **It comes with tests**: see the testing policy below.
3. **It never says SAFE without a control.** A check may report SAFE only when a control has shown that it could have
   seen the problem: the test host answered (reachability), and the runtime connects when the compromised roots are
   forced in (positive control), or for a probe that can't force a root, it opens a normal site (and, inside a
   container, refuses a self-signed one). When a control fails or can't be run, the result is UNKNOWN ("could not be
   tested"), never SAFE. A new check comes with a test that a failed control gives UNKNOWN.
4. **It has no runtime dependencies.** Node's built-in modules only. `package.json` has no `dependencies` and a test
   enforces it. There are no development dependencies either; propose one in an issue before adding it.
5. **It stays local and read-only.** The command reads, runs the runtimes it checks, and opens TLS connections to the
   incident's test hosts and control sites. It writes nothing, changes nothing and sends nothing else. Only
   `fix/fix-macos.sh` changes the system, and only when someone runs it on purpose.
6. **It leaves `fix/fix-macos.sh` byte-identical**, unless the change is to the Mac fix itself. www.deimoscore.com
   serves that exact file and prints its SHA-256, and CI fails if the hash changes. A deliberate change updates the
   site's download, the printed hash and the site's changelog record together, and is tested on copies of the
   certificate file with `test/fix-macos.check.sh`.
7. **The documents stay true.** If a change makes a sentence in the README, [ASSURANCE_CASE.md](ASSURANCE_CASE.md)
   or [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) untrue, that sentence changes in the same commit, and the change
   gets a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

## Testing policy

This is a formal requirement, not a preference.

**Any change that adds or alters behaviour MUST include a test** in the automated suite (`test/`). A pull request
that changes behaviour without one will not be merged. That covers a new check, a new incident type, a new option, a
change to what any line or exit code says, and a change to a control.

**Every bug fix MUST come with a regression test** that fails without the fix. Put the fix back out, watch the test
fail, then restore it; a test that has never failed has not shown it can.

Tests run offline. A check that needs the network is tested against a local stand-in (the suite builds a throwaway
certificate authority and a canary server on 127.0.0.1, fake programs on a private `PATH`, and fake containers),
never against the advisory's real hosts.

| File | For |
|---|---|
| `test/wardlatch.test.mjs` | The checks: probes and their controls, discovery, version rules, workflows, keys, WordPress, containers |
| `test/cli.test.mjs` | The command end to end: options, output, `--json`, exit codes |
| `test/incidents.test.mjs` | The incident data: shape, https sources, the bundled roots' fingerprints, the copyable fix commands |
| `test/conventions.test.mjs` | The coding standard below, where a machine can check it |
| `test/fix-macos.check.sh` | `fix/fix-macos.sh` on copies of a Mac's `/etc/ssl/cert.pem` (CI, macOS) |

`npm run coverage` (Node 22.8 or later) reports line, branch and function coverage of `bin/` and `lib/` with Node's
built-in coverage, and fails below 80% of lines or functions.

## Coding standards

**JavaScript** (`bin/`, `lib/`, `test/`) follows the house style of the existing code. These rules are checked by
`test/conventions.test.mjs`, so a pull request that breaks one fails CI:

- ES modules (`.mjs`); imports are Node built-ins with the `node:` prefix, or the project's own files.
- Child processes are started with `execFile` or `execFileSync` and an argument list; never `exec`, never
  `shell: true`, never `eval` or `new Function`.
- The shipped code (`bin/`, `lib/`) imports no function that writes, moves or deletes files, and opens files only with
  `O_RDONLY`.
- Only `lib/probe.mjs` opens network connections.
- Certificate verification is never switched off, except the one reachability handshake in `lib/probe.mjs`, which
  sends nothing. No `--insecure`, `-k`, `NODE_TLS_REJECT_UNAUTHORIZED`, `CERT_NONE` or the like.
- Every source file opens with `SPDX-License-Identifier: Apache-2.0` and `Copyright 2026 Deimos AI LLC` (after the
  shebang, if any). `fix/fix-macos.sh` is the exception, covered by [REUSE.toml](REUSE.toml).
- UTF-8, LF line ends, no tabs, no trailing spaces, a final newline.

Every module is also syntax-checked with `node --check` on Node 18, 20 and 22, the tests run with
`--throw-deprecation` so a deprecated Node API fails CI, and CodeQL's `security-and-quality` queries run on every
push. Layout that no tool checks (two-space indentation, single quotes, semicolons, comments that say why rather than
what) is settled in review by matching the surrounding code.

**Shell** (`fix/`, `test/*.sh`): bash with `set -euo pipefail`, every expansion quoted, and clean under
[ShellCheck](https://www.shellcheck.net/)'s default checks, which CI runs.

## Incidents

Each incident is one JSON file in `lib/incidents/`, named after its `id`. It needs a public, https `advisory` source;
a check that runs locally (a trust probe, a version rule, a file or plugin rule); and a fix text a person can act on.
State only what the source supports, and credit it. When an advisory changes (a fixed version ships, a test host
moves), the incident file changes with a dated line in the changelog.

## Working on it

    git clone https://github.com/deimos-hq/wardlatch.git
    cd wardlatch
    npm test                     # needs node 18.17+, git and openssl on the machine; nothing to install
    node bin/wardlatch.mjs       # run the command from the checkout

Releases are cut by the maintainer: [docs/RELEASING.md](docs/RELEASING.md).
