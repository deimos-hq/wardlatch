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

1. **The tests pass**: `npm test` (that is, `node --test test/*.test.mjs`) on Node 18.17 or later. CI runs it on Node 18, 20,
   22, 24 and 26, on Linux and macOS.
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

Tests must never read or write the home folder of the person running them. Every test file loads
`test/support/no-real-home.cjs` first (a test checks it). Its purpose is narrow: to catch a test of this project, or a
process it starts, that reads or writes a real home by accident, and fail that test. It is not a sandbox, and code
written to get past it can. It goes with every Node process a test starts through `child_process` (spawn, exec,
execFile, fork and their Sync forms), and with those they start in turn (by `--require`, or by `NODE_OPTIONS`, which the
process gets back as it was), and with each Worker thread one of them starts with `worker_threads.Worker`. There, a look
in a home by these routes fails the test: a path given to an `fs` function (callback, Sync and promise forms) or stream
class, a glob, a `require()` or (from Node 22.15) an `import` of a file, of a package name or of a `#` name of
package.json's `imports` (a package in the checkout's own `node_modules` loads; Node's search going on into a home's
`node_modules` is refused), a change of folder, a working folder there, a program there or found through a `PATH`
folder there (not one a shell command runs: below), a `.env` file `process.loadEnvFile` reads, a `node:sqlite`
database, backup or extension there (on a Node with `setAuthorizer`, a file SQL attaches too; a SQLite URI is refused
whole), a Node started with `--env-file`, `--env-file-if-exists`,
`--experimental-config-file`, `--config-file` or `--experimental-default-config-file` reading a file there; and a walk
that can reach one: a recursive listing, copy, watch or `rm` of a folder that holds it, or a recursive listing, copy,
watch or glob below which a link leads into it. In the test it throws; in a process or Worker the test started it stops
that process or thread (exit 70) and leaves a note that fails the test even when nothing reads that exit code. A path is
compared as the system reads it (links and `..` followed; on macOS in any case, and also by its text with any
`/System/Volumes/Data` or `/Volumes/<x>` at its start taken off, so such a spelling is refused even where it names
nothing), and under sudo SUDO_USER's home is off limits too. The `PATH` the tests start with loses its folders there.
`test/no-real-home.test.mjs` tries each of these routes on a made-up home, and checks that each wrapped fs function
still does its work outside it. A test that needs a home builds one in its own temporary folder;
`test/support/fake-home.cjs` makes one appear at `/Users/<name>` (or `/home/<name>`).

Routes the net is known not to watch, said plainly. The list is not complete: a route named in neither list may be
unwatched too. A test must not reach a home by any of them; the net won't notice.

- A program that isn't Node (git, curl, a shell), and a Node that such a program starts below the command (the command
  builds its children's environments, and tests read them); a program a shell command runs (`execSync`, `exec`,
  `shell: true`: of such a command the net checks only its working folder), wherever it is; a program started with
  `process.execve`.
- What Node itself reads or writes as a process starts or ends, outside any test code: command-line flags other than the
  five above that name a file or folder (`--snapshot-blob`, `--openssl-config`, `--redirect-warnings`,
  `--localstorage-file`, `--tls-keylog`, `--watch-path`, `--test-reporter-destination`, the report, profile and
  diagnostic folders), those five in a shell command's words, a `#!` line or the words of a program that isn't Node
  and starts one (`/usr/bin/env node --env-file=...`), variables such as `NODE_EXTRA_CA_CERTS`, `NODE_V8_COVERAGE`,
  `NODE_COMPILE_CACHE` and `NODE_REPL_HISTORY`, and, for a module outside any package, the package.json Node looks for
  in each folder above it (for the module's type); and, on macOS, the system's CoreFoundation library reading
  `~/.CFUserTextEncoding` as every process starts, Node included, before any code of the test runs.
- Node functions that open a file, folder or socket without `fs`: a unix socket (`net`'s listen and connect, `http`'s
  `socketPath`), `v8.writeHeapSnapshot`, `process.report.writeReport`, `process.dlopen`, WASI's preopened folders,
  `module.enableCompileCache` (it makes and writes its cache folder there), and `module.findPackageJSON`, which reads
  the package.json it finds there (some of its forms are refused, not all: `findPackageJSON('..', base)` is not).
- An `import` on a Node older than 22.15, which has no `module.registerHooks`: there only `require()` is checked.
- Threads the net isn't given: `module.register`'s hooks thread, and a Worker made from the class its prototype gives
  (`Worker.prototype.constructor`).
- Code written to get past it: an option whose getter gives another value when Node reads it, a link or file changed
  between the net's look and Node's, an `fs` function kept from before the net loaded, Node's internal bindings.

| File | For |
|---|---|
| `test/wardlatch.test.mjs` | The checks: probes and their controls, discovery, version rules, workflows, keys, WordPress, containers |
| `test/cli.test.mjs` | The command end to end: options, output, `--json`, exit codes |
| `test/incidents.test.mjs` | The incident data: shape, https sources, the bundled roots' fingerprints, the copyable fix commands |
| `test/conventions.test.mjs` | The coding standard below, where a machine can check it |
| `test/redteam.test.mjs` | Real-world machine setups from the 0.1.9 red team, each asserting what a correct tool says; the limits the 0.1.9 changelog documents run as todo |
| `test/release-check.test.mjs` | The release gate, `scripts/release-check.mjs`, on throwaway repositories |
| `test/mutate.test.mjs` | The mutation gate, `scripts/mutate.mjs --critical`, on a tiny throwaway repository, driven by tests that fail on a fixed schedule and at random; and `scripts/gaps-only-shrink.mjs` |
| `test/corpus.test.mjs` | The corpus runner, `scripts/corpus/run.mjs`, on tiny made-up corpora |
| `test/guardrails.test.mjs` | The workflows' tokens and concurrency, and what the documents say about the gates, read as text |
| `test/no-real-home.test.mjs` | The tests' safety net, `test/support/no-real-home.cjs`: each route it watches, on a made-up home, and its clean twin |
| `test/fix-macos.check.sh` | `fix/fix-macos.sh` on copies of a Mac's `/etc/ssl/cert.pem` (CI, macOS) |

`npm run coverage` (Node 22.8 or later) reports line, branch and function coverage of `bin/` and `lib/` with Node's
built-in coverage, and fails below 80% of lines or functions.

Two more checks test the tests, and CI runs both on every push and pull request:

- **Critical mutants** (`npm run mutate:critical`, Node 22.1 or later): each `'UNKNOWN'` and `'EXPOSED'` in
  `bin/wardlatch.mjs` and `lib/*.mjs` (a status made, passed, returned or compared; the JSON in `lib/incidents/` is not
  planted) is changed to `'SAFE'` in a copy of the code, one occurrence at a time, and the suite must fail on every
  copy. The static test that rejects any SAFE literal outside `safe()` is skipped in the copies, so behaviour tests must
  do the catching, and any other test that reads the code's text instead of running it is found and set aside: a test
  that fails on one more copy, with an inert SAFE in code that never runs at the end of every file planted in, is never
  counted as a catch (the suite runs there at least twice: a test that fails there only some of the time ends the run
  with exit 2; and the static test itself must fail there, or the run stops). A planted bug counts as caught only
  when a test that failed in the suite then fails on its own on the copy and passes on its own on the unmutated code,
  3 times each, interleaved; that test is recorded (results.json, and the job summary in CI). The unmutated code
  must pass first, at least twice at the same load, every test the same each time. A test seen giving different
  results on the same code ends the run with exit 2, named. What that leaves: an uncaught planted bug still reads as
  caught if an unrelated test that fails at random with probability p fails in exactly the right runs, at most
  p⁴(1−p)³ for one planted bug (at most 0.84%), and less for the whole gate to pass with it (`scripts/mutate.mjs` works
  it out). A survivor, a timeout or an error fails CI unless `scripts/mutants-allowed.json` lists the survivor with the
  reason no behaviour can tell it apart, or `scripts/mutants-gaps.json` lists it as a known test gap. The gaps list is
  the honest record of what the tests don't catch yet (8 of the 107 places in the 0.1.9 code, each approved by the
  maintainer on 2026-10-25; the other 34 the 0.1.9 list named are now caught). Both lists may only
  shrink: CI fails when a listed one starts being caught until it comes off its list, and on a change that adds an
  entry to either (`scripts/gaps-only-shrink.mjs`); and the release gate refuses a release while any entry added since
  the last release lacks the maintainer's approval written on it (`"approved": "maintainer, YYYY-MM-DD"`). For a
  release only the maintainer adds to either list: deliberately stricter than [CLAUDE.md](CLAUDE.md), which lets an
  equivalent survivor onto the allow list with a reason a reviewer agreed to. It runs one suite at a time unless
  `--jobs` says more (CI runs 4). `npm run mutate` plants every kind of bug, `'REVIEW'` changed to `'SAFE'` among them
  (26 places in the 0.1.9 code), and only reports what it catches; it runs weekly on GitHub in four shards
  (`.github/workflows/mutation.yml`), not on a laptop.
- **The corpus** (`scripts/corpus/`): realistic machine layouts, clean and bad, run with the change and with the last
  release; every difference is listed in the job summary for review. In CI it is a report: some layouts stand in for
  folders a service or another person owns, which only root can set up. As a gate (`run.mjs --gate`: clean layouts
  exit 0; each bad layout is caught as its manifest says it must be, EXPOSED where it must be EXPOSED, with exit 1 for
  an EXPOSED finding) it is run as root with real owners before a release, and the class audit quotes its GATE PASSED
  line, which names the SHA-256 of the `bin/` and `lib/` it ran: the release gate looks for it, for the release's
  code. It stops, never passing, when it would check nothing: no clean or no bad layout, a bad layout that doesn't say
  what it must find, an unknown `--only` name, a `--jobs` or `--timeout` that isn't a whole number of at least 1, or
  fewer layout × incident runs than the corpus has.

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

Every module is also syntax-checked with `node --check` on Node 18, 20, 22, 24 and 26, the tests run with
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

AI coding agents working in this repository follow [CLAUDE.md](CLAUDE.md) as well as this file.
