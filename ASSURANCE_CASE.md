# Assurance case

Why Wardlatch's security requirements are met, and where they are not.

An assurance case is an argument, not a checklist. This states what Wardlatch must guarantee, what it defends
against, where the trust boundaries are, and the evidence for each claim, naming the test or mechanism that enforces
it. **Where something is not defended, it says so.** A case that claims more than it can support is worse than none.

Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Reporting a flaw: [SECURITY.md](SECURITY.md).

---

## 1. What Wardlatch must guarantee

These are its security requirements: what a user can rely on.

| # | Requirement | Why it matters |
|---|---|---|
| **R1** | **Never SAFE without evidence.** A line says SAFE only after a control has shown the check could have seen exposure; otherwise it says "could not be tested" (UNKNOWN), and the exit code is 2, not 0. | A security check that says SAFE when it couldn't know is worse than no check: people stop looking. |
| **R2** | **Sends nothing about the user.** The only network traffic is TLS connections to the incident's public test hosts and two control sites (the advisory's page, and a self-signed test site for containers). | People run it on work machines and servers. It must not become a leak while looking for one. |
| **R3** | **The command changes nothing.** No file, setting, package or container is written, moved or deleted. | A diagnostic must be safe to run anywhere, including in CI and on production servers. |
| **R4** | **Never prints a secret it finds.** A committed key is reported by type, file, line and a mask. | Output is pasted into tickets and chats. |
| **R5** | **What it reads can't forge what it prints.** Names from the disk, git and containers can't hide or rewrite a line. | The things being checked may be under an attacker's control (a compromised WordPress site, a cloned repository). |
| **R6** | **No host shell, no dependencies.** Programs are started with argument lists; the code is Node's standard library and this repository. | Removes command injection and a supply chain from a tool meant for supply-chain incidents. |
| **R7** | **The Mac fix leaves `/etc/ssl/cert.pem` intact or correctly cleaned, never worse**, with a backup it never overwrites, and puts the original back if the result is wrong. | It runs as root on a file every built-in tool on the Mac depends on. |

What a user **cannot** expect: a SAFE covers the runtimes Wardlatch found, for the incidents it knows, at the moment
it ran, and nothing more. It fixes nothing (except the Mac fix, when run). It does not check browsers, compiled
programs, files inside container images, other user accounts, or git history (see section 4).

## 2. Threat model

**Assets:** the truth of the answer; the integrity of the machine; the privacy of the machine and its secrets; the
integrity of `/etc/ssl/cert.pem` when the Mac fix runs.

**Adversaries considered:**

- **Whoever holds the leaked keys** (the incident's attacker). The reason the tool exists. They would prefer the
  machine to stay exposed and to be reported SAFE.
- **Hostile content in the places Wardlatch looks**: a cloned repository from a stranger, a compromised WordPress
  site with planted plugins, a container running somebody else's image. Wardlatch reads all of these, and some of
  them are under an attacker's control by definition.
- **The network and the test hosts.** The advisory's test hosts are run by third parties; the path to them is
  untrusted.
- **A supply-chain attacker** targeting the package, its dependencies or its CI.

**Out of scope:** an attacker who already runs code as the user or as root, or controls the user's `PATH`; a hostile
maintainer; a compromise of npm itself or of the runtimes being checked.

## 3. Trust boundaries and the argument

```
   untrusted network                    the user's machine (runs as the user, never asks for root)
 ┌──────────────────┐   TLS only    ┌─────────────────────────────────────────────────────────────┐
 │ advisory test    │◄──────────────┤ probe.mjs ── runtimes on PATH (trusted like the user's shell) │
 │ hosts, controls  │  B1           │      │                                                      │
 └──────────────────┘               │ bin/wardlatch.mjs ◄── lib/incidents (shipped, reviewed data) │
                                    │      │                                                      │
 ┌──────────────────┐  read, git,   │      ├─ B2 ──► scanned folders: repositories, venvs,        │
 │ terminal / CI    │◄─ B5 ─────────┤      │         WordPress sites (partly attacker-controlled)  │
 │ (escaped text,   │  escaped      │      └─ B3 ──► containers via docker/podman exec            │
 │  or JSON)        │               │                (attacker-controlled images)                 │
 └──────────────────┘               └─────────────────────────────────────────────────────────────┘
   B4: npm ──► the user (the package itself)        B6: fix-macos.sh ──► /etc/ssl/cert.pem (as root)
```

**R1, never SAFE without evidence: boundary B1.**
Three controls stand between a failed connection and a SAFE. (1) Reachability: a host that doesn't complete a
handshake is left out, and with no host up, every line is UNKNOWN. (2) The positive control: the same runtime must
connect to a live test host when it trusts only the compromised roots, or the line is UNKNOWN; this catches a runtime
that can't connect at all (a proxy, a firewall, a broken install) and would otherwise look like a refusal. (3) Where a
root can't be forced (macOS's networking stack, containers), a normal site must open first, and inside a container a
self-signed site must be refused, or the line is UNKNOWN. UNKNOWN sets exit code 2, so CI does not pass on it.
*Evidence:* `test/wardlatch.test.mjs` (no host up is UNKNOWN; a failed positive control is UNKNOWN; a failed system
control is UNKNOWN; containers with no tool, or a tool that accepts a self-signed site, are UNKNOWN; a plugin whose
version can't be read is UNKNOWN) against a local throwaway CA and canary; `test/cli.test.mjs` for the exit codes. `test/incidents.test.mjs` checks that the bundled
roots are exactly the advisory's, by SHA-256 fingerprint, so the positive control forces in the right keys.

**R2, sends nothing: boundary B1.** Only `lib/probe.mjs` opens connections, and the containers' probe script makes
its requests from inside the container to the same hosts. The probes send a plain `GET /` and add nothing from the
machine: a request carries only what any request from that runtime carries (the machine's address, and the runtime's
default User-Agent, which names it and its version). Responses are discarded (`-o /dev/null`, `r.resume()`), and only
success or failure is read. The reachability handshake sends no request at all. There is no telemetry code. *Evidence:* `test/conventions.test.mjs`
fails if any other shipped module imports a network module or calls `fetch`.

**R3, changes nothing.** The shipped code imports no file-writing function, opens files only read-only, and the
container probe only runs a request. *Evidence:* `test/conventions.test.mjs` fails on any import of a write, delete,
rename, copy or chmod function in `bin/` or `lib/`, and on any `open` without `O_RDONLY` or with a flag that writes.

**R4, no secret printed.** `scanText` keeps the first four characters and the length, or a fixed marker for private
keys and service-account files. *Evidence:* `test/wardlatch.test.mjs` and `test/cli.test.mjs` assert the key never
appears in text or JSON output.

**R5, output can't be forged: boundary B5.** Every name printed passes through one function that escapes control
characters (`\x1b` is shown, not obeyed), so a plugin folder named to clear its own line shows up in full. `--json`
output is escaped by `JSON.stringify`. *Evidence:* `test/cli.test.mjs` plants such a folder and checks that no raw
control character reaches the output.

**R6, no host shell, no dependencies: boundaries B2, B3, B4.** Every program is started with `execFile` and an
argument list, so a file or container name is never parsed by a shell. Inside a container, the probe script is a
fixed string and the URL and timeout are passed as positional arguments (`"$1"`, `"$2"`), not spliced in. Options are
checked against an allowlist before anything runs. `package.json` declares no dependencies. *Evidence:*
`test/conventions.test.mjs` (only `execFile`/`execFileSync`, no `shell: true`, no `eval`, imports only `node:`
built-ins and the project's files, no `dependencies`); `test/cli.test.mjs` (unknown options refused).

**R7, the Mac fix: boundary B6.** The script refuses a file that looks damaged (fewer than 50 certificates), writes
the cleaned copy to a fresh `mktemp` file and checks it before using it (the two roots gone, every other certificate
still there, at least 50 left), makes a dated backup and refuses to overwrite an existing one, copies the clean file
in and sets 644, then re-tests with `/usr/bin/curl` and restores the backup if the file still trusts the test host.
It changes nothing on a Mac that is already clean, so running it twice is safe. *Evidence:* CI runs
`test/fix-macos.check.sh` on macOS against copies of the runner's real `/etc/ssl/cert.pem`: the original, a second
run, undo from the backup, an empty file, a truncated file and a missing file, plus the refusal on Linux. CI also
fails if the script stops matching the SHA-256 published with the download, so the file people run is the file that
was tested.

### Secure design principles

| Principle | How it applies |
|---|---|
| Economy of mechanism | About 600 lines, no dependencies, no build step, no server, no configuration file. |
| Fail-safe defaults | Any doubt is UNKNOWN and exit 2, never SAFE; an unknown option stops the run; the Mac fix's every check failing means "nothing changed". |
| Complete mediation | Every trust result passes through the controls in `check()` / `checkContainer()`; there is no path from a probe to SAFE that skips them. |
| Open design | All of it is public, including the test hosts; nothing depends on an attacker not knowing how it works. There are no secrets in it. |
| Separation of privilege | Looking and changing are separate programs: the command can't change the system, and the Mac fix must be run on purpose, with the user's password. |
| Least privilege | The command runs as the user and never asks for root. The Mac fix uses `sudo` only for the commands that write, and not at all on a writable copy. |
| Least common mechanism | Nothing shared between users or runs: no cache, no state, no daemon. The Mac fix's temporary file comes from `mktemp` and is removed on exit. |
| Psychological acceptability | Four plain statuses, a fix under every problem, exit codes for CI, and the README's privacy promise in one paragraph. |
| Limited attack surface | No listening socket, no network input beyond connection results, no dependencies, nothing written. |
| Input validation with allowlists | Options against a fixed list; `--incident` against the shipped ids; versions only as digits and dots from a known pattern; the container tool name as a single word; incident data checked by tests. |

### Common weaknesses, and how each is countered

| Weakness | Where it could arise | Countered by |
|---|---|---|
| OS command injection (CWE-78) | Names of files, repositories and containers reaching a command | `execFile` with argument lists only; container script takes positional arguments; enforced by test |
| Code injection (CWE-94) | Evaluating data | No `eval`, no `new Function`; enforced by test |
| Improper certificate validation (CWE-295) | The probes and Wardlatch's own TLS | Verification on everywhere except the reachability handshake, which sends nothing and decides only "up or not"; enforced by test |
| Exposure of sensitive information (CWE-200, CWE-532) | Key findings, output, network | Keys masked; nothing sent; tests on text and JSON output |
| Improper neutralization of escape sequences (CWE-150) | Names printed to a terminal | One escaping function for every printed name; test with a planted name |
| Uncontrolled resource consumption (CWE-400) | Huge trees, huge files, pipes, hung programs | Depth limits (4 to 5 levels), file-size caps (512 KB for the key scan, 2 MB for plugin files), only regular files read and pipes opened non-blocking, a 4,000-file cap per plugin, a timeout on every child process and connection |
| Path traversal and symlink attacks (CWE-22, CWE-59) | Writing outside a folder | Nothing is written. Directory walks don't follow symlinked folders |
| Untrusted search path (CWE-426) | Running programs by name | By design for `PATH` (it checks what the user runs); see section 4 for virtual environments |
| Race conditions (CWE-367) | A scanned file swapped between its size check and its read; the Mac fix's temporary and backup files | The command checks and reads a file through one read-only, non-blocking descriptor (`lib/files.mjs`). The Mac fix uses `mktemp`, checks the backup name is free first, and writes the file in place with one `cp` after its checks |
| Supply chain (CWE-1357) | Dependencies, CI | No dependencies; every GitHub Action pinned by full commit SHA; Dependabot proposes updates through review |

## 4. What is NOT defended

Read this section before relying on anything above.

**Fixed after 0.1.2: a found virtual environment's interpreter is never run.** Up to 0.1.2, a folder under the
searched paths that contained `pyvenv.cfg` and `bin/python` had that `bin/python` run, so a repository cloned from a
stranger could ship a fake "python" that Wardlatch would execute. Since then Wardlatch only reads files in a found
environment: its certifi bundle (`lib/python*/site-packages/certifi/cacert.pem`) and version (the dist-info), and it
tests that bundle with a curl the machine already trusts (`/usr/bin/curl`, else the first on `PATH`) and `--cacert`.
An environment without certifi uses its base Python's trust, which is checked through `PATH`. A test plants a fake
interpreter that would leave a marker file and fails if it ever runs.

**Python runs with `-I -S`.** The eMudhra probe starts each `python3` on `PATH` with `-I` (no user site, no
environment variables) and, since 0.1.7, `-S` (no `site` module), because `-I` alone still runs `.pth` files from
site-packages at startup, and a malicious package can drop one there (LiteLLM 1.107.0's `cook.pth`). The probe needs only
the standard library's `ssl`. A test plants a marker `.pth` in a real virtual environment, checks that an ordinary start
runs it, and fails if the probe does. **Found 22 October 2026 while adding the LiteLLM incident:** 0.1.0 to 0.1.6 started
that Python without `-S`, so on a machine with LiteLLM 1.107.0 in the global Python's site-packages, running Wardlatch
also ran the stealer, as any Python start there does.

**Installed software is read, never run.** The GitLab, LiteLLM and Plex checks (`lib/installs.mjs`) read version files,
hash files in site-packages and list local container images with `docker images` / `podman images` (an argument list,
a timeout with SIGKILL); nothing they find is executed.

**Programs on `PATH` are trusted, except a program an incident says may itself be malware.** Every `node`, `curl`,
`python3`, and each tool named in a version rule, is run as found, as your shell would. A `PATH` that includes `.` or a
writable folder is outside what Wardlatch can defend. A rule marked `noExec` is never run: the file is hashed and
compared with the builds the vendor published as compromised, and the temp directories are searched for the traces
the malware leaves. Since 0.1.6 the OVHcloud CLI rule works this way, with the five MD5 hashes and the `envchecker-`
folder from OVHcloud's advisory (GHSA-862f-55f5-vmvw); a test plants a program that would leave a marker file and
fails if it ever runs. **Found in our own review, 21 October 2026:** 0.1.0 to 0.1.5 read the OVHcloud CLI's version by
running `ovhcloud --version`, so on a machine that still held one of the compromised builds, running Wardlatch would
also have run the stealer. Anyone who ran an earlier Wardlatch with a compromised `ovhcloud` installed should follow
that rule's fix.

**Git reads each repository's own configuration.** Wardlatch runs `git ls-files` and `git log` in every repository
it finds. It runs no hooks, no pager and no `git status`, but it does not override the repository's config either.

**An on-path attacker can produce a false SAFE for a host.** After the controls pass, any failure to connect counts
as a refusal. An attacker on the network path who lets the reachability handshake and the positive control through,
then drops the next connection to the same host, would make a trusting runtime look like a refusing one. The
connections are indistinguishable on the wire except for their order, which makes this hard, but it is not
prevented.

**A probe sees what its tool sees, and nothing else.** Inside a container, the result is for the image's `curl`,
`python3` or `wget`, not for the application, which may carry its own trust list (a Java truststore, a bundled CA
file). On the host, a program that passes its own CA bundle, or runs under a different environment (a `launchd` or
`systemd` service, another user), may trust differently from the probe, which uses the current shell's environment.

**What is not covered at all:** browsers (the README sends you to the advisory's check page), compiled programs (Go,
Rust, Electron; the output says what to rebuild with), container images that aren't running, runtimes not on `PATH`
and outside the searched folders, other user accounts, git history for committed keys (current files only), and
Windows, which is untested.

**Version rules trust the version a program prints.** A modified binary that lies about its version is not detected.

**The incident data is a snapshot.** Fixed versions, test hosts and fix texts are what the sources said when the
file was written. They can go stale until the next update; each source is linked so it can be checked.

**REVIEW lines are leads, not verdicts.** A new workflow file or plugin folder is listed because it could be
malicious, not because it is. The committed-key scan looks for high-confidence shapes only; a key in an unusual format
is missed.

**The Mac fix finds the two roots by the header lines macOS writes above each certificate** (`=== …/CN=…`). If Apple
changed that format, the script would find no root to remove; it then re-tests online, and reports EXPOSED if the file
still trusts the test host. If the test host were also down at that moment, it would report the file as clean without
having been able to check. The script also trusts `/usr/bin/curl` for the re-test.

**Releases 0.1.0 to 0.1.2 are not signed by the project**, and there is one maintainer and no second reviewer. A named
successor has held admin access to the repository and co-owned the npm package since 21 October 2026, but has not yet
rehearsed a release (see [GOVERNANCE.md](GOVERNANCE.md#continuity)).

## 5. Supply chain

No runtime or development dependencies: `npm install` of Wardlatch fetches only Wardlatch. CI runs on every push and
pull request: the tests on Node 18, 20 and 22 on Linux and macOS with deprecations as errors, `node --check` on every
module, ShellCheck, the Mac fix on copies of a real `cert.pem` and its checksum, REUSE licence and DCO sign-off checks,
and CodeQL with `security-and-quality`. OpenSSF Scorecard runs on every push to `main` and weekly. Every action is
pinned to a full commit SHA, workflows get read-only tokens unless a job needs more, and Dependabot proposes action
updates weekly. GitHub secret scanning and push protection are on for the repository. A release cut from a tag gets a
Sigstore attestation of its source archive and npm package ([docs/RELEASING.md](docs/RELEASING.md)); 0.1.3 and every
release since were cut that way.

## 6. How this document stays true

It is wrong the moment the code disagrees with it. A change to a control, a probe, what is sent, what is written,
what is printed or the Mac fix updates this file in the same commit, or the change does not land
([CONTRIBUTING.md](CONTRIBUTING.md)).
