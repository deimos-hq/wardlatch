# Architecture

How Wardlatch is put together, and why it is shaped this way. The security argument that rests on this structure is
in [ASSURANCE_CASE.md](../ASSURANCE_CASE.md).

## The shape

Two independent programs, about 700 lines in all, with no dependencies beyond Node's built-in modules and the
programs already on the machine:

- **The command**, `wardlatch` (`bin/wardlatch.mjs` and `lib/`): looks, reports, gives a fix per line, and changes
  nothing. Published on npm and run with `npx wardlatch@latest`.
- **The Mac fix**, `fix/fix-macos.sh`: one bash script that changes one file, `/etc/ssl/cert.pem`, when a person runs
  it on purpose. Not part of the npm package; downloaded from www.deimoscore.com/wardlatch/#mac (byte-identical to
  this repository's copy) or deployed by device management.

```
                    lib/incidents/*.json   (what to check: one file per incident, data only)
                              |
  argv ──> bin/wardlatch.mjs ─┼──> trust incidents ──> discover.mjs ──> runtimes on PATH, venvs, OS store
  (checked:                   |                    ──> probe.mjs ────> TLS to the advisory's test hosts
   known options only)        |                    ──> containers.mjs ─> docker/podman exec, inside each container
                              ├──> version rules ───> binaries.mjs ───> `<tool> --version` of programs on PATH
                              ├──> workflows ───────> workflows.mjs ──> git log in local repositories (git.mjs)
                              ├──> committed keys ──> secrets.mjs ────> git ls-files (git.mjs), then read tracked files
                              └──> WordPress ───────> wordpress.mjs ──> read plugin headers and files
                              |
                              v
             one result per line: SAFE · EXPOSED · UNKNOWN ("could not be tested") · REVIEW
                              |
          text (names escaped, a fix under each problem)  or  --json  ──>  exit code 0 / 1 / 2
```

## Components

| Path | What it does | What it touches |
|---|---|---|
| `bin/wardlatch.mjs` | Checks the options against the known list, loads the incidents, runs each one's checks, prints a line per result (control characters in names escaped), sets the exit code: 1 if anything is EXPOSED, else 2 if anything is UNKNOWN, else 0. REVIEW lines never change it. A trust check that found nothing to test is one UNKNOWN line, and on Windows (not supported) so is each program check. | Reads `lib/incidents/` and `package.json`. |
| `lib/incidents/*.json` | One incident each: `id`, `type`, `title`, `date`, `advisory` (the public source), and the type's data: test hosts and fix texts (trust), version rules (binaries), a date (workflows), plugin rules (WordPress). | Data only. Checked by `test/incidents.test.mjs`. |
| `lib/incidents/emudhra-2026-10-roots.pem` | The two public root certificates the compromised intermediates chain to, used only by the positive control. | Data only; fingerprints checked against the incident file. |
| `lib/discover.mjs` | Finds what to probe: every `node`, `curl` and `python3` on `PATH` (deduplicated by real path), `/usr/bin/curl` and `/usr/bin/python3`, macOS's `nscurl`, the Linux distribution's CA bundle, and Python virtual environments (a folder with `pyvenv.cfg` and `bin/python`) under the folders searched, noting each one's `certifi`. | Lists directories (5 levels; skips `node_modules`, `.git`, `Library`; does not follow symlinked folders). Runs each program on `PATH` once for its version (`python3 -V` exits before Python's start-up code). Never runs a found environment's own `bin/python`. |
| `lib/probe.mjs` | The trust check. `reachable()` does a TLS handshake with verification off and sends nothing, to learn whether a test host is up. `probe()` makes the runtime itself open a verified connection, with the user's environment. `check()` runs the controls, then the probes. | The only module that opens network connections. |
| `lib/containers.mjs` | Lists running containers (`docker ps` / `podman ps`) and runs a small `sh` script inside each with `exec`: it uses whichever of `curl`, `python3` or `wget` the image has, and prints only which tool it used. An engine that is installed but can't be asked (it hangs past 10 seconds, refuses, or fails for any reason other than "not running") is UNKNOWN, not "no containers". | Runs the engine's `ps` and `exec`, each killed if it outlives its timeout. Writes nothing into a container. |
| `lib/binaries.mjs` | Version rules: a bad range, a fixed version, or one fixed version per release line (and "end of life" when a line gets none). | Runs `<tool> --version` (or the rule's arguments) for programs found on `PATH`. |
| `lib/workflows.mjs` | Finds git repositories (4 levels) and lists `.github/workflows` files added since a date. | `git log --no-show-signature --no-ext-diff --no-textconv` in each repository, through `lib/git.mjs`. |
| `lib/secrets.mjs` | High-confidence key shapes in the files git tracks (up to 512 KB each, binary files skipped). A finding keeps the type, file, line and a mask, never the key. | `git ls-files`, through `lib/git.mjs`, then reads files. |
| `lib/git.mjs` | Runs git in a repository Wardlatch found, with every setting in the repository's own config that could make `ls-files` or `log` start a program overridden: `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C <repo>`, with lazy fetching off (`GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL` set to no real protocol). See [ASSURANCE_CASE.md](../ASSURANCE_CASE.md#4-what-is-not-defended). | Runs `git`. |
| `lib/wordpress.mjs` | Finds WordPress installs (5 levels), reads plugin version headers (a version that can't be read is UNKNOWN), searches a plugin's files for an indicator string (up to 4,000 files of under 2 MB), lists plugin folders created since a date. | Reads files and folder dates. |
| `lib/files.mjs` | `readCapped()`: reads a file only if it is a regular file under a size cap, checking and reading through one read-only, non-blocking file descriptor, so it can't be swapped for a huge file, a device or a pipe in between. Used by the key scan and the WordPress checks. | Opens files read-only. |
| `fix/fix-macos.sh` | The Mac fix. See below. | `/etc/ssl/cert.pem` and a dated backup beside it. |

Every child process is started with `execFile` and an argument list, never through a shell on the host, and every
one has a timeout (5 to 20 seconds).

## The trust check, step by step

The question is whether a runtime will complete a verified TLS connection to a site whose certificate chains to a
compromised key. Version numbers can't answer it reliably: each runtime has its own trust list (bundled, from the
OS, from `certifi`, from an environment variable), and only the runtime knows which one it is using. So Wardlatch
asks each runtime to make the connection itself.

1. **Reachability** (`reachable`, once per test host): a TLS handshake with certificate verification off. If it
   completes, the host is up. Nothing is sent over it; it is closed at once. Hosts that don't answer are left out; if
   none answers, every line is UNKNOWN.
2. **Positive control** (`check`, once per runtime): the runtime connects to the first reachable host while trusting
   *only* the two compromised roots (`--cacert` for curl, `ca:` for Node, `cafile=` for Python). If it can't connect
   even then, the probe can't see exposure on this runtime, and the line is UNKNOWN.
   macOS's networking stack (`nscurl`) can't be pointed at a CA file, so it gets a normal-site control instead: it
   must open the advisory's own page, or the line is UNKNOWN.
3. **The probe**: the runtime connects to each reachable host with its own defaults and the user's environment, the
   way the user's code would. Any host it reaches makes the line EXPOSED, naming the hosts; none makes it SAFE.

Probes per runtime:

| Runtime | How it is asked |
|---|---|
| `curl` | `curl -s -o /dev/null --max-time N [--cacert roots] URL` (the Linux system store adds `--cacert <bundle>`) |
| `node` | `node -e <script>`: `fetch()` for the probe, `https.get` with `ca:` for the control |
| `python`, `python-certifi` | `python3 -I -S -c <script>`: `ssl.create_default_context()` (or `certifi.where()`) and `urllib`. `-S` skips the `site` module, so no `.pth` file or `sitecustomize.py` runs (since 0.1.7); `-I` leaves out the user's site-packages, the `PYTHON*` variables and the current folder |
| macOS system | `nscurl URL`, read from its output, since it exits 0 even when the load fails |
| a container | `sh -c <script>` inside it via `docker exec` / `podman exec`, using `curl`, else `python3 -I -S`, else `wget`; first a normal site must open, then `self-signed.badssl.com` must be refused, or the tool doesn't check certificates and the line is UNKNOWN |

## The Mac fix

`fix/fix-macos.sh` makes the advisory's change to `/etc/ssl/cert.pem` (removing the two roots, identified by the
`=== …/CN=` header line macOS writes above each certificate) and adds checks around it:

```
refuse if not macOS, file missing, or < 50 certificates  ──> exit 2, nothing changed
no bad root left?  ──> re-test online ──> SAFE (or EXPOSED if it still trusts) ──> nothing changed
write the cleaned copy to a mktemp file
  check: no bad root left, count = before − removed, ≥ 50 certificates   else exit 2, nothing changed
dated backup (never overwrites one) ──> copy the cleaned file in ──> chmod 644
re-test with /usr/bin/curl against the advisory's test host:
  refused (60) ──> SAFE, fixed       still trusted (0) ──> restore the backup, exit 1       no answer ──> fixed, not re-tested
```

It uses `sudo` only for the commands that write (the backup, the copy, the `chmod`, and a restore), and not at all
when the file and its folder are writable by the user (as in the tests, which point it at a copy with
`WARDLATCH_CERT_FILE`).

## Why it is built this way

- **No dependencies.** A tool for supply-chain incidents should not bring its own supply chain. Node's standard
  library covers everything it needs.
- **Data, not code, per incident.** A new incident is usually a JSON file: hosts, version rules, fix texts. The code
  changes only when an incident needs a new kind of check.
- **Run the real thing.** The probes use the runtimes themselves, with the user's environment, so a result reflects
  what the user's code would do, including `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and a virtual environment's own
  `certifi`.
- **Controls before verdicts.** Every SAFE is preceded by evidence that the check could have said EXPOSED.
- **Read-only command, separate fix.** Applying a fix is the person's decision. The one fix that ships is a separate
  script with its own safety checks, run on purpose.

## Tests and CI

`test/` runs offline against stand-ins: a throwaway CA and HTTPS server on 127.0.0.1, fake programs on a private
`PATH`, fake containers, throwaway git repositories and WordPress sites. CI (`.github/workflows/`) runs it on Node 18,
20 and 22 on Linux and macOS, and adds ShellCheck, the Mac fix on copies of a real `cert.pem`, the Mac fix's checksum,
REUSE and DCO checks, CodeQL and OpenSSF Scorecard. Details: [CONTRIBUTING.md](../CONTRIBUTING.md#testing-policy).
