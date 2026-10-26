# Architecture

How Wardlatch is put together, and why it is shaped this way. The security argument that rests on this structure is
in [ASSURANCE_CASE.md](../ASSURANCE_CASE.md).

## The shape

Two independent programs, about 2,000 lines in all, with no dependencies beyond Node's built-in modules and the
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
                              ├──> version rules ───> binaries.mjs ───> `<tool> --version`, or for a noExec rule the file's MD5 and temp folders (never run)
                              ├──> workflows ───────> workflows.mjs ──> git log in local repositories (git.mjs)
                              ├──> committed keys ──> secrets.mjs ────> git ls-files (git.mjs), then read tracked files
                              ├──> WordPress ───────> wordpress.mjs ──> read plugin headers and files
                              ├──> installed software > installs.mjs ─> version files, site-packages by hash, image digests (never run)
                              └──> header settings ─> headers.mjs ────> read curl/wget/git/npm/agent configs and *_HEADERS (never run)
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
| `lib/incidents/*.json` | One incident each: `id`, `type`, `title`, `date`, `advisory` (the public source), and the type's data: test hosts and fix texts (trust), version rules (binaries), the start of the review window (workflows: `since`), plugin rules and the start of their review window (WordPress: `addedSince`). A window's start is an explicit UTC instant, such as `2026-08-30T00:00:00Z`, never a bare date. | Data only. Checked by `test/incidents.test.mjs`. |
| `lib/incidents/emudhra-2026-10-root-aaa.pem`, `-root-emsign.pem` | The two public root certificates the compromised intermediates chain to, one per file: each root's positive control forces only its own (the incident's `canaryRoots`). `emudhra-2026-10-roots.pem` holds both, for a test host with no group. | Data only; fingerprints and names checked against the incident file. |
| `lib/discover.mjs` | Finds what to probe: the first `node`, `curl` and `python3` on `PATH` (the ones the shell runs) and later copies that are compiled programs (`copiesToRun` in `lib/binaries.mjs`), `/usr/bin/curl` and `/usr/bin/python3`, macOS's `nscurl`, the Linux distribution's CA bundle, the bundle `REQUESTS_CA_BUNDLE` names, and Python virtual environments (a folder with `pyvenv.cfg` and `bin/python`) under the folders searched, noting each one's `certifi`. | Lists directories (5 levels; skips `node_modules`, `.git`, and macOS's own folders: its Library at `/`, in `/System` and in home folders, the Trash, the Photos and Photo Booth libraries; does not follow symlinked folders). Runs each program on `PATH` once for its version (`python3 -V` exits before Python's start-up code). Never runs a found environment's own `bin/python`. |
| `lib/probe.mjs` | The trust check. `reachable()` does a TLS handshake with verification off and sends nothing, to learn whether a test host is up. `probe()` makes the runtime itself open a verified connection, with the user's trust settings (CA files and folders, proxies, `NODE_OPTIONS`' trust flags: an allowlist in `lib/run.mjs`). `check()` runs the controls, then the probes. | The only module that opens network connections. |
| `lib/containers.mjs` | Lists running containers (`docker ps` / `podman ps`) and runs a small `sh` script inside each with `exec`: it uses whichever of `curl`, `python3` or `wget` the image has, and prints one line: which tool it used and the result (`ok`, `refused` or `error`), read from that line alone, never from `docker exec`'s exit code (which is 1 when the container has stopped). An engine that is installed but can't be asked (it hangs past 10 seconds, refuses, or fails for any reason other than "not running") is UNKNOWN, not "no containers"; `engineFailure()` is the one rule for that, for running containers and local images alike. | Runs the engine's `ps` and `exec`, each killed if it outlives its timeout. Writes nothing into a container. |
| `lib/binaries.mjs` | Version rules: a bad range, a fixed version, or one fixed version per release line (and "end of life" when a line gets none). | Runs `<tool> --version` (or the rule's arguments) for programs found on `PATH` (and, for PHP, versioned `php`, `php-fpm` and `php-cgi` programs in its known install folders: `copiesMatching`), except a rule marked `noExec` (the OVHcloud CLI): that program is never run; its file is hashed and `$TMPDIR`, `/tmp`, `/var/tmp` and every macOS per-user temp folder (`/private/var/folders/*/*/T`) are listed for the malware's folder. |
| `lib/workflows.mjs` | Finds git repositories (4 levels; it stops at the first repository, so one nested inside another isn't looked for) and lists `.github/workflows` files added by commits whose committer time is on or after the incident's start, merge-only additions included, each with the commit, its committer date in UTC and its author. git gets no date: every commit of every ref is read, whatever its date, and the review compares each commit's committer time (seconds since 1970) with the start itself, so a back-dated commit can't stop the reading (up to 0.1.9 `git log --since` did, at the first commit dated before the start, and the bare date `2026-09-01` reached git, which read it as 1 Sep at the run's time of day in the zone git ran in: up to 0.1.8 that of the `TZ` Wardlatch was started with, which git got too, the machine's when it was unset; in 0.1.9, which gave git no `TZ`, the machine's). A start that isn't an explicit UTC instant, a committer time that isn't a plain whole number, a shallow repository wherever its history is cut (git says it is shallow, or its shallow file is there and not empty: a cut commit's date is whatever its maker wrote), and a shallow file that can't be read are UNKNOWN. | In each repository, through `lib/git.mjs`: `git rev-parse --is-shallow-repository --git-path shallow` (then reads that file, if any; when the history is cut, `git log --no-show-signature --all --format='%H %ct'` once more, only to name the newest cut's date), `git log --no-show-signature --all --format='%H %ct'` (every commit, up to 256 MB of list), then, only when some commit is on or after the start, `git log --no-show-signature --no-ext-diff --no-textconv --no-renames --diff-merges=combined --no-walk=unsorted --stdin --diff-filter=A --name-only -- .github/workflows`, given exactly those commits. 20 seconds per call. |
| `lib/secrets.mjs` | High-confidence key shapes in the files git tracks, read from git's own record of each file (links, submodules and files a sparse checkout leaves out are not followed) (a text file up to 8 MB is read whole, a larger one up to 512 MB in overlapping pieces that end at line breaks, each match counted in one piece; a larger or unreadable one is UNKNOWN; binary files, judged by their first 8,000 bytes as git does, skipped; UTF-16 with a byte-order mark decoded). A tracked file deleted in the working tree is read from git's store, in a few runs however many there are; a skip-worktree file that is on disk is scanned like any other. A finding keeps the type, file, line and a mask, never the key. | `git ls-files -s -t`, then `git cat-file --batch-check` and `--batch` for deleted files, through `lib/git.mjs`; reads files. |
| `lib/git.mjs` | Runs git in a repository Wardlatch found, with every setting in the repository's own config that could make `ls-files` or `log` start a program overridden: `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c log.showRoot=true -c core.commitGraph=false -c advice.graftFileDeprecated=false -C <absolute repo>`, with lazy fetching off (`GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL` set to no real protocol), `GIT_NO_REPLACE_OBJECTS=1` and `GIT_GRAFT_FILE=/dev/null` (git reads each commit's own parents: a replace ref doesn't put another commit in a commit's place, though `log --all` still reads the commit it points to as one more tip; no grafts file; and with `core.commitGraph=false` no commit-graph file), and the caller's other `GIT_*` variables removed (since 0.1.8; `GIT_DIR` had pointed every scan at another repository). git is found on `PATH` and run by its full path, from `/`. See [ASSURANCE_CASE.md](../ASSURANCE_CASE.md#4-what-is-not-defended). | Runs `git`. |
| `lib/wordpress.mjs` | Finds WordPress installs (5 levels, dot-folders included, sites inside other sites too; a locked dot-folder below a root, such as www-data's `.ssh`, is listed for review) and every plugins folder on disk each can use, leftovers included (`pluginDirs()`: wp-content beside the core, or one level up when that isn't a core, and Bedrock's `app/`). It doesn't read PHP: a wp-config.php that names `WP_CONTENT_DIR` or `WP_PLUGIN_DIR`, a Bedrock config that names `CONTENT_DIR` or `WP_PLUGIN_DIR` beyond its stock lines, or one of those files (or Bedrock's environments folder) that can't be read, makes the site UNKNOWN; reads plugin version headers (a version that can't be read is UNKNOWN), searches a plugin's files for an indicator string (up to 4,000 files of under 2 MB, 12 levels deep; what a cap leaves unsearched is UNKNOWN), lists plugin folders created since a date. | Reads files and folder dates. |
| `lib/installs.mjs` | Installed software (GitLab, LiteLLM, Plex): a product's version from its own files, judged like a program's version; files a malicious release drops in Python's site-packages, matched by name or SHA-256; the malware's temp-folder markers; local container images by digest or tag. | Reads files; lists images with `docker images` / `podman images`. Nothing it finds is run. |
| `lib/headers.mjs` | Your name or email (read from your own git config, never sent or printed), or any email address, in the header settings your tools send: `~/.curlrc`, `~/.wgetrc`, git's `http.extraHeader` and `http.userAgent`, npm's `user-agent`, coding-agent and MCP client configs (JSON with comments allowed; `--header` arguments included), and `*_HEADERS` / `*_USER_AGENT` variables; `.curlrc` lines are read on the safe side (`curlLine()`: your name or email anywhere after a header option counts, escapes undone), the config files a `config`/`expand-config`/`-K` line brings in and a header file `-H @file` names are read too (once each per use, at most 32 of 1 MB), and curl variables are UNKNOWN. A finding keeps the file, the header's name and what it carries, never the value. | Reads files and the environment. Runs nothing. |
| `lib/owners.mjs` | Who a folder Wardlatch couldn't open belongs to: a person (this user or a login account; for WordPress, the web server's account), so not having looked is UNKNOWN, or a service (root, a database, nobody, a rootless container's uids), so it is listed in one REVIEW line. Used only by `gaps()` in `bin/wardlatch.mjs`. | Reads `/etc/passwd`, `/etc/subuid`, `/etc/subgid` and folder owners. |
| `lib/crash.mjs` | Imported first: a crash exits 2 (could not be tested), or 1 when an EXPOSED line was already printed. | None. |
| `lib/run.mjs` | The only way a program is started: absolute path, argument list, cwd `/`, SIGKILL timeout, and an allowlisted environment per purpose (`version`, `git`, `engine`, `probe`); standard input only for `runSync` when the caller gives it (git's batch reads), and closed at once for every other program. | Starts programs. |
| `lib/files.mjs` | The only way the disk is read: `pathState` (file, dir, other, gone or denied), `listDir` (entries, gone or denied), `readCapped`/`readText`/`hashFile` (regular files under a cap, through one non-blocking descriptor), `readHead`, `realPath`. | Reads files and folders. |
| `lib/report.mjs` | `safe(searched, fields)`: the only way a SAFE result is made, and never without the list of what was looked at. | None. |
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
2. **Positive control** (`check`, once per runtime, per distrusted root): the runtime connects to one answering host
   of each root while trusting *only that root* (the incident's `canaryRoots`: `--cacert` for curl, `ca:` for Node,
   `cafile=` for Python). If it can't connect even then, the probe can't see exposure on this runtime, and the line is
   UNKNOWN. A root with no answering host makes the line UNKNOWN too, unless some host connected: a runtime that trusts
   only that root would refuse every host that did answer.
   macOS's networking stack (`nscurl`) can't be pointed at a CA file, so it gets a normal-site control instead: it
   must open the advisory's own page, or the line is UNKNOWN.
3. **The probe**: the runtime connects to each reachable host with its own defaults and the user's trust settings, the
   way the user's code would, run from `/`. Python is the exception: it starts with `-I -S`, so its start-up files
   (`.pth`, `sitecustomize.py`) and anything they change about trust are left out. Any host it reaches makes the line EXPOSED, naming the hosts. Only a certificate-verification refusal counts as a refusal (curl exit 60, a Node certificate error code, Python's `SSLCertVerificationError`): when no host connected, every refusal of that kind makes it SAFE, and any other failure makes it UNKNOWN.

Probes per runtime:

| Runtime | How it is asked |
|---|---|
| `curl` | `curl -s -o /dev/null --max-time N [--cacert roots] URL` (the Linux system store and a virtual environment's certifi add `--cacert <bundle>`; a bundle that can't be found is UNKNOWN) |
| `node` | `node -e <script>`: `https.get` for the probe, and with `ca:` for the control (since 0.1.7; `fetch()` before, which Node 17 and older lack) |
| `python` | `python3 -I -S -c <script>`: `ssl.create_default_context()` and `urllib`. A virtual environment's certifi is not run through Python: it is a `curl` row with `--cacert <bundle>`. `-S` skips the `site` module, so no `.pth` file or `sitecustomize.py` runs (since 0.1.7); `-I` leaves out the user's site-packages, the `PYTHON*` variables and the current folder |
| macOS system | `nscurl URL`, read from its output, since it exits 0 even when the load fails; only NSURLErrorDomain -1202 and -1203 (an untrusted or unknown root) is a refusal; a date error (-1201, -1204) is an error |
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
- **Run the real thing.** The probes use the runtimes themselves, with the user's trust settings, so a result reflects
  what the user's code would do, including `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and a virtual environment's own
  `certifi`. Except for what would mean running what is being checked: Python's start-up files are skipped (`-I -S`),
  every program runs from `/` (`go version` with `GOTOOLCHAIN=local`), and `node_modules/.bin` folders are dropped from
  `PATH`.
- **Controls before verdicts.** Every SAFE is preceded by evidence that the check could have said EXPOSED.
- **Read-only command, separate fix.** Applying a fix is the person's decision. The one fix that ships is a separate
  script with its own safety checks, run on purpose.

## Tests and CI

`test/` runs offline against stand-ins: a throwaway CA and HTTPS server on 127.0.0.1, fake programs on a private
`PATH`, fake containers, throwaway git repositories and WordPress sites. CI (`.github/workflows/`) runs it on Node 18,
20 and 22 on Linux and macOS, and adds ShellCheck, the Mac fix on copies of a real `cert.pem`, the Mac fix's checksum,
REUSE and DCO checks, CodeQL and OpenSSF Scorecard. Details: [CONTRIBUTING.md](../CONTRIBUTING.md#testing-policy).
