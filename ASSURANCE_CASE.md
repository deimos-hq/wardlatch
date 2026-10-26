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
self-signed site must be refused, or the line is UNKNOWN. A trust check that finds nothing to test is UNKNOWN (always
so on Windows), and so is a container engine that is installed but can't be asked: one that hangs, refuses or fails
for any reason other than "not running". (4) Since 0.1.7, on the host, only a certificate-verification refusal (curl
exit 60, a Node certificate error code, Python's `SSLCertVerificationError`, macOS's NSURLErrorDomain -1202 and -1203) counts as "does not trust"; when no test
host connected and any probe failed for another reason (a reset, a timeout, a bundle that can't be opened, a missing
API), the line is UNKNOWN. Up to 0.1.6 every failure counted as a refusal, and a Node.js older than 18, which has no
`fetch()`, read SAFE without being tested. UNKNOWN sets exit code 2, so CI does not pass on it.
*Evidence:* `test/wardlatch.test.mjs` (no host up is UNKNOWN; a failed positive control is UNKNOWN; a failed system
control is UNKNOWN; containers with no tool, or a tool that accepts a self-signed site, are UNKNOWN; a plugin whose
version can't be read is UNKNOWN) against a local throwaway CA and canary; `test/cli.test.mjs` for the exit codes,
nothing to test, Windows, and a hung or failing container engine. `test/incidents.test.mjs` checks that the bundled
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
| Economy of mechanism | About 2,000 lines, no dependencies, no build step, no server, no configuration file. |
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
| Uncontrolled resource consumption (CWE-400) | Huge trees, huge files, pipes, hung programs | Depth limits (4 to 5 levels), file-size caps (512 MB for the key scan, read in pieces past 8 MB; 2 MB for plugin files; what a cap leaves unread is UNKNOWN), only regular files read and pipes opened non-blocking, a 4,000-file cap per plugin, a timeout on every child process and connection |
| Path traversal and symlink attacks (CWE-22, CWE-59) | Writing outside a folder | Nothing is written. Directory walks don't follow symlinked folders |
| Untrusted search path (CWE-426) | Running programs by name | By design for `PATH` (it checks what the user runs); see section 4 for virtual environments |
| Race conditions (CWE-367) | A scanned file swapped between its size check and its read; the Mac fix's temporary and backup files | The command checks and reads a file through one read-only, non-blocking descriptor (`lib/files.mjs`). The Mac fix uses `mktemp`, checks the backup name is free first, and writes the file in place with one `cp` after its checks |
| Supply chain (CWE-1357) | Dependencies, CI | No dependencies; every GitHub Action pinned by full commit SHA; Dependabot proposes updates through review |

### Three rules the tests enforce (0.1.9)

Most of the advisories so far were the same few mistakes found again in new places. Since 0.1.9 each is held back by
a single gateway, and `test/contract-0.1.9.test.mjs` fails if any code goes around it:

- **One way to run a program** (`lib/run.mjs`): an absolute path, an argument list, the folder `/`, a timeout that
  kills with SIGKILL, and an environment built from an allowlist for its purpose (version read, git, container engine,
  trust probe). A trust probe gets what changes a runtime's trust or its route to a host (CA files and folders,
  proxies, `NODE_OPTIONS`' trust flags) and nothing else: no code-loading settings (`NODE_OPTIONS --require`,
  `OPENSSL_CONF`, `LD_PRELOAD`, `SHELLOPTS`). When the person's environment has settings like that which could add
  trust (`NODE_OPTIONS --require mac-ca`, `OPENSSL_CONF`), the run has an
  UNKNOWN row naming them, so it can't end all SAFE without having tested them.
- **One way to look at the disk** (`lib/files.mjs`): it tells "not there" from "couldn't look", reads only regular files
  under a size cap, and never blocks on a FIFO.
- **One way to say SAFE** (`lib/report.mjs`): a SAFE result can't be made without a list of what was looked at; with
  nothing looked at, the answer is UNKNOWN.

## 4. What is NOT defended

Read this section before relying on anything above.

**Fixed after 0.1.2: a found virtual environment's interpreter is never run.** Up to 0.1.2, a folder under the
searched paths that contained `pyvenv.cfg` and `bin/python` had that `bin/python` run, so a repository cloned from a
stranger could ship a fake "python" that Wardlatch would execute. Starting a real environment's Python also ran the
`.pth` files in its site-packages (see the next paragraphs). Since then Wardlatch only reads files in a found
environment: its certifi bundle (`lib/python*/site-packages/certifi/cacert.pem`) and version (the dist-info), and it
tests that bundle with a curl the machine already trusts (`/usr/bin/curl`, else the first on `PATH`) and `--cacert`.
An environment without certifi uses its base Python's trust, which is checked through `PATH`. A test plants a fake
interpreter that would leave a marker file and fails if it ever runs.

**Installed software is read, never run.** The GitLab, LiteLLM and Plex checks (`lib/installs.mjs`) read version files,
hash files in site-packages and list local container images with `docker images` / `podman images` (an argument list,
a timeout with SIGKILL); nothing they find is executed.

**Header settings are read, never used.** The identity-headers check (`lib/headers.mjs`) reads your name and email from your own git config files as text (git is not run, and `include` lines are not followed), and compares them with the header settings in files and the environment. Neither your identity nor any header value is printed, written or sent; a test checks the output and the `--json` output for both.

**git gets a clean environment, not the caller's.** Since 0.1.8 git runs without the caller's `GIT_*` variables (except `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_NOSYSTEM`, which only choose your own config files, and `GIT_TEST_ASSUME_DIFFERENT_OWNER`, which can only make git refuse a repository): `GIT_DIR` or `GIT_WORK_TREE` from a hook or a CI step had pointed every scan at one other repository, and the git checks read SAFE without having looked (0.1.0 to 0.1.7). A test sets both kinds and expects the found repository to be read and nothing planted to run.

**Programs on `PATH` are trusted, except a program an incident says may itself be malware.** The first `node`, `curl`
and `python3` on `PATH`, and later copies that are compiled programs (a later script is never run), `/usr/bin/curl`, `/usr/bin/python3`, and each tool named in a version rule, is run from the
place it was found, the one your shell would pick; the PHP check also runs the first `php`, `php-fpm` or `php-cgi` of
each versioned name in its known install folders off `PATH` (the `sbin` folders, macOS Homebrew's `php@*` kegs, Remi, cPanel,
Plesk), where a second PHP serving the sites lives. Each is run once for its version (`node -v`, `curl --version`,
`python3 -V`, or the rule's arguments), and each runtime once more per test connection, with the arguments in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#the-trust-check-step-by-step). Python is not started the way your shell
would start it: see the next paragraph. Since 0.1.7 every `node_modules/.bin` folder and every relative entry is
dropped from `PATH` before anything runs (npx puts the current project's `node_modules/.bin` first, so a project could
otherwise have Wardlatch run its own `git` or `python3`; when nothing is left, `PATH` is `/usr/bin:/bin`, and git is
run by its full path), every program runs from `/` (so a version manager picks your default, not the current project's
pin; `--paths` folders and relative CA settings such as `SSL_CERT_FILE` are made absolute first),
`GOTOOLCHAIN=local` stops `go version` downloading or running the newer Go a project's `go.mod` asks for (a Go you
pinned with `GOTOOLCHAIN` is read from that setting, without running go, and judged too), and PHP's version is read with `php -n -v`, which loads no `php.ini` and no extension; a
test puts marker programs in a `node_modules/.bin` and fails if one runs, and another records the folder, the Go
setting and PHP's arguments. npx also starts Wardlatch with the current project's own `node_modules/.bin/node` if it
has one, and applies its `.npmrc`; Wardlatch can't undo either: run it from your home folder. A `PATH` that includes a writable folder is outside what Wardlatch can defend. A rule marked `noExec` is never run: the file is hashed and compared with the builds the vendor published as
compromised, and the temp directories are searched for the traces the malware leaves. Since 0.1.6 the OVHcloud CLI rule works this way, with the five MD5 hashes and the `envchecker-`
folder from OVHcloud's advisory (GHSA-862f-55f5-vmvw); a test plants a program that would leave a marker file and
fails if it ever runs. **Found in our own review, 21 October 2026:** 0.1.0 to 0.1.5 read the OVHcloud CLI's version by
running `ovhcloud --version`, so on a machine that still held one of the compromised builds, running Wardlatch would
also have run the stealer. Anyone who ran an earlier Wardlatch with a compromised `ovhcloud` installed should follow
that rule's fix.

**Python's start-up files are not run.** At start-up Python imports `site`, which runs every `.pth` file in that
interpreter's site-packages, and a malicious package can put code there that runs on every Python start (LiteLLM
1.107.0's `cook.pth`, 21 October 2026). `-I` does not stop this: it leaves out only the user's own site-packages, the
`PYTHON*` environment variables and the current folder. So since 0.1.7 the trust probe runs `python3 -I -S -c
<script>`: `-S` skips `site`, and with it every `.pth` file and `sitecustomize.py`. The probe needs only the standard
library. The version is read with `python3 -V`, which exits before any start-up code. Inside a container `python3` runs
with `-I -S` too; one older than 3.4 has no `-I`, fails the normal-site control and is UNKNOWN. The cost: a `.pth` file
or `sitecustomize.py` that changes how that Python trusts certificates (pip-system-certs, which makes it use the
system's store, for example) no longer applies to the probe, so the result can differ from what your code sees. In
particular, as before, the `certifi` in the own site-packages of a Python on `PATH` is not tested yet (a virtual environment's
is): a Python whose code uses an old `certifi` can read SAFE here. *Evidence:* a test builds a
real virtual environment with a marker `.pth`, checks that an ordinary `-I` start runs it, and fails if the probe does;
another runs the container script with a `python3` that rejects `-I` and expects UNKNOWN. **Found 21 October 2026,
[GHSA-xcqr-prh6-6g8w](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-xcqr-prh6-6g8w):** 0.1.0 to
0.1.6 started each `python3` on `PATH` and `/usr/bin/python3` with `-I` alone, so a malicious `.pth` in that
interpreter's own site-packages ran when Wardlatch started it (an activated virtual environment, conda environment,
pyenv version or Homebrew Python included). 0.1.0 to 0.1.2 also started the `bin/python` of each virtual environment
found under the searched folders, which ran that environment's `.pth` files. 0.1.2 to 0.1.6 ran `python3` without `-I`
inside running containers that had no `curl`, which also loaded the image's user site-packages. On the host, a copy
installed with `pip install --user` was not run, because `-I` leaves out the user's site-packages.

**Git runs with the repository's program settings overridden.** Wardlatch runs `git ls-files` (committed keys) and
`git log` (workflow review) in every repository it finds, and a repository's own `.git/config` can name programs for
git to run. A cloned repository starts with git's default config, but one unpacked from an archive or copied from
elsewhere can carry any config it likes. Since 0.1.7 both run through `lib/git.mjs`, by git's full path and from `/`,
as `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c log.showRoot=true -C <repo>` (since 0.1.10
also `--work-tree=<repo>`: see below), with
`GIT_NO_REPLACE_OBJECTS=1` (`log.showRoot=false` would hide the files of a root commit; up to 0.1.6 a workflow added
in a repository's first commit could read SAFE that way), and `log` adds `--no-show-signature --no-ext-diff
--no-textconv --no-renames`. A `-c` setting wins over every config file. So `ls-files` runs no `core.fsmonitor` program, and `log`
runs no `gpg.program` (nor `gpg.ssh.program` or `gpg.x509.program`) to check a signed commit. `diff.external`, a diff
driver's `command` or `textconv`, and `filter` programs run only for a patch or a checkout, which neither command
makes. Neither command runs a hook now that nothing is fetched (the fetch in 0.1.0 to 0.1.6 did: see below), and
with no terminal git starts no pager. Lazy fetching is off too
(`GIT_NO_LAZY_FETCH=1`, and `GIT_ALLOW_PROTOCOL` set to no real protocol for a git too old to know that variable): in
a partial clone, `git log` fetches a missing tree or blob from the remote the config names, running `core.sshCommand`,
`remote.<name>.uploadpack` or a credential helper on the way, and sending a request. *Evidence:* `test/cli.test.mjs`
plants a repository whose config names a program for `core.fsmonitor`, the three `gpg` programs, `diff.external`, a
diff driver's `command` and `textconv`, both `filter` programs and `core.pager`, with hooks and a signed commit that
adds a workflow file. It checks that plain `git ls-files` and `git log` do start the planted programs, then runs both
checks and fails if any program runs. Another test makes a partial clone whose `uploadpack` leaves a marker if git
fetches from it. **Found 21
October 2026, [GHSA-x8rh-w6q6-4r3h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x8rh-w6q6-4r3h):**
0.1.0 to 0.1.6 ran `git log`, and 0.1.1 to 0.1.6 ran `git ls-files`, with the repository's own config, so a
repository under the searched folders whose config set `core.fsmonitor`, or `log.showSignature` with `gpg.program`,
had its program run by Wardlatch, and a treeless partial clone, or a blobless one with a workflow renamed within the
folder, made `git log` fetch from the clone's own remote and write what it fetched into `.git/objects` (a request and a
change Wardlatch promises never to make). That fetch ran the repository's own `reference-transaction` hook, which needs
no config, and `core.alternateRefsCommand` when `objects/info/alternates` exists, and a crafted config could also make
it run a program (`core.sshCommand`, `remote.<name>.uploadpack`, a credential helper, an `ext::` remote). Since 0.1.7, when git fails in
a repository (a treeless partial clone missing what it would have to fetch, a repository git refuses to open, a
timeout), that repository is an UNKNOWN line with git's reason, and the SAFE line counts only the repositories git
could read; up to 0.1.6 it was left out without a word and still counted. Git itself and any `git-remote-*` helper are programs on
`PATH`, trusted as above.

**Git reads the repository Wardlatch found, from its top.** A repository's own config can also change where git
reads paths from, or which history it reads. **Found 26 October 2026** (an independent check of 0.1.10): with
`core.worktree` in `.git/config` (or `.git/config.worktree`) naming a folder above the repository, such as `/tmp`, git
took the repository's folder as a subfolder of that one, `git log` found nothing under `.github/workflows` and `git
ls-files` listed nothing, so the workflow review (0.1.0 to 0.1.9) and the committed-keys check (0.1.1 to 0.1.9) read
SAFE, exit code 0, for a repository holding a workflow or a key. Since 0.1.10 every git call gets
`--work-tree=<repo>`, which wins over `core.worktree`, `core.bare` and `GIT_WORK_TREE`. A `commondir` file written
into a `.git` folder makes git read the refs and commits of the repository it names (git writes one only in a linked
worktree's folder under `.git/worktrees`, whose `.git` is a file): the workflow review and the committed-keys check
now read such a repository, and one whose `.git` folder git doesn't take as the repository (an empty one inside
another repository), UNKNOWN. The folders are compared by device and inode, not by path text: on macOS a `--paths`
in another case, or in NFC for a name stored as NFD, is the same folder (comparing the text read such a clean
repository UNKNOWN in an earlier cut, 7bdca07). Checked on git 2.54 and not a miss: `core.worktree` set through
`include.path`, `includeIf`, `-c` or the person's global config (git doesn't use it from there), `core.bare=true` in
the `.git` folder of a repository with its files beside it, `diff.relative`, `log.follow`, `core.ignoreCase`, and the
caller's `GIT_*` location and pathspec variables, which git doesn't get. **Known limits:** a workflow under a folder
whose name differs only in case (`.GitHub/Workflows`) isn't listed; whether GitHub runs one there hasn't been
checked. A `.git` file is followed as git follows it, whatever repository it names, so one naming an empty
repository (or a folder whose `commondir` file names one) reads SAFE: `git clone --separate-git-dir` makes the same
shape with no pointer back, and a linked worktree's pointer back can be written by whoever writes the `.git` file, so
no rule tells them apart. In the bare-repository-with-worktrees layout (`.bare`, a `.git` file `gitdir: ./.bare`,
worktrees in subfolders) the search stops at the outer folder, and the committed-keys check scans no worktree's
files (SAFE); pass the worktree's folder to scan it. *Evidence:* `test/workflows.test.mjs` sets `core.worktree`
above the repository (absolute, relative, in `config.worktree`, with `diff.relative` and `log.follow`) and
`core.bare=true`, each with a clean twin that must read SAFE, plants a `commondir` file and an empty `.git` folder
inside another repository (UNKNOWN), reads a linked worktree and a submodule's own folder as before, and on macOS
reads a repository given in another case and in NFC for NFD; `test/cli.test.mjs` sets `core.worktree` above the
repository for a committed key (twin SAFE), plants a `commondir` file and an empty inner `.git` (UNKNOWN; twins read),
and finds a key given in another case and in NFC for NFD (twins SAFE).

**An on-path attacker can produce a false SAFE for a host.** After the controls pass, a certificate refusal counts as
a refusal. An attacker on the network path who lets the reachability handshake and the positive control through,
then answers the next connection to the same host with a certificate of their own, would make a trusting runtime look
like a refusing one (since 0.1.7 a dropped connection is UNKNOWN instead). The
connections are indistinguishable on the wire except for their order, which makes this hard, but it is not
prevented.

**A probe sees what its tool sees, and nothing else.** Inside a container, the result is for the image's `curl`,
`python3` or `wget`, not for the application, which may carry its own trust list (a Java truststore, a bundled CA
file). On the host, a program that passes its own CA bundle, or runs under a different environment (a `launchd` or
`systemd` service, another user), may trust differently from the probe, which uses the current shell's trust settings (an allowlist in `lib/run.mjs`).

**What is not covered at all:** browsers (the README sends you to the advisory's check page), compiled programs (Go,
Rust, Electron; the output says what to rebuild with), container images that aren't running, runtimes not on `PATH`
and outside the searched folders, runtimes in a `node_modules/.bin` folder on `PATH`, other user accounts, git history for committed keys (current files only), and
Windows, which is not supported: since 0.1.7 the trust check and the program checks say UNKNOWN there instead of a
SAFE they couldn't support; the other checks run, untested.

**Version rules trust the version a program prints.** A modified binary that lies about its version is not detected.

**The incident data is a snapshot.** Fixed versions, test hosts and fix texts are what the sources said when the
file was written. They can go stale until the next update; each source is linked so it can be checked.

**REVIEW lines are leads, not verdicts.** A new workflow file or plugin folder is listed because it could be
malicious, not because it is. Folders a service owns that Wardlatch couldn't open are listed the same way: they were
not searched, and running with sudo includes them; a person's locked folder is UNKNOWN instead, since it could hold
that person's projects. The committed-key scan looks for high-confidence shapes only; a key in an unusual format
is missed.

**The workflow review reads commits by the date they claim.** git gets no date. `git log --all --format='%H %ct'`
lists every commit that any ref or `HEAD` leads to, with its committer time in seconds since 1970, and Wardlatch keeps
those on or after the incident's start, an explicit UTC instant (for `github-actions-2026-10`, 30 Aug 2026 00:00 UTC),
by comparing whole numbers in its own code; `git log --no-walk=unsorted --stdin` then lists the workflow files that
exactly those commits added. The SAFE line names the instant, and a review line shows the date, in UTC, of the
committer time compared. git reads each commit with its own parents: replace refs don't substitute one commit for
another (`GIT_NO_REPLACE_OBJECTS=1`; a ref under `refs/replace/` is still read as an ordinary tip, so the commit it
points to is read as one more commit, which can add a workflow to the list but never hide one), no grafts file is read
(`GIT_GRAFT_FILE=/dev/null`), no commit-graph file is used (`core.commitGraph=false`), and nothing is fetched.
Each commit in the window that added a workflow file gets its own line, newest first: a file added, deleted and added
again is listed at every commit that added it (up to 3cff5c5 it was listed once, at the earliest, so a later re-add
by someone else wasn't shown). **Known limit: a change to a workflow file that already existed isn't listed; the check
lists added files, as the campaign added them.** **Known limit: a workflow whose own commit is dated before 30 Aug 2026
isn't listed, because whoever makes a commit sets its date.** For the same reason a shallow repository is UNKNOWN wherever its history is cut ("its history is cut
(a shallow repository; the newest cut is commit …, dated …), so workflows added below the cut can't be seen: run git
fetch --unshallow, then run again"), whether `git rev-parse --is-shallow-repository` says `true` or the shallow file
git reads is there and not empty: the cut commit's date is no sign that the window is all there, since a `--depth 1`
clone of a back-dated tip is cut below every workflow beneath it, and a shallow file can be written into a full
repository. A CI checkout with `fetch-depth: 1` is therefore UNKNOWN (exit code 2); with `fetch-depth: 0` it is read.
A committer time git prints that isn't a plain whole number (git prints none for a date it can't read), a shallow file
that can't be read, a start that isn't an explicit UTC instant, a git call that takes over 20 seconds (every run reads
the whole history: about 7 seconds for 1.56 million commits on an Apple M5 Pro), and a list of commits over 256 MB
(about 5 million commits) are UNKNOWN, never SAFE.
**Found 25 October 2026:** 0.1.0 to 0.1.9 gave git the bare date `2026-09-01`, which git reads as 1 Sep at the current
time of day in the zone it runs in: up to 0.1.8 the zone of the `TZ` Wardlatch was started with, which git got with
the rest of the caller's environment (the machine's when `TZ` was unset), and in 0.1.9, which gives git no `TZ`, the
machine's. A workflow committed on 31 Aug, or on 1 Sep before the hour the check ran, was not read, and the
review could read SAFE with exit code 0; the sources say to check from 31 Aug. And git, given a start with `--since`,
stops following a line of history at the first commit dated before it, so one back-dated commit on top of a branch
hid every workflow beneath it, however they were dated (0.1.9's known limits named this only for a commit made on a
machine with a wrong clock). Checked on 0.1.9's code with git 2.54: a commit whose committer date git can't read did
the same as a back-dated one; a workflow added and removed again on a merged side branch was passed by (given a path,
`git log` follows only the parent a merge matches); and in a shallow clone cut inside the window, a workflow added and
removed below the cut wasn't seen. Each read SAFE. An independent check of this fix found two more the same day: an
earlier cut took a shallow clone cut before the start as the whole window, so a `--depth 1` clone of a tip dated
2025, over a workflow committed on 5 Sep 2026, read SAFE with the workflow file in its tree; and the CHANGELOG's hand
check listed nothing for a workflow only a merge commit adds or for a root commit under `log.showRoot=false`, missed
one renamed within `.github/workflows`, and followed a replace ref and a grafts file. *Evidence:*
`test/workflows.test.mjs` plants workflows a second inside the window, at 05:00 on 31 Aug at UTC+8, at 09:00 UTC on
1 Sep, and under the advisory's own file names on 31 Aug, and expects each listed, with the command run in two time
zones; it plants one at the window's first second, made at UTC-7, and expects it listed with the date 2026-08-30, in
one run with no `TZ` set; a workflow a second before the window must read SAFE. A back-dated commit on top, between two
workflows, and on a merged and deleted side branch must hide nothing; a workflow added and removed on a side branch
must be listed; a replace ref and a grafts file (cutting the history, or re-parenting the commit) must hide nothing; a
shallow repository must read UNKNOWN wherever it is cut (inside the window or before it, at a back-dated tip, or by a
shallow file written into a full repository, empty or not, even under a git that says the repository isn't shallow,
or says it is with no shallow file), and so must one whose shallow file can't be read, while the same history cloned
whole is read; partial clones whose remote is gone must be read with nothing fetched (a treeless one with commits in
the window is UNKNOWN); a commit whose date git can't read, a git that prints a committer time that isn't a plain
whole number, and a start that isn't an explicit UTC instant must read UNKNOWN; a git that writes down its arguments
must get no `--since`, `--after`, `--until`, `--before`, `--max-age`, `--min-age` or `--since-as-filter`; and the
CHANGELOG's hand check, found in the file wherever a release puts it (exactly one) and run as written, must list every
workflow the review lists, at the same commit and UTC date, in repositories with a replace ref, a crafted commit-graph
file, a merge-only workflow, a root commit under `log.showRoot=false`, renames, a commit at the start's own second
from UTC-7, one authored before the window and committed inside it, a workflow only on a branch not checked out, a
side branch that added and removed one, a signed commit whose repository names a `gpg.program` (which must not run),
and a blobless partial clone whose remote is gone; it must stop with an error in a treeless one, with nothing fetched;
with a grafts file it must list them only before the window, as its warning says; for a commit whose date git can't
read it must show no date; and git must get `--no-pager`, `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=none` from it.
Each has a clean twin (for the hand check, a workflow committed a second before the window from UTC-7, and one
authored inside the window but committed a second before it, which the review doesn't list and the line shows dated
2026-08-29T23:59:59Z).
A workflow file added, deleted and added again inside the window must be listed at both commits, newest first, by the
review and by the line (twins: two files each added once, one line each; a file added before the window and again
inside it, listed only at the commit inside it); a file only changed inside the window must read SAFE, and this
document, the CHANGELOG and the README must state that limit.
`test/incidents.test.mjs` holds the start of every incident's window (`since`, `addedSince`) to an explicit UTC
instant.

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
