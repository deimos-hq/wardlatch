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
programs (except that the Brotli decoder check reads node and bun programs and native libraries as bytes), files inside
container images, other user accounts, or git history (see section 4).

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

**Bundled decoders are read, never run, and a string is the evidence.** The Brotli check (`lib/brotli.mjs`) reads node and bun programs, Python packages' native files and Brotli libraries as bytes; nothing it finds is run, and it starts no program at all (not `otool`, not `ldd`, which can run the program it is given). Its SAFE rests on the decoder's own error table: the exact string `_ERROR_FORMAT_BLOCK_SWITCH` that the fix added, NUL-delimited, exactly as often as the control string `_ERROR_FORMAT_BLOCK_LENGTH_1` that every decoder has. The marker without the control, or more often than it, is UNKNOWN. Node's `zlib.constants` names (`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`) contain the marker but come from the header Node was compiled against, so they never count and never decide: a node with them and no table is judged by the library it links, or is UNKNOWN. Each build of a universal (fat) Mach-O file is judged on its own, since the loader maps one; a file with a table that also links a Brotli library needs that library SAFE too; Brotli 1.0's error texts have no `_ERROR_FORMAT_` prefix (Debian 12's libbrotli1 is 1.0.9), and short words like `BLOCK_SWITCH` could be in any program, so that form is judged (maintainer, 2026-10-25) only as a whole table: every copy of `BLOCK_LENGTH_1` must sit in the run of names from `HUFFMAN_SPACE` to `DISTANCE` in Brotli's order (NUL-delimited, up to 16 NULs between two, either way round), followed by `BLOCK_SWITCH` and `DICTIONARY_NOT_SET` (1.0.10, SAFE), or by `DICTIONARY_NOT_SET` at once (1.0.4 to 1.0.9) or `COMPOUND_DICTIONARY` and `DICTIONARY_NOT_SET` (1.0.3) (EXPOSED, and for a Debian library its package version decides, as for the 1.1 form), and `BLOCK_SWITCH` must be nowhere else; anything else in that form (scattered, out of order, partial, 1.0.0 to 1.0.2's tables, more copies than the 64 kept, a stray `BLOCK_SWITCH`) is UNKNOWN, alone or beside a 1.1-form table, and an unfixed 1.0 table beside a fixed 1.1 one is EXPOSED. The 1.0 layout was checked against clang's and against Debian 12's own GCC builds of libbrotli1 (1.0.9-2+b6 EXPOSED, 1.0.9-2+deb12u1 SAFE by its table, which adds `BLOCK_SWITCH`; amd64 and arm64, fetched from deb.debian.org and checked against the archive's signed index): a layout it doesn't match reads UNKNOWN. What that can't defend: a partial backport that adds the new error code to `decode.h` without the logic in `decode.c` would read SAFE, and so would a file that holds a fixed and an unfixed decoder whose strings the linker merged into one, or an unfixed table plus one stray NUL-delimited copy of the marker elsewhere in the file (a count can't tell which table a string belongs to). The `libnode` a file links (a distribution's node is a launcher for it, and so is Homebrew's) is followed and judged by the same rules, one level, beside a table or a Brotli library too, and must be SAFE as well: an unfixed libnode is EXPOSED, and one not found, unreadable or behind a link that can't be followed is UNKNOWN (Homebrew's node links `@rpath/libnode.147.dylib`, found through its own `LC_RPATH`); a compiled `node` on `PATH` with no sign of Node.js is a REVIEW line only when it is a version manager's known shim (a link to volta-shim, mise, rtx or proto-shim, or a copy of proto-shim, as proto writes its shims, in proto's shims folder or carrying the message only proto-shim holds, `Invalid shim name detected. Unable to execute the appropriate proto tool.`, from its own source, `crates/cli/src/main_shim.rs`; never by `PROTO_SHIM_NAME`, which proto's CLI holds too), and a script named `node` only when it is asdf's or nodenv's shim, in its manager's shims folder, in each case whose nodes were read: at least one of its folders of runtimes (its manager's layouts as its own source has them, under the folders its variables name, `ASDF_DATA_DIR`, whose leading `~/` is the home folder as asdf reads it, and `NODENV_ROOT` included, its usual folder, and the folder above its shims folder; for asdf, `installs/nodejs` and `installs/node`, counting only the folders of the plugins its shim's `# asdf-plugin:` lines name) is there and was listed, every one that is there could be listed, and no variable names one by a relative path; UNKNOWN otherwise, so an unread node never ends the run in exit 0. Any other script named `node` or `bun` on `PATH` is UNKNOWN. A variable is split on `:` only where its manager splits it (mise's `MISE_SHARED_INSTALL_DIRS`). What that can't defend: mise's configuration-file settings (`shared_install_dirs` and the like) are not read, and nvm, fnm and n are read only in their usual folders. What a file links is read as the loader reads it (maintainer's decision #24, 2026-10-25), from the binary format, never from a string that looks like a path: a Mach-O build's header and load commands (32- and 64-bit, either byte order, each build of a universal file on its own: `ncmds` commands, each at least 8 bytes and a multiple of 4, inside `sizeofcmds`, which is inside the build and at most 1 MB), whose `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB` names (each at its offset in its command, up to a NUL inside the command) are its links, beside `LC_RPATH`, `LC_ID_DYLIB` and `LC_DYLD_ENVIRONMENT`; and an ELF file's program headers, its one `PT_DYNAMIC` segment, and the `DT_NEEDED`, `DT_SONAME`, `DT_RPATH` and `DT_RUNPATH` entries of its dynamic table, read through `DT_STRTAB` (placed in the file by the `PT_LOAD` segment that maps it) and `DT_STRSZ` (32- and 64-bit, either byte order). Every read is bounded, checked against the file's size and charged to the run's reading budget before it is made (a candidate's look too: its first 8 bytes, a universal file's list of builds, and 64 bytes a build); headers that don't fit their format, or a file that is neither, are UNKNOWN beside a fixed table, and so is any `LC_DYLD_ENVIRONMENT` (it sets dyld's own variables, which move every library a program links). The Brotli libraries and libnode a file links are exactly those entries whose file name starts with `libbrotlidec`, or is `libnode` or starts with `libnode.`, `libnode-` or `libnode_`, in any case. Which copy of each the loader takes is not emulated (the maintainer's rule, round 7): where dyld or ld.so could take a different copy, every candidate must be SAFE, or the file is UNKNOWN (EXPOSED if any candidate is EXPOSED). That covers each `LC_RPATH`, `DT_RUNPATH` or `DT_RPATH` folder that holds a file of that name, not just the first; a candidate that isn't a loadable Mach-O or ELF library for the file's CPU (a Mach-O dylib with a build of the same `cputype`, whatever its `cpusubtype`, since dyld loads an arm64e dylib into an arm64 program, probe m1e, and x86_64h beside x86_64; or an ELF shared object of the same class, byte order and machine; anything else the loader passes over and looks on), which is UNKNOWN; the `glibc-hwcaps/*` subfolders of every folder searched for a soname; and, on ELF, a library's program's folders too (glibc reads the program's `DT_RPATH` for a library with no `DT_RUNPATH`, musl the program's `DT_RUNPATH` or `DT_RPATH` whatever the library's: both are taken), so a library read without its program (an ELF file is a program only when it is `ET_EXEC` or flagged `DF_1_PIE`) is UNKNOWN when its own folders don't stop the search (below). In full: an absolute path as it is; `@loader_path` beside the file (its real folder, as dyld takes it); `$ORIGIN` as both the file's real folder and the folder it was reached by (glibc takes a library's from the path it opened it by); `@executable_path` beside it only in a main program; `@rpath` through every `LC_RPATH` entry (on Mach-O only the file's own resolved `@rpath`, `@loader_path` or absolute path is looked in), and a bare ELF soname through every folder of its own `DT_RUNPATH` (its `DT_RPATH` only without one) and of its program's, `@loader_path` and `$ORIGIN` expanded; then, for an ELF soname, the standard library folders and those `/etc/ld.so.conf` (and musl's `/etc/ld-musl-*.path`) name, where every copy is a candidate, and a soname is UNKNOWN there when any of that configuration or a library folder couldn't be read, or an `include` line names a folder other than `ld.so.conf.d`, or has a `..` in it (not followed). One thing only stops the search before those folders (the safe-side rule, round 8): a copy the loader can load in a plain folder (not a `glibc-hwcaps` one) of the file's own `DT_RUNPATH`, or of its own `DT_RPATH` when it has none, there however `$ORIGIN` reads, with every copy found loadable and nothing left that couldn't be followed. A copy found through the program's folders, or only in a `glibc-hwcaps` subfolder, is a candidate that must be SAFE and never stops it: glibc never takes a program's `DT_RUNPATH` for a library, nor the program's `DT_RPATH` for a library with a `DT_RUNPATH` of its own (probes C1, C2), and looks in a hwcaps subfolder only on a CPU of that level, musl never (H5). A search folder, or a `glibc-hwcaps` folder, that can't be looked at may hold a copy: UNKNOWN. Each candidate's path is put together as written and resolved by the operating system (`realpath(3)`), never cleaned up as text first (Node's own `realpathSync` does that), so `..` after a link goes where the kernel goes; the candidate is named by its real path. The same holds for every path Wardlatch takes from outside (round 8): each program on `PATH` is its folder and name as written (with `PATH` `x/link/../bin` the shell runs the program in the folder above the link's target, not in `x/bin`) and is told apart from the others by its real path, and so are a temp folder, the folders a version manager's variables, the home folder and a Python package's `RECORD` name, and a relative CA setting made absolute; where the programs that read a path disagree (asdf's Go, npm and the Node-based agents clean a `..` up as text), both readings are read. A file that contradicts itself is UNKNOWN: an ELF file whose dynamic table at `PT_DYNAMIC`'s `p_offset` differs from the table the loader reads at its `p_vaddr`, placed in the file by the `PT_LOAD` segment that maps it (or at an address no `PT_LOAD` maps), and one whose dynamic table or string table (`DT_STRTAB`) is at an address in the page-rounded range of more than one `PT_LOAD` segment: the kernel and ld.so map them a page at a time, a later one over the earlier, so another segment's bytes may be there (probes E4b, E4c). A segment's page is its `p_align`, at most 64 KB, and 64 KB when that is under 4 KB; a file with one `PT_LOAD` for each address reads as before. Each library found is judged, one level: one that links a Brotli library or libnode of its own is UNKNOWN for the program that links it, and an EXPOSED library decides over a link that can't be followed, a library that isn't SAFE and a name it may load. A link that doesn't lead to a file Wardlatch can read is UNKNOWN, named: not found, behind a folder it can't look into, a relative path or a relative search folder (dyld and ld.so look for it from the folder the program is started in), `@executable_path` in a library, `$LIB` or `$PLATFORM`. The bytes outside the link table are read for one thing only, a library the program may load while it runs (`dlopen`): a Brotli library's or libnode's file name the loader can load (`libbrotlidec` or `libnode`, then an optional tag such as `-ba690955`, versions, and `.dylib`, or `.so` and its versions, whole or inside a longer string; or such a name the end of the file cuts off) that is not one of the file's own names is UNKNOWN, beside a table too, unless a library it links is EXPOSED. Its own names are a name inside its link table, a whole C string equal to one of its links or to its own install name or soname, and its code-signing identifier when that is its own file name: nothing else, so a Brotli library's own file name exempts nothing, and a fixed decoder library that also links or names another decoder is never SAFE. A static archive's or object file's name (`libnode_base.a(callback.o)`, of which nodejs.org's Node.js 26.12.1 for macOS names about 400 in its debug map), a separate debugging-information file's name (one ending in `.debug`, as a stripped ELF library's `.gnu_debuglink` names it, `libbrotlidec.so.1.1.0-1.1.0-4.fc40.x86_64.debug` on Fedora) or a word is no such name; on macOS, whose disks ignore case, names are found and compared ignoring it. A build is looked at for at most 65,536 mentions of each name; past them it is UNKNOWN. What that can't defend: a library loaded under another name (a link called `libfoo.dylib` to a Brotli library, a name a program puts together while it runs, or a name with other bytes in it, such as `libbrotlidec\x01.so.1`) can't be seen; where the loader finds an ELF soname among the system's folders is decided by its cache, which isn't read, so every copy there must be SAFE; what the dynamic loader is told when the program starts (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`), and the `LC_RPATH` entries of the program that loads a library (which dyld also searches for that library's `@rpath`), are not known to Wardlatch, so a library found only through them reads "not found"; a loader's other reasons to pass over a copy of the right format and CPU (its platform, its code signature, its version) are not read, so such a copy is judged as one the loader takes; dyld's fallback folders (`/usr/local/lib`, `/usr/lib`) after an absolute path it can't load are not read either; and glibc before 2.37 also looked in legacy hwcaps subfolders (`tls`, `haswell`, `x86_64` and the like), which are not read. A copy found only through the program's folders never stops the search, so a program whose fixed copy glibc takes that way (its `DT_RPATH`, for a library with neither) reads EXPOSED beside an unfixed copy in the system's folders (probe C3): a false EXPOSED, never a false SAFE. A loader whose pages are larger than 64 KB is not covered by the page rule. Folders named with `--paths` are read as text, as the shell's `cd` reads them. A position-independent program without `DF_1_PIE` (an older toolchain's) is read as a library, so a soname its own folders don't hold reads UNKNOWN. A file over 512 MB (or past the run's 4 GB reading budget) is UNKNOWN. A distribution's library without the marker is judged by its package version, compared by exact string with the incident's table (Debian's fixed security builds by binary version, its unfixed packages by the source version every rebuild keeps), and only when dpkg's md5sums list for that package names the very file with the same MD5: a library a `make install` or a vendor put at a system place is not the package's; a version not in the table, one it can't read (an rpm database), or a file no package record names is UNKNOWN. *Evidence:* `test/brotli.test.mjs` (the Homebrew-libnode case, where a substring search would read a header as a fix; a whole link to an unfixed libnode beside a fixed table or a fixed Brotli library EXPOSED, and one it can't follow UNKNOWN; a distribution's node whose libnode is found but not SAFE, or whose loader configuration could not all be read, UNKNOWN; a universal file whose every build lacks the fix EXPOSED in that build's words; decoy strings that contain the marker; the marker without the control; names that lie; links read from the link table as the loader reads it (each command that loads a library, 32- and 64-bit, either byte order; `@rpath` through `LC_RPATH`, in a universal node laid out as Homebrew's, with its libnode judged; `DT_RUNPATH` `$ORIGIN/../lib` and `DT_RPATH`; every candidate, after round 6's dyld and ld.so probes: an unfixed copy in the second `LC_RPATH` folder EXPOSED, a fixed copy of another CPU type, class, machine, byte order or file type UNKNOWN and an unfixed one the loader takes instead EXPOSED (m1, m1b, E1, E1m), an arm64e or x86_64h copy judged (m1e: unfixed EXPOSED), `..` after a link as the kernel takes it (m5, m6), `$ORIGIN` as either folder, a program's `DT_RPATH` and `DT_RUNPATH` for its libnode's soname (E2, E2r), a library read without its program UNKNOWN, `glibc-hwcaps` subfolders, what stops the search before the system's folders (a fixed copy found only through the program's folders, C1, C2, C3, or only in a hwcaps subfolder, H5, beside an unfixed system copy EXPOSED; one in the file's own `DT_RUNPATH` SAFE; a folder that holds the copy only one way `$ORIGIN` reads stops nothing), a search folder that can't be looked at UNKNOWN (m7), a dynamic table at `p_offset` that isn't the one at `p_vaddr` UNKNOWN (E4), a dynamic or string table on a page two `PT_LOAD` segments map UNKNOWN (E4b, E4c), and a candidate's look charged to the reading budget; macOS's caseless names by default; a name offset that skips bytes in its command; names with a tab, a newline, DEL, a control byte or é; an upper-case name), and `LC_DYLD_ENVIRONMENT`, headers that don't fit their format and other formats UNKNOWN beside a fixed table; unreadable files, FIFOs, oversized files and the reading budget UNKNOWN; planted programs never run; the distribution table by exact string; Brotli 1.0's whole tables, 1.0.3 and 1.0.9 EXPOSED and 1.0.10 SAFE, packed or padded and either way round, Debian 12's libbrotli1 as GCC lays it out (its security build SAFE by its table) and by its package version, and its near misses UNKNOWN; a Brotli library's or libnode's loadable file name outside the link table (`libbrotlidec.so.1` as `dlopen` takes it, a message naming it, a name the end of the file cuts off) UNKNOWN beside a fixed table, and a debug map's `libnode_base.a(member)` names, more than 64 of them, SAFE; a Brotli library's own names (its install name, soname and code-signing identifier) and only those, a fixed one that links or names another decoder never SAFE (mutant A-self-wide); EXPOSED over UNKNOWN between the Brotli library and libnode, either way round, and between two links (mutant B-exposed-masked); more mentions than are looked at UNKNOWN; a relative load path or search folder UNKNOWN beside a table; each layout of volta, mise, rtx, proto, asdf and nodenv, a mise variable holding one path with a `:` in it, proto's copies of proto-shim by place and by marker (a program holding only `PROTO_SHIM_NAME` is no shim), asdf's and nodenv's script shims, asdf's `node` plugin and a shim of one plugin beside another plugin's folder (UNKNOWN), a plugin line of fewer than four parts and a shim over 64 KB naming no plugin (UNKNOWN, mutant D-3-segments), a script in proto's shims folder (UNKNOWN, mutant m19), `ASDF_DATA_DIR` set to `~/...` or `~` (and `~other/...` still unsure), and a shim whose folder of runtimes is missing, closed or named by a relative variable, or any other script named `node`, UNKNOWN through the command; and a `..` after a link in `PATH`, a version manager's variable, the home folder, a package's `RECORD` and an `ld.so.conf` `include`, each read as the program that reads it does) and `test/paths.test.mjs` (the same for programs on `PATH`, `$TMPDIR`, site-packages folders, the trust check's curl and the header settings' folders), each with its clean twin.

**Header settings are read, never used.** The identity-headers check (`lib/headers.mjs`) reads your name and email from your own git config files as text (git is not run, and `include` lines are not followed), and compares them with the header settings in files and the environment. Neither your identity nor any header value is printed, written or sent; a test checks the output and the `--json` output for both. A settings folder the home folder or a variable names with a `..` after a link in it is read both ways (round 8): as written, as git, curl and wget open it, and cleaned up as text, as npm and the Node-based agents and editors do (`test/paths.test.mjs`).

**git gets a clean environment, not the caller's.** Since 0.1.8 git runs without the caller's `GIT_*` variables (except `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_NOSYSTEM`, which only choose your own config files, and `GIT_TEST_ASSUME_DIFFERENT_OWNER`, which can only make git refuse a repository): `GIT_DIR` or `GIT_WORK_TREE` from a hook or a CI step had pointed every scan at one other repository, and the git checks read SAFE without having looked (0.1.0 to 0.1.7). A test sets both kinds and expects the found repository to be read and nothing planted to run.

**Programs on `PATH` are trusted, except a program an incident says may itself be malware.** The first `node`, `curl`
and `python3` on `PATH`, and later copies that are compiled programs (a later script is never run), `/usr/bin/curl`, `/usr/bin/python3`, and each tool named in a version rule, is run from the
place it was found, the one your shell would pick: each `PATH` folder and the program's name put together as written,
never cleaned up as text, so a `..` after a link in a `PATH` folder goes where the shell goes (up to 0.1.9 `x/link/../bin`
was read as `x/bin`, another file), and each copy once by its real path as the operating system resolves it; the PHP check also runs the first `php`, `php-fpm` or `php-cgi` of
each versioned name in its known install folders off `PATH` (the `sbin` folders, macOS Homebrew's `php@*` kegs, Remi, cPanel,
Plesk), where a second PHP serving the sites lives. Each is run once for its version (`node -v`, `curl --version`,
`python3 -V`, or the rule's arguments), and each runtime once more per test connection, with the arguments in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#the-trust-check-step-by-step). Python is not started the way your shell
would start it: see the next paragraph. Since 0.1.7 every `node_modules/.bin` folder and every relative entry is
dropped from `PATH` before anything runs (npx puts the current project's `node_modules/.bin` first, so a project could
otherwise have Wardlatch run its own `git` or `python3`; when nothing is left, `PATH` is `/usr/bin:/bin`, and git is
run by its full path), every program runs from `/` (so a version manager picks your default, not the current project's
pin; `--paths` folders and relative CA settings such as `SSL_CERT_FILE` are made absolute first, a CA setting by
putting the starting folder in front of it as written, so a `..` in it stays where your own programs take it),
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
as `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c log.showRoot=true -C <repo>`, with
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
