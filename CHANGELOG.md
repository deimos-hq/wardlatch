# Changelog

What changed in each release of the `wardlatch` package on npm, newest first, written to help you decide whether to
update. Run `npx wardlatch@latest` to get the latest release: a bare `npx wardlatch` runs any copy already installed
globally or in the current project, whatever its version (and npm older than 9.6.5 also reuses a copy npx cached
earlier).

Every release has a signed tag (`v0.1.0` onwards; 0.1.0 to 0.1.2 were tagged afterwards at the commit npm recorded as
each one's `gitHead`), and 0.1.3 onwards were built and attested by the release workflow. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.16] - 2026-11-11

Three incidents, and Macs that took Apple's 9 November update now get answers instead of "could not be tested".

- **Brotli, CVE-2026-111497** (`brotli-2026-10`). The decoder flaw in Node.js, Bun, Python packages (Brotli, brotlicffi,
  Pillow, opencv-python) and Brotli libraries. CISA lists Google's Brotli as known to be exploited (added 27 Oct 2026,
  due 10 Nov). Wardlatch reads each decoder's own bytes, because version numbers mislead here (Node.js 26.12.1 is fixed
  and reports Brotli 1.2.0). On a Mac it also says what Apple's notes of 9 Nov say of macOS's own copy.
- **Google Chrome, CVE-2026-125350** (`chrome-2026-11`). Fixed in 157.0.8103.50 (.51 on Mac and Windows) on 9 Nov;
  Google says an exploit exists in the wild. Wardlatch reads the installed version and never starts Chrome.
- **CISA's catalog dates** under every incident CISA lists as exploited: SSHole, Brotli, PHP and Plex.
- **After Apple's update** (macOS 27.2.1, 26.7.3, 15.8.3): 0.1.14 and 0.1.15 read the built-in curl and python3 as
  "could not be tested" on an updated Mac, because those tools now refuse the compromised certificates even when the
  withdrawn roots are put back. That refusal is now counted for what it is, Apple's own block.

Sources: [CISA's catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[Brotli 1.2.1](https://github.com/google/brotli/releases/tag/v1.2.1),
[Apple's notes for macOS 27.2.1](https://support.apple.com/en-us/149718), [26.7.3](https://support.apple.com/en-us/149719)
and [15.8.3](https://support.apple.com/en-us/149720), [Apple's eMudhra page](https://support.apple.com/en-us/149555),
[Chrome's stable update of 9 Nov](https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_018223192.html).
What we measured on one Mac on 10 Nov 2026, before and after its update to 27.2.1, is in
`test/support/fixtures/README.md`; the tests are `test/brotli-0.1.16.test.mjs`, `test/brotli.test.mjs`,
`test/kev.test.mjs`, `test/apple-update-0.1.16.test.mjs` and `test/chrome-0.1.16.test.mjs`.

### Security

Two defects in released code that could read SAFE where something was wrong. ADVISORY: owner's decision, pending.

- **On a Mac, a virtual environment's certifi could read SAFE because of Apple's trust, not certifi's list** (0.1.x
  to 0.1.15, macOS only). Wardlatch tested a venv's certifi bundle by giving it to the built-in curl with `--cacert`.
  Apple's curl doesn't keep to a CA file: when the file can't vouch for a site it falls back to the system's trust
  (long-standing: curl issue #12604, 2023, which Apple says is intended). So the row measured Apple's trust, which
  blocks the compromised certificates, and a certifi list that still held a withdrawn root could read SAFE, while a
  program using that list with its own OpenSSL would trust the chain. A bundle row now first gives the curl a CA file
  holding only a certificate that vouches for no site (`lib/negative-control.pem`, made for this; no private key is
  kept). If the curl still opens a normal site, or if it blocks the compromised keys itself, the bundle is read by key
  instead (below). Found on 10 Nov 2026 by an inspection of an updated Mac; fixed the same day.
- **A path with `..` after a link was cleaned up as text, so Wardlatch read, ran or hashed another file than the one
  your programs use** (0.1.0 to 0.1.15). The fix was written on the Brotli branch in late October and recorded on
  1 Nov 2026 as a defect in released code, then held with that branch until this release: nine days longer than this
  policy allows, because it was not split out of an unfinished branch. Details under Fixed below.

### Added

- **CISA KEV lines.** An incident whose CVE is in CISA's Known Exploited Vulnerabilities catalog prints one line under
  its title, in CISA's own vendor and product words ("CISA KEV: Google Brotli CVE-2026-111497 is known to be exploited ·
  added 27 Oct 2026 · due date for US federal agencies 10 Nov 2026 · <link>"), and `--json` carries the rows with their
  links under `incidents[].kev`. Wardlatch never fetches the catalog: `scripts/kev-snapshot.mjs` copies the rows from a
  whole read of CISA's feed before a release (it refuses a partial one), and `test/kev.test.mjs` fails if an incident
  file and that copy disagree in either direction. Catalog 2026.11.09: SSHole, Brotli, PHP (two CVEs) and Plex (four)
  are listed; GitLab's CVE-2026-110264 and Chrome's CVE-2026-125350 are not.
- **`chrome-2026-11`.** Reads Chrome's `Info.plist` in `/Applications` and `~/Applications` and dpkg's record of
  `google-chrome-stable`. Below 157.0.8103.50 is EXPOSED. At or past it is REVIEW, not SAFE: a Chrome left open since
  it updated runs the old version until it restarts, and no file says which version is running. Other Chromium
  browsers, Chrome's other channels and Chrome from snap, Flatpak or an RPM are named under "not covered".
- **macOS's own Brotli.** On a Mac the Brotli check gives one row from the macOS version and Apple's notes of 9 Nov
  2026, and says that is all it rests on (Apple's copy is inside the system, not a file Wardlatch reads): SAFE on
  27.2.1, 26.7.3, 15.8.3 or later; EXPOSED, with "update macOS", before them; could not be tested on macOS 14 or older,
  for which Apple names no update. It stands in for no other row: the all-clear for copies on disk is still given.
- **Leftover copies of `/etc/ssl/cert.pem`.** On a release Apple names, each `/etc/ssl/cert.pem.*` that still holds a
  withdrawn root (by key) is a REVIEW line, the Mac fix's own backup included, with Apple's words: don't restore it,
  even if a program stops connecting after the update, and delete it once you have updated. Read, never changed.
- **pip's own CA list** (`pip/_vendor/certifi/cacert.pem`, in the machine's Python folders and in apps' Pythons) is read
  by key: a REVIEW line when it still holds a withdrawn root. pip uses it only with `--use-deprecated=legacy-certs`, and
  on one Mac on 27.2.1, pip 26.1.2 and 26.2.1 given that flag connected to a compromised test host of the emSign family
  (the AAA family was refused, since pip's own list had dropped AAA).
- **certifi inside apps' own Pythons** (Blender, Unity's Emscripten Python) is read by key: a REVIEW line when it holds
  a withdrawn root. Those Pythons' plain `ssl` default reads no list; their bundled certifi and requests accepted
  compromised hosts on one Mac. Whether the apps themselves connect that way was not shown.
- **Read by key.** Where a CA file is judged as a file (`lib/macos.mjs` `bundleHolds`), each certificate's public key is
  compared with the two withdrawn roots and the seven withdrawn keys, so a relabelled, re-issued or cross-signed copy
  is caught; a block that can't be read keeps the line at "could not be tested", never SAFE.

- **`brotli-2026-10`: the Brotli decoder flaw (CVE-2026-111497), in Node.js, Bun, Python packages and Brotli
  libraries.** Built over twelve review rounds (24 Oct to 1 Nov 2026) on a side branch, and landed in 0.1.16. A new kind of check
  (`bundled`, `lib/brotli.mjs`) that reads the decoder itself instead of a version number, because the version numbers
  mislead here: Node.js 26.12.1 is fixed and reports Brotli 1.2.0, Homebrew's node uses Homebrew's Brotli, Debian's
  fixed packages keep 1.0.9 and 1.1.0. The fix added an error code, so a fixed decoder's error table holds the string
  `_ERROR_FORMAT_BLOCK_SWITCH`. Others used that error name as the sign of the fix before this check:
  OrchestratorInc/agent-orchestrator pull request #7107 looked for the string in a library file, and baealex/BLEX pull
  request #580 asked the decoder for it at run time (`BrotliDecoderErrorString(-17)`), both on 23 October. Wardlatch's is
  the same idea, built into the check: an exact, NUL-delimited match plus a control string every decoder has
  (`_ERROR_FORMAT_BLOCK_LENGTH_1`), reading bytes only. Trail of Bits' brotli-checker is another tool that finds bundled
  copies; it checks source trees and ELF builds, and Wardlatch points to it.
  - Brotli 1.0 writes the same table without the prefix (1.0.x's `BrotliDecoderErrorString` has `return #NAME;`, 1.1.0
    on `return #PREFIX #NAME;`; both read in google/brotli's own `c/dec/decode.c` at v1.0.9, v1.0.10 and v1.1.0), so
    Debian 12's libbrotli1 1.0.9 holds `BLOCK_LENGTH_1`, and 1.0.10, the fix on the 1.0 line, adds `BLOCK_SWITCH`
    (code -17, right after `DISTANCE`). Those short words could be in any program, so that form is judged only as a
    whole table (maintainer, 2026-10-25): the names from `HUFFMAN_SPACE` to `DISTANCE` in Brotli's order
    around `BLOCK_LENGTH_1`, each NUL-delimited (up to 16 NULs between two, as a compiler pads strings it aligns),
    either way round (the order `decode.h` lists them, as clang lays them out, or by code), then `BLOCK_SWITCH` and
    `DICTIONARY_NOT_SET` (1.0.10), `DICTIONARY_NOT_SET` at once (1.0.4 to 1.0.9), or `COMPOUND_DICTIONARY` and
    `DICTIONARY_NOT_SET` (1.0.3, the first affected release, whose `decode.h` lists `DISTANCE` then
    `COMPOUND_DICTIONARY`).
  - What proves SAFE: the marker exactly as often as the control, in the file (in each build of a universal Mach-O file,
    with every Brotli library a file with a table also links SAFE too) or in the Brotli library it links (every
    candidate, by its real path, named in the receipt), or a Debian package version its table lists as fixed, for the
    very file that package installed (dpkg's md5sums list names it with the same MD5). In Brotli 1.0's form: every copy
    of `BLOCK_LENGTH_1` in a whole table with `BLOCK_SWITCH` in its place, and `BLOCK_SWITCH` nowhere else.
  - What is EXPOSED: the control without the marker (or fewer markers than controls), in the file or its library; a
    whole Brotli 1.0 table without `BLOCK_SWITCH` (a fixed 1.1-form table beside it included), which for a Debian
    library hands over to its package version as the 1.1 form does (Debian 12's own 1.0.9-2+b6 reads EXPOSED by both;
    its security build 1.0.9-2+deb12u1 adds `BLOCK_SWITCH` in its place and reads SAFE by its table alone); a Debian
    package built from a source version its table lists as without the fix (every rebuild, such as 1.1.0-2+b7, keeps
    its source's version), again for the file that package installed. A bundled copy with no fixed release yet
    (Pillow, opencv-python) is EXPOSED, and its fix line says no release had a fixed Brotli on 24 October and to update
    when one ships.
  - What a file links is read as the loader reads it (maintainer's decision #24, 2026-10-25), from the binary format,
    never from strings that look like paths: a Mach-O build's header and load commands (`LC_LOAD_DYLIB`,
    `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB`, with `LC_RPATH`,
    `LC_ID_DYLIB` and `LC_DYLD_ENVIRONMENT`; 32- and 64-bit, either byte order, each build of a universal file on its
    own) and an ELF file's dynamic table (`DT_NEEDED`, and `DT_AUXILIARY` and `DT_FILTER`, whose objects glibc loads
    too; `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`, through `DT_STRTAB`), every read bounded and checked against the file.
    Its Brotli libraries and libnode are exactly the entries named `libbrotlidec*`, or `libnode` and `libnode.*`,
    `libnode-*`, `libnode_*` (any case). Which copy of each a loader
    takes is not predicted (maintainer's decision #25; rounds 6 to 8 modelled where dyld and ld.so look first, and each
    verifier found another way a real loader takes a different copy: x86_64h under Rosetta, glibc 2.36's old hardware
    subfolders, a library another library loaded first, the kernel's page size, ABI flags). Every file a loader might
    take for the link is a candidate. The folders a loader might look in: every folder named by the file's own search
    paths and those of every library followed from it (`DT_RPATH` and `DT_RUNPATH`, both, and `LC_RPATH`, with `$ORIGIN`,
    `@loader_path` and, in a program, `@executable_path` put in); the system's folders (on Linux `/lib`, `/usr/lib`,
    `/lib64`, `/usr/lib64`, `/usr/local/lib`, the multiarch folders and those `/etc/ld.so.conf`, its usual
    `ld.so.conf.d/*.conf` include and musl's `/etc/ld-musl-*.path` name; on macOS `/usr/local/lib` and `/usr/lib`, dyld's
    fallback folders); and the folders below those, except package folders (`site-packages`, `dist-packages`,
    `node_modules`) and folders named `debug`, which no loader searches unless a search path names them (a folder a
    search path names is searched whatever its name). Every library the file links, and every library those link (the
    closure), is looked for the same way, and every candidate followed, so its search paths join the folders. The link
    is SAFE when every candidate is SAFE and EXPOSED when every candidate is EXPOSED; a mix, a candidate that can't be
    judged, none found by the link's own name, a folder or library on the way that can't be read, a path that can't be
    followed (relative, empty, another `$` or `@` word; on the way, a library's own link to a Brotli library or libnode
    too, while the file's own, and, when it links libnode, every libnode's, each a candidate for that link, are judged
    in their rows), or the reading budget spent is "could not be tested". Which copy
    a loader takes first, and whether it can load a copy (its CPU type, subtype, platform or ABI flags), decide nothing.
    Round 10's rules (decision #25 standing), each of which only widens the candidates or the closure, and none of which
    models which copy wins: (1) a library reached by more than one path (a link to it in another folder) has `$ORIGIN`
    and `@loader_path` put in as its real folder and as the folder of every path it is found by, not only the first's
    (round 9 kept one path per file, and missed the folder glibc and musl take `$ORIGIN` from: probe O1); (2) every
    Brotli library (or libnode) that any link of any object in the closure reaches, by any name or path (the name it was
    linked by, a path it was reached by, absolute or resolved, its real file name, its `LC_ID_DYLIB` or `DT_SONAME`), is
    a candidate for every Brotli (or libnode) link in the closure, so a copy another library loads first, or one a loader
    hands a later link for its install name or soname, is in the set (probes N1, N10, N11 and N13 with the real dyld,
    G1, G1o and G1c from glibc's source; round 9's "a library another library loads first is covered" was not true of
    them); (3) in every folder and subfolder looked in, every file of exactly the link's file name (compared ignoring
    case on macOS), every file whose `DT_SONAME` or `LC_ID_DYLIB` has that file name, and, for a Brotli library or
    libnode, every file whose name starts with `libbrotlidec` (or is `libnode`, `libnode.*`, `libnode-*`,
    `libnode_*`), compared ignoring case on macOS, is a candidate, and so is the name itself when it is an absolute
    path, or an `@` or `$ORIGIN` path (probes G2, G2b: ldconfig caches a `glibc-hwcaps` subfolder's
    `libbrotlidec.so.1.2.0` by its own file, under its soname); only a file no loader can load is passed over, a static
    archive (`!<arch>`) or plain text (a linker script, a `pkg-config` or libtool file), never a file for its name
    alone (one whose name ends in `.debug` is a candidate like any other), and any other file that can't be read as
    Mach-O or ELF is "could not be tested", so Debian's `libbrotli-dev` layout
    (`libbrotlidec.so` → `.so.1` → `.so.1.0.9`, `libbrotlidec.a`, `pkgconfig/libbrotlidec.pc`) and Homebrew's
    (`libbrotlidec.dylib` → `.1.dylib` → `.1.2.1.dylib`) read as the one file each installs; and a wider name never
    stands in for the link: a
    link no file answers by its own name (its path, its file name, an install name or soname of that name) is not
    found; (4) the folders below a searched one are looked in down to 4 levels (probe G3: on x86-64, glibc 2.36
    searches `tls/haswell/avx512_1/x86_64` on an Intel CPU with AVX-512, most x86 cloud servers; round 9's 3 levels
    rested on `tls/haswell/x86_64` being the deepest; another machine's, s390x's say, can go deeper); (5) in every
    folder looked in, `<folder>/<the link's file name>` is also opened (a `stat`) as the loader opens it, for every
    link followed, so a folder whose file system ignores case (ext4 with casefold, vfat, exFAT, WSL's `/mnt/c`) gives
    its copy under another case, and a library found so is followed too (probe G6; round 9 compared names by case off
    macOS); (6) the loader's inputs that are not variables: every word in `/etc/ld.so.preload` (split on spaces, tabs,
    line feeds and `:` as glibc's `elf/rtld.c` splits it, with no comment taken out, as glibc's own loop for its
    comments can leave a later comment's words in, or parts of them: with no `#` and no NUL in the file, the words are
    every name glibc may load, and more; with a `#` or a NUL, every link is "could not be tested") is a library that
    joins the closure, looked for as the program's own links, and its Brotli links count under (2), while a preload
    file that can't be read, a word in it with a `#` or a NUL in it, or a name in it that can't be followed, makes
    every link "could not be tested"; and a program whose `PT_INTERP` is not one of the system's loaders, glibc's or
    musl's per-architecture names under `/lib`, `/lib64`, `/usr/lib` and `/usr/lib64` and the multiarch folders
    `/lib/<triplet>` and `/usr/lib/<triplet>` (21 of Debian's tuples, x32's not among them), compared with repeated
    slashes read as one and nothing else cleaned up (`ld-linux-x86-64.so.2`, `ld-linux.so.2`, `ld-linux-aarch64.so.1`,
    `ld-linux-aarch64_be.so.1`, `ld-linux-armhf.so.3`, `ld-linux.so.3`, `ld64.so.1`, `ld64.so.2`, `ld.so.1`, the riscv32
    and riscv64, loongarch64, ia64 and MIPS NaN2008 names, and musl's `ld-musl-<arch>.so.1` for `x86_64`, `i386`,
    `aarch64`, `aarch64_be`, `arm`, `armhf`, `armeb`, `armebhf`, `riscv32`, `riscv64`, `powerpc`, `powerpc64`,
    `powerpc64le`, `s390x`, the MIPS names, `loongarch64`, `m68k`, `microblaze`, `microblazeel`, `or1k` and `sh`; no x32
    loader, by any name or in any folder, as x32's own folders, `/libx32` and `/usr/libx32`, are not looked in:
    `SYSTEM_LOADERS`), or whose `PT_INTERP` can't be read, is "could not be tested", since another loader (Homebrew's
    on Linux, Nix's, Guix's, a vendored glibc) searches its own folders. The cost: on a machine that also holds an
    unfixed copy in a system folder (an old 32-bit copy, say), a program with a fixed private copy is "could not be
    tested", and that system copy's own row is EXPOSED; a program whose closure reaches both a fixed and an unfixed
    copy is "could not be tested", even where one library certainly loads the unfixed one; a second libnode version
    installed beside the one a node links is a candidate too; an empty element in a search path (`a::b`, `a:`, or a
    whole empty `DT_RUNPATH` or `DT_RPATH`) is read as a folder named by a relative path, "could not be tested",
    because glibc 2.36 keeps an empty element beside others as the folder the program is started in (`fillin_rpath`),
    though it ignores a search path that is empty as a whole (`decompose_rpath`) and musl skips every empty element; an
    `/etc/ld.so.preload` with a `#` (a comment) or a NUL in it makes every link "could not be tested"; so does a
    `PT_INTERP` spelled any other way (`/lib64/./ld-linux-x86-64.so.2`), and any x32 program's; and so do more than
    65,536 folders to look in, or 4,096 libraries to follow, for one file (not measured on a large Linux `/usr/lib` or
    `/usr/local/lib`, where package folders are not walked either; on the Mac this was checked on, `/usr/local/lib` and
    `/usr/lib` are 184 folders).
    Round 11 (decision #25 standing, the owner's safe-side rules after round 10's verifier): package folders and
    `debug` folders are no longer walked, so Pillow's unfixed copy under an Intel Mac's
    `/usr/local/lib/python3.13/site-packages/PIL/.dylibs` no longer makes Homebrew's node "could not be tested"
    (Pillow's own row reads it EXPOSED), nor Fedora's `/usr/lib/debug/usr/lib64/libbrotlidec.so.1.1.0-….debug` every
    Brotli link; `/etc/ld.so.preload` is read with no comment taken out (probe H1: glibc's comment loop may leave a
    second comment's path in, and preload it); `DT_AUXILIARY` and `DT_FILTER` are links (H2a, H2f); a library on the
    way whose own Brotli link can't be followed leaves the closure incomplete (H4); every followed library's name is
    opened in each folder (H3); and the `PT_INTERP` list takes `/usr/lib64`, the multiarch folders and repeated
    slashes. Round 12 (the owner's safe-side fixes after round 11's verifier): no x32 loader is in the `PT_INTERP` list
    any more, by any name or in any folder, so an x32 program, which may load an unfixed copy from `/libx32` or
    `/usr/libx32`, folders not looked in, is "could not be tested" (probe X1 read SAFE in round 11); and a file is
    never passed over for its name, so an unfixed library named `libbrotlidec.so.1.0.9.debug` in
    `glibc-hwcaps/x86-64-v3`, which ldconfig caches by its own file name, is a candidate (probe C7 read SAFE in round
    11). Each path is handed to the operating system as written (`realpath(3)`), so `..` after a link goes
    where the kernel goes (Node's own `realpathSync` cleans it up as text first). An ELF file contradicts itself and is
    "could not be tested" when its dynamic table at `PT_DYNAMIC`'s `p_offset` isn't the one the loader reads at its
    `p_vaddr`, and when its dynamic table or string table (`DT_STRTAB`) is at an address in the page-rounded range of
    more than one `PT_LOAD` (the kernel and ld.so map them a page at a time, a later one over the earlier, so another
    segment's bytes may be there), with every page a kernel for its machine may use: 4 KB on x86 and x86-64, and 4, 16
    and 64 KB on any other machine, never the file's `p_align`; with one `PT_LOAD` for each address it reads as before.
    The run's 4 GB reading budget is charged before each of these reads: each file judged (its first 8 bytes, a
    universal file's list of builds, its bytes, and each build's headers: header, load commands or program headers,
    `PT_INTERP`, dynamic table, the names it reads and its code signature's identifier); each folder the candidate
    search lists (4 KB before it is listed, then 256 bytes an entry, once a run); each file in such a folder (its first
    8 bytes, and a Mach-O, universal or ELF file's list of builds and headers, once a run), and a candidate's first 4 KB
    when it is none of those nor an archive (to tell plain text); each library followed by its path (the same); a
    library read again for its MD5, against dpkg's record; and a `node` on `PATH` read for proto-shim's marker. Not
    charged (each read once per use, each capped): dpkg's status file (up to 128 MB, for each library judged by its
    package version), dpkg's `md5sums` lists (4 MB each), each Python package's `RECORD` or `installed-files.txt` (4 MB)
    and the first 8 KB of its `METADATA` or `PKG-INFO`, `/etc/ld.so.conf`, its `ld.so.conf.d` files and musl's path
    files (64 KB each), `/etc/ld.so.preload` (64 KB), apk's installed database (64 MB), `/etc/os-release` (64 KB), an
    asdf shim's plugin lines (its first 64 KB), the first 4 bytes of each program found, and the folder listings outside
    the candidate search (`PATH`, site-packages, the version managers' and library places' folders). Each candidate is
    judged, one level, and a link whose every candidate is EXPOSED decides over one that isn't SAFE. The rest of the
    file is read only for a library it may load while it runs (`dlopen`): a Brotli library's or libnode's file name the
    loader can load (`libbrotlidec.so.1`, `libnode.147.dylib`, `libbrotlidec-ba690955.so.1.1.0`, in a message or a path
    too) that is not one of the file's own (in its link table, a whole copy of one of its links or of its own install
    name or soname, its code-signing identifier when that is its own file name, and nothing else) makes it "could not be
    tested"; a static archive's or object file's name (`libnode_base.a(callback.o)`), a debugging-information file's
    name (`libbrotlidec.so.1.0.9.debug`, as a stripped library's `.gnu_debuglink` gives it) or a word does not. So
    nodejs.org's Node.js 26.12.1 for macOS, whose debug map names about 400 static archive members, reads SAFE by its
    own table, and Homebrew's node, which links `@rpath/libnode.147.dylib`, is followed to its libnode and judged (an
    earlier draft of this check read both as "could not be tested").
  - What is "could not be tested": the marker without the control; no table and no library it can follow (a stripped
    static copy, a link not found or behind a folder it can't look into, `@executable_path` in a library, `$LIB` or
    `$PLATFORM`, a relative path such as `lib/libbrotlidec.1.dylib` or `../lib/libbrotlidec.so.1`, or a relative search
    folder, which dyld and ld.so look for from the folder the program is started in and which the reason names, any link
    when the loader's configuration or a folder looked in couldn't all be read; each of these beside a table too); copies
    of a linked library that disagree, or one that can't be judged (a FIFO, a link into a closed folder); headers
    that don't fit their format, a file that is neither Mach-O nor ELF, `LC_DYLD_ENVIRONMENT`, a library a program links
    that links a Brotli library or libnode of its own, and a name it may load while it runs (above), or more mentions of
    the names than the 65,536 a build is looked at for, beside a table too; Brotli 1.0's unprefixed error texts that are
    not whole tables (scattered, out of order, only some of them, a table followed by none of these, which is how 1.0.0
    to 1.0.2 read, more copies than the 64 kept, or `BLOCK_SWITCH` anywhere but in its place), alone or beside a fixed
    table; a file it can't read (a node or bun at mode 0111 included), over 512 MB or bigger than what is left of the
    run's 4 GB reading budget; a universal file whose builds overlap (read build by build, they would read the same
    bytes again); a zipped egg of a Brotli package; a distribution library without the marker whose package version
    isn't in the table or can't be read, or that no package installed as it is now. Node's `zlib.constants` names, which
    contain the marker as a substring, never decide.
  - A link to `libnode`, the library that holds Node.js's code (a distribution's node is a launcher for it, and so
    is Homebrew's), is followed and judged by the same rules, one level, beside a table or a Brotli library too, and
    must be SAFE as well: a libnode without the fix makes the file EXPOSED, and one it can't follow, find or read makes
    it "could not be tested". Homebrew's node links `@rpath/libnode.147.dylib`, found through its own `LC_RPATH`
    (`@loader_path/../lib`), and its libnode links Homebrew's Brotli library. A compiled `node` on `PATH` that shows
    no sign of Node.js is a REVIEW line only for a version manager's known shim (a link to volta-shim, mise, rtx or
    proto-shim; or a copy of proto-shim, which is how proto writes its shims today, in proto's shims folder or carrying
    the message only proto-shim holds, `Invalid shim name detected. Unable to execute the appropriate proto tool.`, from
    its own source, `crates/cli/src/main_shim.rs`, and not `PROTO_SHIM_NAME`, which proto's CLI holds too) whose nodes
    were read, and a script named `node` on `PATH` is one only for asdf's or nodenv's shim, in its shims folder: at
    least one of its folders of runtimes is there and was listed, every one that is there could be listed, and no
    variable names one by a path that doesn't start at `/`; otherwise it is "could not be tested" (exit 2), so a node it
    starts that Wardlatch didn't read never ends the run in exit 0. Any other script named `node` or `bun` on `PATH`
    (npm's node wrapper, one of your own) is "could not be tested" too. Those folders are each manager's layouts as its
    own source has them: volta's `$VOLTA_HOME` or `~/.volta`, `tools/image/node/<version>/bin/node` and its older
    layouts' `tools/image/node/<node>/<npm>/bin/node`; mise's `$MISE_DATA_DIR`, `$XDG_DATA_HOME/mise` or
    `~/.local/share/mise`, and its system installs (`$MISE_SYSTEM_DATA_DIR` or `/usr/local/share/mise`), each with
    `installs/node` and `installs/nodejs` (the asdf plugin's name, which mise up to 2024.1 renamed to `node` when it
    started), and `$MISE_INSTALLS_DIR`, `$MISE_SYSTEM_INSTALLS_DIR` and the list `$MISE_SHARED_INSTALL_DIRS` (the only
    variable split on `:`, as mise splits it; every other one is one path, a `:` in it included, as each manager reads
    it); rtx's `$RTX_DATA_DIR`, `$XDG_DATA_HOME/rtx` or `~/.local/share/rtx`, with `installs/node` and `installs/nodejs`
    (before rtx renamed it); proto's `$PROTO_HOME`, `$XDG_DATA_HOME/proto` or `~/.proto`, with `tools/node`; asdf's
    `$ASDF_DATA_DIR` (a leading `~/` in it, or a bare `~`, is your home folder, as asdf reads it since 0.17.0) or
    `~/.asdf`, with `installs/nodejs` and `installs/node` (a plugin named `node`), where asdf's shim counts only the
    folder of the plugins its `# asdf-plugin:` lines name, as asdf writes and reads them (a shim of another plugin, or
    of none, is "could not be tested"); nodenv's `$NODENV_ROOT` or `~/.nodenv`, with `versions`; and for each, the
    folder above the one its shim is in when that is its shims folder (volta's `bin`, the others' `shims`). The nodes in
    all of these are read whether or not a shim is on `PATH` (the folder above a shim's, when there is one). Any other
    compiled `node` with no sign of Node.js (a packed node, a shim Wardlatch doesn't know) is "could not be tested".
  - Fix lines follow the by-hand guide (https://www.deimoscore.com/wardlatch/brotli/): the fixed release for each
    Node.js line, "move to 22, 24 or 26" for the end-of-life ones, the library's own update for a node that links one
    (but Node.js's fix when libnode's own decoder decides: libnode is Node.js's own library), Bun 1.4.4, `Brotli>=1.2.1`
    and `brotlicffi>=1.2.1.0`, `brew upgrade brotli`, the conda and MacPorts updates, Debian's fixed packages.
  - `lib/files.mjs` gains `scanBytes` (fixed byte strings counted in a large file, or one range of it, read in 4 MB
    pieces, with each hit's place in the file, and needles found ignoring ASCII case and kept only when the caller's
    test takes them, up to a number of looks), `readAt` (up to 64 KB from an offset, for an ELF file's dynamic segment
    and a universal file's header), `sizeOf`, and `programKind` (which tells a file that can't be read from one that
    isn't a program). `lib/installs.mjs` exports `SITE_PATTERNS` for the tests.
  - Known limits: not yet run on a Linux nodejs.org build, whose linker may have merged the decoder's strings into
    Node's constant names; such a node would read "could not be tested" until that is checked on CI. A Brotli decoder
    in a library loaded under another name (a link called `libfoo.dylib` whose install name or soname is no Brotli
    library's either, such as a `libz.so.1` holding one; a name a program puts together while it runs; or a name with
    other bytes in it, such as `libbrotlidec\x01.so.1`) can't be seen. Loader variables set when a program runs
    (`LD_LIBRARY_PATH`, `LD_PRELOAD`, `DYLD_*`) are not known; `ld.so.cache` entries for a file outside the folders the
    loader's configuration names are not read; a library a program opens with `dlopen` by a path that isn't in its link
    table can't be seen (when its name is in the file, the file is still "could not be tested"); folders more than 4
    levels below a searched one are not looked in. Nor are libraries in dyld's shared cache (macOS keeps its own there,
    not as files, so they aren't followed), the program that loads a library read on its own (a Python package's file,
    read without Python), and so its folders and the libraries it loads first, or a folder below a searched one that
    another account owns and this account can't open (no program this account runs can load from it). nvm, fnm and n kept outside
    their usual folders (`NVM_DIR` and the like) are not read. An asdf plugin for Node.js named other than `nodejs` or `node` is not read, so its shim
    reads "could not be tested". mise's settings in its configuration files (`shims_dir`, `system_installs_dir`,
    `shared_install_dirs`) are not read, only its variables. A partial backport that adds
    the new error code without the decoder's fix would read SAFE, and so would an unfixed table beside one stray
    NUL-delimited copy of the marker (in the 1.1 form; in the 1.0 form a stray copy makes it UNKNOWN). Brotli 1.0's
    table layout was checked against clang's (1.0.9's and 1.0.10's lists compiled at -O0, -O2 and -Os) and against
    Debian 12's own GCC builds (libbrotli1 1.0.9-2+b6 and 1.0.9-2+deb12u1, amd64 and arm64, from deb.debian.org, each
    checked against the archive's signed index): GCC lays the names out in `decode.h`'s order, one NUL apart on amd64
    and each padded to 8 bytes on arm64, which the reader takes as it is. Another compiler's layout it doesn't match
    reads "could not be tested", never SAFE. A linker that merges a 1.0 name into a longer string ending in it
    (`BLOCK_LENGTH_1` into `_ERROR_FORMAT_BLOCK_LENGTH_1`) hides that table, as with two decoders in one image.
- The tests never look in the home folder of the person running them (where macOS keeps Desktop, Documents, Downloads,
  Library, Photos and Mail): every test file loads `test/support/no-real-home.cjs` first, which refuses any look there,
  in the test and in every Node process it starts, and drops the home's folders from the `PATH` the tests start with.
  The sudo test and the two tests of macOS's own Library build a `/Users/<name>` home of their own
  (`test/support/fake-home.cjs`); `test/cli.test.mjs` gives the command an empty HOME of its own.

### Changed

- **Apple's own block is counted as a block.** On macOS 27.2.1 the built-in curl and python3 refuse the 12 certificates
  as revoked even when the withdrawn roots are given to them, offline too (curl exits 60 with "certificate revoked";
  the certificate error is 23). The probes now tell that refusal from any other: curl prints its verification result,
  and python3's probe reports verify code 23 as a block. As for Node.js, a block counts only if the same tool still
  opens a normal site. On an updated Mac the built-in curl and python3 read SAFE, "blocks the compromised keys
  themselves", from what they do.
- **When a tool's refusal can't be read either way**, on a release Apple names, the file it reads stands in: SAFE only
  when it refused every test host, opened a normal site, and `/etc/ssl/cert.pem` holds none of the withdrawn roots or
  keys with every certificate read. A host it opens is EXPOSED on every path. `SSL_CERT_FILE`, `SSL_CERT_DIR` or a
  `.curlrc` keep the line at "could not be tested" and say why.
- **"We haven't measured what an update does to a file changed by hand"** is now what we measured: on one Mac on 10 Nov
  2026, the update from 27.2 to 27.2.1 replaced a hand-changed `cert.pem` with Apple's file. Other Macs and the 26.7.3
  and 15.8.3 updates were not measured.
- **Brotli facts, re-read on 10 Nov 2026**: Debian's tracker now lists 1.2.0-4.1 as forky's fix (it had none on
  24 Oct); the newest Pillow (13.0.0, 16 Oct) and opencv-python (4.14.0.94, 28 Jul) on PyPI predate Brotli's fix, so the
  fix texts say so with dates; iPhones and iPads are named under "not covered".
- **The Go rebuild advice** says it is for Linux and containers: on a Mac, Go checks certificates through Apple's
  trust, which Apple says blocks the 12 for apps that use it.
- **Docker**: "Docker is not running, so it has no running containers to check (start it and run again to include
  them)", and "containers were not checked (--no-containers)".

### Fixed

- **A failed forced-roots control no longer hides a connection.** When one root's control passed and the other's was
  refused, the check returned "could not be tested" before probing any test host plainly, so a tool that connected to a
  compromised chain read exit 2 instead of 1. Every control failure now probes the hosts plainly first, and a connection
  is EXPOSED.
- **A path with `..` after a link was cleaned up as text, so Wardlatch read, ran or hashed another file than the one
  your programs use** (0.1.0 to 0.1.15). With `PATH` holding `x/link/../bin`, the shell runs the program in the folder
  above the link's target, then `bin`; Wardlatch put `x/bin/<name>` together with `path.join` and checked that one
  (and a second real file in `x/bin` was dropped as one already read). Each `PATH` copy is now the folder and the name
  as written, `${folder}/${name}`, resolved by the operating system (`realpath(3)`), and copies are told apart by that
  real path; the same for PHP's versioned names on `PATH`, the trust check's runtimes and the curl that tests the
  Linux trust store, `$TMPDIR` (a temp folder could be taken for `/tmp`, and `/tmp` left unsearched), a relative CA
  setting made absolute (`SSL_CERT_FILE=lnk/../ca.pem`), a Python package's `RECORD` path, and the folders the home
  folder or a variable names (a version manager's, `XDG_CONFIG_HOME`, `CURL_HOME`, `NPM_CONFIG_USERCONFIG`, a library
  or site-packages place under `~`). Where the programs that read a path disagree (git, curl, wget, Codex, the shell
  and volta, mise, proto and nodenv take a `..` after the link; npm, the Node-based agents and editors, and asdf's Go
  clean it up as text), both readings are read. An `ld.so.conf` `include` with a `..` is not followed (a gap, so an ELF
  soname is "could not be tested"). Folders named with `--paths` are still read as text, as the shell's `cd` reads
  them.

## [0.1.15] - 2026-11-10

The first new incident since 22 October: SSHole, CVE-2026-123158. sshd in OpenSSH before 10.6p2, on Linux with musl
libc and without PAM, accepts a very long password for an account whose password field is `*` (no password set, as for a
key-only account) when another local account has a `$5$` or `$6$` hash. Alpine's advisory says 257 to 1024 bytes; the CVE
record says between 256 and 1024 characters. Alpine is such a system. CISA added it to its Known Exploited
Vulnerabilities catalog on 9 Nov 2026, due 12 Nov. Sources:
[Alpine's advisory](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/) (5 Nov),
[the CVE record](https://www.cve.org/CVERecord?id=CVE-2026-123158),
[OpenSSH 10.6p2's release notes](https://www.openssh.org/releasenotes.html#10.6p2),
[Alpine's secdb](https://secdb.alpinelinux.org/) for each branch's fixed build, and
[CISA's catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-123158).
This fixes no security defect in Wardlatch, so there is no advisory. `test/sshole-0.1.15.test.mjs` holds the tests.

### Added

- **`sshole-2026-11`**, Linux only, read-only. It never runs sshd (not even `sshd -T`) and never connects to a port.
  - **musl or not**: `/etc/alpine-release`, or musl's loader `/lib/ld-musl-*.so.1`. A glibc system is SAFE only when
    every sshd program found names glibc's loader; one that doesn't may be built against musl, and is UNKNOWN.
  - **The package**: `openssh-server`, and Alpine's two PAM builds `openssh-server-pam` and `openssh-server-krb5` (both
    built `--with-pam`, per aports `main/openssh/APKBUILD`), in
    `/lib/apk/db/installed`, judged against Alpine's fixed builds (edge 10.6_p2-r0, 3.24 10.3_p1-r2 … 3.16 9.0_p1-r6).
    Alpine backported the fix, so on 3.24 10.3_p1-r2 is fixed though it is below 10.6p2, and 10.3_p1-r1 is not. At or
    above 10.6_p2 a build is fixed anywhere. Below it, only the fix of the branch `/etc/alpine-release` names counts:
    revision numbers mean nothing across branches (edge built an unfixed 10.0_p1-r11 in September 2025, the very
    version of 3.22's fixed build), so a newer build pinned from another branch is UNKNOWN, and on edge, on 3.15 or
    older, or where the release can't be read, anything below 10.6_p2 is not fixed, except a version that is one of
    Alpine's fixed builds, which can't be told apart there and is UNKNOWN (so is 3.23's fixed build on 3.24). A version
    that can't be read is UNKNOWN. An sshd program apk didn't install, or a link where apk installed one, makes a
    fixed package UNKNOWN. Beside an unfixed one it is named as not read, and since it may read a configuration other than
    `/etc/ssh`'s,
    nothing in `/etc/ssh` can make the row REVIEW then; only the account reasons can.
  - **A fixed package with an older daemon**: Alpine says upgrading doesn't restart a running sshd. A running `sshd`
    (or `sshd.pam`, `sshd.krb5`) that started before its program was installed is UNKNOWN with "restart sshd". The
    install time is the file's inode change time, since apk sets each file's modification time from the package. The start
    times come from `/proc`, and are believed only when this process's own start, read the same way, comes out right.
  - **An unfixed package** is EXPOSED, unless something Alpine's advisory says the flaw needs was read as missing,
    which makes it REVIEW (still to update): `PasswordAuthentication no` with no `Match` block setting it again, a PAM
    build alone with `UsePAM yes`, no account with `*` that the flaw can use, or no `$`-hash. Any setting in
    `/etc/conf.d/sshd`, a second sshd instance, or a running sshd started with `-o` or `-f` on its command line (read
    from `/proc/<pid>/cmdline`) makes the settings "not read", as does a command line or a process list this can't read,
    or an `Include` it can't read. A REVIEW line names what wasn't read, as an EXPOSED line does.
    `/etc/shadow` is read only when this user may (usually root), and only counted: no name, field or hash is printed.
    `/etc/passwd` is read for accounts with `*` and no shadow line. Root counts only with `PermitRootLogin yes`, as
    Alpine says. Accounts from a directory service can't be seen here, so they never make it REVIEW. What couldn't be
    read is named on the line.
  - The fix is Alpine's: `apk upgrade -U -a`, then restart sshd, or turn password logins off until then (after checking
    that a key login works). Wardlatch doesn't read logs, so it can't say whether anyone got in; it gives Alpine's
    advice on where to look.
  - Not covered: sshd in containers and images.

## [0.1.14] - 2026-11-10

Apple shipped its fix for `/etc/ssl/cert.pem` on 9 November 2026, and from that day Wardlatch's words "no macOS release
has fixed it yet" and "run this again after every update" were wrong. Apple says macOS 27.2.1, 26.7.3 and 15.8.3 remove
the two withdrawn roots from the file, "along with three other eMudhra root CA certificates", and that on these releases
the built-in command-line tools stop accepting the 12 compromised certificates
([Apple, support.apple.com/en-us/149555](https://support.apple.com/en-us/149555), as published on 9 Nov 2026). This
release says so. No result changes: SAFE, EXPOSED and UNKNOWN still come from what each tool does with the test hosts,
not from a version number. This fixes no security defect, so there is no advisory. `test/apple-fix-0.1.14.test.mjs`
holds the tests.

### Changed

- **The built-in curl's and python3's fix texts follow the macOS release.** On a Mac, Wardlatch reads `ProductVersion`
  from `/System/Library/CoreServices/SystemVersion.plist` (a file read; nothing is run for it).
  - On 27.2, 26.7.2, 15.8.2 or any earlier release of those three, or when the version can't be read, an EXPOSED
    `/usr/bin/curl` or `/usr/bin/python3` is told to update macOS, and to use the Mac fix if it can't.
  - On macOS 14 or older, for which Apple names no update, it is told to update to macOS 15 or later if it can, and
    otherwise to use the Mac fix.
  - On 27.2.1, 26.7.3, 15.8.3 or later, where Apple says the roots are gone, it is told how to look at the file, that
    Apple says not to restore a backup made before the update, and how to remove the roots.
  - The python3 text no longer says "see the curl line", which wasn't there when curl read SAFE.
- **A note under the eMudhra rows on a Mac**: the macOS version, what Apple says of it, and whether `/etc/ssl/cert.pem`
  still holds `emSign Root CA - G1`, `emSign Root CA - C1` or `emSign ECC Root CA - C3`, the three other roots Apple's
  update removes. Apple did not say their keys were compromised, so they are a note and change no result. On a release
  Apple says removes them, a file that still holds them is not what Apple says the update installs, and the note says so.
  A file from which no certificate can be read says that, rather than nothing. `--json` carries the note as `macos`:
  `{ version, appleFix, source, notes }`.
- **An UNKNOWN for the built-in curl or python3 on 27.2.1, 26.7.3, 15.8.3 or later says why it may be one.** Apple says
  those releases block the 12 certificates in the built-in tools themselves, which could make the test's forced-roots
  control fail too. We haven't measured that on an updated Mac, so the row stays UNKNOWN and says so, and its reason
  no longer says the error was not a block.
- **The words "a macOS update puts Apple's original file back" are now about a Mac that can't update to those
  releases.** We measured updates to 26.7.2 (27 Oct) and 27.2 (28 Oct) doing it. We haven't measured what an update to
  27.2.1, 26.7.3 or 15.8.3 does to a file already changed by hand, and nothing here says.
- **The Mac fix download has a new digest, for its words only.** Its opening comment, the scope lines under every SAFE
  and the message for a damaged file said that no macOS release had fixed the file and that every update undoes the fix.
  They name Apple's releases now, and the Undo line says Apple's own limit on it: don't undo after updating to 27.2.1,
  26.7.3 or 15.8.3. No line of its logic changed, and no verdict or exit code. Its SHA-256 is
  `0dae0dc901a23aba216211f4ef6002a6d75b232fe479ef79db463d5c1dc9b98c`; a copy with SHA-256 `893f53cb...` needn't be replaced.
- **The Mac fix's test suite could fail on a run that was fine.** `test/fix-macos.check.sh` piped the output into
  `grep -q`, and under `pipefail` grep stopping at its first match can kill the writer, so a case read "printed no line"
  while it had printed two. Seen once in four runs under load; the old form failed 7 times in 300 on a 5,000-line output.
  It reads a here-string now.

## [0.1.13] - 2026-11-03

We found every defect under Security below ourselves, on 2 November 2026, while checking the advisories for 0.1.11 and
0.1.12. Each could read `SAFE` where something was wrong. If 0.1.12 or earlier said `SAFE`, run this version. The advisory is
GHSA-2q92-ggx3-wq82. `test/seat11.test.mjs` holds the tests; L1 runs on Linux only.

### Security

- **A project file one level past the header walk was not read.** A folder past a walk's limit that holds only files
  makes no row, so a `.mcp.json` in a project with no `.git`, five levels below a folder searched, read `SAFE`. The
  walk reads the project files one level past its limit now.

- **The quick look stopped at a link.** `~/app/proj` as a link to a project with a stealer in its `.venv` read `SAFE`,
  reachable or locked. The quick look now goes through a link that leads to a folder, as deep as it goes into a folder.
  A locked target is UNKNOWN. On a Mac, EPERM there is named under the result as `~/.Trash` is, because `~/OneDrive` as a
  link to a folder macOS protects would otherwise end every run in exit 2. A link past a locked folder can't be told
  from a link to a file, and the quick look still reports only one named like a venv.

- **A venv whose own name isn't valid UTF-8 had no row at the quick look's last level,** on Linux. It is UNKNOWN now.

### Changed

- **The Mac fix download has a new digest, for its words only.** Its comments and three of its messages said that a site
  loading "through this file" showed what the file trusts. The Mac's curl also falls back to Apple's trust (seat 16,
  measured 2 Nov 2026), so they say what was measured now, and the message for a test site still trusted after the fix
  names that third cause. No line of its logic changed, and no verdict or exit code. A copy with SHA-256 `c8bba160...` needn't be
  replaced.

## [0.1.12] - 2026-11-02

We found every defect under Security below ourselves, on 2 November 2026, in a second read of 0.1.11 made after it
shipped, three reviews of this release's drafts, and a differential against 0.1.11 over about 250,000 generated cases. Each could read `SAFE` where something was wrong. If 0.1.11 or
earlier said `SAFE`, run this version. The Mac fix download doesn't change. The advisories, published on 2 Nov 2026: GHSA-qg36-5mwx-mvpf for these
defects, and GHSA-c2fw-7h9h-g6qr and GHSA-j6fm-jfg3-q89q for those in 0.1.11. `test/seat6.test.mjs` to `test/seat10.test.mjs` hold the tests. Two of seat 6's, I4-H2 and R11, pass on 0.1.11: they pin fixes already made. There is no test for the Linux
link name.

### Security

- **Apple's own Python folders were never searched.** `/Library/Python/3.x/site-packages`, where `sudo pip3` installs, and
  the site folders of the Command Line Tools and Xcode are the ones `/usr/bin/python3` names, and none was on the list.
  A stealer in one read `SAFE`, exit 0.

- **A link to a folder the run couldn't reach was dropped with no row.** All four walks asked whether a link led to a
  folder, and a locked target is neither a folder nor gone. A venv, repository or WordPress site behind one read `SAFE`,
  exit 0, while the same link reachable read UNKNOWN. On Linux a link with a name that isn't valid UTF-8 fell in the same
  hole. Below the folders searched it is UNKNOWN now, and so is a link to a file behind a locked folder, which the run
  can't tell from one. In the quick look round the home folder only a link named like a venv is reported.

- **The quick look missed a venv it could not enter.** `~/app/.venv` as a link to a locked target, or a folder of mode
  0644, read `SAFE`. It is UNKNOWN now, and so is any folder of that mode there, whatever its name.

- **0.1.11 put a name back in charge of a verdict.** Its quick look left out `.Trash`, `Photo Booth Library` and
  `*.photoslibrary` by name at any depth, so a locked `~/Documents/clients.photoslibrary` holding a stealer read `SAFE` and
  the same folder called `work` read UNKNOWN. Now only `~/.Trash`, and `Photo Booth Library` and any `*.photoslibrary` in
  `~/Pictures`, are left out, and only on EPERM, which macOS gives there and a sandbox or security tool can give too.
  When they are refused they are not searched, and the line under the result names them, says how many items at their
  top level went unsearched, and says how to search them: Full Disk Access, or emptying the Trash. macOS answers for a folder's own metadata
  while refusing its contents, so a refused folder holding nothing is proven empty and isn't mentioned. That works on APFS;
  on another disk the count is left out.

- **The temp-folder fix in 0.1.11 stopped short.** With `/private/var/folders`, or the level below it, refused, the run
  read `SAFE`, exit 0, with `T` gone from what it looked at. Those levels are UNKNOWN now, as is the per-user folder through
  `T`'s row, except `zz`, which holds only system users. Inside a sandbox that refuses them this can read UNKNOWN where nothing is wrong: it is a place not looked at.

- **A `sitecustomize.py` changed by one byte read `SAFE`.** The published file was `EXPOSED` and anything else had no row,
  by an option that silenced the line. It is a REVIEW line now, and the option is gone. A file of that name inside a
  site-packages turns that check's SAFE into REVIEW, exit 0. Homebrew's own is one folder up and isn't read. A
  `sitecustomize/` package, or either compiled with no source, which Python runs the same way, is a REVIEW line too. The
  owner's decision, 2 Nov 2026.

- **WordPress leftovers read `SAFE`.** `<site>/content/plugins` beside a stock site is checked now, as `backup/plugins` was,
  and so is a folder under any parent that holds a listed plugin (`wp-content/upgrade`, `backup/old`). A folder holding a
  listed plugin's main file is that plugin, whatever it is called (`rank-math-pro`, a pasted version number, a change of
  case), in the live plugins folder too, where it had only an "added" REVIEW line. A folder with the plugin's name in it,
  set off by anything but a letter or digit (`plugin copy`, `plugin 2`, `old-plugin`), and without the main file, has its
  indicator searched and is a REVIEW line. So is a folder of the exact name in a parent with no `plugins` in its name; it
  was not looked at before. A link at a copy's name counts. `--paths` naming a copy, a link to the plugin, or a folder holding
  its main file, is checked as the exact name is.

- **Private keys in forms LibreSSL loads read `SAFE`.** Lengths that aren't minimal, however long; a constructed OCTET STRING;
  high-tag forms (`3f 10`, `3f 80 10`, `1f 02`), for the outer element and the ones inside; a version other than a single
  byte 0 or 1, however written; a short key with no NUL byte. These go through one reader now, which normalises the tag and
  the length, and they are found, or UNKNOWN where they can't be read. A file that merely begins `0.`, such as a `VERSION` of
  `0.1.0`, read UNKNOWN, exit 2, and no longer does.

- **Header forms read `SAFE`.** In TOML, `--header` or `http_headers` in an inline table, a dotted key split by a quote, a
  quoted key holding `=`, a `]` or a quoted word in a comment, multi-line strings and escapes: a small tokenizer now reads
  the file beside the line reader, and a row from either counts, so a file a strict parser gives up on loses nothing. Text
  inside a multi-line string can therefore be a REVIEW line. A file with a multi-line string never closed and no header the
  line reader can see is UNKNOWN, as broken JSON is. In git config, a
  value continued by a backslash on a file's last line with no line end, quotes inside a value (`ada"@"example.org`), and a
  CR or U+2028 inside one. A FIFO at `.mcp.json` in a project with no `.git`. A project file in a repository's subfolder is
  still not read, in this release or earlier.

### Fixed

- A PKCS #1 public key in DER read UNKNOWN, exit 2, for an ordinary public key. It stays quiet now, on its whole shape: two
  INTEGERs, a modulus and a small exponent.
- A `--paths` folder that is a plugin's now checks its parent once, however many were named. The sitecustomize advice no
  longer lands on a Docker image's row, where it told a healthy machine to rotate every secret. Both were in drafts only.
- `test/round6.test.mjs` failed in place of skipping inside a sandbox.
- `test/fix-macos.check.sh` said it is safe on your own Mac, and on a Mac with a network it contacts the advisory's test
  host. Its header says so now, and how to keep it offline.
- SECURITY.md said this repository is ahead of the download. It stopped being true on 2 Nov 2026.

## [0.1.11] - 2026-11-02

We found every defect under Security below ourselves, in reviews of our own work from 29 October to 2 November 2026,
and each entry ends with the day it was found and the day it was fixed (dates in US Pacific time, as the commits record
them). The fixes to the command ship in this package. The Mac fix download changes only when the site serves the new
script and its digest together (SECURITY.md, step 4), so a copy downloaded before then has none of its fixes. The
advisories, published on 2 Nov 2026, are GHSA-c2fw-7h9h-g6qr for the command and GHSA-j6fm-jfg3-q89q for the Mac fix.

### Security

- **Folders Wardlatch could not open were passed over in four more places, and each read `SAFE`.** All four are in 0.1.10
  too. A folder name that isn't valid UTF-8 read as not there, on Linux, and everything under it was skipped, in every
  walker. A folder the quick look round the home folder could not open was skipped with no row, so a stealer in
  `~/Documents` read `SAFE`, exit 0, on a terminal without access to it; it is UNKNOWN now, except `.Trash` and the two
  Photos libraries, which macOS keeps to itself on every Mac. A settings file the system refused with EPERM was counted
  as not used, when the person's own tools may read it; it is UNKNOWN now. This user's own per-user temp folder that
  could not be listed was dropped; it is UNKNOWN now. And a `PATH` folder that can be entered but not listed hid
  `php8.1`; for a rule with several names it is UNKNOWN now. `test/round6.test.mjs`. *Found and fixed 2 Nov 2026.*

- **Fourteen more places a real finding read `SAFE`, found and fixed 2 Nov 2026.** The git config parser now reads a section
  and key on one line, a value continued with a backslash, and a `;` inside quotes. A TOML `args` array is read as a JSON
  one is. A compromised WordPress copy beside a core, under a folder like `plugins.bak`, in a folder named for its
  version, or at `Version: 3.0.123.0` is matched; a single-file plugin added in the window is a REVIEW line. A dangling
  image with a known-bad digest is `EXPOSED`, and an engine whose list can't be read is UNKNOWN. A LiteLLM tag the rule's
  text names, with an unlisted digest, is a REVIEW line. A bare repository, a `pip --target` folder, and `.mcp.json` in a
  project with no `.git` are read. A failing program's warning is no longer taken for its version, a venv with only
  `bin/python3` is probed, and a FIFO in place of a certifi bundle is UNKNOWN. `test/seat5.test.mjs`.

- **A failed control could hide the only EXPOSED the Mac fix can print (never released).** Round 5 took the date off
  curl's 0 and left the 0 inside the control's `if`, so when the ordinary website failed for any reason (a DNS block, a
  firewall, a timeout, an inspecting proxy) the test site was not read, and a Mac whose curl verified the advisory's
  chain read `SAFE`, exit 0. 0.1.10 reads the test site first and never had this. The test site is now read before the
  control on both paths, the 0 is `EXPOSED` whatever the control says, and the control gates the 60 alone, as the
  script's comments already claimed. `test/fix-macos.check.sh` gains the case, with the 60 as its control. *Found and
  fixed 2 Nov 2026 by the four-seat panel.*

- **A committed private key written with non-minimal DER lengths was skipped with no row.** `derKind()` reads the common
  encodings and LibreSSL reads more; a key rewritten with a five-byte length, or a two-byte version number, was neither
  found nor counted as unread, so the repository read `SAFE`, exit 0. A file that begins as a DER element and is not
  read as one is now UNKNOWN, on the working tree and on git's copy of a deleted file, whatever it is called.
  `test/round6.test.mjs`. *Found and fixed 2 Nov 2026 by the four-seat panel.*

- **The containers' date gate failed open.** A missing or unreadable `canaryNotAfter` meant "not expired", so containers
  were probed past the real expiry and every refusal read `SAFE`. Latent: today's value parses. It now closes, and
  `test/round6.test.mjs` pins it. *Found and fixed 2 Nov 2026 by the four-seat panel.*

- **A `--paths` folder that isn't there said nothing on the checks that don't search it, and exited 0.** The README
  promised an UNKNOWN line. It is one now, on every check. A folder that is there and plays no part is named under the
  all-clear as not searched, and in `pathsNotSearched` with `--json`, never in the receipt (AUDIT-11). *Found 29 Oct
  2026, fixed 2 Nov 2026.*

- **A NUL byte hid a withdrawn root from the Mac fix, and not from the tools the fix is about.** macOS's
  `/bin/bash` 3.2 `read` cuts a line at its first NUL byte and drops the rest of it, and so does `awk`
  (measured: `printf 'ab\0cd\n'` comes back from `read` as `ab`, length 2). LibreSSL does not: it reads the file
  with `BIO_gets` in 253-byte pieces and cuts *each piece* at its first NUL, so on a line longer than 253 bytes it
  reads every piece after the first. So one certificate block could carry base64 that `curl`, `git`, `ruby`, `perl`
  and `openssl` decode as `AAA Certificate Services` or `emSign ECC Root CA - G3` while the fix, reading the same
  block line by line, saw an innocent throwaway certificate — and said `SAFE`, exit 0, "no longer holds the two
  roots. Nothing changed", with the root still verifying through that file before and after. No earlier check caught
  it: the `-----BEGIN` marker still only ever started a line, so the round-3 gate matched nothing; the counts agreed;
  and every certificate the fix did read had a fingerprint and a key, so the completeness gate passed too. A
  line-length check cannot stand in for it, because `awk` measures the line it already cut: on such a file
  `awk 'length($0)>252'` reports no line at all. `roots()` now counts the NUL bytes on *bytes*, with `tr`, before it
  reads a line, and any at all makes the run UNKNOWN, exit 2, with nothing changed and a line saying why. Every path
  that reads the file for withdrawn roots goes through `roots()` — the snapshot, the backup, the re-reads from the
  file itself, the cleaned file and `built()` — so one test covers them all. The same refusal makes true a sentence
  that was not: `strip()` rewrote the file with `awk`, so every line holding a NUL byte came out cut short, while
  the header said it "removes only each withdrawn root's own lines … and nothing else in the file" (measured: Apple's
  file plus `# admin note: keep\0 this whole line` was rewritten with that line cut, under a SAFE that named only the
  roots). Apple's own file holds no NUL byte and no line over 231 bytes, so this costs it nothing.
  `test/fix-macos.check.sh` gains three cases: a block built so that LibreSSL reads the withdrawn root and a line
  reader does not, for each root, each shown first to be read that way by LibreSSL and to verify the root through the
  file (otherwise the case would measure nothing); a NUL byte outside any block, in a file that still holds both
  roots, so it is about a run that *did* rewrite the file; and the control that a file with no NUL byte is still
  fixed, without which a change that refused everything would pass. *Found 31 Oct 2026, fixed 1 Nov 2026 (73038cb).*

- **A compromised eMudhra intermediate, or `emSign Root TLS CA - G3`, left in the bundle read SAFE.** The incident is
  a compromise of eight CA keys, six of them TLS, in 12 certificates. Removing the two withdrawn roots clears the
  compromised intermediates only for a reader that insists on a chain ending at a self-signed root in the file.
  `/usr/bin/curl` 8.7.1 does not: like curl since 7.68 on OpenSSL-style backends it takes *every* CA certificate in a
  `--cacert` file as a trust anchor, and Apple's `git` goes through the same libcurl, as does the built-in `perl`. So
  a `cert.pem` holding one of those intermediates kept trusting everything it had issued after both roots were gone,
  and the fix — which looked only for the two roots — said `SAFE`, exit 0, nothing changed. `emSign Root TLS CA - G3`,
  which issued six of the 12, is worse again: besides the cross-signed certificate the advisory's hosts serve, it
  exists as a **self-signed** certificate, which is a full trust anchor for every reader, `python3` and the `openssl`
  CLI included, with no partial chain needed. Measured on the branch as it stood: all 14 of those certificates read
  SAFE, exit 0, unchanged, each still readable out of the file by LibreSSL afterwards; and the advisory's `ov-g3c`
  leaf verified through the cleaned bundle plus its intermediate under `openssl verify -partial_chain`, and failed
  through the cleaned bundle alone. The fix now carries seven more keys and removes any certificate holding one, by
  key, in the same way and with the same machinery as the roots' keys: the six compromised TLS intermediate keys
  (which cover all 12 certificates, because each intermediate was issued twice, under `emSign Root TLS CA - G3` and
  under `AAA Certificate Services`) and `emSign Root TLS CA - G3`'s own key, which covers both of its certificates at
  once. A bundle too small to rebuild that holds one of them is UNKNOWN with the key named, not "nothing to remove".
  `lib/incidents/emudhra-2026-10.json` carries the seven as `withdrawnKeys`, apart from `distrustedRoots`, which
  drives the probes' forced-roots control and has one PEM file and one canary group per entry. Each key value was
  derived from its certificates three times — LibreSSL 3.3.6, OpenSSL 4.0.3 and node's own `crypto` — and refused if
  it came out as the SHA-256 of no input (`e3b0c442…`). `test/fix-macos.check.sh` gains one case per certificate, 14
  of them, each with LibreSSL as the oracle that the key was in the file before the run and gone after it, counted by
  the SHA-256 of the SubjectPublicKeyInfo rather than by a name; plus the control that a bundle holding none of them
  is left alone, and the small-bundle case. `test/incidents.test.mjs` gains the data's own checks, including that
  none of the seven is in the macOS bundle Apple ships — with the two withdrawn roots as that scan's positive
  control, since a scan that read nothing would report every key absent. The owner's decision #38, 31 Oct 2026, was
  to add `emSign Root TLS CA - G3`: "Yes, add it." *Found 31 Oct 2026, fixed 1 Nov 2026 (4f05d5f the data; 73038cb the
  fix; 1d98436 the refusal's first line).*

- **The Mac fix's online checks could be made to measure Apple's block instead of the file.** `/usr/bin/curl` 8.7.1 is
  built with LibreSSL *and* SecureTransport, and `CURL_SSL_BACKEND` picks one at run time. The fix's `-q` keeps
  `~/.curlrc` out; nothing kept the environment out, and the probes run as the person who typed the command, with
  their environment. Under SecureTransport the `--cacert` anchors are judged by Apple's Security framework, which
  blocks the eMudhra certificates (19 and 23 October 2026) whatever file it is given, so the answer stops being about
  `/etc/ssl/cert.pem` at all: measured, a copy of the cleaned file plus `emSign Root TLS CA - G3` read EXPOSED by
  default and SAFE with `CURL_SSL_BACKEND=secure-transport`, while the default `curl` through that same file still
  loaded the test site. An unknown backend name selects SecureTransport too, so the library has to be named rather
  than the variable merely cleared. Both probes now say `CURL_SSL_BACKEND=openssl`, which measured on this Mac
  selects LibreSSL; the proxy variables are deliberately left alone, since they decide how the network is reached and
  not which library judges the chain. `test/fix-macos.check.sh` gains a case that runs with the variable set to
  `secure-transport`, to nothing, and to a name curl does not know, and reads back from the curl stand-in what each
  probe was actually given. *Found 31 Oct 2026, fixed 1 Nov 2026 (73038cb).*

- **From 3 May 2027 the Mac fix would have called every unfixed Mac safe.** `curl`'s exit 60 is
  `CURLE_PEER_FAILED_VERIFICATION`, which covers an expired certificate as well as one signed by a key the file does
  not trust — measured on a throwaway pair, an expired leaf gives 60 through a file that trusts its root and through
  one that does not alike, which are the two readings this test exists to tell apart. The advisory's test leaves
  expire 3 May 2027 01:04:36 UTC, so from that day "refuses the compromised keys" would have been printed for a file
  that still held both roots, and the EXPOSED branches could never have fired again.

  **The first fix for this was itself a false SAFE, and this entry is the second.** It read the clock and, on or
  after that date — or whenever this Mac's date could not be read at all, which counts as past it — stopped reading
  the test site entirely. But exit 60 is not the only reading the test site gives. Exit **0** means the chain
  *verified*, which an expired leaf cannot do: measured again on 1 Nov 2026 on a throwaway CA on loopback, one fresh
  server per reading, a valid leaf gives 0 through a bundle that trusts its CA and 60 through one that does not,
  while an expired leaf gives 60 through **both**. So expiry poisons the 60 and leaves the 0 exactly as sound as it
  ever was. The date gate discarded both, so a Mac that *was* exposed read `SAFE`, exit 0 — from 3 May 2027, and
  from the day it shipped on any Mac whose clock is dead or years fast. The harness's own canary case asserted that
  SAFE as correct, which is why the suite was green over it. Found by the 1 Nov 2026 four-seat panel and two
  independent re-reads.

  What is in place now. On the path that fixes the file the date is **gone**, replaced by a positive control that
  cannot go stale: the test site is read once through the file as it *was* — which still held a withdrawn root, so
  the site's own chain had to be accepted — and once through the cleaned file. A 0 through the old file establishes
  in one reading that the host answered, that its leaf is still valid, that nothing is answering for it, and that
  the probe can still tell a trusting file from a refusing one; only then is a 60 through the new file read as a
  refusal. The 0 through the new file is `EXPOSED`, exit 1, on every date and gated by nothing at all. This is the
  mechanism `lib/probe.mjs` already used against this very class, and `canaryNotAfter` remains a date only where a
  control is impossible — for containers, which "ha[ve] no forced-roots control" (`bin/wardlatch.mjs`), and for this
  fix's **already-clean** path, where the file holds neither withdrawn root, so nothing in the run's hands is
  something the test site ought to accept and there is no control to be had. There the date stays, over the 60
  alone; the 0 is `EXPOSED` there too, on every date. Net: past 3 May 2027 a live canary makes the 60 readable
  again, which the gate lost outright, and a dead canary stops a 60 being read as a refusal *today*, which the date
  never covered.

  `test/fix-macos.check.sh` now drives the test host from a list rather than one answer, because the fix reads it
  twice on the fix path and a single answer cannot tell the two readings apart — which is exactly the blind spot
  that let this through. Its cases: a live canary before the date and at the date, a year later and with no readable
  clock; `STUB_TEST=0` at the date and with no clock, which must be EXPOSED, exit 1; a dead canary at 60, 28 and 7;
  and the already-clean path's 0 against its 60. The site's own one-line test has the same gate and the same defect
  in its own form — past the date, and whenever the date is unreadable (it reads an unreadable date as `99999999`),
  it prints `UNKNOWN` without probing the test site at all, so it discards the 0 too. It is honest about having
  nothing, because it has no file verdict to fall back on, but it should still probe and still report a 0. It is a
  site artefact under the posting freeze and **was not changed**. *Found 31 Oct 2026; first fix 1 Nov 2026 (73038cb), found
  defective and fixed again the same day (d856e68).*

- **The Mac fix undid itself on what the network said.** After writing the cleaned `/etc/ssl/cert.pem`, it re-tested
  against the advisory's test host and, if that host answered and was trusted (`curl` exit 0), copied the backup back
  over the file. The backup is Apple's original: it holds both withdrawn roots. Anything that can answer for
  `dv-g3b-emudhra.we-have-a-problem.com` on the Mac's network — a transparent proxy, a captive portal, or anyone
  holding the compromised eMudhra keys, which is anyone at all, since they were computed from published certificates —
  could therefore make the fix hand both roots back to the Mac it had just fixed, and that Mac is the one that could
  then never be fixed. The re-test now reports and never reverts: a still-trusted test host prints EXPOSED (exit 1)
  with the fix left in place and the backup named, because the cleaned file holds strictly fewer roots than the
  original and is never the worse of the two. (Until 31 Oct 2026 that line also printed the undo command, which puts
  the withdrawn roots back; it no longer does: below.) The only restore left compares the file it wrote with the file
  it built (`cmp`) and restores the backup when they differ — two local files, no probe result — and declares itself
  in the script as `# wardlatch:revert-reason=content-mismatch`. `test/fix-macos.check.sh` gains a case for each of
  those two, and until 29 Oct 2026 this entry claimed one that did not exist. *For the re-test:* a copy of the script
  whose one network command is a stub, because no real network can be made to answer this way on demand — a network
  that accepts everything must leave the fix in place, and it fails on the 0.1.10 script, which puts both roots back
  on the file. *For the restore:* a copy whose write puts something other than the file the script built into
  `/etc/ssl/cert.pem`, because nothing else can make that happen on demand — the original has to come back, byte for
  byte, with EXPOSED and exit 1 and the backup named. That case also checks that the restore the script declares is
  the only one in it and that `content-mismatch` is the only reason declared, so a revert added later without a
  declaration fails until it has a case of its own. It fails on a copy of the script with the restore line removed,
  which leaves the unchecked bytes in the file. *Found and fixed 29 Oct 2026 (0df5d72; the restore's case, 127b6c8).*
- **A verdict was read out of the test host with no control.** `curl` exit 60 was taken as "the host refused us" and
  anything else as "the host didn't answer", when on a network where nothing answers at all both readings are
  worthless; for five days the npm command had a control for every row and the Mac fix had none. It now fetches
  `$CONTROL_URL` (`https://www.apple.com/`, the host the one-line test on the page already uses) through the same
  certificate file first, and reads the test host only if that loads. If it doesn't, a cleaned file is reported as
  fixed *in the file*, with the control's `curl` code, and no online claim is made. A second stubbed case in
  `test/fix-macos.check.sh` covers it: a network where nothing answers must not be read as a refusal. On the 0.1.10
  script it prints "now refuses the compromised keys" about a test nothing performed. *Found and fixed 29 Oct 2026
  (e71d3f6).*
- **And the control was read only *after* the file had been replaced,** so the same error survived one step further
  down: "this network answers nothing" and "the change I have just made broke certificate validation on this Mac"
  arrived as the same `curl` code, and that branch printed `SAFE Fixed in the file` and exited 0 for both. The
  control is now read through the file as it is, before anything is written, and again after, which makes three
  readings. The control failing both times is the network, reported with both codes and no online claim. The control
  loading both times means the test host's answer is about the test host, and is read as before. The control loading
  before the change and not after it is the one reading that is about the change: it prints UNKNOWN (exit 2) with
  both codes, keeps the fix and reverts nothing. **It deliberately does not revert**, and there is no second
  `wardlatch:revert-reason` for one. The two files differ by exactly the withdrawn roots removed, so either the
  control host's certificate really is issued under one of them, or something on the network is presenting one
  that is — and the second is a MITM producing that pair of readings on purpose, which is the reverting-on-the-
  network door this release closed, re-opened from the side. Both readings say the same thing about what to do:
  eMudhra's private keys are computable from certificates eMudhra published, so trusting that root again to make a
  page load is not a repair. (Since 31 Oct 2026 only a refused certificate, curl 60, gets this reading; a network
  that stopped answering, curl 6, 7 or 28, is read as that, with no word about an attack: below.) Three stubbed cases
  in `test/fix-macos.check.sh` cover the three readings, using a stub whose control answers differ between the two
  calls. On the script before this change, the before-but-not-after case prints `SAFE Fixed in the file` and exits 0.
  *Found and fixed 29 Oct 2026 (68f1faf).*
- **The Mac fix rewrote `/etc/ssl/cert.pem` in place, and an interrupt did not stop it.** Two defects in the same
  three lines of a script people run with `sudo`. The write was `cp "$tmp" "$FILE"`, which truncates the file and
  then rewrites it, so a Ctrl-C, a `SIGTERM`, a `sudo` timeout or a power cut during the copy left a partially
  written bundle — and the content-mismatch check below it never ran, because the same interruption ended the
  script. The Mac's built-in `curl`, `git`, `python3` and `openssl` then all read a stump of a certificate file,
  with no TLS working at all, until somebody ran the script again. The replacement is now built in a file beside
  `/etc/ssl/cert.pem` and renamed over it, so an interruption leaves either the old bundle or the new one and never
  half of either. Separately, the script's `trap` was on `EXIT` alone, and — measured under macOS's own
  `/bin/bash` 3.2.57 — that does not stop it: a `SIGINT` arriving while bash waits on a plain foreground command is
  swallowed, and bash carries on to the next line with `set -euo pipefail` in force. Interrupted just before the
  write, the old script went on to replace the file and printed `SAFE … now refuses the compromised keys`, exit 0,
  about a run that had been cancelled. (It stops if the signal lands in a command substitution, so it failed only
  some of the time.) The trap is now `EXIT HUP INT TERM`, which is what the one-line fix on the page has trapped
  since 28 Oct 2026, and it removes the file beside `/etc/ssl/cert.pem` too. (Until 31 Oct this entry said the
  one-liner "has always trapped" it. It had not: from 21 to 28 Oct the page's one-line fix, then the advisory's own
  command, wrote the file through `tee` with no trap.) A run stopped that way exits 2, the code this script already
  uses for "couldn't tell", because an interrupted run reached no verdict and because the exit-code table the Mac
  page publishes for Jamf, Kandji and Intune lists 0, 1 and 2 — a fourth code would be one no fleet policy has a
  branch for. That table's exit-2 row now also names the symbolic link, the unverified backup and the interrupted
  run, and says that some exits 2 follow a change to the file. (Until 31 Oct this entry and the table said one case
  did. There were three: a run stopped after the file was replaced, a restore that could not be made, and a control
  that loaded before the change and not after. The table now names each.) Two cases in `test/fix-macos.check.sh`
  drive copies of the script, because a power cut and an interrupt landing inside a copy cannot be arranged on
  demand: on the script before this change the first leaves a bundle under 50 certificates and the second exits 0
  with a SAFE line. *Found and fixed 29 Oct 2026 (f89b128).*
- **The Mac fix wrote through a symlinked `/etc/ssl/cert.pem`.** There was no `-L` test in it anywhere, and
  `[ -f "$FILE" ]` is true for a symbolic link to a regular file. On a Mac whose `cert.pem` is a link, the fix
  edited whatever it pointed at, put its dated backup beside the link rather than beside the file, and printed
  SAFE; with the atomic replacement above it would instead have replaced the link and left the Mac's real bundle
  untouched and still trusting the compromised keys. The one-line fix on the page refuses a symbolic link, and the
  site's Record names that refusal as a safety property of ours (CL-42) — the download people run with `sudo` did
  not have it. It now refuses one, names the file to run against instead, changes nothing and exits 2. (Since 31 Oct
  2026 it also gives the true reason and prints the command that fixes that file: below.) *Found and fixed 29 Oct
  2026 (1026b1b).*
- **The Mac fix never checked the backup it told you to restore from.** `cp -p "$FILE" "$backup"` was not verified.
  The script then replaced the file and printed an `Undo:` command naming that backup, and the content-mismatch
  restore uses the same file as the only checked file in the run — so a short or failed backup write made both the
  instruction and the restore wrong, silently. CL-43 was already a correction about that instruction. The backup is
  now compared (`cmp`) with the file it came from before anything is replaced: UNKNOWN, exit 2, nothing changed.
  (Until 31 Oct 2026 the bad copy stayed under the dated backup's name, named in the line with "don't restore from
  it"; since then it is compared with the file the run checked, and a copy that fails or differs is removed, so the
  dated name only ever holds a complete, checked copy: below.) *Found and fixed 29 Oct 2026 (acf4489).*
- **Not every write to `/etc/ssl/cert.pem` was the one-step one, and none of them was checked.** Two defects an
  independent review found in the lines the atomic-write correction above had just rewritten. The
  content-mismatch restore still copied the backup over the file **in place** — the very defect the forward write
  had been redesigned to remove, left live on the one path that runs when something has already gone wrong;
  interrupted mid-restore it left whatever part of the file it had copied by then, and exited 2 printing nothing at
  all. (Until 31 Oct 2026 this entry said "a 500-byte stump of 0 certificates": 500 bytes is where the harness's case
  cuts the file to stand for an interrupt, not something the old script was measured to leave.) And none
  of the writes — the backup, the copy, the chmod, the rename, the restore — was checked, so `set -e` ended the run
  with the failing command's own status, which is **1**, the code the published exit-code table reads as EXPOSED,
  with nothing printed: a full disk, a read-only volume, an expired `sudo` timestamp, a user who is not a sudoer or
  SIP each reported "this Mac still trusts the compromised keys" and gave no line to read. On the restore path the
  failure skipped the EXPOSED block entirely, so the file kept bytes nobody had checked and the backup was never
  named. There is now one function, `replace()`, that writes to the file and is the only thing in the script that
  does: a copy into a file beside it, then a rename over it, every step checked, the file removed and
  `/etc/ssl/cert.pem` untouched if any step fails. The forward write and the restore both go through it, and a
  restore that cannot be made is UNKNOWN (exit 2). The temporary file's name was fixed and recorded before it was
  made, so a signal in that gap no longer stranded one beside the bundle for ever. (Since 31 Oct 2026: a restore that
  cannot be made names the backup and what it holds, and no command to put it back; and the file beside the bundle
  is made by `mktemp`, with a file made before its name reached the script removed by `strays()`: below.) Four
  cases cover it, all rewriting `replace()` by name so they survive the lines around it moving, and each one goes
  red on the shape it replaces. *Found 29 Oct, fixed 30 Oct 2026 (c6e5dd1).*
- **A run stopped after the file had been replaced said nothing about it.** Exit 2 means "couldn't tell, read the
  printed line", and an interrupt landing in either probe — up to 15 seconds each, which is exactly when somebody
  decides the script has hung — exited 2 with no line at all, after the file had already been changed. The signal
  handler now says the file was replaced, what was removed, and names the backup and the undo command. (It went by
  a flag set after the rename, and on 31 Oct 2026 that turned out to leave a window with no line, and a wrong line
  during a restore: below.) *Found 29 Oct, fixed 30 Oct 2026 (c6e5dd1).*
- **A failing cleanup could turn UNKNOWN into EXPOSED.** Measured on macOS's own `/bin/bash` 3.2.57: with `set -e`
  in force, a command that fails inside the `EXIT` trap ends the trap *and* overrides the script's exit status. One
  failed `rm` in the cleanup therefore turned `exit 2` into `exit 1` — the code a Jamf, Kandji or Intune policy
  reads as "this Mac still trusts the compromised keys". `return 0` at the end of the function does not help,
  because errexit ends the function before reaching it; every command in the cleanup now ends in `|| true`, which
  is load-bearing and not tidiness. A case asserts a refused run still exits 2 with a deliberately failing
  cleanup, and goes red without the `|| true`. *Found 29 Oct, fixed 30 Oct 2026 (c6e5dd1).*
- **The Mac fix deleted whatever followed a removed root, printed SAFE and exited 0.** `strip()` set its skip when a
  dropped certificate's block began and cleared it only at the next `###` or `=== ` line, so everything after a
  removed root went with it as far as the next header: a trailing comment, an administrator's note, a line naming
  what follows. None of that is a certificate, so the count of certificates in the rebuilt file still came out at
  exactly `before - found`, the check comparing the counts passed, and the run printed SAFE, exit 0, with those lines
  gone and nothing said about them — damage to `/etc/ssl/cert.pem`, which SECURITY.md puts in scope ("intact or
  correctly cleaned"), under a SAFE line, in the file every built-in TLS client on the Mac reads. (Until 31 Oct 2026
  this entry called it "the false SAFE SECURITY.md puts first". It is the scope's fourth item, damage to the file;
  the roots the SAFE line reported removed had been removed.) Apple's shipped file has a `=== ` line above every
  certificate, so it was never live there; it was live on any hand-concatenated bundle, which is the ordinary case,
  because an administrator appends a corporate
  TLS-inspection root to `/etc/ssl/cert.pem` precisely because `curl` ignores the keychain. A certificate's block
  ends at its `-----END CERTIFICATE-----` line, so that is where the skip is cleared now. It cannot leave part of a
  dropped certificate behind, which would be worse: a block's start line is its own BEGIN line, or the `=== ` line
  above it with no END line in between, so the first END line at or after the start is that certificate's own. The
  one thing after it that may still go is the single empty separator Apple writes between blocks, and only empty
  lines are taken there, which is why the output on Apple's own file is still byte for byte the advisory's removal.
  It also no longer under-skips: a stray `###` line between a dropped root's name line and its BEGIN line cleared
  the old skip mid-block and left that root in the output, which the count check then refused rather than removing
  it (measured on a built bundle before the change). The case in `test/fix-macos.check.sh` is a bundle of all 128
  certificates with a note line after every one of them: all 128 notes must still be there afterwards. Against the
  script as it stood it loses exactly the two that followed the withdrawn roots and still exits 0 with SAFE printed,
  which is the whole defect, so the case asserts that too and cannot pass for the wrong reason. (On 31 Oct 2026 this
  turned out not to be the whole of it: a `=== ` line an administrator wrote above a root they had appended, every
  line between it and the root, and every empty line after a root, not just one, still went with it: below.)
  *Found and fixed 30 Oct 2026 (d33f7d5).*
- **The second 50-certificate floor could only ever refuse a correct answer, and left those Macs with no way to be
  fixed.** The check on the rebuilt file was one condition — a withdrawn root still in it, a count that does not
  match, or fewer than 50 certificates — behind one line that reported all three as arithmetic: "The cleaned file
  didn't come out as expected (N certificates before, M after)". Two of those three are not count problems, and the
  count printed beside them was right. The floor was the worse one: the check at the top of the script already
  refuses a bundle of fewer than 50 certificates before anything is read out of it, so a run reaching the rebuild
  started at 50 or more and removed 1 or 2 roots, and 50−1, 50−2 and 51−2 are the only results under 50 — every one
  of them exactly `before - found`, which the count check had already proved right. So it could fire only on an
  arithmetically correct rebuild. On a 51-certificate bundle holding both roots it refused 49, the right answer, said
  the arithmetic had failed when it had not, never mentioned a floor, and left that Mac unfixable. It could not have
  caught a mangled rebuild either: one that lost or kept a certificate is caught by the count check, and one that
  changed no count would not be caught by a floor. The floor is gone; the count check and the fingerprint re-read of
  the rebuilt file are the whole of what is checked there, now as three separate reasons, each naming the one thing
  it found and nothing it did not. Three cases, where nothing had reached the branch at all: a 50-certificate bundle
  built from the fixture (which the floor refuses, as arithmetic, with the floor put back); the three reasons, each
  on a copy of the script whose rebuild is changed in the one way that reaches one of them; and
  `test/support/mojave-shapes.sh` shape E, which now matches a floor's own words rather than "UNKNOWN", which almost
  any refusal would have satisfied. *Found and fixed 30 Oct 2026 (4abd710).*
- **A correctly fixed Mac was told to put the withdrawn roots back.** With the floor above gone, a small bundle is
  fixed properly on the first run — 51 certificates holding both roots become 49 — and the second run then hit the
  *entry* floor, fewer than 50 certificates, which said the file "looks damaged" and gave one instruction:
  `Put a backup back (ls $FILE*.bak; sudo cp -p <backup> $FILE)`. That backup is the only one this script ever
  writes: a copy of the file as it was, taken immediately before the removal, holding both withdrawn roots. So the
  one piece of advice a correctly fixed Mac was given was to restore the compromised file, in a script people run as
  root, with nothing said about what that would restore — the same defect as the network-triggered revert removed
  above, reached by another route. It also called a file damaged on no evidence: a 49-certificate bundle may simply
  be short, and this fix has nothing to remove from one that holds neither root. The floor now reads the file before
  it says anything about it. Under the floor and holding **neither** root, with every certificate readable, it
  reports UNKNOWN (exit 2), changes nothing, and gives the facts only: the count it found, that the file holds
  neither withdrawn root so this fix has nothing to remove, and that something else may be wrong with it. It does
  not say the file looks damaged, does not name a backup, and claims nothing about whether the Mac is safe. Under the
  floor and **still holding** a root, it keeps the refusal it had, minus the advice: it says a root is still in the
  file and that an older copy of the file holds the withdrawn roots too, and names the one route that does work (a
  macOS update restores Apple's own `cert.pem`, after which this can be run again). Under the floor with a
  certificate that **cannot be read**, the existing "a certificate in this file couldn't be read" refusal applies,
  which never advised a backup. The BEGIN-TRUSTED-CERTIFICATE check and the fingerprint pass now run before the
  floor, because the floor has to be able to say whether a withdrawn root is in the file and a block this fix cannot
  read could hold one. Three cases in `test/fix-macos.check.sh`, all failing against a copy of the script with the
  floor put back where it stood: a small bundle run twice (the first run's backup is asserted to hold the roots,
  because that is why the old advice was a defect); a small bundle still holding a root; and the existing truncated-
  file case, which asserted only exit 2, the file unchanged and no backup written — all three of which the old
  wording satisfied while telling the reader a file holding neither root looked damaged and sending them to a backup
  holding both. It now also asserts the count is named, that the file holds neither root, and that the output does
  not say "looks damaged", does not name a backup, and does not print SAFE. That took the harness from 27 cases to
  29; it ran 60 at 33641f9 (31 Oct 2026), 76 after the third read of that day, and runs 94 after the fourth (below). *Found and fixed 30
  Oct 2026 (13ec3bc).*

The rest of this section was found by an independent read of this release as it stood on 30 Oct (176b94e): five
readers with different lenses, then a refuter for each, who reproduced every finding in a scratch copy before it
counted. Each fix below has a test that fails on 176b94e and passes after it.

- **A folder the system refused with EPERM read SAFE, exit 0. Owner decision #32 makes it could-not-be-tested,
  exit 2, whoever owns it.** Commit 4209d15 (29 Oct, in no release) made an EPERM on a folder whose mode would let the
  run in a "stated gap": a REVIEW line beside the all-clear, outside the counts, exit 0, printed as "1 folder macOS is
  protecting was not searched … sudo cannot open it". Its basis was that EPERM is macOS's privacy protection and
  cannot be forged without root. That was false. An ordinary unprivileged sandbox gives exactly that EPERM —
  `sandbox-exec` with `(deny file-read-data (subpath …))`, the kind coding agents run tools in — and so may a Linux
  security module, fanotify or a FUSE file system, where the same macOS sentence was printed. Measured on macOS 27.2:
  a virtual environment holding the LiteLLM 1.107.0 stealer's install record and `cook.pth`, inside a folder an
  unprivileged profile refuses, read SAFE, exit 0, where the same environment read EXPOSED twice, exit 1, with
  nothing refused. The owner decided on 31 Oct 2026, in his words "Yes, UNKNOWN": any folder Wardlatch could not
  open, EPERM included, is UNKNOWN with exit 2, never SAFE. The reason is the rule the tool exists to keep: a folder
  nobody opened is a folder nobody tested, whoever refused it, and could-not-be-tested is never rounded up to SAFE.
  The row now says the system refused it, with the errno, the mode and the owner (`code` and `basis` in `--json`),
  and whether the folder's own permission bits would have let this run in. On macOS it says that privacy protection
  is a common cause, which allowing the terminal Full Disk Access may lift, and that a sandbox the run is inside, or a
  security tool, refuses the same way and sudo may not lift it; it never claims to know which. Off macOS it names a
  sandbox, a security module or a FUSE mount. As built here, the rule covered EPERM only: a service's folders that
  refuse with EACCES kept the rule of 22 Oct 2026, one review line beside an all-clear, exit 0, until the owner's
  decision #33 made them could-not-be-tested too (below). The cost, judged: on a Mac whose searched folders include ones macOS protects, a run now
  exits 2 until the terminal has Full Disk Access or those folders are left out. Tests in
  `test/independent-read.test.mjs`: the LiteLLM case through an EPERM the test makes, the row's words, and a real
  unprivileged `sandbox-exec` run, which skips and says why when it is already inside a sandbox; the three tests that
  held the stated-gap design were changed for the new rule in a commit of their own, with no code. *Found and fixed
  31 Oct 2026 (2b9a23b; the tests, 31ab90d).*
- **A folder whose full path was too long to open read as "not there", and a site in it read SAFE.**
  `lib/files.mjs` counted ENAMETOOLONG as gone. A folder past PATH_MAX (1,024 bytes on macOS) is there — the walk
  listed its name — and only can't be opened by that path: Rank Math PRO 3.0.123 in a site under four 251-byte
  folders read "SAFE no WordPress installs found in 1 folder searched", exit 0. It is now could-not-be-tested
  whoever owns it, with the path's length and no sudo or Full Disk Access advice, since neither helps. *Found and
  fixed 31 Oct 2026 (d37457d).*
- **A virtual environment, its `site-packages` or a WordPress plugins folder given with `--paths` was never examined,
  and read SAFE.** Every walker tested only the folders inside the one it was given, never that folder itself:
  `--incident litellm-2026-10 --paths <the venv>` read SAFE, exit 0, with `litellm-1.107.0.dist-info` inside it and the
  venv named in the receipt — and giving the venv to `--paths` is what the trust check's own advice for a linked venv
  says to do. `--paths <site>/wp-content/plugins` holding Rank Math PRO 3.0.123 read "SAFE no WordPress installs
  found". A folder given that is a venv, a `site-packages` or `dist-packages` folder, a plugins folder, a
  `wp-content`, or one listed plugin's own folder is now checked as one found below a searched folder is. (Not
  wholly, as the third read found: a venv given was probed instead of walked, so the venvs inside it vanished, and a
  listed plugin's own folder was checked only when its main file was in it: below.) *Found and fixed 31 Oct 2026
  (53c3029).*
- **A link counted as covered when its target had only been listed, which reopened AUDIT-8 in the default run.** A
  listing is not a walk: a target listed at a walk's depth limit has folders nobody opened, and the installs check's
  quick look round the home folder lists two levels and says nothing about what it can't open. `~/Development/x`
  linking to `~/clients`, with `litellm-1.107.0.dist-info` in `~/clients/client/app/.venv`, read SAFE, exit 0, in a
  run with no `--paths`. A link is now covered only when the same walk went through its target at least as deep as
  following the link would have, and the quick look round the home folder covers nothing. *Found and fixed 31 Oct
  2026 (40998aa).*
- **The walkers' depth limits were silent: a site, a venv or a repository one level past one read SAFE.** Each walk
  stops at a depth — 5 levels for WordPress, virtual environments and the trust check, 4 for repositories (the
  workflow, key and header checks) — and said nothing: Rank Math PRO 3.0.123 six levels down read "SAFE no WordPress
  installs found in 1 folder searched", exit 0. Each folder a limit stopped at that holds more to walk (a folder, a
  link or a `.git`) now goes into one UNKNOWN row per check, "N folders are deeper than this check walks (5 levels
  below the folders searched) … Pass --paths with a folder nearer to them", with the folders in `--json` as `paths`;
  there is no all-clear beside it, and the exit code is 2. Judged: on a developer's machine the WordPress and trust
  checks will exit 2 more often, since a project folder often runs deeper than 5 levels outside any repository; that
  is the true answer while the limits stand. *Found and fixed 31 Oct 2026 (98178ba).*
- **Folder names hid whole trees with no word, while the documents said no name decides a walk.** The walkers skip
  folders by name — WordPress: `node_modules`, `.git` and `.venv`; repositories: `node_modules`, `.venv` and `venv`;
  virtual environments and the trust check: `node_modules` and `.git` — and an all-clear resting on such a walk never
  said so: Rank Math PRO 3.0.123 under `node_modules/site`, `.venv/site` or `.git/site`, and a workflow under
  `venv/repo`, each read SAFE, exit 0. (The skips predate this release; `docs/ARCHITECTURE.md`'s "no other name …
  decides a walk", and 4209d15's title, came with it.) The names are still not walked. Every all-clear that rests on
  such a walk now names them on the line under it ("folders named node_modules, .git or .venv, and macOS's own Library
  folders, are not searched") and in `--json` as `notSearched`, and the trust check says the same under its rows. The
  SAFE sentence itself is unchanged, so a script that reads it still does. *Found and fixed 31 Oct 2026 (82826e8).*
- **The trust check dropped a link to a folder that holds environments, with no row.** It reported a link it
  declined only when the link's name or contents looked like an environment; any other went nowhere: `root/work`
  linking to a volume with a certifi venv in `app/.venv` gave no row of any kind, exit 0. Every other link whose
  target the walk did not walk as deep is now an UNKNOWN row, as in the other checks. *Found and fixed 31 Oct 2026
  (48ce421).*
- **A private key committed in DER was skipped with no row, and the repository read SAFE.** The key scan skipped every
  binary file, so a key saved with `openssl rsa -outform der` under a name that isn't a text file's was passed over:
  a repository holding `deploy-key.der` read "SAFE no committed keys found in the files of 1 local repository". A file
  of one DER element (up to 1 MB) is now read by its structure, whatever its name: the shape of a PKCS #1 RSA,
  PKCS #8, encrypted PKCS #8, SEC1 EC or OpenSSL DSA private key, or of a PKCS #12 key store, is a REVIEW finding of
  that type on line 1, shown as "(binary DER, not shown)", never the key. (A store in BER, a key with one byte after
  it, and a key after a certificate were still skipped, as the third read found: below.) *Found and fixed 31 Oct 2026
  (1ea7a06).*
- **The header check let a link to a folder root owns ride beside SAFE, and told the person to use sudo for a link to
  their own folder.** It called the repository walk with no list for links, so links fell into the list of folders it
  could not open: a link to a folder root owns went into the service review line beside SAFE, exit 0, while every
  other check makes a link it did not follow UNKNOWN; and a link to a readable folder of the person's own was
  "could not be opened … run Wardlatch with sudo …, or allow your terminal Full Disk Access", which is false twice.
  Both are now link rows, "is a link to a folder somewhere else, so it was not followed". *Found and fixed 31 Oct
  2026 (d083524).*
- **The Mac fix could print SAFE, exit 0, with both withdrawn roots still in the file.** `roots()` compared each
  fingerprint with `grep -qxF "$fp" <<<"$ROOTS"`, and macOS's `/bin/bash` 3.2 writes every here-string to a file in
  `/private/var/tmp`, whatever `TMPDIR` says. Where that write fails — a sandbox, an endpoint agent's policy, a full
  disk — `grep` fails, and a failure read as "no match": every certificate was "not a withdrawn root". The count of
  roots found came from another here-string, came back empty, and was taken as 0. Measured on the unchanged script
  under a profile refusing writes to `/private/var/tmp`: SAFE, exit 0, on a byte-identical file holding both roots. A
  fingerprint that came back empty or garbled counted as "not a withdrawn root" too. `roots()` now reads the file
  itself and pipes each certificate to `openssl`, with no temporary file and no here-string, and fails — UNKNOWN,
  exit 2, nothing changed — if a certificate can't be read, a block has no END before the next BEGIN, or the
  number of valid fingerprints read is not the number of certificates counted. That last test is the completeness
  gate: it makes an `openssl` that fails without saying so a failure. *Found and fixed 31 Oct 2026 (93b4b4f).*
- **A change made while the Mac fix waited for the password was lost, and the run said SAFE.** The "changed while
  this ran" check compared the file with the snapshot *before* the backup step, which is where the interactive run
  waits for the password, and the backup was then compared with the file, not with the snapshot. Measured: an
  administrator's root appended during the wait was gone from the file, kept only in the backup, and the run printed
  SAFE, exit 0. The backup is now compared with the snapshot, and the file with the snapshot again immediately
  before the replacement; a change at either point stops the run, says which, and replaces nothing. (The second
  comparison was about 0.6 seconds before the rename, as the third read found, and a change in that time was lost:
  below.) *Found and fixed 31 Oct 2026 (d555aff).*
- **The Mac fix checked the cleaned file in the user's temporary folder, and root copied it into place later.** A
  process running as the same user could change that copy in between — append a withdrawn root, or swap a certificate
  — and the check after the rename compared the file with that same copy, so either landed under SAFE, exit 0. (The
  refuter who checked it judged it defence in depth: such a process can already reach the script's `PATH`.) The cleaned
  file's SHA-256 is now taken from the rebuild itself, and `replace()` checks the file it made beside the bundle, in
  a folder only the bundle's owner can write, before the rename: that digest, and the count and fingerprint checks
  again. (The snapshot all of those checks were made on was still taken on trust, as the third read found: below.)
  *Found and fixed 31 Oct 2026 (2add6b3).*
- **A symbolic link planted at the new file's name made the bundle itself a link.** `replace()` built the new file at
  a fixed name, `.wardlatch-new.<pid>`, guarded by `[ ! -e ]`, which is true for a link to nothing: `cp` wrote
  through the link, `mv` put the link where the bundle was, and the run said SAFE, exit 0. It needs write access to
  `/etc/ssl` and a guessed process ID. `mktemp` now makes the file, refusing anything at the name, and `strays()`
  removes a file of this run's made before its name reached the script. *Found and fixed 31 Oct 2026 (86db56b).*
- **The Mac fix removed lines that were not a withdrawn root's own.** `strip()` started a removed root's block at the
  nearest `=== ` line above it, whatever that line was, so an administrator's own `=== ` line above a root they had
  appended, and every line between it and the certificate, went with the root, under SAFE, exit 0; after the END
  line it took every empty line, not the one separator. It now removes exactly each root's own BEGIN-to-END block,
  its name lines only when they sit directly above the block and are that root's (Apple's shape, ending in that
  root's own `SHA256 Fingerprint=` line, or mk-ca-bundle's), and the one empty line after it, and keeps every other
  line. On Apple's own file the result is still byte for byte the advisory's removal. (An indented line inside a
  root's Apple entry still went with it, as the third read found: below.) *Found and fixed 31 Oct 2026 (6e07aaa).*
- **A backup copy that failed part-way left a truncated file under the backup's dated name.** Measured: a
  245,760-byte stump of the 333,483-byte file, cut mid-certificate, beside "Couldn't write the backup"; and a backup
  that failed the comparison stayed under the dated name too. The copy is now made under a temporary name beside
  the bundle, compared with the snapshot, and only then linked to its dated name, which `link` refuses if anything
  already has it; if any step fails the copy is removed and the line says no backup was kept. *Found and fixed 31 Oct
  2026 (40592de).*
- **A failed `mktemp` ended the Mac fix with exit 1 — EXPOSED, in the published table — and no line.** The two
  `mktemp` calls ran unchecked under `set -e`, before any trap, so a full or unwritable temporary folder ended the
  run with `mktemp`'s own status. Each is now checked: UNKNOWN, "Couldn't make a temporary file … Nothing changed",
  exit 2. *Found and fixed 31 Oct 2026 (0fea0d4).*
- **A stopped run could print nothing, or say the file held the cleaned file when it held the original.** The signal
  handler chose its words by a flag set after `replace()` returned, so a signal between the rename and the flag left
  the file replaced, exit 2 and no line; a signal during the content-mismatch restore printed "had already been
  replaced with the cleaned file … It is whole" about a file holding the original, both roots included; and a run
  stopped before it changed anything printed nothing, though exit 2 means "read the printed line". It now always
  prints one, and reads what the file holds from its SHA-256: the cleaned file (with the backup and the undo line),
  the file the run read, or bytes the run did not build or check (with the backup named and no command to put it
  back). (Not always, as a third read the same day found: a signal before the traps were set, or a Ctrl-\, still
  ended the run with no line, and a signal after the verdict added a second one. Since then it prints exactly one
  from its first command on: below.) *Found and fixed 31 Oct 2026 (c71be13).*
- **The Mac fix printed a command that puts the withdrawn roots back, on readings a network can produce.** After a
  certificate refused once the change was made — a reading someone on the network holding a compromised key can
  produce at will — it argued against reverting and then printed an `Undo:` line; with the test site still trusted
  after the fix, another such reading, it did the same; and after a restore that failed it said "Put it back
  yourself, now: sudo cp -p …". Each now names the backup and what it holds, and prints no command to restore it.
  The undo line stays under a SAFE result and under a run stopped after the file was fixed. *Found and fixed 31 Oct
  2026 (0ab23c7).*

The rest of this section was found by a third read, of this branch as it stood after the fixes above (33641f9, 31 Oct
2026): three readers who re-checked every earlier finding and looked for new ones, and, the same day, a red-team pass
and an attacker's reading of the specification. Each fix below has a test that fails on 33641f9 and passes after it.

- **A withdrawn root hidden after other text on a line stayed in the file, and the Mac fix said SAFE.** ec955f9
  (under Fixed) counted a certificate only where a line starts with `-----BEGIN`, on the model that LibreSSL reads one
  nowhere else. LibreSSL reads the file 253 bytes at a time, so a marker that falls at byte 253, 506, … of a longer
  line starts a certificate it trusts (OpenSSL 3.6.4: byte 254). Measured: with AAA Certificate Services behind 253
  bytes of padding on one physical line, LibreSSL 3.3.6 read one certificate more than the fix counted, the Mac's own
  `curl` connected to a local test server through a root hidden the same way, and the fix printed SAFE, exit 0 — or,
  on a file also holding the plain roots, "Fixed in the file" with the hidden copy left. At 176b94e, before ec955f9,
  the fix removed the hidden copy. Readers differ, so the fix now models none of them: a line where `-----BEGIN` comes
  after other text,
  anywhere in it, stops the run before anything is read out of the file — UNKNOWN, exit 2, nothing changed, and the
  line says how many such lines there are and to edit them. The script also runs with `LC_ALL=C`, because in a UTF-8
  locale macOS's `grep` does not match a line holding bytes that are not valid UTF-8, so a marker after such bytes went
  uncounted. *Found and fixed 31 Oct 2026 (6c93de4; the case that expected the old model, 697bcc9).*
- **A copy of a withdrawn root with another fingerprint and the same key stayed in the file under SAFE.** The fix
  found the two roots by their certificates' SHA-256 fingerprints alone. A copy of a root with one bit of its
  signature flipped, or a root re-issued with the same key, has another fingerprint and the same public key, and is
  still trusted: measured with a throwaway root and leaf, LibreSSL 3.3.6, OpenSSL 3.6.4 and Apple's `python3`
  (LibreSSL 2.8.3) all trust the bit-flipped copy as an anchor, since none checks an anchor's own signature. Each
  certificate is now read with one `openssl` call for its fingerprint and its public key, and one that carries either
  root's SubjectPublicKeyInfo is removed too, with its block and the one empty line after it, and named as what it is
  ("a certificate with the key of AAA Certificate Services"); "removed both withdrawn roots" alone is printed only when
  the file held each root once and nothing else with their keys. The SHA-256 of each key is in the script's comment
  (AAA Certificate Services `bd153ed7…`, emSign ECC Root CA - G3 `8d417db2…`). *Found and fixed 31 Oct 2026
  (da2e93a).* (It compared the key as written, so the same key stored another way stayed: below.)
- **A process running as the same user could still land its own root in the file under SAFE.** 2add6b3 (above) took
  the cleaned file's SHA-256 from the rebuild, but every check, the list of certificates to remove and the rebuild
  itself still came from the snapshot in the user's temporary folder, and nothing tied them to the file being
  replaced. Measured, 4 runs of 4 on the unchanged script: a same-user process swapped one certificate of the snapshot
  for its own root while the snapshot was read, put the snapshot back before the backup was compared with it, and the
  root landed in `/etc/ssl/cert.pem` with SAFE, exit 0. Now the backup, made beside the file where only its owner can
  change it, must bear out everything read from the snapshot before anything is replaced: the snapshot's SHA-256, each
  certificate to be removed as what it was found to be, and the cleaned file's SHA-256 when it is cleaned the same
  way; and a file found clean is read again from the file itself before SAFE is said about it. Any of these failing is
  UNKNOWN, exit 2, nothing replaced. (Judged, and left open: the control read before the change still goes through the
  snapshot, so such a process could make it fail, which turns the one reading about the change into SAFE "Fixed in the
  file … nothing was re-tested online". The file is fixed and checked in that case.) *Found and fixed 31 Oct 2026
  (888e20a).* (Not quite everything: the removal list was not shown complete, and the line under the 50-certificate
  floor came from the snapshot alone: below.)
- **"Compared again immediately before the replacement" was about 0.6 seconds before it.** d555aff (above) compared
  the file with the snapshot before `replace()`, which then made the new file and fingerprinted every certificate in
  it again (126 `openssl` calls, measured at 0.6 s) before the rename. A change to the bundle in that time — another
  writer, a device-management agent — was thrown away by the rename, was in the backup neither, and the run said SAFE,
  exit 0 (measured, 4 runs of 4). The comparison is now inside `replace()`, after the new file is built and checked and
  immediately before the rename; what is left between them is the test's own return and the start of `mv`, and the
  script's header names that moment as the one change it cannot see. *Found and fixed 31 Oct 2026 (d8eafba).*
- **An administrator's indented note inside a withdrawn root's entry went with the root, under SAFE.** 6e07aaa
  (above) removed a root's Apple entry when every line between its `=== ` line and the certificate was indented, empty
  or one of three fixed lines, so a note such as `    # IT note: AAA kept for the legacy SCEP server until 2027` was
  deleted with it, exit 0. The entry is now compared, whole, with what this Mac's `openssl` prints for that certificate,
  and removed only when it is exactly that; otherwise every line above the certificate stays, and only the certificate
  and the one empty line after it go. On macOS 27.2's own file the result is still byte for byte the advisory's
  removal (measured, all 128 entries). (Judged, not measured: on an older macOS whose `openssl` prints an entry
  differently from the text in that Mac's file, the entry's text stays and only the certificate goes; no withdrawn
  root is left, and its name is still readable in the file.) *Found and fixed 31 Oct 2026 (b3fc5a0).*
- **A stopped run could still print nothing, or two lines.** The traps were set after `uname`, `readlink`, `id`,
  `dirname` and both `mktemp` calls, so a signal in that time ended the run with 129, 130 or 143, no line, and the
  snapshot left in the temporary folder. Ctrl-\ (`SIGQUIT`) was never trapped, so it ended the run with 131, no line,
  and a `.wardlatch-new.<pid>` file left beside the bundle, root's in a real run, that no later run removes. And a signal
  while the cleanup at exit ran, after the verdict, printed a second line under it ("UNKNOWN  Stopped …") and turned
  exit 0 into 2. The traps are now the first commands the script runs, `QUIT` is trapped with `HUP`, `INT` and `TERM`,
  and those signals are ignored once the last reading is in and during the cleanup. Each was measured with a stand-in
  that holds the moment open; in a real run the first and the third are milliseconds wide. A signal no program can
  catch (`SIGKILL`) still ends it with no line. *Found and fixed 31 Oct 2026 (1ab35b2, b609f86, 33e7b52).*
  (USR1, ALRM and XCPU, and a signal while the cleaned file was written, also ended it with no line: below.)
- **Names from the disk could carry hidden characters into the output, in text and in `--json`.** The escaper wrote
  out C0 and C1 control characters and nothing else, and `--json` escaped DEL and C1 only. A folder name holding
  U+2028 starts a line of its own in many renderers and in a language model reading the output, U+202E reverses what
  follows, U+200B hides inside a word, and the tag characters (U+E0000 to U+E007F) are invisible on screen and read as
  text by a language model; APFS accepts all of them. Measured at 33641f9: a venv under such a folder, a git author, a
  tracked file, a plugin folder, a certifi version string and a link named with them all reached the output raw.
  `lib/escape.mjs` is now the one escaper: it writes out every character of Unicode categories Cc, Cf, Cs, Co, Cn, Zl
  and Zp and the whole tag block, in the text output, `--list` and the version line; in `--json` every `reason` is
  escaped the same way, and every other string keeps its real value with those characters written as JSON escapes.
  It makes the hidden visible; it cannot make a planted sentence in plain letters untrue. *Found and fixed 31 Oct 2026
  (b420d92).* (Default-ignorable characters outside those categories, and U+2800, still passed: below.)
- **A venv given with `--paths` hid every venv inside it, and a folder or a link named `site-packages` stopped the
  walk.** 53c3029 (above) probed a `--paths` folder that is a virtual environment *instead of* walking it, so a
  project made with `python3 -m venv .` holding `services/api/.venv`, whose bundle trusts the compromised roots, read
  SAFE, exit 0 (EXPOSED at 176b94e). The installs walk took a folder or a link named `site-packages` or
  `dist-packages` one level deep and never walked or reported it, so a venv holding the LiteLLM stealer below one read
  SAFE, exit 0, and a link of that name escaped the link rule. Neither walk went into a venv found below a searched
  folder, and the trust check given a venv's `lib` or `site-packages` folder examined nothing. Every folder given with
  `--paths` is now walked; every venv met is checked and walked, except the folders it keeps its own files in (`bin`,
  `Scripts`, `include`, `Include`, `lib`, `lib64`, `Lib`, `share`, `etc`), which are checked with it and named on the
  line under every result that rests on the walk; a venv's own `site-packages` checks its venv; any other folder of
  that name is walked like any folder, and a link of that name is a link not followed. *Found and fixed 31 Oct 2026
  (2ce50f0).* ("Checked with it" was untrue: nothing in `bin`, `share` or `etc` was read, and a PyPy or
  Windows-layout venv's packages were never found: below.)
- **A PKCS #12 store in BER, a DER key with one byte after it, and a key after a certificate were skipped with no
  row.** 1ea7a06 (above) refused an indefinite length and allowed only line ends after the element, so such a file,
  under a name that isn't a text file's, read "SAFE no committed keys found". LibreSSL 3.3.6 and OpenSSL 4.0.3 read the
  BER store and load a DER key with a trailing NUL or space (measured). Constructed elements of indefinite length are
  now read (nesting capped at 32), a key is a key whatever follows it, and the elements after a certificate are read
  for a key; a certificate followed by anything else still makes no row, and a store read in BER is named "(BER)". The
  first form of this read the elements after a certificate in quadratic time — a 33 KB file took 2.9 s, and one under
  the 1 MB cap could have held the scan for about half an hour — and was corrected before it merged (400,000 elements,
  3.8 ms; its test fails on the commit before 3dbf80c, and passes on 33641f9, which never read past a certificate). A
  test now also holds the key check on git's copy of a tracked file deleted from the working tree, which a
  planted change could remove with every test green. *Found and fixed 31 Oct 2026 (81b267d, 3dbf80c).*
  (Not past a 1 MB cap: below.)
- **A listed plugin's own folder without its main file, and a Bedrock checkout with no core, read SAFE.** A `--paths`
  folder named as a listed plugin was checked only when the plugin's main file was in it, so a backdoored Rank Math
  PRO folder whose `rank-math-pro.php` was gone, with `inc/loader.php` still carrying the indicator, read "SAFE no
  WordPress installs found in 1 folder searched", exit 0; and a Bedrock checkout before `composer install`
  (`app/plugins` holding the compromised release, no core yet) read SAFE, exit 0. Such a folder is now checked
  whatever is in it (with no main file its version is UNKNOWN, and the indicator is still searched for), and an
  `app/plugins` folder is checked as a plugins folder when Bedrock's config is beside it or beside its web root, or
  when it holds a folder named as a listed plugin. *Found and fixed 31 Oct 2026 (de7def8).*
- **A service's folder Wardlatch could not open rode beside SAFE as a review line, exit 0. Owner decision #33 makes it
  could-not-be-tested, exit 2.** Decision #32 (above) covered EPERM; a folder a service owns that refused with EACCES
  was still one REVIEW line beside the all-clear. The owner decided on 31 Oct 2026, in his words "UNKNOWN too": such
  folders are now one UNKNOWN row per check (`15 folders owned by service accounts, not searched`), with each folder's
  errno, mode and owner and the advice to run with sudo, no all-clear beside it, and exit 2; in `--json` the row has
  the check's own kind, `what: "service folders"`, `paths` and `folders`. It replaces the rule of 22 Oct 2026. Measured
  on `/private/var/spool`: SAFE and exit 0 before, UNKNOWN and exit 2 now. *Found and fixed 31 Oct 2026 (4c6e130;
  the tests, 3590346).*
- **A virtual environment whose packages are not at `lib/python3*/site-packages` read SAFE.** The third read's walk
  found a venv's packages only there, so a PyPy venv (`lib/pypy3.X/site-packages`), a Windows-layout one
  (`Lib/site-packages`) or an older PyPy one (beside `pyvenv.cfg`) holding the LiteLLM stealer read SAFE, exit 0, and
  a PyPy venv's certifi was never tested. They are found in every one of those layouts now. *Found and fixed 31 Oct
  2026 (1a8141e).* (That left a gap this round's strict audit measured — the code took any folder of a venv whose name
  began `lib`, in any case, as its lib folder, so a venv inside a project-venv's `libs/` was not looked for — and
  c0b5334 closed it: a venv's lib folders are `lib`, `lib64` and `Lib` under those names or any spelling this disk
  opens them by, which is what the line under the all-clear now says.)
- **A venv's own `bin`, `share` and `etc` were never searched, while the line under the all-clear said they were
  "checked with it".** 2ce50f0 (above) skipped them, so a stealer's venv inside a project-venv's own `lib/`, `share/`,
  `bin/` or `etc/` read SAFE, exit 0. A venv is now walked like any folder but its own package folders, which are
  checked and not walked, and the line under the all-clear says exactly that. *Found and fixed 31 Oct 2026 (7886340).*
- **A link to a virtual environment hid any venv inside it.** The link was marked as walked, so it had no row and a
  venv inside the linked one was never looked for. Its packages are still checked through it, and it is now a link not
  followed, could-not-be-tested. *Found and fixed 31 Oct 2026 (d5b890f).*
- **A repository inside another was not checked, and the all-clear did not say so.** The workflow, committed-keys and
  header checks stop at the first repository. The line under each of their all-clears now says "a repository inside
  another repository is not looked for: pass --paths with it to include it". *Found and fixed 31 Oct 2026 (a86a2f3).*
- **A DER key followed by more than 1 MB of other bytes was skipped with no row.** The key reader read files under a
  1 MB cap before it looked at their structure. It now reads the first 1 MB, and a key in it is a key. A file whose
  first element is anything else still claims nothing past 1 MB. *Found and fixed 31 Oct 2026 (008f5f9).* (That left a
  gap this round's strict audit measured — a store whose own outer element ran past the 1 MB cap was skipped with no
  row at all — and b66a928 closed it: such a file is now named, or UNKNOWN with the cap given, never skipped.)
- **A loose copy of a plugins folder under any other parent read SAFE.** A `plugins` folder holding a listed plugin's
  folder is now checked as a site's are, whatever its parent, unless it sits in a found site's own folder. *Found and
  fixed 31 Oct 2026 (8982069).*
- **Invisible characters outside the escaper's categories still reached the output raw.** Variation selectors,
  U+034F, the Hangul fillers and the braille blank (U+2800) passed in text and `--json`. The escaper now also writes
  out every Default_Ignorable_Code_Point and U+2800, and a backslash that would read as one of its forms is written
  `\\`, so a folder literally named `t\u{202e}t` no longer prints like one holding U+202E. *Found and fixed 31 Oct 2026
  (bffd3ab, 83616bd).*
- **A crash turned the printable `\x0a` in an error's text into a line break.** A path holding those four characters
  could start a line of its own, such as one beginning SAFE, on stderr. The stack is now escaped a line at a time.
  A real line break inside an error's own message still starts a line (measured 31 Oct 2026; open). *Found and fixed
  31 Oct 2026 (3ffcb0d).*
- **The Mac fix left a copy of emSign's key stored in another encoding, under SAFE.** da2e93a (above) compared the key
  as `openssl x509 -pubkey` prints it, which keeps an EC point's form and an explicit curve: a copy with the point
  compressed or hybrid, or explicit parameters, which LibreSSL and `/usr/bin/curl` trust, stayed in the file, as did
  an RSA key labelled RSA-PSS. The key is now compared as `openssl` decodes it. *Found and fixed 31 Oct 2026
  (c6882a7).*
- **The Mac fix had root copy a path in the user's temporary folder.** `sudo cp` follows a link, so a process running
  as the user that turned the cleaned file into a link to a root-only file while the run waited for the password got
  root to copy that file beside the bundle and make it readable by everyone for a moment. The new file is now written
  by `tee` from input the user's own shell opens. *Found and fixed 31 Oct 2026 (3ca047d).*
- **The Mac fix's backup check did not prove the removal list complete.** It checked each listed root in the backup;
  a root hidden from the snapshot's reads was never listed, and only the check on the new file stopped it landing. The
  backup must now read exactly as the snapshot did. And under 50 certificates, what the line says about the file is now
  read from the file itself, not the snapshot. *Found and fixed 31 Oct 2026 (a98c950, a4d1e4d).*
- **The Mac fix could still end with no line, or with EXPOSED's exit code after a fix.** USR1, ALRM (a timeout) and
  XCPU ended it with 158, 142 or 152 and no line, after the rename too; a signal while the cleaned file was written
  sent its line into that file; and a verdict line that could not be written ended the run with 1. Every signal whose
  default ends a process, except the fault signals, is now trapped; the line goes to the standard output the run
  started with; and the run exits 0 only after SAFE and 1 only after EXPOSED. The fault signals and SIGKILL still end it
  with no line. *Found and fixed 31 Oct 2026 (937b8bd, c84e2a0, 2adc8b1).*
- **The Mac fix printed a link's target inside the command it told the reader to run.** A target holding a single
  quote broke out of the quoting, so the printed command ran a command of the link maker's choosing. A target name is
  now printed only when it is plain. *Found and fixed 31 Oct 2026 (d979f6e).*

### Fixed
- **359 of the 361 folders a run called "could not be tested" on one Mac were not gaps at all, and the two
  sentences printed about them were false.** Measured there: `--incident wordpress-plugins-2026-10 --paths ~` gave
  311 could-not-be-tested, 0 safe, exit 2; `--incident github-actions-2026-10 --paths ~` gave 50. Of the 311, **310**
  were symbolic links under `~/.cache/uv/wheels-vN/` that every one resolve into `~/.cache/uv/archive-v0/` — a tree
  the same run had already walked, so the bytes had been read — and every walker pushed every link it declined into
  the gap channel unconditionally. Of the 50, **49** were folders that are perfectly **readable** (`~/.config`,
  `~/.ssh`, `~/.claude`, `~/.local`, `~/.gnupg`): `lib/workflows.mjs` chose not to walk any dot-folder outside a list
  of tool-cache names, and then reported that choice through the channel whose consumers print *"could not be opened,
  so it was not searched: run Wardlatch with sudo"*. The walk never tried to open them, so the sentence was untrue and
  the advice could not work. "I chose not to look" was being written into the channel reserved for "I could not look",
  and the real gaps on that machine were buried under 359 false ones — which is how could-not-be-tested becomes the
  footnote nobody reads, and how a tool that always exits 2 teaches people to write `|| true`.
  Three things changed. **A link whose target the same walk already walked is not a gap** and is dropped
  (`lib/files.mjs` `unwalkedLinks`, compared by `fileId()` — device and inode, the identity that survives links,
  firmlinks and macOS's two spellings of the start-up disk, as AUDIT-25 already uses for roots). Identity, not a path
  prefix: a walk skips `node_modules` and stops at a depth cap, so a target merely *inside* a searched folder may
  never have been opened. (Until 31 Oct 2026 a target the walk had only *listed* counted, which reopened AUDIT-8 in
  the default run; it now has to have been walked as deep as following the link would have: see Security.)
  **Dot-folders are walked like any other folder**, and the `TOOL_CACHES` name list is gone with the `denied?.push()`
  that fed on it; they are almost all readable, so walking them costs a walk and produces no row. That list also held
  `.Trash` and `.Trashes`, so until now `mkdir .Trash` in a project still hid a repository from the workflow and key
  checks — AUDIT-5 only half fixed. And **a folder skipped by its name alone now gets a row when it refuses**, below.
- **A folder macOS is protecting was reported as one that "could not be opened", with advice that cannot work, or
  skipped by its name with nothing recorded at all.** `isSystemFolder()` skipped `.Trash`, `.Trashes`,
  `Photo Booth Library` and `*.photoslibrary` by name, which made `mkdir .Trashes` a hiding place from every walk
  (AUDIT-5) — and it was wrong about the real article too: measured 29 Oct 2026, a modern `*.photoslibrary` has **no
  `Contents` directory**, so the bundle-marker gate returned false for the Photos library and true for Photo Booth
  Library only by accident. Those arms are deleted, and so is the parent gate behind them: those folders are walked
  like any other, and one that refuses is read for what it is. A folder the system refuses with **EPERM** is
  could-not-be-tested, exit 2, whoever owns it (owner decision #32, under Security), and its row carries **a basis a
  reader can check with one `ls -ld`** — the errno, the mode and the owner, in the printed reason and in `--json` —
  and, on macOS, the remedy that may work: privacy protection is a common cause, which allowing the terminal Full
  Disk Access may lift, and a sandbox the run is inside refuses the same way, so the row never claims to know which.
  (From 4209d15 until 31 Oct 2026 this entry described a different rule, which never shipped: an EPERM on a folder
  whose mode would let the run in was a "stated gap", a REVIEW line beside the all-clear with exit 0, on the claim
  that EPERM "cannot be forged without root". That claim was false, and decision #32 replaced the rule: see
  Security.) Everything else is as it was: a person-owned EACCES stays could-not-be-tested and exit 2, and a
  service's EACCES folder was one review line until decision #33 (under Security) made it could-not-be-tested too.
- **An all-clear that sits beside folders a service owns, which it couldn't open, now records how many,** as `gaps`
  next to `searched` in its receipt, so exit 0 reads "I opened these, could not open 3, here they are and here is
  what would open them" rather than listing only what was opened and leaving the reader to assume the rest was
  nothing. *On the Mac that was measured, on 29 Oct 2026:* the first command went from 311 could-not-be-tested to
  **10**, the second from 50 to **11**, and three folders macOS protects (`~/.Trash` and the two photo libraries)
  were stated in one review line. Those figures were measured under the stated-gap rule that decision #32 replaced,
  and before the link, depth-limit and skipped-name corrections under Security; they have not been measured again,
  and they would differ: those three folders are now could-not-be-tested rows, a link whose target was only listed
  now counts, and so does a folder past a depth limit. (Decision #33, under Security, replaced this too: a service's
  folders are now one UNKNOWN row, no all-clear is printed beside it, and the command no longer writes `gaps`.)
- **`test/support/mojave-shapes.sh` was testing the live network while saying it was offline, and one of its cases
  could not fail.** Its stub `curl` was dead code: it put one on `PATH`, but the fix calls `/usr/bin/curl` by
  absolute path on purpose, so `PATH` could never shadow it. All five shapes made live requests to
  `www.apple.com` and to the advisory's test host, each shape's result depended on what the network answered that
  minute, and the branch the file's header claimed to exercise was not the branch taken — shape A printing "now
  refuses the compromised keys" was the proof, since that line cannot be reached through a `curl` that exits 7. It
  now drives a copy of the script with the network command behind `WARDLATCH_CURL`, as
  `test/fix-macos.check.sh` does, and stops with a message if that substitution matches nothing. Shape D looked
  for the fragment `neither` in the output while `shape()` writes its bundle to `run-neither.pem`, which the fix
  echoes in every line: the assertion matched the *filename* and would have passed for any output at all. It now
  looks for what the script prints. And the harness exited 0 however many shapes failed, so it could gate nothing;
  it exits 1 now. Until 31 Oct 2026 it ran in no CI job; it now runs in the mac-fix job on macOS (below).
- **Three more in `test/fix-macos.check.sh`,** landed with the write-path commit above and recorded here.
  `$emsign` was assigned only if a certificate matched the emSign fingerprint, inside a block guarded by "this
  bundle holds a withdrawn root" — which an AAA-only bundle satisfies — so on exactly the Mojave-era shape the
  sibling harness exists for, the suite died with `emsign: unbound variable` instead of reporting; it now says
  which root the bundle is missing and why the case cannot run. The byte-for-byte comparison with the advisory's
  own removal sits behind two conditions and could silently not run inside a case that still printed ok; it now
  says when it is skipped and why. And the guard on the curl stub only asserted that the substitution had changed
  *something*, so it would have passed with one call site left reaching the real network — which is how the
  sibling harness came to be wrong; it now counts every occurrence and requires all of them behind the stub.
- **The Mac fix's own harness read the machine's live `/etc/ssl/cert.pem`,** so its green depended on the Mac
  running it being unfixed. `test/fix-macos.check.sh` took its bundle from `${1:-/etc/ssl/cert.pem}` while every
  removal case and every network case sits inside `if [ "$found" -gt 0 ]`: on an already-fixed Mac, or on CI's
  `macos-latest` the day Apple ships a fixed bundle, six of its cases skipped with a NOTE and the suite still
  exited 0. It now defaults to the vendored unfixed fixture `test/support/fixtures/macos-27.2-cert.pem`, which
  `test/support/mojave-shapes.sh` was moved to in this same release for the same reason; a bundle holding neither
  withdrawn root is a failure rather than a NOTE, every case counts itself, and the run prints and checks the
  total, so a case that stops running cannot pass as silence. It counted 20 cases when this landed, 60 at 33641f9 (31
  Oct 2026), 76 after the third read of that day, and 94 after the fourth (below).
- **"Something other than this file is trusting the compromised keys" misdiagnosed the two likeliest causes.** When
  the fix has removed both roots and the advisory's test host is still trusted, two ordinary things look exactly
  like that: a TLS-inspecting proxy's own root added to the certificate file, which makes the proxy sign everything
  including that host; or the test host re-issuing its certificate from an ordinary CA, which makes it load for
  everyone and test nothing. The old wording sent an administrator hunting for something else on their own Mac. It
  now names both and says to rule them out first; the verdict, the exit code and the rule that the fix is kept are
  unchanged. `removed_phrase()` also took an argument it never read, at five call sites, and no longer does.


- **The Mac fix told the user it covers `perl` and `ruby`.** Its last lines named "the built-in curl, git, python3,
  openssl, perl and ruby", while the Wardlatch Mac FAQ says in as many words that we tested the first four and treat
  perl and ruby as unmeasured by us. The advisory named them on 21 Oct 2026 and has since narrowed its macOS section
  back. The script is the artefact people run with `sudo`, so it is the worst place to carry an assurance we disclaim
  elsewhere: it now names the four we measured and says the other two are not among them.

These were found by the same independent read of 31 Oct 2026, and each fix has a test that fails on 176b94e:

- **`mandatoryRefusal()` misread a folder's permission bits, and its test of them could be deleted with no test
  failing.** The others' bits counted for the folder's owner, whom the system judges by the owner's bits alone, so a
  folder of mode 0005 that its owner cannot list was said to be one whose "permission bits would let this run in";
  and every test handed it EACCES, which returns before the mode is read, so replacing the test with `return true`
  left the whole suite green. It now reads the bits the system applies — the owner's for the owner, the group's for a
  member of the group, the others' for everyone else (ACLs are not read) — and since decision #32 it decides only
  whether a row says that clause, never the exit code. (456b715)
- **A DER certificate was could-not-be-tested for ever, as "a text file that reads as binary".** A tracked `.crt`,
  `.pem` or `.key` holding a NUL byte in its first 8 KB was UNKNOWN with "it is named as a text file but reads as
  binary", so a repository with a DER fixture exited 2 with no way to clear it, and the sentence was untrue. A file
  with an X.509 certificate's DER shape holds no secret and now makes no row; a binary file under a text file's name
  that is neither a DER key nor a certificate is still UNKNOWN, with a true sentence. (4c1ded4)
- **A link to a repository or a virtual environment the same walk had checked was could-not-be-tested, and the
  advice printed could not clear it.** A found repository and a probed environment were never recorded as walked,
  so `current` linking to `proj` was "a link to a folder somewhere else" beside `proj`'s own clean row, exit 2, and
  passing both to `--paths`, as the line advised, changed nothing. A found repository, a probed environment and a
  venv the installs check reads from a searched folder now count as walked whole. (132e17d)
- **Every clean Rank Math PRO install read could-not-be-tested: the indicator search would not read a `readme.txt`.**
  It read only code files, skipped pictures, fonts and archives, and reported every other file — `readme.txt`, a
  `.pot`, `.json`, `LICENSE` — as not searched, so a clean site read SAFE for the plugin and UNKNOWN for the search,
  exit 2, with no remedy. Every file that isn't a picture, font, style sheet, source map (`.map`), archive, media
  file, document, translation file (`.mo`, `.po`) or `.lock` file is now searched (a `.min.js` file is searched, as
  code), within the same caps (4,000 files of under 2 MB, 12 levels deep; what a cap leaves out is still UNKNOWN).
  The files of those kinds are passed over with no row. (1d1055b)
- **The installs check's quick look round the home folder made every link it declined could-not-be-tested.** That
  look says nothing about a folder it can't open, by design, but reported every link: `~/OneDrive` linking into
  `~/Library/CloudStorage`, as cloud-drive clients make it, made every LiteLLM run exit 2, whatever `--paths` named.
  It now reports no link, as it reports no folder it can't open; a link below a searched folder is reported as
  before. (f1d13ba)
- **The Mac fix gave a network that stopped answering the reading for an attack.** When the control loaded before
  the change and not after it, every failure got the reading for a refused certificate — the two files differ only
  by the withdrawn roots, so the site's certificate needs one, or someone is presenting one, "and the second is what
  an attack on this Mac would look like". curl 6 (a name that didn't resolve), 7 (no connection) and 28 (no answer
  in time) fail before or without any certificate being refused. Those three now print "this network stopped
  answering", with what each code means and nothing said about the change; only curl 60 gets the certificate
  reading; any other code is given as it is, and the run says it reads nothing into it. All exit 2 with the fix
  kept. (16533a6)
- **What the Mac fix said it removed was not what the file held.** On a bundle holding one root, as every Mac of the
  Mojave era does, it said "removed 1 of the 2 withdrawn roots; the other was already absent from this Mac", a claim
  about a Mac drawn from one file; it said "removed both withdrawn roots" for two copies of AAA Certificate Services;
  and its reading of a refused certificate named AAA Certificate Services on a file that never held it. It now names
  what it removed, copies counted — "removed AAA Certificate Services (this file did not hold the other withdrawn
  root, emSign ECC Root CA - G3)", and the mirror — and the other readings name what the file held. (fa6a876)
- **A comment that mentions the BEGIN marker made a bundle the Mac fix could never fix.** A line such as "paste each
  certificate from its -----BEGIN CERTIFICATE----- line …" counted as a certificate that couldn't be read, so the run
  said UNKNOWN, exit 2, on a bundle the Mac's LibreSSL reads without complaint. A certificate now begins only at a line
  that starts with the marker, which is all LibreSSL reads as one. (ec955f9) (That last sentence was untrue, as the
  third read of 31 Oct found: LibreSSL reads the file 253 bytes at a time and starts a certificate at a marker that
  falls at byte 253, 506, … of a longer line, so a withdrawn root hidden that way stayed in the file under SAFE. Since
  6c93de4 a line where the marker comes after other text is UNKNOWN, exit 2, nothing changed, and the line says which
  lines to edit, so a comment like the one above is refused again, now for that reason: under Security, above.)
- **The Mac fix's refusal of a symlinked `/etc/ssl/cert.pem` gave an untrue reason, and advice with no way to follow
  it.** It said replacing the link would leave the file the Mac reads as it is; in fact the rename would replace the
  link with a file of the script's own, so `/etc/ssl/cert.pem` would stop following the file an administrator linked
  it to, and that file would be left as it was. And it said to run the fix against that file without saying how. It
  now gives that reason, names the file the link points to, and prints the command:
  `WARDLATCH_CERT_FILE='<that file>' bash '<this script>'`. (7f74002)
- **A refused `sudo` was reported as a full disk.** The first `sudo` call was the backup copy, where the interactive
  run asks for the password, so a wrong password three times or no answer in time printed "Couldn't write the
  backup … Check the disk has room". The fix now asks for the privilege on its own first (`sudo -v`), and if that
  fails says so: "sudo didn't give this run the privilege to write <file> (sudo -v failed), so nothing was changed",
  exit 2. (A refusal at a later prompt was still blamed on the disk, as the third read found: below.) (08bb777)
- **The Mac fix made its temporary files where macOS chose, not where `TMPDIR` says.** `mktemp -t` on macOS uses the
  per-user temporary folder and ignores `TMPDIR`, so the harness's check that no temporary file was left behind,
  which watches the `TMPDIR` it sets, watched a folder the fix never wrote to and could not fail. They are now made
  with `mktemp "${TMPDIR:-/tmp}/wardlatch.XXXXXX"`. (775befc)
- **The Mac fix's header said things the script did not do.** It had a sentence with words missing ("so an
  interruption leaves or the new one"), said the script "never tells you to restore a backup" while it printed
  "Put it back yourself, now", gave the old reason for refusing a link, said it refuses to replace a file that changed
  meanwhile on a path where it did not, and promised two network readings that curl 6, 7 and 28 merged. It now says
  what the script does, including that every exit on macOS prints a SAFE, EXPOSED or UNKNOWN line (which held from
  the script's first command on only once the fixes for the third read of 31 Oct set the traps first: below). (0d5dbe5)

These were found by the third read of 31 Oct 2026 (33641f9), and each fix has a test that fails on 33641f9:

- **A `sudo` that refused a later prompt was still blamed on the disk, and its own words were hidden.** With
  `Defaults timestamp_timeout=0` every `sudo` call asks for the password again. A refusal at the backup's `mktemp`
  printed "Couldn't make a file beside … for the backup (mktemp failed). Check the disk has room (df -h /)" with sudo's
  message sent to `/dev/null`, and every later step said "Check the disk has room" too. Each privileged step after
  `sudo -v` now keeps what it printed, and the line that reports its failure gives those words ("Couldn't copy … to
  make the backup (cp said: sudo: 3 incorrect password attempts)"); the disk advice is added only when the words are
  about disk space. (62e1974)
- **A full temporary folder was reported as "Can't read" the bundle.** When the snapshot copy failed, the line said
  the file couldn't be read, whatever the cause. It now checks whether the file reads in full, and if it does says
  that the copy into the temporary folder failed and that the folder may be full, or not writable by this run. (3eaef0a)
- **Rows outside `gaps()` still told a person to run Wardlatch with `sudo` for an EPERM.** The LiteLLM check's
  site-packages and version-file rows, and the WordPress check's plugin, indicator-search and plugins-folder rows and
  its config-file doubt, said "run Wardlatch with sudo" for a folder a sandbox refused, which sudo may not open. Every
  row about an EPERM now says what `gaps()` says (the system refused it, what commonly does, and that sudo may not
  lift it), and "run Wardlatch with sudo" stays for a folder shut by its own mode (EACCES), which sudo opens. The rows
  were UNKNOWN before and still are. (7984d90)
- **A folder past a depth limit holding only `node_modules` made a depth-limit row.** `holdsMore()` counted any
  folder, link or `.git` past the cap, whatever the walk would have done with it, so a run exited 2 over a folder no
  deeper walk would enter. It now counts only what the asking walk would go into: not the names it skips, not macOS's
  own Library, a link only when it leads to a folder, and `.git` only for the repository walk. (bbff817)
- **A walker's gap lists were optional, so a caller that left one out got a walk that said nothing.** No caller left
  one out; three tests did (Development, below). Each walk now takes its lists from `gapLists()`, and a walk that has a
  gap to report and no list to put it in throws, which is could-not-be-tested, never SAFE. (d0745c6)
- **The eMudhra fix text for the Mac's built-in curl named the 28 Sep releases as the newest.** macOS 27.2, 26.7.2
  and 15.8.2 shipped on 26 Oct 2026. Measured on macOS 27.2, its `/etc/ssl/cert.pem` still holds both withdrawn roots,
  byte-identical to the vendored fixture, so only "the newest" was stale; the text now names those releases and says
  that Apple says the file will be updated in a future macOS update. (331d2f0)
- **The eMudhra incident file lacked its two roots' key hashes.** Each `distrustedRoots` entry in
  `lib/incidents/emudhra-2026-10.json` now carries `spkiSha256`, the SHA-256 of the root's SubjectPublicKeyInfo
  (AAA Certificate Services `bd153ed7…`, emSign ECC Root CA - G3 `8d417db2…`), re-derived from the incident's own
  certificates with two `openssl` builds and checked by a test against them. Nothing in the command reads it yet: it
  is data for the Mac fix and for whoever matches a root by its key. (d38d898)
- **The Mac fix's header said nothing read from its snapshot is taken on trust.** One reading is: the control before
  the change goes through the snapshot, and nothing bears it out (section 4 of ASSURANCE_CASE.md already said so).
  The header now names it. A comment, so only the digest changed, with CI's pin in the same commit. (8b878a3)
- **A real line break in a crash's message started a verdict line of its own on stderr.** `lib/crash.mjs` split the
  stack on every real line break and escaped each piece separately, so the message's own line breaks survived: an
  error whose text held an LF before `SAFE     no LiteLLM 1.107.0 files or markers found` printed that as a line a
  reader — or a reader's agent — sees under a crash that exits 2. APFS takes an LF in a name, so a path carries one
  in exactly as it carries the four printable characters `\x0a` that were fixed on 31 October; the comment added then
  said a line break inside a message stayed escaped, and it did not. The message and the frames are now escaped
  apart: the end of the message comes from the error's own `message`, never from the shape of the text, and a line
  break is kept only where the line after it is a stack frame. Found 31 Oct 2026, fixed 1 Nov 2026. (23ed53b)
- **The Mac fix named the wrong file when a linked bundle's target ended in a line break.** `/etc/ssl/cert.pem` as a
  symbolic link to a file called `real.pem` followed by a line break was reported, and put into the printed
  `WARDLATCH_CERT_FILE=... bash ...` command, as a link to `real.pem` — a different file, which can be sitting beside
  it. `readlink` cannot tell the two names apart at all: measured on macOS 27.2, it prints a target that does not end
  in a line break **with** one added and a target that does end in one **without**, so both come back as the same
  bytes, and a command substitution drops what is left. The target is now read with `/usr/bin/stat -nf '%Y'`, which
  adds nothing, and a sentinel holds the end, so `plain()` sees whatever the name really holds and a name with a line
  break in it is never printed. Only whoever can create the link can do this, which for `/etc/ssl` is root. Found
  31 Oct 2026, fixed 1 Nov 2026. The script's digest changes with it:
  `c8bba160a8a9c30f2f850cd8987429b297612ea580e77404fddbbfe7ddc167a6`, the digest at this release. The
  site's download, the hash on its page and its changelog record have **not** been updated and must be, together,
  before this script is published (SECURITY.md, step 4).

### Development (no code in the package changes)

- **`test/fix-macos.check.sh` ran 60 cases at 33641f9 (31 Oct 2026), where it ran 29** (76 after the third read of
  that day, and 94 after the fourth: below). Thirty new cases for what the independent read found in the Mac fix, and one for `strays()`;
  stand-ins for `cp`, `mv`, `mktemp`, `chmod` and
  `sudo` on `PATH` make a copy fail part-way, a rename pause or a file change in mid run (the real `sudo` never runs).
  Every run on macOS must now print a line starting SAFE, EXPOSED or UNKNOWN. Assertions that were wrong were
  corrected, among them ones that required a command putting the withdrawn roots back.
  One case, `heredoc-trigger`, applies a sandbox profile of its own, so when the harness itself runs inside a sandbox
  (`WL_NESTED_SANDBOX=1`) it is named NOT RUN rather than counted. The header no longer says the harness needs the
  network: it never did, and every case passes with none. (a4a4e35, 4ef7e98)
- **`test/support/mojave-shapes.sh` runs in CI**, in the mac-fix job on macOS, offline, and fails if any shape
  misbehaves; it writes under `TMPDIR`, not a fixed `/tmp`, and shapes B and C assert the root removed by name instead
  of "the other was already absent". CI pinned the Mac fix's SHA-256 after this round,
  `7d0640b49b63b5964cb96aecca474446d4cac5884cb10f147eb627beb7f66cd1`, pinned
  `98f8d58cadcdde8802451f3993e3030c5dad24a65d25777956593220b572bc39` after the third read, and pins
  `d8a4bffd43f97449f2d92b8c5b5cb2e908f698cb09482fb3cb9e3ba2c07a97a5` since the fourth (below). (a4a4e35, dcbd3a7)
- **`test/support/errno-mechanisms.mjs` exited 0 without measuring, and counted a failed setup as a claim that
  holds.** Its exit code is its verdict, and a run that found no folder macOS protects said the half of the rule about
  them was unverified and still exited 0. A claim whose setup could not be applied is now UNMEASURED, counted apart,
  and so is the half about folders macOS protects when there are none to measure; it exits 0 only when every claim
  was measured and held, 1 when one
  broke, and 2 when nothing broke but something was not measured. Since decision #32 it also measures the claim that
  decision rests on: an unprivileged `sandbox-exec` profile gives EPERM on a folder of mode 0755 owned by the person
  running (UNMEASURED inside another sandbox, where a profile can't be applied). (1791ed8)
- **A test now holds the "not found on PATH" all-clear when a `PATH` folder no longer exists.** A planted bug that
  dropped the filter keeping a missing folder out of the receipt turned that all-clear into "UNKNOWN internal error",
  and no test failed. The code was right; the test was missing. (54b8fd6)
- **Two test comments said nothing unprivileged could produce an EPERM.** An unprivileged `sandbox-exec` profile
  does, which is why decision #32 was needed; the comments now say so. (b04e122)
- **`test/fix-macos.check.sh` runs 76 cases, where it ran 60 at 33641f9.** Sixteen new cases for what the third read
  found: `mode`, `begin-mid-line`, `labels` (a withdrawn root as `X509 CERTIFICATE` and as `TRUSTED CERTIFICATE`,
  which LibreSSL, OpenSSL and Apple's `python3` trust and the fix refuses), `same-key`, `key-constants`,
  `snapshot-swap`, `changed-in-replace`, `sudo-refused-later`, `early-signal`, `sigquit`, `signal-at-exit`,
  `indent-note`, `admin-heading`, `tmpdir-full`, `backup-guards` and `digest-from-rebuild`; new stand-ins for `grep`,
  `rm`, `uname` and `date`, and new modes for the `cp`, `chmod`, `sudo` and `mktemp` ones (the real `sudo` still never
  runs). Three hold properties no case held, each shown to bite with a planted change the whole harness had passed:
  the dated backup's two guards against overwriting an earlier one; the new file's SHA-256 taken from the rebuild, not
  from the copy in the temporary folder; and an administrator's `=== ` heading above a withdrawn root's entry kept.
  And a case that could not run is no longer counted as run: under root the unreadable-file case is named NOT RUN,
  and the end of the run checks that every case counted printed its `ok` line. `marker-comment`, which expected the
  ec955f9 model, now expects UNKNOWN, and five checks are grouped as `{ A && B; } || fail` for ShellCheck's SC2015.
  (9b30707, d261ddb, 697bcc9, fccf2bd, 4e012ce, 176916f, ac55333, b54c601, b3b7ecf)
- **`fix/fix-macos.sh` is executable again.** 6e07aaa changed its mode in git from 100755 to 100644 without saying so,
  so `./fix/fix-macos.sh` in a clone said "Permission denied"; its bytes and SHA-256 were unchanged, and the download
  is run with `bash`. It is 100755 again, and the harness's `mode` case reads the mode git records. (9b30707)
- **CI pins the Mac fix's SHA-256 after the third read,**
  `98f8d58cadcdde8802451f3993e3030c5dad24a65d25777956593220b572bc39`. (9b1b2b1)
- **Five tests changed with no code, each because it relied on what this round changed.** Three walker tests left a
  gap list out and so relied on the walk staying silent about it (9bc3ebc); a Bedrock test pinned exit 2 where its own
  fixture holds an exposed plugin, which is now found (1877e3c); and the venv depth-row guard could not fail on the
  change it was written against, because its fixture stopped one level short (d93be93).
- **`test/fix-macos.check.sh` runs 94 cases, where it ran 76 after the third read.** Eighteen new cases, each written
  against a defect the fourth read fixed or a planted change the third read's re-reads found every case passing:
  `samekey-enc` and `key-undecoded` (the key in other encodings, and a key `openssl` can't decode), `locale` (a hidden
  root in Terminal's default UTF-8 locale, and a pad ending in `-`), `root-reads`, `hide-root` and `built-last`,
  `changed-in-built` and `reswap-after-link` (the two race fixes of the third read, each now held by a case),
  `floor-swap`, `sig-in-strip`, `every-signal`, `exit-signals` and `settled`, `stdout-fails`, `link-name`,
  `clean-reads-file`, `disk-advice` and `other-runs-files`. Each names the planted change it catches, and each was
  planted and caught. Its signal cases are no longer failed, blaming the fix, when the harness starts with a signal
  ignored, as a background job from a script does: they restore the signal first, and say so in a NOTE. (affd77c,
  4aab444, 854e995, and the fixing commits under Security)
- **Tests for the lib changes the third read's re-reads planted and no test caught.** Seven of twelve survived the
  node suite. New tests are written against each: holdsMore() counting macOS's Library (L04), Bedrock 1.0.0's layout
  (L09), `--list` without the escaper (L12) and the venv rules (9b24e8e, c669ac7, c34a486); the key reader's
  strictness (L05, L06) and the crash message (L11) in the tests of 008f5f9 and 3ffcb0d. Not every planted change of
  this round's own lib code is caught yet: the round's strict audit found some that survive, and they are open. Four tests changed with no
  code: decision #33 replaced the rule three tests pinned (3590346), a walker test counted a leaf folder past the cap
  where no venv can be (aefb596), the escaper test expected the wrong selector for "A" (087d63c), and a comment
  described the venv walk as the third read left it (40b5e29).
- **CI pins the Mac fix's SHA-256 after the fourth read,**
  `d8a4bffd43f97449f2d92b8c5b5cb2e908f698cb09482fb3cb9e3ba2c07a97a5` (8b878a3). On the way it pinned
  `f060d8165aaf8e21e103737ce9cefe55d49f7e8d3ff8323d91be4e00ca325a73` (0604364) and
  `0d183c2bfbf0bd0d585fd3f8db5ac1728893beb83bfc31c9b024696443ad16cc` (66a70ec), neither of which the site has had.
  Fourteen of the sixteen commits of the Mac fix's branch this round changed the script without the pin, so CI's pin
  step fails on each of them alone (measured, commit by commit); from 8b878a3 the pin changes in the same commit as the
  script.
- **`test/fix-macos.check.sh` lost its executable bit, unannounced.** a98c950 changed its mode in git from 100755 to
  100644, the slip 6e07aaa made with the fix itself. CI runs it as `bash test/fix-macos.check.sh`, so nothing fails,
  and no test reads the harness's own mode. It is still 100644 on this branch; restoring it is a mode-only commit.

## [0.1.10] - 2026-10-27

### Security

- **The Mac fix (`fix/fix-macos.sh`) could say SAFE for a file that still trusted the leaked eMudhra keys.** It found
  the two roots by their `=== …/CN=` name lines. Some copies of `/etc/ssl/cert.pem` (on some managed Macs) have no
  name lines, so it found neither root and removed nothing. If the advisory's test site then answered, it printed
  EXPOSED (exit 1) and changed nothing; if the site didn't answer, it printed "SAFE … no longer holds the two roots"
  (exit 0) for a file that still trusted the keys. It now finds the two roots by their SHA-256 fingerprints, removes
  them whether or not the file has name lines (on Apple's file, byte for byte the advisory's removal, as before), and
  refuses a file with a certificate it can't read (UNKNOWN, exit 2, nothing changed). It also refuses a file holding
  blocks curl trusts but the fix doesn't read (`BEGIN TRUSTED CERTIFICATE`, `BEGIN X509 CERTIFICATE`): an emSign root
  appended in that form would otherwise have read SAFE with the test site unreachable. It works on a snapshot of the
  file and won't replace it if it changed meanwhile, it refuses a file it can't read, and its re-test ignores
  `~/.curlrc` (`curl -q`). `test/fix-macos.check.sh` gains the cases, counts the roots by fingerprint, and checks
  that each run prints nothing on stderr and leaves no temporary files; the new cases fail on the old script. The
  download on www.deimoscore.com changes with it (SHA-256 `50e1e41d…21b1`). The advisory's own one-line command has
  the same blind spot: on a file with no name lines it removes nothing.
- The Mac fix now says that a macOS update puts Apple's original file back (macOS 26.7.2 did, on 27 Oct 2026), so it
  should be run again after every update; its last line says `npx wardlatch@latest`, and it names the tools the file
  covers (the built-in curl, git, python3, openssl, perl and ruby) and that Apple's `pip3` has its own copy.

### Fixed

- **The workflow review read SAFE without having read every workflow in the window, in two ways (0.1.0 to 0.1.9).**
  Both came from giving git the window's start with `git log --since`.
  - *The start was a bare date.* The `github-actions-2026-10` incident gave the window's start as `2026-09-01`, passed
    to git as it was, and git reads a bare date as that day at the current time of day, in the zone git runs in: up
    to 0.1.8 the zone of the `TZ` Wardlatch was started with (the machine's when `TZ` was unset), which git got with
    the rest of the caller's environment, and in 0.1.9, which gives git no `TZ`, the machine's. So the window began on
    1 Sep at the hour the check ran: a workflow committed on 31 Aug, or on 1 Sep before that hour, was not read, and
    with nothing else found the review said "no workflow files added since 2026-09-01", SAFE, exit code 0. The sources
    say to check from 31 Aug (The Hacker News and StepSecurity, with no time zone), and GitGuardian reports a commit
    through the same compromised account at 00:30 UTC on 30 Aug. No test had a commit near the start of the window.
  - *git stopped reading at a back-dated commit.* Given `--since`, git stops following a line of history at the first
    commit dated before the start (its walk drops that commit before queueing its parents; only `--since-as-filter`,
    git 2.37 and later, doesn't). Whoever makes a commit sets its date, so one commit dated before the window, on top
    of a branch, hid every workflow added beneath it, however those were dated: on 0.1.9's code with git 2.54, a
    workflow committed on 10 Oct with a commit dated 1 Jan 2025 on top read SAFE, exit code 0; one beneath a
    back-dated commit with another workflow above it was left out; and a workflow on a side branch behind a
    back-dated commit, merged inside the window and the branch deleted, read SAFE. 0.1.9's known limits named this
    only for a later commit made on a machine with a wrong clock.
  - Also found while fixing this, each checked on 0.1.9's code with git 2.54. A commit whose committer date git can't
    read, on top of a workflow, did the same as a back-dated one (git takes it as 1970): SAFE. A workflow added on a
    side branch and removed again before the merge, all inside the window, read SAFE: given a path, `git log` follows
    only the parent a merge's files match and passed the side branch by. In a shallow clone cut inside the window, a
    workflow added and removed again below the cut was never seen (SAFE), and a workflow still there at the cut was
    listed as added by the cut commit, at that commit's date. Not a miss in 0.1.9: a replace ref (`refs/replace/`)
    couldn't put another commit in place of a workflow's commit (`GIT_NO_REPLACE_OBJECTS=1`, since 0.1.7; the commit
    the ref points to is read as one more commit), and a `.git/info/grafts` file wasn't read
    (`GIT_GRAFT_FILE=/dev/null`, in 0.1.9); both still hold.
  - The window now starts at 30 Aug 2026 00:00 UTC (`"since": "2026-08-30T00:00:00Z"`, with its sources in
    `sinceSource`). The review takes only an explicit UTC instant (`YYYY-MM-DDTHH:MM:SSZ`); anything else is
    UNKNOWN, never SAFE.
  - git gets no date at all. `git log --all --format='%H %ct'` lists every commit any branch, tag or other ref leads
    to, with its committer time in seconds since 1970, and the review keeps those on or after the start by comparing
    whole numbers in its own code. Then `git log --no-walk=unsorted --stdin` lists the workflow files that exactly
    those commits added: no walk, so no side branch is passed by, and only those commits are compared with their
    parents (a treeless partial clone with nothing in the window needs no tree, and reads SAFE as before).
    A committer time git prints that isn't a plain whole number (git prints none for a date it can't read) makes the
    repository UNKNOWN, never a commit left out. `--since-as-filter` would have kept the date in git, but needs git
    2.37, and Ubuntu 22.04 ships 2.34.1: every repository there would have read UNKNOWN.
  - A shallow repository is UNKNOWN, wherever its history is cut: "its history is cut (a shallow repository; the
    newest cut is commit …, dated 10 Oct 2026 12:00 UTC), so workflows added below the cut can't be seen: run git
    fetch --unshallow, then run again". Shallow means `git rev-parse --is-shallow-repository` says `true`, or the
    shallow file git reads (`git rev-parse --git-path shallow`) is there and not empty; one Wardlatch can't read is
    UNKNOWN too. A cut commit's date is no sign that the window is all there, because whoever makes a commit sets its
    date: an earlier cut of this fix read a history cut before the start as whole, so a `--depth 1` clone of a tip
    dated 2025, over a workflow committed on 5 Sep 2026, read SAFE, exit code 0, with the workflow file in the clone's
    own tree. A shallow file can also be written into a full repository, and git then reads nothing below the commits
    it names.
  - The SAFE line names the instant and the date it compares: "no workflow files added in commits dated on or after
    30 Aug 2026 00:00 UTC (committer date) in N local repositories". The date a review line shows is the commit's
    committer date in UTC, the date of the time the review compares: a commit made at 30 Aug 2026 00:00 UTC from
    UTC-7, where it was still 29 Aug, shows 2026-08-30. Up to 0.1.9 the line showed the author date, and an earlier cut
    of this fix the committer date in the commit's own zone.
  - The WordPress check's `addedSince` was already an explicit UTC instant; a test now holds the start of every
    incident's window to one.
  - *A file added more than once was listed at one commit (0.1.0 to 0.1.9, and this fix up to 3cff5c5).* The review
    kept one line per workflow file, at the earliest commit in the window that added it. A file added, deleted and
    added again with other contents was listed once, at the first commit: Alice adds `.github/workflows/ci.yml` on
    5 Sep and deletes it the next day, Mallory adds `ci.yml` again on 8 Oct, and the review showed only "added …
    2026-09-05 Alice". It now lists every commit in the window that added each workflow file, one REVIEW line (and one
    `--json` row, with the same `file` and `commit` fields) per file and commit, newest first: "added 4123d9f
    2026-10-08 Mallory", then "added 3fc2679 2026-09-05 Alice". With nothing added in the window, the SAFE line is
    unchanged.
  - Still not covered: a workflow whose own commit is dated before 30 Aug 2026 isn't listed, because whoever makes a
    commit sets its date (ASSURANCE_CASE.md, section 4). And a change to a workflow file that already existed isn't
    listed; the check lists added files, as the campaign added them: a commit that only changes a workflow committed
    before the window reads SAFE.
  - **What to do:** if 0.1.0 to 0.1.9 said SAFE for `github-actions-2026-10`, run a release with this fix again, or
    paste this line at the top folder of each repository, in a POSIX shell such as bash or zsh (it doesn't run as
    pasted in PowerShell or cmd). It has no date in it (given one, git stops reading a branch at the first commit
    dated before it) and reads what the review reads, in one command:
    `TZ=UTC GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL=none git --no-pager --work-tree=. --no-replace-objects -c core.commitGraph=false -c advice.graftFileDeprecated=true log --all --full-history --root --no-renames --diff-merges=combined --diff-filter=A --name-only --no-show-signature --date=iso-strict-local --format='%h %ct %cd %an' -- .github/workflows`
    It lists every workflow file that any commit of any branch, tag or other ref added, each under its commit's hash,
    committer time in seconds since 1970 (`%ct`), committer date in UTC (for convenience only) and author, whatever
    the date; a file added, deleted and added again is listed under each commit that added it, as the review lists
    it. **Review every line whose number (the commit time, in seconds) is 1788048000 or more, or isn't a plain
    number.** 1788048000 is the start, 2026-08-30T00:00:00Z. Compare that one integer and ignore the date text: for
    committer times too far in the future for git to turn into a date, git prints 1970-01-01T00:00:00Z or even a
    negative year, and those commits are in the window too. A line with no number and no date (three spaces after
    its hash) has a committer date git can't read: count it as in the window as well (the review reads the second
    kind UNKNOWN). As in the review, paths are read from the top of the folder the line runs in (`--work-tree=.`),
    whatever the repository's own `core.worktree` says (set to a folder above the repository, it made git read
    `.github/workflows` from the repository's place inside that folder, and the line up to ffacde4 listed nothing),
    a replace ref doesn't put another commit in a commit's place, a commit-graph
    file isn't used, a side branch a merge brings in is read, a root commit's files are listed whatever
    `log.showRoot` says, a workflow that only a merge commit adds is listed, one renamed into or within
    `.github/workflows` is listed as added, and nothing a repository's own config names is run: no signature is
    checked (the config can name the program that checks one), no pager is started (`core.pager`, `pager.log`), and
    nothing is fetched (in a partial clone, a fetch runs what the config names for the remote:
    `GIT_NO_LAZY_FETCH=1` stops it, and `GIT_ALLOW_PROTOCOL=none` refuses every transport for a git too old to know
    that; a partial clone without a tree the line needs stops with an error, where the review reads
    UNKNOWN). Five things the line can't get past: a `.git/info/grafts` file makes it unreliable (git follows the
    file, and no git option turns that off; the review doesn't read it; git's "hint: Support for
    <GIT_DIR>/info/grafts is deprecated" is the sign that one is there, and the line asks git to always show it); a
    `commondir` file in a `.git` folder makes git read the history of the repository it names instead (git puts one
    only in a linked worktree's folder under `.git/worktrees`; `ls .git/commondir` shows one, and the review reads
    that repository UNKNOWN); a `.git` file names the repository git reads, whichever it is (`cat .git` shows it;
    the review follows it too); a `GIT_DIR` set in the shell points git at that repository instead (`unset GIT_DIR`
    first; a `GIT_COMMON_DIR` or `GIT_OBJECT_DIRECTORY` there makes git stop with an error); and in a shallow clone
    what is below the cut isn't there to list (run `git fetch --unshallow` first).
  - Tests (`test/workflows.test.mjs`), each with a clean twin a second before the window or without the trick:
    workflows committed just inside the window (00:00:01 UTC on 30 Aug, 05:00 on 31 Aug at UTC+8, 09:00 UTC on 1 Sep,
    and the advisory's own file names, `github_actions_security.yml` and `security-audit.yml`, on 31 Aug) are listed
    with the command run under `TZ=Pacific/Kiritimati` and `TZ=America/Los_Angeles`; one committed at the start's own
    second, 30 Aug 00:00:00 UTC, from UTC-7, is listed with the date 2026-08-30 (that test runs once, with no `TZ`
    set); a back-dated commit on top, between two workflows, and on a merged and deleted side branch hides nothing; a
    workflow added and removed on a side branch is listed; a replace ref and a grafts file (cutting the history, or
    re-parenting the commit) hide nothing; a shallow repository is UNKNOWN wherever it is cut (inside the window or
    before it, at a back-dated tip over a workflow committed on 5 Sep, or by a shallow file written into a full
    repository, empty or not, even under a git that says the repository isn't shallow, or says it is with no shallow
    file), and so is one whose shallow file can't be read, while the same history cloned whole is read; partial
    clones whose remote is gone are read with nothing fetched (blobless: listed; treeless: UNKNOWN with commits in the
    window, SAFE without); a commit whose committer date git can't read, and a git that prints a committer time that
    isn't a plain whole number (empty, `x`, `-5`, `1.5`, `+1790000000`, ...), are UNKNOWN; a committer time past what
    a date can hold is listed; a start that isn't an explicit UTC instant (a bare date, another form, a day or hour
    that doesn't exist, a year past 9999 or before 0) is UNKNOWN; a git that writes down its arguments gets no
    `--since`, `--after`, `--until`, `--before`, `--max-age`, `--min-age` or `--since-as-filter`. And the "What to
    do" line above, found in this file wherever it is (a release moves it under its version's heading, and none or
    two fails) and run as written, must list every workflow the review lists, at the same commit and UTC date, in
    repositories with a replace ref, a crafted commit-graph file, a workflow only a merge commit adds, a root commit
    under `log.showRoot=false`, renames, a commit at the start's own second from UTC-7, one authored before the window
    and committed inside it, a workflow only on a branch that isn't checked out, a side branch that added and removed
    one, a signed commit under a config that names a `gpg.program` (which must not run), and a blobless partial clone
    whose remote is gone (nothing fetched); in a treeless one it must stop with an error, with nothing fetched; with a
    grafts file it must list them only before the window, as the line's own warning says; and for a commit whose
    committer date git can't read it must show no date. A git that writes down what it gets must get `--no-pager`,
    `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=none` from it (no run through a pipe can see the pager, and on git
    2.54 either setting alone stops the fetch). Its clean twins: a workflow committed a second before the window from
    UTC-7, and one authored inside the window but committed a second before it, aren't in the review, and the line
    shows each dated 2026-08-29T23:59:59Z, which a reader can tell is outside it. Far-future committer times (2^63-1,
    9223372036854775807, which git shows as 1970-01-01T00:00:00Z, and 67768000000000000 with the ends of its band,
    67767976233532800 and 67768036191676799, where git 2.54 shows a negative year such as -2147482895-02-16T20:26:40Z)
    are listed by the review and the line, and a reader who compares only the line's `%ct` number with 1788048000
    counts every one of them, while a commit at 1788047999 is skipped. The line an earlier cut of this
    entry gave fails that test, and so does this one with any one of its options left out but `--diff-filter=A`
    (without which it lists more). A workflow file added, deleted and added again inside the window is listed at both
    commits, newest first, by the review and by the line; its clean twins: two different files each added once are
    one line each, and a file added before the window, deleted, and added again inside it is listed only at the
    commit inside it. A workflow file only changed inside the window reads SAFE, and a test holds this entry,
    ASSURANCE_CASE.md and README.md to the sentence that says so.
  - Run on older code with this CHANGELOG, 23 of the 24 tests in `test/workflows.test.mjs` fail on 0.1.9's code (the
    24th reads only this file), 17 on this fix's first cut, which still gave git the start (44bb10f), and 10 on its
    second (865d0d1, the code at 3dbf26b: shallow repositories, the UTC date a line shows, the git calls made, and the
    hand check). Each planted bug fails at least one: the start given to git, as `--since` or `--since-as-filter`;
    the start's own second left out; the start's form not checked; no shallow check; a cut dated before the start
    taken as the window all there; git's answer or the shallow file alone taken as the sign; any committer time
    accepted; replace refs, grafts or a commit-graph file followed; one walk instead of two calls; the date in the
    commit's own zone; the hand check looked for only under `[Unreleased]`, or showing the author date. Those counts
    are of the 24 tests before the fix for a file added more than once; at 3cff5c5, with this CHANGELOG, the
    re-added file's test and the hand check's test fail (the review listed one commit), and so does the test of the
    documented limit without its sentence, while the two clean twins pass.
- **A repository's own config could make the workflow review (0.1.0 to 0.1.9) and the committed-keys check (0.1.1 to
  0.1.9) read SAFE without having read it.** A repository's `.git/config`, or its `.git/config.worktree` with
  `extensions.worktreeConfig`, can name another working folder: `core.worktree`. Set to a folder above the repository
  (`/tmp` for one under `/tmp`, or `../..`), git took the repository's folder as a subfolder of that one and read
  every path from there: `git log` found nothing under `.github/workflows` and `git ls-files` listed nothing. A full
  repository with a workflow committed on 5 Sep 2026 read "SAFE … in 1 local repository", exit code 0, and so did one
  with a committed key; the hand line above, as this entry gave it up to ffacde4, printed nothing. Setting it takes
  write access to the repository's `.git` folder; a clone can't carry it. Found by an independent check of this
  release with `core.worktree=/tmp`. Wardlatch now gives git the working folder on the command line,
  `--work-tree=<the folder it found>`, which wins over `core.worktree`, `core.bare` and `GIT_WORK_TREE`, so paths are
  read from that folder's top; the hand line gets `--work-tree=.`.
  - The same class, each checked with git 2.54 on 0.1.9's code and on ffacde4, with a workflow committed on 5 Sep: a
    `commondir` file written into a `.git` folder makes git read the refs and commits of the repository it names, and
    one naming an empty repository read SAFE. git writes a `commondir` file only in a linked worktree's own folder
    under `.git/worktrees`, and a linked worktree's `.git` is a file, so a `.git` folder whose history git reads from
    anywhere else is now UNKNOWN, for the workflow review and the committed-keys check ("git reads its history from
    …, which a commondir file in its .git folder names …"), and so is a `.git` folder git doesn't take as the
    repository at all (an empty one inside another repository, where git reads the outer one; an earlier cut of this
    fix, 7bdca07, had the keys check list the outer repository's files under the inner folder, files that aren't
    there). The `.git` folder is compared with git's by what it is on disk (device and inode), not by how its path
    is spelled: on macOS, `--paths` in another case, or in NFC for a name stored as NFD, names the same folder while
    git prints the name on disk, and 7bdca07, which compared the strings, read such a clean repository UNKNOWN.
  - Not a miss before, on either: `core.worktree` naming a folder that isn't above the repository, or set through
    `include.path`, `includeIf` or `-c` (git takes it only from `.git/config` and `config.worktree`); `core.bare=true`
    in the `.git` folder of a repository with its files beside it (but see the bare layout below);
    `diff.relative`, `log.follow`, `diff.noprefix`, `log.diffMerges`, `diff.renames`, `core.ignoreCase` and
    `core.precomposeUnicode`, each on its own (`diff.relative` and `log.follow` hid a workflow only together with a
    `core.worktree` above the repository, which hid it anyway); and, from the caller's environment, `GIT_DIR`,
    `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_SHALLOW_FILE`, `GIT_OBJECT_DIRECTORY`,
    `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_LITERAL_PATHSPECS`, `GIT_GLOB_PATHSPECS`, `GIT_NOGLOB_PATHSPECS`,
    `GIT_ICASE_PATHSPECS`, `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`, none of which git gets (`lib/run.mjs`'s
    allowlist). `GIT_CONFIG_GLOBAL`, which git does get, names the person's own config, and `core.worktree` there is
    not used either.
  - Not covered, before or now: a workflow under a folder whose name differs only in case, such as
    `.GitHub/Workflows`, isn't listed, whatever `core.ignoreCase` says (git compares each commit's paths exactly).
    Whether GitHub runs a workflow from such a folder hasn't been checked. A `.git` file is followed as git follows
    it, whatever repository it names: one naming an empty repository reads SAFE for both checks (0.1.9, ffacde4 and
    now), and so does, for the workflow review, one naming a folder whose `commondir` file names an empty
    repository. No rule based on the layout tells those apart from clean ones: `git clone --separate-git-dir`
    writes a `.git` file naming a repository that has no pointer back to it, and the pointer back a linked worktree's
    folder holds is a file anyone who can write the `.git` file can write too (and a worktree moved by hand has a stale
    one). A check that compares the workflow files on disk with the tree of the commit checked out could, and is
    planned for a later release. `cat .git` shows which repository a `.git` file names. This case is out of scope
    because whoever can write to a repository's `.git` can hide a workflow without any trick of layout, for example
    by deleting the branch ref that leads to it, and every version reads SAFE then. And in the
    bare-repository-with-worktrees layout (a `.bare` folder,
    a `.git` file saying `gitdir: ./.bare`, and each worktree in a subfolder), the search stops at the outer folder,
    as for any repository: the workflow review reads its history, but the committed-keys check scans no worktree's
    files and reads SAFE (as in 0.1.9). Pass a worktree's own folder with `--paths` to scan it.
  - Tests. `test/workflows.test.mjs`: a workflow committed on 5 Sep in a repository whose `core.worktree` names the
    folder above it (absolute, as `../..`, in `config.worktree`, and with `diff.relative` and `log.follow` on top) is
    listed, and so with `core.bare=true`; each but `core.bare` first shows that git as it runs by default lists
    nothing, and each has a clean twin, the same setting with the workflow a second before the window, which reads
    SAFE, not UNKNOWN. A linked worktree and a submodule's own folder (where git sets `core.worktree` itself) are
    listed as before. A `commondir` file naming an empty repository is UNKNOWN, and so is an empty `.git` folder
    inside another repository; without the file the repository is listed, and the outer one reads SAFE. On a file
    system that takes them as one folder (macOS), `--paths` in another case (`casedir` for `CaseDir`) and in NFC for
    a name stored as NFD lists the workflow, from the folder above and from the repository's own; clean twins, SAFE.
    Every git call gets `--work-tree=` the folder it gets as `-C`. The hand line must list the workflow in three
    `core.worktree` repositories too (above the repository, in `config.worktree`, and with `diff.relative` and
    `log.follow`). `test/cli.test.mjs`: a committed key under `core.worktree` (in `.git/config` and in
    `config.worktree`) is found, clean twin SAFE; a `commondir` file naming an empty repository and an empty `.git`
    folder inside another repository are UNKNOWN for the keys check, and without the file, and from the outer
    folder, the key is found; `--paths` in another case or in NFC for NFD finds the key, clean twins SAFE. Run with
    this CHANGELOG: on ffacde4's code 6 of these tests fail (both `core.worktree` tests, both `commondir` tests, the
    git-arguments test and the hand check's, which compares with the review), while the linked-worktree, submodule
    and spelling tests pass; on 7bdca07's, 3 (the keys `commondir` test, the workflow spelling test, and the
    workflow `commondir` test for its reason's wording); with `--work-tree` left out of `lib/git.mjs`, 4; with the
    own-`.git` check comparing path strings, both spelling tests; with it left out of the keys check, the keys
    `commondir` test; with it left out of both, those two `commondir` tests and the git-arguments test; and with
    `--work-tree=.` left out of the hand line, the hand check's test.

### Changed

- **A shallow clone reads UNKNOWN for the workflow review, exit code 2.** That includes the usual CI checkout:
  `actions/checkout` fetches a single commit (`fetch-depth: 1`) unless told otherwise. 0.1.9 read a shallow clone as
  if its history began at the cut. To check a repository in CI, check it out with `fetch-depth: 0`; on your own
  machine, run `git fetch --unshallow` in it first.
- **The workflow review reads each repository's whole history on every run.** On the maintainer's Mac (Apple M5 Pro,
  git 2.54), the whole command on one repository took 0.5 s for 100,000 commits (0.06 s when 0.1.9 stopped at the
  start), 0.8 s for 100,000 commits with 9,800 workflow files added over time (0.4 s before), and 7 s for 1.56 million
  commits (0.1 s before); an independent check measured 0.44 s and 7.1 s for the first and last. The list of commits
  takes about 52 bytes each, and up to 256 MB is read (about 5 million commits; 0.1.9's first cut read 64 MB and so
  lost its findings past about 1.3 million). Each git call stops after 20 seconds: a repository with millions of
  commits on a slower machine can reach that, and then reads UNKNOWN ("git did not finish in time"), never SAFE; one
  that prints more than that is UNKNOWN too ("git wrote more than could be read").

### Development (no code in the package changes)

- The tests never look in the home folder of the person running them (where macOS keeps Desktop, Documents, Downloads,
  Library, Photos and Mail): every test file loads `test/support/no-real-home.cjs` first, which refuses any look there
  by Node (fs in every form, globs, streams, `require()` and, from Node 22.15, `import` (of a file, a package name or a
  `#` name), a change of folder, a program, working folder or `PATH` folder there, a `.env` file `process.loadEnvFile`
  reads, a `node:sqlite` database there, a Node started with `--env-file` or a config-file flag naming a file there, and
  a walk that can reach it), in the test, in every Node process it starts at any depth and in each Worker thread they
  start; a refusal in a process the test started fails the test even when nothing reads that process's exit code. It is
  not a sandbox: code written to get past it can. Paths are compared as the system reads them (links and `..` followed,
  but the link a path names last for `lstat`, `readlink`, `unlink`, `rmdir`, `rm`, `lchown` and `lutimes`, and on macOS
  in any case and under the start-up disk's other names, by their text too), and under sudo SUDO_USER's home is off
  limits too. It drops the home's folders from the `PATH` the tests start with. The sudo test and the two tests of
  macOS's own Library build a `/Users/<name>` home of their own (`test/support/fake-home.cjs`); `test/cli.test.mjs`
  gives the command an empty HOME of its own and none of the runner's `XDG_*`, `GOENV` or `GOTOOLCHAIN` (on a CI runner
  `XDG_CONFIG_HOME` sent the go check into the runner's home), and the version test gives the go check one.
  `test/no-real-home.test.mjs` tries each route the net watches on a made-up home. What it can't
  stop: a program that isn't Node (and a Node one starts below the command), and macOS's own read of
  `~/.CFUserTextEncoding` as any process starts (CONTRIBUTING.md, Testing policy).

## [0.1.9] - 2026-10-23

A fixes-only release: no new incident checks. Every item below was found by a root-cause audit of all releases from
0.1.0 to 0.1.8, and each kind of mistake is now held back by a rule the test suite enforces, not just by the fix.

### Security

- Advisories: [GHSA-766p-78h4-77gr](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-766p-78h4-77gr) (forced-roots refusal read as a block, 0.1.4–0.1.8),
  [GHSA-gxqr-jm2v-mcm8](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-gxqr-jm2v-mcm8) (container failures read as refusals, 0.1.2–0.1.8) and
  [GHSA-9m5q-pvx5-fp26](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-9m5q-pvx5-fp26) (parts not examined left out, 0.1.0–0.1.8).
- **A forced-roots refusal for any reason read as the runtime's own block, the strongest SAFE.** Since 0.1.4 a runtime
  that couldn't connect with the compromised roots forced in, but could open a normal site, was reported as blocking the
  compromised keys itself. A TLS-inspecting firewall, a DNS filter answering for the test hosts, a hostname mismatch or
  an expired test certificate made every runtime read SAFE. Now only Node's own block (`CERT_REVOKED`, which Node
  26.12.1, 24.22.1 and 22.23.4 give for these keys) counts; any other failure is UNKNOWN, and curl, which has no block
  of its own, never counts. The test hosts must also present the compromised chain's issuer (`EM DV/OV/EV TLS CA -
  G3B/G3C`), so something answering in their place is reported, not tested. macOS's own stack: a certificate date error
  (-1201, -1204) is no longer read as a refusal.
- **Inside containers, any failure counted as a refusal.** The probe script exited 1 for a timeout or a DNS failure as
  for a certificate refusal, so a container that couldn't reach the test hosts read SAFE (the host probe stopped doing
  this in 0.1.7). Now only curl 60, Python's certificate error and wget 5 are refusals; anything else is UNKNOWN.
- **Folders Wardlatch couldn't open were skipped silently, and nothing searched still read SAFE.** A folder it couldn't
  open is now reported by who owns it, one rule for every check (`lib/owners.mjs`): one a person owns (it could hold
  their projects or sites: this user, or any login account, uid 1000 and up on Linux and 501 and up on macOS, a company
  directory's included; for WordPress, the web server's account too) is UNKNOWN; one a service owns (root, a database,
  "nobody", a rootless container's uids) is named in one REVIEW line, which doesn't change the exit code. A searched
  folder itself (a `--paths` folder, `/var/www`), or something already found or known (a virtual environment's own
  folders, `~/.local/lib`, a temp folder), that can't be opened is always UNKNOWN. For WordPress, a locked dot-folder
  below a root (www-data's `.ssh`) is listed for review whoever owns it. A `--paths` folder that doesn't exist is UNKNOWN (exit 2), not "SAFE, 0 repositories"; with no `--paths`
  and none of the usual folders on the machine (a fresh server, a CI runner), the check is SAFE and lists the folders
  it looked for.
- **Environment allowlist.** Every program Wardlatch runs gets an environment built for its purpose from an allowlist
  (`lib/run.mjs`), not the caller's environment: `DEVELOPER_DIR` still redirected macOS's `/usr/bin/git` shim after
  0.1.8's `GIT_*` fix, and `NODE_OPTIONS --require` ran inside the trust probes. `DOCKER_HOST` and `CONTAINER_HOST`
  are followed only to a local socket the person or root owns (Colima, Podman, rootless Docker); a remote one, and
  `DOCKER_CONTEXT`, `DOCKER_CONFIG` and `CONTAINER_CONNECTION`, are not, and when one is set and an engine is installed
  an UNKNOWN row says so. Since the second review a trust
  probe's environment is an allowlist too: the first cut still dropped a list of names, and `OPENSSL_CONF` loaded a
  module into the probe, and `SHELLOPTS` with `PS4` ran a command inside a version manager's bash shim.
- **A container that stopped mid-check read SAFE.** `docker exec` itself exits 1 when the container has stopped, the
  code the probe used for a refusal. The result is now read from a line the probe prints, never the exit code.
- **A runtime that trusted only one of the two roots read SAFE when that root's test hosts were down.** Each test host
  now names the root its chain ends at, the forced-roots control runs on a host for each root with only that root
  forced in (with both, a chain could finish at the other root), and a runtime or container is SAFE only when every
  root had a host that answered.
- **A trust setting the probe doesn't get could leave a SAFE that wasn't tested.** A CA added through `NODE_OPTIONS
  --require` (mac-ca, syswide-cas) or `OPENSSL_CONF` is now an UNKNOWN row (options that add no trust, such as
  `--max-old-space-size` in either spelling, don't count). A trust probe also gets `NIX_SSL_CERT_FILE`, and the
  person's `CURL_HOME` and `XDG_CONFIG_HOME`, so the probe's curl reads the start-up file the person's curl reads.
  The person's own `NODE_TLS_REJECT_UNAUTHORIZED` reaches the Node probe, so a Node run with checking off reads
  EXPOSED.
- **A `DOCKER_HOST` not followed, while a local engine answered, read SAFE in the LiteLLM image check**, which never
  looked at the engine it named. It is UNKNOWN there too.

### Fixed

- Temp markers: the macOS per-user temp folder is searched even when `TMPDIR` is unset (sudo, cron, launchd), and under
  sudo the person's own home folder is searched, not root's.
- Copies of a program on `PATH`, one rule for the trust check and the version checks: the first (the one the shell
  runs) and every later copy that is a compiled program are run and judged (a fixed php first no longer hides a
  vulnerable one); a later copy that is a script is named in a REVIEW line (in `--json` too), never run for the first time
  by Wardlatch.
  "Not installed" now says it searched `PATH`.
- The workflow review lists a workflow that only a merge commit adds (git's combined view: merging main into an old
  branch doesn't list main's workflows again), ignores grafts and the commit-graph file, and never shows git's own
  hints as the reason a repository couldn't be read.
- The header check reads more of the files curl and git read: CRLF files, `$CURL_HOME/.curlrc`, `$CURL_HOME/.config/curlrc`, `~/.config/curlrc`, the
  file `GIT_CONFIG_GLOBAL` names, `WGETRC`, `NPM_CONFIG_USERCONFIG` (not all of them: see Known limits).
- Three false SAFEs found in the last checks before release, all in 0.1.8 too: a Plex Media Server in any dpkg state
  but plain "installed" (held with `apt-mark hold`, marked for removal, unpacked, half-configured, waiting on triggers)
  read as not installed, though its files were on disk (half-installed is now UNKNOWN); a PHP release candidate or `-dev` build of
  a fixed version (`8.4.27RC1`, older than the fix) read as fixed; and a virtual environment's certifi bundle on a
  machine with no curl to test it with was dropped without a line (now UNKNOWN). A fourth, from the same checks: the PHP
  check judged only the program called `php`, so on a server with several PHP versions an old `php8.1`, and the
  `php-fpm8.1` serving the sites, read SAFE; versioned `php`, `php-fpm` and `php-cgi` programs on `PATH`, in the `sbin`
  folders and in macOS Homebrew's `php@*`, Remi, cPanel and Plesk install folders are now each judged (one file reached by two
  names, once; a later copy of a name that is a script is not run).
- Bounded work: hand-written parsers instead of patterns that backtracked (a planted line took 22 s), a capped JSON walk
  and a 1 MB cap on a repository's config files (a planted 16 MB `.mcp.json` took 1.4 GB), every file read through one
  reader that never blocks on a FIFO, and every program killed with SIGKILL at its timeout.
- Every SAFE line is a result row in `--json` too, with the list of what it searched (`searched`). A SAFE row without one
  becomes UNKNOWN in `--json` and the exit code, however it was made, and a line under the output withdraws it.
- The header check: a missing `--paths` folder, a folder it couldn't open, or a config nested deeper than it reads is
  UNKNOWN, not SAFE. A settings file this user can't open (so their own tools can't read it either) is not used, and
  one set to `/dev/null` (CI's way of switching it off) is empty. A `--paths` entry that is a file is UNKNOWN in every
  check that searches folders.
- A virtual environment whose `lib` folder couldn't be opened is an UNKNOWN row, not dropped.
- The WordPress indicator search says what its caps left unsearched (files over 2 MB, past 4,000 files, deeper than 12
  levels): UNKNOWN, not SAFE.
- Under sudo, git keeps `SUDO_UID`, so the person's own repositories aren't refused as "dubious ownership"; a sudo user
  whose home folder isn't found (including a directory name such as `ada@corp.example`) is an UNKNOWN row, not a silent
  search of root's home, in the checks that read the home folder.
- A crash inside Wardlatch exits 2 (could not be tested), not 1 (exposed), unless an EXPOSED line was already printed.
  A container's probe output counts only with exactly one result line.
- File reads are capped by what is read, not only by the size reported at open.
- The key scan reads every tracked text file up to 512 MB (0.1.8 skipped files over 512 KB, and unreadable ones, without
  a word): past 8 MB in overlapping pieces that end at line breaks, so a key is never cut in two and each match is
  counted in exactly one piece. A placeholder word (`example`, `fake`) counts only right next to a key, never anywhere on
  its line (one `example.com` on a minified line hid every key on it). It reads git's own record of each file: a
  committed link is not followed (git stores the target's name, not its contents), and an empty tracked file in a folder
  that can't be opened (a `.gitkeep`) is not reported.
- macOS's own folders (its Library at `/`, in `/System` and in a home folder, the Trash, the Photos libraries) are never
  searched; any other folder named Library is (0.1.8 skipped every Library folder). A trust probe also gets `CURL_SSL_BACKEND`, which picks macOS
  curl's trust store.
- From the bug hunt before release (a red team's 75 scenario tests and 614 planted bugs; `test/bughunt-0.1.9.test.mjs`):
  - **False SAFEs:**
    - Podman refusing its socket (permission denied) read as "not running" in the image check, so the run could end SAFE.
      One rule now classifies engine failures for running containers and local images alike.
    - A Bedrock site (core in `web/wp`, plugins in `web/app/plugins`), or WordPress in its own directory with
      `wp-content` one level up, was never found: "no WordPress installs found". Every plugins folder a site can use,
      and leftover ones beside it, is checked now, not only the first found (a core still holding its bundled
      `wp-content` beside the live one read SAFE about the wrong plugins). Wardlatch doesn't read PHP (owner, 23 Oct):
      when the wp-config.php WordPress reads names `WP_CONTENT_DIR` or `WP_PLUGIN_DIR` anywhere, when Bedrock's
      `config/application.php` (past its stock lines) or `config/environments/*.php` names `CONTENT_DIR` or
      `WP_PLUGIN_DIR`, or
      when one of those files can't be read, the site is UNKNOWN: its plugins may be elsewhere. So is a core with no
      content folder in any of those places.
    - A site inside another site's folder (`public_html/blog`) was never searched: the search stopped at the first.
    - A key in a tracked file deleted from the working tree (still in the index, HEAD and every push) was skipped. git's
      own copy is scanned now, in a few git runs however many there are. A file marked skip-worktree that is on disk is
      scanned like any other.
    - A key in a UTF-16 file with a byte-order mark (PowerShell 5's `Out-File`) was skipped as binary.
    - A real key with an example key (of any kind) beside it on the same line was taken for a placeholder.
    - curl's `-H @file` (`header = "@file"`, `-H@file`) was checked as a file name, never as the headers in the file.
      The file is read now; one named by a relative path is UNKNOWN, and one curl couldn't read either sends nothing.
    - `.curlrc` lines with short options in a cluster (`-sH "From: …"`, `-sA …`) or an attached value (`-HFrom:…`),
      `proxy-header`, curl 8.3's `expand-` forms, and the config files a `config =`, `expand-config` or `-K` line
      brings in (`-K file`, `-K/file`, `-sK file`) were not read. They are now, on the safe side (owner, 23 Oct): your name or email anywhere after a header
      option counts, with backslash escapes undone. curl variables (a `variable` line, or `{{name}}` in an `expand-`
      line), which can build a header from pieces, are UNKNOWN. Brought-in files are read once per use, at most 32 of 1 MB.
      File names are read as curl reads them: split only at ASCII white space (a no-break or narrow space is part of
      the name), with escapes undone only inside quotes.
    - The bundle `REQUESTS_CA_BUNDLE` names (what requests and pip trust in place of certifi) was never tested. It is
      tested now, and is UNKNOWN when there is no curl to test it with, when it names a folder, or when it can't be
      opened.
  - **Not tested, now said:**
    - Docker Desktop or a Podman machine stopped: its local images couldn't be listed, and only a note said so. It is a
      REVIEW line now (owner, 23 Oct; the exit code doesn't change, since a quit Docker Desktop is normal on a laptop).
    - On Linux with neither curl nor python3, the distribution's CA bundle went untested without a line: UNKNOWN now
      (owner, 23 Oct). With python3 there, python3 tests that bundle.
  - **False UNKNOWNs:**
    - `DOCKER_HOST` naming a local socket that is gone (Colima or a Podman machine stopped) read as an unfollowed host.
      It is "not running" now, when the socket's folder is there, is this user's or root's, and no one else can write
      to it.
    - A JSON-with-comments file whose last setting is commented out after a trailing comma (VS Code writes these) read
      as invalid.
  - **Options and wording:**
    - `--paths ""` and `--incident ""` (an unset variable in a script) are refused, exit 2: an empty `--paths` searched
      the current folder.
    - `--incident` can be given more than once: 0.1.8 checked only the first.
    - A WordPress site found with none of the listed plugins said "no WordPress installs found"; it now says how many
      were found.
    - A README sentence about the operating system's trust was cut off.

### Known limits

- The issuer check compares the issuer's common name, not a fingerprint: something on the network that copies the name
  gets past it (the forced-roots control still catches it for curl, Node and Python, not for macOS's own stack or
  containers).
- The workflow review reads commits dated on or after the incident's date: a commit given an earlier date isn't seen,
  and git stops reading a branch at a commit dated before it, so a correctly dated workflow behind a later commit from a
  machine with a wrong clock can be missed too. (0.1.9's first cut read the whole history to catch that, and lost its
  findings on repositories past about 1.3 million commits; taken out, owner, 22 Oct.)
- The key scan and the workflow review stop at the first repository they find, as 0.1.8 did: a repository nested inside
  another one, a git worktree placed inside one, and submodules are not read.
- A later copy of a program on `PATH` that is a script, not a compiled program, is not run, so its version isn't judged.
- A folder that can't be opened and whose owner can't be read counts as a person's: UNKNOWN.
- A PHP install folder that is closed (an admin's locked `/opt/remi`) is UNKNOWN once for each pattern that reaches it
  (bin and sbin: two lines for one folder), with the reason written for a program file.
- A locked folder on the way to a known install place (a vendor's folder under `/opt` or `/srv`, a `python3.X`, a
  `git` user's home holding `/home/git/gitlab`) is UNKNOWN whoever owns it, and the line names the place Wardlatch was
  looking for, which may lie below the locked folder. On a server with a `git` user whose home is closed, the GitLab
  check reads UNKNOWN even with no GitLab installed: run it with sudo.
- The header check doesn't read git's system config (`/etc/gitconfig`, `GIT_CONFIG_SYSTEM`), files a git config
  includes (`include.path`, `includeIf`), or `/etc/wgetrc`: a header set only there isn't seen. The SAFE line's receipt
  lists the files it read.
- A site folder owned by root that this user can't open (a hardened `root:www-data 750`) is a service's by the rule:
  listed for review, not UNKNOWN; run Wardlatch with sudo on a web server to include such sites.
- A file of Wardlatch's own that fails to load (a broken install) exits 1, before anything of Wardlatch's runs.
- Runtimes are run from `/` with the person's default selection: a version chosen per shell or per project
  (`PYENV_VERSION`, `.nvmrc`, `.tool-versions`) is not followed, so the runtime tested can differ from the one a project
  uses.
- The engine is the one the person's own docker or podman configuration selects (their home folder's config), which can
  name a remote host, or a local socket `DOCKER_HOST` names; a remote `DOCKER_HOST` and the like are not followed.
- Inside containers, a refusal of the test hosts can't be told from a DNS filter or TLS-inspecting proxy on the
  containers' network that answers for them with its own certificate (the issuer check covers the host's network only).
- Searches don't reach: PyPy environments (`lib/pypy3.x`); OpenLiteSpeed's `lsphp` and DirectAdmin's `/usr/local/php*`
  installs; repositories in hidden folders, more than 4 levels down, or linked in by a symbolic link; and a site linked
  into a web root by a symbolic link. A `~` written literally in `PATH` (which the shell expands) is dropped with the
  other relative entries.
- A UTF-16 file without a byte-order mark is skipped as binary, and a UTF-16 file over 8 MB is UNKNOWN (it isn't read
  in pieces). Files a sparse checkout leaves out of the working tree (skip-worktree, not on disk) are not scanned, as in
  0.1.8.
- WordPress: a site whose wp-config.php names `WP_CONTENT_DIR` or `WP_PLUGIN_DIR` anywhere (even in a comment, or to
  use it rather than move it) is UNKNOWN, since Wardlatch doesn't read PHP; so is a Bedrock site whose config names
  `CONTENT_DIR` beyond its stock lines (even an environment file setting `/app` again; its `WP_CONTENT_URL` line counts
  as stock only in the exact forms Bedrock shipped, 1.0.0 to today). A move made outside the files
  read is not seen: in a file wp-config.php brings in with `require` or `include` (a `wp-config-local.php`), through
  `eval` (the Docker image's `WORDPRESS_CONFIG_EXTRA`) or PHP's `auto_prepend_file`, with a changed Bedrock
  `$webroot_dir` or `$root_dir`, or under a constant name built from pieces. A `config/` folder beside a core that can't
  be opened, or whose `environments/` can't be opened or listed, is a doubt even when it isn't Bedrock's (UNKNOWN). A wp-config.php over 1 MB is UNKNOWN. Must-use plugins
  (`mu-plugins`) are not checked, and the indicator search doesn't enter a linked folder inside a plugin. Leftover plugins folders beside a site are checked too, so a stale copy of a
  plugin can read EXPOSED: its files are still on the web server.
- `.curlrc` is read on the safe side, not as curl parses it: a line with a header option and your name or email after
  it is EXPOSED even when curl refuses the line or sends only part of it (an unquoted value is cut at its first space;
  `--header=x` and an attached value followed by another word are refused; a later `-A` replaces an earlier one; long
  names in capitals are refused by curl 8.7 but were taken by older curl). Fix or remove such a line. Abbreviated long
  option names (`user-agen`, which older curl took) are not read; `cookie` and `referer` lines are outside this check;
  a `-K` inside a cluster with its file attached (`-sKfile`) is not followed. Start-up files some curl versions read
  and 8.7.1 doesn't (`$XDG_CONFIG_HOME/curlrc`) are read too, on the safe side.
- `DOCKER_HOST` naming a socket whose folder is gone too (a stopped Podman machine's after a reboot) is not followed:
  UNKNOWN, as for a remote host. Start the engine, or pass `--no-containers`.
- A later copy of a program on `PATH` that can be run but not read (mode 111) is taken for a script: named for review,
  not run.
- `--paths` given for a folder and a folder inside it reports a finding in the inner one twice, and `--list --json`
  prints text.

### Changed (rules the tests now enforce)

- Only `lib/run.mjs` starts programs; only `lib/files.mjs` touches the file system; only `lib/report.mjs` makes a SAFE,
  and only with a receipt. `test/contract-0.1.9.test.mjs` (written before the fixes, independently) holds all three.

## [0.1.8] - 2026-10-22

### Added

- **GitLab CVE-2026-110264** (`gitlab-2026-10`): the version read from GitLab's own files, judged per release line;
  18.10 and older have no patch; a fixed self-compiled install is REVIEW (it also needs GitLab's Ruby patch).
- **LiteLLM 1.107.0** (`litellm-2026-10`): the release record and the files it drops in site-packages (`cook.pth` and
  `cook.py` by name, `sitecustomize.py` by SHA-256) across system, Homebrew, user, pyenv, conda, pipx, uv, Poetry and
  Pipenv installs and virtual environments; the stealer's markers in the temp folders; local images by digest, by the
  published digest prefixes or by the `v1.107.0` tag. Python is never started for this.
- **Plex Media Server** (`plex-2026-10`): the version from the Debian package record or the macOS app; 1.43.3.10861 and
  later are fixed.
- The `installs` check type (`lib/installs.mjs`): installed software is read, never run.
- `identity-headers-2026-10`: agents that tell websites who you are. Finds your name or email, or any email address, in the header settings your tools send (curl and wget start-up files, git's http.extraHeader and http.userAgent, npm's user-agent, coding-agent and MCP client configs, `*_HEADERS` variables). Read-only; values are never printed.

### Security

- Advisory: [GHSA-84hq-29mv-c9fj](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-84hq-29mv-c9fj).
- **A git environment variable could point the git checks at another repository, and they read SAFE.** Run where
  `GIT_DIR` or `GIT_WORK_TREE` is set (inside a git hook, or a CI step that sets them), 0.1.0 to 0.1.7 ran every
  `git log` and `git ls-files` against that one repository instead of each repository found, so the GitHub Actions
  review and the committed-key scan reported a repository clean without having read it (exit code 0). Other `GIT_*`
  variables (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_EXEC_PATH` and the like) could set config or name
  programs the `-c` overrides don't cover. 0.1.8 drops every `GIT_*` variable before running git, except the three that
  only choose your own global and system config files and `GIT_TEST_ASSUME_DIFFERENT_OWNER`, which can only make git
  refuse a repository. Found by a new test in our own review; a test sets `GIT_DIR`
  and `GIT_CONFIG_PARAMETERS` and expects the real repository to be read and nothing to run.

### Fixed

- A version with a suffix (`19.4.2-ee`, Plex's `1.43.3.10861-07dfddaeb`) is compared by its leading number; such a
  part used to compare as equal, which could read a vulnerable version as SAFE. A pre-release of a fixed version is
  older than the fix.
- On Windows, which is not supported yet, the installed-software checks report UNKNOWN instead of SAFE.
- From the release review: a folder Wardlatch can't open (another user's home, a root-owned virtual environment, a
  locked site-packages) and a `sitecustomize.py` it can't read are UNKNOWN, never "not installed"; a planted config
  that is deeply nested, huge or holds a very long value can no longer crash or stall the header check (iterative
  walk, depth and size caps, a bounded email pattern, and one bad file is UNKNOWN while the rest are still read); wget
  settings are read in any spelling (`useragent`, `user-agent`), Codex's `[..._headers]` tables are read, curl's `-a`
  and `-h` are no longer taken for headers, and only a value's own key or the key right above it makes it a header; a
  local image without a repository digest is still matched by its tag. Each has a regression test.
- From the red-team audit (also in 0.1.7 and earlier): a planted FIFO as a virtual environment's certifi `METADATA`
  or `__init__.py` hung the run (those two files are now read like every other, regular files under a size cap only);
  `--json` now escapes DEL and C1 control characters from names on disk, as the text output already did.
- OVHcloud's temp-folder marker is matched with any number of digits.
- Release: the workflow checks the attestation bundle (present, one bundle, and `gh attestation verify` for both files,
  bound to this workflow) before it publishes a release, so a change in the attest action can't ship a release without it.
- Tests for branches the suite didn't reach: GOTOOLCHAIN's last line winning and `GOENV=off`; each folder in
  `SSL_CERT_DIR` made absolute; Python and curl failures that aren't certificate refusals; `sitecustomize.py` never run
  (skipped where the distribution's own sitecustomize is imported first, as on CI's Ubuntu); `.` and empty `PATH` entries; `core.fsmonitor` through `include.path`, `includeIf` and
  the worktree config; a program whose version or file can't be read.

## [0.1.7] - 2026-10-22

### Security

- Advisory: [GHSA-xcqr-prh6-6g8w](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-xcqr-prh6-6g8w).
- **Wardlatch no longer runs Python's start-up files.** At start-up Python runs every `.pth` file and any
  `sitecustomize.py` in its site-packages, and a malicious package can put code there: LiteLLM 1.107.0, compromised on
  PyPI on 21 October 2026, ships `cook.pth` and a `sitecustomize.py`. The eMudhra check started each `python3` on `PATH`
  and `/usr/bin/python3` with `-I`, which does not stop this. So with 0.1.0 to 0.1.6, if that interpreter's own
  site-packages held a malicious `.pth` (in an activated virtual environment, a conda environment, a pyenv version or
  Homebrew's Python, for example), running Wardlatch ran it. 0.1.0 to 0.1.2 also started the `bin/python` of each
  virtual environment found under the searched folders, which ran that environment's `.pth` files. That `bin/python` did not have to be
  Python: any program a cloned repository put there was run (fixed in 0.1.3; [GHSA-383w-hfwc-vx2h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-383w-hfwc-vx2h)). 0.1.2 to 0.1.6 ran
  `python3` without `-I` inside running containers that had no `curl`, which ran the `.pth` files of the image's
  Python, its user site-packages included; a running container from LiteLLM's own images (pulled on 21 October
  between 11:46 and 14:20 UTC) would be such a case if it had no `curl`. On the host, a copy installed with `pip install --user` was not run, because `-I` leaves out
  the user's site-packages. 0.1.7 runs `python3 -I -S`, on the host and in containers: `-S` skips the `site` module,
  and with it every `.pth` file and `sitecustomize.py`. A container's `python3` older than 3.4, which has no `-I`, is
  UNKNOWN. Found in our own review; a test plants a marker `.pth` in a real virtual environment and fails if the probe
  runs it. If one of those Pythons held LiteLLM 1.107.0, every start of it ran the stealer, Wardlatch's included:
  follow LiteLLM's advisory.
  The trade-off: a `.pth` file or `sitecustomize.py` that changes how Python trusts certificates (pip-system-certs, for
  example) no longer applies to the probe, and, as before, the `certifi` in the own site-packages of a Python on `PATH` is
  not tested yet (a virtual environment's is). A Python whose code uses an old `certifi` that way can read SAFE here; the
  certifi check for those is planned.
- Advisory: [GHSA-x8rh-w6q6-4r3h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x8rh-w6q6-4r3h).
- **A repository's own git config can no longer make Wardlatch run a program, and git never fetches.** The workflow
  review runs `git log` (since 0.1.0) and the committed-key scan runs `git ls-files` (since 0.1.1) in each repository
  under the searched folders, and git reads that repository's `.git/config`. With 0.1.1 to 0.1.6, a repository whose
  config set `core.fsmonitor` had that program run by `git ls-files`; with 0.1.0 to 0.1.6, one whose config set
  `log.showSignature` and
  `gpg.program` (or `gpg.ssh.program` or `gpg.x509.program`), with a signed commit that added a workflow file since 1
  September 2026, had that program run by `git log`. In a partial clone (`--filter=tree:0`, or `blob:none` when a
  workflow renamed within the folder needed its contents), `git log` fetched the missing objects from the clone's own
  remote, such as github.com, with your usual SSH key or credential helper, and wrote what it fetched into that
  repository's `.git/objects`: a request and a change Wardlatch promises never to make, and ones that needed no crafted
  config. The fetch also ran the repository's own `reference-transaction` hook (in `.git/hooks`, or wherever
  `core.hooksPath` points), which needs no config at all, and `core.alternateRefsCommand` when the repository has
  `objects/info/alternates`. A crafted config could also make that fetch run a program (`core.sshCommand`,
  `remote.<name>.uploadpack`, a credential helper, an `ext::` remote). A cloned repository carries no such config and
  no hooks, but one unpacked from an archive or copied from elsewhere can. 0.1.7 runs git by its full path, from `/`,
  as `git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c log.showRoot=true`, `log` with
  `--no-show-signature --no-ext-diff --no-textconv --no-renames`, and lazy fetching off (`GIT_NO_LAZY_FETCH=1`, and
  `GIT_ALLOW_PROTOCOL` for older git). Tests plant
  programs for `core.fsmonitor`, `gpg.program`, diff drivers, filters, the pager and hooks, and a partial clone whose
  fetch would run one, and fail if any of them runs.
- Advisory: [GHSA-x4qj-7j53-r4cv](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x4qj-7j53-r4cv) (this item and the `log.showRoot` one under Fixed).
- **A Node.js older than 18 is tested, and only a certificate refusal reads as "does not trust".** 0.1.0 to 0.1.6
  reported any Node.js older than 18 on `PATH` as SAFE without testing it: the probe used `fetch()`, which Node 17 and
  older lack, so it failed, and every failure counted as a refusal once the forced-roots control (which used
  `https.get`) had passed. Node's bundled roots include Comodo's AAA Certificate Services (Node 10 to 17; 12 to 17 also emSign ECC Root CA - G3),
  so such a Node really is exposed. 0.1.7 probes with `https.get`, and on the host counts a failure as a refusal only when it is a
  certificate-verification error (curl exit 60, a Node certificate error code, Python's `SSLCertVerificationError`, macOS's NSURLErrorDomain -1201 to -1204);
  any other failure, when no test host connected, is UNKNOWN. Found by the critic of the 0.1.7 review; a test runs a
  Node with `fetch` removed against a trusting local test host and expects EXPOSED.
- **Hardening: programs found from the place you started Wardlatch.** From 0.1.0 to 0.1.6, run with npx from inside a
  project, Wardlatch could run that project's own programs: npx puts the project's `node_modules/.bin` first on `PATH`,
  where Wardlatch looks up `git`, `python3`, `node`, `curl`, `php`, `go` and the container engines. And `go version`,
  run from a project whose `go.mod` asks for a newer Go, can download and run that Go (a request to the Go module
  proxy, which Wardlatch promises never to make). 0.1.7 drops every `node_modules/.bin` folder and any relative entry
  from `PATH` before anything runs (and uses `/usr/bin:/bin` when nothing is left), runs git by its full path, runs
  every program from `/` (with `--paths` folders and relative CA settings such as `SSL_CERT_FILE` made absolute
  first), sets `GOTOOLCHAIN=local`, and reads PHP's version with `php -n -v`, which loads no `php.ini` and no
  extension. A Go you pinned with `GOTOOLCHAIN` (for example `go1.26.5`) is read from that setting without running go,
  and judged too. npx also starts Wardlatch with the project's own `node_modules/.bin/node` if it has one, and applies
  its `.npmrc`; Wardlatch can't undo either: run it from your home folder. Found in an independent review.

### Fixed

- **No silent all-clear when the eMudhra check has nothing to test.** When it found no runtime to test (always the
  case for the machine itself on Windows, and possible elsewhere), it printed nothing for it, and the run could exit 0.
  Now it prints one UNKNOWN line ("not checked on Windows yet (Windows is not supported)" on Windows, or "the runtimes
  on this machine were not checked: Windows is not supported yet" when containers were checked; "no runtime was found
  to test" elsewhere; `kind` `runtimes` in `--json`), so the exit code
  is 2. On Windows the OVHcloud CLI and PHP checks say UNKNOWN too, instead of SAFE: they look only for macOS and Linux
  program names. The OVHcloud stealer's temp folder is still found there, and still EXPOSED.
- **A container engine that can't be asked is UNKNOWN, not "not running".** From 0.1.2 to 0.1.6, any failure of
  `docker ps` or `podman ps` other than "permission denied" read as "not running", so a hung Docker Desktop, or one
  answering "error during connect", let the eMudhra check end all SAFE (exit 0) with its running containers never
  checked. Now only an engine that isn't installed, or says it can't connect to its daemon, counts as not running. A
  hang (killed after 10 seconds), more output than can be read, or any other failure is an UNKNOWN line with the reason
  and what to do. A pipeline whose engine is installed but stuck now exits 2 where it exited 0; `--no-containers` skips
  running containers. The `docker exec` or `podman exec` command Wardlatch starts is now killed with SIGKILL, not
  SIGTERM, if it outlives its timeout. Found in an independent review.
- **A repository git can't read is UNKNOWN, not clean.** Up to 0.1.6, when `git log` or `git ls-files` failed in a
  repository (a git refusing a folder owned by another user, a timeout), the workflow review and the committed-key
  scan left it out without a word and still counted it in their SAFE line. Now each such repository is an UNKNOWN line
  with git's reason, and the SAFE line counts only what git could read. Since git no longer fetches, a treeless partial
  clone (`--filter=tree:0`) is one of them.
- **A workflow renamed within `.github/workflows` is listed.** The workflow review now runs `git log --no-renames`, so a
  workflow file renamed into place is listed as added, and a blobless partial clone needs nothing fetched.
- **A workflow added in a repository's first commit is listed, whatever `log.showRoot` says.** Up to 0.1.6, with
  `log.showRoot=false` in the repository's config or your own, `git log` showed no files for a root commit, so a
  workflow added there was missed and the review could read SAFE ([GHSA-x4qj-7j53-r4cv](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-x4qj-7j53-r4cv)). git now runs with `-c log.showRoot=true`, and with
  `GIT_NO_REPLACE_OBJECTS=1`, so `refs/replace/` can't swap one commit for another. Found in an independent review.
- **A Python environment found through a relative `--paths` folder is tested.** Since every program runs from `/`, a
  relative folder would have given curl a bundle path it couldn't open, and the environment would have read SAFE.
  Folders are made absolute first, and a curl row whose own bundle can't be found is UNKNOWN. No release had this:
  it was found in the review of 0.1.7 before release.

## [0.1.6] - 2026-10-21

### Security

- Advisory: [GHSA-23m2-fmmq-w3pr](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-23m2-fmmq-w3pr).
- **The OVHcloud CLI check no longer runs the program.** 0.1.0 to 0.1.5 read its version with `ovhcloud --version`.
  On a machine that still held one of the compromised builds, that would have run the credential stealer, which
  OVHcloud's advisory warns against. 0.1.6 never runs it: it compares the file's MD5 with the five compromised builds
  OVHcloud published (GHSA-862f-55f5-vmvw), and looks in `$TMPDIR`, `/tmp` and `/var/tmp` for the `envchecker-NNNNNNNNN`
  folder the stealer leaves every time it runs, so a machine where it already ran is EXPOSED even if the binary is
  gone, while that folder is still in the temp directory (a reboot or temp cleanup can remove it; a SAFE result does
  not clear a machine that installed or updated the CLI in the window). A clean copy reads SAFE whatever its version: OVHcloud says only downloads from the 94-minute window were
  affected, so 0.1.0 to 0.1.5 flagged every copy of v0.11.0 to v0.15.0, wrongly. Found in our own review while updating to the
  advisory. If you ran an earlier Wardlatch with a compromised `ovhcloud` installed, treat every secret the machine held then as
  exposed and replace it, whatever Wardlatch reports now (the advisory has the details).
- Rules can now mark a program as possible malware (`noExec`, `md5Bad`, `tmpTrace`); a test plants a program that
  would leave a marker file and fails if it ever runs.

### Changed

- The OVHcloud fix lists what the stealer took, from OVHcloud's advisory: cloud, SSH, Kubernetes, Docker, npm and
  Terraform credentials, `.netrc` and git credentials, and the histories of AI coding tools.


## [0.1.5] - 2026-10-21

### Changed

- **A second maintainer with full access.** @mlimano5 is an admin of the repository and an owner of the npm package
  ([GOVERNANCE.md](GOVERNANCE.md#continuity)).
- **The repository moved to the Deimos AI organization:** [github.com/deimos-hq/wardlatch](https://github.com/deimos-hq/wardlatch).
  Old links and `git clone` URLs redirect. 0.1.3 and 0.1.4 still verify under the earlier name
  ([docs/RELEASING.md](docs/RELEASING.md#verifying-a-release)).
- PHP's fix text for 8.1 and older now says the PHP project published minimal source backports for 7.4, 8.0 and 8.1, for
  people who build PHP themselves.

## [0.1.4] - 2026-10-21

### Fixed

- **A runtime that blocks the compromised keys outright now reads SAFE, not UNKNOWN.** Node.js 26.12.1, 24.22.1 and
  22.23.4 reject chains through the compromised keys even when their roots are trusted, so Wardlatch's positive control
  (forcing those roots in) could no longer connect, and 0.1.3 reported "positive control failed". Now, when the forced
  roots are refused, Wardlatch opens a normal site: if that works, the refusal is the runtime's own block, and the result
  is SAFE with the note "blocks the compromised keys themselves". If the normal site fails too, it stays UNKNOWN.

### Changed

- The Node.js fix now names the fixed releases: 26.12.1, 24.22.1 and 22.23.4, published on 21 October 2026.

## [0.1.3] - 2026-10-21

### Changed

- **PHP's fixed versions are in.** PHP released 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 21 October 2026, fixing
  CVE-2026-109618 and CVE-2026-109619 (unauthenticated remote code execution). A `php` older than its branch's fix is
  EXPOSED; 8.1 and older are reported as end of life (the PHP project ships them no fix; use a vendor backport or
  move to a supported branch). The "waiting for the release" state is gone.

### Security

- **A found Python virtual environment's own interpreter is never run.** Up to 0.1.2, Wardlatch ran the `bin/python`
  of each environment it found under the searched folders, so a repository cloned from a stranger could ship a fake
  interpreter that would run as you ([GHSA-383w-hfwc-vx2h](https://github.com/deimos-hq/wardlatch/security/advisories/GHSA-383w-hfwc-vx2h), recorded on 22 October). Now it reads the environment's certifi bundle and version as files and tests the
  bundle with a curl the machine already trusts (`--cacert`). An environment without certifi uses its base Python's
  trust, which is checked through `PATH`. Found by this project's own review; no report of it being exploited.

### Added

- `fix/fix-macos.sh`, the Mac fix: removes the two roots tied to the leaked eMudhra keys from `/etc/ssl/cert.pem`
  with checks around the advisory's change (no change on a fixed Mac, a dated backup it never overwrites, a check of
  the new file before it replaces the old one, permissions kept at 644, a re-test, and a restore on a wrong result).
  It is the same file as the download on www.deimoscore.com (SHA-256 `22153b4a…6a86`). The README documents it.
- Project documents: [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) (sign-off under the DCO, a test
  for every behaviour change), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [GOVERNANCE.md](GOVERNANCE.md),
  [ROADMAP.md](ROADMAP.md), [ASSURANCE_CASE.md](ASSURANCE_CASE.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
  [docs/RELEASING.md](docs/RELEASING.md), and this file.
- Continuous integration on every push and pull request: the tests on Node 18, 20 and 22 on Linux and macOS,
  `node --check` on every module, ShellCheck, the Mac fix's checksum and a run on copies of the certificate file,
  REUSE licence and DCO sign-off checks, CodeQL, OpenSSF Scorecard. A release workflow attests the source archive and
  npm package with Sigstore.
- Tests for the command end to end, the incident data and the coding standard: 36 tests, up from 15.
- A licence and copyright header on every source file, and [REUSE.toml](REUSE.toml) for the rest.

### Changed

- The macOS curl fix text points to the Mac fix download first.
- An unknown option, or `--paths` or `--incident` without a value, is refused with exit code 2 and a message before
  anything runs. Before, an unknown option was ignored and the full check ran, and a trailing `--paths` crashed.
- Names that come from the disk, git or a container engine (file and folder names, plugin folders, authors) are
  printed with control characters escaped, so a planted name can't erase or rewrite its own line on the screen.
  `--json` output was already escaped.
- `--help` and the README name the two control sites (the advisory's page, and a self-signed test site for
  containers) among the connections Wardlatch makes; they mentioned only the test hosts. The README documents every
  option, the statuses, the exit codes and the `--json` fields.
- `package.json` links the GitHub repository, homepage and issue tracker, and adds `npm run coverage`.

### Fixed

- A WordPress plugin whose version header can't be read is "could not be tested" (UNKNOWN, exit code 2), not SAFE.
- The committed-key scan and the WordPress checks check a file's size and read it through one read-only file
  descriptor, so a file swapped in between (for a huge file, a device or a pipe) can't stall or exhaust the run. The
  plugin version header is read under the same 2 MB cap. Found by CodeQL.
- `npm test` runs on Node 22: it passed the `test/` folder, which Node 22's test runner reads as a file name.

## [0.1.2] - 2026-10-21

Published 07:53 UTC. npm `gitHead`: `bcf739c`.

### Added

- Running Docker and Podman containers are checked from inside, with the image's own `curl`, `python3` or `wget`.
  Two controls come first: a normal site must open, and a self-signed one must be refused. Images with no tool
  (distroless) and tools that don't verify certificates say "could not be tested". `--no-containers` skips them.
  Nothing is written into a container.

### Changed

- Fixes that come per release line (PHP, Go) say plainly when your line is end of life and gets no fix.
- eMudhra fix texts: macOS's `/etc/ssl/cert.pem` is read by the built-in curl, git, python3 and openssl, and no macOS
  release has updated it (the current ones date from 28 September 2026); Node's fix is merged and awaiting a release.
  The container fix text points to the home-server section of the page.

### Fixed

- The copyable macOS fix command runs `awk` with `sudo`. With a plain `awk`, a root-only backup could not be read and
  `/etc/ssl/cert.pem` was left empty (advisory issue #35).

## [0.1.1] - 2026-10-21

Published 05:57 UTC. npm `gitHead`: `49ea20c`.

### Added

- `committed-keys-2026-10`: the files your local git repositories track are scanned for high-confidence key shapes
  (cloud keys, private keys, service-account files, GitHub, npm, Slack and Stripe tokens). A finding shows the type,
  file and line, never the key. Lines marked `secrets-ok`, `gitleaks:allow` or `pragma: allowlist secret` are skipped.
- `wordpress-plugins-2026-10`: WordPress installs under the folders searched (and `/var/www`, `~/Sites`) are checked
  for Rank Math PRO 3.0.123 and the attack's indicator, UpdraftPlus before 1.26.13 / 2.26.13, and plugin folders added
  since 18 October to review.

### Fixed

- Long output is no longer cut off when it goes to a pipe: Wardlatch sets its exit code and lets the output finish,
  instead of exiting at once.

## [0.1.0] - 2026-10-21

Published 05:14 UTC. npm `gitHead`: `4d4f295`. The first release.

### Added

- `emudhra-2026-10`: does each runtime on this machine still trust the compromised eMudhra intermediates? Real,
  verified TLS connections to the advisory's 12 test hosts from every `node`, `curl` and `python3` on `PATH`, Python
  virtual environments and their `certifi`, macOS's own networking stack and the Linux distribution's trust store.
  Each host is first checked for reachability, and each runtime first proves it can see exposure (the positive
  control); otherwise the line says "could not be tested", never "safe". cloudflared (fixed in 2026.10.2) and Go
  (1.27.3 / 1.26.10) are checked by version.
- `ovhcloud-cli-2026-10` (OVHcloud CLI 0.11.0 to 0.15.0), `php-2026-10` (pending PHP's fixed versions) and
  `github-actions-2026-10` (workflow files added since 1 September, to review; review lines don't change the exit
  code).
- `--json`, `--list`, `--incident`, `--paths`; exit code 0 safe, 1 exposed, 2 could not be tested.

npm also lists `0.0.0-stage` (21 October, 05:13 UTC), a 331-byte, two-file placeholder from npm's staged publishing,
described on npm as a "Temporary package placeholder". It is not a release and holds none of Wardlatch's code.

[Unreleased]: https://github.com/deimos-hq/wardlatch/compare/v0.1.15...main
[0.1.15]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.15
[0.1.14]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.14
[0.1.13]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.13
[0.1.12]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.12
[0.1.11]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.11
[0.1.10]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.10
[0.1.9]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.9
[0.1.8]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.8
[0.1.7]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.7
[0.1.6]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.6
[0.1.5]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.5
[0.1.4]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.4
[0.1.3]: https://github.com/deimos-hq/wardlatch/releases/tag/v0.1.3
[0.1.2]: https://github.com/deimos-hq/wardlatch/tree/bcf739c318dd60397a76360ac68e04138fd532bd
[0.1.1]: https://github.com/deimos-hq/wardlatch/tree/49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e
[0.1.0]: https://github.com/deimos-hq/wardlatch/tree/4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d
