# Release reviews

Each release from 0.1.10 on has a folder here, `docs/reviews/X.Y.Z/`, holding the two reviews the release gate
(`npm run release-check`, [docs/RELEASING.md](../RELEASING.md)) looks for. Releases up to 0.1.9 predate the gate; their
reviews are summarised in CHANGELOG.md.

Both files are written by someone, or a fresh agent, who wrote none of the code they review. Each begins with the one
thing the gate reads in it, a block of four lines, exactly as here, at the very top of the file:

    ```
    Commit: <the full or short sha of the commit reviewed, in lower-case hex as git prints it>
    Verdict: READY
    ```

A fenced block at the top of a file is shown on the page as it is written: nothing before it can hide it, and a
reader sees what the gate reads. Written any other way (in bold, in a quote, under a title, with a full-width colon
or an invisible character in it), it is not the block, and the file is refused. Any other verdict (NOT READY, READY
WITH NITS) fails the gate until the findings are fixed, each fix reviewed again, and the block updated with the new
commit.

The rest of the file is the reviewer's. The gate doesn't read it for what it means, and doesn't try to read it the way
Markdown, HTML or a browser would show it either: it refuses the file when any line after the block has one of these,
anywhere in the line, whatever the line says. They are checked in this order, and the gate names the line and the
first reason it finds.

- **A character outside printable ASCII.** Only ASCII letters, digits, punctuation, spaces and tabs. So no letter
  outside ASCII, as written or after Unicode's look-alike forms are folded (NFKC: a full-width `ｆ` is one), no
  zero-width, format, control or right-to-left character, no look-alike symbol (`℮`), and no other space. Write `--`
  for a dash, `->` for an arrow, and straight quotes.
- **HTML**: `<` followed by a letter, `/`, `!` or `?` (a tag, a comment, an autolink). `a < b` is fine.
- **A character reference**: `&` followed by `#` or a letter (`&#101;`, `&amp;`, and `R&D` too). `R & D` is fine.
- **A backslash**, anywhere.
- **A mark inside a word**: one or more of `*`, `_`, `~` and backticks between two letters or digits (`RE*AD*Y`, and
  `GH_TOKEN` too). Marks around a word are fine: `**S1**`, `` `lib/a.mjs` ``.
- **A link**: `]` followed by `(` or `:`, with or without spaces or tabs between (a link, an image, a link reference
  or footnote definition). Write a URL as it is, `https://...`; `[S1]` alone is fine.
- **An emoji code**: letters, digits, `_`, `+` or `-` between two colons (GitHub shows `:a:` as a letter). `Note: x`
  and `node:fs` are fine; `12:30:00` is not.
- **A `$`** (GitHub shows text between two as math, which drops spaces).
- **A fence with an info string**: three backticks or tildes, then, after any spaces or tabs, anything but another
  backtick or tilde (GitHub shows `math` and `mermaid` blocks as math and diagrams). A plain fence is fine.
- **"verdict" or "ready"**, in any case, even inside another word: write "by then", not "already".
- **"commit" or "commits"** as a word ("committed" is fine): say "change" or "fix".
- **A commit id**: hex digits, in either case, that git could resolve as a commit in this repository: a word of 4
  or more (a word: letters and digits between any other characters), or 7 or more in a row inside another word (as
  `git describe` writes a commit, `v0.1.9-3-g0657ddb`). The gate asks git about each, as written and in lower case,
  and it passes only when git finds nothing by it, or one file or folder (a blob or a tree): so it is refused when it
  begins the id of a commit or a tag, names a branch or a tag, or could mean more than one object. Two are not read
  for one: the block's own commit written in full, as `git rev-parse` prints it (in lower case), and an advisory id
  (`GHSA-xxxx-xxxx-xxxx`). A number or a word that happens to begin a commit id here (2026, face, added) is refused
  too: write it another way. Name a fix by what it changed.

That is all the gate guarantees about the prose: a review that says otherwise in other words ("do not ship") is for
the person reading it to catch. The gate also refuses the release if anything that runs (`bin/`, `lib/`, `fix/`,
`test/`, `scripts/`, `.github/`, and `package.json` apart from its version) changed after the reviewed commit; a file
moved out of those folders counts as a change.

## CLASS-AUDIT.md

A review of all the code by kind of bug, not by diff:

- **Inputs:** every input each check trusts: the environment each child process inherits, the working directory,
  `PATH`, config files, files on disk. What happens when each is missing, unreadable, huge, a link, a FIFO, hostile.
- **Every SAFE and every exit 0:** what control proves the check could have seen the problem, and what the receipt says
  was searched. Anything unproven is UNKNOWN.
- **Bounded:** every read and every pattern on untrusted text has a cap and runs in linear time.
- **Nothing found is run:** no program, script or config found on the machine is executed.
- **Every advisory, again:** one line per advisory in CHANGELOG.md (`GHSA-xxxx-xxxx-xxxx: ...`) saying how its kind of
  mistake was looked for in all the code, and what was found. The gate checks every advisory is named.
- **The corpus gate:** the last line of `node scripts/corpus/run.mjs <corpus> <last-release>/bin/wardlatch.mjs
  bin/wardlatch.mjs --gate`, run as root with real owners for the service and other-person folders
  ([docs/RELEASING.md](../RELEASING.md), step 5), quoted as it printed it: `GATE PASSED for B <version> (bin/ and lib/
  sha256 <hash>): ...`. The gate checks the line is there, that its SHA-256 is that of the release commit's `bin/` and
  `lib/` (so the corpus gate ran on the code being released), and that no `GATE FAILED` is.

## INDEPENDENT-REVIEW.md

A strict review of everything the release changes, with each finding classed MUST-FIX, SHOULD-FIX or known limit, what
was done about it, and the tests that prove each fix bites, after the block that names the commit reviewed and the
verdict.
