# Release reviews

Each release from 0.1.10 on has a folder here, `docs/reviews/X.Y.Z/`, holding the two reviews the release gate
(`npm run release-check`, [docs/RELEASING.md](../RELEASING.md)) looks for. Releases up to 0.1.9 predate the gate; their
reviews are summarised in CHANGELOG.md.

Both files are written by someone, or a fresh agent, who wrote none of the code they review. Each begins with the block
the gate reads, four lines, exactly as here, at the very top of the file:

    ```
    Commit: <the full or short sha of the commit reviewed, in lower-case hex as git prints it>
    Verdict: READY
    ```

The gate reads the verdict and the commit reviewed from that block, and from nowhere else. Written any other way (in
bold, in a quote, under a title, with a full-width colon or an invisible character in it), it is not the block, and the
file is refused. Any other verdict (NOT READY, READY WITH NITS) fails the gate until the findings are fixed, each fix
reviewed again, and the block updated with the new commit.

## What the gate guarantees about the rest of a review, and what it doesn't

The rest of the file is the reviewer's. The gate doesn't read it for what it means, and doesn't render it the way
Markdown, HTML or GitHub would. What it does is refuse a review that has, after the block, one of a listed set of known
ways to hide or add a verdict or a commit id: the list below. A way that isn't on the list is not refused. So the gate
**can't prove that the page GitHub shows says what the text says**, and a review that says "don't release this" in
other words is not refused.

What stands behind that is people, not the gate:

- **The pull request into `main`.** Since 25 October 2026 the repository's ruleset lets changes reach `main` only
  through a pull request that passes the required checks, so a review is on a page GitHub shows before it reaches
  `main`. The ruleset requires no approving review: today the maintainer is the only reviewer.
- **The maintainer's approval in the `release` environment.** On `main` since 25 October 2026, the job of the release
  workflow that publishes runs in the `release` environment, which waits for the maintainer's approval (an admin can
  bypass it).
- **The reviewers' own reading**, of the reviews as GitHub shows them.

The gate also refuses the release if anything that runs (`bin/`, `lib/`, `fix/`, `test/`, `scripts/`, `.github/`, and
`package.json` apart from its version) changed after the reviewed commit; a file moved out of those folders counts as a
change.

## The list

The gate reads each line after the block once, for items 1 to 14 in this order, each a pattern or a count on the
line itself, and stops at the first it finds, naming the line and the reason. Only when no line has any of them is
git asked about item 15, for every line at once; the gate then names the first line with such a word.

1. **A character outside printable ASCII.** Only ASCII letters, digits, punctuation, spaces and tabs. So no letter
   outside ASCII, as written or after Unicode's look-alike forms are folded (NFKC: a full-width `ｆ` is one), no
   zero-width, format, control or right-to-left character, no look-alike symbol (`℮`), and no other space. Write `--`
   for a dash, `->` for an arrow, and straight quotes.
2. **HTML**: `<` followed by a letter, `/`, `!` or `?` (a tag, a comment, an autolink). `a < b` is fine.
3. **A character reference**: `&` followed by `#` or a letter (`&#101;`, `&amp;`, and `R&D` too). `R & D` is fine.
4. **A backslash**, anywhere.
5. **A mark inside a word**: one or more of `*`, `_`, `~` and backticks between two letters or digits (`RE*AD*Y`, and
   `GH_TOKEN` and `HEAD~2` too). Marks around a word are fine: `**S1**`, `` `lib/a.mjs` ``.
6. **A link**: `]` followed by `(` or `:`, with or without spaces or tabs between (a link, an image, a link reference
   or footnote definition). Write a URL as it is, `https://...`; `[S1]` alone is fine.
7. **An emoji code**: letters, digits, `_`, `+` or `-` between two colons (GitHub shows `:a:` as a letter). `Note: x`
   and `node:fs` are fine; `12:30:00` is not, and neither is a table's centred `:---:`.
8. **A `$`** (GitHub shows text between two as math, which drops spaces).
9. **A fence with an info string**: three backticks or tildes, then, after any spaces or tabs, anything but another
   backtick or tilde (GitHub shows `math` and `mermaid` blocks as math and diagrams). A plain fence is fine.
10. **A commit as `git describe` writes one**: `-`, a number, `-g` and 4 or more hex digits, anywhere (`v0.1.9-3-g0657`
    names the commit `0657` begins), whatever git makes of it.
11. **An ordered-list marker of 2 or more digits**: at the start of a line, after any quote marks, bullets or one-digit
    markers, 2 or more digits, then `.` or `)`, then a space, a tab or the end of the line (`10.`, `0657.`, `> 12)`,
    `1. 10.`). GitHub shows `0657.` as `657.`, and numbers every item after a list's first itself, whatever is written:
    write `1.` for each item.
12. **A table row with more cells than its header.** A line of only `|`, `:`, `-`, spaces and tabs, with at least one
    `-` (after any quote marks, spaces and tabs), starts a table, and the next blank line ends it. Inside one, a row
    with more cells than that line is refused: GitHub doesn't show a row's cells past its header's. A row's cells are
    its `|`s plus one, less one for a `|` at its start and one for a `|` at its end. A line like `---` (a rule, or a
    heading's underline) starts one too, of one cell: leave a blank line after it before a table or a line with `|`s.
13. **The block's words, said again**, in any case, after a fixed fold of look-alikes in which `l`, `I`, `1` and `|`
    read as `i`, and `0` as `o`: "verdict" or "ready" anywhere, even inside another word (`VERD1CT`, and `already`
    too: write "by then"); "commit", "commits", "ship" or "ships" as a word (`C0MMIT`, `SH|P`, and plain "ship" too;
    "committed", "shipped" and "ownership" are fine): say "change" or "fix".
14. **A search of the commit messages**: a word (between spaces or tabs) that starts with `:/` or has `^{/` in it. git
    would take the rest as a pattern, search the commit messages with it and name the commit it finds; the gate
    refuses it without asking git, as one such pattern kept git busy for over 20 seconds before it was stopped.
15. **A commit id, or a word git resolves to a commit.** git, with `core.disambiguate=none`, is asked about two kinds of
    word, in this clone, and the review is refused when git finds by one a commit, a tag, or more than one object
    ("ambiguous"); a word passes when git finds nothing, or one file or folder (a blob or a tree):
    - **hex digits**, in either case: a word of 4 or more (a word: letters and digits between any other characters),
      or 7 or more in a row inside another word, asked as written and in lower case. Not read for one: the block's own
      commit written in full, as `git rev-parse` prints it (in lower case), and the four words of an advisory id
      (`GHSA-xxxx-xxxx-xxxx`) that stands as a whole word; an advisory id glued to other letters or digits
      (`GHSA-abcd-abcd-0657ddb...`) is not one, and every word in it is read. A number or word that happens to begin a
      commit id here (2026, face, added) is refused too: write it another way.
    - **every word between spaces and tabs, exactly as written**, as `git rev-parse --verify` would read it: a branch
      or tag name (`main`, `v0.1.9`; `origin` in a clone with `origin/HEAD`; on a Mac, `head` as well as `HEAD`),
      `HEAD^^`, `@`, `<id>^`. Write a release as `0.1.9`, and name a fix by what it changed. When git stops on a word
      (`@{u}` with no upstream), the review is refused, as git couldn't say what it names.

## What the list doesn't catch

Each of these is on a page a person reads, and none is refused by the gate:

- A verdict or a refusal in other words ("don't release this", "S1 is still open").
- A name git would resolve, with a mark or punctuation attached, so the word as written is not one git knows:
  `` `main` ``, `(v0.1.9)`, `HEAD,`. Hex digits in such a word are still asked about (item 15).
- A range (`v0.1.9..main`), which git doesn't resolve as one name, and a branch or tag that exists in another clone but
  not in the one the gate runs in.
- Anything else Markdown or GitHub shows differently from how it is written that isn't on the list.

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
