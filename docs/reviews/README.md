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

The rest of the file is the reviewer's, and the gate doesn't read it for what it means. It only makes sure nothing in
it says the block's words again (read with Unicode's look-alike forms folded and invisible characters removed):

- **No letter outside ASCII** (and no combining mark), so no look-alike letter can spell a verdict or a commit.
- **No "verdict" or "ready"**, in any case, even inside another word: write "by then", not "already".
- **No "commit" or "commits"** as a word ("committed" is fine): say "change" or "fix".
- **No commit id**: no word of 7 to 40 hex digits, however it is labelled (a number of 7 digits or more is one too:
  write "1 MiB", not 1048576). Name a fix by what it changed.
- **No HTML comment** (`<!--`).

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
