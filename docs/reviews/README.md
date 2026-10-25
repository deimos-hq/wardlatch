# Release reviews

Each release from 0.1.10 on has a folder here, `docs/reviews/X.Y.Z/`, holding the two reviews the release gate
(`npm run release-check`, [docs/RELEASING.md](../RELEASING.md)) looks for. Releases up to 0.1.9 predate the gate; their
reviews are summarised in CHANGELOG.md.

Both files are written by someone, or a fresh agent, who wrote none of the code they review. Each holds one verdict
and one reviewed commit, written so that the gate and a reader can only read them one way:

    Commit: <the full or short sha of the commit reviewed>
    Verdict: READY

- **The verdict is said once.** The word "verdict" appears once in the file, on its verdict line; READY in capitals
  appears once, on that line; "not ready" and "ready with" appear nowhere, in any case. A heading, a table row, an
  earlier round or a note of what the verdict will become is a second verdict, and the file is refused: change the one
  line instead.
- **The commit is labelled once.** One line labels a commit, the `Commit:` line. Another `Commit:`, `Commit (round
  1):`, `Commit = ...`, `Commit — ...`, a table cell or a heading that says "Commit" is refused. "Commit" in a
  sentence is fine.
- **Nothing hidden.** No HTML comment (`<!--`): the gate would read what a reader doesn't see.

Quote, list, heading and emphasis marks around either line don't matter (`> **Verdict:** READY` is a verdict line),
and the gate reads the text with Unicode's look-alike forms folded (NFKC: a full-width colon is a colon) and invisible
characters removed. Any other verdict (NOT READY, READY WITH NITS) fails the gate until the findings are fixed, each
fix reviewed again, and the file updated with the new commit. The gate also refuses the release if anything that runs
(`bin/`, `lib/`, `fix/`, `test/`, `scripts/`, `.github/`, and `package.json` apart from its version) changed after the
reviewed commit; a file moved out of those folders counts as a change.

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
  ([docs/RELEASING.md](../RELEASING.md), step 5), quoted as it printed it: `GATE PASSED for B ...`. The gate checks
  the line is there and that no `GATE FAILED` is.

## INDEPENDENT-REVIEW.md

A strict review of everything the release changes, with each finding classed MUST-FIX, SHOULD-FIX or known limit, what
was done about it, and the tests that prove each fix bites. Ends with the commit reviewed and the verdict.
