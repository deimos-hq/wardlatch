# Release reviews

Each release from 0.1.10 on has a folder here, `docs/reviews/X.Y.Z/`, holding the two reviews the release gate
(`npm run release-check`, [docs/RELEASING.md](../RELEASING.md)) looks for. Releases up to 0.1.9 predate the gate; their
reviews are summarised in CHANGELOG.md.

Both files are written by someone, or a fresh agent, who wrote none of the code they review. Each needs exactly one of
each of these two lines (a file with two verdicts, or two commits, is refused):

    Commit: <the full or short sha of the commit reviewed>
    Verdict: READY

Any other verdict (NOT READY, READY WITH NITS) fails the gate until the findings are fixed, each fix reviewed again, and
the file updated with the new commit. The gate also refuses the release if anything that runs (`bin/`, `lib/`, `fix/`,
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

## INDEPENDENT-REVIEW.md

A strict review of everything the release changes, with each finding classed MUST-FIX, SHOULD-FIX or known limit, what
was done about it, and the tests that prove each fix bites. Ends with the commit reviewed and the verdict.
