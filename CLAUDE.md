# Rules for AI coding agents in this repository

Wardlatch's whole value is an honest SAFE. Its users act on SAFE by doing nothing, so a false SAFE is the worst bug this
tool can have, worse than a crash. Between 21 and 23 October 2026 it shipped nine releases and nine security advisories,
most of them false SAFEs, and six "fixes" brought in new bugs, two of them false SAFEs from a cosmetic change. These rules
come from that. They apply to every session, on every account, before every change. [CONTRIBUTING.md](CONTRIBUTING.md) still
applies in full; where this file is stricter, follow this file.

## The rules

1. **When in doubt, UNKNOWN.** SAFE needs a control that showed the check could have seen the problem, and a receipt of
   what was searched. Anything you couldn't check, couldn't read, or aren't sure about is UNKNOWN ("could not be tested"),
   never SAFE and never silently left out.
2. **Never copy another program's language.** When a fix starts to imitate how curl parses its config, how PHP evaluates a
   file, how a shell quotes, stop. Write a simple rule that reads on the safe side and says UNKNOWN when in doubt, and
   put it to the maintainer. Exact emulation is a project, not a patch; four review rounds in a row proved it never
   converges.
3. **Your own change is not safe until someone else says so.** Every fix commit, however small, gets a new independent
   strict check (a fresh agent or person who didn't write it) before anyone calls it done. Never review your own fix.
4. **Review by kind of bug, not by diff.** For any change, and before any release, go through every input source (each
   environment variable a child process inherits, the working directory, `PATH`, config files, files on disk), every
   path that ends in SAFE or exit 0 and what it proves, every read and pattern (bounded?), and confirm nothing found on
   the machine is ever run. Look again for every past advisory's kind of mistake (CHANGELOG.md names them all).
5. **After a check says READY, change code only for a real problem**: a false SAFE, a false UNKNOWN on a clean machine,
   a wrong exit code, or a documented claim that is untrue. Wording, which path a line names, dead code: write it in the
   changelog's Known limits instead. A cosmetic "fix" after READY is how two false SAFEs shipped.
6. **Every test must bite.** Put the guarded line back out (in a copy) and watch the test fail before you trust it.
   `node --test --test-name-pattern` takes a regex: parentheses in a test name can match nothing and look like a pass.
   A fixture must model the real attack, and every bad-case test needs a clean-machine twin beside it.
7. **Every pattern run on untrusted text is linear by construction.** Anchor at the start, no end-anchored `+$` (write a
   loop), no nested quantifiers. Time a 1 MB hostile line in the test.
8. **Honest words.** A flaw that was in every release since 0.1.0 is "we missed this since 0.1.0, and here is why",
   never "a new flaw nobody found". Copy numbers from the output, never from memory. Write "(maintainer, date: ...)" only
   for what the maintainer decided; your own inference is yours.
9. **Slow down.** Fewer, reviewed releases beat many fast ones. After a security release, releases pause for the freeze
   the maintainer sets (after 0.1.9: at least a week, to 31 October 2026); whether anything breaks it is the maintainer's
   call, never yours. A new incident starts as a one-page spec (what proves exposed, what proves safe, what is UNKNOWN)
   for the maintainer to approve before code.

## What you never do

- Tag, push to `main`, publish to npm, publish an advisory or post anything public without the maintainer's explicit
  word for that action. The maintainer runs `npm publish` and does 2FA.
- Work around a gate: no `--no-verify`, no editing `scripts/mutants-allowed.json` to make a survivor go away without a
  reason a reviewer agreed to, no adding a new survivor to `scripts/mutants-gaps.json` (that list only shrinks, and
  only the maintainer adds to it), no skipping `npm run release-check`, no weakening a test so it passes, and no moving a
  failing red-team scenario into `KNOWN_LIMITS` or marking any test todo or skip without the maintainer's word and a
  line in the changelog's Known limits.
- Change `fix/fix-macos.sh`, even by a byte, unless the change is to the Mac fix itself (its SHA-256 is published).
- Add a dependency, or code that writes files, sends data, or opens connections outside `lib/probe.mjs`
  (CONTRIBUTING.md, "What an acceptable contribution looks like").
- Run heavy jobs on the maintainer's laptop in parallel. One at a time; the full mutation run belongs on CI.

## Before you call a change done

- `npm test` passes (the red-team scenarios are part of it; the 14 limits the 0.1.9 changelog documents run as todo).
- A bug fix has a regression test that fails without the fix, and you watched it fail.
- If the change touches a line that gives or tests a status: `npm run mutate:critical -- --only <file>` (Node 22.1+)
  reports no survivor in that file, and the tests that caught each planted bug are behaviour tests (results.json).
- A sentence in README.md, ASSURANCE_CASE.md, docs/ARCHITECTURE.md or CHANGELOG.md that the change made untrue is
  fixed in the same commit.
- An independent strict check of the commit has come back clean.

## Releases

[docs/RELEASING.md](docs/RELEASING.md), "Before you cut a release". `npm run release-check` must print READY on the
release commit: it checks the changelog, the two reviews in `docs/reviews/<version>/` (the class audit and an
independent review, each READY for this code), that the class audit names every advisory, and that every GitHub check
passed on the commit, including the critical-mutant gate and the corpus report.
