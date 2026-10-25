# Releasing

Releases are cut by the maintainer or the successor, the two owners of the `wardlatch` package on npm
([GOVERNANCE.md](../GOVERNANCE.md)). There is no build: a release is the source in `bin/` and `lib/`, packed by npm.

## Before you cut a release

The tag comes last. Nothing below is optional, and none of it is done by the person or agent who wrote the change
being reviewed ([CLAUDE.md](../CLAUDE.md), rule 3).

1. **Freeze the candidate.** The release commit's code (`bin/`, `lib/`, `fix/`, `test/`, `scripts/`, `.github/`) is
   final. After the reviews below, only the changelog, the version and other documents may change; the gate refuses a
   release whose code changed after its reviews.
2. **The class audit**, `docs/reviews/X.Y.Z/CLASS-AUDIT.md`: a review of all the code, not just the change, by kind of
   bug: every input source each check trusts (each environment variable a child process inherits, the working directory,
   `PATH`, config files, files on disk), every path that ends in SAFE or exit 0 and what it proves, every read and
   pattern (bounded?), and that nothing found on the machine is run. It names every advisory in CHANGELOG.md and says
   how that advisory's kind of mistake was looked for again. Format: [docs/reviews/README.md](reviews/README.md).
3. **The independent review**, `docs/reviews/X.Y.Z/INDEPENDENT-REVIEW.md`: a strict review of the release's changes by
   someone, or a fresh agent, who wrote none of them. Every finding is fixed (each fix gets its own new review) or
   written into the changelog's Known limits, until the verdict is READY.
4. **Read the latest weekly mutation report** (Actions, "Mutation (full, report)"; it plants `'REVIEW'` changed to
   `'SAFE'` too, which the per-commit gate doesn't) and the known test gaps in `scripts/mutants-gaps.json`. A survivor
   or a gap in code this release touched gets a test first, or the class audit says why it can't matter.
5. **Push and let CI finish.** Every check must pass on the release commit, including `critical mutants` (it exits 0:
   no survivor outside the two lists, and no closed or stale entry; each `'UNKNOWN'` and `'EXPOSED'` in the code
   changed to `'SAFE'` is either caught by a behaviour test, named in the job summary, or a known gap in
   `scripts/mutants-gaps.json`; no test gave different results on the same code) and `gaps and allow lists only
   shrink`. Read the job summary of `corpus (report against last release)`: every difference from the last release is
   intended, or it is a finding. Then run the corpus as a gate, as root with real owners for the service and
   other-person folders, as the 0.1.9 review did: `node scripts/corpus/run.mjs <corpus> <last-release>/bin/wardlatch.mjs
   bin/wardlatch.mjs --gate` must print GATE PASSED, and the class audit quotes that line. The line names the SHA-256
   of the `bin/` and `lib/` it ran, and the release gate needs the release commit's: run it on the code being released.
   Read the todo lines of `npm test` too (the documented limits): a todo test is not checked further, so a limit that
   got worse still reads as the same todo; one that fails differently from its documented limit is a finding.
6. **`npm run release-check` prints READY** on that commit, from a clean checkout of `main` (gh signed in). It checks
   1 to 5 where a machine can (the dated changelog section under an empty Unreleased, both reviews READY for this code
   in the block each begins with, with nothing that runs changed since, package.json apart from its version included,
   every advisory named in the class audit, the corpus gate's GATE PASSED for this code quoted there, every GitHub
   check passed), and that nothing was added to `scripts/mutants-gaps.json` or `scripts/mutants-allowed.json` since
   the last release without the maintainer's approval written on the entry (`"approved": "maintainer, YYYY-MM-DD"`).
   That is deliberately stricter than [CLAUDE.md](../CLAUDE.md), which lets an equivalent survivor onto the allow list
   with a reason a reviewer agreed to: for a release, only the maintainer adds to either list. The last release is the
   newest tag in this history with a GitHub release the gate trusts as the release workflow's: published by
   github-actions[bot] for a tag `vX.Y.Z`, neither a draft nor a prerelease, and either immutable (GitHub's `immutable`
   is `true`) or never edited after it was published (GitHub's `updated_at` no later than its `published_at`). The
   release workflow repeats its checks in a job whose token only reads, checking that the tagged commit is on `main`
   instead of the clean checkout of `main` (and reading GitHub's checks and releases with its own token); it refuses a
   tag for a version older than 0.1.10, and publishes nothing without them.

   Of the repository's protections, the gate relies on two. **Immutable releases**: GitHub keeps an immutable
   release's tag and files whatever is edited later, so the gate trusts one edited after it was published. **The tag
   ruleset** (only admins create, move or delete `v*` tags): for a release that isn't immutable (0.1.3 to 0.1.9, cut
   before immutable releases were turned on), the gate takes the tag in the clone as the one released, and only the
   ruleset keeps anyone but an admin from moving it. It doesn't rely on **the `release` environment**: it reads
   nothing from it, and trusts no tag for having been allowed to run the release workflow.

   What the gate can't check is the reviews' prose. It reads the verdict and the commit only from the block each
   review begins with, and after it refuses a listed set of known ways to hide or add a verdict or a commit id
   ([docs/reviews/README.md](reviews/README.md) lists them, and what they don't catch); it can't prove that the page
   GitHub shows says what the text says. What stands behind that is the pull request into `main` (the ruleset lets
   changes reach `main` only that way, with no approving review required), the maintainer's approval in the `release`
   environment, and the reviewers' own reading.

Fewer, reviewed releases beat many fast ones. After a security release, releases pause for the freeze the maintainer
sets (after 0.1.9: at least a week); whether anything breaks it is the maintainer's call.

## How to cut one

```bash
# 1. The changelog: move "Unreleased" under "## [X.Y.Z] - YYYY-MM-DD" and update the links at the bottom.
#    (The reviews in docs/reviews/X.Y.Z/ come first: "Before you cut a release", above.)
# 2. The version. It must match the tag exactly; the release workflow refuses otherwise.
npm version X.Y.Z --no-git-tag-version
git commit -s -am "X.Y.Z: <what changed, in one line>"
git push origin main                      # wait for CI to go green
npm run release-check                     # must print READY on this commit

# 3. A signed, annotated tag on that commit. tag.gpgsign is set, so git signs it with the
#    maintainer's SSH signing key, and GitHub shows it as Verified.
git tag -s vX.Y.Z -m "wardlatch X.Y.Z"
git push origin vX.Y.Z
```

The tag push runs `.github/workflows/release.yml`: first, in a job whose token can only read, the full test suite and
the release gate (`release-check.mjs --ci`); then, in a job that runs only after both pass, a check that the tag
matches `package.json`, and it builds the source archive (`git archive`) and the npm package (`npm pack`), attests both
with Sigstore, and publishes a GitHub release with the changelog section as its notes. **If any step fails, no release
appears.** The workflow never publishes to npm.

```bash
# 4. Publish to npm the exact package the workflow attested, so what is on npm can be verified.
gh release download vX.Y.Z -p 'wardlatch-X.Y.Z.tgz' -R deimos-hq/wardlatch
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
npm publish ./wardlatch-X.Y.Z.tgz
```

```bash
# 5. If the release fixes a draft security advisory, publish it once the package is on npm: the changelog and the
#    release notes link to it, and it links back to them. Then request its CVE, and update any published advisory
#    whose workaround or impact the new one changes.
gh api -X PATCH repos/deimos-hq/wardlatch/security-advisories/GHSA-xxxx-xxxx-xxxx -f state=published
gh api -X POST repos/deimos-hq/wardlatch/security-advisories/GHSA-xxxx-xxxx-xxxx/cve
```

If `fix/fix-macos.sh` changed in the release, the download on www.deimoscore.com, the SHA-256 printed on the page and
the site's changelog record change at the same time, and the hash pinned in `.github/workflows/ci.yml` with them.

### Tags for the releases before the workflow

0.1.0 to 0.1.2 were published before any tag existed. These are the commits npm recorded as each one's `gitHead`
(a pack of each matches the published package's file count and size):

```bash
git tag -s v0.1.0 4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d -m "wardlatch 0.1.0 (npm, 21 Oct 2026 05:14 UTC)"
git tag -s v0.1.1 49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e -m "wardlatch 0.1.1 (npm, 21 Oct 2026 05:57 UTC)"
git tag -s v0.1.2 bcf739c318dd60397a76360ac68e04138fd532bd -m "wardlatch 0.1.2 (npm, 21 Oct 2026 07:53 UTC)"
git push origin v0.1.0 v0.1.1 v0.1.2
```

Pushing them starts no release: those commits contain no workflow files. They mark where each release came from; they
do not sign the packages already on npm.

## Verifying a release

For a release cut through the workflow, the package on npm and the source archive each carry a Sigstore attestation
bound to the GitHub workflow run and commit that built them, recorded in a public transparency log. There is no key to
import.

```bash
npm pack wardlatch@X.Y.Z                 # downloads wardlatch-X.Y.Z.tgz from npm without installing it
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
```

Without GitHub's attestation store, use the bundle attached to the release:

```bash
gh attestation verify wardlatch-X.Y.Z.tgz --bundle wardlatch-X.Y.Z.tgz.sigstore.json --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
sha256sum -c SHA256SUMS                  # the files are byte for byte what was published
```

**0.1.3 and 0.1.4 verify under the repository's earlier name.** The repository moved from
`thearchitect0x-glitch/wardlatch` to `deimos-hq/wardlatch` on 21 October 2026, after those two releases. Their
attestations name the repository they were built in, and that cannot change, so verify them with the earlier name and the
bundle attached to the release:

```bash
gh attestation verify wardlatch-0.1.4.tgz --bundle wardlatch-0.1.4.tgz.sigstore.json --repo thearchitect0x-glitch/wardlatch
```

The tag is signed with the maintainer's SSH signing key, which GitHub lists for the account:

```bash
gh api users/thearchitect0x-glitch/ssh_signing_keys --jq '.[].key' | sed 's/^/thearchitect0x-glitch /' > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag vX.Y.Z
```

An attestation answers "which workflow, at which commit, built this file". It does not answer whether that commit was
any good; the tests, CodeQL and review are what address that.
