# Releasing

Releases are cut by the maintainer or the successor, the two owners of the `wardlatch` package on npm
([GOVERNANCE.md](../GOVERNANCE.md)). There is no build: a release is the source in `bin/` and `lib/`, packed by npm.

## How to cut one

```bash
# 1. The changelog: move "Unreleased" under "## [X.Y.Z] - YYYY-MM-DD" and update the links at the bottom.
# 2. The version. It must match the tag exactly; the release workflow refuses otherwise.
npm version X.Y.Z --no-git-tag-version
git commit -s -am "X.Y.Z: <what changed, in one line>"
git push origin main                      # wait for CI to go green

# 3. A signed, annotated tag on that commit. tag.gpgsign is set, so git signs it with the
#    maintainer's SSH signing key, and GitHub shows it as Verified.
git tag -s vX.Y.Z -m "wardlatch X.Y.Z"
git push origin vX.Y.Z
```

The tag push runs `.github/workflows/release.yml`: the full test suite, a check that the tag matches
`package.json`, then it builds the source archive (`git archive`) and the npm package (`npm pack`), attests both with
Sigstore, and publishes a GitHub release with the changelog section as its notes. **If any step fails, no release
appears.** The workflow never publishes to npm.

```bash
# 4. Publish to npm the exact package the workflow attested, so what is on npm can be verified.
gh release download vX.Y.Z -p 'wardlatch-X.Y.Z.tgz' -R deimos-hq/wardlatch
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch
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
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch
```

Without GitHub's attestation store, use the bundle attached to the release:

```bash
gh attestation verify wardlatch-X.Y.Z.tgz --bundle wardlatch-X.Y.Z.tgz.sigstore.json --repo deimos-hq/wardlatch
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
