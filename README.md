# Wardlatch

**Does the wrong key still turn?**

When a certificate authority's keys leak, browsers update within hours. The rest of your machine doesn't. curl, Node,
Python and every project's own certificate bundle each keep their own list of who to trust, and each has to be fixed
on its own. Wardlatch tells you which ones still trust the leaked keys, and checks this week's other leaks too.

```
npx wardlatch
```

```
SAFE     node 26.12.0  /opt/homebrew/bin/node
EXPOSED  node 26.12.0  /usr/local/bin/node  trusts 6/12
         fix: Node bundles its own roots; the fix is pending upstream ...
SAFE     curl 8.7.1  /usr/bin/curl
SAFE     certifi 2026.10.19  ~/Development/app/.venv

11 safe · 1 exposed · 0 could not be tested
```

## How it works

It doesn't compare version numbers. It asks each runtime to open a real, verified TLS connection to public test hosts
whose certificates are signed with the compromised keys, the way your own code would, with your own environment.
If a runtime connects, it still trusts them.

Two checks keep the answer honest:

- **Is the test host up?** Each host is first reached with verification off. If none answers, the result is
  *could not be tested*, never *safe*.
- **Could this check have failed?** Each runtime is first run once with the compromised roots forced in. If it can't
  connect even then, the probe can't see exposure on that runtime, and the result is *could not be tested*, never
  *safe*.

## What it looks at

- every `node`, `curl` and `python3` on your `PATH`, plus the operating system's own
- Python virtual environments (and their `certifi`) under `~/Development`, `~/code`, `~/src`, `~/projects`, `~/dev`,
  `~/work`, or the folders you give with `--paths`

Compiled programs (Go, Rust, Electron) carry the trust list of the toolchain that built them; Wardlatch prints what to
rebuild them with. Check your browser on the advisory's own page.

## Privacy

Wardlatch runs on your machine. It sends nothing anywhere: no telemetry, no results, no machine details. The only
network traffic is the TLS handshakes to the incident's public test hosts. It changes nothing on your system; each
result comes with the fix for you to apply.

```
npx wardlatch --help
npx wardlatch --json          # for CI and scripts; exit code 0 safe · 1 exposed · 2 could not be tested
npx wardlatch --list          # incidents it knows
```

## Incidents

`npx wardlatch` checks all of them; `--incident <id>` checks one.

- `emudhra-2026-10`: eMudhra intermediate CA compromise, 20 Oct 2026 ([advisory](https://emudhra.we-have-a-problem.com/)). Real TLS probes per runtime, plus cloudflared (fixed in 2026.10.2) and the Go toolchain (1.27.3 / 1.26.10).
- `ovhcloud-cli-2026-10`: OVHcloud CLI v0.11.0 to v0.15.0 swapped for a secret-stealer on 19 Oct ([report](https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html)). Flags an installed copy in that range.
- `php-2026-10`: two critical PHP flaws, fixes due 21 Oct 14:00 UTC ([report](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)). Flags an installed PHP until the fixed versions are known.
- `github-actions-2026-10`: credential-stealing workflow files planted in tens of thousands of repositories since 7 Oct ([report](https://thehackernews.com/2026/10/credential-stealing-github-actions.html)). Lists workflow files added to your local repositories since 1 Sep, to review. Review lines don't change the exit code.

- `committed-keys-2026-10`: keys committed to code, the lesson of the TiDB Cloud breach ([PingCAP](https://www.pingcap.com/trust-hub/security/security-update-october-2026/)). Scans the files your local git repositories track for cloud keys, private keys, service-account files and GitHub, npm, Slack and Stripe tokens. A finding shows the type, file and line, never the key. Lines marked `secrets-ok`, `gitleaks:allow` or `pragma: allowlist secret` are skipped. Current files only: for history, use gitleaks or trufflehog.

- `wordpress-plugins-2026-10`: Rank Math PRO 3.0.123 shipped with a backdoor (15 to 16 Oct; clean 3.0.124) and stolen UpdraftCentral keys were used to plant backdoor plugins from 18 Oct ([Patchstack](https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/)). Finds WordPress installs under the folders searched (and `/var/www`), flags Rank Math PRO 3.0.123 and the attack's indicator, UpdraftPlus before 1.26.13 / 2.26.13, and lists plugin folders added since 18 Oct to review. Run it on the server.

When the next one happens, it gets added here.

---

A free tool from Deimos AI LLC. Apache-2.0.
