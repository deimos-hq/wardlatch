# Wardlatch

**Does the wrong key still turn?**

When a certificate authority's keys leak, browsers update within hours. The rest of your machine doesn't. curl, Node,
Python and every project's own certificate bundle each keep their own list of who to trust, and each has to be fixed
on its own. Wardlatch tells you which ones still trust the leaked keys.

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

- `emudhra-2026-10`: eMudhra intermediate CA compromise, 20 Oct 2026 ([advisory](https://emudhra.we-have-a-problem.com/)).

When the next one happens, it gets added here.

---

A free tool from Deimos AI LLC. Apache-2.0.
