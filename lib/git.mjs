// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// git, run read-only in a repository Wardlatch found. A repository's own .git/config can name programs for git to run.
// A cloned repository starts with git's default config, but one unpacked from an archive or copied from elsewhere can
// carry any config it likes. Settings given with -c win over every config file, so each one that could make
// `ls-files` or `log --name-only` start a program is set here:
// - core.fsmonitor=false: `ls-files` would run the program it names to ask which files changed.
// - log.showSignature=false: `log` would run gpg.program (or gpg.ssh.program, gpg.x509.program) for each signed commit
//   it shows. lib/workflows.mjs also passes --no-show-signature.
// - No lazy fetch. In a partial clone, `log` fetches a missing tree or blob from the remote the config names, and on
//   the way runs core.sshCommand, remote.<name>.uploadpack or a credential helper, and sends a request. Newer git skips
//   the fetch with GIT_NO_LAZY_FETCH=1. GIT_ALLOW_PROTOCOL, set to no real protocol, refuses every transport, for a git
//   too old to know that variable. The missing object then makes git fail, and that repository reports nothing.
// - --no-pager: git starts no pager when its output is not a terminal, and here it never is; this makes it explicit.
// diff.external, a diff driver's command and textconv run only for a patch, which `log --name-only` doesn't make;
// lib/workflows.mjs passes --no-ext-diff and --no-textconv as well. ls-files and log run no hooks.
import { execFileSync } from 'node:child_process';

const ENV = { GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: 'none' };
const ARGS = ['--no-pager', '-c', 'core.fsmonitor=false', '-c', 'log.showSignature=false'];

/** git <args> in `repo`, with the settings above. Returns stdout, and throws when git fails (as execFileSync does). */
export const git = (repo, args, opts = {}) => execFileSync('git', [...ARGS, '-C', repo, ...args], { ...opts, env: { ...process.env, ...ENV } });
