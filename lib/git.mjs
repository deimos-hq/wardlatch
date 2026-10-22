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
// - log.showRoot=true: with log.showRoot=false (in the repository's config or the person's), `log` shows no files for a
//   root commit, so a workflow added in the first commit would be missed and the review would read SAFE.
// - GIT_NO_REPLACE_OBJECTS=1: refs/replace/ can't swap one commit for another in what `log` shows.
// diff.external, a diff driver's command and textconv run only for a patch, which `log --name-only` doesn't make;
// lib/workflows.mjs passes --no-ext-diff and --no-textconv as well. ls-files and log run no hooks.
// git itself is found on PATH and run by its absolute path, from /, with the repository given as an absolute -C. A
// bare name could otherwise resolve in the current folder (a project, when started with npx).
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { findOnPath } from './binaries.mjs';

const ENV = { GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: 'none', GIT_NO_REPLACE_OBJECTS: '1' };
const ARGS = ['--no-pager', '-c', 'core.fsmonitor=false', '-c', 'log.showSignature=false', '-c', 'log.showRoot=true'];

/** git <args> in `repo`, with the settings above. Returns stdout, and throws when git fails (as execFileSync does). */
export const git = (repo, args, opts = {}) => {
  const bin = findOnPath(process.platform === 'win32' ? 'git.exe' : 'git');
  if (!bin) throw Object.assign(new Error('git is not installed'), { code: 'ENOENT' });
  return execFileSync(bin, [...ARGS, '-C', resolve(repo), ...args], { ...opts, cwd: '/', env: { ...process.env, ...ENV } });
};

/** Why a git call failed, in one short line: git's first line of stderr, else the timeout or exit status. */
export const gitError = (e) => (String(e.stderr ?? '').split('\n').map((l) => l.trim()).find(Boolean)
  ?? (e.code === 'ETIMEDOUT' ? 'git did not finish in time' : e.code === 'ENOENT' ? 'git is not installed' : `git failed${e.status != null ? ` (exit ${e.status})` : ''}`)).slice(0, 160);
