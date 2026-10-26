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
// - GIT_NO_REPLACE_OBJECTS=1: a ref under refs/replace/ can't put another commit in a commit's place in what `log`
//   shows. The ref is still a ref: `log --all` reads the commit it points to as one more tip.
// - The environment is lib/run.mjs's allowlist for git, not the caller's: GIT_DIR or GIT_WORK_TREE from a hook or a CI
//   step pointed every scan at one other repository (GHSA-84hq-29mv-c9fj), and DEVELOPER_DIR did the same through
//   macOS's /usr/bin/git shim, which 0.1.8's list of dropped GIT_* names didn't cover.
// - GIT_GRAFT_FILE=/dev/null and core.commitGraph=false: a .git/info/grafts file can re-parent a planted commit onto one
//   that already has the file, and a crafted commit-graph can do the same; neither is read. advice.graftFileDeprecated
//   =false: git 2.54 otherwise prints an 8-line hint about grafts on every log, which became the reason shown.
// diff.external, a diff driver's command and textconv run only for a patch, which `log --name-only` doesn't make;
// lib/workflows.mjs passes --no-ext-diff and --no-textconv as well. ls-files and log run no hooks.
// git itself is found on PATH and run by its absolute path, from /, with the repository given as an absolute -C. A
// bare name could otherwise resolve in the current folder (a project, when started with npx).
import { runSync } from './run.mjs';
import { resolve } from 'node:path';
import { findOnPath } from './binaries.mjs';

const ENV = { GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: 'none', GIT_NO_REPLACE_OBJECTS: '1', GIT_GRAFT_FILE: '/dev/null' };
const ARGS = ['--no-pager', '-c', 'core.fsmonitor=false', '-c', 'log.showSignature=false', '-c', 'log.showRoot=true', '-c', 'core.commitGraph=false', '-c', 'advice.graftFileDeprecated=false'];

/** git <args> in `repo`, with the settings above. Returns stdout (a string, or a Buffer with encoding 'buffer'), and throws
 *  when git fails (as execFileSync does). */
export const git = (repo, args, { timeout = 20000, maxBuffer, encoding, input } = {}) => {
  const bin = findOnPath(process.platform === 'win32' ? 'git.exe' : 'git');
  if (!bin) throw Object.assign(new Error('git is not installed'), { code: 'ENOENT' });
  return runSync(bin, [...ARGS, '-C', resolve(repo), ...args], { purpose: 'git', timeout, maxBuffer, encoding, input, env: ENV });
};

/** Why a git call failed, in one short line: a timeout or too much output by name, else git's first line of stderr that
 *  isn't a hint, else the exit status. */
export const gitError = (e) => (e.code === 'ETIMEDOUT' ? 'git did not finish in time' : e.code === 'ENOBUFS' ? 'git wrote more than could be read'
  : String(e.stderr ?? '').split('\n').map((l) => l.trim()).find((l) => l && !/^hint:/i.test(l))
    ?? (e.code === 'ENOENT' ? 'git is not installed' : `git failed${e.status != null ? ` (exit ${e.status})` : ''}`)).slice(0, 160);
