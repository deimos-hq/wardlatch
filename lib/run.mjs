// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The one way Wardlatch starts a program. Every child gets an argument list (never a shell), an absolute program path,
// the folder /, a timeout that kills with SIGKILL (a program that ignores SIGTERM, or leaves a child holding the pipe,
// can't hang the run), and an environment built for its PURPOSE from an allowlist, never the caller's environment as is.
//
// Why an allowlist: up to 0.1.8 children inherited the caller's environment, minus a list of known-bad names. A list
// is always one name short: GIT_DIR pointed every git scan at another repository (GHSA-84hq-29mv-c9fj), and
// DEVELOPER_DIR did the same through macOS's /usr/bin/git shim. Here a child only gets what its purpose needs.
//
// Purposes:
//   version  a found program asked for its version (node -v, curl --version, php -n -v, go version, ...)
//   git      git, run read-only in a repository Wardlatch found (lib/git.mjs adds its own settings)
//   engine   docker or podman, listing containers or images, or running the probe inside a container
//   probe    a runtime asked to open a TLS connection the way the person's own programs would: the person's own
//            environment (CA bundles, proxies, OpenSSL config all change what a runtime trusts, and that is what is
//            being measured), minus anything that would load code into the probe (NODE_OPTIONS --require and the like)
import { execFile, execFileSync } from 'node:child_process';
import { isAbsolute } from 'node:path';

const PURPOSES = ['version', 'git', 'engine', 'probe'];
// what every child may keep from the caller: where to find programs, whose home it is, and nothing that changes
// what a program reads, runs or connects to
const BASE = ['PATH', 'HOME', 'USER', 'LOGNAME'];
const KEEP = {
  version: [],
  // the person's own global and system git config (read like ~/.gitconfig); the test-only owner check can only refuse
  git: ['XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM', 'GIT_TEST_ASSUME_DIFFERENT_OWNER'],
  // which engine: the one the person's own docker config in their home folder selects. DOCKER_HOST, DOCKER_CONTEXT,
  // DOCKER_CONFIG and the podman equivalents are not passed: they can point at any host and come from whoever started
  // Wardlatch (a CI step, a hook). The CLI reports a run where one is set as UNKNOWN for the containers it names.
  engine: ['XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME'],
};
// fixed values per purpose: no locale surprises in parsed output, and Go never switches toolchains
const SET = { version: { LC_ALL: 'C', GOTOOLCHAIN: 'local' }, git: { LC_ALL: 'C' }, engine: { LC_ALL: 'C' }, probe: {} };
// NODE_OPTIONS: only the flags that change what Node trusts reach a probe. 0.1.9's first cut dropped a list of flags
// that load code, and --snapshot-blob still ran code inside a probe: a list of what to drop is always one flag short.
const TRUST_FLAG = /^--(?:use-openssl-ca|use-bundled-ca|use-system-ca|tls-min-v1\.[0-3]|tls-max-v1\.[23]|tls-cipher-list=[\w:+!@.-]+)$/;
const trustFlagsOnly = (v) => String(v).split(/\s+/).filter((w) => TRUST_FLAG.test(w)).join(' ');
// never passed to a probe: they load code into the program, or point it at files the caller chose (a .curlrc named by
// CURL_HOME can make curl write files); the person's own ~/.curlrc still applies, as it does to their own curl
const PROBE_DROP = /^(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_\w+|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME|PYTHONINSPECT|NODE_PATH|NODE_REPL_EXTERNAL_MODULE|CURL_HOME|BASH_ENV|ENV)$/;

/** The environment a child gets for `purpose`, plus `extra` (an object of the caller's own settings, never a string). */
export function envFor(purpose, extra = {}, env = process.env) {
  if (!PURPOSES.includes(purpose)) throw new Error(`unknown purpose "${purpose}"`);
  if (extra === null || typeof extra !== 'object' || Array.isArray(extra)) throw new TypeError('extra must be an object');
  let out;
  if (purpose === 'probe') {
    out = Object.fromEntries(Object.entries(env).filter(([k]) => !PROBE_DROP.test(k)));
    if (out.NODE_OPTIONS !== undefined) out.NODE_OPTIONS = trustFlagsOnly(out.NODE_OPTIONS);
    if (!out.NODE_OPTIONS) delete out.NODE_OPTIONS;
  } else {
    out = {};
    for (const k of [...BASE, ...KEEP[purpose]]) if (env[k] !== undefined) out[k] = env[k];
  }
  return { ...out, ...SET[purpose], ...extra };
}

function options(bin, purpose, { timeout, maxBuffer = 16 * 1024 * 1024, env = {}, encoding = 'utf8' }) {
  if (!isAbsolute(String(bin))) throw new Error(`not an absolute program path: ${bin}`);
  if (!(timeout > 0)) throw new Error('a timeout is required');
  return { cwd: '/', timeout, killSignal: 'SIGKILL', maxBuffer, encoding, env: envFor(purpose, env), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true };
}

/** Run and wait. Returns stdout; throws as execFileSync does (e.status, e.stdout, e.stderr, e.code 'ETIMEDOUT'). */
export function runSync(bin, args, { purpose, ...opts }) {
  return execFileSync(bin, args, options(bin, purpose, opts));
}

/** Run without blocking → Promise<{ err, stdout, stderr }> (never rejects). */
export function run(bin, args, { purpose, ...opts }) {
  let o;
  try { o = options(bin, purpose, opts); } catch (err) { return Promise.resolve({ err, stdout: '', stderr: '' }); }
  return new Promise((res) => execFile(bin, args, o, (err, stdout, stderr) => res({ err, stdout: stdout ?? '', stderr: stderr ?? '' })));
}
