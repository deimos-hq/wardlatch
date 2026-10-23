// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Running containers keep the trust list their image was built with, whatever the host has. For each running
// container, a tool inside it (curl, python3 or wget, whichever the image has) opens a normal site first (the control),
// then a self-signed site (it must refuse it, or the tool doesn't check certificates and can show nothing), then the
// test hosts. Read-only: `ps` and `exec` of a request; nothing is written into any container.
import { dirname } from 'node:path';
import { run, runSync } from './run.mjs';
import { findOnPath } from './binaries.mjs';
import { safe } from './report.mjs';
import { pathState, ownerOf, writableByOthers } from './files.mjs';
import { uncoveredRoots } from './probe.mjs';

const SELF_SIGNED = 'https://self-signed.badssl.com/';
// Prints one line, `tool=<name> wardlatch-result=<ok|refused|error>` (or `wardlatch-result=notool`), and the result is
// read from that line only: ok when it connected with verification on, refused only when the tool refused the
// certificate (curl 60, Python's SSLCertVerificationError, wget 5), error for anything else (a timeout, DNS, a reset).
// Up to 0.1.8 every failure was a refusal, so a container whose network couldn't reach the test hosts read SAFE (the
// host probe stopped doing that in 0.1.7, GHSA-x4qj-7j53-r4cv). Up to 27cdfbd the result was the exit code, and
// `docker exec` itself exits 1 when the container has stopped: a container that stopped mid-check read SAFE. No line,
// no result.
// python3 runs with -I -S, as on the host: no user site, no PYTHON* variables, no current folder on the path, and no
// `site`, so no .pth file in the image's site-packages runs. It exits 10 for a refusal, so a crash (exit 1) is an
// error; a python3 older than 3.4 has no -I and exits with an error too: the normal-site control then fails, so the
// container is UNKNOWN, never SAFE.
const PROBE = `u="$1"; t="$2"; say() { echo "tool=$1 wardlatch-result=$2"; exit 0; }
if command -v curl >/dev/null 2>&1; then curl -s -o /dev/null --max-time "$t" "$u"; r=$?; [ $r -eq 0 ] && say curl ok; [ $r -eq 60 ] && say curl refused; say curl error
elif command -v python3 >/dev/null 2>&1; then python3 -I -S -c 'import sys,ssl,urllib.request,urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2]))
except urllib.error.HTTPError:
    sys.exit(0)
except Exception as e:
    r=getattr(e,"reason",e); V=getattr(ssl,"SSLCertVerificationError",None)
    sys.exit(10 if (V and isinstance(r,V)) or (isinstance(r,ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(r)) else 11)' "$u" "$t" >/dev/null 2>&1; r=$?
  [ $r -eq 0 ] && say python3 ok; [ $r -eq 10 ] && say python3 refused; say python3 error
elif command -v wget >/dev/null 2>&1; then wget -q -O /dev/null -T "$t" "$u" >/dev/null 2>&1; r=$?; [ $r -eq 0 ] && say wget ok; [ $r -eq 5 ] && say wget refused; say wget error
else echo wardlatch-result=notool; fi`;

// Which engine to ask (owner, 22 Oct 2026). DOCKER_HOST or CONTAINER_HOST naming a local socket file (unix://...) owned by
// this user or root is followed: that is how Colima, Podman machine and rootless Docker are set up, and 0.1.9's first
// cut, which followed none, made every such machine read UNKNOWN. One naming anything else (tcp://, ssh://), or a
// socket owned by someone else, could point the engine at any host, and is not followed; nor are DOCKER_CONTEXT,
// DOCKER_CONFIG and CONTAINER_CONNECTION, which can name remote hosts. → { env: what the engine gets, refused: names }
export function engineHost(env = process.env) {
  const out = { env: {}, refused: [] };
  for (const k of ['DOCKER_HOST', 'CONTAINER_HOST']) {
    if (!env[k]) continue;
    const sock = (/^unix:\/\/(\/.+)$/.exec(env[k]) ?? [])[1];
    // a socket file that is gone (Colima or Podman machine stopped) names no host at all: followed, the engine then says
    // it isn't running, as it would for the person (0.1.9's first cut said UNKNOWN: an unfollowed host)
    // (its folder must be this user's or root's and closed to everyone else, not /tmp, so no one else can put a socket
    // there while Wardlatch runs)
    const mine = (p) => [0, process.getuid?.()].includes(ownerOf(p));
    const st = sock ? pathState(sock) : '';
    if ((st === 'other' && mine(sock)) || (st === 'gone' && pathState(dirname(sock)) === 'dir' && mine(dirname(sock)) && writableByOthers(dirname(sock)) === false)) out.env[k] = env[k];
    else out.refused.push(k);
  }
  // docker ignores DOCKER_CONTEXT when DOCKER_HOST is set: a followed DOCKER_HOST settles which engine is asked
  for (const k of ['DOCKER_CONTEXT', 'DOCKER_CONFIG', 'CONTAINER_CONNECTION']) if (env[k] && !(k === 'DOCKER_CONTEXT' && out.env.DOCKER_HOST)) out.refused.push(k);
  return out;
}
// With a variable refused and no engine answering locally, the containers it names were not checked: a gap to report,
// not "not running".
export const HOST_NOT_FOLLOWED = 'DOCKER_HOST (or CONTAINER_HOST) names a remote host or a socket another user owns, and Wardlatch does not follow it, since it can point at any host: select the engine with `docker context use` instead, or pass --no-containers';

// What docker and podman print when their daemon or machine isn't running: the only failure that means "no containers".
const NOT_RUNNING = /cannot connect to (the )?(docker|podman)|is the docker daemon running|failed to connect to the docker API|unable to connect to podman/i;

/**
 * Why asking an engine failed: 'missing' (it can't be started), 'denied', 'not-running', 'timeout', 'too-much' or
 * 'other'. The one rule for containers and local images alike. Permission comes first: Podman's refusal of its socket
 * says both "Cannot connect to Podman" and "permission denied", and up to b03e7be the image check read it as not running
 * (SAFE, exit 0) while the container check said UNKNOWN.
 */
export function engineFailure(e) {
  const stderr = String(e.stderr ?? '');
  if (e.code === 'ENOENT') return 'missing';
  if (/permission denied/i.test(`${stderr}${e.message ?? ''}`)) return 'denied';
  if (NOT_RUNNING.test(stderr)) return 'not-running';
  if (e.code === 'ETIMEDOUT') return 'timeout';
  if (e.code === 'ENOBUFS') return 'too-much';
  return 'other';
}
export const ENGINE_DENIED = 'permission denied: run with sudo, or add this user to the docker group';

/**
 * Running containers → [{ id, name, image }]; null when the engine isn't installed or isn't running; { error } when it
 * is there but can't be asked (hung, refused, too much output, any other failure). An error is UNKNOWN, never "no
 * containers": up to 0.1.6 every failure but "permission denied" read as not running, and the run could end all SAFE.
 */
export function listContainers(engine) {
  const bin = findOnPath(engine);
  if (!bin) return null;
  try {
    const out = runSync(bin, ['ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'], { purpose: 'engine', timeout: 10000, env: engineHost().env });
    return out.split('\n').filter(Boolean).map((l) => { const [id, name, image] = l.split('\t'); return { id, name, image }; });
  } catch (e) {
    const stderr = String(e.stderr ?? '');
    const why = engineFailure(e);
    if (why === 'missing') return null;
    if (why === 'denied') return { error: ENGINE_DENIED };
    if (why === 'not-running') return engineHost().refused.some((k) => k.endsWith('_HOST')) ? { error: HOST_NOT_FOLLOWED } : null;
    if (why === 'timeout') return { error: 'did not answer within 10 seconds: restart it and run again, or pass --no-containers to skip running containers' };
    if (why === 'too-much') return { error: 'listed more containers than could be read: pass --no-containers to skip them' };
    const first = (stderr.split('\n').map((l) => l.trim()).find(Boolean) ?? String(e.code ?? (e.status != null ? `exit ${e.status}` : e.signal ?? 'no message'))).slice(0, 160);
    return { error: `could not list its containers (${first})` };
  }
}

/** One request from inside the container → { result: 'ok' | 'refused' | 'error', tool, missing, why }. The result
 *  comes from the probe's own line; without it (the container stopped, the engine failed, no shell) it is an error. */
async function probeIn(engine, id, url, timeoutMs) {
  const t = String(Math.ceil(timeoutMs / 1000));
  const bin = findOnPath(engine);
  if (!bin) return { result: 'error', tool: undefined, missing: false, why: `${engine} not found` };
  const { err, stdout, stderr } = await run(bin, ['exec', id, 'sh', '-c', PROBE, 'wardlatch', url, t], { purpose: 'engine', timeout: timeoutMs + 6000, env: engineHost().env });
  // exactly one result line: more than one (an image printing its own) is no result
  const lines = [...String(stdout).matchAll(/^(?:tool=(\w+) )?wardlatch-result=(ok|refused|error|notool)$/gm)];
  const m = lines.length === 1 ? lines[0] : null;
  // 126 and 127: the container has no `sh` to run the probe with (the engine itself exits 1 for its own errors)
  if (!m && (err?.code === 126 || err?.code === 127)) return { result: 'error', tool: undefined, missing: true };
  if (!m) return { result: 'error', tool: undefined, missing: false, why: (String(stderr).split('\n').map((l) => l.trim()).find(Boolean) ?? String(err?.code ?? 'no result')).slice(0, 160) };
  return { result: m[2] === 'notool' ? 'error' : m[2], tool: m[1], missing: m[2] === 'notool' };
}

/**
 * Check one container against the reachable canaries.
 * → { status: SAFE | EXPOSED | UNKNOWN, tool?, trusted: string[], tested, reason?, searched? }
 */
export async function checkContainer(engine, ct, canaries, { controlUrl, timeoutMs = 7000 } = {}) {
  const up = canaries.filter((c) => c.up);
  const unknown = (reason, tool) => ({ status: 'UNKNOWN', tool, trusted: [], tested: 0, reason });
  if (!up.length) return unknown('no test host answered, so trust could not be tested');
  const control = await probeIn(engine, ct.id, controlUrl, timeoutMs);
  if (control.missing) return unknown('no shell, curl, python3 or wget inside to test with: rebuild it on a fixed base image, or mount the host\'s fixed bundle (see the page)');
  if (!control.tool) return unknown(`a test could not be run inside this container (${control.why})`);
  if (control.result !== 'ok') return unknown('control failed: this container could not open a normal site, so a refusal would prove nothing', control.tool);
  // the self-signed site must be REFUSED for its certificate: accepted, the tool doesn't check certificates; failing for
  // another reason, it proves nothing either way
  const self = await probeIn(engine, ct.id, SELF_SIGNED, timeoutMs);
  if (self.result === 'ok') return unknown(`control failed: ${control.tool} in this container accepted a self-signed site, so it doesn't check certificates and can't show trust`, control.tool);
  if (self.result !== 'refused') return unknown(`control failed: ${control.tool} in this container could not reach the self-signed test site, so it can't be shown to check certificates`, control.tool);
  const results = await Promise.all(up.map(async (c) => ({ id: c.id, got: (await probeIn(engine, ct.id, c.url, timeoutMs)).result })));
  const hits = results.filter((x) => x.got === 'ok').map((x) => x.id);
  const failed = results.filter((x) => x.got === 'error').length;
  // a failure that is not a certificate refusal proves nothing: without a connection or a refusal, it is not a SAFE
  if (!hits.length && failed) return unknown(`${failed} of ${up.length} test connections from inside this container failed for a reason other than a certificate refusal, so its trust could not be confirmed`, control.tool);
  const uncovered = uncoveredRoots(canaries);
  if (!hits.length && uncovered.length) return unknown(`no test host chained to ${uncovered.join(' or ')} answered, so this container's trust in that root could not be tested`, control.tool);
  const fields = { tool: control.tool, trusted: hits, tested: up.length };
  return hits.length ? { status: 'EXPOSED', ...fields } : safe(up.map((c) => c.host ?? c.url), fields);
}
