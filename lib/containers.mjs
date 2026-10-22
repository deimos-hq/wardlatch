// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Running containers keep the trust list their image was built with, whatever the host has. For each running
// container, a tool inside it (curl, python3 or wget, whichever the image has) opens a normal site first (the control),
// then a self-signed site (it must refuse it, or the tool doesn't check certificates and can show nothing), then the
// test hosts. Read-only: `ps` and `exec` of a request; nothing is written into any container.
import { run, runSync } from './run.mjs';
import { findOnPath } from './binaries.mjs';
import { safe } from './report.mjs';

const SELF_SIGNED = 'https://self-signed.badssl.com/';
// Prints tool=<name>, then exits 0 if it connected with verification on, 1 only if the tool refused the certificate
// (curl 60, Python's SSLCertVerificationError, wget 5), 2 for any other failure (a timeout, DNS, a reset), and 3 if the
// image has no tool. Up to 0.1.8 every failure exited 1, so a container whose network couldn't reach the test hosts
// read SAFE: the host probe stopped doing that in 0.1.7 (GHSA-x4qj-7j53-r4cv), the container probe didn't.
// python3 runs with -I -S, as on the host: no user site, no PYTHON* variables, no current folder on the path, and no
// `site`, so no .pth file in the image's site-packages runs. A python3 older than 3.4 has no -I and exits with an
// error: the normal-site control then fails, so the container is UNKNOWN, never SAFE.
const PROBE = `u="$1"; t="$2"
if command -v curl >/dev/null 2>&1; then echo tool=curl; curl -s -o /dev/null --max-time "$t" "$u"; r=$?; [ $r -eq 0 ] && exit 0; [ $r -eq 60 ] && exit 1; exit 2
elif command -v python3 >/dev/null 2>&1; then echo tool=python3; python3 -I -S -c 'import sys,ssl,urllib.request,urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2]))
except urllib.error.HTTPError:
    sys.exit(0)
except Exception as e:
    r=getattr(e,"reason",e); V=getattr(ssl,"SSLCertVerificationError",None)
    sys.exit(1 if (V and isinstance(r,V)) or (isinstance(r,ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(r)) else 2)' "$u" "$t" >/dev/null 2>&1; exit $?
elif command -v wget >/dev/null 2>&1; then echo tool=wget; wget -q -O /dev/null -T "$t" "$u" >/dev/null 2>&1; r=$?; [ $r -eq 0 ] && exit 0; [ $r -eq 5 ] && exit 1; exit 2
else exit 3; fi`;

// DOCKER_HOST / CONTAINER_HOST are not passed to the engine (lib/run.mjs). With one set and no local engine answering,
// the containers it names were not checked: that is a gap to report, not "not running".
export const HOST_NOT_FOLLOWED = 'DOCKER_HOST (or CONTAINER_HOST) is set, and Wardlatch does not follow it, since it can point at any host: select the engine with `docker context use` instead, or pass --no-containers';

// What docker and podman print when their daemon or machine isn't running: the only failure that means "no containers".
const NOT_RUNNING = /cannot connect to (the )?(docker|podman)|is the docker daemon running|failed to connect to the docker API|unable to connect to podman/i;

/**
 * Running containers → [{ id, name, image }]; null when the engine isn't installed or isn't running; { error } when it
 * is there but can't be asked (hung, refused, too much output, any other failure). An error is UNKNOWN, never "no
 * containers": up to 0.1.6 every failure but "permission denied" read as not running, and the run could end all SAFE.
 */
export function listContainers(engine) {
  const bin = findOnPath(engine);
  if (!bin) return null;
  try {
    const out = runSync(bin, ['ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'], { purpose: 'engine', timeout: 10000 });
    return out.split('\n').filter(Boolean).map((l) => { const [id, name, image] = l.split('\t'); return { id, name, image }; });
  } catch (e) {
    const stderr = String(e.stderr ?? '');
    if (e.code === 'ENOENT') return null;
    if (/permission denied/i.test(`${stderr}${e.message ?? ''}`)) return { error: 'permission denied: run with sudo, or add this user to the docker group' };
    if (NOT_RUNNING.test(stderr)) return process.env.DOCKER_HOST || process.env.CONTAINER_HOST ? { error: HOST_NOT_FOLLOWED } : null;
    if (e.code === 'ETIMEDOUT') return { error: 'did not answer within 10 seconds: restart it and run again, or pass --no-containers to skip running containers' };
    if (e.code === 'ENOBUFS') return { error: 'listed more containers than could be read: pass --no-containers to skip them' };
    const first = (stderr.split('\n').map((l) => l.trim()).find(Boolean) ?? String(e.code ?? (e.status != null ? `exit ${e.status}` : e.signal ?? 'no message'))).slice(0, 160);
    return { error: `could not list its containers (${first})` };
  }
}

/** One request from inside the container → { result: 'ok' | 'refused' | 'error', tool, missing }. */
async function probeIn(engine, id, url, timeoutMs) {
  const t = String(Math.ceil(timeoutMs / 1000));
  const bin = findOnPath(engine);
  if (!bin) return { result: 'error', tool: undefined, missing: false };
  const { err, stdout } = await run(bin, ['exec', id, 'sh', '-c', PROBE, 'wardlatch', url, t], { purpose: 'engine', timeout: timeoutMs + 6000 });
  const tool = (/tool=(\w+)/.exec(stdout) ?? [])[1];
  const code = err ? (typeof err.code === 'number' ? err.code : -1) : 0;
  return { result: code === 0 ? 'ok' : code === 1 ? 'refused' : 'error', tool, missing: !tool };
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
  const fields = { tool: control.tool, trusted: hits, tested: up.length };
  return hits.length ? { status: 'EXPOSED', ...fields } : safe(up.map((c) => c.host ?? c.url), fields);
}
