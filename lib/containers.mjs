// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Running containers keep the trust list their image was built with, whatever the host has. For each running
// container, a tool inside it (curl, python3 or wget, whichever the image has) opens a normal site first (the control),
// then a self-signed site (it must refuse it, or the tool doesn't check certificates and can show nothing), then the
// test hosts. Read-only: `ps` and `exec` of a request; nothing is written into any container.
import { execFile, execFileSync } from 'node:child_process';

const SELF_SIGNED = 'https://self-signed.badssl.com/';
// Prints tool=<name>, then exits 0 if it connected with verification on, 1 if not, 3 if the image has no tool.
// python3 runs with -I -S, as on the host: no user site, no PYTHON* variables, no current folder on the path, and no
// `site`, so no .pth file in the image's site-packages runs. A python3 older than 3.4 has no -I and exits with an
// error: the normal-site control then fails, so the container is UNKNOWN, never SAFE.
const PROBE = `u="$1"; t="$2"
if command -v curl >/dev/null 2>&1; then echo tool=curl; curl -s -o /dev/null --max-time "$t" "$u" && exit 0 || exit 1
elif command -v python3 >/dev/null 2>&1; then echo tool=python3; python3 -I -S -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2]))' "$u" "$t" >/dev/null 2>&1 && exit 0 || exit 1
elif command -v wget >/dev/null 2>&1; then echo tool=wget; wget -q -O /dev/null -T "$t" "$u" >/dev/null 2>&1 && exit 0 || exit 1
else exit 3; fi`;

// What docker and podman print when their daemon or machine isn't running: the only failure that means "no containers".
const NOT_RUNNING = /cannot connect to (the )?(docker|podman)|is the docker daemon running|failed to connect to the docker API|unable to connect to podman/i;

/**
 * Running containers → [{ id, name, image }]; null when the engine isn't installed or isn't running; { error } when it
 * is there but can't be asked (hung, refused, too much output, any other failure). An error is UNKNOWN, never "no
 * containers": up to 0.1.6 every failure but "permission denied" read as not running, and the run could end all SAFE.
 */
export function listContainers(engine) {
  try {
    const out = execFileSync(engine, ['ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'], { encoding: 'utf8', timeout: 10000, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    return out.split('\n').filter(Boolean).map((l) => { const [id, name, image] = l.split('\t'); return { id, name, image }; });
  } catch (e) {
    const stderr = String(e.stderr ?? '');
    if (e.code === 'ENOENT') return null;
    if (/permission denied/i.test(`${stderr}${e.message ?? ''}`)) return { error: 'permission denied: run with sudo, or add this user to the docker group' };
    if (NOT_RUNNING.test(stderr)) return null;
    if (e.code === 'ETIMEDOUT') return { error: 'did not answer within 10 seconds: restart it and run again, or pass --no-containers to skip running containers' };
    if (e.code === 'ENOBUFS') return { error: 'listed more containers than could be read: pass --no-containers to skip them' };
    const first = (stderr.split('\n').map((l) => l.trim()).find(Boolean) ?? String(e.code ?? (e.status != null ? `exit ${e.status}` : e.signal ?? 'no message'))).slice(0, 160);
    return { error: `could not list its containers (${first})` };
  }
}

/** One request from inside the container → { ok, tool, missing }. */
function probeIn(engine, id, url, timeoutMs) {
  const t = String(Math.ceil(timeoutMs / 1000));
  return new Promise((res) => execFile(engine, ['exec', id, 'sh', '-c', PROBE, 'wardlatch', url, t], { timeout: timeoutMs + 6000, killSignal: 'SIGKILL', encoding: 'utf8' }, (err, out) => {
    const tool = (/tool=(\w+)/.exec(out ?? '') ?? [])[1];
    res({ ok: !err, tool, missing: !tool });
  }));
}

/**
 * Check one container against the reachable canaries.
 * → { status: 'SAFE' | 'EXPOSED' | 'UNKNOWN', tool?, trusted: string[], tested, reason? }
 */
export async function checkContainer(engine, ct, canaries, { controlUrl, timeoutMs = 7000 } = {}) {
  const up = canaries.filter((c) => c.up);
  const unknown = (reason, tool) => ({ status: 'UNKNOWN', tool, trusted: [], tested: 0, reason });
  if (!up.length) return unknown('no test host answered, so trust could not be tested');
  const control = await probeIn(engine, ct.id, controlUrl, timeoutMs);
  if (control.missing) return unknown('no shell, curl, python3 or wget inside to test with: rebuild it on a fixed base image, or mount the host\'s fixed bundle (see the page)');
  if (!control.ok) return unknown('control failed: this container could not open a normal site, so a refusal would prove nothing', control.tool);
  if ((await probeIn(engine, ct.id, SELF_SIGNED, timeoutMs)).ok) return unknown(`control failed: ${control.tool} in this container accepted a self-signed site, so it doesn't check certificates and can't show trust`, control.tool);
  const hits = (await Promise.all(up.map(async (c) => ((await probeIn(engine, ct.id, c.url, timeoutMs)).ok ? c.id : null)))).filter(Boolean);
  return { status: hits.length ? 'EXPOSED' : 'SAFE', tool: control.tool, trusted: hits, tested: up.length };
}
