// Running containers keep the trust list their image was built with, whatever the host has. For each running
// container, a tool inside it (curl, python3 or wget, whichever the image has) opens a normal site first (the control),
// then a self-signed site (it must refuse it, or the tool doesn't check certificates and can show nothing), then the
// test hosts. Read-only: `ps` and `exec` of a request; nothing is written into any container.
import { execFile, execFileSync } from 'node:child_process';

const SELF_SIGNED = 'https://self-signed.badssl.com/';
// Prints tool=<name>, then exits 0 if it connected with verification on, 1 if not, 3 if the image has no tool.
const PROBE = `u="$1"; t="$2"
if command -v curl >/dev/null 2>&1; then echo tool=curl; curl -s -o /dev/null --max-time "$t" "$u" && exit 0 || exit 1
elif command -v python3 >/dev/null 2>&1; then echo tool=python3; python3 -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2]))' "$u" "$t" >/dev/null 2>&1 && exit 0 || exit 1
elif command -v wget >/dev/null 2>&1; then echo tool=wget; wget -q -O /dev/null -T "$t" "$u" >/dev/null 2>&1 && exit 0 || exit 1
else exit 3; fi`;

/** Running containers → [{ id, name, image }]; { error } when the engine can't be asked; null when it isn't running. */
export function listContainers(engine) {
  try {
    const out = execFileSync(engine, ['ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'], { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
    return out.split('\n').filter(Boolean).map((l) => { const [id, name, image] = l.split('\t'); return { id, name, image }; });
  } catch (e) {
    const err = `${e.stderr ?? ''}${e.message ?? ''}`;
    if (/permission denied/i.test(err)) return { error: 'permission denied: run with sudo, or add this user to the docker group' };
    return null;   // the daemon isn't running (or isn't installed properly): there are no running containers to check
  }
}

/** One request from inside the container → { ok, tool, missing }. */
function probeIn(engine, id, url, timeoutMs) {
  const t = String(Math.ceil(timeoutMs / 1000));
  return new Promise((res) => execFile(engine, ['exec', id, 'sh', '-c', PROBE, 'wardlatch', url, t], { timeout: timeoutMs + 6000, encoding: 'utf8' }, (err, out) => {
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
