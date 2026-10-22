// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Probe one runtime: can it complete a VERIFIED TLS connection to a canary host? It runs the runtime itself, the way
// your code would, with your environment. A connection means the runtime still trusts the compromised chain.
import { execFile } from 'node:child_process';
import { connect } from 'node:tls';
import { isIP } from 'node:net';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';

// Each probe exits 0 when it connected, 1 only when the connection was refused for a certificate-verification error, and
// anything else for any other failure (an HTTP error status still means a verified connection: 0) (no fetch in Node 17 and older, a timeout, a reset, a bundle that can't be
// opened). Only a verification refusal counts as "does not trust"; any other failure makes the line UNKNOWN. Up to 0.1.6
// every failure counted as a refusal, and a Node.js older than 18, which has no fetch(), read SAFE untested.
const NODE = (t) => `const [u,ca]=process.argv.slice(1);
const fail=(e)=>{const c=String((e&&e.code)||(e&&e.cause&&e.cause.code)||'');process.exit(/^(?:CERT_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_|ERR_TLS_CERT_ALTNAME_INVALID$)/.test(c)?1:3);};
require('https').get(u,Object.assign({timeout:${t}},ca?{ca:require('fs').readFileSync(ca)}:{}),r=>{r.resume();process.exit(0)}).on('error',fail).on('timeout',()=>process.exit(3));`;
const PY = (t) => `import sys,ssl,urllib.request,urllib.error
u=sys.argv[1]; ca=sys.argv[2] if len(sys.argv)>2 else None
ctx=ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
try:
    urllib.request.urlopen(u,timeout=${t / 1000},context=ctx)
except urllib.error.HTTPError:
    sys.exit(0)
except Exception as e:
    r=getattr(e,'reason',e)
    V=getattr(ssl,'SSLCertVerificationError',None)
    sys.exit(1 if (V and isinstance(r,V)) or (isinstance(r,ssl.SSLError) and 'CERTIFICATE_VERIFY_FAILED' in str(r)) else 3)`;

/** Exit code of a probe → 'ok' (connected), 'refused' (a certificate-verification refusal) or 'error' (anything else). */
const outcome = (kind, err) => {
  if (!err) return 'ok';
  const code = typeof err.code === 'number' ? err.code : null;
  if (kind === 'curl') return code === 60 ? 'refused' : 'error';   // 60: the peer's certificate could not be verified
  return code === 1 ? 'refused' : 'error';
};

/**
 * One verified connection → 'ok', 'refused' (certificate verification failed) or 'error' (any other failure).
 * forcedCa: trust ONLY this file (the positive control).
 */
export function probe(rt, url, { timeoutMs = 7000, forcedCa } = {}) {
  let argv;
  switch (rt.kind) {
    case 'curl': argv = [...(rt.args ?? []), '-s', '-o', '/dev/null', '--max-time', String(Math.ceil(timeoutMs / 1000)), ...(forcedCa ? ['--cacert', forcedCa] : []), url]; break;
    // macOS's own networking stack (what Safari and Apple's apps use). nscurl exits 0 even when the load fails,
    // so success is read from its output. It can't be pointed at a CA file, so it has no forced-CA control.
    case 'macos-system':
      if (forcedCa) return Promise.resolve('error');
      return new Promise((res) => execFile(rt.bin, [url], { timeout: timeoutMs + 4000, cwd: '/' }, (err, _out, errOut) => res(!err && nscurlOk(errOut) ? 'ok' : !err && /NSURLErrorDomain Code=-120[1-4]\b/.test(errOut) ? 'refused' : 'error')));
    // nscurl's refusal is a certificate error (-1201 bad date, -1202 untrusted, -1203 unknown root, -1204 not yet
    // valid); a refused, reset or timed-out connection is an error, never a refusal.
    // https.get, not fetch(): Node 17 and older have no global fetch. A refusal is a local certificate-verification
    // code only (anchored: a server's TLS alert such as ERR_SSL_TLSV13_ALERT_BAD_CERTIFICATE is not one).
    case 'node': argv = ['-e', NODE(timeoutMs), url, ...(forcedCa ? [forcedCa] : [])]; break;
    // -S as well as -I: -I doesn't stop Python running .pth files from site-packages at startup, and a malicious package
    // can drop one there (LiteLLM 1.107.0's cook.pth, 21 Oct 2026). The probe needs only the standard library's ssl.
    case 'python': argv = ['-I', '-S', '-c', PY(timeoutMs), url, ...(forcedCa ? [forcedCa] : [])]; break;
    default: return Promise.resolve('error');
  }
  // from /, so a version manager's shim picks the person's default runtime, not the current project's pin
  return new Promise((res) => execFile(rt.bin, argv, { timeout: timeoutMs + 4000, cwd: '/', env: { ...process.env, ...(rt.env ?? {}) } }, (err) => res(outcome(rt.kind, err))));
}

/** nscurl prints "Load failed with error: …" (NSURLErrorDomain) when the connection is refused. */
export const nscurlOk = (text) => !/Load failed|NSURLErrorDomain|error/i.test(text);

/** Kinds whose probe can trust ONLY a given CA file; the rest are controlled with a normal site instead. */
export const canForceCa = (kind) => kind !== 'macos-system';

/** Reachability control: a handshake with verification OFF, so a host that is down is never mistaken for "not trusted". */
export function reachable(host, port = 443, timeoutMs = 7000) {
  return new Promise((res) => {
    const s = connect({ host, port, ...(isIP(host) ? {} : { servername: host }), rejectUnauthorized: false, timeout: timeoutMs }, () => { s.end(); res(true); });
    s.on('error', () => res(false)); s.on('timeout', () => { s.destroy(); res(false); });
  });
}

/**
 * Check one runtime against every reachable canary.
 * → { status: 'SAFE' | 'EXPOSED' | 'UNKNOWN', trusted: string[], tested, reason? }
 * UNKNOWN when no canary answers, or when the positive control fails (the probe could not have seen exposure).
 */
export async function check(rt, canaries, { rootsPem, timeoutMs, controlUrl } = {}) {
  const up = canaries.filter((c) => c.up);
  if (!up.length) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'no test host answered, so trust could not be tested' };
  // A curl row that names its own bundle (a virtual environment's certifi, a Linux system bundle) needs that file: curl
  // would fail on a missing one, every test host would look refused, and the forced-roots control, whose --cacert comes
  // later and wins, would still pass. That would read SAFE without having tested the bundle.
  const ca = rt.kind === 'curl' && (rt.args ?? []).indexOf('--cacert');
  if (ca !== false && ca >= 0 && !(rt.args[ca + 1] && isAbsolute(rt.args[ca + 1]) && existsSync(rt.args[ca + 1])))
    return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `the CA bundle to test (${rt.args[ca + 1] ?? 'none given'}) could not be found, so it was not tested` };
  let blocks = false;
  if (canForceCa(rt.kind)) {
    if (rootsPem && (await probe(rt, up[0].url, { timeoutMs, forcedCa: rootsPem })) !== 'ok') {
      // Refused even with the compromised roots forced in. Either the runtime blocks the compromised keys themselves
      // (Node.js 26.12.1 and later reject chains through them whatever the roots), or it can't connect at all. A normal
      // site tells the two apart: if it opens, the refusal is the runtime's own block, the strongest SAFE there is.
      if (!controlUrl || (await probe(rt, controlUrl, { timeoutMs })) !== 'ok')
        return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'positive control failed: even with the compromised roots forced in, this runtime could not connect, and it could not open a normal site either, so the check cannot see exposure here' };
      blocks = true;
    }
  } else if (controlUrl && (await probe(rt, controlUrl, { timeoutMs })) !== 'ok') {
    return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'control failed: this runtime could not open a normal site either, so a refusal here would prove nothing' };
  }
  const results = await Promise.all(up.map(async (c) => ({ id: c.id, got: await probe(rt, c.url, { timeoutMs }) })));
  const hits = results.filter((x) => x.got === 'ok').map((x) => x.id);
  // a failure that is not a certificate refusal proves nothing: without a connection, it is not a SAFE
  const failed = results.filter((x) => x.got === 'error').length;
  if (!hits.length && failed) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `${failed} of ${up.length} test connections failed for a reason other than a certificate refusal, so this runtime's trust could not be confirmed` };
  const r = { status: hits.length ? 'EXPOSED' : 'SAFE', trusted: hits, tested: up.length };
  if (blocks && !hits.length) r.note = 'blocks the compromised keys themselves, even with their roots trusted';
  return r;
}
