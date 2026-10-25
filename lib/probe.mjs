// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Probe one runtime: can it complete a VERIFIED TLS connection to a canary host? It runs the runtime itself, the way
// your code would, with your environment. A connection means the runtime still trusts the compromised chain.
import { run } from './run.mjs';
import { connect } from 'node:tls';
import { isIP } from 'node:net';
import { pathState, readText } from './files.mjs';
import { isAbsolute } from 'node:path';
import { safe } from './report.mjs';

// Each probe exits 0 when it connected, 1 only when the connection was refused for a certificate-verification error, and
// anything else for any other failure (an HTTP error status still means a verified connection: 0) (no fetch in Node 17 and older, a timeout, a reset, a bundle that can't be
// opened). Only a verification refusal counts as "does not trust"; any other failure makes the line UNKNOWN. Up to 0.1.6
// every failure counted as a refusal, and a Node.js older than 18, which has no fetch(), read SAFE untested.
// Node exits 4 for CERT_REVOKED: Node.js 26.12.1, 24.22.1 and 22.23.4 refuse chains through the compromised keys
// with exactly that code, whatever roots are trusted. It is the only refusal that can mean "blocks the keys themselves".
// The forced roots arrive as text in WARDLATCH_CA (read by the parent through lib/files.mjs), not as a path the child
// would have to open itself.
const NODE = (t) => `const [u]=process.argv.slice(1);const ca=process.env.WARDLATCH_CA;
const fail=(e)=>{const c=String((e&&e.code)||(e&&e.cause&&e.cause.code)||'');process.exit(c==='CERT_REVOKED'?4:/^(?:CERT_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_|ERR_TLS_CERT_ALTNAME_INVALID$)/.test(c)?1:3);};
require('https').get(u,Object.assign({timeout:${t}},ca?{ca}:{}),r=>{r.resume();process.exit(0)}).on('error',fail).on('timeout',()=>process.exit(3));`;
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

/** Exit code of a probe → 'ok' (connected), 'blocked' (Node's own block of the compromised keys, CERT_REVOKED),
 *  'refused' (any other certificate-verification refusal) or 'error' (anything else). */
const outcome = (kind, err) => {
  if (!err) return 'ok';
  const code = typeof err.code === 'number' ? err.code : null;
  if (kind === 'curl') return code === 60 ? 'refused' : 'error';   // 60: the peer's certificate could not be verified
  if (kind === 'node' && code === 4) return 'blocked';
  return code === 1 ? 'refused' : 'error';
};

/**
 * One verified connection → 'ok', 'blocked', 'refused' (certificate verification failed) or 'error' (any other failure).
 * forcedCa: trust ONLY this file (the positive control).
 */
export function probe(rt, url, { timeoutMs = 7000, forcedCa } = {}) {
  let argv, caEnv = {};
  switch (rt.kind) {
    case 'curl': argv = [...(rt.args ?? []), '-s', '-o', '/dev/null', '--max-time', String(Math.ceil(timeoutMs / 1000)), ...(forcedCa ? ['--cacert', forcedCa] : []), url]; break;
    // macOS's own networking stack (what Safari and Apple's apps use). nscurl exits 0 even when the load fails,
    // so success is read from its output. It can't be pointed at a CA file, so it has no forced-CA control.
    case 'macos-system':
      if (forcedCa) return Promise.resolve('error');
      return run(rt.bin, [url], { purpose: 'probe', timeout: timeoutMs + 4000 }).then(({ err, stderr }) => (!err && nscurlOk(stderr) ? 'ok' : !err && /NSURLErrorDomain Code=-120[23]\b/.test(stderr) ? 'refused' : 'error'));
    // nscurl's refusal is an untrusted or unknown root (-1202, -1203): what macOS's own block of these keys gives. A
    // bad date (-1201, -1204), as when the test site's certificate expires, says nothing about trust: an error, never
    // a refusal (0.1.8 read it as SAFE). So is a refused, reset or timed-out connection.
    // https.get, not fetch(): Node 17 and older have no global fetch. A refusal is a local certificate-verification
    // code only (anchored: a server's TLS alert such as ERR_SSL_TLSV13_ALERT_BAD_CERTIFICATE is not one).
    case 'node': {
      argv = ['-e', NODE(timeoutMs), url];
      if (forcedCa) { const pem = readText(forcedCa, 1024 * 1024); if (!pem) return Promise.resolve('error'); caEnv = { WARDLATCH_CA: pem }; }
      break;
    }
    // -S as well as -I: -I doesn't stop Python running .pth files from site-packages at startup, and a malicious package
    // can drop one there (LiteLLM 1.107.0's cook.pth, 21 Oct 2026). The probe needs only the standard library's ssl.
    // -B: Python writes no .pyc cache. -I alone still lets python.org, Homebrew, pyenv and uv Pythons write __pycache__
    // beside a standard-library module whose cache is missing or stale, in a folder the person owns; Apple's
    // /usr/bin/python3 writes none under -I, but its plain runs cache into ~/Library/Caches/com.apple.python. A flag, not
    // PYTHONDONTWRITEBYTECODE: -I ignores every PYTHON* variable. Up to 0.1.9 the probe had no -B.
    // The forced roots go in as cafile=, never through SSL_CERT_FILE: Apple's /usr/bin/python3 (LibreSSL 2.8.3) ignores
    // SSL_CERT_FILE and SSL_CERT_DIR, so its default context, here as in the person's own programs, reads
    // /etc/ssl/cert.pem whatever they say; cafile= is read by every Python. One that couldn't use the forced file would
    // refuse the control, and the line is UNKNOWN.
    case 'python': argv = ['-I', '-S', '-B', '-c', PY(timeoutMs), url, ...(forcedCa ? [forcedCa] : [])]; break;
    default: return Promise.resolve('error');
  }
  // from /, so a version manager's shim picks the person's default runtime, not the current project's pin
  // rt.env is a test's own settings when it is an object; a found environment's row carries its folder there as text,
  // which is not settings (0.1.8 spread the string into the environment as variables named 0, 1, 2, ...)
  const extra = { ...(rt.env && typeof rt.env === 'object' ? rt.env : {}), ...caEnv };
  return run(rt.bin, argv, { purpose: 'probe', timeout: timeoutMs + 4000, env: extra }).then(({ err }) => outcome(rt.kind, err));
}

/** nscurl prints "Load failed with error: …" (NSURLErrorDomain) when the connection is refused. */
export const nscurlOk = (text) => !/Load failed|NSURLErrorDomain|error/i.test(text);

/** Kinds whose probe can trust ONLY a given CA file; the rest are controlled with a normal site instead. */
export const canForceCa = (kind) => kind !== 'macos-system';

/**
 * Reachability control: a handshake with verification OFF, so a host that is down is never mistaken for "not trusted".
 * Sends nothing. → { up, issuer }: the issuer's common name, so the caller can tell the real test chain from something
 * on the network answering in its place (a TLS-inspecting firewall, a DNS filter's block page).
 */
export function reachable(host, port = 443, timeoutMs = 7000) {
  return new Promise((res) => {
    const s = connect({ host, port, ...(isIP(host) ? {} : { servername: host }), rejectUnauthorized: false, timeout: timeoutMs }, () => { const issuer = s.getPeerCertificate?.()?.issuer?.CN ?? ''; s.end(); res({ up: true, issuer }); });
    s.on('error', () => res({ up: false, issuer: '' })); s.on('timeout', () => { s.destroy(); res({ up: false, issuer: '' }); });
  });
}

/** The distrusted roots (each canary's `root`) that no answering test host chains to: a runtime that trusts only that
 *  root would refuse every host that did answer, and read SAFE (27cdfbd, with the six AAA hosts down). */
export const uncoveredRoots = (canaries) => {
  const roots = [...new Set(canaries.map((c) => c.root).filter(Boolean))];
  return roots.filter((r) => !canaries.some((c) => c.up && c.root === r));
};

/**
 * Check one runtime against every reachable canary.
 * → { status: SAFE | EXPOSED | UNKNOWN, trusted: string[], tested, reason?, searched? }
 * UNKNOWN when no canary answers, or when the positive control fails (the probe could not have seen exposure).
 */
export async function check(rt, canaries, { rootsPem, timeoutMs, controlUrl } = {}) {
  const up = canaries.filter((c) => c.up);
  if (!up.length) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'no test host answered, so trust could not be tested' };
  // A curl row that names its own bundle (a virtual environment's certifi, a Linux system bundle) needs that file: curl
  // would fail on a missing one, every test host would look refused, and the forced-roots control, whose --cacert comes
  // later and wins, would still pass. That would read SAFE without having tested the bundle.
  const ca = rt.kind === 'curl' && (rt.args ?? []).indexOf('--cacert');
  if (ca !== false && ca >= 0 && !(rt.args[ca + 1] && isAbsolute(rt.args[ca + 1]) && pathState(rt.args[ca + 1]) === 'file'))
    return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `the CA bundle to test (${rt.args[ca + 1] ?? 'none given'}) could not be found, so it was not tested` };
  let blocks = false;
  if (canForceCa(rt.kind)) {
    // the forced-roots control on one answering host per distrusted root, with ONLY that root forced in (the host's
    // `pem`): each root's chain must be one this runtime could complete through that root. With both roots forced,
    // an AAA host's chain could finish at the emSign root, and a runtime trusting only AAA read SAFE (d59e114).
    const roots = [...new Set(up.map((c) => c.root).filter(Boolean))];
    const controls = roots.length ? roots.map((r) => up.find((c) => c.root === r)) : [up[0]];
    const got = await Promise.all(controls.map((c) => ((c.pem ?? rootsPem) ? probe(rt, c.url, { timeoutMs, forcedCa: c.pem ?? rootsPem }) : 'ok')));
    const forced = got.every((g) => g === 'blocked') ? 'blocked' : got.find((g) => g !== 'ok' && g !== 'blocked') ?? 'ok';
    if (forced === 'blocked') {
      // Node's own block (CERT_REVOKED) even with the compromised roots trusted. Only that code counts: a name mismatch,
      // an expired test certificate, a TLS-inspecting firewall or a timeout made 0.1.4 to 0.1.8 read "blocks" here, the
      // strongest SAFE, for every runtime. A normal site must still open.
      if (!controlUrl || (await probe(rt, controlUrl, { timeoutMs })) !== 'ok')
        return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'positive control failed: even with the compromised roots forced in, this runtime could not connect, and it could not open a normal site either, so the check cannot see exposure here' };
      blocks = true;
    } else if (forced !== 'ok') {
      return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `positive control failed: with the compromised roots forced in, this runtime still could not connect to the test site (${forced === 'refused' ? 'a certificate error that is not the runtime\'s block of these keys' : 'a connection error'}), so a refusal would prove nothing here` };
    }
  } else if (controlUrl && (await probe(rt, controlUrl, { timeoutMs })) !== 'ok') {
    return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'control failed: this runtime could not open a normal site either, so a refusal here would prove nothing' };
  }
  const results = await Promise.all(up.map(async (c) => ({ id: c.id, got: await probe(rt, c.url, { timeoutMs }) })));
  const hits = results.filter((x) => x.got === 'ok').map((x) => x.id);
  // a host blocked by the runtime itself is a refusal too
  // a failure that is not a certificate refusal proves nothing: without a connection, it is not a SAFE
  const failed = results.filter((x) => x.got === 'error').length;
  if (!hits.length && failed) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `${failed} of ${up.length} test connections failed for a reason other than a certificate refusal, so this runtime's trust could not be confirmed` };
  const uncovered = uncoveredRoots(canaries);
  if (!hits.length && uncovered.length) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: `no test host chained to ${uncovered.join(' or ')} answered, so this runtime's trust in that root could not be tested` };
  const fields = { trusted: hits, tested: up.length };
  const r = hits.length ? { status: 'EXPOSED', ...fields } : safe(up.map((c) => c.host ?? c.url), fields);
  if (blocks && !hits.length) r.note = 'blocks the compromised keys themselves, even with their roots trusted';
  return r;
}
