// Probe one runtime: can it complete a VERIFIED TLS connection to a canary host? It runs the runtime itself, the way
// your code would, with your environment. A connection means the runtime still trusts the compromised chain.
import { execFile } from 'node:child_process';
import { connect } from 'node:tls';
import { isIP } from 'node:net';

const NODE = (t) => `const [u,ca]=process.argv.slice(1);
if(ca){require('https').get(u,{ca:require('fs').readFileSync(ca),timeout:${t}},r=>{r.resume();process.exit(0)}).on('error',()=>process.exit(1)).on('timeout',()=>process.exit(1));}
else fetch(u,{signal:AbortSignal.timeout(${t})}).then(()=>process.exit(0),()=>process.exit(1));`;
const PY = (certifi, t) => `import sys,ssl,urllib.request
u=sys.argv[1]; ca=sys.argv[2] if len(sys.argv)>2 else None
${certifi ? 'import certifi\nctx=ssl.create_default_context(cafile=ca or certifi.where())' : 'ctx=ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()'}
urllib.request.urlopen(u,timeout=${t / 1000},context=ctx)`;

/** true when the runtime connected with verification on. forcedCa: trust ONLY this file (the positive control). */
export function probe(rt, url, { timeoutMs = 7000, forcedCa } = {}) {
  let argv;
  switch (rt.kind) {
    case 'curl': argv = ['-s', '-o', '/dev/null', '--max-time', String(Math.ceil(timeoutMs / 1000)), ...(forcedCa ? ['--cacert', forcedCa] : []), url]; break;
    case 'node': argv = ['-e', NODE(timeoutMs), url, ...(forcedCa ? [forcedCa] : [])]; break;
    case 'python': case 'python-certifi': argv = ['-I', '-c', PY(rt.kind === 'python-certifi', timeoutMs), url, ...(forcedCa ? [forcedCa] : [])]; break;
    default: return Promise.resolve(false);
  }
  return new Promise((res) => execFile(rt.bin, argv, { timeout: timeoutMs + 4000, env: { ...process.env, ...(rt.env ?? {}) } }, (err) => res(!err)));
}

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
export async function check(rt, canaries, { rootsPem, timeoutMs } = {}) {
  const up = canaries.filter((c) => c.up);
  if (!up.length) return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'no test host answered, so trust could not be tested' };
  if (rootsPem && !(await probe(rt, up[0].url, { timeoutMs, forcedCa: rootsPem })))
    return { status: 'UNKNOWN', trusted: [], tested: 0, reason: 'positive control failed: even with the compromised roots forced in, this runtime could not connect, so the check cannot see exposure here' };
  const hits = (await Promise.all(up.map(async (c) => ((await probe(rt, c.url, { timeoutMs })) ? c.id : null)))).filter(Boolean);
  return { status: hits.length ? 'EXPOSED' : 'SAFE', trusted: hits, tested: up.length };
}
