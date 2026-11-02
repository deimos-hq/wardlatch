// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The key forms under test. Keys are made here, in memory and a temp rig, and never printed.
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tlv, kids, lenBytes } from './seat7-lib.mjs';
export const PW = 'seat9-not-a-secret';
export const O = '/usr/bin/openssl';
const B = (...x) => Buffer.from(x);
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const p1 = rsa.privateKey.export({ type: 'pkcs1', format: 'der' });
export const p8 = rsa.privateKey.export({ type: 'pkcs8', format: 'der' });
export const enc = rsa.privateKey.export({ type: 'pkcs8', format: 'der', cipher: 'aes-256-cbc', passphrase: PW });
export const pub1 = rsa.publicKey.export({ type: 'pkcs1', format: 'der' });
// SEC1 with no NUL byte anywhere: no public key (its BIT STRING starts with 00), and a private value with none
function nulFree() {
  for (;;) {
    const d = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'sec1', format: 'der' });
    const k = kids(d);
    if (!k[1].includes(0)) return k;
  }
}
const sk = nulFree();
export const seq = (kk, tag = 0x30) => tlv(tag, Buffer.concat(kk));
export const indef = (kk, tag = [0x30]) => Buffer.concat([Buffer.from([...tag, 0x80]), ...kk, B(0, 0)]);
const V = { two: B(2, 2, 1, 1), hi: B(0x1f, 2, 1, 1), long: B(2, 0x81, 1, 1), hipad: B(0x1f, 0x80, 2, 1, 1), big: B(2, 2, 1, 0) };
const ver = (n) => B(2, 1, n);
const rsaKids = kids(p1), p8Kids = kids(p8), encKids = kids(enc);
const retag = (el, tag) => { const h = el[1] < 0x80 ? 2 : 2 + (el[1] & 0x7f); return Buffer.concat([Buffer.from(tag), el.subarray(1, h), el.subarray(h)]); };
// PKCS #8 of the NUL-free EC key: 02 01 v, the algorithm, then the SEC1 in an OCTET STRING
const ecAlg = Buffer.from('301306072a8648ce3d020106082a8648ce3d030107', 'hex');
const sec1Plain = seq([ver(1), sk[1], sk[2]]);
const ec8 = (v) => seq([ver(v), ecAlg, tlv(4, sec1Plain)]);
const LOAD = {
  ec: (f) => [['ec', '-inform', 'DER', '-in', f, '-noout']],
  rsa: (f) => [['rsa', '-inform', 'DER', '-in', f, '-noout']],
  p8: (f) => [['pkcs8', '-inform', 'DER', '-nocrypt', '-in', f, '-out', '/dev/null']],
  enc: (f) => [['pkcs8', '-inform', 'DER', '-in', f, '-passin', `pass:${PW}`, '-out', '/dev/null']],
  any: (f) => [['pkey', '-inform', 'DER', '-in', f, '-noout']],
};
export const loads = (kind, f) => LOAD[kind](f).some((a) => spawnSync(O, a, { encoding: 'buffer' }).status === 0);
export const FORMS = {
  // short outer, no NUL anywhere: the text gate
  'ctl SEC1 no NUL v1 (found)': ['ec', seq([ver(1), sk[1], sk[2]])],
  'ctl SEC1 no NUL v2 (D6c, fixed)': ['ec', seq([ver(2), sk[1], sk[2]])],
  'SEC1 no NUL v8': ['ec', seq([ver(8), sk[1], sk[2]])],
  'SEC1 no NUL v0x41': ['ec', seq([ver(0x41), sk[1], sk[2]])],
  'SEC1 no NUL two-byte version': ['ec', seq([V.two, sk[1], sk[2]])],
  'SEC1 no NUL version 1f 02': ['ec', seq([V.hi, sk[1], sk[2]])],
  'SEC1 no NUL version long length': ['ec', seq([V.long, sk[1], sk[2]])],
  'PKCS8 EC no NUL v9': ['p8', ec8(9)],
  'outer 3f 10, SEC1 no NUL two-byte version': ['ec', seq([V.two, sk[1], sk[2]], [0x3f, 0x10])],
  // high-tag with a padded tag number
  'ctl outer 3f 10 RSA (D6d, fixed)': ['rsa', seq(rsaKids, [0x3f, 0x10])],
  'ctl version 1f 02 RSA (D6d, fixed)': ['rsa', seq([B(0x1f, 2, 1, 0), ...rsaKids.slice(1)])],
  'outer 3f 80 10 RSA': ['rsa', seq(rsaKids, [0x3f, 0x80, 0x10])],
  'version 1f 80 02 RSA': ['rsa', seq([B(0x1f, 0x80, 2, 1, 0), ...rsaKids.slice(1)])],
  'outer 3f 80 80 10 PKCS8': ['p8', seq(p8Kids, [0x3f, 0x80, 0x80, 0x10])],
  'version 1f 80 02 PKCS8': ['p8', seq([B(0x1f, 0x80, 2, 1, 0), ...p8Kids.slice(1)])],
  // 30 80: left to shapeOf
  'ctl 30 80 RSA as made (found)': ['rsa', indef(rsaKids)],
  '30 80 RSA two-byte version': ['rsa', indef([V.big, ...rsaKids.slice(1)])],
  '30 80 RSA version 1f 02': ['rsa', indef([B(0x1f, 2, 1, 0), ...rsaKids.slice(1)])],
  '30 80 RSA version 2': ['rsa', indef([ver(2), ...rsaKids.slice(1)])],
  '30 80 PKCS8 two-byte version': ['p8', indef([V.big, ...p8Kids.slice(1)])],
  '30 80 PKCS8 version 2': ['p8', indef([ver(2), ...p8Kids.slice(1)])],
  '30 80 PKCS8 alg 3f 10': ['p8', indef([p8Kids[0], retag(p8Kids[1], [0x3f, 0x10]), p8Kids[2]])],
  '30 80 PKCS8 octets 1f 04': ['p8', indef([p8Kids[0], p8Kids[1], retag(p8Kids[2], [0x1f, 0x04])])],
  '30 80 SEC1 version 2': ['ec', indef([ver(2), sk[1], sk[2]])],
  '30 80 SEC1 two-byte version': ['ec', indef([V.two, sk[1], sk[2]])],
  '30 80 SEC1 constructed octets': ['ec', indef([ver(1), tlv(0x24, sk[1]), sk[2]])],
  '30 80 enc alg 3f 10': ['enc', indef([retag(encKids[0], [0x3f, 0x10]), encKids[1]])],
  '30 80 enc octets 1f 04': ['enc', indef([encKids[0], retag(encKids[1], [0x1f, 0x04])])],
  'ctl 30 80 enc as made (found)': ['enc', indef(encKids)],
  // encrypted, spelling of the inner parts
  'enc alg 3f 10': ['enc', seq([retag(encKids[0], [0x3f, 0x10]), encKids[1]])],
  'enc alg 3f 80 10': ['enc', seq([retag(encKids[0], [0x3f, 0x80, 0x10]), encKids[1]])],
  'enc oid 1f 06': ['enc', (() => { const a = kids(encKids[0]); return seq([seq([retag(a[0], [0x1f, 0x06]), ...a.slice(1)]), encKids[1]]); })()],
  'enc oid 1f 80 06': ['enc', (() => { const a = kids(encKids[0]); return seq([seq([retag(a[0], [0x1f, 0x80, 0x06]), ...a.slice(1)]), encKids[1]]); })()],
  'enc octets 1f 04': ['enc', seq([encKids[0], retag(encKids[1], [0x1f, 0x04])])],
  'enc outer 3f 10 alg 3f 10': ['enc', seq([retag(encKids[0], [0x3f, 0x10]), encKids[1]], [0x3f, 0x10])],
  'enc outer 3f 80 10': ['enc', seq(encKids, [0x3f, 0x80, 0x10])],
  'ctl enc outer 3f 10 (found by shape)': ['enc', seq(encKids, [0x3f, 0x10])],
};
export const NOT_KEYS = {
  'RSA public PKCS#1': pub1,
  'ECDSA signature with a NUL': (() => { const r = Buffer.alloc(32, 0x11), s = Buffer.alloc(32, 0x22); s[5] = 0; return seq([tlv(2, r), tlv(2, s)]); })(),
  'ECDSA signature no NUL': (() => { const r = Buffer.alloc(32, 0x11), s = Buffer.alloc(32, 0x22); return seq([tlv(2, r), tlv(2, s)]); })(),
  'DSA params p q g': seq([tlv(2, Buffer.concat([B(0), Buffer.alloc(128, 0x55)])), tlv(2, Buffer.concat([B(0), Buffer.alloc(32, 0x66)])), tlv(2, Buffer.alloc(128, 0x33))]),
  'DH params p g': seq([tlv(2, Buffer.concat([B(0), Buffer.alloc(256, 0x55)])), tlv(2, B(2))]),
  'text "0a" + words': Buffer.from('0a hello world\n'),
  'text ?\\x10 and an AWS-shaped key': Buffer.concat([B(0x3f, 0x10), Buffer.from(' AKIA' + 'IOSFODNN7QQQQQQQ\n')]),
};
