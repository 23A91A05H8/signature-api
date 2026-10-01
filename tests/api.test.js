'use strict';

const { test, describe, before } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const request = require('supertest');
const { createApp } = require('../src/app');
const { normalizeJson } = require('../src/crypto/normalizer');

const app = createApp();
const post = (path, body) => request(app).post(path).send(body);
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

async function newKeys(algorithm) {
  const res = await post('/api/keys/generate', algorithm ? { algorithm } : undefined);
  assert.strictEqual(res.status, 200);
  return res.body;
}
async function signWith(payload, privateKey) {
  const res = await post('/api/sign', { payload, privateKey });
  assert.strictEqual(res.status, 200);
  return res.body.signature;
}

let A; // RSA key pair
let B; // second RSA key pair
let ED; // Ed25519 key pair

before(async () => {
  A = await newKeys();
  B = await newKeys();
  ED = await newKeys('ed25519');
});

describe('req-1 key generation', () => {
  test('returns 200 with PEM public/private keys (no body)', async () => {
    const res = await request(app).post('/api/keys/generate');
    assert.strictEqual(res.status, 200);
    assert.match(res.body.publicKey, /-----BEGIN PUBLIC KEY-----/);
    assert.match(res.body.privateKey, /-----BEGIN PRIVATE KEY-----/);
  });
  test('supports Ed25519 and rejects unknown algorithms', async () => {
    assert.match(ED.publicKey, /-----BEGIN PUBLIC KEY-----/);
    const res = await post('/api/keys/generate', { algorithm: 'dsa' });
    assert.strictEqual(res.status, 400);
  });
});

describe('req-2 payload signing', () => {
  test('returns 200 and a valid Base64 signature for a complex payload', async () => {
    const res = await post('/api/sign', {
      payload: { any_key: 'any_value', nested: { foo: 'bar' }, list: [1, 2, { z: 1, a: 2 }] },
      privateKey: A.privateKey,
    });
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.signature.length > 0);
    assert.match(res.body.signature, B64);
  });
});

describe('req-3 signature verification', () => {
  test('valid signature -> isValid true (RSA)', async () => {
    const payload = { any_key: 'any_value' };
    const signature = await signWith(payload, A.privateKey);
    const res = await post('/api/verify', { payload, signature, publicKey: A.publicKey });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { isValid: true });
  });
  test('valid signature -> isValid true (Ed25519)', async () => {
    const payload = { hello: 'world' };
    const signature = await signWith(payload, ED.privateKey);
    const res = await post('/api/verify', { payload, signature, publicKey: ED.publicKey });
    assert.deepStrictEqual(res.body, { isValid: true });
  });
  test('PEM keys with literal \\n sequences still work', async () => {
    const payload = { a: 1 };
    const signature = await signWith(payload, A.privateKey.replace(/\n/g, '\\n'));
    const res = await post('/api/verify', {
      payload, signature, publicKey: A.publicKey.replace(/\n/g, '\\n'),
    });
    assert.deepStrictEqual(res.body, { isValid: true });
  });
  test('UTF-8 / emoji payloads round-trip', async () => {
    const payload = { msg: 'héllo 🌍 世界' };
    const signature = await signWith(payload, A.privateKey);
    const res = await post('/api/verify', { payload, signature, publicKey: A.publicKey });
    assert.strictEqual(res.body.isValid, true);
  });
});

describe('req-4 tamper detection', () => {
  test('{"amount":1000} signature rejects {"amount":1001}', async () => {
    const signature = await signWith({ amount: 1000 }, A.privateKey);
    const res = await post('/api/verify', {
      payload: { amount: 1001 }, signature, publicKey: A.publicKey,
    });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { isValid: false });
  });
  test('PASS BAR: flipping any single bit of the signature fails verify', async () => {
    for (const keys of [A, ED]) {
      const payload = { amount: 1000 };
      const sig = Buffer.from(await signWith(payload, keys.privateKey), 'base64');
      // flip one bit in a handful of positions (first, middle, last byte)
      for (const idx of [0, Math.floor(sig.length / 2), sig.length - 1]) {
        const tampered = Buffer.from(sig);
        tampered[idx] ^= 0x01;
        const res = await post('/api/verify', {
          payload, signature: tampered.toString('base64'), publicKey: keys.publicKey,
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.isValid, false, `bit flip at byte ${idx} must fail`);
      }
    }
  });
  test('PASS BAR: flipping a single bit of the payload fails verify', async () => {
    const payload = { data: 'A' }; // 'A' = 0x41
    const signature = await signWith(payload, A.privateKey);
    const flipped = { data: String.fromCharCode('A'.charCodeAt(0) ^ 0x01) }; // '@'
    const res = await post('/api/verify', { payload: flipped, signature, publicKey: A.publicKey });
    assert.deepStrictEqual(res.body, { isValid: false });
  });
  test('adding / removing a field fails verify', async () => {
    const signature = await signWith({ a: 1 }, A.privateKey);
    for (const payload of [{ a: 1, b: 2 }, {}, { a: '1' }]) {
      const res = await post('/api/verify', { payload, signature, publicKey: A.publicKey });
      assert.strictEqual(res.body.isValid, false);
    }
  });
});

describe('req-5 key mismatch detection', () => {
  test('signature by key A fails against key B public key', async () => {
    const payload = { who: 'alice' };
    const signature = await signWith(payload, A.privateKey);
    const res = await post('/api/verify', { payload, signature, publicKey: B.publicKey });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { isValid: false });
  });
  test('RSA signature against an Ed25519 public key -> isValid false', async () => {
    const payload = { who: 'alice' };
    const signature = await signWith(payload, A.privateKey);
    const res = await post('/api/verify', { payload, signature, publicKey: ED.publicKey });
    assert.deepStrictEqual(res.body, { isValid: false });
  });
});

describe('req-6 invalid signature format', () => {
  test('non-Base64 signature does not crash (400 or isValid false)', async () => {
    const res = await post('/api/verify', {
      payload: { a: 1 }, signature: 'invalid_not_base64!@#', publicKey: A.publicKey,
    });
    assert.notStrictEqual(res.status, 500);
    assert.ok(res.status === 400 || (res.status === 200 && res.body.isValid === false));
  });
  test('bad padding / truncated / garbage signatures are handled', async () => {
    for (const signature of ['abc', 'AAAA=', '====', 'QUJD', '   ', 'A'.repeat(1000)]) {
      const res = await post('/api/verify', { payload: { a: 1 }, signature, publicKey: A.publicKey });
      assert.notStrictEqual(res.status, 500, `signature "${signature.slice(0, 8)}"`);
      assert.ok(res.status === 400 || res.body.isValid === false);
    }
  });
});

describe('req-7 deterministic normalization', () => {
  test('different key order verifies with the same signature', async () => {
    const signature = await signWith({ role: 'admin', user: 1 }, A.privateKey);
    const res = await post('/api/verify', {
      payload: { user: 1, role: 'admin' }, signature, publicKey: A.publicKey,
    });
    assert.deepStrictEqual(res.body, { isValid: true });
  });
  test('same data, different key order -> identical signature (RSA PKCS#1 v1.5 is deterministic)', async () => {
    const s1 = await signWith({ b: 2, a: 1 }, A.privateKey);
    const s2 = await signWith({ a: 1, b: 2 }, A.privateKey);
    assert.strictEqual(s1, s2);
  });
  test('integer-like keys are order-independent too', async () => {
    const p1 = JSON.parse('{"10":"x","2":"y","b":1,"1":"z"}');
    const p2 = JSON.parse('{"1":"z","b":1,"2":"y","10":"x"}');
    assert.strictEqual(normalizeJson(p1), normalizeJson(p2));
  });
  test('array order IS significant', async () => {
    const signature = await signWith({ l: [1, 2] }, A.privateKey);
    const res = await post('/api/verify', { payload: { l: [2, 1] }, signature, publicKey: A.publicKey });
    assert.strictEqual(res.body.isValid, false);
  });
  test('normalizer output is compact, sorted and keeps UTF-8', () => {
    assert.strictEqual(normalizeJson({ b: { d: 3, c: 2 }, a: 1 }), '{"a":1,"b":{"c":2,"d":3}}');
    assert.strictEqual(normalizeJson({ e: '🌍' }), '{"e":"🌍"}');
    assert.strictEqual(normalizeJson([3, null, true, 'x']), '[3,null,true,"x"]');
  });
});

describe('req-8 health check', () => {
  test('GET /api/health -> 200 {status:"ok"}', async () => {
    const res = await request(app).get('/api/health');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { status: 'ok' });
  });
});

describe('req-9 missing / invalid keys', () => {
  test('sign: malformed privateKey -> 400 with message; server stays responsive', async () => {
    const res = await post('/api/sign', { payload: { a: 1 }, privateKey: 'not_a_key' });
    assert.strictEqual(res.status, 400);
    assert.ok(res.body.error);
    assert.ok(!/stack|at\s.+\(/i.test(res.body.error));
    const ok = await post('/api/sign', { payload: { a: 1 }, privateKey: A.privateKey });
    assert.strictEqual(ok.status, 200);
  });
  test('sign: missing privateKey / payload -> 400', async () => {
    assert.strictEqual((await post('/api/sign', { payload: { a: 1 } })).status, 400);
    assert.strictEqual((await post('/api/sign', { privateKey: A.privateKey })).status, 400);
    assert.strictEqual((await post('/api/sign', {})).status, 400);
  });
  test('sign: a PUBLIC key given as privateKey -> 400', async () => {
    const res = await post('/api/sign', { payload: { a: 1 }, privateKey: A.publicKey });
    assert.strictEqual(res.status, 400);
  });
  test('sign: PEM with valid headers but garbage body -> 400', async () => {
    const bad = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----';
    const res = await post('/api/sign', { payload: { a: 1 }, privateKey: bad });
    assert.strictEqual(res.status, 400);
  });
  test('verify: malformed / missing publicKey -> 400', async () => {
    const signature = await signWith({ a: 1 }, A.privateKey);
    assert.strictEqual(
      (await post('/api/verify', { payload: { a: 1 }, signature, publicKey: 'nope' })).status, 400);
    assert.strictEqual(
      (await post('/api/verify', { payload: { a: 1 }, signature })).status, 400);
    // a private key must not be accepted where a public key is expected
    assert.strictEqual(
      (await post('/api/verify', { payload: { a: 1 }, signature, publicKey: A.privateKey })).status, 400);
  });
  test('verify: missing payload / signature -> 400', async () => {
    const signature = await signWith({ a: 1 }, A.privateKey);
    assert.strictEqual((await post('/api/verify', { signature, publicKey: A.publicKey })).status, 400);
    assert.strictEqual((await post('/api/verify', { payload: {}, publicKey: A.publicKey })).status, 400);
  });
  test('invalid JSON body -> 400, unknown route -> 404, oversize -> 413', async () => {
    const bad = await request(app).post('/api/sign').set('Content-Type', 'application/json').send('{oops');
    assert.strictEqual(bad.status, 400);
    assert.strictEqual((await request(app).get('/nope')).status, 404);
    const big = await post('/api/sign', { payload: { x: 'a'.repeat(1.2 * 1024 * 1024) }, privateKey: 'k' });
    assert.strictEqual(big.status, 413);
  });
  test('works with a PKCS#1 RSA private key too', async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    });
    const signature = await signWith({ a: 1 }, privateKey);
    const res = await post('/api/verify', { payload: { a: 1 }, signature, publicKey });
    assert.strictEqual(res.body.isValid, true);
  });
});

describe('req-10 recursive normalization', () => {
  test('nested objects with reordered keys verify', async () => {
    const a = { user: { id: 1, name: 'Alice' }, meta: { v: 2 } };
    const b = { meta: { v: 2 }, user: { name: 'Alice', id: 1 } };
    const signature = await signWith(a, A.privateKey);
    const res = await post('/api/verify', { payload: b, signature, publicKey: A.publicKey });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { isValid: true });
  });
  test('deep nesting inside arrays is normalized as well', () => {
    assert.strictEqual(
      normalizeJson({ l: [{ b: 1, a: { d: 1, c: 2 } }] }),
      '{"l":[{"a":{"c":2,"d":1},"b":1}]}');
  });
});
