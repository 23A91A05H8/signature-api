# Digital Signature & Tamper Detection API

A stateless REST API that generates asymmetric key pairs, **deterministically normalizes JSON**,
signs payloads and verifies signatures to detect tampering. Built with **Node.js + Express** using
only the built-in `crypto` module (OpenSSL under the hood).

* **Algorithms:** RSA (default, 2048-bit, `RSA-SHA256` / PKCS#1 v1.5) and **Ed25519** (`"algorithm": "ed25519"`).
* **Stateless:** keys are never stored – the client supplies the key on every `sign` / `verify` call.
* Algorithm is auto-detected from the key you pass to `/api/sign` and `/api/verify`.

## Quick start

```bash
npm install
cp .env.example .env      # optional
npm start                 # http://localhost:3000
npm test                  # runs the automated test-suite (node:test + supertest)
```
Requires Node.js 18+.

## Project structure

```
src/
├── controllers/   # HTTP <-> core logic (keys, sign, verify, health)
├── crypto/
│   ├── keygen.js      # RSA / Ed25519 key generation (PEM: SPKI + PKCS#8)
│   ├── keys.js        # PEM parsing/validation, digest selection
│   ├── normalizer.js  # deterministic (recursive) JSON normalization
│   ├── signer.js      # sign -> Base64
│   └── verifier.js    # strict Base64 decode + verify -> boolean
├── middleware/errorHandler.js   # safe 400/404/413/500 responses, no stack leaks
├── errors.js
├── app.js         # Express app + 1 MB body limit
└── server.js      # entry point
tests/api.test.js  # one test group per requirement (req-1 ... req-10)
```

## Endpoints

| Method | Path | Body | Success response |
|---|---|---|---|
| GET  | `/api/health` | – | `200 {"status":"ok"}` |
| POST | `/api/keys/generate` | none (optional `{"algorithm":"rsa"\|"ed25519"}`) | `200 {"publicKey","privateKey"}` (PEM) |
| POST | `/api/sign` | `{"payload":<any JSON>,"privateKey":"<PEM>"}` | `200 {"signature":"<Base64>"}` |
| POST | `/api/verify` | `{"payload":<any JSON>,"signature":"<Base64>","publicKey":"<PEM>"}` | `200 {"isValid":true\|false}` |

Errors: `400 {"error":"..."}` for missing fields, malformed keys (`Invalid private key format`,
`Invalid public key format`), malformed Base64 (`Malformed Base64 signature`) or invalid JSON bodies;
`413` for bodies over the limit; `404` unknown route. Stack traces are never returned.

### curl walkthrough

```bash
# 1. keys
curl -s -X POST localhost:3000/api/keys/generate > keys.json

# 2. sign
PRIV=$(node -p "JSON.stringify(require('./keys.json').privateKey)")
PUB=$(node -p "JSON.stringify(require('./keys.json').publicKey)")
SIG=$(curl -s -X POST localhost:3000/api/sign -H 'content-type: application/json' \
  -d "{\"payload\":{\"amount\":1000,\"to\":\"bob\"},\"privateKey\":$PRIV}" | node -p "JSON.parse(require('fs').readFileSync(0)).signature")

# 3. verify (key order does not matter)  -> {"isValid":true}
curl -s -X POST localhost:3000/api/verify -H 'content-type: application/json' \
  -d "{\"payload\":{\"to\":\"bob\",\"amount\":1000},\"signature\":\"$SIG\",\"publicKey\":$PUB}"

# 4. tampered -> {"isValid":false}
curl -s -X POST localhost:3000/api/verify -H 'content-type: application/json' \
  -d "{\"payload\":{\"to\":\"bob\",\"amount\":1001},\"signature\":\"$SIG\",\"publicKey\":$PUB}"
```

## Design notes

* **Normalization** (`normalizer.js`): keys sorted recursively, no whitespace, arrays keep order, UTF-8 preserved.
  It is a hand-written serializer on purpose – JavaScript orders integer-like keys (`"1"`, `"10"`) numerically
  regardless of insertion order, so "sort keys then `JSON.stringify`" is not actually deterministic.
* **No double hashing:** `crypto.sign('sha256', data, key)` hashes internally for RSA; Ed25519 uses `null` (pure EdDSA).
* **UTF-8** is explicit for every string→bytes conversion.
* **Strict Base64:** Node's decoder silently skips invalid characters, so signatures are validated with a strict
  regex first → clean `400` instead of a crash or a false positive.
* **Tamper / wrong-key / wrong-length signatures** return `200 {"isValid": false}`; only *structurally unusable
  input* (bad Base64, bad key, missing fields) returns `400`.
* **Key hygiene:** a private key is rejected where a public key is expected (no silent derivation); RSA < 2048 bits is rejected;
  literal `\n` sequences inside PEM strings are restored.
* **Constant-time comparison** is delegated to OpenSSL via `crypto.verify`.
* **DoS guard:** JSON body limit (default 1 MB, `BODY_LIMIT`).
* The private key is sent to `/api/sign` as the task specifies – in real deployments run this over TLS only and never log request bodies.
