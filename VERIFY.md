# Verification checklist

Run `npm test` – every requirement has a matching test group in `tests/api.test.js`.

| Req | Requirement | Test group / name |
|---|---|---|
| 1 | Key generation (`POST /api/keys/generate`) | `req-1 key generation` |
| 2 | Payload signing (`POST /api/sign`) | `req-2 payload signing` |
| 3 | Signature verification (`POST /api/verify`) | `req-3 signature verification` |
| 4 | Tamper detection (`1000` vs `1001`, bit-flip pass bar) | `req-4 tamper detection` |
| 5 | Key mismatch detection | `req-5 key mismatch detection` |
| 6 | Invalid Base64 signature handled (no 500) | `req-6 invalid signature format` |
| 7 | Deterministic normalization (key order) | `req-7 deterministic normalization` |
| 8 | Health check `GET /api/health` | `req-8 health check` |
| 9 | Missing / invalid keys -> 400, server stays up | `req-9 missing / invalid keys` |
| 10 | Recursive normalization of nested objects | `req-10 recursive normalization` |

Seed pass bar ("bit-flip after signing fails verify"): `PASS BAR: flipping any single bit of the signature…`
and `PASS BAR: flipping a single bit of the payload…`.
