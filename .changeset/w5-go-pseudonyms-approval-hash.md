---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

`verifyGoAuditChain` now understands the rotating pseudonyms of theauth-go (`r1:<period>:<hex>`). Before, a row written with rotation on reported `pseudonym_mismatch` whenever `pseudonymSecret` was given. A new `periodSecrets` option (object or `Map` keyed by period) checks them, a period without a secret is trusted as stored and counted in `pseudonymsUnchecked`, and `theauth audit verify-go` gains `--period-secrets <file>`.

The approval hash is now byte for byte the one theauth-go computes for JSON shaped arguments: keys sorted by UTF-8 bytes, Go's string escaping, `-0` kept, a bigint written as digits. `NaN`, `Infinity` and other unhashable values now throw, so the call is denied instead of hashing like `null`. Shared vectors written by the real Go code, plus an end to end vector (real Go chain, rotating pseudonyms, signed head, truncation cuts) ship in the test fixtures.
