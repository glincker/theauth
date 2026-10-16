---
"@glinr/theauth": patch
---

Session and audit correctness fixes. Session refresh now creates the replacement before deleting the old session, and a concurrent refresh that loses the race no longer leaves two live sessions. `maxConcurrent` is re-checked after insert, so concurrent sign-ins cannot exceed the cap (a racer that loses is dropped and `create()` throws `MultiSessionLimitError`). A failing audit write no longer makes `authorize()` throw. When the delegated fallback runs, one audit row is written for the final result instead of an orphan row per path. `canonicalJson` rejects reference cycles and serializes BigInt. Rate limit windows are parsed once at construction, a zero window is rejected, and the `client_id` body scan reads at most 8 KB.
