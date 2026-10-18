---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add `verifyGoHeadCheckpoint` and `verifyGoHeadSignature` to verify the signed head checkpoint written by theauth-go (`checkpoint.CreateHeadCheckpoint`). Compared with rows exported from the Go log, it reports `chain_truncated` when a chain was cut off its tail (or is missing) and `head_mismatch` when the row at the signed position has another hash, after checking the Ed25519 signature, the domain separation and the sorted head list. Test vectors signed and judged by the real Go code ship in the test fixtures.

`theauth audit verify-go` gains `--head <file> --head-key <file>` to run the head check next to the chain check.
