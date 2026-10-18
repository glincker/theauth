# Go audit chain vector generator

`chainvectors_gen_test.go` produced `packages/core/tests/fixtures/go-audit-chain-vectors.json`. It is
documentation of how the vectors were made, not part of theauth-go and not built here.

Every hash in the fixture comes from the real `BuildChainEntry` in theauth-go
(`internal/audit/chainhash.go`, `ChainHashVersion` 1). The generator also re-verifies each chain with
the real `VerifyChainRows` before writing it. The negative vectors (expected reasons) are declared in
the generator and checked by the TypeScript test, not by Go.

Because the hashing code is internal to the Go module, the generator is a `_test.go` file in package
`audit`. Run it in a scratch copy, never inside the real checkout:

```sh
S=$(mktemp -d)
git -C /path/to/theauth/go archive HEAD | tar -x -C "$S"
cp chainvectors_gen_test.go "$S/internal/audit/"
cd "$S"
GOWORK=off GEN_OUT=/abs/path/go-audit-chain-vectors.json GEN_PRODUCER="theauth-go internal/audit @ <commit>" \
  go test -run TestGenerateGoChainVectors ./internal/audit
```

Then copy the output to `packages/core/tests/fixtures/go-audit-chain-vectors.json` and run
`vitest run tests/audit-go-chain-vectors.test.ts` in `packages/core`. If the Go hashing changes, the
vectors and `src/audit/go-chain-verify.ts` must change together. The pseudonym secret used is the
32 ASCII bytes `0123456789abcdef0123456789abcdef` (the same as Go's own golden test), stored as hex.
