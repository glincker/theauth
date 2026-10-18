# Go head checkpoint vector generator

`head_vectors_gen_test.go` produced `packages/core/tests/fixtures/go-head-checkpoint-vectors.json`. It
is documentation of how the vectors were made, not part of theauth-go and not built here.

Heads are signed with the real `headSignedBytes` in theauth-go (`audit/checkpoint/head.go`) using the
RFC 8032 section 7.1 test 1 secret key. Each case's expected result comes from the real
`VerifyHeadCheckpoint` (mode `signature`) or `CheckHeadCheckpoint` (mode `live`), so the TypeScript
verifier is checked against Go, not against itself.

The generator uses unexported helpers of package `checkpoint`, so it is a `_test.go` file in that
package. Run it in a scratch copy, never inside the real checkout:

```sh
S=$(mktemp -d)
cp -R /path/to/theauth/go/. "$S"
cp head_vectors_gen_test.go "$S/audit/checkpoint/"
cd "$S"
GOWORK=off GEN_OUT=/abs/path/go-head-checkpoint-vectors.json go test -run TestGenerateHeadVectors ./audit/checkpoint
```

Then run `npx vitest run tests/audit-go-head-vectors.test.ts` in `packages/core`. If the Go wire format
changes, the vectors and `src/audit/go-head-verify.ts` must change together.
