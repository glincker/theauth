# Go end to end vector generator (chain rows plus signed head)

`e2e_vectors_gen_test.go` produced `packages/core/tests/fixtures/go-e2e-head-vectors.json`. It is not
part of theauth-go and not built here. It builds three real chains with `BuildChainEntryWith` (stable
and rotating `r1:` pseudonyms, one erased row), signs the chain heads with the real
`CreateHeadCheckpoint` (RFC 8032 test 1 key), checks the chains with the real `VerifyChainRowsKeys`,
and records the real `CheckHeadCheckpoint` result for four cuts of the log. The TypeScript test
`tests/audit-go-e2e-vectors.test.ts` runs `verifyGoAuditChain` and `verifyGoHeadCheckpoint` over the
same exported rows. Run it in a scratch copy, never inside the real checkout:

```sh
S=$(mktemp -d)
rsync -a --exclude .git /path/to/theauth/go/ "$S"/
cp e2e_vectors_gen_test.go "$S/audit/checkpoint/"
cd "$S"
GOWORK=off GEN_OUT=/abs/go-e2e-head-vectors.json go test -count=1 -run TestGenerateE2EVectors ./audit/checkpoint
```
