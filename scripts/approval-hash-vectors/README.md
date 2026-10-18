# Approval hash vector generator

`inputs.json` lists argument bags (raw JSON text) for the cross language check of the approval hash.
`approval_hash_gen_test.go` runs each one through the real `HashApprovalAction` of theauth-go and
writes `packages/core/tests/fixtures/approval-hash-vectors.json`. It is not part of theauth-go and
not built here. Each input is decoded two ways: `float64` (plain `json.Unmarshal`) and `useNumber`
(`UseNumber`, numbers keep their source text). Run it in a scratch copy, never inside the real
checkout:

```sh
S=$(mktemp -d)
rsync -a --exclude .git /path/to/theauth/go/ "$S"/
cp approval_hash_gen_test.go "$S/policy/toolguard/"
cd "$S"
GOWORK=off GEN_IN=/abs/inputs.json GEN_OUT=/abs/approval-hash-vectors.json \
  go test -count=1 -run TestGenerateApprovalHashVectors ./policy/toolguard
```

Then run `npx vitest run tests/approval-hash-vectors.test.ts` in `packages/core`.
