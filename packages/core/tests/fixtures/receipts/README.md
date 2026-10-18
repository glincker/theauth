# Receipt fixtures

`go-fixture.json` is a byte-identical copy of `go/audit/checkpoint/testdata/go-fixture.json` in the theauth-go repository (written by `TestWriteGoFixture`). `tests/audit-receipt-go-fixture.test.ts` verifies it with the TypeScript checkpoint and receipt verifiers, so CI fails if the two libraries drift apart.

Refresh after the Go fixture changes: `node scripts/refresh-go-receipt-fixture.mjs` (run from the `sdk` directory). It copies from `../go` when that checkout exists and does nothing otherwise. CI never needs it.
