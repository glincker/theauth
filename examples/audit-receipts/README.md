# Audit receipts

Signs a checkpoint of the audit log, mints a receipt for one decision that reveals only a few fields, and verifies it the way a counterparty would, with just the receipt JSON and a public key. It also shows a consistency proof between two checkpoints.

This folder has no `package.json`. Run it from a project that depends on `@glinr/theauth` (with the checkpoint exports available), for example:

```bash
npx tsx index.ts
```

Read `docs/audit-checkpoints.mdx` for what a receipt does and does not prove.
