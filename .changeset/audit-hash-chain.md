---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add an opt-in tamper-evident audit trail. `audit: { tamperEvident: true, hmacKey }` links each audit row to the previous one with a SHA-256 or HMAC hash, one chain per agent. New `theauth.audit.verifyAuditChain`, `replayAgent` and `exportAudit` (JSONL plus a signed manifest), a `verifyAuditExport` helper, and `theauth audit verify` / `theauth audit replay` in the CLI. `theauth_audit_logs` gains nullable `chain_seq`, `prev_hash` and `hash` columns and a unique index on `(agent_id, chain_seq)`; `createTables` adds them to existing databases and old rows are left alone. Nothing changes unless you turn it on.
