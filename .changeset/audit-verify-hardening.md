---
"@glinr/theauth": patch
---

Audit chain verification no longer trusts records anyone with database write access could write.

- `audit.erasure` records are now appended to the agent's hash chain, and every entry carries an HMAC (audit key) over the erased row's id, seq, hash, previous hash, hash version and erasure reason. For an anonymized version 1 row the entry also pins the hash of the row as erasure left it, so editing it later is still tamper. `verifyAuditChain` recomputes the MACs and reports `erasure_unchained` or `erasure_forged` instead of excusing the gap or edit. Unsigned erasure records from earlier unreleased 2.0 builds are not accepted and there is no compatibility path for them.
- A chained row whose `hash_version` was rewritten to NULL or 1 is reported as `version_downgrade`.
- Deleting the oldest rows of a chain is reported as `truncated_prefix`. A chain may start at seq 1, after a retention checkpoint (now HMAC signed), or at an anchor written by the new `theauth.audit.checkpoint()`, which also returns anchors and heads to pin outside the database. `verifyAuditChain` accepts them as `anchors` (`anchor_mismatch` when a pinned row changed) next to `expectedHeads`. `allowUnanchoredPrefix: true` restores the old lenient start check.
- `theauth.audit.verifyAuditChain` is now on the public `audit` facade, as the docs already showed.
- Tool arguments can no longer plant system fields in audit `parameters`: `approvalId` and every key starting with `theauth` are stripped from caller arguments before they are written.
