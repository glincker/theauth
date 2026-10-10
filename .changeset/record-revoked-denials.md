---
"@glinr/theauth": patch
---

Record denied attempts by revoked and expired agents in the audit log. `authorize()` and `authorizeByToken()` now write a `denied` row with reason `agent_revoked` or `agent_expired` for a known agent, so the attempt is visible and stays on the agent's hash chain. Decisions are unchanged. Unknown agent ids and unknown tokens still write no row.
