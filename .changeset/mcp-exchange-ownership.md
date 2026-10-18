---
"@glinr/theauth": patch
---

Fix a privilege escalation in the unreleased MCP token exchange binding (2.0 work). No published release is affected: the exchange binding was never released.

- Token exchange now checks that the subject token's user owns, or reaches over live delegation links from an agent they own, every agent the child token names (the presenting client's agent, the actor token's agent and every hop). Otherwise it returns `invalid_grant` and writes a `mcp.token_exchange` denied audit row under the refused agent.
- An exchanged token's `agent_id` and `principal.agent` are now the acting agent, the last entry of `theauth_dlg.agt`, never the presenting client's agent outside the binding. Validation refuses a bound token whose `agent_id` is not in `agt`.
- Ordinary tokens of a client bound to a delegated agent now name the agent's live inbound path in `theauth_dlg` (`agt: [root, ..., agent]`, one `lnk` per hop), so revoking a parent delegation is seen in cached mode and on `revalidate()` in offline mode, not only in live mode.
- Exchanged tokens carry `theauth_pjti`, the jtis of their subject token lineage. Revoking a parent token (RFC 7009, or its refresh family) now revokes every token exchanged from it. The `theauth_dlg` version stays `1`; validators that predate the new claim ignore it.
