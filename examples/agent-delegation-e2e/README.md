# Agent delegation, end to end

One runnable script that shows the whole story: a user delegates a scoped token to an agent, an MCP server verifies it through theAuth's OAuth 2.1 server, the agent is denied when it reaches outside its scope, the audit log records all of it, and revoking the parent delegation cuts the agent off on its next call.

Everything runs in one process with an in-memory SQLite database. No network access, model or API key is needed.

## Run

```bash
pnpm install
pnpm --filter @glinr/theauth-example-agent-delegation-e2e start
```

From inside this folder, `pnpm start` does the same.

## What happens

1. **Delegation.** Alice owns `alice-assistant` (read and write on `mcp:reports:*`). She delegates read only to `report-bot` with `auth.delegate()`.
2. **Scoped token.** The agent app registers as an OAuth client and is bound to `report-bot` with `mcp.clients.bindAgent()`, so its tokens carry `agent_id`. It runs the authorization code flow with PKCE and gets `mcp:read mcp:write`, then narrows it to `mcp:read` with RFC 8693 token exchange. The new token carries an `act` claim naming the agent app.
3. **Allowed call.** The MCP server calls `mcp.requireScopes(request, ["mcp:read"])`. The token verifies and `read_report` succeeds.
4. **Explain, then denied call.** `auth.explain(agentId, "write", "mcp:reports:delete_report")` returns the decision (`deny`), its code (`no_permission`) and the matched grant (none, because the delegated rule covers read only). Then `delete_report` needs `mcp:write` and the same call returns 403 with an `insufficient_scope` challenge. The typed result (`check.error.code`, `check.rejected`) says why and which agent the token belonged to.
5. **Hook (optional).** A `beforeAuthorize` hook receives the delegation chain, logs its depth and denies a resource on an example blocklist. The block writes a `hook_denied` audit row. Hooks fail closed.
6. **Audit.** The server writes one audit row per MCP decision with `recordAuditEvent`, next to the `delegation.create` row and the hook rows theAuth wrote itself. `audit.query` returns newest first with same-second rows in write order, so the script reverses it and checks the order.
7. **Revocation.** `auth.delegation.revoke(chain.id, { revokedBy })` marks the parent link revoked and writes a `delegation.revoke` row naming Alice. The MCP module is configured with `delegationStore`, so it re-checks the chain on every validation and rejects the still unexpired token with 401 and the code `DELEGATION_REVOKED`.

## Expected output

IDs and the port are random and the timestamps are the time of your run. Everything else should match.

```text
> tsx src/index.ts



== Setup: owner, agents and delegation
   parent agent           alice-assistant (7606b5f4-817...)
   child agent            report-bot (49816fef-55a...)
   delegation             3ad2b191-3e0... read on mcp:reports:*

== Step 1: Alice approves a scoped OAuth grant for the agent app
   client bound to        report-bot (49816fef-55a...)
   user grant scopes      mcp:read mcp:write
   agent token scopes     mcp:read (narrowed by token exchange)

== Step 2: agent calls read_report (needs mcp:read)
   HTTP                   200
   result                 {"content":"[simulated] read_report ok"}

== Step 3: why would delete_report be denied? (theauth.explain)
   decision               deny (code no_permission)
   reason                 No permission grants agent "report-bot" access to "write" on "mcp:reports:delete_report"
   matched grant          none (no rule matches write on this resource)

== Step 3b: agent calls delete_report (needs mcp:write)
   HTTP                   403
   result                 {"error":"Token is missing required scope: mcp:write","code":"INSUFFICIENT_SCOPE","status":403,"challenge":"Bearer error=\"insufficient_scope\", scope=\"mcp:write\", resource_metadata=\"http://127.0.0.1:53663/api/auth/.well-known/oauth-protected-resource\""}

== Step 4: beforeAuthorize hook (optional guard on theauth.authorize)
   [hook] source=authorize chain depth=1 resource=mcp:reports:q3
   read q3                allowed=true
   [hook] source=authorize chain depth=1 resource=mcp:reports:payroll
   read payroll           allowed=false code=hook_denied
   audit id               a265e91a-b8a...

== Audit log (write order)
   2026-10-18T01:14:28.000Z allowed  delegation.create delegation:3ad2b191-3e0b-4ebc-84fc-83f8e5f32565 ()
   2026-10-18T01:14:28.000Z allowed  mcp.tools.call mcp:reports:read_report (scope mcp:read granted)
   2026-10-18T01:14:28.000Z denied   mcp.tools.call mcp:reports:delete_report (INSUFFICIENT_SCOPE: Token is missing required scope: mcp:write)
   2026-10-18T01:14:28.000Z allowed  read mcp:reports:q3 [allowed] ()
   2026-10-18T01:14:28.000Z denied   read mcp:reports:payroll [hook_denied] (resource is on the example blocklist)
   write order check      ok

== Revocation: Alice revokes the parent delegation
   revoked                3ad2b191-3e0...
   HTTP                   401
   result                 {"error":"Delegation chain is no longer valid (revoked link)","code":"DELEGATION_REVOKED","status":401,"challenge":"Bearer error=\"invalid_token\", error_description=\"Delegation chain is no longer valid (revoked link)\", resource_metadata=\"http://127.0.0.1:53663/api/auth/.well-known/oauth-protected-resource\", scope=\"mcp:read\""}

== Audit log after revocation
   2026-10-18T01:14:28.000Z allowed  delegation.create delegation:3ad2b191-3e0b-4ebc-84fc-83f8e5f32565 ()
   2026-10-18T01:14:28.000Z allowed  mcp.tools.call mcp:reports:read_report (scope mcp:read granted)
   2026-10-18T01:14:28.000Z denied   mcp.tools.call mcp:reports:delete_report (INSUFFICIENT_SCOPE: Token is missing required scope: mcp:write)
   2026-10-18T01:14:28.000Z allowed  read mcp:reports:q3 [allowed] ()
   2026-10-18T01:14:28.000Z denied   read mcp:reports:payroll [hook_denied] (resource is on the example blocklist)
   2026-10-18T01:14:28.000Z allowed  delegation.revoke delegation:3ad2b191-3e0b-4ebc-84fc-83f8e5f32565 revokedBy=user-alice ()
   2026-10-18T01:14:28.000Z denied   mcp.tools.call mcp:reports:read_report (DELEGATION_REVOKED: Delegation chain is no longer valid (revoked link))
   write order check      ok
```

## Notes

- The owner is created with `auth.user.create()`.
- The MCP server uses the database stores: `createMcpModule({ auth, ... })` keeps clients, codes, tokens and refresh families in the same SQLite database, and resolves each OAuth client in a delegation chain to the agent bound with `mcp.clients.bindAgent()`. The script only supplies the user arm of `resolveActorAgentId` (the token subject is a user, not an agent, so Alice maps to her root agent). See [MCP OAuth 2.1](../../docs/mcp.mdx).
- A rejected call is attributed from `check.rejected`, which is only set for a token whose signature verified, so the audit row names the agent without trusting an unverified token.
- The `mcp.tools.call` rows come from the example's `recordAuditEvent` calls. The `read` rows are written by `auth.authorize()`.
