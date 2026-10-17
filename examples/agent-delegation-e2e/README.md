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
2. **Scoped token.** The agent app runs the authorization code flow with PKCE and gets `mcp:read mcp:write`, then narrows it to `mcp:read` with RFC 8693 token exchange. The new token carries an `act` claim naming the agent app.
3. **Allowed call.** The MCP server calls `mcp.requireScopes(request, ["mcp:read"])`. The token verifies and `read_report` succeeds.
4. **Denied call.** `delete_report` needs `mcp:write`. The same call returns 403 with a step-up challenge.
5. **Audit.** The server writes one audit row per decision with `recordAuditEvent`, next to the `delegation.create` row theAuth wrote itself.
6. **Revocation.** `auth.delegation.revoke()` marks the parent link revoked. The MCP module is configured with `delegationStore`, so it re-checks the chain on every validation and rejects the still unexpired token with 401.

## Expected output

IDs are random and the timestamps are the time of your run. Everything else should match.

```text
> tsx src/index.ts


== Setup: owner, agents and delegation
   parent agent           alice-assistant (f6358e84-72e...)
   child agent            report-bot (813814c5-a9b...)
   delegation             8b8ed5e0-1de... read on mcp:reports:*

== Step 1: Alice approves a scoped OAuth grant for the agent app
   user grant scopes      mcp:read mcp:write
   agent token scopes     mcp:read (narrowed by token exchange)

== Step 2: agent calls read_report (needs mcp:read)
   HTTP                   200
   result                 {"content":"[simulated] read_report ok"}

== Step 3: agent calls delete_report (needs mcp:write)
   HTTP                   403
   result                 {"error":"insufficient scope","status":403}

== Audit log
   2026-10-17T23:07:25.000Z allowed  delegation.create delegation:8b8ed5e0-1dec-4f74-b52b-b2cc9de5fd0d ()
   2026-10-17T23:07:25.000Z allowed  mcp.tools.call mcp:reports:read_report (scope mcp:read granted)
   2026-10-17T23:07:25.000Z denied   mcp.tools.call mcp:reports:delete_report (missing scope mcp:write)

== Revocation: Alice revokes the parent delegation
   revoked                8b8ed5e0-1de...
   HTTP                   401
   result                 {"error":"Delegation chain is no longer valid (revoked link)","status":401}

== Audit log after revocation
   2026-10-17T23:07:25.000Z allowed  delegation.create delegation:8b8ed5e0-1dec-4f74-b52b-b2cc9de5fd0d ()
   2026-10-17T23:07:25.000Z allowed  mcp.tools.call mcp:reports:read_report (scope mcp:read granted)
   2026-10-17T23:07:25.000Z denied   mcp.tools.call mcp:reports:delete_report (missing scope mcp:write)
   2026-10-17T23:07:25.000Z denied   mcp.tools.call mcp:reports:read_report (token rejected: Delegation chain is no longer valid (revoked link))
```

## Notes

- The owner row is inserted with drizzle. A marked `TODO(auth.user.create)` comment in `src/index.ts` shows the line `auth.user.create()` replaces.
- theAuth has no built-in link from an OAuth client to an agent. The script supplies it through `resolveActorAgentId`. See [MCP OAuth 2.1](../../docs/mcp.mdx).
- The MCP server uses in-memory token and client stores, as in `examples/mcp-server`. Use your database in production.
