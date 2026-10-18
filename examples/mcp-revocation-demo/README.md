# MCP live revocation demo

One script that shows the headline feature: revoke a delegation and the agent's MCP token stops working on the very next request, even though the token is signed, unexpired and unchanged.

It runs in one process with in memory SQLite. No server, no network, no model, no API key. Output is deterministic and takes about two seconds, so it works for a 30 second screen recording.

## Run it

From the repo root, after `pnpm install`:

```bash
pnpm --filter @glinr/theauth build   # only if packages/core/dist is missing or stale
npx tsx examples/mcp-revocation-demo/demo.ts
```

This directory has no `package.json` on purpose, so it adds nothing to the workspace or the lockfile. The two files import the built package by relative path (`../../packages/core/dist`). In your own app, import from `@glinr/theauth` and `@glinr/theauth/mcp` instead. `tsx` comes from the root `node_modules`.

## What it does

1. Creates an owner (alice), an assistant agent with read and write, and a sub-agent that is delegated read only. Registers one OAuth client per agent, binds each to its agent, and mints a narrowed token through RFC 8693 token exchange.
2. Calls `read_report` with the token: allowed.
3. Calls `delete_report`: denied with 403, then prints `explain()` for the denial, including the near miss hint.
4. Decodes the token (the raw token is never printed) and prints the `act` claim, `agent_id` and the `theauth_dlg` binding.
5. Revokes the parent delegation.
6. Calls again: rejected with 401 `DELEGATION_REVOKED` on the next request. Prints the audit rows in write order.
7. Repeats the revoke against a `cached` resource server (learns by polling, bounded by `maxStalenessMs`) and an `offline` one (keeps working until `exp`).
8. Introspects the revoked token as a listed resource server, then as a caller that is not listed.

## Real output

```text
=== 1. Setup: owner, assistant, sub-agent, delegation, MCP client, token exchange
    # alice owns an assistant (read, write). The assistant delegates read only to a sub-agent.
    assistant            alice-assistant (read, write on mcp:reports:*)
    sub-agent            alice-sub-agent (no permissions of its own)
    delegation           assistant to sub-agent, read on mcp:reports:*
    # The user approves the assistant app (mcp:read mcp:write). The sub-agent app narrows that token (RFC 8693).
    token minted         scope mcp:read, bound to the delegation (raw token not printed)

=== 2. Call read_report (needs mcp:read)
    read_report          HTTP 200 OK

=== 3. Call delete_report (needs mcp:write), then ask explain() why
    delete_report        HTTP 403 INSUFFICIENT_SCOPE
                         Token is missing required scope: mcp:write
    explain decision     deny (code no_permission)
    explain reason       No permission grants agent "alice-sub-agent" access to "write" on "mcp:reports:delete_report"
    near miss            delegation grant mcp:reports:* [read]
    mismatch             action
    hint                 action "write" is not granted (grant holds: read)

=== 4. What the token says about who is acting (decoded, not raw)
    scope                mcp:read
    sub (the user)       alice
    act chain            sub-agent app (OAuth client bound to the sub-agent) (outermost is the current actor)
    agent_id             sub-agent
    theauth_dlg.agt      assistant, sub-agent
    theauth_dlg.lnk      the delegation above

=== 5. alice revokes the delegation. The token is unexpired and its signature is valid
    revoked              the assistant to sub-agent delegation

=== 6. Very next request with the same token (live mode)
    read_report          HTTP 401 DELEGATION_REVOKED
                         Delegation has been revoked
    # Audit rows for alice's agents, in write order:
    allowed              mcp.tools.call mcp:reports:read_report
                         reason: scope mcp:read granted
    denied               mcp.tools.call mcp:reports:delete_report
                         reason: INSUFFICIENT_SCOPE: Token is missing required scope: mcp:write
    allowed              delegation.revoke delegation:<id> revokedBy=alice
    denied               mcp.tools.call mcp:reports:read_report
                         reason: DELEGATION_REVOKED: Delegation has been revoked

=== 7a. cached mode: a second server instance learns by polling (poll 200ms, bound 1000ms)
    before revoke        HTTP 200 OK
    right after revoke   HTTP 200 OK
    after the poll       HTTP 401 DELEGATION_REVOKED
                         Delegation has been revoked
    within the bound     yes (under maxStalenessMs plus timer slack)
    # The window above is the price of skipping a database read on every request.

=== 7b. offline mode: signature and exp only
    before revoke        HTTP 200 OK
    1.5s after revoke    HTTP 200 OK
    still valid for      about 60 minutes (until exp), nothing can cut that short
    # Offline is fine when accessTokenTtl is a few minutes. Here it is 3600 seconds on purpose.
    # The live module still refuses this same token:
    same token, live     HTTP 401 DELEGATION_REVOKED
                         Delegation has been revoked

=== 8. Introspection of the revoked token (RFC 7662, always live)
    orders-api (listed)  {"active":false,"theauth_inactive_reason":"delegation_revoked"}
    stranger-api         {"active":false}
    # Only a caller entitled to the audience learns why. Everyone else sees active false.
    # Done. Revoke the delegation, and the next live request fails. No token list, no redeploy.
```

IDs and the audit timestamps are not printed, so two runs match.

## What to notice

- Step 6 needs no token list and no redeploy. The token carries `theauth_dlg`, which names the delegation link it rests on, and the live check reads that link on every request.
- Step 7a is the honest cost of `cached` mode. The cached server answers 200 until its next poll, then 401. The bound is `maxStalenessMs`.
- Step 7b is the honest cost of `offline` mode. Nothing cuts the token short before `exp`, so keep `accessTokenTtl` at a few minutes if you use it. The demo leaves it at 3600 seconds so the gap is visible.
- Step 8: a listed resource server learns the reason (`delegation_revoked`). Any other caller gets exactly `{"active":false}`.

## Files

- `demo.ts`: the narrated script.
- `helpers.ts`: setup, token minting, the per tool check (`requireScopes` plus an audit row) and the introspection call.

The step by step walkthrough is in the tutorial `docs/tutorials/live-revocation.mdx`. Background is in `docs/mcp-revocation.mdx`.
