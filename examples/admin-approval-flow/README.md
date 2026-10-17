# Admin approval flow

```bash
pnpm --filter @glinr/theauth-example-admin-approval-flow start
```

Expected output is a numbered transcript, seven steps:

1. A theAuth server starts with `adminApi` for alice and bob.
2. The admin MCP server (writes on, actor `alice-mcp`) calls `revoke_delegation`: `pending` with an `approvalId`, delegation still active.
3. Alice approves her own request: `403 SELF_APPROVAL`.
4. Bob lists pending approvals and approves.
5. The tool is called again with the `approvalId`: `executed`, delegation `revoked`.
6. Replaying the same `approvalId` is refused (`APPROVAL_ALREADY_USED`).
7. The audit events are printed: requested, pending, approve, consume, revoke, executed.

What it proves: an MCP agent cannot change admin state alone. A second human must approve, the approval is bound to one action and resource, spends once, and every step is audited.

Test: `pnpm --filter @glinr/theauth-example-admin-approval-flow test`.
