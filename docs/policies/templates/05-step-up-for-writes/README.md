# Template 05, Step-up approval for writes

Reads are allowed without ceremony. Writes and deletes require a human to approve before the agent can proceed. The engine returns `allowed: false` with a fixed reason string when `requireApproval` is set, so your application layer can detect it and start an approval flow (see [Approval flows](/approval)) rather than treat it as a hard deny.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "data-bot" },
  action: "write",       // or "delete" for the gated path
  resource: "database:records",
});
```

## Example decisions

| Action | Decision |
|---|---|
| `read` | **allow**, no constraint |
| `write` | **deny**, requires approval |
| `delete` | **deny**, requires approval |

## Tweak this

- Approval does not change the decision. `evaluate()` and `authorize()` do not read approval requests, and there is no bypass token, so the permission keeps denying after a human approves. Record the approval with `theauth.approval`, then perform the action from your own code. If you instead remove the constraint row, call `theauth.policy.invalidate({ agentId })` because `requireApproval` denials are cached for up to the cache TTL.
- Combine with `timeWindow` (template 07) on the same permission. Constraints on one permission are all checked, in this order: rate limit, argument patterns, approval, time window, IP allowlist; the first failure is the reason returned.
