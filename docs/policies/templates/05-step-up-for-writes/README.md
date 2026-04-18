# Template 05, Step-up approval for writes

Reads are allowed without ceremony. Writes and deletes require a human to approve before the agent can proceed. The engine returns `allowed: false` with a fixed reason string when `requireApproval` is set, so your application layer knows to start an approval flow rather than treat it as a hard deny.

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

- After approval is granted, re-evaluate with a short-lived token that bypasses `requireApproval`, or remove the constraint row from the DB for the approved session.
- Combine with `timeWindow` (template 07) so approvals are only requested during business hours.
