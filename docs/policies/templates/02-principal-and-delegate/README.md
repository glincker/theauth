# Template 02, Principal and delegated agent

A principal agent owns read and write access to a resource. It delegates a read-only subset to a second agent with an expiry date. When the delegation expires the delegate is denied even for reads. This models short-lived assistant agents or third-party integrations that should lose access automatically.

## Input shape

```ts
// Principal
engine.evaluate({ subject: { agentId: "principal-id" }, action: "write", resource: "reports:monthly" });

// Delegate
engine.evaluate({ subject: { agentId: "delegate-id" }, action: "read", resource: "reports:monthly" });
```

The delegation chain must be inserted into `kavach_delegation_chains` with `status: "active"` and `expiresAt` in the future.

## Example decisions

| Agent | Action | Decision |
|---|---|---|
| principal | `write` | **allow**, direct permission |
| delegate | `read` | **allow**, active delegation |
| delegate | `write` | **deny**, delegated scope is read-only |

## Tweak this

- Set `expiresAt` to `Date.now() + 3_600_000` for a one-hour window.
- Reduce `maxDepth` on the chain row to prevent the delegate from re-delegating further.
