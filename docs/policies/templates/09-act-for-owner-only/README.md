# Template 09, Agent acts only for its owner within delegated scope

A worker agent can act only on its owner's resources, only inside the scope the owner's agent delegated to it, and only while the request names that owner. See [Delegation chains](/delegation).

## Input shape

```ts
// Worker reading inside the delegated scope, for its own owner
await theauth.policy.evaluate({
  subject: { agentId: "worker-id", ownerId: "user-123" },
  action: "read",
  resource: "files:user-123:project-a",
});

// Same worker, request names a different owner
await theauth.policy.evaluate({
  subject: { agentId: "worker-id", ownerId: "user-999" },
  action: "read",
  resource: "files:user-999:project-a",
});
```

Create the link with `theauth.delegate()`. The delegating agent must hold every permission it delegates. The result carries `rootOwnerId` and `path`, and `decision.principal` returns the same lineage on each check.

## Example decisions

| Agent | Action | Resource | Decision |
|---|---|---|---|
| owner agent | `write` | `files:user-123:notes` | **allow**, direct permission |
| worker, `ownerId` user-123 | `read` | `files:user-123:project-a` | **allow**, active delegation |
| worker, `ownerId` user-123 | `write` | `files:user-123:project-a` | **deny**, delegated scope is read-only |
| worker, `ownerId` user-123 | `read` | `files:user-123:project-b` | **deny**, outside delegated scope |
| worker, `ownerId` user-999 | `read` | `files:user-999:project-a` | **deny**, `POLICY_OWNER_MISMATCH` |
| worker, after expiry or `delegation.revoke()` | `read` | `files:user-123:project-a` | **deny**, no active delegation |
| revoked worker | `read` | `files:user-123:project-a` | **deny**, `POLICY_AGENT_INACTIVE` |

## Tweak this

- Use a short `expiresAt` and `maxDepth: 1` so the worker cannot be extended further without a new call.
- Revoke with `theauth.delegation.revoke(chain.id)`. Downstream links are revoked too. `agent.revoke()` does not revoke delegations in the TypeScript package, so do both.
- Constraints on delegated permissions are stored and enforced. Narrowing against the parent: `requireApproval` is OR-ed, `maxCallsPerHour` takes the lower value, and lists (`allowedArgPatterns`, `ipAllowlist`) are intersected.
- The owner check compares `subject.ownerId` with the agent's own `ownerId`. Take the value from your authenticated session, not from the agent's input. If `subject.ownerId` is omitted, no owner check runs.
- Audit what the worker did for this owner with `theauth.audit.query({ agentId: worker.id })`, or `replayAgent(worker.id, { userId })`.
