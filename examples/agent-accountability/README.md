# Agent accountability example

A runnable, in-memory demo of the accountability loop for an AI agent: who it is,
what it may do, who said yes, and what the record shows. No external services.

## Run

```bash
pnpm install
pnpm --filter @glinr/theauth-example-agent-accountability start
```

Test: `pnpm --filter @glinr/theauth-example-agent-accountability test`

## What it demonstrates

1. Create an agent identity bound to an owning user.
2. Delegate scoped, short-lived authority (read only, 15 minutes) to it. The
   refund grant carries a `requireApproval` constraint, which is stored on the
   chain. The chain reports the root owner.
3. The agent acts. `policy.evaluate` runs before every action and returns
   allow, deny or escalate. A write is denied, and the refund escalates because
   the delegated permission carries `requireApproval`. With `openApproval`, the
   escalation opens an approval request.
4. A human approves the request. Passing its `approvalId` to the next `policy.evaluate` unlocks exactly that one action, and a second use is denied.
5. The human decision is written to the tamper-evident audit log and the chain verifies.
6. The owner revokes the agent and its next attempt is denied with `POLICY_AGENT_INACTIVE`.

The source is `src/loop.ts` (the loop) and `src/index.ts` (transcript printer).

## Expected output

```
[1] Create an agent identity owned by alice
    agent refund-worker (92373bdc-b51) owner=user-alice

[2] Delegate narrow authority for 15 minutes
    chain 4ef44f7e-b30 grants crm:notes read and refund (approval required), root owner user-alice, expires 2026-10-16T04:26:13.305Z

[3] Agent attempts actions; policy runs first
    read  mcp:crm:notes      -> ALLOWED
    write mcp:crm:notes      -> DENIED (POLICY_NO_MATCHING_PERMISSION)
    exec  mcp:payments:refund -> HELD (This action requires human approval before execution)

[4] High-value action waits for a human
    approval apr_91220fce pending for user-alice
    alice -> APPROVED
    exec  mcp:payments:refund -> ALLOWED with approval
    again mcp:payments:refund -> DENIED (APPROVAL_ALREADY_USED)

[5] Record the human decision and verify the audit chain
    8 audit entries for refund-worker
    chain ok=true rows checked=8

[6] Owner revokes the agent
    read  mcp:crm:notes      -> DENIED (POLICY_AGENT_INACTIVE)
```

IDs and timestamps vary per run.

## What this proves

- Responsible: the agent identity is tied to an owner (steps 1 and 2), so every action has a named person behind it.
- Accountable: the owner approves or denies high-value actions (step 4) and can revoke at any time (step 6).
- Consulted: the policy check and the approval request ask the right party before a risky action runs (step 3).
- Informed: the decision and every attempt land in a hash-chained audit log that verifies (step 5).

## Notes

- An approval does nothing on its own. The call must carry the `approvalId`, and
  `policy.evaluate` (or `authorize`) then checks it is approved, for this agent,
  action and resource, unexpired and unused, and spends it in one atomic step.
  The audit row for that allow records `approver_id` and the approval id.
- The final decision row (step 5) is written by the example with `insertAuditRow`
  to put the human decision into the chain. The policy decisions, delegation and
  approval events are chained by the SDK.
- `input_provenance` is not set by this example or by the SDK.
