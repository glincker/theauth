# Template 08, Spending limit with human approval above a threshold

An agent may make small payments on its own, up to a call cap per hour. A payment at or above the threshold makes `policy.evaluate()` return `escalate`, and a human approves before it runs. See [Approval flows](/approval).

## Input shape

```ts
import { spendLimitPolicy } from "./policy";

// createTheAuth({ ..., policy: spendLimitPolicy })

const decision = await theauth.policy.evaluate(
  {
    subject: { agentId: agent.id, ownerId: agent.ownerId },
    action: "execute",
    resource: "payments:transfer",
    context: { risk: { amount: 250, currency: "USD" } },
  },
  { openApproval: true },
);

if (decision.decision === "escalate") {
  const requestId = decision.escalation?.approvalRequestId;
  // Notify a human. After approval.approve(requestId, approverId), run the payment from your code.
}
```

## Example decisions

| Amount | Decision |
|---|---|
| 40 | **allow**, under the threshold |
| 99 | **allow**, just under the threshold |
| 100 | **escalate**, at the threshold |
| 250 | **escalate**, an approval request is opened |
| 40, 51st call in the hour | **deny**, rate limit exceeded |

## Tweak this

- The threshold is the `minAmount` of a risk tier in the engine config. The amount comes from `context.risk.amount`, which your code sets. The engine does not read it from the arguments.
- A tier can also match `currency`, `dataClasses` and `irreversible`, and `require` can be `approval` or `step_up`. The strongest matching tier wins.
- Approval is a record, not a bypass. The decision stays `escalate` after a human approves. Run the payment from your own code after `approval.get()` returns `approved`.
- Cumulative spend is not tracked. Budget policies (`theauth.policies`) cap token cost and call counts, not currency, and `evaluate()` does not consult them. See [Budget policies](/budget-policies).
- Set `policyVersion` and it is written to the `policy_version` field of each audit row.
