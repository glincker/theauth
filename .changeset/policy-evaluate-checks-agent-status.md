---
"@glinr/theauth": patch
---

`policy.evaluate` now denies revoked, suspended and expired agents with `POLICY_AGENT_INACTIVE`. Requests that arrive with an agent token were already rejected once the agent was revoked, but `evaluate` takes an agent id directly and never read the agent's status, so a revoked agent could still be allowed by a matching permission. If you gate actions with `evaluate`, upgrade.
