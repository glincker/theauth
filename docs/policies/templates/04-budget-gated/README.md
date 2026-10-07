# Template 04, Budget-gated agent

An agent may call the LLM gateway up to a fixed number of times per rolling hour. Beyond that cap every call is denied until the window resets. This prevents runaway loops from consuming unbounded compute budget. The counter lives in `theauth_rate_limits` and increments on each allowed call.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "budget-bot" },
  action: "execute",
  resource: "llm:gateway",
});
```

## Example decisions

| Call count in window | Decision |
|---|---|
| 0-99 | **allow**, under cap |
| 100 or more | **deny**, limit reached |

The window is a rolling hour. Calls are counted in 5 minute buckets and every bucket from the last hour is summed. The counter is keyed by agent and requested resource string, and it increments when the rate check passes (before the other constraints on the same permission run). Budget policies (`theauth.policies`) are a separate module and are not consulted by `evaluate()` or `authorize()`.

## Tweak this

- Lower `maxCallsPerHour` to `10` during initial rollout and raise it once you trust the agent.
- When requests go through `theauth.authorize()`, the `onViolation` hook receives a `rate_limited` violation when the cap is hit, which you can use to alert the team.
