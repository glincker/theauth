# Template 04, Budget-gated agent

An agent may call the LLM gateway up to a fixed number of times per rolling hour. Beyond that cap every call is denied until the window resets. This prevents runaway loops from consuming unbounded compute budget. The counter lives in `kavach_rate_limits` and increments on each allowed call.

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
| 100 | **deny**, limit reached |

## Tweak this

- Lower `maxCallsPerHour` to `10` during initial rollout and raise it once you trust the agent.
- Pair with a webhook on the deny event to alert the team before the hour resets.
