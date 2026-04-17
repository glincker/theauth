# Template 07, Business-hours-only access

An agent may send emails only between 09:00 and 17:00. Calls outside that window are denied. The window is evaluated against the server process clock using `HH:MM` string comparison, so `"17:01" > "17:00"` means after-hours is denied correctly.

## Input shape

```ts
engine.evaluate({
  subject: { agentId: "email-bot" },
  action: "execute",
  resource: "tool:send_email",
  context: { timestamp: new Date() },  // informational only; engine uses server clock
});
```

## Example decisions

| Server time | Decision |
|---|---|
| 10:30 | **allow**, inside window |
| 17:00 | **allow**, end of window, inclusive |
| 17:01 | **deny**, after hours |
| 08:59 | **deny**, before hours |

## Engine limitation

The engine does not support timezone-aware time windows. It calls `new Date().getHours()` on the server process, which returns the local timezone of the process. There is no `tz` field on `timeWindow`. To enforce a specific timezone, either start the process with `TZ=America/New_York` or pre-convert the current time before calling `evaluate`. Passing `context.timestamp` does not influence the clock check.

## Tweak this

- Change `end` to `"23:59"` to allow evening work without removing the morning floor.
- Add an `ipAllowlist` constraint alongside `timeWindow` to require the agent to also call from a known office IP range.
