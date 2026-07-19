---
title: Trust Scoring
description: TrustScore is a 0 to 100 value derived from each agent's audit log, mapping to five named levels that gate autonomy, approval requirements, and rate limit strictness.
---

# Trust Scoring

A trust score is a 0-100 number that reflects how much an agent has earned autonomous operation. New agents start with a baseline of 50. Over time, successful calls raise the score; denied requests, permission violations, and anomalous patterns lower it.

The score maps to one of five named levels that your application can use to gate behavior: requiring human approval for low-trust agents, unlocking faster paths for high-trust ones.

Scores are computed from the audit log, not guessed. An agent cannot self-report a high score.

## TrustScore fields

| Field | Type | Description |
|---|---|---|
| `agentId` | `string` | The agent this score belongs to. |
| `score` | `number` | Numeric value from 0 to 100. |
| `level` | `string` | Named trust level derived from the score. |
| `factors.successRate` | `number` | Percentage of all calls that were allowed. |
| `factors.denialRate` | `number` | Percentage of all calls that were denied. |
| `factors.ageInDays` | `number` | Days since the agent was created. |
| `factors.totalCalls` | `number` | Total authorization calls in the audit log. |
| `factors.anomalyCount` | `number` | Denied calls matching privilege escalation patterns. |
| `factors.lastViolation` | `string \| undefined` | ISO timestamp of the most recent denied call. |
| `computedAt` | `string` | ISO timestamp of when this score was last computed. |

## How scores are computed

The formula starts at 50 and applies adjustments:

```
score = 50
score += min(25, floor(allowedCalls / 100))   // +1 per 100 successful calls, capped at +25
score -= deniedCalls x 5                       // -5 per denial
score -= anomalyCount x 10                     // -10 per privilege escalation attempt
score += 10 if ageInDays > 30                  // bonus for established agents
score += 5  if ageInDays > 7                   // smaller bonus for recent agents
score = clamp(score, 0, 100)
```

## Trust levels

| Score range | Level | Typical gate |
|---|---|---|
| 0-19 | `untrusted` | Block or require manual approval on every call |
| 20-39 | `limited` | Restrict to read-only actions |
| 40-59 | `standard` | Normal operation |
| 60-79 | `trusted` | Unlock higher rate limits |
| 80-100 | `elevated` | Skip approval gates, highest autonomy |

## Querying trust scores

```typescript
const score = await kavach.trust.getScore(agentId);

console.log(score.score);   // 73
console.log(score.level);   // "trusted"
console.log(score.factors); // { successRate: 0.94, denialRate: 0.06, ... }
```

## Using trust scores to gate behavior

```typescript
const score = await kavach.trust.getScore(agentId);

if (score.level === 'untrusted' || score.level === 'limited') {
  // Route to a human-in-the-loop approval flow
  await kavach.approval.request({ agentId, action, resource });
} else {
  // Proceed directly
  const result = await kavach.authorize(agentId, { action, resource });
}
```

## Anomaly detection

TheAuth can flag agents that exhibit unusual patterns. Configure thresholds in `createAuth`:

```typescript
anomaly: {
  highFrequencyThreshold: 200,       // calls per agent per hour
  highDenialRateThreshold: 30,       // denial rate percentage
  expectedHours: { start: 8, end: 20 }, // flag off-hours access
},
```

Anomaly events lower the trust score and can trigger webhooks if configured.

## Related pages

- [Agent Identity](agents.md)
- [Audit Events](../reference/audit-events.md)
- [Configuration](../reference/configuration.md)
