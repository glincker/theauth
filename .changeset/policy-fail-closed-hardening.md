---
"@glinr/theauth": patch
---

Security fix: the policy engine now fails closed on several constraint edge cases. `maxCallsPerHour: 0` denies every call instead of meaning no limit. IPv4 allowlist parsing rejects octets such as `1abc`. `allowedArgPatterns` checks strings nested in objects and arrays, and an invalid pattern denies instead of throwing. Time windows must be `HH:MM`, support overnight ranges (start after end), and a malformed window denies. `policy.evaluate` denies an agent id with no matching row with `POLICY_AGENT_NOT_FOUND`. A throwing `afterAuthorize` or `onViolation` hook no longer causes an unhandled rejection. Delegation chain limits no longer spread large arrays into `Math.min`.
