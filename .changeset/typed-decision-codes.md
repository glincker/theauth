---
"@glinr/theauth": major
---

Add typed decision codes. `authorize()`, `authorizeByToken()` and `policy.evaluate()` return a `code` from the closed set `DECISION_CODES`, and `onViolation` receives `code` next to `type`. `onViolation.type` is now derived from the code instead of substring matching on the reason text, so an agent named `pirate-bot` is no longer reported as `rate_limited`, and a `beforeAuthorize` block is always `permission_denied` with code `hook_denied`. `PolicyDecision.code` is a new required field. `classifyViolation` is deprecated. New exports: `DECISION_CODES`, `DecisionCode`, `DenialCode`, `isDecisionCode`, `violationTypeOf`. See the upgrade notes in `docs/upgrading-to-2.mdx`.
