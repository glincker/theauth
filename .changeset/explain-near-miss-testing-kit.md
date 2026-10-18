---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

`explain()` now returns `nearMisses`: when no grant matches, up to three own or delegated grants that failed on resource or action, each with a plain hint and a score (empty when `matchedGrant` is set). New `@glinr/theauth/testing` subpath with `createTestAuth`, `definePolicySuite`, `runPolicySuite`, `expectAllowed`, `expectDenied` and vitest matchers, and a new `theauth policy test <suite>` command (`--json`, `--config`, exit 1 on failure).

Upgrade notes: `ExplainResult` gains a required `nearMisses` field. Code that builds an `ExplainResult` by hand needs `nearMisses: []`.
