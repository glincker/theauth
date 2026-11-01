# Coverage plan: packages/core

Measured 2026-10-31 with `pnpm --filter @glinr/theauth coverage` (vitest, v8 provider, existing config). Whole package, before this branch: lines 89.28%, branches 80.40%, functions 91.87%.

## Security-relevant modules

Line and branch coverage before this branch, with the target. Targets are 95% lines and 85% branches for modules that decide access.

| Module | Role | Lines | Branches | Target |
| --- | --- | --- | --- | --- |
| src/http/routes/delegations.ts | Delegation routes, owner scoping by id | 77.8% | 56.7% | 95 / 85 |
| src/vault/plugin.ts | Token vault routes | 63.0% | 38.5% | 90 / 75 |
| src/mcp/binding.ts | Token binding (DPoP, thumbprint) | 85.6% | 64.8% | 95 / 85 |
| src/mcp/server.ts | MCP token verification | 79.1% | 82.4% | 90 / 85 |
| src/mcp/consent.ts | Consent decisions | 85.2% | 66.7% | 95 / 85 |
| src/mcp/memory-stores.ts | Token stores | 67.0% | 50.6% | 85 / 75 |
| src/http/routes/audit.ts | Owner filter on audit routes | 87.5% | 68.3% | 95 / 85 |
| src/http/routes/agents.ts | Agent management routes | 94.4% | 76.9% | 95 / 85 |
| src/http/require-agent.ts | Bearer parsing, token authorization | 97.0% | 88.9% | keep |
| src/authorize/pipeline.ts | authorize, expiresAt check | 98.7% | 90.8% | keep |
| src/delegation/constraints.ts | Constraint narrowing on delegation | 100% | 97.4% | keep |
| src/auth/client-ip.ts | Trusted proxy IP resolution | 100% | 93.3% | keep |

After this branch: lines 89.28%, branches 80.41%, functions 91.87%. The gain is small because the targeted modules were already well covered; the tests pin behaviour (regressions) rather than raise the number. Branch gains: require-agent 88.9 to 93.3, token-format 75 to 100, constraints 97.4 to 98.7. The remaining gap is in the routes and MCP rows above.

## Added in this branch

- tests/http/owner-scope-by-id.test.ts: id-addressed routes refuse another owner's agent (GHSA-rw7g-rg23-6225).
- tests/client-ip-forged-header.test.ts: forged X-Forwarded-For table (GHSA-r79r-x4p9-7q2c). End to end coverage already exists in tests/http/peer-address.test.ts.
- tests/delegation-constraint-inheritance.test.ts: child constraints only narrow.
- tests/token-header-parsing.test.ts: table and seeded fuzz for Authorization and token prefix parsing.
- tests/agent-expiry.test.ts: boundary case at the exact expiresAt instant.

## Next

1. Cover the unauthorised and not-found branches of src/http/routes/delegations.ts and src/vault/plugin.ts.
2. Add negative cases for src/mcp/binding.ts (mismatched thumbprint, replayed proof).
3. Add fast-check as a dev dependency to turn the seeded fuzz loops into property tests.
