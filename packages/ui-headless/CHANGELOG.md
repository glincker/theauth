# @glinr/theauth-ui-headless

## 0.2.0

### Minor Changes

- 1cd4db9: Agent tokens: `GoApiToken` gains `kind`, `agentName` and `delegatedBy`, and `apiTokens.mint` accepts `kind` and `agentName`. `useApiTokens` takes a `kind` filter and `useAgentTokens` mints, lists and revokes agent tokens. New `@glinr/theauth-ui-headless` package with unstyled `SessionList`, `ApiTokenList`, `MintTokenForm`, `DeviceApproval`, `StepUpDialog` and `useStepUpRetry`.
- 713c698: Bearer-mode client and agent self-service. `createTheAuthGoClient` takes `getToken`, which sets `Authorization` and omits credentials. `apiTokens.current()` and `apiTokens.revokeCurrent()` call the bearer-only `/auth/tokens/current`; a cookie session gets `auth.bearer_required` (`isBearerRequired`). New `agents` (list, register, revoke) and `delegations` (list, grant, revoke) client methods over `/auth/account/*`, with `useCurrentToken`, `useAgents`, `useDelegations` hooks and unstyled `AgentList` and `AgentRegisterForm` components.
- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
