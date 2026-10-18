---
"@glinr/theauth": minor
---

Step-up follow-ups. `POST /auth/passkey/step-up/options` and `/auth/passkey/step-up/verify` re-authenticate the current session with a passkey, with no second session, and refuse a credential that belongs to another user. Social sign-in now records a `federated` method (`amr` `fed`, single factor) and adds the provider's registered RFC 8176 `amr` hints from its ID token without ever raising `acr`. The headless `totp.handleRequest` and `passkey.handleRequest` handlers now record a step up on the caller's own session. `AuthMethod` gains `"federated"`, `AuthEvent` gains optional `idpAmr`, and `CreateSessionOptions` gains `idpAmr`. `mcp/types.ts` and `theauth-core.ts` are split under 500 lines with the same exports. See `docs/step-up-auth.mdx`.
