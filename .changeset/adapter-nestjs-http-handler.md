---
"@glinr/theauth-nestjs": major
---

Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`) using `toWebRequest` and `sendWebResponse`. `TheAuthModule` and `theAuthMiddleware` are now thin glue and serve every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`. New `requireScope(auth, { action, resource })` guard for `@UseGuards` and `getAgent(request)`.

Upgrade notes:

- `TheAuthModuleOptions` and `TheAuthNestjsOptions` are now `theauth` plus the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). For `theAuthMiddleware`, `basePath` defaults to where you mount it.
- Removed the deprecated `AuthModule`, `AuthModuleOptions`, `AuthNestjsOptions`, `authMiddleware` and `buildAuthRouter`. Use `TheAuthModule`, `TheAuthModuleOptions`, `TheAuthNestjsOptions` and `theAuthMiddleware`.
- `buildTheAuthRouter(auth, mcp?, options?)` now returns a middleware function instead of an Express `Router`. Mount it with `app.use(path, ...)` as before.
- `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial.
- The client IP now comes from the socket peer address, or from forwarded headers when `trustedProxy` is set.
