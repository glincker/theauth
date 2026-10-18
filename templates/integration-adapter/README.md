# theAuth integration adapter (template)

A starting point for a community integration. It registers a `beforeAuthorize` hook with theAuth and denies by default when the integration fails.

## Use it

1. Copy this directory into your own repository.
2. Rename `name` in `package.json` and replace the placeholder `evaluate()` in `src/index.ts` with your policy check.
3. Pin `@glinr/theauth` to the version you tested against in your peer range.
4. Register the hook at startup:

```typescript
import { createTheAuth } from "@glinr/theauth";
import { createBeforeAuthorizeHook } from "./index.js";

const theauth = await createTheAuth({
  database: { provider: "sqlite-native", url: "theauth.db" },
  hooks: {
    beforeAuthorize: createBeforeAuthorizeHook({ timeoutMs: 2000 }),
  },
});
```

## Contract

- Input: `{ agentId, action, resource, arguments? }`.
- Output: `{ allow: boolean; reason?: string }` or nothing. Returning nothing lets the call proceed. This template always returns an explicit decision.
- Errors and timeouts deny with a reason. See `docs/hooks.mdx` for the full hook semantics.

## Guard vendors

If your integration is a policy service, you do not need this template. Expose an HTTPS endpoint that follows the remote guard protocol (`docs/guards.mdx`) and customers wire it with `httpGuard`. Verify the request with `verifyGuardRequest` and sign every verdict with `signGuardResponse`, because `httpGuard` denies unsigned responses. Check it with `npx @glinr/theauth-conformance guard <url> --secret <s>`.

## Framework adapters

This template is for hook integrations. To integrate a web framework instead, wrap `createTheAuthHandler` from `@glinr/theauth/http` (web `Request` in, `Response` out) rather than re-implementing routes, and wrap `requireAgent` for a `requireScope` guard. See `docs/adapters/routes.mdx`.

## Scripts

- `npm test`: run the vitest suite.
- `npm run build`: compile to `dist/`.
