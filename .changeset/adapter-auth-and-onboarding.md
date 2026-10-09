---
"@glinr/theauth": minor
"@glinr/theauth-hono": major
"@glinr/theauth-express": major
"@glinr/theauth-fastify": major
"@glinr/theauth-nestjs": major
"@glinr/theauth-nextjs": major
"@glinr/theauth-nuxt": major
"@glinr/theauth-sveltekit": major
"@glinr/theauth-astro": major
"@glinr/theauth-solidstart": major
"@glinr/theauth-tanstack": major
"@glinr/create-theauth-app": minor
"@glinr/theauth-cli": patch
---

Security: the framework adapters no longer serve the management routes anonymously.

BREAKING (adapters): `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` now require an authenticated caller. Pass `authenticate: (request) => ({ id }) | null` to the adapter, or configure `auth.session` on `createTheAuth` to accept any valid session. With neither, the adapter throws when it is created. For local development only, `allowUnauthenticated: true` restores the old behavior and logs a warning. `/authorize/token`, MCP, password reset, email verification and plugin routes are unchanged.

Other fixes:

- hono and fastify: plugin routes now work when the adapter is mounted under a prefix (`app.route("/x", theAuthHono(...))`, `register(plugin, { prefix })`) instead of returning 404.
- core: `plugins: [magicLink(...)]` (and the email OTP, 2FA, passkey, API key and organization plugins) now create their tables, matching the config-key form.
- core: new `createAdapterGuard` and `isProtectedAdapterPath` exports used by every adapter.
- create-theauth-app: templates pin `@glinr/*` packages to the versions in this release instead of stale ranges, list `sql.js` (the driver behind `provider: "sqlite"`) and `zod`, and the hono-mcp template protects its management routes with an `ADMIN_API_KEY`. The next-saas catch-all route now passes the TheAuth instance to the adapter.
