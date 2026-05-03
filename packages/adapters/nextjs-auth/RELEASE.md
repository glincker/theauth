# Releasing @kavachos/nextjs-auth

## First-time publish (v0.1.0)

```bash
cd kavachos/packages/adapters/nextjs-auth
pnpm build
pnpm publish --access public
```

You'll need to be logged into npm with publish rights to the @kavachos org:

```bash
npm login
npm whoami    # should show your npm user
```

## After publish

In glinr-me's `apps/web/package.json`, swap the file dep:

```diff
- "@kavachos/nextjs-auth": "file:../../../kavachos/packages/adapters/nextjs-auth"
+ "@kavachos/nextjs-auth": "^0.1.0"
```

Then `cd apps/web && pnpm install` and verify `npx tsc --noEmit` still passes.

## Tag the release

```bash
git tag @kavachos/nextjs-auth@0.1.0
git push --tags
```

## v0.2 wishlist (when revisiting)

- HMAC-SHA256 sign the cookie cache (currently plain JSON — readable by anyone with the cookie, but cannot be forged)
- Tests for `withAuth()` middleware (currently only lower-level helpers have tests)
- Plugin slot for 2FA / org-context / multi-session
- better-auth-style `auth.api` namespacing for more ergonomic imports
