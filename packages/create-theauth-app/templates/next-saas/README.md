# __APP_NAME__

A Next.js SaaS starter with [theAuth](https://theauth.dev) auth built in.

## What's included

- **Next.js 15** with App Router and TypeScript
- **theAuth** for agent identity, session management, and auth
- **Drizzle ORM** with **__DB_DRIVER__**: schema-first, type-safe
- Sign-in / sign-out flow wired to `/api/auth/[...theauth]`
- An agents list page at `/agents`

## Getting started

```bash
cp .env.example .env
# Edit .env: set THEAUTH_SECRET and DATABASE_URL

pnpm install
pnpm run db:push
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `THEAUTH_SECRET` | Yes | Long random string, used to sign sessions |
| `DATABASE_URL` | Yes | SQLite: `./theauth.db` · Postgres: connection string |

## Project structure

```
src/
  app/
    api/auth/[...theauth]/route.ts  : TheAuth HTTP handler
    agents/page.tsx                : agent list UI
    layout.tsx                     : TheAuthProvider wrapper
    page.tsx                       : home / landing
  lib/
    theauth.ts                      : singleton TheAuth instance
```

## Optional: sign-in UI

The template ships without sign-in screens. If you want them, copy the components into `src/components/theauth` as source you own:

```bash
npx @glinr/theauth-cli add sign-in sign-up
```

Then render `SignIn` from `src/components/theauth/sign-in` inside the `TheAuthProvider` already in `layout.tsx`. Skip this if you bring your own UI.

## Deploying

Any Node.js host works. For Vercel, add `THEAUTH_SECRET` and `DATABASE_URL` in project settings, then push.

If you switch to Postgres, update `DATABASE_URL` and run `pnpm run db:push` to apply migrations.
