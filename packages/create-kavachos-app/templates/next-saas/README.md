# __APP_NAME__

A Next.js SaaS starter with [KavachOS](https://kavachos.com) auth built in.

## What's included

- **Next.js 15** with App Router and TypeScript
- **KavachOS** for agent identity, session management, and auth
- **Drizzle ORM** with **__DB_DRIVER__** — schema-first, type-safe
- Sign-in / sign-out flow wired to `/api/auth/[...kavach]`
- An agents list page at `/agents`

## Getting started

```bash
cp .env.example .env
# Edit .env: set KAVACHOS_SECRET and DATABASE_URL

pnpm install
pnpm run db:push
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `KAVACHOS_SECRET` | Yes | Long random string, used to sign sessions |
| `DATABASE_URL` | Yes | SQLite: `file:./kavach.db` · Postgres: connection string |

## Project structure

```
src/
  app/
    api/auth/[...kavach]/route.ts  — KavachOS HTTP handler
    agents/page.tsx                — agent list UI
    layout.tsx                     — KavachProvider wrapper
    page.tsx                       — home / landing
  lib/
    kavach.ts                      — singleton KavachOS instance
```

## Deploying

Any Node.js host works. For Vercel, add `KAVACHOS_SECRET` and `DATABASE_URL` in project settings, then push.

If you switch to Postgres, update `DATABASE_URL` and run `pnpm run db:push` to apply migrations.
