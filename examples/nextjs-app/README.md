# Next.js app example

Full-stack Next.js 15 app with TheAuth authentication. Uses `@glinr/theauth-nextjs` adapter and `@glinr/theauth-react` hooks.

## Run

```bash
pnpm install
pnpm dev
# App starts on http://localhost:3000
```

## Features

- Sign up / sign in pages
- Protected routes with middleware
- Session management via `useSession()` hook

## Deploy

This folder depends on workspace packages (`workspace:*`), so it only installs inside the monorepo and a one-click deploy button would fail. To get a deployable copy, scaffold a standalone project with `npm create theauth-app@latest` and pick the `next-saas` template.
