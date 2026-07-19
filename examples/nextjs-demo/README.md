# TheAuth Next.js Demo

A working demo of TheAuth auth and agent features built with Next.js App Router.

## Run

```bash
cd examples/nextjs-demo
pnpm install
pnpm dev
```

Open http://localhost:3002

## What it demonstrates

- Email and password sign up / sign in
- Email verification (check terminal for link)
- Agent creation with permissions
- Token display on create / rotate
- Authorization checks (allow/deny)
- Audit trail
- Token rotation
- Session management via `@glinr/theauth-react` hooks

## Structure

```
app/
  page.tsx                    # Sign in / sign up
  dashboard/page.tsx          # Authenticated dashboard
  auth/verify-email/page.tsx  # Email verification
  api/theauth/[...theauth]/   # All TheAuth API routes
lib/
  kavach.ts                   # Singleton TheAuth instance
```

## Notes

- SQLite database written to `theauth-demo.db` in the project root
- No `.env` required, everything runs out of the box
- Verification and password reset links print to the terminal in dev
