# Hono server example

Full auth server using TheAuth with the Hono adapter. Includes sign-up, sign-in, session management, and agent CRUD.

## Run

```bash
pnpm install
pnpm dev
# Server starts on http://localhost:3000
```

## Endpoints

- `POST /api/theauth/sign-up` - Create account
- `POST /api/theauth/sign-in` - Sign in
- `GET /api/theauth/session` - Get current session
- `POST /api/theauth/sign-out` - Sign out
