# Hono server example

Full auth server using KavachOS with the Hono adapter. Includes sign-up, sign-in, session management, and agent CRUD.

## Run

```bash
pnpm install
pnpm dev
# Server starts on http://localhost:3000
```

## Endpoints

- `POST /api/kavach/sign-up` - Create account
- `POST /api/kavach/sign-in` - Sign in
- `GET /api/kavach/session` - Get current session
- `POST /api/kavach/sign-out` - Sign out
