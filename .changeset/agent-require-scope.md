---
"@glinr/theauth-hono": minor
"@glinr/theauth-nextjs": minor
"@glinr/theauth-express": minor
---

Add a one-line `requireScope({ action, resource })` route guard to the Hono, Next.js, and Express adapters. It reads the agent bearer token, calls `authorizeByToken`, answers 401 for a missing or invalid token and 403 with the denial reason when not allowed, and otherwise attaches the agent identity to the request context.
