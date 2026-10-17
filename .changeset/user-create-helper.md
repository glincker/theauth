---
"@glinr/theauth": minor
---

Add `auth.user.create({ email, name?, id? })` and `auth.user.get(idOrEmail)`. `create` validates the email with zod, lowercases it, generates an id when none is given, and is idempotent on email (returns the existing row instead of throwing). The quickstart no longer needs a hand-written Drizzle insert into `theauth_users`.
