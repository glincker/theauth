---
"@glinr/theauth": minor
---

Add `theauth.user.create({ email, name?, id?, metadata? })` and `theauth.user.get(idOrEmail)`. `create` validates the email with zod, lowercases it, and generates an id when none is given. For the same email it returns the existing row unchanged. It throws `UserError` with code `USER_EMAIL_CONFLICT` when the requested id differs from that row's id, and `USER_ID_CONFLICT` when the requested id belongs to another email. Invalid input throws `USER_INVALID_INPUT`. The quickstart no longer needs a hand-written insert into `theauth_users`.
