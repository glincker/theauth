---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add `supabase` and `workos` sources to the user importer and `theauth migrate`. Supabase reads `auth.users` rows (JSON or CSV, with optional `auth.identities`) and keeps bcrypt `encrypted_password` hashes for lazy migration. WorkOS reads List users API output and accepts an optional support-provided hash file, because the API returns no hashes. New guides: `migrate/from-supabase` and `migrate/from-workos`.
