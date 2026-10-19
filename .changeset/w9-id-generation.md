---
"@glinr/theauth": minor
---

Add `advanced.database.generateId` to choose how user, session and OAuth account ids are made: `"uuid"` (default), `"uuidv7"` (time ordered, RFC 9562, monotonic within a millisecond) or `({ model }) => string`. Results are validated (1 to 191 characters, `A-Z a-z 0-9 _ - .`). Database generated ids (`false`, `"serial"`) throw `THEAUTH_ID_UNSUPPORTED` because every table stores and references ids as text. Exports `generateUuidV7` and `IdGenerationError`.

Also: the Google One Tap plugin now builds its session manager with the configured `databaseHooks`, so session hooks run for One Tap sign in.
