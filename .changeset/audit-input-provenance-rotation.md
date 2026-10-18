---
"@glinr/theauth": minor
---

Audit input provenance and rotating pseudonyms.

- `authorize`, `authorizeByToken` and `policy.evaluate` record where a call's inputs came from. Pass `context.inputs` with kinds `user_message`, `tool_output`, `retrieved_document` or `agent`, an optional id and the content (hashed and dropped) or a SHA-256. Only the hash is stored in `input_provenance`, merged with taint labels. `guardTool` takes the same list as an `inputs` option.
- The argument name `inputProvenance` is now reserved in audit parameters, so tool arguments cannot plant a source.
- `audit.query` takes `provenance: { kind?, hash? }`. `hashInputContent` computes the hash to look for.
- New `audit.pseudonymRotation: { periodDays, retainPeriods? }` gives each subject a different pseudonym per period under a random per-period secret. Old period secrets are shredded, so a key holder cannot link a subject across periods. Chain verification and export keep working, and raw ids in a shredded period are no longer checked against their pseudonym.
