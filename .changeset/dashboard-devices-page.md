---
"@glinr/theauth-dashboard": minor
---

New Devices page: fleet health counters from `GET /devices/stats`, a device list you can filter by status (last seen, suspend, resume, revoke), a detail view with credential kinds, and an enrollment token form that shows the plaintext token once.

Fixes:

- The audit client now matches the core `GET /audit` route. It sends `actions`, `since`, `until` and `provenanceKind`, reads the bare array the route returns, resolves agent names from the agent list, and keeps `inputs`. The old client expected `{ entries, total, offset }` and sent parameters the route ignores.
- `PaginatedAuditLogs` has `hasMore` instead of `total`, because the route returns no total. The audit table and Security page were updated to match, and `escalated` rows now render.
- Audit export returns the response body as text. CSV exports used to fail because the client parsed them as JSON.
- Error messages from core error bodies (`{ error: { message } }`) are shown instead of the HTTP status text. Error codes are unchanged.
