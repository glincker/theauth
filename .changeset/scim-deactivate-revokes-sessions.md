---
"@glinr/theauth": patch
---

SCIM user deactivation (PUT or PATCH with `active=false`) and DELETE now delete the user's sessions. Previously the user was banned but kept live sessions.
