---
"@glinr/theauth-cli": minor
"@glinr/theauth-dashboard": minor
---

The dashboard no longer keeps its secret in `sessionStorage`. `POST /api/dashboard/auth` with the secret sets an HttpOnly, SameSite=Strict session cookie that lasts eight hours, `GET` reports whether it is valid and `DELETE` signs out.
