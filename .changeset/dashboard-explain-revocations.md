---
"@glinr/theauth-dashboard": minor
"@glinr/theauth": minor
---

The dashboard gains an Explain page and a Revocations page, and the approvals inbox now says so when the approvals API is not mounted.

Explain takes an agent id, action and resource and calls `POST /explain`, showing the decision code, the matched grant, constraint steps and the closest grants that nearly matched. Revocations shows the live `theauth_mcp_revocations` rows, the revocation bus counters, every live delegation link with the links and tokens a revoke would deny, and a revoke action for delegations, agents, users, clients and tokens. Every revoke is written to the audit log.

Core `adminApi` adds `GET /revocations`, `GET /revocations/delegations` and `POST /revocations`. Security fix: `DELETE /delegations/:id` on the admin API now pushes the revoked links to the instance revocation bus. Before, only the chain rows changed, so MCP tokens tied to a revoked delegation stayed valid on other instances until they expired.

Upgrade notes: mount the admin API at `/api` for the dashboard to reach the new routes. A core without them answers 404 and the page shows a short notice instead of failing.
