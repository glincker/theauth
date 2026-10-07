# SCIM + Okta example

A minimal SCIM 2.0 server you can point Okta at. No fake data, no stubs, run it, hand Okta the bearer, watch provisioning work.

## Run it

```bash
export SCIM_TOKEN=$(openssl rand -hex 32)
export SCIM_AGENT_ID=agent-scim-provisioner   # optional, defaults to this
pnpm install
pnpm --filter @glinr/theauth-example-scim-okta start
```

First boot creates `theauth.db`, but not the schema. Create the tables first the way `examples/hono-server` does. You still need to seed the audit agent so every provisioning write has a caller attached:

```bash
# one-shot seed (via sqlite3 cli)
sqlite3 theauth.db "
INSERT INTO theauth_users(id, email, name, created_at, updated_at)
VALUES ('sys-owner', 'system@example.com', 'System', strftime('%s','now'), strftime('%s','now'));
INSERT INTO theauth_agents(id, owner_id, name, type, status, token_hash, token_prefix, created_at, updated_at)
VALUES ('agent-scim-provisioner', 'sys-owner', 'scim-provisioner', 'service', 'active', 'placeholder', 'kv_sys', strftime('%s','now'), strftime('%s','now'));
"
```

Smoke test:

```bash
curl -s -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:3000/scim/v2/ServiceProviderConfig | jq .
```

## Okta side

In Okta Admin, then Applications, your SCIM-enabled app, Provisioning, Integration:

| Field | Value |
|-|-|
| SCIM connector base URL | `https://your-host/scim/v2` |
| Unique identifier field for users | `userName` |
| Supported provisioning actions | Push New Users, Push Profile Updates, Push Groups |
| Authentication Mode | HTTP Header |
| HTTP Header, Authorization | `Bearer $SCIM_TOKEN` |

Test Connector Configuration should come back green. If Okta complains about `/Schemas` or filter support, look at the troubleshooting section below.

## What's supported

- `GET /ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`, `/Me`
- `GET/POST/PUT/PATCH/DELETE /Users`
- `GET/POST/PUT/PATCH/DELETE /Groups`
- Full RFC 7644 filter grammar (eq, ne, co, sw, ew, gt, ge, lt, le, pr, and, or, not, parens, value-path)
- PATCH path expressions including `emails[type eq "work"].value`
- Sort via `sortBy` + `sortOrder`
- Enterprise User extension (`employeeNumber`, `department`, `manager`, ...)
- Audit log row on every successful provisioning write
- `/Bulk` returns a spec-correct 501

Not supported (yet):

- Bulk operations (intentional, returns 501)
- ETag / conditional requests
- Groups PATCH with value-filter member ops (routes through the legacy handler)

## Common Okta test suite queries

The Okta SCIM test suite probes these filter shapes. All of them work here:

```
userName eq "jdoe"
userName eq "jdoe" and active eq true
emails[type eq "work" and value ew "@acme.com"]
meta.lastModified gt "2024-01-01T00:00:00Z"
```

## Troubleshooting

- `401 Unauthorized`: check the `Authorization` header is exactly `Bearer <token>`, no extra whitespace, token matches `SCIM_TOKEN`.
- `400 invalidFilter`: the filter parser rejected the syntax. Copy the filter into the curl repro and check the detail field. Grammar is at the [filter reference](https://docs.theauth.dev/auth/scim-filter-reference).
- `400 mutability`: tried to PATCH an immutable field like `id`, `meta.created`, or `externalId`. Remove that op.
- `413 tooMany`: PATCH payload has more than 1000 ops. Split into smaller batches.
- `501` on `/Me`: you didn't pass `resolveSelf` in the config. That endpoint is opt-in.
- No audit rows appearing: check the `SCIM_AGENT_ID` actually exists in `theauth_agents`. The audit write is best-effort and swallows FK failures so the SCIM call still succeeds.
