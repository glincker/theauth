---
title: API Endpoints
description: Full HTTP endpoint reference for TheAuth including agent CRUD, token authorization, delegation chains, audit log queries, and MCP OAuth 2.1 endpoints.
---

# API Endpoints

All REST endpoints are mounted by the framework adapter (Hono, Express, Next.js, etc.). The base path defaults to `/api/kavach` unless you configure a different mount point.

!!! note
    All endpoints require a valid Bearer token unless noted as public. Obtain a token through the MCP OAuth 2.1 flow or by creating an agent with `kavach.agent.create()`.

## Agent endpoints

### Create agent

```
POST /agents
```

Creates a new agent identity.

**Request body**

```json
{
  "ownerId": "user_01abc",
  "name": "GitHub Automation",
  "type": "autonomous",
  "permissions": [
    {
      "resource": "mcp:github:*",
      "actions": ["read", "write"],
      "constraints": {
        "maxCallsPerHour": 100
      }
    }
  ],
  "expiresAt": "2026-12-31T23:59:59Z",
  "metadata": {}
}
```

**Response** `201 Created`

```json
{
  "id": "agt_...",
  "token": "kv_...",
  "name": "GitHub Automation",
  "type": "autonomous",
  "status": "active",
  "permissions": [...],
  "createdAt": "2026-06-01T00:00:00Z"
}
```

The `token` is returned only in this response. It is not recoverable after this point.

### List agents

```
GET /agents?userId=user_01abc&status=active&type=autonomous
```

**Response** `200 OK`

```json
{
  "agents": [...],
  "total": 5
}
```

### Get agent

```
GET /agents/:id
```

### Update agent

```
PATCH /agents/:id
```

Updates `name`, `permissions`, `metadata`, or `expiresAt`. Permission changes take effect immediately.

### Revoke agent

```
DELETE /agents/:id
```

Revocation is permanent.

### Rotate token

```
POST /agents/:id/rotate
```

Issues a new token and invalidates the old one atomically.

**Response** `200 OK`

```json
{
  "token": "kv_..."
}
```

## Authorization endpoints

### Authorize by agent ID

```
POST /authorize
```

**Request body**

```json
{
  "agentId": "agt_...",
  "action": "read",
  "resource": "mcp:github:repos",
  "ip": "1.2.3.4"
}
```

**Response** `200 OK`

```json
{
  "allowed": true,
  "auditId": "aud_..."
}
```

Or if denied:

```json
{
  "allowed": false,
  "reason": "PERMISSION_DENIED",
  "auditId": "aud_..."
}
```

### Authorize by bearer token

```
POST /authorize/token
```

Same as above but accepts the raw bearer token instead of the agent ID. Use this in HTTP middleware where only the token is available.

**Request body**

```json
{
  "token": "kv_...",
  "action": "read",
  "resource": "mcp:github:repos"
}
```

## Delegation endpoints

### Create delegation

```
POST /delegations
```

**Request body**

```json
{
  "fromAgent": "agt_...",
  "toAgent": "agt_...",
  "permissions": [...],
  "expiresAt": "2026-06-01T01:00:00Z",
  "maxDepth": 2
}
```

### List delegations

```
GET /delegations/:agentId
```

Returns all active delegation chains for the given agent (both incoming and outgoing).

### Revoke delegation

```
DELETE /delegations/:id
```

## Audit endpoints

### Query audit log

```
GET /audit?agentId=agt_...&result=denied&since=2026-01-01T00:00:00Z&limit=100
```

### Export audit log

```
GET /audit/export?format=csv&since=2026-01-01T00:00:00Z
```

Supported formats: `json`, `csv`.

## MCP OAuth endpoints

When `mcp` is passed to the adapter, these endpoints are registered in addition to the above:

| Endpoint | RFC | Visibility |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | Public |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | Public |
| `POST /oauth/register` | RFC 7591 | Public |
| `GET /oauth/authorize` | OAuth 2.1 | Public |
| `POST /oauth/token` | OAuth 2.1 | Public |
| `POST /oauth/revoke` | RFC 7009 | Authenticated |

## Related pages

- [Adapters Catalog](adapters.md)
- [Error Codes](errors.md)
- [MCP Authorization](../concepts/mcp-authorization.md)
