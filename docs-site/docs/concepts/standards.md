---
title: Standards Alignment
description: Which IETF drafts TheAuth maps to, and how to emit the matching claims on issued tokens.
---

# Standards Alignment

TheAuth tracks two emerging IETF drafts for agent authorization:

- `draft-goswami-agentic-jwt-00` (agentic JWT claims)
- `draft-liu-agent-operation-authorization-01` (three-layer user-workload-token binding)

Claim names are defined in a single file so future audits are a one-file review.

## The claim constants

Every claim name lives in `packages/core/src/standards/claims.ts` as `AGENTIC_JWT_CLAIMS`. Each constant has a JSDoc reference to the relevant draft section.

```ts
import { AGENTIC_JWT_CLAIMS } from "@glinr/theauth/standards";

AGENTIC_JWT_CLAIMS.AGENT_ID;         // "agent_id"
AGENTIC_JWT_CLAIMS.AGENT_TYPE;       // "agent_type"
AGENTIC_JWT_CLAIMS.ON_BEHALF_OF;     // "on_behalf_of"
AGENTIC_JWT_CLAIMS.ACT;              // "act"
AGENTIC_JWT_CLAIMS.MAY_ACT;          // "may_act"
AGENTIC_JWT_CLAIMS.TRUST_TIER;       // "trust_tier"
AGENTIC_JWT_CLAIMS.AUDIT_REF;        // "audit_ref"
AGENTIC_JWT_CLAIMS.TOOL_CONSTRAINTS; // "tool_constraints"
AGENTIC_JWT_CLAIMS.WORKLOAD_BINDING; // "wit"
AGENTIC_JWT_CLAIMS.OPERATION;        // "operation"
```

## Turning claim emission on

Claim emission is off by default. Flip the `emitAgenticJwtClaims` flag on your config to start populating claims on issued JWTs:

```ts
import { createTheAuth } from "@glinr/theauth";

const kavach = createTheAuth({
  database: { url: process.env.DATABASE_URL },
  secret: process.env.THEAUTH_SECRET,
  emitAgenticJwtClaims: true,
});
```

## Claim mapping

| Claim | Draft | Description |
|---|---|---|
| `agent_id` | draft-goswami-agentic-jwt-00 | Stable `agt_` prefixed identifier |
| `agent_type` | draft-goswami-agentic-jwt-00 | `autonomous`, `delegated`, or `service` |
| `on_behalf_of` | draft-goswami-agentic-jwt-00 | User ID the agent acts for |
| `act` | RFC 8693 | Identity switching (delegation) |
| `may_act` | RFC 8693 | Permitted delegation targets |
| `trust_tier` | draft-goswami-agentic-jwt-00 | Trust level at issuance time |
| `audit_ref` | draft-goswami-agentic-jwt-00 | `aud_` prefixed audit entry |
| `tool_constraints` | draft-goswami-agentic-jwt-00 | Encoded permission constraints |
| `wit` | draft-liu-agent-operation-authorization-01 | Workload identity token binding |
| `operation` | draft-liu-agent-operation-authorization-01 | The operation being authorized |

## MCP OAuth 2.1 RFCs

In addition to the agentic drafts, the MCP authorization server tracks:

| RFC | Topic |
|---|---|
| OAuth 2.1 | Base authorization framework |
| RFC 8414 | Authorization Server Metadata |
| RFC 9728 | Protected Resource Metadata |
| RFC 7591 | Dynamic Client Registration |
| RFC 8707 | Resource Indicators |
| RFC 7009 | Token Revocation |

!!! info "CIMD"
    Client Identity and Metadata Discovery (CIMD) alignment is under evaluation for a future release.

## Related pages

- [MCP Authorization](mcp-authorization.md)
- [Configuration](../reference/configuration.md)
