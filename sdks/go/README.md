# theauth-go

Go client for [TheAuth](https://github.com/glincker/theauth). Auth OS for AI agents and humans.

Agent identity, permissions, delegation chains, audit logs, and human authentication over a single typed API.

## Install

```bash
go get github.com/glincker/theauth-go
```

Requires Go 1.21+. No external dependencies.

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "time"

    theauth "github.com/glincker/theauth-go"
)

func main() {
    client := theauth.NewClient("https://your-app.com/api/kavach",
        theauth.WithToken("kv_..."),
        theauth.WithTimeout(10*time.Second),
    )

    ctx := context.Background()

    agent, err := client.Agents.Create(ctx, theauth.CreateAgentInput{
        OwnerID: "user-123",
        Name:    "github-reader",
        Type:    theauth.AgentTypeAutonomous,
        Permissions: []theauth.Permission{
            {Resource: "mcp:github:*", Actions: []string{"read"}},
        },
    })
    if err != nil {
        panic(err)
    }

    result, err := client.Authorize(ctx, agent.ID, theauth.AuthorizeRequest{
        Action:   "read",
        Resource: "mcp:github:repos",
    })
    if err != nil {
        panic(err)
    }

    fmt.Printf("allowed=%v auditId=%s\n", result.Allowed, result.AuditID)
}
```

## Configuration

```go
client := theauth.NewClient(baseURL,
    theauth.WithToken("kv_..."),          // bearer token for every request
    theauth.WithTimeout(10*time.Second),  // HTTP timeout (default 30s)
    theauth.WithHeader("X-Tenant", "acme"), // extra header on every request
    theauth.WithHTTPClient(customHTTPClient), // bring your own http.Client
)
```

## Agents

```go
// Create
agent, err := client.Agents.Create(ctx, theauth.CreateAgentInput{
    OwnerID: "user-123",
    Name:    "data-pipeline",
    Type:    theauth.AgentTypeService,
    Permissions: []theauth.Permission{
        {
            Resource: "mcp:s3:my-bucket/*",
            Actions:  []string{"read", "write"},
            Constraints: &theauth.PermissionConstraints{
                MaxCallsPerHour: ptr(1000),
            },
        },
    },
    ExpiresAt: ptr("2025-12-31T23:59:59Z"),
})

// List (with optional filters)
status := theauth.AgentStatusActive
agents, err := client.Agents.List(ctx, &theauth.AgentFilters{
    Status: &status,
})

// Get (returns nil, nil when not found)
agent, err := client.Agents.Get(ctx, "agent-id")

// Update
agent, err := client.Agents.Update(ctx, "agent-id", theauth.UpdateAgentInput{
    Name: ptr("new-name"),
})

// Rotate token
agent, err := client.Agents.Rotate(ctx, "agent-id")

// Revoke
err = client.Agents.Revoke(ctx, "agent-id")

// Authorize
result, err := client.Agents.Authorize(ctx, "agent-id", theauth.AuthorizeRequest{
    Action:   "read",
    Resource: "mcp:github:repos",
})
// result.Allowed bool
// result.AuditID string

// Effective permissions (own + delegated)
perms, err := client.Agents.GetEffectivePermissions(ctx, "agent-id")
```

## Auth (human users)

```go
// Sign in
resp, err := client.Auth.SignIn(ctx, "user@example.com", "password")
// resp.User   theauth.User
// resp.Session theauth.Session (contains Token)

// Sign up (name is optional, pass "" to omit)
resp, err := client.Auth.SignUp(ctx, "user@example.com", "password", "Alice")

// Sign out (pass "" to use the client's default token)
err = client.Auth.SignOut(ctx, resp.Session.Token)

// Get session (returns nil, nil when expired or missing)
session, err := client.Auth.GetSession(ctx, "tok_...")

// Authorize by agent token (when you have the raw token, not the ID)
result, err := client.Auth.AuthorizeByToken(ctx, "kv_agent_token", theauth.AuthorizeRequest{
    Action:   "execute",
    Resource: "mcp:deploy:production",
})
```

## Audit

```go
// Query (returns entries, newest first)
entries, err := client.Audit.Query(ctx, &theauth.AuditFilters{
    AgentID: ptr("agent-id"),
    Since:   ptr("2024-01-01T00:00:00Z"),
    Limit:   ptr(50),
})

// Query paginated (includes total count)
result, err := client.Audit.QueryPaginated(ctx, &theauth.AuditFilters{
    Limit:  ptr(20),
    Offset: ptr(40),
})
// result.Entries []AuditEntry
// result.Total   *int

// Export as JSON or CSV
csv, err := client.Audit.Export(ctx, &theauth.ExportOptions{
    Format: theauth.ExportFormatCSV,
    Since:  ptr("2024-01-01T00:00:00Z"),
})
```

## Delegation

```go
// Create a delegation
chain, err := client.Delegation.Create(ctx, theauth.DelegateInput{
    FromAgent: "agent-orchestrator",
    ToAgent:   "agent-worker",
    Permissions: []theauth.Permission{
        {Resource: "mcp:github:*", Actions: []string{"read"}},
    },
    ExpiresAt: "2025-06-01T00:00:00Z",
    MaxDepth:  ptr(2),
})

// List chains for an agent
chains, err := client.Delegation.ListChains(ctx, "agent-worker")

// Revoke a delegation
err = client.Delegation.Revoke(ctx, "delegation-id")

// Effective permissions (merged own + all delegated)
perms, err := client.Delegation.GetEffectivePermissions(ctx, "agent-worker")
```

## Error handling

All API errors implement the `error` interface and can be type-checked:

```go
agent, err := client.Agents.Get(ctx, id)
if err != nil {
    switch {
    case theauth.IsNotFound(err):
        // 404 - resource doesn't exist
    case theauth.IsAuthentication(err):
        // 401 - invalid or missing token
    case theauth.IsPermission(err):
        // 403 - insufficient permissions
    case theauth.IsRateLimit(err):
        rl := err.(*theauth.ErrRateLimit)
        if rl.RetryAfter != nil {
            time.Sleep(time.Duration(*rl.RetryAfter) * time.Second)
        }
    case theauth.IsServer(err):
        // 5xx - server-side error
    default:
        // network error or unexpected
    }
}
```

All error types embed `KavachError` which exposes `.Code`, `.Message`, `.StatusCode`, and `.Details`.

## Types reference

| Type | Description |
|------|-------------|
| `Agent` | Agent identity with token, permissions, status |
| `Permission` | Resource pattern + allowed actions + optional constraints |
| `PermissionConstraints` | Rate limits, time windows, IP allowlists, approval gates |
| `DelegationChain` | Delegation link between two agents |
| `AuditEntry` | Immutable audit record |
| `PaginatedAuditLogs` | Audit entries + total count |
| `AuthResponse` | User + session returned by sign-in/sign-up |
| `User` | Human user account |
| `Session` | Active session token |
| `AuthorizeResult` | `Allowed bool` + `AuditID string` |

## License

MIT
