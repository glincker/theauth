# theauth-go

Go client for [theAuth](https://github.com/glincker/theauth). Auth OS for AI agents and humans.

Agent identity, permissions, delegation chains, audit logs, and human authentication over a single typed API.

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
go get github.com/glincker/theauth-go
```

Requires Go 1.21+. No external dependencies.

This is the REST client for the TypeScript server. The Go server library (v2) is a separate project, [theauth-go](https://github.com/glincker/theauth-go).

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
    client := theauth.NewClient("https://your-app.com/api/theauth",
        theauth.WithToken("ta_..."),
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
    theauth.WithToken("ta_..."),          // bearer token for every request
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
// result.Code    theauth.DecisionCode, for example theauth.DecisionNoPermission

// Effective permissions (own + delegated)
perms, err := client.Agents.GetEffectivePermissions(ctx, "agent-id")
```

## Decisions, explain, approvals and introspection

A denied call is a result, not an error: the server answers 403 (401 for a bad
token), and the client returns `Allowed: false` with a `Code` to branch on.

```go
result, err := client.Agents.Authorize(ctx, "agent-id", theauth.AuthorizeRequest{
    Action: "write", Resource: "db:orders",
})
if err == nil && result.Code == theauth.DecisionApprovalRequired {
    // open an approval, wait for a human, then retry with ApprovalID set
}

// Explain: the decision, the delegation chain behind the agent, constraint
// checks and the closest grants that did not match. Nothing is audited.
why, err := client.Agents.Explain(ctx, theauth.ExplainRequest{
    AgentID: "agent-id", Action: "write", Resource: "db:orders",
})
// why.Delegation.RootOwnerID, why.Delegation.Path, why.NearMisses[0].Hint

// Approvals (admin API plugin, admin user token)
opened, err := client.Approvals.Open(ctx, theauth.OpenApprovalInput{Action: "admin:rotate", Resource: "agent:a1"})
decision, err := client.Approvals.Approve(ctx, opened.ID)
// A quorum: two distinct approvers. decision.Status stays ApprovalPending until the second one.
two, err := client.Approvals.Open(ctx, theauth.OpenApprovalInput{Action: "admin:rotate", Resource: "agent:a1", RequiredApprovals: 2})
spent, err := client.Approvals.Consume(ctx, opened.ID, theauth.ConsumeApprovalInput{Action: "admin:rotate", Resource: "agent:a1"})

// Token introspection (RFC 7662), authenticated as an OAuth client
info, err := client.MCP.Introspect(ctx, theauth.IntrospectInput{
    Token: accessToken, ClientID: "rs-1", ClientSecret: "...",
})
// info.Active, info.AgentID, info.Delegation.Agt, info.InactiveReason
```

The request and response shapes follow [`sdks/openapi.json`](../openapi.json),
which is generated from the server's route table. A test in this module checks
that the routes these calls use exist in that document.

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
result, err := client.Auth.AuthorizeByToken(ctx, "ta_agent_token", theauth.AuthorizeRequest{
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

## MCP servers

```go
srv, err := client.MCP.Register(ctx, theauth.RegisterMcpServerInput{
    Name:         "github",
    Endpoint:     "https://mcp.example.com",
    Tools:        []string{"read_repo"},
    AuthRequired: true,
    RateLimitRPM: ptr(60),
})

servers, err := client.MCP.List(ctx)

// Get returns nil, nil when not found
srv, err = client.MCP.Get(ctx, "server-id")
```

## Plugin endpoints

Call routes declared with `defineEndpoint` on the TypeScript server. `:name` path segments are filled from `Params`.

```go
var out struct{ ID string `json:"id"` }
err := client.Request(ctx, theauth.RequestOptions{
    Method: "POST",
    Path:   "/auth/team/:teamId/invite",
    Params: map[string]string{"teamId": "t1"},
    Body:   map[string]string{"email": "a@b.c"},
}, &out)

// Shorthand without path params
err = client.Do(ctx, "GET", "/auth/team/list", map[string]string{"limit": "10"}, nil, &out)
```

Validation failures return a `*theauth.TheAuthError` with the server's `Issues`. Use `theauth.ValidationIssues(err)` to read them from any error type.

## DPoP (RFC 9449)

```go
prover, err := theauth.NewDPoPProver() // generates an ES256 (P-256) key
client.UseDPoP(prover)                 // wraps the client's HTTP transport

// Or on your own http.Client (copied, not mutated)
hc := theauth.DPoPHTTPClient(http.DefaultClient, prover, theauth.WithDPoPAccessToken("tok"))

jkt := prover.Thumbprint() // cnf.jkt value
```

Each request carries a `DPoP` proof (`htm`, `htu` without query or fragment, `iat`, `jti`, and `ath` when a token is sent). A Bearer token becomes `Authorization: DPoP <token>`. The server `DPoP-Nonce` is cached per origin and a `use_dpop_nonce` challenge is retried once. Reuse a key with `WithDPoPKey`.

## Step-up (RFC 9470)

A resource that needs a stronger or fresher sign-in answers 401 with
`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age="..."`.
The client returns `*theauth.ErrStepUpRequired` (`IsAuthentication` is also true for it) with the parsed challenge.

```go
_, err := client.Approvals.Approve(ctx, approvalID)
var su *theauth.ErrStepUpRequired
if errors.As(err, &su) && su.Challenge != nil {
    params := su.Challenge.AuthorizeParams() // acr_values and max_age
    // Send the user through authorization again with these query parameters.
    fmt.Println(params)
}
```

`ParseStepUpChallenge(resp.Header.Values("WWW-Authenticate")...)` reads a header you got some other way. `StepUpParams`, `ACRSatisfies(have, want...)` and `AuthIsFresh(authTime, maxAge, now, skew)` cover the rest. The class order is a theAuth rule (`ACRNone`, `ACRSingleFactor`, `ACRMFA`, `ACRPhishingResistant`); an unknown acr never satisfies another.

## Sender constrained agent tokens

Bind a token to a DPoP key (RFC 9449) or a client certificate (RFC 8705) with the `cnf` claim (RFC 7800).

```go
prover, _ := theauth.NewDPoPProver()
agent, err := client.Agents.Create(ctx, theauth.CreateAgentInput{
    OwnerID: "user-123",
    Name:    "reader",
    Type:    theauth.AgentTypeAutonomous,
    Permissions: []theauth.Permission{{Resource: "mcp:github:*", Actions: []string{"read"}}},
    Cnf:     theauth.DPoPConfirmation(prover),
})

bound := theauth.NewClient(baseURL, theauth.WithToken(agent.Token))
bound.UseDPoP(prover)

client.Agents.Rotate(ctx, agent.ID)                                            // keeps the binding
client.Agents.RotateWith(ctx, agent.ID, theauth.RotateOptions{Unbind: true})   // plain bearer again
```

`MTLSConfirmation(certDER)` builds the certificate form. `Agent.Cnf` and `IntrospectionResponse.Cnf` read it back.

## Input provenance

Say what the model had in context when it asked for a call. The server hashes `Content` with its audit key and never stores it.

```go
res, err := client.Agents.Authorize(ctx, agent.ID, theauth.AuthorizeRequest{
    Action:   "execute",
    Resource: "mcp:github:create_issue",
    Inputs: []theauth.ProvenanceInput{
        {Kind: theauth.ProvenanceUserMessage, ID: "msg_123", Content: userText},
        {Kind: theauth.ProvenanceRetrievedDocument, ID: pageURL, Content: pageText},
    },
})
```

For a proxy that cannot rewrite bodies, `EncodeInputsHeader(inputs)` returns the value for the `TheAuth-Inputs` header (base64url JSON, at most 32 inputs and 8192 characters).

## Devices

`client.Devices` is the registry (needs a user or admin token). `client.Device` is what a device calls as itself.

```go
// Admin: register a device that signs its own assertions. The key comes first,
// the id only exists after registering, so bind it afterwards.
signer, _ := theauth.NewDeviceAssertionSigner("")
spec, _ := theauth.JWKCredential(signer.PublicJWK())
reg, err := client.Devices.Register(ctx, theauth.RegisterDeviceInput{
    OwnerID:     "user-123",
    Name:        "Pump 4",
    Permissions: []theauth.Permission{{Resource: "mqtt:plant/a/pump4/#", Actions: []string{"publish"}}},
    Credential:  &spec,
})
_ = signer.Bind(reg.Device.ID)

// Device: check an action. The signer makes a new assertion for every call.
res, err := client.Device.Authorize(ctx, signer, theauth.AuthorizeRequest{
    Action: "publish", Resource: "mqtt:plant/a/pump4/temp",
})

// Admin: a bulk token for a factory run. The device enrolls itself with it.
maxUses, ttl := 50, 86400
tok, _ := client.Devices.CreateEnrollmentToken(ctx, theauth.EnrollmentTokenInput{
    OwnerID: "user-123", Kind: theauth.EnrollmentBulk, MaxUses: &maxUses, TTLSeconds: &ttl,
})
enrolled, _ := client.Device.Enroll(ctx, theauth.EnrollDeviceInput{
    Token: tok.Token, Name: "Pump 5", Credential: theauth.PSKCredential(),
})
psk := theauth.DevicePSK(enrolled.Credential.Secret) // shown once

_, _ = client.Devices.Suspend(ctx, reg.Device.ID, "stolen")
```

`DeviceAssertionSigner` builds the `device-assertion+jwt` the server verifies (ES256, a fresh `jti` each time, `aud` `theauth`, lifetime up to 300 seconds). Pass it, a `DevicePSK` or a `DeviceToken` as the credential of `Device.Authorize` and `Device.Bundle`. A signer signs a new assertion on every call, which the server's one time `jti` rule needs. `Devices.IssueBundle` and `Device.Bundle` return the signed offline policy bundle for devices that cannot call home. `JWKCredential` refuses a private JWK before it leaves the process.

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
    case theauth.IsCSRFRejected(err):
        // 403 with code CSRF_REJECTED
    case theauth.IsServer(err):
        // 5xx - server-side error
    default:
        // network error or unexpected
    }
}
```

All error types embed `TheAuthError` which exposes `.Code`, `.Message`, `.StatusCode`, `.Details`, and `.Issues` (validation issues from plugin endpoints). `theauth.IsRateLimited(err)` returns the `Retry-After` seconds.

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
| `McpServer` | Registered MCP server |
| `DPoPProver` | ES256 key holder that builds DPoP proofs |

## License

MIT
