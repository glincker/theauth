# theauth

Python SDK for [theAuth](https://theauth.dev). Auth OS for AI agents and humans.

[![PyPI](https://img.shields.io/pypi/v/theauth)](https://pypi.org/project/theauth/)
[![Python](https://img.shields.io/pypi/pyversions/theauth)](https://pypi.org/project/theauth/)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../LICENSE)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

---

## Install

```bash
pip install theauth
```

Requires Python 3.9+ and `httpx`.

---

## Quick start

### Async (recommended)

```python
import asyncio
from theauth import TheAuthClient
from theauth.types import CreateAgentInput
from theauth.permissions import read, with_approval, execute

async def main():
    async with TheAuthClient(
        base_url="https://your-app.com/api/theauth",
        token="ta_...",
    ) as client:
        # Create an agent
        agent = await client.agents.create(
            CreateAgentInput(
                owner_id="user-123",
                name="github-reader",
                type="autonomous",
                permissions=[
                    read("mcp:github:*"),
                    with_approval(execute("mcp:deploy:production")),
                ],
            )
        )

        # Check authorization
        result = await client.authorize(
            agent.id,
            AuthorizeRequest(action="read", resource="mcp:github:repos"),
        )
        print(result.allowed)  # True

asyncio.run(main())
```

### Sync

```python
from theauth import TheAuthSyncClient
from theauth.types import CreateAgentInput
from theauth.permissions import read

with TheAuthSyncClient(
    base_url="https://your-app.com/api/theauth",
    token="ta_...",
) as client:
    agent = client.agents.create(
        CreateAgentInput(
            owner_id="user-123",
            name="github-reader",
            type="autonomous",
            permissions=[read("mcp:github:*")],
        )
    )
    print(agent.id, agent.token)
```

---

## Authentication

Sign in and sign up with email and password.

```python
async with TheAuthClient(base_url="https://your-app.com/api/theauth") as client:
    # Sign up
    auth = await client.auth.sign_up(
        email="user@example.com",
        password="secure-password",
        name="Alice",
    )
    print(auth.user.id)
    print(auth.session.token)

    # Sign in later
    auth = await client.auth.sign_in(
        email="user@example.com",
        password="secure-password",
    )

    # Get current session
    session = await client.auth.get_session(token=auth.session.token)

    # Sign out
    await client.auth.sign_out()
```

---

## Agent management

```python
from theauth.types import AgentFilters, UpdateAgentInput

# List agents for a user
agents = await client.agents.list(AgentFilters(user_id="user-123", status="active"))

# Get a single agent (returns None if not found)
agent = await client.agents.get("agent-abc123")

# Update name or permissions
agent = await client.agents.update(
    "agent-abc123",
    UpdateAgentInput(name="better-name"),
)

# Rotate the token (old token is immediately invalidated)
agent = await client.agents.rotate("agent-abc123")
print(agent.token)  # ta_new_...

# Revoke (delete) an agent
await client.agents.revoke("agent-abc123")
```

---

## Authorization

```python
from theauth.types import AuthorizeRequest

# Authorize by agent ID (requires admin/service token on the client)
result = await client.authorize(
    "agent-abc123",
    AuthorizeRequest(
        action="execute",
        resource="mcp:deploy:production",
        arguments={"version": "1.2.3"},
    ),
)
print(result.allowed)   # True / False
print(result.audit_id)  # "aud_..."

# Authorize using the agent's own bearer token (no admin token needed)
result = await client.auth.authorize_by_token(
    agent_token="ta_agent_xyz",
    request=AuthorizeRequest(action="read", resource="mcp:github:repos"),
)
```

---

### Decision codes

A denied call is a result, not an exception: the server answers 403 (401 for a
bad token) and the client returns `allowed=False` with a `code` to branch on.
Scope refusals (`{ error }` bodies) still raise `PermissionError`.

```python
from theauth import is_allowed_code
from theauth.types import AuthorizeRequest

result = await client.agents.authorize(
    agent.id,
    AuthorizeRequest(action="write", resource="db:orders", approval_id=approval_id),
)
if result.code == "approval_required":
    ...  # open an approval, wait for a human, retry with approval_id
print(is_allowed_code(result.code))
```

### Explain

```python
from theauth import ExplainRequest

why = await client.agents.explain(
    ExplainRequest(agent_id=agent.id, action="write", resource="db:orders")
)
print(why.decision, why.code)
print(why.delegation.root_owner_id, why.delegation.path)  # who stands behind the agent
for miss in why.near_misses:
    print(miss.hint)
```

### Approvals

Needs the admin API plugin and an admin user token.

```python
from theauth import ConsumeApprovalInput, OpenApprovalInput

opened = await client.approvals.open(OpenApprovalInput("admin:rotate", "agent:a1"))
pending = await client.approvals.list_pending(limit=20)
await client.approvals.approve(opened.id)
spent = await client.approvals.consume(opened.id, ConsumeApprovalInput("admin:rotate", "agent:a1"))

# A quorum: two distinct approvers, neither of them the requester.
two = await client.approvals.open(
    OpenApprovalInput("admin:rotate", "agent:a1", required_approvals=2)
)
step = await client.approvals.approve(two.id)  # step.status is "pending" until the second approver
```

### Step-up

When an action needs a stronger or fresher sign-in, the server answers 401 with
`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age="..."`
([RFC 9470](https://www.rfc-editor.org/rfc/rfc9470)). The client raises
`StepUpRequiredError`, a subclass of `AuthenticationError`, and the parsed
challenge is on `error.challenge`.

```python
from theauth import StepUpRequiredError

try:
    await client.approvals.approve(approval_id)
except StepUpRequiredError as err:
    params = err.challenge.authorize_params() if err.challenge else {}
    # Send the user through authorization again with acr_values and max_age.
    print(params)  # {"acr_values": "urn:theauth:acr:mfa", "max_age": "300"}
```

`parse_step_up_challenge(header)` reads a header you got some other way,
`step_up_params(acr_values, max_age)` builds the query parameters, and
`acr_satisfies(have, want)` and `auth_is_fresh(auth_time, max_age)` check a
token's `acr` and `auth_time` before you call. The class order is a theAuth rule
(`none`, `single-factor`, `mfa`, `phishing-resistant`); an unknown `acr` never
satisfies another.

### Sender constrained agent tokens

Bind a token to a DPoP key ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449))
or a client certificate ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) with
the `cnf` claim ([RFC 7800](https://www.rfc-editor.org/rfc/rfc7800)). A stolen
token is then useless without the key.

```python
from theauth import DPoPProver, dpop_confirmation
from theauth.dpop import DPoPAuth
from theauth.permissions import read
from theauth.types import CreateAgentInput

prover = DPoPProver()
agent = await client.agents.create(
    CreateAgentInput(
        owner_id="user-123",
        name="reader",
        type="autonomous",
        permissions=[read("mcp:github:*")],
        cnf=dpop_confirmation(prover),
    )
)
bound = TheAuthClient(base_url=BASE, token=agent.token, auth=DPoPAuth(prover))
await client.agents.rotate(agent.id)            # keeps the binding
await client.agents.rotate(agent.id, cnf=None)  # back to a plain bearer token
```

`mtls_confirmation(cert_der)` builds the certificate form. `Agent.cnf` and
`IntrospectionResponse.jkt` or `.x5t_s256` read it back.

### Input provenance

Say what the model had in context when it asked for a call. The server hashes
`content` with its audit key and never stores it.

```python
from theauth import ProvenanceInput
from theauth.types import AuthorizeRequest

await client.agents.authorize(
    agent.id,
    AuthorizeRequest(
        action="execute",
        resource="mcp:github:create_issue",
        inputs=[
            ProvenanceInput("user_message", id="msg_123", content=user_text),
            ProvenanceInput("retrieved_document", id=page_url, content=page_text),
        ],
    ),
)
```

For a proxy that cannot rewrite bodies, `inputs_headers(inputs)` returns the
`TheAuth-Inputs` header (base64url JSON, at most 32 inputs and 8192 characters).

## Devices

`client.devices` is the registry (needs a user or admin token) and `client.device`
is what a device calls as itself.

```python
from theauth import (
    CredentialSpec, DeviceAssertionSigner, EnrollDeviceInput,
    EnrollmentTokenInput, RegisterDeviceInput,
)
from theauth.types import AuthorizeRequest, Permission

# Admin: register a device that signs its own assertions. The key comes first,
# the id only exists after registering, so bind it afterwards.
signer = DeviceAssertionSigner()
reg = await client.devices.register(
    RegisterDeviceInput(
        owner_id="user-123",
        name="Pump 4",
        permissions=[Permission("mqtt:plant/a/pump4/#", ["publish"])],
        credential=CredentialSpec.from_jwk(signer.public_jwk),
    )
)
signer.bind(reg.device.id)

# Admin: a bulk token for a factory run, then the device enrolls itself.
token = await client.devices.create_enrollment_token(
    EnrollmentTokenInput("user-123", "bulk", max_uses=50, ttl_seconds=86400)
)
enrolled = await client.device.enroll(
    EnrollDeviceInput(token.token, "Pump 5", CredentialSpec.psk(), hardware_id="hw-77")
)
psk = enrolled.credential.secret  # shown once

# Device: check an action with the PSK or a signed assertion.
result = await client.device.authorize(psk, AuthorizeRequest("publish", "mqtt:plant/a/pump4/temp"))
await client.devices.suspend(reg.device.id, "stolen")
```

`DeviceAssertionSigner` builds the `device-assertion+jwt` the server verifies
(ES256, a fresh `jti` each time, `aud` `theauth`, lifetime up to 300 seconds).
Pass it, a PSK string or a ready JWT as the credential of `device.authorize` and
`device.bundle`. A signer signs a new assertion on every call, which the server's
one time `jti` rule needs. `devices.issue_bundle` and `device.bundle` return the
signed offline policy bundle for devices that cannot call home. A private JWK is
refused by `CredentialSpec.from_jwk` before it leaves the process.

### SPIFFE

With `devices.spiffe` set on the server, the admin calls cover the four SPIFFE routes:

```python
from theauth import SpiffePresentation

check = await client.devices.spiffe_verify(SpiffePresentation.x509(chain_pem))  # mints nothing
cred = await client.devices.link_spiffe(device_id, spiffe_id="spiffe://example.org/ns/prod/sa/pump")
issued = await client.devices.spiffe_token(chain_pem)  # token bound to the certificate (RFC 8705)

# Device side, with a JWT-SVID. A refused SVID raises AuthenticationError, code is the failure code.
me = await client.device.spiffe_verify(jwt_svid)
```

A failed admin check is a result (`check.ok` false, `check.code` says why), not an exception.
A mapping owned by another user reads as `unknown_workload`. An X.509-SVID cannot go to
`device.spiffe_verify`: the server takes it from the TLS handshake, never from the body.

## Framework guards

`theauth.integrations` checks `authorize` before a tool runs and fails closed. It covers LangGraph (`guard_tool`, `guard_node`), CrewAI (`guard`, `guard_crewai_tool`), the OpenAI Agents SDK (`guard_function_tool`) and any function (`guard`). The frameworks are never imported by `theauth`.

```python
from theauth import TheAuthSyncClient
from theauth.integrations import Gate, guard

client = TheAuthSyncClient(base_url="https://YOUR_HOST/api/auth", timeout=5)
gate = Gate.from_token(client, "ta_...")


@guard(gate, "refund")
def refund(order_id: str, amount: float) -> dict:
    return {"order_id": order_id, "refunded": amount}
```

A refused call returns `{"ok": False, "denied": True, "toolName", "code", "reason", "approvalRequired", "auditId"}`. See the LangGraph and CrewAI page in the docs for each framework and for the approval wait.

## Permissions helpers

The `theauth.permissions` module provides shorthand constructors.

```python
from theauth.permissions import (
    read,
    write,
    execute,
    read_write,
    full_access,
    with_approval,
    rate_limited,
)
from theauth.types import PermissionConstraints

# Simple read permission
perm = read("mcp:github:*")

# Require human approval before execution
perm = with_approval(execute("mcp:deploy:production"))

# Limit to 100 calls per hour
perm = rate_limited(read("mcp:github:*"), max_calls_per_hour=100)

# Full manual construction
from theauth.types import Permission
perm = Permission(
    resource="mcp:github:*",
    actions=["read", "write"],
    constraints=PermissionConstraints(
        max_calls_per_hour=200,
        ip_allowlist=["10.0.0.0/8"],
    ),
)
```

---

## Audit log

```python
from theauth.types import AuditFilters, ExportOptions

# Query the audit log
entries = await client.audit.query(
    AuditFilters(
        agent_id="agent-abc123",
        result="allowed",
        limit=50,
    )
)
for entry in entries:
    print(entry.timestamp, entry.action, entry.resource, entry.result)

# Paginated response (includes total count)
page = await client.audit.query_paginated(AuditFilters(limit=20, offset=0))
print(f"{len(page.entries)} of {page.total}")

# Export as JSON or CSV
csv_text = await client.audit.export(
    ExportOptions(
        format="csv",
        since="2024-01-01T00:00:00Z",
    )
)
```

---

## Delegation

Delegate a subset of an agent's permissions to another agent, with an optional
depth limit.

```python
from theauth.types import DelegateInput
from theauth.permissions import read

# Create a delegation
chain = await client.delegation.create(
    DelegateInput(
        from_agent="agent-abc123",
        to_agent="agent-def456",
        permissions=[read("mcp:github:repos")],
        expires_at="2025-12-31T00:00:00Z",
        max_depth=2,
    )
)

# List all chains for an agent
chains = await client.delegation.list_chains("agent-abc123")

# Get the effective (merged) permissions for an agent
perms = await client.delegation.get_effective_permissions("agent-def456")

# Revoke a delegation
await client.delegation.revoke(chain.id)
```

---

## MCP servers

```python
from theauth.types import RegisterMcpServerInput

server = await client.mcp.register(
    RegisterMcpServerInput(
        name="github-mcp",
        endpoint="https://mcp.github.com",
        tools=["read_file", "list_repos"],
        rate_limit_rpm=60,
    )
)
servers = await client.mcp.list()
server = await client.mcp.get(server.id)  # None if not found
```

---

### Token introspection

```python
from theauth import IntrospectInput

info = await client.mcp.introspect(
    IntrospectInput(token=access_token, client_id="rs-1", client_secret="...")
)
print(info.active, info.agent_id, info.delegation, info.inactive_reason)
```

The request and response shapes follow [`sdks/openapi.json`](../openapi.json),
which is generated from the server's route table. `tests/test_parity.py` checks
that the routes these calls use exist in that document.

## Plugin routes

`request()` calls any route, including plugin endpoints declared with `defineEndpoint`.
Query params with `None` values are dropped. A failed validation raises `ValidationError`.

```python
from theauth import ValidationError

try:
    out = await client.request(
        "POST", "/auth/team/invite", json={"email": "a@b.c"}, params={"dry_run": True}
    )
except ValidationError as e:
    for issue in e.issues or []:
        print(issue["path"], issue["message"])
```

A 403 `CSRF_REJECTED` raises `PermissionError` and a 429 `RATE_LIMITED` raises
`RateLimitError`; check `e.code` to tell them apart from other 403s.

---

## DPoP (RFC 9449)

Install the optional extra: `pip install "theauth[dpop]"` (needs `cryptography`).

```python
from theauth import TheAuthSyncClient
from theauth.dpop import DPoPAuth

auth = DPoPAuth()            # generates an ES256 key pair
print(auth.thumbprint())     # jkt to bind tokens to

with TheAuthSyncClient(base_url="https://your-app.com/api/theauth", token="at_...", auth=auth) as client:
    client.agents.list()
```

Each request carries a `DPoP` proof and `Authorization: DPoP <token>` with an `ath`
claim. The server `DPoP-Nonce` is cached per origin and a `use_dpop_nonce` challenge
is retried once. `DPoPAuth` is a plain `httpx.Auth`, so it also works with your own
`httpx.Client` or `httpx.AsyncClient`. Use `DPoPProver` directly to build proofs by hand.

---

## Error handling

All exceptions inherit from `theauth.TheAuthError`.

```python
from theauth.errors import (
    TheAuthError,
    AuthenticationError,  # 401
    PermissionError,       # 403
    NotFoundError,         # 404
    RateLimitError,        # 429, has .retry_after
    ServerError,           # 5xx
    NetworkError,          # Transport failure
    ValidationError,       # 400/422 with .issues (plugin endpoint input)
)

try:
    agent = await client.agents.get("agent-missing")
except NotFoundError:
    print("Agent does not exist")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except AuthenticationError:
    print("Check your token")
except TheAuthError as e:
    print(f"[{e.code}] {e.message} (HTTP {e.status_code})")
```

---

## Configuration

```python
TheAuthClient(
    base_url="https://your-app.com/api/theauth",  # required
    token="ta_...",                               # optional bearer token
    headers={"X-Tenant": "acme"},                # extra headers on every request
    timeout=30.0,                                 # seconds (default 30)
    auth=None,                                    # optional httpx.Auth, e.g. DPoPAuth()
)
```

---

## License

MIT
