"""TheAuth Python SDK.

Auth OS for AI agents and humans. Wraps the TheAuth REST API with a clean,
typed Python interface.

Quickstart (async)::

    import asyncio
    from theauth import TheAuthClient
    from theauth.types import CreateAgentInput
    from theauth.permissions import read

    async def main():
        async with TheAuthClient(
            base_url="https://your-app.com/api/theauth",
            token="ta_...",
        ) as client:
            agent = await client.agents.create(
                CreateAgentInput(
                    owner_id="user-123",
                    name="github-reader",
                    type="autonomous",
                    permissions=[read("mcp:github:*")],
                )
            )
            print(agent.id)

    asyncio.run(main())

Quickstart (sync)::

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
        print(agent.id)
"""

from theauth.client import (
    TheAuthClient,
    TheAuthSyncClient,
    TheAuthClient,
    TheAuthSyncClient,
)
from theauth.approvals import (
    ApprovalDecision,
    ApprovalOpened,
    ApprovalState,
    ConsumeApprovalInput,
    OpenApprovalInput,
    PendingApproval,
)
from theauth.codes import DECISION_CODES, DecisionCode, is_allowed_code
from theauth.decisions import (
    DecisionDelegation,
    DelegationLink,
    ExplainRequest,
    ExplainResult,
)
from theauth.confirmation import (
    dpop_confirmation,
    jkt_confirmation,
    mtls_confirmation,
    x5t_confirmation,
)
from theauth.devices import (
    AttestationNonce,
    CredentialSpec,
    Device,
    DeviceAssertionSigner,
    DeviceBundle,
    DeviceCredential,
    DeviceFilters,
    DeviceRegistration,
    DeviceStats,
    EnrollDeviceInput,
    EnrollmentToken,
    EnrollmentTokenInput,
    RegisterDeviceInput,
    UpdateDeviceInput,
)
from theauth.dpop import DPoPAuth, DPoPProver, normalize_htu
from theauth.errors import (
    AuthenticationError,
    TheAuthError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
    StepUpRequiredError,
    TheAuthError,
    ValidationError,
)
from theauth.introspection import (
    ActorClaim,
    DelegationBinding,
    IntrospectInput,
    IntrospectionResponse,
)
from theauth.provenance import encode_inputs_header, inputs_headers
from theauth.step_up import (
    ACR_MFA,
    ACR_NONE,
    ACR_ORDER,
    ACR_PHISHING_RESISTANT,
    ACR_SINGLE_FACTOR,
    StepUpChallenge,
    acr_satisfies,
    auth_is_fresh,
    parse_step_up_challenge,
    step_up_params,
)
from theauth.types import (
    Agent,
    AgentFilters,
    AuditEntry,
    AuditFilters,
    AuthorizeRequest,
    AuthorizeResult,
    AuthResponse,
    CreateAgentInput,
    DelegateInput,
    DelegationChain,
    ExportOptions,
    McpServer,
    Permission,
    PermissionConstraints,
    ProvenanceInput,
    RegisterMcpServerInput,
    Session,
    UpdateAgentInput,
    User,
)

__all__ = [
    # Clients
    "TheAuthClient",
    "TheAuthSyncClient",
    # Clients (deprecated aliases, use TheAuthClient / TheAuthSyncClient instead)
    "TheAuthClient",
    "TheAuthSyncClient",
    # DPoP (requires theauth[dpop])
    "DPoPAuth",
    "DPoPProver",
    "normalize_htu",
    # Errors
    "TheAuthError",
    # Errors (deprecated alias, use TheAuthError instead)
    "TheAuthError",
    "AuthenticationError",
    "PermissionError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
    "ValidationError",
    "StepUpRequiredError",
    # Decisions, approvals, introspection
    "DECISION_CODES",
    "DecisionCode",
    "is_allowed_code",
    "ExplainRequest",
    "ExplainResult",
    "DecisionDelegation",
    "DelegationLink",
    "OpenApprovalInput",
    "ApprovalOpened",
    "PendingApproval",
    "ApprovalState",
    "ApprovalDecision",
    "ConsumeApprovalInput",
    "IntrospectInput",
    "IntrospectionResponse",
    "ActorClaim",
    "DelegationBinding",
    # Step-up (RFC 9470)
    "StepUpChallenge",
    "parse_step_up_challenge",
    "step_up_params",
    "acr_satisfies",
    "auth_is_fresh",
    "ACR_NONE",
    "ACR_SINGLE_FACTOR",
    "ACR_MFA",
    "ACR_PHISHING_RESISTANT",
    "ACR_ORDER",
    # Sender constrained tokens (RFC 7800)
    "dpop_confirmation",
    "jkt_confirmation",
    "mtls_confirmation",
    "x5t_confirmation",
    # Input provenance
    "ProvenanceInput",
    "encode_inputs_header",
    "inputs_headers",
    # Devices
    "AttestationNonce",
    "CredentialSpec",
    "Device",
    "DeviceAssertionSigner",
    "DeviceBundle",
    "DeviceCredential",
    "DeviceFilters",
    "DeviceRegistration",
    "DeviceStats",
    "EnrollDeviceInput",
    "EnrollmentToken",
    "EnrollmentTokenInput",
    "RegisterDeviceInput",
    "UpdateDeviceInput",
    # Types
    "Agent",
    "AgentFilters",
    "AuditEntry",
    "AuditFilters",
    "AuthorizeRequest",
    "AuthorizeResult",
    "AuthResponse",
    "CreateAgentInput",
    "DelegateInput",
    "DelegationChain",
    "ExportOptions",
    "McpServer",
    "Permission",
    "PermissionConstraints",
    "RegisterMcpServerInput",
    "Session",
    "UpdateAgentInput",
    "User",
]

__version__ = "0.1.0"
