"""Shared fixtures for TheAuth SDK tests."""

from __future__ import annotations

import pytest
import respx

from theauth import KavachClient, KavachSyncClient


BASE_URL = "https://test.theauth.dev/api/kavach"


@pytest.fixture
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def async_client() -> KavachClient:
    return KavachClient(base_url=BASE_URL, token="kv_test_token")


@pytest.fixture
def sync_client() -> KavachSyncClient:
    return KavachSyncClient(base_url=BASE_URL, token="kv_test_token")


# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

AGENT_FIXTURE = {
    "id": "agent-abc123",
    "ownerId": "user-123",
    "name": "github-reader",
    "type": "autonomous",
    "token": "kv_agent_xyz",
    "permissions": [
        {"resource": "mcp:github:*", "actions": ["read"]},
    ],
    "status": "active",
    "expiresAt": None,
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "tenantId": None,
}

USER_FIXTURE = {
    "id": "user-123",
    "email": "user@example.com",
    "name": "Test User",
    "createdAt": "2024-01-01T00:00:00Z",
}

SESSION_FIXTURE = {
    "id": "sess-abc",
    "userId": "user-123",
    "token": "sess_token_xyz",
    "expiresAt": "2025-01-01T00:00:00Z",
    "createdAt": "2024-01-01T00:00:00Z",
}

AUTH_RESPONSE_FIXTURE = {
    "success": True,
    "data": {
        "user": USER_FIXTURE,
        "session": SESSION_FIXTURE,
    },
}

DELEGATION_FIXTURE = {
    "id": "del-abc123",
    "fromAgent": "agent-abc123",
    "toAgent": "agent-def456",
    "permissions": [{"resource": "mcp:github:*", "actions": ["read"]}],
    "expiresAt": "2025-01-01T00:00:00Z",
    "depth": 1,
    "createdAt": "2024-01-01T00:00:00Z",
}

AUDIT_ENTRY_FIXTURE = {
    "id": "aud-abc123",
    "agentId": "agent-abc123",
    "userId": "user-123",
    "action": "read",
    "resource": "mcp:github:repos",
    "parameters": {},
    "result": "allowed",
    "durationMs": 42,
    "timestamp": "2024-01-01T00:00:00Z",
    "reason": None,
    "tokensCost": None,
}

AUTHORIZE_RESULT_FIXTURE = {
    "allowed": True,
    "auditId": "aud-abc123",
    "reason": None,
}

MCP_SERVER_FIXTURE = {
    "id": "mcp-abc123",
    "name": "github-mcp",
    "endpoint": "https://mcp.github.com",
    "tools": ["read_file", "list_repos"],
    "authRequired": True,
    "createdAt": "2024-01-01T00:00:00Z",
}
