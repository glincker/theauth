"""Quorum approvals on the Python client: request body and the progress fields."""

from __future__ import annotations

import json

import httpx
import respx

from theauth import OpenApprovalInput, TheAuthSyncClient

BASE_URL = "https://test.theauth.dev/api/theauth"


@respx.mock
def test_open_sends_required_approvals_and_reads_the_quorum() -> None:
    route = respx.post(f"{BASE_URL}/approvals").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "a1",
                "status": "pending",
                "action": "admin:rotate",
                "resource": "agent:a1",
                "expiresAt": "2030-01-01T00:00:00Z",
                "requiredApprovals": 2,
            },
        )
    )
    with TheAuthSyncClient(BASE_URL, token="t") as client:
        opened = client.approvals.open(
            OpenApprovalInput("admin:rotate", "agent:a1", required_approvals=2)
        )
    assert json.loads(route.calls[0].request.content)["requiredApprovals"] == 2
    assert opened.required_approvals == 2


@respx.mock
def test_open_omits_the_quorum_when_unset() -> None:
    route = respx.post(f"{BASE_URL}/approvals").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "a1",
                "status": "pending",
                "action": "admin:rotate",
                "resource": "agent:a1",
                "expiresAt": "e",
            },
        )
    )
    with TheAuthSyncClient(BASE_URL, token="t") as client:
        opened = client.approvals.open(OpenApprovalInput("admin:rotate", "agent:a1"))
    assert "requiredApprovals" not in json.loads(route.calls[0].request.content)
    assert opened.required_approvals == 1


@respx.mock
def test_get_and_approve_report_progress() -> None:
    respx.get(f"{BASE_URL}/approvals/a1").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "a1",
                "status": "pending",
                "action": "admin:rotate",
                "resource": "agent:a1",
                "expiresAt": "e",
                "requiredApprovals": 3,
                "approvalsReceived": 1,
                "approvers": ["alice"],
            },
        )
    )
    respx.post(f"{BASE_URL}/approvals/a1/approve").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "a1",
                "status": "pending",
                "respondedAt": "r",
                "requiredApprovals": 3,
                "approvalsReceived": 2,
            },
        )
    )
    with TheAuthSyncClient(BASE_URL, token="t") as client:
        state = client.approvals.get("a1")
        decision = client.approvals.approve("a1")
    assert state is not None
    assert (state.required_approvals, state.approvals_received, state.approvers) == (
        3,
        1,
        ["alice"],
    )
    assert decision.status == "pending" and decision.approvals_received == 2
