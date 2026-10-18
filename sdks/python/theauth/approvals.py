"""Approval requests: open, list, decide and spend (admin API plugin routes)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.errors import NotFoundError


@dataclass
class OpenApprovalInput:
    """Open an approval request. ``action`` must look like ``admin:<name>``."""

    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"action": self.action, "resource": self.resource}
        if self.arguments is not None:
            out["arguments"] = self.arguments
        return out


@dataclass
class ApprovalOpened:
    """Returned when a request is opened."""

    id: str
    status: str
    action: str
    resource: str
    expires_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalOpened":
        return cls(
            id=data["id"],
            status=data["status"],
            action=data["action"],
            resource=data["resource"],
            expires_at=data["expiresAt"],
        )


@dataclass
class PendingApproval:
    """One entry of the pending list. ``arguments`` is redacted JSON text, cut at 2 KB."""

    id: str
    action: str
    resource: str
    requested_by: str
    created_at: str
    expires_at: str
    arguments: str
    arguments_truncated: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PendingApproval":
        return cls(
            id=data["id"],
            action=data["action"],
            resource=data["resource"],
            requested_by=data["requestedBy"],
            created_at=data["createdAt"],
            expires_at=data["expiresAt"],
            arguments=data["arguments"],
            arguments_truncated=data["argumentsTruncated"],
        )


@dataclass
class ApprovalState:
    """Current state of one request. ``status`` is pending, approved, denied or expired."""

    id: str
    status: str
    action: str
    resource: str
    expires_at: str
    responded_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalState":
        return cls(
            id=data["id"],
            status=data["status"],
            action=data["action"],
            resource=data["resource"],
            expires_at=data["expiresAt"],
            responded_at=data.get("respondedAt"),
        )


@dataclass
class ApprovalDecision:
    """Returned by approve and deny."""

    id: str
    status: str
    responded_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalDecision":
        return cls(id=data["id"], status=data["status"], responded_at=data["respondedAt"])


@dataclass
class ConsumeApprovalInput:
    """The call an approved request is spent on."""

    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"action": self.action, "resource": self.resource}
        if self.arguments is not None:
            out["arguments"] = self.arguments
        return out


def _path(approval_id: str, suffix: str = "") -> str:
    return f"/approvals/{quote(approval_id, safe='')}{suffix}"


def _list_params(limit: Optional[int]) -> Dict[str, str]:
    params = {"status": "pending"}
    if limit is not None:
        params["limit"] = str(limit)
    return params


class AsyncApprovalsResource:
    """Async approval requests. Needs the admin API plugin and an admin user token."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def open(self, input: OpenApprovalInput) -> ApprovalOpened:
        """Create a pending approval request."""
        data = await self._http.request("POST", "/approvals", json=input.to_dict())
        return ApprovalOpened.from_dict(data)

    async def list_pending(self, limit: Optional[int] = None) -> List[PendingApproval]:
        """Pending, unexpired requests, newest first (default 50, at most 100)."""
        data = await self._http.request("GET", "/approvals", params=_list_params(limit))
        return [PendingApproval.from_dict(x) for x in data]

    async def get(self, approval_id: str) -> Optional[ApprovalState]:
        """Read a request. Returns ``None`` when it does not exist."""
        try:
            data = await self._http.request("GET", _path(approval_id))
        except NotFoundError:
            return None
        return ApprovalState.from_dict(data)

    async def approve(self, approval_id: str) -> ApprovalDecision:
        """Approve a pending request (409 when it is no longer pending)."""
        data = await self._http.request("POST", _path(approval_id, "/approve"))
        return ApprovalDecision.from_dict(data)

    async def deny(self, approval_id: str) -> ApprovalDecision:
        """Deny a pending request."""
        data = await self._http.request("POST", _path(approval_id, "/deny"))
        return ApprovalDecision.from_dict(data)

    async def consume(self, approval_id: str, input: ConsumeApprovalInput) -> bool:
        """Spend an approved request once. Returns ``True`` when it was spent."""
        data = await self._http.request(
            "POST", _path(approval_id, "/consume"), json=input.to_dict()
        )
        return bool(data["consumed"])


class SyncApprovalsResource:
    """Sync approval requests. Needs the admin API plugin and an admin user token."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def open(self, input: OpenApprovalInput) -> ApprovalOpened:
        """Create a pending approval request."""
        data = self._http.request("POST", "/approvals", json=input.to_dict())
        return ApprovalOpened.from_dict(data)

    def list_pending(self, limit: Optional[int] = None) -> List[PendingApproval]:
        """Pending, unexpired requests, newest first."""
        data = self._http.request("GET", "/approvals", params=_list_params(limit))
        return [PendingApproval.from_dict(x) for x in data]

    def get(self, approval_id: str) -> Optional[ApprovalState]:
        """Read a request. Returns ``None`` when it does not exist."""
        try:
            data = self._http.request("GET", _path(approval_id))
        except NotFoundError:
            return None
        return ApprovalState.from_dict(data)

    def approve(self, approval_id: str) -> ApprovalDecision:
        """Approve a pending request."""
        data = self._http.request("POST", _path(approval_id, "/approve"))
        return ApprovalDecision.from_dict(data)

    def deny(self, approval_id: str) -> ApprovalDecision:
        """Deny a pending request."""
        data = self._http.request("POST", _path(approval_id, "/deny"))
        return ApprovalDecision.from_dict(data)

    def consume(self, approval_id: str, input: ConsumeApprovalInput) -> bool:
        """Spend an approved request once. Returns ``True`` when it was spent."""
        data = self._http.request("POST", _path(approval_id, "/consume"), json=input.to_dict())
        return bool(data["consumed"])
