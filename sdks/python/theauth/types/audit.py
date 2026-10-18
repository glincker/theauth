"""Audit log entries and filters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

from theauth.codes import DecisionCode


AuditResult = Literal["allowed", "denied", "rate_limited", "escalated"]


@dataclass
class AuditEntry:
    """A single audit log record."""

    id: str
    agent_id: str
    user_id: str
    action: str
    resource: str
    parameters: Dict[str, Any]
    result: AuditResult
    duration_ms: int
    timestamp: str
    reason: Optional[str] = None
    tokens_cost: Optional[float] = None
    #: Decision code of the entry, absent on rows written before it existed.
    code: Optional[DecisionCode] = None
    #: What happened: ``authorize``, ``delegation.create``, ``approval.approve`` and so on.
    event: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        return cls(
            id=data["id"],
            agent_id=data["agentId"],
            user_id=data["userId"],
            action=data["action"],
            resource=data["resource"],
            parameters=data.get("parameters", {}),
            result=data["result"],
            duration_ms=data["durationMs"],
            timestamp=data["timestamp"],
            reason=data.get("reason"),
            tokens_cost=data.get("tokensCost"),
            code=data.get("code"),
            event=data.get("event"),
        )


@dataclass
class AuditFilters:
    """Query filters for the audit log."""

    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    since: Optional[str] = None
    until: Optional[str] = None
    actions: Optional[List[str]] = None
    result: Optional[AuditResult] = None
    limit: Optional[int] = None
    offset: Optional[int] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if self.agent_id is not None:
            params["agentId"] = self.agent_id
        if self.user_id is not None:
            params["userId"] = self.user_id
        if self.since is not None:
            params["since"] = self.since
        if self.until is not None:
            params["until"] = self.until
        if self.actions is not None:
            params["actions"] = ",".join(self.actions)
        if self.result is not None:
            params["result"] = self.result
        if self.limit is not None:
            params["limit"] = str(self.limit)
        if self.offset is not None:
            params["offset"] = str(self.offset)
        return params


@dataclass
class PaginatedAuditLogs:
    """Paginated audit log response."""

    entries: List[AuditEntry]
    total: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PaginatedAuditLogs":
        return cls(
            entries=[AuditEntry.from_dict(e) for e in data.get("entries", [])],
            total=data.get("total"),
        )
