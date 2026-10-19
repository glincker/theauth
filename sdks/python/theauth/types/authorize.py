"""Authorization requests and results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

from theauth.codes import DecisionCode


ProvenanceKind = Literal["user_message", "tool_output", "retrieved_document", "agent"]


@dataclass
class ProvenanceInput:
    """One input that shaped the call, for the provenance record (``inputs`` on authorize).

    Send ``content`` and let the server hash it, or send a ``hash`` you computed
    yourself (then set ``hash_version`` to the version the server expects, 2 today).
    """

    kind: ProvenanceKind
    id: Optional[str] = None
    content: Optional[str] = None
    hash: Optional[str] = None
    hash_version: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind}
        if self.id is not None:
            out["id"] = self.id
        if self.content is not None:
            out["content"] = self.content
        if self.hash is not None:
            out["hash"] = self.hash
        if self.hash_version is not None:
            out["hashVersion"] = self.hash_version
        return out


@dataclass
class AuthorizeRequest:
    """A request to check whether an agent may perform an action."""

    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None
    #: Id of an approved approval request. When the matched permission requires
    #: approval, the server spends it (single use) and allows the call.
    approval_id: Optional[str] = None
    #: What the model saw before it asked for this call (provenance chips in the audit log).
    inputs: Optional[List[ProvenanceInput]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "action": self.action,
            "resource": self.resource,
        }
        if self.arguments is not None:
            out["arguments"] = self.arguments
        if self.approval_id is not None:
            out["approvalId"] = self.approval_id
        if self.inputs is not None:
            out["inputs"] = [i.to_dict() for i in self.inputs]
        return out


@dataclass
class AuthorizeResult:
    """Result of an authorization check.

    A denied call is still a result (the server answers 403, or 401 for an
    identity failure): branch on ``code``, not on ``reason``.
    """

    allowed: bool
    audit_id: str
    reason: Optional[str] = None
    #: Machine-readable outcome, one of :data:`theauth.codes.DecisionCode`.
    code: Optional[DecisionCode] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizeResult":
        return cls(
            allowed=data["allowed"],
            audit_id=data["auditId"],
            reason=data.get("reason"),
            code=data.get("code"),
        )
