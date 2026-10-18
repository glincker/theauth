"""Permission grants and their constraints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional



@dataclass
class PermissionConstraints:
    """Optional constraints attached to a permission grant."""

    max_calls_per_hour: Optional[int] = None
    allowed_arg_patterns: Optional[List[str]] = None
    require_approval: Optional[bool] = None
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    ip_allowlist: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PermissionConstraints":
        tw = data.get("timeWindow") or {}
        return cls(
            max_calls_per_hour=data.get("maxCallsPerHour"),
            allowed_arg_patterns=data.get("allowedArgPatterns"),
            require_approval=data.get("requireApproval"),
            time_window_start=tw.get("start"),
            time_window_end=tw.get("end"),
            ip_allowlist=data.get("ipAllowlist"),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.max_calls_per_hour is not None:
            out["maxCallsPerHour"] = self.max_calls_per_hour
        if self.allowed_arg_patterns is not None:
            out["allowedArgPatterns"] = self.allowed_arg_patterns
        if self.require_approval is not None:
            out["requireApproval"] = self.require_approval
        if self.time_window_start is not None or self.time_window_end is not None:
            out["timeWindow"] = {
                "start": self.time_window_start,
                "end": self.time_window_end,
            }
        if self.ip_allowlist is not None:
            out["ipAllowlist"] = self.ip_allowlist
        return out


@dataclass
class Permission:
    """A single permission grant: resource pattern + allowed actions."""

    resource: str
    actions: List[str]
    constraints: Optional[PermissionConstraints] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Permission":
        constraints = None
        if data.get("constraints"):
            constraints = PermissionConstraints.from_dict(data["constraints"])
        return cls(
            resource=data["resource"],
            actions=data["actions"],
            constraints=constraints,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "resource": self.resource,
            "actions": self.actions,
        }
        if self.constraints is not None:
            out["constraints"] = self.constraints.to_dict()
        return out
