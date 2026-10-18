"""Decision codes: the machine-readable outcome of an authorization decision."""

from __future__ import annotations

from typing import Literal, Tuple

DecisionCode = Literal[
    "allowed",
    "approval_consumed",
    "no_permission",
    "rate_limited",
    "ip_not_allowed",
    "time_restricted",
    "argument_rejected",
    "approval_required",
    "approval_invalid",
    "agent_not_found",
    "agent_revoked",
    "agent_expired",
    "invalid_token",
    "owner_mismatch",
    "hook_denied",
    "hook_timeout",
    "hook_error",
    "taint_violation",
    "risk_escalation",
    "policy_indeterminate",
]

#: Every code the server sets today, in the order the server lists them. The
#: server may add codes, so keep a default branch when you switch on one.
DECISION_CODES: Tuple[str, ...] = (
    "allowed",
    "approval_consumed",
    "no_permission",
    "rate_limited",
    "ip_not_allowed",
    "time_restricted",
    "argument_rejected",
    "approval_required",
    "approval_invalid",
    "agent_not_found",
    "agent_revoked",
    "agent_expired",
    "invalid_token",
    "owner_mismatch",
    "hook_denied",
    "hook_timeout",
    "hook_error",
    "taint_violation",
    "risk_escalation",
    "policy_indeterminate",
)


def is_allowed_code(code: object) -> bool:
    """True when the code means the call went through."""
    return code in ("allowed", "approval_consumed")
