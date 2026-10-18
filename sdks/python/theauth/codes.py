"""Decision codes: the machine-readable outcome of an authorization decision."""

from __future__ import annotations

from typing import Literal, Tuple

DecisionCode = Literal[
    # BEGIN GENERATED decision-codes literal
    "allowed",
    "approval_consumed",
    "no_permission",
    "rate_limited",
    "ip_not_allowed",
    "time_restricted",
    "argument_rejected",
    "approval_required",
    "approval_invalid",
    "approval_not_found",
    "approval_pending",
    "approval_denied",
    "approval_expired",
    "approval_already_used",
    "approval_mismatch",
    "approval_arguments_mismatch",
    "approval_step_up_insufficient",
    "approval_granted",
    "agent_not_found",
    "agent_revoked",
    "agent_expired",
    "invalid_token",
    "confirmation_required",
    "confirmation_failed",
    "device_not_found",
    "device_suspended",
    "device_revoked",
    "device_expired",
    "owner_mismatch",
    "hook_denied",
    "hook_timeout",
    "hook_error",
    "taint_violation",
    "risk_escalation",
    "policy_indeterminate",
    # END GENERATED decision-codes literal
]

#: Every code the server sets today, in the order the server lists them. The
#: server may add codes, so keep a default branch when you switch on one.
DECISION_CODES: Tuple[str, ...] = (
    # BEGIN GENERATED decision-codes tuple
    "allowed",
    "approval_consumed",
    "no_permission",
    "rate_limited",
    "ip_not_allowed",
    "time_restricted",
    "argument_rejected",
    "approval_required",
    "approval_invalid",
    "approval_not_found",
    "approval_pending",
    "approval_denied",
    "approval_expired",
    "approval_already_used",
    "approval_mismatch",
    "approval_arguments_mismatch",
    "approval_step_up_insufficient",
    "approval_granted",
    "agent_not_found",
    "agent_revoked",
    "agent_expired",
    "invalid_token",
    "confirmation_required",
    "confirmation_failed",
    "device_not_found",
    "device_suspended",
    "device_revoked",
    "device_expired",
    "owner_mismatch",
    "hook_denied",
    "hook_timeout",
    "hook_error",
    "taint_violation",
    "risk_escalation",
    "policy_indeterminate",
    # END GENERATED decision-codes tuple
)


def is_allowed_code(code: object) -> bool:
    """True when the code means the call went through."""
    return code in ("allowed", "approval_consumed")
