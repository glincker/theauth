"""Explain: why an agent is allowed or denied, with the delegation chain behind it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from theauth.codes import DecisionCode
from theauth.types import Permission


@dataclass
class ExplainRequest:
    """Ask why an agent would be allowed or denied an action. Nothing is audited."""

    agent_id: str
    action: str
    resource: str
    arguments: Optional[Dict[str, Any]] = None
    #: Request metadata. ``ip`` is checked against ``ipAllowlist``.
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    #: ISO 8601 instant to evaluate time windows at. Defaults to now.
    at: Optional[str] = None
    #: Call the beforeAuthorize hook in dry run mode.
    run_hooks: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "agentId": self.agent_id,
            "action": self.action,
            "resource": self.resource,
        }
        if self.arguments is not None:
            out["arguments"] = self.arguments
        context: Dict[str, str] = {}
        if self.ip is not None:
            context["ip"] = self.ip
        if self.user_agent is not None:
            context["userAgent"] = self.user_agent
        if context:
            out["context"] = context
        if self.at is not None:
            out["at"] = self.at
        if self.run_hooks is not None:
            out["runHooks"] = self.run_hooks
        return out


@dataclass
class DelegationLink:
    """One grant on the path from the root agent to the acting agent."""

    delegation_id: str
    from_agent: str
    to_agent: str
    permissions: List[Permission]
    depth: int
    max_depth: int
    expires_at: str
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationLink":
        return cls(
            delegation_id=data["delegationId"],
            from_agent=data["fromAgent"],
            to_agent=data["toAgent"],
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
            depth=data["depth"],
            max_depth=data["maxDepth"],
            expires_at=data["expiresAt"],
            created_at=data["createdAt"],
        )


@dataclass
class DecisionDelegation:
    """Who stands behind the acting agent, root human first."""

    path: List[str]
    #: Grants along ``path``, root first. Empty when the agent is not delegated.
    links: List[DelegationLink]
    #: Every active grant whose ``to_agent`` is the acting agent.
    inbound: List[DelegationLink]
    root_owner_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionDelegation":
        return cls(
            root_owner_id=data.get("rootOwnerId"),
            path=list(data.get("path", [])),
            links=[DelegationLink.from_dict(x) for x in data.get("links", [])],
            inbound=[DelegationLink.from_dict(x) for x in data.get("inbound", [])],
        )


@dataclass
class ExplainAgent:
    """The agent an explanation is about."""

    id: str
    name: str
    owner_id: str
    status: str
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainAgent":
        return cls(
            id=data["id"],
            name=data["name"],
            owner_id=data["ownerId"],
            status=data["status"],
            expires_at=data.get("expiresAt"),
        )


@dataclass
class MatchedGrant:
    """The rule that decided, or came closest."""

    source: str
    index: int
    permission: Permission
    resource_match: str
    action_match: str
    link: Optional[DelegationLink] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MatchedGrant":
        link = data.get("link")
        return cls(
            source=data["source"],
            index=data["index"],
            permission=Permission.from_dict(data["permission"]),
            resource_match=data["resourceMatch"],
            action_match=data["actionMatch"],
            link=DelegationLink.from_dict(link) if link else None,
        )


@dataclass
class ConstraintStep:
    """One constraint check on the matched grant."""

    constraint: str
    outcome: str
    detail: str
    observed: Any = None
    configured: Any = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConstraintStep":
        return cls(
            constraint=data["constraint"],
            outcome=data["outcome"],
            detail=data["detail"],
            observed=data.get("observed"),
            configured=data.get("configured"),
        )


@dataclass
class ExplainAttempt:
    """How one permission set was tried."""

    source: str
    rules_checked: int
    outcome: str
    code: DecisionCode

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainAttempt":
        return cls(
            source=data["source"],
            rules_checked=data["rulesChecked"],
            outcome=data["outcome"],
            code=data["code"],
        )


@dataclass
class ExplainHook:
    """State of the beforeAuthorize hook."""

    configured: bool
    evaluated: bool
    outcome: Optional[str] = None
    reason: Optional[str] = None
    guard: Optional[str] = None
    rule_id: Optional[str] = None
    elapsed_ms: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainHook":
        return cls(
            configured=data["configured"],
            evaluated=data["evaluated"],
            outcome=data.get("outcome"),
            reason=data.get("reason"),
            guard=data.get("guard"),
            rule_id=data.get("ruleId"),
            elapsed_ms=data.get("elapsedMs"),
        )


@dataclass
class NearMiss:
    """A grant that failed on resource or action, with a hint."""

    source: str
    grant_resource: str
    grant_actions: List[str]
    mismatch: List[str]
    hint: str
    score: float
    delegation_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NearMiss":
        grant = data["grant"]
        return cls(
            source=data["source"],
            grant_resource=grant["resource"],
            grant_actions=list(grant["actions"]),
            mismatch=list(data.get("mismatch", [])),
            hint=data["hint"],
            score=data["score"],
            delegation_id=data.get("delegationId"),
        )


@dataclass
class TraceStep:
    """One step of the evaluation, in order."""

    stage: str
    outcome: str
    detail: str
    data: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceStep":
        return cls(
            stage=data["stage"],
            outcome=data["outcome"],
            detail=data["detail"],
            data=data.get("data"),
        )


@dataclass
class ExplainResult:
    """The full account of an authorization decision."""

    decision: str
    allowed: bool
    code: DecisionCode
    reason: str
    agent: Optional[ExplainAgent]
    #: Null when the agent was not found.
    delegation: Optional[DecisionDelegation]
    hook: ExplainHook
    evaluated_at: str
    matched_grant: Optional[MatchedGrant] = None
    constraints: List[ConstraintStep] = field(default_factory=list)
    attempts: List[ExplainAttempt] = field(default_factory=list)
    near_misses: List[NearMiss] = field(default_factory=list)
    trace: List[TraceStep] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExplainResult":
        agent = data.get("agent")
        delegation = data.get("delegation")
        matched = data.get("matchedGrant")
        return cls(
            decision=data["decision"],
            allowed=data["allowed"],
            code=data["code"],
            reason=data["reason"],
            agent=ExplainAgent.from_dict(agent) if agent else None,
            delegation=DecisionDelegation.from_dict(delegation) if delegation else None,
            hook=ExplainHook.from_dict(data["hook"]),
            evaluated_at=data["evaluatedAt"],
            matched_grant=MatchedGrant.from_dict(matched) if matched else None,
            constraints=[ConstraintStep.from_dict(x) for x in data.get("constraints", [])],
            attempts=[ExplainAttempt.from_dict(x) for x in data.get("attempts", [])],
            near_misses=[NearMiss.from_dict(x) for x in data.get("nearMisses", [])],
            trace=[TraceStep.from_dict(x) for x in data.get("trace", [])],
        )
