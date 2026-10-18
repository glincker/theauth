"""Token introspection (RFC 7662) request and response types."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote


@dataclass
class IntrospectInput:
    """A token introspection request. The caller authenticates as an OAuth client."""

    token: str
    #: Advisory: ``access_token`` or ``refresh_token``.
    token_type_hint: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    def form(self) -> Dict[str, str]:
        out = {"token": self.token}
        if self.token_type_hint:
            out["token_type_hint"] = self.token_type_hint
        return out

    def headers(self) -> Dict[str, str]:
        """HTTP Basic client credentials (``client_secret_basic``), when a client id is set."""
        if not self.client_id:
            return {}
        pair = f"{quote(self.client_id, safe='')}:{quote(self.client_secret or '', safe='')}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}


@dataclass
class ActorClaim:
    """RFC 8693 ``act`` claim: the actor, with earlier hops nested."""

    sub: Optional[str] = None
    client_id: Optional[str] = None
    act: Optional["ActorClaim"] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActorClaim":
        nested = data.get("act")
        return cls(
            sub=data.get("sub"),
            client_id=data.get("client_id"),
            act=cls.from_dict(nested) if isinstance(nested, dict) else None,
        )


@dataclass
class DelegationBinding:
    """The ``theauth_dlg`` claim: the authority path the token rests on."""

    v: int
    #: Agent ids on the authority path, root first.
    agt: List[str]
    #: Delegation chain id for each consecutive pair in ``agt``.
    lnk: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationBinding":
        return cls(v=data["v"], agt=list(data.get("agt", [])), lnk=list(data.get("lnk", [])))


@dataclass
class IntrospectionResponse:
    """The RFC 7662 answer. A caller that is not entitled to the token gets only ``active=False``."""

    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    sub: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    #: The ``aud`` claim, always as a list.
    aud: List[str] = field(default_factory=list)
    iss: Optional[str] = None
    jti: Optional[str] = None
    token_type: Optional[str] = None
    #: DPoP key thumbprint (``cnf.jkt``).
    jkt: Optional[str] = None
    act: Optional[ActorClaim] = None
    agent_id: Optional[str] = None
    #: Set for tokens bound to a delegation chain.
    delegation: Optional[DelegationBinding] = None
    #: Only for entitled callers, and only when ``active`` is false.
    inactive_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntrospectionResponse":
        aud = data.get("aud")
        act = data.get("act")
        dlg = data.get("theauth_dlg")
        cnf = data.get("cnf")
        return cls(
            active=bool(data["active"]),
            scope=data.get("scope"),
            client_id=data.get("client_id"),
            sub=data.get("sub"),
            exp=data.get("exp"),
            iat=data.get("iat"),
            aud=[aud] if isinstance(aud, str) else list(aud or []),
            iss=data.get("iss"),
            jti=data.get("jti"),
            token_type=data.get("token_type"),
            jkt=cnf.get("jkt") if isinstance(cnf, dict) else None,
            act=ActorClaim.from_dict(act) if isinstance(act, dict) else None,
            agent_id=data.get("agent_id"),
            delegation=DelegationBinding.from_dict(dlg) if isinstance(dlg, dict) else None,
            inactive_reason=data.get("theauth_inactive_reason"),
        )
