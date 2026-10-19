"""Device registry types. Field names follow the ``/devices`` and ``/device/*`` routes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

from theauth.types.permissions import Permission

DeviceStatus = Literal["active", "suspended", "revoked"]
DeviceCredentialKind = Literal["psk", "jwk", "x509", "spiffe"]
EnrollmentKind = Literal["claim", "bulk"]


@dataclass
class CredentialSpec:
    """The credential a device is registered or enrolled with.

    Build one with :meth:`psk`, :meth:`jwk` or :meth:`x509` rather than by hand.
    """

    kind: DeviceCredentialKind
    jwk: Optional[Dict[str, str]] = None
    thumbprint: Optional[str] = None

    @classmethod
    def psk(cls) -> "CredentialSpec":
        """Ask the server for a fresh pre shared key. It comes back once, as ``secret``."""
        return cls(kind="psk")

    @classmethod
    def from_jwk(cls, public_jwk: Dict[str, str]) -> "CredentialSpec":
        """Register the public half of a device key (EC P-256, EC P-384 or Ed25519).

        A JWK that carries a private member (``d``) is refused here, before it
        leaves the process.
        """
        if "d" in public_jwk:
            raise ValueError("pass the public JWK only, never the private key")
        return cls(kind="jwk", jwk=dict(public_jwk))

    @classmethod
    def x509(cls, thumbprint: str) -> "CredentialSpec":
        """Register a client certificate by its ``x5t#S256`` thumbprint (RFC 8705)."""
        return cls(kind="x509", thumbprint=thumbprint)

    def to_dict(self) -> Dict[str, Any]:
        if self.kind == "jwk":
            return {"kind": "jwk", "jwk": self.jwk}
        if self.kind == "x509":
            return {"kind": "x509", "thumbprint": self.thumbprint}
        return {"kind": "psk"}


@dataclass
class DeviceCredential:
    """One credential row. ``secret`` is set only on the call that created a PSK."""

    id: str
    device_id: str
    kind: DeviceCredentialKind
    lookup: str
    status: Literal["active", "revoked"]
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    public_jwk: Optional[Dict[str, Any]] = None
    secret: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceCredential":
        return cls(
            id=data["id"],
            device_id=data["deviceId"],
            kind=data["kind"],
            lookup=data["lookup"],
            status=data["status"],
            created_at=data["createdAt"],
            expires_at=data.get("expiresAt"),
            last_used_at=data.get("lastUsedAt"),
            public_jwk=data.get("publicJwk"),
            secret=data.get("secret"),
        )


@dataclass
class Device:
    """A device and the agent behind it (``agent_id`` holds permissions and audit rows)."""

    id: str
    agent_id: str
    owner_id: str
    name: str
    status: DeviceStatus
    created_at: str
    updated_at: str
    groups: List[str] = field(default_factory=list)
    permissions: List[Permission] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    kind: Optional[str] = None
    hardware_id: Optional[str] = None
    tenant_id: Optional[str] = None
    status_reason: Optional[str] = None
    enrollment_id: Optional[str] = None
    attestation: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    last_seen_ip: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        return cls(
            id=data["id"],
            agent_id=data["agentId"],
            owner_id=data["ownerId"],
            name=data["name"],
            status=data["status"],
            created_at=data["createdAt"],
            updated_at=data["updatedAt"],
            groups=list(data.get("groups", [])),
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
            metadata=dict(data.get("metadata", {})),
            kind=data.get("kind"),
            hardware_id=data.get("hardwareId"),
            tenant_id=data.get("tenantId"),
            status_reason=data.get("statusReason"),
            enrollment_id=data.get("enrollmentId"),
            attestation=data.get("attestation"),
            expires_at=data.get("expiresAt"),
            last_seen_at=data.get("lastSeenAt"),
            last_seen_ip=data.get("lastSeenIp"),
        )


@dataclass
class DeviceRegistration:
    """Returned by register and enroll: the device, and its credential when one was made."""

    device: Device
    credential: Optional[DeviceCredential] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceRegistration":
        cred = data.get("credential")
        return cls(
            device=Device.from_dict(data["device"]),
            credential=DeviceCredential.from_dict(cred) if cred else None,
        )


@dataclass
class RegisterDeviceInput:
    """Register one device (admin route)."""

    owner_id: str
    name: str
    kind: Optional[str] = None
    hardware_id: Optional[str] = None
    groups: Optional[List[str]] = None
    permissions: Optional[List[Permission]] = None
    metadata: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None
    credential: Optional[CredentialSpec] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ownerId": self.owner_id, "name": self.name}
        if self.kind is not None:
            out["kind"] = self.kind
        if self.hardware_id is not None:
            out["hardwareId"] = self.hardware_id
        if self.groups is not None:
            out["groups"] = self.groups
        if self.permissions is not None:
            out["permissions"] = [p.to_dict() for p in self.permissions]
        if self.metadata is not None:
            out["metadata"] = self.metadata
        if self.expires_at is not None:
            out["expiresAt"] = self.expires_at
        if self.credential is not None:
            out["credential"] = self.credential.to_dict()
        return out


@dataclass
class UpdateDeviceInput:
    """Fields to change on a device. Everything is optional."""

    name: Optional[str] = None
    kind: Optional[str] = None
    groups: Optional[List[str]] = None
    permissions: Optional[List[Permission]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.name is not None:
            out["name"] = self.name
        if self.kind is not None:
            out["kind"] = self.kind
        if self.groups is not None:
            out["groups"] = self.groups
        if self.permissions is not None:
            out["permissions"] = [p.to_dict() for p in self.permissions]
        if self.metadata is not None:
            out["metadata"] = self.metadata
        return out


@dataclass
class DeviceFilters:
    """Query filters for listing devices."""

    owner_id: Optional[str] = None
    status: Optional[DeviceStatus] = None
    group: Optional[str] = None
    enrollment_id: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None

    def to_params(self) -> Dict[str, str]:
        params: Dict[str, str] = {}
        for key, value in (
            ("ownerId", self.owner_id),
            ("status", self.status),
            ("group", self.group),
            ("enrollmentId", self.enrollment_id),
            ("limit", self.limit),
            ("offset", self.offset),
        ):
            if value is not None:
                params[key] = str(value)
        return params


@dataclass
class DeviceStats:
    """Fleet health counters from ``GET /devices/stats``."""

    total: int
    active: int
    suspended: int
    revoked: int
    seen_last_hour: int
    seen_last_day: int
    never_seen: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceStats":
        return cls(
            total=data["total"],
            active=data["active"],
            suspended=data["suspended"],
            revoked=data["revoked"],
            seen_last_hour=data["seenLastHour"],
            seen_last_day=data["seenLastDay"],
            never_seen=data["neverSeen"],
        )


@dataclass
class EnrollmentTokenInput:
    """Create a claim code (one device) or a bulk token (a fleet rollout)."""

    owner_id: str
    kind: EnrollmentKind
    max_uses: Optional[int] = None
    ttl_seconds: Optional[int] = None
    permissions: Optional[List[Permission]] = None
    groups: Optional[List[str]] = None
    device_kind: Optional[str] = None
    device_ttl_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ownerId": self.owner_id, "kind": self.kind}
        if self.max_uses is not None:
            out["maxUses"] = self.max_uses
        if self.ttl_seconds is not None:
            out["ttlSeconds"] = self.ttl_seconds
        if self.permissions is not None:
            out["permissions"] = [p.to_dict() for p in self.permissions]
        if self.groups is not None:
            out["groups"] = self.groups
        if self.device_kind is not None:
            out["deviceKind"] = self.device_kind
        if self.device_ttl_seconds is not None:
            out["deviceTtlSeconds"] = self.device_ttl_seconds
        return out


@dataclass
class EnrollmentToken:
    """A new enrollment token. ``token`` is the plaintext and is returned once."""

    id: str
    kind: EnrollmentKind
    token: str
    owner_id: str
    max_uses: int
    expires_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnrollmentToken":
        return cls(
            id=data["id"],
            kind=data["kind"],
            token=data["token"],
            owner_id=data["ownerId"],
            max_uses=data["maxUses"],
            expires_at=data["expiresAt"],
        )


@dataclass
class EnrollDeviceInput:
    """What a device sends to ``POST /device/enroll`` (no other credential needed)."""

    token: str
    name: str
    credential: CredentialSpec
    hardware_id: Optional[str] = None
    #: Attestation evidence, when the server requires it.
    evidence: Optional[str] = None
    #: The nonce from :meth:`attestation_nonce` that the evidence is bound to.
    nonce: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "token": self.token,
            "name": self.name,
            "credential": self.credential.to_dict(),
        }
        if self.hardware_id is not None:
            out["hardwareId"] = self.hardware_id
        if self.evidence is not None:
            out["evidence"] = self.evidence
        if self.nonce is not None:
            out["nonce"] = self.nonce
        if self.metadata is not None:
            out["metadata"] = self.metadata
        return out


@dataclass
class AttestationNonce:
    """Single use nonce to bind into attestation evidence (RFC 9334 freshness)."""

    nonce: str
    expires_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttestationNonce":
        return cls(nonce=data["nonce"], expires_at=data["expiresAt"])


@dataclass
class DeviceBundle:
    """A signed offline policy bundle (compact JWS, ``typ`` ``device-policy+jwt``)."""

    token: str
    claims: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceBundle":
        return cls(token=data["token"], claims=dict(data.get("claims", {})))


@dataclass
class SpiffePresentation:
    """An SVID handed to an admin route: an X.509 chain (PEM, leaf first) or a compact JWT-SVID."""

    kind: Literal["x509", "jwt"]
    chain: Optional[str] = None
    token: Optional[str] = None

    @classmethod
    def x509(cls, chain: str) -> "SpiffePresentation":
        return cls(kind="x509", chain=chain)

    @classmethod
    def jwt(cls, token: str) -> "SpiffePresentation":
        return cls(kind="jwt", token=token)

    def to_dict(self) -> Dict[str, Any]:
        if self.kind == "jwt":
            return {"kind": "jwt", "token": self.token}
        return {"kind": "x509", "chain": self.chain}


@dataclass
class SpiffeSvid:
    kind: Literal["x509", "jwt"]
    expires_at: str
    thumbprint: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpiffeSvid":
        return cls(
            kind=data["kind"], expires_at=data["expiresAt"], thumbprint=data.get("thumbprint")
        )


@dataclass
class SpiffePrincipal:
    type: Literal["device", "agent"]
    id: str
    name: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpiffePrincipal":
        return cls(type=data["type"], id=data["id"], name=data["name"])


@dataclass
class SpiffeVerifyResult:
    """Answer of a SPIFFE verification. ``code`` is ``"ok"`` or a failure code such as ``expired``."""

    ok: bool
    code: str
    reason: Optional[str] = None
    spiffe_id: Optional[str] = None
    svid: Optional[SpiffeSvid] = None
    principal: Optional[SpiffePrincipal] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpiffeVerifyResult":
        svid = data.get("svid")
        principal = data.get("principal")
        return cls(
            ok=data["ok"],
            code=data["code"],
            reason=data.get("reason"),
            spiffe_id=data.get("spiffeId"),
            svid=SpiffeSvid.from_dict(svid) if svid else None,
            principal=SpiffePrincipal.from_dict(principal) if principal else None,
        )


@dataclass
class SpiffeIssuedToken:
    """An agent token bound to an X.509-SVID (RFC 8705). ``token`` is returned once."""

    agent_id: str
    token: str
    cnf: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpiffeIssuedToken":
        return cls(agent_id=data["agentId"], token=data["token"], cnf=dict(data.get("cnf") or {}))
