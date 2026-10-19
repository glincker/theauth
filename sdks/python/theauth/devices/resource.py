"""Device routes: the admin registry (``/devices``) and the calls a device makes itself (``/device/*``)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

from theauth._http import AsyncTransport, SyncTransport
from theauth.devices.assertion import DeviceAssertionSigner
from theauth.devices.types import (
    AttestationNonce,
    CredentialSpec,
    Device,
    DeviceBundle,
    DeviceCredential,
    DeviceFilters,
    DeviceRegistration,
    DeviceStats,
    EnrollDeviceInput,
    EnrollmentToken,
    EnrollmentTokenInput,
    RegisterDeviceInput,
    SpiffeIssuedToken,
    SpiffePresentation,
    SpiffeVerifyResult,
    UpdateDeviceInput,
)
from theauth.errors import NotFoundError
from theauth.types.authorize import AuthorizeRequest, AuthorizeResult

#: A device credential: a ``tdk_`` pre shared key, a ready assertion JWT, or a signer
#: that makes a fresh assertion for every call.
DeviceAuth = Union[str, DeviceAssertionSigner]


def device_auth_headers(credential: DeviceAuth) -> Dict[str, str]:
    """``Authorization`` header for a device credential."""
    if isinstance(credential, DeviceAssertionSigner):
        return credential.authorization_header()
    if not credential:
        raise ValueError("a device credential is required")
    return {"Authorization": f"Bearer {credential}"}


def _id(device_id: str, suffix: str = "") -> str:
    return f"/devices/{quote(device_id, safe='')}{suffix}"


def _suspend_body(reason: Optional[str]) -> Optional[Dict[str, Any]]:
    return {"reason": reason} if reason is not None else None


def _bundle_body(ttl_seconds: Optional[int]) -> Optional[Dict[str, Any]]:
    return {"ttlSeconds": ttl_seconds} if ttl_seconds is not None else None


def _stats_params(owner_id: Optional[str]) -> Optional[Dict[str, str]]:
    return {"ownerId": owner_id} if owner_id else None


def _link_body(
    spiffe_id: Optional[str], presentation: Optional[SpiffePresentation]
) -> Dict[str, Any]:
    if (spiffe_id is None) == (presentation is None):
        raise ValueError("pass exactly one of spiffe_id or presentation")
    if presentation is not None:
        return {"presentation": presentation.to_dict()}
    return {"spiffeId": spiffe_id}


class AsyncDevicesResource:
    """Async device registry. Needs a user or admin token."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def register(self, input: RegisterDeviceInput) -> DeviceRegistration:
        """Register a device. A PSK credential's ``secret`` is in the result, once."""
        data = await self._http.request("POST", "/devices", json=input.to_dict())
        return DeviceRegistration.from_dict(data)

    async def list(self, filters: Optional[DeviceFilters] = None) -> List[Device]:
        data = await self._http.request(
            "GET", "/devices", params=filters.to_params() if filters else None
        )
        return [Device.from_dict(d) for d in data]

    async def get(self, device_id: str) -> Optional[Device]:
        """Read a device. Returns ``None`` when it does not exist."""
        try:
            data = await self._http.request("GET", _id(device_id))
        except NotFoundError:
            return None
        return Device.from_dict(data)

    async def update(self, device_id: str, input: UpdateDeviceInput) -> Device:
        data = await self._http.request("PATCH", _id(device_id), json=input.to_dict())
        return Device.from_dict(data)

    async def suspend(self, device_id: str, reason: Optional[str] = None) -> Device:
        """Block the device until :meth:`resume`. Its credentials stay valid but are refused."""
        data = await self._http.request(
            "POST", _id(device_id, "/suspend"), json=_suspend_body(reason)
        )
        return Device.from_dict(data)

    async def resume(self, device_id: str) -> Device:
        data = await self._http.request("POST", _id(device_id, "/resume"))
        return Device.from_dict(data)

    async def revoke(self, device_id: str) -> List[str]:
        """Revoke for good. Returns the ids of the delegations that were revoked with it."""
        data = await self._http.request("DELETE", _id(device_id))
        return list(data["revokedDelegations"])

    async def add_credential(self, device_id: str, spec: CredentialSpec) -> DeviceCredential:
        data = await self._http.request("POST", _id(device_id, "/credentials"), json=spec.to_dict())
        return DeviceCredential.from_dict(data)

    async def revoke_credential(self, device_id: str, credential_id: str) -> None:
        await self._http.request(
            "DELETE", _id(device_id, f"/credentials/{quote(credential_id, safe='')}")
        )

    async def issue_bundle(self, device_id: str, ttl_seconds: Optional[int] = None) -> DeviceBundle:
        """Issue a signed offline policy bundle for a device (needs ``devices.bundleSigning``)."""
        data = await self._http.request(
            "POST", _id(device_id, "/bundle"), json=_bundle_body(ttl_seconds)
        )
        return DeviceBundle.from_dict(data)

    async def stats(self, owner_id: Optional[str] = None) -> DeviceStats:
        """Fleet health counters."""
        data = await self._http.request("GET", "/devices/stats", params=_stats_params(owner_id))
        return DeviceStats.from_dict(data)

    async def create_enrollment_token(self, input: EnrollmentTokenInput) -> EnrollmentToken:
        """Create a claim code or bulk token. The plaintext ``token`` is returned once."""
        data = await self._http.request("POST", "/devices/enrollment-tokens", json=input.to_dict())
        return EnrollmentToken.from_dict(data)

    async def revoke_enrollment_token(self, token_id: str) -> None:
        await self._http.request("DELETE", f"/devices/enrollment-tokens/{quote(token_id, safe='')}")

    async def spiffe_verify(self, presentation: SpiffePresentation) -> SpiffeVerifyResult:
        """Check an SVID against the trust bundles. Mints nothing. A mapping owned by someone else reads as unmapped."""
        data = await self._http.request(
            "POST", "/devices/spiffe/verify", json=presentation.to_dict()
        )
        return SpiffeVerifyResult.from_dict(data)

    async def spiffe_token(self, chain: str) -> SpiffeIssuedToken:
        """Issue an agent token bound to an X.509-SVID (rotates the agent token). Agent workloads only."""
        data = await self._http.request("POST", "/devices/spiffe/token", json={"chain": chain})
        return SpiffeIssuedToken.from_dict(data)

    async def link_spiffe(
        self,
        device_id: str,
        *,
        spiffe_id: Optional[str] = None,
        presentation: Optional[SpiffePresentation] = None,
    ) -> DeviceCredential:
        """Link a SPIFFE ID to a device, by id in a configured trust domain or by a verified SVID."""
        data = await self._http.request(
            "POST", _id(device_id, "/spiffe"), json=_link_body(spiffe_id, presentation)
        )
        return DeviceCredential.from_dict(data)


class AsyncDeviceApiResource:
    """Async calls a device makes as itself. Enroll, nonce and JWKS need no credential."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._http = transport

    async def enroll(self, input: EnrollDeviceInput) -> DeviceRegistration:
        """Enroll with a claim code or bulk token and receive a device identity."""
        data = await self._http.request("POST", "/device/enroll", json=input.to_dict())
        return DeviceRegistration.from_dict(data)

    async def attestation_nonce(self) -> AttestationNonce:
        data = await self._http.request("POST", "/device/attestation-nonce")
        return AttestationNonce.from_dict(data)

    async def authorize(self, credential: DeviceAuth, request: AuthorizeRequest) -> AuthorizeResult:
        """Check an action as the device. A denial is a result, a bad credential is a 401 result."""
        data = await self._http.request_decision(
            "/device/authorize",
            json=request.to_dict(),
            extra_headers=device_auth_headers(credential),
        )
        return AuthorizeResult.from_dict(data)

    async def bundle(self, credential: DeviceAuth) -> DeviceBundle:
        """Fetch a fresh offline policy bundle for the calling device."""
        data = await self._http.request(
            "GET", "/device/bundle", extra_headers=device_auth_headers(credential)
        )
        return DeviceBundle.from_dict(data)

    async def jwks(self) -> Dict[str, Any]:
        """Public keys that verify offline policy bundles."""
        data = await self._http.request("GET", "/device/jwks")
        return data  # type: ignore[no-any-return]

    async def spiffe_verify(self, jwt_svid: str) -> SpiffeVerifyResult:
        """Verify the device's own JWT-SVID. A refused SVID raises ``AuthenticationError`` with the failure code.

        An X.509-SVID cannot be sent here: the server reads it from the TLS handshake or a trusted proxy header.
        """
        if not jwt_svid:
            raise ValueError("a JWT-SVID is required")
        data = await self._http.request(
            "POST",
            "/device/spiffe/verify",
            extra_headers={"Authorization": f"Bearer {jwt_svid}"},
        )
        return SpiffeVerifyResult.from_dict(data)


class SyncDevicesResource:
    """Sync device registry. Needs a user or admin token."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def register(self, input: RegisterDeviceInput) -> DeviceRegistration:
        """Register a device. A PSK credential's ``secret`` is in the result, once."""
        data = self._http.request("POST", "/devices", json=input.to_dict())
        return DeviceRegistration.from_dict(data)

    def list(self, filters: Optional[DeviceFilters] = None) -> List[Device]:
        data = self._http.request("GET", "/devices", params=filters.to_params() if filters else None)
        return [Device.from_dict(d) for d in data]

    def get(self, device_id: str) -> Optional[Device]:
        """Read a device. Returns ``None`` when it does not exist."""
        try:
            data = self._http.request("GET", _id(device_id))
        except NotFoundError:
            return None
        return Device.from_dict(data)

    def update(self, device_id: str, input: UpdateDeviceInput) -> Device:
        data = self._http.request("PATCH", _id(device_id), json=input.to_dict())
        return Device.from_dict(data)

    def suspend(self, device_id: str, reason: Optional[str] = None) -> Device:
        """Block the device until :meth:`resume`."""
        data = self._http.request("POST", _id(device_id, "/suspend"), json=_suspend_body(reason))
        return Device.from_dict(data)

    def resume(self, device_id: str) -> Device:
        data = self._http.request("POST", _id(device_id, "/resume"))
        return Device.from_dict(data)

    def revoke(self, device_id: str) -> List[str]:
        """Revoke for good. Returns the ids of the delegations that were revoked with it."""
        data = self._http.request("DELETE", _id(device_id))
        return list(data["revokedDelegations"])

    def add_credential(self, device_id: str, spec: CredentialSpec) -> DeviceCredential:
        data = self._http.request("POST", _id(device_id, "/credentials"), json=spec.to_dict())
        return DeviceCredential.from_dict(data)

    def revoke_credential(self, device_id: str, credential_id: str) -> None:
        self._http.request("DELETE", _id(device_id, f"/credentials/{quote(credential_id, safe='')}"))

    def issue_bundle(self, device_id: str, ttl_seconds: Optional[int] = None) -> DeviceBundle:
        """Issue a signed offline policy bundle for a device (needs ``devices.bundleSigning``)."""
        data = self._http.request("POST", _id(device_id, "/bundle"), json=_bundle_body(ttl_seconds))
        return DeviceBundle.from_dict(data)

    def stats(self, owner_id: Optional[str] = None) -> DeviceStats:
        """Fleet health counters."""
        data = self._http.request("GET", "/devices/stats", params=_stats_params(owner_id))
        return DeviceStats.from_dict(data)

    def create_enrollment_token(self, input: EnrollmentTokenInput) -> EnrollmentToken:
        """Create a claim code or bulk token. The plaintext ``token`` is returned once."""
        data = self._http.request("POST", "/devices/enrollment-tokens", json=input.to_dict())
        return EnrollmentToken.from_dict(data)

    def revoke_enrollment_token(self, token_id: str) -> None:
        self._http.request("DELETE", f"/devices/enrollment-tokens/{quote(token_id, safe='')}")

    def spiffe_verify(self, presentation: SpiffePresentation) -> SpiffeVerifyResult:
        """Check an SVID against the trust bundles. Mints nothing. A mapping owned by someone else reads as unmapped."""
        data = self._http.request(
            "POST", "/devices/spiffe/verify", json=presentation.to_dict()
        )
        return SpiffeVerifyResult.from_dict(data)

    def spiffe_token(self, chain: str) -> SpiffeIssuedToken:
        """Issue an agent token bound to an X.509-SVID (rotates the agent token). Agent workloads only."""
        data = self._http.request("POST", "/devices/spiffe/token", json={"chain": chain})
        return SpiffeIssuedToken.from_dict(data)

    def link_spiffe(
        self,
        device_id: str,
        *,
        spiffe_id: Optional[str] = None,
        presentation: Optional[SpiffePresentation] = None,
    ) -> DeviceCredential:
        """Link a SPIFFE ID to a device, by id in a configured trust domain or by a verified SVID."""
        data = self._http.request(
            "POST", _id(device_id, "/spiffe"), json=_link_body(spiffe_id, presentation)
        )
        return DeviceCredential.from_dict(data)


class SyncDeviceApiResource:
    """Sync calls a device makes as itself. Enroll, nonce and JWKS need no credential."""

    def __init__(self, transport: SyncTransport) -> None:
        self._http = transport

    def enroll(self, input: EnrollDeviceInput) -> DeviceRegistration:
        """Enroll with a claim code or bulk token and receive a device identity."""
        data = self._http.request("POST", "/device/enroll", json=input.to_dict())
        return DeviceRegistration.from_dict(data)

    def attestation_nonce(self) -> AttestationNonce:
        data = self._http.request("POST", "/device/attestation-nonce")
        return AttestationNonce.from_dict(data)

    def authorize(self, credential: DeviceAuth, request: AuthorizeRequest) -> AuthorizeResult:
        """Check an action as the device. A denial is a result, a bad credential is a 401 result."""
        data = self._http.request_decision(
            "/device/authorize",
            json=request.to_dict(),
            extra_headers=device_auth_headers(credential),
        )
        return AuthorizeResult.from_dict(data)

    def bundle(self, credential: DeviceAuth) -> DeviceBundle:
        """Fetch a fresh offline policy bundle for the calling device."""
        data = self._http.request(
            "GET", "/device/bundle", extra_headers=device_auth_headers(credential)
        )
        return DeviceBundle.from_dict(data)

    def jwks(self) -> Dict[str, Any]:
        """Public keys that verify offline policy bundles."""
        data = self._http.request("GET", "/device/jwks")
        return data  # type: ignore[no-any-return]

    def spiffe_verify(self, jwt_svid: str) -> SpiffeVerifyResult:
        """Verify the device's own JWT-SVID. A refused SVID raises ``AuthenticationError`` with the failure code.

        An X.509-SVID cannot be sent here: the server reads it from the TLS handshake or a trusted proxy header.
        """
        if not jwt_svid:
            raise ValueError("a JWT-SVID is required")
        data = self._http.request(
            "POST",
            "/device/spiffe/verify",
            extra_headers={"Authorization": f"Bearer {jwt_svid}"},
        )
        return SpiffeVerifyResult.from_dict(data)
