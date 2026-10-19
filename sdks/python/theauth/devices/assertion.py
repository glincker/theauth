"""Device assertion JWTs: how a device proves itself with a key it holds.

Layout from ``iot-device-identity.md`` (D3), built on the RFC 7523 section 3 client
assertion with the RFC 9449 replay rules::

    header  {"alg": "ES256", "typ": "device-assertion+jwt", "kid": <RFC 7638 thumbprint>}
    payload {"iss": id, "sub": id, "aud": "theauth", "iat": n, "exp": n+60, "jti": <random>}

Send it as ``Authorization: Bearer <jwt>``. Each assertion has a fresh ``jti``
and the server accepts a ``jti`` once, so sign one per request. The lifetime is
capped at 300 seconds by the server.

Requires the optional ``cryptography`` package: ``pip install "theauth[dpop]"``.
ES256 (P-256) only here; the server also takes ES384 and EdDSA keys.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, Optional

from theauth.dpop import _b64url, _crypto, _encode_json, _sha256_url

DEVICE_ASSERTION_TYP = "device-assertion+jwt"
#: Longest lifetime the server accepts (exp minus iat).
MAX_LIFETIME_SECONDS = 300
DEFAULT_AUDIENCE = "theauth"


class DeviceAssertionSigner:
    """Owns a device P-256 key and signs device assertions.

    Args:
        device_id: The device id the server assigned at registration or enrollment.
            Pass ``None`` to create the key first (you need ``public_jwk`` to
            register), then call :meth:`bind` with the id you get back.
        private_key: Existing ``cryptography`` EC private key on P-256. A new
            one is generated when omitted. Register ``public_jwk`` with
            :meth:`theauth.devices.CredentialSpec.from_jwk`.
        audience: Must equal the server's ``devices.audience`` (default ``"theauth"``).
        lifetime: Seconds between ``iat`` and ``exp``, 1 to 300. Default 60.
        now: Clock returning seconds since the epoch.
    """

    def __init__(
        self,
        device_id: Optional[str] = None,
        private_key: Optional[Any] = None,
        *,
        audience: str = DEFAULT_AUDIENCE,
        lifetime: int = 60,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        if device_id is not None and not device_id:
            raise ValueError("device_id must not be empty")
        if not 1 <= lifetime <= MAX_LIFETIME_SECONDS:
            raise ValueError(f"lifetime must be 1 to {MAX_LIFETIME_SECONDS} seconds")
        _hashes, ec, _decode = _crypto()
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP256R1
        ):
            raise ValueError("the device key must be an ECDSA P-256 private key")
        self.device_id: Optional[str] = device_id
        self.audience = audience
        self._lifetime = lifetime
        self._now = now or time.time
        self._private_key = private_key
        numbers = private_key.public_key().public_numbers()
        self.public_jwk: Dict[str, str] = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }

    def bind(self, device_id: str) -> "DeviceAssertionSigner":
        """Set the device id after registration. Returns ``self``."""
        if not device_id:
            raise ValueError("device_id must not be empty")
        self.device_id = device_id
        return self

    @property
    def kid(self) -> str:
        """RFC 7638 SHA-256 thumbprint of the public key. The server looks the credential up by it."""
        import json

        j = self.public_jwk
        canonical = json.dumps(
            {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}, separators=(",", ":")
        )
        return _sha256_url(canonical)

    def sign(self) -> str:
        """A new signed assertion with a fresh ``jti``."""
        if not self.device_id:
            raise ValueError("bind(device_id) first: the signer has no device id yet")
        hashes, ec, decode_dss_signature = _crypto()
        iat = int(self._now())
        header = {"alg": "ES256", "typ": DEVICE_ASSERTION_TYP, "kid": self.kid}
        claims = {
            "iss": self.device_id,
            "sub": self.device_id,
            "aud": self.audience,
            "iat": iat,
            "exp": iat + self._lifetime,
            "jti": _b64url(os.urandom(16)),
        }
        signing_input = f"{_encode_json(header)}.{_encode_json(claims)}"
        der = self._private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input}.{_b64url(raw)}"

    def authorization_header(self) -> Dict[str, str]:
        """``{"Authorization": "Bearer <new assertion>"}`` for one request."""
        return {"Authorization": f"Bearer {self.sign()}"}
