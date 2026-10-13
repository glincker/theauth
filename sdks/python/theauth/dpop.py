"""DPoP (RFC 9449) proof-of-possession helpers.

Mirrors ``packages/client/src/dpop.ts``. :class:`DPoPProver` owns an ES256 key
pair and builds proofs. :class:`DPoPAuth` is an :class:`httpx.Auth` that works
on both sync and async clients: it attaches the proof (and the ``DPoP``
authorization scheme with an ``ath`` claim when an access token is known),
caches the server nonce per origin and retries once on ``use_dpop_nonce``.

Requires the optional ``cryptography`` package: ``pip install "theauth[dpop]"``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any, Callable, Dict, Generator, Optional, Tuple, Union
from urllib.parse import urlsplit

import httpx

_INSTALL_HINT = (
    "DPoP support requires the 'cryptography' package. "
    "Install it with: pip install \"theauth[dpop]\""
)


def _crypto() -> Any:
    """Import cryptography lazily with a clear error when it is missing."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(_INSTALL_HINT) from exc
    return hashes, ec, decode_dss_signature


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _encode_json(value: Any) -> str:
    return _b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _sha256_url(value: str) -> str:
    return _b64url(hashlib.sha256(value.encode("utf-8")).digest())


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin_and_path(value: str) -> Tuple[str, str]:
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    host = parts.hostname
    if not scheme or not host:
        raise ValueError(f"DPoP requires an absolute URL, got {value!r}")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    origin = f"{scheme}://{host}"
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        origin = f"{origin}:{port}"
    return origin, parts.path or "/"


def normalize_htu(value: str) -> str:
    """``htu`` form: scheme, host and path only. Raises ``ValueError`` if not absolute."""
    origin, path = _origin_and_path(value)
    return f"{origin}{path}"


def _origin_of(url: str) -> str:
    return _origin_and_path(url)[0]


class DPoPProver:
    """Owns an ES256 key pair, builds DPoP proofs and caches server nonces.

    Args:
        private_key: Existing ``cryptography`` EC private key on P-256. A new
            one is generated when omitted.
        now: Clock returning seconds since the epoch. Defaults to
            :func:`time.time`.
    """

    def __init__(
        self,
        private_key: Optional[Any] = None,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        _hashes, ec, _decode = _crypto()
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP256R1
        ):
            raise ValueError("DPoP key pair must be an ECDSA P-256 key pair")
        self._private_key = private_key
        self._now = now or time.time
        numbers = private_key.public_key().public_numbers()
        self.public_jwk: Dict[str, str] = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }
        self._nonces: Dict[str, str] = {}

    def thumbprint(self) -> str:
        """RFC 7638 SHA-256 JWK thumbprint (the ``jkt`` / ``cnf.jkt`` value)."""
        j = self.public_jwk
        canonical = json.dumps(
            {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]},
            separators=(",", ":"),
        )
        return _sha256_url(canonical)

    def create_proof(
        self,
        method: str,
        url: str,
        *,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """Build a signed ``dpop+jwt`` proof for one request.

        Args:
            method: HTTP method (upper-cased into ``htm``).
            url: Absolute request URL. Query and fragment are dropped from ``htu``.
            access_token: Include to bind the proof to a resource request (``ath``).
            nonce: Server-provided nonce, when one is known for the origin.
        """
        hashes, ec, decode_dss_signature = _crypto()
        claims: Dict[str, Any] = {
            "htm": method.upper(),
            "htu": normalize_htu(url),
            "iat": int(self._now()),
            "jti": _b64url(os.urandom(16)),
        }
        if access_token:
            claims["ath"] = _sha256_url(access_token)
        if nonce:
            claims["nonce"] = nonce
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk}
        signing_input = f"{_encode_json(header)}.{_encode_json(claims)}"
        der = self._private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input}.{_b64url(raw)}"

    def get_nonce(self, url: str) -> Optional[str]:
        """Cached nonce for the origin of ``url``, if any."""
        return self._nonces.get(_origin_of(url))

    def set_nonce(self, url: str, nonce: str) -> None:
        self._nonces[_origin_of(url)] = nonce


def _is_nonce_challenge(response: httpx.Response) -> bool:
    if response.status_code not in (400, 401):
        return False
    if not response.headers.get("DPoP-Nonce"):
        return False
    if "use_dpop_nonce" in response.headers.get("WWW-Authenticate", ""):
        return True
    if response.status_code != 400:
        return False
    try:
        body = response.json()
    except Exception:
        return False
    return isinstance(body, dict) and body.get("error") == "use_dpop_nonce"


AccessTokenSource = Union[str, Callable[[], Optional[str]]]


class DPoPAuth(httpx.Auth):
    """``httpx.Auth`` flow that signs each request with a DPoP proof.

    Works on :class:`httpx.Client` and :class:`httpx.AsyncClient`, and can be
    passed as ``auth=`` to ``TheAuthClient`` / ``TheAuthSyncClient``.

    Args:
        prover: Reuse a prover (and its nonce cache). One is created when omitted.
        access_token: Access token, or a zero-argument callable resolved per
            request. When omitted, a ``Bearer`` token already present on the
            request is re-sent under the ``DPoP`` scheme and bound with ``ath``.
        private_key: Forwarded to :class:`DPoPProver` when no prover is given.
        now: Forwarded to :class:`DPoPProver` when no prover is given.
    """

    requires_request_body = True
    requires_response_body = True

    def __init__(
        self,
        prover: Optional[DPoPProver] = None,
        access_token: Optional[AccessTokenSource] = None,
        *,
        private_key: Optional[Any] = None,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        self.prover = prover or DPoPProver(private_key=private_key, now=now)
        self._access_token = access_token

    def thumbprint(self) -> str:
        return self.prover.thumbprint()

    def _resolve_token(self, request: httpx.Request) -> Optional[str]:
        source = self._access_token
        configured: Optional[str] = source() if callable(source) else source
        if configured:
            return configured
        header = str(request.headers.get("Authorization", ""))
        scheme, _, value = header.partition(" ")
        if scheme.lower() in ("bearer", "dpop") and value:
            return value
        return None

    def _sign(self, request: httpx.Request, token: Optional[str]) -> None:
        url = str(request.url)
        request.headers["DPoP"] = self.prover.create_proof(
            request.method,
            url,
            access_token=token,
            nonce=self.prover.get_nonce(url),
        )
        if token:
            request.headers["Authorization"] = f"DPoP {token}"

    def _remember_nonce(self, request: httpx.Request, response: httpx.Response) -> None:
        nonce = response.headers.get("DPoP-Nonce")
        if nonce:
            self.prover.set_nonce(str(request.url), nonce)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = self._resolve_token(request)
        self._sign(request, token)
        response = yield request
        self._remember_nonce(request, response)
        if _is_nonce_challenge(response):
            self._sign(request, token)
            response = yield request
            self._remember_nonce(request, response)
