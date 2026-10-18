"""Sender constrained agent tokens (RFC 7800 ``cnf`` claim).

Create or rotate an agent with a ``cnf`` member and the server refuses the token
unless the caller proves the key or certificate too. For DPoP (RFC 9449) the
member is ``jkt``, the RFC 7638 thumbprint of the proof key. For mutual TLS
(RFC 8705) it is ``x5t#S256``, the base64url SHA-256 of the DER certificate.

Example::

    prover = DPoPProver()
    agent = client.agents.create(
        CreateAgentInput(..., cnf=dpop_confirmation(prover)),
    )
    bound = TheAuthSyncClient(base_url, token=agent.token, auth=DPoPAuth(prover))
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict

_THUMBPRINT = re.compile(r"^[A-Za-z0-9_-]{43}$")


def dpop_confirmation(prover: Any) -> Dict[str, str]:
    """``cnf`` binding a token to a DPoP key: ``{"jkt": prover.thumbprint()}``.

    Accepts a :class:`theauth.dpop.DPoPProver` or a :class:`theauth.dpop.DPoPAuth`.
    """
    return {"jkt": _checked(prover.thumbprint())}


def jkt_confirmation(thumbprint: str) -> Dict[str, str]:
    """``cnf`` from a JWK thumbprint you already hold (43 base64url characters)."""
    return {"jkt": _checked(thumbprint)}


def mtls_confirmation(certificate_der: bytes) -> Dict[str, str]:
    """``cnf`` binding a token to a client certificate (RFC 8705 section 3.1)."""
    digest = hashlib.sha256(certificate_der).digest()
    return {"x5t#S256": base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")}


def x5t_confirmation(thumbprint: str) -> Dict[str, str]:
    """``cnf`` from a certificate thumbprint you already hold (43 base64url characters)."""
    return {"x5t#S256": _checked(thumbprint)}


def _checked(value: str) -> str:
    if not _THUMBPRINT.match(value):
        raise ValueError("a SHA-256 thumbprint is 43 base64url characters")
    return value
