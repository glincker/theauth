"""Tests for DPoP proofs and the httpx Auth flow. Mirrors packages/client/tests/dpop.test.ts."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List

import httpx
import pytest
import respx

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from theauth import TheAuthClient, TheAuthSyncClient  # noqa: E402
from theauth.dpop import DPoPAuth, DPoPProver, normalize_htu  # noqa: E402

from tests.conftest import BASE_URL  # noqa: E402


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(jwt: str) -> Dict[str, Any]:
    h, p, s = jwt.split(".")
    return {
        "header": json.loads(_unb64(h)),
        "payload": json.loads(_unb64(p)),
        "signing_input": f"{h}.{p}".encode(),
        "signature": _unb64(s),
    }


def verify(jwt: str) -> bool:
    d = decode(jwt)
    jwk = d["header"]["jwk"]
    x = int.from_bytes(_unb64(jwk["x"]), "big")
    y = int.from_bytes(_unb64(jwk["y"]), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    sig = d["signature"]
    assert len(sig) == 64
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, d["signing_input"], ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False
    return True


def sha256_url(v: str) -> str:
    return _b64(hashlib.sha256(v.encode()).digest())


class TestNormalizeHtu:
    def test_drops_query_fragment_and_lowercases_host(self) -> None:
        assert normalize_htu("https://Example.COM/a/b?x=1#f") == "https://example.com/a/b"

    def test_drops_default_port_keeps_custom(self) -> None:
        assert normalize_htu("https://a.test:443/x") == "https://a.test/x"
        assert normalize_htu("http://a.test:8080/x") == "http://a.test:8080/x"

    def test_relative_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_htu("/relative")


class TestProver:
    def test_builds_verifiable_proof(self) -> None:
        prover = DPoPProver(now=lambda: 1_700_000_000)
        jwt = prover.create_proof("post", "https://as.test/token?a=b")
        d = decode(jwt)
        assert d["header"]["typ"] == "dpop+jwt"
        assert d["header"]["alg"] == "ES256"
        assert d["payload"]["htm"] == "POST"
        assert d["payload"]["htu"] == "https://as.test/token"
        assert d["payload"]["iat"] == 1_700_000_000
        assert isinstance(d["payload"]["jti"], str)
        assert "ath" not in d["payload"]
        assert verify(jwt) is True

    def test_header_jwk_is_public_only(self) -> None:
        jwk = decode(DPoPProver().create_proof("GET", "https://rs.test/x"))["header"]["jwk"]
        assert sorted(jwk) == ["crv", "kty", "x", "y"]

    def test_fresh_jti(self) -> None:
        p = DPoPProver()
        a = decode(p.create_proof("GET", "https://rs.test/x"))
        b = decode(p.create_proof("GET", "https://rs.test/x"))
        assert a["payload"]["jti"] != b["payload"]["jti"]

    def test_ath_and_nonce(self) -> None:
        d = decode(
            DPoPProver().create_proof(
                "GET", "https://rs.test/x", access_token="tok-123", nonce="n-1"
            )
        )
        assert d["payload"]["ath"] == sha256_url("tok-123")
        assert d["payload"]["nonce"] == "n-1"

    def test_thumbprint_rfc7638_and_stable(self) -> None:
        p = DPoPProver()
        j = p.public_jwk
        canonical = json.dumps(
            {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}, separators=(",", ":")
        )
        assert p.thumbprint() == sha256_url(canonical)
        assert p.thumbprint() == p.thumbprint()

    def test_existing_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        assert DPoPProver(private_key=key).thumbprint() == DPoPProver(private_key=key).thumbprint()

    def test_rejects_wrong_curve(self) -> None:
        with pytest.raises(ValueError):
            DPoPProver(private_key=ec.generate_private_key(ec.SECP384R1()))

    def test_nonce_cache_per_origin(self) -> None:
        p = DPoPProver()
        p.set_nonce("https://as.test/token", "n1")
        assert p.get_nonce("https://as.test/other") == "n1"
        assert p.get_nonce("https://rs.test/") is None


def _nonce_challenge_body() -> httpx.Response:
    return httpx.Response(
        400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "srv-1"}
    )


class TestAuthFlowSync:
    def test_sends_dpop_header_and_scheme(self) -> None:
        with respx.mock:
            route = respx.get("https://rs.test/tools").mock(return_value=httpx.Response(200, json={}))
            with httpx.Client(auth=DPoPAuth(access_token="AT")) as c:
                c.get("https://rs.test/tools?cursor=1")
        req = route.calls[0].request
        assert req.headers["authorization"] == "DPoP AT"
        d = decode(req.headers["dpop"])
        assert d["payload"]["htu"] == "https://rs.test/tools"
        assert d["payload"]["htm"] == "GET"
        assert d["payload"]["ath"] == sha256_url("AT")

    def test_retries_once_on_400_nonce_and_replays_body(self) -> None:
        seen: List[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.content)
            if len(seen) == 1:
                return _nonce_challenge_body()
            return httpx.Response(200, json={}, headers={"DPoP-Nonce": "srv-2"})

        with respx.mock:
            route = respx.post("https://as.test/token").mock(side_effect=handler)
            with httpx.Client(auth=DPoPAuth()) as c:
                res = c.post("https://as.test/token", content=b"grant_type=x")
                assert res.status_code == 200
                assert seen == [b"grant_type=x", b"grant_type=x"]
                second = route.calls[1].request
                assert decode(second.headers["dpop"])["payload"]["nonce"] == "srv-1"
                c.post("https://as.test/token", content=b"a=b")
                third = route.calls[2].request
                assert decode(third.headers["dpop"])["payload"]["nonce"] == "srv-2"

    def test_retries_on_401_www_authenticate(self) -> None:
        responses = [
            httpx.Response(
                401,
                headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "rs-1"},
            ),
            httpx.Response(200, text="ok"),
        ]
        with respx.mock:
            route = respx.get("https://rs.test/tools").mock(side_effect=responses)
            with httpx.Client(auth=DPoPAuth(access_token="AT")) as c:
                assert c.get("https://rs.test/tools").status_code == 200
        assert route.call_count == 2

    def test_does_not_loop(self) -> None:
        with respx.mock:
            route = respx.post("https://as.test/token").mock(return_value=_nonce_challenge_body())
            with httpx.Client(auth=DPoPAuth()) as c:
                assert c.post("https://as.test/token", content=b"x=1").status_code == 400
        assert route.call_count == 2

    def test_no_retry_for_other_400(self) -> None:
        with respx.mock:
            route = respx.post("https://as.test/token").mock(
                return_value=httpx.Response(
                    400, json={"error": "invalid_grant"}, headers={"DPoP-Nonce": "n"}
                )
            )
            with httpx.Client(auth=DPoPAuth()) as c:
                c.post("https://as.test/token", content=b"x=1")
        assert route.call_count == 1

    def test_callable_token(self) -> None:
        with respx.mock:
            route = respx.get("https://rs.test/x").mock(return_value=httpx.Response(200))
            with httpx.Client(auth=DPoPAuth(access_token=lambda: "from-getter")) as c:
                c.get("https://rs.test/x")
        assert route.calls[0].request.headers["authorization"] == "DPoP from-getter"


class TestWithTheAuthClients:
    def test_sync_client_rebinds_bearer_token(self) -> None:
        auth = DPoPAuth()
        with respx.mock:
            route = respx.get(f"{BASE_URL}/agents").mock(return_value=httpx.Response(200, json=[]))
            with TheAuthSyncClient(base_url=BASE_URL, token="tok", auth=auth) as client:
                client.agents.list()
        req = route.calls[0].request
        assert req.headers["authorization"] == "DPoP tok"
        assert decode(req.headers["dpop"])["payload"]["ath"] == sha256_url("tok")

    @pytest.mark.asyncio
    async def test_async_client_retries_nonce(self) -> None:
        responses = [_nonce_challenge_body(), httpx.Response(200, json=[])]
        with respx.mock:
            route = respx.get(f"{BASE_URL}/agents").mock(side_effect=responses)
            async with TheAuthClient(base_url=BASE_URL, token="tok", auth=DPoPAuth()) as client:
                assert await client.agents.list() == []
        assert route.call_count == 2
        second = route.calls[1].request
        assert decode(second.headers["dpop"])["payload"]["nonce"] == "srv-1"
