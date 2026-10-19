"""SPIFFE routes on the Python client: bodies checked on the wire, routes checked against openapi.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest
import respx

from theauth import (
    AuthenticationError,
    SpiffePresentation,
    TheAuthClient,
    TheAuthSyncClient,
)

from tests.conftest import BASE_URL

OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"
ROBOT = "spiffe://example.org/ns/prod/sa/robot"

VERIFIED = {
    "ok": True,
    "code": "ok",
    "spiffeId": ROBOT,
    "svid": {"kind": "x509", "expiresAt": "2030-01-01T00:00:00.000Z", "thumbprint": "abc"},
    "principal": {"type": "device", "id": "dev_1", "name": "Pump 4"},
}

CRED = {
    "id": "cred_1",
    "deviceId": "dev_1",
    "kind": "spiffe",
    "lookup": ROBOT,
    "status": "active",
    "createdAt": "2030-01-01T00:00:00.000Z",
}


def _sent(route: Any) -> Dict[str, Any]:
    return json.loads(route.calls.last.request.content)  # type: ignore[no-any-return]


class TestAdminRoutes:
    @respx.mock
    def test_verify_sends_the_presentation_and_parses_the_answer(self) -> None:
        route = respx.post(f"{BASE_URL}/devices/spiffe/verify").mock(
            return_value=httpx.Response(200, json={"data": VERIFIED})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            out = client.devices.spiffe_verify(SpiffePresentation.x509("PEM"))
            assert _sent(route) == {"kind": "x509", "chain": "PEM"}
            assert out.ok and out.spiffe_id == ROBOT
            assert out.svid is not None and out.svid.thumbprint == "abc"
            assert out.principal is not None and out.principal.type == "device"
            client.devices.spiffe_verify(SpiffePresentation.jwt("a.b.c"))
            assert _sent(route) == {"kind": "jwt", "token": "a.b.c"}

    @respx.mock
    def test_a_failed_verification_is_a_result(self) -> None:
        respx.post(f"{BASE_URL}/devices/spiffe/verify").mock(
            return_value=httpx.Response(
                200, json={"data": {"ok": False, "code": "unknown_workload", "reason": "none"}}
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            out = client.devices.spiffe_verify(SpiffePresentation.jwt("x"))
            assert not out.ok and out.code == "unknown_workload" and out.principal is None

    @respx.mock
    def test_token_returns_the_bound_token(self) -> None:
        route = respx.post(f"{BASE_URL}/devices/spiffe/token").mock(
            return_value=httpx.Response(
                201,
                json={"data": {"agentId": "agt_1", "token": "ta_x", "cnf": {"x5t#S256": "t"}}},
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            out = client.devices.spiffe_token("PEM")
            assert _sent(route) == {"chain": "PEM"}
            assert out.agent_id == "agt_1" and out.token == "ta_x" and out.cnf == {"x5t#S256": "t"}

    @respx.mock
    def test_link_by_id_or_by_svid_and_path_escaping(self) -> None:
        route = respx.post(f"{BASE_URL}/devices/dev%2F1/spiffe").mock(
            return_value=httpx.Response(201, json={"data": CRED})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            cred = client.devices.link_spiffe("dev/1", spiffe_id=ROBOT)
            assert _sent(route) == {"spiffeId": ROBOT} and cred.lookup == ROBOT
            client.devices.link_spiffe("dev/1", presentation=SpiffePresentation.x509("PEM"))
            assert _sent(route) == {"presentation": {"kind": "x509", "chain": "PEM"}}

    def test_link_needs_exactly_one_source(self) -> None:
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            with pytest.raises(ValueError):
                client.devices.link_spiffe("d")
            with pytest.raises(ValueError):
                client.devices.link_spiffe(
                    "d", spiffe_id=ROBOT, presentation=SpiffePresentation.jwt("x")
                )

    @respx.mock
    async def test_async_client(self) -> None:
        respx.post(f"{BASE_URL}/devices/spiffe/verify").mock(
            return_value=httpx.Response(200, json={"data": VERIFIED})
        )
        respx.post(f"{BASE_URL}/devices/d1/spiffe").mock(
            return_value=httpx.Response(201, json={"data": CRED})
        )
        async with TheAuthClient(BASE_URL, token="t") as client:
            assert (await client.devices.spiffe_verify(SpiffePresentation.jwt("x"))).ok
            assert (await client.devices.link_spiffe("d1", spiffe_id=ROBOT)).kind == "spiffe"


class TestDeviceSide:
    @respx.mock
    def test_jwt_svid_goes_in_the_bearer_header_not_the_client_token(self) -> None:
        route = respx.post(f"{BASE_URL}/device/spiffe/verify").mock(
            return_value=httpx.Response(200, json={"data": VERIFIED})
        )
        with TheAuthSyncClient(BASE_URL, token="admin") as client:
            assert client.device.spiffe_verify("a.b.c").ok
            req = route.calls.last.request
            assert req.headers["authorization"] == "Bearer a.b.c"
            assert not req.content

    @respx.mock
    def test_a_refused_svid_raises_with_the_code(self) -> None:
        respx.post(f"{BASE_URL}/device/spiffe/verify").mock(
            return_value=httpx.Response(
                401, json={"error": {"code": "wrong_audience", "message": "audience"}}
            )
        )
        with TheAuthSyncClient(BASE_URL) as client:
            with pytest.raises(AuthenticationError) as err:
                client.device.spiffe_verify("a.b.c")
            assert err.value.code == "wrong_audience"

    def test_empty_svid_is_refused_before_the_request(self) -> None:
        with TheAuthSyncClient(BASE_URL) as client:
            with pytest.raises(ValueError):
                client.device.spiffe_verify("")


class TestRouteContract:
    @respx.mock
    def test_routes_exist_in_openapi_json(self) -> None:
        respx.route().mock(return_value=httpx.Response(200, json={}))
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            for call in (
                lambda: client.devices.spiffe_verify(SpiffePresentation.jwt("x")),
                lambda: client.devices.spiffe_token("PEM"),
                lambda: client.devices.link_spiffe("x", spiffe_id=ROBOT),
                lambda: client.device.spiffe_verify("a.b.c"),
            ):
                try:
                    call()
                except (KeyError, TypeError):
                    pass
        doc = json.loads(OPENAPI.read_text())
        patterns = []
        for path, methods in doc["paths"].items():
            regex = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$"
            patterns.extend((m.upper(), re.compile(regex)) for m in methods)
        prefix = httpx.URL(BASE_URL).path
        assert len(respx.calls) == 4
        for rec in respx.calls:
            path = rec.request.url.raw_path.decode().split("?")[0][len(prefix):]
            assert any(m == rec.request.method and p.match(path) for m, p in patterns), path
