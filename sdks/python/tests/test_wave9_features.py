"""Wave 9 features on the Python client: step-up, cnf, provenance inputs, devices.

Request bodies are checked on the wire with respx, and the route contract is checked
against sdks/openapi.json so a renamed server route fails here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import httpx
import pytest
import respx

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from theauth import (  # noqa: E402
    AuthenticationError,
    CredentialSpec,
    DeviceAssertionSigner,
    DPoPProver,
    EnrollDeviceInput,
    EnrollmentTokenInput,
    ProvenanceInput,
    RegisterDeviceInput,
    StepUpRequiredError,
    TheAuthClient,
    TheAuthSyncClient,
    acr_satisfies,
    auth_is_fresh,
    dpop_confirmation,
    encode_inputs_header,
    inputs_headers,
    mtls_confirmation,
    parse_step_up_challenge,
    step_up_params,
)
from theauth.devices import DeviceFilters, UpdateDeviceInput  # noqa: E402
from theauth.permissions import read  # noqa: E402
from theauth.types import AuthorizeRequest, CreateAgentInput  # noqa: E402

from tests.conftest import BASE_URL  # noqa: E402

OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def body_of(route: Any) -> Any:
    return json.loads(route.calls.last.request.content)


DEVICE_ROW: Dict[str, Any] = {
    "id": "dev_1",
    "agentId": "agt_1",
    "ownerId": "user_1",
    "name": "Pump 4",
    "kind": "sensor",
    "hardwareId": "hw-77",
    "status": "active",
    "groups": ["plant-a"],
    "permissions": [{"resource": "mqtt:plant/a/#", "actions": ["publish"]}],
    "metadata": {},
    "expiresAt": None,
    "lastSeenAt": None,
    "createdAt": "2030-01-01T00:00:00.000Z",
    "updatedAt": "2030-01-01T00:00:00.000Z",
}
CRED_ROW: Dict[str, Any] = {
    "id": "cred_1",
    "deviceId": "dev_1",
    "kind": "psk",
    "lookup": "abc",
    "status": "active",
    "expiresAt": None,
    "lastUsedAt": None,
    "createdAt": "2030-01-01T00:00:00.000Z",
}


class TestStepUpChallenge:
    HEADER = (
        'Bearer error="insufficient_user_authentication", '
        'error_description="A stronger authentication is required", '
        'acr_values="urn:theauth:acr:mfa urn:theauth:acr:phishing-resistant", max_age="300", '
        'resource_metadata="https://api.example.org/.well-known/oauth-protected-resource"'
    )

    def test_parses_the_rfc_9470_challenge(self) -> None:
        c = parse_step_up_challenge(self.HEADER)
        assert c is not None
        assert c.scheme == "Bearer"
        assert c.acr_values == ["urn:theauth:acr:mfa", "urn:theauth:acr:phishing-resistant"]
        assert c.max_age == 300
        assert c.error_description == "A stronger authentication is required"
        assert c.resource_metadata is not None
        assert c.authorize_params() == {
            "acr_values": "urn:theauth:acr:mfa urn:theauth:acr:phishing-resistant",
            "max_age": "300",
        }

    def test_finds_the_step_up_challenge_among_several(self) -> None:
        header = 'Basic realm="x", DPoP error="insufficient_user_authentication", max_age=60'
        c = parse_step_up_challenge(header)
        assert c is not None and c.scheme == "DPoP" and c.max_age == 60 and c.acr_values == []

    def test_other_errors_and_empty_headers_are_not_step_up(self) -> None:
        assert parse_step_up_challenge(None) is None
        assert parse_step_up_challenge("") is None
        assert parse_step_up_challenge('Bearer error="invalid_token"') is None
        assert parse_step_up_challenge("Bearer") is None

    def test_a_bad_max_age_is_dropped_not_guessed(self) -> None:
        for raw in ("-5", "1.5", "abc", "", "99999999999999999999x"):
            c = parse_step_up_challenge(
                f'Bearer error="insufficient_user_authentication", max_age="{raw}"'
            )
            assert c is not None and c.max_age is None

    def test_quoted_commas_and_escapes_stay_inside_the_value(self) -> None:
        c = parse_step_up_challenge(
            'Bearer error_description="a, b \\"c\\"", error="insufficient_user_authentication"'
        )
        assert c is not None and c.error_description == 'a, b "c"'

    def test_param_names_are_case_insensitive(self) -> None:
        c = parse_step_up_challenge('Bearer Error="insufficient_user_authentication", MAX_AGE="0"')
        assert c is not None and c.max_age == 0

    def test_step_up_params_validate(self) -> None:
        assert step_up_params(["a", "b"], 0) == {"acr_values": "a b", "max_age": "0"}
        assert step_up_params("a b") == {"acr_values": "a b"}
        assert step_up_params() == {}
        for bad in (-1, True, 1.5):
            with pytest.raises(ValueError):
                step_up_params(max_age=bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            step_up_params(["has space"])
        with pytest.raises(ValueError):
            step_up_params([""])

    def test_acr_ordering_is_weakest_first_and_unknown_never_satisfies(self) -> None:
        mfa = "urn:theauth:acr:mfa"
        phr = "urn:theauth:acr:phishing-resistant"
        assert acr_satisfies(phr, mfa)
        assert acr_satisfies(mfa, mfa)
        assert not acr_satisfies(mfa, phr)
        assert acr_satisfies(mfa, [phr, mfa])
        assert not acr_satisfies(None, mfa)
        assert not acr_satisfies("urn:other:strong", mfa)
        assert not acr_satisfies(phr, "urn:other:strong")

    def test_freshness(self) -> None:
        assert auth_is_fresh(1000, 300, now=1300)
        assert not auth_is_fresh(1000, 300, now=1301)
        assert not auth_is_fresh(None, 300, now=1)
        assert not auth_is_fresh(2000, 300, now=1000)
        assert auth_is_fresh(1005, 300, now=1000, skew=10)

    @respx.mock
    def test_401_challenge_raises_step_up_required_with_the_challenge(self) -> None:
        respx.post(f"{BASE_URL}/approvals/a1/approve").mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": self.HEADER},
                json={"error": {"code": "STEP_UP_REQUIRED", "message": "needs a stronger sign-in"}},
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            with pytest.raises(StepUpRequiredError) as caught:
                client.approvals.approve("a1")
        assert isinstance(caught.value, AuthenticationError)
        assert caught.value.status_code == 401 and caught.value.code == "STEP_UP_REQUIRED"
        assert caught.value.challenge is not None and caught.value.challenge.max_age == 300

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_client_raises_the_same_error(self) -> None:
        respx.post(f"{BASE_URL}/approvals/a1/approve").mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": self.HEADER},
                json={"error": "insufficient_user_authentication"},
            )
        )
        async with TheAuthClient(BASE_URL, token="t") as client:
            with pytest.raises(StepUpRequiredError) as caught:
                await client.approvals.approve("a1")
        assert caught.value.challenge is not None

    @respx.mock
    def test_error_code_without_a_header_still_raises_with_no_challenge(self) -> None:
        respx.post(f"{BASE_URL}/approvals/a1/approve").mock(
            return_value=httpx.Response(
                401, json={"error": {"code": "STEP_UP_REQUIRED", "message": "again"}}
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            with pytest.raises(StepUpRequiredError) as caught:
                client.approvals.approve("a1")
        assert caught.value.challenge is None

    @respx.mock
    def test_a_plain_401_is_not_a_step_up(self) -> None:
        respx.post(f"{BASE_URL}/approvals/a1/approve").mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                json={"error": {"code": "UNAUTHORIZED", "message": "no"}},
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            with pytest.raises(AuthenticationError) as caught:
                client.approvals.approve("a1")
        assert not isinstance(caught.value, StepUpRequiredError)


AGENT_ROW: Dict[str, Any] = {
    "id": "a1",
    "ownerId": "u1",
    "name": "bot",
    "type": "autonomous",
    "token": "ta_x",
    "permissions": [],
    "status": "active",
    "expiresAt": None,
    "cnf": {"jkt": "A" * 43},
    "createdAt": "2030-01-01T00:00:00.000Z",
    "updatedAt": "2030-01-01T00:00:00.000Z",
}


class TestConfirmation:
    @respx.mock
    def test_create_sends_cnf_and_reads_it_back(self) -> None:
        route = respx.post(f"{BASE_URL}/agents").mock(
            return_value=httpx.Response(201, json={"data": AGENT_ROW})
        )
        prover = DPoPProver()
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            agent = client.agents.create(
                CreateAgentInput("u1", "bot", "autonomous", [read("db:*")], cnf=dpop_confirmation(prover))
            )
        assert body_of(route)["cnf"] == {"jkt": prover.thumbprint()}
        assert agent.cnf == {"jkt": "A" * 43}

    @respx.mock
    def test_create_without_cnf_sends_none(self) -> None:
        route = respx.post(f"{BASE_URL}/agents").mock(
            return_value=httpx.Response(201, json={"data": {**AGENT_ROW, "cnf": None}})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            agent = client.agents.create(CreateAgentInput("u1", "bot", "autonomous", [read("db:*")]))
        assert "cnf" not in body_of(route)
        assert agent.cnf is None

    @respx.mock
    def test_rotate_keeps_changes_or_removes_the_binding(self) -> None:
        route = respx.post(f"{BASE_URL}/agents/a1/rotate").mock(
            return_value=httpx.Response(200, json={"data": AGENT_ROW})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            client.agents.rotate("a1")
            assert route.calls.last.request.content == b""
            client.agents.rotate("a1", cnf={"jkt": "B" * 43})
            assert body_of(route) == {"cnf": {"jkt": "B" * 43}}
            client.agents.rotate("a1", cnf=None)
            assert body_of(route) == {"cnf": None}

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_rotate_matches(self) -> None:
        route = respx.post(f"{BASE_URL}/agents/a1/rotate").mock(
            return_value=httpx.Response(200, json={"data": AGENT_ROW})
        )
        async with TheAuthClient(BASE_URL, token="t") as client:
            await client.agents.rotate("a1", cnf=None)
        assert body_of(route) == {"cnf": None}

    def test_dpop_thumbprint_is_rfc_7638(self) -> None:
        prover = DPoPProver()
        j = prover.public_jwk
        canonical = json.dumps(
            {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}, separators=(",", ":")
        )
        expected = _b64(hashlib.sha256(canonical.encode()).digest())
        assert dpop_confirmation(prover) == {"jkt": expected}

    def test_mtls_confirmation_is_the_der_sha256(self) -> None:
        der = b"not a real certificate, only bytes"
        assert mtls_confirmation(der) == {"x5t#S256": _b64(hashlib.sha256(der).digest())}

    def test_malformed_thumbprints_are_refused_early(self) -> None:
        from theauth import jkt_confirmation, x5t_confirmation

        for bad in ("", "short", "A" * 44, "A" * 42 + "="):
            with pytest.raises(ValueError):
                jkt_confirmation(bad)
            with pytest.raises(ValueError):
                x5t_confirmation(bad)


class TestIntrospectionCnf:
    def test_reads_both_binding_members(self) -> None:
        from theauth import IntrospectionResponse

        bound = IntrospectionResponse.from_dict(
            {"active": True, "cnf": {"jkt": "J" * 43, "x5t#S256": "X" * 43}}
        )
        assert bound.jkt == "J" * 43 and bound.x5t_s256 == "X" * 43
        plain = IntrospectionResponse.from_dict({"active": True})
        assert plain.jkt is None and plain.x5t_s256 is None


class TestProvenanceInputs:
    @respx.mock
    def test_inputs_go_in_the_body(self) -> None:
        route = respx.post(f"{BASE_URL}/authorize").mock(
            return_value=httpx.Response(
                200, json={"data": {"allowed": True, "auditId": "au1", "code": "allowed"}}
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            client.agents.authorize(
                "a1",
                AuthorizeRequest(
                    "execute",
                    "mcp:x:y",
                    inputs=[
                        ProvenanceInput("user_message", id="m1", content="hello"),
                        ProvenanceInput("tool_output", hash="a" * 64, hash_version=2),
                    ],
                ),
            )
        assert body_of(route)["inputs"] == [
            {"kind": "user_message", "id": "m1", "content": "hello"},
            {"kind": "tool_output", "hash": "a" * 64, "hashVersion": 2},
        ]

    @respx.mock
    def test_no_inputs_means_no_key(self) -> None:
        route = respx.post(f"{BASE_URL}/authorize/token").mock(
            return_value=httpx.Response(
                200, json={"data": {"allowed": True, "auditId": "au1", "code": "allowed"}}
            )
        )
        with TheAuthSyncClient(BASE_URL) as client:
            client.auth.authorize_by_token("ta_x", AuthorizeRequest("read", "db:x"))
        assert "inputs" not in body_of(route)

    def test_header_is_base64url_json_without_padding(self) -> None:
        value = encode_inputs_header([ProvenanceInput("retrieved_document", id="https://e.org/ü")])
        assert "=" not in value and "+" not in value and "/" not in value
        assert json.loads(_unb64(value)) == [{"kind": "retrieved_document", "id": "https://e.org/ü"}]
        assert inputs_headers([ProvenanceInput("agent")]) == {
            "TheAuth-Inputs": encode_inputs_header([ProvenanceInput("agent")])
        }

    def test_header_limits_match_the_server(self) -> None:
        with pytest.raises(ValueError):
            encode_inputs_header([ProvenanceInput("agent")] * 33)
        encode_inputs_header([ProvenanceInput("agent")] * 32)
        with pytest.raises(ValueError):
            encode_inputs_header([ProvenanceInput("user_message", content="x" * 7000)])


class TestDeviceAssertion:
    def decode(self, jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
        h, p, s = jwt.split(".")
        return (
            json.loads(_unb64(h)),
            json.loads(_unb64(p)),
            f"{h}.{p}".encode(),
            _unb64(s),
        )

    def test_layout_matches_the_design_doc(self) -> None:
        signer = DeviceAssertionSigner("dev_1", now=lambda: 1_800_000_000.9)
        header, payload, _, _ = self.decode(signer.sign())
        assert header == {"alg": "ES256", "typ": "device-assertion+jwt", "kid": signer.kid}
        assert payload["iss"] == payload["sub"] == "dev_1"
        assert payload["aud"] == "theauth"
        assert payload["iat"] == 1_800_000_000 and payload["exp"] == 1_800_000_060
        assert 16 <= len(payload["jti"]) <= 256

    def test_signature_verifies_with_the_public_jwk(self) -> None:
        signer = DeviceAssertionSigner("dev_1")
        _, _, signing_input, sig = self.decode(signer.sign())
        j = signer.public_jwk
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_unb64(j["x"]), "big"), int.from_bytes(_unb64(j["y"]), "big"), ec.SECP256R1()
        )
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        numbers.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))

    def test_kid_is_the_rfc_7638_thumbprint(self) -> None:
        signer = DeviceAssertionSigner("dev_1")
        j = signer.public_jwk
        canonical = json.dumps(
            {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]}, separators=(",", ":")
        )
        assert signer.kid == _b64(hashlib.sha256(canonical.encode()).digest())

    def test_every_assertion_has_a_fresh_jti(self) -> None:
        signer = DeviceAssertionSigner("dev_1")
        jtis = {self.decode(signer.sign())[1]["jti"] for _ in range(50)}
        assert len(jtis) == 50

    def test_custom_audience_and_bounds(self) -> None:
        signer = DeviceAssertionSigner("dev_1", audience="fleet", lifetime=300, now=lambda: 10)
        payload = self.decode(signer.sign())[1]
        assert payload["aud"] == "fleet" and payload["exp"] - payload["iat"] == 300
        for bad in (0, 301, -1):
            with pytest.raises(ValueError):
                DeviceAssertionSigner("dev_1", lifetime=bad)
        with pytest.raises(ValueError):
            DeviceAssertionSigner("")

    def test_key_first_then_bind_the_id(self) -> None:
        signer = DeviceAssertionSigner()
        with pytest.raises(ValueError):
            signer.sign()
        with pytest.raises(ValueError):
            signer.bind("")
        jwk = signer.public_jwk
        assert signer.bind("dev_9") is signer
        _, payload, _, _ = self.decode(signer.sign())
        assert payload["iss"] == "dev_9" and signer.public_jwk == jwk

    def test_rejects_keys_that_are_not_p256(self) -> None:
        with pytest.raises(ValueError):
            DeviceAssertionSigner("dev_1", ec.generate_private_key(ec.SECP384R1()))
        with pytest.raises(ValueError):
            DeviceAssertionSigner("dev_1", "not a key")

    def test_a_private_jwk_never_leaves_the_process(self) -> None:
        with pytest.raises(ValueError):
            CredentialSpec.from_jwk({"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret"})
        signer = DeviceAssertionSigner("dev_1")
        assert "d" not in signer.public_jwk
        assert CredentialSpec.from_jwk(signer.public_jwk).to_dict()["jwk"] == signer.public_jwk


class TestDevices:
    @respx.mock
    def test_register_sends_the_credential_and_reads_the_one_time_secret(self) -> None:
        route = respx.post(f"{BASE_URL}/devices").mock(
            return_value=httpx.Response(
                201,
                json={"data": {"device": DEVICE_ROW, "credential": {**CRED_ROW, "secret": "tdk_abc"}}},
            )
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            result = client.devices.register(
                RegisterDeviceInput(
                    "user_1",
                    "Pump 4",
                    kind="sensor",
                    hardware_id="hw-77",
                    groups=["plant-a"],
                    permissions=[read("mqtt:plant/a/#")],
                    credential=CredentialSpec.psk(),
                )
            )
        sent = body_of(route)
        assert sent["credential"] == {"kind": "psk"} and sent["hardwareId"] == "hw-77"
        assert sent["permissions"] == [{"resource": "mqtt:plant/a/#", "actions": ["read"]}]
        assert result.device.agent_id == "agt_1" and result.device.permissions[0].resource == "mqtt:plant/a/#"
        assert result.credential is not None and result.credential.secret == "tdk_abc"

    @respx.mock
    def test_list_get_update_suspend_resume_revoke(self) -> None:
        lst = respx.get(f"{BASE_URL}/devices").mock(
            return_value=httpx.Response(200, json={"data": [DEVICE_ROW]})
        )
        respx.get(f"{BASE_URL}/devices/dev_1").mock(
            return_value=httpx.Response(200, json={"data": DEVICE_ROW})
        )
        respx.get(f"{BASE_URL}/devices/nope").mock(
            return_value=httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "no"}})
        )
        patch = respx.patch(f"{BASE_URL}/devices/dev_1").mock(
            return_value=httpx.Response(200, json={"data": DEVICE_ROW})
        )
        susp = respx.post(f"{BASE_URL}/devices/dev_1/suspend").mock(
            return_value=httpx.Response(200, json={"data": {**DEVICE_ROW, "status": "suspended"}})
        )
        respx.post(f"{BASE_URL}/devices/dev_1/resume").mock(
            return_value=httpx.Response(200, json={"data": DEVICE_ROW})
        )
        rev = respx.delete(f"{BASE_URL}/devices/dev_1").mock(
            return_value=httpx.Response(200, json={"data": {"revokedDelegations": ["d1", "d2"]}})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            devices = client.devices.list(DeviceFilters(owner_id="user_1", status="active", limit=10))
            assert [d.id for d in devices] == ["dev_1"]
            query = dict(lst.calls.last.request.url.params)
            assert query == {"ownerId": "user_1", "status": "active", "limit": "10"}
            assert client.devices.get("dev_1") is not None
            assert client.devices.get("nope") is None
            client.devices.update("dev_1", UpdateDeviceInput(name="Pump 5", groups=["b"]))
            assert body_of(patch) == {"name": "Pump 5", "groups": ["b"]}
            assert client.devices.suspend("dev_1", "stolen").status == "suspended"
            assert body_of(susp) == {"reason": "stolen"}
            client.devices.suspend("dev_1")
            assert susp.calls.last.request.content == b""
            assert client.devices.resume("dev_1").status == "active"
            assert client.devices.revoke("dev_1") == ["d1", "d2"]
            assert rev.called

    @respx.mock
    def test_ids_are_path_escaped(self) -> None:
        route = respx.get(f"{BASE_URL}/devices/a%2Fb%3Fc").mock(
            return_value=httpx.Response(200, json={"data": DEVICE_ROW})
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            client.devices.get("a/b?c")
        assert route.called

    @respx.mock
    def test_credentials_bundle_stats_and_enrollment_tokens(self) -> None:
        add = respx.post(f"{BASE_URL}/devices/dev_1/credentials").mock(
            return_value=httpx.Response(201, json={"data": {**CRED_ROW, "kind": "x509", "lookup": "t"}})
        )
        delc = respx.delete(f"{BASE_URL}/devices/dev_1/credentials/cred_1").mock(
            return_value=httpx.Response(204)
        )
        bundle = respx.post(f"{BASE_URL}/devices/dev_1/bundle").mock(
            return_value=httpx.Response(200, json={"data": {"token": "a.b.c", "claims": {"exp": 1}}})
        )
        stats = respx.get(f"{BASE_URL}/devices/stats").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "total": 5,
                        "active": 3,
                        "suspended": 1,
                        "revoked": 1,
                        "seenLastHour": 2,
                        "seenLastDay": 3,
                        "neverSeen": 1,
                    }
                },
            )
        )
        tok = respx.post(f"{BASE_URL}/devices/enrollment-tokens").mock(
            return_value=httpx.Response(
                201,
                json={
                    "data": {
                        "id": "e1",
                        "kind": "bulk",
                        "token": "tde_x",
                        "ownerId": "user_1",
                        "maxUses": 50,
                        "expiresAt": "2030-01-02T00:00:00.000Z",
                    }
                },
            )
        )
        deltok = respx.delete(f"{BASE_URL}/devices/enrollment-tokens/e1").mock(
            return_value=httpx.Response(204)
        )
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            cred = client.devices.add_credential("dev_1", CredentialSpec.x509("T" * 43))
            assert body_of(add) == {"kind": "x509", "thumbprint": "T" * 43} and cred.kind == "x509"
            client.devices.revoke_credential("dev_1", "cred_1")
            assert delc.called
            assert client.devices.issue_bundle("dev_1", 600).token == "a.b.c"
            assert body_of(bundle) == {"ttlSeconds": 600}
            s = client.devices.stats("user_1")
            assert (s.total, s.seen_last_hour, s.never_seen) == (5, 2, 1)
            assert dict(stats.calls.last.request.url.params) == {"ownerId": "user_1"}
            made = client.devices.create_enrollment_token(
                EnrollmentTokenInput("user_1", "bulk", max_uses=50, ttl_seconds=3600, groups=["g"])
            )
            assert made.token == "tde_x" and made.max_uses == 50
            assert body_of(tok) == {
                "ownerId": "user_1",
                "kind": "bulk",
                "maxUses": 50,
                "ttlSeconds": 3600,
                "groups": ["g"],
            }
            client.devices.revoke_enrollment_token("e1")
            assert deltok.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_register_and_stats(self) -> None:
        respx.post(f"{BASE_URL}/devices").mock(
            return_value=httpx.Response(201, json={"data": {"device": DEVICE_ROW}})
        )
        async with TheAuthClient(BASE_URL, token="t") as client:
            result = await client.devices.register(RegisterDeviceInput("user_1", "Pump 4"))
        assert result.credential is None and result.device.id == "dev_1"

    @respx.mock
    def test_device_enroll_needs_no_credential_and_nonce_parses(self) -> None:
        enroll = respx.post(f"{BASE_URL}/device/enroll").mock(
            return_value=httpx.Response(
                201, json={"data": {"device": DEVICE_ROW, "credential": CRED_ROW}}
            )
        )
        nonce = respx.post(f"{BASE_URL}/device/attestation-nonce").mock(
            return_value=httpx.Response(
                200, json={"data": {"nonce": "n1", "expiresAt": "2030-01-01T00:05:00.000Z"}}
            )
        )
        with TheAuthSyncClient(BASE_URL) as client:
            assert client.device.attestation_nonce().nonce == "n1"
            reg = client.device.enroll(
                EnrollDeviceInput(
                    "ABCDE-FGHJK",
                    "Pump 4",
                    CredentialSpec.psk(),
                    hardware_id="hw-77",
                    evidence="ev",
                    nonce="n1",
                )
            )
        assert reg.device.id == "dev_1"
        assert "authorization" not in enroll.calls.last.request.headers
        assert body_of(enroll) == {
            "token": "ABCDE-FGHJK",
            "name": "Pump 4",
            "credential": {"kind": "psk"},
            "hardwareId": "hw-77",
            "evidence": "ev",
            "nonce": "n1",
        }
        assert nonce.called

    @respx.mock
    def test_device_authorize_uses_the_device_credential_not_the_client_token(self) -> None:
        route = respx.post(f"{BASE_URL}/device/authorize").mock(
            return_value=httpx.Response(
                403,
                json={"data": {"allowed": False, "auditId": "au1", "code": "device_suspended"}},
            )
        )
        with TheAuthSyncClient(BASE_URL, token="admin-token") as client:
            result = client.device.authorize(
                "tdk_secret",
                AuthorizeRequest("publish", "mqtt:plant/a/t1", inputs=[ProvenanceInput("agent")]),
            )
        assert not result.allowed and result.code == "device_suspended"
        assert route.calls.last.request.headers["authorization"] == "Bearer tdk_secret"
        assert "agentId" not in body_of(route) and body_of(route)["inputs"] == [{"kind": "agent"}]

    @respx.mock
    def test_a_signer_makes_a_new_assertion_per_call(self) -> None:
        route = respx.post(f"{BASE_URL}/device/authorize").mock(
            return_value=httpx.Response(
                200, json={"data": {"allowed": True, "auditId": "au1", "code": "allowed"}}
            )
        )
        signer = DeviceAssertionSigner("dev_1")
        with TheAuthSyncClient(BASE_URL) as client:
            client.device.authorize(signer, AuthorizeRequest("read", "x"))
            first = route.calls.last.request.headers["authorization"]
            client.device.authorize(signer, AuthorizeRequest("read", "x"))
            second = route.calls.last.request.headers["authorization"]
        assert first.startswith("Bearer ") and first != second

    @respx.mock
    def test_a_bad_device_credential_is_a_401_result(self) -> None:
        respx.post(f"{BASE_URL}/device/authorize").mock(
            return_value=httpx.Response(
                401, json={"data": {"allowed": False, "auditId": "", "code": "invalid_token"}}
            )
        )
        with TheAuthSyncClient(BASE_URL) as client:
            assert not client.device.authorize("tdk_bad", AuthorizeRequest("a", "b")).allowed

    def test_empty_credentials_are_refused_before_the_request(self) -> None:
        with TheAuthSyncClient(BASE_URL) as client:
            with pytest.raises(ValueError):
                client.device.bundle("")

    @respx.mock
    def test_bundle_and_jwks(self) -> None:
        respx.get(f"{BASE_URL}/device/bundle").mock(
            return_value=httpx.Response(200, json={"data": {"token": "h.p.s", "claims": {}}})
        )
        respx.get(f"{BASE_URL}/device/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [{"kty": "EC"}]})
        )
        with TheAuthSyncClient(BASE_URL) as client:
            assert client.device.bundle("tdk_x").token == "h.p.s"
            assert client.device.jwks() == {"keys": [{"kty": "EC"}]}


class TestRouteContract:
    @respx.mock
    def test_every_new_route_exists_in_openapi_json(self) -> None:
        respx.route().mock(return_value=httpx.Response(200, json={}))
        with TheAuthSyncClient(BASE_URL, token="t") as client:
            calls = [
                lambda: client.devices.register(RegisterDeviceInput("o", "n")),
                lambda: client.devices.list(),
                lambda: client.devices.get("x"),
                lambda: client.devices.update("x", UpdateDeviceInput(name="n")),
                lambda: client.devices.suspend("x"),
                lambda: client.devices.resume("x"),
                lambda: client.devices.revoke("x"),
                lambda: client.devices.add_credential("x", CredentialSpec.psk()),
                lambda: client.devices.revoke_credential("x", "y"),
                lambda: client.devices.issue_bundle("x"),
                lambda: client.devices.stats(),
                lambda: client.devices.create_enrollment_token(EnrollmentTokenInput("o", "claim")),
                lambda: client.devices.revoke_enrollment_token("x"),
                lambda: client.device.enroll(EnrollDeviceInput("t", "n", CredentialSpec.psk())),
                lambda: client.device.attestation_nonce(),
                lambda: client.device.authorize("tdk_x", AuthorizeRequest("a", "b")),
                lambda: client.device.bundle("tdk_x"),
                lambda: client.device.jwks(),
            ]
            for call in calls:
                try:
                    call()
                except (KeyError, TypeError):
                    pass  # empty bodies do not decode, only the request matters here
        doc = json.loads(OPENAPI.read_text())
        patterns: List[Tuple[str, "re.Pattern[str]"]] = []
        for path, methods in doc["paths"].items():
            regex = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$"
            for method in methods:
                patterns.append((method.upper(), re.compile(regex)))
        seen = respx.calls
        assert len(seen) == len(calls)
        prefix = httpx.URL(BASE_URL).path
        for call_record in seen:
            path = call_record.request.url.raw_path.decode().split("?")[0][len(prefix):]
            method = call_record.request.method
            assert any(m == method and p.match(path) for m, p in patterns), (
                f"{method} {path} is not in openapi.json"
            )
