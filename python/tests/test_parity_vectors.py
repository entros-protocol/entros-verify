"""Cross-language parity test runner against ../spec/vectors/agent-permit-v2/*.json."""

from __future__ import annotations

import asyncio
import base64
import json
import math
from pathlib import Path
from typing import cast

import httpx
import pytest

from entros_verify import (
    CanonicalizationError,
    DpopVerificationInput,
    EntrosClient,
    InMemoryPermitNonceStoreV2,
    IssuedPermitResponse,
    JsonObject,
    PolicyV2,
    RefusalCode,
    StaticJwksProvider,
    StepUpRequiredResponse,
    WebAuthnAssertionInput,
    canonicalize_action_v2,
    canonicalize_jcs,
    derive_webauthn_challenge,
    hash_action_v2,
    verify_agent_permit_v2,
    verify_agent_permit_v2_async,
    verify_scitt_receipt,
    verify_voice_liveness_verdict,
    verify_webauthn_assertion,
)
from entros_verify.adapters.fastmcp import (
    RequestStateClaims,
    sign_request_state,
    verify_request_state,
)
from entros_verify.scitt import ScittVerificationError
from entros_verify.voice import VoiceCodec

VECTORS_DIR = Path(__file__).resolve().parents[2] / "spec" / "vectors" / "agent-permit-v2"


def _load_json(filename: str) -> dict[str, object]:
    path = VECTORS_DIR / filename
    assert path.exists(), f"Missing shared parity vector file: {path}"
    loaded: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def test_jcs_valid_parity_vectors() -> None:
    data = _load_json("jcs-vectors.json")
    valid_cases = cast(list[dict[str, object]], data["valid"])
    assert len(valid_cases) >= 5

    for case in valid_cases:
        vec_id = cast(str, case["id"])
        action_input = cast(dict[str, object], case["input"])
        expected_canonical = cast(str, case["expected_canonical_json"])
        expected_digest = cast(str, case["expected_request_digest"])

        assert canonicalize_action_v2(action_input) == expected_canonical, vec_id
        assert hash_action_v2(action_input) == expected_digest, vec_id

        if "raw_json" in case:
            parsed_raw = cast(dict[str, object], json.loads(cast(str, case["raw_json"])))
            assert canonicalize_action_v2(parsed_raw) == expected_canonical, f"{vec_id} (raw_json)"
            assert hash_action_v2(parsed_raw) == expected_digest, f"{vec_id} (raw_json)"


def test_jcs_reject_parity_vectors() -> None:
    data = _load_json("jcs-vectors.json")
    reject_cases = cast(list[dict[str, object]], data["reject"])
    assert len(reject_cases) >= 11

    for case in reject_cases:
        vec_id = cast(str, case["id"])
        case_type = cast(str, case["case_type"])

        if case_type in ("lone_high_surrogate", "lone_low_surrogate"):
            code_unit = int(cast(str, case["code_unit_hex"]), 16)
            bad_str = f"prefix-{chr(code_unit)}-suffix"
            with pytest.raises(CanonicalizationError, match="surrogate"):
                canonicalize_jcs({"s": bad_str})
            with pytest.raises(CanonicalizationError, match="surrogate"):
                hash_action_v2(
                    {
                        "kind": "mcp.tool_call",
                        "server": "unicode-mcp",
                        "tool": "check",
                        "arguments": {"bad": bad_str},
                    }
                )
        elif case_type == "non_finite_number":
            kind = cast(str, case["value_kind"])
            val = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[kind]
            with pytest.raises(CanonicalizationError, match="finite"):
                canonicalize_jcs({"n": val})
        elif case_type == "max_depth_exceeded":
            depth = cast(int, case["depth"])
            nested: dict[str, object] = {"leaf": 1}
            for _ in range(depth):
                nested = {"a": nested}
            with pytest.raises(CanonicalizationError, match="depth"):
                canonicalize_jcs(nested)
        elif case_type == "action_validation":
            bad_action = cast(dict[str, object], case["input"])
            with pytest.raises(CanonicalizationError):
                hash_action_v2(bad_action)
        else:
            pytest.fail(f"Unhandled JCS reject vector case_type={case_type!r} ({vec_id})")


def test_jws_eddsa_valid_parity_vectors() -> None:
    data = _load_json("jws-eddsa-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))
    now = cast(int, data["now_seconds"])

    voice_case = cast(dict[str, object], data["valid_voice_verdict"])
    voice_res = verify_voice_liveness_verdict(
        cast(str, voice_case["jws"]),
        jwks=jwks,
        now_seconds=now,
    )
    assert voice_res.ok, f"valid_voice_verdict failed: {voice_res}"
    assert voice_res.verdict is not None
    assert voice_res.verdict.model_dump() == voice_case["expected_claims"]

    abstain_case = cast(dict[str, object], data["valid_voice_abstain"])
    abstain_res = verify_voice_liveness_verdict(
        cast(str, abstain_case["jws"]),
        jwks=jwks,
        now_seconds=now,
    )
    assert abstain_res.ok, f"valid_voice_abstain failed: {abstain_res}"
    assert abstain_res.verdict is not None
    assert abstain_res.verdict.abstain_reason == "packet_loss"
    assert abstain_res.verdict.model_dump() == abstain_case["expected_claims"]

    permit_case = cast(dict[str, object], data["valid_agent_permit"])
    expected_claims = cast(dict[str, object], permit_case["expected_claims"])
    policy = PolicyV2(
        policy_id=cast(str, expected_claims["policy_id"]),
        allowed_assurance_tiers=["voice_plus_passkey"],
        required_modalities=["voice_liveness", "webauthn_uv"],
        max_evidence_age_seconds=120,
        max_permit_lifetime_seconds=300,
        require_continuity=True,
        require_dpop=False,
        require_scitt_receipt=True,
    )
    permit_res = verify_agent_permit_v2(
        cast(str, permit_case["jws"]),
        policy=policy,
        expected_audience=cast(str, expected_claims["aud"]),
        expected_request_digest=cast(str, expected_claims["request_digest"]),
        jwks=jwks,
        now_seconds=now,
    )
    assert permit_res.ok, f"valid_agent_permit failed: {permit_res}"
    assert permit_res.permit is not None
    assert permit_res.permit.model_dump(exclude_none=False)["jti"] == expected_claims["jti"]


def test_jws_eddsa_invalid_parity_vectors() -> None:
    data = _load_json("jws-eddsa-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))
    now = cast(int, data["now_seconds"])
    invalid_cases = cast(list[dict[str, object]], data["invalid_cases"])
    assert len(invalid_cases) >= 12

    default_policy = PolicyV2(
        policy_id="wire-transfer-high-v2",
        allowed_assurance_tiers=["voice_plus_passkey"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        max_permit_lifetime_seconds=300,
    )

    for case in invalid_cases:
        vec_id = cast(str, case["id"])
        expected_typ = cast(str, case["expected_typ"])
        jws = cast(str, case["jws"])
        expected_reason = RefusalCode(cast(str, case["expected_reason"]))

        if expected_typ == "entros-voice-liveness+jwt":
            res = verify_voice_liveness_verdict(jws, jwks=jwks, now_seconds=now)
            assert not res.ok, f"{vec_id} unexpectedly succeeded"
            assert res.reason == expected_reason, f"{vec_id}: got {res.reason}, want {expected_reason}"
        else:
            permit_res = verify_agent_permit_v2(
                jws,
                policy=default_policy,
                expected_audience="https://mcp.acme-bank.example/v1/mcp",
                expected_request_digest="46cce3c855fad84ea66dc03884f83f836cbb17cf9171e41ecb0789f558265be4",
                jwks=jwks,
                now_seconds=now,
            )
            assert not permit_res.ok, f"{vec_id} unexpectedly succeeded"
            assert permit_res.decision == "deny", vec_id
            assert permit_res.reason == expected_reason, (
                f"{vec_id}: got {permit_res.reason}, want {expected_reason}"
            )


def test_webauthn_p256_parity_vectors() -> None:
    data = _load_json("webauthn-p256-vectors.json")
    deriv = cast(dict[str, object], data["challenge_derivation"])
    jti = cast(str, deriv["jti"])
    req_digest = cast(str, deriv["request_digest"])

    chal_bytes, chal_b64 = derive_webauthn_challenge(jti, req_digest)
    assert chal_bytes.hex() == deriv["expected_challenge_hex"]
    assert chal_b64 == deriv["expected_challenge_b64url"]

    pub_info = cast(dict[str, object], data["public_key"])
    pub_sec1_b64 = cast(str, pub_info["uncompressed_b64url"])
    pub_jwk = cast(JsonObject, pub_info["jwk"])
    expected_rp_id = cast(str, data["expected_rp_id"])
    expected_origin = cast(str, data["expected_origin"])

    valid_cases = cast(list[dict[str, object]], data["valid"])
    assert len(valid_cases) == 2
    assert any(c["is_high_s"] is True for c in valid_cases)
    assert any(c["is_high_s"] is False for c in valid_cases)

    for case in valid_cases:
        vec_id = cast(str, case["id"])
        raw = cast(dict[str, object], case["assertion"])
        expected_digest = cast(str, case["expected_assertion_digest"])
        stored_count = cast(int | None, case.get("stored_sign_count"))

        for pub_repr in (pub_sec1_b64, pub_jwk):
            res = verify_webauthn_assertion(
                WebAuthnAssertionInput(
                    authenticator_data=cast(str, raw["authenticator_data"]),
                    client_data_json=cast(str, raw["client_data_json"]),
                    signature=cast(str, raw["signature"]),
                    credential_id=cast(str, raw["credential_id"]),
                    public_key=pub_repr,
                    expected_rp_id=expected_rp_id,
                    expected_origin=expected_origin,
                    stored_sign_count=stored_count,
                ),
                jti=jti,
                request_digest=req_digest,
                expected_assertion_digest=expected_digest,
            )
            assert res.ok, f"{vec_id} failed: {res}"
            assert res.assertion_digest == expected_digest

    invalid_cases = cast(list[dict[str, object]], data["invalid"])
    assert len(invalid_cases) == 10
    for case in invalid_cases:
        vec_id = cast(str, case["id"])
        raw = cast(dict[str, object], case["assertion"])
        expected_reason = RefusalCode(cast(str, case["expected_reason"]))
        stored_count = cast(int | None, case.get("stored_sign_count"))
        res = verify_webauthn_assertion(
            WebAuthnAssertionInput(
                authenticator_data=cast(str, raw["authenticator_data"]),
                client_data_json=cast(str, raw["client_data_json"]),
                signature=cast(str, raw["signature"]),
                credential_id=cast(str, raw["credential_id"]),
                public_key=pub_sec1_b64,
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                stored_sign_count=stored_count,
            ),
            jti=jti,
            request_digest=req_digest,
        )
        assert not res.ok, f"{vec_id} unexpectedly passed"
        assert res.reason == expected_reason, f"{vec_id}: got {res.reason}, want {expected_reason}"


def test_scitt_receipt_parity_vectors() -> None:
    data = _load_json("scitt-receipt-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))

    valid_cases = cast(list[dict[str, object]], data["valid"])
    assert len(valid_cases) == 2
    for case in valid_cases:
        vec_id = cast(str, case["id"])
        receipt_b64 = cast(str, case["receipt_b64url"])
        receipt_bytes = bytes.fromhex(cast(str, case["receipt_hex"]))

        for receipt_input in (receipt_b64, receipt_bytes):
            res = verify_scitt_receipt(receipt_input, jwks=jwks)
            assert res.merkle_root_hex == case["expected_merkle_root_hex"], vec_id
            assert res.tree_size == case["expected_tree_size"], vec_id
            assert res.leaf_index == case["expected_leaf_index"], vec_id
            assert res.kid == case["expected_kid"], vec_id
            assert res.payload.model_dump(by_alias=True) == case["expected_statement"], vec_id

    invalid_cases = cast(list[dict[str, object]], data["invalid"])
    assert len(invalid_cases) == 10
    for case in invalid_cases:
        vec_id = cast(str, case["id"])
        receipt_b64 = cast(str, case["receipt_b64url"])
        with pytest.raises(ScittVerificationError):
            verify_scitt_receipt(receipt_b64, jwks=jwks)
        assert case["expected_reason"] == "scitt_receipt_invalid", vec_id


def test_policy_v2_matrix_parity_vectors() -> None:
    data = _load_json("policy-v2-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))
    cases = cast(list[dict[str, object]], data["cases"])
    assert len(cases) >= 20

    for case in cases:
        vec_id = cast(str, case["id"])
        policy = PolicyV2.model_validate(case["policy"])
        action = cast(dict[str, object], case["action"])
        expected_aud = cast(str, case["expected_audience"])
        now = cast(int, case["now_seconds"])
        permit_jws = cast(str, case["permit_jws"])
        expected_decision = cast(str, case["expected_decision"])
        expected_reason = cast(str, case["expected_reason"])

        dpop_input: DpopVerificationInput | None = None
        if "dpop_proof" in case and case["dpop_proof"] is not None:
            dpop_input = DpopVerificationInput(
                proof_jwt=cast(str, case["dpop_proof"]),
                htm=cast(str, case["dpop_htm"]),
                htu=cast(str, case["dpop_htu"]),
            )

        res = verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience=expected_aud,
            jwks=jwks,
            action=action,
            now_seconds=now,
            dpop=dpop_input,
        )
        assert res.decision == expected_decision, f"{vec_id}: got {res}, want {expected_decision}"
        if expected_decision == "allow":
            assert res.ok, vec_id
            assert res.reason is None, vec_id
        else:
            assert not res.ok, vec_id
            assert res.reason == RefusalCode(expected_reason), (
                f"{vec_id}: got {res.reason}, want {expected_reason}"
            )


def test_policy_v2_non_mutating_precheck_scenario() -> None:
    data = _load_json("policy-v2-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))
    scenario = cast(dict[str, object], data["non_mutating_precheck_scenario"])
    jti = cast(str, scenario["jti"])
    policy = PolicyV2.model_validate(scenario["policy"])
    expected_aud = cast(str, scenario["expected_audience"])
    now = cast(int, scenario["now_seconds"])

    store = InMemoryPermitNonceStoreV2()
    store.register(
        jti=jti,
        created_at=now - 40,
        expires_at=now + 260,
        aud=expected_aud,
        policy_id=policy.policy_id,
    )

    probes = cast(list[dict[str, object]], scenario["invalid_probes"])
    assert len(probes) >= 3
    for probe in probes:
        probe_id = cast(str, probe["id"])
        res = verify_agent_permit_v2(
            cast(str, probe["permit_jws"]),
            policy=policy,
            expected_audience=expected_aud,
            jwks=jwks,
            action=cast(dict[str, object], probe["action"]),
            now_seconds=now,
            dpop=DpopVerificationInput(
                proof_jwt=cast(str, probe["dpop_proof"]),
                htm=cast(str, probe["dpop_htm"]),
                htu=cast(str, probe["dpop_htu"]),
            ),
            nonce_store=store,
            require_registered_nonce=True,
        )
        assert not res.ok, probe_id
        assert res.reason == RefusalCode(cast(str, probe["expected_reason"])), probe_id
        # Pending nonce must remain completely unconsumed after every failed precheck probe.
        record = store.peek(jti)
        assert record is not None and record.consumed_at is None, f"{probe_id} mutated nonce!"

    final = cast(dict[str, object], scenario["final_valid_attempt"])
    final_res = verify_agent_permit_v2(
        cast(str, final["permit_jws"]),
        policy=policy,
        expected_audience=expected_aud,
        jwks=jwks,
        action=cast(dict[str, object], final["action"]),
        now_seconds=now,
        dpop=DpopVerificationInput(
            proof_jwt=cast(str, final["dpop_proof"]),
            htm=cast(str, final["dpop_htm"]),
            htu=cast(str, final["dpop_htu"]),
        ),
        nonce_store=store,
        require_registered_nonce=True,
    )
    assert final_res.ok and final_res.decision == "allow"
    consumed = store.peek(jti)
    assert consumed is not None and consumed.consumed_at == now


async def test_policy_v2_32_way_concurrent_replay_scenario() -> None:
    data = _load_json("policy-v2-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], data["jwks"]))
    scenario = cast(dict[str, object], data["concurrent_replay_scenario"])

    concurrency = cast(int, scenario["concurrency"])
    assert concurrency == 32
    jti = cast(str, scenario["jti"])
    policy = PolicyV2.model_validate(scenario["policy"])
    action = cast(dict[str, object], scenario["action"])
    expected_aud = cast(str, scenario["expected_audience"])
    now = cast(int, scenario["now_seconds"])
    permit_jws = cast(str, scenario["permit_jws"])
    dpop = DpopVerificationInput(
        proof_jwt=cast(str, scenario["dpop_proof"]),
        htm=cast(str, scenario["dpop_htm"]),
        htu=cast(str, scenario["dpop_htu"]),
    )

    store = InMemoryPermitNonceStoreV2()
    store.register(
        jti=jti,
        created_at=now - 40,
        expires_at=now + 260,
        aud=expected_aud,
        policy_id=policy.policy_id,
    )

    async def _attempt() -> tuple[str, RefusalCode | None]:
        res = await verify_agent_permit_v2_async(
            permit_jws,
            policy=policy,
            expected_audience=expected_aud,
            jwks=jwks,
            action=action,
            now_seconds=now,
            dpop=dpop,
            nonce_store=store,
            require_registered_nonce=True,
        )
        return res.decision, res.reason

    outcomes = await asyncio.gather(*(_attempt() for _ in range(concurrency)))
    allows = sum(1 for decision, _ in outcomes if decision == "allow")
    replayed = sum(
        1 for decision, reason in outcomes if decision == "deny" and reason == RefusalCode.NONCE_REPLAYED
    )
    assert allows == scenario["expected_allows"] == 1
    assert replayed == scenario["expected_nonce_replayed"] == 31


def test_wire_contracts_parity_vectors() -> None:
    wire = _load_json("wire-contracts.json")
    jws_data = _load_json("jws-eddsa-vectors.json")
    jwks = StaticJwksProvider(cast(dict[str, object], jws_data["jwks"]))
    jws_now = cast(int, jws_data["now_seconds"])
    valid_voice_jws = cast(str, cast(dict[str, object], jws_data["valid_voice_verdict"])["jws"])

    # 1. Cross-runtime MRTR requestState HMAC-SHA256 parity with TS and Rust.
    mrtr = cast(dict[str, object], wire["mrtr_request_state"])
    claims_raw = cast(dict[str, object], mrtr["claims"])
    claims = RequestStateClaims(
        v=cast(int, claims_raw["v"]),
        jti=cast(str, claims_raw["jti"]),
        request_digest=cast(str, claims_raw["request_digest"]),
        aud=cast(str, claims_raw["aud"]),
        policy_id=cast(str, claims_raw["policy_id"]),
        iat=cast(int, claims_raw["iat"]),
        exp=cast(int, claims_raw["exp"]),
    )
    secret = cast(str, mrtr["secret_utf8"]).encode("utf-8")
    token = sign_request_state(claims, secret)
    expected_mrtr_token = cast(str, mrtr["expected_token"])
    assert token == expected_mrtr_token

    verified = verify_request_state(
        expected_mrtr_token,
        secret,
        now_seconds=cast(int, mrtr["now_valid"]),
    )
    assert verified == claims

    expired = verify_request_state(
        expected_mrtr_token,
        secret,
        now_seconds=cast(int, mrtr["now_expired"]),
    )
    assert expired is None

    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_request_state(claims, cast(str, mrtr["short_secret_utf8"]).encode("utf-8"))

    # 2. Voice analyze standard Base64 audio_b64 + all codec mappings.
    va = cast(dict[str, object], wire["voice_analyze"])
    audio_bytes = bytes.fromhex(cast(str, va["audio_hex"]))
    assert base64.b64encode(audio_bytes).decode("ascii") == va["audio_b64_standard"]

    for mapping in cast(list[dict[str, object]], va["codec_mappings"]):
        seen: list[dict[str, object]] = []

        def _va_handler(
            request: httpx.Request,
            bucket: list[dict[str, object]] = seen,
        ) -> httpx.Response:
            assert request.url.path == va["path"]
            bucket.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(
                200,
                json={
                    "request_id": "req_wire_py",
                    "verdict": "likely_human",
                    "verdict_jws": valid_voice_jws,
                    "inference_ms": 14.2,
                },
            )

        with EntrosClient(
            "https://api.entros.io",
            api_key="entros_test_key",
            jwks=jwks,
            transport=httpx.MockTransport(_va_handler),
        ) as client:
            res = client.analyze_voice(
                audio_bytes,
                session_id="lk_room_bank_8831_caller_01",
                codec=cast(VoiceCodec, mapping["sdk_codec"]),
                operating_profile="wideband_clean",
                now_seconds=jws_now,
            )
            assert res.verdict is not None and res.verdict.verdict == "likely_human"
            assert seen[0]["audio_b64"] == va["audio_b64_standard"]
            assert seen[0]["encoding"] == mapping["wire_encoding"]
            if mapping["sample_rate_hz"] is None:
                assert "sample_rate_hz" not in seen[0]
            else:
                assert seen[0]["sample_rate_hz"] == mapping["sample_rate_hz"]

    # 3. Permits issue (200/202), step-up (create/poll/complete), verify (200/403/409), receipt jti validation.
    pi = cast(dict[str, object], wire["permits_issue"])
    ps = cast(dict[str, object], wire["permits_step_up"])
    pv = cast(dict[str, object], wire["permits_verify"])
    pr = cast(dict[str, object], wire["permits_receipt"])

    action = cast(dict[str, object], pi["canonical_action"])
    assert hash_action_v2(action) == pi["expected_request_digest"]

    policy = PolicyV2(
        policy_id="pol_wire_v2",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
        max_permit_lifetime_seconds=300,
    )
    queue: list[tuple[int, dict[str, object]]] = [
        (200, cast(dict[str, object], pi["response_200_issued"])),
        (202, cast(dict[str, object], pi["response_202_step_up_required"])),
        (cast(int, ps["create_status"]), cast(dict[str, object], ps["create_response_201"])),
        (200, cast(dict[str, object], ps["poll_response_pending"])),
        (200, cast(dict[str, object], ps["poll_response_completed"])),
        (200, cast(dict[str, object], ps["complete_response_200"])),
        (200, cast(dict[str, object], pv["response_200_allow"])),
        (403, cast(dict[str, object], pv["response_403_deny"])),
        (409, cast(dict[str, object], pv["response_409_replay"])),
    ]
    recorded_bodies: list[dict[str, object]] = []

    def _permit_handler(request: httpx.Request) -> httpx.Response:
        recorded_bodies.append(json.loads(request.content.decode("utf-8")))
        status, body = queue.pop(0)
        return httpx.Response(status, json=body)

    with EntrosClient(
        "https://api.entros.io",
        api_key="entros_api_key",
        jwks=jwks,
        transport=httpx.MockTransport(_permit_handler),
    ) as client:
        r_issued = client.issue_permit(
            sub="usr_01",
            actor={"id": "spiffe://acme/agent"},
            aud="https://mcp.example.com/tools",
            action=action,
            policy=policy,
            voice_verdict_jws=valid_voice_jws,
        )
        assert isinstance(r_issued, IssuedPermitResponse)
        assert recorded_bodies[0]["ttl_seconds"] == pi["default_ttl_seconds"]

        r_step_up = client.issue_permit(
            sub="usr_01",
            actor={"id": "spiffe://acme/agent"},
            aud="https://mcp.example.com/tools",
            action=action,
            policy=policy,
        )
        assert isinstance(r_step_up, StepUpRequiredResponse)

        r_create = client.request_step_up(
            protocol="mcp_mrtr",
            sub="usr_01",
            actor={"id": "spiffe://acme/agent"},
            aud="https://mcp.example.com/tools",
            policy_id="pol_wire_v2",
            request_digest=str(pi["expected_request_digest"]),
        )
        assert recorded_bodies[2]["operation"] == "create"
        assert r_create.protocol == "mcp_mrtr"

        poll_req = cast(dict[str, object], ps["poll_request"])
        poll_jti = cast(str, poll_req["jti"])
        r_pending = client.poll_step_up(poll_jti)
        assert recorded_bodies[3] == poll_req
        assert r_pending.status == "pending"

        r_completed_poll = client.poll_step_up(poll_jti)
        assert r_completed_poll.status == "completed"

        r_complete = client.complete_step_up(
            jti=poll_jti,
            webauthn_assertion={
                "credential_id": "cred_1",
                "authenticator_data": "AQID",
                "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                "signature": "MEUC",
            },
            public_key="04" + "11" * 64,
            expected_rp_id="approve.entros.io",
            expected_origin="https://approve.entros.io",
        )
        assert recorded_bodies[5]["operation"] == "complete"
        assert r_complete.jti == poll_jti

        r_v200 = client.verify_permit_online(
            permit_jws="header.payload.sig",
            expected_aud="https://mcp.example.com/tools",
            action=action,
            policy=policy,
        )
        assert r_v200.verified is True
        assert r_v200.reason is None

        r_v403 = client.verify_permit_online(
            permit_jws="header.payload.sig",
            expected_aud="https://mcp.example.com/tools",
            action=action,
            policy=policy,
        )
        assert r_v403.verified is False and r_v403.reason == "assurance_downgrade"

        r_v409 = client.verify_permit_online(
            permit_jws="header.payload.sig",
            expected_aud="https://mcp.example.com/tools",
            action=action,
            policy=policy,
        )
        assert r_v409.verified is False and r_v409.reason == "nonce_replayed"

        for bad_jti in cast(list[str], pr["invalid_jtis"]):
            with pytest.raises(ValueError, match="64-char"):
                client.get_receipt(bad_jti)
