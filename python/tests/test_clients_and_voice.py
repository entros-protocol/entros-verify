"""Unit tests for sync/async REST clients, WebSocket /v1/voice/stream, and zero audio logging."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import entros_verify
from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    AsyncEntrosClient,
    EntrosApiError,
    EntrosClient,
    IssuedPermitResponse,
    JwksCache,
    PolicyV2,
    ScittDecisionPayload,
    ScittReceiptResult,
    StaticJwksProvider,
    StepUpRequiredResponse,
    hash_action_v2,
)
from entros_verify._testing import (
    b64url_encode_nopad,
    create_scitt_receipt,
    sign_eddsa_compact_jws,
)


def _setup_fixture() -> tuple[Ed25519PrivateKey, dict[str, object], str, str, str, int]:
    priv = Ed25519PrivateKey.generate()
    jwks: dict[str, object] = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "entros-k1",
                "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
            }
        ]
    }
    now = 1795450150
    action: dict[str, object] = {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD"},
    }
    digest = hash_action_v2(action)
    jti = "5" * 64
    voice_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="entros-k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "6" * 64,
            "iat": now - 10,
            "exp": now + 110,
            "session_id": "call-abc",
            "verdict": "likely_human",
            "calibrated_llr": 4.9,
            "operating_profile": "webrtc_16k",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 22.0,
                "speech_ms": 2100,
                "clipping": 0.0,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [],
            "consistency_drift": {
                "status": "evaluated",
                "windows_evaluated": 3,
                "floor_spread_db": 1.0,
                "tail_decay_spread_db": 1.1,
                "spectral_tilt_drift": 0.3,
                "reason": None,
            },
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    scitt_b64 = create_scitt_receipt(
        private_key=priv,
        kid="entros-k1",
        payload=ScittDecisionPayload(
            schema="entros-scitt-permit-v2",
            jti=jti,
            request_digest=digest,
            policy_id="wire-v2",
            aud="https://mcp.acme.example/v1/mcp",
            decision="allow",
            reason="accepted",
            assurance_tier="voice_liveness_webrtc",
            modality=["voice_liveness"],
            freshness_verified_at=now - 10,
            evaluated_at=now,
            model_version="0" * 64,
            retention="memory_only",
        ),
    )
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="entros-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": jti,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "voice_liveness_webrtc",
            "modality": ["voice_liveness"],
            "freshness_verified_at": now - 10,
            "continuity": {
                "session_id": "call-abc",
                "mode": "call_session",
                "call_continuity_verified": True,
            },
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": voice_jws,
            "webauthn_assertion_digest": None,
            "policy_id": "wire-v2",
            "scitt_receipt": scitt_b64,
        },
    )
    return priv, jwks, voice_jws, permit_jws, scitt_b64, now


def test_public_exports_exclude_signing_helpers() -> None:
    for helper in (
        "sign_eddsa_compact_jws",
        "create_scitt_receipt",
        "b64url_encode_nopad",
        "b64url_decode_nopad",
    ):
        assert helper not in entros_verify.__all__
        assert not hasattr(entros_verify, helper)


def test_sync_entros_client_endpoints_and_zero_audio_leak() -> None:
    priv, jwks, voice_jws, permit_jws, scitt_b64, now = _setup_fixture()
    secret_audio = b"\x00\x01\x7f\x80\xfb\xffSENSITIVE_RAW_CALLER_AUDIO_SAMPLE_BYTES_12345"
    secret_b64 = base64.b64encode(secret_audio).decode("ascii")
    action: dict[str, object] = {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD"},
    }
    digest = hash_action_v2(action)
    policy = PolicyV2(
        policy_id="wire-v2",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
        require_continuity=True,
        require_scitt_receipt=True,
    )
    mismatched_scitt = create_scitt_receipt(
        private_key=priv,
        kid="entros-k1",
        payload=ScittDecisionPayload(
            schema="entros-scitt-permit-v2",
            jti="8" * 64,
            request_digest=digest,
            policy_id="wire-v2",
            aud="https://mcp.acme.example/v1/mcp",
            decision="allow",
            reason="accepted",
            assurance_tier="voice_liveness_webrtc",
            modality=["voice_liveness"],
            freshness_verified_at=now - 10,
            evaluated_at=now,
            model_version="0" * 64,
            retention="memory_only",
        ),
    )

    poll_calls = [0]
    verify_calls = [0]
    issue_calls = [0]

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer test-key" or request.url.path == "/.well-known/jwks.json"
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json=jwks)
        if request.url.path == "/v1/voice/analyze":
            body = json.loads(request.content.decode("utf-8"))
            if body.get("session_id") == "fail-session":
                return httpx.Response(500, json={"error": "inference_unavailable"})
            assert body["audio_b64"] == secret_b64
            if body["encoding"] == "wav":
                assert "sample_rate_hz" not in body
            else:
                assert body["encoding"] == "pcm16"
                assert body["sample_rate_hz"] == 16000
            return httpx.Response(
                200,
                json={
                    "request_id": "req-1",
                    "verdict": "likely_human",
                    "verdict_jws": voice_jws,
                    "inference_ms": 12.5,
                },
            )
        if request.url.path == "/v1/permits/issue":
            body = json.loads(request.content.decode("utf-8"))
            assert body["ttl_seconds"] == 300
            issue_calls[0] += 1
            if issue_calls[0] == 1:
                return httpx.Response(
                    200,
                    json={
                        "status": "issued",
                        "permit_jws": permit_jws,
                        "jti": "5" * 64,
                        "request_digest": digest,
                        "assurance_tier": "voice_liveness_webrtc",
                        "expires_at": now + 295,
                        "scitt_receipt": scitt_b64,
                    },
                )
            return httpx.Response(
                202,
                json={
                    "status": "step_up_required",
                    "reason": "voice_abstention_requires_passkey",
                    "required_assurance_tier": "voice_plus_passkey",
                    "request_digest": digest,
                    "recommended_step_up_endpoint": "/v1/permits/step-up",
                },
            )
        if request.url.path == "/v1/permits/step-up":
            body = json.loads(request.content.decode("utf-8"))
            op = body["operation"]
            if op == "create":
                assert body["protocol"] == "oidc_ciba"
                return httpx.Response(
                    200,
                    json={
                        "jti": "7" * 64,
                        "protocol": "oidc_ciba",
                        "approval_url": "https://approve.entros.io/consent?jti=" + "7" * 64,
                        "challenge_b64url": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
                        "expires_at": now + 300,
                        "ciba": {"auth_req_id": "ciba-req-1", "expires_in": 300, "interval": 2},
                    },
                )
            if op == "poll":
                poll_calls[0] += 1
                if poll_calls[0] == 1:
                    return httpx.Response(
                        200,
                        json={"status": "pending", "jti": "7" * 64, "expires_at": now + 300},
                    )
                return httpx.Response(
                    200,
                    json={
                        "status": "completed",
                        "jti": "7" * 64,
                        "request_digest": digest,
                        "assurance_tier": "voice_plus_passkey",
                        "freshness_verified_at": now - 5,
                        "expires_at": now + 300,
                        "webauthn_assertion_digest": "f" * 64,
                        "permit_jws": permit_jws,
                        "scitt_receipt": scitt_b64,
                    },
                )
            if op == "complete":
                return httpx.Response(
                    200,
                    json={
                        "jti": "7" * 64,
                        "request_digest": digest,
                        "assurance_tier": "voice_plus_passkey",
                        "freshness_verified_at": now - 5,
                        "expires_at": now + 300,
                        "webauthn_assertion_digest": "f" * 64,
                        "permit_jws": permit_jws,
                        "scitt_receipt": scitt_b64,
                    },
                )
        if request.url.path == "/v1/permits/verify":
            verify_calls[0] += 1
            if verify_calls[0] == 1:
                return httpx.Response(
                    200,
                    json={
                        "verified": True,
                        "ok": True,
                        "decision": "allow",
                        "jti": "5" * 64,
                        "assurance_tier": "voice_liveness_webrtc",
                        "scitt_receipt": scitt_b64,
                    },
                )
            if verify_calls[0] == 2:
                return httpx.Response(
                    403,
                    json={
                        "verified": False,
                        "decision": "deny",
                        "refusal_code": "assurance_downgrade",
                        "jti": "5" * 64,
                    },
                )
            return httpx.Response(
                409,
                json={
                    "verified": False,
                    "decision": "deny",
                    "refusal_code": "nonce_replayed",
                    "jti": "5" * 64,
                },
            )
        if request.url.path == "/v1/permits/receipt/" + ("5" * 64):
            return httpx.Response(200, json={"scitt_receipt": scitt_b64})
        if request.url.path == "/v1/permits/receipt/" + ("9" * 64):
            return httpx.Response(200, json={"scitt_receipt": mismatched_scitt})
        return httpx.Response(404)

    with EntrosClient(
        "https://api.entros.io",
        api_key="test-key",
        transport=httpx.MockTransport(_handler),
    ) as client:
        analyzed = client.analyze_voice(secret_audio, session_id="call-abc", now_seconds=now)
        assert analyzed.verdict is not None and analyzed.verdict.verdict == "likely_human"
        assert analyzed.inference_ms == 12.5

        analyzed_wav = client.analyze_voice(
            secret_audio, session_id="call-abc", codec="wav", now_seconds=now
        )
        assert analyzed_wav.verdict is not None

        # Session ID mismatch between request and signed verdict must fail closed.
        with pytest.raises(EntrosApiError, match="session_id"):
            client.analyze_voice(secret_audio, session_id="wrong-session", now_seconds=now)

        issued = client.issue_permit(
            sub="usr-1",
            actor={"id": "spiffe://acme.example/agent"},
            aud="https://mcp.acme.example/v1/mcp",
            action=action,
            policy=policy,
            session_id="call-abc",
            voice_verdict_jws=voice_jws,
        )
        assert isinstance(issued, IssuedPermitResponse)
        assert issued.permit_jws == permit_jws

        step_up_needed = client.issue_permit(
            sub="usr-1",
            actor={"id": "spiffe://acme.example/agent"},
            aud="https://mcp.acme.example/v1/mcp",
            action=action,
            policy=policy,
        )
        assert isinstance(step_up_needed, StepUpRequiredResponse)
        assert step_up_needed.required_assurance_tier == "voice_plus_passkey"

        step_up = client.request_step_up(
            protocol="oidc_ciba",
            sub="usr-1",
            actor={"id": "spiffe://acme.example/agent"},
            aud="https://mcp.acme.example/v1/mcp",
            policy_id="wire-v2",
            action=action,
            session_id="call-abc",
        )
        assert step_up.protocol == "oidc_ciba" and step_up.auth_req_id == "ciba-req-1"

        poll_pending = client.poll_step_up("7" * 64)
        assert poll_pending.status == "pending"
        poll_done = client.poll_step_up("7" * 64)
        assert poll_done.status == "completed" and poll_done.completed is not None

        completed = client.complete_step_up(
            jti="7" * 64,
            webauthn_assertion={
                "credential_id": "AQID",
                "authenticator_data": "AQID",
                "client_data_json": "AQID",
                "signature": "AQID",
            },
            public_key="04" + "11" * 64,
            expected_rp_id="approve.entros.io",
            expected_origin="https://approve.entros.io",
        )
        assert completed.jti == "7" * 64

        online_ok = client.verify_permit_online(
            permit_jws=permit_jws,
            expected_aud="https://mcp.acme.example/v1/mcp",
            action=action,
            policy=policy,
        )
        assert online_ok.verified and online_ok.decision == "allow"

        online_403 = client.verify_permit_online(
            permit_jws=permit_jws,
            expected_aud="https://mcp.acme.example/v1/mcp",
            action=action,
            policy=policy,
        )
        assert not online_403.verified and online_403.refusal_code == "assurance_downgrade"

        online_409 = client.verify_permit_online(
            permit_jws=permit_jws,
            expected_aud="https://mcp.acme.example/v1/mcp",
            action=action,
            policy=policy,
        )
        assert not online_409.verified and online_409.refusal_code == "nonce_replayed"

        offline = client.verify_permit_offline(
            permit_jws,
            policy=policy,
            expected_audience="https://mcp.acme.example/v1/mcp",
            action=action,
            now_seconds=now,
        )
        assert offline.ok and offline.scitt_receipt is not None

        receipt = client.get_receipt("5" * 64, verify=True)
        assert isinstance(receipt, ScittReceiptResult)
        assert receipt.payload.jti == "5" * 64

        # Invalid/path-traversal jti rejected before URL construction.
        for bad_jti in ("../admin/keys", "0" * 64, "NOT_HEX"):
            with pytest.raises(ValueError, match="64-char"):
                client.get_receipt(bad_jti)

        # Receipt whose verified payload.jti differs from requested jti must fail closed.
        with pytest.raises(EntrosApiError, match="jti"):
            client.get_receipt("9" * 64, verify=True)

        # Error path must never leak raw audio bytes or Base64 audio.
        with pytest.raises(EntrosApiError) as exc_info:
            client.analyze_voice(secret_audio, session_id="fail-session", now_seconds=now)
        msg = str(exc_info.value)
        assert "SENSITIVE_RAW_CALLER_AUDIO" not in msg
        assert secret_b64 not in msg


async def test_client_forwards_revoked_kids_with_caller_jwks() -> None:
    _, jwks, voice_jws, _, _, now = _setup_fixture()

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "request_id": "req-rev",
                "verdict": "likely_human",
                "verdict_jws": voice_jws,
                "inference_ms": 9.0,
            },
        )

    with (
        EntrosClient(
            "https://api.entros.io",
            jwks=StaticJwksProvider(jwks),
            revoked_kids={"entros-k1"},
            transport=httpx.MockTransport(_handler),
        ) as sync_client,
        pytest.raises(EntrosApiError, match="revoked_kid"),
    ):
        sync_client.analyze_voice(b"\x00\x01" * 80, session_id="call-abc", now_seconds=now)

    async with AsyncEntrosClient(
        "https://api.entros.io",
        jwks=StaticJwksProvider(jwks),
        revoked_kids={"entros-k1"},
        transport=httpx.MockTransport(_handler),
    ) as async_client:
        with pytest.raises(EntrosApiError, match="revoked_kid"):
            await async_client.analyze_voice(
                b"\x00\x01" * 80, session_id="call-abc", now_seconds=now
            )


async def test_async_voice_analyze_and_websocket_stream_use_real_async_jwks() -> None:
    _, jwks, voice_jws, _, _, now = _setup_fixture()
    received_audio: list[bytes] = []
    received_controls: list[dict[str, object]] = []
    received_auth_headers: list[str | None] = []
    received_subprotocols: list[str | None] = []
    jwks_fetches = [0]

    class _AsyncOnlyTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/jwks.json":
                jwks_fetches[0] += 1
                return httpx.Response(200, json=jwks)
            if request.url.path == "/v1/voice/analyze":
                return httpx.Response(
                    200,
                    json={
                        "request_id": "req-async-1",
                        "verdict": "likely_human",
                        "verdict_jws": voice_jws,
                        "inference_ms": 10.0,
                    },
                )
            return httpx.Response(404)

    async def _ws_handler(websocket: websockets.ServerConnection) -> None:
        assert websocket.request is not None
        received_auth_headers.append(websocket.request.headers.get("Authorization"))
        received_subprotocols.append(websocket.request.headers.get("Sec-WebSocket-Protocol"))

        start_raw = await websocket.recv()
        assert isinstance(start_raw, str)
        start = json.loads(start_raw)
        assert start["type"] == "start"
        assert start["session_id"] == "call-abc"
        assert start["codec"] == "pcm16"
        assert start["sample_rate_hz"] == 16000
        assert start["operating_profile"] == "webrtc_16k"

        async for message in websocket:
            if isinstance(message, bytes):
                received_audio.append(message)
            else:
                frame = json.loads(message)
                received_controls.append(frame)
                if frame.get("type") == "flush":
                    await websocket.send(json.dumps({"type": "verdict", "verdict_jws": voice_jws}))
                elif frame.get("type") == "stop":
                    await websocket.close()
                    break

    async with websockets.serve(_ws_handler, "127.0.0.1", 0) as server:
        sock = next(iter(server.sockets))
        port = sock.getsockname()[1]

        async_jwks = JwksCache(
            "https://api.entros.io/.well-known/jwks.json",
            async_transport=_AsyncOnlyTransport(),
        )
        async with AsyncEntrosClient(
            f"http://127.0.0.1:{port}",
            api_key="stream-secret-key",
            jwks=async_jwks,
            transport=_AsyncOnlyTransport(),
        ) as client:
            # 1. Async REST analyze must verify via async JWKS without calling sync get_key().
            analyzed = await client.analyze_voice(
                b"\x01\x02" * 160,
                session_id="call-abc",
                now_seconds=now,
            )
            assert analyzed.verdict is not None and analyzed.verdict.verdict == "likely_human"

            # 2. Async WS stream verifies with real async JWKS and sends Authorization: Bearer.
            async with client.stream_voice(
                session_id="call-abc",
                codec="pcm16_16k",
                now_seconds=now,
            ) as stream:
                await stream.send_audio(b"\x01\x02" * 320)
                await stream.pause()
                await stream.resume()
                await stream.finish_utterance()
                await stream.stop()
                verdicts = [v async for v in stream.receive_verdicts()]

        assert jwks_fetches[0] == 1
        assert received_auth_headers == ["Bearer stream-secret-key"]
        assert received_subprotocols == [None]
        assert len(received_audio) == 1 and len(received_audio[0]) == 640
        assert [c["type"] for c in received_controls] == ["pause", "resume", "flush", "stop"]
        assert len(verdicts) == 1
        assert verdicts[0].verdict is not None
        assert verdicts[0].verdict.verdict == "likely_human"

    # Inbound server error frame on WebSocket must surface as EntrosApiError.
    async def _ws_error_handler(websocket: websockets.ServerConnection) -> None:
        await websocket.recv()  # start frame
        await websocket.send(
            json.dumps(
                {
                    "type": "error",
                    "error_code": "session_rate_limited",
                    "message": "Too many audio chunks",
                }
            )
        )
        await websocket.close()

    async with websockets.serve(_ws_error_handler, "127.0.0.1", 0) as err_server:
        err_port = next(iter(err_server.sockets)).getsockname()[1]
        async with (
            AsyncEntrosClient(
                f"http://127.0.0.1:{err_port}",
                jwks=StaticJwksProvider(jwks),
            ) as err_client,
            err_client.stream_voice(session_id="call-abc", now_seconds=now) as stream,
        ):
            with pytest.raises(EntrosApiError, match="Too many audio chunks") as exc_info:
                _ = [v async for v in stream.receive_verdicts()]
            assert exc_info.value.error_code == "session_rate_limited"


async def test_client_fail_closed_verify_receipt_consistency_voice_null_jwks_and_ws_cleanup() -> None:
    from unittest.mock import AsyncMock, patch

    from entros_verify.voice import VoiceClient, VoiceStreamSession

    _, jwks, voice_jws, permit_jws, scitt_b64, now = _setup_fixture()
    policy = PolicyV2(
        policy_id="wire-v2",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
    )
    action: dict[str, object] = {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD"},
    }

    # 1. HTTP 403 returning verified=True/decision="allow" and HTTP 200 mismatched verified/decision must fail closed.
    responses = [
        httpx.Response(403, json={"verified": True, "decision": "allow"}),
        httpx.Response(200, json={"verified": True, "decision": "deny"}),
        httpx.Response(
            200,
            json={"scitt_receipt": scitt_b64},
            headers={"Content-Type": "APPLICATION/JSON; charset=utf-8"},
        ),
    ]

    def _handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    with EntrosClient(
        "https://api.entros.io",
        jwks=jwks,
        transport=httpx.MockTransport(_handler),
    ) as client:
        with pytest.raises(EntrosApiError, match=r"non-2xx|allow"):
            client.verify_permit_online(
                permit_jws=permit_jws,
                expected_aud="https://mcp.acme.example/v1/mcp",
                action=action,
                policy=policy,
            )
        with pytest.raises(EntrosApiError, match=r"disagree"):
            client.verify_permit_online(
                permit_jws=permit_jws,
                expected_aud="https://mcp.acme.example/v1/mcp",
                action=action,
                policy=policy,
            )
        # Case-insensitive Content-Type + verify=False decodes Base64URL JSON to raw CBOR bytes.
        raw_receipt = client.get_receipt("5" * 64, verify=False)
        assert isinstance(raw_receipt, bytes)
        assert raw_receipt.startswith(b"\xd2")  # CBOR Tag 18

    # 2. VoiceClient(jwks=None) returns verdict=None instead of fabricating an unverified VoiceLivenessVerdict.
    def _voice_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "request_id": "req-no-jwks",
                "verdict": "likely_human",
                "verdict_jws": voice_jws,
                "inference_ms": 5.0,
            },
        )

    with VoiceClient(
        "https://api.entros.io",
        jwks=None,
        transport=httpx.MockTransport(_voice_handler),
    ) as vc:
        res = vc.analyze(b"\x00\x01" * 80, session_id="call-abc")
        assert res.verdict is None
        assert res.verdict_jws == voice_jws

    # 3. VoiceStreamSession.connect() closes opened ws if sending start frame raises.
    fake_ws = AsyncMock()
    fake_ws.send.side_effect = RuntimeError("write failed")
    with patch("entros_verify.voice.websockets.connect", new=AsyncMock(return_value=fake_ws)):
        session = VoiceStreamSession(
            ws_url="wss://api.entros.io/v1/voice/stream",
            session_id="call-leak-test",
        )
        with pytest.raises(EntrosApiError, match="Failed to open voice stream"):
            await session.connect()
        fake_ws.close.assert_awaited_once()

    # 4. Inbound WebSocket error frame redacts long Base64 blobs and bounds length to 240 chars.
    long_b64 = "A" * 100
    async def _ws_leak_err(websocket: websockets.ServerConnection) -> None:
        await websocket.recv()
        await websocket.send(
            json.dumps(
                {
                    "type": "error",
                    "code": "bad_frame",
                    "message": f"failed payload={long_b64} " + ("x" * 300),
                }
            )
        )
        await websocket.close()

    async with websockets.serve(_ws_leak_err, "127.0.0.1", 0) as leak_server:
        port = next(iter(leak_server.sockets)).getsockname()[1]
        async with (
            AsyncEntrosClient(f"http://127.0.0.1:{port}", jwks=StaticJwksProvider(jwks)) as c,
            c.stream_voice(session_id="call-abc", now_seconds=now) as stream,
        ):
            with pytest.raises(EntrosApiError) as exc_info:
                _ = [v async for v in stream.receive_verdicts()]
            err_text = str(exc_info.value)
            assert long_b64 not in err_text
            assert "[redacted]" in err_text
            assert len(err_text) <= 240
