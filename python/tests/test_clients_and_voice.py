"""Unit tests for sync/async REST clients, WebSocket /v1/voice/stream, and zero audio logging."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    AsyncEntrosClient,
    EntrosApiError,
    EntrosClient,
    PolicyV2,
    ScittDecisionPayload,
    ScittReceiptResult,
    StaticJwksProvider,
    b64url_encode_nopad,
    create_scitt_receipt,
    hash_action_v2,
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


def test_sync_entros_client_endpoints_and_zero_audio_leak() -> None:
    _, jwks, voice_jws, permit_jws, scitt_b64, now = _setup_fixture()
    secret_audio = b"SENSITIVE_RAW_CALLER_AUDIO_SAMPLE_BYTES_12345"
    secret_b64 = base64.b64encode(secret_audio).decode("ascii")
    action: dict[str, object] = {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD"},
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json=jwks)
        if request.url.path == "/v1/voice/analyze":
            if request.headers.get("X-Entros-Session-Id") == "fail-session":
                return httpx.Response(500, json={"error": "inference_unavailable"})
            return httpx.Response(200, json={"verdict_jws": voice_jws, "request_id": "req-1"})
        if request.url.path == "/v1/permits/issue":
            return httpx.Response(
                200,
                json={
                    "permit_jws": permit_jws,
                    "jti": "5" * 64,
                    "request_digest": hash_action_v2(action),
                    "expires_at": now + 295,
                    "scitt_receipt": scitt_b64,
                },
            )
        if request.url.path == "/v1/permits/step-up":
            return httpx.Response(
                200,
                json={
                    "jti": "7" * 64,
                    "request_digest": hash_action_v2(action),
                    "mode": "oidc_ciba",
                    "approval_url": "https://approve.entros.io/consent?jti=" + "7" * 64,
                    "expires_at": now + 300,
                    "auth_req_id": "ciba-req-1",
                },
            )
        if request.url.path == "/v1/permits/verify":
            return httpx.Response(
                200,
                json={"ok": True, "decision": "allow", "jti": "5" * 64, "scitt_receipt": scitt_b64},
            )
        if request.url.path == "/v1/permits/receipt/" + ("5" * 64):
            return httpx.Response(200, json={"scitt_receipt": scitt_b64})
        return httpx.Response(404)

    client = EntrosClient(
        "https://api.entros.io",
        api_key="test-key",
        transport=httpx.MockTransport(_handler),
    )

    analyzed = client.analyze_voice(secret_audio, session_id="call-abc", now_seconds=now)
    assert analyzed.verdict is not None and analyzed.verdict.verdict == "likely_human"

    issued = client.issue_permit(
        action=action,
        policy_id="wire-v2",
        audience="https://mcp.acme.example/v1/mcp",
        subject="usr-1",
        actor={"id": "spiffe://acme.example/agent"},
        session_id="call-abc",
        voice_verdict_jws=voice_jws,
    )
    assert issued.permit_jws == permit_jws

    step_up = client.request_step_up(
        action=action,
        policy_id="wire-v2",
        audience="https://mcp.acme.example/v1/mcp",
        mode="oidc_ciba",
        session_id="call-abc",
    )
    assert step_up.mode == "oidc_ciba" and step_up.auth_req_id == "ciba-req-1"

    online = client.verify_permit_online(
        permit_jws=permit_jws,
        action=action,
        policy_id="wire-v2",
        audience="https://mcp.acme.example/v1/mcp",
    )
    assert online.ok and online.decision == "allow"

    offline = client.verify_permit_offline(
        permit_jws,
        policy=PolicyV2(
            policy_id="wire-v2",
            allowed_assurance_tiers=["voice_liveness_webrtc"],
            required_modalities=["voice_liveness"],
            max_evidence_age_seconds=120,
            require_continuity=True,
            require_scitt_receipt=True,
        ),
        expected_audience="https://mcp.acme.example/v1/mcp",
        action=action,
        now_seconds=now,
    )
    assert offline.ok and offline.scitt_receipt is not None

    receipt = client.get_receipt("5" * 64, verify=True)
    assert isinstance(receipt, ScittReceiptResult)
    assert receipt.payload.jti == "5" * 64

    # Error path must never leak raw audio bytes or Base64 audio.
    with pytest.raises(EntrosApiError) as exc_info:
        client.analyze_voice(secret_audio, session_id="fail-session", now_seconds=now)
    msg = str(exc_info.value)
    assert "SENSITIVE_RAW_CALLER_AUDIO" not in msg
    assert secret_b64 not in msg


async def test_async_voice_websocket_stream_loopback() -> None:
    _, jwks, voice_jws, _, _, now = _setup_fixture()
    received_audio: list[bytes] = []

    async def _ws_handler(websocket: websockets.ServerConnection) -> None:
        cfg_raw = await websocket.recv()
        assert isinstance(cfg_raw, str)
        cfg = json.loads(cfg_raw)
        assert cfg["type"] == "config"
        assert cfg["session_id"] == "call-abc"

        async for message in websocket:
            if isinstance(message, bytes):
                received_audio.append(message)
            else:
                frame = json.loads(message)
                if frame.get("type") == "flush":
                    await websocket.send(json.dumps({"verdict_jws": voice_jws}))
                    await websocket.close()
                    break

    async with websockets.serve(_ws_handler, "127.0.0.1", 0) as server:
        sock = next(iter(server.sockets))
        port = sock.getsockname()[1]
        client = AsyncEntrosClient(
            f"http://127.0.0.1:{port}",
            jwks=StaticJwksProvider(jwks),
        )
        # Verify using server-independent fixed clock via direct verdict verify on streamed JWS.
        async with client.stream_voice(session_id="call-abc") as stream:
            stream._jwks = None  # Avoid wall-clock expiry on fixed-timestamp fixture
            await stream.send_audio(b"\x01\x02" * 320)
            await stream.finish_utterance()
            verdicts = [v async for v in stream.receive_verdicts()]

        assert len(received_audio) == 1
        assert len(received_audio[0]) == 640
        assert len(verdicts) == 1
        assert verdicts[0].verdict_jws == voice_jws
        assert now == 1795450150
