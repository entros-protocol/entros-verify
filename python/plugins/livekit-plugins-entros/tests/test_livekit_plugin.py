"""Unit tests for livekit-plugins-entros raw track firewall and @entros_voice_gate."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    AsyncEntrosClient,
    InMemoryPermitNonceStoreV2,
    PolicyV2,
    StaticJwksProvider,
    b64url_encode_nopad,
    hash_action_v2,
    sign_eddsa_compact_jws,
)
from entros_verify.voice import VoiceAnalyzeResponse
from livekit_plugins_entros import (
    EntrosVoiceFirewall,
    EntrosVoiceGateBlocked,
    entros_voice_gate,
)


@dataclass(frozen=True)
class _FakeAudioFrame:
    data: bytes
    sample_rate: int = 16000
    num_channels: int = 1


class _FakeAudioStream:
    def __init__(self, frames: list[_FakeAudioFrame]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[_FakeAudioFrame]:
        for f in self._frames:
            yield f


class _FakeVoiceStreamSink:
    def __init__(self, verdict_jws: str) -> None:
        self.sent_chunks: list[bytes] = []
        self.flushed = False
        self._verdict_jws = verdict_jws

    async def __aenter__(self) -> _FakeVoiceStreamSink:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    async def send_audio(self, raw_audio_chunk: bytes) -> None:
        self.sent_chunks.append(raw_audio_chunk)

    async def finish_utterance(self) -> None:
        self.flushed = True

    async def receive_verdicts(self) -> AsyncIterator[VoiceAnalyzeResponse]:
        yield VoiceAnalyzeResponse(verdict_jws=self._verdict_jws)


def _voice_jws(
    priv: Ed25519PrivateKey,
    *,
    session_id: str,
    verdict: str,
    now: int,
) -> str:
    return sign_eddsa_compact_jws(
        private_key=priv,
        kid="lk-k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "a" * 64,
            "iat": now - 5,
            "exp": now + 115,
            "session_id": session_id,
            "verdict": verdict,
            "calibrated_llr": None if verdict == "insufficient_signal" else (4.5 if verdict == "likely_human" else 0.1),
            "operating_profile": "webrtc_16k",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 22.0,
                "speech_ms": 2000,
                "clipping": 0.0,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [],
            "consistency_drift": {
                "status": "evaluated",
                "windows_evaluated": 3,
                "floor_spread_db": 1.0,
                "tail_decay_spread_db": 1.0,
                "spectral_tilt_drift": 0.2,
                "reason": None,
            },
            "abstain_reason": "low_snr" if verdict == "insufficient_signal" else None,
            "retention": "memory_only",
        },
    )


async def test_livekit_raw_track_streaming_forbids_denoising_and_gates_tools() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "lk-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    now = 1795450150
    session_id = "lk_room_bank_01"
    suspicious_jws = _voice_jws(priv, session_id=session_id, verdict="suspicious", now=now)
    sink = _FakeVoiceStreamSink(suspicious_jws)

    def _mock_api(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/permits/step-up"
        return httpx.Response(
            200,
            json={
                "jti": "9" * 64,
                "request_digest": "8" * 64,
                "mode": "oidc_ciba",
                "approval_url": "https://approve.entros.io/consent?jti=" + "9" * 64,
                "expires_at": now + 300,
                "auth_req_id": "ciba-lk-1",
            },
        )

    client = AsyncEntrosClient(
        "https://api.entros.io",
        jwks=jwks,
        transport=httpx.MockTransport(_mock_api),
    )
    firewall = EntrosVoiceFirewall(
        client=client,
        jwks=jwks,
        stream_factory=lambda _: sink,
        clock=lambda: now,
    )

    stream = _FakeAudioStream([_FakeAudioFrame(data=b"\x01\x02" * 160)])

    # Upstream denoising must fail closed.
    with pytest.raises(ValueError, match="Upstream denoising is forbidden"):
        await firewall.attach_raw_audio_track(
            session_id=session_id,
            audio_stream=stream,
            denoiser_applied=True,
        )

    # Raw 16 kHz track streams cleanly and stores verified signed verdict by session_id.
    rec = await firewall.attach_raw_audio_track(
        session_id=session_id,
        audio_stream=stream,
        denoiser_applied=False,
    )
    assert rec is not None and rec.verdict.verdict == "suspicious"
    assert sink.flushed and len(sink.sent_chunks) == 1

    policy = PolicyV2(
        policy_id="lk-wire-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv", "voice_plus_passkey"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()
    executed = [0]

    @entros_voice_gate(
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        nonce_store=store,
        jwks=jwks,
        firewall=firewall,
        step_up_mode="oidc_ciba",
        clock=lambda: now,
    )
    async def transfer_funds(amount: int) -> dict[str, object]:
        executed[0] += 1
        return {"ok": True, "amount": amount}

    # Suspicious verdict without permit triggers OIDC CIBA step-up without running tool.
    step_up_out = await transfer_funds(amount=500, entros_session_id=session_id)
    assert isinstance(step_up_out, dict)
    assert step_up_out["decision"] == "step_up_required"
    assert step_up_out["mode"] == "oidc_ciba"
    assert step_up_out["voice_verdict"] == "suspicious"
    assert executed[0] == 0

    # With a valid single-use AgentPermit v2, tool executes once and replay is denied.
    digest = hash_action_v2(
        {
            "kind": "voice.tool_call",
            "server": "livekit-voice-agent",
            "tool": "transfer_funds",
            "arguments": {"amount": 500},
        }
    )
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="lk-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-lk",
            "actor": {"id": "spiffe://acme.example/lk-agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "c" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": session_id, "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "d" * 64,
            "policy_id": "lk-wire-v2",
            "scitt_receipt": None,
        },
    )
    allowed = await transfer_funds(amount=500, entros_session_id=session_id, entros_permit=permit_jws)
    assert allowed == {"ok": True, "amount": 500}
    assert executed[0] == 1

    replayed = await transfer_funds(amount=500, entros_session_id=session_id, entros_permit=permit_jws)
    assert isinstance(replayed, dict) and replayed["reason"] == "nonce_replayed"
    assert executed[0] == 1

    # likely_synthetic denies immediately even when raise_on_block=True.
    synth_jws = _voice_jws(priv, session_id=session_id, verdict="likely_synthetic", now=now)
    await firewall.record_verdict_jws(session_id, synth_jws)

    @entros_voice_gate(
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        nonce_store=store,
        jwks=jwks,
        firewall=firewall,
        raise_on_block=True,
        clock=lambda: now,
    )
    async def reset_mfa() -> str:
        return "done"

    with pytest.raises(EntrosVoiceGateBlocked, match="voice_verdict_not_allowed"):
        await reset_mfa(entros_session_id=session_id)
