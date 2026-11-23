"""Unit tests for pipecat-entros EntrosVoiceFirewallProcessor."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    InMemoryPermitNonceStoreV2,
    PolicyV2,
    StaticJwksProvider,
    b64url_encode_nopad,
    hash_action_v2,
    sign_eddsa_compact_jws,
)
from pipecat_entros import (
    EntrosStepUpRequiredFrame,
    EntrosVoiceFirewallProcessor,
    EntrosVoiceVerdictFrame,
    FrameDirection,
    FunctionCallInProgressFrame,
    InputAudioRawFrame,
)


async def test_pipecat_parallel_audio_tap_verdict_frame_and_function_gating() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "pc-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    now = 1795450150
    session_id = "pc_call_77"
    policy = PolicyV2(
        policy_id="pc-transfer-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()
    tapped_audio: list[tuple[bytes, int]] = []

    async def _tap(raw_audio: bytes, sample_rate: int) -> None:
        tapped_audio.append((raw_audio, sample_rate))

    processor = EntrosVoiceFirewallProcessor(
        session_id=session_id,
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        nonce_store=store,
        audio_tap_callback=_tap,
        gated_functions={"transfer_funds"},
        clock=lambda: now,
    )

    # 1. Raw InputAudioRawFrame passes downstream untouched without blocking STT.
    raw_pcm = b"\x10\x20\x30\x40" * 80
    audio_frame = InputAudioRawFrame(audio=raw_pcm, sample_rate=16000, num_channels=1)
    await processor.process_frame(audio_frame, FrameDirection.DOWNSTREAM)
    await processor.drain_audio_taps()

    assert len(tapped_audio) == 1 and tapped_audio[0] == (raw_pcm, 16000)
    assert processor.pushed_frames[0][0] is audio_frame
    assert audio_frame.audio == raw_pcm

    # 2. Signed VoiceLivenessVerdict emits EntrosVoiceVerdictFrame downstream.
    verdict_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="pc-k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "e" * 64,
            "iat": now - 5,
            "exp": now + 115,
            "session_id": session_id,
            "verdict": "likely_human",
            "calibrated_llr": 4.4,
            "operating_profile": "webrtc_16k",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 24.0,
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
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    verdict_frame = await processor.ingest_verdict_jws(verdict_jws)
    assert verdict_frame is not None
    assert isinstance(processor.pushed_frames[-1][0], EntrosVoiceVerdictFrame)

    # 3. Ungated tool passes straight through.
    ungated = FunctionCallInProgressFrame(function_name="check_balance", tool_call_id="tc-0", arguments={})
    await processor.process_frame(ungated, FrameDirection.DOWNSTREAM)
    assert processor.pushed_frames[-1][0] is ungated

    # 4. Gated tool without permit is halted and emits EntrosStepUpRequiredFrame.
    blocked_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-1",
        arguments={"amount": 250},
    )
    await processor.process_frame(blocked_call, FrameDirection.DOWNSTREAM)
    last_frame = processor.pushed_frames[-1][0]
    assert isinstance(last_frame, EntrosStepUpRequiredFrame)
    assert last_frame.tool_call_id == "tc-1"

    # 5. Gated tool with valid AgentPermit v2 passes once, then replay is blocked.
    digest = hash_action_v2(
        {
            "kind": "voice.tool_call",
            "server": "pipecat-voice-agent",
            "tool": "transfer_funds",
            "arguments": {"amount": 250},
        }
    )
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="pc-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-pc",
            "actor": {"id": "spiffe://acme.example/pc-agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "f" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": session_id, "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "1" * 64,
            "policy_id": "pc-transfer-v2",
            "scitt_receipt": None,
        },
    )
    approved_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-2",
        arguments={"amount": 250},
        permit_jws=permit_jws,
    )
    await processor.process_frame(approved_call, FrameDirection.DOWNSTREAM)
    assert processor.pushed_frames[-1][0] is approved_call

    replay_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-3",
        arguments={"amount": 250},
        permit_jws=permit_jws,
    )
    await processor.process_frame(replay_call, FrameDirection.DOWNSTREAM)
    replay_frame = processor.pushed_frames[-1][0]
    assert isinstance(replay_frame, EntrosStepUpRequiredFrame)
    assert replay_frame.reason == "nonce_replayed"
