"""Unit tests for Policy v2 evaluation, all refusal codes, and threaded/async nonce races."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    InMemoryPermitNonceStoreV2,
    NonceStoreError,
    PolicyV2,
    RefusalCode,
    StaticJwksProvider,
    VoiceRules,
    b64url_encode_nopad,
    hash_action_v2,
    sign_eddsa_compact_jws,
    verify_agent_permit_v2,
)
from entros_verify.nonce_store import NonceConsumeResult, PermitNonceRecord


def _make_issuer() -> tuple[Ed25519PrivateKey, StaticJwksProvider]:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    return priv, jwks


def _base_action() -> dict[str, object]:
    return {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD"},
    }


def test_nonce_store_32_way_multithreaded_race_and_not_found() -> None:
    priv, jwks = _make_issuer()
    action = _base_action()
    now = 1795450150
    jti = "1" * 64
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "user-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": jti,
            "iat": now - 10,
            "exp": now + 290,
            "request_digest": hash_action_v2(action),
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 20,
            "continuity": {"session_id": "sess-1", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "a" * 64,
            "policy_id": "p-v2",
            "scitt_receipt": None,
        },
    )
    policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        max_permit_lifetime_seconds=300,
    )
    store = InMemoryPermitNonceStoreV2()

    # Unregistered jti returns nonce_not_found when require_registered_nonce=True.
    missing_res = verify_agent_permit_v2(
        permit_jws,
        policy=policy,
        expected_audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        action=action,
        now_seconds=now,
        nonce_store=store,
        require_registered_nonce=True,
    )
    assert not missing_res.ok and missing_res.reason == RefusalCode.NONCE_NOT_FOUND

    # Register jti and fire 32 parallel threads.
    store.register(jti=jti, created_at=now - 10, expires_at=now + 290)

    def _worker(_: int) -> tuple[bool, RefusalCode | None]:
        res = verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience="https://mcp.acme.example/v1/mcp",
            jwks=jwks,
            action=action,
            now_seconds=now,
            nonce_store=store,
            require_registered_nonce=True,
        )
        return res.ok, res.reason

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(_worker, range(32)))

    assert sum(1 for ok, _ in results if ok) == 1
    assert sum(1 for ok, r in results if not ok and r == RefusalCode.NONCE_REPLAYED) == 31


def test_nonce_store_backend_error_maps_to_state_unavailable() -> None:
    class FailingNonceStore:
        def register(
            self,
            *,
            jti: str,
            expires_at: int,
            created_at: int,
            request_digest: str | None = None,
            aud: str | None = None,
            policy_id: str | None = None,
        ) -> None:
            raise NonceStoreError("backend_down", "Redis unreachable")

        def peek(self, jti: str) -> PermitNonceRecord | None:
            return None

        def consume_once(
            self,
            *,
            jti: str,
            now_seconds: int,
            expires_at: int,
            require_registered: bool = False,
            request_digest: str | None = None,
            aud: str | None = None,
            policy_id: str | None = None,
        ) -> NonceConsumeResult:
            raise NonceStoreError("backend_down", "Redis unreachable")

    priv, jwks = _make_issuer()
    action = _base_action()
    now = 1795450150
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "user-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "2" * 64,
            "iat": now - 10,
            "exp": now + 290,
            "request_digest": hash_action_v2(action),
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 20,
            "continuity": {"session_id": "sess-1", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "a" * 64,
            "policy_id": "p-v2",
            "scitt_receipt": None,
        },
    )
    policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    res = verify_agent_permit_v2(
        permit_jws,
        policy=policy,
        expected_audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        action=action,
        now_seconds=now,
        nonce_store=FailingNonceStore(),
    )
    assert not res.ok
    assert res.decision == "unavailable"
    assert res.reason == RefusalCode.STATE_UNAVAILABLE


def test_voice_model_version_pin_and_partial_spoof_probability_ceiling() -> None:
    priv, jwks = _make_issuer()
    action = _base_action()
    now = 1795450150
    voice_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "3" * 64,
            "iat": now - 20,
            "exp": now + 100,
            "session_id": "call-1",
            "verdict": "likely_human",
            "calibrated_llr": 4.2,
            "operating_profile": "webrtc_16k",
            "model_version": "b" * 64,
            "signal_quality": {
                "snr_db": 20.0,
                "speech_ms": 2000,
                "clipping": 0.001,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [
                {"start_ms": 160, "end_ms": 320, "spoof_probability": 0.85}
            ],
            "consistency_drift": {
                "status": "evaluated",
                "windows_evaluated": 3,
                "floor_spread_db": 1.2,
                "tail_decay_spread_db": 1.4,
                "spectral_tilt_drift": 0.4,
                "reason": None,
            },
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "user-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "4" * 64,
            "iat": now - 10,
            "exp": now + 290,
            "request_digest": hash_action_v2(action),
            "assurance_tier": "voice_liveness_webrtc",
            "modality": ["voice_liveness"],
            "freshness_verified_at": now - 20,
            "continuity": {
                "session_id": "call-1",
                "mode": "call_session",
                "call_continuity_verified": True,
            },
            "uniqueness_status": "session_bound",
            "voice_verdict_jws": voice_jws,
            "webauthn_assertion_digest": None,
            "policy_id": "voice-p",
            "scitt_receipt": None,
        },
    )

    # Disallowed model_version -> voice_profile_disallowed.
    pinned_policy = PolicyV2(
        policy_id="voice-p",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
        voice_rules=VoiceRules(
            allowed_model_versions=["c" * 64],
            max_partial_spoof_spans=2,
        ),
    )
    res_model = verify_agent_permit_v2(
        permit_jws,
        policy=pinned_policy,
        expected_audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_model.ok and res_model.reason == RefusalCode.VOICE_PROFILE_DISALLOWED

    # Allowed span count (2) but spoof_probability 0.85 > ceiling 0.5 -> partial_spoof_detected.
    prob_policy = PolicyV2(
        policy_id="voice-p",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
        voice_rules=VoiceRules(
            allowed_model_versions=["b" * 64],
            max_partial_spoof_spans=2,
            max_partial_spoof_probability=0.5,
        ),
    )
    res_prob = verify_agent_permit_v2(
        permit_jws,
        policy=prob_policy,
        expected_audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_prob.ok and res_prob.reason == RefusalCode.PARTIAL_SPOOF_DETECTED


def test_all_31_refusal_codes_defined() -> None:
    assert len(list(RefusalCode)) == 31
