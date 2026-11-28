"""Unit tests for Policy v2 evaluation, all refusal codes, and threaded/async nonce races."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    AgentPermitV2,
    DpopVerificationInput,
    InMemoryDpopJtiStore,
    InMemoryPermitNonceStoreV2,
    JwksUnavailableError,
    NonceStoreError,
    PolicyV2,
    RefusalCode,
    StaticJwksProvider,
    VoiceRules,
    WebAuthnVerificationResult,
    compute_access_token_hash,
    compute_jwk_thumbprint,
    evaluate_policy_v2,
    hash_action_v2,
    verify_agent_permit_v2,
    verify_agent_permit_v2_async,
    verify_voice_liveness_verdict,
)
from entros_verify._testing import b64url_encode_nopad, sign_eddsa_compact_jws
from entros_verify.jwks import KeyLookupResult
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


def test_policy_parity_modality_ordering_cnf_mismatch_and_uniqueness_refusal() -> None:
    priv, jwks = _make_issuer()
    action = _base_action()
    digest = hash_action_v2(action)
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"

    def _mint(overrides: dict[str, object]) -> str:
        payload: dict[str, object] = {
            "iss": "https://api.entros.io",
            "sub": "user-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": audience,
            "jti": "5" * 64,
            "iat": now - 10,
            "exp": now + 290,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 20,
            "continuity": {"session_id": "sess-1", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "a" * 64,
            "policy_id": "p-v2",
            "scitt_receipt": None,
        }
        payload.update(overrides)
        return sign_eddsa_compact_jws(
            private_key=priv,
            kid="k1",
            typ=AGENT_PERMIT_TYP,
            payload=payload,
        )

    base_policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )

    # Unsorted modality list -> invalid_permit.
    unsorted_jws = _mint({"modality": ["webauthn_uv", "voice_liveness"]})
    res_unsorted = verify_agent_permit_v2(
        unsorted_jws,
        policy=base_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_unsorted.ok and res_unsorted.reason == RefusalCode.INVALID_PERMIT

    # Duplicate modality list -> invalid_permit.
    dup_jws = _mint({"modality": ["webauthn_uv", "webauthn_uv"]})
    res_dup = verify_agent_permit_v2(
        dup_jws,
        policy=base_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_dup.ok and res_dup.reason == RefusalCode.INVALID_PERMIT

    # cnf.jkt != actor.key_jkt -> invalid_permit (Step 7 structural invariant).
    cnf_mismatch_jws = _mint(
        {
            "actor": {
                "id": "spiffe://acme.example/agent",
                "key_jkt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            "cnf": {"jkt": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
        }
    )
    res_cnf = verify_agent_permit_v2(
        cnf_mismatch_jws,
        policy=base_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_cnf.ok and res_cnf.reason == RefusalCode.INVALID_PERMIT

    # uniqueness_requirement mismatch -> assurance_downgrade.
    session_policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        uniqueness_requirement="require_session_bound",
    )
    res_unmeasured = verify_agent_permit_v2(
        _mint({"uniqueness_status": "unmeasured"}),
        policy=session_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_unmeasured.ok and res_unmeasured.reason == RefusalCode.ASSURANCE_DOWNGRADE

    idp_policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        uniqueness_requirement="require_enterprise_idp_subject",
    )
    res_session = verify_agent_permit_v2(
        _mint({"uniqueness_status": "session_bound"}),
        policy=idp_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    assert not res_session.ok and res_session.reason == RefusalCode.ASSURANCE_DOWNGRADE


def test_all_31_refusal_codes_defined() -> None:
    assert len(list(RefusalCode)) == 31


async def test_policy_v2_parity_fixes_and_nonce_policy_binding() -> None:
    priv, jwks = _make_issuer()
    action = _base_action()
    digest = hash_action_v2(action)
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"

    # 1. VoiceRules default allows wideband_clean and applies no hidden LLR/SNR/speech floors when voice_rules=None.
    wideband_voice_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "1" * 64,
            "iat": now - 10,
            "exp": now + 110,
            "session_id": "call-wb",
            "verdict": "likely_human",
            "calibrated_llr": 0.2,  # below old hidden 1.5 floor
            "operating_profile": "wideband_clean",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 4.0,  # below old hidden 10.0 floor
                "speech_ms": 600,  # below old hidden 1500 floor
                "clipping": 0.0,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [],
            "consistency_drift": {
                "status": "not_applicable",
                "windows_evaluated": 1,
                "floor_spread_db": None,
                "tail_decay_spread_db": None,
                "spectral_tilt_drift": None,
                "reason": "single_window",
            },
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    wideband_permit = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {
                "id": "spiffe://acme.example/agent",
                "act": {"sub": "delegate-1", "actor_type": "orchestrator"},
            },
            "aud": audience,
            "jti": "2" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "voice_liveness_webrtc",
            "modality": ["voice_liveness"],
            "freshness_verified_at": now - 10,
            "continuity": {"session_id": "call-wb", "mode": "call_session", "call_continuity_verified": True},
            "uniqueness_status": "session_bound",
            "voice_verdict_jws": wideband_voice_jws,
            "webauthn_assertion_digest": None,
            "policy_id": "wb-pol",
            "scitt_receipt": "not-even-valid-cbor-ignored-when-not-required",
        },
    )
    wb_policy = PolicyV2(
        policy_id="wb-pol",
        allowed_assurance_tiers=["voice_liveness_webrtc"],
        required_modalities=["voice_liveness"],
        max_evidence_age_seconds=120,
        require_scitt_receipt=False,
        voice_rules=None,
    )
    res_wb = verify_agent_permit_v2(
        wideband_permit,
        policy=wb_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
    )
    # Proves: (a) Actor.act plain JSON object accepted, (b) wideband_clean + no hidden voice floors,
    # (c) unrequired malformed scitt_receipt ignored cleanly.
    assert res_wb.ok and res_wb.permit is not None
    assert res_wb.permit.actor.act == {"sub": "delegate-1", "actor_type": "orchestrator"}

    # 2. Steps 8..18 run BEFORE remote voice_jwks / scitt_jwks fetches.
    voice_jwks_calls = [0]

    class _SpyFailingJwks:
        def get_key(self, kid: str) -> KeyLookupResult:
            voice_jwks_calls[0] += 1
            raise JwksUnavailableError("should not be called when Step 11 aud fails")

        async def get_key_async(self, kid: str) -> KeyLookupResult:
            voice_jwks_calls[0] += 1
            raise JwksUnavailableError("should not be called when Step 11 aud fails")

    wrong_aud = verify_agent_permit_v2(
        wideband_permit,
        policy=wb_policy,
        expected_audience="https://other.example/mcp",
        jwks=jwks,
        voice_jwks=_SpyFailingJwks(),
        scitt_jwks=_SpyFailingJwks(),
        action=action,
        now_seconds=now,
    )
    assert not wrong_aud.ok and wrong_aud.reason == RefusalCode.AUDIENCE_MISMATCH
    assert voice_jwks_calls[0] == 0

    # 3. Expired voice verdict with retention != memory_only returns VOICE_RETENTION_VIOLATION first.
    bad_ret_expired = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "3" * 64,
            "iat": now - 500,
            "exp": now - 100,  # expired!
            "session_id": "call-wb",
            "verdict": "likely_human",
            "calibrated_llr": 4.0,
            "operating_profile": "webrtc_16k",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 20.0,
                "speech_ms": 2000,
                "clipping": 0.0,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [],
            "consistency_drift": {
                "status": "not_applicable",
                "windows_evaluated": 1,
                "floor_spread_db": None,
                "tail_decay_spread_db": None,
                "spectral_tilt_drift": None,
                "reason": "single_window",
            },
            "abstain_reason": None,
            "retention": "disk_persisted",
        },
    )
    ret_res = verify_voice_liveness_verdict(bad_ret_expired, jwks=jwks, now_seconds=now)
    assert not ret_res.ok and ret_res.reason == RefusalCode.VOICE_RETENTION_VIOLATION

    # 4. Standalone evaluate_policy_v2 enforces webauthn_result.assertion_digest == permit.webauthn_assertion_digest.
    permit_obj = AgentPermitV2.model_validate(
        {
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {"id": "spiffe://acme/agent"},
            "aud": audience,
            "jti": "4" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 10,
            "continuity": {"session_id": "s1", "mode": "step_up_only"},
            "uniqueness_status": "unmeasured",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "a" * 64,
            "policy_id": "pk-pol",
            "scitt_receipt": None,
        }
    )
    mismatch_wa = evaluate_policy_v2(
        permit=permit_obj,
        policy=PolicyV2(
            policy_id="pk-pol",
            allowed_assurance_tiers=["passkey_webauthn_uv"],
            required_modalities=["webauthn_uv"],
            max_evidence_age_seconds=120,
        ),
        expected_audience=audience,
        expected_request_digest=digest,
        now_seconds=now,
        webauthn_result=WebAuthnVerificationResult(
            ok=True,
            assertion_digest="b" * 64,
            sign_count=1,
        ),
    )
    assert not mismatch_wa.ok and mismatch_wa.reason == RefusalCode.WEBAUTHN_ASSERTION_INVALID

    # 5. Step 15 checks policy.required_modalities only (passkey_webauthn_uv with required_modalities=[]).
    no_req_mod = evaluate_policy_v2(
        permit=permit_obj.model_copy(update={"modality": ["voice_liveness"]}),
        policy=PolicyV2(
            policy_id="pk-pol",
            allowed_assurance_tiers=["passkey_webauthn_uv"],
            required_modalities=[],
            max_evidence_age_seconds=120,
        ),
        expected_audience=audience,
        expected_request_digest=digest,
        now_seconds=now,
    )
    assert no_req_mod.ok

    # 6. Nonce store enforces policy_id match on consume_once.
    store = InMemoryPermitNonceStoreV2()
    store.register(
        jti="7" * 64,
        created_at=now - 5,
        expires_at=now + 295,
        request_digest=digest,
        aud=audience,
        policy_id="expected-policy",
    )
    wrong_pol_consume = store.consume_once(
        jti="7" * 64,
        now_seconds=now,
        expires_at=now + 295,
        require_registered=True,
        request_digest=digest,
        aud=audience,
        policy_id="different-policy",
    )
    assert wrong_pol_consume.status == "not_found"

    # 7. Async verification resamples wall clock after async JWKS fetch before consume_once.
    clock_ticks = iter([now, now + 500])  # expires during async JWKS fetch
    fresh_store = InMemoryPermitNonceStoreV2()
    with patch("entros_verify.policy.time.time", side_effect=lambda: next(clock_ticks)):
        expired_midflight = await verify_agent_permit_v2_async(
            wideband_permit,
            policy=wb_policy,
            expected_audience=audience,
            jwks=jwks,
            action=action,
            nonce_store=fresh_store,
        )
    assert not expired_midflight.ok
    assert expired_midflight.reason == RefusalCode.PERMIT_EXPIRED
    assert fresh_store.peek("2" * 64) is None


async def test_precheck_step28_ordering_callable_clock_voice_recheck_and_dpop_jti_store() -> None:
    priv, jwks = _make_issuer()
    dpop_priv = Ed25519PrivateKey.generate()
    dpop_jwk: dict[str, object] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode_nopad(dpop_priv.public_key().public_bytes_raw()),
    }
    jkt = compute_jwk_thumbprint(dpop_jwk)
    action = _base_action()
    digest = hash_action_v2(action)
    now = 1795450500
    audience = "https://mcp.acme.example/v1/mcp"

    scitt_calls = [0]

    class _SpyScittJwks:
        def get_key(self, kid: str) -> KeyLookupResult:
            scitt_calls[0] += 1
            raise JwksUnavailableError("SCITT must not run when Steps 20..27 fail")

        async def get_key_async(self, kid: str) -> KeyLookupResult:
            scitt_calls[0] += 1
            raise JwksUnavailableError("SCITT must not run when Steps 20..27 fail")

    # 1. Step 27 DPoP failure must short-circuit BEFORE Step 28 SCITT (zero scitt_jwks calls).
    dpop_permit = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {"id": "spiffe://acme/agent", "key_jkt": jkt},
            "aud": audience,
            "jti": "9" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": "s1", "mode": "step_up_only"},
            "uniqueness_status": "unmeasured",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "a" * 64,
            "policy_id": "dpop-scitt-pol",
            "scitt_receipt": "invalid-scitt-cbor",
            "cnf": {"jkt": jkt},
        },
    )
    dpop_scitt_policy = PolicyV2(
        policy_id="dpop-scitt-pol",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        require_dpop=True,
        require_scitt_receipt=True,
    )
    missing_dpop_sync = verify_agent_permit_v2(
        dpop_permit,
        policy=dpop_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        scitt_jwks=_SpyScittJwks(),
        action=action,
        now_seconds=now,
    )
    assert not missing_dpop_sync.ok and missing_dpop_sync.reason == RefusalCode.DPOP_PROOF_INVALID
    missing_dpop_async = await verify_agent_permit_v2_async(
        dpop_permit,
        policy=dpop_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        scitt_jwks=_SpyScittJwks(),
        action=action,
        now_seconds=now,
    )
    assert not missing_dpop_async.ok and missing_dpop_async.reason == RefusalCode.DPOP_PROOF_INVALID
    assert scitt_calls[0] == 0

    # 2. Wired dpop_jti_store: failed Step 28 SCITT does NOT burn DPoP jti; replay denies without burning permit nonce; error -> state_unavailable.
    import json

    dpop_hdr = b64url_encode_nopad(
        json.dumps({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": dpop_jwk}, separators=(",", ":")).encode()
    )
    dpop_pay = b64url_encode_nopad(
        json.dumps(
            {
                "jti": "dpop-jti-wired-1",
                "htm": "POST",
                "htu": audience,
                "iat": now,
                "ath": compute_access_token_hash(dpop_permit),
            },
            separators=(",", ":"),
        ).encode()
    )
    dpop_sig = b64url_encode_nopad(dpop_priv.sign(f"{dpop_hdr}.{dpop_pay}".encode("ascii")))
    dpop_input = DpopVerificationInput(
        proof_jwt=f"{dpop_hdr}.{dpop_pay}.{dpop_sig}",
        htm="POST",
        htu=audience,
    )
    dpop_store = InMemoryDpopJtiStore()
    fail_scitt = verify_agent_permit_v2(
        dpop_permit,
        policy=dpop_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
        dpop=dpop_input,
        dpop_jti_store=dpop_store,
    )
    assert not fail_scitt.ok and fail_scitt.reason == RefusalCode.SCITT_RECEIPT_INVALID

    # Since Step 28 failed, DPoP jti is still unconsumed and passes when SCITT is not required.
    no_scitt_policy = dpop_scitt_policy.model_copy(update={"require_scitt_receipt": False})
    ok_first = verify_agent_permit_v2(
        dpop_permit,
        policy=no_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=now,
        dpop=dpop_input,
        dpop_jti_store=dpop_store,
    )
    assert ok_first.ok

    # Replaying the DPoP jti fails with DPOP_PROOF_INVALID without burning permit nonce.
    permit_nonce_store = InMemoryPermitNonceStoreV2()
    replayed_dpop = await verify_agent_permit_v2_async(
        dpop_permit,
        policy=no_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=lambda: now,
        dpop=dpop_input,
        dpop_jti_store=dpop_store,
        nonce_store=permit_nonce_store,
    )
    assert not replayed_dpop.ok and replayed_dpop.reason == RefusalCode.DPOP_PROOF_INVALID
    assert permit_nonce_store.peek("9" * 64) is None

    class _ExplodingDpopStore:
        def consume(self, jti: str, expires_at: int, now_seconds: int) -> bool:
            raise RuntimeError("dpop redis offline")

    unavail_dpop = await verify_agent_permit_v2_async(
        dpop_permit,
        policy=no_scitt_policy,
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=lambda: now,
        dpop=dpop_input,
        dpop_jti_store=_ExplodingDpopStore(),
    )
    assert not unavail_dpop.ok
    assert unavail_dpop.decision == "unavailable"
    assert unavail_dpop.reason == RefusalCode.STATE_UNAVAILABLE

    # 3. Callable now_seconds re-checks voice verdict exp after async JWKS fetch before nonce consume.
    short_voice = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "6" * 64,
            "iat": now - 25,
            "exp": now + 10,
            "session_id": "call-clock",
            "verdict": "likely_human",
            "calibrated_llr": 4.2,
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
                "status": "not_applicable",
                "windows_evaluated": 1,
                "floor_spread_db": None,
                "tail_decay_spread_db": None,
                "spectral_tilt_drift": None,
                "reason": "single_window",
            },
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    voice_permit = sign_eddsa_compact_jws(
        private_key=priv,
        kid="k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {"id": "spiffe://acme/agent"},
            "aud": audience,
            "jti": "8" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "voice_liveness_webrtc",
            "modality": ["voice_liveness"],
            "freshness_verified_at": now - 25,
            "continuity": {"session_id": "call-clock", "mode": "call_session", "call_continuity_verified": True},
            "uniqueness_status": "session_bound",
            "voice_verdict_jws": short_voice,
            "webauthn_assertion_digest": None,
            "policy_id": "voice-clock-pol",
            "scitt_receipt": None,
        },
    )
    ticks = iter([now, now + 20])
    voice_store = InMemoryPermitNonceStoreV2()
    voice_exp = await verify_agent_permit_v2_async(
        voice_permit,
        policy=PolicyV2(
            policy_id="voice-clock-pol",
            allowed_assurance_tiers=["voice_liveness_webrtc"],
            required_modalities=["voice_liveness"],
            max_evidence_age_seconds=120,
        ),
        expected_audience=audience,
        jwks=jwks,
        action=action,
        now_seconds=lambda: next(ticks),
        nonce_store=voice_store,
    )
    assert not voice_exp.ok and voice_exp.reason == RefusalCode.VOICE_VERDICT_INVALID
    assert voice_store.peek("8" * 64) is None
