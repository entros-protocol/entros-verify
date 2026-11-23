"""Unit tests for strict RFC 8032 / zip215=False Ed25519 JWS and JWKS caching."""

from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    JwksCache,
    JwksUnavailableError,
    PolicyV2,
    RefusalCode,
    ScittDecisionPayload,
    ScittVerificationError,
    StaticJwksProvider,
    b64url_encode_nopad,
    create_scitt_receipt,
    sign_eddsa_compact_jws,
    verify_agent_permit_v2,
    verify_agent_permit_v2_async,
    verify_ed25519_strict,
    verify_scitt_receipt,
    verify_scitt_receipt_async,
    verify_voice_liveness_verdict,
    verify_voice_liveness_verdict_async,
)


def _ed25519_jwk(priv: Ed25519PrivateKey, kid: str, *, status: str | None = None) -> dict[str, object]:
    raw_pub = priv.public_key().public_bytes_raw()
    entry: dict[str, object] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "kid": kid,
        "x": b64url_encode_nopad(raw_pub),
    }
    if status is not None:
        entry["status"] = status
    return entry


def test_strict_ed25519_rejects_small_order_non_canonical_and_high_scalar() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    msg = b"entros-strict-ed25519-test"
    sig = priv.sign(msg)
    assert verify_ed25519_strict(pub, sig, msg)

    # 1. Identity small-order public key (order 1) + R=identity, S=0.
    id_point = bytes([1]) + bytes(31)
    assert not verify_ed25519_strict(id_point, id_point + bytes(32), msg)

    # 2. Order-2 small-order point (0, -1): p - 1 = 0xecffff...7f.
    order2 = ((1 << 255) - 20).to_bytes(32, "little")
    assert not verify_ed25519_strict(order2, order2 + bytes(32), msg)

    # 3. Non-canonical y = p (2^255 - 19) encoding of y = 0.
    non_canonical_y = ((1 << 255) - 19).to_bytes(32, "little")
    assert not verify_ed25519_strict(non_canonical_y, sig, msg)

    # 4. Non-canonical x = 0 with sign bit 1 on identity point (0, 1).
    non_canonical_zero_x = bytearray(id_point)
    non_canonical_zero_x[31] |= 0x80
    assert not verify_ed25519_strict(bytes(non_canonical_zero_x), sig, msg)

    # 5. Signature scalar S >= L (adding L to valid S).
    l_order = (1 << 252) + 27742317777372353535851937790883648493
    s_int = int.from_bytes(sig[32:], "little")
    bad_sig = sig[:32] + (s_int + l_order).to_bytes(32, "little")
    assert not verify_ed25519_strict(pub, bad_sig, msg)


def test_jwks_cache_ttl_negative_cache_and_single_refresh() -> None:
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    now_holder = [1000.0]
    fetch_count = [0]
    active_keys: list[dict[str, object]] = [_ed25519_jwk(k1, "kid-1")]

    def _handler(request: httpx.Request) -> httpx.Response:
        fetch_count[0] += 1
        return httpx.Response(200, json={"keys": list(active_keys)})

    cache = JwksCache(
        "https://api.entros.io/.well-known/jwks.json",
        ttl_seconds=300.0,
        negative_cache_seconds=10.0,
        clock=lambda: now_holder[0],
        sync_transport=httpx.MockTransport(_handler),
    )

    # First fetch loads kid-1.
    r1 = cache.get_key("kid-1")
    assert r1.status == "found"
    assert fetch_count[0] == 1

    # Repeated lookup within TTL hits cache without network call.
    now_holder[0] += 100.0
    assert cache.get_key("kid-1").status == "found"
    assert fetch_count[0] == 1

    # Unknown kid triggers exactly one refresh, then negative-caches for >= 10s.
    assert cache.get_key("missing-kid").status == "unknown"
    assert fetch_count[0] == 2
    now_holder[0] += 5.0
    assert cache.get_key("missing-kid").status == "unknown"
    assert fetch_count[0] == 2

    # Key rotation: after negative cache expires, unknown kid refreshes and resolves kid-2.
    active_keys.append(_ed25519_jwk(k2, "kid-2"))
    assert cache.get_key("kid-2").status == "found"
    assert fetch_count[0] == 3

    # After 300s TTL expires, cache refreshes.
    now_holder[0] += 301.0
    assert cache.get_key("kid-2").status == "found"
    assert fetch_count[0] == 4


def test_jwks_cache_validates_bounds_and_handles_unavailable() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        JwksCache("https://api.entros.io/.well-known/jwks.json", ttl_seconds=301.0)
    with pytest.raises(ValueError, match="negative_cache_seconds"):
        JwksCache("https://api.entros.io/.well-known/jwks.json", negative_cache_seconds=9.0)
    with pytest.raises(ValueError, match="canonical"):
        JwksCache("http://insecure.example/.well-known/jwks.json")

    def _fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    failing_cache = JwksCache(
        "https://api.entros.io/.well-known/jwks.json",
        sync_transport=httpx.MockTransport(_fail),
    )
    with pytest.raises(JwksUnavailableError):
        failing_cache.get_key("any-kid")

    priv = Ed25519PrivateKey.generate()
    token = sign_eddsa_compact_jws(
        private_key=priv,
        kid="kid-1",
        typ=AGENT_PERMIT_TYP,
        payload={"iss": "https://api.entros.io"},
    )
    policy = PolicyV2(
        policy_id="p",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    res = verify_agent_permit_v2(
        token,
        policy=policy,
        expected_audience="https://mcp.example/v1",
        expected_request_digest="a" * 64,
        jwks=failing_cache,
        now_seconds=1795450150,
    )
    assert not res.ok
    assert res.decision == "unavailable"
    assert res.reason == RefusalCode.STATE_UNAVAILABLE


async def test_caller_revoked_kids_enforced_for_static_provider_and_jwks_cache() -> None:
    priv = Ed25519PrivateKey.generate()
    priv_other = Ed25519PrivateKey.generate()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    digest = "a" * 64
    jwks_doc: dict[str, object] = {
        "keys": [
            _ed25519_jwk(priv, "kid-target"),
            _ed25519_jwk(priv_other, "kid-provider-revoked"),
        ]
    }
    static_provider = StaticJwksProvider(jwks_doc, revoked_kids={"kid-provider-revoked"})

    fetch_count = [0]

    def _handler(request: httpx.Request) -> httpx.Response:
        fetch_count[0] += 1
        return httpx.Response(200, json=jwks_doc)

    cache_provider = JwksCache(
        "https://api.entros.io/.well-known/jwks.json",
        sync_transport=httpx.MockTransport(_handler),
        async_transport=httpx.MockTransport(_handler),
    )

    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="kid-target",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "user-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": audience,
            "jti": "1" * 64,
            "iat": now - 10,
            "exp": now + 290,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 10,
            "continuity": {"session_id": "sess-1", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "b" * 64,
            "policy_id": "p-v2",
            "scitt_receipt": None,
        },
    )
    voice_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="kid-target",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "2" * 64,
            "iat": now - 10,
            "exp": now + 110,
            "session_id": "sess-1",
            "verdict": "likely_human",
            "calibrated_llr": 3.5,
            "operating_profile": "webrtc_16k",
            "model_version": "c" * 64,
            "signal_quality": {
                "snr_db": 22.0,
                "speech_ms": 1800,
                "clipping": 0.001,
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
    scitt_receipt = create_scitt_receipt(
        private_key=priv,
        kid="kid-target",
        payload=ScittDecisionPayload(
            schema="entros-scitt-permit-v2",
            jti="1" * 64,
            request_digest=digest,
            policy_id="p-v2",
            aud=audience,
            decision="allow",
            reason="accepted",
            assurance_tier="passkey_webauthn_uv",
            modality=["webauthn_uv"],
            freshness_verified_at=now - 10,
            evaluated_at=now,
            model_version=None,
            retention="memory_only",
        ),
    )
    policy = PolicyV2(
        policy_id="p-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )

    # Without caller revocation, all three verify against StaticJwksProvider.
    assert verify_agent_permit_v2(
        permit_jws,
        policy=policy,
        expected_audience=audience,
        expected_request_digest=digest,
        jwks=static_provider,
        now_seconds=now,
        revoked_kids={"unrelated-kid"},
    ).ok
    assert verify_voice_liveness_verdict(
        voice_jws,
        jwks=static_provider,
        now_seconds=now,
        revoked_kids={"unrelated-kid"},
    ).ok
    assert verify_scitt_receipt(
        scitt_receipt,
        jwks=static_provider,
        revoked_kids={"unrelated-kid"},
    ).kid == "kid-target"

    # Provider-level revocation still applies when caller also passes revoked_kids.
    provider_revoked_jws = sign_eddsa_compact_jws(
        private_key=priv_other,
        kid="kid-provider-revoked",
        typ=AGENT_PERMIT_TYP,
        payload={"iss": "https://api.entros.io"},
    )
    res_union = verify_agent_permit_v2(
        provider_revoked_jws,
        policy=policy,
        expected_audience=audience,
        expected_request_digest=digest,
        jwks=static_provider,
        now_seconds=now,
        revoked_kids={"unrelated-kid"},
    )
    assert not res_union.ok and res_union.reason == RefusalCode.REVOKED_KID

    # Caller-supplied revoked_kids MUST reject for both StaticJwksProvider and JwksCache
    # across sync and async permit, voice, and SCITT verifiers (zero fetches for JwksCache).
    for provider in (static_provider, cache_provider):
        p_sync = verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            expected_request_digest=digest,
            jwks=provider,
            now_seconds=now,
            revoked_kids={"kid-target"},
        )
        assert not p_sync.ok and p_sync.reason == RefusalCode.REVOKED_KID

        p_async = await verify_agent_permit_v2_async(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            expected_request_digest=digest,
            jwks=provider,
            now_seconds=now,
            revoked_kids={"kid-target"},
        )
        assert not p_async.ok and p_async.reason == RefusalCode.REVOKED_KID

        v_sync = verify_voice_liveness_verdict(
            voice_jws,
            jwks=provider,
            now_seconds=now,
            revoked_kids={"kid-target"},
        )
        assert not v_sync.ok and v_sync.reason == RefusalCode.REVOKED_KID

        v_async = await verify_voice_liveness_verdict_async(
            voice_jws,
            jwks=provider,
            now_seconds=now,
            revoked_kids={"kid-target"},
        )
        assert not v_async.ok and v_async.reason == RefusalCode.REVOKED_KID

        with pytest.raises(ScittVerificationError, match="revoked"):
            verify_scitt_receipt(
                scitt_receipt,
                jwks=provider,
                revoked_kids={"kid-target"},
            )
        with pytest.raises(ScittVerificationError, match="revoked"):
            await verify_scitt_receipt_async(
                scitt_receipt,
                jwks=provider,
                revoked_kids={"kid-target"},
            )

    assert fetch_count[0] == 0
