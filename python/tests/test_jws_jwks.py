"""Unit tests for strict RFC 8032 / zip215=False Ed25519 JWS and JWKS caching."""

from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    JwksCache,
    JwksUnavailableError,
    PolicyV2,
    RefusalCode,
    b64url_encode_nopad,
    sign_eddsa_compact_jws,
    verify_agent_permit_v2,
    verify_ed25519_strict,
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
