"""Unit tests for WebAuthn P-256 (low-S & high-S), SCITT COSE_Sign1, and RFC 9449 DPoP."""

from __future__ import annotations

import hashlib
import json

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from entros_verify import (
    AGENT_PERMIT_TYP,
    InMemoryDpopJtiStore,
    PolicyV2,
    RefusalCode,
    ScittDecisionPayload,
    StaticJwksProvider,
    WebAuthnAssertionInput,
    compute_access_token_hash,
    compute_jwk_thumbprint,
    compute_webauthn_assertion_digest,
    derive_webauthn_challenge,
    hash_action_v2,
    verify_agent_permit_v2,
    verify_dpop_proof,
    verify_scitt_receipt,
    verify_scitt_receipt_async,
    verify_webauthn_assertion,
)
from entros_verify._testing import (
    b64url_encode_nopad,
    create_scitt_receipt,
    sign_eddsa_compact_jws,
)
from entros_verify.scitt import ScittVerificationError

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _ed25519_jwk(priv: Ed25519PrivateKey, *, include_private: bool = False) -> dict[str, object]:
    jwk: dict[str, object] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
    }
    if include_private:
        jwk["d"] = b64url_encode_nopad(priv.private_bytes_raw())
    return jwk


def _p256_jwk(priv: ec.EllipticCurvePrivateKey) -> dict[str, object]:
    nums = priv.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode_nopad(nums.x.to_bytes(32, "big")),
        "y": b64url_encode_nopad(nums.y.to_bytes(32, "big")),
    }


def _sign_eddsa_dpop(
    priv: Ed25519PrivateKey,
    payload: dict[str, object],
    *,
    include_private: bool = False,
    extra_header: dict[str, object] | None = None,
) -> str:
    header: dict[str, object] = {
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": _ed25519_jwk(priv, include_private=include_private),
    }
    if extra_header:
        header.update(extra_header)
    h_b64 = b64url_encode_nopad(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode_nopad(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = priv.sign(f"{h_b64}.{p_b64}".encode("ascii"))
    return f"{h_b64}.{p_b64}.{b64url_encode_nopad(sig)}"


def test_webauthn_accepts_all_key_formats_and_enforces_sign_count_and_strict_json() -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    jti = "4f8c2a19d7e34b6081a5c9e02f3b4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3"
    req_digest = "46cce3c855fad84ea66dc03884f83f836cbb17cf9171e41ecb0789f558265be4"
    _, chal_b64 = derive_webauthn_challenge(jti, req_digest)

    rp_id = "approve.entros.io"
    origin = "https://approve.entros.io"
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + (7).to_bytes(4, "big")
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": chal_b64,
            "origin": origin,
            "crossOrigin": True,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    signed_data = auth_data + hashlib.sha256(client_data).digest()
    raw_der = priv.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    r_val, s_val = decode_dss_signature(raw_der)
    high_s = s_val if s_val > P256_ORDER // 2 else P256_ORDER - s_val
    high_s_der = encode_dss_signature(r_val, high_s)
    cred_id = b"cred-hardware-key-1"

    pem_pub = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    der_pub = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sec1_comp = pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )

    expected_digest = compute_webauthn_assertion_digest(
        authenticator_data=auth_data,
        client_data_json=client_data,
        credential_id=cred_id,
        der_signature=high_s_der,
    )

    # crossOrigin=True rejected by default.
    denied = verify_webauthn_assertion(
        WebAuthnAssertionInput(
            authenticator_data=auth_data,
            client_data_json=client_data,
            signature=high_s_der,
            credential_id=cred_id,
            public_key=pem_pub,
            expected_rp_id=rp_id,
            expected_origin=origin,
            allow_cross_origin=False,
        ),
        jti=jti,
        request_digest=req_digest,
    )
    assert not denied.ok and denied.reason == RefusalCode.WEBAUTHN_ASSERTION_INVALID

    # Accepted across PEM, SPKI DER, and compressed SEC1 when allow_cross_origin=True.
    for key_repr in (pem_pub, der_pub, sec1_comp):
        res = verify_webauthn_assertion(
            WebAuthnAssertionInput(
                authenticator_data=auth_data,
                client_data_json=client_data,
                signature=high_s_der,
                credential_id=cred_id,
                public_key=key_repr,
                expected_rp_id=rp_id,
                expected_origin=origin,
                stored_sign_count=0,
                allow_cross_origin=True,
            ),
            jti=jti,
            request_digest=req_digest,
            expected_assertion_digest=expected_digest,
        )
        assert res.ok and res.sign_count == 7
        assert res.assertion_digest == expected_digest

    # Rollback to sign_count == 0 when stored_sign_count > 0 must be rejected.
    zero_count_auth = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
    valid_client_data = json.dumps(
        {"type": "webauthn.get", "challenge": chal_b64, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    zero_sig = priv.sign(
        zero_count_auth + hashlib.sha256(valid_client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    rollback = verify_webauthn_assertion(
        WebAuthnAssertionInput(
            authenticator_data=zero_count_auth,
            client_data_json=valid_client_data,
            signature=zero_sig,
            credential_id=cred_id,
            public_key=pem_pub,
            expected_rp_id=rp_id,
            expected_origin=origin,
            stored_sign_count=5,
        ),
        jti=jti,
        request_digest=req_digest,
    )
    assert not rollback.ok and rollback.reason == RefusalCode.WEBAUTHN_ASSERTION_INVALID

    # Duplicate JSON keys in clientDataJSON must be rejected.
    dup_client_data = (
        f'{{"type":"webauthn.get","challenge":"{chal_b64}",'
        f'"origin":"https://evil.example","origin":"{origin}"}}'
    ).encode()
    dup_sig = priv.sign(
        auth_data + hashlib.sha256(dup_client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    dup_res = verify_webauthn_assertion(
        WebAuthnAssertionInput(
            authenticator_data=auth_data,
            client_data_json=dup_client_data,
            signature=dup_sig,
            credential_id=cred_id,
            public_key=pem_pub,
            expected_rp_id=rp_id,
            expected_origin=origin,
        ),
        jti=jti,
        request_digest=req_digest,
    )
    assert not dup_res.ok and dup_res.reason == RefusalCode.WEBAUTHN_ASSERTION_INVALID


async def test_scitt_hardening_crit_duplicate_keys_strict_fields_and_deny_decision() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "scitt-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    action: dict[str, object] = {
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250},
    }
    req_digest = hash_action_v2(action)
    jti = "4f8c2a19d7e34b6081a5c9e02f3b4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3"
    now = 1795450110
    payload = ScittDecisionPayload(
        schema="entros-scitt-permit-v2",
        jti=jti,
        request_digest=req_digest,
        policy_id="wire-transfer-high-v2",
        aud="https://mcp.acme-bank.example/v1/mcp",
        decision="allow",
        reason="accepted",
        assurance_tier="passkey_webauthn_uv",
        modality=["webauthn_uv"],
        freshness_verified_at=now - 10,
        evaluated_at=now,
        model_version=None,
        retention="memory_only",
    )
    sibling_a = hashlib.sha256(b"leaf-a").digest()
    sibling_b = hashlib.sha256(b"leaf-b").digest()
    receipt_b64 = create_scitt_receipt(
        private_key=priv,
        kid="scitt-k1",
        payload=payload,
        tree_size=4,
        leaf_index=2,
        audit_path=[sibling_a, sibling_b],
    )
    verified = verify_scitt_receipt(receipt_b64, jwks=jwks)
    assert verified.tree_size == 4 and verified.leaf_index == 2
    verified_async = await verify_scitt_receipt_async(receipt_b64, jwks=jwks)
    assert verified_async.merkle_root_hex == verified.merkle_root_hex

    # Trailing bytes after CBOR envelope must be rejected.
    raw = cbor2.dumps(cbor2.CBORTag(18, [b"a", {}, b"b", b"\x00" * 64])) + b"\x00"
    with pytest.raises(ScittVerificationError, match="Trailing"):
        verify_scitt_receipt(raw, jwks=jwks)

    # Helper to sign arbitrary protected map + payload bytes for adversarial COSE tests.
    def _sign_raw_cose(protected_bytes: bytes, payload_bytes: bytes) -> bytes:
        leaf = hashlib.sha256(b"\x00" + payload_bytes).digest()
        sig_struct = cbor2.dumps(["Signature1", protected_bytes, b"", leaf])
        sig = priv.sign(sig_struct)
        return cbor2.dumps(
            cbor2.CBORTag(18, [protected_bytes, {396: {-1: [1, 0, []]}}, payload_bytes, sig])
        )

    valid_payload_bytes = json.dumps(
        payload.model_dump(by_alias=True), separators=(",", ":")
    ).encode("utf-8")

    # COSE protected header label 2 (crit) must be rejected.
    crit_protected = cbor2.dumps({1: -8, 2: [99], 4: b"scitt-k1", 395: 1})
    with pytest.raises(ScittVerificationError, match="crit"):
        verify_scitt_receipt(_sign_raw_cose(crit_protected, valid_payload_bytes), jwks=jwks)

    # Duplicate CBOR map key in protected header must be rejected.
    # Map of 4 pairs: {1: -8, 4: b"scitt-k1", 395: 1, 1: -8}
    dup_cbor_protected = (
        bytes([0xA4])
        + cbor2.dumps(1)
        + cbor2.dumps(-8)
        + cbor2.dumps(4)
        + cbor2.dumps(b"scitt-k1")
        + cbor2.dumps(395)
        + cbor2.dumps(1)
        + cbor2.dumps(1)
        + cbor2.dumps(-8)
    )
    with pytest.raises(ScittVerificationError, match=r"[Dd]uplicate"):
        verify_scitt_receipt(_sign_raw_cose(dup_cbor_protected, valid_payload_bytes), jwks=jwks)

    # Duplicate JSON keys in SCITT payload_bstr must be rejected.
    normal_protected = cbor2.dumps({1: -8, 4: b"scitt-k1", 395: 1})
    dup_json_payload = valid_payload_bytes[:-1] + b',"decision":"deny"}'
    with pytest.raises(ScittVerificationError, match=r"[Dd]uplicate"):
        verify_scitt_receipt(_sign_raw_cose(normal_protected, dup_json_payload), jwks=jwks)

    # Invalid standalone SCITT statement fields (bad jti / non-canonical aud) must be rejected.
    bad_jti_payload = payload.model_dump(by_alias=True)
    bad_jti_payload["jti"] = "not-64-hex"
    with pytest.raises(ScittVerificationError):
        verify_scitt_receipt(
            _sign_raw_cose(normal_protected, json.dumps(bad_jti_payload).encode("utf-8")),
            jwks=jwks,
        )

    # Valid SCITT receipt with decision="deny" must be rejected during permit verification (Step 28).
    deny_payload = payload.model_copy(update={"decision": "deny", "reason": "policy_denied"})
    deny_receipt = create_scitt_receipt(private_key=priv, kid="scitt-k1", payload=deny_payload)
    assert verify_scitt_receipt(deny_receipt, jwks=jwks).payload.decision == "deny"

    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="scitt-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-1",
            "actor": {"id": "spiffe://acme/agent"},
            "aud": "https://mcp.acme-bank.example/v1/mcp",
            "jti": jti,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": req_digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 10,
            "continuity": {"session_id": "s1", "mode": "step_up_only"},
            "uniqueness_status": "unmeasured",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "f" * 64,
            "policy_id": "wire-transfer-high-v2",
            "scitt_receipt": deny_receipt,
        },
    )
    permit_res = verify_agent_permit_v2(
        permit_jws,
        policy=PolicyV2(
            policy_id="wire-transfer-high-v2",
            allowed_assurance_tiers=["passkey_webauthn_uv"],
            required_modalities=["webauthn_uv"],
            max_evidence_age_seconds=120,
            require_scitt_receipt=True,
        ),
        expected_audience="https://mcp.acme-bank.example/v1/mcp",
        action=action,
        jwks=jwks,
        now_seconds=now,
    )
    assert not permit_res.ok and permit_res.reason == RefusalCode.SCITT_RECEIPT_INVALID


def test_dpop_eddsa_es256_hardening_and_replay_store() -> None:
    ed_priv = Ed25519PrivateKey.generate()
    jkt = compute_jwk_thumbprint(_ed25519_jwk(ed_priv))
    permit_jws = "header.payload.signature"
    ath = compute_access_token_hash(permit_jws)
    now = 1795450150

    # Default port :443 normalization & query/fragment stripping on expected_htu succeeds.
    valid_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-unique-1",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now - 5,
            "ath": ath,
        },
    )
    jti_store = InMemoryDpopJtiStore()
    ok_res = verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="post",
        expected_htu="https://mcp.acme-bank.example:443/v1/mcp?ignored=1#frag",
        permit_jws=permit_jws,
        now_seconds=now,
        jti_store=jti_store,
    )
    assert ok_res.ok and ok_res.jkt == jkt

    # Replaying the exact same DPoP jti must be rejected by jti_store.
    replay_res = verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
        jti_store=jti_store,
    )
    assert not replay_res.ok and replay_res.detail is not None and "replay" in replay_res.detail.lower()

    # Query/fragment inside proof payload["htu"] must be rejected per RFC 9449 Section 4.2.
    query_in_payload = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-query-leak",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp?leak=1",
            "iat": now - 5,
            "ath": ath,
        },
    )
    assert not verify_dpop_proof(
        proof_jwt=query_in_payload,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok

    # Forbidden DPoP headers (crit, jku, x5u, x5c) must be rejected.
    forbidden_headers: tuple[dict[str, object], ...] = (
        {"crit": ["exp"]},
        {"jku": "https://evil.example/jwks.json"},
        {"x5u": "https://evil.example/cert.pem"},
        {"x5c": ["MIIB"]},
    )
    for forbidden in forbidden_headers:
        bad_hdr = _sign_eddsa_dpop(
            ed_priv,
            {
                "jti": "dpop-forbidden-hdr",
                "htm": "POST",
                "htu": "https://mcp.acme-bank.example/v1/mcp",
                "iat": now,
                "ath": ath,
            },
            extra_header=forbidden,
        )
        assert not verify_dpop_proof(
            proof_jwt=bad_hdr,
            expected_jkt=jkt,
            expected_htm="POST",
            expected_htu="https://mcp.acme-bank.example/v1/mcp",
            permit_jws=permit_jws,
            now_seconds=now,
        ).ok

    # Userinfo in htu must be rejected.
    userinfo_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-userinfo",
            "htm": "POST",
            "htu": "https://user:pass@mcp.acme-bank.example/v1/mcp",
            "iat": now,
            "ath": ath,
        },
    )
    assert not verify_dpop_proof(
        proof_jwt=userinfo_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://user:pass@mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok

    # Private JWK parameter inside DPoP header must be rejected.
    leaked_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-unique-2",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now - 5,
            "ath": ath,
        },
        include_private=True,
    )
    assert not verify_dpop_proof(
        proof_jwt=leaked_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok

    # Stale DPoP iat must be rejected.
    stale_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-unique-3",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now - 120,
            "ath": ath,
        },
    )
    assert not verify_dpop_proof(
        proof_jwt=stale_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
        max_age_seconds=60,
    ).ok

    # Verify ES256 JWK key path as well.
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = _p256_jwk(ec_priv)
    ec_jkt = compute_jwk_thumbprint(ec_jwk)
    h_b64 = b64url_encode_nopad(
        json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": ec_jwk}, separators=(",", ":")).encode()
    )
    p_b64 = b64url_encode_nopad(
        json.dumps(
            {
                "jti": "dpop-ec-1",
                "htm": "POST",
                "htu": "https://mcp.acme-bank.example/v1/mcp",
                "iat": now,
                "ath": ath,
            },
            separators=(",", ":"),
        ).encode()
    )
    der = ec_priv.sign(f"{h_b64}.{p_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der)
    raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")
    ec_proof = f"{h_b64}.{p_b64}.{b64url_encode_nopad(raw_sig)}"
    assert verify_dpop_proof(
        proof_jwt=ec_proof,
        expected_jkt=ec_jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok


def test_dpop_scitt_and_webauthn_parity_hardening_regressions() -> None:
    # 1. WebAuthn: 130-char uncompressed hex public key & derive_webauthn_challenge validation.
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_uncompressed_hex = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()
    assert len(pub_uncompressed_hex) == 130 and pub_uncompressed_hex.startswith("04")

    jti = "4f8c2a19d7e34b6081a5c9e02f3b4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3"
    req_digest = "46cce3c855fad84ea66dc03884f83f836cbb17cf9171e41ecb0789f558265be4"
    _, chal_b64 = derive_webauthn_challenge(jti, req_digest)
    rp_id = "approve.entros.io"
    origin = "https://approve.entros.io"
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + (1).to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": chal_b64, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    sig = priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    hex_res = verify_webauthn_assertion(
        WebAuthnAssertionInput(
            authenticator_data=auth_data,
            client_data_json=client_data,
            signature=sig,
            credential_id=b"cred-hex",
            public_key=pub_uncompressed_hex,
            expected_rp_id=rp_id,
            expected_origin=origin,
        ),
        jti=jti,
        request_digest=req_digest,
    )
    assert hex_res.ok

    with pytest.raises(ValueError, match="jti"):
        derive_webauthn_challenge("0" * 64, req_digest)
    with pytest.raises(ValueError, match="request_digest"):
        derive_webauthn_challenge(jti, "not-hex")

    # 2. DPoP: non-ASCII ath/expected_jkt fail cleanly without UnicodeEncodeError; dot-segment normalization; bounds; full store fails closed.
    ed_priv = Ed25519PrivateKey.generate()
    jkt = compute_jwk_thumbprint(_ed25519_jwk(ed_priv))
    permit_jws = "header.payload.signature"
    ath = compute_access_token_hash(permit_jws)
    now = 1795450200

    non_ascii_ath_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-nonascii",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now,
            "ath": "café-non-ascii",
        },
    )
    assert not verify_dpop_proof(
        proof_jwt=non_ascii_ath_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok

    valid_proof = _sign_eddsa_dpop(
        ed_priv,
        {
            "jti": "dpop-dotseg",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now,
            "ath": ath,
        },
    )
    assert not verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt="non-ascii-é",
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok
    assert verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/sub/../mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    ).ok
    assert not verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=0,
    ).ok
    assert not verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="POST",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
        max_age_seconds=0,
    ).ok

    full_dpop_store = InMemoryDpopJtiStore(max_entries=2)
    assert full_dpop_store.consume("j1", now + 60, now)
    assert full_dpop_store.consume("j2", now + 60, now)
    # Full store fails closed instead of evicting active j1.
    assert not full_dpop_store.consume("j3", now + 60, now)
    assert not full_dpop_store.consume("j1", now + 60, now)

    # 3. SCITT: rejects CBOR major type 7, excessive nesting depth (> 16), blank kid, and crit (2) in unprotected map.
    scitt_priv = Ed25519PrivateKey.generate()
    scitt_jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "scitt-k2",
                    "x": b64url_encode_nopad(scitt_priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    payload_bytes = json.dumps(
        {
            "schema": "entros-scitt-permit-v2",
            "jti": jti,
            "request_digest": req_digest,
            "policy_id": "pol_1",
            "aud": "https://mcp.acme-bank.example/v1/mcp",
            "decision": "allow",
            "reason": "accepted",
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 10,
            "evaluated_at": now,
            "model_version": None,
            "retention": "memory_only",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    leaf = hashlib.sha256(b"\x00" + payload_bytes).digest()
    normal_prot = cbor2.dumps({1: -8, 4: b"scitt-k2", 395: 1})
    sig_val = scitt_priv.sign(cbor2.dumps(["Signature1", normal_prot, b"", leaf]))

    # Unprotected crit (2) must be rejected.
    unprot_crit = cbor2.dumps(
        cbor2.CBORTag(18, [normal_prot, {2: [99], 396: {-1: [1, 0, []]}}, payload_bytes, sig_val])
    )
    with pytest.raises(ScittVerificationError, match="crit"):
        verify_scitt_receipt(unprot_crit, jwks=scitt_jwks)

    # CBOR major type 7 (True/float) inside COSE structure must be rejected.
    major7 = cbor2.dumps(
        cbor2.CBORTag(18, [normal_prot, {396: {-1: [1, 0, []]}, 999: True}, payload_bytes, sig_val])
    )
    with pytest.raises(ScittVerificationError, match=r"major type.*7"):
        verify_scitt_receipt(major7, jwks=scitt_jwks)

    # Nesting depth > 16 must be rejected.
    nested: object = []
    for _ in range(20):
        nested = [nested]
    deep_cbor = cbor2.dumps(
        cbor2.CBORTag(18, [normal_prot, {396: {-1: [1, 0, []]}, 998: nested}, payload_bytes, sig_val])
    )
    with pytest.raises(ScittVerificationError, match="nesting"):
        verify_scitt_receipt(deep_cbor, jwks=scitt_jwks)

    # Blank kid must be rejected.
    blank_kid_prot = cbor2.dumps({1: -8, 4: b"   ", 395: 1})
    blank_sig = scitt_priv.sign(cbor2.dumps(["Signature1", blank_kid_prot, b"", leaf]))
    blank_cbor = cbor2.dumps(
        cbor2.CBORTag(18, [blank_kid_prot, {396: {-1: [1, 0, []]}}, payload_bytes, blank_sig])
    )
    with pytest.raises(ScittVerificationError, match="kid"):
        verify_scitt_receipt(blank_cbor, jwks=scitt_jwks)
