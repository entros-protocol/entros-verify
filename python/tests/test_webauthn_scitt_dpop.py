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
from joserfc.jwk import ECKey, OKPKey

from entros_verify import (
    RefusalCode,
    ScittDecisionPayload,
    StaticJwksProvider,
    WebAuthnAssertionInput,
    b64url_encode_nopad,
    compute_access_token_hash,
    compute_webauthn_assertion_digest,
    create_scitt_receipt,
    derive_webauthn_challenge,
    verify_dpop_proof,
    verify_scitt_receipt,
    verify_scitt_receipt_async,
    verify_webauthn_assertion,
)
from entros_verify.scitt import ScittVerificationError

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_webauthn_accepts_all_key_formats_and_cross_origin_toggle() -> None:
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


async def test_scitt_create_and_verify_roundtrip_and_trailing_bytes() -> None:
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
    payload = ScittDecisionPayload(
        schema="entros-scitt-permit-v2",
        jti="4f8c2a19d7e34b6081a5c9e02f3b4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3",
        request_digest="46cce3c855fad84ea66dc03884f83f836cbb17cf9171e41ecb0789f558265be4",
        policy_id="wire-transfer-high-v2",
        aud="https://mcp.acme-bank.example/v1/mcp",
        decision="allow",
        reason="accepted",
        assurance_tier="passkey_webauthn_uv",
        modality=["webauthn_uv"],
        freshness_verified_at=1795450100,
        evaluated_at=1795450110,
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


def _sign_eddsa_dpop(okp_key: OKPKey, payload: dict[str, object], *, include_private: bool = False) -> str:
    jwk_dict = okp_key.as_dict(private=include_private)
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk_dict}
    h_b64 = b64url_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    raw_priv = okp_key.raw_value
    assert isinstance(raw_priv, Ed25519PrivateKey)
    sig = raw_priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{b64url_encode_nopad(sig)}"


def test_dpop_eddsa_and_es256_verification_and_rejections() -> None:
    okp_key = OKPKey.generate_key("Ed25519")
    jkt = okp_key.thumbprint()
    permit_jws = "header.payload.signature"
    now = 1795450150

    valid_proof = _sign_eddsa_dpop(
        okp_key,
        {
            "jti": "dpop-unique-1",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp?ignored=1#frag",
            "iat": now - 5,
            "ath": compute_access_token_hash(permit_jws),
        },
    )
    ok_res = verify_dpop_proof(
        proof_jwt=valid_proof,
        expected_jkt=jkt,
        expected_htm="post",
        expected_htu="https://mcp.acme-bank.example/v1/mcp",
        permit_jws=permit_jws,
        now_seconds=now,
    )
    assert ok_res.ok and ok_res.jkt == jkt

    # Private JWK parameter inside DPoP header must be rejected.
    leaked_proof = _sign_eddsa_dpop(
        okp_key,
        {
            "jti": "dpop-unique-2",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now - 5,
            "ath": compute_access_token_hash(permit_jws),
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
        okp_key,
        {
            "jti": "dpop-unique-3",
            "htm": "POST",
            "htu": "https://mcp.acme-bank.example/v1/mcp",
            "iat": now - 120,
            "ath": compute_access_token_hash(permit_jws),
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
    ec_key = ECKey.generate_key("P-256")
    ec_jkt = ec_key.thumbprint()
    ec_priv = ec_key.raw_value
    assert isinstance(ec_priv, ec.EllipticCurvePrivateKey)
    h_b64 = b64url_encode_nopad(
        json.dumps(
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": ec_key.as_dict(private=False)},
            separators=(",", ":"),
        ).encode()
    )
    p_b64 = b64url_encode_nopad(
        json.dumps(
            {
                "jti": "dpop-ec-1",
                "htm": "POST",
                "htu": "https://mcp.acme-bank.example/v1/mcp",
                "iat": now,
                "ath": compute_access_token_hash(permit_jws),
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
