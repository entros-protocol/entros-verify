"""Zero-CBOR WebAuthn navigator.credentials.get() P-256 assertion verifier.

Accepts both low-S and high-S ASN.1 DER ECDSA P-256 (ES256) signatures emitted
by hardware FIDO2 authenticators, verifies UP=1 and UV=1 flags, validates
rpIdHash/origin/challenge with constant-time comparisons, checks signCount
rollback, and computes the canonical domain-separated webauthn_assertion_digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from entros_verify.canonical import canonicalize_jcs_bytes
from entros_verify.jws import (
    _parse_json_object_strict,
    b64url_decode_nopad,
    b64url_encode_nopad,
)
from entros_verify.models import (
    JsonObject,
    RefusalCode,
    WebAuthnAssertionInput,
    WebAuthnVerificationResult,
)

WEBAUTHN_CHALLENGE_PREFIX = b"Entros-WebAuthn-Challenge-v2\n"
WEBAUTHN_ASSERTION_PREFIX = b"Entros-WebAuthn-Assertion-v2\n"
FLAG_UP = 0x01
FLAG_UV = 0x04
MIN_AUTH_DATA_LEN = 37
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX130_RE = re.compile(r"^[0-9a-fA-F]{130}$")
_ZERO_HEX64 = "0" * 64


def _is_non_zero_hex64(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64_RE.match(value)) and value != _ZERO_HEX64


def _coerce_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return b64url_decode_nopad(value)
    raise ValueError("Expected bytes or unpadded Base64URL string")


def _coerce_client_data_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        # Accept raw UTF-8 JSON object string or unpadded Base64URL-encoded JSON.
        stripped = value.lstrip()
        if stripped.startswith("{"):
            return value.encode("utf-8")
        return b64url_decode_nopad(value)
    raise ValueError("Expected bytes or string for clientDataJSON")


def _load_p256_public_key(public_key: bytes | str | JsonObject) -> ec.EllipticCurvePublicKey:
    """Load an ECDSA P-256 public key from SEC1 raw bytes, SPKI DER, PEM, Base64URL, or JWK."""
    if isinstance(public_key, dict):
        if public_key.get("kty") != "EC" or public_key.get("crv") != "P-256":
            raise ValueError("JWK public key must be EC P-256")
        x_raw = public_key.get("x")
        y_raw = public_key.get("y")
        if not isinstance(x_raw, str) or not isinstance(y_raw, str):
            raise ValueError("JWK EC key requires Base64URL x and y coordinates")
        x_bytes = b64url_decode_nopad(x_raw)
        y_bytes = b64url_decode_nopad(y_raw)
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise ValueError("P-256 coordinates must be 32 bytes each")
        sec1 = b"\x04" + x_bytes + y_bytes
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sec1)

    raw_bytes: bytes
    if isinstance(public_key, str):
        if "-----BEGIN" in public_key:
            loaded_pem = serialization.load_pem_public_key(public_key.encode("utf-8"))
            if not isinstance(loaded_pem, ec.EllipticCurvePublicKey) or not isinstance(
                loaded_pem.curve, ec.SECP256R1
            ):
                raise ValueError("PEM key must be ECDSA P-256")
            return loaded_pem
        if len(public_key) == 130 and _HEX130_RE.match(public_key):
            raw_bytes = bytes.fromhex(public_key)
            if raw_bytes[0] != 0x04:
                raise ValueError("Uncompressed hex P-256 public key must start with 0x04")
        else:
            raw_bytes = b64url_decode_nopad(public_key)
    elif isinstance(public_key, bytes):
        if public_key.startswith(b"-----BEGIN"):
            loaded_pem = serialization.load_pem_public_key(public_key)
            if not isinstance(loaded_pem, ec.EllipticCurvePublicKey) or not isinstance(
                loaded_pem.curve, ec.SECP256R1
            ):
                raise ValueError("PEM key must be ECDSA P-256")
            return loaded_pem
        raw_bytes = public_key
    else:
        raise ValueError("Unsupported public_key representation")

    if len(raw_bytes) in (33, 65) and raw_bytes[0] in (0x02, 0x03, 0x04):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_bytes)

    loaded_der = serialization.load_der_public_key(raw_bytes)
    if not isinstance(loaded_der, ec.EllipticCurvePublicKey) or not isinstance(
        loaded_der.curve, ec.SECP256R1
    ):
        raise ValueError("DER SPKI key must be ECDSA P-256")
    return loaded_der


def derive_webauthn_challenge(jti: str, request_digest: str) -> tuple[bytes, str]:
    """Derive 32-byte permit_challenge and its unpadded Base64URL encoding."""
    if not _is_non_zero_hex64(jti):
        raise ValueError("Permit jti must be a non-zero 64-char lowercase hex string")
    if not _is_non_zero_hex64(request_digest):
        raise ValueError("Permit request_digest must be a non-zero 64-char lowercase hex string")
    preimage = (
        WEBAUTHN_CHALLENGE_PREFIX
        + jti.encode("ascii")
        + b"\n"
        + request_digest.encode("ascii")
    )
    digest = hashlib.sha256(preimage).digest()
    return digest, b64url_encode_nopad(digest)


def compute_webauthn_assertion_digest(
    *,
    authenticator_data: bytes,
    client_data_json: bytes,
    credential_id: bytes,
    der_signature: bytes,
) -> str:
    """Compute lowercase 64-hex domain-separated webauthn_assertion_digest."""
    if len(authenticator_data) < MIN_AUTH_DATA_LEN:
        raise ValueError("authenticatorData must be at least 37 bytes")
    rp_id_hash = authenticator_data[:32]
    client_data_hash = hashlib.sha256(client_data_json).digest()
    tuple_obj: dict[str, str] = {
        "auth_data_sha256": hashlib.sha256(authenticator_data).hexdigest(),
        "client_data_sha256": client_data_hash.hex(),
        "credential_id": b64url_encode_nopad(credential_id),
        "rp_id_hash": rp_id_hash.hex(),
        "signature_sha256": hashlib.sha256(der_signature).hexdigest(),
    }
    assertion_tuple = canonicalize_jcs_bytes(tuple_obj, field="webauthn_assertion")
    return hashlib.sha256(WEBAUTHN_ASSERTION_PREFIX + assertion_tuple).hexdigest()


def verify_webauthn_assertion(
    assertion: WebAuthnAssertionInput,
    *,
    jti: str,
    request_digest: str,
    expected_assertion_digest: str | None = None,
) -> WebAuthnVerificationResult:
    """Verify a raw WebAuthn P-256 assertion without CBOR dependencies.

    Accepts both low-S and high-S DER signatures. Enforces rpIdHash, origin,
    challenge, signCount monotonicity, P-256 signature, and UP=1/UV=1 flags.
    """
    try:
        auth_data = _coerce_bytes(assertion.authenticator_data)
        client_data_raw = _coerce_client_data_bytes(assertion.client_data_json)
        der_sig = _coerce_bytes(assertion.signature)
        cred_id = _coerce_bytes(assertion.credential_id)
        pub_key = _load_p256_public_key(assertion.public_key)
    except (ValueError, TypeError):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    if len(auth_data) < MIN_AUTH_DATA_LEN or len(cred_id) == 0:
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")

    try:
        expected_rp_id_hash = hashlib.sha256(assertion.expected_rp_id.encode("utf-8")).digest()
        expected_origin_bytes = assertion.expected_origin.encode("utf-8")
        _, expected_challenge_b64url = derive_webauthn_challenge(jti, request_digest)
    except (ValueError, UnicodeEncodeError):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )
    if not hmac.compare_digest(rp_id_hash, expected_rp_id_hash):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    # Reject signCount rollback whenever stored_sign_count > 0 (including rollback to 0).
    if (
        assertion.stored_sign_count is not None
        and assertion.stored_sign_count > 0
        and sign_count <= assertion.stored_sign_count
    ):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    # Parse and validate clientDataJSON strictly.
    try:
        client_data = _parse_json_object_strict(client_data_raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    if client_data.get("type") != "webauthn.get":
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    origin = client_data.get("origin")
    if not isinstance(origin, str) or not hmac.compare_digest(
        origin.encode("utf-8"), expected_origin_bytes
    ):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    cross_origin = client_data.get("crossOrigin")
    if cross_origin is True and not assertion.allow_cross_origin:
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    challenge = client_data.get("challenge")
    if not isinstance(challenge, str) or not hmac.compare_digest(
        challenge.encode("utf-8"), expected_challenge_b64url.encode("ascii")
    ):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    # Validate strict ASN.1 DER structure and verify ECDSA P-256 (low-S and high-S accepted).
    try:
        r_int, s_int = decode_dss_signature(der_sig)
        if r_int <= 0 or s_int <= 0:
            return WebAuthnVerificationResult(
                ok=False,
                reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
            )
        if encode_dss_signature(r_int, s_int) != der_sig:
            return WebAuthnVerificationResult(
                ok=False,
                reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
            )
        client_data_hash = hashlib.sha256(client_data_raw).digest()
        signed_data = auth_data + client_data_hash
        pub_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    # Require UP=1 and UV=1 flags after cryptographic checks.
    if (flags & FLAG_UP) != FLAG_UP or (flags & FLAG_UV) != FLAG_UV:
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_UV_REQUIRED,
        )

    assertion_digest = compute_webauthn_assertion_digest(
        authenticator_data=auth_data,
        client_data_json=client_data_raw,
        credential_id=cred_id,
        der_signature=der_sig,
    )
    if expected_assertion_digest is not None and (
        not expected_assertion_digest.isascii()
        or not hmac.compare_digest(
            assertion_digest.encode("ascii"), expected_assertion_digest.encode("ascii")
        )
    ):
        return WebAuthnVerificationResult(
            ok=False,
            reason=RefusalCode.WEBAUTHN_ASSERTION_INVALID,
        )

    return WebAuthnVerificationResult(
        ok=True,
        reason=None,
        sign_count=sign_count,
        assertion_digest=assertion_digest,
        rp_id_hash_hex=rp_id_hash.hex(),
    )
