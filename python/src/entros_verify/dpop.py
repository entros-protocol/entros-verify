"""RFC 9449 DPoP (dpop+jwt) proof verifier using joserfc and cryptography.

Verifies sender-constrained AgentPermit v2 presentation proofs:
- Protected header typ == "dpop+jwt", asymmetric alg ("EdDSA" or "ES256"), embedded public jwk.
- RFC 7638 thumbprint of embedded jwk matches expected cnf.jkt / actor.key_jkt.
- Cryptographic JWS signature verification (strict Ed25519 for EdDSA; ECDSA P-256 for ES256).
- Claims: htm, htu (normalized without query/fragment), ath == b64url(SHA-256(permit_jws)), iat, jti.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from joserfc.jwk import ECKey, JWKRegistry, OKPKey

from entros_verify.jws import (
    _parse_json_object_strict,
    b64url_decode_nopad,
    b64url_encode_nopad,
    verify_ed25519_strict,
)
from entros_verify.models import MAX_CLOCK_SKEW_SECONDS

ALLOWED_DPOP_ALGS = frozenset({"EdDSA", "ES256"})
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


@dataclass(frozen=True)
class DpopVerificationResult:
    """Result of verifying an RFC 9449 DPoP proof JWT."""

    ok: bool
    jkt: str | None = None
    jti: str | None = None
    detail: str | None = None


def compute_access_token_hash(token: str) -> str:
    """Compute RFC 9449 ath = BASE64URL(SHA-256(ASCII(token)))."""
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return b64url_encode_nopad(digest)


def _normalize_htu(uri: str) -> str:
    """Strip query and fragment from an HTTP URI per RFC 9449 section 4.2."""
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("Invalid htu URI")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))


def _verify_es256_jws_signature(jwk_dict: dict[str, object], signing_input: bytes, raw_sig: bytes) -> bool:
    """Verify JWS ES256 raw (R || S) 64-byte signature over P-256."""
    if len(raw_sig) != 64:
        return False
    x_val = jwk_dict.get("x")
    y_val = jwk_dict.get("y")
    if not isinstance(x_val, str) or not isinstance(y_val, str):
        return False
    try:
        x_bytes = b64url_decode_nopad(x_val)
        y_bytes = b64url_decode_nopad(y_val)
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            return False
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + x_bytes + y_bytes
        )
        r_int = int.from_bytes(raw_sig[:32], "big")
        s_int = int.from_bytes(raw_sig[32:], "big")
        if r_int <= 0 or s_int <= 0:
            return False
        der_sig = encode_dss_signature(r_int, s_int)
        pub.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_dpop_proof(
    *,
    proof_jwt: str,
    expected_jkt: str,
    expected_htm: str,
    expected_htu: str,
    permit_jws: str,
    now_seconds: int,
    max_age_seconds: int = 60,
) -> DpopVerificationResult:
    """Verify an RFC 9449 DPoP proof bound to an AgentPermit v2 JWS."""
    if not isinstance(proof_jwt, str) or proof_jwt.count(".") != 2:
        return DpopVerificationResult(ok=False, detail="Malformed DPoP JWT")

    header_b64, payload_b64, sig_b64 = proof_jwt.split(".")
    try:
        header = _parse_json_object_strict(b64url_decode_nopad(header_b64))
        payload = _parse_json_object_strict(b64url_decode_nopad(payload_b64))
        sig_bytes = b64url_decode_nopad(sig_b64)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return DpopVerificationResult(ok=False, detail="Invalid DPoP encoding or JSON")

    if header.get("typ") != "dpop+jwt":
        return DpopVerificationResult(ok=False, detail="DPoP typ must be dpop+jwt")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_DPOP_ALGS:
        return DpopVerificationResult(ok=False, detail="Unsupported DPoP algorithm")

    jwk_obj = header.get("jwk")
    if not isinstance(jwk_obj, dict):
        return DpopVerificationResult(ok=False, detail="DPoP header missing public jwk")
    if any(field in jwk_obj for field in _PRIVATE_JWK_FIELDS):
        return DpopVerificationResult(ok=False, detail="DPoP jwk must not contain private key fields")

    try:
        imported = JWKRegistry.import_key(dict(jwk_obj))
        if imported.is_private:
            return DpopVerificationResult(ok=False, detail="DPoP jwk must be public")
        computed_jkt = imported.thumbprint()
    except Exception:
        return DpopVerificationResult(ok=False, detail="Invalid DPoP embedded JWK")

    if not hmac.compare_digest(computed_jkt.encode("ascii"), expected_jkt.encode("ascii")):
        return DpopVerificationResult(ok=False, detail="DPoP JWK thumbprint mismatch")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if alg == "EdDSA":
        if not isinstance(imported, OKPKey) or jwk_obj.get("crv") != "Ed25519":
            return DpopVerificationResult(ok=False, detail="EdDSA DPoP requires Ed25519 OKP JWK")
        x_val = jwk_obj.get("x")
        if not isinstance(x_val, str):
            return DpopVerificationResult(ok=False, detail="Missing Ed25519 x coordinate")
        try:
            pub_bytes = b64url_decode_nopad(x_val)
        except ValueError:
            return DpopVerificationResult(ok=False, detail="Invalid Ed25519 x coordinate")
        if not verify_ed25519_strict(pub_bytes, sig_bytes, signing_input):
            return DpopVerificationResult(ok=False, detail="DPoP EdDSA signature invalid")
    elif alg == "ES256":
        if not isinstance(imported, ECKey) or jwk_obj.get("crv") != "P-256":
            return DpopVerificationResult(ok=False, detail="ES256 DPoP requires P-256 EC JWK")
        if not _verify_es256_jws_signature(jwk_obj, signing_input, sig_bytes):
            return DpopVerificationResult(ok=False, detail="DPoP ES256 signature invalid")

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti.strip():
        return DpopVerificationResult(ok=False, detail="DPoP missing jti")

    htm = payload.get("htm")
    if not isinstance(htm, str) or htm.upper() != expected_htm.upper():
        return DpopVerificationResult(ok=False, detail="DPoP htm mismatch")

    htu = payload.get("htu")
    if not isinstance(htu, str):
        return DpopVerificationResult(ok=False, detail="DPoP missing htu")
    try:
        if _normalize_htu(htu) != _normalize_htu(expected_htu):
            return DpopVerificationResult(ok=False, detail="DPoP htu mismatch")
    except ValueError:
        return DpopVerificationResult(ok=False, detail="Invalid htu format")

    iat = payload.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return DpopVerificationResult(ok=False, detail="DPoP missing integer iat")
    if iat > now_seconds + MAX_CLOCK_SKEW_SECONDS:
        return DpopVerificationResult(ok=False, detail="DPoP iat exceeds forward clock skew")
    if now_seconds - iat > max_age_seconds:
        return DpopVerificationResult(ok=False, detail="DPoP proof expired")

    ath = payload.get("ath")
    expected_ath = compute_access_token_hash(permit_jws)
    if not isinstance(ath, str) or not hmac.compare_digest(
        ath.encode("ascii"), expected_ath.encode("ascii")
    ):
        return DpopVerificationResult(ok=False, detail="DPoP ath mismatch")

    return DpopVerificationResult(ok=True, jkt=computed_jkt, jti=jti)
