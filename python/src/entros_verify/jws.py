"""Strict RFC 7515 JWS compact parsing and RFC 8032 / FIPS 186-5 Ed25519 verification.

Enforces zip215=False semantics in addition to cryptography's Ed25519 verification:
- Rejects small-order public keys and small-order signature R points (8*P == O).
- Rejects non-canonical point encodings (y >= p or x == 0 with sign bit 1).
- Rejects signature scalars S >= L.
- Rejects non-EdDSA algorithms and forbidden jwk/jku/x5u/x5c/crit headers.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from entros_verify.errors import JwsVerificationError
from entros_verify.models import RefusalCode

# Ed25519 curve constants (RFC 8032 section 5.1)
_ED25519_P = (1 << 255) - 19
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_SQRT_M1 = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_FORBIDDEN_HEADERS = frozenset({"jwk", "jku", "x5u", "x5c", "crit"})


def b64url_encode_nopad(data: bytes) -> str:
    """Encode bytes using unpadded URL-safe Base64."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode_nopad(segment: str) -> bytes:
    """Strictly decode unpadded Base64URL, rejecting padding and non-canonical bits."""
    if not isinstance(segment, str) or not segment or not _B64URL_RE.match(segment):
        raise ValueError("Invalid unpadded Base64URL segment")
    if len(segment) % 4 == 1:
        raise ValueError("Invalid Base64URL length")
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    if b64url_encode_nopad(decoded) != segment:
        raise ValueError("Non-canonical Base64URL encoding")
    return decoded


def _parse_json_object_strict(raw_bytes: bytes) -> dict[str, object]:
    """Decode strict UTF-8 JSON object rejecting duplicate keys and NaN/Infinity."""

    def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, val in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = val
        return result

    def _reject_constant(constant: str) -> object:
        raise ValueError(f"Forbidden JSON constant: {constant}")

    text = raw_bytes.decode("utf-8")
    parsed: object = json.loads(
        text,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError("JSON root must be an object")
    return parsed


def _decode_ed25519_point_strict(point_bytes: bytes) -> tuple[int, int, int, int] | None:
    """Decode a 32-byte Ed25519 point enforcing canonical RFC 8032 encoding.

    Returns extended coordinates (X, Y, Z, T) on success, or None if invalid.
    """
    if len(point_bytes) != 32:
        return None
    p = _ED25519_P
    y = int.from_bytes(point_bytes, "little") & ((1 << 255) - 1)
    if y >= p:
        return None
    sign_bit = (point_bytes[31] >> 7) & 1

    y2 = (y * y) % p
    u = (y2 - 1) % p
    v = (_ED25519_D * y2 + 1) % p
    if v == 0:
        return None
    x2 = (u * pow(v, p - 2, p)) % p

    if x2 == 0:
        if sign_bit == 1:
            # Non-canonical encoding of x = 0 with sign bit set.
            return None
        x = 0
    else:
        x = pow(x2, (p + 3) // 8, p)
        if (x * x - x2) % p != 0:
            x = (x * _SQRT_M1) % p
        if (x * x - x2) % p != 0:
            return None
        if (x & 1) != sign_bit:
            x = p - x

    # Verify curve equation: (-x^2 + y^2) == (1 + d * x^2 * y^2) mod p
    if ((-x * x + y2) - (1 + _ED25519_D * x * x * y2)) % p != 0:
        return None

    return (x, y, 1, (x * y) % p)


def _ed25519_double(pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Double an extended twisted Edwards point (a = -1)."""
    p = _ED25519_P
    x1, y1, z1, _ = pt
    a = (x1 * x1) % p
    b = (y1 * y1) % p
    c = (2 * z1 * z1) % p
    h = (a + b) % p
    x1_plus_y1 = (x1 + y1) % p
    e = (h - (x1_plus_y1 * x1_plus_y1) % p) % p
    g = (a - b) % p
    f = (c + g) % p
    x3 = (e * f) % p
    y3 = (g * h) % p
    t3 = (e * h) % p
    z3 = (f * g) % p
    return (x3, y3, z3, t3)


def _is_identity(pt: tuple[int, int, int, int]) -> bool:
    p = _ED25519_P
    x, y, z, _ = pt
    return (x % p == 0) and ((y - z) % p == 0)


def _is_small_order(pt: tuple[int, int, int, int]) -> bool:
    """Return True if 8 * pt equals the neutral element (torsion subgroup)."""
    doubled = _ed25519_double(_ed25519_double(_ed25519_double(pt)))
    return _is_identity(doubled)


def verify_ed25519_strict(
    public_key_bytes: bytes,
    signature_bytes: bytes,
    message: bytes,
) -> bool:
    """Verify an Ed25519 signature under strict RFC 8032 / zip215=False rules."""
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        return False

    # Reject non-canonical signature scalar S >= L.
    s_scalar = int.from_bytes(signature_bytes[32:64], "little")
    if s_scalar >= _ED25519_L:
        return False

    # Reject non-canonical or small-order public key A.
    pub_point = _decode_ed25519_point_strict(public_key_bytes)
    if pub_point is None or _is_small_order(pub_point):
        return False

    # Reject non-canonical or small-order signature point R.
    r_point = _decode_ed25519_point_strict(signature_bytes[0:32])
    if r_point is None or _is_small_order(r_point):
        return False

    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature_bytes, message)
    except (ValueError, InvalidSignature):
        return False
    return True


@dataclass(frozen=True)
class ParsedJws:
    """Parsed compact JWS structure before signature verification."""

    header: dict[str, object]
    payload: dict[str, object]
    signing_input: bytes
    signature: bytes
    kid: str
    typ: str


def parse_and_validate_jws_header(
    compact_jws: str,
    *,
    expected_typ: str,
) -> ParsedJws:
    """Parse a compact JWS and validate header rules in precheck order (steps 1 to 4)."""
    if not isinstance(compact_jws, str) or compact_jws.count(".") != 2:
        raise JwsVerificationError(RefusalCode.INVALID_JWS.value, "Malformed compact JWS")

    header_b64, payload_b64, sig_b64 = compact_jws.split(".")
    try:
        header_bytes = b64url_decode_nopad(header_b64)
        payload_bytes = b64url_decode_nopad(payload_b64)
        signature_bytes = b64url_decode_nopad(sig_b64)
        header = _parse_json_object_strict(header_bytes)
        payload = _parse_json_object_strict(payload_bytes)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwsVerificationError(
            RefusalCode.INVALID_JWS.value,
            f"Malformed JWS encoding or JSON: {exc}",
        ) from exc

    # Step 2: Enforce alg == "EdDSA" and reject forbidden header parameters.
    alg = header.get("alg")
    if alg != "EdDSA" or any(key in header for key in _FORBIDDEN_HEADERS):
        raise JwsVerificationError(
            RefusalCode.UNSUPPORTED_ALG.value,
            "JWS must use alg=EdDSA without jwk/jku/x5u/x5c/crit headers",
        )

    # Step 3: Enforce exact typ match.
    typ = header.get("typ")
    if typ != expected_typ:
        raise JwsVerificationError(
            RefusalCode.INVALID_TYP.value,
            f"Expected typ={expected_typ!r}",
        )

    # Step 4 (partial): Ensure kid is present and non-empty string.
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise JwsVerificationError(
            RefusalCode.UNKNOWN_KID.value,
            "JWS protected header is missing a valid kid",
        )

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return ParsedJws(
        header=header,
        payload=payload,
        signing_input=signing_input,
        signature=signature_bytes,
        kid=kid,
        typ=typ,
    )


def sign_eddsa_compact_jws(
    *,
    private_key: Ed25519PrivateKey,
    kid: str,
    typ: str,
    payload: dict[str, object],
) -> str:
    """Sign a compact EdDSA JWS with unpadded Base64URL encoding."""
    header = {"typ": typ, "alg": "EdDSA", "kid": kid}
    header_b64 = b64url_encode_nopad(
        json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    payload_b64 = b64url_encode_nopad(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    sig_b64 = b64url_encode_nopad(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"
