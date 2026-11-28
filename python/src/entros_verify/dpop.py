"""RFC 9449 DPoP (dpop+jwt) proof verifier using internal RFC 7638 thumbprints and cryptography.

Verifies sender-constrained AgentPermit v2 presentation proofs:
- Protected header typ == "dpop+jwt", asymmetric alg ("EdDSA" or "ES256"), embedded public jwk,
  and zero forbidden headers (crit, jku, x5u, x5c).
- RFC 7638 SHA-256 thumbprint of embedded jwk matches expected cnf.jkt / actor.key_jkt.
- Cryptographic JWS signature verification (strict Ed25519 for EdDSA; ECDSA P-256 for ES256).
- Claims: htm, htu (no query/fragment in proof; normalized default ports), ath, iat, jti.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from entros_verify.canonical import canonicalize_jcs_bytes
from entros_verify.jws import (
    _parse_json_object_strict,
    b64url_decode_nopad,
    b64url_encode_nopad,
    verify_ed25519_strict,
)
from entros_verify.models import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_TIMESTAMP_SECONDS,
    MIN_TIMESTAMP_SECONDS,
)

ALLOWED_DPOP_ALGS = frozenset({"EdDSA", "ES256"})
_FORBIDDEN_DPOP_HEADERS = frozenset({"crit", "jku", "x5u", "x5c"})
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_LAZY_PRUNE_INTERVAL_SECONDS = 10


@dataclass(frozen=True)
class DpopVerificationResult:
    """Result of verifying an RFC 9449 DPoP proof JWT."""

    ok: bool
    jkt: str | None = None
    jti: str | None = None
    iat: int | None = None
    detail: str | None = None


@runtime_checkable
class DpopJtiStore(Protocol):
    """Protocol for tracking seen DPoP proof jti values to prevent replay."""

    def consume(self, jti: str, expires_at: int, now_seconds: int) -> bool: ...


class InMemoryDpopJtiStore:
    """Thread-safe bounded in-memory DPoP jti replay store."""

    def __init__(self, *, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._entries: dict[str, int] = {}
        self._last_prune_at: int | None = None
        self._lock = threading.Lock()

    def _prune_unlocked(self, now_seconds: int) -> None:
        expired = [key for key, exp in self._entries.items() if now_seconds >= exp]
        for key in expired:
            del self._entries[key]
        self._last_prune_at = now_seconds

    def consume(self, jti: str, expires_at: int, now_seconds: int) -> bool:
        if not jti or not jti.strip():
            return False
        with self._lock:
            existing_exp = self._entries.get(jti)
            if existing_exp is not None:
                if now_seconds < existing_exp:
                    return False
                del self._entries[jti]
            should_prune = len(self._entries) >= self._max_entries or (
                len(self._entries) > 0
                and self._last_prune_at is not None
                and now_seconds - self._last_prune_at >= _LAZY_PRUNE_INTERVAL_SECONDS
            )
            if should_prune:
                self._prune_unlocked(now_seconds)
            elif self._last_prune_at is None:
                self._last_prune_at = now_seconds
            # Fail closed rather than evicting active unexpired proof jtis.
            if len(self._entries) >= self._max_entries:
                return False
            self._entries[jti] = expires_at
            return True


def compute_jwk_thumbprint(jwk: Mapping[str, object]) -> str:
    """Compute an RFC 7638 SHA-256 JWK thumbprint (unpadded Base64URL)."""
    kty = jwk.get("kty")

    def _req(field: str) -> str:
        val = jwk.get(field)
        if not isinstance(val, str) or not val:
            raise ValueError(f"JWK missing required string member '{field}'")
        return val

    members: dict[str, str]
    if kty == "OKP":
        members = {"crv": _req("crv"), "kty": "OKP", "x": _req("x")}
    elif kty == "EC":
        members = {"crv": _req("crv"), "kty": "EC", "x": _req("x"), "y": _req("y")}
    elif kty == "RSA":
        members = {"e": _req("e"), "kty": "RSA", "n": _req("n")}
    elif kty == "oct":
        members = {"k": _req("k"), "kty": "oct"}
    else:
        raise ValueError(f"Unsupported JWK kty: {kty!r}")

    canonical = canonicalize_jcs_bytes(members, field="jwk")
    return b64url_encode_nopad(hashlib.sha256(canonical).digest())


def compute_access_token_hash(token: str) -> str:
    """Compute RFC 9449 ath = BASE64URL(SHA-256(ASCII(token)))."""
    if not isinstance(token, str) or not token.isascii():
        raise ValueError("DPoP access token must be ASCII")
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return b64url_encode_nopad(digest)


def _remove_dot_segments(path: str) -> str:
    """Normalize '.' and '..' path segments per RFC 3986 section 5.2.4."""
    if not path:
        return "/"
    segments = path.split("/")
    output: list[str] = []
    ends_with_slash = path.endswith("/")
    last_idx = len(segments) - 1
    for idx, seg in enumerate(segments):
        if idx == 0 and seg == "":
            continue
        if seg == ".":
            if idx == last_idx:
                ends_with_slash = True
            continue
        if seg == "..":
            if output:
                output.pop()
            if idx == last_idx:
                ends_with_slash = True
            continue
        if seg == "" and idx == last_idx:
            continue
        output.append(seg)
    if not output:
        return "/"
    normalized = "/" + "/".join(output)
    if ends_with_slash:
        normalized += "/"
    return normalized


def _normalize_htu(uri: str) -> str:
    """Normalize HTTP URI per RFC 9449 section 4.2, rejecting userinfo, normalizing dot-segments, and stripping default ports."""
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("Invalid htu URI")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("htu URI must not contain userinfo")
    hostname = parts.hostname
    if not hostname:
        raise ValueError("htu URI missing hostname")
    port = parts.port
    default_port = 443 if scheme == "https" else 80
    host_formatted = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    netloc = (
        f"{host_formatted}:{port}"
        if (port is not None and port != default_port)
        else host_formatted
    )
    return urlunsplit((scheme, netloc, _remove_dot_segments(parts.path or "/"), "", ""))


def _verify_es256_jws_signature(
    jwk_dict: dict[str, object], signing_input: bytes, raw_sig: bytes
) -> bool:
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
    jti_store: DpopJtiStore | None = None,
) -> DpopVerificationResult:
    """Verify an RFC 9449 DPoP proof bound to an AgentPermit v2 JWS."""
    if not isinstance(proof_jwt, str) or proof_jwt.count(".") != 2:
        return DpopVerificationResult(ok=False, detail="Malformed DPoP JWT")

    header_b64, payload_b64, sig_b64 = proof_jwt.split(".")
    try:
        header = _parse_json_object_strict(b64url_decode_nopad(header_b64))
        payload = _parse_json_object_strict(b64url_decode_nopad(payload_b64))
        sig_bytes = b64url_decode_nopad(sig_b64)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return DpopVerificationResult(ok=False, detail="Invalid DPoP encoding or JSON")

    for forbidden in _FORBIDDEN_DPOP_HEADERS:
        if forbidden in header:
            return DpopVerificationResult(
                ok=False, detail=f"Forbidden DPoP header '{forbidden}'"
            )

    if header.get("typ") != "dpop+jwt":
        return DpopVerificationResult(ok=False, detail="DPoP typ must be dpop+jwt")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_DPOP_ALGS:
        return DpopVerificationResult(ok=False, detail="Unsupported DPoP algorithm")

    jwk_obj = header.get("jwk")
    if not isinstance(jwk_obj, dict):
        return DpopVerificationResult(ok=False, detail="DPoP header missing public jwk")
    if any(field in jwk_obj for field in _PRIVATE_JWK_FIELDS):
        return DpopVerificationResult(
            ok=False, detail="DPoP jwk must not contain private key fields"
        )

    try:
        computed_jkt = compute_jwk_thumbprint(jwk_obj)
    except Exception:
        return DpopVerificationResult(ok=False, detail="Invalid DPoP embedded JWK")

    if (
        not isinstance(now_seconds, int)
        or isinstance(now_seconds, bool)
        or not (MIN_TIMESTAMP_SECONDS <= now_seconds <= MAX_TIMESTAMP_SECONDS)
    ):
        return DpopVerificationResult(ok=False, detail="Invalid DPoP verifier clock timestamp")
    if (
        not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or max_age_seconds < 1
    ):
        return DpopVerificationResult(ok=False, detail="DPoP max_age_seconds must be >= 1")
    if not isinstance(expected_jkt, str) or not expected_jkt or not expected_jkt.isascii():
        return DpopVerificationResult(ok=False, detail="Invalid expected DPoP thumbprint")
    if not isinstance(permit_jws, str) or not permit_jws or not permit_jws.isascii():
        return DpopVerificationResult(ok=False, detail="Invalid permit JWS for DPoP ath binding")

    if not hmac.compare_digest(computed_jkt.encode("ascii"), expected_jkt.encode("ascii")):
        return DpopVerificationResult(ok=False, detail="DPoP JWK thumbprint mismatch")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if alg == "EdDSA":
        if jwk_obj.get("kty") != "OKP" or jwk_obj.get("crv") != "Ed25519":
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
        if jwk_obj.get("kty") != "EC" or jwk_obj.get("crv") != "P-256":
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
    if "?" in htu or "#" in htu:
        return DpopVerificationResult(
            ok=False, detail="DPoP payload htu must not contain query or fragment parts"
        )
    try:
        if _normalize_htu(htu) != _normalize_htu(expected_htu):
            return DpopVerificationResult(ok=False, detail="DPoP htu mismatch")
    except ValueError:
        return DpopVerificationResult(ok=False, detail="Invalid htu format")

    iat = payload.get("iat")
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or not (MIN_TIMESTAMP_SECONDS <= iat <= MAX_TIMESTAMP_SECONDS)
    ):
        return DpopVerificationResult(ok=False, detail="DPoP missing valid integer iat")
    if iat > now_seconds + MAX_CLOCK_SKEW_SECONDS:
        return DpopVerificationResult(ok=False, detail="DPoP iat exceeds forward clock skew")
    if now_seconds - iat > max_age_seconds:
        return DpopVerificationResult(ok=False, detail="DPoP proof expired")

    ath = payload.get("ath")
    expected_ath = compute_access_token_hash(permit_jws)
    if (
        not isinstance(ath, str)
        or not ath.isascii()
        or not hmac.compare_digest(ath.encode("ascii"), expected_ath.encode("ascii"))
    ):
        return DpopVerificationResult(ok=False, detail="DPoP ath mismatch")

    if jti_store is not None:
        fresh = jti_store.consume(
            jti,
            iat + max_age_seconds + MAX_CLOCK_SKEW_SECONDS,
            now_seconds,
        )
        if not fresh:
            return DpopVerificationResult(ok=False, detail="DPoP jti replay detected")

    return DpopVerificationResult(ok=True, jkt=computed_jkt, jti=jti, iat=iat)
