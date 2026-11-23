"""Definite-length CBOR Tag 18 COSE_Sign1 IETF SCITT (RFC 9942 / RFC 9943) verifier.

Validates:
- Definite-length CBOR encoding (rejects indefinite-length items and trailing bytes).
- CBOR Tag 18 (COSE_Sign1) 4-element array [protected_bstr, unprotected_map, payload_bstr, signature_bstr].
- Protected headers: 1 (alg) == -8 (EdDSA), 4 (kid) == bstr, 395 (vds) == 1.
- Unprotected header 396 (vdp): { -1: [tree_size, leaf_index, [audit_path_32b...]] }.
- Leaf hash SHA-256(0x00 || payload_bstr) folded with RFC 9162 audit path into Merkle root.
- Strict RFC 8032 / zip215=False Ed25519 signature over COSE Sig_structure containing the root.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from entros_verify.canonical import canonicalize_jcs_bytes
from entros_verify.jwks import JwksKeySource, as_jwks_source
from entros_verify.jws import b64url_decode_nopad, b64url_encode_nopad, verify_ed25519_strict
from entros_verify.models import ScittDecisionPayload, ScittReceiptResult

COSE_SIGN1_TAG = 18
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_HEADER_VDS = 395
COSE_HEADER_VDP = 396
COSE_ALG_EDDSA = -8
VDS_RFC9162_SHA256 = 1
VDP_INCLUSION_PROOF_KEY = -1


class ScittVerificationError(Exception):
    """Raised when a SCITT COSE_Sign1 receipt fails validation."""


def _validate_definite_cbor_item(data: bytes, offset: int, depth: int = 0) -> int:
    """Walk one CBOR item verifying definite-length encoding; return next byte offset."""
    if depth > 64:
        raise ScittVerificationError("CBOR nesting exceeds limit")
    if offset >= len(data):
        raise ScittVerificationError("Truncated CBOR input")

    initial = data[offset]
    offset += 1
    major = initial >> 5
    ai = initial & 0x1F

    if ai == 31:
        raise ScittVerificationError("Indefinite-length CBOR is forbidden")

    if ai < 24:
        arg = ai
    elif ai == 24:
        if offset + 1 > len(data):
            raise ScittVerificationError("Truncated CBOR 1-byte argument")
        arg = data[offset]
        offset += 1
    elif ai == 25:
        if offset + 2 > len(data):
            raise ScittVerificationError("Truncated CBOR 2-byte argument")
        arg = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    elif ai == 26:
        if offset + 4 > len(data):
            raise ScittVerificationError("Truncated CBOR 4-byte argument")
        arg = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
    elif ai == 27:
        if offset + 8 > len(data):
            raise ScittVerificationError("Truncated CBOR 8-byte argument")
        arg = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
    else:
        raise ScittVerificationError(f"Reserved CBOR additional info: {ai}")

    if major in (0, 1, 7):
        return offset
    if major in (2, 3):
        end = offset + arg
        if end > len(data):
            raise ScittVerificationError("Truncated CBOR byte/text string")
        return end
    if major == 4:
        for _ in range(arg):
            offset = _validate_definite_cbor_item(data, offset, depth + 1)
        return offset
    if major == 5:
        for _ in range(arg):
            offset = _validate_definite_cbor_item(data, offset, depth + 1)
            offset = _validate_definite_cbor_item(data, offset, depth + 1)
        return offset
    if major == 6:
        return _validate_definite_cbor_item(data, offset, depth + 1)
    raise ScittVerificationError(f"Unknown CBOR major type: {major}")


def assert_definite_length_cbor(data: bytes) -> None:
    """Assert that data is a single complete definite-length CBOR item with no trailing bytes."""
    if not data:
        raise ScittVerificationError("Empty CBOR input")
    end_offset = _validate_definite_cbor_item(data, 0)
    if end_offset != len(data):
        raise ScittVerificationError("Trailing bytes after CBOR envelope")


def compute_rfc9162_merkle_root(
    *,
    payload_bstr: bytes,
    tree_size: int,
    leaf_index: int,
    audit_path: list[bytes],
) -> bytes:
    """Compute the RFC 9162 SHA-256 Merkle root from leaf payload and inclusion proof."""
    if isinstance(tree_size, bool) or isinstance(leaf_index, bool):
        raise ScittVerificationError("tree_size and leaf_index must be integers")
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        raise ScittVerificationError("Invalid Merkle tree_size or leaf_index")

    leaf_hash = hashlib.sha256(b"\x00" + payload_bstr).digest()
    fn = leaf_index
    sn = tree_size - 1
    current = leaf_hash

    for sibling in audit_path:
        if not isinstance(sibling, bytes) or len(sibling) != 32:
            raise ScittVerificationError("Merkle audit_path hashes must be 32-byte values")
        if sn == 0:
            raise ScittVerificationError("Audit path contains excess hashes")
        if (fn & 1) == 1 or fn == sn:
            current = hashlib.sha256(b"\x01" + sibling + current).digest()
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            current = hashlib.sha256(b"\x01" + current + sibling).digest()
        fn >>= 1
        sn >>= 1

    if sn != 0:
        raise ScittVerificationError("Audit path is incomplete for tree_size")
    return current


def build_cose_sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    """Encode RFC 9052 COSE_Sign1 Sig_structure deterministically."""
    sig_structure = ["Signature1", protected_bstr, b"", payload]
    return cbor2.dumps(sig_structure, canonical=True)


def _decode_scitt_envelope(raw_bytes: bytes) -> tuple[bytes, dict[object, object], bytes, bytes]:
    assert_definite_length_cbor(raw_bytes)
    try:
        decoded: object = cbor2.loads(raw_bytes)
    except Exception as exc:
        raise ScittVerificationError(f"CBOR decode failed: {exc}") from exc

    if not isinstance(decoded, cbor2.CBORTag) or decoded.tag != COSE_SIGN1_TAG:
        raise ScittVerificationError("SCITT receipt must be CBOR Tag 18 (COSE_Sign1)")

    inner = decoded.value
    if not isinstance(inner, list) or len(inner) != 4:
        raise ScittVerificationError("COSE_Sign1 must be a 4-element array")

    protected_bstr, unprotected_map, payload_bstr, signature_bstr = inner
    if not isinstance(protected_bstr, bytes) or not protected_bstr:
        raise ScittVerificationError("COSE_Sign1 protected header must be a non-empty bstr")
    if not isinstance(unprotected_map, dict):
        raise ScittVerificationError("COSE_Sign1 unprotected header must be a map")
    if not isinstance(payload_bstr, bytes) or not payload_bstr:
        raise ScittVerificationError("COSE_Sign1 payload must be a non-empty bstr")
    if not isinstance(signature_bstr, bytes) or len(signature_bstr) != 64:
        raise ScittVerificationError("COSE_Sign1 signature must be a 64-byte Ed25519 signature")

    return protected_bstr, unprotected_map, payload_bstr, signature_bstr


def _parse_and_validate_receipt_parts(
    receipt: bytes | str,
) -> tuple[str, int, int, int, bytes, bytes, bytes, ScittDecisionPayload]:
    raw_bytes: bytes
    if isinstance(receipt, str):
        try:
            raw_bytes = b64url_decode_nopad(receipt)
        except ValueError as exc:
            raise ScittVerificationError(f"Invalid Base64URL SCITT receipt: {exc}") from exc
    elif isinstance(receipt, bytes):
        raw_bytes = receipt
    else:
        raise ScittVerificationError("SCITT receipt must be bytes or Base64URL string")

    protected_bstr, unprotected_map, payload_bstr, signature_bstr = _decode_scitt_envelope(raw_bytes)

    assert_definite_length_cbor(protected_bstr)
    try:
        protected_map: object = cbor2.loads(protected_bstr)
    except Exception as exc:
        raise ScittVerificationError(f"Invalid protected header CBOR: {exc}") from exc

    if not isinstance(protected_map, dict):
        raise ScittVerificationError("Protected header must be a CBOR map")

    alg = protected_map.get(COSE_HEADER_ALG)
    if alg != COSE_ALG_EDDSA or isinstance(alg, bool):
        raise ScittVerificationError("Protected header alg (1) must equal -8 (EdDSA)")

    kid_raw = protected_map.get(COSE_HEADER_KID)
    if not isinstance(kid_raw, bytes) or not kid_raw:
        raise ScittVerificationError("Protected header kid (4) must be a non-empty byte string")
    try:
        kid = kid_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScittVerificationError("Protected header kid (4) must be valid UTF-8") from exc

    vds = protected_map.get(COSE_HEADER_VDS)
    if vds != VDS_RFC9162_SHA256 or isinstance(vds, bool):
        raise ScittVerificationError("Protected header vds (395) must equal 1")

    vdp = unprotected_map.get(COSE_HEADER_VDP)
    if not isinstance(vdp, dict):
        raise ScittVerificationError("Unprotected header vdp (396) must be a map")

    proof = vdp.get(VDP_INCLUSION_PROOF_KEY)
    if not isinstance(proof, list) or len(proof) != 3:
        raise ScittVerificationError("vdp inclusion proof (-1) must be [tree_size, leaf_index, audit_path]")

    tree_size, leaf_index, audit_path_raw = proof
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or not isinstance(audit_path_raw, list)
    ):
        raise ScittVerificationError("Invalid vdp inclusion proof types")

    audit_path: list[bytes] = []
    for item in audit_path_raw:
        if not isinstance(item, bytes) or len(item) != 32:
            raise ScittVerificationError("Audit path entry must be 32 bytes")
        audit_path.append(item)

    merkle_root = compute_rfc9162_merkle_root(
        payload_bstr=payload_bstr,
        tree_size=tree_size,
        leaf_index=leaf_index,
        audit_path=audit_path,
    )

    try:
        payload_obj: object = json.loads(payload_bstr.decode("utf-8"))
        payload = ScittDecisionPayload.model_validate(payload_obj)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ScittVerificationError(f"Invalid SCITT payload JSON: {exc}") from exc

    sig_structure = build_cose_sig_structure(protected_bstr, merkle_root)
    return kid, vds, tree_size, leaf_index, merkle_root, sig_structure, signature_bstr, payload


def verify_scitt_receipt(
    receipt: bytes | str,
    *,
    jwks: JwksKeySource | Mapping[str, object],
    revoked_kids: set[str] | frozenset[str] | None = None,
) -> ScittReceiptResult:
    """Synchronously verify an IETF SCITT COSE_Sign1 receipt and its Merkle inclusion proof."""
    (
        kid,
        vds,
        tree_size,
        leaf_index,
        merkle_root,
        sig_structure,
        signature_bstr,
        payload,
    ) = _parse_and_validate_receipt_parts(receipt)

    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    lookup = source.get_key(kid)
    if lookup.status != "found" or lookup.key is None:
        raise ScittVerificationError(f"SCITT signing key unavailable: {lookup.status}")

    if not verify_ed25519_strict(lookup.key.public_key_bytes, signature_bstr, sig_structure):
        raise ScittVerificationError("SCITT COSE_Sign1 Ed25519 signature verification failed")

    return ScittReceiptResult(
        kid=kid,
        vds=vds,
        tree_size=tree_size,
        leaf_index=leaf_index,
        merkle_root_hex=merkle_root.hex(),
        payload=payload,
    )


async def verify_scitt_receipt_async(
    receipt: bytes | str,
    *,
    jwks: JwksKeySource | Mapping[str, object],
    revoked_kids: set[str] | frozenset[str] | None = None,
) -> ScittReceiptResult:
    """Asynchronously verify an IETF SCITT COSE_Sign1 receipt and its Merkle inclusion proof."""
    (
        kid,
        vds,
        tree_size,
        leaf_index,
        merkle_root,
        sig_structure,
        signature_bstr,
        payload,
    ) = _parse_and_validate_receipt_parts(receipt)

    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    lookup = await source.get_key_async(kid)
    if lookup.status != "found" or lookup.key is None:
        raise ScittVerificationError(f"SCITT signing key unavailable: {lookup.status}")

    if not verify_ed25519_strict(lookup.key.public_key_bytes, signature_bstr, sig_structure):
        raise ScittVerificationError("SCITT COSE_Sign1 Ed25519 signature verification failed")

    return ScittReceiptResult(
        kid=kid,
        vds=vds,
        tree_size=tree_size,
        leaf_index=leaf_index,
        merkle_root_hex=merkle_root.hex(),
        payload=payload,
    )


def create_scitt_receipt(
    *,
    private_key: Ed25519PrivateKey,
    kid: str,
    payload: ScittDecisionPayload | Mapping[str, object],
    tree_size: int = 1,
    leaf_index: int = 0,
    audit_path: list[bytes] | None = None,
) -> str:
    """Create a deterministic Base64URL-encoded SCITT COSE_Sign1 receipt (for testing/issuers)."""
    payload_dict: object
    if isinstance(payload, ScittDecisionPayload):
        payload_dict = payload.model_dump(by_alias=True)
    else:
        payload_dict = dict(payload)

    payload_bstr = canonicalize_jcs_bytes(payload_dict, field="scitt_payload")
    path = audit_path or []
    merkle_root = compute_rfc9162_merkle_root(
        payload_bstr=payload_bstr,
        tree_size=tree_size,
        leaf_index=leaf_index,
        audit_path=path,
    )
    protected_map = {
        COSE_HEADER_ALG: COSE_ALG_EDDSA,
        COSE_HEADER_KID: kid.encode("utf-8"),
        COSE_HEADER_VDS: VDS_RFC9162_SHA256,
    }
    protected_bstr = cbor2.dumps(protected_map, canonical=True)
    unprotected_map = {
        COSE_HEADER_VDP: {
            VDP_INCLUSION_PROOF_KEY: [tree_size, leaf_index, path],
        }
    }
    sig_structure = build_cose_sig_structure(protected_bstr, merkle_root)
    signature_bstr = private_key.sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(
        COSE_SIGN1_TAG,
        [protected_bstr, unprotected_map, payload_bstr, signature_bstr],
    )
    raw_cbor = cbor2.dumps(cose_sign1, canonical=True)
    return b64url_encode_nopad(raw_cbor)
