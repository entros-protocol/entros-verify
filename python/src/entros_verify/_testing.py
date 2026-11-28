"""Internal signing and low-level codec helpers for test suites and fixtures."""

from entros_verify.jws import (
    ParsedJws,
    b64url_decode_nopad,
    b64url_encode_nopad,
    parse_and_validate_jws_header,
    sign_eddsa_compact_jws,
)
from entros_verify.scitt import (
    assert_definite_length_cbor,
    build_cose_sig_structure,
    compute_rfc9162_merkle_root,
    create_scitt_receipt,
)

__all__ = [
    "ParsedJws",
    "assert_definite_length_cbor",
    "b64url_decode_nopad",
    "b64url_encode_nopad",
    "build_cose_sig_structure",
    "compute_rfc9162_merkle_root",
    "create_scitt_receipt",
    "parse_and_validate_jws_header",
    "sign_eddsa_compact_jws",
]
