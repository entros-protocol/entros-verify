"""Typed error classes for entros-verify.

Error messages never include raw audio bytes or base64-encoded audio payloads.
"""

from __future__ import annotations


class EntrosVerifyError(Exception):
    """Base error raised by entros-verify operations."""


class CanonicalizationError(EntrosVerifyError):
    """Raised when an action or JSON value fails RFC 8785 validation."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message)


class JwsVerificationError(EntrosVerifyError):
    """Raised when JWS compact parsing or cryptographic verification fails."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class JwksUnavailableError(EntrosVerifyError):
    """Raised when JWKS discovery fails due to transport or server error."""


class NonceStoreError(EntrosVerifyError):
    """Raised on invalid nonce store configuration or backend failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class EntrosApiError(EntrosVerifyError):
    """Raised when an Entros API HTTP or WebSocket call fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)
