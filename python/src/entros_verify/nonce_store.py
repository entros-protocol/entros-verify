"""Atomic post-precheck single-use PermitNonceStoreV2 protocol and in-memory store.

Consumers run all non-mutating cryptographic and policy prechecks before
invoking consume_once so forged probes never burn pending nonces.
"""

from __future__ import annotations

import threading
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from entros_verify.errors import NonceStoreError

NonceConsumeStatus = Literal["consumed", "not_found", "already_consumed", "expired"]


@dataclass(frozen=True)
class PermitNonceRecord:
    """Tracked single-use AgentPermit v2 nonce entry."""

    jti: str
    expires_at: int
    created_at: int
    consumed_at: int | None = None
    request_digest: str | None = None
    aud: str | None = None
    policy_id: str | None = None


@dataclass(frozen=True)
class NonceConsumeResult:
    """Outcome of an atomic single-use jti consumption attempt."""

    status: NonceConsumeStatus
    record: PermitNonceRecord | None = None
    consumed_at: int | None = None


@runtime_checkable
class PermitNonceStoreV2(Protocol):
    """Protocol for atomic single-use AgentPermit v2 nonce stores.

    Production multi-instance deployments should implement consume_once using
    an atomic compare-and-swap (e.g., SQL UPDATE ... WHERE consumed_at IS NULL
    or Redis SET NX / Lua CAS).
    """

    def register(
        self,
        *,
        jti: str,
        expires_at: int,
        created_at: int,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> Awaitable[None] | None: ...

    def peek(self, jti: str) -> Awaitable[PermitNonceRecord | None] | PermitNonceRecord | None: ...

    def consume_once(
        self,
        *,
        jti: str,
        now_seconds: int,
        expires_at: int,
        require_registered: bool = False,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> Awaitable[NonceConsumeResult] | NonceConsumeResult: ...


_LAZY_PRUNE_INTERVAL_SECONDS = 10


class InMemoryPermitNonceStoreV2:
    """Thread-safe and asyncio-safe single-process atomic PermitNonceStoreV2.

    Every state transition happens synchronously inside a threading.Lock without
    yielding to the event loop, guaranteeing at most 1/N success under concurrent
    async or multi-threaded replay storms.
    """

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        retain_consumed_seconds: int = 3_600,
    ) -> None:
        if max_entries < 1:
            raise NonceStoreError("invalid_record", "max_entries must be >= 1")
        if retain_consumed_seconds < 0:
            raise NonceStoreError("invalid_record", "retain_consumed_seconds must be >= 0")
        self._max_entries = max_entries
        self._retain_consumed_seconds = retain_consumed_seconds
        self._records: dict[str, PermitNonceRecord] = {}
        self._last_prune_at: int | None = None
        self._lock = threading.Lock()

    def _is_stale(self, record: PermitNonceRecord, now_seconds: int) -> bool:
        if record.consumed_at is None:
            return now_seconds >= record.expires_at
        return now_seconds >= record.expires_at + self._retain_consumed_seconds

    def _prune_unlocked(self, now_seconds: int) -> int:
        if now_seconds < 1:
            return 0
        to_delete = [
            jti for jti, record in self._records.items() if self._is_stale(record, now_seconds)
        ]
        for jti in to_delete:
            del self._records[jti]
        self._last_prune_at = now_seconds
        return len(to_delete)

    def _maybe_prune_unlocked(self, now_seconds: int) -> None:
        if now_seconds < 1:
            return
        if not self._records:
            self._last_prune_at = now_seconds
            return
        if len(self._records) >= self._max_entries or (
            self._last_prune_at is not None
            and now_seconds - self._last_prune_at >= _LAZY_PRUNE_INTERVAL_SECONDS
        ):
            self._prune_unlocked(now_seconds)
        elif self._last_prune_at is None:
            self._last_prune_at = now_seconds

    def prune(self, now_seconds: int) -> int:
        """Remove expired pending entries and consumed entries past retention."""
        with self._lock:
            return self._prune_unlocked(now_seconds)

    def register(
        self,
        *,
        jti: str,
        expires_at: int,
        created_at: int,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> None:
        """Register a pending server-tracked challenge under its unique jti."""
        if not jti:
            raise NonceStoreError("invalid_record", "jti must be non-empty")
        with self._lock:
            existing = self._records.get(jti)
            if existing is not None:
                if created_at >= 1 and self._is_stale(existing, created_at):
                    del self._records[jti]
                else:
                    raise NonceStoreError("duplicate_nonce", f"Nonce {jti} is already registered")
            self._maybe_prune_unlocked(created_at)
            if len(self._records) >= self._max_entries:
                raise NonceStoreError("capacity_reached", "Nonce store capacity reached")
            self._records[jti] = PermitNonceRecord(
                jti=jti,
                expires_at=expires_at,
                created_at=created_at,
                consumed_at=None,
                request_digest=request_digest,
                aud=aud,
                policy_id=policy_id,
            )

    def peek(self, jti: str) -> PermitNonceRecord | None:
        """Non-mutating lookup for inspection before prechecks."""
        with self._lock:
            return self._records.get(jti)

    def consume_once(
        self,
        *,
        jti: str,
        now_seconds: int,
        expires_at: int,
        require_registered: bool = False,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> NonceConsumeResult:
        """Atomically consume jti at most once across concurrent callers."""
        with self._lock:
            existing = self._records.get(jti)
            if existing is not None:
                if existing.consumed_at is not None:
                    return NonceConsumeResult(
                        status="already_consumed",
                        record=existing,
                        consumed_at=existing.consumed_at,
                    )
                if now_seconds >= existing.expires_at:
                    return NonceConsumeResult(status="expired", record=existing)
                if (
                    existing.request_digest is not None
                    and request_digest is not None
                    and existing.request_digest != request_digest
                ):
                    return NonceConsumeResult(status="not_found")
                if existing.aud is not None and aud is not None and existing.aud != aud:
                    return NonceConsumeResult(status="not_found")
                if existing.policy_id is not None and existing.policy_id != policy_id:
                    return NonceConsumeResult(status="not_found")
                consumed = PermitNonceRecord(
                    jti=existing.jti,
                    expires_at=existing.expires_at,
                    created_at=existing.created_at,
                    consumed_at=now_seconds,
                    request_digest=existing.request_digest or request_digest,
                    aud=existing.aud or aud,
                    policy_id=existing.policy_id or policy_id,
                )
                self._records[jti] = consumed
                return NonceConsumeResult(
                    status="consumed",
                    record=consumed,
                    consumed_at=now_seconds,
                )

            if require_registered:
                return NonceConsumeResult(status="not_found")

            if now_seconds >= expires_at:
                return NonceConsumeResult(status="expired")

            self._maybe_prune_unlocked(now_seconds)
            if len(self._records) >= self._max_entries:
                raise NonceStoreError("capacity_reached", "Nonce store capacity reached")

            consumed = PermitNonceRecord(
                jti=jti,
                expires_at=expires_at,
                created_at=now_seconds,
                consumed_at=now_seconds,
                request_digest=request_digest,
                aud=aud,
                policy_id=policy_id,
            )
            self._records[jti] = consumed
            return NonceConsumeResult(
                status="consumed",
                record=consumed,
                consumed_at=now_seconds,
            )

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._records)
