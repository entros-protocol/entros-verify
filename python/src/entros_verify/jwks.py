"""JWKS discovery, caching, key revocation, and Ed25519 public key resolution.

Enforces:
- Maximum positive cache TTL of 300 seconds.
- Minimum negative-cache and global refresh cooldown floor of 10 seconds to prevent origin flooding.
- Single-flight deduplication across concurrent sync threads and async tasks.
- Bounded negative cache size (4,096 entries max) with expiry pruning.
- Explicit rejection of revoked keys (JWKS status="revoked" or local revocation set).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx

from entros_verify.errors import JwksUnavailableError
from entros_verify.jws import b64url_decode_nopad
from entros_verify.models import RefusalCode
from entros_verify.uri import is_canonical_uri

MAX_JWKS_CACHE_TTL_SECONDS = 300.0
MIN_NEGATIVE_CACHE_SECONDS = 10.0
MAX_NEGATIVE_CACHE_ENTRIES = 4_096


@dataclass(frozen=True)
class JwkEd25519Key:
    """Parsed Ed25519 verification key entry from a JWKS document."""

    kid: str
    public_key_bytes: bytes
    revoked: bool = False


@dataclass(frozen=True)
class KeyLookupResult:
    """Outcome of resolving a kid from a JWKS key source."""

    status: str  # "found" | "unknown" | "revoked"
    key: JwkEd25519Key | None = None

    @property
    def refusal_code(self) -> RefusalCode | None:
        if self.status == "unknown":
            return RefusalCode.UNKNOWN_KID
        if self.status == "revoked":
            return RefusalCode.REVOKED_KID
        return None


def parse_jwks_document(jwks: Mapping[str, object]) -> dict[str, JwkEd25519Key]:
    """Parse a JWKS JSON object into Ed25519 OKP verification keys keyed by kid."""
    raw_keys = jwks.get("keys")
    if not isinstance(raw_keys, list):
        raise ValueError("JWKS document must contain a 'keys' list")

    parsed: dict[str, JwkEd25519Key] = {}
    for entry in raw_keys:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        use = entry.get("use")
        if use is not None and use != "sig":
            continue
        alg = entry.get("alg")
        if alg is not None and alg != "EdDSA":
            continue
        kid = entry.get("kid")
        x_val = entry.get("x")
        if not isinstance(kid, str) or not kid.strip() or not isinstance(x_val, str):
            continue
        try:
            pub_bytes = b64url_decode_nopad(x_val)
        except ValueError:
            continue
        if len(pub_bytes) != 32:
            continue
        existing = parsed.get(kid)
        revoked = (entry.get("status") == "revoked") or (
            existing is not None and existing.revoked
        )
        parsed[kid] = JwkEd25519Key(kid=kid, public_key_bytes=pub_bytes, revoked=revoked)
    return parsed


@runtime_checkable
class JwksKeySource(Protocol):
    """Protocol implemented by synchronous and asynchronous JWKS key providers."""

    def get_key(self, kid: str) -> KeyLookupResult: ...

    def get_key_async(self, kid: str) -> Awaitable[KeyLookupResult]: ...


class _RevokedKidsJwksWrapper:
    """Wrap an existing JwksKeySource with additional caller-supplied revoked kids."""

    def __init__(
        self,
        inner: JwksKeySource,
        revoked_kids: set[str] | frozenset[str],
    ) -> None:
        self._inner = inner
        self._revoked_kids = frozenset(revoked_kids)

    def get_key(self, kid: str) -> KeyLookupResult:
        if kid in self._revoked_kids:
            return KeyLookupResult(status="revoked")
        return self._inner.get_key(kid)

    async def get_key_async(self, kid: str) -> KeyLookupResult:
        if kid in self._revoked_kids:
            return KeyLookupResult(status="revoked")
        return await self._inner.get_key_async(kid)


def as_jwks_source(
    source: JwksKeySource | Mapping[str, object],
    *,
    revoked_kids: set[str] | frozenset[str] | None = None,
) -> JwksKeySource:
    """Adapt a raw JWKS mapping or existing provider into a JwksKeySource."""
    if isinstance(source, Mapping):
        return StaticJwksProvider(source, revoked_kids=revoked_kids)
    if revoked_kids:
        return _RevokedKidsJwksWrapper(source, revoked_kids)
    return source


class StaticJwksProvider:
    """In-memory JWKS key provider for offline verification and unit tests."""

    def __init__(
        self,
        jwks: Mapping[str, object],
        *,
        revoked_kids: set[str] | frozenset[str] | None = None,
    ) -> None:
        self._keys = parse_jwks_document(jwks)
        self._revoked_kids = frozenset(revoked_kids or ())

    def get_key(self, kid: str) -> KeyLookupResult:
        if kid in self._revoked_kids:
            return KeyLookupResult(status="revoked")
        key = self._keys.get(kid)
        if key is None:
            return KeyLookupResult(status="unknown")
        if key.revoked:
            return KeyLookupResult(status="revoked", key=key)
        return KeyLookupResult(status="found", key=key)

    async def get_key_async(self, kid: str) -> KeyLookupResult:
        return self.get_key(kid)


@dataclass
class _SyncInflightRefresh:
    event: threading.Event
    error: Exception | None = None


class JwksCache:
    """Synchronous and asynchronous JWKS cache with bounded TTL, cooldown, and pooled HTTP."""

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: float = MAX_JWKS_CACHE_TTL_SECONDS,
        negative_cache_seconds: float = MIN_NEGATIVE_CACHE_SECONDS,
        revoked_kids: set[str] | frozenset[str] | None = None,
        timeout_seconds: float = 5.0,
        clock: Callable[[], float] | None = None,
        sync_transport: httpx.BaseTransport | None = None,
        async_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not is_canonical_uri(jwks_url, allow_empty_path=False):
            raise ValueError("jwks_url must be a canonical HTTPS or 127.0.0.1 URI")
        if ttl_seconds <= 0 or ttl_seconds > MAX_JWKS_CACHE_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be in (0, {MAX_JWKS_CACHE_TTL_SECONDS}]")
        if negative_cache_seconds < MIN_NEGATIVE_CACHE_SECONDS:
            raise ValueError(f"negative_cache_seconds must be >= {MIN_NEGATIVE_CACHE_SECONDS}")

        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._negative_cache_seconds = negative_cache_seconds
        self._revoked_kids = frozenset(revoked_kids or ())
        self._timeout_seconds = timeout_seconds
        self._clock = clock or time.monotonic
        self._sync_transport = sync_transport
        self._async_transport = async_transport

        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

        self._lock = threading.Lock()
        self._sync_inflight: _SyncInflightRefresh | None = None
        self._async_inflight_loop: asyncio.AbstractEventLoop | None = None
        self._async_inflight: asyncio.Future[None] | None = None

        self._keys: dict[str, JwkEd25519Key] = {}
        self._loaded_at: float | None = None
        self._last_refresh_attempt_at: float | None = None
        self._negative_cache: dict[str, float] = {}

    def close(self) -> None:
        """Close the pooled synchronous HTTP client if initialized."""
        with self._lock:
            client = self._sync_client
            self._sync_client = None
        if client is not None:
            client.close()

    async def aclose(self) -> None:
        """Close the pooled asynchronous HTTP client if initialized."""
        with self._lock:
            client = self._async_client
            self._async_client = None
        if client is not None:
            await client.aclose()

    def __enter__(self) -> JwksCache:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    async def __aenter__(self) -> JwksCache:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    def _get_sync_client(self) -> httpx.Client:
        with self._lock:
            if self._sync_client is None:
                self._sync_client = httpx.Client(
                    timeout=self._timeout_seconds,
                    transport=self._sync_transport,
                )
            return self._sync_client

    def _get_async_client(self) -> httpx.AsyncClient:
        with self._lock:
            if self._async_client is None:
                self._async_client = httpx.AsyncClient(
                    timeout=self._timeout_seconds,
                    transport=self._async_transport,
                )
            return self._async_client

    def _is_expired(self, now: float) -> bool:
        return self._loaded_at is None or (now - self._loaded_at) >= self._ttl_seconds

    def _can_refresh_for_unknown(self, kid: str, now: float) -> bool:
        if self._is_negatively_cached(kid, now):
            return False
        return (
            self._last_refresh_attempt_at is None
            or (now - self._last_refresh_attempt_at) >= self._negative_cache_seconds
        )

    def _lookup_cached(self, kid: str) -> KeyLookupResult | None:
        if kid in self._revoked_kids:
            return KeyLookupResult(status="revoked")
        key = self._keys.get(kid)
        if key is None:
            return None
        if key.revoked:
            return KeyLookupResult(status="revoked", key=key)
        return KeyLookupResult(status="found", key=key)

    def _is_negatively_cached(self, kid: str, now: float) -> bool:
        expires_at = self._negative_cache.get(kid)
        if expires_at is None:
            return False
        if now < expires_at:
            return True
        self._negative_cache.pop(kid, None)
        return False

    def _record_negative_cache(self, kid: str, now: float) -> None:
        # Insertion order follows monotonic expiry timestamps, so stop at the first live entry.
        while self._negative_cache:
            oldest_kid, oldest_exp = next(iter(self._negative_cache.items()))
            if now >= oldest_exp:
                del self._negative_cache[oldest_kid]
            else:
                break
        if kid in self._negative_cache:
            del self._negative_cache[kid]
        elif len(self._negative_cache) >= MAX_NEGATIVE_CACHE_ENTRIES:
            oldest = next(iter(self._negative_cache))
            del self._negative_cache[oldest]
        self._negative_cache[kid] = now + self._negative_cache_seconds

    def _apply_jwks(self, jwks: Mapping[str, object], now: float) -> None:
        parsed = parse_jwks_document(jwks)
        self._keys = parsed
        self._loaded_at = now
        for kid in parsed:
            self._negative_cache.pop(kid, None)

    def _fetch_sync(self) -> Mapping[str, object]:
        try:
            client = self._get_sync_client()
            response = client.get(self._jwks_url)
            response.raise_for_status()
            data: object = response.json()
        except Exception as exc:
            raise JwksUnavailableError(f"Failed to fetch JWKS: {exc}") from exc
        if not isinstance(data, Mapping):
            raise JwksUnavailableError("JWKS response was not a JSON object")
        return data

    async def _fetch_async(self) -> Mapping[str, object]:
        try:
            client = self._get_async_client()
            response = await client.get(self._jwks_url)
            response.raise_for_status()
            data: object = response.json()
        except Exception as exc:
            raise JwksUnavailableError(f"Failed to fetch JWKS: {exc}") from exc
        if not isinstance(data, Mapping):
            raise JwksUnavailableError("JWKS response was not a JSON object")
        return data

    def get_key(self, kid: str) -> KeyLookupResult:
        """Resolve kid synchronously with single-flight deduplication and refresh cooldown."""
        while True:
            now = self._clock()
            wait_flight: _SyncInflightRefresh | None = None
            leader_flight: _SyncInflightRefresh | None = None
            with self._lock:
                if kid in self._revoked_kids:
                    return KeyLookupResult(status="revoked")
                expired = self._is_expired(now)
                if not expired:
                    cached = self._lookup_cached(kid)
                    if cached is not None:
                        return cached
                    if not self._can_refresh_for_unknown(kid, now):
                        return KeyLookupResult(status="unknown")

                if self._sync_inflight is not None:
                    wait_flight = self._sync_inflight
                else:
                    self._last_refresh_attempt_at = now
                    leader_flight = _SyncInflightRefresh(event=threading.Event())
                    self._sync_inflight = leader_flight

            if wait_flight is not None:
                wait_flight.event.wait()
                if wait_flight.error is not None:
                    raise wait_flight.error
                with self._lock:
                    after_now = self._clock()
                    if not self._is_expired(after_now):
                        cached = self._lookup_cached(kid)
                        if cached is not None:
                            return cached
                        if not self._can_refresh_for_unknown(kid, after_now):
                            return KeyLookupResult(status="unknown")
                continue

            assert leader_flight is not None
            try:
                jwks = self._fetch_sync()
                refreshed_now = self._clock()
                with self._lock:
                    self._apply_jwks(jwks, refreshed_now)
                    cached = self._lookup_cached(kid)
                    if cached is not None:
                        return cached
                    self._record_negative_cache(kid, refreshed_now)
                    return KeyLookupResult(status="unknown")
            except Exception as exc:
                leader_flight.error = exc
                raise
            finally:
                with self._lock:
                    if self._sync_inflight is leader_flight:
                        self._sync_inflight = None
                leader_flight.event.set()

    async def get_key_async(self, kid: str) -> KeyLookupResult:
        """Resolve kid asynchronously with single-flight Future coalescing."""
        loop = asyncio.get_running_loop()
        while True:
            now = self._clock()
            wait_future: asyncio.Future[None] | None = None
            leader_future: asyncio.Future[None] | None = None
            with self._lock:
                if kid in self._revoked_kids:
                    return KeyLookupResult(status="revoked")
                expired = self._is_expired(now)
                if not expired:
                    cached = self._lookup_cached(kid)
                    if cached is not None:
                        return cached
                    if not self._can_refresh_for_unknown(kid, now):
                        return KeyLookupResult(status="unknown")

                if (
                    self._async_inflight is not None
                    and not self._async_inflight.done()
                    and self._async_inflight_loop is loop
                ):
                    wait_future = self._async_inflight
                else:
                    self._last_refresh_attempt_at = now
                    leader_future = loop.create_future()
                    self._async_inflight = leader_future
                    self._async_inflight_loop = loop

            if wait_future is not None:
                await asyncio.shield(wait_future)
                with self._lock:
                    after_now = self._clock()
                    if not self._is_expired(after_now):
                        cached = self._lookup_cached(kid)
                        if cached is not None:
                            return cached
                        if not self._can_refresh_for_unknown(kid, after_now):
                            return KeyLookupResult(status="unknown")
                continue

            assert leader_future is not None
            try:
                jwks = await self._fetch_async()
                refreshed_now = self._clock()
                with self._lock:
                    self._apply_jwks(jwks, refreshed_now)
                    cached = self._lookup_cached(kid)
                    if cached is None:
                        self._record_negative_cache(kid, refreshed_now)
                if not leader_future.done():
                    leader_future.set_result(None)
                return cached if cached is not None else KeyLookupResult(status="unknown")
            except BaseException as exc:
                if not leader_future.done():
                    if isinstance(exc, Exception):
                        leader_future.set_exception(exc)
                        leader_future.exception()
                    else:
                        leader_future.cancel()
                raise
            finally:
                with self._lock:
                    if self._async_inflight is leader_future:
                        self._async_inflight = None
                        self._async_inflight_loop = None
