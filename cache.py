"""
cache.py
Phase 2.5 — Redis caching layer for VirusTotal responses.

Design:
  • Key format:  pf2:vt:<ioc>   (namespace prefix from config)
  • Value:       JSON-serialised VT response dict
  • TTL:         24 hours (configurable via REDIS_CACHE_TTL)
  • The RedisCache class is a thin, synchronous wrapper intentionally:
    aiohttp coroutines call .get() / .set() from a thread-pool executor
    inside the async enrichment layer so the event loop is never blocked.
  • If Redis is unavailable the cache degrades gracefully — all lookups
    return None and all writes are silently skipped.  This means the
    pipeline still works; it just loses caching benefits.
"""

import json
import logging
from typing import Any, Dict, Optional

import redis  # type: ignore

from config import (
    REDIS_CACHE_TTL,
    REDIS_DB,
    REDIS_HOST,
    REDIS_KEY_PREFIX,
    REDIS_PASSWORD,
    REDIS_PORT,
)

log = logging.getLogger(__name__)


class RedisCache:
    """
    Thread-safe Redis cache wrapper with graceful degradation.

    Usage
    -----
    cache = RedisCache()

    # Store a VT response
    cache.set("1.2.3.4", {"vt_score": 5, ...})

    # Retrieve it
    data = cache.get("1.2.3.4")   # → dict | None
    if data is None:
        # cache miss → call API
    """

    def __init__(self) -> None:
        self._client: Optional[redis.Redis] = None
        self._available = False
        self._hits   = 0
        self._misses = 0
        self._writes = 0
        self._errors = 0
        self._connect()

    def _connect(self) -> None:
        """Attempt to connect; set _available flag accordingly."""
        try:
            self._client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                socket_connect_timeout=3,
                socket_timeout=5,
                decode_responses=True,   # keys and values come back as str
            )
            self._client.ping()
            self._available = True
            log.info(
                "Redis connected: %s:%d db=%d  TTL=%ds",
                REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_CACHE_TTL,
            )
        except (redis.ConnectionError, redis.TimeoutError) as exc:
            log.warning(
                "Redis unavailable (%s) — caching disabled for this run.", exc
            )
            self._available = False

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, ioc: str) -> Optional[Dict[str, Any]]:
        """
        Return the cached VT response for *ioc*, or None on miss/error.
        """
        if not self._available or not ioc:
            return None

        key = REDIS_KEY_PREFIX + ioc
        try:
            raw = self._client.get(key)  # type: ignore[union-attr]
            if raw is None:
                self._misses += 1
                return None
            self._hits += 1
            return json.loads(raw)
        except (redis.RedisError, json.JSONDecodeError) as exc:
            self._errors += 1
            log.debug("Cache GET error for %s: %s", ioc, exc)
            return None

    def set(self, ioc: str, data: Dict[str, Any]) -> None:
        """
        Persist the VT response dict under *ioc* with the configured TTL.
        No-op if Redis is unavailable or *data* is empty.
        """
        if not self._available or not ioc or not data:
            return

        key = REDIS_KEY_PREFIX + ioc
        try:
            serialised = json.dumps(data, default=str)
            self._client.setex(key, REDIS_CACHE_TTL, serialised)  # type: ignore[union-attr]
            self._writes += 1
            log.debug("Cache SET %s (TTL=%ds)", ioc, REDIS_CACHE_TTL)
        except redis.RedisError as exc:
            self._errors += 1
            log.debug("Cache SET error for %s: %s", ioc, exc)

    def exists(self, ioc: str) -> bool:
        """Return True if the key is present in Redis."""
        if not self._available or not ioc:
            return False
        key = REDIS_KEY_PREFIX + ioc
        try:
            return bool(self._client.exists(key))  # type: ignore[union-attr]
        except redis.RedisError:
            return False

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "cache_hits":   self._hits,
            "cache_misses": self._misses,
            "cache_writes": self._writes,
            "cache_errors": self._errors,
        }

    @property
    def is_available(self) -> bool:
        return self._available
