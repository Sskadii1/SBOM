"""
modules/agents/rate_limiter.py - Token-bucket rate limiter for external API calls.

Provides per-endpoint throttling (OSV API, OpenRouter LLM) with
automatic retry and exponential back-off on HTTP 429 / rate-limit errors.
"""

import logging
import time
import threading
from typing import Callable, Optional, TypeVar

import requests

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Thread-safe token-bucket rate limiter.

    Parameters
    ----------
    calls_per_second : float
        Maximum sustained call rate (e.g. 5.0 = 5 calls/s).
        For per-minute limits pass ``calls_per_minute / 60``.
    burst : int, optional
        Maximum burst size (bucket capacity). Defaults to
        ``max(1, int(calls_per_second))``.
    name : str
        Label used in log messages.
    """

    def __init__(
        self,
        calls_per_second: float,
        burst: Optional[int] = None,
        name: str = "api",
    ):
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be > 0")

        self.calls_per_second = calls_per_second
        self.burst = burst if burst is not None else max(1, int(calls_per_second))
        self.name = name

        self._tokens: float = float(self.burst)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Core acquire
    # ------------------------------------------------------------------

    def acquire(self) -> None:
        """Block until a token is available."""
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # Calculate how long to wait for the next token
            wait = (1.0 - self._tokens) / self.calls_per_second

        logger.debug(f"[RateLimit:{self.name}] throttling {wait:.2f}s")
        time.sleep(wait)

        with self._lock:
            self._refill()
            self._tokens = max(0.0, self._tokens - 1.0)

    def _refill(self) -> None:
        """Add tokens proportional to elapsed time (call inside lock)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self.burst),
            self._tokens + elapsed * self.calls_per_second,
        )
        self._last_refill = now

    # ------------------------------------------------------------------
    # Retry helper
    # ------------------------------------------------------------------

    def call_with_retry(
        self,
        fn: Callable[[], T],
        max_retries: int = 3,
        base_backoff: float = 2.0,
    ) -> T:
        """
        Call ``fn`` with rate limiting + exponential back-off on 429/503.

        Parameters
        ----------
        fn : callable
            Zero-argument callable that performs the HTTP request and
            raises ``requests.HTTPError`` on non-2xx responses.
        max_retries : int
            Maximum number of retry attempts after a rate-limit error.
        base_backoff : float
            Base back-off time in seconds; doubles each retry.

        Returns
        -------
        The return value of ``fn``.

        Raises
        ------
        requests.HTTPError
            Re-raised if retries are exhausted or it's not a 429/503.
        Exception
            Any non-HTTP exception from ``fn`` is propagated immediately.
        """
        for attempt in range(max_retries + 1):
            self.acquire()
            try:
                return fn()
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                if status in (429, 503) and attempt < max_retries:
                    retry_after = _parse_retry_after(exc.response)
                    wait = retry_after if retry_after else base_backoff * (2 ** attempt)
                    logger.warning(
                        f"[RateLimit:{self.name}] HTTP {status} — "
                        f"retry {attempt + 1}/{max_retries} in {wait:.1f}s"
                    )
                    time.sleep(wait)
                else:
                    raise
        # Unreachable, but satisfies type checkers
        raise RuntimeError("call_with_retry: exhausted retries without return or raise")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_retry_after(response: Optional[requests.Response]) -> Optional[float]:
    """Return the Retry-After header value in seconds, if present."""
    if response is None:
        return None
    header = response.headers.get("Retry-After")
    if header is None:
        return None
    try:
        return float(header)
    except ValueError:
        return None
