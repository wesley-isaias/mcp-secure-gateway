"""Per-client token-bucket rate limiter with an injectable clock."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """Allows ``burst`` calls at once, refilled at ``per_second`` calls per second."""

    def __init__(
        self,
        per_second: float,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
        max_clients: int = 10_000,
    ):
        if per_second <= 0 or burst < 1:
            raise ValueError("per_second must be > 0 and burst >= 1")
        self._rate = per_second
        self._burst = float(burst)
        self._clock = clock
        self._max_clients = max_clients
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(client, (self._burst, now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            if client not in self._buckets and len(self._buckets) >= self._max_clients:
                # Bound memory: drop the stalest bucket before tracking a new client.
                stalest = min(self._buckets, key=lambda c: self._buckets[c][1])
                del self._buckets[stalest]
            self._buckets[client] = (tokens, now)
            return allowed
