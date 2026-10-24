from __future__ import annotations

import time
from collections import deque
from threading import Lock


class SlidingWindowRateLimiter:
    """Bounded single-process limiter; use a shared store for multiple replicas.

    The key cap protects memory against unlimited one-off client identities.
    When full and no expired buckets remain, new identities fail closed.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int = 60,
        *,
        max_keys: int = 10_000,
    ):
        if max_requests < 1 or window_seconds < 1 or max_keys < 1:
            raise ValueError("rate-limit parameters must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()
        self._last_cleanup = time.monotonic()

    def _prune(self, cutoff: float) -> None:
        for key, bucket in list(self._events.items()):
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                del self._events[key]

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if now - self._last_cleanup >= self.window_seconds:
                self._prune(cutoff)
                self._last_cleanup = now

            if key not in self._events:
                if len(self._events) >= self.max_keys:
                    self._prune(cutoff)
                    if len(self._events) >= self.max_keys:
                        return False
                self._events[key] = deque()

            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True
