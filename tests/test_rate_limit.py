from __future__ import annotations

import pytest

from app import rate_limit
from app.rate_limit import SlidingWindowRateLimiter


def test_per_identity_window_limit(monkeypatch):
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: 100.0)
    limiter = SlidingWindowRateLimiter(2, window_seconds=60)
    assert limiter.allow("client-1") is True
    assert limiter.allow("client-1") is True
    assert limiter.allow("client-1") is False
    assert limiter.allow("client-2") is True


def test_new_identity_fails_closed_when_key_capacity_is_reached(monkeypatch):
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: 100.0)
    limiter = SlidingWindowRateLimiter(3, max_keys=2)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("c") is False
    assert len(limiter._events) == 2
    assert limiter.allow("a") is True


def test_expired_buckets_reclaimed_before_capacity_denial(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock[0])
    limiter = SlidingWindowRateLimiter(1, window_seconds=60, max_keys=1)
    assert limiter.allow("a") is True
    clock[0] = 161.0
    assert limiter.allow("b") is True
    assert "a" not in limiter._events
    assert len(limiter._events) == 1


def test_rejects_invalid_configuration():
    for kwargs in ({"max_requests": 0}, {"max_requests": 1, "window_seconds": 0}, {"max_requests": 1, "max_keys": 0}):
        with pytest.raises(ValueError, match="positive"):
            SlidingWindowRateLimiter(**kwargs)
