# -*- coding: utf-8 -*-
"""Process-wide cancellable request gates shared by independent workers."""

from __future__ import annotations

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import math
import threading
import time


_MAX_COOLDOWN_SECONDS = 86_400.0
_DEFAULT_RETRY_AFTER_SECONDS = 600.0


class GateCancelled(RuntimeError):
    pass


def _finite_number(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _bounded_default(default: object) -> float:
    value = _finite_number(default)
    if value is None or value < 0:
        raise ValueError("default cooldown must be finite and non-negative")
    return min(value, _MAX_COOLDOWN_SECONDS)


def retry_after_seconds(
    headers: object, default: float = _DEFAULT_RETRY_AFTER_SECONDS
) -> float:
    """Return one bounded, finite server cooldown from HTTP response headers.

    ``Retry-After`` accepts either a non-negative delay or an HTTP date.
    Invalid values fall through to ``X-RateLimit-Reset`` and finally to the
    caller's default instead of accidentally becoming a zero-second delay.
    """

    fallback = _bounded_default(default)
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return fallback

    value = getter("Retry-After")
    if value is not None:
        delay = _finite_number(value)
        if delay is not None and delay >= 0:
            return min(delay, _MAX_COOLDOWN_SECONDS)
        try:
            target = parsedate_to_datetime(str(value)).timestamp()
            date_delay = target - time.time()
        except (TypeError, ValueError, OverflowError, OSError):
            pass
        else:
            if math.isfinite(date_delay):
                return max(0.0, min(date_delay, _MAX_COOLDOWN_SECONDS))

    reset = getter("X-RateLimit-Reset")
    if reset is not None:
        target = _finite_number(reset)
        if target is not None:
            reset_delay = target - time.time()
            if math.isfinite(reset_delay):
                return max(0.0, min(reset_delay, _MAX_COOLDOWN_SECONDS))
    return fallback


class SharedRequestGate:
    """Bound concurrency and start pace across otherwise isolated sessions."""

    def __init__(self, concurrency: int) -> None:
        if type(concurrency) is not int or concurrency < 1:
            raise ValueError("concurrency must be positive")
        self._slots = threading.BoundedSemaphore(concurrency)
        self._pace_lock = threading.Lock()
        self._next_start = 0.0

    def defer(self, seconds: float) -> None:
        """Move the shared next-start deadline forward after a server cooldown."""
        value = _finite_number(seconds)
        if value is None:
            raise ValueError("cooldown must be finite")
        delay = max(0.0, min(value, _MAX_COOLDOWN_SECONDS))
        with self._pace_lock:
            self._next_start = max(self._next_start, time.monotonic() + delay)

    def _wait_for_start(self, stop_event: threading.Event, min_interval: float) -> None:
        while True:
            if stop_event.is_set():
                raise GateCancelled("operation cancelled")
            with self._pace_lock:
                now = time.monotonic()
                delay = self._next_start - now
                if delay <= 0:
                    self._next_start = now + max(0.0, float(min_interval))
                    return
            if stop_event.wait(min(delay, 0.2)):
                raise GateCancelled("operation cancelled")

    @contextmanager
    def slot(self, stop_event: threading.Event, *, min_interval: float = 0.0):
        acquired = False
        try:
            while not self._slots.acquire(timeout=0.2):
                if stop_event.is_set():
                    raise GateCancelled("operation cancelled")
            acquired = True
            self._wait_for_start(stop_event, min_interval)
            if stop_event.is_set():
                raise GateCancelled("operation cancelled")
            yield
        finally:
            if acquired:
                self._slots.release()


MEDIA_REQUEST_GATE = SharedRequestGate(2)


__all__ = [
    "GateCancelled",
    "MEDIA_REQUEST_GATE",
    "SharedRequestGate",
    "retry_after_seconds",
]
