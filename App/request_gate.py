# -*- coding: utf-8 -*-
"""Process-wide cancellable request gates shared by independent workers."""

from __future__ import annotations

from contextlib import contextmanager
import threading
import time


class GateCancelled(RuntimeError):
    pass


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
        delay = max(0.0, min(float(seconds), 86_400.0))
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


__all__ = ["GateCancelled", "MEDIA_REQUEST_GATE", "SharedRequestGate"]
