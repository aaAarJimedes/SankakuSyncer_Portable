# -*- coding: utf-8 -*-
"""Deterministic tests for process-wide request pacing."""

from __future__ import annotations

import threading
import time
import unittest

from request_gate import GateCancelled, SharedRequestGate


class SharedRequestGateTests(unittest.TestCase):
    def test_pre_cancelled_slot_is_never_entered_without_a_cooldown(self):
        gate = SharedRequestGate(1)
        stop_event = threading.Event()
        stop_event.set()
        with self.assertRaises(GateCancelled):
            with gate.slot(stop_event):
                self.fail("pre-cancelled slot must not be entered")

    def test_defer_delays_the_next_slot(self):
        gate = SharedRequestGate(1)
        gate.defer(0.04)
        started = time.monotonic()
        with gate.slot(threading.Event()):
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.025)

    def test_waiting_for_a_long_cooldown_is_cancellable(self):
        gate = SharedRequestGate(1)
        stop_event = threading.Event()
        gate.defer(60)
        timer = threading.Timer(0.03, stop_event.set)
        timer.start()
        try:
            with self.assertRaises(GateCancelled):
                with gate.slot(stop_event):
                    self.fail("cancelled slot must not be entered")
        finally:
            timer.cancel()

    def test_concurrency_must_be_positive(self):
        for value in (0, -1, 1.0, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SharedRequestGate(value)


if __name__ == "__main__":
    unittest.main()
