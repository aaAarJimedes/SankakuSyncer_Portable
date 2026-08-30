# -*- coding: utf-8 -*-
"""Deterministic tests for process-wide request pacing."""

from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from request_gate import GateCancelled, SharedRequestGate, retry_after_seconds


class RetryAfterTests(unittest.TestCase):
    def test_numeric_http_date_reset_and_default_values(self):
        self.assertEqual(retry_after_seconds({"Retry-After": "0"}), 0.0)
        self.assertEqual(retry_after_seconds({"Retry-After": "12"}), 12.0)
        self.assertEqual(
            retry_after_seconds({"Retry-After": "999999999999999999"}),
            86_400.0,
        )
        with mock.patch("request_gate.time.time", return_value=1_000.0):
            self.assertEqual(
                retry_after_seconds(
                    {"Retry-After": "Thu, 01 Jan 1970 00:20:00 GMT"}
                ),
                200.0,
            )
            self.assertEqual(
                retry_after_seconds({"X-RateLimit-Reset": "1300"}),
                300.0,
            )
            self.assertEqual(
                retry_after_seconds({"X-RateLimit-Reset": "900"}),
                0.0,
            )
        self.assertEqual(retry_after_seconds({"Retry-After": "broken"}), 600.0)
        self.assertEqual(
            retry_after_seconds({"Retry-After": "broken"}, default=0.0),
            0.0,
        )
        self.assertEqual(retry_after_seconds(object()), 600.0)

    def test_invalid_retry_after_falls_through_to_valid_reset(self):
        invalid_values = (
            "NaN",
            float("nan"),
            "Infinity",
            "-Infinity",
            "1e1000000",
            -1,
            10**1000,
        )
        with mock.patch("request_gate.time.time", return_value=1_000.0):
            for value in invalid_values:
                with self.subTest(value=repr(value)):
                    self.assertEqual(
                        retry_after_seconds(
                            {
                                "Retry-After": value,
                                "X-RateLimit-Reset": "1030",
                            }
                        ),
                        30.0,
                    )

    def test_non_finite_or_overflowing_reset_uses_finite_default(self):
        invalid_values = (
            "NaN",
            float("nan"),
            "Infinity",
            "-Infinity",
            "1e1000000",
            10**1000,
            "broken",
        )
        for value in invalid_values:
            with self.subTest(value=repr(value)):
                self.assertEqual(
                    retry_after_seconds(
                        {"X-RateLimit-Reset": value}, default=17.0
                    ),
                    17.0,
                )

    def test_invalid_retry_after_without_reset_uses_default(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e1000000", -1):
            with self.subTest(value=value):
                self.assertEqual(
                    retry_after_seconds({"Retry-After": value}),
                    600.0,
                )

    def test_default_must_be_finite_and_non_negative(self):
        for value in (float("nan"), float("inf"), float("-inf"), -1, 10**1000):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                retry_after_seconds({}, default=value)


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

    def test_defer_rejects_non_finite_or_overflowing_values(self):
        gate = SharedRequestGate(1)
        for value in (float("nan"), float("inf"), float("-inf"), 10**1000):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                gate.defer(value)
        self.assertEqual(gate._next_start, 0.0)

    def test_concurrency_must_be_positive(self):
        for value in (0, -1, 1.0, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SharedRequestGate(value)


if __name__ == "__main__":
    unittest.main()
