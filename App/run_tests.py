# -*- coding: utf-8 -*-
"""Discover and run the deterministic offline regression suite."""

from __future__ import annotations

from contextlib import ExitStack
import os
import socket
import sys
import unittest
import urllib.request
from unittest import mock

import http_transport


APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Discovery imports executable Python.  Disable bytecode writes before
# importing a single test module.  UI smoke tests disable WebEngine itself;
# unsafe Chromium command-line flags are never installed process-wide.
sys.dont_write_bytecode = True
os.environ["SANKAKU_DISABLE_WEBENGINE"] = "1"


def _reject_network(*_args, **_kwargs):
    raise AssertionError("offline regression test attempted live network access")


def run_all_tests() -> bool:
    """Run all ``test_*.py`` files with common network transports blocked."""
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)

    # Apply the guards before discovery: import-time traffic is a test failure,
    # not a loophole around per-test mocks.
    with ExitStack() as stack:
        # Python socket guards do not cover ctypes WinHTTP calls.  Production
        # bindings are disabled at their first native operation; tests that
        # exercise Session inject a fake bindings object instead.
        stack.enter_context(
            mock.patch.object(
                http_transport._WinHttpBindings,
                "open",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                socket.socket,
                "connect",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                socket.socket,
                "connect_ex",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                socket.socket,
                "sendto",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                socket,
                "create_connection",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                urllib.request.OpenerDirector,
                "open",
                side_effect=_reject_network,
            )
        )
        stack.enter_context(
            mock.patch.object(
                urllib.request,
                "urlopen",
                side_effect=_reject_network,
            )
        )
        suite = unittest.defaultTestLoader.discover(
            start_dir=APP_DIR,
            pattern="test_*.py",
            top_level_dir=APP_DIR,
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)

    print(
        f"tests={result.testsRun} failures={len(result.failures)} "
        f"errors={len(result.errors)} skipped={len(result.skipped)}"
    )
    return result.wasSuccessful()


if __name__ == "__main__":
    raise SystemExit(0 if run_all_tests() else 1)
