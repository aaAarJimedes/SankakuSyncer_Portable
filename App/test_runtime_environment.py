# -*- coding: utf-8 -*-
"""Tests for pre-Qt inherited-environment hardening."""

from __future__ import annotations

from pathlib import Path
import unittest

from runtime_environment import (
    UNSAFE_INHERITED_ENVIRONMENT,
    sanitize_runtime_environment,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class RuntimeEnvironmentTests(unittest.TestCase):
    def test_polluted_environment_is_removed_case_insensitively(self):
        environment = {
            "qtwebengine_chromium_flags": "--no-sandbox --proxy-server=evil",
            "QTWEBENGINE_REMOTE_DEBUGGING": "9222",
            "HTTPS_PROXY": "http://evil:8080",
            "SSLKEYLOGFILE": "secret.log",
            "SAFE_VALUE": "keep",
        }
        sanitize_runtime_environment(environment)
        self.assertEqual(environment["SAFE_VALUE"], "keep")
        self.assertEqual(environment["QT_SSL_BACKEND"], "schannel")
        forbidden = {name.casefold() for name in UNSAFE_INHERITED_ENVIRONMENT}
        self.assertFalse(any(name.casefold() in forbidden for name in environment))

    def test_main_sanitizes_before_the_first_pyside_import(self):
        text = (PROJECT_ROOT / "App" / "main.py").read_text("utf-8")
        sanitize_at = text.index("sanitize_runtime_environment()")
        pyside_at = text.index("from PySide6")
        self.assertLess(sanitize_at, pyside_at)

    def test_normal_launchers_clear_inherited_webengine_knobs_and_select_schannel(self):
        for name in ("run.bat", "run_debug.bat"):
            with self.subTest(name=name):
                text = (PROJECT_ROOT / name).read_text("utf-8").casefold()
                for variable in UNSAFE_INHERITED_ENVIRONMENT:
                    self.assertIn(f'set "{variable.casefold()}=', text)
                self.assertIn('set "qt_ssl_backend=schannel"', text)

    def test_development_console_requires_explicit_opt_in(self):
        text = (PROJECT_ROOT / "dev_console.bat").read_text("utf-8").casefold()
        self.assertIn("--enable-development-console", text)
        self.assertIn("explicit opt-in", text)


if __name__ == "__main__":
    unittest.main()
