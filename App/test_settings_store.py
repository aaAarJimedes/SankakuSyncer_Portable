# -*- coding: utf-8 -*-
"""Offline tests for validated, credential-free settings persistence."""

from __future__ import annotations

import copy
import json
import math
import os
import tempfile
import unittest
from unittest import mock

import settings_store as settings_module
from settings_store import SettingsError, SettingsStore


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.data_dir = self._temporary.name
        self.store = SettingsStore(self.data_dir)

    def tearDown(self):
        self._temporary.cleanup()

    def _write_json(self, payload) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.store.path, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False)

    def test_missing_file_uses_independent_defaults(self):
        self.assertEqual(self.store.values, SettingsStore.DEFAULTS)
        self.assertIsNot(self.store.values, SettingsStore.DEFAULTS)
        self.assertEqual(self.store.get("page_size"), 24)
        self.assertIs(self.store.get("remember_credentials"), False)
        self.assertEqual(self.store.get("unknown", "fallback"), "fallback")
        self.store.values["page_size"] = 12
        other = SettingsStore(self.data_dir)
        self.assertEqual(other.get("page_size"), 24)

    def test_round_trip_all_supported_types(self):
        expected = {
            "download_dir": r"D:\Media\Sankaku",
            "default_rating": "all",
            "request_delay": 2.5,
            "request_timeout": 45,
            "max_retries": 7,
            "page_size": 32,
            "proxy": "http://127.0.0.1:8080",
            "remember_credentials": False,
            "credential_vault_receipt": "a" * 64,
            "prefer_original": False,
            "save_metadata": False,
            "window_geometry": "test-geometry",
        }
        self.store.update(expected)
        self.store.save()

        reloaded = SettingsStore(self.data_dir)
        self.assertEqual(reloaded.values, expected)
        self.assertEqual(reloaded.last_error, "")
        with open(reloaded.path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotIn("password", payload)
        self.assertNotIn("access_token", payload)

    def test_partial_valid_file_fills_missing_defaults(self):
        self._write_json({"schema_version": 1, "page_size": 40})
        self.assertTrue(self.store.load())
        self.assertEqual(self.store.get("page_size"), 40)
        self.assertEqual(self.store.get("request_timeout"), 30)
        self.assertEqual(self.store.get("default_rating"), "s")

    def test_update_is_transactional_on_late_validation_failure(self):
        before = copy.deepcopy(self.store.values)
        with self.assertRaises(SettingsError):
            self.store.update(
                {
                    "page_size": 40,
                    "request_timeout": 181,
                }
            )
        self.assertEqual(self.store.values, before)

    def test_unknown_set_and_update_are_rejected(self):
        with self.assertRaises(SettingsError):
            self.store.set("unknown", True)
        with self.assertRaises(SettingsError):
            self.store.update({"page_size": 20, "unknown": True})
        self.assertEqual(self.store.get("page_size"), 24)

    def test_numeric_boundaries_are_inclusive_and_booleans_are_not_numbers(self):
        accepted = {
            "request_delay": (0.5, 30.0),
            "request_timeout": (5, 180),
            "max_retries": (0, 10),
            "page_size": (8, 40),
        }
        for key, values in accepted.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.store.set(key, value)
                    expected = float(value) if key == "request_delay" else value
                    self.assertEqual(self.store.get(key), expected)

        invalid = {
            "request_delay": (0.49, 30.01, math.inf, math.nan, True),
            "request_timeout": (4, 181, 5.0, True),
            "max_retries": (-1, 11, 1.0, False),
            "page_size": (7, 41, 8.0, True),
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaises(SettingsError):
                        self.store.set(key, value)

    def test_enum_boolean_and_string_boundaries(self):
        for rating in ("s", "q", "e", "all"):
            self.store.set("default_rating", rating)
            self.assertEqual(self.store.get("default_rating"), rating)
        with self.assertRaises(SettingsError):
            self.store.set("default_rating", "safe")

        for key in ("remember_credentials", "prefer_original", "save_metadata"):
            for value in (True, False):
                self.store.set(key, value)
                self.assertIs(self.store.get(key), value)
            for value in (0, 1, "true", None):
                with self.subTest(key=key, value=value):
                    with self.assertRaises(SettingsError):
                        self.store.set(key, value)

        download_at_limit = "D:\\" + "x" * (32768 - 3)
        self.store.set("download_dir", download_at_limit)
        self.assertEqual(self.store.get("download_dir"), download_at_limit)
        with self.assertRaises(SettingsError):
            self.store.set("download_dir", download_at_limit + "x")
        with self.assertRaises(SettingsError):
            self.store.set("download_dir", "bad\npath")

        geometry_at_limit = "g" * 16384
        self.store.set("window_geometry", geometry_at_limit)
        with self.assertRaises(SettingsError):
            self.store.set("window_geometry", geometry_at_limit + "g")

        for receipt in ("", "0" * 64, "abcdef" * 10 + "abcd"):
            self.store.set("credential_vault_receipt", receipt)
            self.assertEqual(self.store.get("credential_vault_receipt"), receipt)
        for receipt in (None, 0, "A" * 64, "g" * 64, "0" * 63, "0" * 65):
            with self.subTest(receipt=receipt):
                with self.assertRaises(SettingsError):
                    self.store.set("credential_vault_receipt", receipt)

    def test_download_directory_accepts_only_canonical_portable_or_absolute_paths(self):
        accepted = (
            ("", ""),
            ("Downloads", "Downloads"),
            (r"downloads\albums\..\saved", "Downloads/saved"),
            (r"D:\Media\Sankaku", r"D:\Media\Sankaku"),
            (r"\\server\share\Sankaku", r"\\server\share\Sankaku"),
        )
        for value, expected in accepted:
            with self.subTest(value=value):
                self.store.set("download_dir", value)
                self.assertEqual(self.store.get("download_dir"), expected)

        rejected = (
            "Media",
            r"..\escape",
            r"Downloads\..\escape",
            r"C:relative",
            r"C:..\escape",
            r"\rooted",
            r"\\?\C:\Media",
            r"\\.\C:\Media",
            r"\??\C:\Media",
            r"Downloads\bad:stream",
            r"Downloads\CON",
            "Downloads/COM¹.txt",
            r"D:\Media\LPT²",
            "Downloads/trailing.",
            "Downloads/trailing ",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(SettingsError):
                    self.store.set("download_dir", value)

    def test_proxy_validation_accepts_only_credential_free_host_and_port(self):
        accepted = (
            "http://127.0.0.1:8080",
            "http://proxy.example:443",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.store.set("proxy", f"  {value}  ")
                self.assertEqual(self.store.get("proxy"), value)
        self.store.set("proxy", "   ")
        self.assertEqual(self.store.get("proxy"), "")

        rejected = (
            "ftp://localhost:21",
            "https://proxy.example:443/",
            "socks4://localhost:1080",
            "socks4a://localhost:1080",
            "socks5://localhost:1080",
            "socks5h://localhost:1080",
            "http://localhost",
            "http://localhost:0",
            "http://localhost:65536",
            "http://user:pass@localhost:8080",
            "http://localhost:8080/path",
            "http://localhost:8080/?query=1",
            "http://localhost:8080/#fragment",
            "http://local host:8080",
            "not-a-url",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(SettingsError):
                    self.store.set("proxy", value)

    def test_corrupt_or_unsupported_files_fail_closed_to_defaults(self):
        cases = (
            b"{not-json",
            json.dumps([]).encode("utf-8"),
            json.dumps({"schema_version": True}).encode("utf-8"),
            json.dumps({"schema_version": 1.0}).encode("utf-8"),
            json.dumps({"schema_version": 2}).encode("utf-8"),
            json.dumps({"schema_version": 1, "unknown": True}).encode("utf-8"),
            json.dumps({"schema_version": 1, "page_size": 41}).encode("utf-8"),
            json.dumps({"schema_version": 1, "proxy": "http://u:p@x:1"}).encode(
                "utf-8"
            ),
        )
        for encoded in cases:
            with self.subTest(encoded=encoded[:50]):
                with open(self.store.path, "wb") as file_obj:
                    file_obj.write(encoded)
                self.store.values["page_size"] = 40
                self.assertFalse(self.store.load())
                self.assertEqual(self.store.values, SettingsStore.DEFAULTS)
                self.assertTrue(self.store.last_error)

    def test_oversize_file_is_rejected_without_reading_it(self):
        with open(self.store.path, "wb") as file_obj:
            file_obj.write(b"{}")
        with mock.patch.object(
            settings_module.os.path,
            "getsize",
            return_value=1024 * 1024 + 1,
        ):
            self.assertFalse(self.store.load())
        self.assertEqual(self.store.values, SettingsStore.DEFAULTS)

    def test_save_revalidates_directly_mutated_values(self):
        self.store.save()
        with open(self.store.path, "rb") as file_obj:
            before = file_obj.read()
        self.store.values["page_size"] = 41
        with self.assertRaises(SettingsError):
            self.store.save()
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)

    def test_atomic_replace_failure_preserves_previous_settings(self):
        self.store.save()
        with open(self.store.path, "rb") as file_obj:
            before = file_obj.read()
        self.store.set("page_size", 40)
        with mock.patch.object(
            settings_module.os,
            "replace",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(SettingsError):
                self.store.save()
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 24)


if __name__ == "__main__":
    unittest.main()
