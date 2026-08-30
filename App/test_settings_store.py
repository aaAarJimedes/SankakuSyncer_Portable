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
from settings_store import (
    SettingsConflictError,
    SettingsCorruptError,
    SettingsError,
    SettingsReadError,
    SettingsStore,
    SettingsWriteError,
)


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
            json.dumps({"schema_version": 1, "request_delay": 10**309}).encode(
                "utf-8"
            ),
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
                self.assertIsInstance(
                    self.store.last_load_error, SettingsCorruptError
                )
                with self.assertRaisesRegex(SettingsWriteError, "尚未可靠载入"):
                    self.store.save()

    def test_corrupt_snapshot_can_be_quarantined_reloaded_and_replaced(self):
        original = b"{broken settings"
        with open(self.store.path, "wb") as file_obj:
            file_obj.write(original)
        self.assertFalse(self.store.load())
        recovery_path = os.path.join(self.data_dir, "settings.corrupt.test.json")

        self.store.quarantine_corrupt(recovery_path)

        with open(recovery_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original)
        self.assertFalse(os.path.exists(self.store.path))
        self.assertTrue(self.store.load())
        self.store.set("page_size", 40)
        self.store.save()
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_quarantine_refuses_to_move_a_replaced_valid_file(self):
        with open(self.store.path, "wb") as file_obj:
            file_obj.write(b"{broken settings")
        self.assertFalse(self.store.load())
        valid = {"schema_version": 1, "page_size": 40}
        replacement = os.path.join(self.data_dir, "valid.tmp")
        with open(replacement, "w", encoding="utf-8") as file_obj:
            json.dump(valid, file_obj, ensure_ascii=False)
        os.replace(replacement, self.store.path)
        recovery_path = os.path.join(self.data_dir, "settings.corrupt.test.json")

        with self.assertRaises(SettingsConflictError):
            self.store.quarantine_corrupt(recovery_path)

        self.assertFalse(os.path.exists(recovery_path))
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_temporary_read_failure_is_distinct_and_preserves_the_file(self):
        self.store.set("download_dir", "Downloads/custom")
        self.store.set("remember_credentials", True)
        self.store.set("credential_vault_receipt", "a" * 64)
        self.store.save()
        with open(self.store.path, "rb") as file_obj:
            before = file_obj.read()

        with mock.patch(
            "builtins.open", side_effect=PermissionError("simulated sharing conflict")
        ):
            self.assertFalse(self.store.load())

        self.assertIsInstance(self.store.last_load_error, SettingsReadError)
        self.assertIn("PermissionError", self.store.last_error)
        self.assertEqual(self.store.values, SettingsStore.DEFAULTS)
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)

        self.store.set("page_size", 40)
        with self.assertRaisesRegex(SettingsWriteError, "尚未可靠载入"):
            self.store.save()
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)

        self.assertTrue(self.store.load())
        self.assertIsNone(self.store.last_load_error)
        self.assertEqual(self.store.get("download_dir"), "Downloads/custom")
        self.assertTrue(self.store.get("remember_credentials"))

        self.store.set("page_size", 40)
        self.store.save()
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_oversize_file_is_rejected_without_reading_its_body(self):
        with open(self.store.path, "wb") as file_obj:
            file_obj.write(b"{}")
        real_open = open

        class OversizedReader:
            def __init__(self, reader):
                self.reader = reader

            def __enter__(self):
                self.reader.__enter__()
                return self

            def __exit__(self, exc_type, exc, traceback):
                return self.reader.__exit__(exc_type, exc, traceback)

            def fileno(self):
                return self.reader.fileno()

            def read(self, _size=-1):
                raise AssertionError("oversized settings body must not be read")

        def oversized_open(path, *args, **kwargs):
            return OversizedReader(real_open(path, *args, **kwargs))

        oversized_stat = mock.Mock(
            st_dev=1,
            st_ino=2,
            st_size=1024 * 1024 + 1,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        with mock.patch("builtins.open", side_effect=oversized_open), mock.patch.object(
            settings_module.os, "fstat", return_value=oversized_stat
        ), mock.patch.object(
            settings_module.os, "stat", return_value=oversized_stat
        ), mock.patch.object(settings_module.os.path, "samestat", return_value=True):
            self.assertFalse(self.store.load())
        self.assertEqual(self.store.values, SettingsStore.DEFAULTS)
        self.assertIsInstance(self.store.last_load_error, SettingsCorruptError)
        with self.assertRaisesRegex(SettingsWriteError, "尚未可靠载入"):
            self.store.save()

    def test_oversize_file_is_never_automatically_quarantined(self):
        limit = 1024 * 1024 + 1
        with open(self.store.path, "wb") as file_obj:
            file_obj.write(b"A" * limit)
        self.assertFalse(self.store.load())
        replacement = os.path.join(self.data_dir, "oversize-replacement.tmp")
        with open(replacement, "wb") as file_obj:
            file_obj.write(b"B" * limit)
        os.replace(replacement, self.store.path)
        recovery_path = os.path.join(self.data_dir, "settings.corrupt.test.json")

        with self.assertRaisesRegex(SettingsWriteError, "没有可安全隔离"):
            self.store.quarantine_corrupt(recovery_path)

        self.assertFalse(os.path.exists(recovery_path))
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(1), b"B")
            self.assertEqual(os.fstat(file_obj.fileno()).st_size, limit)

    def test_stale_missing_baseline_cannot_overwrite_first_creator(self):
        first = SettingsStore(self.data_dir)
        stale = SettingsStore(self.data_dir)
        first.set("page_size", 40)
        first.save()

        stale.set("page_size", 32)
        with self.assertRaisesRegex(SettingsConflictError, "另一个程序"):
            stale.save()

        self.assertEqual(stale.get("page_size"), 32)
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_stale_existing_baseline_cannot_overwrite_newer_settings(self):
        self.store.save()
        first = SettingsStore(self.data_dir)
        stale = SettingsStore(self.data_dir)
        first.set("request_timeout", 45)
        first.save()

        stale.set("page_size", 32)
        with self.assertRaisesRegex(SettingsConflictError, "另一个程序"):
            stale.save()

        on_disk = SettingsStore(self.data_dir)
        self.assertEqual(on_disk.get("request_timeout"), 45)
        self.assertEqual(on_disk.get("page_size"), 24)

    def test_digest_detects_equal_size_change_with_restored_mtime(self):
        self.store.save()
        writer = SettingsStore(self.data_dir)
        stale = SettingsStore(self.data_dir)
        before_stat = os.stat(self.store.path)
        with open(self.store.path, "rb") as file_obj:
            before_bytes = file_obj.read()

        writer.set("page_size", 40)
        writer.save()
        os.utime(
            self.store.path,
            ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns),
        )
        after_stat = os.stat(self.store.path)
        with open(self.store.path, "rb") as file_obj:
            after_bytes = file_obj.read()
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        self.assertNotEqual(after_bytes, before_bytes)

        stale.set("page_size", 32)
        with self.assertRaises(SettingsConflictError):
            stale.save()
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_external_file_deletion_is_a_signature_conflict(self):
        self.store.save()
        os.remove(self.store.path)
        self.store.set("page_size", 40)

        with self.assertRaises(SettingsConflictError):
            self.store.save()

        self.assertFalse(os.path.exists(self.store.path))
        self.assertEqual(self.store.get("page_size"), 40)

    def test_process_lock_closes_check_then_replace_window(self):
        self.store.save()
        writer = SettingsStore(self.data_dir)
        competing = SettingsStore(self.data_dir)
        real_atomic_write = writer._atomic_write
        blocked = []

        def interleaved_write(encoded, expected_signature):
            competing.set("page_size", 32)
            with self.assertRaises(SettingsConflictError):
                competing.save()
            blocked.append(True)
            real_atomic_write(encoded, expected_signature)

        with mock.patch.object(
            writer, "_atomic_write", side_effect=interleaved_write
        ):
            writer.set("page_size", 40)
            writer.save()

        self.assertEqual(blocked, [True])
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)

    def test_empty_hardlinked_lock_file_is_never_modified(self):
        lock_path = os.path.join(self.data_dir, ".settings-store.lock")
        os.remove(lock_path)
        victim_path = os.path.join(self.data_dir, "empty-victim.bin")
        with open(victim_path, "wb"):
            pass
        os.link(victim_path, lock_path)

        loaded = SettingsStore(self.data_dir)

        self.assertIsNone(loaded.last_load_error)
        with open(victim_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"")

    def test_process_lock_acquire_error_survives_cleanup_close_error(self):
        real_close = os.close

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError("simulated cleanup close failure")

        if os.name == "nt":
            import msvcrt

            acquire_failure = mock.patch.object(
                msvcrt,
                "locking",
                side_effect=OSError("simulated lock contention"),
            )
        else:
            import fcntl

            acquire_failure = mock.patch.object(
                fcntl,
                "flock",
                side_effect=OSError("simulated lock contention"),
            )
        with acquire_failure, mock.patch.object(
            settings_module.os,
            "close",
            side_effect=close_then_fail,
        ):
            with self.assertRaises(SettingsConflictError):
                settings_module._SettingsProcessLock(self.data_dir).__enter__()

    def test_lock_exit_failure_does_not_publish_a_committed_baseline(self):
        fail_exit = False

        class ExitFailLock:
            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                if fail_exit:
                    raise OSError("simulated lock release failure")

        store = SettingsStore(
            self.data_dir,
            lock_factory=lambda: ExitFailLock(),
        )
        store.set("page_size", 40)
        fail_exit = True

        with self.assertRaisesRegex(SettingsWriteError, "事务锁失败"):
            store.save()

        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 40)
        fail_exit = False
        with self.assertRaises(SettingsConflictError):
            store.save()

    def test_quarantine_lock_exit_failure_keeps_unknown_baseline(self):
        fail_exit = False

        class ExitFailLock:
            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                if fail_exit:
                    raise OSError("simulated lock release failure")

        with open(self.store.path, "wb") as file_obj:
            file_obj.write(b"{broken settings")
        store = SettingsStore(
            self.data_dir,
            lock_factory=lambda: ExitFailLock(),
        )
        self.assertIsInstance(store.last_load_error, SettingsCorruptError)
        recovery_path = os.path.join(self.data_dir, "settings.corrupt.test.json")
        fail_exit = True

        with self.assertRaisesRegex(SettingsWriteError, "事务锁失败"):
            store.quarantine_corrupt(recovery_path)

        self.assertFalse(os.path.exists(store.path))
        self.assertTrue(os.path.isfile(recovery_path))
        with self.assertRaisesRegex(SettingsWriteError, "尚未可靠载入"):
            store.save()

    def test_load_retries_when_path_is_replaced_after_snapshot_read(self):
        old_payload = {"schema_version": 1, "page_size": 24}
        new_payload = {"schema_version": 1, "page_size": 40}
        self._write_json(old_payload)
        replacement_path = os.path.join(self.data_dir, "replacement.tmp")
        with open(replacement_path, "w", encoding="utf-8") as file_obj:
            json.dump(new_payload, file_obj, ensure_ascii=False)

        real_open = open
        store_path = self.store.path
        replaced = False

        class ReplacingReader:
            def __init__(self, reader):
                self.reader = reader

            def __enter__(self):
                self.reader.__enter__()
                return self

            def __exit__(self, exc_type, exc, traceback):
                nonlocal replaced
                result = self.reader.__exit__(exc_type, exc, traceback)
                if not replaced:
                    os.replace(replacement_path, store_path)
                    replaced = True
                return result

            def fileno(self):
                return self.reader.fileno()

            def read(self, size=-1):
                return self.reader.read(size)

        def replace_after_first_read(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            reader = real_open(path, *args, **kwargs)
            if (
                not replaced
                and os.path.abspath(os.fspath(path))
                == os.path.abspath(store_path)
                and mode == "rb"
            ):
                return ReplacingReader(reader)
            return reader

        with mock.patch("builtins.open", side_effect=replace_after_first_read):
            self.assertTrue(self.store.load())

        self.assertTrue(replaced)
        self.assertEqual(self.store.get("page_size"), 40)
        self.store.set("page_size", 32)
        self.store.save()
        self.assertEqual(SettingsStore(self.data_dir).get("page_size"), 32)

    def test_continuously_changing_snapshot_leaves_unknown_baseline(self):
        self.store.save()
        with mock.patch.object(
            settings_module.os.path, "samestat", return_value=False
        ):
            self.assertFalse(self.store.load())

        self.assertIsInstance(self.store.last_load_error, SettingsReadError)
        self.store.set("page_size", 40)
        with self.assertRaisesRegex(SettingsWriteError, "尚未可靠载入"):
            self.store.save()

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
