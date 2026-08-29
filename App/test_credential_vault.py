# -*- coding: utf-8 -*-
"""Offline tests for credential validation and encrypted-file handling."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import credential_vault as vault_module
from credential_vault import CredentialVault, Credentials, VaultError


_TEST_PREFIX = b"UNIT-REVERSIBLE-V1\x00"
_TEST_MASK = 0xA5


def _test_protect(clear: bytes) -> bytes:
    """Reversible test transform; deliberately not encryption or DPAPI."""
    if not isinstance(clear, bytes) or not clear:
        raise VaultError("invalid test plaintext")
    return _TEST_PREFIX + bytes(value ^ _TEST_MASK for value in clear)


def _test_unprotect(protected: bytes) -> bytes:
    if not isinstance(protected, bytes) or not protected.startswith(_TEST_PREFIX):
        raise VaultError("invalid test protected payload")
    body = protected[len(_TEST_PREFIX) :]
    return bytes(value ^ _TEST_MASK for value in body)


class CredentialValidationTests(unittest.TestCase):
    def test_accepts_bounded_dummy_values(self):
        values = Credentials(
            username="u" * 320,
            password="p" * 4096,
            access_token="t" * (128 * 1024),
        ).validated()
        self.assertEqual(len(values.username), 320)
        self.assertEqual(len(values.password), 4096)
        self.assertEqual(len(values.access_token), 128 * 1024)

    def test_rejects_missing_overlong_and_control_bearing_values(self):
        invalid = (
            Credentials("", "dummy-password"),
            Credentials("dummy-user", ""),
            Credentials("u" * 321, "dummy-password"),
            Credentials("dummy-user", "p" * 4097),
            Credentials("dummy-user", "dummy-password", "t" * (128 * 1024 + 1)),
            Credentials("dummy\nuser", "dummy-password"),
            Credentials("dummy-user", "dummy\x00password"),
            Credentials("dummy-user", "dummy-password", "token\x7f"),
        )
        for credentials in invalid:
            with self.subTest(credentials=credentials):
                with self.assertRaises(VaultError):
                    credentials.validated()

    def test_rejects_non_text_fields(self):
        for credentials in (
            Credentials(None, "dummy-password"),
            Credentials("dummy-user", None),
            Credentials("dummy-user", "dummy-password", None),
        ):
            with self.subTest(credentials=credentials):
                with self.assertRaises(VaultError):
                    credentials.validated()


class CredentialVaultTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.data_dir = self._temporary.name
        self.vault = CredentialVault(
            self.data_dir,
            protect=_test_protect,
            unprotect=_test_unprotect,
        )

    def tearDown(self):
        self._temporary.cleanup()

    def _write_clear_payload(self, payload) -> None:
        clear = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.vault.path, "wb") as file_obj:
            file_obj.write(vault_module._MAGIC + _test_protect(clear))

    def test_round_trip_uses_only_injected_reversible_transform(self):
        protect = mock.Mock(wraps=_test_protect)
        unprotect = mock.Mock(wraps=_test_unprotect)
        vault = CredentialVault(
            self.data_dir,
            protect=protect,
            unprotect=unprotect,
        )
        values = Credentials(
            username="unit-user",
            password="unit-password",
            access_token="unit-token",
        )

        self.assertFalse(vault.exists())
        self.assertIsNone(vault.load())
        vault.save(values)
        self.assertTrue(vault.exists())
        with open(vault.path, "rb") as file_obj:
            stored = file_obj.read()
        self.assertTrue(stored.startswith(vault_module._MAGIC + _TEST_PREFIX))
        self.assertNotIn(b"unit-user", stored)
        self.assertNotIn(b"unit-password", stored)
        self.assertNotIn(b"unit-token", stored)
        self.assertEqual(vault.load(), values)
        self.assertEqual(protect.call_count, 1)
        self.assertEqual(unprotect.call_count, 1)

        vault.clear()
        self.assertFalse(vault.exists())
        self.assertIsNone(vault.load())

    def test_save_replaces_an_existing_payload_atomically(self):
        first = Credentials("first-user", "first-password", "first-token")
        second = Credentials("second-user", "second-password", "second-token")
        self.vault.save(first)
        with open(self.vault.path, "rb") as file_obj:
            first_bytes = file_obj.read()
        self.vault.save(second)
        with open(self.vault.path, "rb") as file_obj:
            second_bytes = file_obj.read()
        self.assertNotEqual(first_bytes, second_bytes)
        self.assertEqual(self.vault.load(), second)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_atomic_replace_failure_preserves_previous_file(self):
        original = Credentials("original-user", "original-password")
        self.vault.save(original)
        with open(self.vault.path, "rb") as file_obj:
            before = file_obj.read()

        with mock.patch.object(
            vault_module.os,
            "replace",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.save(Credentials("new-user", "new-password"))

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)
        self.assertEqual(self.vault.load(), original)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_protect_failure_and_oversize_output_do_not_create_a_file(self):
        failing = CredentialVault(
            self.data_dir,
            protect=mock.Mock(side_effect=VaultError("test protection failed")),
            unprotect=_test_unprotect,
        )
        with self.assertRaises(VaultError):
            failing.save(Credentials("unit-user", "unit-password"))
        self.assertFalse(failing.exists())

        oversized = CredentialVault(
            self.data_dir,
            protect=lambda _clear: b"x" * (vault_module._MAX_FILE_BYTES + 1),
            unprotect=_test_unprotect,
        )
        with self.assertRaises(VaultError):
            oversized.save(Credentials("unit-user", "unit-password"))
        self.assertFalse(oversized.exists())

    def test_rejects_wrong_magic_and_oversize_file(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.vault.path, "wb") as file_obj:
            file_obj.write(b"not-a-supported-vault")
        with self.assertRaises(VaultError):
            self.vault.load()

        with mock.patch.object(vault_module, "_MAX_FILE_BYTES", 16):
            with open(self.vault.path, "wb") as file_obj:
                file_obj.write(b"x" * 17)
            with self.assertRaises(VaultError):
                self.vault.load()

    def test_rejects_malformed_decrypted_payloads(self):
        valid = {
            "schema_version": 1,
            "username": "unit-user",
            "password": "unit-password",
            "access_token": "",
        }
        invalid_payloads = (
            [],
            {**valid, "unexpected": True},
            {key: value for key, value in valid.items() if key != "password"},
            {**valid, "schema_version": 2},
            {**valid, "username": "unit\nuser"},
            {**valid, "password": None},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                self._write_clear_payload(payload)
                with self.assertRaises(VaultError):
                    self.vault.load()

    def test_rejects_invalid_utf8_and_invalid_json_after_unprotect(self):
        os.makedirs(self.data_dir, exist_ok=True)
        for clear in (b"\xff", b"not-json"):
            with self.subTest(clear=clear):
                with open(self.vault.path, "wb") as file_obj:
                    file_obj.write(vault_module._MAGIC + _test_protect(clear))
                with self.assertRaises(VaultError):
                    self.vault.load()

    def test_unprotect_failure_is_sanitized_as_vault_error(self):
        self.vault.save(Credentials("unit-user", "unit-password"))
        failing = CredentialVault(
            self.data_dir,
            protect=_test_protect,
            unprotect=mock.Mock(side_effect=VaultError("test unprotect failure")),
        )
        with self.assertRaises(VaultError):
            failing.load()

    def test_clear_wraps_filesystem_failure(self):
        self.vault.save(Credentials("unit-user", "unit-password"))
        with mock.patch.object(
            vault_module.os,
            "remove",
            side_effect=PermissionError("simulated permission failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.clear()
        self.assertTrue(self.vault.exists())


if __name__ == "__main__":
    unittest.main()
