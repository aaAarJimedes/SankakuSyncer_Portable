# -*- coding: utf-8 -*-
"""Offline tests for login validation and password-free session persistence."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import credential_vault as vault_module
from credential_vault import (
    CredentialVault,
    Credentials,
    StoredSession,
    VaultError,
    VaultSnapshot,
)


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
    def test_accepts_bounded_dummy_login_values(self):
        values = Credentials(username="u" * 320, password="p" * 4096).validated()
        self.assertEqual(len(values.username), 320)
        self.assertEqual(len(values.password), 4096)
        self.assertFalse(hasattr(values, "access_token"))

    def test_rejects_missing_overlong_and_control_bearing_login_values(self):
        invalid = (
            Credentials("", "dummy-password"),
            Credentials("dummy-user", ""),
            Credentials("u" * 321, "dummy-password"),
            Credentials("dummy-user", "p" * 4097),
            Credentials("dummy\nuser", "dummy-password"),
            Credentials("dummy-user", "dummy\x00password"),
        )
        for credentials in invalid:
            with self.subTest(credentials=credentials):
                with self.assertRaises(VaultError):
                    credentials.validated()

    def test_rejects_non_text_login_fields(self):
        for credentials in (
            Credentials(None, "dummy-password"),
            Credentials("dummy-user", None),
        ):
            with self.subTest(credentials=credentials):
                with self.assertRaises(VaultError):
                    credentials.validated()


class StoredSessionValidationTests(unittest.TestCase):
    def test_accepts_bounded_dummy_session_values(self):
        values = StoredSession(
            username="u" * 320,
            access_token="t" * (128 * 1024),
        ).validated()
        self.assertEqual(len(values.username), 320)
        self.assertEqual(len(values.access_token), 128 * 1024)
        self.assertFalse(hasattr(values, "password"))

    def test_rejects_invalid_session_values(self):
        invalid = (
            StoredSession("", "dummy-token"),
            StoredSession("dummy-user", ""),
            StoredSession("u" * 321, "dummy-token"),
            StoredSession("dummy-user", "t" * (128 * 1024 + 1)),
            StoredSession("dummy\nuser", "dummy-token"),
            StoredSession("dummy-user", "token\x7f"),
            StoredSession(None, "dummy-token"),
            StoredSession("dummy-user", None),
        )
        for session in invalid:
            with self.subTest(session=session):
                with self.assertRaises(VaultError):
                    session.validated()


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

    def _write_clear_payload(self, payload) -> bytes:
        clear = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        stored = vault_module._MAGIC + _test_protect(clear)
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.vault.path, "wb") as file_obj:
            file_obj.write(stored)
        return stored

    def _read_clear_payload(self) -> dict:
        with open(self.vault.path, "rb") as file_obj:
            stored = file_obj.read()
        clear = _test_unprotect(stored[len(vault_module._MAGIC) :])
        decoded = json.loads(clear.decode("utf-8"))
        self.assertIsInstance(decoded, dict)
        return decoded

    def test_schema2_round_trip_and_clear_json_never_contain_password(self):
        clear_inputs: list[bytes] = []

        def capture_protect(clear: bytes) -> bytes:
            clear_inputs.append(clear)
            return _test_protect(clear)

        protect = mock.Mock(side_effect=capture_protect)
        unprotect = mock.Mock(wraps=_test_unprotect)
        vault = CredentialVault(
            self.data_dir,
            protect=protect,
            unprotect=unprotect,
        )
        values = StoredSession(username="unit-user", access_token="unit-token")

        self.assertFalse(vault.exists())
        self.assertIsNone(vault.load())
        vault.save(values)
        self.assertTrue(vault.exists())
        self.assertEqual(len(clear_inputs), 1)
        decoded = json.loads(clear_inputs[0].decode("utf-8"))
        self.assertEqual(
            decoded,
            {
                "schema_version": 2,
                "username": "unit-user",
                "access_token": "unit-token",
            },
        )
        self.assertNotIn("password", decoded)
        self.assertNotIn(b"password", clear_inputs[0])

        with open(vault.path, "rb") as file_obj:
            stored = file_obj.read()
        self.assertTrue(stored.startswith(vault_module._MAGIC + _TEST_PREFIX))
        self.assertNotIn(b"unit-user", stored)
        self.assertNotIn(b"unit-token", stored)
        self.assertEqual(vault.load(), values)
        self.assertEqual(protect.call_count, 1)
        self.assertEqual(unprotect.call_count, 1)

        vault.clear()
        self.assertFalse(vault.exists())
        self.assertIsNone(vault.load())

    def test_save_rejects_ephemeral_login_credentials(self):
        with self.assertRaises(VaultError):
            self.vault.save(Credentials("unit-user", "unit-password"))
        self.assertFalse(self.vault.exists())

    def test_snapshot_restore_existing_is_exact_opaque_and_uses_no_crypto(self):
        original = StoredSession("snapshot-user", "snapshot-token")
        self.vault.save(original)
        with open(self.vault.path, "rb") as file_obj:
            original_bytes = file_obj.read()

        protect = mock.Mock(side_effect=AssertionError("snapshot must not protect"))
        unprotect = mock.Mock(side_effect=AssertionError("snapshot must not decrypt"))
        opaque_vault = CredentialVault(
            self.data_dir,
            protect=protect,
            unprotect=unprotect,
        )
        snapshot = opaque_vault.snapshot()

        self.assertIsInstance(snapshot, VaultSnapshot)
        self.assertTrue(snapshot.existed)
        self.assertEqual(snapshot._protected_payload, original_bytes)
        self.assertNotIn("snapshot-user", repr(snapshot))
        self.assertNotIn("snapshot-token", repr(snapshot))
        self.assertFalse(hasattr(snapshot, "username"))
        self.assertFalse(hasattr(snapshot, "password"))
        self.assertFalse(hasattr(snapshot, "access_token"))

        self.vault.save(StoredSession("replacement-user", "replacement-token"))
        opaque_vault.restore(snapshot)

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original_bytes)
        self.assertEqual(self.vault.load(), original)
        protect.assert_not_called()
        unprotect.assert_not_called()

    def test_snapshot_restore_absence_clears_without_using_crypto(self):
        protect = mock.Mock(side_effect=AssertionError("snapshot must not protect"))
        unprotect = mock.Mock(side_effect=AssertionError("snapshot must not decrypt"))
        opaque_vault = CredentialVault(
            self.data_dir,
            protect=protect,
            unprotect=unprotect,
        )
        snapshot = opaque_vault.snapshot()
        self.assertFalse(snapshot.existed)
        self.assertIsNone(snapshot._protected_payload)

        self.vault.save(StoredSession("temporary-user", "temporary-token"))
        opaque_vault.restore(snapshot)

        self.assertFalse(self.vault.exists())
        protect.assert_not_called()
        unprotect.assert_not_called()

    def test_snapshot_restores_bounded_corrupt_bytes_and_rejects_unsafe_values(self):
        bounded_payloads = (
            b"",
            b"not-a-protected-vault",
            vault_module._MAGIC,
        )
        os.makedirs(self.data_dir, exist_ok=True)
        for payload in bounded_payloads:
            with self.subTest(payload=payload):
                with open(self.vault.path, "wb") as file_obj:
                    file_obj.write(payload)
                snapshot = self.vault.snapshot()
                self.vault.save(StoredSession("replacement-user", "replacement-token"))
                self.vault.restore(snapshot)
                with open(self.vault.path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), payload)

        invalid_payloads = (
            vault_module._MAGIC
            + b"x" * (vault_module._MAX_FILE_BYTES - len(vault_module._MAGIC) + 1),
            bytearray(vault_module._MAGIC + b"x"),
        )
        for payload in invalid_payloads:
            with self.subTest(payload_type=type(payload), length=len(payload)):
                with self.assertRaises(VaultError):
                    VaultSnapshot(payload)
        with self.assertRaises(VaultError):
            self.vault.restore(object())

        oversized = vault_module._MAGIC + b"x" * (
            vault_module._MAX_FILE_BYTES - len(vault_module._MAGIC) + 1
        )
        with open(self.vault.path, "wb") as file_obj:
            file_obj.write(oversized)
        with self.assertRaises(VaultError):
            self.vault.snapshot()

    def test_schema1_empty_token_is_removed_instead_of_retaining_password(self):
        self._write_clear_payload(
            {
                "schema_version": 1,
                "username": "legacy-user",
                "password": "legacy-password",
                "access_token": "",
            }
        )

        self.assertIsNone(self.vault.load())
        self.assertFalse(self.vault.exists())

    def test_snapshot_restore_replace_failure_preserves_current_file(self):
        self.vault.save(StoredSession("rollback-user", "rollback-token"))
        snapshot = self.vault.snapshot()
        self.vault.save(StoredSession("current-user", "current-token"))
        with open(self.vault.path, "rb") as file_obj:
            current_bytes = file_obj.read()

        with mock.patch.object(
            vault_module.os,
            "replace",
            side_effect=OSError("simulated restore failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.restore(snapshot)

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), current_bytes)
        self.assertEqual(self.vault.load(), StoredSession("current-user", "current-token"))
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_snapshot_restore_absence_clear_failure_preserves_current_file(self):
        snapshot = self.vault.snapshot()
        current = StoredSession("current-user", "current-token")
        self.vault.save(current)
        with open(self.vault.path, "rb") as file_obj:
            current_bytes = file_obj.read()

        with mock.patch.object(
            vault_module.os,
            "remove",
            side_effect=PermissionError("simulated rollback clear failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.restore(snapshot)

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), current_bytes)
        self.assertEqual(self.vault.load(), current)

    def test_schema1_load_migrates_atomically_to_password_free_schema2(self):
        legacy = {
            "schema_version": 1,
            "username": "legacy-user",
            "password": "legacy-password",
            "access_token": "legacy-token",
        }
        before = self._write_clear_payload(legacy)

        result = self.vault.load()

        self.assertEqual(result, StoredSession("legacy-user", "legacy-token"))
        with open(self.vault.path, "rb") as file_obj:
            after = file_obj.read()
        self.assertNotEqual(after, before)
        decoded = self._read_clear_payload()
        self.assertEqual(
            decoded,
            {
                "schema_version": 2,
                "username": "legacy-user",
                "access_token": "legacy-token",
            },
        )
        self.assertNotIn("password", decoded)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_schema1_migration_protect_failure_preserves_original_file(self):
        before = self._write_clear_payload(
            {
                "schema_version": 1,
                "username": "legacy-user",
                "password": "legacy-password",
                "access_token": "legacy-token",
            }
        )
        failing = CredentialVault(
            self.data_dir,
            protect=mock.Mock(side_effect=VaultError("test protection failed")),
            unprotect=_test_unprotect,
        )

        with self.assertRaises(VaultError):
            failing.load()

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_schema1_migration_replace_failure_preserves_original_file(self):
        before = self._write_clear_payload(
            {
                "schema_version": 1,
                "username": "legacy-user",
                "password": "legacy-password",
                "access_token": "legacy-token",
            }
        )

        with mock.patch.object(
            vault_module.os,
            "replace",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.load()

        with open(self.vault.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.endswith(".tmp")],
            [],
        )

    def test_save_replaces_an_existing_schema2_payload_atomically(self):
        first = StoredSession("first-user", "first-token")
        second = StoredSession("second-user", "second-token")
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

    def test_atomic_replace_failure_preserves_previous_schema2_file(self):
        original = StoredSession("original-user", "original-token")
        self.vault.save(original)
        with open(self.vault.path, "rb") as file_obj:
            before = file_obj.read()

        with mock.patch.object(
            vault_module.os,
            "replace",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(VaultError):
                self.vault.save(StoredSession("new-user", "new-token"))

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
            failing.save(StoredSession("unit-user", "unit-token"))
        self.assertFalse(failing.exists())

        oversized = CredentialVault(
            self.data_dir,
            protect=lambda _clear: b"x" * (vault_module._MAX_FILE_BYTES + 1),
            unprotect=_test_unprotect,
        )
        with self.assertRaises(VaultError):
            oversized.save(StoredSession("unit-user", "unit-token"))
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

    def test_rejects_malformed_schema2_payloads(self):
        valid = {
            "schema_version": 2,
            "username": "unit-user",
            "access_token": "unit-token",
        }
        invalid_payloads = (
            [],
            {**valid, "unexpected": True},
            {key: value for key, value in valid.items() if key != "access_token"},
            {**valid, "schema_version": True},
            {**valid, "schema_version": 3},
            {**valid, "username": "unit\nuser"},
            {**valid, "username": None},
            {**valid, "access_token": ""},
            {**valid, "access_token": "token\x7f"},
            {**valid, "access_token": None},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                self._write_clear_payload(payload)
                with self.assertRaises(VaultError):
                    self.vault.load()

    def test_rejects_malformed_schema1_payloads_without_rewriting_them(self):
        valid = {
            "schema_version": 1,
            "username": "legacy-user",
            "password": "legacy-password",
            "access_token": "legacy-token",
        }
        invalid_payloads = (
            {**valid, "unexpected": True},
            {key: value for key, value in valid.items() if key != "password"},
            {**valid, "schema_version": True},
            {**valid, "username": "legacy\nuser"},
            {**valid, "password": ""},
            {**valid, "password": None},
            {**valid, "access_token": None},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                before = self._write_clear_payload(payload)
                with self.assertRaises(VaultError):
                    self.vault.load()
                with open(self.vault.path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), before)

    def test_rejects_invalid_utf8_and_invalid_json_after_unprotect(self):
        os.makedirs(self.data_dir, exist_ok=True)
        for clear in (b"\xff", b"not-json"):
            with self.subTest(clear=clear):
                with open(self.vault.path, "wb") as file_obj:
                    file_obj.write(vault_module._MAGIC + _test_protect(clear))
                with self.assertRaises(VaultError):
                    self.vault.load()

    def test_pathological_json_and_nonbyte_unprotect_output_are_sanitized(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.vault.path, "wb") as file_obj:
            file_obj.write(vault_module._MAGIC + b"opaque")

        clear_payloads = (
            b'{"schema_version":' + b"9" * 5000 + b"}",
            (b"[" * 2000) + b"0" + (b"]" * 2000),
            "not-bytes",
            b"x" * (vault_module._MAX_FILE_BYTES + 1),
        )
        for clear in clear_payloads:
            with self.subTest(output_type=type(clear), length=len(clear)):
                vault = CredentialVault(
                    self.data_dir,
                    protect=_test_protect,
                    unprotect=mock.Mock(return_value=clear),
                )
                with self.assertRaises(VaultError):
                    vault.load()

    def test_unprotect_failure_is_sanitized_as_vault_error(self):
        self.vault.save(StoredSession("unit-user", "unit-token"))
        failing = CredentialVault(
            self.data_dir,
            protect=_test_protect,
            unprotect=mock.Mock(side_effect=VaultError("test unprotect failure")),
        )
        with self.assertRaises(VaultError):
            failing.load()

    def test_clear_wraps_filesystem_failure(self):
        self.vault.save(StoredSession("unit-user", "unit-token"))
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
