# -*- coding: utf-8 -*-
"""Offline crash-boundary tests for credential persistence coordination."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import credential_persistence as persistence_module
from credential_persistence import (
    CredentialJournal,
    CredentialPersistence,
    CredentialPersistenceError,
    JournalEntry,
)
from credential_vault import CredentialVault, StoredSession, VaultReceipt
from settings_store import SettingsConflictError, SettingsError, SettingsStore


_PREFIX = b"test-protected:"


def _protect(clear: bytes) -> bytes:
    return _PREFIX + bytes(byte ^ 0x5A for byte in clear)


def _unprotect(protected: bytes) -> bytes:
    if not protected.startswith(_PREFIX):
        raise ValueError("invalid test ciphertext")
    return bytes(byte ^ 0x5A for byte in protected[len(_PREFIX) :])


class _NullLock:
    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return None


class CredentialPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.data_dir = self._temporary.name
        self.settings = SettingsStore(self.data_dir)
        self.vault = CredentialVault(
            self.data_dir,
            protect=_protect,
            unprotect=_unprotect,
        )
        self.journal = CredentialJournal(self.data_dir)
        self.persistence = self._make_persistence(
            self.settings, self.vault, journal=self.journal
        )

    def tearDown(self):
        self._temporary.cleanup()

    def _make_persistence(self, settings, vault, *, journal=None):
        return CredentialPersistence(
            self.data_dir,
            settings,
            vault,
            journal=journal or CredentialJournal(self.data_dir),
            lock_factory=_NullLock,
        )

    def _reload(self):
        settings = SettingsStore(self.data_dir)
        vault = CredentialVault(
            self.data_dir,
            protect=_protect,
            unprotect=_unprotect,
        )
        return settings, vault, self._make_persistence(settings, vault)

    def test_journal_strict_round_trip_and_contains_no_identity_or_secret(self):
        self.journal.begin_enable(False)
        self.assertEqual(
            self.journal.load(),
            JournalEntry("enable", "pending", previous_remember=False),
        )
        receipt = VaultReceipt("a" * 64)
        self.journal.mark_vault_written(False, receipt)
        self.assertEqual(
            self.journal.load(),
            JournalEntry(
                "enable",
                "vault_written",
                previous_remember=False,
                vault_receipt=receipt,
            ),
        )
        with open(self.journal.path, "rb") as file_obj:
            encoded = file_obj.read()
        for forbidden in (b"unit-user", b"unit-token", b"unit-password"):
            self.assertNotIn(forbidden, encoded)
        self.journal.clear()
        self.journal.begin_disable()
        self.assertEqual(self.journal.load(), JournalEntry("disable", "pending"))

    def test_journal_rejects_unknown_fields_wrong_types_and_oversize(self):
        os.makedirs(self.data_dir, exist_ok=True)
        invalid = (
            {
                "schema_version": True,
                "operation": "disable",
                "phase": "pending",
            },
            {
                "schema_version": 1,
                "operation": "disable",
                "phase": "pending",
                "token": "must-not-be-accepted",
            },
            {
                "schema_version": 1,
                "operation": "enable",
                "phase": "pending",
                "previous_remember": 1,
            },
            {
                "schema_version": 1,
                "operation": "enable",
                "phase": "vault_written",
                "previous_remember": False,
                "vault_receipt": "A" * 64,
            },
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with open(self.journal.path, "w", encoding="utf-8") as file_obj:
                    json.dump(payload, file_obj)
                with self.assertRaises(CredentialPersistenceError):
                    self.journal.load()
        with open(self.journal.path, "wb") as file_obj:
            file_obj.write(b"x" * (persistence_module._MAX_JOURNAL_BYTES + 1))
        with self.assertRaises(CredentialPersistenceError):
            self.journal.load()

    def test_pending_enable_always_fails_closed_without_loading_old_or_new_vault(self):
        old = StoredSession("old-user", "old-token")
        new = StoredSession("new-user", "new-token")
        self.persistence.enable(
            old, previous_remember=False, settings_write_allowed=True
        )
        for replace_vault in (False, True):
            with self.subTest(replace_vault=replace_vault):
                settings, real_vault, _unused = self._reload()
                journal = CredentialJournal(self.data_dir)
                journal.begin_enable(True)
                if replace_vault:
                    real_vault.save(new)
                spy_vault = mock.Mock(wraps=real_vault)
                persistence = self._make_persistence(settings, spy_vault)
                result = persistence.recover_and_load(settings_write_allowed=True)
                self.assertTrue(result.resolved)
                self.assertFalse(result.remember_credentials)
                self.assertIsNone(result.session)
                spy_vault.load.assert_not_called()
                spy_vault.load_matching.assert_not_called()
                self.assertFalse(real_vault.exists())
                self.assertFalse(settings.get("remember_credentials"))
                self.assertEqual(settings.get("credential_vault_receipt"), "")
                if replace_vault:
                    self.assertTrue(self.settings.load())
                    self.persistence.enable(
                        old, previous_remember=False, settings_write_allowed=True
                    )

    def test_vault_written_rolls_forward_only_the_matching_new_session(self):
        session = StoredSession("new-user", "new-token")
        self.journal.begin_enable(False)
        receipt = self.vault.save(session)
        self.journal.mark_vault_written(False, receipt)

        result = self.persistence.recover_and_load(settings_write_allowed=True)

        self.assertTrue(result.resolved)
        self.assertEqual(result.session, session)
        self.assertTrue(self.settings.get("remember_credentials"))
        self.assertEqual(
            self.settings.get("credential_vault_receipt"), receipt.sha256
        )
        self.assertFalse(self.journal.exists())

    def test_vault_written_mismatch_clears_vault_and_disables(self):
        first = StoredSession("first-user", "first-token")
        second = StoredSession("second-user", "second-token")
        self.journal.begin_enable(False)
        first_receipt = self.vault.save(first)
        self.journal.mark_vault_written(False, first_receipt)
        self.vault.save(second)

        result = self.persistence.recover_and_load(settings_write_allowed=True)

        self.assertTrue(result.resolved)
        self.assertFalse(result.remember_credentials)
        self.assertIsNone(result.session)
        self.assertFalse(self.vault.exists())
        self.assertFalse(self.settings.get("remember_credentials"))

    def test_settings_failure_after_new_vault_never_restores_old_session(self):
        old = StoredSession("old-user", "old-token")
        new = StoredSession("new-user", "new-token")
        self.persistence.enable(
            old, previous_remember=False, settings_write_allowed=True
        )
        with mock.patch.object(
            self.settings,
            "save",
            side_effect=SettingsError("simulated settings failure"),
        ):
            with self.assertRaises(SettingsError):
                self.persistence.enable(
                    new, previous_remember=True, settings_write_allowed=True
                )
        entry = self.journal.load()
        self.assertEqual(entry.phase, "vault_written")
        self.assertEqual(self.vault.load(), new)

        settings, vault, persistence = self._reload()
        recovered = persistence.recover_and_load(settings_write_allowed=True)
        self.assertEqual(recovered.session, new)
        self.assertNotEqual(recovered.session, old)
        self.assertEqual(vault.load(), new)
        self.assertTrue(settings.get("remember_credentials"))

    def test_enable_conflict_preserves_external_settings_and_recovers_new_vault(self):
        session = StoredSession("conflict-user", "conflict-token")
        external = SettingsStore(self.data_dir)
        external.set("page_size", 32)
        external.save()

        with self.assertRaises(SettingsConflictError):
            self.persistence.enable(
                session,
                previous_remember=False,
                settings_write_allowed=True,
            )

        entry = self.journal.load()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.operation, "enable")
        self.assertEqual(entry.phase, "vault_written")
        self.assertIsNotNone(entry.vault_receipt)
        self.assertEqual(self.vault.load_matching(entry.vault_receipt), session)
        self.assertTrue(self.persistence.prevents_automatic_load_except(session))

        on_disk = SettingsStore(self.data_dir)
        self.assertEqual(on_disk.get("page_size"), 32)
        self.assertFalse(on_disk.get("remember_credentials"))
        self.assertEqual(on_disk.get("credential_vault_receipt"), "")

        recovered_vault = CredentialVault(
            self.data_dir,
            protect=_protect,
            unprotect=_unprotect,
        )
        recovered_persistence = self._make_persistence(on_disk, recovered_vault)
        recovered = recovered_persistence.recover_and_load(
            settings_write_allowed=True
        )

        self.assertTrue(recovered.resolved)
        self.assertEqual(recovered.session, session)
        self.assertTrue(recovered.remember_credentials)
        self.assertEqual(on_disk.get("page_size"), 32)
        self.assertTrue(on_disk.get("remember_credentials"))
        self.assertEqual(
            on_disk.get("credential_vault_receipt"),
            entry.vault_receipt.sha256,
        )
        self.assertFalse(self.journal.exists())

    def test_disable_conflict_preserves_external_settings_and_recovers_disabled(self):
        session = StoredSession("conflict-user", "conflict-token")
        self.persistence.enable(
            session,
            previous_remember=False,
            settings_write_allowed=True,
        )
        original_receipt = self.settings.get("credential_vault_receipt")

        external = SettingsStore(self.data_dir)
        external.set("page_size", 32)
        external.save()

        with self.assertRaises(CredentialPersistenceError):
            self.persistence.disable(settings_write_allowed=True)

        self.assertFalse(self.vault.exists())
        self.assertEqual(self.journal.load(), JournalEntry("disable", "pending"))
        self.assertTrue(self.persistence.prevents_automatic_load_except(None))

        on_disk = SettingsStore(self.data_dir)
        self.assertEqual(on_disk.get("page_size"), 32)
        self.assertTrue(on_disk.get("remember_credentials"))
        self.assertEqual(
            on_disk.get("credential_vault_receipt"), original_receipt
        )

        recovered_vault = CredentialVault(
            self.data_dir,
            protect=_protect,
            unprotect=_unprotect,
        )
        recovered_persistence = self._make_persistence(on_disk, recovered_vault)
        recovered = recovered_persistence.recover_and_load(
            settings_write_allowed=True
        )

        self.assertTrue(recovered.resolved)
        self.assertFalse(recovered.remember_credentials)
        self.assertIsNone(recovered.session)
        self.assertEqual(on_disk.get("page_size"), 32)
        self.assertFalse(on_disk.get("remember_credentials"))
        self.assertEqual(on_disk.get("credential_vault_receipt"), "")
        self.assertFalse(self.journal.exists())

    def test_disable_failure_leaves_barrier_and_recovery_is_idempotent(self):
        session = StoredSession("unit-user", "unit-token")
        self.persistence.enable(
            session, previous_remember=False, settings_write_allowed=True
        )
        with mock.patch.object(
            self.settings,
            "save",
            side_effect=SettingsError("simulated settings failure"),
        ):
            with self.assertRaises(CredentialPersistenceError):
                self.persistence.disable(settings_write_allowed=True)
        self.assertFalse(self.vault.exists())
        self.assertEqual(self.journal.load(), JournalEntry("disable", "pending"))

        settings, vault, persistence = self._reload()
        first = persistence.recover_and_load(settings_write_allowed=True)
        second = persistence.recover_and_load(settings_write_allowed=True)
        self.assertTrue(first.resolved)
        self.assertTrue(second.resolved)
        self.assertFalse(first.remember_credentials)
        self.assertFalse(second.remember_credentials)
        self.assertFalse(vault.exists())
        self.assertFalse(settings.get("remember_credentials"))

    def test_corrupt_journal_fails_closed_without_echoing_raw_content(self):
        session = StoredSession("unit-user", "unit-token")
        receipt = self.vault.save(session)
        self.settings.set("remember_credentials", True)
        self.settings.set("credential_vault_receipt", receipt.sha256)
        self.settings.save()
        raw_secret = b"broken-unit-secret-do-not-echo"
        with open(self.journal.path, "wb") as file_obj:
            file_obj.write(raw_secret)

        result = self.persistence.recover_and_load(settings_write_allowed=True)

        self.assertTrue(result.resolved)
        self.assertFalse(result.remember_credentials)
        self.assertNotIn(raw_secret.decode("ascii"), result.message)
        self.assertFalse(self.vault.exists())
        self.assertFalse(self.journal.exists())

    def test_unwritable_recovery_keeps_marker_as_a_load_barrier(self):
        session = StoredSession("unit-user", "unit-token")
        self.journal.begin_enable(False)
        receipt = self.vault.save(session)
        self.journal.mark_vault_written(False, receipt)

        result = self.persistence.recover_and_load(settings_write_allowed=False)

        self.assertFalse(result.resolved)
        self.assertIsNone(result.session)
        self.assertTrue(self.journal.exists())
        self.assertFalse(self.settings.get("remember_credentials"))

    def test_unwritable_new_enable_supersedes_every_older_marker_with_new_session(self):
        old = StoredSession("old-user", "old-token")
        new = StoredSession("new-user", "new-token")
        for marker_mode in ("pending", "vault_written", "corrupt"):
            with self.subTest(marker_mode=marker_mode), tempfile.TemporaryDirectory() as data_dir:
                settings = SettingsStore(data_dir)
                vault = CredentialVault(
                    data_dir, protect=_protect, unprotect=_unprotect
                )
                journal = CredentialJournal(data_dir)
                if marker_mode == "pending":
                    journal.begin_enable(False)
                    vault.save(old)
                elif marker_mode == "vault_written":
                    journal.begin_enable(False)
                    receipt = vault.save(old)
                    journal.mark_vault_written(False, receipt)
                else:
                    with open(journal.path, "wb") as file_obj:
                        file_obj.write(b"corrupt-old-marker")
                    vault.save(old)
                persistence = CredentialPersistence(
                    data_dir,
                    settings,
                    vault,
                    journal=journal,
                    lock_factory=_NullLock,
                )

                with self.assertRaises(SettingsError):
                    persistence.enable(
                        new,
                        previous_remember=False,
                        settings_write_allowed=False,
                    )

                entry = journal.load()
                self.assertEqual(entry.phase, "vault_written")
                self.assertEqual(vault.load_matching(entry.vault_receipt), new)
                reloaded = SettingsStore(data_dir)
                recovered = CredentialPersistence(
                    data_dir,
                    reloaded,
                    vault,
                    journal=journal,
                    lock_factory=_NullLock,
                ).recover_and_load(settings_write_allowed=True)
                self.assertEqual(recovered.session, new)
                self.assertNotEqual(recovered.session, old)

    def test_disable_marker_failure_still_fails_closed_best_effort(self):
        session = StoredSession("unit-user", "unit-token")
        self.persistence.enable(
            session, previous_remember=False, settings_write_allowed=True
        )
        with mock.patch.object(
            self.journal,
            "supersede_with_disable",
            side_effect=CredentialPersistenceError("simulated marker failure"),
        ):
            with self.assertRaises(CredentialPersistenceError):
                self.persistence.disable(settings_write_allowed=True)
        self.assertFalse(self.vault.exists())
        self.assertFalse(self.settings.get("remember_credentials"))
        self.assertEqual(self.settings.get("credential_vault_receipt"), "")

    def test_journal_clear_failure_is_recovered_without_changing_session(self):
        session = StoredSession("unit-user", "unit-token")
        with mock.patch.object(
            self.journal,
            "clear",
            side_effect=CredentialPersistenceError("simulated clear failure"),
        ):
            with self.assertRaises(CredentialPersistenceError):
                self.persistence.enable(
                    session,
                    previous_remember=False,
                    settings_write_allowed=True,
                )
        self.assertTrue(self.journal.exists())
        settings, vault, persistence = self._reload()
        recovered = persistence.recover_and_load(settings_write_allowed=True)
        self.assertEqual(recovered.session, session)
        self.assertEqual(vault.load(), session)

    def test_stable_state_requires_matching_receipt_and_legacy_state_is_cleared(self):
        session = StoredSession("unit-user", "unit-token")
        self.persistence.enable(
            session, previous_remember=False, settings_write_allowed=True
        )
        settings, vault, persistence = self._reload()
        loaded = persistence.recover_and_load(settings_write_allowed=True)
        self.assertEqual(loaded.session, session)

        settings.set("credential_vault_receipt", "")
        settings.save()
        settings, vault, persistence = self._reload()
        legacy = persistence.recover_and_load(settings_write_allowed=True)
        self.assertTrue(legacy.resolved)
        self.assertFalse(legacy.remember_credentials)
        self.assertIsNone(legacy.session)
        self.assertFalse(vault.exists())
        self.assertFalse(settings.get("remember_credentials"))

    def test_enable_rejects_absent_unverified_session_without_arming_orphan(self):
        orphan = StoredSession("orphan-user", "orphan-token")
        self.vault.save(orphan)
        with self.assertRaises(CredentialPersistenceError):
            self.persistence.enable(
                None,
                previous_remember=False,
                settings_write_allowed=True,
            )
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.settings.get("remember_credentials"))

    def test_process_lock_blocks_a_second_writer_and_releases_cleanly(self):
        first = persistence_module._CredentialProcessLock(self.data_dir)
        second = persistence_module._CredentialProcessLock(self.data_dir)
        with first:
            with self.assertRaises(CredentialPersistenceError):
                with second:
                    self.fail("second credential writer unexpectedly acquired the lock")
        with persistence_module._CredentialProcessLock(self.data_dir):
            pass

    def test_hardlinked_process_lock_is_rejected_without_modifying_target(self):
        lock_path = os.path.join(self.data_dir, ".credential-transaction.lock")
        if os.path.lexists(lock_path):
            os.remove(lock_path)
        victim_path = os.path.join(
            self.data_dir, "empty-credential-lock-victim.bin"
        )
        with open(victim_path, "wb"):
            pass
        os.link(victim_path, lock_path)

        with self.assertRaises(CredentialPersistenceError):
            with persistence_module._CredentialProcessLock(self.data_dir):
                self.fail("hardlinked credential lock was accepted")

        with open(victim_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"")

    def test_process_lock_close_failure_preserves_the_body_exception(self):
        real_close = os.close

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError("simulated close failure")

        with mock.patch.object(
            persistence_module.os,
            "close",
            side_effect=close_then_fail,
        ):
            with self.assertRaisesRegex(SettingsError, "body failure"):
                with persistence_module._CredentialProcessLock(self.data_dir):
                    raise SettingsError("body failure")

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
            persistence_module.os,
            "close",
            side_effect=close_then_fail,
        ):
            with self.assertRaises(CredentialPersistenceError):
                persistence_module._CredentialProcessLock(
                    self.data_dir
                ).__enter__()

    def test_process_lock_close_failure_does_not_false_fail_committed_changes(self):
        real_close = os.close

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError("simulated close failure")

        session = StoredSession("close-user", "close-token")
        with mock.patch.object(
            persistence_module.os,
            "close",
            side_effect=close_then_fail,
        ):
            self.persistence.enable(
                session,
                previous_remember=False,
                settings_write_allowed=True,
            )

        reloaded_settings = SettingsStore(self.data_dir)
        receipt = VaultReceipt(
            reloaded_settings.get("credential_vault_receipt")
        ).validated()
        self.assertTrue(reloaded_settings.get("remember_credentials"))
        self.assertEqual(self.vault.load_matching(receipt), session)
        self.assertFalse(self.journal.exists())

        with mock.patch.object(
            persistence_module.os,
            "close",
            side_effect=close_then_fail,
        ):
            self.persistence.disable(settings_write_allowed=True)

        disabled_settings = SettingsStore(self.data_dir)
        self.assertFalse(disabled_settings.get("remember_credentials"))
        self.assertEqual(disabled_settings.get("credential_vault_receipt"), "")
        self.assertFalse(self.vault.exists())
        self.assertFalse(self.journal.exists())

    def test_barrier_confirmation_matrix_never_trusts_an_old_bound_session(self):
        old = StoredSession("old-user", "old-token")
        new = StoredSession("new-user", "new-token")
        self.assertFalse(self.persistence.prevents_automatic_load_except(None))

        self.journal.begin_disable()
        self.assertTrue(self.persistence.prevents_automatic_load_except(None))
        self.assertTrue(self.persistence.prevents_automatic_load_except(new))
        self.journal.clear()

        self.journal.begin_enable(False)
        self.assertTrue(self.persistence.prevents_automatic_load_except(None))
        self.assertTrue(self.persistence.prevents_automatic_load_except(new))
        self.journal.clear()

        self.journal.begin_enable(False)
        receipt = self.vault.save(new)
        self.journal.mark_vault_written(False, receipt)
        self.assertTrue(self.persistence.prevents_automatic_load_except(new))
        self.assertFalse(self.persistence.prevents_automatic_load_except(old))
        self.assertFalse(self.persistence.prevents_automatic_load_except(None))

        self.vault.save(old)
        self.assertTrue(self.persistence.prevents_automatic_load_except(None))
        self.assertTrue(self.persistence.prevents_automatic_load_except(new))
        with open(self.journal.path, "wb") as file_obj:
            file_obj.write(b"corrupt-marker")
        self.assertTrue(self.persistence.prevents_automatic_load_except(None))
        self.assertTrue(self.persistence.prevents_automatic_load_except(new))

    def test_real_process_exit_at_each_durable_boundary_recovers_deterministically(self):
        app_dir = os.path.dirname(__file__)
        child = r'''
import os
import sys
sys.path.insert(0, sys.argv[1])
from credential_persistence import CredentialJournal
from credential_vault import CredentialVault, StoredSession
from settings_store import SettingsStore

prefix = b"crash-test-protected:"
def protect(clear):
    return prefix + bytes(byte ^ 0x33 for byte in clear)
def unprotect(protected):
    if not protected.startswith(prefix):
        raise ValueError("invalid test ciphertext")
    return bytes(byte ^ 0x33 for byte in protected[len(prefix):])

data_dir = sys.argv[2]
phase = sys.argv[3]
settings = SettingsStore(data_dir)
vault = CredentialVault(data_dir, protect=protect, unprotect=unprotect)
journal = CredentialJournal(data_dir)
if phase.startswith("enable_"):
    journal.begin_enable(bool(settings.get("remember_credentials")))
    if phase == "enable_pending":
        os._exit(23)
    receipt = vault.save(StoredSession("crash-new", "crash-token"))
    if phase == "enable_vault":
        os._exit(23)
    journal.mark_vault_written(True, receipt)
    if phase == "enable_marked":
        os._exit(23)
    settings.set("remember_credentials", True)
    settings.set("credential_vault_receipt", receipt.sha256)
    settings.save()
    os._exit(23)
journal.supersede_with_disable()
if phase == "disable_pending":
    os._exit(23)
vault.clear()
if phase == "disable_vault":
    os._exit(23)
settings.set("remember_credentials", False)
settings.set("credential_vault_receipt", "")
settings.save()
os._exit(23)
'''
        phases = (
            "enable_pending",
            "enable_vault",
            "enable_marked",
            "enable_settings",
            "disable_pending",
            "disable_vault",
            "disable_settings",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as data_dir:
                settings = SettingsStore(data_dir)
                vault = CredentialVault(
                    data_dir,
                    protect=lambda clear: b"crash-test-protected:"
                    + bytes(byte ^ 0x33 for byte in clear),
                    unprotect=lambda protected: bytes(
                        byte ^ 0x33
                        for byte in protected[len(b"crash-test-protected:") :]
                    ),
                )
                journal = CredentialJournal(data_dir)
                persistence = CredentialPersistence(
                    data_dir,
                    settings,
                    vault,
                    journal=journal,
                    lock_factory=_NullLock,
                )
                persistence.enable(
                    StoredSession("crash-old", "old-token"),
                    previous_remember=False,
                    settings_write_allowed=True,
                )

                completed = subprocess.run(
                    [sys.executable, "-B", "-c", child, app_dir, data_dir, phase],
                    check=False,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(completed.returncode, 23)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr, b"")

                reloaded_settings = SettingsStore(data_dir)
                reloaded_vault = CredentialVault(
                    data_dir,
                    protect=lambda clear: b"crash-test-protected:"
                    + bytes(byte ^ 0x33 for byte in clear),
                    unprotect=lambda protected: bytes(
                        byte ^ 0x33
                        for byte in protected[len(b"crash-test-protected:") :]
                    ),
                )
                recovered = CredentialPersistence(
                    data_dir,
                    reloaded_settings,
                    reloaded_vault,
                    journal=CredentialJournal(data_dir),
                    lock_factory=_NullLock,
                ).recover_and_load(settings_write_allowed=True)
                if phase in {"enable_marked", "enable_settings"}:
                    self.assertEqual(
                        recovered.session,
                        StoredSession("crash-new", "crash-token"),
                    )
                else:
                    self.assertIsNone(recovered.session)
                    self.assertFalse(recovered.remember_credentials)


if __name__ == "__main__":
    unittest.main()
