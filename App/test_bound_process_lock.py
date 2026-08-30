# -*- coding: utf-8 -*-
"""Real-filesystem tests for handle-bound short transaction locks."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import bound_process_lock as lock_module
from bound_process_lock import (
    BoundProcessLock,
    BoundProcessLockBusy,
    BoundProcessLockError,
)
import credential_persistence as credential_module
import settings_store as settings_module
import task_store as task_module


class BoundProcessLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.data_dir = os.path.join(self._temporary.name, "Data")

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _make_symlink(
        self,
        target: str,
        link: str,
        *,
        directory: bool = False,
    ) -> None:
        try:
            os.symlink(target, link, target_is_directory=directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"filesystem symlinks are unavailable: {type(exc).__name__}")

    def test_acquire_blocks_same_name_then_releases(self):
        first = BoundProcessLock(self.data_dir, ".unit.lock")
        second = BoundProcessLock(self.data_dir, ".unit.lock")

        with first:
            self.assertTrue(os.path.isfile(first.path))
            with self.assertRaisesRegex(
                BoundProcessLockBusy,
                "^process lock is unavailable$",
            ):
                second.__enter__()

        with second:
            pass

    def test_different_names_do_not_share_one_lock_domain(self):
        with BoundProcessLock(self.data_dir, ".first.lock"):
            with BoundProcessLock(self.data_dir, ".second.lock"):
                pass

    def test_three_store_adapters_keep_distinct_nested_lock_domains(self):
        with settings_module._SettingsProcessLock(self.data_dir):
            with task_module._TaskStoreProcessLock(self.data_dir):
                with credential_module._CredentialProcessLock(self.data_dir):
                    pass

    def test_independent_process_is_blocked_then_can_acquire_after_release(self):
        child_code = (
            "import sys; from bound_process_lock import BoundProcessLock,"
            " BoundProcessLockBusy, BoundProcessLockError; "
            "lock=BoundProcessLock(sys.argv[1],sys.argv[2]); "
            "\ntry:\n lock.__enter__()\n"
            "except BoundProcessLockBusy:\n raise SystemExit(23)\n"
            "except BoundProcessLockError:\n raise SystemExit(24)\n"
            "else:\n lock.__exit__(None,None,None); raise SystemExit(0)\n"
        )

        def run_child() -> subprocess.CompletedProcess[bytes]:
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            return subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child_code,
                    self.data_dir,
                    ".process.lock",
                ],
                cwd=os.path.dirname(__file__),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

        with BoundProcessLock(self.data_dir, ".process.lock"):
            blocked = run_child()
        released = run_child()

        self.assertEqual(blocked.returncode, 23, blocked.stderr.decode(errors="replace"))
        self.assertEqual(released.returncode, 0, released.stderr.decode(errors="replace"))

    def test_existing_lock_bytes_are_never_modified(self):
        os.makedirs(self.data_dir)
        path = os.path.join(self.data_dir, ".unit.lock")
        expected = b"legacy-lock-byte\x00"
        with open(path, "wb") as file_obj:
            file_obj.write(expected)

        with BoundProcessLock(self.data_dir, ".unit.lock"):
            pass

        with open(path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), expected)

    def test_bound_root_paths_and_token_are_valid_only_while_held(self):
        lock = BoundProcessLock(self.data_dir, ".unit.lock")
        with self.assertRaises(BoundProcessLockError):
            _ = lock.root_token
        with self.assertRaises(BoundProcessLockError):
            _ = lock.bound_root_paths

        with lock:
            first_token = lock.root_token
            second_token = lock.root_token
            io_path, display_path = lock.bound_root_paths
            self.assertEqual(first_token, second_token)
            self.assertTrue(os.path.samestat(os.stat(io_path), os.stat(display_path)))
            with open(os.path.join(io_path, "bound-write.bin"), "xb") as file_obj:
                file_obj.write(b"bound")
            with open(os.path.join(display_path, "bound-write.bin"), "rb") as file_obj:
                self.assertEqual(file_obj.read(), b"bound")

        with self.assertRaises(BoundProcessLockError):
            _ = lock.root_token
        with self.assertRaises(BoundProcessLockError):
            _ = lock.bound_root_paths

    def test_hardlinked_lock_is_rejected_without_touching_target(self):
        os.makedirs(self.data_dir)
        victim = os.path.join(self.data_dir, "victim.bin")
        lock_path = os.path.join(self.data_dir, ".unit.lock")
        expected = b"must remain unchanged"
        with open(victim, "wb") as file_obj:
            file_obj.write(expected)
        os.link(victim, lock_path)

        with self.assertRaises(BoundProcessLockError) as caught:
            BoundProcessLock(self.data_dir, ".unit.lock").__enter__()
        self.assertNotIsInstance(caught.exception, BoundProcessLockBusy)

        with open(victim, "rb") as file_obj:
            self.assertEqual(file_obj.read(), expected)

    def test_symlinked_lock_is_rejected_without_touching_target(self):
        os.makedirs(self.data_dir)
        victim = os.path.join(self.data_dir, "victim.bin")
        lock_path = os.path.join(self.data_dir, ".unit.lock")
        expected = b"must remain unchanged"
        with open(victim, "wb") as file_obj:
            file_obj.write(expected)
        self._make_symlink(victim, lock_path)

        with self.assertRaises(BoundProcessLockError) as caught:
            BoundProcessLock(self.data_dir, ".unit.lock").__enter__()
        self.assertNotIsInstance(caught.exception, BoundProcessLockBusy)

        with open(victim, "rb") as file_obj:
            self.assertEqual(file_obj.read(), expected)

    def test_directory_at_lock_name_is_rejected(self):
        os.makedirs(os.path.join(self.data_dir, ".unit.lock"))

        with self.assertRaises(BoundProcessLockError) as caught:
            BoundProcessLock(self.data_dir, ".unit.lock").__enter__()
        self.assertNotIsInstance(caught.exception, BoundProcessLockBusy)

    def test_symlinked_data_root_is_rejected(self):
        real_root = os.path.join(self._temporary.name, "real-data")
        linked_root = os.path.join(self._temporary.name, "linked-data")
        os.mkdir(real_root)
        self._make_symlink(real_root, linked_root, directory=True)

        with self.assertRaises(BoundProcessLockError):
            BoundProcessLock(linked_root, ".unit.lock").__enter__()

        self.assertFalse(os.path.lexists(os.path.join(real_root, ".unit.lock")))

    def test_reentrant_enter_is_rejected_and_original_lock_remains_held(self):
        lock = BoundProcessLock(self.data_dir, ".unit.lock")
        with lock:
            with self.assertRaises(BoundProcessLockError):
                lock.__enter__()
            with self.assertRaises(BoundProcessLockError):
                BoundProcessLock(self.data_dir, ".unit.lock").__enter__()

    def test_exit_validation_failure_is_reported_after_a_successful_body(self):
        validator = (
            "_win_validate_held" if os.name == "nt" else "_posix_validate_held"
        )
        with mock.patch.object(
            lock_module,
            validator,
            side_effect=BoundProcessLockError("process lock is unavailable"),
        ):
            with self.assertRaises(BoundProcessLockError):
                with BoundProcessLock(self.data_dir, ".unit.lock"):
                    pass

        with BoundProcessLock(self.data_dir, ".unit.lock"):
            pass

    def test_exit_validation_failure_does_not_hide_the_body_exception(self):
        validator = (
            "_win_validate_held" if os.name == "nt" else "_posix_validate_held"
        )
        with mock.patch.object(
            lock_module,
            validator,
            side_effect=BoundProcessLockError("process lock is unavailable"),
        ):
            with self.assertRaisesRegex(ValueError, "original body failure"):
                with BoundProcessLock(self.data_dir, ".unit.lock"):
                    raise ValueError("original body failure")

    def test_store_adapters_translate_exit_validation_failures(self):
        validator = (
            "_win_validate_held" if os.name == "nt" else "_posix_validate_held"
        )
        cases = (
            (
                settings_module._SettingsProcessLock,
                settings_module.SettingsConflictError,
            ),
            (
                task_module._TaskStoreProcessLock,
                task_module.TaskStoreConflictError,
            ),
            (
                credential_module._CredentialProcessLock,
                credential_module.CredentialPersistenceError,
            ),
        )
        for factory, expected_error in cases:
            with self.subTest(factory=factory.__name__):
                with mock.patch.object(
                    lock_module,
                    validator,
                    side_effect=BoundProcessLockError(
                        "process lock is unavailable"
                    ),
                ):
                    with self.assertRaises(expected_error):
                        with factory(self.data_dir):
                            pass

    def test_invalid_lock_names_fail_closed(self):
        for name in (
            "",
            ".",
            "..",
            "nested/lock",
            "nested\\lock",
            "C:lock",
            "\ud800",
            "x" * 32_767,
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    BoundProcessLockError,
                    "^process lock is unavailable$",
                ):
                    BoundProcessLock(self.data_dir, name)

    def test_operational_failure_is_fixed_and_suppresses_private_cause(self):
        private_detail = os.path.join(self.data_dir, "private-user-path")
        with mock.patch.object(
            lock_module.os,
            "makedirs",
            side_effect=OSError(private_detail),
        ):
            with self.assertRaises(BoundProcessLockError) as caught:
                BoundProcessLock(self.data_dir, ".unit.lock").__enter__()

        self.assertEqual(str(caught.exception), "process lock is unavailable")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertNotIn(private_detail, str(caught.exception))

    @unittest.skipIf(os.name == "nt", "POSIX-specific post-flock identity check")
    def test_posix_retarget_during_acquire_is_rejected(self):
        import fcntl

        os.makedirs(self.data_dir)
        lock_path = os.path.join(self.data_dir, ".unit.lock")
        real_flock = fcntl.flock

        def flock_then_retarget(descriptor, operation):
            real_flock(descriptor, operation)
            os.remove(lock_path)
            with open(lock_path, "wb"):
                pass

        with mock.patch.object(fcntl, "flock", side_effect=flock_then_retarget):
            with self.assertRaises(BoundProcessLockError):
                BoundProcessLock(self.data_dir, ".unit.lock").__enter__()

    @unittest.skipIf(os.name == "nt", "POSIX-specific exit identity check")
    def test_posix_retarget_while_held_is_not_reported_as_success(self):
        lock = BoundProcessLock(self.data_dir, ".unit.lock")

        with self.assertRaises(BoundProcessLockError):
            with lock:
                os.remove(lock.path)
                with open(lock.path, "wb"):
                    pass

    @unittest.skipIf(os.name == "nt", "POSIX-specific root identity check")
    def test_posix_data_root_retarget_while_held_is_not_reported_as_success(self):
        moved_root = os.path.join(self._temporary.name, "moved-data")

        try:
            with self.assertRaises(BoundProcessLockError):
                with BoundProcessLock(self.data_dir, ".unit.lock"):
                    os.rename(self.data_dir, moved_root)
                    os.mkdir(self.data_dir)
        finally:
            if os.path.isdir(self.data_dir):
                os.rmdir(self.data_dir)
            if os.path.isdir(moved_root):
                os.rename(moved_root, self.data_dir)

    @unittest.skipIf(os.name == "nt", "POSIX-specific nonblocking FIFO check")
    def test_posix_fifo_at_lock_name_is_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo is unavailable")
        os.makedirs(self.data_dir)
        os.mkfifo(os.path.join(self.data_dir, ".unit.lock"))

        with self.assertRaises(BoundProcessLockError):
            BoundProcessLock(self.data_dir, ".unit.lock").__enter__()

    @unittest.skipUnless(os.name == "nt", "Windows share-mode name binding")
    def test_windows_lock_name_and_data_root_cannot_be_retargeted_while_held(self):
        lock = BoundProcessLock(self.data_dir, ".unit.lock")
        moved_root = os.path.join(self._temporary.name, "moved-data")

        with lock:
            with self.assertRaises(OSError):
                os.remove(lock.path)
            with self.assertRaises(OSError):
                os.rename(self.data_dir, moved_root)

        os.rename(self.data_dir, moved_root)
        os.rename(moved_root, self.data_dir)

    @unittest.skipUnless(os.name == "nt", "Windows native-handle validation")
    def test_windows_hardlink_added_while_held_is_not_reported_as_success(self):
        lock = BoundProcessLock(self.data_dir, ".unit.lock")
        alias = os.path.join(self.data_dir, ".alias.lock")
        linked = False

        try:
            with lock:
                try:
                    os.link(lock.path, alias)
                except OSError:
                    pass
                else:
                    linked = True
                    with self.assertRaises(BoundProcessLockError):
                        BoundProcessLock(self.data_dir, ".alias.lock").__enter__()
        except BoundProcessLockError:
            self.assertTrue(linked)
        else:
            self.assertFalse(linked)

        if linked:
            os.remove(alias)

    @unittest.skipUnless(os.name == "nt", "Windows case-compatible lookup")
    def test_windows_lock_lookup_preserves_case_insensitive_compatibility(self):
        os.makedirs(self.data_dir)
        existing = os.path.join(self.data_dir, ".UNIT.LOCK")
        expected = b"legacy case variant"
        with open(existing, "wb") as file_obj:
            file_obj.write(expected)

        with BoundProcessLock(self.data_dir, ".unit.lock"):
            requested = os.path.join(self.data_dir, ".unit.lock")
            self.assertTrue(os.path.samefile(existing, requested))

        with open(existing, "rb") as file_obj:
            self.assertEqual(file_obj.read(), expected)

    @unittest.skipUnless(os.name == "nt", "Windows x64 ctypes ABI contract")
    def test_windows_native_structure_abi_is_validated(self):
        import bound_process_lock as lock_module

        lock_module._win_validate_abi()
        self.assertEqual(sys.maxsize, 2**63 - 1)


if __name__ == "__main__":
    unittest.main()
