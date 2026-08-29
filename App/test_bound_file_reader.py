# -*- coding: utf-8 -*-
"""Offline tests for handle-bound, integrity-bound local-file reads."""

from __future__ import annotations

import ctypes
from dataclasses import replace
import errno
import hashlib
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import bound_file_reader
from bound_file_reader import (
    BoundFileCancelled,
    BoundFileError,
    BoundFileMissing,
    BoundFileUnreadable,
    MAX_BOUND_FILE_BYTES,
    MAX_BOUND_STREAM_BYTES,
    get_bound_root_identity,
    open_bound_root,
    read_verified_child,
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class BoundFileReaderTests(unittest.TestCase):
    def test_public_read_limit_matches_offline_preview_budget(self):
        self.assertEqual(MAX_BOUND_FILE_BYTES, 20 * 1024 * 1024)

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name
        self.root = os.path.join(self.base, "root 中文")
        os.makedirs(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, name: str, payload: bytes, *, root: str | None = None) -> str:
        path = os.path.join(root or self.root, name)
        with open(path, "wb") as file_obj:
            file_obj.write(payload)
        return path

    def _read(
        self,
        name: str,
        payload: bytes,
        *,
        identity=None,
        event: threading.Event | None = None,
    ) -> bytes:
        return read_verified_child(
            self.root,
            identity or get_bound_root_identity(self.root),
            name,
            len(payload),
            _sha256(payload),
            event,
            MAX_BOUND_FILE_BYTES,
        )

    def _assert_root_can_be_renamed(self) -> None:
        moved = os.path.join(self.base, "renamed root")
        os.rename(self.root, moved)
        os.rename(moved, self.root)

    def test_normal_read_is_exact_and_leaves_no_open_handle(self):
        payload = (b"verified-local-payload-" * 20_000) + b"end"
        self._write("Post_1.bin", payload)

        self.assertEqual(self._read("Post_1.bin", payload), payload)
        self._assert_root_can_be_renamed()

    def test_session_exposes_identity_names_safe_size_and_small_read(self):
        payload = b"session-bound-sidecar"
        self._write("Post_session.json", payload)
        self._write("ignored.tmp", b"ignored")

        with open_bound_root(self.root) as session:
            self.assertEqual(session.identity, get_bound_root_identity(self.root))
            self.assertEqual(
                set(session.list_names()),
                {"Post_session.json", "ignored.tmp"},
            )
            self.assertEqual(session.stat_child("Post_session.json"), len(payload))
            self.assertEqual(session.read_small_file("Post_session.json"), payload)
            self.assertFalse(session.closed)

        self.assertTrue(session.closed)
        session.close()
        with self.assertRaisesRegex(BoundFileError, "根目录不可用"):
            session.list_names()
        self._assert_root_can_be_renamed()

    def test_session_missing_child_is_distinct_fixed_and_redacted(self):
        secret_name = "missing-private-sidecar.json"
        with open_bound_root(self.root) as session:
            for operation in (
                lambda: session.stat_child(secret_name),
                lambda: session.read_small_file(secret_name),
                lambda: session.inspect_child(secret_name),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(BoundFileMissing) as caught:
                        operation()
                    self.assertEqual(str(caught.exception), "本地文件不存在")
                    self.assertNotIn(secret_name, str(caught.exception))

    def test_posix_open_error_classifies_only_known_operational_failures(self):
        secret = os.path.join(self.base, "private-native-detail")
        for code in (errno.EACCES, errno.EPERM, errno.EBUSY, errno.EIO):
            with self.subTest(code=code):
                translated = bound_file_reader._posix_child_open_error(
                    OSError(code, secret)
                )
                self.assertIsInstance(translated, BoundFileUnreadable)
                self.assertEqual(str(translated), "本地文件不可读")
                self.assertNotIn(secret, str(translated))

        for code in (errno.ELOOP, errno.EISDIR, errno.ENOTDIR, 123_456):
            with self.subTest(code=code):
                translated = bound_file_reader._posix_child_open_error(
                    OSError(code, secret)
                )
                self.assertIs(type(translated), BoundFileError)
                self.assertEqual(str(translated), "本地文件无法安全读取")
                self.assertNotIn(secret, str(translated))

        contradictory = bound_file_reader._posix_child_open_error(
            PermissionError(errno.ELOOP, secret)
        )
        self.assertIs(type(contradictory), BoundFileError)
        self.assertEqual(str(contradictory), "本地文件无法安全读取")

    def test_opened_file_io_failures_are_unreadable_and_release_descriptors(self):
        payload = b"operational-io-failure"
        name = "Post_unreadable.bin"
        self._write(name, payload)
        secret = os.path.join(self.base, "private-read-detail")

        with open_bound_root(self.root) as session:
            with mock.patch(
                "bound_file_reader.os.fstat",
                side_effect=OSError(errno.EIO, secret),
            ):
                with self.assertRaises(BoundFileUnreadable) as caught:
                    session.stat_child(name)
            self.assertEqual(str(caught.exception), "本地文件不可读")
            self.assertNotIn(secret, str(caught.exception))
            self.assertIn(name, session.list_names())

        identity = get_bound_root_identity(self.root)
        with mock.patch(
            "bound_file_reader.os.read",
            side_effect=OSError(errno.EIO, secret),
        ):
            with self.assertRaises(BoundFileUnreadable) as caught:
                self._read(name, payload, identity=identity)
        self.assertEqual(str(caught.exception), "本地文件不可读")
        self.assertNotIn(secret, str(caught.exception))
        self._assert_root_can_be_renamed()

    def test_stream_inspection_hashes_large_file_without_payload_aggregation(self):
        size = MAX_BOUND_FILE_BYTES + 1_048_613
        name = "Post_large.bin"
        path = os.path.join(self.root, name)
        with open(path, "wb") as file_obj:
            file_obj.truncate(size)

        expected_sha256 = hashlib.sha256()
        expected_md5 = hashlib.md5(usedforsecurity=False)
        zero_chunk = b"\x00" * (256 * 1024)
        remaining = size
        while remaining:
            chunk = zero_chunk[: min(len(zero_chunk), remaining)]
            expected_sha256.update(chunk)
            expected_md5.update(chunk)
            remaining -= len(chunk)

        import tracemalloc

        with open_bound_root(self.root) as session:
            with mock.patch("bound_file_reader.os.read", wraps=os.read) as reads:
                tracemalloc.start()
                inspection = session.inspect_child(
                    name,
                    max_bytes=MAX_BOUND_STREAM_BYTES,
                    prefix_bytes=37,
                )
                _current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            self.assertGreater(reads.call_count, 2)
            self.assertLess(peak, 4 * 1024 * 1024)
            self.assertEqual(inspection.size, size)
            self.assertEqual(inspection.sha256, expected_sha256.hexdigest())
            self.assertEqual(inspection.md5, expected_md5.hexdigest())
            self.assertEqual(inspection.prefix, b"\x00" * 37)

            with mock.patch("bound_file_reader.os.read") as read_body:
                with self.assertRaisesRegex(BoundFileError, "超过安全大小上限"):
                    session.read_small_file(name)
            read_body.assert_not_called()

    def test_session_stream_cancellation_closes_child_but_not_root(self):
        payload = b"x" * (bound_file_reader._READ_CHUNK_BYTES * 2 + 19)
        self._write("Post_cancel.bin", payload)
        stopped = threading.Event()
        real_read = os.read
        read_calls = 0

        def cancelling_read(descriptor: int, size: int) -> bytes:
            nonlocal read_calls
            chunk = real_read(descriptor, size)
            read_calls += 1
            stopped.set()
            return chunk

        with open_bound_root(self.root) as session:
            with mock.patch(
                "bound_file_reader.os.read", side_effect=cancelling_read
            ):
                with self.assertRaises(BoundFileCancelled):
                    session.inspect_child("Post_cancel.bin", stopped)
            self.assertEqual(read_calls, 1)
            stopped.clear()
            self.assertEqual(session.stat_child("Post_cancel.bin"), len(payload))
        self._assert_root_can_be_renamed()

    def test_cancellation_after_root_open_closes_the_new_session_token(self):
        with mock.patch(
            "bound_file_reader._check_cancelled",
            side_effect=(None, BoundFileCancelled("本地文件读取已取消")),
        ):
            with self.assertRaises(BoundFileCancelled):
                open_bound_root(self.root)
        self._assert_root_can_be_renamed()

    @unittest.skipUnless(os.name == "nt", "Windows delete-sharing test")
    def test_windows_session_blocks_root_exchange_until_close(self):
        payload = b"original-session-root"
        self._write("Post_root.bin", payload)
        moved = os.path.join(self.base, "parked-root")
        replacement = os.path.join(self.base, "replacement-root")
        os.makedirs(replacement)
        with open(os.path.join(replacement, "Post_root.bin"), "wb") as file_obj:
            file_obj.write(b"replacement-session")

        session = open_bound_root(self.root)
        try:
            with self.assertRaises(OSError):
                os.rename(self.root, moved)
            self.assertEqual(session.list_names(), ("Post_root.bin",))
            self.assertEqual(session.read_small_file("Post_root.bin"), payload)
        finally:
            session.close()
        os.rename(self.root, moved)
        os.rename(replacement, self.root)
        os.rename(self.root, replacement)
        os.rename(moved, self.root)

    @unittest.skipIf(os.name == "nt", "POSIX retained-dirfd session test")
    def test_posix_session_survives_path_replacement_using_original_dirfd(self):
        original = b"original-session-root"
        replacement_payload = b"replacement-session"
        self._write("Post_root.bin", original)
        moved = os.path.join(self.base, "parked-root")
        replacement = os.path.join(self.base, "replacement-root")
        os.makedirs(replacement)
        self._write("Post_root.bin", replacement_payload, root=replacement)

        with open_bound_root(self.root) as session:
            os.rename(self.root, moved)
            os.rename(replacement, self.root)
            self.assertEqual(session.list_names(), ("Post_root.bin",))
            self.assertEqual(session.read_small_file("Post_root.bin"), original)

        os.rename(self.root, replacement)
        os.rename(moved, self.root)

    def test_root_identity_mismatch_never_attempts_to_open_child(self):
        payload = b"bound-root"
        self._write("Post_2.bin", payload)
        identity = get_bound_root_identity(self.root)
        changed_id = bytes([identity.file_id[0] ^ 1]) + identity.file_id[1:]
        mismatched = replace(identity, file_id=changed_id)
        seam = "_win_open_child" if os.name == "nt" else "_posix_open_child"

        with mock.patch.object(bound_file_reader, seam) as open_child:
            with self.assertRaisesRegex(BoundFileError, "根目录已变化"):
                self._read("Post_2.bin", payload, identity=mismatched)

        open_child.assert_not_called()
        self._assert_root_can_be_renamed()

    def test_same_size_replacement_is_rejected_by_sha256(self):
        original = b"A" * 8192
        replacement = b"B" * len(original)
        path = self._write("Post_3.bin", original)
        identity = get_bound_root_identity(self.root)
        with open(path, "wb") as file_obj:
            file_obj.write(replacement)

        with self.assertRaisesRegex(BoundFileError, "摘要与已验证记录"):
            read_verified_child(
                self.root,
                identity,
                "Post_3.bin",
                len(original),
                _sha256(original),
                None,
                MAX_BOUND_FILE_BYTES,
            )
        self._assert_root_can_be_renamed()

    def test_wrong_size_is_rejected_before_payload_read(self):
        payload = b"size-bound"
        self._write("Post_size.bin", payload)
        identity = get_bound_root_identity(self.root)

        with mock.patch("bound_file_reader._read_fd_verified") as read_payload:
            with self.assertRaisesRegex(BoundFileError, "长度与已验证记录"):
                read_verified_child(
                    self.root,
                    identity,
                    "Post_size.bin",
                    len(payload) + 1,
                    _sha256(payload),
                    None,
                    MAX_BOUND_FILE_BYTES,
                )
        read_payload.assert_not_called()
        self._assert_root_can_be_renamed()

    def test_preflight_and_mid_read_cancellation_close_everything(self):
        payload = b"x" * (bound_file_reader._READ_CHUNK_BYTES * 2 + 17)
        self._write("Post_4.bin", payload)
        identity = get_bound_root_identity(self.root)

        stopped = threading.Event()
        stopped.set()
        with self.assertRaises(BoundFileCancelled):
            self._read("Post_4.bin", payload, identity=identity, event=stopped)
        self._assert_root_can_be_renamed()

        stopped.clear()
        real_read = os.read
        read_calls = 0

        def cancelling_read(descriptor: int, size: int) -> bytes:
            nonlocal read_calls
            chunk = real_read(descriptor, size)
            read_calls += 1
            if read_calls == 1:
                stopped.set()
            return chunk

        with mock.patch("bound_file_reader.os.read", side_effect=cancelling_read):
            with self.assertRaises(BoundFileCancelled):
                self._read("Post_4.bin", payload, identity=identity, event=stopped)
        self.assertEqual(read_calls, 1)
        self._assert_root_can_be_renamed()

    def test_child_symlink_or_reparse_point_is_rejected_before_read(self):
        target = os.path.join(self.base, "outside.bin")
        payload = b"outside-but-readable"
        with open(target, "wb") as file_obj:
            file_obj.write(payload)
        link = os.path.join(self.root, "Post_link.bin")
        try:
            os.symlink(target, link, target_is_directory=False)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlink unavailable: {type(exc).__name__}")

        identity = get_bound_root_identity(self.root)
        with mock.patch("bound_file_reader._read_fd_verified") as read_payload:
            with self.assertRaises(BoundFileError):
                read_verified_child(
                    self.root,
                    identity,
                    "Post_link.bin",
                    len(payload),
                    _sha256(payload),
                    None,
                    MAX_BOUND_FILE_BYTES,
                )
        read_payload.assert_not_called()
        self._assert_root_can_be_renamed()

    def test_root_symlink_or_reparse_point_is_rejected(self):
        target = os.path.join(self.base, "real-root")
        link = os.path.join(self.base, "linked-root")
        os.makedirs(target)
        try:
            os.symlink(target, link, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlink unavailable: {type(exc).__name__}")
        with self.assertRaisesRegex(BoundFileError, "根目录不可用|根目录不安全"):
            get_bound_root_identity(link)
        moved_link = os.path.join(self.base, "renamed-linked-root")
        os.rename(link, moved_link)
        os.rename(moved_link, link)

    @unittest.skipUnless(os.name == "nt", "Windows handle-relative open test")
    def test_ancestor_rename_cannot_redirect_the_bound_child(self):
        original_parent = os.path.join(self.base, "live-parent")
        original_root = os.path.join(original_parent, "downloads")
        replacement_parent = os.path.join(self.base, "replacement-parent")
        replacement_root = os.path.join(replacement_parent, "downloads")
        parked_parent = os.path.join(self.base, "parked-parent")
        os.makedirs(original_root)
        os.makedirs(replacement_root)
        original = b"ORIGINAL-BOUND-CONTENT"
        replacement = b"REPLACEMENT-OUTSIDE!!!"
        self.assertEqual(len(original), len(replacement))
        self._write("Post_5.bin", original, root=original_root)
        self._write("Post_5.bin", replacement, root=replacement_root)
        identity = get_bound_root_identity(original_root)
        real_open_child = bound_file_reader._win_open_child
        swapped = False

        def swap_ancestor_then_open(root_handle: int, basename: str) -> int:
            nonlocal swapped
            moved_original = False
            try:
                os.rename(original_parent, parked_parent)
                moved_original = True
                os.rename(replacement_parent, original_parent)
                swapped = True
            except OSError:
                if moved_original and not os.path.exists(original_parent):
                    try:
                        os.rename(parked_parent, original_parent)
                    except OSError:
                        pass
                raise BoundFileError("本地文件无法安全读取") from None
            return real_open_child(root_handle, basename)

        try:
            with mock.patch(
                "bound_file_reader._win_open_child",
                side_effect=swap_ancestor_then_open,
            ):
                try:
                    result = read_verified_child(
                        original_root,
                        identity,
                        "Post_5.bin",
                        len(original),
                        _sha256(original),
                        None,
                        MAX_BOUND_FILE_BYTES,
                    )
                except BoundFileError:
                    result = None
        finally:
            if swapped:
                os.rename(original_parent, replacement_parent)
                os.rename(parked_parent, original_parent)
        if swapped:
            self.assertEqual(result, original)
        else:
            self.assertIsNone(result, "a blocked ancestor rename must fail safely")
            os.rename(original_parent, parked_parent)
            os.rename(parked_parent, original_parent)

    @unittest.skipIf(os.name == "nt", "POSIX directory-fd rename test")
    def test_posix_ancestor_rename_still_reads_from_bound_root(self):
        original_parent = os.path.join(self.base, "live-parent")
        original_root = os.path.join(original_parent, "downloads")
        replacement_parent = os.path.join(self.base, "replacement-parent")
        replacement_root = os.path.join(replacement_parent, "downloads")
        parked_parent = os.path.join(self.base, "parked-parent")
        os.makedirs(original_root)
        os.makedirs(replacement_root)
        original = b"ORIGINAL-BOUND-CONTENT"
        replacement = b"REPLACEMENT-OUTSIDE!!!"
        self.assertEqual(len(original), len(replacement))
        self._write("Post_posix.bin", original, root=original_root)
        self._write("Post_posix.bin", replacement, root=replacement_root)
        identity = get_bound_root_identity(original_root)
        real_open_child = bound_file_reader._posix_open_child
        swapped = False

        def swap_ancestor_then_open(root_fd: int, basename: str) -> int:
            nonlocal swapped
            os.rename(original_parent, parked_parent)
            os.rename(replacement_parent, original_parent)
            swapped = True
            return real_open_child(root_fd, basename)

        try:
            with mock.patch(
                "bound_file_reader._posix_open_child",
                side_effect=swap_ancestor_then_open,
            ):
                result = read_verified_child(
                    original_root,
                    identity,
                    "Post_posix.bin",
                    len(original),
                    _sha256(original),
                    None,
                    MAX_BOUND_FILE_BYTES,
                )
        finally:
            if swapped:
                os.rename(original_parent, replacement_parent)
                os.rename(parked_parent, original_parent)
        self.assertEqual(result, original)

    @unittest.skipIf(
        os.name == "nt" or not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
        "POSIX FIFO test",
    )
    def test_posix_fifo_is_rejected_without_blocking_and_can_be_cancelled(self):
        fifo_path = os.path.join(self.root, "Post_fifo.bin")
        os.mkfifo(fifo_path)
        identity = get_bound_root_identity(self.root)
        stopped = threading.Event()
        outcome: list[BaseException] = []
        finished = threading.Event()

        def attempt_read() -> None:
            try:
                read_verified_child(
                    self.root,
                    identity,
                    "Post_fifo.bin",
                    1,
                    _sha256(b"x"),
                    stopped,
                    MAX_BOUND_FILE_BYTES,
                )
            except BaseException as exc:
                outcome.append(exc)
            finally:
                finished.set()

        worker = threading.Thread(target=attempt_read, daemon=True)
        started = time.monotonic()
        worker.start()
        completed_without_rescue = finished.wait(1.0)
        if not completed_without_rescue:
            stopped.set()
            writer = None
            try:
                writer = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                pass
            finally:
                if writer is not None:
                    os.close(writer)
            finished.wait(1.0)
        self.assertTrue(completed_without_rescue, "FIFO open blocked before validation")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], BoundFileError)
        self._assert_root_can_be_renamed()

    def test_invalid_names_limits_and_digests_are_fixed_redacted_errors(self):
        payload = b"x"
        self._write("safe.bin", payload)
        identity = get_bound_root_identity(self.root)
        cases = (
            ("../safe.bin", 1, _sha256(payload), 10),
            ("nested/safe.bin", 1, _sha256(payload), 10),
            ("nested\\safe.bin", 1, _sha256(payload), 10),
            (r"C:\private\safe.bin", 1, _sha256(payload), 10),
            ("bad:name.bin", 1, _sha256(payload), 10),
            ("bad\x00name.bin", 1, _sha256(payload), 10),
            ("safe.bin", True, _sha256(payload), 10),
            ("safe.bin", 1, "A" * 64, 10),
            ("safe.bin", 1, _sha256(payload), True),
            ("safe.bin", 1, _sha256(payload), MAX_BOUND_FILE_BYTES + 1),
        )
        for name, size, digest, limit in cases:
            with self.subTest(name=name, size=size, digest=digest, limit=limit):
                with self.assertRaises(BoundFileError) as caught:
                    read_verified_child(
                        self.root,
                        identity,
                        name,
                        size,
                        digest,
                        None,
                        limit,
                    )
                rendered = str(caught.exception)
                self.assertNotIn(self.root, rendered)
                self.assertNotIn("OSError", rendered)
                self.assertNotIn("WinError", rendered)

    def test_missing_secret_path_and_native_failure_are_not_echoed(self):
        secret = os.path.join(self.base, "private-secret-root")
        with self.assertRaises(BoundFileError) as caught:
            get_bound_root_identity(secret)
        rendered = str(caught.exception)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(self.base, rendered)
        self.assertNotIn("OSError", rendered)

    def test_unexpected_internal_error_is_redacted_and_releases_root(self):
        payload = b"unexpected-boundary"
        self._write("Post_boundary.bin", payload)
        identity = get_bound_root_identity(self.root)
        seam = "_win_open_child" if os.name == "nt" else "_posix_open_child"
        secret = os.path.join(self.base, "secret-native-detail")

        with mock.patch.object(
            bound_file_reader,
            seam,
            side_effect=OSError(secret),
        ):
            with self.assertRaises(BoundFileError) as caught:
                self._read("Post_boundary.bin", payload, identity=identity)
        rendered = str(caught.exception)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(self.base, rendered)
        self.assertNotIn("OSError", rendered)
        self._assert_root_can_be_renamed()

    @unittest.skipUnless(os.name == "nt", "Windows handle cleanup test")
    def test_windows_fd_conversion_failure_closes_child_and_root_handles(self):
        payload = b"handle-cleanup"
        self._write("Post_6.bin", payload)
        identity = get_bound_root_identity(self.root)
        with mock.patch(
            "bound_file_reader._win_handle_to_fd",
            side_effect=BoundFileError("本地文件无法安全读取"),
        ):
            with self.assertRaises(BoundFileError):
                self._read("Post_6.bin", payload, identity=identity)
        self._assert_root_can_be_renamed()

    @unittest.skipUnless(os.name == "nt", "Windows NtCreateFile ABI test")
    def test_windows_child_open_is_root_relative_and_reparse_safe(self):
        root_handle = 0x4242
        child_handle = 0x4343
        basename = "Post_7.bin"
        captured: dict[str, object] = {}

        def fake_nt_create_file(
            output_handle,
            desired_access,
            object_attributes,
            io_status,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        ) -> int:
            del io_status, allocation_size, file_attributes, ea_buffer, ea_length
            output = ctypes.cast(
                output_handle,
                ctypes.POINTER(bound_file_reader.wintypes.HANDLE),
            )
            output.contents.value = child_handle
            attributes = ctypes.cast(
                object_attributes,
                ctypes.POINTER(bound_file_reader._OBJECT_ATTRIBUTES),
            ).contents
            name = attributes.ObjectName.contents
            captured.update(
                root=attributes.RootDirectory,
                name=ctypes.wstring_at(name.Buffer, name.Length // 2),
                desired=int(desired_access),
                share=int(share_access),
                disposition=int(create_disposition),
                options=int(create_options),
            )
            return 0

        with mock.patch(
            "bound_file_reader._NtCreateFile",
            side_effect=fake_nt_create_file,
        ):
            result = bound_file_reader._win_open_child(root_handle, basename)

        self.assertEqual(result, child_handle)
        self.assertEqual(captured["root"], root_handle)
        self.assertEqual(captured["name"], basename)
        self.assertEqual(
            captured["desired"],
            bound_file_reader._FILE_READ_DATA
            | bound_file_reader._FILE_READ_ATTRIBUTES
            | bound_file_reader._SYNCHRONIZE,
        )
        self.assertEqual(captured["share"], bound_file_reader._FILE_SHARE_READ)
        self.assertEqual(captured["disposition"], bound_file_reader._FILE_OPEN)
        self.assertEqual(
            captured["options"],
            bound_file_reader._FILE_SYNCHRONOUS_IO_NONALERT
            | bound_file_reader._FILE_NON_DIRECTORY_FILE
            | bound_file_reader._FILE_OPEN_REPARSE_POINT,
        )

    @unittest.skipUnless(os.name == "nt", "Windows NTSTATUS classification test")
    def test_windows_open_statuses_keep_operational_and_unsafe_failures_distinct(
        self,
    ):
        child_handle = 0x5151

        def failing_open(status: int):
            def fake_nt_create_file(output_handle, *_args) -> int:
                output = ctypes.cast(
                    output_handle,
                    ctypes.POINTER(bound_file_reader.wintypes.HANDLE),
                )
                output.contents.value = child_handle
                return status

            return fake_nt_create_file

        for status in bound_file_reader._WINDOWS_UNREADABLE_OPEN_STATUSES:
            with self.subTest(status=status), mock.patch(
                "bound_file_reader._NtCreateFile",
                side_effect=failing_open(status),
            ), mock.patch("bound_file_reader._win_close_handle") as close_handle:
                with self.assertRaises(BoundFileUnreadable) as caught:
                    bound_file_reader._win_open_child(0x4242, "Post_status.bin")
                self.assertEqual(str(caught.exception), "本地文件不可读")
                close_handle.assert_called_once_with(child_handle)

        unsafe_status = ctypes.c_int32(0xC00000BA).value
        with mock.patch(
            "bound_file_reader._NtCreateFile",
            side_effect=failing_open(unsafe_status),
        ), mock.patch("bound_file_reader._win_close_handle") as close_handle:
            with self.assertRaises(BoundFileError) as caught:
                bound_file_reader._win_open_child(0x4242, "Post_status.bin")
        self.assertIs(type(caught.exception), BoundFileError)
        self.assertEqual(str(caught.exception), "本地文件无法安全读取")
        close_handle.assert_called_once_with(child_handle)


if __name__ == "__main__":
    unittest.main()
