# -*- coding: utf-8 -*-
"""Real-filesystem tests for the public bound archive-tree API."""

from __future__ import annotations

import ctypes
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import bound_archive_tree as bound_tree
from tools.bound_archive_tree import BoundTreeError, TreeLimits, open_bound_tree


class BoundArchiveTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "source tree 中文"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _new_root(self, name: str) -> Path:
        root = self.base / name
        root.mkdir()
        return root

    @staticmethod
    def _write(root: Path, relative: tuple[str, ...], payload: bytes) -> Path:
        path = root.joinpath(*relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    @staticmethod
    def _private_directories(root: Path) -> None:
        (root / "Data").mkdir()
        (root / "Downloads").mkdir()

    def _file_index(self, snapshot, relative: tuple[str, ...]) -> int:
        matches = [
            index
            for index in snapshot.file_indexes
            if snapshot.relative_parts(index) == relative
        ]
        self.assertEqual(matches, matches[:1], f"duplicate snapshot path: {relative!r}")
        self.assertEqual(len(matches), 1, f"missing snapshot path: {relative!r}")
        return matches[0]

    def test_limits_publish_conservative_defaults(self) -> None:
        limits = TreeLimits()
        self.assertEqual(limits.max_entries, 100_000)
        self.assertEqual(limits.max_depth, 128)
        self.assertEqual(limits.max_component_utf8, 1_024)
        self.assertEqual(limits.max_relative_utf8, 32_768)
        self.assertEqual(limits.max_file_bytes, 50 * 1_024**3)
        self.assertEqual(limits.max_total_bytes, 100 * 1_024**3)

    def test_nested_unicode_snapshot_verification_and_copy(self) -> None:
        self._private_directories(self.root)
        relative = ("App", "猫图层", "夜空 ★.txt")
        payload = ("已验证的 Unicode 内容\n" * 31).encode("utf-8")
        self._write(self.root, relative, payload)
        self._write(self.root, ("README.md",), b"public\n")

        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(
                private_directories=("Data", "Downloads"),
                hash_files=True,
            )
            file_index = self._file_index(snapshot, relative)
            node = snapshot.nodes[file_index]

            self.assertEqual(snapshot.relative_parts(file_index), relative)
            self.assertIsInstance(snapshot.relative_parts(file_index), tuple)
            self.assertEqual(node.name, relative[-1])
            self.assertEqual(node.kind, "file")
            self.assertEqual(node.size, len(payload))
            self.assertEqual(node.sha256, hashlib.sha256(payload).hexdigest())
            self.assertIsNotNone(node.identity)
            self.assertIsNotNone(node.change_token)
            self.assertFalse(
                set(snapshot.directory_indexes) & set(snapshot.file_indexes)
            )
            self.assertEqual(
                set(snapshot.directory_indexes) | set(snapshot.file_indexes),
                set(range(len(snapshot.nodes))),
            )

            session.verify_snapshot(snapshot, verify_content=True)
            session.verify_private_directories(snapshot)
            target = io.BytesIO()
            copied = session.copy_verified_file(snapshot, file_index, target)
            self.assertEqual(copied, len(payload))
            self.assertEqual(target.getvalue(), payload)

        # A snapshot is an immutable value and remains useful after its session closes.
        self.assertEqual(snapshot.relative_parts(file_index), relative)
        self.assertEqual(snapshot.nodes[file_index].sha256, node.sha256)

    def test_missing_private_directory_is_rejected(self) -> None:
        (self.root / "Data").mkdir()
        with open_bound_tree(self.root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(
                    private_directories=("Data", "Downloads"),
                    hash_files=True,
                )

    def test_nonempty_private_directory_is_rejected(self) -> None:
        self._private_directories(self.root)
        self._write(self.root, ("Data", "private-token.txt"), b"secret")
        with open_bound_tree(self.root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(
                    private_directories=("Data", "Downloads"),
                    hash_files=True,
                )

    def test_private_directory_case_variant_is_rejected(self) -> None:
        (self.root / "data").mkdir()
        (self.root / "Downloads").mkdir()
        actual_names = os.listdir(self.root)
        if "data" not in actual_names:
            self.skipTest("filesystem did not preserve the requested directory case")

        with open_bound_tree(self.root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(
                    private_directories=("Data", "Downloads"),
                    hash_files=True,
                )

    def test_file_symlink_or_reparse_point_is_rejected(self) -> None:
        root = self._new_root("file-link-root")
        outside = self.base / "outside.bin"
        outside.write_bytes(b"outside")
        link = root / "linked.bin"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks unavailable: {type(exc).__name__}")

        with open_bound_tree(root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(private_directories=(), hash_files=True)

    def test_directory_symlink_or_reparse_point_is_rejected(self) -> None:
        root = self._new_root("directory-link-root")
        outside = self._new_root("outside-directory")
        (outside / "payload.bin").write_bytes(b"outside")
        link = root / "linked-directory"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks unavailable: {type(exc).__name__}")

        with open_bound_tree(root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(private_directories=(), hash_files=True)

    def test_symlink_or_reparse_point_root_is_rejected(self) -> None:
        target = self._new_root("plain-target-root")
        link = self.base / "linked-root"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks unavailable: {type(exc).__name__}")

        session = None
        try:
            with self.assertRaises(BoundTreeError):
                session = open_bound_tree(link)
        finally:
            if session is not None:
                session.close()

    def test_hardlinked_regular_file_is_rejected_when_supported(self) -> None:
        root = self._new_root("hardlink-root")
        outside = self.base / "hardlink-origin.bin"
        outside.write_bytes(b"shared inode")
        linked = root / "ordinary-looking.bin"
        try:
            os.link(outside, linked)
        except (AttributeError, NotImplementedError, OSError) as exc:
            self.skipTest(f"hard links unavailable: {type(exc).__name__}")
        if linked.stat().st_nlink < 2:
            self.skipTest("filesystem does not report hard-link counts")

        with open_bound_tree(root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(private_directories=(), hash_files=True)

    def test_casefold_collision_is_rejected_when_filesystem_supports_it(self) -> None:
        root = self._new_root("casefold-root")
        (root / "Readme.txt").write_bytes(b"first")
        try:
            (root / "README.TXT").write_bytes(b"second")
        except OSError as exc:
            self.skipTest(f"case-distinct names unavailable: {type(exc).__name__}")
        colliding_names = [
            name for name in os.listdir(root) if name.casefold() == "readme.txt"
        ]
        if len(colliding_names) != 2:
            self.skipTest("filesystem is case-insensitive")

        with open_bound_tree(root) as session:
            with self.assertRaises(BoundTreeError):
                session.snapshot(private_directories=(), hash_files=True)

    def test_ancestor_exchange_after_snapshot_makes_copy_fail_closed(self) -> None:
        relative = ("App", "nested", "payload.bin")
        original = b"ORIGINAL-BOUND-CONTENT"
        replacement = b"REPLACEMENT-OUTSIDE!!!"
        self.assertEqual(len(original), len(replacement))
        source_parent = self.root / "App"
        self._write(self.root, relative, original)
        replacement_parent = self._new_root("replacement-App")
        self._write(replacement_parent, ("nested", "payload.bin"), replacement)
        parked_parent = self.base / "parked-App"

        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(private_directories=(), hash_files=True)
            file_index = self._file_index(snapshot, relative)
            moved_original = False
            try:
                source_parent.rename(parked_parent)
                moved_original = True
                replacement_parent.rename(source_parent)
            except OSError as exc:
                if moved_original and not source_parent.exists():
                    try:
                        parked_parent.rename(source_parent)
                    except OSError:
                        pass
                self.skipTest(f"ancestor exchange unavailable: {type(exc).__name__}")

            target = io.BytesIO()
            with self.assertRaises(BoundTreeError):
                session.copy_verified_file(snapshot, file_index, target)
            self.assertEqual(target.getvalue(), b"")

    def test_same_size_content_change_is_rejected_after_timestamp_restore(self) -> None:
        relative = ("payload.bin",)
        original = b"A" * 8_192
        replacement = b"B" * len(original)
        source = self._write(self.root, relative, original)

        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(private_directories=(), hash_files=True)
            file_index = self._file_index(snapshot, relative)
            original_stat = source.stat()
            source.write_bytes(replacement)
            try:
                os.utime(
                    source,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
            except (NotImplementedError, OSError):
                pass

            with self.assertRaises(BoundTreeError):
                session.verify_snapshot(snapshot, verify_content=True)
            with self.assertRaises(BoundTreeError):
                session.copy_verified_file(snapshot, file_index, io.BytesIO())

    def test_verified_copy_requires_a_content_hashed_snapshot(self) -> None:
        relative = ("payload.bin",)
        self._write(self.root, relative, b"payload")
        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(private_directories=(), hash_files=False)
            file_index = self._file_index(snapshot, relative)
            self.assertIsNone(snapshot.nodes[file_index].sha256)
            with self.assertRaises(BoundTreeError):
                session.copy_verified_file(snapshot, file_index, io.BytesIO())

    def test_copy_never_writes_bytes_beyond_the_snapshot_size(self) -> None:
        relative = ("payload.bin",)
        payload = b"snapshot payload"
        self._write(self.root, relative, payload)
        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(private_directories=(), hash_files=True)
            file_index = self._file_index(snapshot, relative)
            target = io.BytesIO()
            chunks = iter((payload, b"grew after the initial state check"))

            with mock.patch.object(
                bound_tree.BoundTreeSession,
                "_read_token",
                autospec=True,
                side_effect=lambda _session, _token, _size: next(chunks, b""),
            ):
                with self.assertRaises(BoundTreeError):
                    session.copy_verified_file(snapshot, file_index, target)

            self.assertEqual(target.getvalue(), payload)

    def test_added_structure_fails_snapshot_verification(self) -> None:
        self._private_directories(self.root)
        self._write(self.root, ("App", "original.txt"), b"original")
        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(
                private_directories=("Data", "Downloads"),
                hash_files=True,
            )
            self._write(self.root, ("App", "added-later.txt"), b"new")
            with self.assertRaises(BoundTreeError):
                session.verify_snapshot(snapshot)

    def test_private_directory_mutation_fails_private_verification(self) -> None:
        self._private_directories(self.root)
        with open_bound_tree(self.root) as session:
            snapshot = session.snapshot(
                private_directories=("Data", "Downloads"),
                hash_files=True,
            )
            session.verify_private_directories(snapshot)
            self._write(self.root, ("Downloads", "appeared.part"), b"private")
            with self.assertRaises(BoundTreeError):
                session.verify_private_directories(snapshot)

    def test_entry_depth_file_and_total_limits_are_enforced(self) -> None:
        cases: list[tuple[str, Path, TreeLimits]] = []

        entries_root = self._new_root("entries-limit-root")
        (entries_root / "one.txt").write_bytes(b"1")
        (entries_root / "two.txt").write_bytes(b"2")
        cases.append(("entries", entries_root, TreeLimits(max_entries=1)))

        depth_root = self._new_root("depth-limit-root")
        self._write(depth_root, ("one", "two", "payload.txt"), b"depth")
        cases.append(("depth", depth_root, TreeLimits(max_depth=1)))

        file_root = self._new_root("file-limit-root")
        (file_root / "large.bin").write_bytes(b"1234")
        cases.append(("file", file_root, TreeLimits(max_file_bytes=3)))

        total_root = self._new_root("total-limit-root")
        (total_root / "one.bin").write_bytes(b"123")
        (total_root / "two.bin").write_bytes(b"456")
        cases.append(
            (
                "total",
                total_root,
                TreeLimits(max_file_bytes=4, max_total_bytes=5),
            )
        )

        for name, root, limits in cases:
            with self.subTest(limit=name), open_bound_tree(
                root, limits=limits
            ) as session:
                with self.assertRaises(BoundTreeError):
                    session.snapshot(private_directories=(), hash_files=True)

    def test_closed_session_rejects_all_operations_and_close_is_idempotent(self) -> None:
        self._private_directories(self.root)
        relative = ("App", "payload.txt")
        self._write(self.root, relative, b"payload")
        session = open_bound_tree(self.root)
        snapshot = session.snapshot(
            private_directories=("Data", "Downloads"),
            hash_files=True,
        )
        file_index = self._file_index(snapshot, relative)

        session.close()
        session.close()
        self.assertTrue(session.closed)
        self.assertEqual(snapshot.relative_parts(file_index), relative)

        operations = (
            lambda: session.snapshot(
                private_directories=("Data", "Downloads"),
                hash_files=True,
            ),
            lambda: session.copy_verified_file(
                snapshot, file_index, io.BytesIO()
            ),
            lambda: session.verify_snapshot(snapshot, verify_content=True),
            lambda: session.verify_private_directories(snapshot),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(BoundTreeError):
                operation()

    @unittest.skipUnless(os.name == "nt", "Windows native relative-open ABI test")
    def test_windows_child_open_is_exact_case_and_root_relative(self) -> None:
        root_handle = 0x4242
        child_handle = 0x5151
        basename = "ExactCase-猫.bin"
        captured: dict[str, object] = {}

        def fake_nt_create_file(
            output_handle,
            desired_access,
            object_attributes,
            _io_status,
            _allocation_size,
            _file_attributes,
            share_access,
            create_disposition,
            create_options,
            _ea_buffer,
            _ea_length,
        ) -> int:
            output = ctypes.cast(
                output_handle,
                ctypes.POINTER(bound_tree.wintypes.HANDLE),
            )
            output.contents.value = child_handle
            attributes = ctypes.cast(
                object_attributes,
                ctypes.POINTER(bound_tree._OBJECT_ATTRIBUTES),
            ).contents
            name = attributes.ObjectName.contents
            captured.update(
                root=attributes.RootDirectory,
                name=ctypes.wstring_at(name.Buffer, name.Length // 2),
                attributes=int(attributes.Attributes),
                desired=int(desired_access),
                share=int(share_access),
                disposition=int(create_disposition),
                options=int(create_options),
            )
            return 0

        with mock.patch.object(
            bound_tree,
            "_NtCreateFile",
            side_effect=fake_nt_create_file,
        ):
            result = bound_tree._win_open_any(root_handle, basename)

        self.assertEqual(result, child_handle)
        self.assertEqual(captured["root"], root_handle)
        self.assertEqual(captured["name"], basename)
        self.assertEqual(captured["attributes"], 0)
        self.assertEqual(
            captured["desired"],
            bound_tree._FILE_READ_DATA
            | bound_tree._FILE_READ_ATTRIBUTES
            | bound_tree._SYNCHRONIZE,
        )
        self.assertEqual(captured["share"], bound_tree._FILE_SHARE_READ)
        self.assertEqual(captured["disposition"], bound_tree._FILE_OPEN)
        self.assertEqual(
            captured["options"],
            bound_tree._FILE_SYNCHRONOUS_IO_NONALERT
            | bound_tree._FILE_OPEN_REPARSE_POINT,
        )

    @unittest.skipUnless(os.name == "nt", "Windows native directory ABI test")
    def test_windows_directory_enumeration_restarts_once_and_resumes(self) -> None:
        calls: list[int] = []
        expected_name = "Unicode 猫.txt"

        def fake_query(_handle, information_class, buffer, _size) -> bool:
            calls.append(int(information_class))
            if len(calls) == 1:
                record = bound_tree._FILE_ID_BOTH_DIR_INFO.from_buffer(buffer)
                encoded = expected_name.encode("utf-16-le")
                record.NextEntryOffset = 0
                record.FileNameLength = len(encoded)
                ctypes.memmove(
                    ctypes.addressof(buffer)
                    + bound_tree._FILE_ID_BOTH_DIR_INFO.FileName.offset,
                    encoded,
                    len(encoded),
                )
                return True
            ctypes.set_last_error(bound_tree._ERROR_NO_MORE_FILES)
            return False

        with mock.patch.object(
            bound_tree,
            "_GetFileInformationByHandleEx",
            side_effect=fake_query,
        ):
            names = bound_tree._win_list_names(0x4242, 10)

        self.assertEqual(names, (expected_name,))
        self.assertEqual(
            calls,
            [
                bound_tree._FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS,
                bound_tree._FILE_ID_BOTH_DIRECTORY_INFO_CLASS,
            ],
        )

    @unittest.skipUnless(os.name == "nt", "Windows native directory ABI test")
    def test_windows_directory_parser_rejects_unaligned_record_offset(self) -> None:
        def fake_query(_handle, _information_class, buffer, _size) -> bool:
            record = bound_tree._FILE_ID_BOTH_DIR_INFO.from_buffer(buffer)
            encoded = "a".encode("utf-16-le")
            record.NextEntryOffset = (
                bound_tree._FILE_ID_BOTH_DIR_INFO.FileName.offset + len(encoded)
            )
            record.FileNameLength = len(encoded)
            ctypes.memmove(
                ctypes.addressof(buffer)
                + bound_tree._FILE_ID_BOTH_DIR_INFO.FileName.offset,
                encoded,
                len(encoded),
            )
            return True

        with mock.patch.object(
            bound_tree,
            "_GetFileInformationByHandleEx",
            side_effect=fake_query,
        ):
            with self.assertRaises(BoundTreeError):
                bound_tree._win_list_names(0x4242, 10)


if __name__ == "__main__":
    unittest.main()
