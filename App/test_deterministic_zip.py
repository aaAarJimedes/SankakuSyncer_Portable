# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import zipfile

from tools import build_deterministic_zip as zipper


class DeterministicZipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "SankakuSyncer Portable 搬移"
        (self.source / "App").mkdir(parents=True)
        (self.source / "Data").mkdir()
        (self.source / "Downloads").mkdir()
        (self.source / "App" / "main.py").write_bytes(b"print('ok')\n")
        (self.source / "README.md").write_bytes("便携测试\n".encode("utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_two_builds_are_byte_identical_despite_source_mtimes(self) -> None:
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        count = zipper.build_deterministic_zip(self.source, first)
        self.assertGreaterEqual(count, 5)

        changed = time.time() + 600
        for path in self.source.rglob("*"):
            os.utime(path, (changed, changed))
        zipper.build_deterministic_zip(self.source, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        with zipfile.ZipFile(first) as archive:
            private_entries = [
                name
                for name in archive.namelist()
                if name.casefold().startswith(("data/", "downloads/"))
            ]
            self.assertEqual(private_entries, ["Data/", "Downloads/"])
            self.assertEqual(
                archive.read("README.md"), "便携测试\n".encode("utf-8")
            )
            self.assertTrue(
                all(info.date_time == zipper.FIXED_ZIP_TIME for info in archive.infolist())
            )

    def test_refuses_nonempty_private_directories_without_creating_output(self) -> None:
        cases = (
            (Path("Data/settings.json"), b"private settings"),
            (Path("Data/.credentials"), b"private vault"),
            (Path("Downloads/item.jpg"), b"private media"),
        )
        for index, (relative, payload) in enumerate(cases):
            with self.subTest(relative=relative.as_posix()):
                private_file = self.source / relative
                private_file.write_bytes(payload)
                output = self.root / f"private-{index}.zip"
                try:
                    with self.assertRaisesRegex(
                        zipper.DeterministicZipError, "must be empty"
                    ):
                        zipper.build_deterministic_zip(self.source, output)
                    self.assertFalse(output.exists())
                    self.assertEqual(private_file.read_bytes(), payload)
                finally:
                    private_file.unlink(missing_ok=True)

    def test_requires_both_private_paths_to_be_plain_directories(self) -> None:
        private = self.source / "Data"
        private.rmdir()
        missing_output = self.root / "missing-private.zip"
        with self.assertRaisesRegex(
            zipper.DeterministicZipError, "required private archive directory is missing"
        ):
            zipper.build_deterministic_zip(self.source, missing_output)
        self.assertFalse(missing_output.exists())

        private.write_bytes(b"not a directory")
        file_output = self.root / "file-private.zip"
        try:
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "must be a plain directory"
            ):
                zipper.build_deterministic_zip(self.source, file_output)
            self.assertFalse(file_output.exists())
            self.assertEqual(private.read_bytes(), b"not a directory")
        finally:
            private.unlink(missing_ok=True)
            private.mkdir()

    def test_refuses_noncanonical_private_directory_case(self) -> None:
        canonical = self.source / "Data"
        alias = self.source / "data"
        try:
            canonical.rename(alias)
        except OSError:
            self.skipTest("filesystem cannot perform a case-only directory rename")
        output = self.root / "aliased-private.zip"
        try:
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "must use canonical name"
            ):
                zipper.build_deterministic_zip(self.source, output)
            self.assertFalse(output.exists())
        finally:
            alias.rename(canonical)

    def test_refuses_private_directory_link_when_supported(self) -> None:
        private = self.source / "Data"
        target = self.root / "empty-private-target"
        private.rmdir()
        target.mkdir()
        try:
            private.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            private.mkdir()
            self.skipTest("directory symbolic links unavailable")
        output = self.root / "linked-private.zip"
        try:
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "must be a plain directory"
            ):
                zipper.build_deterministic_zip(self.source, output)
            self.assertFalse(output.exists())
        finally:
            private.unlink(missing_ok=True)
            private.mkdir()

    def test_rechecks_private_directories_before_publishing(self) -> None:
        output = self.root / "raced-private.zip"
        original_write = zipper._write_file
        injected = False

        def write_then_inject(archive, root, relative) -> None:
            nonlocal injected
            original_write(archive, root, relative)
            if not injected:
                injected = True
                (self.source / "Data" / "settings.json").write_bytes(b"late private")

        with mock.patch.object(zipper, "_write_file", side_effect=write_then_inject):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "must be empty"
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertFalse(output.exists())
        self.assertEqual(
            (self.source / "Data" / "settings.json").read_bytes(), b"late private"
        )

    def test_archive_verification_failure_never_publishes_output(self) -> None:
        output = self.root / "verification-failed.zip"
        with mock.patch.object(
            zipper.zipfile.ZipFile, "testzip", return_value="App/main.py"
        ):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "temporary archive failed verification"
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertFalse(output.exists())

    def test_rechecks_private_directories_after_archive_verification(self) -> None:
        output = self.root / "post-verification-race.zip"
        original_verify = zipper._verify_archive

        def verify_then_inject(path, expected) -> None:
            original_verify(path, expected)
            (self.source / "Data" / "late.txt").write_bytes(b"late private")

        with mock.patch.object(zipper, "_verify_archive", side_effect=verify_then_inject):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "must be empty"
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertFalse(output.exists())
        self.assertEqual(
            (self.source / "Data" / "late.txt").read_bytes(), b"late private"
        )

    def test_concurrent_foreign_output_is_preserved(self) -> None:
        output = self.root / "concurrent.zip"

        def publish_foreign(_source, destination) -> None:
            Path(destination).write_bytes(b"foreign output")
            raise FileExistsError

        with mock.patch.object(zipper.os, "link", side_effect=publish_foreign):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "appeared concurrently"
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertEqual(output.read_bytes(), b"foreign output")

    def test_refuses_existing_output_without_overwriting(self) -> None:
        output = self.root / "release.zip"
        output.write_bytes(b"keep")
        with self.assertRaises(zipper.DeterministicZipError):
            zipper.build_deterministic_zip(self.source, output)
        self.assertEqual(output.read_bytes(), b"keep")

    def test_refuses_output_inside_source(self) -> None:
        output = self.source / "release.zip"
        with self.assertRaises(zipper.DeterministicZipError):
            zipper.build_deterministic_zip(self.source, output)
        self.assertFalse(output.exists())

    def test_refuses_symbolic_link_when_supported(self) -> None:
        link = self.source / "App" / "linked.py"
        try:
            link.symlink_to(self.source / "App" / "main.py")
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links unavailable")
        output = self.root / "release.zip"
        with self.assertRaises(zipper.DeterministicZipError):
            zipper.build_deterministic_zip(self.source, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
