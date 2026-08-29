# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest
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
            self.assertIn("Data/", archive.namelist())
            self.assertIn("Downloads/", archive.namelist())
            self.assertEqual(
                archive.read("README.md"), "便携测试\n".encode("utf-8")
            )
            self.assertTrue(
                all(info.date_time == zipper.FIXED_ZIP_TIME for info in archive.infolist())
            )

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
