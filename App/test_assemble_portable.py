# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools import assemble_portable as assembler


class AssemblePortableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.runtime = self.root / "runtime-final"
        self.source.mkdir()
        self.runtime.mkdir()
        for name in assembler.ROOT_FILES:
            path = self.source / name
            if path.suffix.casefold() in {".bat", ".vbs"}:
                path.write_bytes((name + "\r\n").encode("utf-8"))
            else:
                path.write_text(name, encoding="utf-8")
        app = self.source / "App"
        app.mkdir()
        (app / "payload.py").write_text("VALUE = 1\n", encoding="utf-8")
        docs = self.source / "docs"
        docs.mkdir()
        (docs / "payload.png").write_bytes(b"png")
        licenses = self.source / "THIRD_PARTY_LICENSES"
        licenses.mkdir()
        (licenses / "LICENSE.txt").write_text("license", encoding="utf-8")
        archive_hash = licenses / "Qt-6.11.2" / "source-archives"
        archive_hash.mkdir(parents=True)
        (archive_hash / "qtbase-everywhere-src-6.11.2.tar.xz.sha256").write_text(
            "0" * 64 + "  qtbase-everywhere-src-6.11.2.tar.xz\n",
            encoding="utf-8",
        )
        (self.runtime / "python.exe").write_bytes(b"python")
        for name in assembler.RUNTIME_AUDIT_FILES:
            (self.runtime / name).write_text(name, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_assembles_explicit_public_tree_and_empty_private_directories(self) -> None:
        destination = self.root / "SankakuSyncer_Portable_Staging"
        count = assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertGreater(count, len(assembler.ROOT_FILES))
        self.assertEqual((destination / "Runtime" / "python.exe").read_bytes(), b"python")
        self.assertTrue((destination / "Data").is_dir())
        self.assertTrue((destination / "Downloads").is_dir())
        self.assertEqual(list((destination / "Data").iterdir()), [])

    def test_refuses_existing_destination_without_overwriting(self) -> None:
        destination = self.root / "SankakuSyncer_Portable_Staging"
        destination.mkdir()
        marker = destination / "user.txt"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertEqual(marker.read_text("utf-8"), "keep")

    def test_refuses_builder_sentinel_and_generated_cache(self) -> None:
        destination = self.root / "SankakuSyncer_Portable_Staging"
        sentinel = self.runtime / ".sankakusyncer-runtime-subset-builder"
        sentinel.write_text("builder", encoding="utf-8")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        sentinel.unlink()
        cache = self.source / "App" / "__pycache__"
        cache.mkdir()
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)

    def test_requires_runtime_audit_files_and_all_release_files(self) -> None:
        destination = self.root / "SankakuSyncer_Release_Staging"
        (self.runtime / assembler.RUNTIME_AUDIT_FILES[0]).unlink()
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        (self.runtime / assembler.RUNTIME_AUDIT_FILES[0]).write_text("ok", encoding="utf-8")
        (self.source / "SBOM.spdx.json").unlink()
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)

    def test_refuses_sensitive_or_unapproved_source_files(self) -> None:
        destination = self.root / "SankakuSyncer_Portable_Staging"
        private = self.source / "App" / ".env.production"
        private.write_text("TOKEN=secret", encoding="utf-8")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())
        private.unlink()

        envrc = self.source / "App" / ".envrc"
        envrc.write_text("export TOKEN=secret", encoding="utf-8")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())
        envrc.unlink()

        key = self.source / "docs" / "release.key"
        key.write_text("not-a-real-key", encoding="utf-8")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())
        key.unlink()

        executable = self.source / "App" / "helper.exe"
        executable.write_bytes(b"MZ")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())

    def test_refuses_launcher_with_lf_only_line_endings(self) -> None:
        destination = self.root / "SankakuSyncer_Portable_Staging"
        launcher = self.source / "run.bat"
        launcher.write_bytes(b"@echo off\necho unsafe\n")
        with self.assertRaises(assembler.AssemblyError):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())

    def test_refuses_overlong_portable_relative_path(self) -> None:
        self.assertEqual(
            assembler.PORTABLE_RELATIVE_PATH_LIMIT,
            assembler.runtime_compliance.PORTABLE_RELATIVE_PATH_LIMIT,
        )
        destination = self.root / "SankakuSyncer_Portable_Staging"
        relative = Path("THIRD_PARTY_LICENSES") / (
            "x" * (assembler.PORTABLE_RELATIVE_PATH_LIMIT - 10) + ".html"
        )
        path = self.source / relative
        path.write_text("notice", encoding="utf-8")
        with self.assertRaisesRegex(
            assembler.AssemblyError, "portable relative path is too long"
        ):
            assembler.assemble_portable(self.source, self.runtime, destination)
        self.assertFalse(destination.exists())

    def test_refuses_symbolic_link_as_source_root_when_supported(self) -> None:
        source_link = self.root / "source-link"
        try:
            source_link.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symbolic links unavailable")
        destination = self.root / "SankakuSyncer_Source_Link_Staging"
        try:
            with self.assertRaisesRegex(
                assembler.AssemblyError, "source is not a plain directory"
            ):
                assembler.assemble_portable(
                    source_link, self.runtime, destination
                )
            self.assertFalse(destination.exists())
        finally:
            source_link.unlink(missing_ok=True)

    def test_refuses_symbolic_link_as_runtime_root_when_supported(self) -> None:
        runtime_link = self.root / "runtime-link"
        try:
            runtime_link.symlink_to(self.runtime, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symbolic links unavailable")
        destination = self.root / "SankakuSyncer_Runtime_Link_Staging"
        try:
            with self.assertRaisesRegex(
                assembler.AssemblyError, "Runtime is not a plain directory"
            ):
                assembler.assemble_portable(
                    self.source, runtime_link, destination
                )
            self.assertFalse(destination.exists())
        finally:
            runtime_link.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
