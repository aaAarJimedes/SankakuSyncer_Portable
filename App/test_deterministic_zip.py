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

        def write_then_inject(*arguments) -> None:
            nonlocal injected
            original_write(*arguments)
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

        def verify_then_inject(
            descriptor,
            expected,
            baseline,
            expected_sha256,
        ) -> None:
            original_verify(descriptor, expected, baseline, expected_sha256)
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

        def publish_foreign(_source, destination, **_kwargs) -> None:
            Path(destination).write_bytes(b"foreign output")
            raise FileExistsError

        with mock.patch.object(zipper.os, "link", side_effect=publish_foreign):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "appeared concurrently"
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertEqual(output.read_bytes(), b"foreign output")

    def test_published_identity_mismatch_preserves_unknown_output(self) -> None:
        output = self.root / "wrong-published-identity.zip"

        def publish_foreign(_source, destination, **_kwargs) -> None:
            Path(destination).write_bytes(b"foreign output")

        with mock.patch.object(zipper.os, "link", side_effect=publish_foreign):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError,
                "published archive identity does not match verification",
            ):
                zipper.build_deterministic_zip(self.source, output)
        self.assertEqual(output.read_bytes(), b"foreign output")

    def test_output_name_replacement_after_bound_check_is_detected(self) -> None:
        output = self.root / "late-output-replacement.zip"
        original_check = zipper._require_same_published
        checks = 0

        def check_then_replace(path, descriptor, baseline, **kwargs) -> None:
            nonlocal checks
            original_check(path, descriptor, baseline, **kwargs)
            checks += 1
            if checks == 1:
                try:
                    path.unlink()
                except PermissionError:
                    self.skipTest(
                        "open published handle prevents pathname replacement"
                    )
                path.write_bytes(b"foreign output after bound check")

        with mock.patch.object(
            zipper,
            "_require_same_published",
            side_effect=check_then_replace,
        ):
            with self.assertRaisesRegex(
                zipper.DeterministicZipError,
                "published archive identity does not match verification",
            ):
                zipper.build_deterministic_zip(self.source, output)

        self.assertEqual(checks, 1)
        self.assertEqual(output.read_bytes(), b"foreign output after bound check")

    def test_hard_link_failure_never_falls_back_to_rename(self) -> None:
        output = self.root / "no-hard-link.zip"
        with mock.patch.object(
            zipper.os,
            "link",
            side_effect=OSError("hard links unavailable"),
        ), mock.patch.object(zipper.os, "rename") as rename:
            with self.assertRaisesRegex(
                zipper.DeterministicZipError,
                "verified hard link",
            ):
                zipper.build_deterministic_zip(self.source, output)
        rename.assert_not_called()
        self.assertFalse(output.exists())

    def test_replaced_temporary_name_is_not_verified_or_deleted(self) -> None:
        output = self.root / "changed-temporary.zip"
        original_private_check = zipper.BoundTreeSession.verify_private_directories
        injected: Path | None = None

        def replace_temporary(session, snapshot) -> None:
            nonlocal injected
            original_private_check(session, snapshot)
            if injected is None:
                matches = list(self.root.glob(f".{output.name}.*.tmp"))
                self.assertEqual(len(matches), 1)
                injected = matches[0]
                try:
                    injected.unlink()
                except PermissionError:
                    self.skipTest(
                        "open temporary handle prevents pathname replacement"
                    )
                injected.write_bytes(b"foreign temporary")

        try:
            with mock.patch.object(
                zipper.BoundTreeSession,
                "verify_private_directories",
                autospec=True,
                side_effect=replace_temporary,
            ), mock.patch.object(zipper, "_verify_archive") as verify:
                with self.assertRaisesRegex(
                    zipper.DeterministicZipError,
                    "temporary archive identity changed",
                ):
                    zipper.build_deterministic_zip(self.source, output)
            verify.assert_not_called()
            self.assertIsNotNone(injected)
            assert injected is not None
            self.assertEqual(injected.read_bytes(), b"foreign temporary")
            self.assertFalse(output.exists())
        finally:
            if injected is not None:
                injected.unlink(missing_ok=True)

    def test_descriptor_digest_rejects_same_size_rewrite_with_restored_mtime(
        self,
    ) -> None:
        path = self.root / "descriptor-digest.tmp"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        try:
            original = b"A" * 4096
            os.write(descriptor, original)
            os.fsync(descriptor)
            baseline = os.fstat(descriptor)
            digest = zipper._descriptor_sha256(descriptor, baseline)

            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, b"B" * len(original))
            os.fsync(descriptor)
            os.utime(
                path,
                ns=(baseline.st_atime_ns, baseline.st_mtime_ns),
            )
            current = os.fstat(descriptor)
            if zipper._regular_file_state(current) != zipper._regular_file_state(
                baseline
            ):
                self.skipTest("filesystem cannot restore the bound file timestamp")

            with self.assertRaisesRegex(
                zipper.DeterministicZipError,
                "temporary archive content changed",
            ):
                zipper._require_descriptor_digest(descriptor, baseline, digest)
        finally:
            os.close(descriptor)
            path.unlink(missing_ok=True)

    def test_same_size_mutation_after_verification_never_publishes(self) -> None:
        output = self.root / "post-verification-mutation.zip"
        original_verify = zipper._verify_archive
        protected_write_denied = False

        def verify_then_mutate(
            descriptor,
            expected,
            baseline,
            expected_sha256,
        ) -> None:
            nonlocal protected_write_denied
            original_verify(descriptor, expected, baseline, expected_sha256)
            os.lseek(descriptor, 0, os.SEEK_SET)
            first = os.read(descriptor, 1)
            self.assertEqual(len(first), 1)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                os.write(descriptor, bytes((first[0] ^ 0x01,)))
            except OSError:
                if os.name != "nt":
                    raise
                protected_write_denied = True
                return
            os.fsync(descriptor)
            matches = list(self.root.glob(f".{output.name}.*.tmp"))
            self.assertEqual(len(matches), 1)
            os.utime(
                matches[0],
                ns=(baseline.st_atime_ns, baseline.st_mtime_ns),
            )
            current = os.fstat(descriptor)
            if zipper._regular_file_state(current) != zipper._regular_file_state(
                baseline
            ):
                self.skipTest("filesystem cannot restore the bound file timestamp")

        with mock.patch.object(
            zipper,
            "_verify_archive",
            side_effect=verify_then_mutate,
        ):
            if os.name == "nt":
                zipper.build_deterministic_zip(self.source, output)
            else:
                with self.assertRaisesRegex(
                    zipper.DeterministicZipError,
                    "temporary archive content changed",
                ):
                    zipper.build_deterministic_zip(self.source, output)

        if os.name == "nt":
            self.assertTrue(protected_write_denied)
            self.assertTrue(output.is_file())
        else:
            self.assertFalse(output.exists())

    def test_success_retains_the_named_temporary_without_path_unlink(self) -> None:
        output = self.root / "retained-temporary.zip"
        with mock.patch.object(
            Path,
            "unlink",
            side_effect=AssertionError("build must not unlink by pathname"),
        ):
            zipper.build_deterministic_zip(self.source, output)

        matches = list(self.root.glob(f".{output.name}.*.tmp"))
        self.assertEqual(len(matches), 1)
        self.assertTrue(os.path.samestat(matches[0].lstat(), output.lstat()))
        self.assertEqual(matches[0].read_bytes(), output.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows native share-mode test")
    def test_windows_temporary_denies_concurrent_writer_from_creation(self) -> None:
        output = self.root / "share-protected.zip"
        original_write = zipper._write_file
        checked = False

        def check_share_then_write(*args, **kwargs) -> None:
            nonlocal checked
            if not checked:
                matches = list(self.root.glob(f".{output.name}.*.tmp"))
                self.assertEqual(len(matches), 1)
                with self.assertRaises(PermissionError):
                    os.open(matches[0], os.O_RDWR)
                checked = True
            original_write(*args, **kwargs)

        with mock.patch.object(
            zipper,
            "_write_file",
            side_effect=check_share_then_write,
        ):
            zipper.build_deterministic_zip(self.source, output)

        self.assertTrue(checked)

    def test_write_after_final_digest_prefix_is_detected(self) -> None:
        output = self.root / "mid-final-digest-write.zip"
        original_open = zipper._open_published
        original_read = zipper._read_descriptor_chunk
        published_descriptor: int | None = None
        write_attempted = False
        mutated = False
        protected_write_denied = False

        def capture_published(path, baseline) -> int:
            nonlocal published_descriptor
            published_descriptor = original_open(path, baseline)
            return published_descriptor

        def read_then_mutate(source, size: int) -> bytes:
            nonlocal write_attempted, mutated, protected_write_denied
            chunk = original_read(source, size)
            if published_descriptor is not None and chunk and not write_attempted:
                write_attempted = True
                before = output.stat()
                writer: int | None = None
                try:
                    writer = os.open(output, os.O_RDWR)
                    os.lseek(writer, 0, os.SEEK_SET)
                    first = os.read(writer, 1)
                    self.assertEqual(len(first), 1)
                    os.lseek(writer, 0, os.SEEK_SET)
                    os.write(writer, bytes((first[0] ^ 0x01,)))
                    os.fsync(writer)
                except PermissionError:
                    if os.name != "nt":
                        raise
                    protected_write_denied = True
                    return chunk
                finally:
                    if writer is not None:
                        os.close(writer)
                mutated = True
                os.utime(output, ns=(before.st_atime_ns, before.st_mtime_ns))
            return chunk

        with mock.patch.object(
            zipper,
            "_open_published",
            side_effect=capture_published,
        ), mock.patch.object(
            zipper,
            "_read_descriptor_chunk",
            side_effect=read_then_mutate,
        ):
            if os.name == "nt":
                zipper.build_deterministic_zip(self.source, output)
            else:
                with self.assertRaisesRegex(
                    zipper.DeterministicZipError,
                    "temporary archive changed while hashing",
                ):
                    zipper.build_deterministic_zip(self.source, output)

        self.assertTrue(write_attempted)
        if os.name == "nt":
            self.assertTrue(protected_write_denied)
            self.assertFalse(mutated)
            self.assertTrue(output.is_file())
        else:
            self.assertTrue(mutated)

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

    def test_refuses_symbolic_link_as_source_root_when_supported(self) -> None:
        link = self.root / "SankakuSyncer Portable source link"
        try:
            link.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symbolic links unavailable")
        output = self.root / "linked-source.zip"
        try:
            with self.assertRaisesRegex(
                zipper.DeterministicZipError, "source must be a plain directory"
            ):
                zipper.build_deterministic_zip(link, output)
            self.assertFalse(output.exists())
        finally:
            link.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
