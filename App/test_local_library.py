# -*- coding: utf-8 -*-
"""Pure offline tests for deterministic, read-only local library scans."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from download_engine import LocalIntegrityError, LocalMetadataError
import local_library
from local_library import LibraryScanError, scan_download_library
from sankaku_api import CancelledError


JPEG = b"\xff\xd8\xffabc"
JPEG_ALT = b"\xff\xd8\xffxyz"


class LocalLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _write_media(self, filename: str, payload: bytes = JPEG) -> str:
        path = os.path.join(self.temp_dir.name, filename)
        with open(path, "wb") as file_obj:
            file_obj.write(payload)
        return path

    def _write_sidecar(
        self,
        filename: str,
        payload: bytes = JPEG,
        *,
        post_id: str | None = None,
        variant: str = "original",
        raw: bytes | None = None,
    ) -> str:
        path = os.path.join(self.temp_dir.name, filename + ".json")
        if raw is not None:
            with open(path, "wb") as file_obj:
                file_obj.write(raw)
            return path
        if post_id is None:
            stem = filename.rsplit(".", 1)[0]
            for suffix in (".sample", ".preview"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            post_id = stem.split(" (", 1)[0]
        document = {
            "schema_version": 2,
            "post_id": post_id,
            "variant": variant,
            "filename": filename,
            "content_type": "image/jpeg",
            "extension": "jpg",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "post": {
                "rating": "s",
                "status": "active",
                "width": 100,
                "height": 50,
                "tags": ["tag"],
                "author": "artist",
                "created_at": "1700000000",
                "is_premium": False,
            },
        }
        with open(path, "w", encoding="utf-8") as file_obj:
            json.dump(document, file_obj)
        return path

    def test_scan_reports_core_states_in_deterministic_order(self):
        verified = self._write_media("b_verified.jpg")
        self._write_sidecar("b_verified.jpg")
        missing_metadata = self._write_media("A_missing.jpg")
        changed = self._write_media("d_changed.jpg", JPEG_ALT)
        self._write_sidecar("d_changed.jpg", JPEG)
        invalid = self._write_media("c_invalid.jpg")
        self._write_sidecar("c_invalid.jpg", raw=b"not-json")
        orphan_sidecar = self._write_sidecar("e_orphan.jpg")
        with open(
            os.path.join(self.temp_dir.name, "notes.txt"),
            "w",
            encoding="utf-8",
        ) as file_obj:
            file_obj.write("ignored")
        os.mkdir(os.path.join(self.temp_dir.name, "nested"))
        with open(
            os.path.join(self.temp_dir.name, "nested", "Nested.jpg"), "wb"
        ) as file_obj:
            file_obj.write(JPEG)
        before: dict[str, bytes] = {}
        for path in (
            verified,
            verified + ".json",
            missing_metadata,
            changed,
            changed + ".json",
            invalid,
            invalid + ".json",
            orphan_sidecar,
        ):
            with open(path, "rb") as file_obj:
                before[path] = file_obj.read()
        progress: list[tuple[int, int, int]] = []

        report = scan_download_library(
            self.temp_dir.name,
            progress=lambda done, total, checked: progress.append(
                (done, total, checked)
            ),
        )

        self.assertEqual(
            [entry.relative_path for entry in report.entries],
            [
                "A_missing.jpg",
                "b_verified.jpg",
                "c_invalid.jpg",
                "d_changed.jpg",
                "e_orphan.jpg",
            ],
        )
        self.assertEqual(
            [entry.status for entry in report.entries],
            [
                "missing_metadata",
                "verified",
                "invalid_metadata",
                "changed",
                "missing_media",
            ],
        )
        self.assertEqual(report.scanned_candidates, 5)
        self.assertEqual(report.verified_count, 1)
        self.assertEqual(report.checked_bytes, len(JPEG) + len(JPEG_ALT))
        self.assertEqual(set(report.status_counts), set(local_library.LIBRARY_STATUSES))
        self.assertEqual(report.status_counts["verified"], 1)
        self.assertEqual(report.status_counts["missing_metadata"], 1)
        self.assertEqual(report.status_counts["invalid_metadata"], 1)
        self.assertEqual(report.status_counts["changed"], 1)
        self.assertEqual(report.status_counts["missing_media"], 1)
        self.assertEqual(
            progress,
            [
                (1, 5, 0),
                (2, 5, len(JPEG)),
                (3, 5, len(JPEG)),
                (4, 5, len(JPEG) + len(JPEG_ALT)),
                (5, 5, len(JPEG) + len(JPEG_ALT)),
            ],
        )
        for path, expected in before.items():
            with open(path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), expected)

    def test_verified_entry_carries_trusted_metadata(self):
        self._write_media("Post_1.sample (2).jpg")
        self._write_sidecar(
            "Post_1.sample (2).jpg",
            post_id="Post_1",
            variant="sample",
        )

        report = scan_download_library(self.temp_dir.name)

        self.assertEqual(report.verified_count, 1)
        entry = report.entries[0]
        self.assertEqual(entry.post_id, "Post_1")
        self.assertEqual(entry.variant, "sample")
        self.assertEqual(entry.content_type, "image/jpeg")
        self.assertEqual(entry.rating, "s")
        self.assertEqual(entry.author, "artist")
        self.assertEqual(entry.tags, ("tag",))
        self.assertEqual(entry.created_at, "1700000000")
        self.assertEqual(entry.sha256, hashlib.sha256(JPEG).hexdigest())

    def test_report_display_metadata_has_explicit_memory_bounds(self):
        self._write_media("Post_bounds.jpg")
        sidecar_path = self._write_sidecar("Post_bounds.jpg")
        with open(sidecar_path, "r", encoding="utf-8") as file_obj:
            document = json.load(file_obj)
        document["post"].update(
            {
                "rating": "r" * 100,
                "author": "a" * 2_000,
                "created_at": "c" * 500,
                "tags": ["t" * 200 for _index in range(100)],
            }
        )
        with open(sidecar_path, "w", encoding="utf-8") as file_obj:
            json.dump(document, file_obj)

        report = scan_download_library(self.temp_dir.name)

        entry = report.entries[0]
        self.assertEqual(entry.status, "verified")
        self.assertLessEqual(len(entry.rating), local_library.MAX_DISPLAY_RATING_CHARS)
        self.assertLessEqual(len(entry.author), local_library.MAX_DISPLAY_AUTHOR_CHARS)
        self.assertLessEqual(
            len(entry.created_at), local_library.MAX_DISPLAY_CREATED_AT_CHARS
        )
        self.assertLessEqual(len(entry.tags), local_library.MAX_DISPLAY_TAGS)
        self.assertTrue(
            all(
                len(tag) <= local_library.MAX_DISPLAY_TAG_CHARS
                for tag in entry.tags
            )
        )
        self.assertIn("安全上限", entry.detail)

    def test_unhashable_variant_is_invalid_and_does_not_abort_scan(self):
        self._write_media("a_bad.jpg")
        bad_sidecar = self._write_sidecar("a_bad.jpg")
        with open(bad_sidecar, "r", encoding="utf-8") as file_obj:
            document = json.load(file_obj)
        document["variant"] = {}
        with open(bad_sidecar, "w", encoding="utf-8") as file_obj:
            json.dump(document, file_obj)
        self._write_media("b_good.jpg")
        self._write_sidecar("b_good.jpg")

        report = scan_download_library(self.temp_dir.name)

        self.assertEqual(
            [entry.status for entry in report.entries],
            ["invalid_metadata", "verified"],
        )
        self.assertEqual(report.verified_count, 1)

    def test_deep_json_is_invalid_and_does_not_abort_scan(self):
        self._write_media("a_deep.jpg")
        deeply_nested = b"[" * 10_000 + b"0" + b"]" * 10_000
        self._write_sidecar("a_deep.jpg", raw=deeply_nested)
        self._write_media("b_good.jpg")
        self._write_sidecar("b_good.jpg")

        report = scan_download_library(self.temp_dir.name)

        self.assertEqual(
            [entry.status for entry in report.entries],
            ["invalid_metadata", "verified"],
        )
        self.assertEqual(report.verified_count, 1)

    def test_exception_statuses_are_preserved_for_user_facing_report(self):
        self._write_media("a.jpg")
        self._write_media("b.jpg")
        failures = [
            LocalIntegrityError("unsafe", status="unsafe_path"),
            LocalIntegrityError("denied", status="unreadable"),
        ]

        with mock.patch(
            "local_library.verify_local_download", side_effect=failures
        ):
            report = scan_download_library(self.temp_dir.name)

        self.assertEqual(
            [entry.status for entry in report.entries],
            ["unsafe_path", "unreadable"],
        )
        self.assertEqual(report.status_counts["unsafe_path"], 1)
        self.assertEqual(report.status_counts["unreadable"], 1)

    def test_candidate_and_directory_limits_fail_instead_of_partial_results(self):
        self._write_media("a.jpg")
        self._write_media("b.jpg")
        with mock.patch.object(local_library, "MAX_LIBRARY_CANDIDATES", 1), mock.patch(
            "local_library.verify_local_download"
        ) as verify:
            with self.assertRaisesRegex(LibraryScanError, "候选"):
                scan_download_library(self.temp_dir.name)
            verify.assert_not_called()

        with mock.patch.object(local_library, "MAX_DIRECTORY_ENTRIES", 1), mock.patch(
            "local_library.verify_local_download"
        ) as verify:
            with self.assertRaisesRegex(LibraryScanError, "项目"):
                scan_download_library(self.temp_dir.name)
            verify.assert_not_called()

    def test_pre_cancelled_scan_never_enumerates_directory(self):
        stop_event = threading.Event()
        stop_event.set()

        with mock.patch("local_library.os.scandir") as scandir:
            with self.assertRaises(CancelledError):
                scan_download_library(self.temp_dir.name, stop_event=stop_event)
            scandir.assert_not_called()

    def test_cancellation_between_candidates_returns_no_partial_report(self):
        self._write_media("a.jpg")
        self._write_media("b.jpg")
        stop_event = threading.Event()
        calls: list[str] = []

        def cancel_first(path: str, **_kwargs):
            calls.append(os.path.basename(path))
            stop_event.set()
            raise LocalMetadataError("missing", status="missing_metadata")

        with mock.patch(
            "local_library.verify_local_download", side_effect=cancel_first
        ):
            with self.assertRaises(CancelledError):
                scan_download_library(self.temp_dir.name, stop_event=stop_event)

        self.assertEqual(calls, ["a.jpg"])

    def test_file_as_root_is_rejected(self):
        path = os.path.join(self.temp_dir.name, "not-a-directory")
        with open(path, "wb") as file_obj:
            file_obj.write(b"x")

        with self.assertRaisesRegex(LibraryScanError, "不安全"):
            scan_download_library(path)

    def test_root_identity_replacement_aborts_without_partial_report(self):
        self._write_media("Post_1.jpg")
        original = os.lstat(self.temp_dir.name)
        replacement = SimpleNamespace(
            st_mode=original.st_mode,
            st_dev=original.st_dev,
            st_ino=original.st_ino + 1,
            st_file_attributes=0,
        )

        with mock.patch(
            "local_library.os.lstat", side_effect=[original, replacement]
        ), mock.patch("local_library.verify_local_download") as verify:
            with self.assertRaisesRegex(LibraryScanError, "被替换"):
                scan_download_library(self.temp_dir.name)
            verify.assert_not_called()

    def test_orphan_sidecar_and_media_pair_count_as_one_candidate(self):
        self._write_media("Post_1.jpg")
        self._write_sidecar("Post_1.jpg")

        report = scan_download_library(self.temp_dir.name)

        self.assertEqual(report.scanned_candidates, 1)
        self.assertEqual(report.verified_count, 1)

    def test_uppercase_orphan_sidecar_is_reported_as_missing_media(self):
        sidecar_path = os.path.join(self.temp_dir.name, "Orphan.jpg.JSON")
        with open(sidecar_path, "wb") as file_obj:
            file_obj.write(b"{}")

        report = scan_download_library(self.temp_dir.name)

        self.assertEqual(report.scanned_candidates, 1)
        self.assertEqual(report.entries[0].relative_path, "Orphan.jpg")
        self.assertEqual(report.entries[0].status, "missing_media")

    def test_default_candidate_limit_is_ui_safe(self):
        self.assertEqual(local_library.MAX_LIBRARY_CANDIDATES, 10_000)


if __name__ == "__main__":
    unittest.main()
