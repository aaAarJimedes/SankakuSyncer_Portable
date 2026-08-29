# -*- coding: utf-8 -*-
"""Offline tests for bounded, read-only local thumbnail decoding."""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import unittest
from unittest import mock
import zlib

from PySide6.QtCore import QByteArray, QBuffer, QIODevice, QSize
from PySide6.QtGui import QColor, QImage

import library_thumbnail
import bound_file_reader
from bound_file_reader import BoundFileError, get_bound_root_identity
from library_thumbnail import (
    LibraryThumbnailError,
    MAX_THUMBNAIL_FILE_BYTES,
    MAX_THUMBNAIL_PNG_BYTES,
    MAX_THUMBNAIL_SOURCE_PIXELS,
    VerifiedThumbnailSource,
    load_library_thumbnail,
)
from sankaku_api import CancelledError


def _encoded_image(width: int, height: int, image_format: str = "PNG") -> bytes:
    image = QImage(width, height, QImage.Format_ARGB32)
    image.fill(QColor(25, 100, 220, 255))
    output = QByteArray()
    buffer = QBuffer(output)
    if not buffer.open(QIODevice.WriteOnly):
        raise AssertionError("test image buffer did not open")
    try:
        if not image.save(buffer, image_format):
            raise AssertionError(f"test runtime cannot encode {image_format}")
        return bytes(output)
    finally:
        buffer.close()


class LibraryThumbnailTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = self.temp_dir.name

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, name: str, payload: bytes) -> str:
        path = os.path.join(self.root, name)
        with open(path, "wb") as file_obj:
            file_obj.write(payload)
        return path

    def _source(self, name: str) -> VerifiedThumbnailSource:
        with open(os.path.join(self.root, name), "rb") as file_obj:
            payload = file_obj.read()
        return VerifiedThumbnailSource(
            relative_path=name,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            content_type={
                ".jpeg": "image/jpeg",
                ".jpg": "image/jpeg",
                ".png": "image/png",
                ".webp": "image/webp",
            }.get(os.path.splitext(name)[1].casefold(), "image/png"),
            root_identity=get_bound_root_identity(self.root),
        )

    def _record(self, name: str) -> VerifiedThumbnailSource:
        return VerifiedThumbnailSource(
            name,
            1,
            "0" * 64,
            "image/png",
            get_bound_root_identity(self.root),
        )

    def _load(self, name: str, stop_event=None, **kwargs):
        return load_library_thumbnail(
            self.root,
            self._source(name),
            stop_event,
            **kwargs,
        )

    def test_valid_png_is_scaled_in_memory_and_reports_source_dimensions(self):
        self._write("Post_1.png", _encoded_image(800, 400))
        before = sorted(os.listdir(self.root))

        result = self._load("Post_1.png", max_edge=120)

        self.assertEqual(result.relative_path, "Post_1.png")
        self.assertEqual(result.size, os.path.getsize(os.path.join(self.root, "Post_1.png")))
        self.assertEqual(result.sha256, self._source("Post_1.png").sha256)
        self.assertEqual((result.width, result.height), (800, 400))
        self.assertTrue(result.png_bytes.startswith(b"\x89PNG\r\n\x1a\n"))
        preview = QImage.fromData(result.png_bytes, "PNG")
        self.assertFalse(preview.isNull())
        self.assertEqual((preview.width(), preview.height()), (120, 60))
        self.assertLessEqual(len(result.png_bytes), MAX_THUMBNAIL_PNG_BYTES)
        self.assertEqual(sorted(os.listdir(self.root)), before)

    def test_preview_is_bound_to_verified_size_and_sha256(self):
        original = _encoded_image(40, 20)
        path = self._write("Post_bound.png", original)
        source = self._source("Post_bound.png")

        changed = bytearray(original)
        changed[-5] ^= 1
        self._write("Post_bound.png", bytes(changed))
        self.assertEqual(os.path.getsize(path), source.size)
        with mock.patch("library_thumbnail._decode_image") as decode:
            with self.assertRaisesRegex(
                LibraryThumbnailError, "安全读取|已验证报告"
            ):
                load_library_thumbnail(self.root, source)
        decode.assert_not_called()

        for invalid in (
            VerifiedThumbnailSource(
                "Post_bound.png",
                True,
                "0" * 64,
                "image/png",
                get_bound_root_identity(self.root),
            ),
            VerifiedThumbnailSource(
                "Post_bound.png",
                1,
                "not-a-sha256",
                "image/png",
                get_bound_root_identity(self.root),
            ),
            VerifiedThumbnailSource(
                "Post_bound.png",
                1,
                "0" * 64,
                "image/jpeg",
                get_bound_root_identity(self.root),
            ),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(LibraryThumbnailError, "验证来源无效"):
                    load_library_thumbnail(self.root, invalid)

    def test_compressed_png_metadata_is_rejected_before_qt_decode(self):
        payload = _encoded_image(8, 8)
        compressed = zlib.compress(b"A" * 4_000_000, level=9)
        data = b"comment\x00\x00" + compressed
        chunk_type = b"zTXt"
        checksum = zlib.crc32(chunk_type)
        checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
        chunk = (
            struct.pack(">I", len(data))
            + chunk_type
            + data
            + struct.pack(">I", checksum)
        )
        iend = payload.rfind(b"\x00\x00\x00\x00IEND")
        self.assertGreater(iend, 0)
        self._write("Post_metadata.png", payload[:iend] + chunk + payload[iend:])
        with mock.patch("library_thumbnail._decode_image") as decode:
            with self.assertRaisesRegex(LibraryThumbnailError, "安全策略"):
                self._load("Post_metadata.png")
        decode.assert_not_called()

    def test_decoder_rebuilds_a_metadata_free_pixel_image(self):
        source = QImage(12, 8, QImage.Format_ARGB32)
        source.fill(QColor(25, 100, 220, 255))
        source.setText("comment", "private metadata")
        output = QByteArray()
        buffer = QBuffer(output)
        self.assertTrue(buffer.open(QIODevice.WriteOnly))
        try:
            self.assertTrue(source.save(buffer, "PNG"))
        finally:
            buffer.close()
        image, width, height = library_thumbnail._decode_image(
            bytes(output),
            expected_format="png",
            stop_event=None,
            max_source_pixels=1_000_000,
            max_edge=360,
        )
        self.assertEqual((width, height), (12, 8))
        self.assertEqual(image.textKeys(), [])
        encoded = library_thumbnail._encode_png(image)
        round_trip = QImage.fromData(encoded, "PNG")
        self.assertFalse(round_trip.isNull())
        self.assertEqual(round_trip.textKeys(), [])

    def test_jpeg_is_accepted_but_format_extension_mismatch_is_rejected(self):
        try:
            jpeg = _encoded_image(80, 40, "JPEG")
        except AssertionError:
            self.skipTest("Qt JPEG encoder is unavailable")
        if not jpeg.startswith(b"\xff\xd8\xff"):
            self.skipTest("Qt JPEG encoder is unavailable")
        self._write("Post_2.jpg", jpeg)
        result = self._load("Post_2.jpg", max_edge=40)
        self.assertEqual((result.width, result.height), (80, 40))

        self._write("Post_mismatch.jpg", _encoded_image(20, 10))
        with self.assertRaisesRegex(LibraryThumbnailError, "格式与扩展名"):
            self._load("Post_mismatch.jpg")

    def test_file_and_parameter_limits_fail_before_decode(self):
        payload = _encoded_image(20, 10)
        self._write("Post_large.png", payload)
        with mock.patch("library_thumbnail._decode_image") as decode:
            with self.assertRaisesRegex(LibraryThumbnailError, "读取安全上限"):
                self._load(
                    "Post_large.png",
                    max_file_bytes=len(payload) - 1,
                )
        decode.assert_not_called()

        for keyword, value in (
            ("max_file_bytes", MAX_THUMBNAIL_FILE_BYTES + 1),
            ("max_source_pixels", MAX_THUMBNAIL_SOURCE_PIXELS + 1),
            ("max_edge", True),
        ):
            with self.subTest(keyword=keyword):
                with self.assertRaisesRegex(LibraryThumbnailError, "参数无效"):
                    self._load("Post_large.png", **{keyword: value})

    def test_pixel_bomb_is_rejected_before_reader_decodes(self):
        self._write("Post_pixels.png", _encoded_image(10, 10))
        reader = mock.Mock()
        reader.size.return_value = QSize(100_000, 100_000)
        with mock.patch("library_thumbnail.QImageReader", return_value=reader):
            with self.assertRaisesRegex(LibraryThumbnailError, "像素数量"):
                self._load("Post_pixels.png", max_source_pixels=1_000_000)
        reader.read.assert_not_called()

    def test_damaged_and_unsupported_formats_are_rejected(self):
        self._write("Post_bad.png", b"\x89PNG\r\n\x1a\nnot-an-image")
        with self.assertRaisesRegex(
            LibraryThumbnailError, "安全策略|无法识别|解码失败"
        ):
            self._load("Post_bad.png")

        self._write("Post_gif.gif", b"GIF89a" + b"\x00" * 20)
        with self.assertRaisesRegex(LibraryThumbnailError, "不是支持"):
            self._load("Post_gif.gif")

        self._write("Post_text.png", b"plain text")
        with self.assertRaisesRegex(LibraryThumbnailError, "格式与扩展名"):
            self._load("Post_text.png")

    def test_only_a_first_level_relative_basename_is_allowed(self):
        absolute = os.path.join(self.root, "Post_1.png")
        for value in (
            "nested/Post_1.png",
            "nested\\Post_1.png",
            "../Post_1.png",
            absolute,
            r"C:\private\Post_1.png",
            ".",
            "bad:name.png",
        ):
            with self.subTest(value=value):
                with self.assertRaises(LibraryThumbnailError):
                    load_library_thumbnail(self.root, self._record(value))

    def test_bound_reader_failure_is_rejected_before_decode(self):
        self._write("Post_changed.png", _encoded_image(20, 10))
        with mock.patch(
            "library_thumbnail.read_verified_child",
            side_effect=BoundFileError("private path detail"),
        ), mock.patch("library_thumbnail._decode_image") as decode:
            with self.assertRaisesRegex(LibraryThumbnailError, "安全读取"):
                self._load("Post_changed.png")
        decode.assert_not_called()

    def test_preflight_and_mid_read_cancellation_raise_cancelled_error(self):
        payload = _encoded_image(20, 10)
        self._write("Post_cancel.png", payload)
        stopped = threading.Event()
        stopped.set()
        with self.assertRaises(CancelledError):
            self._load("Post_cancel.png", stopped)

        large_payload = payload + b"x" * (bound_file_reader._READ_CHUNK_BYTES + 10)
        self._write("Post_mid.png", large_payload)
        stopped.clear()
        real_read = os.read
        read_calls = 0

        def cancelling_read(descriptor, size):
            nonlocal read_calls
            chunk = real_read(descriptor, size)
            read_calls += 1
            if read_calls == 1:
                stopped.set()
            return chunk

        with mock.patch("bound_file_reader.os.read", side_effect=cancelling_read):
            with self.assertRaises(CancelledError):
                self._load("Post_mid.png", stopped)
        self.assertEqual(read_calls, 1)

    def test_errors_do_not_echo_paths_exception_text_or_types(self):
        secret = os.path.join(self.root, "private-secret.png")
        with mock.patch(
            "library_thumbnail.read_verified_child",
            side_effect=BoundFileError(f"PRIVATE DETAIL {secret}"),
        ):
            with self.assertRaises(LibraryThumbnailError) as caught:
                load_library_thumbnail(
                    self.root, self._record("private-secret.png")
                )
        rendered = str(caught.exception)
        self.assertNotIn(self.root, rendered)
        self.assertNotIn("PRIVATE DETAIL", rendered)
        self.assertNotIn("OSError", rendered)

    def test_png_output_has_an_independent_size_limit(self):
        self._write("Post_output.png", _encoded_image(20, 10))
        oversized = b"x" * (MAX_THUMBNAIL_PNG_BYTES + 1)
        with mock.patch("library_thumbnail._encode_png", return_value=oversized):
            with self.assertRaisesRegex(LibraryThumbnailError, "PNG 输出"):
                self._load("Post_output.png")


if __name__ == "__main__":
    unittest.main()
