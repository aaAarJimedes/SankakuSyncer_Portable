# -*- coding: utf-8 -*-
"""Offline structural tests for the metadata-free thumbnail policy."""

from __future__ import annotations

import base64
import struct
import unittest
import zlib

from image_metadata_policy import (
    ImageMetadataPolicyError,
    validate_minimum_image_container,
    validate_thumbnail_payload,
)


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type)
    checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", checksum)
    )


def _plain_png(*extra_chunks: tuple[bytes, bytes]) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    image_data = zlib.compress(b"\x00\x11\x22\x33\xff")
    chunks = [_png_chunk(b"IHDR", ihdr)]
    chunks.extend(_png_chunk(kind, data) for kind, data in extra_chunks)
    chunks.extend((_png_chunk(b"IDAT", image_data), _png_chunk(b"IEND", b"")))
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def _jpeg_segment(marker: int, data: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(data) + 2) + data


def _jpeg_dqt() -> bytes:
    return _jpeg_segment(0xDB, b"\x00" + bytes(range(1, 65)))


def _jpeg_dht() -> bytes:
    dc = b"\x00" + bytes((1,)) + b"\x00" * 15 + b"\x00"
    ac = b"\x10" + bytes((1,)) + b"\x00" * 15 + b"\x00"
    return _jpeg_segment(0xC4, dc + ac)


def _jpeg_sof(marker: int = 0xC0) -> bytes:
    data = b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    return _jpeg_segment(marker, data)


def _jpeg_sos(*, spectral_start=0, spectral_end=63) -> bytes:
    data = bytes((1, 1, 0, spectral_start, spectral_end, 0))
    return _jpeg_segment(0xDA, data)


def _synthetic_jpeg(*, progressive=False, app_prefix=b"") -> bytes:
    sof = _jpeg_sof(0xC2 if progressive else 0xC0)
    first_end = 0 if progressive else 63
    payload = (
        b"\xff\xd8"
        + app_prefix
        + _jpeg_dqt()
        + sof
        + _jpeg_dht()
        + _jpeg_sos(spectral_start=0, spectral_end=first_end)
        + b"\x11\xff\x00\x22\xff\xd0\x33"
    )
    if progressive:
        payload += (
            _jpeg_sos(spectral_start=1, spectral_end=63)
            + b"\x44\xff\xd7\x55"
        )
    return payload + b"\xff\xd9"


def _webp_chunk(chunk_type: bytes, data: bytes) -> bytes:
    padding = b"\x00" if len(data) & 1 else b""
    return chunk_type + struct.pack("<I", len(data)) + data + padding


def _webp(*chunks: bytes) -> bytes:
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _vp8_payload(extra=b"") -> bytes:
    return b"\x10\x00\x00\x9d\x01\x2a\x01\x00\x01\x00" + extra


class ImageMetadataPolicyTests(unittest.TestCase):
    def test_minimum_container_boundaries_cover_supported_rasters(self):
        gif = base64.b64decode(
            b"R0lGODdhAQABAIEAAAECAwAAAAAAAAAAACwAAAAAAQABAAAIBAABBAQAOw=="
        )
        fixtures = (
            ("jpeg", _synthetic_jpeg()),
            ("png", _plain_png()),
            ("gif", gif),
            ("webp", _webp(_webp_chunk(b"VP8 ", _vp8_payload()))),
        )
        for image_format, payload in fixtures:
            with self.subTest(image_format=image_format):
                validate_minimum_image_container(
                    image_format,
                    size=len(payload),
                    prefix=payload[:12],
                    suffix=payload[-12:],
                )
                for damaged in (
                    payload[:-1],
                    payload + b"trailing",
                ):
                    with self.assertRaisesRegex(
                        ImageMetadataPolicyError, "边界不完整"
                    ):
                        validate_minimum_image_container(
                            image_format,
                            size=len(damaged),
                            prefix=damaged[:12],
                            suffix=damaged[-12:],
                        )

    def test_minimum_container_rejects_header_only_and_bad_webp_length(self):
        header_only = (
            ("jpeg", b"\xff\xd8\xff"),
            ("png", b"\x89PNG\r\n\x1a\n"),
            ("gif", b"GIF89a"),
            ("webp", b"RIFF\x04\x00\x00\x00WEBP"),
        )
        for image_format, payload in header_only:
            with self.subTest(image_format=image_format), self.assertRaisesRegex(
                ImageMetadataPolicyError, "边界不完整"
            ):
                validate_minimum_image_container(
                    image_format,
                    size=len(payload),
                    prefix=payload[:12],
                    suffix=payload[-12:],
                )

        valid = _webp(_webp_chunk(b"VP8 ", _vp8_payload()))
        bad_size = bytearray(valid)
        struct.pack_into("<I", bad_size, 4, len(valid) - 9)
        with self.assertRaisesRegex(ImageMetadataPolicyError, "边界不完整"):
            validate_minimum_image_container(
                "image/webp",
                size=len(bad_size),
                prefix=bytes(bad_size[:12]),
                suffix=bytes(bad_size[-12:]),
            )

    def test_minimum_container_arguments_are_fixed_and_redacted(self):
        secret = b"PRIVATE_BOUNDARY_SECRET"
        cases = (
            (None, 30, b"\xff\xd8\xff", b"\xff\xd9"),
            ("jpeg", True, b"\xff\xd8\xff", b"\xff\xd9"),
            ("jpeg", 1, secret, b""),
            ("bmp", 30, b"BM", b""),
        )
        for image_format, size, prefix, suffix in cases:
            with self.subTest(image_format=image_format), self.assertRaises(
                ImageMetadataPolicyError
            ) as caught:
                validate_minimum_image_container(
                    image_format,
                    size=size,
                    prefix=prefix,
                    suffix=suffix,
                )
            self.assertNotIn("PRIVATE_BOUNDARY_SECRET", str(caught.exception))

    def test_plain_png_passes(self):
        validate_thumbnail_payload(_plain_png(), "png")

    def test_png_rejects_small_high_compression_text_metadata(self):
        compressed = zlib.compress(b"A" * 1_000_000, level=9)
        ztxt = b"comment\x00\x00" + compressed
        itxt = b"comment\x00\x01\x00\x00\x00" + compressed
        self.assertLess(len(ztxt), 2_000)
        self.assertLess(len(itxt), 2_000)
        for chunk_type, data in ((b"zTXt", ztxt), (b"iTXt", itxt)):
            with self.subTest(chunk=chunk_type):
                with self.assertRaisesRegex(ImageMetadataPolicyError, "PNG 结构"):
                    validate_thumbnail_payload(
                        _plain_png((chunk_type, data)), "png"
                    )

    def test_png_rejects_metadata_animation_unknown_crc_and_bad_boundaries(self):
        for chunk_type in (
            b"tEXt",
            b"iCCP",
            b"eXIf",
            b"acTL",
            b"fcTL",
            b"fdAT",
        ):
            with self.subTest(chunk=chunk_type):
                with self.assertRaises(ImageMetadataPolicyError):
                    validate_thumbnail_payload(
                        _plain_png((chunk_type, b"metadata")), "png"
                    )

        valid = _plain_png()
        corrupt_crc = bytearray(valid)
        corrupt_crc[-1] ^= 1
        duplicate_ihdr = _plain_png(
            (b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        )
        cases = (
            valid[:-1],
            valid + b"trailing",
            bytes(corrupt_crc),
            duplicate_ihdr,
            b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 0xFFFFFFFF) + b"IDAT",
        )
        for index, payload in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, "png")

        for chunk_type, data in (
            (b"pHYs", struct.pack(">IIB", 3780, 3780, 1)),
            (b"gAMA", struct.pack(">I", 45455)),
            (b"cHRM", struct.pack(">8I", *([1] * 8))),
            (b"sRGB", b"\x00"),
        ):
            with self.subTest(safe_chunk=chunk_type):
                validate_thumbnail_payload(_plain_png((chunk_type, data)), "png")

        with self.assertRaises(ImageMetadataPolicyError):
            validate_thumbnail_payload(_plain_png((b"pHYs", b"short")), "png")

    def test_jpeg_entropy_stuffing_restart_and_progressive_scan_boundaries_pass(self):
        validate_thumbnail_payload(_synthetic_jpeg(), "jpeg")
        validate_thumbnail_payload(_synthetic_jpeg(progressive=True), "jpg")

    def test_runtime_jpeg_encoder_output_passes_when_available(self):
        from PySide6.QtCore import QByteArray, QBuffer, QIODevice
        from PySide6.QtGui import QColor, QImage

        image = QImage(8, 6, QImage.Format_RGB32)
        image.fill(QColor(30, 90, 180))
        output = QByteArray()
        buffer = QBuffer(output)
        self.assertTrue(buffer.open(QIODevice.WriteOnly))
        try:
            if not image.save(buffer, "JPEG"):
                self.skipTest("Qt JPEG encoder is unavailable")
        finally:
            buffer.close()
        validate_thumbnail_payload(bytes(output), "jpeg")

    def test_jpeg_allows_only_one_bounded_app0_and_app14(self):
        app0 = _jpeg_segment(0xE0, b"JFIF\x00")
        app14 = _jpeg_segment(0xEE, b"Adobe")
        validate_thumbnail_payload(
            _synthetic_jpeg(app_prefix=app0 + app14), "jpeg"
        )
        rejected = (
            _synthetic_jpeg(app_prefix=app0 + app0),
            _synthetic_jpeg(app_prefix=_jpeg_segment(0xEE, b"x" * 65)),
            _synthetic_jpeg(app_prefix=_jpeg_segment(0xE1, b"Exif\x00\x00")),
            _synthetic_jpeg(app_prefix=_jpeg_segment(0xFE, b"comment")),
        )
        for index, payload in enumerate(rejected):
            with self.subTest(case=index), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, "jpeg")

    def test_jpeg_rejects_truncation_missing_structure_unknown_and_trailing(self):
        valid = _synthetic_jpeg()
        no_sof = b"\xff\xd8" + _jpeg_sos() + b"\x11\xff\xd9"
        no_sos = b"\xff\xd8" + _jpeg_sof() + b"\xff\xd9"
        unknown = (
            b"\xff\xd8"
            + _jpeg_segment(0xC8, b"")
            + _jpeg_sof()
            + _jpeg_sos()
            + b"\x11\xff\xd9"
        )
        cases = (
            valid[:-1],
            valid[:-2],
            valid + b"trailing",
            no_sof,
            no_sos,
            unknown,
            b"\xff\xd8\xff\xe0\x00\x01\xff\xd9",
            b"\xff\xd8\xff\xdb\x00\x43\x00" + b"\x01" * 10,
        )
        for index, payload in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, "jpeg")

    def test_simple_and_extended_metadata_free_webp_structures_pass(self):
        validate_thumbnail_payload(
            _webp(_webp_chunk(b"VP8 ", _vp8_payload())), "webp"
        )
        validate_thumbnail_payload(
            _webp(_webp_chunk(b"VP8L", b"\x2f\x00\x00\x00\x00")),
            "webp",
        )
        vp8x = b"\x10\x00\x00\x00" + b"\x00" * 6
        validate_thumbnail_payload(
            _webp(
                _webp_chunk(b"VP8X", vp8x),
                _webp_chunk(b"ALPH", b"\x00"),
                _webp_chunk(b"VP8 ", _vp8_payload()),
            ),
            "webp",
        )

    def test_runtime_webp_encoder_output_passes_when_available(self):
        from PySide6.QtCore import QByteArray, QBuffer, QIODevice
        from PySide6.QtGui import QColor, QImage

        image = QImage(8, 6, QImage.Format_RGB32)
        image.fill(QColor(30, 90, 180))
        output = QByteArray()
        buffer = QBuffer(output)
        self.assertTrue(buffer.open(QIODevice.WriteOnly))
        try:
            if not image.save(buffer, "WEBP"):
                self.skipTest("Qt WebP encoder is unavailable")
        finally:
            buffer.close()
        validate_thumbnail_payload(bytes(output), "webp")

    def test_webp_rejects_metadata_animation_unknown_flags_and_multiple_main_data(self):
        main = _webp_chunk(b"VP8 ", _vp8_payload())
        for chunk_type in (b"ICCP", b"EXIF", b"XMP ", b"ANIM", b"ANMF", b"JUNK"):
            with self.subTest(chunk=chunk_type), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(
                    _webp(_webp_chunk(chunk_type, b"metadata"), main),
                    "webp",
                )

        bad_flags = b"\x20\x00\x00\x00" + b"\x00" * 6
        rejected = (
            _webp(main, main),
            _webp(
                _webp_chunk(b"VP8X", bad_flags),
                _webp_chunk(b"ALPH", b"\x00"),
                main,
            ),
            _webp(_webp_chunk(b"VP8X", b"\x00" * 10), main),
            _webp(_webp_chunk(b"ALPH", b"\x00"), main),
        )
        for index, payload in enumerate(rejected):
            with self.subTest(case=index), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, "webp")

    def test_webp_riff_size_padding_truncation_and_trailing_are_strict(self):
        odd_main = _webp(_webp_chunk(b"VP8 ", _vp8_payload(b"x")))
        bad_padding = bytearray(odd_main)
        bad_padding[-1] = 1
        bad_size = bytearray(odd_main)
        struct.pack_into("<I", bad_size, 4, len(odd_main) - 9)
        data = _vp8_payload(b"x")
        missing_pad_body = b"WEBP" + b"VP8 " + struct.pack("<I", len(data)) + data
        missing_pad = b"RIFF" + struct.pack("<I", len(missing_pad_body)) + missing_pad_body
        cases = (
            bytes(bad_padding),
            bytes(bad_size),
            odd_main[:-1],
            odd_main + b"trailing",
            missing_pad,
        )
        for index, payload in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, "webp")

    def test_errors_are_fixed_and_never_echo_payload(self):
        secret = b"PRIVATE_PAYLOAD_SECRET"
        for image_format in ("png", "jpeg", "webp"):
            with self.subTest(image_format=image_format):
                with self.assertRaises(ImageMetadataPolicyError) as caught:
                    validate_thumbnail_payload(secret, image_format)
                self.assertNotIn("PRIVATE_PAYLOAD_SECRET", str(caught.exception))

        for payload, image_format in (
            (bytearray(b"x"), "png"),
            (b"x", "gif"),
            (b"x", None),
        ):
            with self.subTest(image_format=image_format), self.assertRaises(
                ImageMetadataPolicyError
            ):
                validate_thumbnail_payload(payload, image_format)


if __name__ == "__main__":
    unittest.main()
