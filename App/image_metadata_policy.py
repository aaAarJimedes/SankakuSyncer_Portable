# -*- coding: utf-8 -*-
"""Strict, metadata-free structural policy for thumbnail image payloads."""

from __future__ import annotations

import struct
import zlib


MAX_POLICY_PAYLOAD_BYTES = 20 * 1024 * 1024
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_ALLOWED_CHUNKS = frozenset(
    {
        b"IHDR",
        b"PLTE",
        b"IDAT",
        b"IEND",
        b"tRNS",
        b"cHRM",
        b"gAMA",
        b"pHYs",
        b"sRGB",
    }
)
_PNG_FIXED_SAFE_CHUNKS = {
    b"cHRM": 32,
    b"gAMA": 4,
    b"pHYs": 9,
    b"sRGB": 1,
}
_JPEG_SOF_MARKERS = frozenset({0xC0, 0xC1, 0xC2})
_JPEG_SEGMENT_MARKERS = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC4, 0xDA, 0xDB, 0xDD, 0xE0, 0xEE}
)


class ImageMetadataPolicyError(ValueError):
    """An image structure is outside the metadata-free thumbnail policy."""


def validate_thumbnail_payload(payload: bytes, image_format: str) -> None:
    """Validate one bounded image without decoding pixels or metadata."""

    if type(payload) is not bytes or not payload:
        raise ImageMetadataPolicyError("缩略图载荷无效")
    if len(payload) > MAX_POLICY_PAYLOAD_BYTES:
        raise ImageMetadataPolicyError("缩略图载荷超过安全上限")
    if not isinstance(image_format, str):
        raise ImageMetadataPolicyError("缩略图格式无效")
    normalized = image_format.casefold()
    if normalized == "png":
        _validate_png(payload)
        return
    if normalized in {"jpeg", "jpg"}:
        _validate_jpeg(payload)
        return
    if normalized == "webp":
        _validate_webp(payload)
        return
    raise ImageMetadataPolicyError("缩略图格式不受支持")


def _png_error() -> None:
    raise ImageMetadataPolicyError("PNG 结构不符合缩略图安全策略")


def _validate_png(payload: bytes) -> None:
    if not payload.startswith(_PNG_SIGNATURE):
        _png_error()
    cursor = len(_PNG_SIGNATURE)
    chunk_index = 0
    saw_ihdr = False
    saw_plte = False
    saw_trns = False
    saw_idat = False
    safe_chunks: set[bytes] = set()
    idat_bytes = 0
    color_type = -1

    while cursor < len(payload):
        if len(payload) - cursor < 12:
            _png_error()
        length = struct.unpack_from(">I", payload, cursor)[0]
        chunk_type = payload[cursor + 4 : cursor + 8]
        data_start = cursor + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if data_end < data_start or crc_end > len(payload):
            _png_error()
        chunk_data = memoryview(payload)[data_start:data_end]
        expected_crc = struct.unpack_from(">I", payload, data_end)[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc or chunk_type not in _PNG_ALLOWED_CHUNKS:
            _png_error()

        if chunk_index == 0 and chunk_type != b"IHDR":
            _png_error()
        if chunk_type == b"IHDR":
            if saw_ihdr or chunk_index != 0 or length != 13:
                _png_error()
            width, height = struct.unpack_from(">II", chunk_data, 0)
            bit_depth = chunk_data[8]
            color_type = chunk_data[9]
            compression = chunk_data[10]
            filter_method = chunk_data[11]
            interlace = chunk_data[12]
            allowed_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width == 0
                or height == 0
                or width > 0x7FFFFFFF
                or height > 0x7FFFFFFF
                or color_type not in allowed_depths
                or bit_depth not in allowed_depths[color_type]
                or compression != 0
                or filter_method != 0
                or interlace not in {0, 1}
            ):
                _png_error()
            saw_ihdr = True
        elif not saw_ihdr:
            _png_error()
        elif chunk_type == b"PLTE":
            if (
                saw_plte
                or saw_idat
                or color_type in {0, 4}
                or length == 0
                or length > 768
                or length % 3
            ):
                _png_error()
            saw_plte = True
        elif chunk_type == b"tRNS":
            if saw_trns or saw_idat or length == 0 or length > 256:
                _png_error()
            if (
                color_type in {4, 6}
                or (color_type == 0 and length != 2)
                or (color_type == 2 and length != 6)
                or (color_type == 3 and not saw_plte)
                or (color_type == 3 and length > 256)
            ):
                _png_error()
            saw_trns = True
        elif chunk_type in _PNG_FIXED_SAFE_CHUNKS:
            if (
                saw_idat
                or chunk_type in safe_chunks
                or length != _PNG_FIXED_SAFE_CHUNKS[chunk_type]
                or (chunk_type == b"gAMA" and bytes(chunk_data) == b"\x00" * 4)
                or (chunk_type == b"pHYs" and chunk_data[8] not in {0, 1})
                or (chunk_type == b"sRGB" and chunk_data[0] > 3)
            ):
                _png_error()
            safe_chunks.add(chunk_type)
        elif chunk_type == b"IDAT":
            if length == 0:
                _png_error()
            saw_idat = True
            idat_bytes += length
        elif chunk_type == b"IEND":
            if length != 0 or not saw_idat or idat_bytes <= 0:
                _png_error()
            cursor = crc_end
            if cursor != len(payload):
                _png_error()
            if color_type == 3 and not saw_plte:
                _png_error()
            return
        cursor = crc_end
        chunk_index += 1
    _png_error()


def _jpeg_error() -> None:
    raise ImageMetadataPolicyError("JPEG 结构不符合缩略图安全策略")


def _jpeg_segment(payload: bytes, cursor: int) -> tuple[bytes, int]:
    if len(payload) - cursor < 2:
        _jpeg_error()
    length = struct.unpack_from(">H", payload, cursor)[0]
    if length < 2:
        _jpeg_error()
    end = cursor + length
    if end < cursor or end > len(payload):
        _jpeg_error()
    return payload[cursor + 2 : end], end


def _validate_dqt(segment: bytes) -> None:
    cursor = 0
    tables = 0
    while cursor < len(segment):
        info = segment[cursor]
        cursor += 1
        precision = info >> 4
        table_id = info & 0x0F
        if precision not in {0, 1} or table_id > 3:
            _jpeg_error()
        size = 64 * (precision + 1)
        if len(segment) - cursor < size:
            _jpeg_error()
        cursor += size
        tables += 1
    if cursor != len(segment) or tables == 0:
        _jpeg_error()


def _validate_dht(segment: bytes) -> None:
    cursor = 0
    tables = 0
    while cursor < len(segment):
        if len(segment) - cursor < 17:
            _jpeg_error()
        info = segment[cursor]
        cursor += 1
        table_class = info >> 4
        table_id = info & 0x0F
        if table_class not in {0, 1} or table_id > 3:
            _jpeg_error()
        symbol_count = sum(segment[cursor : cursor + 16])
        cursor += 16
        if symbol_count <= 0 or symbol_count > 256:
            _jpeg_error()
        if len(segment) - cursor < symbol_count:
            _jpeg_error()
        cursor += symbol_count
        tables += 1
    if cursor != len(segment) or tables == 0:
        _jpeg_error()


def _validate_sof(segment: bytes) -> None:
    if len(segment) < 6:
        _jpeg_error()
    precision = segment[0]
    height = struct.unpack_from(">H", segment, 1)[0]
    width = struct.unpack_from(">H", segment, 3)[0]
    components = segment[5]
    if (
        precision != 8
        or width == 0
        or height == 0
        or components not in {1, 2, 3, 4}
        or len(segment) != 6 + 3 * components
    ):
        _jpeg_error()
    identifiers: set[int] = set()
    for index in range(components):
        base = 6 + index * 3
        identifier = segment[base]
        horizontal = segment[base + 1] >> 4
        vertical = segment[base + 1] & 0x0F
        table_id = segment[base + 2]
        if (
            identifier in identifiers
            or horizontal not in {1, 2, 3, 4}
            or vertical not in {1, 2, 3, 4}
            or table_id > 3
        ):
            _jpeg_error()
        identifiers.add(identifier)


def _validate_sos(segment: bytes) -> None:
    if not segment:
        _jpeg_error()
    components = segment[0]
    if components not in {1, 2, 3, 4} or len(segment) != 1 + 2 * components + 3:
        _jpeg_error()
    identifiers: set[int] = set()
    for index in range(components):
        identifier = segment[1 + index * 2]
        table_selectors = segment[2 + index * 2]
        if (
            identifier in identifiers
            or table_selectors >> 4 > 3
            or table_selectors & 0x0F > 3
        ):
            _jpeg_error()
        identifiers.add(identifier)
    spectral_start = segment[-3]
    spectral_end = segment[-2]
    approximation = segment[-1]
    if spectral_start > 63 or spectral_end > 63 or approximation >> 4 > 13 or approximation & 0x0F > 13:
        _jpeg_error()


def _next_entropy_marker(payload: bytes, cursor: int) -> int:
    while cursor < len(payload):
        if payload[cursor] != 0xFF:
            cursor += 1
            continue
        cursor += 1
        while cursor < len(payload) and payload[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(payload):
            _jpeg_error()
        marker = payload[cursor]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            cursor += 1
            continue
        return cursor - 1
    _jpeg_error()
    raise AssertionError("unreachable")


def _validate_jpeg(payload: bytes) -> None:
    if len(payload) < 4 or payload[:2] != b"\xff\xd8":
        _jpeg_error()
    cursor = 2
    saw_sof = False
    saw_sos = False
    saw_app0 = False
    saw_app14 = False

    while cursor < len(payload):
        if payload[cursor] != 0xFF:
            _jpeg_error()
        while cursor < len(payload) and payload[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(payload):
            _jpeg_error()
        marker = payload[cursor]
        cursor += 1
        if marker == 0xD9:
            if not saw_sof or not saw_sos or cursor != len(payload):
                _jpeg_error()
            return
        if (
            marker in {0x00, 0x01, 0xD8}
            or 0xD0 <= marker <= 0xD7
            or 0xE1 <= marker <= 0xED
            or marker == 0xEF
            or marker == 0xFE
            or marker not in _JPEG_SEGMENT_MARKERS
        ):
            _jpeg_error()
        segment, cursor = _jpeg_segment(payload, cursor)
        if marker == 0xE0:
            if saw_app0 or saw_sos or len(segment) > 64 * 1024:
                _jpeg_error()
            saw_app0 = True
        elif marker == 0xEE:
            if saw_app14 or saw_sos or len(segment) > 64:
                _jpeg_error()
            saw_app14 = True
        elif marker in _JPEG_SOF_MARKERS:
            if saw_sof or saw_sos:
                _jpeg_error()
            _validate_sof(segment)
            saw_sof = True
        elif marker == 0xDB:
            _validate_dqt(segment)
        elif marker == 0xC4:
            _validate_dht(segment)
        elif marker == 0xDD:
            if len(segment) != 2:
                _jpeg_error()
        elif marker == 0xDA:
            if not saw_sof:
                _jpeg_error()
            _validate_sos(segment)
            saw_sos = True
            cursor = _next_entropy_marker(payload, cursor)
    _jpeg_error()


def _webp_error() -> None:
    raise ImageMetadataPolicyError("WebP 结构不符合缩略图安全策略")


def _validate_vp8(data: bytes) -> None:
    if (
        len(data) < 10
        or data[3:6] != b"\x9d\x01\x2a"
        or struct.unpack_from("<H", data, 6)[0] & 0x3FFF == 0
        or struct.unpack_from("<H", data, 8)[0] & 0x3FFF == 0
    ):
        _webp_error()


def _validate_vp8l(data: bytes) -> None:
    if len(data) < 5 or data[0] != 0x2F:
        _webp_error()


def _validate_webp(payload: bytes) -> None:
    if (
        len(payload) < 20
        or payload[:4] != b"RIFF"
        or payload[8:12] != b"WEBP"
        or struct.unpack_from("<I", payload, 4)[0] != len(payload) - 8
    ):
        _webp_error()
    cursor = 12
    chunks: list[tuple[bytes, memoryview]] = []
    while cursor < len(payload):
        if len(payload) - cursor < 8:
            _webp_error()
        chunk_type = payload[cursor : cursor + 4]
        length = struct.unpack_from("<I", payload, cursor + 4)[0]
        data_start = cursor + 8
        data_end = data_start + length
        padded_end = data_end + (length & 1)
        if data_end < data_start or padded_end > len(payload):
            _webp_error()
        if length & 1 and payload[data_end] != 0:
            _webp_error()
        chunks.append((chunk_type, memoryview(payload)[data_start:data_end]))
        cursor = padded_end
    if cursor != len(payload) or not chunks:
        _webp_error()

    chunk_types = [chunk_type for chunk_type, _data in chunks]
    allowed = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH"}
    if any(chunk_type not in allowed for chunk_type in chunk_types):
        _webp_error()
    main_count = chunk_types.count(b"VP8 ") + chunk_types.count(b"VP8L")
    if main_count != 1:
        _webp_error()

    if chunk_types == [b"VP8 "]:
        _validate_vp8(chunks[0][1])
        return
    if chunk_types == [b"VP8L"]:
        _validate_vp8l(chunks[0][1])
        return
    if chunk_types != [b"VP8X", b"ALPH", b"VP8 "]:
        _webp_error()
    vp8x = chunks[0][1]
    alpha = chunks[1][1]
    if (
        len(vp8x) != 10
        or vp8x[0] != 0x10
        or vp8x[1:4] != b"\x00\x00\x00"
        or not alpha
    ):
        _webp_error()
    _validate_vp8(chunks[2][1])


__all__ = [
    "ImageMetadataPolicyError",
    "MAX_POLICY_PAYLOAD_BYTES",
    "validate_thumbnail_payload",
]
