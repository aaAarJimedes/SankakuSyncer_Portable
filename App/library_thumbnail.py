# -*- coding: utf-8 -*-
"""Bounded, read-only thumbnail decoding for verified local downloads."""

from __future__ import annotations

from dataclasses import dataclass
import ntpath
import os
import re
import threading

from PySide6.QtCore import QByteArray, QBuffer, QIODevice, QSize, Qt
from PySide6.QtGui import QImage, QImageReader, QPainter

from bound_file_reader import (
    BoundFileCancelled,
    BoundFileError,
    BoundRootIdentity,
    read_verified_child,
)
from image_metadata_policy import (
    ImageMetadataPolicyError,
    validate_thumbnail_payload,
)
from sankaku_api import CancelledError


MAX_THUMBNAIL_FILE_BYTES = 20 * 1024 * 1024
MAX_THUMBNAIL_SOURCE_PIXELS = 16_000_000
MAX_THUMBNAIL_EDGE = 360
MAX_THUMBNAIL_PNG_BYTES = 4 * 1024 * 1024
MAX_RELATIVE_NAME_BYTES = 1024
_SUPPORTED_EXTENSIONS = {
    ".jpeg": "jpeg",
    ".jpg": "jpeg",
    ".png": "png",
    ".webp": "webp",
}
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


class LibraryThumbnailError(RuntimeError):
    """A safe, user-displayable local thumbnail failure."""


@dataclass(frozen=True, slots=True)
class VerifiedThumbnailSource:
    """Immutable integrity binding copied from one verified library entry."""

    relative_path: str
    size: int
    sha256: str
    content_type: str
    root_identity: BoundRootIdentity


@dataclass(frozen=True, slots=True)
class LibraryThumbnail:
    """One integrity-bound in-memory PNG plus source image dimensions."""

    relative_path: str
    size: int
    sha256: str
    content_type: str
    root_identity: BoundRootIdentity
    width: int
    height: int
    png_bytes: bytes


def load_library_thumbnail(
    output_dir: str,
    source: VerifiedThumbnailSource,
    stop_event: threading.Event | None = None,
    *,
    max_file_bytes: int = MAX_THUMBNAIL_FILE_BYTES,
    max_source_pixels: int = MAX_THUMBNAIL_SOURCE_PIXELS,
    max_edge: int = MAX_THUMBNAIL_EDGE,
) -> LibraryThumbnail:
    """Read and decode one first-level image without network or disk writes."""

    _validate_limits(max_file_bytes, max_source_pixels, max_edge)
    (
        name,
        expected_size,
        expected_sha256,
        expected_content_type,
        expected_format,
        expected_root_identity,
    ) = _validated_source(source)
    if expected_size > max_file_bytes:
        raise LibraryThumbnailError("缩略图源文件超过读取安全上限")
    _check_cancelled(stop_event)
    try:
        payload = read_verified_child(
            output_dir,
            expected_root_identity,
            name,
            expected_size,
            expected_sha256,
            stop_event,
            max_file_bytes,
        )
    except BoundFileCancelled:
        raise CancelledError("本地缩略图读取已取消") from None
    except BoundFileError:
        raise LibraryThumbnailError("缩略图源文件无法安全读取") from None
    actual_sha256 = expected_sha256
    _check_cancelled(stop_event)
    if _payload_format(payload) != expected_format:
        raise LibraryThumbnailError("缩略图源文件格式与扩展名不匹配")
    try:
        validate_thumbnail_payload(payload, expected_format)
    except ImageMetadataPolicyError:
        raise LibraryThumbnailError("缩略图源文件结构不符合安全策略") from None

    try:
        image, source_width, source_height = _decode_image(
            payload,
            expected_format=expected_format,
            stop_event=stop_event,
            max_source_pixels=max_source_pixels,
            max_edge=max_edge,
        )
        _check_cancelled(stop_event)
        png_bytes = _encode_png(image)
    except (CancelledError, LibraryThumbnailError):
        raise
    except Exception:
        raise LibraryThumbnailError("缩略图处理失败") from None
    if not png_bytes or len(png_bytes) > MAX_THUMBNAIL_PNG_BYTES:
        raise LibraryThumbnailError("缩略图 PNG 输出超过内存安全上限")
    _check_cancelled(stop_event)
    return LibraryThumbnail(
        relative_path=name,
        size=expected_size,
        sha256=actual_sha256,
        content_type=expected_content_type,
        root_identity=expected_root_identity,
        width=source_width,
        height=source_height,
        png_bytes=png_bytes,
    )


def _validate_limits(max_file_bytes: int, max_source_pixels: int, max_edge: int) -> None:
    if (
        type(max_file_bytes) is not int
        or not 1 <= max_file_bytes <= MAX_THUMBNAIL_FILE_BYTES
        or type(max_source_pixels) is not int
        or not 1 <= max_source_pixels <= MAX_THUMBNAIL_SOURCE_PIXELS
        or type(max_edge) is not int
        or not 1 <= max_edge <= MAX_THUMBNAIL_EDGE
    ):
        raise LibraryThumbnailError("缩略图读取参数无效")


def _validated_source(
    source: object,
) -> tuple[str, int, str, str, str, BoundRootIdentity]:
    if not isinstance(source, VerifiedThumbnailSource):
        raise LibraryThumbnailError("缩略图验证来源无效")
    name, expected_format = _validated_name(source.relative_path)
    if (
        type(source.size) is not int
        or not 1 <= source.size <= MAX_THUMBNAIL_FILE_BYTES
        or not isinstance(source.sha256, str)
        or _SHA256_RE.fullmatch(source.sha256) is None
        or not isinstance(source.content_type, str)
        or not isinstance(source.root_identity, BoundRootIdentity)
    ):
        raise LibraryThumbnailError("缩略图验证来源无效")
    content_type = source.content_type.strip().casefold()
    content_format = {
        "image/jpeg": "jpeg",
        "image/jpg": "jpeg",
        "image/png": "png",
        "image/webp": "webp",
    }.get(content_type)
    if content_format != expected_format:
        raise LibraryThumbnailError("缩略图验证来源无效")
    return (
        name,
        source.size,
        source.sha256.casefold(),
        content_type,
        expected_format,
        source.root_identity,
    )


def _validated_name(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise LibraryThumbnailError("缩略图相对文件名无效")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise LibraryThumbnailError("缩略图相对文件名无效") from None
    if (
        len(encoded) > MAX_RELATIVE_NAME_BYTES
        or os.path.isabs(value)
        or ntpath.isabs(value)
        or os.path.basename(value) != value
        or ntpath.basename(value) != value
        or "/" in value
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise LibraryThumbnailError("缩略图只允许下载目录第一层文件")
    extension = os.path.splitext(value)[1].casefold()
    expected_format = _SUPPORTED_EXTENSIONS.get(extension)
    if expected_format is None:
        raise LibraryThumbnailError("该文件不是支持的静态图片格式")
    return value, expected_format


def _payload_format(payload: bytes) -> str:
    if payload.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if (
        len(payload) >= 12
        and payload[:4] == b"RIFF"
        and payload[8:12] == b"WEBP"
    ):
        return "webp"
    return ""


def _decode_image(
    payload: bytes,
    *,
    expected_format: str,
    stop_event: threading.Event | None,
    max_source_pixels: int,
    max_edge: int,
) -> tuple[QImage, int, int]:
    source = QByteArray(payload)
    buffer = QBuffer()
    buffer.setData(source)
    if not buffer.open(QIODevice.ReadOnly):
        raise LibraryThumbnailError("缩略图内存读取失败")
    try:
        QImageReader.setAllocationLimit(64)
        reader = QImageReader(
            buffer, QByteArray(expected_format.encode("ascii"))
        )
        reader.setAutoTransform(True)
        reader.setDecideFormatFromContent(False)
        source_size = reader.size()
        width = int(source_size.width())
        height = int(source_size.height())
        if width <= 0 or height <= 0:
            raise LibraryThumbnailError("图片格式无法识别或已经损坏")
        if width > max_source_pixels // height:
            raise LibraryThumbnailError("图片像素数量超过安全上限")
        scaled = source_size.scaled(
            QSize(max_edge, max_edge), Qt.KeepAspectRatio
        )
        if not scaled.isValid() or scaled.width() <= 0 or scaled.height() <= 0:
            raise LibraryThumbnailError("图片缩略尺寸无效")
        reader.setScaledSize(scaled)
        _check_cancelled(stop_event)
        image = reader.read()
        if image.isNull():
            raise LibraryThumbnailError("图片解码失败")
        _check_cancelled(stop_event)
        if image.width() > max_edge or image.height() > max_edge:
            image = image.scaled(
                max_edge,
                max_edge,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        if (
            image.isNull()
            or image.width() <= 0
            or image.height() <= 0
            or image.width() > max_edge
            or image.height() > max_edge
        ):
            raise LibraryThumbnailError("图片缩略输出无效")
        clean = QImage(image.size(), QImage.Format_ARGB32)
        if clean.isNull():
            raise LibraryThumbnailError("图片缩略输出无效")
        clean.fill(Qt.transparent)
        painter = QPainter()
        if not painter.begin(clean):
            raise LibraryThumbnailError("图片缩略输出无效")
        try:
            painter.drawImage(0, 0, image)
        finally:
            painter.end()
        image = clean
        _check_cancelled(stop_event)
        return image, width, height
    finally:
        buffer.close()


def _encode_png(image: QImage) -> bytes:
    output = QByteArray()
    buffer = QBuffer(output)
    if not buffer.open(QIODevice.WriteOnly):
        raise LibraryThumbnailError("缩略图 PNG 内存写入失败")
    try:
        if not image.save(buffer, "PNG"):
            raise LibraryThumbnailError("缩略图 PNG 编码失败")
        return bytes(output)
    finally:
        buffer.close()


def _check_cancelled(stop_event: threading.Event | None) -> None:
    if stop_event is None:
        return
    try:
        stopped = bool(stop_event.is_set())
    except Exception:
        stopped = True
    if stopped:
        raise CancelledError("本地缩略图读取已取消")


__all__ = [
    "LibraryThumbnail",
    "LibraryThumbnailError",
    "MAX_THUMBNAIL_EDGE",
    "MAX_THUMBNAIL_FILE_BYTES",
    "MAX_THUMBNAIL_PNG_BYTES",
    "MAX_THUMBNAIL_SOURCE_PIXELS",
    "VerifiedThumbnailSource",
    "load_library_thumbnail",
]
