# -*- coding: utf-8 -*-
"""Bounded, deterministic, read-only scanning of the portable download root."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import stat
import threading
from typing import Callable

from download_engine import (
    LOCAL_MEDIA_EXTENSIONS,
    LocalIntegrityError,
    LocalMetadataError,
    verify_local_download,
)
from sankaku_api import CancelledError


MAX_DIRECTORY_ENTRIES = 100_000
MAX_LIBRARY_CANDIDATES = 10_000
MAX_DISPLAY_TAGS = 24
MAX_DISPLAY_TAG_CHARS = 96
MAX_DISPLAY_AUTHOR_CHARS = 256
MAX_DISPLAY_CREATED_AT_CHARS = 96
MAX_DISPLAY_RATING_CHARS = 32
MAX_DISPLAY_DETAIL_CHARS = 512
LIBRARY_STATUSES = (
    "verified",
    "changed",
    "invalid_metadata",
    "missing_media",
    "missing_metadata",
    "unsafe_path",
    "unreadable",
)
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MEDIA_NAME_RE = re.compile(
    r"^(?P<post_id>[A-Za-z0-9][A-Za-z0-9_-]{0,63})"
    r"(?:\.(?P<variant>sample|preview))?"
    r"(?: \(([1-9][0-9]*)\))?\.([A-Za-z0-9]+)$",
    re.IGNORECASE,
)


class LibraryScanError(RuntimeError):
    """The selected download root could not be scanned safely."""


@dataclass(frozen=True, slots=True)
class LibraryEntry:
    status: str
    post_id: str
    variant: str
    relative_path: str
    size: int
    content_type: str
    rating: str
    author: str
    tags: tuple[str, ...]
    created_at: str
    detail: str
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class LibraryReport:
    entries: tuple[LibraryEntry, ...]
    scanned_candidates: int
    verified_count: int
    checked_bytes: int
    status_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class _RootIdentity:
    device: int
    inode: int


def scan_download_library(
    output_dir: str,
    stop_event: threading.Event | None = None,
    progress: Callable[[int, int, int], None] | None = None,
) -> LibraryReport:
    """Scan only the first level of *output_dir* and revalidate each candidate.

    ``progress`` receives ``(processed_candidates, total_candidates,
    checked_bytes)``.  The
    directory-entry and candidate limits keep both runtime and memory bounded;
    exceeding either limit fails explicitly instead of returning a partial view.
    """

    cancellation = stop_event or threading.Event()
    root, root_identity = _validated_root(output_dir)
    names = _collect_candidates(root, cancellation)
    _assert_root_identity(root, root_identity)
    total = len(names)
    results: list[LibraryEntry] = []
    status_counts = {status: 0 for status in LIBRARY_STATUSES}
    checked_bytes = 0

    for index, name in enumerate(names, start=1):
        _check_cancelled(cancellation)
        _assert_root_identity(root, root_identity)
        media_path = os.path.join(root, name)
        fallback_size = _plain_candidate_size(media_path)
        fallback_post_id, fallback_variant = _identity_from_filename(name)
        try:
            verified = verify_local_download(
                media_path,
                output_dir=root,
                stop_event=cancellation,
            )
        except CancelledError:
            raise
        except LocalMetadataError as exc:
            _assert_root_identity(root, root_identity)
            status = exc.status if exc.status in status_counts else "invalid_metadata"
            entry = LibraryEntry(
                status=status,
                post_id=fallback_post_id,
                variant=fallback_variant,
                relative_path=name,
                size=fallback_size,
                content_type="",
                rating="",
                author="",
                tags=(),
                created_at="",
                detail=_display_text(str(exc), MAX_DISPLAY_DETAIL_CHARS)[0],
            )
        except LocalIntegrityError as exc:
            _assert_root_identity(root, root_identity)
            checked_bytes += exc.checked_bytes
            status = exc.status if exc.status in status_counts else "changed"
            entry = LibraryEntry(
                status=status,
                post_id=fallback_post_id,
                variant=fallback_variant,
                relative_path=name,
                size=fallback_size,
                content_type="",
                rating="",
                author="",
                tags=(),
                created_at="",
                detail=_display_text(str(exc), MAX_DISPLAY_DETAIL_CHARS)[0],
            )
        else:
            _assert_root_identity(root, root_identity)
            checked_bytes += verified.size
            rating, rating_changed = _display_text(
                verified.rating, MAX_DISPLAY_RATING_CHARS
            )
            author, author_changed = _display_text(
                verified.author, MAX_DISPLAY_AUTHOR_CHARS
            )
            created_at, created_changed = _display_text(
                verified.created_at, MAX_DISPLAY_CREATED_AT_CHARS
            )
            tags, tags_changed = _display_tags(verified.tags)
            entry = LibraryEntry(
                status="verified",
                post_id=verified.post_id,
                variant=verified.variant,
                relative_path=verified.relative_path,
                size=verified.size,
                content_type=verified.content_type,
                rating=rating,
                author=author,
                tags=tags,
                created_at=created_at,
                detail=(
                    "部分元数据显示已按安全上限截断或清理"
                    if any(
                        (
                            rating_changed,
                            author_changed,
                            created_changed,
                            tags_changed,
                        )
                    )
                    else ""
                ),
                sha256=verified.sha256,
            )
        results.append(entry)
        status_counts[entry.status] += 1
        if progress is not None:
            progress(index, total, checked_bytes)
        _check_cancelled(cancellation)

    _assert_root_identity(root, root_identity)
    return LibraryReport(
        entries=tuple(results),
        scanned_candidates=total,
        verified_count=status_counts["verified"],
        checked_bytes=checked_bytes,
        status_counts=dict(status_counts),
    )


def _validated_root(output_dir: str) -> tuple[str, _RootIdentity]:
    try:
        raw = os.fspath(output_dir)
        if not isinstance(raw, str) or not raw:
            raise ValueError("empty root")
        root = os.path.abspath(raw)
    except (OSError, TypeError, ValueError) as exc:
        raise LibraryScanError(
            f"下载目录不可用（{type(exc).__name__}）"
        ) from exc
    return root, _read_root_identity(root)


def _read_root_identity(root: str) -> _RootIdentity:
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise LibraryScanError(
            f"下载目录不可用（{type(exc).__name__}）"
        ) from exc
    attributes = int(getattr(root_stat, "st_file_attributes", 0))
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_ISLNK(root_stat.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
    ):
        raise LibraryScanError("下载目录路径不安全（拒绝链接或重解析点）")
    return _RootIdentity(device=root_stat.st_dev, inode=root_stat.st_ino)


def _assert_root_identity(root: str, expected: _RootIdentity) -> None:
    if _read_root_identity(root) != expected:
        raise LibraryScanError("下载目录在扫描期间被替换")


def _collect_candidates(root: str, cancellation: threading.Event) -> list[str]:
    names: set[str] = set()
    seen_entries = 0
    _check_cancelled(cancellation)
    try:
        with os.scandir(root) as iterator:
            for item in iterator:
                _check_cancelled(cancellation)
                seen_entries += 1
                if seen_entries > MAX_DIRECTORY_ENTRIES:
                    raise LibraryScanError(
                        f"下载目录项目超过 {MAX_DIRECTORY_ENTRIES} 项安全上限"
                    )
                candidate = _candidate_media_name(item.name)
                if candidate is None:
                    continue
                names.add(candidate)
                if len(names) > MAX_LIBRARY_CANDIDATES:
                    raise LibraryScanError(
                        f"本地媒体候选超过 {MAX_LIBRARY_CANDIDATES} 项安全上限"
                    )
    except CancelledError:
        raise
    except LibraryScanError:
        raise
    except OSError as exc:
        raise LibraryScanError(
            f"下载目录读取失败（{type(exc).__name__}）"
        ) from exc
    return sorted(names, key=lambda value: (value.casefold(), value))


def _candidate_media_name(name: str) -> str | None:
    if not name or name.startswith("."):
        return None
    candidate = name[:-5] if name.casefold().endswith(".json") else name
    _stem, separator, extension = candidate.rpartition(".")
    if not separator or extension.casefold() not in LOCAL_MEDIA_EXTENSIONS:
        return None
    return candidate


def _identity_from_filename(name: str) -> tuple[str, str]:
    match = _MEDIA_NAME_RE.fullmatch(name)
    if match is None:
        return "", ""
    return match.group("post_id"), (match.group("variant") or "original").lower()


def _plain_candidate_size(path: str) -> int:
    try:
        path_stat = os.lstat(path)
    except OSError:
        return 0
    attributes = int(getattr(path_stat, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or stat.S_ISLNK(path_stat.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
    ):
        return 0
    return max(0, int(path_stat.st_size))


def _display_text(value: str, limit: int) -> tuple[str, bool]:
    cleaned = "".join(
        character if character.isprintable() else " " for character in value
    )
    changed = cleaned != value
    if len(cleaned) > limit:
        cleaned = cleaned[: max(0, limit - 1)] + "…"
        changed = True
    return cleaned, changed


def _display_tags(values: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
    changed = len(values) > MAX_DISPLAY_TAGS
    tags: list[str] = []
    for value in values[:MAX_DISPLAY_TAGS]:
        rendered, was_changed = _display_text(value, MAX_DISPLAY_TAG_CHARS)
        tags.append(rendered)
        changed = changed or was_changed
    return tuple(tags), changed


def _check_cancelled(stop_event: threading.Event) -> None:
    if stop_event.is_set():
        raise CancelledError("本地下载库扫描已取消")


__all__ = [
    "LIBRARY_STATUSES",
    "LibraryEntry",
    "LibraryReport",
    "LibraryScanError",
    "scan_download_library",
]
