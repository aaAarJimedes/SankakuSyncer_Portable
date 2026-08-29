# -*- coding: utf-8 -*-
"""Bounded, deterministic, read-only scanning of the portable download root."""

from __future__ import annotations

from dataclasses import dataclass
import re
import threading
from typing import Callable

from bound_file_reader import (
    BoundFileCancelled,
    BoundFileError,
    BoundRootIdentity,
    BoundRootSession,
    open_bound_root,
)
from download_engine import (
    LOCAL_MEDIA_EXTENSIONS,
    LocalIntegrityError,
    LocalMetadataError,
    MAX_MEDIA_BYTES,
    verify_bound_local_download,
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
    root_identity: BoundRootIdentity | None = None


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
    try:
        with open_bound_root(output_dir, cancellation) as session:
            return _scan_bound_session(session, cancellation, progress)
    except BoundFileCancelled:
        raise CancelledError("本地下载库扫描已取消") from None
    except BoundFileError as exc:
        raise LibraryScanError(str(exc)) from None


def _scan_bound_session(
    session: BoundRootSession,
    cancellation: threading.Event,
    progress: Callable[[int, int, int], None] | None,
) -> LibraryReport:
    names = _collect_candidates(session, cancellation)
    total = len(names)
    results: list[LibraryEntry] = []
    status_counts = {status: 0 for status in LIBRARY_STATUSES}
    checked_bytes = 0

    for index, name in enumerate(names, start=1):
        _check_cancelled(cancellation)
        fallback_size = _plain_candidate_size(session, name, cancellation)
        fallback_post_id, fallback_variant = _identity_from_filename(name)
        try:
            verified = verify_bound_local_download(
                session,
                name,
                stop_event=cancellation,
            )
        except CancelledError:
            raise
        except LocalMetadataError as exc:
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

    _check_cancelled(cancellation)
    return LibraryReport(
        entries=tuple(results),
        scanned_candidates=total,
        verified_count=status_counts["verified"],
        checked_bytes=checked_bytes,
        status_counts=dict(status_counts),
        root_identity=session.identity,
    )


def _collect_candidates(
    session: BoundRootSession, cancellation: threading.Event
) -> list[str]:
    names: set[str] = set()
    _check_cancelled(cancellation)
    for name in session.list_names(
        stop_event=cancellation,
        max_entries=MAX_DIRECTORY_ENTRIES,
    ):
        _check_cancelled(cancellation)
        candidate = _candidate_media_name(name)
        if candidate is None:
            continue
        names.add(candidate)
        if len(names) > MAX_LIBRARY_CANDIDATES:
            raise LibraryScanError(
                f"本地媒体候选超过 {MAX_LIBRARY_CANDIDATES} 项安全上限"
            )
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


def _plain_candidate_size(
    session: BoundRootSession,
    name: str,
    cancellation: threading.Event,
) -> int:
    try:
        return session.stat_child(
            name,
            stop_event=cancellation,
            max_bytes=MAX_MEDIA_BYTES,
        )
    except BoundFileCancelled:
        raise CancelledError("本地下载库扫描已取消") from None
    except BoundFileError:
        return 0


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
