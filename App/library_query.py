# -*- coding: utf-8 -*-
"""Pure, bounded filtering and sorting for one committed local-library report."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import unicodedata
from typing import Iterable

from local_library import (
    LIBRARY_STATUSES,
    MAX_LIBRARY_CANDIDATES,
    LibraryEntry,
)


MAX_LIBRARY_QUERY_CHARS = 256
LIBRARY_SORTS = ("id_asc", "id_desc", "newest", "largest")


class LibraryQueryError(ValueError):
    """One local-only library query is outside the bounded UI contract."""


def query_library_entries(
    entries: Iterable[LibraryEntry],
    *,
    status: str = "",
    query: str = "",
    sort: str = "id_asc",
) -> tuple[LibraryEntry, ...]:
    """Return a deterministic view without mutating the committed report."""

    if not isinstance(status, str) or (status and status not in LIBRARY_STATUSES):
        raise LibraryQueryError("本地库状态筛选无效")
    if not isinstance(sort, str) or sort not in LIBRARY_SORTS:
        raise LibraryQueryError("本地库排序方式无效")
    normalized_query = _normalize_query(query)
    tokens = tuple(part for part in normalized_query.split() if part)

    prepared: list[LibraryEntry] = []
    for index, entry in enumerate(entries):
        if index >= MAX_LIBRARY_CANDIDATES:
            raise LibraryQueryError("本地库条目超过安全上限")
        if not isinstance(entry, LibraryEntry):
            raise LibraryQueryError("本地库条目格式无效")
        prepared.append(entry)
    selected = [
        entry
        for entry in prepared
        if (not status or entry.status == status)
        and (not tokens or _matches(entry, tokens))
    ]
    if sort == "id_asc":
        selected.sort(key=_identity_key)
    elif sort == "id_desc":
        selected.sort(key=_identity_key, reverse=True)
    elif sort == "newest":
        selected.sort(key=_newest_key, reverse=True)
    else:
        selected.sort(key=_largest_key, reverse=True)
    return tuple(selected)


def _normalize_query(value: str) -> str:
    if not isinstance(value, str):
        raise LibraryQueryError("本地库搜索内容无效")
    if len(value) > MAX_LIBRARY_QUERY_CHARS:
        raise LibraryQueryError("本地库搜索内容过长")
    normalized = unicodedata.normalize("NFKC", value)
    if len(normalized) > MAX_LIBRARY_QUERY_CHARS:
        raise LibraryQueryError("本地库搜索内容过长")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise LibraryQueryError("本地库搜索内容包含控制字符")
    return normalized.strip().casefold()


def _matches(entry: LibraryEntry, tokens: tuple[str, ...]) -> bool:
    haystack = unicodedata.normalize(
        "NFKC",
        " ".join(
            (
                entry.post_id,
                entry.variant,
                entry.relative_path,
                entry.content_type,
                entry.rating,
                entry.author,
                entry.created_at,
                *entry.tags,
            )
        ),
    ).casefold()
    return all(token in haystack for token in tokens)


def _post_id_key(value: str) -> tuple[int, int, str]:
    folded = value.casefold()
    if folded.isascii() and folded.isdecimal():
        return 0, int(folded), folded
    return 1, 0, folded


def _entry_tie_key(entry: LibraryEntry) -> tuple[object, ...]:
    return (
        entry.status,
        entry.post_id,
        entry.variant,
        entry.relative_path,
        entry.size,
        entry.content_type,
        entry.rating,
        entry.author,
        entry.tags,
        entry.created_at,
        entry.detail,
        entry.sha256,
    )


def _identity_key(entry: LibraryEntry) -> tuple[object, ...]:
    return (
        _post_id_key(entry.post_id),
        entry.variant.casefold(),
        entry.relative_path.casefold(),
        _entry_tie_key(entry),
    )


def _created_value(value: str) -> tuple[int, float, str]:
    candidate = value.strip()
    if not candidate:
        return 0, 0.0, ""
    try:
        numeric = float(candidate)
    except ValueError:
        numeric = math.nan
    if math.isfinite(numeric):
        return 2, numeric, candidate.casefold()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        timestamp = parsed.timestamp()
    except (OverflowError, ValueError):
        return 1, 0.0, candidate.casefold()
    return 2, timestamp, candidate.casefold()


def _newest_key(
    entry: LibraryEntry,
) -> tuple[int, float, str, tuple[object, ...]]:
    kind, timestamp, text = _created_value(entry.created_at)
    return kind, timestamp, text, _identity_key(entry)


def _largest_key(
    entry: LibraryEntry,
) -> tuple[int, tuple[object, ...]]:
    size = entry.size if type(entry.size) is int and entry.size >= 0 else -1
    return size, _identity_key(entry)


__all__ = [
    "LIBRARY_SORTS",
    "LibraryQueryError",
    "MAX_LIBRARY_QUERY_CHARS",
    "query_library_entries",
]
