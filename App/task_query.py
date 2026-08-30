# -*- coding: utf-8 -*-
"""Pure, bounded filtering for the persisted download-task view."""

from __future__ import annotations

import unicodedata
from typing import Iterable

from task_store import DownloadTask, MAX_TASKS, TASK_STATES


MAX_TASK_QUERY_CHARS = 256


class TaskQueryError(ValueError):
    """One local-only task query is outside the bounded UI contract."""


def query_tasks(
    tasks: Iterable[DownloadTask],
    *,
    status: str = "",
    query: str = "",
) -> tuple[DownloadTask, ...]:
    """Return a stable filtered view without mutating the task store."""

    if not isinstance(status, str) or (status and status not in TASK_STATES):
        raise TaskQueryError("任务状态筛选无效")
    normalized_query = _normalize_query(query)
    tokens = tuple(part for part in normalized_query.split() if part)

    selected: list[DownloadTask] = []
    for index, task in enumerate(tasks):
        if index >= MAX_TASKS:
            raise TaskQueryError("任务条目超过安全上限")
        if not isinstance(task, DownloadTask):
            raise TaskQueryError("任务条目格式无效")
        if status and task.status != status:
            continue
        if tokens and not _matches(task, tokens):
            continue
        selected.append(task)
    return tuple(selected)


def _normalize_query(value: str) -> str:
    if not isinstance(value, str):
        raise TaskQueryError("任务搜索内容无效")
    if len(value) > MAX_TASK_QUERY_CHARS:
        raise TaskQueryError("任务搜索内容过长")
    normalized = unicodedata.normalize("NFKC", value)
    if len(normalized) > MAX_TASK_QUERY_CHARS:
        raise TaskQueryError("任务搜索内容过长")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise TaskQueryError("任务搜索内容包含控制字符")
    return normalized.strip().casefold()


def _matches(task: DownloadTask, tokens: tuple[str, ...]) -> bool:
    values = (
        task.post_id,
        task.status,
        task.rating,
        task.added_at,
        task.updated_at,
        task.error,
        *task.output_files,
    )
    if not all(isinstance(value, str) for value in values):
        raise TaskQueryError("任务条目格式无效")
    haystack = unicodedata.normalize("NFKC", " ".join(values)).casefold()
    return all(token in haystack for token in tokens)


__all__ = ["MAX_TASK_QUERY_CHARS", "TaskQueryError", "query_tasks"]
