# -*- coding: utf-8 -*-
"""Atomic, credential-free download task persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import ntpath
import os
import tempfile
import threading
from typing import Callable, Iterable

from bound_process_lock import BoundProcessLock, BoundProcessLockError
from sankaku_url_policy import canonical_post_url, normalize_page_url, normalize_post_id


MAX_TASKS = 10_000
MAX_ERROR_CHARS = 1000
MAX_REVISION = 2**63 - 1
_MAX_TASK_STORE_BYTES = 16 * 1024 * 1024
_TASK_LOCK_NAME = ".task-store.lock"
TASK_STATES = frozenset(
    {"pending", "queued", "running", "completed", "failed", "cancelled"}
)
ACTIVE_TASK_STATES = frozenset({"queued", "running"})
RETRYABLE_STATES = frozenset({"pending", "failed", "cancelled"})
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {f"COM{suffix}" for suffix in ("¹", "²", "³")}
    | {f"LPT{suffix}" for suffix in ("¹", "²", "³")}
)
_WINDOWS_INVALID_COMPONENT_CHARS = frozenset('<>:"|?*')


class TaskStoreFailure(RuntimeError):
    """Common root for every task-store persistence failure."""


class TaskStoreError(TaskStoreFailure):
    """Application-handled task validation or persistence failure."""


class TaskStoreCorruptError(TaskStoreError):
    """The on-disk task store was read but failed structural validation."""

    def __init__(
        self,
        message: str,
        *,
        snapshot_signature: tuple[int, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.snapshot_signature = snapshot_signature


class TaskStoreReadError(TaskStoreError):
    """The task store or its file identity could not be read."""


class TaskStoreWriteError(TaskStoreError):
    """A normal task-store mutation could not be durably committed."""


class TaskStoreConflictError(TaskStoreError):
    """The on-disk task store changed after this instance loaded it."""


class TaskStoreRecoveryError(TaskStoreFailure):
    """A valid store was parsed but recovery could not be reported safely.

    This intentionally does not inherit :class:`TaskStoreError`.  A recovery
    transaction may already have committed a newer valid revision, so failure
    must abort startup for a fresh load and must never enter corrupt-file
    quarantine handling.
    """


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class DownloadTask:
    post_id: str
    source_url: str
    status: str = "pending"
    added_at: str = ""
    updated_at: str = ""
    rating: str = ""
    error: str = ""
    output_files: tuple[str, ...] = ()

    def validated(self, *, recover_interrupted: bool = False) -> "DownloadTask":
        post_id = normalize_post_id(self.post_id)
        if post_id is None:
            raise TaskStoreError("invalid post ID")
        source = normalize_page_url(self.source_url) or canonical_post_url(post_id)
        if source is None:
            raise TaskStoreError("invalid source URL")
        status = self.status
        if status not in TASK_STATES:
            raise TaskStoreError("invalid task status")
        if recover_interrupted and status in ACTIVE_TASK_STATES:
            status = "pending"
        added = _validate_timestamp(self.added_at) or _utc_now()
        updated = _validate_timestamp(self.updated_at) or added
        rating = self.rating if self.rating in {"", "s", "q", "e"} else ""
        error = self.error if isinstance(self.error, str) else ""
        error = error[:MAX_ERROR_CHARS]
        if any(ord(char) < 32 and char not in "\t\n\r" for char in error):
            error = ""
        if not isinstance(self.output_files, (list, tuple)) or len(self.output_files) > 100:
            raise TaskStoreError("invalid output file list")
        outputs = tuple(_validate_relative_path(value) for value in self.output_files)
        return DownloadTask(
            post_id=post_id,
            source_url=source,
            status=status,
            added_at=added,
            updated_at=updated,
            rating=rating,
            error=error,
            output_files=outputs,
        )


def _validate_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        return ""
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 32768:
        raise TaskStoreError("invalid output path")
    windows_value = value.replace("/", "\\")
    drive, _tail = ntpath.splitdrive(windows_value)
    raw_parts = tuple(part for part in windows_value.split("\\") if part)
    normalized = ntpath.normpath(windows_value)
    parts = tuple(part for part in normalized.split("\\") if part)
    if (
        drive
        or ntpath.isabs(windows_value)
        or not parts
        or any(part == ".." for part in raw_parts)
        or any(ord(char) < 32 for char in normalized)
    ):
        raise TaskStoreError("invalid output path")
    for part in parts:
        if (
            part in {".", ".."}
            or part.endswith((".", " "))
            or any(char in _WINDOWS_INVALID_COMPONENT_CHARS for char in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_BASENAMES
        ):
            raise TaskStoreError("invalid output path")
    return "/".join(parts)


class _TaskStoreProcessLock:
    """Short-lived cross-process lock around one task-store transaction."""

    def __init__(self, data_dir: str) -> None:
        self._lock = BoundProcessLock(data_dir, _TASK_LOCK_NAME)
        self.path = self._lock.path

    def __enter__(self) -> "_TaskStoreProcessLock":
        try:
            self._lock.__enter__()
        except BoundProcessLockError as exc:
            raise TaskStoreConflictError(
                "任务篮正在被另一个程序更新，请稍后重试"
            ) from exc
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        try:
            self._lock.__exit__(_exc_type, _exc, _traceback)
        except BoundProcessLockError as exc:
            raise TaskStoreConflictError(
                "任务篮正在被另一个程序更新，请稍后重试"
            ) from exc


def _signature_for(data: bytes) -> tuple[int, str]:
    return len(data), hashlib.sha256(data).hexdigest()


def _stat_identity(file_stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        getattr(file_stat, "st_mtime_ns", 0),
        getattr(file_stat, "st_ctime_ns", 0),
    )


def _read_task_store_snapshot(
    path: str,
) -> tuple[bytes, tuple[int, str], bool] | None:
    for _attempt in range(3):
        try:
            with open(path, "rb") as file_obj:
                before = os.fstat(file_obj.fileno())
                encoded = (
                    b""
                    if before.st_size > _MAX_TASK_STORE_BYTES
                    else file_obj.read(_MAX_TASK_STORE_BYTES + 1)
                )
                after = os.fstat(file_obj.fileno())
            current = os.stat(path)
        except FileNotFoundError:
            if os.path.lexists(path):
                raise TaskStoreReadError("任务篮路径无法安全读取")
            return None
        except OSError as exc:
            raise TaskStoreReadError(
                f"任务篮读取失败（{type(exc).__name__}）"
            ) from exc
        if (
            _stat_identity(before) != _stat_identity(after)
            or not os.path.samestat(after, current)
            or after.st_size != current.st_size
            or getattr(after, "st_mtime_ns", 0)
            != getattr(current, "st_mtime_ns", 0)
        ):
            continue
        oversized = (
            after.st_size > _MAX_TASK_STORE_BYTES
            or len(encoded) > _MAX_TASK_STORE_BYTES
        )
        if oversized:
            return b"", (after.st_size, "oversized"), True
        if len(encoded) != after.st_size:
            continue
        return encoded, _signature_for(encoded), False
    raise TaskStoreReadError("任务篮在读取期间持续发生变化")


def quarantine_corrupt_task_store(
    data_dir: str,
    recovery_path: str,
    expected_signature: tuple[int, str] | None,
    *,
    lock_factory: Callable[[], object] | None = None,
) -> None:
    """Move one fully hashed corrupt task snapshot aside under its lock."""

    absolute_data_dir = os.path.abspath(os.fspath(data_dir))
    source = os.path.join(absolute_data_dir, "tasks.json")
    destination = os.path.abspath(os.fspath(recovery_path))
    if (
        not isinstance(expected_signature, tuple)
        or len(expected_signature) != 2
        or type(expected_signature[0]) is not int
        or not 0 <= expected_signature[0] <= _MAX_TASK_STORE_BYTES
        or not isinstance(expected_signature[1], str)
        or len(expected_signature[1]) != 64
        or any(char not in "0123456789abcdef" for char in expected_signature[1])
    ):
        raise TaskStoreWriteError(
            "任务篮未取得完整内容摘要，不能安全隔离"
        )
    if (
        os.path.normcase(os.path.dirname(destination))
        != os.path.normcase(absolute_data_dir)
        or os.path.normcase(destination) == os.path.normcase(source)
        or os.path.lexists(destination)
    ):
        raise TaskStoreWriteError("损坏任务篮备份路径无效")
    process_lock_factory = lock_factory or (
        lambda: _TaskStoreProcessLock(absolute_data_dir)
    )
    try:
        with process_lock_factory():
            if os.path.lexists(destination):
                raise TaskStoreWriteError("损坏任务篮备份路径已被占用")
            snapshot = _read_task_store_snapshot(source)
            if (
                snapshot is None
                or snapshot[2]
                or snapshot[1] != expected_signature
            ):
                raise TaskStoreConflictError(
                    "任务篮已在隔离前发生变化，请重新启动后再试"
                )
            try:
                os.replace(source, destination)
            except OSError as exc:
                raise TaskStoreWriteError(
                    f"损坏任务篮备份失败（{type(exc).__name__}）"
                ) from exc
    except OSError as exc:
        raise TaskStoreWriteError(
            f"任务篮事务锁失败（{type(exc).__name__}）"
        ) from exc


class TaskStore:
    SCHEMA_VERSION = 1

    def __init__(
        self,
        data_dir: str,
        *,
        lock_factory: Callable[[], object] | None = None,
    ) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, "tasks.json")
        self._lock = threading.RLock()
        self._tasks: dict[str, DownloadTask] = {}
        self._revision = 0
        self._signature: tuple[int, str] | None = None
        self._process_lock_factory = lock_factory or (
            lambda: _TaskStoreProcessLock(self.data_dir)
        )
        self.load()

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def list(self) -> list[DownloadTask]:
        with self._lock:
            return list(self._tasks.values())

    def get(self, post_id: str) -> DownloadTask | None:
        normalized = normalize_post_id(post_id)
        with self._lock:
            return self._tasks.get(normalized or "")

    def add_many(self, values: Iterable[DownloadTask | str]) -> tuple[int, int]:
        added = 0
        duplicates = 0
        with self._lock:
            candidate = dict(self._tasks)
            for value in values:
                if isinstance(value, DownloadTask):
                    task = value.validated()
                else:
                    post_id = normalize_post_id(value)
                    if post_id is None:
                        raise TaskStoreError("invalid post ID")
                    task = DownloadTask(
                        post_id=post_id,
                        source_url=canonical_post_url(post_id) or "",
                    ).validated()
                if task.post_id in candidate:
                    duplicates += 1
                    continue
                if len(candidate) >= MAX_TASKS:
                    raise TaskStoreError("task limit reached")
                candidate[task.post_id] = task
                added += 1
            if added:
                self._commit(candidate)
        return added, duplicates

    def update(self, post_id: str, **changes) -> DownloadTask:
        normalized = normalize_post_id(post_id)
        if normalized is None:
            raise TaskStoreError("invalid post ID")
        allowed = {"status", "rating", "error", "output_files", "source_url"}
        if not changes or set(changes) - allowed:
            raise TaskStoreError("invalid task update")
        with self._lock:
            current = self._tasks.get(normalized)
            if current is None:
                raise TaskStoreError("task not found")
            updated = replace(current, updated_at=_utc_now(), **changes).validated()
            candidate = dict(self._tasks)
            candidate[normalized] = updated
            self._commit(candidate)
            return updated

    def update_many(self, post_ids: Iterable[str], **changes) -> list[DownloadTask]:
        """Atomically apply one validated transition to all existing IDs."""
        allowed = {"status", "rating", "error", "output_files", "source_url"}
        if not changes or set(changes) - allowed:
            raise TaskStoreError("invalid task update")
        normalized_ids: list[str] = []
        seen: set[str] = set()
        for value in post_ids:
            post_id = normalize_post_id(value)
            if post_id is None:
                raise TaskStoreError("invalid post ID")
            if post_id not in seen:
                seen.add(post_id)
                normalized_ids.append(post_id)
        with self._lock:
            missing = [post_id for post_id in normalized_ids if post_id not in self._tasks]
            if missing:
                raise TaskStoreError("task not found")
            candidate = dict(self._tasks)
            updated_tasks: list[DownloadTask] = []
            timestamp = _utc_now()
            for post_id in normalized_ids:
                updated = replace(
                    candidate[post_id], updated_at=timestamp, **changes
                ).validated()
                candidate[post_id] = updated
                updated_tasks.append(updated)
            if updated_tasks:
                self._commit(candidate)
            return updated_tasks

    def retry(self, post_ids: Iterable[str]) -> int:
        changed = 0
        with self._lock:
            candidate = dict(self._tasks)
            for value in post_ids:
                post_id = normalize_post_id(value)
                task = candidate.get(post_id or "")
                if task is None or task.status not in {"failed", "cancelled", "completed"}:
                    continue
                candidate[task.post_id] = replace(
                    task,
                    status="pending",
                    error="",
                    output_files=(),
                    updated_at=_utc_now(),
                ).validated()
                changed += 1
            if changed:
                self._commit(candidate)
        return changed

    def remove(self, post_ids: Iterable[str]) -> int:
        with self._lock:
            candidate = dict(self._tasks)
            targets: list[str] = []
            seen: set[str] = set()
            for value in post_ids:
                post_id = normalize_post_id(value)
                if post_id and post_id in candidate and post_id not in seen:
                    seen.add(post_id)
                    targets.append(post_id)
            if any(
                candidate[post_id].status in ACTIVE_TASK_STATES
                for post_id in targets
            ):
                raise TaskStoreError("活动下载任务不能移除，请先停止当前批次")
            for post_id in targets:
                del candidate[post_id]
            if targets:
                self._commit(candidate)
            return len(targets)

    def pending(self) -> list[DownloadTask]:
        with self._lock:
            return [task for task in self._tasks.values() if task.status in RETRYABLE_STATES]

    def load(self) -> bool:
        with self._lock:
            recovery_performed = False
            try:
                with self._process_lock_factory():
                    (
                        tasks,
                        revision,
                        signature,
                        recovery_performed,
                    ) = self._load_under_process_lock()
            except TaskStoreConflictError as exc:
                if recovery_performed:
                    raise TaskStoreRecoveryError(
                        "任务篮恢复事务锁失败（TaskStoreConflictError）"
                    ) from exc
                raise
            except OSError as exc:
                if recovery_performed:
                    raise TaskStoreRecoveryError(
                        f"任务篮恢复事务锁失败（{type(exc).__name__}）"
                    ) from exc
                raise TaskStoreReadError(
                    f"任务篮事务锁失败（{type(exc).__name__}）"
                ) from exc
            self._tasks = tasks
            self._revision = revision
            self._signature = signature
            return True

    def _load_under_process_lock(
        self,
    ) -> tuple[dict[str, DownloadTask], int, tuple[int, str] | None, bool]:
        snapshot = self._read_file_snapshot()
        if snapshot is None:
            return {}, 0, None, False
        encoded, signature, oversized = snapshot
        if oversized:
            raise TaskStoreCorruptError("task store is too large")

        def corrupt(message: str) -> TaskStoreCorruptError:
            return TaskStoreCorruptError(
                message,
                snapshot_signature=signature,
            )

        try:
            payload = json.loads(encoded.decode("utf-8"))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise corrupt(f"任务篮内容损坏（{type(exc).__name__}）") from exc
        try:
            if not isinstance(payload, dict) or set(payload) != {
                "schema_version",
                "revision",
                "tasks",
            }:
                raise corrupt("invalid task store shape")
            if payload["schema_version"] != self.SCHEMA_VERSION:
                raise corrupt("unsupported task schema")
            if (
                type(payload["revision"]) is not int
                or not 0 <= payload["revision"] <= MAX_REVISION
            ):
                raise corrupt("invalid revision")
            if (
                not isinstance(payload["tasks"], list)
                or len(payload["tasks"]) > MAX_TASKS
            ):
                raise corrupt("invalid task list")
            tasks: dict[str, DownloadTask] = {}
            for item in payload["tasks"]:
                if not isinstance(item, dict) or set(item) != {
                    "post_id",
                    "source_url",
                    "status",
                    "added_at",
                    "updated_at",
                    "rating",
                    "error",
                    "output_files",
                }:
                    raise corrupt("invalid task item")
                task = DownloadTask(**item).validated(recover_interrupted=True)
                if task.post_id in tasks:
                    raise corrupt("duplicate task")
                tasks[task.post_id] = task
        except TaskStoreCorruptError:
            raise
        except (TaskStoreError, TypeError, ValueError, OverflowError) as exc:
            raise corrupt(f"任务篮内容损坏（{type(exc).__name__}）") from exc

        revision = payload["revision"]
        interrupted = any(
            item.get("status") in ACTIVE_TASK_STATES for item in payload["tasks"]
        )
        recovery_performed = False
        if interrupted:
            try:
                if revision >= MAX_REVISION:
                    raise TaskStoreWriteError(
                        "任务篮版本号已达到安全上限"
                    )
                recovered_revision = revision + 1
                recovered = self._encode(tasks, recovered_revision)
                if signature != self._file_signature():
                    raise TaskStoreConflictError(
                        "任务篮已被另一个程序修改，请重新打开后再试"
                    )
                self._atomic_write(recovered, signature)
                signature = self._verified_committed_signature(recovered)
                recovery_performed = True
            except TaskStoreFailure as exc:
                raise TaskStoreRecoveryError(
                    f"任务篮恢复状态无法持久化（{type(exc).__name__}）"
                ) from exc
            revision = recovered_revision

        return tasks, revision, signature, recovery_performed

    def _commit(self, tasks: dict[str, DownloadTask]) -> None:
        if self._revision >= MAX_REVISION:
            raise TaskStoreWriteError("任务篮版本号已达到安全上限")
        revision = self._revision + 1
        encoded = self._encode(tasks, revision)
        try:
            with self._process_lock_factory():
                if self._signature != self._file_signature():
                    raise TaskStoreConflictError(
                        "任务篮已被另一个程序修改，请重新打开后再试"
                    )
                expected_signature = self._signature
                self._atomic_write(encoded, expected_signature)
                signature = self._verified_committed_signature(encoded)
        except OSError as exc:
            raise TaskStoreWriteError(
                f"任务篮事务锁失败（{type(exc).__name__}）"
            ) from exc
        self._tasks = tasks
        self._revision = revision
        self._signature = signature

    def _encode(self, tasks: dict[str, DownloadTask], revision: int) -> bytes:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "revision": revision,
            "tasks": [
                {**asdict(task), "output_files": list(task.output_files)}
                for task in tasks.values()
            ],
        }
        try:
            encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode(
                "utf-8"
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise TaskStoreWriteError(
                f"任务篮序列化失败（{type(exc).__name__}）"
            ) from exc
        if len(encoded) > _MAX_TASK_STORE_BYTES:
            raise TaskStoreWriteError("任务篮超过 16 MiB 安全上限")
        return encoded

    @staticmethod
    def _signature_for(data: bytes) -> tuple[int, str]:
        return _signature_for(data)

    def _read_file_snapshot(
        self,
    ) -> tuple[bytes, tuple[int, str], bool] | None:
        return _read_task_store_snapshot(self.path)

    def _file_signature(self) -> tuple[int, str] | None:
        snapshot = self._read_file_snapshot()
        return None if snapshot is None else snapshot[1]

    def _verified_committed_signature(self, encoded: bytes) -> tuple[int, str]:
        expected = self._signature_for(encoded)
        if self._file_signature() != expected:
            raise TaskStoreConflictError("任务篮在保存后被另一个程序修改")
        return expected

    def _atomic_write(
        self,
        data: bytes,
        expected_signature: tuple[int, str] | None,
    ) -> None:
        temp_path = None
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".tasks.", suffix=".tmp", dir=self.data_dir
            )
            with os.fdopen(descriptor, "wb") as file_obj:
                file_obj.write(data)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            if self._file_signature() != expected_signature:
                raise TaskStoreConflictError(
                    "任务篮在保存期间被另一个程序修改"
                )
            os.replace(temp_path, self.path)
            temp_path = None
        except OSError as exc:
            raise TaskStoreWriteError(
                f"任务篮保存失败（{type(exc).__name__}）"
            ) from exc
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass


__all__ = [
    "ACTIVE_TASK_STATES",
    "DownloadTask",
    "MAX_REVISION",
    "MAX_TASKS",
    "RETRYABLE_STATES",
    "TASK_STATES",
    "TaskStore",
    "TaskStoreConflictError",
    "TaskStoreCorruptError",
    "TaskStoreError",
    "TaskStoreFailure",
    "TaskStoreReadError",
    "TaskStoreRecoveryError",
    "TaskStoreWriteError",
    "quarantine_corrupt_task_store",
]
