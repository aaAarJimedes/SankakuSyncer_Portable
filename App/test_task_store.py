# -*- coding: utf-8 -*-
"""Offline tests for task validation, persistence, and writer conflicts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

import task_store as task_module
from sankaku_url_policy import canonical_post_url
from task_store import (
    DownloadTask,
    MAX_REVISION,
    TaskStore,
    TaskStoreConflictError,
    TaskStoreCorruptError,
    TaskStoreError,
    TaskStoreFailure,
    TaskStoreReadError,
    TaskStoreRecoveryError,
    TaskStoreWriteError,
)


_FIXED_TIME = "2026-08-29T01:02:03+00:00"


def _task_record(post_id: str, *, status: str = "pending", **changes) -> dict:
    """Create an exact on-disk task item through production validation."""
    task = DownloadTask(
        post_id=post_id,
        source_url=canonical_post_url(post_id) or "",
        status=status,
        added_at=_FIXED_TIME,
        updated_at=_FIXED_TIME,
        **changes,
    ).validated()
    record = asdict(task)
    record["output_files"] = list(task.output_files)
    return record


class DownloadTaskValidationTests(unittest.TestCase):
    def test_normalizes_source_timestamps_rating_error_and_paths(self):
        task = DownloadTask(
            post_id="a" * 64,
            source_url="not an official URL",
            added_at="2026-08-29T09:02:03+08:00",
            updated_at="not-a-timestamp",
            rating="unknown",
            error="e" * 1001,
            output_files=(r"images\.\nested\file.jpg",),
        ).validated()

        self.assertEqual(task.post_id, "a" * 64)
        self.assertEqual(task.source_url, canonical_post_url("a" * 64))
        self.assertEqual(task.added_at, _FIXED_TIME)
        self.assertEqual(task.updated_at, _FIXED_TIME)
        self.assertEqual(task.rating, "")
        self.assertEqual(len(task.error), task_module.MAX_ERROR_CHARS)
        self.assertEqual(task.output_files, ("images/nested/file.jpg",))

    def test_rejects_invalid_identity_and_state(self):
        for task in (
            DownloadTask("a" * 65, ""),
            DownloadTask("valid_id", "", status="paused"),
        ):
            with self.subTest(task=task):
                with self.assertRaises(TaskStoreError):
                    task.validated()

    def test_invalid_timestamps_fall_back_to_current_aware_time(self):
        with mock.patch.object(task_module, "_utc_now", return_value=_FIXED_TIME):
            task = DownloadTask(
                "timestamp_test",
                "",
                added_at="2026-08-29T01:02:03",
                updated_at="x" * 65,
            ).validated()
        self.assertEqual(task.added_at, _FIXED_TIME)
        self.assertEqual(task.updated_at, _FIXED_TIME)

    def test_error_control_characters_are_cleared(self):
        task = DownloadTask("control_error", "", error="bad\x00message").validated()
        self.assertEqual(task.error, "")
        self.assertEqual(
            DownloadTask("allowed_error", "", error="line 1\nline 2\tend").validated().error,
            "line 1\nline 2\tend",
        )

    def test_output_file_boundaries(self):
        accepted = DownloadTask(
            "one_hundred_outputs",
            "",
            output_files=tuple(f"files/{index}.jpg" for index in range(100)),
        ).validated()
        self.assertEqual(len(accepted.output_files), 100)

        invalid_values = (
            "files/one.jpg",
            tuple(f"files/{index}.jpg" for index in range(101)),
            ("",),
            ("../escape.jpg",),
            (r"C:\escape.jpg",),
            (r"C:relative.jpg",),
            (r"C:..\escape.jpg",),
            ("bad:stream.jpg",),
            ("CON",),
            ("NUL.txt",),
            ("COM¹.txt",),
            ("LPT³",),
            ("trailing.",),
            ("trailing ",),
            ("bad?.jpg",),
            ("bad\x00name.jpg",),
            ("x" * 32769,),
            (123,),
        )
        for value in invalid_values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TaskStoreError):
                    DownloadTask("bad_output", "", output_files=value).validated()


class TaskStoreTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.data_dir = self._temporary.name
        self.store = TaskStore(self.data_dir)

    def tearDown(self):
        self._temporary.cleanup()

    def _write_json(self, payload) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.store.path, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False)

    def _payload(self, tasks, *, revision=0):
        return {"schema_version": 1, "revision": revision, "tasks": list(tasks)}

    def test_missing_store_starts_empty(self):
        self.assertEqual(self.store.revision, 0)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.store.pending(), [])
        self.assertIsNone(self.store.get("missing"))
        self.assertIsNone(self.store.get("invalid post id"))
        self.assertFalse(os.path.exists(self.store.path))

    def test_add_many_counts_duplicates_preserves_order_and_round_trips(self):
        custom = DownloadTask(
            "second_id",
            "invalid source falls back",
            rating="q",
            output_files=("downloads/second.jpg",),
        )
        self.assertEqual(
            self.store.add_many(["first_id", "first_id", custom]),
            (2, 1),
        )
        self.assertEqual([task.post_id for task in self.store.list()], ["first_id", "second_id"])
        self.assertEqual(self.store.revision, 1)
        self.assertEqual(self.store.get("second_id").rating, "q")
        self.assertEqual(
            self.store.get("second_id").source_url,
            canonical_post_url("second_id"),
        )

        reloaded = TaskStore(self.data_dir)
        self.assertEqual(reloaded.revision, 1)
        self.assertEqual(reloaded.list(), self.store.list())

    def test_update_retry_pending_and_remove_lifecycle(self):
        self.store.add_many(["pending_id", "failed_id", "done_id", "cancelled_id"])
        self.store.update("failed_id", status="failed", error="temporary")
        self.store.update(
            "done_id",
            status="completed",
            rating="e",
            output_files=(r"done\image.jpg",),
        )
        self.store.update("cancelled_id", status="cancelled", error="cancelled")

        self.assertEqual(
            {task.post_id for task in self.store.pending()},
            {"pending_id", "failed_id", "cancelled_id"},
        )
        self.assertEqual(
            self.store.retry(["failed_id", "done_id", "cancelled_id", "missing", "failed_id"]),
            3,
        )
        for post_id in ("failed_id", "done_id", "cancelled_id"):
            task = self.store.get(post_id)
            self.assertEqual(task.status, "pending")
            self.assertEqual(task.error, "")
            self.assertEqual(task.output_files, ())

        self.assertEqual(self.store.remove(["pending_id", "pending_id", "bad id", "missing"]), 1)
        self.assertIsNone(self.store.get("pending_id"))
        self.assertEqual(self.store.remove(["missing"]), 0)

    def test_update_many_commits_one_atomic_transition(self):
        self.store.add_many(["bulk_one", "bulk_two"])
        with mock.patch.object(
            self.store, "_commit", wraps=self.store._commit
        ) as commit:
            updated = self.store.update_many(
                ["bulk_one", "bulk_two", "bulk_one"],
                status="queued",
                error="",
            )

        self.assertEqual([task.post_id for task in updated], ["bulk_one", "bulk_two"])
        self.assertEqual([task.status for task in updated], ["queued", "queued"])
        self.assertEqual(commit.call_count, 1)
        with open(self.store.path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        self.assertEqual(
            [task["status"] for task in payload["tasks"]], ["queued", "queued"]
        )

    def test_update_many_is_atomic_on_missing_or_invalid_late_task(self):
        self.store.add_many(["bulk_one", "bulk_two"])
        before = self.store.list()
        with open(self.store.path, "rb") as file_obj:
            before_bytes = file_obj.read()

        with self.assertRaises(TaskStoreError):
            self.store.update_many(["bulk_one", "missing"], status="queued")
        self.assertEqual(self.store.list(), before)
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before_bytes)

        with self.assertRaises(TaskStoreError):
            self.store.update_many(
                ["bulk_one", "bulk_two"], status="not-a-state"
            )
        self.assertEqual(self.store.list(), before)
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before_bytes)

    def test_update_rejects_invalid_requests_without_mutation(self):
        self.store.add_many(["kept_id"])
        before = self.store.list()
        before_revision = self.store.revision
        cases = (
            ("kept_id", {}),
            ("kept_id", {"unknown": True}),
            ("kept_id", {"status": "paused"}),
            ("missing_id", {"status": "failed"}),
            ("invalid id", {"status": "failed"}),
        )
        for post_id, changes in cases:
            with self.subTest(post_id=post_id, changes=changes):
                with self.assertRaises(TaskStoreError):
                    self.store.update(post_id, **changes)
                self.assertEqual(self.store.list(), before)
                self.assertEqual(self.store.revision, before_revision)

    def test_add_many_is_atomic_on_invalid_late_value(self):
        def values():
            yield "would_be_valid"
            yield "invalid post id"

        with self.assertRaises(TaskStoreError):
            self.store.add_many(values())
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.store.revision, 0)
        self.assertFalse(os.path.exists(self.store.path))

    def test_task_limit_is_enforced_without_partial_commit(self):
        with mock.patch.object(task_module, "MAX_TASKS", 2):
            with self.assertRaisesRegex(TaskStoreError, "task limit"):
                self.store.add_many(["limit_1", "limit_2", "limit_3"])
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.store.revision, 0)

    def test_interrupted_tasks_are_recovered_and_committed(self):
        self._write_json(
            self._payload(
                [
                    _task_record("queued_id", status="queued"),
                    _task_record("running_id", status="running"),
                    _task_record("completed_id", status="completed"),
                ],
                revision=7,
            )
        )

        recovered = TaskStore(self.data_dir)
        self.assertEqual(recovered.revision, 8)
        self.assertEqual(recovered.get("queued_id").status, "pending")
        self.assertEqual(recovered.get("running_id").status, "pending")
        self.assertEqual(recovered.get("completed_id").status, "completed")
        with open(recovered.path, "r", encoding="utf-8") as file_obj:
            on_disk = json.load(file_obj)
        self.assertEqual(on_disk["revision"], 8)
        self.assertEqual(
            {item["post_id"]: item["status"] for item in on_disk["tasks"]},
            {
                "queued_id": "pending",
                "running_id": "pending",
                "completed_id": "completed",
            },
        )

    def test_malformed_json_and_invalid_store_shapes_are_rejected(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.store.path, "w", encoding="utf-8") as file_obj:
            file_obj.write("{not-json")
        with self.assertRaises(TaskStoreCorruptError):
            TaskStore(self.data_dir)

        valid_item = _task_record("valid_item")
        invalid_payloads = (
            [],
            {"schema_version": 1, "revision": 0, "tasks": [], "extra": True},
            self._payload([], revision=True),
            self._payload([], revision=-1),
            {"schema_version": 2, "revision": 0, "tasks": []},
            {"schema_version": 1, "revision": 0, "tasks": {}},
            self._payload([{**valid_item, "extra": True}]),
            self._payload([{**valid_item, "status": "paused"}]),
            self._payload([valid_item, valid_item]),
            self._payload([{**valid_item, "output_files": ["../escape.jpg"]}]),
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                self._write_json(payload)
                with self.assertRaises(TaskStoreCorruptError):
                    TaskStore(self.data_dir)

    def test_oversized_store_is_rejected_before_parsing(self):
        self._write_json(self._payload([]))
        with mock.patch.object(
            task_module.os.path,
            "getsize",
            return_value=16 * 1024 * 1024 + 1,
        ):
            with self.assertRaises(TaskStoreCorruptError):
                TaskStore(self.data_dir)

    def test_read_failure_is_distinct_from_corrupt_content(self):
        self._write_json(self._payload([]))
        with mock.patch.object(
            task_module.os.path,
            "getsize",
            side_effect=PermissionError("simulated read failure"),
        ):
            with self.assertRaises(TaskStoreReadError):
                TaskStore(self.data_dir)

    def test_pathological_json_numbers_and_nesting_are_classified_as_corrupt(self):
        os.makedirs(self.data_dir, exist_ok=True)
        payloads = (
            b'{"schema_version":1,"revision":' + b"9" * 5000 + b',"tasks":[]}',
            (b"[" * 2000) + b"0" + (b"]" * 2000),
        )
        for payload in payloads:
            with self.subTest(prefix=payload[:20]):
                with open(self.store.path, "wb") as file_obj:
                    file_obj.write(payload)
                with self.assertRaises(TaskStoreCorruptError):
                    TaskStore(self.data_dir)

        self._write_json(self._payload([], revision=MAX_REVISION + 1))
        with self.assertRaises(TaskStoreCorruptError):
            TaskStore(self.data_dir)

    def test_revision_limit_is_classified_for_recovery_and_normal_mutation(self):
        interrupted = self._payload(
            [_task_record("limit_recovery", status="running")],
            revision=MAX_REVISION,
        )
        self._write_json(interrupted)
        with open(self.store.path, "rb") as file_obj:
            original = file_obj.read()

        with self.assertRaises(TaskStoreRecoveryError) as raised:
            TaskStore(self.data_dir)
        self.assertIsInstance(raised.exception.__cause__, TaskStoreWriteError)
        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original)

        self._write_json(self._payload([], revision=MAX_REVISION))
        loaded = TaskStore(self.data_dir)
        with self.assertRaises(TaskStoreWriteError):
            loaded.add_many(["revision_limit"])
        self.assertEqual(loaded.list(), [])
        self.assertEqual(loaded.revision, MAX_REVISION)

    def test_failed_reload_preserves_current_in_memory_state(self):
        self.store.add_many(["preserved_id"])
        before = self.store.list()
        before_revision = self.store.revision
        with open(self.store.path, "w", encoding="utf-8") as file_obj:
            file_obj.write("not-json")

        with self.assertRaises(TaskStoreCorruptError):
            self.store.load()
        self.assertEqual(self.store.list(), before)
        self.assertEqual(self.store.revision, before_revision)

    def test_stale_writer_detects_creation_by_another_instance(self):
        first = self.store
        stale = TaskStore(self.data_dir)
        first.add_many(["first_writer"])

        with self.assertRaisesRegex(TaskStoreConflictError, "另一个程序"):
            stale.add_many(["stale_writer"])
        self.assertEqual(stale.list(), [])
        self.assertEqual(stale.revision, 0)
        self.assertEqual([task.post_id for task in TaskStore(self.data_dir).list()], ["first_writer"])

    def test_stale_writer_detects_update_to_existing_file(self):
        self.store.add_many(["shared_id"])
        first = TaskStore(self.data_dir)
        stale = TaskStore(self.data_dir)
        first.update("shared_id", status="failed", error="new state")

        with self.assertRaisesRegex(TaskStoreConflictError, "另一个程序"):
            stale.remove(["shared_id"])
        self.assertEqual(stale.get("shared_id").status, "pending")
        self.assertEqual(TaskStore(self.data_dir).get("shared_id").status, "failed")

    def test_external_file_deletion_is_a_signature_conflict(self):
        self.store.add_many(["delete_conflict"])
        before = self.store.list()
        before_revision = self.store.revision
        os.remove(self.store.path)

        with self.assertRaisesRegex(TaskStoreConflictError, "另一个程序"):
            self.store.update("delete_conflict", status="failed")
        self.assertEqual(self.store.list(), before)
        self.assertEqual(self.store.revision, before_revision)

    def test_atomic_replace_failure_preserves_disk_and_memory(self):
        self.store.add_many(["atomic_id"])
        with open(self.store.path, "rb") as file_obj:
            before_bytes = file_obj.read()
        before_tasks = self.store.list()
        before_revision = self.store.revision

        with mock.patch.object(task_module.os, "replace", side_effect=PermissionError("locked")):
            with self.assertRaisesRegex(TaskStoreWriteError, "保存失败"):
                self.store.update("atomic_id", status="completed")

        with open(self.store.path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), before_bytes)
        self.assertEqual(self.store.list(), before_tasks)
        self.assertEqual(self.store.revision, before_revision)
        self.assertEqual(
            [name for name in os.listdir(self.data_dir) if name.startswith(".tasks.")],
            [],
        )

    def test_recovery_write_failures_preserve_valid_original_file(self):
        self._write_json(
            self._payload(
                [
                    _task_record("queued_recovery", status="queued"),
                    _task_record("running_recovery", status="running"),
                ],
                revision=12,
            )
        )
        with open(self.store.path, "rb") as file_obj:
            original = file_obj.read()

        failures = (
            (task_module.os, "fsync", OSError("simulated fsync failure")),
            (task_module.os, "replace", PermissionError("simulated replace failure")),
        )
        for target, attribute, failure in failures:
            with self.subTest(operation=attribute), mock.patch.object(
                target, attribute, side_effect=failure
            ):
                with self.assertRaisesRegex(
                    TaskStoreRecoveryError, "恢复状态无法持久化"
                ) as raised:
                    TaskStore(self.data_dir)

            self.assertIsInstance(raised.exception.__cause__, TaskStoreWriteError)
            with open(self.store.path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), original)
            self.assertEqual(
                [
                    name
                    for name in os.listdir(self.data_dir)
                    if name.startswith(".tasks.")
                ],
                [],
            )

    def test_recovery_error_bypasses_legacy_corrupt_file_handler(self):
        self.assertTrue(issubclass(TaskStoreRecoveryError, TaskStoreFailure))
        self.assertFalse(issubclass(TaskStoreRecoveryError, TaskStoreError))

    def test_one_store_serializes_simultaneous_thread_writers(self):
        worker_count = 8
        barrier = threading.Barrier(worker_count)

        def add(index):
            barrier.wait(timeout=5)
            return self.store.add_many([f"thread_{index}"])

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(add, range(worker_count)))

        self.assertEqual(results, [(1, 0)] * worker_count)
        self.assertEqual(self.store.revision, worker_count)
        self.assertEqual(
            {task.post_id for task in self.store.list()},
            {f"thread_{index}" for index in range(worker_count)},
        )
        self.assertEqual(TaskStore(self.data_dir).list(), self.store.list())


if __name__ == "__main__":
    unittest.main()
