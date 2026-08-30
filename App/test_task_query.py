# -*- coding: utf-8 -*-
"""Offline tests for bounded download-task filtering."""

from __future__ import annotations

import unittest
from unittest import mock

import task_query
from task_query import TaskQueryError, query_tasks
from task_store import DownloadTask, TASK_STATES


_FIXED_TIME = "2026-08-30T00:00:00+00:00"


def _task(post_id: str, *, status: str = "pending", **changes) -> DownloadTask:
    return DownloadTask(
        post_id=post_id,
        source_url="",
        status=status,
        added_at=_FIXED_TIME,
        updated_at=_FIXED_TIME,
        **changes,
    ).validated()


class TaskQueryTests(unittest.TestCase):
    def test_empty_query_preserves_task_store_order_without_mutation(self):
        tasks = (
            _task("third"),
            _task("first", status="failed", error="temporary failure"),
            _task("second", status="completed", output_files=("images/result.jpg",)),
        )
        before = tuple(tasks)

        self.assertEqual(query_tasks(tasks), tasks)
        self.assertEqual(tasks, before)

    def test_status_filter_accepts_every_persisted_state(self):
        tasks = tuple(_task(f"task_{status}", status=status) for status in TASK_STATES)
        for status in TASK_STATES:
            with self.subTest(status=status):
                self.assertEqual(
                    [task.post_id for task in query_tasks(tasks, status=status)],
                    [f"task_{status}"],
                )

    def test_nfkc_casefold_and_tokens_search_id_output_and_error(self):
        tasks = (
            _task(
                "Post_ALPHA",
                status="failed",
                error="Server TEMPORARY failure",
                output_files=("Images/Blue_Sky.JPG",),
            ),
            _task("Post_BETA", status="failed", error="different"),
        )

        self.assertEqual(
            [task.post_id for task in query_tasks(tasks, query="ｐｏｓｔ_alpha blue_sky")],
            ["Post_ALPHA"],
        )
        self.assertEqual(
            [task.post_id for task in query_tasks(tasks, status="failed", query="temporary")],
            ["Post_ALPHA"],
        )

    def test_invalid_status_query_and_controls_fail_closed(self):
        tasks = (_task("kept"),)
        invalid = (
            {"status": "unknown"},
            {"status": 1},
            {"query": 1},
            {"query": "x" * (task_query.MAX_TASK_QUERY_CHARS + 1)},
            {"query": "bad\nquery"},
            {"query": "bad\u200bquery"},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(TaskQueryError):
                    query_tasks(tasks, **arguments)

    def test_non_task_and_over_limit_iterables_fail_closed(self):
        with self.assertRaises(TaskQueryError):
            query_tasks([object()])
        with mock.patch.object(task_query, "MAX_TASKS", 2):
            with self.assertRaises(TaskQueryError):
                query_tasks((_task("one"), _task("two"), _task("three")))


if __name__ == "__main__":
    unittest.main()
