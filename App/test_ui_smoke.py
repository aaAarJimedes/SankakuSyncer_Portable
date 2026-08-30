# -*- coding: utf-8 -*-
"""Offline construction and portability smoke tests for the desktop UI."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

from bound_file_reader import BoundRootIdentity, get_bound_root_identity

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("SANKAKU_DISABLE_WEBENGINE", "1")


class _FakeSignal:
    def __init__(self) -> None:
        self._callbacks = []

    def connect(self, callback) -> None:
        self._callbacks.append(callback)

    def emit(self, *args) -> None:
        for callback in list(self._callbacks):
            callback(*args)


class _FakeSearchWorker:
    instances = []

    def __init__(self, settings, token, tags, rating, cursor, parent=None) -> None:
        self.settings = settings
        self.token = token
        self.tags = tags
        self.rating = rating
        self.cursor = cursor
        self.parent = parent
        self.succeeded = _FakeSignal()
        self.failed = _FakeSignal()
        self.cancelled = _FakeSignal()
        self.finished = _FakeSignal()
        self.running = False
        self.cancel_count = 0
        self.deleted = False
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True

    def isRunning(self) -> bool:  # noqa: N802 - Qt-compatible fake
        return self.running

    def cancel(self) -> None:
        self.cancel_count += 1

    def deleteLater(self) -> None:  # noqa: N802 - Qt-compatible fake
        self.deleted = True

    def complete(self) -> None:
        self.running = False
        self.finished.emit()


class _FakeLibraryWorker:
    instances = []

    def __init__(self, output_dir, parent=None) -> None:
        self.output_dir = os.path.abspath(output_dir)
        self.parent = parent
        self.progress = _FakeSignal()
        self.succeeded = _FakeSignal()
        self.failed = _FakeSignal()
        self.cancelled = _FakeSignal()
        self.finished = _FakeSignal()
        self.running = False
        self.cancel_count = 0
        self.deleted = False
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True

    def isRunning(self) -> bool:  # noqa: N802 - Qt-compatible fake
        return self.running

    def cancel(self) -> None:
        self.cancel_count += 1

    def wait(self, _milliseconds: int) -> bool:
        self.running = False
        return True

    def deleteLater(self) -> None:  # noqa: N802 - Qt-compatible fake
        self.deleted = True

    def complete(self) -> None:
        self.running = False
        self.finished.emit()


class _FakeLibraryThumbnailWorker:
    instances = []

    def __init__(self, output_dir, source, parent=None) -> None:
        self.output_dir = os.path.abspath(output_dir)
        self.source = source
        self.relative_path = source.relative_path
        self.parent = parent
        self.succeeded = _FakeSignal()
        self.failed = _FakeSignal()
        self.cancelled = _FakeSignal()
        self.finished = _FakeSignal()
        self.running = False
        self.cancel_count = 0
        self.wait_calls = []
        self.deleted = False
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True

    def isRunning(self) -> bool:  # noqa: N802 - Qt-compatible fake
        return self.running

    def cancel(self) -> None:
        self.cancel_count += 1

    def wait(self, milliseconds: int) -> bool:
        self.wait_calls.append(milliseconds)
        self.running = False
        return True

    def deleteLater(self) -> None:  # noqa: N802 - Qt-compatible fake
        self.deleted = True

    def complete(self) -> None:
        self.running = False
        self.finished.emit()


class _FakeDownloadWorker:
    instances = []

    def __init__(self, settings, token, tasks, parent=None) -> None:
        self.settings = settings
        self.token = token
        self.tasks = list(tasks)
        self.parent = parent
        self.item_started = _FakeSignal()
        self.item_progress = _FakeSignal()
        self.item_succeeded = _FakeSignal()
        self.item_warning = _FakeSignal()
        self.item_failed = _FakeSignal()
        self.batch_finished = _FakeSignal()
        self.batch_blocked = _FakeSignal()
        self.finished = _FakeSignal()
        self.running = False
        self.cancel_count = 0
        self.deleted = False
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True

    def isRunning(self) -> bool:  # noqa: N802 - Qt-compatible fake
        return self.running

    def cancel(self) -> None:
        self.cancel_count += 1

    def wait(self, _milliseconds: int) -> bool:
        self.running = False
        return True

    def deleteLater(self) -> None:  # noqa: N802 - Qt-compatible fake
        self.deleted = True

    def complete(self) -> None:
        self.running = False
        self.finished.emit()


class _MemoryVault:
    def __init__(self, state=None) -> None:
        self.state = state
        self.receipt = None
        self._generation = 0
        self.saved = []
        self.clear_count = 0
        self.restore_count = 0
        self.failures = {}

    def _fail(self, operation: str) -> None:
        failure = self.failures.get(operation)
        if failure is not None:
            raise failure

    def exists(self) -> bool:
        return self.state is not None

    def snapshot(self):
        self._fail("snapshot")
        return self.state

    def restore(self, snapshot) -> None:
        self.restore_count += 1
        self._fail("restore")
        self.state = snapshot

    def save(self, session):
        from credential_vault import VaultReceipt

        self._fail("save")
        self.saved.append(session)
        self.state = session
        self._generation += 1
        self.receipt = VaultReceipt(f"{self._generation:064x}")
        return self.receipt

    def clear(self) -> None:
        self.clear_count += 1
        self._fail("clear")
        self.state = None
        self.receipt = None

    def load(self):
        self._fail("load")
        return self.state

    def matches(self, receipt) -> bool:
        return self.receipt == receipt and self.state is not None

    def load_matching(self, receipt):
        self._fail("load")
        return self.state if self.matches(receipt) else None


class MainWindowOfflineSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtCore import QCoreApplication, Qt

        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])
        from ui_main_window import MAIN_TAB_TITLES, MainWindow

        cls.MainWindow = MainWindow
        cls.main_tab_titles = MAIN_TAB_TITLES

    def _close(self, window) -> None:
        window.close()
        window.deleteLater()
        self.app.processEvents()

    @staticmethod
    def _png_bytes(width=12, height=8) -> bytes:
        from PySide6.QtCore import QByteArray, QBuffer, QIODevice
        from PySide6.QtGui import QColor, QImage

        image = QImage(width, height, QImage.Format_ARGB32)
        image.fill(QColor(20, 110, 220, 255))
        payload = QByteArray()
        buffer = QBuffer(payload)
        if not buffer.open(QIODevice.WriteOnly):
            raise AssertionError("PNG test buffer did not open")
        try:
            if not image.save(buffer, "PNG"):
                raise AssertionError("PNG test image did not encode")
            return bytes(payload)
        finally:
            buffer.close()

    @staticmethod
    def _library_entry(
        post_id,
        *,
        status="verified",
        relative_path=None,
        size=1,
        author="",
        tags=(),
        created_at="",
        content_type="image/jpeg",
    ):
        from local_library import LibraryEntry

        return LibraryEntry(
            status=status,
            post_id=post_id,
            variant="original",
            relative_path=relative_path or f"{post_id}.jpg",
            size=size,
            content_type=content_type,
            rating="s",
            author=author,
            tags=tuple(tags),
            created_at=created_at,
            detail="",
            sha256="a" * 64 if status == "verified" else "",
        )

    @staticmethod
    def _library_report(entries):
        from local_library import LIBRARY_STATUSES, LibraryReport

        prepared = tuple(entries)
        counts = {
            status: sum(entry.status == status for entry in prepared)
            for status in LIBRARY_STATUSES
        }
        return LibraryReport(
            entries=prepared,
            scanned_candidates=len(prepared),
            verified_count=counts["verified"],
            checked_bytes=sum(
                entry.size for entry in prepared if entry.status == "verified"
            ),
            status_counts=counts,
        )

    def test_construction_is_offline_and_browser_is_lazy(self):
        from ui_browser_tab import BrowserTab

        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            BrowserTab, "ensure_loaded", autospec=True
        ) as ensure_loaded:
            window = self.MainWindow(root)
            try:
                self.assertEqual(len(self.main_tab_titles), 5)
                self.assertEqual(
                    tuple(
                        window.tabs.tabText(index)
                        for index in range(window.tabs.count())
                    ),
                    self.main_tab_titles,
                )
                self.assertIsNone(window.search_worker)
                self.assertIsNone(window.login_worker)
                self.assertIsNone(window.download_worker)
                self.assertIsNone(window.library_worker)
                self.assertEqual(window.results_summary.text(), "输入标签后点击搜索")
                self.assertEqual(window.search_edit.accessibleName(), "搜索标签")
                self.assertEqual(window.result_list.accessibleName(), "搜索结果")
                self.assertEqual(window.stop_search_button.accessibleName(), "停止搜索")
                self.assertFalse(window.previous_button.isEnabled())
                self.assertFalse(window.next_button.isEnabled())
                self.assertFalse(window.stop_search_button.isEnabled())
                ensure_loaded.assert_not_called()
            finally:
                self._close(window)

    def test_task_view_filters_searches_and_keeps_download_all_global(self):
        from task_store import DownloadTask

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker",
            _FakeDownloadWorker,
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(
                    (
                        DownloadTask("Pending_One", ""),
                        DownloadTask(
                            "Failed_Blue",
                            "",
                            status="failed",
                            error="temporary server failure",
                            output_files=("images/blue_sky.jpg",),
                        ),
                        DownloadTask(
                            "Completed_One",
                            "",
                            status="completed",
                            output_files=("images/finished.jpg",),
                        ),
                    )
                )
                window._refresh_tasks()

                visible_ids = lambda: [
                    window.task_model.task_at(row).post_id
                    for row in range(window.task_model.rowCount())
                ]
                self.assertEqual(
                    visible_ids(),
                    ["Pending_One", "Failed_Blue", "Completed_One"],
                )

                window.task_filter_combo.setCurrentIndex(
                    window.task_filter_combo.findData("failed")
                )
                window.task_search_edit.setText("blue_sky temporary")
                self.assertEqual(visible_ids(), ["Failed_Blue"])
                window.task_table.selectRow(0)
                self.assertEqual(window._selected_task_ids(), ["Failed_Blue"])

                window._retry_selected_tasks()
                self.assertEqual(window.task_store.get("Failed_Blue").status, "pending")
                self.assertEqual(visible_ids(), [])
                self.assertIn("显示 0 / 共 3", window.task_summary.text())

                window.task_search_edit.clear()
                window.task_filter_combo.setCurrentIndex(
                    window.task_filter_combo.findData("completed")
                )
                self.assertEqual(visible_ids(), ["Completed_One"])
                window._start_download(selected_only=False)
                self.assertEqual(len(_FakeDownloadWorker.instances), 1)
                self.assertEqual(
                    [task.post_id for task in _FakeDownloadWorker.instances[0].tasks],
                    ["Pending_One", "Failed_Blue"],
                )
            finally:
                self._close(window)

    def test_task_refresh_preserves_selection_current_and_viewport_by_post_id(self):
        from PySide6.QtCore import QItemSelectionModel
        from PySide6.QtWidgets import QAbstractItemView, QHeaderView
        from task_store import DownloadTask

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                tasks = tuple(
                    DownloadTask(
                        f"Post_{index:03d}",
                        "",
                        status="completed" if index % 4 == 0 else "pending",
                    )
                    for index in range(160)
                )
                window.task_store.add_many(tasks)
                window._refresh_tasks()
                window.tabs.setCurrentIndex(2)
                window.resize(720, 440)
                header = window.task_table.horizontalHeader()
                for column in range(window.task_model.columnCount()):
                    header.setSectionResizeMode(column, QHeaderView.Fixed)
                    header.resizeSection(column, 220)
                window.task_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
                window.show()
                self.app.processEvents()

                def row_for(post_id):
                    return next(
                        row
                        for row in range(window.task_model.rowCount())
                        if window.task_model.task_at(row).post_id == post_id
                    )

                selection = window.task_table.selectionModel()
                for post_id in ("Post_061", "Post_119"):
                    selection.select(
                        window.task_model.index(row_for(post_id), 0),
                        QItemSelectionModel.Select | QItemSelectionModel.Rows,
                    )
                selection.setCurrentIndex(
                    window.task_model.index(row_for("Post_119"), 5),
                    QItemSelectionModel.NoUpdate,
                )
                window.task_table.scrollTo(
                    window.task_model.index(row_for("Post_081"), 0),
                    QAbstractItemView.PositionAtTop,
                )
                vertical = window.task_table.verticalScrollBar()
                vertical.setValue(min(vertical.value() + 7, vertical.maximum()))
                horizontal = window.task_table.horizontalScrollBar()
                self.assertGreater(horizontal.maximum(), 0)
                horizontal.setValue(min(73, horizontal.maximum()))
                expected_horizontal = horizontal.value()
                self.app.processEvents()
                top_before_index = window.task_table.indexAt(
                    window.task_table.viewport().rect().topLeft()
                )
                top_before = window.task_model.task_at(top_before_index.row())
                self.assertEqual(top_before.post_id, "Post_081")
                expected_top_offset = window.task_table.visualRect(top_before_index).top()
                self.assertLess(expected_top_offset, 0)
                resets = []
                window.task_model.modelReset.connect(lambda: resets.append(True))

                window.task_filter_combo.setCurrentIndex(
                    window.task_filter_combo.findData("pending")
                )
                self.app.processEvents()

                self.assertEqual(resets, [True])
                self.assertEqual(
                    window._selected_task_ids(), ["Post_061", "Post_119"]
                )
                current = window.task_table.currentIndex()
                self.assertEqual(
                    window.task_model.task_at(current.row()).post_id, "Post_119"
                )
                self.assertEqual(current.column(), 5)
                top_after = window.task_table.indexAt(
                    window.task_table.viewport().rect().topLeft()
                )
                self.assertTrue(top_after.isValid())
                self.assertEqual(
                    window.task_model.task_at(top_after.row()).post_id, "Post_081"
                )
                self.assertEqual(
                    window.task_table.visualRect(top_after).top(), expected_top_offset
                )
                self.assertEqual(horizontal.value(), expected_horizontal)
            finally:
                self._close(window)

    def test_task_refresh_drops_hidden_and_deleted_ids_without_resurrection(self):
        from PySide6.QtCore import QItemSelectionModel
        from task_store import DownloadTask

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(
                    (
                        DownloadTask("Pending_A", "", status="pending"),
                        DownloadTask("Failed_B", "", status="failed"),
                        DownloadTask("Failed_C", "", status="failed"),
                    )
                )
                window._refresh_tasks()
                selection = window.task_table.selectionModel()
                selection.select(
                    window.task_model.index(0, 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )
                selection.select(
                    window.task_model.index(1, 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )
                selection.setCurrentIndex(
                    window.task_model.index(0, 3), QItemSelectionModel.NoUpdate
                )

                window.task_filter_combo.setCurrentIndex(
                    window.task_filter_combo.findData("failed")
                )
                self.assertEqual(window._selected_task_ids(), ["Failed_B"])
                self.assertFalse(window.task_table.currentIndex().isValid())

                window.task_filter_combo.setCurrentIndex(
                    window.task_filter_combo.findData("")
                )
                self.assertEqual(window._selected_task_ids(), ["Failed_B"])
                self.assertFalse(window.task_table.currentIndex().isValid())

                failed_b_row = next(
                    row
                    for row in range(window.task_model.rowCount())
                    if window.task_model.task_at(row).post_id == "Failed_B"
                )
                failed_c_row = next(
                    row
                    for row in range(window.task_model.rowCount())
                    if window.task_model.task_at(row).post_id == "Failed_C"
                )
                selection = window.task_table.selectionModel()
                selection.select(
                    window.task_model.index(failed_c_row, 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )
                selection.setCurrentIndex(
                    window.task_model.index(failed_b_row, 2),
                    QItemSelectionModel.NoUpdate,
                )
                window.task_store.remove(["Failed_B"])
                window._refresh_tasks()

                self.assertEqual(window._selected_task_ids(), ["Failed_C"])
                self.assertFalse(window.task_table.currentIndex().isValid())
            finally:
                self._close(window)

    def test_task_refresh_updates_same_rows_without_model_reset(self):
        from PySide6.QtCore import QItemSelectionModel
        from PySide6.QtWidgets import QAbstractItemView, QHeaderView
        from task_store import DownloadTask

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(
                    tuple(
                        DownloadTask(f"Post_{index:03d}", "", status="pending")
                        for index in range(160)
                    )
                )
                window._refresh_tasks()
                window.tabs.setCurrentIndex(2)
                window.resize(720, 440)
                header = window.task_table.horizontalHeader()
                for column in range(window.task_model.columnCount()):
                    header.setSectionResizeMode(column, QHeaderView.Fixed)
                    header.resizeSection(column, 220)
                window.task_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
                window.show()
                self.app.processEvents()
                selection = window.task_table.selectionModel()
                selection.select(
                    window.task_model.index(119, 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )
                selection.setCurrentIndex(
                    window.task_model.index(119, 5), QItemSelectionModel.NoUpdate
                )
                vertical = window.task_table.verticalScrollBar()
                horizontal = window.task_table.horizontalScrollBar()
                self.assertGreater(vertical.maximum(), 0)
                self.assertGreater(horizontal.maximum(), 0)
                vertical.setValue(min(923, vertical.maximum()))
                horizontal.setValue(min(73, horizontal.maximum()))
                self.app.processEvents()
                expected_vertical = vertical.value()
                expected_horizontal = horizontal.value()
                top_before = window.task_table.indexAt(
                    window.task_table.viewport().rect().topLeft()
                )
                self.assertTrue(top_before.isValid())
                expected_top_id = window.task_model.task_at(top_before.row()).post_id
                expected_top_offset = window.task_table.visualRect(top_before).top()
                resets = []
                changes = []
                window.task_model.modelReset.connect(lambda: resets.append(True))
                window.task_model.dataChanged.connect(
                    lambda top_left, bottom_right, roles: changes.append(
                        (top_left.row(), bottom_right.row(), tuple(roles))
                    )
                )

                window.task_store.update("Post_119", status="completed")
                window._refresh_tasks()
                self.app.processEvents()

                self.assertEqual(resets, [])
                self.assertEqual(len(changes), 1)
                self.assertEqual(changes[0][:2], (119, 119))
                self.assertEqual(window._selected_task_ids(), ["Post_119"])
                current = window.task_table.currentIndex()
                self.assertTrue(current.isValid())
                self.assertEqual(
                    window.task_model.task_at(current.row()).post_id, "Post_119"
                )
                self.assertEqual(current.column(), 5)
                self.assertEqual(window.task_model.task_at(119).status, "completed")
                self.assertEqual(vertical.value(), expected_vertical)
                self.assertEqual(horizontal.value(), expected_horizontal)
                top_after = window.task_table.indexAt(
                    window.task_table.viewport().rect().topLeft()
                )
                self.assertTrue(top_after.isValid())
                self.assertEqual(
                    window.task_model.task_at(top_after.row()).post_id,
                    expected_top_id,
                )
                self.assertEqual(
                    window.task_table.visualRect(top_after).top(), expected_top_offset
                )
            finally:
                self._close(window)

    def test_selected_task_ids_reads_selection_ranges_at_task_limit(self):
        from PySide6.QtCore import QItemSelection, QItemSelectionModel
        from task_store import DownloadTask, MAX_TASKS

        class _SelectionRangeCoordinates:
            def __init__(self, selected_range):
                self._selected_range = selected_range

            def isValid(self):  # noqa: N802 - Qt-compatible facade
                return self._selected_range.isValid()

            def top(self):
                return self._selected_range.top()

            def bottom(self):
                return self._selected_range.bottom()

            def left(self):
                return self._selected_range.left()

            def right(self):
                return self._selected_range.right()

        class _SelectionCoordinates:
            def __init__(self, selection):
                self._selection = selection

            def __iter__(self):
                return (
                    _SelectionRangeCoordinates(selected_range)
                    for selected_range in self._selection
                )

        class _SelectionRangesOnly:
            def __init__(self, selection_model):
                self._selection_model = selection_model

            def selection(self):
                return _SelectionCoordinates(self._selection_model.selection())

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                tasks = tuple(
                    DownloadTask(f"Post_{index:05d}", "", status="pending")
                    for index in range(MAX_TASKS)
                )
                window.task_model.set_tasks(tasks)
                selection_model = window.task_table.selectionModel()
                selection_model.select(
                    QItemSelection(
                        window.task_model.index(0, 0),
                        window.task_model.index(
                            len(tasks) - 1, window.task_model.columnCount() - 1
                        ),
                    ),
                    QItemSelectionModel.ClearAndSelect,
                )

                with mock.patch.object(
                    window.task_table,
                    "selectionModel",
                    return_value=_SelectionRangesOnly(selection_model),
                ), mock.patch.object(
                    window.task_model,
                    "index",
                    side_effect=AssertionError("must not materialize selected indexes"),
                ), mock.patch.object(
                    window.task_model,
                    "createIndex",
                    side_effect=AssertionError("must not materialize selected indexes"),
                ):
                    selected_ids = window._selected_task_ids()

                self.assertEqual(len(selected_ids), len(tasks))
                self.assertEqual(selected_ids[0], "Post_00000")
                self.assertEqual(selected_ids[-1], "Post_09999")

                selection_model.select(
                    window.task_model.index(4, 0),
                    QItemSelectionModel.ClearAndSelect,
                )
                with mock.patch.object(
                    window.task_table,
                    "selectionModel",
                    return_value=_SelectionRangesOnly(selection_model),
                ), mock.patch.object(
                    window.task_model,
                    "index",
                    side_effect=AssertionError("must not materialize selected indexes"),
                ), mock.patch.object(
                    window.task_model,
                    "createIndex",
                    side_effect=AssertionError("must not materialize selected indexes"),
                ):
                    self.assertEqual(window._selected_task_ids(), [])
            finally:
                self._close(window)

    def test_search_cancel_is_single_shot_and_preserves_committed_page(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.SearchWorker", _FakeSearchWorker
        ):
            _FakeSearchWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._search_query = "old_tag"
                window._search_rating = "s"
                window._search_cursor = "cursor-a"
                window._cursor_history = [""]
                window._next_cursor = "cursor-b"
                window.results_summary.setText("本页 2 项")
                window.previous_button.setEnabled(True)
                window.next_button.setEnabled(True)
                window.search_edit.setText("new_tag")

                window._start_search(reset=True)
                worker = _FakeSearchWorker.instances[-1]
                self.assertTrue(window.stop_search_button.isEnabled())
                self.assertFalse(window.search_button.isEnabled())
                self.assertFalse(window.previous_button.isEnabled())
                self.assertFalse(window.next_button.isEnabled())

                window._stop_search()
                window._stop_search()
                self.assertEqual(worker.cancel_count, 1)
                self.assertFalse(window.stop_search_button.isEnabled())
                worker.cancelled.emit()
                worker.complete()

                self.assertEqual(window._search_query, "old_tag")
                self.assertEqual(window._search_cursor, "cursor-a")
                self.assertEqual(window._cursor_history, [""])
                self.assertEqual(window._next_cursor, "cursor-b")
                self.assertEqual(window.results_summary.text(), "本页 2 项")
                self.assertTrue(window.previous_button.isEnabled())
                self.assertTrue(window.next_button.isEnabled())
                self.assertNotIn("搜索失败", window.log_view.toPlainText())
                self.assertIn("搜索已取消", window.status_label.text())
            finally:
                self._close(window)

    def test_success_racing_after_stop_cannot_replace_the_committed_page(self):
        from sankaku_api import SearchPage

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.SearchWorker", _FakeSearchWorker
        ):
            _FakeSearchWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._search_query = "old_tag"
                window._search_rating = "s"
                window._search_cursor = "cursor-a"
                window._cursor_history = [""]
                window._next_cursor = "cursor-b"
                window.results_summary.setText("本页 4 项")

                window._search_next()
                worker = _FakeSearchWorker.instances[-1]
                window._stop_search()
                worker.succeeded.emit(SearchPage((), "cursor-c", "cursor-a"))
                worker.complete()

                self.assertEqual(window._search_query, "old_tag")
                self.assertEqual(window._search_cursor, "cursor-a")
                self.assertEqual(window._cursor_history, [""])
                self.assertEqual(window._next_cursor, "cursor-b")
                self.assertEqual(window.results_summary.text(), "本页 4 项")
                self.assertIn("搜索已取消", window.status_label.text())
            finally:
                self._close(window)

    def test_new_search_waits_for_prior_finished_signal_even_after_thread_stops(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.SearchWorker", _FakeSearchWorker
        ):
            _FakeSearchWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.search_edit.setText("first")
                window._start_search(reset=True)
                first = _FakeSearchWorker.instances[-1]
                first.running = False

                window.search_edit.setText("second")
                window._start_search(reset=True)
                self.assertEqual(len(_FakeSearchWorker.instances), 1)
                self.assertIs(window.search_worker, first)

                first.failed.emit("first failed")
                first.complete()
                window._start_search(reset=True)
                self.assertEqual(len(_FakeSearchWorker.instances), 2)
                self.assertEqual(_FakeSearchWorker.instances[-1].tags, "second")
            finally:
                # Finish the second fake so closeEvent sees no live worker.
                if window.search_worker is not None:
                    window.search_worker.failed.emit("cleanup")
                    window.search_worker.complete()
                self._close(window)

    def test_pagination_is_transactional_across_failure_and_success(self):
        from sankaku_api import SearchPage

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.SearchWorker", _FakeSearchWorker
        ):
            _FakeSearchWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._search_query = "committed_tag"
                window._search_rating = "s"
                window._search_cursor = "cursor-a"
                window._cursor_history = [""]
                window._next_cursor = "cursor-b"
                window.results_summary.setText("本页 3 项")
                window.search_edit.setText("edited_but_not_submitted")
                questionable = window.rating_combo.findData("q")
                window.rating_combo.setCurrentIndex(questionable)

                window._search_next()
                failed = _FakeSearchWorker.instances[-1]
                self.assertEqual(failed.tags, "committed_tag")
                self.assertEqual(failed.rating, "s")
                self.assertEqual(failed.cursor, "cursor-b")
                failed.failed.emit("单页读取失败")
                failed.complete()

                self.assertEqual(window._search_cursor, "cursor-a")
                self.assertEqual(window._cursor_history, [""])
                self.assertEqual(window._next_cursor, "cursor-b")
                self.assertEqual(window.results_summary.text(), "本页 3 项")
                self.assertTrue(window.previous_button.isEnabled())
                self.assertTrue(window.next_button.isEnabled())

                window._search_next()
                succeeded = _FakeSearchWorker.instances[-1]
                succeeded.succeeded.emit(SearchPage((), "cursor-c", "cursor-a"))
                succeeded.complete()

                self.assertEqual(window._search_query, "committed_tag")
                self.assertEqual(window._search_rating, "s")
                self.assertEqual(window._search_cursor, "cursor-b")
                self.assertEqual(window._cursor_history, ["", "cursor-a"])
                self.assertEqual(window._next_cursor, "cursor-c")
                self.assertEqual(window.results_summary.text(), "本页 0 项")
                self.assertTrue(window.previous_button.isEnabled())
                self.assertTrue(window.next_button.isEnabled())
            finally:
                self._close(window)

    def test_local_library_success_commits_report_filters_and_uses_saved_path(self):
        from PySide6.QtCore import Qt
        from local_library import LibraryEntry, LibraryReport

        entries = (
            LibraryEntry(
                status="verified",
                post_id="Post_A",
                variant="original",
                relative_path="Post_A.jpg",
                size=2048,
                content_type="image/jpeg",
                rating="s",
                author="artist",
                tags=("tag_a", "tag_b"),
                created_at="2026-01-01T00:00:00Z",
                detail="",
                sha256="a" * 64,
            ),
            LibraryEntry(
                status="missing_metadata",
                post_id="Post_B",
                variant="sample",
                relative_path="Post_B.sample.png",
                size=1024,
                content_type="image/png",
                rating="",
                author="",
                tags=(),
                created_at="",
                detail="缺少相邻元数据",
            ),
        )
        report = LibraryReport(
            entries=entries,
            scanned_candidates=2,
            verified_count=1,
            checked_bytes=2048,
            status_counts={
                "verified": 1,
                "changed": 0,
                "invalid_metadata": 0,
                "missing_media": 0,
                "missing_metadata": 1,
                "unsafe_path": 0,
                "unreadable": 0,
            },
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryScanWorker", _FakeLibraryWorker
        ):
            _FakeLibraryWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._start_library_scan()
                worker = _FakeLibraryWorker.instances[-1]
                self.assertEqual(
                    worker.output_dir,
                    os.path.abspath(os.path.join(root, "Downloads")),
                )
                self.assertFalse(window.library_scan_button.isEnabled())
                self.assertTrue(window.library_stop_button.isEnabled())
                worker.progress.emit(1, 2, 5_000_000_000)
                self.assertIn("4.7 GiB", window.library_summary.text())
                worker.succeeded.emit(report)
                worker.complete()
                self.assertIs(window._library_report, report)
                self.assertEqual(window.library_model.rowCount(), 2)
                self.assertIn("已验证 1", window.library_summary.text())
                self.assertEqual(
                    window.library_model.data(
                        window.library_model.index(0, 7), Qt.ToolTipRole
                    ),
                    "tag_a tag_b",
                )
                self.assertIsNone(
                    window.library_model.data(window.library_model.index(-1, 0))
                )

                missing_index = window.library_filter_combo.findData(
                    "missing_metadata"
                )
                window.library_filter_combo.setCurrentIndex(missing_index)
                self.assertEqual(window.library_model.rowCount(), 1)
                self.assertEqual(
                    window.library_model.data(window.library_model.index(0, 0)),
                    "Post_B",
                )
                with mock.patch.object(window, "_open_post") as open_post:
                    window._open_library_row(0, 0)
                open_post.assert_called_once_with("Post_B")
            finally:
                self._close(window)

    def test_local_library_ui_combines_search_status_and_all_sort_modes(self):
        entries = (
            self._library_entry(
                "10",
                relative_path="sunrise.jpeg",
                size=30,
                author="Alice Artist",
                tags=("blue_sky", "landscape"),
                created_at="2024-01-01T00:00:00Z",
            ),
            self._library_entry(
                "2",
                relative_path="mountain.webp",
                size=100,
                author="Bob Creator",
                tags=("red_sunset",),
                created_at="2026-01-01T00:00:00Z",
                content_type="image/webp",
            ),
            self._library_entry(
                "3",
                status="changed",
                relative_path="archive.png",
                size=200,
                author="Alice Artist",
                tags=("blue_sky", "portrait"),
                created_at="2025-01-01T00:00:00Z",
                content_type="image/png",
            ),
        )
        report = self._library_report(entries)

        def visible_ids(window):
            return [
                window.library_model.data(window.library_model.index(row, 0))
                for row in range(window.library_model.rowCount())
            ]

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._library_report = report
                window._library_report_root = os.path.join(root, "Downloads")
                window._library_report_root_identity = get_bound_root_identity(
                    window._library_report_root
                )
                window._refresh_library_table()
                self.assertEqual(visible_ids(window), ["2", "3", "10"])

                expected_queries = (
                    ("10", ["10"]),
                    ("alice", ["3", "10"]),
                    ("blue_sky", ["3", "10"]),
                    ("mountain.webp", ["2"]),
                )
                for query, expected in expected_queries:
                    with self.subTest(query=query):
                        window.library_search_edit.setText(query)
                        self.assertEqual(visible_ids(window), expected)

                verified_index = window.library_filter_combo.findData("verified")
                window.library_filter_combo.setCurrentIndex(verified_index)
                window.library_search_edit.setText("alice blue_sky")
                self.assertEqual(visible_ids(window), ["10"])

                changed_index = window.library_filter_combo.findData("changed")
                window.library_filter_combo.setCurrentIndex(changed_index)
                window.library_search_edit.setText("alice archive.png")
                self.assertEqual(visible_ids(window), ["3"])

                window.library_filter_combo.setCurrentIndex(
                    window.library_filter_combo.findData("")
                )
                window.library_search_edit.clear()
                expected_sorts = (
                    ("id_asc", ["2", "3", "10"]),
                    ("id_desc", ["10", "3", "2"]),
                    ("newest", ["2", "3", "10"]),
                    ("largest", ["3", "2", "10"]),
                )
                for sort, expected in expected_sorts:
                    with self.subTest(sort=sort):
                        window.library_sort_combo.setCurrentIndex(
                            window.library_sort_combo.findData(sort)
                        )
                        self.assertEqual(visible_ids(window), expected)
                self.assertEqual(_FakeLibraryThumbnailWorker.instances, [])
            finally:
                self._close(window)

    def test_library_refresh_preserves_context_and_preview_by_relative_path(self):
        from PySide6.QtCore import QItemSelectionModel
        from PySide6.QtWidgets import QAbstractItemView, QHeaderView

        entries = tuple(
            self._library_entry(f"Post_{index:03d}") for index in range(160)
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            window._library_report = self._library_report(entries)
            try:
                window._refresh_library_table()
                window.tabs.setCurrentIndex(3)
                window.resize(760, 460)
                header = window.library_table.horizontalHeader()
                for column in range(window.library_model.columnCount()):
                    header.setSectionResizeMode(column, QHeaderView.Fixed)
                    header.resizeSection(column, 220)
                window.library_table.setVerticalScrollMode(
                    QAbstractItemView.ScrollPerPixel
                )
                window.show()
                self.app.processEvents()

                def row_for(relative_path):
                    return next(
                        row
                        for row in range(window.library_model.rowCount())
                        if window.library_model.entry_at(row).relative_path
                        == relative_path
                    )

                selection = window.library_table.selectionModel()
                selected_path = "Post_119.jpg"
                selection.select(
                    window.library_model.index(row_for(selected_path), 0),
                    QItemSelectionModel.ClearAndSelect
                    | QItemSelectionModel.Rows,
                )
                selection.setCurrentIndex(
                    window.library_model.index(row_for(selected_path), 7),
                    QItemSelectionModel.NoUpdate,
                )
                self.app.processEvents()
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), 1)
                preview_worker = _FakeLibraryThumbnailWorker.instances[0]
                self.assertIs(window.library_preview_worker, preview_worker)

                top_path = "Post_081.jpg"
                window.library_table.scrollTo(
                    window.library_model.index(row_for(top_path), 0),
                    QAbstractItemView.PositionAtTop,
                )
                vertical = window.library_table.verticalScrollBar()
                vertical.setValue(min(vertical.value() + 7, vertical.maximum()))
                horizontal = window.library_table.horizontalScrollBar()
                self.assertGreater(horizontal.maximum(), 0)
                horizontal.setValue(min(73, horizontal.maximum()))
                expected_horizontal = horizontal.value()
                self.app.processEvents()
                top_before = window.library_table.indexAt(
                    window.library_table.viewport().rect().topLeft()
                )
                self.assertTrue(top_before.isValid())
                self.assertEqual(
                    window.library_model.entry_at(top_before.row()).relative_path,
                    top_path,
                )
                expected_top_offset = window.library_table.visualRect(top_before).top()
                self.assertLess(expected_top_offset, 0)

                resets = []
                window.library_model.modelReset.connect(lambda: resets.append(True))
                window.library_sort_combo.setCurrentIndex(
                    window.library_sort_combo.findData("id_desc")
                )
                self.app.processEvents()

                self.assertEqual(resets, [True])
                current = window.library_table.currentIndex()
                self.assertTrue(current.isValid())
                self.assertEqual(
                    window.library_model.entry_at(current.row()).relative_path,
                    selected_path,
                )
                self.assertEqual(current.column(), 7)
                self.assertEqual(
                    [
                        window.library_model.entry_at(index.row()).relative_path
                        for index in window.library_table.selectionModel().selectedRows()
                    ],
                    [selected_path],
                )
                top_after = window.library_table.indexAt(
                    window.library_table.viewport().rect().topLeft()
                )
                self.assertTrue(top_after.isValid())
                self.assertEqual(
                    window.library_model.entry_at(top_after.row()).relative_path,
                    top_path,
                )
                self.assertEqual(
                    window.library_table.visualRect(top_after).top(),
                    expected_top_offset,
                )
                self.assertEqual(horizontal.value(), expected_horizontal)
                self.assertIs(window.library_preview_worker, preview_worker)
                self.assertEqual(preview_worker.cancel_count, 0)

                window.library_search_edit.setText("119")
                self.app.processEvents()
                current = window.library_table.currentIndex()
                self.assertTrue(current.isValid())
                self.assertEqual(
                    window.library_model.entry_at(current.row()).relative_path,
                    selected_path,
                )
                self.assertIs(window.library_preview_worker, preview_worker)
                self.assertEqual(preview_worker.cancel_count, 0)

                window.library_search_edit.setText("does_not_match")
                self.app.processEvents()
                self.assertFalse(window.library_table.currentIndex().isValid())
                self.assertEqual(
                    window.library_table.selectionModel().selectedRows(), []
                )
                self.assertEqual(preview_worker.cancel_count, 1)
                self.assertIsNone(window._library_preview_entry)

                window.library_search_edit.clear()
                self.app.processEvents()
                self.assertFalse(window.library_table.currentIndex().isValid())
                self.assertEqual(
                    window.library_table.selectionModel().selectedRows(), []
                )
                self.assertEqual(preview_worker.cancel_count, 1)
            finally:
                if window.library_preview_worker is not None:
                    window.library_preview_worker.complete()
                self._close(window)

    def test_library_refresh_restarts_preview_when_binding_changes(self):
        from dataclasses import replace
        from PySide6.QtCore import QItemSelectionModel

        original = self._library_entry("Bound", relative_path="Bound.jpg")
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            window._library_report = self._library_report((original,))
            try:
                window._refresh_library_table()
                selection = window.library_table.selectionModel()
                selection.select(
                    window.library_model.index(0, 0),
                    QItemSelectionModel.ClearAndSelect
                    | QItemSelectionModel.Rows,
                )
                selection.setCurrentIndex(
                    window.library_model.index(0, 3),
                    QItemSelectionModel.NoUpdate,
                )
                self.app.processEvents()
                first = _FakeLibraryThumbnailWorker.instances[-1]

                changed = replace(original, size=original.size + 1, sha256="b" * 64)
                window._library_report = self._library_report((changed,))
                resets = []
                changes = []
                window.library_model.modelReset.connect(lambda: resets.append(True))
                window.library_model.dataChanged.connect(
                    lambda top_left, bottom_right, _roles: changes.append(
                        (top_left.row(), bottom_right.row())
                    )
                )
                window._refresh_library_table()

                self.assertEqual(resets, [])
                self.assertEqual(changes, [(0, 0)])
                self.assertEqual(first.cancel_count, 1)
                self.assertIs(window.library_preview_worker, first)
                self.assertIsNotNone(window._library_preview_pending)
                self.assertEqual(window._library_preview_pending[1].entry, changed)
                current = window.library_table.currentIndex()
                self.assertTrue(current.isValid())
                self.assertEqual(current.column(), 3)
                self.assertEqual(
                    window.library_model.entry_at(current.row()), changed
                )

                first.complete()
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), 2)
                replacement = _FakeLibraryThumbnailWorker.instances[-1]
                self.assertIs(window.library_preview_worker, replacement)
                self.assertEqual(replacement.source.size, changed.size)
                self.assertEqual(replacement.source.sha256, changed.sha256)

                other_root = os.path.join(root, "OtherDownloads")
                os.makedirs(other_root)
                other_identity = get_bound_root_identity(other_root)
                window._library_report_root = other_root
                window._library_report_root_identity = other_identity
                window._refresh_library_table()
                self.assertEqual(replacement.cancel_count, 1)
                self.assertIsNotNone(window._library_preview_pending)
                pending_binding = window._library_preview_pending[1]
                self.assertEqual(pending_binding.report_root, other_root)
                self.assertEqual(pending_binding.report_root_identity, other_identity)
                self.assertEqual(pending_binding.entry, changed)

                replacement.complete()
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), 3)
                rebound = _FakeLibraryThumbnailWorker.instances[-1]
                self.assertIs(window.library_preview_worker, rebound)
                self.assertEqual(rebound.output_dir, os.path.abspath(other_root))
                self.assertEqual(rebound.source.root_identity, other_identity)
                rebound.complete()
            finally:
                if window.library_preview_worker is not None:
                    window.library_preview_worker.complete()
                self._close(window)

    def test_local_library_preview_starts_only_for_verified_supported_images(self):
        supported = (
            self._library_entry("Jpeg", relative_path="Jpeg.jpg"),
            self._library_entry(
                "Png", relative_path="Png.png", content_type="image/png"
            ),
            self._library_entry(
                "Webp", relative_path="Webp.webp", content_type="image/webp"
            ),
        )
        unverified = self._library_entry(
            "Changed", status="changed", relative_path="Changed.jpg"
        )
        video = self._library_entry(
            "Video", relative_path="Video.mp4", content_type="video/mp4"
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            try:
                window._library_report = self._library_report(
                    (*supported, unverified, video)
                )
                window._refresh_library_table()

                def select(entry):
                    row = next(
                        index
                        for index in range(window.library_model.rowCount())
                        if window.library_model.entry_at(index) is entry
                    )
                    window.library_table.setCurrentIndex(
                        window.library_model.index(row, 0)
                    )
                    self.app.processEvents()

                for entry in supported:
                    with self.subTest(path=entry.relative_path):
                        previous = len(_FakeLibraryThumbnailWorker.instances)
                        select(entry)
                        self.assertEqual(
                            len(_FakeLibraryThumbnailWorker.instances), previous + 1
                        )
                        worker = _FakeLibraryThumbnailWorker.instances[-1]
                        self.assertEqual(worker.relative_path, entry.relative_path)
                        self.assertEqual(
                            worker.output_dir,
                            os.path.abspath(window._library_report_root),
                        )
                        self.assertTrue(worker.running)
                        worker.complete()
                        self.assertIsNone(window.library_preview_worker)

                previous = len(_FakeLibraryThumbnailWorker.instances)
                select(unverified)
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), previous)
                self.assertIn("未通过完整性", window.library_preview_image.text())

                select(video)
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), previous)
                self.assertIn("不提供离线图片预览", window.library_preview_image.text())
            finally:
                self._close(window)

    def test_local_library_preview_serializes_latest_request_and_ignores_stale_signals(self):
        from library_thumbnail import LibraryThumbnail

        first_entry = self._library_entry("A", relative_path="A.jpg")
        latest_entry = self._library_entry(
            "B", relative_path="B.png", content_type="image/png"
        )
        stale_result = LibraryThumbnail(
            relative_path="A.jpg",
            size=first_entry.size,
            sha256=first_entry.sha256,
            content_type=first_entry.content_type,
            root_identity=BoundRootIdentity(
                "windows" if os.name == "nt" else "posix", 1, b"stale"
            ),
            width=100,
            height=50,
            png_bytes=self._png_bytes(),
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            try:
                window._request_library_preview(first_entry)
                first = _FakeLibraryThumbnailWorker.instances[-1]
                window._request_library_preview(latest_entry)

                self.assertEqual(first.cancel_count, 1)
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), 1)
                self.assertIs(window.library_preview_worker, first)
                self.assertIsNotNone(window._library_preview_pending)
                self.assertEqual(
                    window._library_preview_pending[1].entry.relative_path, "B.png"
                )
                loading_text = window.library_preview_image.text()
                loading_meta = window.library_preview_meta.text()

                first.succeeded.emit(stale_result)
                first.failed.emit("stale failure must be ignored")
                self.assertEqual(window.library_preview_image.text(), loading_text)
                self.assertEqual(window.library_preview_meta.text(), loading_meta)
                self.assertTrue(window.library_preview_image.pixmap().isNull())

                first.complete()
                self.assertTrue(first.deleted)
                self.assertEqual(len(_FakeLibraryThumbnailWorker.instances), 2)
                latest = _FakeLibraryThumbnailWorker.instances[-1]
                self.assertIs(window.library_preview_worker, latest)
                self.assertEqual(latest.relative_path, "B.png")
                self.assertTrue(latest.running)
                self.assertIsNone(window._library_preview_pending)

                first.succeeded.emit(stale_result)
                first.failed.emit("late stale failure must be ignored")
                self.assertEqual(window.library_preview_image.text(), loading_text)
                self.assertEqual(window.library_preview_meta.text(), loading_meta)
                self.assertIs(window.library_preview_worker, latest)
                latest.complete()
            finally:
                if window.library_preview_worker is not None:
                    window.library_preview_worker.complete()
                self._close(window)

    def test_local_library_preview_success_loads_png_on_the_main_thread(self):
        from PySide6.QtCore import QThread
        from library_thumbnail import LibraryThumbnail

        entry = self._library_entry(
            "Preview", relative_path="Preview.png", content_type="image/png"
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            result = LibraryThumbnail(
                relative_path="Preview.png",
                size=entry.size,
                sha256=entry.sha256,
                content_type=entry.content_type,
                root_identity=window._library_report_root_identity,
                width=640,
                height=320,
                png_bytes=self._png_bytes(24, 12),
            )
            observed_main_thread = []
            original = window._library_preview_succeeded

            def recording_success(*args):
                observed_main_thread.append(
                    QThread.currentThread() is self.app.thread()
                )
                return original(*args)

            try:
                with mock.patch.object(
                    window,
                    "_library_preview_succeeded",
                    side_effect=recording_success,
                ):
                    window._request_library_preview(entry)
                    worker = _FakeLibraryThumbnailWorker.instances[-1]
                    worker.succeeded.emit(result)
                self.assertEqual(observed_main_thread, [True])
                pixmap = window.library_preview_image.pixmap()
                self.assertFalse(pixmap.isNull())
                self.assertEqual((pixmap.width(), pixmap.height()), (24, 12))
                self.assertEqual(window.library_preview_image.text(), "")
                self.assertIn("原图 640 × 320", window.library_preview_meta.text())
                worker.complete()
            finally:
                if window.library_preview_worker is not None:
                    window.library_preview_worker.complete()
                self._close(window)

    def test_close_cancels_and_waits_for_an_active_library_preview(self):
        class FakeEvent:
            accepted = False
            ignored = False

            def accept(self):
                self.accepted = True

            def ignore(self):
                self.ignored = True

        entry = self._library_entry("Closing", relative_path="Closing.jpg")
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryThumbnailWorker",
            _FakeLibraryThumbnailWorker,
        ):
            _FakeLibraryThumbnailWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report_root = os.path.join(root, "Downloads")
            window._library_report_root_identity = get_bound_root_identity(
                window._library_report_root
            )
            event = FakeEvent()
            try:
                window._request_library_preview(entry)
                worker = _FakeLibraryThumbnailWorker.instances[-1]
                window.closeEvent(event)
                self.assertGreaterEqual(worker.cancel_count, 1)
                self.assertEqual(len(worker.wait_calls), 1)
                self.assertGreaterEqual(worker.wait_calls[0], 0)
                self.assertLessEqual(worker.wait_calls[0], 10_000)
                self.assertTrue(event.accepted)
                self.assertFalse(event.ignored)
            finally:
                window.library_preview_worker = None
                self._close(window)

    def test_local_library_stop_is_single_shot_and_late_success_is_ignored(self):
        from local_library import LibraryReport

        old = LibraryReport(
            entries=(),
            scanned_candidates=7,
            verified_count=0,
            checked_bytes=0,
            status_counts={},
        )
        late = LibraryReport(
            entries=(),
            scanned_candidates=99,
            verified_count=0,
            checked_bytes=0,
            status_counts={},
        )
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryScanWorker", _FakeLibraryWorker
        ):
            _FakeLibraryWorker.instances.clear()
            window = self.MainWindow(root)
            window._library_report = old
            try:
                window._start_library_scan()
                worker = _FakeLibraryWorker.instances[-1]
                window._stop_library_scan()
                window._stop_library_scan()
                self.assertEqual(worker.cancel_count, 1)
                worker.succeeded.emit(late)
                worker.cancelled.emit()
                worker.complete()
                self.assertIs(window._library_report, old)
                self.assertIn("已取消", window.status_label.text())
                self.assertNotIn("正在", window.library_summary.text())
                self.assertIn("显示 0 / 0", window.library_summary.text())
                self.assertTrue(window.library_scan_button.isEnabled())
            finally:
                self._close(window)

    def test_local_library_failure_without_old_report_restores_terminal_summary(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryScanWorker", _FakeLibraryWorker
        ):
            _FakeLibraryWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window._start_library_scan()
                worker = _FakeLibraryWorker.instances[-1]
                worker.progress.emit(1, 3, 4096)
                worker.failed.emit("下载目录不可用（PermissionError）")
                worker.complete()
                self.assertIsNone(window._library_report)
                self.assertEqual(window.library_model.rowCount(), 0)
                self.assertEqual(window.library_summary.text(), "扫描失败，未生成报告")
                self.assertNotIn("正在", window.library_summary.text())
            finally:
                self._close(window)

    def test_local_library_worker_construction_failure_restores_summary(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.LibraryScanWorker",
            side_effect=RuntimeError("sensitive detail"),
        ), mock.patch("ui_main_window.QMessageBox.warning") as warning:
            window = self.MainWindow(root)
            try:
                window._start_library_scan()
                self.assertIsNone(window.library_worker)
                self.assertEqual(window.library_summary.text(), "未能启动扫描")
                self.assertTrue(window.library_scan_button.isEnabled())
                self.assertFalse(window.library_stop_button.isEnabled())
                self.assertNotIn("sensitive detail", warning.call_args.args[-1])
            finally:
                self._close(window)

    def test_local_library_and_download_batches_are_mutually_exclusive(self):
        class IdleWorker:
            def isRunning(self) -> bool:  # noqa: N802 - Qt-compatible fake
                return False

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                window.library_worker = IdleWorker()
                window._start_download(selected_only=False)
                self.assertIn("本地库校验", window.status_label.text())
                window.library_worker = None

                window.download_worker = IdleWorker()
                window._start_library_scan()
                self.assertIn("下载批次", window.status_label.text())
            finally:
                window.download_worker = None
                window.library_worker = None
                self._close(window)

    def test_close_cancels_and_waits_for_an_active_library_scan(self):
        class FakeEvent:
            accepted = False
            ignored = False

            def accept(self):
                self.accepted = True

            def ignore(self):
                self.ignored = True

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            worker = _FakeLibraryWorker(root, window)
            worker.start()
            window.library_worker = worker
            event = FakeEvent()
            try:
                window.closeEvent(event)
                self.assertEqual(worker.cancel_count, 1)
                self.assertTrue(event.accepted)
                self.assertFalse(event.ignored)
            finally:
                window.library_worker = None
                self._close(window)

    def test_new_download_waits_for_prior_finished_signal_after_thread_stops(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                first = _FakeDownloadWorker.instances[-1]
                first.running = False

                # QThread can report stopped before its queued finished signal
                # reaches the window.  That ownership gap must stay closed.
                window._start_download(selected_only=False)
                self.assertEqual(len(_FakeDownloadWorker.instances), 1)
                self.assertIs(window.download_worker, first)
                self.assertIn("已有下载批次", window.status_label.text())

                first.batch_finished.emit(first, 0, 0, True)
                self.assertEqual(window.task_store.get("Post_A").status, "cancelled")
                first.complete()
                self.assertIsNone(window.download_worker)

                window._start_download(selected_only=False)
                self.assertEqual(len(_FakeDownloadWorker.instances), 2)
                self.assertIs(window.download_worker, _FakeDownloadWorker.instances[-1])
            finally:
                if window.download_worker is not None:
                    owner = window.download_worker
                    owner.batch_finished.emit(owner, 0, 0, True)
                    window.download_worker.complete()
                self._close(window)

    def test_blocked_download_batch_requeues_owned_tasks_for_immediate_retry(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A", "Post_B"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]
                self.assertEqual(
                    [window.task_store.get(value).status for value in ("Post_A", "Post_B")],
                    ["queued", "queued"],
                )
                window.task_store.add_many(["Post_NotOwned"])
                window.task_store.update("Post_NotOwned", status="queued")

                reason = "下载初始化发生内部错误（RuntimeError）"
                worker.batch_blocked.emit(worker, reason)
                worker.batch_finished.emit(worker, 0, 0, True)

                recovered = [
                    window.task_store.get(value) for value in ("Post_A", "Post_B")
                ]
                self.assertEqual([task.status for task in recovered], ["pending", "pending"])
                self.assertEqual([task.error for task in recovered], [reason, reason])
                self.assertEqual(
                    [task.post_id for task in window.task_store.pending()],
                    ["Post_A", "Post_B"],
                )
                self.assertEqual(
                    window.task_store.get("Post_NotOwned").status, "queued"
                )
                self.assertIn(reason, window.status_label.text())
                self.assertIn("恢复为待处理", window.status_label.text())
                worker.complete()
                self.assertIsNone(window.download_worker)
            finally:
                if window.download_worker is not None:
                    owner = window.download_worker
                    owner.batch_finished.emit(owner, 0, 0, True)
                    window.download_worker.complete()
                self._close(window)

    def test_unreported_download_end_defensively_recovers_active_tasks(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]

                worker.batch_finished.emit(worker, 0, 0, False)

                task = window.task_store.get("Post_A")
                self.assertEqual(task.status, "pending")
                self.assertIn("异常结束", task.error)
                self.assertIn("异常任务已恢复", window.status_label.text())
                worker.complete()
            finally:
                if window.download_worker is not None:
                    owner = window.download_worker
                    owner.batch_finished.emit(owner, 0, 0, True)
                    window.download_worker.complete()
                self._close(window)

    def test_stopped_download_reports_task_recovery_failure(self):
        from task_store import TaskStoreError

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]

                with mock.patch.object(
                    window.task_store,
                    "update_many",
                    side_effect=TaskStoreError("simulated persistence failure"),
                ):
                    worker.batch_finished.emit(worker, 0, 0, True)

                self.assertEqual(window.task_store.get("Post_A").status, "queued")
                self.assertIn("任务状态恢复失败", window.status_label.text())
                self.assertNotIn("已停止", window.status_label.text())
                worker.complete()
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_blocked_download_preserves_reason_when_recovery_fails(self):
        from task_store import TaskStoreError

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]
                reason = "登录已失效，请重新登录"
                worker.batch_blocked.emit(worker, reason)

                with mock.patch.object(
                    window.task_store,
                    "update_many",
                    side_effect=TaskStoreError("simulated persistence failure"),
                ):
                    worker.batch_finished.emit(worker, 0, 0, True)

                self.assertEqual(window.task_store.get("Post_A").status, "queued")
                self.assertIn(reason, window.status_label.text())
                self.assertIn("任务状态恢复失败", window.status_label.text())
                worker.complete()
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_download_constructor_rollback_failure_is_visible(self):
        from task_store import TaskStoreError

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            original_update_many = window.task_store.update_many
            calls = 0

            def fail_second_update(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise TaskStoreError("simulated rollback failure")
                return original_update_many(*args, **kwargs)

            try:
                window.task_store.add_many(["Post_A"])
                with (
                    mock.patch.object(
                        window.task_store,
                        "update_many",
                        side_effect=fail_second_update,
                    ),
                    mock.patch(
                        "ui_main_window.DownloadWorker",
                        side_effect=RuntimeError("sensitive constructor detail"),
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning") as warning,
                ):
                    window._start_download(selected_only=False)

                self.assertEqual(window.task_store.get("Post_A").status, "queued")
                message = warning.call_args.args[-1]
                self.assertIn("任务状态恢复失败", message)
                self.assertNotIn("sensitive constructor detail", message)
            finally:
                self._close(window)

    def test_download_start_failure_restores_tasks_and_releases_owner(self):
        class FailingStartDownloadWorker(_FakeDownloadWorker):
            def start(self) -> None:
                raise RuntimeError("sensitive start detail")

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", FailingStartDownloadWorker
        ), mock.patch("ui_main_window.QMessageBox.warning") as warning:
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)

                worker = _FakeDownloadWorker.instances[-1]
                task = window.task_store.get("Post_A")
                self.assertEqual(task.status, "pending")
                self.assertIn("启动失败", task.error)
                self.assertIsNone(window.download_worker)
                self.assertEqual(window._download_task_ids, frozenset())
                self.assertTrue(worker.deleted)
                self.assertEqual(worker.token, "")
                self.assertFalse(window.stop_download_button.isEnabled())
                message = warning.call_args.args[-1]
                self.assertIn("任务已恢复为待处理", message)
                self.assertNotIn("sensitive start detail", message)
            finally:
                self._close(window)

    def test_normal_download_terminals_are_not_overwritten_by_batch_fallback(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A", "Post_B"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]

                worker.item_started.emit(worker, "Post_A")
                worker.item_succeeded.emit(
                    worker,
                    "Post_A",
                    SimpleNamespace(relative_path="Post_A.jpg"),
                )
                worker.item_started.emit(worker, "Post_B")
                worker.item_failed.emit(worker, "Post_B", "媒体不可用")
                worker.batch_finished.emit(worker, 1, 1, False)

                self.assertEqual(window.task_store.get("Post_A").status, "completed")
                self.assertEqual(window.task_store.get("Post_B").status, "failed")
                self.assertEqual(
                    window.task_store.get("Post_A").output_files,
                    ("Post_A.jpg",),
                )
                worker.complete()
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_remove_protects_owned_batch_but_allows_external_tasks(self):
        from types import SimpleNamespace

        from PySide6.QtCore import QItemSelectionModel
        from PySide6.QtWidgets import QMessageBox

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Owned_A", "External_B"])
                window._refresh_tasks()

                def row_for(post_id):
                    return next(
                        row
                        for row in range(window.task_model.rowCount())
                        if window.task_model.task_at(row).post_id == post_id
                    )

                selection = window.task_table.selectionModel()
                selection.select(
                    window.task_model.index(row_for("Owned_A"), 0),
                    QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows,
                )
                window._start_download(selected_only=True)
                worker = _FakeDownloadWorker.instances[-1]
                self.assertEqual([task.post_id for task in worker.tasks], ["Owned_A"])

                selection.select(
                    window.task_model.index(row_for("External_B"), 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows,
                )
                self.assertEqual(
                    window._selected_task_ids(), ["Owned_A", "External_B"]
                )
                self.assertFalse(window.remove_tasks_button.isEnabled())
                with mock.patch(
                    "ui_main_window.QMessageBox.question"
                ) as question:
                    window._remove_selected_tasks()
                question.assert_not_called()
                self.assertIsNotNone(window.task_store.get("Owned_A"))
                self.assertIsNotNone(window.task_store.get("External_B"))
                self.assertIn("当前下载批次", window.status_label.text())

                selection.select(
                    window.task_model.index(row_for("External_B"), 0),
                    QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows,
                )
                self.assertTrue(window.remove_tasks_button.isEnabled())
                with mock.patch(
                    "ui_main_window.QMessageBox.question",
                    return_value=QMessageBox.Yes,
                ) as question:
                    window._remove_selected_tasks()
                question.assert_called_once()
                self.assertIsNone(window.task_store.get("External_B"))
                self.assertEqual(window.task_store.get("Owned_A").status, "queued")

                worker.item_succeeded.emit(
                    worker,
                    "Owned_A",
                    SimpleNamespace(relative_path="Owned_A.jpg"),
                )
                self.assertEqual(window.task_store.get("Owned_A").status, "completed")
                window.task_table.selectRow(row_for("Owned_A"))
                self.assertFalse(window.remove_tasks_button.isEnabled())
                worker.batch_finished.emit(worker, 1, 0, False)
                worker.running = False
                self.assertFalse(window.remove_tasks_button.isEnabled())
                with mock.patch(
                    "ui_main_window.QMessageBox.question"
                ) as question:
                    window._remove_selected_tasks()
                question.assert_not_called()
                self.assertIsNotNone(window.task_store.get("Owned_A"))

                worker.complete()
                self.assertIsNone(window.download_worker)
                self.assertTrue(window.remove_tasks_button.isEnabled())
                with mock.patch(
                    "ui_main_window.QMessageBox.question",
                    return_value=QMessageBox.Yes,
                ):
                    window._remove_selected_tasks()
                self.assertIsNone(window.task_store.get("Owned_A"))
            finally:
                if window.download_worker is not None:
                    owner = window.download_worker
                    owner.batch_finished.emit(owner, 0, 0, True)
                    owner.complete()
                self._close(window)

    def test_user_stop_cancels_only_unfinished_owned_tasks(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A", "Post_B"])
                window._start_download(selected_only=False)
                worker = _FakeDownloadWorker.instances[-1]
                worker.item_succeeded.emit(
                    worker,
                    "Post_A",
                    SimpleNamespace(relative_path="Post_A.jpg"),
                )

                window._stop_download()
                worker.batch_finished.emit(worker, 1, 0, True)

                self.assertEqual(worker.cancel_count, 1)
                self.assertEqual(window.task_store.get("Post_A").status, "completed")
                cancelled = window.task_store.get("Post_B")
                self.assertEqual(cancelled.status, "cancelled")
                self.assertIn("用户停止", cancelled.error)
                self.assertIn("已停止", window.status_label.text())
                worker.complete()
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_stale_download_signals_cannot_modify_replacement_batch(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                stale = _FakeDownloadWorker.instances[-1]

                window.task_store.add_many(["Post_B"])
                window.task_store.update("Post_B", status="queued")
                replacement = _FakeDownloadWorker({}, "", [], window)
                replacement.start()
                window.download_worker = replacement
                window._download_task_ids = frozenset({"Post_B"})
                window._download_block_reason = ""
                window.status_label.setText("replacement active")

                stale.item_started.emit(stale, "Post_B")
                stale.item_progress.emit(stale, "Post_B", 1, 2)
                stale.item_succeeded.emit(
                    stale,
                    "Post_B",
                    SimpleNamespace(relative_path="wrong.jpg"),
                )
                stale.item_warning.emit(stale, "Post_B", "stale warning")
                stale.item_failed.emit(stale, "Post_B", "stale failure")
                stale.batch_blocked.emit(stale, "stale block")
                stale.batch_finished.emit(stale, 9, 9, True)

                task = window.task_store.get("Post_B")
                self.assertEqual(task.status, "queued")
                self.assertEqual(task.error, "")
                self.assertEqual(task.output_files, ())
                self.assertEqual(window._download_block_reason, "")
                self.assertEqual(window.status_label.text(), "replacement active")
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_stale_download_finished_signal_cannot_clear_new_owner(self):
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.DownloadWorker", _FakeDownloadWorker
        ):
            _FakeDownloadWorker.instances.clear()
            window = self.MainWindow(root)
            try:
                window.task_store.add_many(["Post_A"])
                window._start_download(selected_only=False)
                stale = _FakeDownloadWorker.instances[-1]
                replacement = _FakeDownloadWorker({}, "", [], window)
                replacement.start()
                window.download_worker = replacement

                stale.complete()

                self.assertTrue(stale.deleted)
                self.assertFalse(replacement.deleted)
                self.assertIs(window.download_worker, replacement)
            finally:
                if window.download_worker is not None:
                    window._download_thread_finished(window.download_worker)
                self._close(window)

    def test_default_download_directory_moves_with_portable_root(self):
        with tempfile.TemporaryDirectory() as parent:
            first_root = os.path.join(parent, "first")
            second_root = os.path.join(parent, "moved 中文")
            os.makedirs(first_root)
            first = self.MainWindow(first_root)
            try:
                self.assertEqual(first.settings.get("download_dir"), "Downloads")
            finally:
                self._close(first)

            os.makedirs(second_root)
            shutil.copytree(
                os.path.join(first_root, "Data"),
                os.path.join(second_root, "Data"),
                dirs_exist_ok=True,
            )
            second = self.MainWindow(second_root)
            try:
                expected = os.path.abspath(os.path.join(second_root, "Downloads"))
                self.assertEqual(second.download_dir_edit.text(), expected)
                self.assertEqual(second._settings_snapshot()["download_dir"], expected)
            finally:
                self._close(second)

    def test_download_directory_resolution_rejects_ambiguous_windows_paths(self):
        from settings_store import SettingsError

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                expected = os.path.abspath(os.path.join(root, "Downloads", "saved"))
                self.assertEqual(
                    window._resolve_download_dir("Downloads/saved"), expected
                )
                for value in (
                    r"C:relative",
                    r"\rooted",
                    r"Downloads\..\escape",
                    "Downloads/trailing ",
                ):
                    with self.subTest(value=value):
                        with self.assertRaises(SettingsError):
                            window._resolve_download_dir(value)
            finally:
                self._close(window)

    def test_disabled_remembrance_clears_an_orphaned_vault_on_startup(self):
        from credential_vault import StoredSession

        orphan = StoredSession("old-user", "old-token")
        vault = _MemoryVault(orphan)
        with tempfile.TemporaryDirectory() as root, mock.patch(
            "ui_main_window.CredentialVault", return_value=vault
        ):
            window = self.MainWindow(root)
            try:
                self.assertIsNone(vault.state)
                self.assertEqual(vault.clear_count, 1)
                self.assertEqual(window.access_token, "")
                self.assertFalse(window.remember_check.isChecked())
            finally:
                self._close(window)

    def test_login_persists_only_password_free_session_and_matching_flag(self):
        from credential_vault import StoredSession

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            vault = _MemoryVault()
            window.vault = vault
            try:
                window.remember_check.setChecked(True)
                window.password_edit.setText("ephemeral-password")
                with mock.patch("ui_main_window.QMessageBox.warning") as warning:
                    window._login_succeeded("unit-user", "unit-token")

                warning.assert_not_called()
                self.assertEqual(vault.saved, [StoredSession("unit-user", "unit-token")])
                self.assertFalse(hasattr(vault.saved[0], "password"))
                self.assertTrue(window.settings.get("remember_credentials"))
                self.assertTrue(window.remember_check.isChecked())
                self.assertEqual(window.access_token, "unit-token")
                self.assertEqual(window.password_edit.text(), "")
                with open(window.settings.path, "rb") as file_obj:
                    stored_settings = file_obj.read()
                self.assertNotIn(b"unit-token", stored_settings)
                self.assertNotIn(b"ephemeral-password", stored_settings)
            finally:
                self._close(window)

    def test_login_settings_failure_keeps_new_vault_behind_recovery_barrier(self):
        from credential_vault import StoredSession
        from settings_store import SettingsError

        previous = StoredSession("old-user", "old-token")
        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            vault = _MemoryVault(previous)
            window.vault = vault
            window.remember_check.setChecked(True)
            try:
                with (
                    mock.patch.object(
                        window.settings,
                        "save",
                        side_effect=SettingsError("simulated settings failure"),
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning") as warning,
                ):
                    window._login_succeeded("new-user", "new-token")

                self.assertEqual(vault.state, StoredSession("new-user", "new-token"))
                self.assertEqual(vault.restore_count, 0)
                self.assertTrue(window.credential_journal.exists())
                self.assertTrue(window.settings.get("remember_credentials"))
                self.assertTrue(window.remember_check.isChecked())
                self.assertEqual(window.access_token, "new-token")
                self.assertEqual(window.session_username, "new-user")
                warning.assert_called_once()
            finally:
                self._close(window)

    def test_new_login_heals_a_vault_that_is_too_corrupt_to_snapshot(self):
        from credential_vault import StoredSession, VaultError

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            vault = _MemoryVault(state=b"oversized-or-unreadable-placeholder")
            vault.failures["snapshot"] = VaultError("simulated oversized vault")
            window.vault = vault
            window.remember_check.setChecked(True)
            try:
                with mock.patch("ui_main_window.QMessageBox.warning") as warning:
                    window._login_succeeded("new-user", "new-token")

                warning.assert_not_called()
                self.assertEqual(vault.state, StoredSession("new-user", "new-token"))
                self.assertTrue(window._session_persisted)
                self.assertTrue(window.settings.get("remember_credentials"))
            finally:
                self._close(window)

    def test_enabling_remembrance_saves_an_existing_verified_live_session(self):
        from credential_vault import StoredSession

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            vault = _MemoryVault()
            window.vault = vault
            try:
                window.remember_check.setChecked(False)
                window._login_succeeded("live-user", "live-token")
                self.assertIsNone(vault.state)
                self.assertFalse(window.settings.get("remember_credentials"))

                window.remember_check.setChecked(True)
                with mock.patch("ui_main_window.QMessageBox.warning") as warning:
                    window._save_settings()

                warning.assert_not_called()
                expected = StoredSession("live-user", "live-token")
                self.assertEqual(vault.state, expected)
                self.assertEqual(vault.saved, [expected])
                self.assertTrue(window.settings.get("remember_credentials"))
            finally:
                self._close(window)

    def test_disabling_remembrance_never_restores_secret_after_settings_failure(self):
        from credential_vault import StoredSession
        from settings_store import SettingsError

        previous = StoredSession("old-user", "old-token")
        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            window.settings.set("remember_credentials", True)
            window.settings.save()
            vault = _MemoryVault(previous)
            window.vault = vault
            window.remember_check.setChecked(False)
            try:
                with (
                    mock.patch.object(
                        window.settings,
                        "save",
                        side_effect=SettingsError("simulated settings failure"),
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning") as warning,
                ):
                    window._save_settings()

                self.assertIsNone(vault.state)
                self.assertEqual(vault.clear_count, 1)
                self.assertEqual(vault.restore_count, 0)
                self.assertFalse(window.settings.get("remember_credentials"))
                self.assertFalse(window.remember_check.isChecked())
                warning.assert_called_once()
            finally:
                self._close(window)

    def test_failed_new_login_persistence_can_be_retried_from_save_settings(self):
        from credential_vault import StoredSession
        from settings_store import SettingsError

        previous = StoredSession("old-user", "old-token")
        expected = StoredSession("new-user", "new-token")
        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            window.settings.set("remember_credentials", True)
            window.settings.save()
            vault = _MemoryVault(previous)
            window.vault = vault
            window.remember_check.setChecked(True)
            window._session_persisted = True
            try:
                with (
                    mock.patch.object(
                        window.settings,
                        "save",
                        side_effect=SettingsError("simulated settings failure"),
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning"),
                ):
                    window._login_succeeded("new-user", "new-token")

                self.assertEqual(vault.state, expected)
                self.assertFalse(window._session_persisted)
                self.assertTrue(window.remember_check.isChecked())

                with mock.patch("ui_main_window.QMessageBox.warning") as warning:
                    window._save_settings()

                warning.assert_not_called()
                self.assertEqual(vault.state, expected)
                self.assertTrue(window._session_persisted)
                self.assertTrue(window.settings.get("remember_credentials"))
            finally:
                self._close(window)

    def test_failed_new_login_then_close_and_restart_never_loads_old_session(self):
        from credential_vault import StoredSession
        from settings_store import SettingsError

        old = StoredSession("old-user", "old-token")
        new = StoredSession("new-user", "new-token")
        with tempfile.TemporaryDirectory() as root:
            first = self.MainWindow(root)
            vault = _MemoryVault()
            first.vault = vault
            first.remember_check.setChecked(True)
            first._login_succeeded(old.username, old.access_token)
            try:
                with (
                    mock.patch.object(
                        first.settings,
                        "save",
                        side_effect=SettingsError("simulated settings failure"),
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning"),
                ):
                    first._login_succeeded(new.username, new.access_token)
                self.assertEqual(vault.state, new)
                self.assertTrue(first.credential_journal.exists())

                with mock.patch.object(
                    first.settings, "save", wraps=first.settings.save
                ) as close_save:
                    first.close()
                    self.app.processEvents()
                close_save.assert_not_called()
            finally:
                first.deleteLater()
                self.app.processEvents()

            with mock.patch(
                "ui_main_window.CredentialVault", return_value=vault
            ):
                second = self.MainWindow(root)
            try:
                self.assertEqual(second.access_token, new.access_token)
                self.assertEqual(second.session_username, new.username)
                self.assertNotEqual(second.access_token, old.access_token)
                self.assertFalse(second.credential_journal.exists())
            finally:
                self._close(second)

    def test_explicit_clear_logs_out_even_when_settings_cannot_be_saved(self):
        from credential_vault import StoredSession
        from PySide6.QtWidgets import QMessageBox
        from settings_store import SettingsError

        for mode in ("save-failure", "save-disabled"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                window = self.MainWindow(root)
                previous = StoredSession("old-user", "old-token")
                vault = _MemoryVault(previous)
                window.vault = vault
                window.access_token = "live-token"
                window.session_username = "live-user"
                window._session_persisted = True
                window.settings.set("remember_credentials", True)
                window.remember_check.setChecked(True)
                patcher = (
                    mock.patch.object(
                        window.settings,
                        "save",
                        side_effect=SettingsError("simulated settings failure"),
                    )
                    if mode == "save-failure"
                    else mock.patch.object(window.settings, "save", wraps=window.settings.save)
                )
                if mode == "save-disabled":
                    window._settings_save_allowed = False
                try:
                    with (
                        patcher,
                        mock.patch(
                            "ui_main_window.QMessageBox.question",
                            return_value=QMessageBox.Yes,
                        ),
                        mock.patch("ui_main_window.QMessageBox.warning") as warning,
                    ):
                        window._clear_credentials()

                    self.assertIsNone(vault.state)
                    self.assertEqual(window.access_token, "")
                    self.assertEqual(window.session_username, "")
                    self.assertFalse(window._session_persisted)
                    self.assertFalse(window.remember_check.isChecked())
                    self.assertFalse(window.settings.get("remember_credentials"))
                    warning.assert_called_once()
                finally:
                    self._settings_save_allowed = True
                    self._close(window)

    def test_explicit_clear_removes_an_oversized_corrupt_vault(self):
        from PySide6.QtWidgets import QMessageBox

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            try:
                with open(window.vault.path, "wb") as file_obj:
                    file_obj.write(b"x" * (1024 * 1024 + 1))
                window.access_token = "live-token"
                window.session_username = "live-user"
                window.remember_check.setChecked(True)
                window.settings.set("remember_credentials", True)
                with (
                    mock.patch(
                        "ui_main_window.QMessageBox.question",
                        return_value=QMessageBox.Yes,
                    ),
                    mock.patch("ui_main_window.QMessageBox.warning") as warning,
                ):
                    window._clear_credentials()

                warning.assert_not_called()
                self.assertFalse(os.path.exists(window.vault.path))
                self.assertEqual(window.access_token, "")
                self.assertFalse(window.remember_check.isChecked())
            finally:
                self._close(window)

    def test_corrupt_task_file_is_preserved_and_window_still_opens(self):
        with tempfile.TemporaryDirectory() as root:
            data_dir = os.path.join(root, "Data")
            os.makedirs(data_dir)
            with open(os.path.join(data_dir, "tasks.json"), "wb") as file_obj:
                file_obj.write(b"\xff\xfebroken")

            window = self.MainWindow(root)
            try:
                backups = [
                    name
                    for name in os.listdir(data_dir)
                    if name.startswith("tasks.corrupt.") and name.endswith(".json")
                ]
                self.assertEqual(len(backups), 1)
                self.assertEqual(window.task_store.list(), [])
            finally:
                self._close(window)

    def test_task_read_failure_is_not_mislabeled_or_quarantined_as_corrupt(self):
        from task_store import TaskStoreReadError

        with tempfile.TemporaryDirectory() as root:
            data_dir = os.path.join(root, "Data")
            os.makedirs(data_dir)
            task_path = os.path.join(data_dir, "tasks.json")
            original = b'{"schema_version":1,"revision":0,"tasks":[]}'
            with open(task_path, "wb") as file_obj:
                file_obj.write(original)

            with mock.patch(
                "ui_main_window.TaskStore",
                side_effect=TaskStoreReadError("simulated read failure"),
            ):
                with self.assertRaises(TaskStoreReadError):
                    self.MainWindow(root)

            with open(task_path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), original)
            self.assertEqual(
                [name for name in os.listdir(data_dir) if name.startswith("tasks.corrupt.")],
                [],
            )

    def test_settings_read_failure_preserves_settings_vault_and_blocks_writes(self):
        from credential_vault import StoredSession, VaultReceipt
        from settings_store import SettingsStore

        with tempfile.TemporaryDirectory() as root:
            data_dir = os.path.join(root, "Data")
            os.makedirs(data_dir)
            receipt = "a" * 64
            stored_session = StoredSession("saved-user", "saved-token")
            settings = SettingsStore(data_dir)
            settings.update(
                {
                    "download_dir": "Downloads/custom",
                    "remember_credentials": True,
                    "credential_vault_receipt": receipt,
                }
            )
            settings.save()
            with open(settings.path, "rb") as file_obj:
                original = file_obj.read()

            vault = _MemoryVault(stored_session)
            vault.receipt = VaultReceipt(receipt)
            real_open = open
            injected = False

            def fail_first_settings_read(path, *args, **kwargs):
                nonlocal injected
                mode = args[0] if args else kwargs.get("mode", "r")
                if (
                    not injected
                    and os.path.abspath(os.fspath(path))
                    == os.path.abspath(settings.path)
                    and "r" in mode
                ):
                    injected = True
                    raise PermissionError("simulated sharing conflict")
                return real_open(path, *args, **kwargs)

            with (
                mock.patch("builtins.open", side_effect=fail_first_settings_read),
                mock.patch("ui_main_window.CredentialVault", return_value=vault),
            ):
                window = self.MainWindow(root)
            try:
                self.assertTrue(injected)
                self.assertFalse(window._settings_state_available)
                self.assertFalse(window._settings_save_allowed)
                self.assertEqual(window.access_token, "")
                self.assertEqual(window.session_username, "")
                self.assertEqual(vault.state, stored_session)
                self.assertEqual(vault.clear_count, 0)
                self.assertFalse(window.login_button.isEnabled())
                self.assertFalse(window.logout_button.isEnabled())
                self.assertFalse(window.save_settings_button.isEnabled())
                self.assertFalse(window.download_all_button.isEnabled())
                self.assertFalse(window.library_scan_button.isEnabled())
                self.assertIn("暂时无法读取", window.log_view.toPlainText())
                self.assertEqual(
                    [
                        name
                        for name in os.listdir(data_dir)
                        if name.startswith("settings.corrupt.")
                    ],
                    [],
                )

                window._save_settings()
                window._start_download(selected_only=False)
                window._start_library_scan()
                window._load_credentials()
                from credential_persistence import CredentialPersistenceError

                with self.assertRaises(CredentialPersistenceError):
                    window._persist_remember_choice(False)
                window._login_succeeded("ignored-user", "ignored-token")
                window._login_finished()
                self.assertIsNone(window.download_worker)
                self.assertIsNone(window.library_worker)
                self.assertFalse(window.login_button.isEnabled())
                self.assertEqual(window.access_token, "")
                self.assertEqual(window.session_username, "")
                self.assertEqual(vault.clear_count, 0)
                self.assertEqual(vault.state, stored_session)
                with open(settings.path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), original)
            finally:
                self._close(window)

            with mock.patch("ui_main_window.CredentialVault", return_value=vault):
                recovered = self.MainWindow(root)
            try:
                self.assertTrue(recovered._settings_state_available)
                self.assertEqual(recovered.access_token, stored_session.access_token)
                self.assertEqual(recovered.session_username, stored_session.username)
                self.assertEqual(vault.clear_count, 0)
                self.assertEqual(
                    recovered.settings.get("download_dir"), "Downloads/custom"
                )
            finally:
                self._close(recovered)

    def test_corrupt_settings_are_backed_up_before_defaults_can_be_saved(self):
        with tempfile.TemporaryDirectory() as root:
            data_dir = os.path.join(root, "Data")
            os.makedirs(data_dir)
            settings_path = os.path.join(data_dir, "settings.json")
            original = b"{broken settings"
            with open(settings_path, "wb") as file_obj:
                file_obj.write(original)

            window = self.MainWindow(root)
            backups = [
                name
                for name in os.listdir(data_dir)
                if name.startswith("settings.corrupt.") and name.endswith(".json")
            ]
            try:
                self.assertEqual(len(backups), 1)
                with open(os.path.join(data_dir, backups[0]), "rb") as file_obj:
                    self.assertEqual(file_obj.read(), original)
                self.assertFalse(os.path.exists(settings_path))
            finally:
                self._close(window)
            self.assertTrue(os.path.isfile(settings_path))

    def test_close_is_refused_while_thumbnail_pool_is_still_running(self):
        class FakePool:
            def __init__(self):
                self.cleared = False
                self.waits: list[int] = []

            def clear(self):
                self.cleared = True

            def waitForDone(self, timeout_ms):  # noqa: N802 - Qt-compatible fake
                self.waits.append(timeout_ms)
                return False

        class FakeWorker:
            def __init__(self):
                self.cancelled = False

            def cancel(self):
                self.cancelled = True

        class FakeEvent:
            def __init__(self):
                self.accepted = False
                self.ignored = False

            def accept(self):
                self.accepted = True

            def ignore(self):
                self.ignored = True

        with tempfile.TemporaryDirectory() as root:
            window = self.MainWindow(root)
            original_pool = window.thumbnail_pool
            pool = FakePool()
            worker = FakeWorker()
            event = FakeEvent()
            window.thumbnail_pool = pool
            window._thumbnail_workers[(1, "123")] = worker
            try:
                with mock.patch.object(window.settings, "save") as save:
                    window.closeEvent(event)
                    save.assert_not_called()
                self.assertTrue(event.ignored)
                self.assertFalse(event.accepted)
                self.assertTrue(worker.cancelled)
                self.assertTrue(pool.cleared)
                self.assertEqual(pool.waits, [3000])
                self.assertIn("缩略图", window.status_label.text())
            finally:
                window.thumbnail_pool = original_pool
                self._close(window)


if __name__ == "__main__":
    unittest.main()
