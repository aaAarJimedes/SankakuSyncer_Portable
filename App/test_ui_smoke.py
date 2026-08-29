# -*- coding: utf-8 -*-
"""Offline construction and portability smoke tests for the desktop UI."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("SANKAKU_DISABLE_WEBENGINE", "1")


class MainWindowOfflineSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtCore import QCoreApplication, Qt

        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])
        from ui_main_window import MainWindow

        cls.MainWindow = MainWindow

    def _close(self, window) -> None:
        window.close()
        window.deleteLater()
        self.app.processEvents()

    def test_construction_is_offline_and_browser_is_lazy(self):
        from ui_browser_tab import BrowserTab

        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            BrowserTab, "ensure_loaded", autospec=True
        ) as ensure_loaded:
            window = self.MainWindow(root)
            try:
                self.assertEqual(window.tabs.count(), 4)
                self.assertIsNone(window.search_worker)
                self.assertIsNone(window.login_worker)
                self.assertIsNone(window.download_worker)
                self.assertEqual(window.results_summary.text(), "输入标签后点击搜索")
                ensure_loaded.assert_not_called()
            finally:
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
