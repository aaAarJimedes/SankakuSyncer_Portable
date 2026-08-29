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


class _MemoryVault:
    def __init__(self, state=None) -> None:
        self.state = state
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

    def save(self, session) -> None:
        self._fail("save")
        self.saved.append(session)
        self.state = session

    def clear(self) -> None:
        self.clear_count += 1
        self._fail("clear")
        self.state = None

    def load(self):
        self._fail("load")
        return self.state


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
                self.assertEqual(window.search_edit.accessibleName(), "搜索标签")
                self.assertEqual(window.result_list.accessibleName(), "搜索结果")
                self.assertEqual(window.stop_search_button.accessibleName(), "停止搜索")
                self.assertFalse(window.previous_button.isEnabled())
                self.assertFalse(window.next_button.isEnabled())
                self.assertFalse(window.stop_search_button.isEnabled())
                ensure_loaded.assert_not_called()
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

    def test_login_settings_failure_rolls_back_vault_but_keeps_live_session(self):
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

                self.assertEqual(vault.state, previous)
                self.assertEqual(vault.restore_count, 1)
                self.assertFalse(window.settings.get("remember_credentials"))
                self.assertFalse(window.remember_check.isChecked())
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

                self.assertEqual(vault.state, previous)
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
