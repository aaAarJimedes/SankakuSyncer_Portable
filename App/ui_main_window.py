# -*- coding: utf-8 -*-
"""Main desktop interface for native discovery, browsing, and downloads."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import os
import re
import time
from typing import Iterable

from PySide6.QtCore import (
    QByteArray,
    QBuffer,
    QIODevice,
    QSize,
    Qt,
    QThreadPool,
    QUrl,
    Slot,
)
from PySide6.QtGui import QDesktopServices, QIcon, QImageReader, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from credential_vault import CredentialVault, Credentials, StoredSession, VaultError
from credential_persistence import (
    CredentialJournal,
    CredentialPersistence,
    CredentialPersistenceError,
)
from sankaku_api import SankakuPost, SearchPage
from sankaku_url_policy import (
    canonical_post_url,
    normalize_page_url,
    normalize_post_id,
    post_id_from_url,
    tag_search_url,
)
from settings_store import SettingsError, SettingsStore
from task_store import DownloadTask, TaskStore, TaskStoreCorruptError, TaskStoreError
from version import APP_DISPLAY_NAME
from workers import DownloadWorker, LoginWorker, SearchWorker, ThumbnailWorker

try:
    from ui_browser_tab import BrowserTab, WEBENGINE_AVAILABLE
except (ImportError, RuntimeError):
    BrowserTab = None
    WEBENGINE_AVAILABLE = False


_URL_RE = re.compile(r"https://[^\s<>\"']+", re.IGNORECASE)
_STATUS_TEXT = {
    "pending": "待处理",
    "queued": "排队中",
    "running": "下载中",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}
_RATING_TEXT = {"s": "Safe", "q": "Questionable", "e": "Explicit", "": "未知"}


class MainWindow(QMainWindow):
    def __init__(self, portable_root: str) -> None:
        super().__init__()
        self.portable_root = os.path.abspath(portable_root)
        self.data_dir = os.path.join(self.portable_root, "Data")
        self.default_download_dir = os.path.join(self.portable_root, "Downloads")
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.default_download_dir, exist_ok=True)

        self._startup_messages: list[str] = []
        self._settings_save_allowed = True
        self.settings = SettingsStore(self.data_dir)
        if self.settings.last_error and os.path.isfile(self.settings.path):
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            recovery_path = os.path.join(
                self.data_dir, f"settings.corrupt.{stamp}.json"
            )
            try:
                os.replace(self.settings.path, recovery_path)
            except OSError as exc:
                self._settings_save_allowed = False
                self._startup_messages.append(
                    "损坏的设置文件无法备份；本次关闭时不会覆盖它"
                    f"（{type(exc).__name__}）。"
                )
            else:
                self._startup_messages.append(
                    f"损坏的设置已原样保留为 {os.path.basename(recovery_path)}。"
                )
        if not self.settings.get("download_dir"):
            self.settings.set("download_dir", "Downloads")
            if not self.settings.last_error:
                try:
                    self.settings.save()
                except SettingsError:
                    pass
        self.vault = CredentialVault(self.data_dir)
        self.credential_journal = CredentialJournal(self.data_dir)
        self.access_token = ""
        self.session_username = ""
        self._session_persisted = False
        self._credential_close_save_blocked = False
        try:
            self.task_store = TaskStore(self.data_dir)
        except TaskStoreCorruptError as exc:
            task_path = os.path.join(self.data_dir, "tasks.json")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            recovery_path = os.path.join(self.data_dir, f"tasks.corrupt.{stamp}.json")
            try:
                os.replace(task_path, recovery_path)
            except OSError:
                raise exc
            self.task_store = TaskStore(self.data_dir)
            self._startup_messages.append(
                f"损坏的任务篮已原样保留为 {os.path.basename(recovery_path)}，当前使用空任务篮。"
            )

        self.search_worker: SearchWorker | None = None
        self.login_worker: LoginWorker | None = None
        self.download_worker: DownloadWorker | None = None
        self._download_block_reason = ""
        self.thumbnail_pool = QThreadPool(self)
        self.thumbnail_pool.setMaxThreadCount(2)
        self._thumbnail_generation = 0
        self._thumbnail_workers: dict[tuple[int, str], ThumbnailWorker] = {}
        self._search_cursor = ""
        self._next_cursor = ""
        self._cursor_history: list[str] = []
        self._search_query = ""
        self._search_rating = ""
        self._pending_search: dict[str, object] | None = None
        self._search_cancel_requested = False
        self._search_terminal_received = False
        self._search_posts: dict[str, SankakuPost] = {}

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.resize(1320, 860)
        self.setMinimumSize(960, 680)
        self._build_ui()
        self._restore_geometry()
        self._load_credentials()
        self._refresh_tasks()
        for message in self._startup_messages:
            self._log(message)
        if self.settings.last_error:
            self._log(self.settings.last_error)

    # ------------------------------ UI construction ------------------------------

    def _build_ui(self) -> None:
        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 8)
        outer.setSpacing(8)

        title_row = QHBoxLayout()
        title = QLabel("Sankaku 浏览下载器")
        title.setObjectName("appTitle")
        subtitle = QLabel("本地优先 · 单并发 · 不绕过验证或权限")
        subtitle.setObjectName("subtleText")
        title_row.addWidget(title)
        title_row.addWidget(subtitle)
        title_row.addStretch(1)
        self.account_badge = QLabel("未登录")
        self.account_badge.setObjectName("accountBadge")
        title_row.addWidget(self.account_badge)
        outer.addLayout(title_row)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_discovery_tab(), "发现与搜索")
        self.browser_tab = self._build_browser_tab()
        self.tabs.addTab(self.browser_tab, "站内浏览")
        self.tabs.addTab(self._build_tasks_tab(), "下载任务")
        self.tabs.addTab(self._build_settings_tab(), "账号与设置")
        self.tabs.currentChanged.connect(self._tab_changed)
        outer.addWidget(self.tabs, 1)

        self.setCentralWidget(central)
        status = QStatusBar(self)
        self.setStatusBar(status)
        self.status_label = QLabel("就绪")
        status.addWidget(self.status_label, 1)
        self.global_progress = QProgressBar()
        self.global_progress.setRange(0, 100)
        self.global_progress.setValue(0)
        self.global_progress.setMaximumWidth(260)
        self.global_progress.hide()
        status.addPermanentWidget(self.global_progress)

    def _build_discovery_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)

        toolbar = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setAccessibleName("搜索标签")
        self.search_edit.setPlaceholderText("输入标签表达式，例如 landscape blue_hair")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.returnPressed.connect(lambda: self._start_search(reset=True))
        toolbar.addWidget(self.search_edit, 1)

        self.rating_combo = QComboBox()
        self.rating_combo.addItem("Safe", "s")
        self.rating_combo.addItem("Questionable", "q")
        self.rating_combo.addItem("Explicit", "e")
        self.rating_combo.addItem("全部分级", "all")
        rating = self.settings.get("default_rating")
        index = self.rating_combo.findData(rating)
        self.rating_combo.setCurrentIndex(max(0, index))
        toolbar.addWidget(self.rating_combo)

        self.search_button = QPushButton("搜索")
        self.search_button.clicked.connect(lambda: self._start_search(reset=True))
        toolbar.addWidget(self.search_button)
        self.stop_search_button = QPushButton("停止搜索")
        self.stop_search_button.setAccessibleName("停止搜索")
        self.stop_search_button.setEnabled(False)
        self.stop_search_button.clicked.connect(self._stop_search)
        toolbar.addWidget(self.stop_search_button)
        self.previous_button = QPushButton("上一页")
        self.previous_button.setEnabled(False)
        self.previous_button.clicked.connect(self._search_previous)
        toolbar.addWidget(self.previous_button)
        self.next_button = QPushButton("下一页")
        self.next_button.setEnabled(False)
        self.next_button.clicked.connect(self._search_next)
        toolbar.addWidget(self.next_button)
        layout.addLayout(toolbar)

        hint = QLabel(
            "默认仅显示 Safe；只有你主动选择其他分级时才请求相应结果。搜索与下载按保守节奏串行访问站点。"
        )
        hint.setWordWrap(True)
        hint.setObjectName("subtleText")
        layout.addWidget(hint)

        self.result_list = QListWidget()
        self.result_list.setAccessibleName("搜索结果")
        self.result_list.setViewMode(QListWidget.IconMode)
        self.result_list.setResizeMode(QListWidget.Adjust)
        self.result_list.setMovement(QListWidget.Static)
        self.result_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.result_list.setIconSize(QSize(190, 190))
        self.result_list.setSpacing(10)
        self.result_list.itemDoubleClicked.connect(self._open_result_in_browser)
        layout.addWidget(self.result_list, 1)

        actions = QHBoxLayout()
        self.results_summary = QLabel("输入标签后点击搜索")
        actions.addWidget(self.results_summary, 1)
        add_selected = QPushButton("加入选中作品")
        add_selected.clicked.connect(self._add_selected_results)
        actions.addWidget(add_selected)
        open_selected = QPushButton("在站内浏览中打开")
        open_selected.clicked.connect(self._open_first_selected_result)
        actions.addWidget(open_selected)
        layout.addLayout(actions)
        return page

    def _build_browser_tab(self) -> QWidget:
        if BrowserTab is None:
            frame = QWidget()
            layout = QVBoxLayout(frame)
            label = QLabel("当前运行环境未提供 Qt WebEngine。原生搜索、任务队列和下载仍可使用。")
            label.setAlignment(Qt.AlignCenter)
            label.setWordWrap(True)
            layout.addWidget(label, 1)
            return frame
        browser = BrowserTab()
        if hasattr(browser, "add_current_requested"):
            browser.add_current_requested.connect(self._add_browser_current)
        if hasattr(browser, "collect_visible_requested"):
            browser.collect_visible_requested.connect(self._add_browser_visible)
        return browser

    def _build_tasks_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)

        actions = QHBoxLayout()
        add_manual = QPushButton("粘贴链接 / ID")
        add_manual.clicked.connect(self._add_manual_tasks)
        actions.addWidget(add_manual)
        download_selected = QPushButton("下载所选")
        download_selected.clicked.connect(lambda: self._start_download(selected_only=True))
        actions.addWidget(download_selected)
        download_all = QPushButton("下载全部待处理")
        download_all.clicked.connect(lambda: self._start_download(selected_only=False))
        actions.addWidget(download_all)
        self.stop_download_button = QPushButton("停止当前批次")
        self.stop_download_button.clicked.connect(self._stop_download)
        self.stop_download_button.setEnabled(False)
        actions.addWidget(self.stop_download_button)
        retry = QPushButton("重新排队所选")
        retry.clicked.connect(self._retry_selected_tasks)
        actions.addWidget(retry)
        remove = QPushButton("移除所选任务")
        remove.clicked.connect(self._remove_selected_tasks)
        actions.addWidget(remove)
        actions.addStretch(1)
        self.task_summary = QLabel()
        actions.addWidget(self.task_summary)
        layout.addLayout(actions)

        splitter = QSplitter(Qt.Vertical)
        self.task_table = QTableWidget(0, 6)
        self.task_table.setHorizontalHeaderLabels(
            ["作品 ID", "分级", "状态", "加入时间", "输出", "说明"]
        )
        self.task_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.task_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.task_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        header = self.task_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        splitter.addWidget(self.task_table)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setPlaceholderText("运行记录只显示状态，不记录密码、令牌或签名媒体地址。")
        splitter.addWidget(self.log_view)
        splitter.setSizes([540, 180])
        layout.addWidget(splitter, 1)
        return page

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)

        account_group = QGroupBox("账号")
        account_form = QFormLayout(account_group)
        self.username_edit = QLineEdit()
        self.username_edit.setMaxLength(320)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setMaxLength(4096)
        self.remember_check = QCheckBox("使用 Windows DPAPI 在本机加密保存")
        self.remember_check.setChecked(bool(self.settings.get("remember_credentials")))
        self.login_button = QPushButton("验证并登录")
        self.login_button.clicked.connect(self._start_login)
        self.logout_button = QPushButton("清除本机凭据")
        self.logout_button.clicked.connect(self._clear_credentials)
        login_row = QHBoxLayout()
        login_row.addWidget(self.login_button)
        login_row.addWidget(self.logout_button)
        login_row.addStretch(1)
        self.login_status = QLabel("尚未验证")
        login_row.addWidget(self.login_status)
        account_form.addRow("用户名", self.username_edit)
        account_form.addRow("密码", self.password_edit)
        account_form.addRow("本机保存", self.remember_check)
        account_form.addRow("", login_row)
        layout.addWidget(account_group)

        network_group = QGroupBox("下载与网络")
        network_form = QFormLayout(network_group)
        self.download_dir_edit = QLineEdit(
            self._resolve_download_dir(str(self.settings.get("download_dir")))
        )
        directory_row = QHBoxLayout()
        directory_row.addWidget(self.download_dir_edit, 1)
        choose_dir = QPushButton("选择目录")
        choose_dir.clicked.connect(self._choose_download_dir)
        directory_row.addWidget(choose_dir)
        network_form.addRow("下载目录", directory_row)

        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0.5, 30.0)
        self.delay_spin.setDecimals(1)
        self.delay_spin.setSingleStep(0.5)
        self.delay_spin.setSuffix(" 秒")
        self.delay_spin.setValue(float(self.settings.get("request_delay")))
        network_form.addRow("API 请求最小间隔", self.delay_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 180)
        self.timeout_spin.setSuffix(" 秒")
        self.timeout_spin.setValue(int(self.settings.get("request_timeout")))
        network_form.addRow("请求超时", self.timeout_spin)

        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(int(self.settings.get("max_retries")))
        network_form.addRow("最大重试", self.retries_spin)

        self.page_size_spin = QSpinBox()
        self.page_size_spin.setRange(8, 40)
        self.page_size_spin.setValue(int(self.settings.get("page_size")))
        network_form.addRow("每页作品", self.page_size_spin)

        self.proxy_edit = QLineEdit(str(self.settings.get("proxy")))
        self.proxy_edit.setPlaceholderText("可选，例如 http://127.0.0.1:8080；不支持代理密码或 SOCKS")
        network_form.addRow("代理", self.proxy_edit)

        self.prefer_original_check = QCheckBox("有权限时优先原文件")
        self.prefer_original_check.setChecked(bool(self.settings.get("prefer_original")))
        network_form.addRow("文件质量", self.prefer_original_check)
        self.metadata_check = QCheckBox("为成功下载写入不含 URL/凭据的 JSON 元数据")
        self.metadata_check.setChecked(bool(self.settings.get("save_metadata")))
        network_form.addRow("本地元数据", self.metadata_check)
        layout.addWidget(network_group)

        notice = QLabel(
            "请只访问和保存你有权使用的内容。本程序不会自动处理 CAPTCHA、不会轮换身份或代理、"
            "不会绕过会员/年龄/地域限制；认证或限流错误会停止并提示，单项 403 只失败该作品。"
        )
        notice.setWordWrap(True)
        notice.setObjectName("noticeLabel")
        layout.addWidget(notice)
        save_button = QPushButton("保存设置")
        save_button.clicked.connect(self._save_settings)
        layout.addWidget(save_button, 0, Qt.AlignRight)
        layout.addStretch(1)
        return page

    # ------------------------------ search ------------------------------

    def _settings_snapshot(self) -> dict:
        snapshot = dict(self.settings.values)
        snapshot["download_dir"] = self._resolve_download_dir(
            str(snapshot.get("download_dir", ""))
        )
        return snapshot

    def _resolve_download_dir(self, value: str) -> str:
        candidate = value.strip() if isinstance(value, str) else ""
        if not candidate:
            return self.default_download_dir
        if os.path.isabs(candidate):
            return os.path.abspath(candidate)
        return os.path.abspath(os.path.join(self.portable_root, candidate))

    def _portable_download_value(self, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            return "Downloads"
        absolute = os.path.abspath(candidate)
        try:
            relative = os.path.relpath(absolute, self.portable_root)
        except ValueError:
            return absolute
        if relative == "Downloads" or relative.startswith("Downloads" + os.sep):
            return relative.replace("\\", "/")
        return absolute

    @Slot(int)
    def _tab_changed(self, index: int) -> None:
        if index < 0 or self.tabs.widget(index) is not self.browser_tab:
            return
        ensure_loaded = getattr(self.browser_tab, "ensure_loaded", None)
        if callable(ensure_loaded):
            ensure_loaded()

    def _start_search(
        self,
        *,
        reset: bool,
        cursor: str | None = None,
        history: list[str] | None = None,
    ) -> None:
        # Keep ownership until the old QThread's queued finished signal has
        # been handled.  isRunning() can already be false in that short window;
        # accepting another Enter press there would let stale cleanup erase the
        # new operation's pending state.
        if self.search_worker is not None:
            self.status_label.setText("搜索正在进行，请稍候")
            return
        if reset:
            tags = self.search_edit.text()
            rating = str(self.rating_combo.currentData())
            target_cursor = ""
            target_history: list[str] = []
        else:
            if cursor is None or history is None:
                return
            # Pagination always continues the last committed search.  Editing
            # the controls only takes effect when the user starts a new search.
            tags = self._search_query
            rating = self._search_rating
            target_cursor = cursor
            target_history = list(history)
        self._pending_search = {
            "query": tags,
            "rating": rating,
            "cursor": target_cursor,
            "history": target_history,
            "prior_summary": self.results_summary.text(),
        }
        self._search_cancel_requested = False
        self._search_terminal_received = False
        self.search_button.setEnabled(False)
        self.stop_search_button.setEnabled(True)
        self.previous_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.results_summary.setText("正在加载…")
        worker = SearchWorker(
            self._settings_snapshot(),
            self.access_token,
            tags,
            rating,
            target_cursor,
            self,
        )
        self.search_worker = worker
        worker.succeeded.connect(self._search_succeeded)
        worker.failed.connect(self._search_failed)
        worker.cancelled.connect(self._search_cancelled)
        worker.finished.connect(self._search_finished)
        worker.start()
        self.status_label.setText("正在按保守节奏读取搜索结果")

    @Slot(object)
    def _search_succeeded(self, result: object) -> None:
        if self._search_cancel_requested:
            return
        if not isinstance(result, SearchPage):
            self._search_failed("搜索结果格式无效")
            return
        pending = self._pending_search
        if pending is None:
            return
        self._search_query = str(pending["query"])
        self._search_rating = str(pending["rating"])
        self._search_cursor = str(pending["cursor"])
        self._cursor_history = list(pending["history"])
        self._next_cursor = result.next_cursor
        self._show_posts(result.posts)
        self.results_summary.setText(f"本页 {len(result.posts)} 项")
        self._pending_search = None
        self._search_terminal_received = True
        self.stop_search_button.setEnabled(False)
        self.status_label.setText("搜索完成")

    @Slot(str)
    def _search_failed(self, message: str) -> None:
        if self._search_cancel_requested:
            self._search_cancelled()
            return
        self._restore_pending_search_summary()
        self._search_terminal_received = True
        self.stop_search_button.setEnabled(False)
        self.status_label.setText(message)
        self._log(f"搜索失败：{message}")

    @Slot()
    def _search_cancelled(self) -> None:
        self._restore_pending_search_summary()
        self._search_terminal_received = True
        self.stop_search_button.setEnabled(False)
        self.status_label.setText("搜索已取消，已保留当前结果")
        self._log("搜索已取消；当前结果与分页位置保持不变。")
        self.search_edit.setFocus(Qt.OtherFocusReason)

    def _restore_pending_search_summary(self) -> None:
        if self._pending_search is not None:
            self.results_summary.setText(
                str(self._pending_search.get("prior_summary", "输入标签后点击搜索"))
            )
        self._pending_search = None

    def _restore_search_navigation(self) -> None:
        busy = bool(self.search_worker and self.search_worker.isRunning())
        self.previous_button.setEnabled(not busy and bool(self._cursor_history))
        self.next_button.setEnabled(not busy and bool(self._next_cursor))

    @Slot()
    def _search_finished(self) -> None:
        if self._pending_search is not None:
            if self._search_cancel_requested:
                self._search_cancelled()
            elif not self._search_terminal_received:
                self._search_failed("搜索未返回结果")
        self.search_button.setEnabled(True)
        self.stop_search_button.setEnabled(False)
        if self.search_worker:
            self.search_worker.deleteLater()
        self.search_worker = None
        self._search_cancel_requested = False
        self._search_terminal_received = False
        self._restore_search_navigation()

    def _stop_search(self) -> None:
        if (
            self.search_worker
            and self.search_worker.isRunning()
            and not self._search_cancel_requested
            and not self._search_terminal_received
        ):
            self._search_cancel_requested = True
            self.stop_search_button.setEnabled(False)
            self.search_worker.cancel()
            self.status_label.setText("正在安全停止搜索…")

    def _search_next(self) -> None:
        if not self._next_cursor:
            return
        self._start_search(
            reset=False,
            cursor=self._next_cursor,
            history=[*self._cursor_history, self._search_cursor],
        )

    def _search_previous(self) -> None:
        if not self._cursor_history:
            return
        self._start_search(
            reset=False,
            cursor=self._cursor_history[-1],
            history=self._cursor_history[:-1],
        )

    def _show_posts(self, posts: Iterable[SankakuPost]) -> None:
        self._cancel_thumbnail_workers()
        self._thumbnail_generation += 1
        generation = self._thumbnail_generation
        self.result_list.clear()
        self._search_posts.clear()
        placeholder = QPixmap(190, 190)
        placeholder.fill(Qt.lightGray)
        for post in posts:
            self._search_posts[post.post_id] = post
            label = (
                f"{post.post_id}\n{_RATING_TEXT.get(post.rating, '未知')} · "
                f"{post.width}×{post.height}"
            )
            item = QListWidgetItem(QIcon(placeholder), label)
            item.setData(Qt.UserRole, post.post_id)
            item.setToolTip(" ".join(post.tag_names[:12]))
            item.setSizeHint(QSize(215, 245))
            self.result_list.addItem(item)
            thumbnail = post.preview_url or post.sample_url
            if thumbnail:
                worker = ThumbnailWorker(generation, post.post_id, thumbnail)
                key = (generation, post.post_id)
                self._thumbnail_workers[key] = worker
                worker.signals.succeeded.connect(self._thumbnail_succeeded)
                worker.signals.failed.connect(self._thumbnail_failed)
                self.thumbnail_pool.start(worker)

    @Slot(int, str, bytes)
    def _thumbnail_succeeded(self, generation: int, post_id: str, data: bytes) -> None:
        self._thumbnail_workers.pop((generation, post_id), None)
        if generation != self._thumbnail_generation:
            return
        buffer = QBuffer(self)
        buffer.setData(QByteArray(data))
        if not buffer.open(QIODevice.ReadOnly):
            return
        reader = QImageReader(buffer)
        reader.setAutoTransform(True)
        # Keep decoder allocations bounded even for a structurally valid but
        # adversarial raster file.  The preview is scaled to 190 px below, so
        # a larger global image allocation offers no user-visible benefit.
        QImageReader.setAllocationLimit(64)
        source_size = reader.size()
        if (
            not source_size.isValid()
            or source_size.width() > 8_192
            or source_size.height() > 8_192
            or source_size.width() * source_size.height() > 16_000_000
        ):
            return
        reader.setScaledSize(source_size.scaled(QSize(190, 190), Qt.KeepAspectRatio))
        image = reader.read()
        if image.isNull():
            return
        icon = QIcon(QPixmap.fromImage(image))
        for index in range(self.result_list.count()):
            item = self.result_list.item(index)
            if item.data(Qt.UserRole) == post_id:
                item.setIcon(icon)
                break

    @Slot(int, str)
    def _thumbnail_failed(self, generation: int, post_id: str) -> None:
        self._thumbnail_workers.pop((generation, post_id), None)

    def _cancel_thumbnail_workers(self) -> None:
        for worker in list(self._thumbnail_workers.values()):
            cancel = getattr(worker, "cancel", None)
            if callable(cancel):
                cancel()
        self.thumbnail_pool.clear()
        self._thumbnail_workers.clear()

    # ------------------------------ tasks and browser ------------------------------

    def _selected_result_ids(self) -> list[str]:
        return [str(item.data(Qt.UserRole)) for item in self.result_list.selectedItems()]

    def _add_selected_results(self) -> None:
        tasks = []
        for post_id in self._selected_result_ids():
            post = self._search_posts.get(post_id)
            if post:
                tasks.append(
                    DownloadTask(
                        post_id=post_id,
                        source_url=canonical_post_url(post_id) or "",
                        rating=post.rating,
                    )
                )
        self._add_tasks(tasks)

    def _open_first_selected_result(self) -> None:
        ids = self._selected_result_ids()
        if ids:
            self._open_post(ids[0])

    def _open_result_in_browser(self, item: QListWidgetItem) -> None:
        self._open_post(str(item.data(Qt.UserRole)))

    def _open_post(self, post_id: str) -> None:
        url = canonical_post_url(post_id)
        if not url:
            return
        opener = getattr(self.browser_tab, "open_url", None)
        if callable(opener):
            opener(url)
            self.tabs.setCurrentWidget(self.browser_tab)
        else:
            QDesktopServices.openUrl(QUrl(url))

    @Slot(str)
    def _add_browser_current(self, value: str) -> None:
        post_id = post_id_from_url(value) or normalize_post_id(value)
        if post_id:
            self._add_tasks([post_id])
        else:
            self.status_label.setText("当前页面不是单个作品页")

    @Slot(list)
    def _add_browser_visible(self, values: list) -> None:
        post_ids = []
        for value in values[:100]:
            post_id = post_id_from_url(value) or normalize_post_id(value)
            if post_id:
                post_ids.append(post_id)
        self._add_tasks(post_ids)

    def _add_manual_tasks(self) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("粘贴作品链接 / ID")
        dialog.setText("请在下方每行粘贴一个官方作品链接或作品 ID：")
        editor = QTextEdit(dialog)
        editor.setPlaceholderText("https://chan.sankakucomplex.com/cn/posts/…\n或作品 ID")
        editor.setMinimumSize(620, 260)
        dialog.layout().addWidget(editor, 1, 0, 1, dialog.layout().columnCount())
        dialog.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        if dialog.exec() != QMessageBox.Ok:
            return
        text = editor.toPlainText()
        post_ids: list[str] = []
        for url in _URL_RE.findall(text):
            post_id = post_id_from_url(url.rstrip(".,;，。；"))
            if post_id:
                post_ids.append(post_id)
        for line in text.splitlines():
            candidate = line.strip()
            if "://" not in candidate:
                post_id = normalize_post_id(candidate)
                if post_id:
                    post_ids.append(post_id)
        self._add_tasks(post_ids)

    def _add_tasks(self, values: Iterable[DownloadTask | str]) -> None:
        try:
            added, duplicates = self.task_store.add_many(values)
        except TaskStoreError as exc:
            QMessageBox.warning(self, "任务未加入", str(exc))
            return
        self._refresh_tasks()
        self.status_label.setText(f"已加入 {added} 项，跳过重复 {duplicates} 项")
        if added:
            self._log(f"任务篮新增 {added} 项；重复 {duplicates} 项。")

    def _refresh_tasks(self) -> None:
        tasks = self.task_store.list()
        self.task_table.setRowCount(len(tasks))
        for row, task in enumerate(tasks):
            id_item = QTableWidgetItem(task.post_id)
            id_item.setData(Qt.UserRole, task.post_id)
            self.task_table.setItem(row, 0, id_item)
            self.task_table.setItem(row, 1, QTableWidgetItem(_RATING_TEXT.get(task.rating, "未知")))
            self.task_table.setItem(row, 2, QTableWidgetItem(_STATUS_TEXT.get(task.status, task.status)))
            self.task_table.setItem(row, 3, QTableWidgetItem(task.added_at.replace("T", " ")[:19]))
            self.task_table.setItem(row, 4, QTableWidgetItem("; ".join(task.output_files)))
            self.task_table.setItem(row, 5, QTableWidgetItem(task.error))
        counts: dict[str, int] = {}
        for task in tasks:
            counts[task.status] = counts.get(task.status, 0) + 1
        self.task_summary.setText(
            f"共 {len(tasks)} · 待处理 {sum(counts.get(x, 0) for x in ('pending','failed','cancelled'))} "
            f"· 完成 {counts.get('completed', 0)}"
        )

    def _selected_task_ids(self) -> list[str]:
        ids: list[str] = []
        for index in self.task_table.selectionModel().selectedRows():
            item = self.task_table.item(index.row(), 0)
            if item:
                ids.append(str(item.data(Qt.UserRole)))
        return ids

    def _retry_selected_tasks(self) -> None:
        try:
            count = self.task_store.retry(self._selected_task_ids())
        except TaskStoreError as exc:
            QMessageBox.warning(self, "重新排队失败", str(exc))
            return
        self._refresh_tasks()
        self.status_label.setText(f"已重新排队 {count} 项")

    def _remove_selected_tasks(self) -> None:
        ids = self._selected_task_ids()
        if not ids:
            return
        if QMessageBox.question(
            self,
            "移除任务",
            f"仅从任务篮移除选中的 {len(ids)} 项；已下载文件不会删除。继续吗？",
        ) != QMessageBox.Yes:
            return
        try:
            count = self.task_store.remove(ids)
        except TaskStoreError as exc:
            QMessageBox.warning(self, "移除失败", str(exc))
            return
        self._refresh_tasks()
        self.status_label.setText(f"已移除 {count} 项任务，媒体文件未改动")

    # ------------------------------ login and settings ------------------------------

    def _credential_persistence(self) -> CredentialPersistence:
        """Build a coordinator around the current stores (also test-friendly)."""
        return CredentialPersistence(
            self.data_dir,
            self.settings,
            self.vault,
            journal=self.credential_journal,
        )

    def _load_credentials(self) -> None:
        try:
            recovery = self._credential_persistence().recover_and_load(
                settings_write_allowed=self._settings_save_allowed
            )
        except CredentialPersistenceError as exc:
            self.remember_check.setChecked(False)
            self.login_status.setText("本机会话恢复被安全阻止")
            self._log(f"本机会话恢复被安全阻止：{exc}")
            return
        self.remember_check.setChecked(recovery.remember_credentials)
        if recovery.message:
            self._log(recovery.message)
        if not recovery.resolved:
            self.remember_check.setChecked(False)
            self.login_status.setText("本机会话恢复待处理；本次不会自动载入")
            return
        values = recovery.session
        if values is not None:
            # Keep only the bearer session in long-lived application state.
            self.access_token = values.access_token
            self.session_username = values.username
            self._session_persisted = True
            self.username_edit.setText(values.username)
            self.password_edit.clear()
            self.login_status.setText("本机会话已载入，尚未联网验证")
            self.account_badge.setText("本机会话已载入")
            self._log("已从 Windows DPAPI 保护文件载入本机会话；密码未保留在输入框。")
        elif recovery.remember_credentials:
            self.login_status.setText("已启用本机记忆，当前没有可载入会话")
        else:
            self.login_status.setText("未启用本机凭据记忆")

    def _start_login(self) -> None:
        if self.login_worker and self.login_worker.isRunning():
            return
        try:
            credentials = Credentials(
                username=self.username_edit.text(),
                password=self.password_edit.text(),
            ).validated()
        except VaultError as exc:
            QMessageBox.warning(self, "登录信息无效", str(exc))
            return
        self.login_button.setEnabled(False)
        self.login_status.setText("正在验证…")
        worker = LoginWorker(self._settings_snapshot(), credentials, self)
        self.login_worker = worker
        worker.succeeded.connect(
            lambda token, username=credentials.username: self._login_succeeded(
                username, token
            )
        )
        worker.failed.connect(self._login_failed)
        worker.finished.connect(self._login_finished)
        worker.start()

    def _login_succeeded(self, username: str, token: str) -> None:
        try:
            session = StoredSession(username, token).validated()
        except VaultError:
            self._login_failed("站点返回了无效会话")
            return
        self.access_token = session.access_token
        self.session_username = session.username
        self._session_persisted = False
        previous_remember = bool(self.settings.get("remember_credentials"))
        remember = self.remember_check.isChecked()
        try:
            self._persist_remember_choice(
                remember,
                session=session,
            )
        except (CredentialPersistenceError, SettingsError, VaultError) as exc:
            safe_barrier = self._credential_persistence().prevents_automatic_load_except(
                session if remember else None
            )
            if remember:
                self.remember_check.setChecked(True if safe_barrier else False)
            else:
                self.remember_check.setChecked(False)
            if not safe_barrier:
                self._credential_close_save_blocked = True
            persistence_note = (
                "已验证安全恢复闸门，重启只会完成当前会话或保持禁用"
                if safe_barrier
                else "未能验证安全恢复闸门；重启前请恢复 Data 写权限并重试"
            )
            QMessageBox.warning(
                self,
                "登录成功，但本机保存失败",
                f"当前会话仍可使用；{persistence_note}。{exc}",
            )
        else:
            self._session_persisted = remember
            self._credential_close_save_blocked = False
        self.password_edit.clear()
        self.login_status.setText("登录已验证")
        self.account_badge.setText("已登录")
        self._log("账号登录验证成功；令牌未写入普通设置或日志。")

    @Slot(str)
    def _login_failed(self, message: str) -> None:
        self.login_status.setText("登录失败")
        if self.access_token:
            self.account_badge.setText("沿用原会话")
            self.login_status.setText("新登录失败，继续使用原已验证会话")
        else:
            self.account_badge.setText("未登录")
        self._log(f"登录失败：{message}")
        QMessageBox.warning(self, "登录失败", message)

    @Slot()
    def _login_finished(self) -> None:
        self.login_button.setEnabled(True)
        if self.login_worker:
            self.login_worker.deleteLater()
        self.login_worker = None

    def _clear_credentials(self) -> None:
        if self.login_worker and self.login_worker.isRunning():
            return
        if QMessageBox.question(
            self,
            "清除本机凭据",
            "将删除 Data 中的 DPAPI 加密凭据并清空当前令牌。不会删除下载或任务。继续吗？",
        ) != QMessageBox.Yes:
            return
        # Explicit logout is immediate in memory.  Durable cleanup follows and
        # may be retried from its disable marker on the next start.
        self.access_token = ""
        self.session_username = ""
        self._session_persisted = False
        self.remember_check.setChecked(False)
        self.username_edit.clear()
        self.password_edit.clear()
        self.login_status.setText("已清除")
        self.account_badge.setText("未登录")
        failure = None
        try:
            self._credential_persistence().disable(
                settings_write_allowed=self._settings_save_allowed
            )
        except (CredentialPersistenceError, SettingsError, VaultError) as exc:
            failure = exc
        if failure is None:
            self._log("已退出并清除本机加密凭据；下载与任务未改动。")
        else:
            safe_barrier = self._credential_persistence().prevents_automatic_load_except(
                None
            )
            pending_note = (
                "已留下禁用恢复标记，下次启动仍不会自动载入"
                if safe_barrier
                else "未能验证禁用恢复闸门；重启前请恢复 Data 写权限后重试"
            )
            self._log("当前会话已退出，但本机凭据清理尚未完全写盘。")
            if not safe_barrier:
                self._credential_close_save_blocked = True
            QMessageBox.warning(
                self,
                "当前会话已退出",
                f"{pending_note}；下载与任务未改动。{failure}",
            )

    def _persist_remember_choice(
        self,
        remember: bool,
        *,
        session: StoredSession | None = None,
    ) -> None:
        """Persist a login choice through the crash-consistent coordinator."""
        previous_remember = bool(self.settings.get("remember_credentials"))
        if not remember:
            self._credential_persistence().disable(
                settings_write_allowed=self._settings_save_allowed
            )
            return
        if session is None:
            raise CredentialPersistenceError("请先完成登录，再启用本机凭据记忆")
        self._credential_persistence().enable(
            session,
            previous_remember=previous_remember,
            settings_write_allowed=self._settings_save_allowed,
        )

    def _choose_download_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "选择下载目录", self.download_dir_edit.text() or self.default_download_dir
        )
        if directory:
            self.download_dir_edit.setText(directory)

    def _save_settings(self) -> None:
        previous_values = dict(self.settings.values)
        previous_remember = bool(previous_values.get("remember_credentials", False))
        remember = self.remember_check.isChecked()
        try:
            self.settings.update(
                {
                    "download_dir": self.download_dir_edit.text(),
                    "default_rating": str(self.rating_combo.currentData()),
                    "request_delay": self.delay_spin.value(),
                    "request_timeout": self.timeout_spin.value(),
                    "max_retries": self.retries_spin.value(),
                    "page_size": self.page_size_spin.value(),
                    "proxy": self.proxy_edit.text(),
                    "prefer_original": self.prefer_original_check.isChecked(),
                    "save_metadata": self.metadata_check.isChecked(),
                }
            )
            self.settings.set(
                "download_dir",
                self._portable_download_value(self.download_dir_edit.text()),
            )
        except (SettingsError, VaultError) as exc:
            self.settings.values = previous_values
            credential_note = ""
            if not remember:
                try:
                    self._credential_persistence().disable(
                        settings_write_allowed=self._settings_save_allowed
                    )
                except (
                    CredentialPersistenceError,
                    SettingsError,
                    VaultError,
                ) as credential_error:
                    credential_note = f"；本机记忆禁用尚未完成：{credential_error}"
                    if not self._credential_persistence().prevents_automatic_load_except(
                        None
                    ):
                        self._credential_close_save_blocked = True
                self.remember_check.setChecked(False)
                self._session_persisted = False
            else:
                self.remember_check.setChecked(previous_remember)
            QMessageBox.warning(self, "设置未保存", f"{exc}{credential_note}")
            return

        if not remember:
            try:
                self._credential_persistence().disable(
                    settings_write_allowed=self._settings_save_allowed
                )
                self._settings_save_allowed = True
            except (CredentialPersistenceError, SettingsError, VaultError) as exc:
                safe_barrier = (
                    self._credential_persistence().prevents_automatic_load_except(None)
                )
                if not safe_barrier:
                    self.settings.values = previous_values
                    self.settings.set("remember_credentials", False)
                    self.settings.set("credential_vault_receipt", "")
                    self._credential_close_save_blocked = True
                self._session_persisted = False
                self.remember_check.setChecked(False)
                QMessageBox.warning(
                    self,
                    "设置未完全保存",
                    (
                        "本机记忆已请求禁用；安全恢复闸门已验证。"
                        if safe_barrier
                        else "本机记忆禁用未能建立安全闸门；重启前请恢复 Data 写权限并重试。"
                    )
                    + f"{exc}",
                )
                return
            self._session_persisted = False
            self._credential_close_save_blocked = False
            self.remember_check.setChecked(False)
            self.status_label.setText("设置已安全保存")
            self._log("普通设置已保存；本机凭据记忆已禁用。")
            return

        current_session = None
        if (
            not self._session_persisted
            and self.session_username
            and self.access_token
        ):
            try:
                current_session = StoredSession(
                    self.session_username,
                    self.access_token,
                ).validated()
            except VaultError as exc:
                self.settings.values = previous_values
                self.remember_check.setChecked(previous_remember)
                QMessageBox.warning(self, "设置未保存", str(exc))
                return
        needs_credential_write = current_session is not None or not previous_remember
        try:
            if needs_credential_write:
                if current_session is None:
                    raise CredentialPersistenceError(
                        "请先完成登录，再启用本机凭据记忆"
                    )
                self._credential_persistence().enable(
                    current_session,
                    previous_remember=previous_remember,
                    settings_write_allowed=self._settings_save_allowed,
                )
            else:
                if not self._settings_save_allowed:
                    raise SettingsError("当前设置文件无法安全覆盖")
                # Receipt and remember flag are unchanged; this writes only
                # the validated ordinary setting edits made above.
                self.settings.save()
            self._settings_save_allowed = True
        except (CredentialPersistenceError, SettingsError, VaultError) as exc:
            safe_barrier = (
                self._credential_persistence().prevents_automatic_load_except(
                    current_session
                )
                if needs_credential_write and current_session is not None
                else False
            )
            pending = self.credential_journal.exists()
            if not pending and not needs_credential_write:
                self.settings.values = previous_values
            elif not safe_barrier:
                self.settings.values = previous_values
                self.settings.set("remember_credentials", False)
                self.settings.set("credential_vault_receipt", "")
                self._credential_close_save_blocked = True
            self.remember_check.setChecked(
                True
                if safe_barrier
                else (False if needs_credential_write else previous_remember)
            )
            self._session_persisted = False
            note = (
                "；安全恢复闸门已验证"
                if safe_barrier
                else ("；现有标记不能证明当前会话，重启前请重试" if pending else "")
            )
            QMessageBox.warning(self, "设置未保存", f"{exc}{note}")
            return

        if needs_credential_write:
            self._session_persisted = True
            self._credential_close_save_blocked = False
        self.status_label.setText("设置已安全保存")
        self._log("普通设置已保存；其中不含账号密码或令牌。")

    # ------------------------------ downloads ------------------------------

    def _start_download(self, *, selected_only: bool) -> None:
        if self.download_worker and self.download_worker.isRunning():
            self.status_label.setText("已有下载批次正在运行")
            return
        selected = set(self._selected_task_ids()) if selected_only else None
        tasks = [
            task
            for task in self.task_store.pending()
            if selected is None or task.post_id in selected
        ]
        if not tasks:
            self.status_label.setText("没有符合条件的可重试任务")
            return
        raw_output = str(self.settings.get("download_dir", "")).strip()
        if not raw_output:
            QMessageBox.warning(self, "无法下载", "请先选择下载目录。")
            return
        output = self._resolve_download_dir(raw_output)
        try:
            os.makedirs(output, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "无法下载", f"下载目录不可写（{type(exc).__name__}）")
            return
        try:
            queued = self.task_store.update_many(
                [task.post_id for task in tasks], status="queued", error=""
            )
        except TaskStoreError as exc:
            QMessageBox.warning(self, "无法开始下载", str(exc))
            return
        self._refresh_tasks()
        try:
            worker = DownloadWorker(self._settings_snapshot(), self.access_token, queued, self)
        except Exception as exc:
            try:
                self.task_store.update_many(
                    [task.post_id for task in queued], status="pending", error=""
                )
            except TaskStoreError:
                pass
            self._refresh_tasks()
            QMessageBox.warning(
                self, "无法开始下载", f"下载线程创建失败（{type(exc).__name__}）"
            )
            return
        self.download_worker = worker
        worker.item_started.connect(self._download_item_started)
        worker.item_progress.connect(self._download_item_progress)
        worker.item_succeeded.connect(self._download_item_succeeded)
        worker.item_warning.connect(self._download_item_warning)
        worker.item_failed.connect(self._download_item_failed)
        worker.batch_finished.connect(self._download_batch_finished)
        worker.batch_blocked.connect(self._download_batch_blocked)
        worker.finished.connect(self._download_thread_finished)
        self.stop_download_button.setEnabled(True)
        self._download_block_reason = ""
        self.global_progress.setRange(0, 0)
        self.global_progress.show()
        self.status_label.setText(f"开始顺序下载 {len(queued)} 项")
        self._log(f"下载批次开始：{len(queued)} 项，单并发。")
        worker.start()

    @Slot(str)
    def _download_item_started(self, post_id: str) -> None:
        try:
            self.task_store.update(post_id, status="running", error="")
        except TaskStoreError as exc:
            self._log(f"任务状态保存失败：{exc}")
        self._refresh_tasks()
        self.status_label.setText(f"正在下载 {post_id}")

    @Slot(str, int, int)
    def _download_item_progress(self, post_id: str, current: int, total: int) -> None:
        if total > 0:
            self.global_progress.setRange(0, 100)
            self.global_progress.setValue(min(100, int(current * 100 / total)))
            self.status_label.setText(
                f"正在下载 {post_id} · {current / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MiB"
            )
        else:
            self.global_progress.setRange(0, 0)

    @Slot(str, object)
    def _download_item_succeeded(self, post_id: str, result: object) -> None:
        relative = getattr(result, "relative_path", "")
        try:
            self.task_store.update(
                post_id,
                status="completed",
                error="",
                output_files=(relative,) if relative else (),
            )
        except TaskStoreError as exc:
            self._log(f"下载成功但任务终态保存失败：{exc}")
        self._refresh_tasks()
        self._log(f"作品 {post_id} 下载完成。")

    @Slot(str, str)
    def _download_item_warning(self, post_id: str, message: str) -> None:
        safe = message[:1000]
        self._log(f"作品 {post_id} 已保存，但有附加警告：{safe}")
        self.status_label.setText(f"{post_id} 已保存；{safe}")

    @Slot(str, str)
    def _download_item_failed(self, post_id: str, message: str) -> None:
        try:
            self.task_store.update(post_id, status="failed", error=message[:1000])
        except TaskStoreError as exc:
            self._log(f"任务失败状态保存失败：{exc}")
        self._refresh_tasks()
        self._log(f"作品 {post_id} 失败：{message}")

    @Slot(int, int, bool)
    def _download_batch_finished(self, succeeded: int, failed: int, cancelled: bool) -> None:
        if cancelled:
            reason = self._download_block_reason or "用户停止了批次"
            remaining = [
                task.post_id
                for task in self.task_store.list()
                if task.status in {"queued", "running"}
            ]
            if remaining:
                try:
                    self.task_store.update_many(
                        remaining,
                        status="pending" if self._download_block_reason else "cancelled",
                        error=reason,
                    )
                except TaskStoreError as exc:
                    self._log(f"未能原子恢复剩余任务：{exc}")
        self._refresh_tasks()
        self.status_label.setText(
            f"批次结束：成功 {succeeded}，失败 {failed}" + ("，已停止" if cancelled else "")
        )
        self._log(
            f"下载批次结束：成功 {succeeded}，失败 {failed}，停止={str(cancelled).lower()}。"
        )

    @Slot(str)
    def _download_batch_blocked(self, message: str) -> None:
        self._download_block_reason = message[:1000]
        self.status_label.setText(message)
        self._log(f"站点要求停止当前批次：{message}")

    @Slot()
    def _download_thread_finished(self) -> None:
        self.stop_download_button.setEnabled(False)
        self.global_progress.hide()
        if self.download_worker:
            self.download_worker.deleteLater()
        self.download_worker = None

    def _stop_download(self) -> None:
        if self.download_worker and self.download_worker.isRunning():
            self.download_worker.cancel()
            self.stop_download_button.setEnabled(False)
            self.status_label.setText("正在安全停止；未完成文件保留为 .part")

    # ------------------------------ lifecycle ------------------------------

    def _log(self, message: str) -> None:
        safe = str(message).replace("\r", " ").strip()
        self.log_view.appendPlainText(safe)

    def _restore_geometry(self) -> None:
        encoded = self.settings.get("window_geometry")
        if isinstance(encoded, str) and encoded:
            try:
                self.restoreGeometry(QByteArray.fromBase64(encoded.encode("ascii")))
            except (ValueError, TypeError):
                pass

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        workers = [self.search_worker, self.login_worker, self.download_worker]
        for worker in workers:
            if worker and worker.isRunning() and hasattr(worker, "cancel"):
                worker.cancel()
        still_running = False
        deadline = time.monotonic() + 10.0
        for worker in workers:
            if worker and worker.isRunning():
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                if not worker.wait(remaining_ms):
                    still_running = True
        if still_running:
            event.ignore()
            self.status_label.setText("正在等待网络任务安全结束，请稍后再关闭")
            return
        self._cancel_thumbnail_workers()
        if not self.thumbnail_pool.waitForDone(3000):
            # A QRunnable cannot be force-terminated safely.  Its cancel()
            # closes the live WinHTTP session, but the native call still needs
            # a short moment to unwind.  Keep the window (and its QObject
            # graph) alive until that has actually happened.
            event.ignore()
            self.status_label.setText("正在等待缩略图网络任务安全结束，请稍后再关闭")
            return
        if (
            self._settings_save_allowed
            and not self._credential_persistence().has_pending()
            and not self._credential_close_save_blocked
        ):
            try:
                geometry = bytes(self.saveGeometry().toBase64()).decode("ascii")
                self.settings.set("window_geometry", geometry)
                self.settings.save()
            except (SettingsError, UnicodeDecodeError):
                pass
        event.accept()


__all__ = ["MainWindow"]
