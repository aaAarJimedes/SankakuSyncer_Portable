# -*- coding: utf-8 -*-
"""Main desktop interface for native discovery, browsing, and downloads."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import time
from typing import Iterable

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QBuffer,
    QIODevice,
    QItemSelection,
    QItemSelectionModel,
    QModelIndex,
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
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from bound_file_reader import BoundRootIdentity
from credential_vault import CredentialVault, Credentials, StoredSession, VaultError
from credential_persistence import (
    CredentialJournal,
    CredentialPersistence,
    CredentialPersistenceError,
)
from library_query import LibraryQueryError, query_library_entries
from library_thumbnail import LibraryThumbnail, VerifiedThumbnailSource
from local_library import LibraryEntry, LibraryReport
from sankaku_api import SankakuPost, SearchPage
from sankaku_url_policy import (
    canonical_post_url,
    normalize_page_url,
    normalize_post_id,
    post_id_from_url,
    tag_search_url,
)
from settings_store import (
    SettingsConflictError,
    SettingsCorruptError,
    SettingsError,
    SettingsReadError,
    SettingsStore,
    normalize_download_directory,
)
from task_query import TaskQueryError, query_tasks
from task_store import (
    ACTIVE_TASK_STATES,
    DownloadTask,
    TaskStore,
    TaskStoreCorruptError,
    TaskStoreError,
    quarantine_corrupt_task_store,
)
from version import APP_DISPLAY_NAME
from workers import (
    DownloadWorker,
    LibraryThumbnailWorker,
    LibraryScanWorker,
    LoginWorker,
    SearchWorker,
    ThumbnailWorker,
)

try:
    from ui_browser_tab import BrowserTab, WEBENGINE_AVAILABLE
except (ImportError, RuntimeError):
    BrowserTab = None
    WEBENGINE_AVAILABLE = False


_URL_RE = re.compile(r"https://[^\s<>\"']+", re.IGNORECASE)
MAIN_TAB_TITLES = (
    "发现与搜索",
    "站内浏览",
    "下载任务",
    "本地下载库",
    "账号与设置",
)
_STATUS_TEXT = {
    "pending": "待处理",
    "queued": "排队中",
    "running": "下载中",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}
_RATING_TEXT = {"s": "Safe", "q": "Questionable", "e": "Explicit", "": "未知"}
_LIBRARY_STATUS_TEXT = {
    "verified": "已验证",
    "changed": "内容已变化",
    "invalid_metadata": "元数据无效",
    "missing_media": "缺少媒体",
    "missing_metadata": "缺少元数据",
    "unsafe_path": "路径不安全",
    "unreadable": "无法读取",
}


@dataclass(frozen=True)
class _TaskViewState:
    selected_ids: frozenset[str]
    current_id: str
    current_column: int
    top_id: str
    top_offset: int
    vertical_scroll: int
    horizontal_scroll: int


@dataclass(frozen=True)
class _LibraryViewState:
    selected_paths: frozenset[str]
    current_path: str
    current_entry: LibraryEntry | None
    current_column: int
    top_path: str
    top_offset: int
    vertical_scroll: int
    horizontal_scroll: int


@dataclass(frozen=True)
class _LibraryPreviewBinding:
    report_root: str
    report_root_identity: BoundRootIdentity | None
    entry: LibraryEntry


@dataclass(frozen=True)
class _DownloadTerminalIntent:
    status: str
    error: str
    output_files: tuple[object, ...] | None = None


def _format_file_size(value: object) -> str:
    if type(value) is not int or value < 0:
        return "—"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return "—"


class _TaskTableModel(QAbstractTableModel):
    """Expose a filtered task view without allocating one item per cell."""

    _HEADERS = ("作品 ID", "分级", "状态", "加入时间", "输出", "说明")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tasks: tuple[DownloadTask, ...] = ()

    def requires_reset(self, tasks: Iterable[DownloadTask]) -> bool:
        prepared = tuple(tasks)
        return len(prepared) != len(self._tasks) or any(
            before.post_id != after.post_id
            for before, after in zip(self._tasks, prepared)
        )

    def set_tasks(self, tasks: Iterable[DownloadTask]) -> bool:
        prepared = tuple(tasks)
        if not self.requires_reset(prepared):
            changed_rows = [
                row
                for row, (before, after) in enumerate(zip(self._tasks, prepared))
                if before != after
            ]
            self._tasks = prepared
            if changed_rows:
                last_column = self.columnCount() - 1
                start = previous = changed_rows[0]
                for row in changed_rows[1:]:
                    if row != previous + 1:
                        self.dataChanged.emit(
                            self.index(start, 0),
                            self.index(previous, last_column),
                            [Qt.DisplayRole, Qt.ToolTipRole],
                        )
                        start = row
                    previous = row
                self.dataChanged.emit(
                    self.index(start, 0),
                    self.index(previous, last_column),
                    [Qt.DisplayRole, Qt.ToolTipRole],
                )
            return False
        self.beginResetModel()
        self._tasks = prepared
        self.endResetModel()
        return True

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._tasks)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if (
            role == Qt.DisplayRole
            and orientation == Qt.Horizontal
            and 0 <= section < len(self._HEADERS)
        ):
            return self._HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._tasks):
            return None
        task = self._tasks[index.row()]
        column = index.column()
        if role == Qt.ToolTipRole and column in {4, 5}:
            return "; ".join(task.output_files) if column == 4 else task.error
        if role != Qt.DisplayRole:
            return None
        values = (
            task.post_id,
            _RATING_TEXT.get(task.rating, "未知"),
            _STATUS_TEXT.get(task.status, task.status),
            task.added_at.replace("T", " ")[:19],
            "; ".join(task.output_files),
            task.error,
        )
        return values[column] if 0 <= column < len(values) else None

    def task_at(self, row: int) -> DownloadTask | None:
        return self._tasks[row] if 0 <= row < len(self._tasks) else None


class _LibraryTableModel(QAbstractTableModel):
    """Expose a bounded library report without allocating one widget per cell."""

    _HEADERS = (
        "作品 ID",
        "版本",
        "完整性",
        "大小",
        "类型",
        "分级",
        "作者",
        "文件 / 说明",
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: tuple[LibraryEntry, ...] = ()

    def requires_reset(self, entries: Iterable[LibraryEntry]) -> bool:
        prepared = tuple(entries)
        return len(prepared) != len(self._entries) or any(
            before.relative_path != after.relative_path
            for before, after in zip(self._entries, prepared)
        )

    def set_entries(self, entries: Iterable[LibraryEntry]) -> bool:
        prepared = tuple(entries)
        if not self.requires_reset(prepared):
            changed_rows = [
                row
                for row, (before, after) in enumerate(zip(self._entries, prepared))
                if before != after
            ]
            self._entries = prepared
            if changed_rows:
                last_column = self.columnCount() - 1
                start = previous = changed_rows[0]
                for row in changed_rows[1:]:
                    if row != previous + 1:
                        self.dataChanged.emit(
                            self.index(start, 0),
                            self.index(previous, last_column),
                            [Qt.DisplayRole, Qt.ToolTipRole],
                        )
                        start = row
                    previous = row
                self.dataChanged.emit(
                    self.index(start, 0),
                    self.index(previous, last_column),
                    [Qt.DisplayRole, Qt.ToolTipRole],
                )
            return False
        self.beginResetModel()
        self._entries = prepared
        self.endResetModel()
        return True

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if (
            role == Qt.DisplayRole
            and orientation == Qt.Horizontal
            and 0 <= section < len(self._HEADERS)
        ):
            return self._HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._entries):
            return None
        entry = self._entries[index.row()]
        column = index.column()
        if role == Qt.ToolTipRole and column == 7 and entry.tags:
            return " ".join(entry.tags)
        if role != Qt.DisplayRole:
            return None
        detail = entry.relative_path
        if entry.detail:
            detail = f"{detail} · {entry.detail}" if detail else entry.detail
        values = (
            entry.post_id,
            entry.variant,
            _LIBRARY_STATUS_TEXT.get(entry.status, entry.status),
            _format_file_size(entry.size),
            entry.content_type,
            _RATING_TEXT.get(entry.rating, entry.rating or "未知"),
            entry.author,
            detail,
        )
        return values[column] if 0 <= column < len(values) else None

    def entry_at(self, row: int) -> LibraryEntry | None:
        return self._entries[row] if 0 <= row < len(self._entries) else None


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
        self._settings_state_available = self.settings.last_load_error is None
        if isinstance(self.settings.last_load_error, SettingsReadError):
            self._settings_save_allowed = False
            self._startup_messages.append(
                "设置文件暂时无法读取，已原样保留；本次不会保存设置、载入或更改本机凭据。"
                "请关闭占用该文件的程序后重新启动。"
            )
        elif isinstance(self.settings.last_load_error, SettingsCorruptError):
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            recovery_path = os.path.join(
                self.data_dir, f"settings.corrupt.{stamp}.json"
            )
            try:
                self.settings.quarantine_corrupt(recovery_path)
            except SettingsError as exc:
                self._settings_save_allowed = False
                self._settings_state_available = False
                self._startup_messages.append(
                    "损坏的设置文件无法备份；本次关闭时不会覆盖它"
                    f"（{type(exc).__name__}）。"
                )
            else:
                self._startup_messages.append(
                    "损坏的设置已在内容摘要复核后隔离为 "
                    f"{os.path.basename(recovery_path)}。"
                )
                if self.settings.load():
                    self._settings_state_available = True
                else:
                    self._settings_save_allowed = False
                    self._settings_state_available = False
                    self._startup_messages.append(
                        "备份后仍无法建立可靠设置基线；本次不会保存设置或更改本机凭据。"
                    )
        if not self.settings.get("download_dir"):
            self.settings.set("download_dir", "Downloads")
            if not self.settings.last_error:
                try:
                    self.settings.save()
                except SettingsConflictError:
                    self._settings_save_allowed = False
                    self._settings_state_available = False
                    self._startup_messages.append(
                        "设置已被外部程序更新；本次保持只读，请重新启动后再试。"
                    )
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
            if exc.snapshot_signature is None:
                raise
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            recovery_path = os.path.join(self.data_dir, f"tasks.corrupt.{stamp}.json")
            quarantine_corrupt_task_store(
                self.data_dir,
                recovery_path,
                exc.snapshot_signature,
            )
            self.task_store = TaskStore(self.data_dir)
            self._startup_messages.append(
                "损坏的任务篮已在内容摘要复核后原样保留为 "
                f"{os.path.basename(recovery_path)}；任务篮已重新载入。"
            )

        self.search_worker: SearchWorker | None = None
        self.login_worker: LoginWorker | None = None
        self.download_worker: DownloadWorker | None = None
        self.library_worker: LibraryScanWorker | None = None
        self.library_preview_worker: LibraryThumbnailWorker | None = None
        self._download_block_reason = ""
        self._download_task_ids: frozenset[str] = frozenset()
        self._download_terminal_owner: object | None = None
        self._download_terminal_intents: dict[str, _DownloadTerminalIntent] = {}
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
        self._library_report: LibraryReport | None = None
        self._library_report_root = ""
        self._library_report_root_identity: BoundRootIdentity | None = None
        self._library_pending_root = ""
        self._library_cancel_requested = False
        self._library_terminal_received = False
        self._library_preview_generation = 0
        self._library_preview_entry: LibraryEntry | None = None
        self._library_preview_binding: _LibraryPreviewBinding | None = None
        self._library_refreshing = False
        self._library_preview_pending: tuple[int, _LibraryPreviewBinding] | None = None

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.resize(1320, 860)
        self.setMinimumSize(960, 680)
        self._build_ui()
        self._restore_geometry()
        if self._settings_state_available:
            self._load_credentials()
        else:
            self.remember_check.setChecked(False)
            self.remember_check.setEnabled(False)
            self.login_button.setEnabled(False)
            self.logout_button.setEnabled(False)
            self.save_settings_button.setEnabled(False)
            self.library_scan_button.setEnabled(False)
            self.download_selected_button.setEnabled(False)
            self.download_all_button.setEnabled(False)
            self.login_status.setText("设置暂时不可用；本机会话未载入")
            self.account_badge.setText("凭据保持原样")
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
        self.tabs.addTab(self._build_discovery_tab(), MAIN_TAB_TITLES[0])
        self.browser_tab = self._build_browser_tab()
        self.tabs.addTab(self.browser_tab, MAIN_TAB_TITLES[1])
        self.tabs.addTab(self._build_tasks_tab(), MAIN_TAB_TITLES[2])
        self.tabs.addTab(self._build_library_tab(), MAIN_TAB_TITLES[3])
        self.tabs.addTab(self._build_settings_tab(), MAIN_TAB_TITLES[4])
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
        self.download_selected_button = QPushButton("下载所选")
        self.download_selected_button.clicked.connect(
            lambda: self._start_download(selected_only=True)
        )
        actions.addWidget(self.download_selected_button)
        self.download_all_button = QPushButton("下载全部待处理")
        self.download_all_button.clicked.connect(
            lambda: self._start_download(selected_only=False)
        )
        actions.addWidget(self.download_all_button)
        self.stop_download_button = QPushButton("停止当前批次")
        self.stop_download_button.clicked.connect(self._stop_download)
        self.stop_download_button.setEnabled(False)
        actions.addWidget(self.stop_download_button)
        retry = QPushButton("重新排队所选")
        retry.clicked.connect(self._retry_selected_tasks)
        actions.addWidget(retry)
        self.remove_tasks_button = QPushButton("移除所选任务")
        self.remove_tasks_button.clicked.connect(self._remove_selected_tasks)
        self.remove_tasks_button.setEnabled(False)
        actions.addWidget(self.remove_tasks_button)
        actions.addStretch(1)
        self.task_summary = QLabel()
        actions.addWidget(self.task_summary)
        layout.addLayout(actions)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("状态"))
        self.task_filter_combo = QComboBox()
        self.task_filter_combo.setAccessibleName("下载任务状态筛选")
        self.task_filter_combo.addItem("全部", "")
        for status in (
            "pending",
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
        ):
            self.task_filter_combo.addItem(_STATUS_TEXT[status], status)
        self.task_filter_combo.currentIndexChanged.connect(
            lambda _index: self._refresh_tasks()
        )
        filters.addWidget(self.task_filter_combo)
        filters.addWidget(QLabel("搜索"))
        self.task_search_edit = QLineEdit()
        self.task_search_edit.setAccessibleName("搜索下载任务")
        self.task_search_edit.setPlaceholderText("作品 ID、输出文件或失败说明（空格分隔多个条件）")
        self.task_search_edit.setClearButtonEnabled(True)
        self.task_search_edit.setMaxLength(256)
        self.task_search_edit.textChanged.connect(lambda _text: self._refresh_tasks())
        filters.addWidget(self.task_search_edit, 1)
        layout.addLayout(filters)

        splitter = QSplitter(Qt.Vertical)
        self.task_table = QTableView()
        self.task_table.setAccessibleName("下载任务筛选结果")
        self.task_model = _TaskTableModel(self.task_table)
        self.task_table.setModel(self.task_model)
        self.task_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.task_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.task_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.task_table.selectionModel().selectionChanged.connect(
            lambda _selected, _deselected: self._update_remove_tasks_action()
        )
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

    def _build_library_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)

        actions = QHBoxLayout()
        self.library_scan_button = QPushButton("扫描并校验")
        self.library_scan_button.setAccessibleName("扫描本地下载库")
        self.library_scan_button.clicked.connect(self._start_library_scan)
        actions.addWidget(self.library_scan_button)
        self.library_stop_button = QPushButton("停止校验")
        self.library_stop_button.setAccessibleName("停止本地库校验")
        self.library_stop_button.clicked.connect(self._stop_library_scan)
        self.library_stop_button.setEnabled(False)
        actions.addWidget(self.library_stop_button)
        actions.addWidget(QLabel("状态"))
        self.library_filter_combo = QComboBox()
        self.library_filter_combo.setAccessibleName("本地库完整性状态筛选")
        self.library_filter_combo.addItem("全部", "")
        for status in (
            "verified",
            "changed",
            "invalid_metadata",
            "missing_media",
            "missing_metadata",
            "unsafe_path",
            "unreadable",
        ):
            self.library_filter_combo.addItem(_LIBRARY_STATUS_TEXT[status], status)
        self.library_filter_combo.currentIndexChanged.connect(
            lambda _index: self._refresh_library_table()
        )
        actions.addWidget(self.library_filter_combo)
        actions.addWidget(QLabel("排序"))
        self.library_sort_combo = QComboBox()
        self.library_sort_combo.setAccessibleName("本地库排序方式")
        self.library_sort_combo.addItem("ID 升序", "id_asc")
        self.library_sort_combo.addItem("ID 降序", "id_desc")
        self.library_sort_combo.addItem("最新创作", "newest")
        self.library_sort_combo.addItem("最大文件", "largest")
        self.library_sort_combo.currentIndexChanged.connect(
            lambda _index: self._refresh_library_table()
        )
        actions.addWidget(self.library_sort_combo)
        actions.addStretch(1)
        self.library_summary = QLabel("尚未扫描")
        actions.addWidget(self.library_summary)
        layout.addLayout(actions)

        self.library_path_label = QLabel(
            self._resolve_download_dir(str(self.settings.get("download_dir", "")))
        )
        self.library_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.library_path_label.setObjectName("subtleText")
        layout.addWidget(self.library_path_label)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("搜索"))
        self.library_search_edit = QLineEdit()
        self.library_search_edit.setAccessibleName("搜索本地下载库")
        self.library_search_edit.setPlaceholderText(
            "作品 ID、作者、标签、文件名（空格分隔多个条件）"
        )
        self.library_search_edit.setClearButtonEnabled(True)
        self.library_search_edit.setMaxLength(256)
        self.library_search_edit.textChanged.connect(
            lambda _text: self._refresh_library_table()
        )
        search_row.addWidget(self.library_search_edit, 1)
        layout.addLayout(search_row)

        notice = QLabel(
            "仅在已保存的下载目录第一层进行只读离线校验；不会联网、删除、修复或自动重下。"
            "缺少元数据的文件不会被标记为完整性通过。"
        )
        notice.setWordWrap(True)
        notice.setObjectName("noticeLabel")
        layout.addWidget(notice)

        self.library_table = QTableView()
        self.library_table.setAccessibleName("本地下载库校验结果")
        self.library_model = _LibraryTableModel(self.library_table)
        self.library_table.setModel(self.library_model)
        self.library_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.library_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.library_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.library_table.doubleClicked.connect(
            lambda index: self._open_library_row(index.row(), index.column())
        )
        self.library_table.setAlternatingRowColors(True)
        self.library_table.verticalHeader().setVisible(False)
        header = self.library_table.horizontalHeader()
        header.setResizeContentsPrecision(200)
        for index in range(7):
            header.setSectionResizeMode(index, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.Stretch)
        self.library_table.selectionModel().currentRowChanged.connect(
            self._library_row_selected
        )

        preview_panel = QFrame()
        preview_panel.setFrameShape(QFrame.StyledPanel)
        preview_panel.setProperty("card", True)
        preview_layout = QVBoxLayout(preview_panel)
        preview_title = QLabel("离线预览")
        preview_title.setObjectName("sectionTitle")
        preview_layout.addWidget(preview_title)
        self.library_preview_image = QLabel("选择一张已验证的静态图片")
        self.library_preview_image.setAccessibleName("本地图片离线预览")
        self.library_preview_image.setAlignment(Qt.AlignCenter)
        self.library_preview_image.setMinimumSize(300, 300)
        self.library_preview_image.setWordWrap(True)
        preview_layout.addWidget(self.library_preview_image, 1)
        self.library_preview_meta = QLabel(
            "预览只读取当前报告中已验证的 JPEG、PNG 或 WebP；不会联网。"
        )
        self.library_preview_meta.setObjectName("subtleText")
        self.library_preview_meta.setWordWrap(True)
        self.library_preview_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        preview_layout.addWidget(self.library_preview_meta)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.library_table)
        splitter.addWidget(preview_panel)
        splitter.setSizes([900, 360])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
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
        self.save_settings_button = QPushButton("保存设置")
        self.save_settings_button.clicked.connect(self._save_settings)
        layout.addWidget(self.save_settings_button, 0, Qt.AlignRight)
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
        candidate = normalize_download_directory(value)
        if not candidate:
            return self.default_download_dir
        if os.path.isabs(candidate):
            return os.path.abspath(candidate)
        resolved = os.path.abspath(
            os.path.join(self.portable_root, candidate.replace("/", os.sep))
        )
        downloads_root = os.path.abspath(
            os.path.join(self.portable_root, "Downloads")
        )
        if os.path.commonpath((resolved, downloads_root)) != downloads_root:
            raise SettingsError("invalid download directory")
        return resolved

    def _portable_download_value(self, value: str) -> str:
        if not value.strip():
            return "Downloads"
        normalized = normalize_download_directory(value)
        if not os.path.isabs(normalized):
            return normalized
        absolute = os.path.abspath(normalized)
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
        try:
            visible = tuple(
                query_tasks(
                    tasks,
                    status=str(self.task_filter_combo.currentData() or ""),
                    query=self.task_search_edit.text(),
                )
            )
        except TaskQueryError as exc:
            self.task_model.set_tasks(())
            self.task_summary.setText(str(exc))
            self._update_remove_tasks_action()
            return
        view_state = (
            self._capture_task_view_state()
            if self.task_model.requires_reset(visible)
            else None
        )
        reset = self.task_model.set_tasks(visible)
        if reset and view_state is not None:
            self._restore_task_view_state(visible, view_state)
        counts: dict[str, int] = {}
        for task in tasks:
            counts[task.status] = counts.get(task.status, 0) + 1
        self.task_summary.setText(
            f"显示 {len(visible)} / 共 {len(tasks)} · "
            f"待处理 {sum(counts.get(x, 0) for x in ('pending','failed','cancelled'))} "
            f"· 完成 {counts.get('completed', 0)}"
        )
        self._update_remove_tasks_action()

    def _capture_task_view_state(self) -> _TaskViewState:
        current = self.task_table.currentIndex()
        current_task = (
            self.task_model.task_at(current.row()) if current.isValid() else None
        )
        top = self.task_table.indexAt(self.task_table.viewport().rect().topLeft())
        top_task = self.task_model.task_at(top.row()) if top.isValid() else None
        top_offset = self.task_table.visualRect(top).top() if top.isValid() else 0
        return _TaskViewState(
            selected_ids=frozenset(self._selected_task_ids()),
            current_id=current_task.post_id if current_task is not None else "",
            current_column=current.column() if current.isValid() else 0,
            top_id=top_task.post_id if top_task is not None else "",
            top_offset=top_offset,
            vertical_scroll=self.task_table.verticalScrollBar().value(),
            horizontal_scroll=self.task_table.horizontalScrollBar().value(),
        )

    def _restore_task_view_state(
        self, visible: Iterable[DownloadTask], state: _TaskViewState
    ) -> None:
        rows_by_id = {task.post_id: row for row, task in enumerate(visible)}
        selection_model = self.task_table.selectionModel()
        selected_rows = sorted(
            rows_by_id[post_id]
            for post_id in state.selected_ids
            if post_id in rows_by_id
        )
        if selected_rows:
            selection = QItemSelection()
            last_column = max(0, self.task_model.columnCount() - 1)
            start = previous = selected_rows[0]
            for row in selected_rows[1:]:
                if row != previous + 1:
                    selection.select(
                        self.task_model.index(start, 0),
                        self.task_model.index(previous, last_column),
                    )
                    start = row
                previous = row
            selection.select(
                self.task_model.index(start, 0),
                self.task_model.index(previous, last_column),
            )
            selection_model.select(selection, QItemSelectionModel.ClearAndSelect)

        current_row = rows_by_id.get(state.current_id)
        if current_row is not None and self.task_model.columnCount() > 0:
            current_column = min(
                max(0, state.current_column), self.task_model.columnCount() - 1
            )
            selection_model.setCurrentIndex(
                self.task_model.index(current_row, current_column),
                QItemSelectionModel.NoUpdate,
            )

        top_row = rows_by_id.get(state.top_id)
        if top_row is not None:
            self.task_table.scrollTo(
                self.task_model.index(top_row, 0),
                QAbstractItemView.PositionAtTop,
            )
            if self.task_table.verticalScrollMode() == QAbstractItemView.ScrollPerPixel:
                bar = self.task_table.verticalScrollBar()
                bar.setValue(bar.value() - state.top_offset)
        else:
            self.task_table.verticalScrollBar().setValue(state.vertical_scroll)
        self.task_table.horizontalScrollBar().setValue(state.horizontal_scroll)

    def _selected_task_ids(self) -> list[str]:
        ids: list[str] = []
        row_count = self.task_model.rowCount()
        column_count = self.task_model.columnCount()
        if row_count <= 0 or column_count <= 0:
            return ids
        selected_rows: set[int] = set()
        partial_masks: dict[int, int] = {}
        full_mask = (1 << column_count) - 1
        for selected_range in self.task_table.selectionModel().selection():
            if not selected_range.isValid():
                continue
            first = max(0, selected_range.top())
            last = min(row_count - 1, selected_range.bottom())
            left = max(0, selected_range.left())
            right = min(column_count - 1, selected_range.right())
            if first > last or left > right:
                continue
            column_mask = ((1 << (right - left + 1)) - 1) << left
            if column_mask == full_mask:
                selected_rows.update(range(first, last + 1))
                continue
            for row in range(first, last + 1):
                partial_masks[row] = partial_masks.get(row, 0) | column_mask
        selected_rows.update(
            row for row, mask in partial_masks.items() if mask == full_mask
        )
        for row in sorted(selected_rows):
            task = self.task_model.task_at(row)
            if task is not None:
                ids.append(task.post_id)
        return ids

    def _retry_selected_tasks(self) -> None:
        try:
            count = self.task_store.retry(self._selected_task_ids())
        except TaskStoreError as exc:
            QMessageBox.warning(self, "重新排队失败", str(exc))
            return
        self._refresh_tasks()
        self.status_label.setText(f"已重新排队 {count} 项")

    def _task_removal_block_reason(self, post_ids: Iterable[str]) -> str:
        normalized = tuple(post_ids)
        if any(post_id in self._download_task_ids for post_id in normalized):
            return (
                "当前下载批次仍拥有所选任务；请先停止并等待批次完全结束后再移除"
            )
        for post_id in normalized:
            task = self.task_store.get(post_id)
            if task is not None and task.status in ACTIVE_TASK_STATES:
                return (
                    "所选任务仍在排队或下载中；请等待批次结束，必要时重启恢复后再移除"
                )
        return ""

    def _update_remove_tasks_action(self) -> None:
        ids = self._selected_task_ids()
        reason = self._task_removal_block_reason(ids)
        self.remove_tasks_button.setEnabled(bool(ids) and not reason)
        self.remove_tasks_button.setToolTip(
            reason or "仅移除任务记录，不删除已经下载的媒体文件"
        )

    def _remove_selected_tasks(self) -> None:
        ids = self._selected_task_ids()
        if not ids:
            return
        block_reason = self._task_removal_block_reason(ids)
        if block_reason:
            self.status_label.setText(block_reason)
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

    # ------------------------------ local library ------------------------------

    def _start_library_scan(self) -> None:
        if not self._settings_state_available:
            self.status_label.setText("设置文件暂时不可用；重启前不会扫描推测的下载目录")
            return
        if self.library_worker is not None:
            self.status_label.setText("本地库校验正在进行，请稍候")
            return
        if self.download_worker is not None:
            self.status_label.setText("请等待当前下载批次结束后再校验本地库")
            return
        output_dir = self._resolve_download_dir(
            str(self.settings.get("download_dir", ""))
        )
        self._cancel_library_preview("扫描期间已暂停离线预览")
        self._library_pending_root = output_dir
        self.library_path_label.setText(output_dir)
        self._library_cancel_requested = False
        self._library_terminal_received = False
        self.library_scan_button.setEnabled(False)
        self.library_stop_button.setEnabled(True)
        self.library_summary.setText("正在枚举并校验…")
        self.global_progress.setRange(0, 0)
        self.global_progress.show()
        try:
            worker = LibraryScanWorker(output_dir, self)
        except Exception as exc:
            self._library_pending_root = ""
            self.library_scan_button.setEnabled(True)
            self.library_stop_button.setEnabled(False)
            self.global_progress.hide()
            self._restore_library_report_summary("未能启动扫描")
            QMessageBox.warning(
                self,
                "无法开始本地库校验",
                f"校验线程创建失败（{type(exc).__name__}）",
            )
            return
        self.library_worker = worker
        worker.progress.connect(self._library_scan_progress)
        worker.succeeded.connect(self._library_scan_succeeded)
        worker.failed.connect(self._library_scan_failed)
        worker.cancelled.connect(self._library_scan_cancelled)
        worker.finished.connect(self._library_scan_finished)
        self.status_label.setText("正在只读校验本地下载库")
        self._log("本地下载库校验开始；只读、离线、不删除文件。")
        worker.start()

    @Slot(int, int, object)
    def _library_scan_progress(
        self, done: int, total: int, checked_bytes: object
    ) -> None:
        if self._library_cancel_requested or self.library_worker is None:
            return
        checked = checked_bytes if type(checked_bytes) is int else 0
        if total > 0:
            self.global_progress.setRange(0, total)
            self.global_progress.setValue(min(total, max(0, done)))
        else:
            self.global_progress.setRange(0, 0)
        self.library_summary.setText(
            f"已校验 {max(0, done)} / {max(0, total)} · {_format_file_size(checked)}"
        )

    @Slot(object)
    def _library_scan_succeeded(self, result: object) -> None:
        if self._library_cancel_requested:
            return
        if not isinstance(result, LibraryReport):
            self._library_scan_failed("本地库报告格式无效")
            return
        self._library_report = result
        self._library_report_root = self._library_pending_root
        self._library_report_root_identity = (
            result.root_identity
            if isinstance(result.root_identity, BoundRootIdentity)
            else None
        )
        self._library_terminal_received = True
        self.library_stop_button.setEnabled(False)
        self._refresh_library_table()
        self.status_label.setText("本地下载库校验完成")
        self._log(
            f"本地库校验完成：候选 {result.scanned_candidates}，"
            f"验证通过 {result.verified_count}。"
        )

    @Slot(str)
    def _library_scan_failed(self, message: str) -> None:
        if self._library_cancel_requested:
            self._library_scan_cancelled()
            return
        self._library_terminal_received = True
        self.library_stop_button.setEnabled(False)
        self._restore_library_report_summary("扫描失败，未生成报告")
        self.status_label.setText(message)
        self._log(f"本地库校验失败：{message}")

    @Slot()
    def _library_scan_cancelled(self) -> None:
        self._library_terminal_received = True
        self.library_stop_button.setEnabled(False)
        self._restore_library_report_summary("已取消，未生成报告")
        self.status_label.setText("本地库校验已取消，保留上次完整报告")
        self._log("本地库校验已取消；未提交不完整扫描结果。")

    @Slot()
    def _library_scan_finished(self) -> None:
        if not self._library_terminal_received:
            if self._library_cancel_requested:
                self._library_scan_cancelled()
            else:
                self._library_scan_failed("本地库校验未返回完整报告")
        self.library_scan_button.setEnabled(True)
        self.library_stop_button.setEnabled(False)
        self.global_progress.hide()
        if self.library_worker:
            self.library_worker.deleteLater()
        self.library_worker = None
        self._library_pending_root = ""
        self._library_cancel_requested = False
        self._library_terminal_received = False

    def _stop_library_scan(self) -> None:
        if (
            self.library_worker
            and self.library_worker.isRunning()
            and not self._library_cancel_requested
            and not self._library_terminal_received
        ):
            self._library_cancel_requested = True
            self.library_stop_button.setEnabled(False)
            self.library_worker.cancel()
            self.status_label.setText("正在安全停止本地库校验…")

    def _refresh_library_table(self) -> None:
        report = self._library_report
        if report is None:
            self._cancel_library_preview("选择一张已验证的静态图片")
            self.library_model.set_entries(())
            return
        selected_status = str(self.library_filter_combo.currentData() or "")
        selected_sort = str(self.library_sort_combo.currentData() or "id_asc")
        try:
            entries = query_library_entries(
                report.entries,
                status=selected_status,
                query=self.library_search_edit.text(),
                sort=selected_sort,
            )
        except LibraryQueryError as exc:
            self._cancel_library_preview("选择一张已验证的静态图片")
            self.library_model.set_entries(())
            self.library_summary.setText(str(exc))
            return
        view_state = self._capture_library_view_state()
        self._library_refreshing = True
        try:
            reset = self.library_model.set_entries(entries)
            if reset:
                self._restore_library_view_state(entries, view_state)
        finally:
            self._library_refreshing = False

        current = self.library_table.currentIndex()
        current_entry = (
            self.library_model.entry_at(current.row()) if current.isValid() else None
        )
        preview_is_still_bound = bool(
            current_entry is not None
            and current_entry == view_state.current_entry
            and self._library_preview_entry == current_entry
            and self._library_preview_binding
            == _LibraryPreviewBinding(
                self._library_report_root,
                self._library_report_root_identity,
                current_entry,
            )
        )
        if current_entry is None:
            if self._library_preview_entry is not None:
                self._cancel_library_preview("选择一张已验证的静态图片")
        elif not preview_is_still_bound:
            self._request_library_preview(current_entry)

        counts = report.status_counts
        self.library_summary.setText(
            f"显示 {len(entries)} / {len(report.entries)} · "
            f"已验证 {counts.get('verified', 0)} · "
            f"变化 {counts.get('changed', 0)} · "
            f"缺元数据 {counts.get('missing_metadata', 0)} · "
            f"缺文件 {counts.get('missing_media', 0)} · "
            f"不可读 {counts.get('unreadable', 0) + counts.get('unsafe_path', 0)}"
        )

    def _capture_library_view_state(self) -> _LibraryViewState:
        current = self.library_table.currentIndex()
        current_entry = (
            self.library_model.entry_at(current.row()) if current.isValid() else None
        )
        top = self.library_table.indexAt(
            self.library_table.viewport().rect().topLeft()
        )
        top_entry = self.library_model.entry_at(top.row()) if top.isValid() else None
        top_offset = self.library_table.visualRect(top).top() if top.isValid() else 0
        selected_paths = frozenset(
            entry.relative_path
            for index in self.library_table.selectionModel().selectedRows()
            if (entry := self.library_model.entry_at(index.row())) is not None
        )
        return _LibraryViewState(
            selected_paths=selected_paths,
            current_path=(
                current_entry.relative_path if current_entry is not None else ""
            ),
            current_entry=current_entry,
            current_column=current.column() if current.isValid() else 0,
            top_path=top_entry.relative_path if top_entry is not None else "",
            top_offset=top_offset,
            vertical_scroll=self.library_table.verticalScrollBar().value(),
            horizontal_scroll=self.library_table.horizontalScrollBar().value(),
        )

    def _restore_library_view_state(
        self, visible: Iterable[LibraryEntry], state: _LibraryViewState
    ) -> None:
        rows_by_path = {
            entry.relative_path: row for row, entry in enumerate(visible)
        }
        selection_model = self.library_table.selectionModel()
        selected_rows = sorted(
            rows_by_path[path]
            for path in state.selected_paths
            if path in rows_by_path
        )
        if selected_rows:
            selection = QItemSelection()
            last_column = max(0, self.library_model.columnCount() - 1)
            for row in selected_rows:
                selection.select(
                    self.library_model.index(row, 0),
                    self.library_model.index(row, last_column),
                )
            selection_model.select(
                selection, QItemSelectionModel.ClearAndSelect
            )

        current_row = rows_by_path.get(state.current_path)
        if current_row is not None and self.library_model.columnCount() > 0:
            current_column = min(
                max(0, state.current_column), self.library_model.columnCount() - 1
            )
            selection_model.setCurrentIndex(
                self.library_model.index(current_row, current_column),
                QItemSelectionModel.NoUpdate,
            )

        top_row = rows_by_path.get(state.top_path)
        if top_row is not None:
            self.library_table.scrollTo(
                self.library_model.index(top_row, 0),
                QAbstractItemView.PositionAtTop,
            )
            if (
                self.library_table.verticalScrollMode()
                == QAbstractItemView.ScrollPerPixel
            ):
                bar = self.library_table.verticalScrollBar()
                bar.setValue(bar.value() - state.top_offset)
        else:
            self.library_table.verticalScrollBar().setValue(state.vertical_scroll)
        self.library_table.horizontalScrollBar().setValue(state.horizontal_scroll)

    def _restore_library_report_summary(self, fallback: str) -> None:
        if self._library_report is None:
            self.library_summary.setText(fallback)
        else:
            self._refresh_library_table()

    @Slot(int, int)
    def _open_library_row(self, row: int, _column: int) -> None:
        entry = self.library_model.entry_at(row)
        if entry and entry.post_id:
            self._open_post(entry.post_id)

    def _library_row_selected(
        self, current: QModelIndex, _previous: QModelIndex
    ) -> None:
        if self._library_refreshing:
            return
        entry = self.library_model.entry_at(current.row()) if current.isValid() else None
        self._request_library_preview(entry)

    def _request_library_preview(self, entry: LibraryEntry | None) -> None:
        self._library_preview_generation += 1
        generation = self._library_preview_generation
        self._library_preview_pending = None
        if self.library_preview_worker is not None:
            self.library_preview_worker.cancel()
        self._library_preview_entry = entry
        self._library_preview_binding = (
            _LibraryPreviewBinding(
                self._library_report_root,
                self._library_report_root_identity,
                entry,
            )
            if entry is not None
            else None
        )

        self.library_preview_image.setPixmap(QPixmap())
        if entry is None:
            self.library_preview_image.setText("选择一张已验证的静态图片")
            self.library_preview_meta.setText(
                "预览只读取当前报告中已验证的 JPEG、PNG 或 WebP；不会联网。"
            )
            return

        self.library_preview_meta.setText(self._library_entry_preview_text(entry))
        extension = os.path.splitext(entry.relative_path)[1].casefold()
        if entry.status != "verified":
            self.library_preview_image.setText("此项未通过完整性验证，不能预览")
            return
        if (
            type(entry.size) is not int
            or entry.size <= 0
            or not isinstance(entry.sha256, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", entry.sha256) is None
        ):
            self.library_preview_image.setText("验证报告不完整，请重新扫描后再预览")
            return
        expected_format = {
            ".jpeg": "jpeg",
            ".jpg": "jpeg",
            ".png": "png",
            ".webp": "webp",
        }.get(extension)
        normalized_content_type = (
            entry.content_type.strip().casefold()
            if isinstance(entry.content_type, str)
            else ""
        )
        content_format = {
            "image/jpeg": "jpeg",
            "image/jpg": "jpeg",
            "image/png": "png",
            "image/webp": "webp",
        }.get(normalized_content_type)
        if expected_format is None:
            self.library_preview_image.setText("此媒体类型不提供离线图片预览")
            return
        if content_format != expected_format:
            self.library_preview_image.setText("验证报告中的图片格式不一致，请重新扫描")
            return
        if (
            not self._library_report_root
            or self._library_report_root_identity is None
        ):
            self.library_preview_image.setText("请重新扫描后再预览")
            return

        self.library_preview_image.setText("正在读取离线预览…")
        binding = self._library_preview_binding
        if binding is None:
            self.library_preview_image.setText("请重新扫描后再预览")
            return
        request = (generation, binding)
        if self.library_preview_worker is not None:
            self._library_preview_pending = request
            return
        self._start_library_preview(request)

    def _start_library_preview(
        self, request: tuple[int, _LibraryPreviewBinding]
    ) -> None:
        generation, binding = request
        output_dir = binding.report_root
        entry = binding.entry
        if generation != self._library_preview_generation:
            return
        try:
            worker = LibraryThumbnailWorker(
                output_dir,
                VerifiedThumbnailSource(
                    relative_path=entry.relative_path,
                    size=entry.size,
                    sha256=entry.sha256,
                    content_type=entry.content_type,
                    root_identity=binding.report_root_identity,
                ),
                self,
            )
        except Exception as exc:
            self.library_preview_image.setText("无法启动离线预览")
            self.library_preview_meta.setText(
                f"预览任务创建失败（{type(exc).__name__}）"
            )
            return
        self.library_preview_worker = worker
        worker.succeeded.connect(
            lambda result, owner=worker, requested=generation, expected=entry: (
                self._library_preview_succeeded(
                    owner, requested, expected, result
                )
            )
        )
        worker.failed.connect(
            lambda message, owner=worker, requested=generation: (
                self._library_preview_failed(owner, requested, message)
            )
        )
        worker.finished.connect(
            lambda owner=worker: self._library_preview_finished(owner)
        )
        worker.start()

    def _library_preview_succeeded(
        self,
        owner: object,
        generation: int,
        expected: LibraryEntry,
        result: object,
    ) -> None:
        if (
            owner is not self.library_preview_worker
            or generation != self._library_preview_generation
        ):
            return
        if (
            not isinstance(result, LibraryThumbnail)
            or result.relative_path != expected.relative_path
            or result.size != expected.size
            or result.sha256 != expected.sha256.casefold()
            or result.content_type != expected.content_type.strip().casefold()
            or result.root_identity != self._library_report_root_identity
        ):
            self._library_preview_failed(
                owner, generation, "离线预览结果格式无效"
            )
            return
        pixmap = QPixmap()
        if not pixmap.loadFromData(result.png_bytes, "PNG") or pixmap.isNull():
            self._library_preview_failed(owner, generation, "离线预览图片无效")
            return
        if pixmap.width() > 360 or pixmap.height() > 360:
            pixmap = pixmap.scaled(
                360,
                360,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        self.library_preview_image.setText("")
        self.library_preview_image.setPixmap(pixmap)
        self.library_preview_meta.setText(
            f"{self._library_entry_preview_text(expected)} · "
            f"原图 {result.width} × {result.height}"
        )

    def _library_preview_failed(
        self, owner: object, generation: int, message: str
    ) -> None:
        if (
            owner is not self.library_preview_worker
            or generation != self._library_preview_generation
        ):
            return
        self.library_preview_image.setPixmap(QPixmap())
        self.library_preview_image.setText("无法生成离线预览")
        self.library_preview_meta.setText(str(message))

    def _library_preview_finished(self, owner: object) -> None:
        delete_later = getattr(owner, "deleteLater", None)
        if callable(delete_later):
            delete_later()
        if owner is not self.library_preview_worker:
            return
        self.library_preview_worker = None
        pending = self._library_preview_pending
        self._library_preview_pending = None
        if pending is not None and pending[0] == self._library_preview_generation:
            self._start_library_preview(pending)

    def _cancel_library_preview(self, message: str) -> None:
        preview_was_active = self._library_preview_entry is not None
        self._library_preview_generation += 1
        self._library_preview_entry = None
        self._library_preview_binding = None
        self._library_preview_pending = None
        if preview_was_active and self.library_preview_worker is not None:
            self.library_preview_worker.cancel()
        if hasattr(self, "library_preview_image"):
            self.library_preview_image.setPixmap(QPixmap())
            self.library_preview_image.setText(message)
            self.library_preview_meta.setText(
                "预览只读取当前报告中已验证的 JPEG、PNG 或 WebP；不会联网。"
            )

    @staticmethod
    def _library_entry_preview_text(entry: LibraryEntry) -> str:
        values = [entry.post_id, _format_file_size(entry.size)]
        if entry.author:
            values.append(entry.author)
        if entry.tags:
            values.append(" ".join(entry.tags[:8]))
        return " · ".join(value for value in values if value)

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
        if not self._settings_state_available:
            self.remember_check.setChecked(False)
            self.login_status.setText("设置文件暂时不可用；本机会话保持原样")
            return
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
        if not self._settings_state_available:
            self.login_status.setText("设置文件暂时不可用；本次不会更改本机凭据")
            return
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
        if not self._settings_state_available:
            self.password_edit.clear()
            self.login_status.setText("设置文件暂时不可用；登录结果未载入")
            self._log("设置文件暂时不可用；已忽略登录结果，且未更改本机凭据。")
            return
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
        self.login_button.setEnabled(self._settings_state_available)
        if self.login_worker:
            self.login_worker.deleteLater()
        self.login_worker = None

    def _clear_credentials(self) -> None:
        if not self._settings_state_available:
            self.login_status.setText("设置文件暂时不可用；加密凭据保持原样")
            return
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
        if not self._settings_state_available:
            raise CredentialPersistenceError(
                "设置文件暂时不可用；本机凭据保持原样"
            )
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
        if not self._settings_state_available:
            self.status_label.setText("设置文件暂时不可用；原文件保持不变")
            return
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
        if not self._settings_state_available:
            self.status_label.setText("设置文件暂时不可用；重启前不会写入推测的下载目录")
            return
        if self.library_worker is not None:
            self.status_label.setText("请等待本地库校验结束后再开始下载")
            return
        # Keep ownership until this worker's queued ``finished`` signal has
        # been handled.  QThread.isRunning() can already be false in that
        # window; accepting a second batch would let stale cleanup erase the
        # new worker and permit overlapping downloads.
        if self.download_worker is not None:
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
            recovered = False
            try:
                self.task_store.update_many(
                    [task.post_id for task in queued], status="pending", error=""
                )
            except TaskStoreError as recovery_exc:
                self._log(
                    "下载线程创建失败，且任务状态恢复失败："
                    f"{type(recovery_exc).__name__}"
                )
            else:
                recovered = True
            self._refresh_tasks()
            detail = (
                "；任务已恢复为待处理"
                if recovered
                else "；任务状态恢复失败，请重启后重试"
            )
            QMessageBox.warning(
                self,
                "无法开始下载",
                f"下载线程创建失败（{type(exc).__name__}）{detail}",
            )
            return
        self.download_worker = worker
        self._download_task_ids = frozenset(task.post_id for task in queued)
        self._download_terminal_owner = worker
        self._download_terminal_intents = {}
        self._update_remove_tasks_action()
        worker.item_started.connect(self._download_item_started)
        worker.item_progress.connect(self._download_item_progress)
        worker.item_succeeded.connect(self._download_item_succeeded)
        worker.item_warning.connect(self._download_item_warning)
        worker.item_failed.connect(self._download_item_failed)
        worker.batch_finished.connect(self._download_batch_finished)
        worker.batch_blocked.connect(self._download_batch_blocked)
        worker.finished.connect(
            lambda owner=worker: self._download_thread_finished(owner)
        )
        self.stop_download_button.setEnabled(True)
        self._download_block_reason = ""
        self.global_progress.setRange(0, 0)
        self.global_progress.show()
        self.status_label.setText(f"开始顺序下载 {len(queued)} 项")
        self._log(f"下载批次开始：{len(queued)} 项，单并发。")
        try:
            worker.start()
        except Exception as exc:
            try:
                running = bool(worker.isRunning())
            except Exception:
                running = True
            if running:
                message = (
                    f"下载线程启动状态异常（{type(exc).__name__}）；"
                    "线程可能仍在运行，请等待或安全停止"
                )
                self.status_label.setText(message)
                self._log(message)
                QMessageBox.warning(self, "下载启动状态异常", message)
                return

            recovered = False
            try:
                self.task_store.update_many(
                    list(self._download_task_ids),
                    status="pending",
                    error="下载线程启动失败，任务已恢复为待处理",
                )
            except TaskStoreError as recovery_exc:
                self._log(
                    "下载线程启动失败，且任务状态恢复失败："
                    f"{type(recovery_exc).__name__}"
                )
            else:
                recovered = True
            self.stop_download_button.setEnabled(False)
            self.global_progress.hide()
            self.download_worker = None
            self._download_task_ids = frozenset()
            self._download_terminal_owner = None
            self._download_terminal_intents = {}
            # ``run()`` normally scrubs this secret in its finally block.  A
            # thread that never started cannot reach that cleanup path.
            if hasattr(worker, "token"):
                worker.token = ""
            delete_later = getattr(worker, "deleteLater", None)
            if callable(delete_later):
                delete_later()
            self._refresh_tasks()
            detail = (
                "；任务已恢复为待处理"
                if recovered
                else "；任务状态恢复失败，请重启后重试"
            )
            message = f"下载线程启动失败（{type(exc).__name__}）{detail}"
            self.status_label.setText(message)
            self._log(message)
            QMessageBox.warning(self, "无法开始下载", message)

    @Slot(object, str)
    def _download_item_started(self, owner: object, post_id: str) -> None:
        if owner is not self.download_worker:
            return
        try:
            self.task_store.update(post_id, status="running", error="")
        except TaskStoreError as exc:
            self._log(f"任务状态保存失败：{exc}")
        self._refresh_tasks()
        self.status_label.setText(f"正在下载 {post_id}")

    @Slot(object, str, int, int)
    def _download_item_progress(
        self, owner: object, post_id: str, current: int, total: int
    ) -> None:
        if owner is not self.download_worker:
            return
        if total > 0:
            self.global_progress.setRange(0, 100)
            self.global_progress.setValue(min(100, int(current * 100 / total)))
            self.status_label.setText(
                f"正在下载 {post_id} · {current / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MiB"
            )
        else:
            self.global_progress.setRange(0, 0)

    @Slot(object, str, object)
    def _download_item_succeeded(
        self, owner: object, post_id: str, result: object
    ) -> None:
        if (
            owner is not self.download_worker
            or owner is not self._download_terminal_owner
            or post_id not in self._download_task_ids
        ):
            return
        relative = getattr(result, "relative_path", "")
        intent = _DownloadTerminalIntent(
            status="completed",
            error="",
            output_files=(relative,) if relative else (),
        )
        self._download_terminal_intents[post_id] = intent
        try:
            self._persist_download_terminal_intent(post_id, intent)
        except TaskStoreError as exc:
            self._log(f"下载成功但任务终态保存失败：{exc}")
        else:
            if self._download_terminal_intents.get(post_id) == intent:
                del self._download_terminal_intents[post_id]
        self._refresh_tasks()
        self._log(f"作品 {post_id} 下载完成。")

    @Slot(object, str, str)
    def _download_item_warning(
        self, owner: object, post_id: str, message: str
    ) -> None:
        if owner is not self.download_worker:
            return
        safe = message[:1000]
        self._log(f"作品 {post_id} 已保存，但有附加警告：{safe}")
        self.status_label.setText(f"{post_id} 已保存；{safe}")

    @Slot(object, str, str)
    def _download_item_failed(
        self, owner: object, post_id: str, message: str
    ) -> None:
        if (
            owner is not self.download_worker
            or owner is not self._download_terminal_owner
            or post_id not in self._download_task_ids
        ):
            return
        intent = _DownloadTerminalIntent(status="failed", error=message[:1000])
        self._download_terminal_intents[post_id] = intent
        try:
            self._persist_download_terminal_intent(post_id, intent)
        except TaskStoreError as exc:
            self._log(f"任务失败状态保存失败：{exc}")
        else:
            if self._download_terminal_intents.get(post_id) == intent:
                del self._download_terminal_intents[post_id]
        self._refresh_tasks()
        self._log(f"作品 {post_id} 失败：{message}")

    def _persist_download_terminal_intent(
        self, post_id: str, intent: _DownloadTerminalIntent
    ) -> None:
        changes: dict[str, object] = {
            "status": intent.status,
            "error": intent.error,
        }
        if intent.output_files is not None:
            changes["output_files"] = intent.output_files
        self.task_store.update(post_id, **changes)

    @Slot(object, int, int, bool)
    def _download_batch_finished(
        self, owner: object, succeeded: int, failed: int, stopped: bool
    ) -> None:
        if owner is not self.download_worker:
            return
        terminal_intents = (
            self._download_terminal_intents
            if owner is self._download_terminal_owner
            else {}
        )
        for post_id, intent in list(terminal_intents.items()):
            try:
                self._persist_download_terminal_intent(post_id, intent)
            except TaskStoreError as exc:
                self._log(f"任务终态重试保存失败（{post_id}）：{exc}")
            else:
                if terminal_intents.get(post_id) == intent:
                    del terminal_intents[post_id]
        unpersisted_terminal_ids = frozenset(terminal_intents)
        remaining = [
            task.post_id
            for task in self.task_store.list()
            if task.post_id in self._download_task_ids
            and task.status in {"queued", "running"}
            and task.post_id not in unpersisted_terminal_ids
        ]
        block_reason = self._download_block_reason
        abnormal_end = bool(remaining) and not stopped
        recovery_attempted = bool(remaining)
        recovery_succeeded = False
        if remaining:
            if block_reason:
                next_status = "pending"
                reason = block_reason
            elif stopped:
                next_status = "cancelled"
                reason = "用户停止了批次"
            else:
                next_status = "pending"
                reason = "下载批次异常结束，任务已恢复为待处理"
            try:
                self.task_store.update_many(
                    remaining,
                    status=next_status,
                    error=reason,
                )
            except TaskStoreError as exc:
                self._log(f"未能原子恢复剩余任务：{exc}")
            else:
                recovery_succeeded = True
                if abnormal_end:
                    self._log("下载批次未报告停止但仍有活动任务，已恢复为待处理。")
        self._refresh_tasks()
        if recovery_attempted and not recovery_succeeded:
            terminal_suffix = "，任务状态恢复失败"
            if block_reason:
                terminal_suffix = (
                    f"；批次已阻断：{block_reason}；任务状态恢复失败"
                )
        elif block_reason:
            terminal_suffix = f"；批次已阻断：{block_reason}"
            if recovery_succeeded:
                terminal_suffix += "；剩余任务已恢复为待处理"
        elif stopped:
            terminal_suffix = "，已停止"
        elif abnormal_end:
            terminal_suffix = "，异常任务已恢复"
        else:
            terminal_suffix = ""
        if unpersisted_terminal_ids:
            terminal_suffix += (
                f"；任务终态未能确认保存 {len(unpersisted_terminal_ids)} 项，"
                "重启后请核对任务状态"
            )
        summary_kind = "媒体" if unpersisted_terminal_ids else ""
        self.status_label.setText(
            f"批次结束：{summary_kind}成功 {succeeded}，失败 {failed}"
            + terminal_suffix
        )
        self._log(
            f"下载批次结束：成功 {succeeded}，失败 {failed}，停止={str(stopped).lower()}。"
        )
        if unpersisted_terminal_ids:
            self._log(
                f"下载批次有 {len(unpersisted_terminal_ids)} 项终态未能持久化；"
                "这些任务未被批次兜底状态覆盖。"
            )

    @Slot(object, str)
    def _download_batch_blocked(self, owner: object, message: str) -> None:
        if owner is not self.download_worker:
            return
        self._download_block_reason = (message or "下载批次被阻断")[:1000]
        self.status_label.setText(self._download_block_reason)
        self._log(f"下载批次已阻断：{self._download_block_reason}")

    @Slot(object)
    def _download_thread_finished(self, owner: object) -> None:
        # A queued signal must never clear a newer operation.  The non-None
        # start guard above normally prevents this state; the identity check
        # remains a defensive invariant for late/re-entrant delivery.
        if owner is not self.download_worker:
            delete_later = getattr(owner, "deleteLater", None)
            if callable(delete_later):
                delete_later()
            return
        self.stop_download_button.setEnabled(False)
        self.global_progress.hide()
        delete_later = getattr(owner, "deleteLater", None)
        if callable(delete_later):
            delete_later()
        self.download_worker = None
        self._download_task_ids = frozenset()
        if owner is self._download_terminal_owner:
            self._download_terminal_owner = None
            self._download_terminal_intents = {}
        self._update_remove_tasks_action()

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
        preview_worker = self.library_preview_worker
        self._cancel_library_preview("正在关闭离线预览…")
        workers = [
            self.search_worker,
            self.login_worker,
            self.download_worker,
            self.library_worker,
            self.library_preview_worker,
        ]
        for worker in workers:
            if (
                worker
                and worker is not preview_worker
                and worker.isRunning()
                and hasattr(worker, "cancel")
            ):
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
            self.status_label.setText("正在等待后台任务安全结束，请稍后再关闭")
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
            except SettingsConflictError:
                QMessageBox.warning(
                    self,
                    "窗口状态未保存",
                    "设置已被外部程序更新；外部文件保持不变，请重新启动后再修改设置。",
                )
            except (SettingsError, UnicodeDecodeError):
                pass
        event.accept()


__all__ = ["MAIN_TAB_TITLES", "MainWindow"]
