# -*- coding: utf-8 -*-
"""Policy-bound Sankaku browser tab with an optional QtWebEngine backend."""

from __future__ import annotations

import os
from typing import Any

from PySide6.QtCore import Qt, QUrl, Signal, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sankaku_url_policy import (
    canonical_post_url,
    is_allowed_browser_resource_url,
    normalize_page_url,
    normalize_tag_query,
    post_id_from_url,
    tag_search_url,
)


HOME_URL = "https://chan.sankakucomplex.com/cn/"
MAX_COLLECTED_POSTS = 100
_MAX_RAW_DOM_CANDIDATES = 400

try:
    if os.environ.get("SANKAKU_DISABLE_WEBENGINE") == "1":
        raise ImportError("Qt WebEngine disabled for offline smoke testing")
    from PySide6.QtWebEngineCore import (
        QWebEnginePage,
        QWebEngineProfile,
        QWebEngineSettings,
        QWebEngineUrlRequestInterceptor,
    )
    from PySide6.QtWebEngineWidgets import QWebEngineView
except (ImportError, OSError) as exc:  # QtWebEngine is an optional UI feature.
    QWebEnginePage = None  # type: ignore[assignment,misc]
    QWebEngineProfile = None  # type: ignore[assignment,misc]
    QWebEngineSettings = None  # type: ignore[assignment,misc]
    QWebEngineUrlRequestInterceptor = None  # type: ignore[assignment,misc]
    QWebEngineView = None  # type: ignore[assignment,misc]
    WEBENGINE_AVAILABLE = False
    WEBENGINE_IMPORT_ERROR = str(exc)
else:
    WEBENGINE_AVAILABLE = True
    WEBENGINE_IMPORT_ERROR = ""


_COLLECT_VISIBLE_POSTS_SCRIPT = rf"""
(() => {{
    const result = [];
    const seen = new Set();
    const anchors = document.querySelectorAll('a[href]');

    for (const anchor of anchors) {{
        if (result.length >= {_MAX_RAW_DOM_CANDIDATES}) break;
        if (anchor.closest('[hidden], [aria-hidden="true"]')) continue;

        const style = window.getComputedStyle(anchor);
        if (style.display === 'none' || style.visibility === 'hidden' ||
            Number.parseFloat(style.opacity || '1') <= 0) continue;

        const rect = anchor.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0 || anchor.getClientRects().length === 0) continue;

        let parsed;
        try {{
            parsed = new URL(anchor.href, document.baseURI);
        }} catch (_error) {{
            continue;
        }}
        if (!/(?:^|\/)(?:posts?|post\/show)\/[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}(?:\/|$)/i.test(parsed.pathname)) {{
            continue;
        }}

        const value = parsed.href;
        if (!seen.has(value)) {{
            seen.add(value);
            result.push(value);
        }}
    }}
    return result;
}})();
"""


def _block_untrusted_resource_request(info: Any) -> bool:
    """Apply the pure URL policy to one WebEngine request.

    Returning a bool keeps the branch independently testable without starting
    Chromium.  A malformed request is blocked closed.
    """
    try:
        allowed = is_allowed_browser_resource_url(info.requestUrl())
    except (AttributeError, RuntimeError, TypeError, ValueError):
        allowed = False
    if not allowed:
        try:
            info.block(True)
        except (AttributeError, RuntimeError, TypeError):
            pass
    return allowed


def _deny_request_object(request: Any) -> bool:
    """Reject one version-dependent WebEngine permission request object."""
    for method_name in (
        "deny",
        "reject",
        "cancel",
        "selectNone",
        "rejectCertificate",
    ):
        method = getattr(request, method_name, None)
        if callable(method):
            try:
                method()
            except (RuntimeError, TypeError):
                continue
            return True
    return False


def _harden_webengine_settings(settings: Any) -> None:
    """Disable browser capabilities which this read-only tab never needs."""
    if QWebEngineSettings is None:
        return
    policy = {
        "JavascriptCanOpenWindows": False,
        "JavascriptCanAccessClipboard": False,
        "JavascriptCanPaste": False,
        "LocalContentCanAccessRemoteUrls": False,
        "LocalContentCanAccessFileUrls": False,
        "HyperlinkAuditingEnabled": False,
        "PluginsEnabled": False,
        "FullScreenSupportEnabled": False,
        "ScreenCaptureEnabled": False,
        "PdfViewerEnabled": False,
        "AllowRunningInsecureContent": False,
        "AllowGeolocationOnInsecureOrigins": False,
        "AllowWindowActivationFromJavaScript": False,
        "PlaybackRequiresUserGesture": True,
        "WebRTCPublicInterfacesOnly": True,
        "DnsPrefetchEnabled": False,
        "NavigateOnDropEnabled": False,
    }
    for name, enabled in policy.items():
        attribute = getattr(QWebEngineSettings.WebAttribute, name, None)
        if attribute is not None:
            settings.setAttribute(attribute, enabled)


if WEBENGINE_AVAILABLE:

    class _PolicyRequestInterceptor(  # type: ignore[misc,valid-type]
        QWebEngineUrlRequestInterceptor
    ):
        """Block outbound resources outside exact Sankaku page/CDN hosts."""

        def interceptRequest(self, info):  # noqa: N802 - Qt API
            _block_untrusted_resource_request(info)

    class _PolicyWebPage(QWebEnginePage):  # type: ignore[misc,valid-type]
        """A page which rejects every navigation outside the pure URL policy."""

        navigation_blocked = Signal()
        new_window_blocked = Signal()
        permission_blocked = Signal()

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.featurePermissionRequested.connect(self._deny_feature_permission)
            self.fileSystemAccessRequested.connect(self._deny_object_permission)
            self.desktopMediaRequested.connect(self._deny_object_permission)
            self.fullScreenRequested.connect(self._deny_object_permission)
            self.quotaRequested.connect(self._deny_object_permission)
            self.registerProtocolHandlerRequested.connect(self._deny_object_permission)
            self.webAuthUxRequested.connect(self._deny_object_permission)
            self.selectClientCertificate.connect(self._deny_object_permission)
            self.certificateError.connect(self._deny_object_permission)

            # Qt 6.8+ exposes a unified permission object in addition to the
            # feature-specific Qt 6.7 signal used above.
            permission_requested = getattr(self, "permissionRequested", None)
            if permission_requested is not None:
                permission_requested.connect(self._deny_object_permission)

        def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
            del navigation_type, is_main_frame
            if normalize_page_url(url, keep_fragment=True) is None:
                self.navigation_blocked.emit()
                return False
            return True

        def createWindow(self, window_type):
            del window_type
            self.new_window_blocked.emit()
            return None

        def chooseFiles(self, mode, old_files, accepted_mime_types):  # noqa: N802 - Qt API
            del mode, old_files, accepted_mime_types
            self.permission_blocked.emit()
            return []

        def _deny_feature_permission(self, origin, feature) -> None:
            self.setFeaturePermission(
                origin,
                feature,
                QWebEnginePage.PermissionPolicy.PermissionDeniedByUser,
            )
            self.permission_blocked.emit()

        def _deny_object_permission(self, request) -> None:
            _deny_request_object(request)
            self.permission_blocked.emit()


class BrowserTab(QWidget):
    """A small embedded browser constrained to approved Sankaku HTTPS pages.

    The two integration signals always carry Python-validated canonical post
    URLs.  JavaScript is used only to observe the already-rendered DOM; its
    result is treated as untrusted input and validated again in Python.
    """

    add_current_requested = Signal(str)
    collect_visible_requested = Signal(list)
    tag_search_requested = Signal(str)
    current_url_changed = Signal(str)
    status_message = Signal(str)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        home_url: str = HOME_URL,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("browserTab")
        self._home_url = normalize_page_url(home_url, keep_fragment=True) or HOME_URL
        self._collect_generation = 0
        self.profile: Any | None = None
        self.page: Any | None = None
        self.web_view: Any | None = None
        self.browser: Any | None = None
        self._request_interceptor: Any | None = None
        self._loaded_once = False

        self._build_controls()
        if WEBENGINE_AVAILABLE:
            self._build_webengine()
            self.address_edit.setText(self._home_url)
            self._set_status("站内浏览尚未联网；打开本页签后再载入主页。")
        else:
            self._build_placeholder()

    @property
    def webengine_available(self) -> bool:
        return WEBENGINE_AVAILABLE

    def _build_controls(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self._outer_layout = outer

        toolbar = QFrame(self)
        toolbar.setObjectName("browserToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 8, 10, 8)
        toolbar_layout.setSpacing(6)

        self.back_button = self._tool_button("←", "后退")
        self.forward_button = self._tool_button("→", "前进")
        self.refresh_button = self._tool_button("↻", "刷新")
        self.home_button = self._tool_button("⌂", "主页")
        self.back_button.setEnabled(False)
        self.forward_button.setEnabled(False)

        self.address_edit = QLineEdit(toolbar)
        self.address_edit.setClearButtonEnabled(True)
        self.address_edit.setPlaceholderText("输入允许的 Sankaku HTTPS 页面地址")
        self.address_edit.setAccessibleName("浏览地址")
        self.address_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.go_button = QPushButton("打开", toolbar)
        self.go_button.setToolTip("打开地址栏中的页面")

        toolbar_layout.addWidget(self.back_button)
        toolbar_layout.addWidget(self.forward_button)
        toolbar_layout.addWidget(self.refresh_button)
        toolbar_layout.addWidget(self.home_button)
        toolbar_layout.addWidget(self.address_edit, 1)
        toolbar_layout.addWidget(self.go_button)
        outer.addWidget(toolbar)

        action_bar = QFrame(self)
        action_layout = QHBoxLayout(action_bar)
        action_layout.setContentsMargins(10, 7, 10, 7)
        action_layout.setSpacing(7)

        self.tag_edit = QLineEdit(action_bar)
        self.tag_edit.setClearButtonEnabled(True)
        self.tag_edit.setPlaceholderText("标签搜索，例如：rating:safe landscape")
        self.tag_edit.setAccessibleName("标签搜索")
        self.tag_search_button = QPushButton("搜索标签", action_bar)
        self.tag_search_button.setProperty("role", "primary")
        self.add_current_button = QPushButton("加入当前作品", action_bar)
        self.collect_visible_button = QPushButton("收集已呈现作品", action_bar)
        self.collect_visible_button.setToolTip("从当前页面收集最多 100 个已呈现的作品链接")

        action_layout.addWidget(self.tag_edit, 1)
        action_layout.addWidget(self.tag_search_button)
        action_layout.addSpacing(8)
        action_layout.addWidget(self.add_current_button)
        action_layout.addWidget(self.collect_visible_button)
        outer.addWidget(action_bar)

        self.status_label = QLabel("", self)
        self.status_label.setObjectName("browserStatus")
        self.status_label.setProperty("muted", True)
        self.status_label.setWordWrap(True)
        self.status_label.setContentsMargins(12, 5, 12, 7)
        outer.addWidget(self.status_label)

        self.address_edit.returnPressed.connect(self._open_address)
        self.go_button.clicked.connect(self._open_address)
        self.tag_edit.returnPressed.connect(self.search_tags)
        self.tag_search_button.clicked.connect(self.search_tags)
        self.home_button.clicked.connect(self.go_home)
        self.add_current_button.clicked.connect(self.request_add_current)
        self.collect_visible_button.clicked.connect(self.collect_visible_posts)

    @staticmethod
    def _tool_button(text: str, tooltip: str) -> QToolButton:
        button = QToolButton()
        button.setText(text)
        button.setToolTip(tooltip)
        button.setAccessibleName(tooltip)
        return button

    def _build_webengine(self) -> None:
        assert QWebEngineProfile is not None
        assert QWebEngineView is not None

        # A profile without a storage name is off-the-record: cookies and the
        # HTTP cache are not intentionally persisted by this browser tab.
        self.profile = QWebEngineProfile(self)
        self._request_interceptor = _PolicyRequestInterceptor(self.profile)
        self.profile.setUrlRequestInterceptor(self._request_interceptor)
        self.web_view = QWebEngineView(self)
        self.browser = self.web_view
        self.page = _PolicyWebPage(self.profile, self.web_view)
        _harden_webengine_settings(self.page.settings())
        self.web_view.setPage(self.page)
        self._outer_layout.addWidget(self.web_view, 1)

        self.page.navigation_blocked.connect(
            lambda: self._set_status("已阻止非官方、非 HTTPS 或含敏感参数的导航。", error=True)
        )
        self.page.new_window_blocked.connect(
            lambda: self._set_status("已阻止网页打开新窗口。", error=True)
        )
        self.page.permission_blocked.connect(
            lambda: self._set_status("已拒绝网页请求设备、文件或身份权限。", error=True)
        )
        self.profile.downloadRequested.connect(self._reject_download)
        self.web_view.urlChanged.connect(self._url_changed)
        self.web_view.loadStarted.connect(
            lambda: self._set_status("正在载入页面…")
        )
        self.web_view.loadProgress.connect(self._load_progress)
        self.web_view.loadFinished.connect(self._load_finished)
        self.back_button.clicked.connect(self.web_view.back)
        self.forward_button.clicked.connect(self.web_view.forward)
        self.refresh_button.clicked.connect(self.web_view.reload)

    def _build_placeholder(self) -> None:
        placeholder = QFrame(self)
        placeholder.setObjectName("browserPlaceholder")
        placeholder_layout = QVBoxLayout(placeholder)
        placeholder_layout.setContentsMargins(42, 42, 42, 42)
        placeholder_layout.addStretch()

        title = QLabel("内嵌浏览器不可用", placeholder)
        title.setProperty("placeholderTitle", True)
        title.setAlignment(Qt.AlignCenter)
        detail = QLabel(
            "当前 Python 环境没有可用的 PySide6 QtWebEngine。\n"
            "下载、任务和设置等其余功能仍可正常使用；安装与 PySide6 "
            "版本匹配的 PySide6-Addons 后重新启动即可启用浏览页。",
            placeholder,
        )
        detail.setAlignment(Qt.AlignCenter)
        detail.setWordWrap(True)
        detail.setProperty("muted", True)
        placeholder_layout.addWidget(title)
        placeholder_layout.addSpacing(8)
        placeholder_layout.addWidget(detail)
        placeholder_layout.addStretch()
        self._outer_layout.addWidget(placeholder, 1)

        self.address_edit.setText(self._home_url)
        for button in (
            self.back_button,
            self.forward_button,
            self.refresh_button,
            self.home_button,
            self.add_current_button,
            self.collect_visible_button,
        ):
            button.setEnabled(False)
        self._set_status("QtWebEngine 缺失，已使用安全占位页。", error=True)

    @Slot()
    def _open_address(self) -> None:
        self.open_url(self.address_edit.text())

    def open_url(self, url: str) -> bool:
        """Open one policy-approved URL and return whether loading was queued."""
        normalized = normalize_page_url(url, keep_fragment=True)
        if normalized is None:
            self._set_status("地址被拒绝：仅允许策略认可的 Sankaku HTTPS 页面。", error=True)
            return False
        self.address_edit.setText(normalized)
        if not WEBENGINE_AVAILABLE or self.web_view is None:
            self._set_status("无法打开页面：当前环境缺少 QtWebEngine。", error=True)
            return False
        self._loaded_once = True
        self.web_view.setUrl(QUrl(normalized))
        return True

    def ensure_loaded(self) -> bool:
        """Load the home page once, only after the user selects this tab."""
        if self._loaded_once:
            return True
        return self.open_url(self._home_url)

    @Slot()
    def go_home(self) -> None:
        self.open_url(self._home_url)

    @Slot()
    def search_tags(self) -> None:
        query = normalize_tag_query(self.tag_edit.text())
        if not query:
            self._set_status("请输入有效的标签搜索表达式。", error=True)
            return
        target = tag_search_url(query, locale="cn")
        if target is None:
            self._set_status("标签表达式超出安全限制。", error=True)
            return
        self.tag_search_requested.emit(query)
        self.open_url(target)

    @Slot()
    def request_add_current(self) -> None:
        current = self.current_url()
        canonical = canonical_post_url(current, locale="cn") if current else None
        if canonical is None:
            self._set_status("当前页面不是可识别的作品详情页。", error=True)
            return
        self.add_current_requested.emit(canonical)
        self._set_status("已提交当前作品。")

    @Slot()
    def collect_visible_posts(self) -> None:
        if not WEBENGINE_AVAILABLE or self.page is None:
            self._set_status("无法收集：当前环境缺少 QtWebEngine。", error=True)
            return
        source_url = self.current_url()
        if not source_url:
            self._set_status("当前页面不在允许的浏览范围内。", error=True)
            return

        self._collect_generation += 1
        generation = self._collect_generation
        self.collect_visible_button.setEnabled(False)
        self._set_status("正在检查当前页面已呈现的作品…")

        def completed(raw_result: Any) -> None:
            if generation != self._collect_generation:
                return
            self.collect_visible_button.setEnabled(True)
            # Do not accept a callback from a page which navigated away while
            # the JavaScript request was in flight.
            if self.current_url() != source_url:
                self._set_status("页面已变化，已丢弃过期的收集结果。", error=True)
                return
            posts = self._validate_collected_posts(raw_result)
            self.collect_visible_requested.emit(posts)
            if posts:
                self._set_status(f"已提交 {len(posts)} 个已呈现作品（上限 {MAX_COLLECTED_POSTS}）。")
            else:
                self._set_status("当前页面没有找到可验证的已呈现作品。")

        try:
            self.page.runJavaScript(_COLLECT_VISIBLE_POSTS_SCRIPT, completed)
        except RuntimeError:
            self.collect_visible_button.setEnabled(True)
            self._set_status("浏览页已关闭，无法收集作品。", error=True)

    @staticmethod
    def _validate_collected_posts(raw_result: Any) -> list[str]:
        if not isinstance(raw_result, list):
            return []
        result: list[str] = []
        seen: set[str] = set()
        for raw_url in raw_result[:_MAX_RAW_DOM_CANDIDATES]:
            if not isinstance(raw_url, str):
                continue
            normalized = normalize_page_url(raw_url)
            if normalized is None or post_id_from_url(normalized) is None:
                continue
            canonical = canonical_post_url(normalized, locale="cn")
            if canonical is None or canonical in seen:
                continue
            seen.add(canonical)
            result.append(canonical)
            if len(result) >= MAX_COLLECTED_POSTS:
                break
        return result

    def current_url(self) -> str:
        if WEBENGINE_AVAILABLE and self.web_view is not None:
            return normalize_page_url(self.web_view.url(), keep_fragment=True) or ""
        return normalize_page_url(self.address_edit.text(), keep_fragment=True) or ""

    @Slot(object)
    def _reject_download(self, download: Any) -> None:
        try:
            download.cancel()
        except RuntimeError:
            pass
        self._set_status("已阻止网页直接下载；请使用受控任务功能。", error=True)

    @Slot(QUrl)
    def _url_changed(self, url: QUrl) -> None:
        normalized = normalize_page_url(url, keep_fragment=True)
        if normalized is None:
            if self.web_view is not None:
                self.web_view.stop()
            self._set_status("检测到不允许的页面，载入已停止。", error=True)
            return
        self.address_edit.setText(normalized)
        self.current_url_changed.emit(normalized)
        self._update_history_buttons()

    @Slot(int)
    def _load_progress(self, value: int) -> None:
        self._set_status(f"正在载入页面… {max(0, min(100, int(value)))}%")

    @Slot(bool)
    def _load_finished(self, succeeded: bool) -> None:
        self._update_history_buttons()
        if succeeded:
            self._set_status("页面已载入。")
        else:
            self._set_status("页面载入失败或被安全策略阻止。", error=True)

    def _update_history_buttons(self) -> None:
        if self.web_view is None:
            self.back_button.setEnabled(False)
            self.forward_button.setEnabled(False)
            return
        try:
            history = self.web_view.history()
            self.back_button.setEnabled(history.canGoBack())
            self.forward_button.setEnabled(history.canGoForward())
        except RuntimeError:
            self.back_button.setEnabled(False)
            self.forward_button.setEnabled(False)

    def _set_status(self, message: str, *, error: bool = False) -> None:
        self.status_label.setText(message)
        self.status_label.setProperty("status", "error" if error else "normal")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.status_message.emit(message)


SankakuBrowserTab = BrowserTab


__all__ = [
    "BrowserTab",
    "HOME_URL",
    "MAX_COLLECTED_POSTS",
    "SankakuBrowserTab",
    "WEBENGINE_AVAILABLE",
    "WEBENGINE_IMPORT_ERROR",
]
