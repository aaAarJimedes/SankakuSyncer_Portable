# -*- coding: utf-8 -*-
"""Qt worker adapters for network and download operations."""

from __future__ import annotations

from email.utils import parsedate_to_datetime
import threading
import time
from urllib.parse import urljoin

from PySide6.QtCore import QObject, QRunnable, QThread, Signal, Slot

from credential_vault import Credentials
from download_engine import DownloadError, MediaDownloader
from http_transport import Session
from request_gate import GateCancelled, MEDIA_REQUEST_GATE
from sankaku_api import (
    AuthenticationError,
    CancelledError,
    RateLimitError,
    SankakuAPI,
    SankakuAPIError,
    SearchPage,
)
from sankaku_url_policy import normalize_media_url
from task_store import DownloadTask
from version import HTTP_USER_AGENT


def _api_from_settings(settings: dict, token: str, stop_event: threading.Event) -> SankakuAPI:
    return SankakuAPI(
        access_token=token,
        request_delay=float(settings.get("request_delay", 3.0)),
        timeout=int(settings.get("request_timeout", 30)),
        max_retries=int(settings.get("max_retries", 4)),
        proxy=str(settings.get("proxy", "")),
        stop_event=stop_event,
    )


class _LiveNetworkResources:
    """Own cancellable network objects and close each of them exactly once."""

    def __init__(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event
        self._lock = threading.Lock()
        self._resources: dict[int, object] = {}

    @staticmethod
    def _close(resource: object) -> None:
        clear_token = getattr(resource, "set_access_token", None)
        if callable(clear_token):
            try:
                clear_token("")
            except Exception:
                pass
        try:
            close = getattr(resource, "close")
            close()
        except Exception:
            # Cancellation/cleanup must continue even if one adapter reports a
            # close error.  Transport Session.close itself is non-throwing.
            pass

    def add(self, resource: object) -> bool:
        with self._lock:
            if not self._stop_event.is_set():
                self._resources[id(resource)] = resource
                return True
        self._close(resource)
        return False

    def close(self, resource: object | None) -> None:
        if resource is None:
            return
        with self._lock:
            owned = self._resources.pop(id(resource), None)
        if owned is not None:
            self._close(owned)

    def cancel(self) -> None:
        self._stop_event.set()
        with self._lock:
            resources = list(self._resources.values())
            self._resources.clear()
        for resource in resources:
            self._close(resource)


class SearchWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        settings: dict,
        token: str,
        tags: str,
        rating: str,
        cursor: str,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = dict(settings)
        self.token = token
        self.tags = tags
        self.rating = rating
        self.cursor = cursor
        self.stop_event = threading.Event()
        self._network = _LiveNetworkResources(self.stop_event)

    def cancel(self) -> None:
        self._network.cancel()

    def run(self) -> None:
        api = None
        try:
            api = _api_from_settings(self.settings, self.token, self.stop_event)
            if not self._network.add(api):
                raise CancelledError("搜索已取消")
            result = api.search_posts(
                self.tags,
                rating=self.rating,
                cursor=self.cursor,
                limit=int(self.settings.get("page_size", 24)),
            )
            self.succeeded.emit(result)
        except SankakuAPIError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"搜索发生内部错误（{type(exc).__name__}）")
        finally:
            self._network.close(api)
            self.token = ""


class LoginWorker(QThread):
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        settings: dict,
        credentials: Credentials,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = dict(settings)
        self.credentials = credentials
        self.stop_event = threading.Event()
        self._network = _LiveNetworkResources(self.stop_event)

    def cancel(self) -> None:
        self._network.cancel()

    def run(self) -> None:
        api = None
        try:
            api = _api_from_settings(self.settings, "", self.stop_event)
            if not self._network.add(api):
                raise CancelledError("登录已取消")
            token = api.authenticate(self.credentials.username, self.credentials.password)
            self.succeeded.emit(token)
        except SankakuAPIError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"登录发生内部错误（{type(exc).__name__}）")
        finally:
            self._network.close(api)
            self.credentials = None  # type: ignore[assignment]


class ThumbnailSignals(QObject):
    succeeded = Signal(int, str, bytes)
    failed = Signal(int, str)


class ThumbnailWorker(QRunnable):
    """Fetch a bounded preview with no credentials or ambient proxies."""

    MAX_BYTES = 20 * 1024 * 1024

    def __init__(self, generation: int, post_id: str, url: str) -> None:
        super().__init__()
        self.generation = generation
        self.post_id = post_id
        self.url = url
        self.stop_event = threading.Event()
        self._network = _LiveNetworkResources(self.stop_event)
        self.signals = ThumbnailSignals()
        self.setAutoDelete(True)

    def cancel(self) -> None:
        self._network.cancel()

    @Slot()
    def run(self) -> None:
        session = None
        try:
            normalized = normalize_media_url(self.url)
            if normalized is None:
                raise ValueError("untrusted thumbnail URL")
            session = Session()
            session.trust_env = False
            if not self._network.add(session):
                raise GateCancelled("thumbnail cancelled")
            current = normalized
            with MEDIA_REQUEST_GATE.slot(self.stop_event, min_interval=0.5):
                for _ in range(4):
                    if self.stop_event.is_set():
                        raise GateCancelled("thumbnail cancelled")
                    response = session.get(
                        current,
                        timeout=(10, 30),
                        stream=True,
                        allow_redirects=False,
                        headers={
                            "Accept-Encoding": "identity",
                            "User-Agent": HTTP_USER_AGENT,
                        },
                    )
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location", "")
                        response.close()
                        normalized_redirect = normalize_media_url(urljoin(current, location))
                        if normalized_redirect is None:
                            raise ValueError("untrusted redirect")
                        current = normalized_redirect
                        continue
                    if response.status_code == 429:
                        wait_seconds = _thumbnail_retry_after_seconds(response.headers)
                        MEDIA_REQUEST_GATE.defer(wait_seconds)
                        response.close()
                        raise ValueError("thumbnail rate limited")
                    if response.status_code != 200:
                        response.close()
                        raise ValueError("thumbnail request failed")
                    content_encoding = response.headers.get("Content-Encoding", "")
                    if (
                        not isinstance(content_encoding, str)
                        or content_encoding.strip().casefold() not in {"", "identity"}
                    ):
                        response.close()
                        raise ValueError("thumbnail compression is not allowed")
                    content_type = response.headers.get("Content-Type", "")
                    if not _thumbnail_content_type_allowed(content_type):
                        response.close()
                        raise ValueError("thumbnail type is not allowed")
                    declared = response.headers.get("Content-Length", "")
                    if declared.isdigit() and int(declared) > self.MAX_BYTES:
                        response.close()
                        raise ValueError("thumbnail is too large")
                    data = bytearray()
                    try:
                        for chunk in response.iter_content(128 * 1024):
                            if self.stop_event.is_set():
                                raise GateCancelled("thumbnail cancelled")
                            if chunk:
                                data.extend(chunk)
                                if len(data) > self.MAX_BYTES:
                                    raise ValueError("thumbnail is too large")
                    finally:
                        response.close()
                    if self.stop_event.is_set():
                        raise GateCancelled("thumbnail cancelled")
                    payload = bytes(data)
                    if not _thumbnail_payload_allowed(content_type, payload):
                        raise ValueError("thumbnail signature is not allowed")
                    self.signals.succeeded.emit(self.generation, self.post_id, payload)
                    return
            raise ValueError("too many redirects")
        except Exception:
            self.signals.failed.emit(self.generation, self.post_id)
        finally:
            self.url = ""
            self._network.close(session)


_THUMBNAIL_CONTENT_TYPES = frozenset(
    {
        "image/gif",
        "image/jpeg",
        "image/jpg",
        "image/pjpeg",
        "image/png",
        "image/webp",
    }
)


def _thumbnail_content_type_allowed(value: object) -> bool:
    media_type = str(value or "").partition(";")[0].strip().lower()
    return media_type in _THUMBNAIL_CONTENT_TYPES


def _thumbnail_payload_allowed(content_type: object, payload: bytes) -> bool:
    """Accept only bounded raster formats with an unambiguous file signature.

    Qt image plugins parse attacker-controlled bytes.  Keeping SVG/XML and
    uncommon image formats out of the preview path reduces that attack surface
    even when a server lies about Content-Type.
    """

    media_type = str(content_type or "").partition(";")[0].strip().lower()
    if media_type in {"image/jpeg", "image/jpg", "image/pjpeg"}:
        return payload.startswith(b"\xff\xd8\xff")
    if media_type == "image/png":
        return payload.startswith(b"\x89PNG\r\n\x1a\n")
    if media_type == "image/gif":
        return payload.startswith((b"GIF87a", b"GIF89a"))
    if media_type == "image/webp":
        return (
            len(payload) >= 12
            and payload.startswith(b"RIFF")
            and payload[8:12] == b"WEBP"
        )
    return False


def _thumbnail_retry_after_seconds(headers: object) -> float:
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return 600.0
    value = getter("Retry-After")
    if value:
        try:
            return max(0.0, min(float(value), 86_400.0))
        except (TypeError, ValueError):
            try:
                target = parsedate_to_datetime(str(value)).timestamp()
                return max(0.0, min(target - time.time(), 86_400.0))
            except (TypeError, ValueError, OverflowError):
                pass
    reset = getter("X-RateLimit-Reset")
    if reset:
        try:
            return max(0.0, min(float(reset) - time.time(), 86_400.0))
        except (TypeError, ValueError):
            pass
    return 600.0


class DownloadWorker(QThread):
    item_started = Signal(str)
    item_progress = Signal(str, int, int)
    item_succeeded = Signal(str, object)
    item_warning = Signal(str, str)
    item_failed = Signal(str, str)
    batch_finished = Signal(int, int, bool)
    batch_blocked = Signal(str)

    def __init__(
        self,
        settings: dict,
        token: str,
        tasks: list[DownloadTask],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.settings = dict(settings)
        self.token = token
        self.tasks = list(tasks)
        self.stop_event = threading.Event()
        self._network = _LiveNetworkResources(self.stop_event)

    def cancel(self) -> None:
        self._network.cancel()

    def run(self) -> None:
        succeeded = 0
        failed = 0
        api = None
        downloader = None
        try:
            api = _api_from_settings(self.settings, self.token, self.stop_event)
            if not self._network.add(api):
                raise CancelledError("下载已取消")
            downloader = MediaDownloader(
                api,
                str(self.settings.get("download_dir", "")),
                timeout=int(self.settings.get("request_timeout", 30)) * 2,
                max_retries=min(3, int(self.settings.get("max_retries", 4))),
                prefer_original=bool(self.settings.get("prefer_original", True)),
                save_metadata=bool(self.settings.get("save_metadata", True)),
                stop_event=self.stop_event,
            )
            if not self._network.add(downloader):
                raise CancelledError("下载已取消")
            for task in self.tasks:
                if self.stop_event.is_set():
                    break
                self.item_started.emit(task.post_id)
                try:
                    result = downloader.download(
                        task.post_id,
                        progress=lambda current, total, post_id=task.post_id: self.item_progress.emit(
                            post_id, current, total
                        ),
                    )
                    succeeded += 1
                    self.item_succeeded.emit(task.post_id, result)
                    if result.metadata_warning:
                        self.item_warning.emit(task.post_id, result.metadata_warning)
                except Exception as exc:
                    if self.stop_event.is_set():
                        break
                    failed += 1
                    if isinstance(exc, (DownloadError, SankakuAPIError, CancelledError)):
                        message = str(exc)
                    else:
                        message = f"下载发生内部错误（{type(exc).__name__}）"
                    self.item_failed.emit(task.post_id, message)
                    if isinstance(exc, (AuthenticationError, RateLimitError)):
                        self.batch_blocked.emit(message or "站点要求停止当前批次")
                        self.stop_event.set()
                        break
        except Exception as exc:
            if not self.stop_event.is_set():
                if isinstance(exc, (DownloadError, SankakuAPIError, CancelledError)):
                    message = str(exc)
                else:
                    message = f"下载初始化发生内部错误（{type(exc).__name__}）"
                self.batch_blocked.emit(message)
        finally:
            self._network.close(downloader)
            self._network.close(api)
            self.token = ""
            self.batch_finished.emit(succeeded, failed, self.stop_event.is_set())


__all__ = [
    "DownloadWorker",
    "LoginWorker",
    "SearchWorker",
    "ThumbnailWorker",
]
