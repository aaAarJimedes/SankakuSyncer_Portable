# -*- coding: utf-8 -*-
"""Qt workers for native network, download, and bounded local operations."""

from __future__ import annotations

import os
import threading
from urllib.parse import urljoin

from PySide6.QtCore import QObject, QRunnable, QThread, Signal, Slot

from credential_vault import Credentials
from download_engine import DownloadError, MediaDownloader
from http_transport import (
    ContentLengthError,
    ContentLengthLimitError,
    Session,
    parse_content_length,
)
from image_metadata_policy import (
    BOUNDARY_PREFIX_BYTES,
    BOUNDARY_SUFFIX_BYTES,
    ImageMetadataPolicyError,
    validate_minimum_image_container,
)
from library_thumbnail import (
    LibraryThumbnailError,
    VerifiedThumbnailSource,
    load_library_thumbnail,
)
from local_library import LibraryScanError, scan_download_library
from request_gate import GateCancelled, MEDIA_REQUEST_GATE, retry_after_seconds
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
    cancelled = Signal()

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
            if self.stop_event.is_set():
                raise CancelledError("搜索已取消")
            self.succeeded.emit(result)
        except CancelledError:
            self.cancelled.emit()
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
                        wait_seconds = retry_after_seconds(response.headers)
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
                    try:
                        declared_length = parse_content_length(
                            response.headers.get("Content-Length"),
                            self.MAX_BYTES,
                        )
                    except ContentLengthLimitError:
                        response.close()
                        raise ValueError("thumbnail is too large")
                    except ContentLengthError:
                        response.close()
                        raise ValueError("thumbnail length is invalid")
                    data = bytearray()
                    try:
                        for chunk in response.iter_content(128 * 1024):
                            if self.stop_event.is_set():
                                raise GateCancelled("thumbnail cancelled")
                            if chunk:
                                data.extend(chunk)
                                if len(data) > self.MAX_BYTES:
                                    raise ValueError("thumbnail is too large")
                                if (
                                    declared_length is not None
                                    and len(data) > declared_length
                                ):
                                    raise ValueError("thumbnail length mismatch")
                    finally:
                        response.close()
                    if self.stop_event.is_set():
                        raise GateCancelled("thumbnail cancelled")
                    if (
                        declared_length is not None
                        and len(data) != declared_length
                    ):
                        raise ValueError("thumbnail length mismatch")
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
    """Accept bounded raster formats with necessary container boundaries.

    Qt image plugins parse attacker-controlled bytes.  Keeping SVG/XML and
    uncommon image formats out of the preview path reduces that attack surface
    even when a server lies about Content-Type.  This is deliberately a
    boundary gate, not a claim that pixel decoding or the file middle is valid.
    """

    media_type = str(content_type or "").partition(";")[0].strip().lower()
    formats = {
        "image/jpeg": "jpeg",
        "image/jpg": "jpeg",
        "image/pjpeg": "jpeg",
        "image/png": "png",
        "image/gif": "gif",
        "image/webp": "webp",
    }
    image_format = formats.get(media_type)
    if image_format is None or type(payload) is not bytes:
        return False
    try:
        validate_minimum_image_container(
            image_format,
            size=len(payload),
            prefix=payload[:BOUNDARY_PREFIX_BYTES],
            suffix=payload[-BOUNDARY_SUFFIX_BYTES:],
        )
    except ImageMetadataPolicyError:
        return False
    return True


class DownloadWorker(QThread):
    # Include the emitting worker in every queued signal.  The window can then
    # reject late events from an obsolete thread instead of applying them to a
    # newer batch that happens to own the same task IDs.
    item_started = Signal(object, str)
    item_progress = Signal(object, str, int, int)
    item_succeeded = Signal(object, str, object)
    item_warning = Signal(object, str, str)
    item_failed = Signal(object, str, str)
    batch_finished = Signal(object, int, int, bool)
    batch_blocked = Signal(object, str)

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
                self.item_started.emit(self, task.post_id)
                try:
                    result = downloader.download(
                        task.post_id,
                        progress=lambda current, total, post_id=task.post_id: self.item_progress.emit(
                            self, post_id, current, total
                        ),
                    )
                    succeeded += 1
                    self.item_succeeded.emit(self, task.post_id, result)
                    if result.metadata_warning:
                        self.item_warning.emit(self, task.post_id, result.metadata_warning)
                except Exception as exc:
                    if self.stop_event.is_set():
                        break
                    failed += 1
                    if isinstance(exc, (DownloadError, SankakuAPIError, CancelledError)):
                        message = str(exc)
                    else:
                        message = f"下载发生内部错误（{type(exc).__name__}）"
                    self.item_failed.emit(self, task.post_id, message)
                    # Only process-wide authentication/rate-limit failures stop
                    # the batch.  API/media access denial errors are per-item
                    # SankakuAPIError/DownloadError values and continue safely.
                    if isinstance(exc, (AuthenticationError, RateLimitError)):
                        self.batch_blocked.emit(
                            self, message or "站点要求停止当前批次"
                        )
                        self.stop_event.set()
                        break
        except Exception as exc:
            if not self.stop_event.is_set():
                if isinstance(exc, (DownloadError, SankakuAPIError, CancelledError)):
                    message = str(exc)
                else:
                    message = f"下载初始化发生内部错误（{type(exc).__name__}）"
                self.batch_blocked.emit(self, message)
                # The window persists every member of this batch as queued
                # before the thread starts.  A construction/runtime-boundary
                # failure must therefore finish as a stopped batch so the UI
                # can atomically return every unstarted task to a retryable
                # state instead of stranding it until the next application
                # restart.
                self.stop_event.set()
        finally:
            self._network.close(downloader)
            self._network.close(api)
            self.token = ""
            self.batch_finished.emit(
                self, succeeded, failed, self.stop_event.is_set()
            )


class LibraryScanWorker(QThread):
    """Run the bounded, read-only local library verification off the UI thread."""

    progress = Signal(int, int, object)
    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, output_dir: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.output_dir = os.path.abspath(output_dir)
        self.stop_event = threading.Event()

    def cancel(self) -> None:
        self.stop_event.set()

    def _progress(self, done: int, total: int, checked_bytes: int) -> None:
        if not self.stop_event.is_set():
            self.progress.emit(done, total, checked_bytes)

    def run(self) -> None:
        try:
            if self.stop_event.is_set():
                raise CancelledError("本地库扫描已取消")
            report = scan_download_library(
                self.output_dir,
                stop_event=self.stop_event,
                progress=self._progress,
            )
            if self.stop_event.is_set():
                raise CancelledError("本地库扫描已取消")
            self.succeeded.emit(report)
        except CancelledError:
            self.cancelled.emit()
        except LibraryScanError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"本地库扫描发生内部错误（{type(exc).__name__}）")


class LibraryThumbnailWorker(QThread):
    """Load one bounded local thumbnail away from the UI thread."""

    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        output_dir: str,
        source: VerifiedThumbnailSource,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.output_dir = os.path.abspath(output_dir)
        self.source = source
        self.stop_event = threading.Event()

    def cancel(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        try:
            if self.stop_event.is_set():
                raise CancelledError("本地缩略图读取已取消")
            result = load_library_thumbnail(
                self.output_dir,
                self.source,
                stop_event=self.stop_event,
            )
            if self.stop_event.is_set():
                raise CancelledError("本地缩略图读取已取消")
            self.succeeded.emit(result)
        except CancelledError:
            self.cancelled.emit()
        except LibraryThumbnailError:
            if self.stop_event.is_set():
                self.cancelled.emit()
            else:
                self.failed.emit("本地缩略图读取失败")
        except Exception as exc:
            if self.stop_event.is_set():
                self.cancelled.emit()
            else:
                self.failed.emit(
                    f"本地缩略图读取发生内部错误（{type(exc).__name__}）"
                )


__all__ = [
    "DownloadWorker",
    "LibraryScanWorker",
    "LibraryThumbnailWorker",
    "LoginWorker",
    "SearchWorker",
    "ThumbnailWorker",
]
