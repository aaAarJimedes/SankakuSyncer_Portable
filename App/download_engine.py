# -*- coding: utf-8 -*-
"""Process-gated, resumable media downloads with verified completion."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import random
import re
import stat
import tempfile
import threading
from typing import Callable
from urllib.parse import urljoin, urlsplit

from bound_file_reader import (
    BoundFileCancelled,
    BoundFileError,
    BoundFileMissing,
    BoundFileTooLarge,
    BoundFileUnreadable,
    BoundRootSession,
)
from http_transport import Response, Session, TransportError
from request_gate import GateCancelled, MEDIA_REQUEST_GATE, retry_after_seconds
from sankaku_api import (
    CancelledError,
    RateLimitError,
    SankakuAPI,
    SankakuPost,
)
from sankaku_url_policy import normalize_media_url, normalize_post_id
from version import HTTP_USER_AGENT


MAX_MEDIA_BYTES = 50 * 1024**3
MAX_REDIRECTS = 4
CHUNK_SIZE = 256 * 1024
_MAX_PART_STATE_BYTES = 64 * 1024
_PART_STATE_SCHEMA = 2
_METADATA_SCHEMA = 2
_MAX_METADATA_BYTES = 256 * 1024
_MAX_PREFIX_BYTES = 1024 * 1024
_MAX_COLLISION_SLOTS = 10_000
_MEDIA_GATE_INTERVAL = 0.25
_LONG_RATE_LIMIT_SECONDS = 600.0
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_CONTENT_RANGE_RE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+)$")
_MIME_EXTENSIONS = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/avif": "avif",
    "image/bmp": "bmp",
    "image/tiff": "tiff",
    "video/mp4": "mp4",
    "video/quicktime": "mov",
    "audio/mp4": "m4a",
    "video/webm": "webm",
    "video/x-matroska": "mkv",
    "video/mpeg": "mpeg",
    "video/x-msvideo": "avi",
    "video/x-flv": "flv",
    "video/x-ms-wmv": "wmv",
    "audio/x-ms-wma": "wma",
    "audio/mpeg": "mp3",
    "audio/ogg": "ogg",
    "audio/opus": "opus",
    "audio/flac": "flac",
    "audio/wav": "wav",
}
_MEDIA_EXTENSIONS = frozenset(_MIME_EXTENSIONS.values())
# Public, immutable candidate set used by the read-only local library scanner.
LOCAL_MEDIA_EXTENSIONS = _MEDIA_EXTENSIONS
_MIME_ALIASES = {
    "image/jpg": "image/jpeg",
    "audio/x-m4a": "audio/mp4",
    "audio/mp4a-latm": "audio/mp4",
    "application/ogg": "audio/ogg",
    "audio/x-flac": "audio/flac",
    "audio/x-wav": "audio/wav",
    "audio/wave": "audio/wav",
    "video/avi": "video/x-msvideo",
    "video/msvideo": "video/x-msvideo",
    "application/x-matroska": "video/x-matroska",
}
_REJECTED_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "image/svg+xml",
        "text/html",
        "text/json",
        "text/plain",
        "text/xml",
    }
)
_PART_FILENAME_RE_TEMPLATE = r"^{post_id}\.download(?: \(([1-9][0-9]*)\))?\.part$"
_FINAL_FILENAME_RE_TEMPLATE = (
    r"^{post_id}{variant_suffix}(?: \(([1-9][0-9]*)\))?\.([a-z0-9]+)$"
)


class DownloadError(RuntimeError):
    """A safe-to-display media download failure."""


class MediaAccessDeniedError(DownloadError):
    """One signed media URL is unavailable to the current account."""


class LocalMetadataError(DownloadError):
    """A local download has no trustworthy schema-2 metadata sidecar."""

    def __init__(self, message: str, *, status: str = "invalid_metadata") -> None:
        super().__init__(message)
        self.status = status


class LocalIntegrityError(DownloadError):
    """A local media file failed path, identity, hash, or signature checks."""

    def __init__(
        self,
        message: str,
        *,
        status: str = "changed",
        checked_bytes: int = 0,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.checked_bytes = max(0, int(checked_bytes))


class _PartSlotCollision(DownloadError):
    """A part/state slot was won concurrently; select another slot."""


@dataclass(frozen=True, slots=True)
class DownloadResult:
    post_id: str
    file_path: str
    relative_path: str
    size: int
    sha256: str
    resumed: bool
    already_present: bool
    metadata_warning: str = ""
    variant: str = "original"
    content_type: str = ""


@dataclass(frozen=True, slots=True)
class LocalMediaVerification:
    """Trusted, read-only view of one fully revalidated local download."""

    post_id: str
    variant: str
    file_path: str
    relative_path: str
    size: int
    sha256: str
    content_type: str
    extension: str
    rating: str
    author: str
    tags: tuple[str, ...]
    created_at: str


@dataclass(frozen=True, slots=True)
class _PartState:
    post_id: str
    variant: str
    declared_type: str
    expected_size: int
    expected_md5: str
    etag: str
    last_modified: str
    total_size: int

    @property
    def if_range(self) -> str:
        return _strong_etag_validator(self.etag) or _http_date_validator(
            self.last_modified
        )


@dataclass(frozen=True, slots=True)
class _FileInspection:
    size: int
    sha256: str
    md5: str
    prefix: bytes
    device: int
    inode: int
    mtime_ns: int = 0


class _RetryableMediaResponse(RuntimeError):
    def __init__(self, status_code: int, wait_seconds: float = 0.0) -> None:
        super().__init__(status_code)
        self.status_code = status_code
        self.wait_seconds = wait_seconds


class MediaDownloader:
    """Download one post at a time using fresh metadata and no auth headers."""

    def __init__(
        self,
        api: SankakuAPI,
        output_dir: str,
        *,
        timeout: int = 60,
        max_retries: int = 3,
        prefer_original: bool = True,
        save_metadata: bool = True,
        stop_event: threading.Event | None = None,
        session_factory: Callable[[], Session] = Session,
    ) -> None:
        self.api = api
        self.output_dir = os.path.abspath(output_dir)
        self.timeout = max(10, min(int(timeout), 300))
        self.max_retries = max(0, min(int(max_retries), 10))
        self.prefer_original = bool(prefer_original)
        self.save_metadata = bool(save_metadata)
        self.stop_event = stop_event or threading.Event()
        self._session = session_factory()
        self._session.trust_env = False
        proxy = str(getattr(api, "proxy", "") or "")
        if proxy:
            configure_proxy = getattr(self._session, "configure_proxy", None)
            if not callable(configure_proxy):
                raise ValueError("session factory cannot configure an explicit proxy")
            configure_proxy(proxy)
        self._session.headers.update(
            {
                "Accept": "image/avif,image/webp,image/*,video/*,audio/*,*/*;q=0.5",
                "Accept-Encoding": "identity",
                "User-Agent": HTTP_USER_AGENT,
            }
        )

    def close(self) -> None:
        self._session.close()

    def download(
        self,
        post_id: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> DownloadResult:
        normalized = normalize_post_id(post_id)
        if normalized is None:
            raise DownloadError("作品编号无效")
        self._check_cancelled()
        post = self.api.get_post(normalized)
        if normalize_post_id(post.post_id) != normalized:
            raise DownloadError("站点返回了不匹配的作品编号")
        media_url, variant = _select_media(post, self.prefer_original)
        if not media_url:
            if post.is_premium:
                raise DownloadError("该作品需要更高的账号权限，未尝试绕过")
            raise DownloadError("站点未向当前账号提供可下载文件")
        if normalize_media_url(media_url) is None:
            raise DownloadError("站点返回了不受信任的媒体地址")
        if any(
            marker in urlsplit(media_url).path.lower()
            for marker in ("expired.png", "redirect.png")
        ):
            raise DownloadError("媒体地址已过期或被站点限制")

        os.makedirs(self.output_dir, exist_ok=True)
        if not os.path.isdir(self.output_dir):
            raise DownloadError("下载目录不可用")
        is_original = variant == "original"
        expected_size = (
            post.file_size
            if is_original and type(post.file_size) is int and post.file_size > 0
            else 0
        )
        if expected_size > MAX_MEDIA_BYTES:
            raise DownloadError("原文件超过 50 GiB 安全上限")
        candidate_md5 = post.md5.lower() if isinstance(post.md5, str) else ""
        expected_md5 = (
            candidate_md5
            if is_original and _MD5_RE.fullmatch(candidate_md5)
            else ""
        )
        expected_type = _trusted_expected_type(post.file_type) if is_original else ""
        expected_extension = (
            _trusted_expected_extension(post.file_ext) if is_original else ""
        )

        reusable = self._find_reusable(
            post,
            post_id=normalized,
            variant=variant,
            expected_type=expected_type,
            expected_extension=expected_extension,
            expected_size=expected_size,
            expected_md5=expected_md5,
        )
        if reusable is not None:
            final_path, inspection, content_type, has_sidecar = reusable
            self._check_cancelled()
            warning = ""
            if not has_sidecar:
                warning = self._metadata_warning(
                    post,
                    final_path,
                    inspection,
                    variant=variant,
                    content_type=content_type,
                )
            return self._result(
                normalized,
                final_path,
                inspection,
                resumed=False,
                already_present=True,
                metadata_warning=warning,
                variant=variant,
                content_type=content_type,
            )

        part_path, state_path, state, existing = self._prepare_part(
            post_id=normalized,
            variant=variant,
            expected_size=expected_size,
            expected_md5=expected_md5,
        )
        (
            inspection,
            resumed,
            content_type,
            extension,
            part_path,
            state_path,
            completed_state,
        ) = self._stream_to_part(
            media_url,
            part_path,
            state_path,
            state=state,
            existing=existing,
            post_id=normalized,
            variant=variant,
            expected_type=expected_type,
            expected_extension=expected_extension,
            expected_size=expected_size,
            expected_md5=expected_md5,
            progress=progress,
        )
        _assert_inspection_identity(part_path, inspection, "未完成文件")
        self._check_cancelled()
        final_path = self._commit_media_no_replace(
            part_path,
            post_id=normalized,
            variant=variant,
            extension=extension,
        )
        _remove_compatible_part_state(
            state_path,
            expected=completed_state,
        )

        warning = self._metadata_warning(
            post,
            final_path,
            inspection,
            variant=variant,
            content_type=content_type,
        )
        return self._result(
            normalized,
            final_path,
            inspection,
            resumed=resumed,
            already_present=False,
            metadata_warning=warning,
            variant=variant,
            content_type=content_type,
        )

    def _result(
        self,
        post_id: str,
        final_path: str,
        inspection: _FileInspection,
        *,
        resumed: bool,
        already_present: bool,
        metadata_warning: str,
        variant: str,
        content_type: str,
    ) -> DownloadResult:
        relative = os.path.relpath(final_path, self.output_dir).replace("\\", "/")
        return DownloadResult(
            post_id=post_id,
            file_path=final_path,
            relative_path=relative,
            size=inspection.size,
            sha256=inspection.sha256,
            resumed=resumed,
            already_present=already_present,
            metadata_warning=metadata_warning,
            variant=variant,
            content_type=content_type,
        )

    def _prepare_part(
        self,
        *,
        post_id: str,
        variant: str,
        expected_size: int,
        expected_md5: str,
    ) -> tuple[str, str, _PartState | None, int]:
        occupied = self._occupied_part_slots(post_id)
        for slot in sorted(occupied):
            part_path, state_path = self._part_paths(post_id, slot)
            part_stat = _plain_file_stat(part_path, "未完成文件")
            state_stat = _plain_file_stat(state_path, "续传状态")
            if part_stat is None or state_stat is None:
                # An orphan or an unauthenticated partial may belong to a
                # different process.  It is never removed or reused.
                continue
            existing = part_stat.st_size
            if not 0 < existing <= MAX_MEDIA_BYTES:
                continue
            state = _load_part_state(state_path)
            if (
                state is not None
                and state.post_id == post_id
                and state.variant == variant
                and state.expected_size == expected_size
                and state.expected_md5 == expected_md5
                and (
                    variant == "original"
                    or state.declared_type in _MIME_EXTENSIONS
                )
                and state.if_range
                and state.total_size > existing
            ):
                return part_path, state_path, state, existing
        for slot in range(_MAX_COLLISION_SLOTS):
            if slot not in occupied:
                part_path, state_path = self._part_paths(post_id, slot)
                return part_path, state_path, None, 0
        raise DownloadError("未完成文件槽位已用尽")

    def _occupied_part_slots(self, post_id: str) -> set[int]:
        pattern = re.compile(
            _PART_FILENAME_RE_TEMPLATE.format(post_id=re.escape(post_id)),
            re.IGNORECASE,
        )
        occupied: set[int] = set()
        try:
            names = os.listdir(self.output_dir)
        except OSError as exc:
            raise DownloadError(
                f"下载目录读取失败（{type(exc).__name__}）"
            ) from exc
        for name in names:
            part_name = name.removesuffix(".state.json")
            match = pattern.fullmatch(part_name)
            if match is not None:
                occupied.add(int(match.group(1) or 0))
        return occupied

    def _part_paths(self, post_id: str, slot: int) -> tuple[str, str]:
        suffix = "" if slot == 0 else f" ({slot})"
        part_path = self._safe_target(f"{post_id}.download{suffix}.part")
        return part_path, part_path + ".state.json"

    def _stream_to_part(
        self,
        media_url: str,
        part_path: str,
        state_path: str,
        *,
        state: _PartState | None,
        existing: int,
        post_id: str,
        variant: str,
        expected_type: str,
        expected_extension: str,
        expected_size: int,
        expected_md5: str,
        progress: Callable[[int, int], None] | None,
    ) -> tuple[_FileInspection, bool, str, str, str, str, _PartState]:
        attempt = 0
        restarted_after_416 = False
        while attempt <= self.max_retries:
            self._check_cancelled()
            resume_from = existing if state is not None and state.if_range else 0
            headers: dict[str, str] = {}
            if resume_from:
                headers = {
                    "Range": f"bytes={resume_from}-",
                    "If-Range": state.if_range,
                }
            try:
                with MEDIA_REQUEST_GATE.slot(
                    self.stop_event, min_interval=_MEDIA_GATE_INTERVAL
                ):
                    self._check_cancelled()
                    response = self._open_media(media_url, headers=headers)
                    try:
                        if response.status_code == 416 and resume_from:
                            if restarted_after_416:
                                raise DownloadError("服务器持续拒绝续传范围")
                            # The existing resumable pair is preserved.  A
                            # fresh variant-neutral slot is used for the full
                            # retry so a server-side resource change cannot
                            # destroy previous bytes.
                            (
                                part_path,
                                state_path,
                                state,
                                existing,
                            ) = self._prepare_fresh_part(post_id)
                            state = None
                            existing = 0
                            restarted_after_416 = True
                            continue
                        if response.status_code in {401, 403}:
                            # Metadata was fetched successfully just before this
                            # credential-free signed-CDN request.  A denial here
                            # applies to this URL/item, not to the API token or
                            # every remaining task in the batch.
                            raise MediaAccessDeniedError(
                                "当前作品的签名媒体地址不可用或无权访问"
                            )
                        if response.status_code == 429:
                            wait_seconds = retry_after_seconds(response.headers)
                            MEDIA_REQUEST_GATE.defer(wait_seconds)
                            if wait_seconds >= _LONG_RATE_LIMIT_SECONDS:
                                raise RateLimitError(
                                    "媒体服务器要求较长冷却，已停止本批次；请稍后手动重试"
                                )
                            raise _RetryableMediaResponse(429, wait_seconds)
                        if response.status_code in {408, 500, 502, 503, 504}:
                            raise _RetryableMediaResponse(response.status_code)
                        (
                            inspection,
                            resumed,
                            new_state,
                            content_type,
                            extension,
                            part_path,
                            state_path,
                        ) = self._consume_response(
                            response,
                            part_path,
                            state_path,
                            state=state,
                            resume_from=resume_from,
                            post_id=post_id,
                            variant=variant,
                            expected_type=expected_type,
                            expected_extension=expected_extension,
                            expected_size=expected_size,
                            expected_md5=expected_md5,
                            progress=progress,
                        )
                        state = new_state
                        return (
                            inspection,
                            resumed,
                            content_type,
                            extension,
                            part_path,
                            state_path,
                            new_state,
                        )
                    finally:
                        response.close()
            except GateCancelled as exc:
                raise CancelledError("下载已取消") from exc
            except _RetryableMediaResponse as exc:
                if attempt >= self.max_retries:
                    if exc.status_code == 429:
                        raise RateLimitError("媒体服务器请求过于频繁，请稍后再试") from exc
                    raise DownloadError(
                        f"媒体服务器暂时不可用（HTTP {exc.status_code}）"
                    ) from exc
                attempt += 1
                self._wait_for_retry(exc.wait_seconds, attempt - 1)
            except TransportError as exc:
                if attempt >= self.max_retries:
                    raise DownloadError(f"媒体连接失败（{type(exc).__name__}）") from exc
                attempt += 1
                self._backoff(attempt - 1)
                part_path, state_path, state, existing = self._prepare_part(
                    post_id=post_id,
                    variant=variant,
                    expected_size=expected_size,
                    expected_md5=expected_md5,
                )
            except OSError as exc:
                if attempt >= self.max_retries:
                    raise DownloadError(f"媒体写入失败（{type(exc).__name__}）") from exc
                attempt += 1
                self._backoff(attempt - 1)
                part_path, state_path, state, existing = self._prepare_part(
                    post_id=post_id,
                    variant=variant,
                    expected_size=expected_size,
                    expected_md5=expected_md5,
                )
        raise DownloadError("媒体重试次数已用尽")

    def _prepare_fresh_part(
        self, post_id: str
    ) -> tuple[str, str, _PartState | None, int]:
        occupied = self._occupied_part_slots(post_id)
        for slot in range(_MAX_COLLISION_SLOTS):
            if slot not in occupied:
                part_path, state_path = self._part_paths(post_id, slot)
                return part_path, state_path, None, 0
        raise DownloadError("未完成文件槽位已用尽")

    def _consume_response(
        self,
        response: Response,
        part_path: str,
        state_path: str,
        *,
        state: _PartState | None,
        resume_from: int,
        post_id: str,
        variant: str,
        expected_type: str,
        expected_extension: str,
        expected_size: int,
        expected_md5: str,
        progress: Callable[[int, int], None] | None,
    ) -> tuple[_FileInspection, bool, _PartState, str, str, str, str]:
        if response.status_code not in {200, 206}:
            self._integrity_failure(
                part_path,
                state_path,
                f"媒体请求失败（HTTP {response.status_code}）",
            )
        try:
            content_type = _validated_content_type(
                response.headers.get("Content-Type", "")
            )
            _validated_content_encoding(
                response.headers.get("Content-Encoding", "")
            )
            content_length = _content_length(
                response.headers.get("Content-Length", "")
            )
        except DownloadError as exc:
            self._integrity_failure(part_path, state_path, str(exc))
        if variant != "original" and content_type not in _MIME_EXTENSIONS:
            self._integrity_failure(
                part_path,
                state_path,
                "衍生媒体响应缺少具体 Content-Type",
            )

        append = False
        total = 0
        if response.status_code == 206:
            if not resume_from:
                self._integrity_failure(
                    part_path,
                    state_path,
                    "服务器在未请求续传时返回了分段响应",
                )
            try:
                start, end, total = _parse_content_range(
                    response.headers.get("Content-Range", "")
                )
            except DownloadError as exc:
                self._integrity_failure(part_path, state_path, str(exc))
            range_length = end - start + 1
            if content_length is not None and content_length != range_length:
                self._integrity_failure(part_path, state_path, "续传响应长度不匹配")
            if state is None or start != resume_from:
                self._integrity_failure(part_path, state_path, "服务器返回了不匹配的续传范围")
            if state.total_size and state.total_size != total:
                self._integrity_failure(part_path, state_path, "续传资源总长度已变化")
            append = True
        else:
            if response.headers.get("Content-Range"):
                self._integrity_failure(part_path, state_path, "完整响应不应包含 Content-Range")
            total = content_length or 0

        if total > MAX_MEDIA_BYTES:
            self._integrity_failure(part_path, state_path, "媒体文件超过 50 GiB 安全上限")
        if expected_size and total and expected_size != total:
            self._integrity_failure(part_path, state_path, "原文件长度与站点元数据不匹配")

        response_etag = _strong_etag_validator(response.headers.get("ETag", ""))
        response_last_modified = _http_date_validator(
            response.headers.get("Last-Modified", "")
        )
        if append and state is not None:
            if state.etag and state.etag != response_etag:
                self._integrity_failure(part_path, state_path, "续传资源 ETag 已变化")
            if (
                not state.etag
                and state.last_modified
                and state.last_modified != response_last_modified
            ):
                self._integrity_failure(part_path, state_path, "续传资源修改时间已变化")
            etag = state.etag or response_etag
            last_modified = state.last_modified or response_last_modified
        else:
            etag = response_etag
            last_modified = response_last_modified

        new_state = _PartState(
            post_id=post_id,
            variant=variant,
            declared_type=content_type,
            expected_size=expected_size,
            expected_md5=expected_md5,
            etag=etag,
            last_modified=last_modified,
            total_size=total or expected_size,
        )
        if append:
            if state is None or state.declared_type != content_type:
                self._integrity_failure(
                    part_path,
                    state_path,
                    "续传资源 Content-Type 已变化",
                )
        elif resume_from:
            # A 200 response to If-Range is a full resource.  Preserve the old
            # authenticated pair and consume this response into a new slot.
            part_path, state_path, _unused, _zero = self._prepare_fresh_part(
                post_id
            )

        current = resume_from if append else 0
        progress_total = total or expected_size
        stream_error = ""
        while True:
            try:
                opened_part = _open_part_for_write(
                    part_path,
                    append=append,
                    expected_size=resume_from,
                )
                if not append:
                    try:
                        _save_part_state(state_path, new_state)
                    except Exception:
                        opened_part.close()
                        raise
                break
            except _PartSlotCollision:
                if append:
                    raise
                part_path, state_path, _unused, _zero = self._prepare_fresh_part(
                    post_id
                )
        with opened_part as file_obj:
            for chunk in response.iter_content(CHUNK_SIZE):
                self._check_cancelled()
                if not chunk:
                    continue
                current += len(chunk)
                if current > MAX_MEDIA_BYTES:
                    stream_error = "媒体文件超过 50 GiB 安全上限"
                    break
                if progress_total and current > progress_total:
                    stream_error = "媒体响应超过声明长度"
                    break
                file_obj.write(chunk)
                if progress:
                    progress(current, progress_total)
            file_obj.flush()
            os.fsync(file_obj.fileno())

        if stream_error:
            self._integrity_failure(part_path, state_path, stream_error)

        if total and current != total:
            self._integrity_failure(part_path, state_path, "媒体下载不完整")
        if expected_size and current != expected_size:
            self._integrity_failure(part_path, state_path, "原文件下载长度不完整")
        if current <= 0:
            self._integrity_failure(part_path, state_path, "媒体文件为空")

        inspection = _inspect_media_file(part_path, self.stop_event)
        if inspection.size != current or (total and inspection.size != total):
            self._integrity_failure(
                part_path,
                state_path,
                "媒体文件在校验前发生并发变化",
            )
        try:
            content_type, extension = _resolve_media_format(
                inspection,
                declared_type=content_type,
                expected_type=expected_type,
                expected_extension=expected_extension,
                expected_size=expected_size,
                expected_md5=expected_md5,
                require_concrete_declared=variant != "original",
            )
        except DownloadError:
            raise
        return (
            inspection,
            append,
            new_state,
            content_type,
            extension,
            part_path,
            state_path,
        )

    def _open_media(self, url: str, *, headers: dict[str, str]) -> Response:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            if normalize_media_url(current) is None:
                raise DownloadError("媒体跳转超出官方域名")
            response = self._session.get(
                current,
                headers=headers,
                timeout=(min(15, self.timeout), self.timeout),
                allow_redirects=False,
                stream=True,
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise DownloadError("媒体跳转缺少目标地址")
            current = urljoin(current, location)
        raise DownloadError("媒体跳转次数过多")

    def _find_reusable(
        self,
        post: SankakuPost,
        *,
        post_id: str,
        variant: str,
        expected_type: str,
        expected_extension: str,
        expected_size: int,
        expected_md5: str,
    ) -> tuple[str, _FileInspection, str, bool] | None:
        # A bare final is reusable only for an original whose freshly fetched
        # site metadata supplies both size and a syntactically valid MD5.  A
        # derivative always requires its schema-2 integrity sidecar.
        original_is_fresh = bool(
            variant == "original"
            and expected_size > 0
            and _MD5_RE.fullmatch(expected_md5)
        )
        suffix = "" if variant == "original" else f".{variant}"
        pattern = re.compile(
            _FINAL_FILENAME_RE_TEMPLATE.format(
                post_id=re.escape(post_id),
                variant_suffix=re.escape(suffix),
            ),
            re.IGNORECASE,
        )
        candidates: list[tuple[int, str, str]] = []
        try:
            names = os.listdir(self.output_dir)
        except OSError as exc:
            raise DownloadError(
                f"下载目录读取失败（{type(exc).__name__}）"
            ) from exc
        for name in names:
            match = pattern.fullmatch(name)
            if match is None:
                continue
            extension = match.group(2).lower()
            if extension not in _MEDIA_EXTENSIONS:
                continue
            slot = int(match.group(1) or 0)
            candidates.append((slot, name, extension))
        for _slot, name, filename_extension in sorted(candidates):
            media_path = self._safe_target(name)
            media_stat = _plain_file_stat(media_path, "目标文件")
            if media_stat is None or media_stat.st_size <= 0:
                continue
            metadata_path = media_path + ".json"
            metadata_stat = _plain_file_stat(metadata_path, "元数据文件")
            sidecar = _load_metadata_sidecar(metadata_path) if metadata_stat else None
            if metadata_stat is not None and sidecar is None:
                continue
            if variant != "original" and sidecar is None:
                continue
            if variant == "original" and not original_is_fresh:
                continue
            try:
                inspection = _inspect_media_file(media_path, self.stop_event)
                if sidecar is not None:
                    if not _metadata_matches_file(
                        sidecar,
                        post_id=post_id,
                        variant=variant,
                        filename=name,
                        filename_extension=filename_extension,
                        inspection=inspection,
                    ):
                        continue
                    content_type, detected_extension = _resolve_media_format(
                        inspection,
                        declared_type=sidecar["content_type"],
                        expected_type=expected_type,
                        expected_extension=expected_extension,
                        expected_size=expected_size,
                        expected_md5=expected_md5,
                        require_concrete_declared=True,
                    )
                else:
                    content_type, detected_extension = _resolve_media_format(
                        inspection,
                        declared_type="",
                        expected_type=expected_type,
                        expected_extension=expected_extension,
                        expected_size=expected_size,
                        expected_md5=expected_md5,
                        require_concrete_declared=False,
                    )
                if detected_extension != filename_extension:
                    continue
            except DownloadError:
                # Invalid ordinary files remain untouched and force allocation
                # of a collision suffix after a fresh verified download.
                continue
            _assert_inspection_identity(media_path, inspection, "目标文件")
            return media_path, inspection, content_type, sidecar is not None
        return None

    def _commit_media_no_replace(
        self,
        part_path: str,
        *,
        post_id: str,
        variant: str,
        extension: str,
    ) -> str:
        suffix = "" if variant == "original" else f".{variant}"
        for slot in range(_MAX_COLLISION_SLOTS):
            collision = "" if slot == 0 else f" ({slot})"
            final_path = self._safe_target(
                f"{post_id}{suffix}{collision}.{extension}"
            )
            sidecar_path = final_path + ".json"
            if _plain_file_stat(final_path, "目标文件") is not None:
                continue
            if _plain_file_stat(sidecar_path, "元数据文件") is not None:
                continue
            self._check_cancelled()
            try:
                _commit_file_no_replace(part_path, final_path)
            except FileExistsError:
                continue
            except OSError as exc:
                raise DownloadError(
                    f"无法提交完成文件（{type(exc).__name__}）"
                ) from exc
            return final_path
        raise DownloadError("目标文件碰撞槽位已用尽")

    def _safe_target(self, filename: str) -> str:
        target = os.path.abspath(os.path.join(self.output_dir, filename))
        try:
            if os.path.commonpath((self.output_dir, target)) != self.output_dir:
                raise DownloadError("下载路径越界")
        except ValueError as exc:
            raise DownloadError("下载路径越界") from exc
        return target

    def _metadata_warning(
        self,
        post: SankakuPost,
        media_path: str,
        inspection: _FileInspection,
        *,
        variant: str,
        content_type: str,
    ) -> str:
        if not self.save_metadata:
            return ""
        try:
            self._save_metadata(
                post,
                media_path,
                inspection,
                variant=variant,
                content_type=content_type,
            )
        except DownloadError as exc:
            return str(exc)
        except Exception as exc:
            return f"媒体已保存，但元数据写入失败（{type(exc).__name__}）"
        return ""

    def _save_metadata(
        self,
        post: SankakuPost,
        media_path: str,
        inspection: _FileInspection,
        *,
        variant: str,
        content_type: str,
    ) -> None:
        # Keep the complete media filename in the sidecar name.  Removing its
        # extension could collide with a media file whose untrusted API
        # extension was ``json`` and atomically replace the verified payload.
        metadata_path = media_path + ".json"
        extension = _MIME_EXTENSIONS[content_type]
        payload = {
            "schema_version": _METADATA_SCHEMA,
            "post_id": post.post_id,
            "variant": variant,
            "filename": os.path.basename(media_path),
            "content_type": content_type,
            "extension": extension,
            "size": inspection.size,
            "sha256": inspection.sha256,
            "post": {
                "rating": post.rating,
                "status": post.status,
                "width": post.width,
                "height": post.height,
                "tags": list(post.tag_names),
                "author": post.author,
                "created_at": post.created_at,
                "is_premium": post.is_premium,
            },
        }
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        if len(encoded) > _MAX_METADATA_BYTES:
            raise DownloadError("媒体已保存，但元数据超过安全上限")
        temp_path = None
        try:
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".metadata.", suffix=".tmp", dir=self.output_dir
            )
            with os.fdopen(descriptor, "wb") as file_obj:
                file_obj.write(encoded)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            _plain_file_stat(metadata_path, "元数据文件")
            _commit_file_no_replace(temp_path, metadata_path)
            temp_path = None
        except FileExistsError as exc:
            raise DownloadError("媒体已保存，但元数据文件已存在，未覆盖") from exc
        except OSError as exc:
            raise DownloadError(f"媒体已保存，但元数据写入失败（{type(exc).__name__}）") from exc
        finally:
            if temp_path:
                _remove_quietly(temp_path)

    def _integrity_failure(
        self, part_path: str, state_path: str, message: str
    ) -> None:
        # Preserve the current pair.  A subsequent run either resumes a
        # validator-bound partial or selects another slot; it never destroys
        # an unauthenticated or concurrently replaced path on failure.
        del part_path, state_path
        raise DownloadError(message)

    def _check_cancelled(self) -> None:
        if self.stop_event.is_set():
            raise CancelledError("下载已取消")

    def _wait_for_retry(self, wait_seconds: float, attempt: int) -> None:
        if wait_seconds > 0:
            if self.stop_event.wait(min(wait_seconds, _LONG_RATE_LIMIT_SECONDS)):
                raise CancelledError("下载已取消")
            return
        self._backoff(attempt)

    def _backoff(self, attempt: int) -> None:
        seconds = min(45.0, 5.0 * (3**attempt) + random.uniform(0.0, 1.0))
        if self.stop_event.wait(seconds):
            raise CancelledError("下载已取消")


def _select_media(post: SankakuPost, prefer_original: bool) -> tuple[str, str]:
    candidates = (
        (("original", post.file_url), ("sample", post.sample_url), ("preview", post.preview_url))
        if prefer_original
        else (("sample", post.sample_url), ("preview", post.preview_url), ("original", post.file_url))
    )
    for variant, url in candidates:
        if url:
            return url, variant
    return "", ""


def _normalize_content_type(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.split(";", 1)[0].strip().lower()
    return _MIME_ALIASES.get(normalized, normalized)


def _trusted_expected_type(value: object) -> str:
    normalized = _normalize_content_type(value)
    return normalized if normalized in _MIME_EXTENSIONS else ""


def _trusted_expected_extension(value: object) -> str:
    if not isinstance(value, str):
        return ""
    extension = value.strip().lower().lstrip(".")
    aliases = {
        "jpe": "jpg",
        "jpeg": "jpg",
        "m4v": "mp4",
        "mpg": "mpeg",
        "oga": "ogg",
        "tif": "tiff",
    }
    extension = aliases.get(extension, extension)
    return extension if extension in _MEDIA_EXTENSIONS else ""


def _content_length(value: object) -> int | None:
    if value in (None, ""):
        return None
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise DownloadError("媒体响应包含无效 Content-Length")
    significant = value.lstrip("0") or "0"
    maximum = str(MAX_MEDIA_BYTES)
    if len(significant) > len(maximum):
        raise DownloadError("媒体文件超过 50 GiB 安全上限")
    length = int(significant)
    if length > MAX_MEDIA_BYTES:
        raise DownloadError("媒体文件超过 50 GiB 安全上限")
    return length


def _parse_content_range(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise DownloadError("服务器返回了无效 Content-Range")
    match = _CONTENT_RANGE_RE.fullmatch(value.strip())
    if match is None:
        raise DownloadError("服务器返回了无效 Content-Range")
    maximum_digits = len(str(MAX_MEDIA_BYTES))
    normalized = tuple(part.lstrip("0") or "0" for part in match.groups())
    if any(len(part) > maximum_digits for part in normalized):
        raise DownloadError("服务器返回了无效 Content-Range")
    start, end, total = (int(part) for part in normalized)
    if start > end or total <= end or total > MAX_MEDIA_BYTES:
        raise DownloadError("服务器返回了无效 Content-Range")
    return start, end, total


def _validated_content_type(value: object) -> str:
    if not isinstance(value, str):
        raise DownloadError("媒体响应包含无效 Content-Type")
    content_type = _normalize_content_type(value)
    if content_type in _REJECTED_MEDIA_TYPES:
        raise DownloadError("媒体地址返回了网页或错误信息")
    if content_type and content_type not in _MIME_EXTENSIONS:
        if content_type != "application/octet-stream":
            raise DownloadError("媒体类型不受支持")
    return content_type


def _validated_content_encoding(value: object) -> None:
    if not isinstance(value, str):
        raise DownloadError("媒体响应包含无效 Content-Encoding")
    if value.strip().casefold() not in {"", "identity"}:
        raise DownloadError("媒体响应使用了不安全的压缩编码")


def _safe_validator(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate or len(candidate) > 1024:
        return ""
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return ""
    return candidate


def _strong_etag_validator(value: object) -> str:
    candidate = _safe_validator(value)
    if (
        len(candidate) >= 2
        and candidate.startswith('"')
        and candidate.endswith('"')
        and '"' not in candidate[1:-1]
        and not candidate.casefold().startswith("w/")
    ):
        return candidate
    return ""


def _http_date_validator(value: object) -> str:
    candidate = _safe_validator(value)
    if not candidate:
        return ""
    try:
        parsed = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, OverflowError):
        return ""
    if parsed is None or parsed.tzinfo is None:
        return ""
    return candidate


def _stat_is_plain_file(file_stat: os.stat_result) -> bool:
    attributes = int(getattr(file_stat, "st_file_attributes", 0))
    return bool(
        stat.S_ISREG(file_stat.st_mode)
        and not stat.S_ISLNK(file_stat.st_mode)
        and not attributes & _WINDOWS_REPARSE_POINT
    )


def _plain_file_stat(path: str, label: str) -> os.stat_result | None:
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DownloadError(f"{label}状态读取失败（{type(exc).__name__}）") from exc
    if not _stat_is_plain_file(file_stat):
        raise DownloadError(f"{label}路径不安全（拒绝链接或重解析点）")
    return file_stat


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _open_plain_for_read(path: str, label: str):
    before = _plain_file_stat(path, label)
    if before is None:
        raise DownloadError(f"{label}不存在")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DownloadError(f"{label}打开失败（{type(exc).__name__}）") from exc
    try:
        opened = os.fstat(descriptor)
        if not _stat_is_plain_file(opened) or not _same_file_identity(before, opened):
            raise DownloadError(f"{label}在打开期间被替换")
        return os.fdopen(descriptor, "rb"), opened
    except Exception:
        os.close(descriptor)
        raise


def _open_part_for_write(path: str, *, append: bool, expected_size: int):
    binary = getattr(os, "O_BINARY", 0)
    common = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOINHERIT", 0)
    if not append:
        if _plain_file_stat(path, "未完成文件") is not None:
            raise _PartSlotCollision("未完成文件已被其他进程占用")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary | common
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            # Resolve the colliding path only to produce a precise safe error;
            # O_EXCL already guaranteed that it was never followed.
            _plain_file_stat(path, "未完成文件")
            raise _PartSlotCollision("未完成文件已被其他进程占用") from exc
        except OSError as exc:
            raise DownloadError(
                f"未完成文件创建失败（{type(exc).__name__}）"
            ) from exc
    else:
        before = _plain_file_stat(path, "未完成文件")
        if before is None:
            raise DownloadError("续传文件已不存在")
        if before.st_size != expected_size:
            raise DownloadError("续传文件大小已被其他进程改变")
        flags = os.O_WRONLY | os.O_APPEND | binary | common
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise DownloadError(
                f"续传文件打开失败（{type(exc).__name__}）"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not _stat_is_plain_file(opened)
                or not _same_file_identity(before, opened)
                or opened.st_size != expected_size
            ):
                raise DownloadError("续传文件在打开期间被替换或改变")
        except Exception:
            os.close(descriptor)
            raise
    try:
        return os.fdopen(descriptor, "ab" if append else "wb")
    except Exception:
        os.close(descriptor)
        raise


def _assert_inspection_identity(
    path: str,
    inspection: _FileInspection,
    label: str,
) -> None:
    current = _plain_file_stat(path, label)
    if (
        current is None
        or current.st_size != inspection.size
        or current.st_dev != inspection.device
        or current.st_ino != inspection.inode
        or (
            inspection.mtime_ns
            and getattr(current, "st_mtime_ns", 0) != inspection.mtime_ns
        )
    ):
        raise DownloadError(f"{label}在校验后被替换或改变")


def _save_part_state(path: str, state: _PartState) -> None:
    payload = {"schema_version": _PART_STATE_SCHEMA, **asdict(state)}
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > _MAX_PART_STATE_BYTES:
        raise DownloadError("续传状态过大")
    temp_path = None
    try:
        descriptor, temp_path = tempfile.mkstemp(
            prefix=".part-state.", suffix=".tmp", dir=os.path.dirname(path)
        )
        with os.fdopen(descriptor, "wb") as file_obj:
            file_obj.write(encoded)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        _plain_file_stat(path, "续传状态")
        _commit_file_no_replace(temp_path, path)
        temp_path = None
    except FileExistsError as exc:
        raise _PartSlotCollision("续传状态已被其他进程占用") from exc
    except OSError as exc:
        raise DownloadError(f"续传状态写入失败（{type(exc).__name__}）") from exc
    finally:
        if temp_path:
            _remove_quietly(temp_path)


def _load_part_state(path: str) -> _PartState | None:
    try:
        path_stat = _plain_file_stat(path, "续传状态")
        if path_stat is None or path_stat.st_size > _MAX_PART_STATE_BYTES:
            return None
        opened, opened_stat = _open_plain_for_read(path, "续传状态")
        with opened:
            raw_payload = opened.read(_MAX_PART_STATE_BYTES + 1)
        if len(raw_payload) > _MAX_PART_STATE_BYTES:
            return None
        current = _plain_file_stat(path, "续传状态")
        if (
            current is None
            or not _same_file_identity(opened_stat, current)
            or current.st_size != opened_stat.st_size
            or getattr(current, "st_mtime_ns", 0)
            != getattr(opened_stat, "st_mtime_ns", 0)
        ):
            raise DownloadError("续传状态在读取期间被替换或改变")
        payload = json.loads(raw_payload.decode("ascii"))
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "post_id",
            "variant",
            "declared_type",
            "expected_size",
            "expected_md5",
            "etag",
            "last_modified",
            "total_size",
        }:
            return None
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != _PART_STATE_SCHEMA
        ):
            return None
        if not isinstance(payload["post_id"], str) or payload["variant"] not in {
            "original",
            "sample",
            "preview",
        }:
            return None
        declared_type = _normalize_content_type(payload["declared_type"])
        if declared_type != payload["declared_type"] or (
            declared_type not in _MIME_EXTENSIONS
            and declared_type not in {"application/octet-stream", ""}
        ):
            return None
        if type(payload["expected_size"]) is not int or not (
            0 <= payload["expected_size"] <= MAX_MEDIA_BYTES
        ):
            return None
        if type(payload["total_size"]) is not int or not (
            0 <= payload["total_size"] <= MAX_MEDIA_BYTES
        ):
            return None
        expected_md5 = payload["expected_md5"]
        if not isinstance(expected_md5, str) or (
            expected_md5 and _MD5_RE.fullmatch(expected_md5) is None
        ):
            return None
        etag = _strong_etag_validator(payload["etag"])
        last_modified = _http_date_validator(payload["last_modified"])
        if etag != payload["etag"] or last_modified != payload["last_modified"]:
            return None
        return _PartState(
            post_id=payload["post_id"],
            variant=payload["variant"],
            declared_type=declared_type,
            expected_size=payload["expected_size"],
            expected_md5=expected_md5,
            etag=etag,
            last_modified=last_modified,
            total_size=payload["total_size"],
        )
    except (
        OSError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return None


def _inspect_media_file(path: str, stop_event: threading.Event) -> _FileInspection:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    prefix = bytearray()
    size = 0
    try:
        opened, opened_stat = _open_plain_for_read(path, "媒体文件")
        with opened as file_obj:
            while True:
                if stop_event.is_set():
                    raise CancelledError("下载已取消")
                chunk = file_obj.read(1024 * 1024)
                if not chunk:
                    break
                if len(prefix) < _MAX_PREFIX_BYTES:
                    prefix.extend(chunk[: _MAX_PREFIX_BYTES - len(prefix)])
                size += len(chunk)
                if size > MAX_MEDIA_BYTES:
                    raise DownloadError("媒体文件超过 50 GiB 安全上限")
                sha256.update(chunk)
                md5.update(chunk)
    except OSError as exc:
        raise DownloadError(f"文件校验失败（{type(exc).__name__}）") from exc
    return _FileInspection(
        size=size,
        sha256=sha256.hexdigest(),
        md5=md5.hexdigest(),
        prefix=bytes(prefix),
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
        mtime_ns=getattr(opened_stat, "st_mtime_ns", 0),
    )


def _validate_media_inspection(
    inspection: _FileInspection,
    *,
    declared_type: str,
    expected_type: str,
    expected_size: int,
    expected_md5: str,
) -> None:
    _resolve_media_format(
        inspection,
        declared_type=declared_type,
        expected_type=_trusted_expected_type(expected_type),
        expected_extension="",
        expected_size=expected_size,
        expected_md5=expected_md5,
        require_concrete_declared=False,
    )


def _resolve_media_format(
    inspection: _FileInspection,
    *,
    declared_type: str,
    expected_type: str,
    expected_extension: str,
    expected_size: int,
    expected_md5: str,
    require_concrete_declared: bool,
) -> tuple[str, str]:
    if inspection.size <= 0:
        raise DownloadError("媒体文件为空")
    if expected_size and inspection.size != expected_size:
        raise DownloadError("原文件长度与站点元数据不匹配")
    if expected_md5 and inspection.md5 != expected_md5:
        raise DownloadError("原文件 MD5 校验失败")
    candidates = _media_signatures(inspection.prefix)
    if not candidates:
        stripped = inspection.prefix.lstrip().lower()
        if stripped.startswith(
            (
                b"<html",
                b"<!doctype",
                b"<?xml",
                b"<svg",
                b"{",
                b"[",
            )
        ):
            raise DownloadError("媒体内容实际是网页或 JSON")
        raise DownloadError("媒体文件签名无效")

    declared = _normalize_content_type(declared_type)
    if declared in _REJECTED_MEDIA_TYPES:
        raise DownloadError("媒体地址返回了网页或错误信息")
    if declared and declared not in _MIME_EXTENSIONS and declared != "application/octet-stream":
        raise DownloadError("媒体类型不受支持")
    concrete_declared = declared if declared in _MIME_EXTENSIONS else ""
    expected = _trusted_expected_type(expected_type)
    if require_concrete_declared and not concrete_declared:
        raise DownloadError("衍生媒体响应缺少具体 Content-Type")
    if concrete_declared and concrete_declared not in candidates:
        raise DownloadError("媒体 Content-Type 与文件签名不匹配")
    if expected and expected not in candidates:
        raise DownloadError("原文件类型与文件签名不匹配")
    if concrete_declared and expected and concrete_declared != expected:
        raise DownloadError("媒体 Content-Type 与原文件类型不匹配")

    if concrete_declared:
        selected = concrete_declared
    elif expected:
        selected = expected
    elif len(candidates) == 1:
        selected = next(iter(candidates))
    else:
        raise DownloadError("媒体容器类型存在歧义，已拒绝保存")
    extension = _MIME_EXTENSIONS[selected]
    if expected_extension and expected_extension != extension:
        raise DownloadError("原文件扩展名与文件签名不匹配")
    return selected, extension


def _media_signatures(data: bytes) -> frozenset[str]:
    if data.startswith(b"\xff\xd8\xff"):
        return frozenset({"image/jpeg"})
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return frozenset({"image/png"})
    if data.startswith((b"GIF87a", b"GIF89a")):
        return frozenset({"image/gif"})
    if len(data) >= 12 and data.startswith(b"RIFF"):
        form_type = data[8:12]
        if form_type == b"WEBP":
            return frozenset({"image/webp"})
        if form_type == b"WAVE":
            return frozenset({"audio/wav"})
        if form_type == b"AVI ":
            return frozenset({"video/x-msvideo"})
    if len(data) >= 16 and data[4:8] == b"ftyp":
        box_size = int.from_bytes(data[0:4], "big")
        if box_size and box_size < 16:
            return frozenset()
        brands = {
            data[index : index + 4]
            for index in range(8, min(len(data), box_size or len(data)), 4)
            if len(data[index : index + 4]) == 4
        }
        if brands & {b"avif", b"avis"}:
            return frozenset({"image/avif"})
        if data[8:12] == b"qt  ":
            return frozenset({"video/quicktime"})
        if data[8:12] in {b"M4A ", b"M4B ", b"M4P "}:
            return frozenset({"audio/mp4"})
        recognized = {
            b"3gp4",
            b"3gp5",
            b"3gp6",
            b"avc1",
            b"dash",
            b"iso2",
            b"iso3",
            b"iso4",
            b"iso5",
            b"iso6",
            b"isom",
            b"M4V ",
            b"mp41",
            b"mp42",
            b"MSNV",
        }
        if brands & recognized:
            return frozenset({"video/mp4", "audio/mp4", "video/quicktime"})
        return frozenset()
    if data.startswith(b"\x1aE\xdf\xa3"):
        doc_type = _ebml_doc_type(data)
        if doc_type == "webm":
            return frozenset({"video/webm"})
        if doc_type == "matroska":
            return frozenset({"video/x-matroska"})
        return frozenset()
    if data.startswith((b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3")):
        return frozenset({"video/mpeg"})
    if data.startswith(b"FLV\x01"):
        return frozenset({"video/x-flv"})
    if _looks_like_mp3(data):
        return frozenset({"audio/mpeg"})
    if data.startswith(b"OggS\x00") and b"OpusHead" in data[:256]:
        return frozenset({"audio/opus", "audio/ogg"})
    if data.startswith(b"OggS\x00") and (
        b"\x01vorbis" in data[:512] or b"Speex   " in data[:512]
    ):
        return frozenset({"audio/ogg"})
    if data.startswith(b"fLaC"):
        return frozenset({"audio/flac"})
    if (
        len(data) >= 14
        and data.startswith(b"BM")
        and data[6:10] == b"\x00\x00\x00\x00"
        and int.from_bytes(data[10:14], "little") >= 14
    ):
        return frozenset({"image/bmp"})
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return frozenset({"image/tiff"})
    if data.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"):
        return frozenset({"video/x-ms-wmv", "audio/x-ms-wma"})
    return frozenset()


def _looks_like_mp3(data: bytes) -> bool:
    if _looks_like_mp3_frame(data, 0):
        return True
    if len(data) < 10 or not data.startswith(b"ID3"):
        return False
    size_bytes = data[6:10]
    if any(byte & 0x80 for byte in size_bytes):
        return False
    tag_size = 0
    for byte in size_bytes:
        tag_size = (tag_size << 7) | byte
    offset = 10 + tag_size + (10 if data[5] & 0x10 else 0)
    return _looks_like_mp3_frame(data, offset)


def _looks_like_mp3_frame(data: bytes, offset: int) -> bool:
    if (
        offset < 0
        or len(data) < offset + 4
        or data[offset] != 0xFF
        or data[offset + 1] & 0xE0 != 0xE0
    ):
        return False
    version = (data[offset + 1] >> 3) & 0x03
    layer = (data[offset + 1] >> 1) & 0x03
    bitrate = (data[offset + 2] >> 4) & 0x0F
    sample_rate = (data[offset + 2] >> 2) & 0x03
    return version != 0x01 and layer != 0 and bitrate not in {0, 0x0F} and sample_rate != 0x03


def _ebml_doc_type(data: bytes) -> str:
    try:
        header_size, position = _read_ebml_vint(data, 4)
        end = min(len(data), position + header_size)
        while position < end:
            element_id, position = _read_ebml_id(data, position)
            element_size, position = _read_ebml_vint(data, position)
            value_end = position + element_size
            if value_end > end:
                return ""
            if element_id == 0x4282:
                return data[position:value_end].decode("ascii").strip().lower()
            position = value_end
    except (IndexError, UnicodeDecodeError, ValueError):
        return ""
    return ""


def _read_ebml_vint(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise ValueError("truncated EBML integer")
    first = data[position]
    mask = 0x80
    width = 1
    while width <= 8 and not first & mask:
        mask >>= 1
        width += 1
    if width > 8 or position + width > len(data):
        raise ValueError("invalid EBML integer")
    value = first & (mask - 1)
    for byte in data[position + 1 : position + width]:
        value = (value << 8) | byte
    return value, position + width


def _read_ebml_id(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise ValueError("truncated EBML id")
    first = data[position]
    mask = 0x80
    width = 1
    while width <= 4 and not first & mask:
        mask >>= 1
        width += 1
    if width > 4 or position + width > len(data):
        raise ValueError("invalid EBML id")
    value = 0
    for byte in data[position : position + width]:
        value = (value << 8) | byte
    return value, position + width


def _load_metadata_sidecar(path: str) -> dict[str, object] | None:
    try:
        path_stat = _plain_file_stat(path, "元数据文件")
        if (
            path_stat is None
            or path_stat.st_size <= 0
            or path_stat.st_size > _MAX_METADATA_BYTES
        ):
            return None
        opened, opened_stat = _open_plain_for_read(path, "元数据文件")
        with opened:
            encoded = opened.read(_MAX_METADATA_BYTES + 1)
        if len(encoded) > _MAX_METADATA_BYTES:
            return None
        current = _plain_file_stat(path, "元数据文件")
        if (
            current is None
            or not _same_file_identity(opened_stat, current)
            or current.st_size != opened_stat.st_size
            or getattr(current, "st_mtime_ns", 0)
            != getattr(opened_stat, "st_mtime_ns", 0)
        ):
            raise DownloadError("元数据文件在读取期间被替换")
    except OSError:
        return None
    return _parse_metadata_sidecar(encoded)


def _parse_metadata_sidecar(encoded: bytes) -> dict[str, object] | None:
    """Validate one already bounded schema-2 sidecar payload."""

    try:
        if type(encoded) is not bytes or not 0 < len(encoded) <= _MAX_METADATA_BYTES:
            return None
        payload = json.loads(encoded.decode("utf-8"))
    except (
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return None
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "post_id",
        "variant",
        "filename",
        "content_type",
        "extension",
        "size",
        "sha256",
        "post",
    }:
        return None
    if payload["schema_version"] != _METADATA_SCHEMA or type(
        payload["schema_version"]
    ) is not int:
        return None
    if (
        not isinstance(payload["post_id"], str)
        or not isinstance(payload["variant"], str)
        or payload["variant"] not in {"original", "sample", "preview"}
    ):
        return None
    filename = payload["filename"]
    if (
        not isinstance(filename, str)
        or not filename
        or filename != os.path.basename(filename)
        or os.path.isabs(filename)
    ):
        return None
    content_type = _normalize_content_type(payload["content_type"])
    if content_type != payload["content_type"] or content_type not in _MIME_EXTENSIONS:
        return None
    extension = payload["extension"]
    if (
        not isinstance(extension, str)
        or extension != _MIME_EXTENSIONS[content_type]
    ):
        return None
    if (
        type(payload["size"]) is not int
        or not 0 < payload["size"] <= MAX_MEDIA_BYTES
        or not isinstance(payload["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["sha256"]) is None
    ):
        return None
    post = payload["post"]
    if not isinstance(post, dict) or set(post) != {
        "rating",
        "status",
        "width",
        "height",
        "tags",
        "author",
        "created_at",
        "is_premium",
    }:
        return None
    if (
        not isinstance(post["rating"], str)
        or not isinstance(post["status"], str)
        or type(post["width"]) is not int
        or type(post["height"]) is not int
        or not 0 <= post["width"] <= 1_000_000
        or not 0 <= post["height"] <= 1_000_000
        or not isinstance(post["tags"], list)
        or len(post["tags"]) > 100_000
        or any(not isinstance(tag, str) for tag in post["tags"])
        or not isinstance(post["author"], str)
        or not isinstance(post["created_at"], str)
        or type(post["is_premium"]) is not bool
    ):
        return None
    return payload


def _metadata_matches_file(
    payload: dict[str, object],
    *,
    post_id: str,
    variant: str,
    filename: str,
    filename_extension: str,
    inspection: _FileInspection,
) -> bool:
    return bool(
        payload["post_id"] == post_id
        and payload["variant"] == variant
        and payload["filename"] == filename
        and payload["extension"] == filename_extension
        and payload["size"] == inspection.size
        and payload["sha256"] == inspection.sha256
    )


def _local_access_status(error: DownloadError, *, missing: str) -> str:
    message = str(error)
    if "不存在" in message:
        return missing
    if "路径不安全" in message or "被替换" in message:
        return "unsafe_path"
    if any(marker in message for marker in ("读取失败", "打开失败", "校验失败")):
        return "unreadable"
    return "changed"


def _validate_local_filename_binding(
    filename: str,
    payload: dict[str, object],
) -> tuple[str, str, str]:
    """Validate fields that can be rejected before hashing a large media file."""

    post_id = payload["post_id"]
    variant = payload["variant"]
    extension = payload["extension"]
    if normalize_post_id(post_id) != post_id:
        raise LocalMetadataError("本地元数据中的作品编号无效")
    suffix = "" if variant == "original" else f".{variant}"
    pattern = re.compile(
        _FINAL_FILENAME_RE_TEMPLATE.format(
            post_id=re.escape(post_id),
            variant_suffix=re.escape(suffix),
        ),
        re.IGNORECASE,
    )
    match = pattern.fullmatch(filename)
    if (
        payload["filename"] != filename
        or match is None
        or match.group(2).lower() != extension
        or int(match.group(1) or 0) >= _MAX_COLLISION_SLOTS
    ):
        raise LocalMetadataError("本地元数据与文件名不匹配")
    return post_id, variant, extension


def _validate_local_media_pair(
    filename: str,
    payload: dict[str, object],
    inspection: _FileInspection,
    binding: tuple[str, str, str],
) -> str:
    """Bind one completed media inspection to its validated sidecar."""

    post_id, variant, extension = binding
    if not _metadata_matches_file(
        payload,
        post_id=post_id,
        variant=variant,
        filename=filename,
        filename_extension=extension,
        inspection=inspection,
    ):
        raise LocalIntegrityError(
            "本地媒体的长度或 SHA-256 与元数据不匹配",
            checked_bytes=inspection.size,
        )
    try:
        content_type, detected_extension = _resolve_media_format(
            inspection,
            declared_type=payload["content_type"],
            expected_type=payload["content_type"],
            expected_extension=extension,
            expected_size=payload["size"],
            expected_md5="",
            require_concrete_declared=True,
        )
        if detected_extension != extension:
            raise DownloadError("本地媒体扩展名与文件签名不匹配")
    except DownloadError as exc:
        raise LocalIntegrityError(
            str(exc), checked_bytes=inspection.size
        ) from exc
    return content_type


def _raise_bound_local_failure(
    error: BoundFileError,
    *,
    target: str,
    checked_bytes: int = 0,
    after_media: bool = False,
) -> None:
    """Translate fixed bound-reader failures without inspecting message text."""

    if isinstance(error, BoundFileCancelled):
        raise CancelledError("本地校验已取消") from None
    if target == "metadata":
        if isinstance(error, BoundFileMissing):
            message, status = "缺少本地元数据", "missing_metadata"
        elif isinstance(error, BoundFileTooLarge):
            message, status = "本地元数据超过安全上限", "invalid_metadata"
        elif isinstance(error, BoundFileUnreadable):
            message, status = "本地元数据不可读", "unreadable"
        else:
            message, status = "本地元数据路径不安全", "unsafe_path"
        if after_media:
            raise LocalIntegrityError(
                message,
                status=status,
                checked_bytes=checked_bytes,
            ) from None
        raise LocalMetadataError(message, status=status) from None

    if isinstance(error, BoundFileMissing):
        message, status = "本地媒体不存在", "missing_media"
    elif isinstance(error, BoundFileTooLarge):
        message, status = "本地媒体超过 50 GiB 安全上限", "changed"
    elif isinstance(error, BoundFileUnreadable):
        message, status = "本地媒体不可读", "unreadable"
    else:
        message, status = "本地媒体路径不安全", "unsafe_path"
    raise LocalIntegrityError(
        message,
        status=status,
        checked_bytes=checked_bytes,
    ) from None


def verify_bound_local_download(
    session: BoundRootSession,
    filename: str,
    stop_event: threading.Event | None = None,
) -> LocalMediaVerification:
    """Revalidate one direct child using an already-open root session."""

    cancellation = stop_event or threading.Event()
    if cancellation.is_set():
        raise CancelledError("本地校验已取消")
    if not isinstance(session, BoundRootSession) or session.closed:
        raise LocalIntegrityError(
            "本地媒体根目录不可用", status="unsafe_path"
        )
    if not isinstance(filename, str) or not filename:
        raise LocalIntegrityError("本地媒体路径无效", status="unsafe_path")

    try:
        media_size = session.stat_child(
            filename,
            stop_event=cancellation,
            max_bytes=MAX_MEDIA_BYTES,
        )
    except BoundFileError as exc:
        _raise_bound_local_failure(exc, target="media")
    if media_size <= 0:
        raise LocalIntegrityError("本地媒体为空")

    sidecar_name = filename + ".json"
    try:
        encoded = session.read_small_file(
            sidecar_name,
            stop_event=cancellation,
            max_bytes=_MAX_METADATA_BYTES,
        )
    except BoundFileError as exc:
        _raise_bound_local_failure(exc, target="metadata")
    payload = _parse_metadata_sidecar(encoded)
    if payload is None:
        raise LocalMetadataError("本地元数据格式无效")
    binding = _validate_local_filename_binding(filename, payload)

    try:
        bound_inspection = session.inspect_child(
            filename,
            stop_event=cancellation,
            max_bytes=MAX_MEDIA_BYTES,
            prefix_bytes=_MAX_PREFIX_BYTES,
        )
    except BoundFileError as exc:
        _raise_bound_local_failure(exc, target="media")
    inspection = _FileInspection(
        size=bound_inspection.size,
        sha256=bound_inspection.sha256,
        md5=bound_inspection.md5,
        prefix=bound_inspection.prefix,
        device=0,
        inode=0,
    )
    post_id, variant, extension = binding
    content_type = _validate_local_media_pair(
        filename, payload, inspection, binding
    )

    try:
        refreshed_encoded = session.read_small_file(
            sidecar_name,
            stop_event=cancellation,
            max_bytes=_MAX_METADATA_BYTES,
        )
    except BoundFileError as exc:
        _raise_bound_local_failure(
            exc,
            target="metadata",
            checked_bytes=inspection.size,
            after_media=True,
        )
    if refreshed_encoded != encoded:
        raise LocalIntegrityError(
            "本地元数据在校验期间发生变化",
            status="changed",
            checked_bytes=inspection.size,
        )
    if cancellation.is_set():
        raise CancelledError("本地校验已取消")

    post = payload["post"]
    return LocalMediaVerification(
        post_id=post_id,
        variant=variant,
        file_path=os.path.join(session.root_path, filename),
        relative_path=filename,
        size=inspection.size,
        sha256=inspection.sha256,
        content_type=content_type,
        extension=extension,
        rating=post["rating"],
        author=post["author"],
        tags=tuple(post["tags"]),
        created_at=post["created_at"],
    )


def verify_local_download(
    media_path: str,
    *,
    output_dir: str | None = None,
    stop_event: threading.Event | None = None,
) -> LocalMediaVerification:
    """Fully revalidate one first-level local download without modifying it.

    The schema-2 sidecar is treated as untrusted input.  This facade deliberately
    reuses the downloader's bounded sidecar parser, no-follow file opening,
    streaming hashes, media signature resolver, and post-read identity check.
    """

    cancellation = stop_event or threading.Event()
    if cancellation.is_set():
        raise CancelledError("本地校验已取消")
    try:
        raw_path = os.fspath(media_path)
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError("empty path")
        absolute_path = os.path.abspath(raw_path)
        root = os.path.abspath(
            os.fspath(output_dir)
            if output_dir is not None
            else os.path.dirname(absolute_path)
        )
        if not root:
            raise ValueError("empty root")
        common = os.path.commonpath((root, absolute_path))
    except (OSError, TypeError, ValueError) as exc:
        raise LocalIntegrityError("本地媒体路径无效", status="unsafe_path") from exc
    if (
        os.path.normcase(common) != os.path.normcase(root)
        or os.path.normcase(os.path.dirname(absolute_path)) != os.path.normcase(root)
    ):
        raise LocalIntegrityError(
            "本地媒体必须位于下载目录第一层", status="unsafe_path"
        )

    filename = os.path.basename(absolute_path)
    try:
        media_stat = _plain_file_stat(absolute_path, "本地媒体")
    except DownloadError as exc:
        raise LocalIntegrityError(
            str(exc), status=_local_access_status(exc, missing="missing_media")
        ) from exc
    metadata_path = absolute_path + ".json"
    try:
        metadata_stat = _plain_file_stat(metadata_path, "本地元数据")
    except DownloadError as exc:
        raise LocalMetadataError(
            str(exc), status=_local_access_status(exc, missing="missing_metadata")
        ) from exc
    if media_stat is None:
        raise LocalIntegrityError("本地媒体不存在", status="missing_media")
    if metadata_stat is None:
        raise LocalMetadataError("缺少本地元数据", status="missing_metadata")
    if media_stat.st_size <= 0:
        raise LocalIntegrityError("本地媒体为空")
    if media_stat.st_size > MAX_MEDIA_BYTES:
        raise LocalIntegrityError("本地媒体超过 50 GiB 安全上限")
    try:
        payload = _load_metadata_sidecar(metadata_path)
    except DownloadError as exc:
        raise LocalMetadataError(
            str(exc), status=_local_access_status(exc, missing="missing_metadata")
        ) from exc
    if payload is None:
        raise LocalMetadataError("本地元数据格式无效")
    binding = _validate_local_filename_binding(filename, payload)

    try:
        inspection = _inspect_media_file(absolute_path, cancellation)
    except CancelledError:
        raise
    except DownloadError as exc:
        raise LocalIntegrityError(
            str(exc), status=_local_access_status(exc, missing="missing_media")
        ) from exc
    if cancellation.is_set():
        raise CancelledError("本地校验已取消")
    post_id, variant, extension = binding
    content_type = _validate_local_media_pair(
        filename, payload, inspection, binding
    )
    post = payload["post"]
    try:
        _assert_inspection_identity(absolute_path, inspection, "本地媒体")
    except DownloadError as exc:
        raise LocalIntegrityError(
            str(exc), checked_bytes=inspection.size
        ) from exc

    if cancellation.is_set():
        raise CancelledError("本地校验已取消")
    try:
        refreshed_payload = _load_metadata_sidecar(metadata_path)
        current_metadata = _plain_file_stat(metadata_path, "本地元数据")
    except DownloadError as exc:
        raise LocalIntegrityError(
            str(exc),
            status=_local_access_status(exc, missing="missing_metadata"),
            checked_bytes=inspection.size,
        ) from exc
    if current_metadata is None:
        raise LocalIntegrityError(
            "本地元数据在校验期间被删除",
            status="missing_metadata",
            checked_bytes=inspection.size,
        )
    if not _same_file_identity(metadata_stat, current_metadata):
        raise LocalIntegrityError(
            "本地元数据在校验期间被替换",
            status="unsafe_path",
            checked_bytes=inspection.size,
        )
    if refreshed_payload is None:
        raise LocalIntegrityError(
            "本地元数据在校验期间变为无效格式",
            status="invalid_metadata",
            checked_bytes=inspection.size,
        )
    if (
        current_metadata.st_size != metadata_stat.st_size
        or getattr(current_metadata, "st_mtime_ns", 0)
        != getattr(metadata_stat, "st_mtime_ns", 0)
        or refreshed_payload != payload
    ):
        raise LocalIntegrityError(
            "本地元数据在校验期间发生变化",
            status="changed",
            checked_bytes=inspection.size,
        )

    if cancellation.is_set():
        raise CancelledError("本地校验已取消")
    return LocalMediaVerification(
        post_id=post_id,
        variant=variant,
        file_path=absolute_path,
        relative_path=filename,
        size=inspection.size,
        sha256=inspection.sha256,
        content_type=content_type,
        extension=extension,
        rating=post["rating"],
        author=post["author"],
        tags=tuple(post["tags"]),
        created_at=post["created_at"],
    )


def _commit_file_no_replace(source: str, destination: str) -> None:
    """Atomically create *destination* without replacing an existing path."""

    if os.name == "nt":
        # MoveFileW, which backs os.rename on Windows, is atomic within the
        # volume and fails when the destination exists.  Unlike os.replace it
        # never carries MOVEFILE_REPLACE_EXISTING.
        os.rename(source, destination)
        return
    # Tests and source runs on POSIX still retain no-clobber semantics.  Both
    # paths are in the same directory/volume, so link creation is atomic.
    os.link(source, destination)
    os.unlink(source)


def _remove_compatible_part_state(path: str, *, expected: _PartState) -> None:
    state = _load_part_state(path)
    if state != expected:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError:
        # The media is already committed.  A leftover state is harmless and
        # is preferable to deleting a path whose identity became uncertain.
        return


def _remove_quietly(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


__all__ = [
    "DownloadError",
    "DownloadResult",
    "LOCAL_MEDIA_EXTENSIONS",
    "LocalIntegrityError",
    "LocalMediaVerification",
    "LocalMetadataError",
    "MAX_MEDIA_BYTES",
    "MediaAccessDeniedError",
    "MediaDownloader",
    "verify_local_download",
    "verify_bound_local_download",
]
