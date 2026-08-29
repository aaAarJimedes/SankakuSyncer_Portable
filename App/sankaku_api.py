# -*- coding: utf-8 -*-
"""Restricted Sankaku API client used by search, login, and downloads."""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import json
import random
import threading
import time
from collections.abc import Mapping
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

from http_transport import Response, Session, TransportError
from sankaku_url_policy import (
    normalize_media_url,
    normalize_post_id,
    normalize_tag_query,
)
from version import HTTP_USER_AGENT


API_ROOT = "https://sankakuapi.com"
API_HOST = "sankakuapi.com"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_TAGS_PER_POST = 500
_GLOBAL_API_REQUEST_LOCK = threading.Lock()
_GLOBAL_API_NEXT_START = 0.0


class SankakuAPIError(RuntimeError):
    """Base API failure whose message is safe to display."""


class AuthenticationError(SankakuAPIError):
    """Credentials or access token were rejected."""


class AccessDeniedError(SankakuAPIError):
    """The current account cannot access one requested resource."""


class RateLimitError(SankakuAPIError):
    """The remote service requested a longer cooldown."""


class CancelledError(SankakuAPIError):
    """The caller cancelled a pending request or cooldown."""


@dataclass(frozen=True, slots=True)
class SankakuPost:
    post_id: str
    rating: str
    status: str
    width: int
    height: int
    file_type: str
    file_ext: str
    file_size: int
    preview_url: str
    sample_url: str
    file_url: str
    tag_names: tuple[str, ...]
    author: str
    created_at: str
    md5: str
    is_premium: bool

    @classmethod
    def from_payload(cls, payload: object) -> "SankakuPost":
        if not isinstance(payload, dict):
            raise SankakuAPIError("站点返回了无效作品数据")
        post_id = normalize_post_id(payload.get("id"))
        if post_id is None:
            raise SankakuAPIError("站点返回了无效作品编号")
        rating = payload.get("rating")
        if rating not in {"s", "q", "e"}:
            rating = ""
        status = payload.get("status") if isinstance(payload.get("status"), str) else ""
        width = _bounded_int(payload.get("width"), 0, 1_000_000)
        height = _bounded_int(payload.get("height"), 0, 1_000_000)
        file_size = _bounded_int(payload.get("file_size"), 0, 1024**4)
        file_type = _bounded_text(payload.get("file_type"), 255)
        file_ext = _bounded_text(payload.get("file_ext"), 32).lstrip(".").lower()
        preview_url = normalize_media_url(payload.get("preview_url")) or ""
        sample_url = normalize_media_url(payload.get("sample_url")) or ""
        file_url = normalize_media_url(payload.get("file_url")) or ""
        raw_tags = payload.get("tag_names")
        tags: list[str] = []
        if isinstance(raw_tags, list):
            for value in raw_tags[:MAX_TAGS_PER_POST]:
                tag = _bounded_text(value, 500)
                if tag:
                    tags.append(tag)
        author_payload = payload.get("author")
        author = ""
        if isinstance(author_payload, dict):
            author = _bounded_text(
                author_payload.get("display_name") or author_payload.get("name"), 500
            )
        created = payload.get("created_at")
        if isinstance(created, dict):
            created = created.get("s")
        created_at = _bounded_text(created, 100)
        md5 = _bounded_text(payload.get("md5"), 64).lower()
        if md5 and (len(md5) != 32 or any(char not in "0123456789abcdef" for char in md5)):
            md5 = ""
        return cls(
            post_id=post_id,
            rating=rating,
            status=status,
            width=width,
            height=height,
            file_type=file_type,
            file_ext=file_ext,
            file_size=file_size,
            preview_url=preview_url,
            sample_url=sample_url,
            file_url=file_url,
            tag_names=tuple(tags),
            author=author,
            created_at=created_at,
            md5=md5,
            is_premium=bool(payload.get("is_premium")),
        )

    def best_media_url(self, prefer_original: bool = True) -> str:
        candidates = (
            (self.file_url, self.sample_url, self.preview_url)
            if prefer_original
            else (self.sample_url, self.file_url, self.preview_url)
        )
        return next((url for url in candidates if url), "")


@dataclass(frozen=True, slots=True)
class SearchPage:
    posts: tuple[SankakuPost, ...]
    next_cursor: str
    previous_cursor: str


def _bounded_text(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        return ""
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        return ""
    return value


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        return 0
    return value


def _rating_tag(rating: str) -> str:
    return {
        "s": "rating:safe",
        "q": "rating:questionable",
        "e": "rating:explicit",
        "all": "",
    }.get(rating, "rating:safe")


class SankakuAPI:
    """Small allowlisted client for Sankaku's read APIs and token login."""

    def __init__(
        self,
        *,
        access_token: str = "",
        request_delay: float = 3.0,
        timeout: int = 30,
        max_retries: int = 4,
        proxy: str = "",
        stop_event: threading.Event | None = None,
        session_factory: Callable[[], Session] = Session,
    ) -> None:
        if not 0.5 <= float(request_delay) <= 30.0:
            raise ValueError("request_delay out of range")
        if not 5 <= int(timeout) <= 180:
            raise ValueError("timeout out of range")
        if not 0 <= int(max_retries) <= 10:
            raise ValueError("max_retries out of range")
        self.request_delay = float(request_delay)
        self.timeout = int(timeout)
        self.max_retries = int(max_retries)
        self.proxy = proxy
        self.stop_event = stop_event or threading.Event()
        self._access_token = ""
        self._session = session_factory()
        self._session.trust_env = False
        self._session.headers.update(
            {
                "Accept": "application/vnd.sankaku.api+json;v=2",
                "User-Agent": HTTP_USER_AGENT,
            }
        )
        if proxy:
            configure_proxy = getattr(self._session, "configure_proxy", None)
            if not callable(configure_proxy):
                raise ValueError("session factory cannot configure an explicit proxy")
            configure_proxy(proxy)
        self.set_access_token(access_token)

    @property
    def access_token(self) -> str:
        return self._access_token

    def set_access_token(self, value: str) -> None:
        if not isinstance(value, str) or len(value) > 128 * 1024:
            raise ValueError("invalid access token")
        if any(ord(char) < 33 or ord(char) == 127 for char in value):
            if value:
                raise ValueError("invalid access token")
        self._access_token = value

    def close(self) -> None:
        self._session.close()

    def authenticate(self, username: str, password: str) -> str:
        if not isinstance(username, str) or not username or len(username) > 320:
            raise AuthenticationError("用户名格式无效")
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise AuthenticationError("密码格式无效")
        if any(ord(char) < 32 or ord(char) == 127 for char in username + password):
            raise AuthenticationError("登录信息格式无效")

        payload = self._request_json(
            "POST",
            "/auth/token",
            json_body={"login": username, "password": password},
            authenticated=False,
            retryable=False,
        )
        if not isinstance(payload, dict) or not payload.get("success"):
            raise AuthenticationError("登录失败，请核对账号、密码或站点验证状态")
        token = payload.get("access_token")
        if not isinstance(token, str) or not token or len(token) > 128 * 1024:
            raise AuthenticationError("登录成功但站点未返回有效令牌")
        if any(ord(char) < 33 or ord(char) == 127 for char in token):
            raise AuthenticationError("站点返回了无效令牌")
        self.set_access_token(token)
        return token

    def search_posts(
        self,
        tags: str = "",
        *,
        rating: str = "s",
        cursor: str = "",
        limit: int = 24,
        language: str = "zh-CN",
    ) -> SearchPage:
        normalized_tags = normalize_tag_query(tags)
        if normalized_tags is None:
            raise SankakuAPIError("标签表达式过长或包含不可见字符")
        if type(limit) is not int or not 1 <= limit <= 40:
            raise SankakuAPIError("每页数量必须为 1–40")
        if cursor and (
            not isinstance(cursor, str)
            or len(cursor) > 1024
            or any(not (char.isalnum() or char in "-_") for char in cursor)
        ):
            raise SankakuAPIError("分页标记无效")
        rating_filter = _rating_tag(rating)
        query = " ".join(part for part in (normalized_tags, rating_filter) if part).strip()
        params: dict[str, object] = {
            "lang": language if language in {"zh-CN", "en", "ja"} else "zh-CN",
            "limit": limit,
            "tags": query,
        }
        if cursor:
            params["next"] = cursor
        payload = self._request_json("GET", "/v2/posts/keyset", params=params)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise SankakuAPIError("站点返回了无效搜索结果")
        posts = _parse_posts(payload["data"])
        meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
        next_cursor = _bounded_text(meta.get("next"), 1024)
        previous_cursor = _bounded_text(meta.get("prev"), 1024)
        return SearchPage(posts=posts, next_cursor=next_cursor, previous_cursor=previous_cursor)

    def get_post(self, post_id: str, *, language: str = "zh-CN") -> SankakuPost:
        normalized = normalize_post_id(post_id)
        if normalized is None:
            raise SankakuAPIError("作品编号无效")
        prefix = "md5:" if len(normalized) == 32 and all(
            char in "0123456789abcdefABCDEF" for char in normalized
        ) else "id_range:"
        payload = self._request_json(
            "GET",
            "/v2/posts",
            params={
                "lang": language if language in {"zh-CN", "en", "ja"} else "zh-CN",
                "page": 1,
                "limit": 1,
                "tags": prefix + normalized,
            },
        )
        items = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(items, list) or not items:
            raise SankakuAPIError("没有找到该作品，或当前账号无权访问")
        post = SankakuPost.from_payload(items[0])
        if post.post_id != normalized and prefix == "id_range:":
            raise SankakuAPIError("站点返回了不匹配的作品")
        return post

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        authenticated: bool = True,
        retryable: bool = True,
    ):
        if not isinstance(path, str) or not path.startswith("/") or "\\" in path:
            raise SankakuAPIError("无效 API 路径")
        url = urljoin(API_ROOT + "/", path.lstrip("/"))
        if urlsplit(url).hostname != API_HOST or not url.startswith(API_ROOT + "/"):
            raise SankakuAPIError("API 地址越界")

        retry_limit = self.max_retries if retryable else 0
        for attempt in range(retry_limit + 1):
            if self.stop_event.is_set():
                raise CancelledError("操作已取消")
            # JSON responses are small and bounded.  Refuse transport
            # compression so a hostile peer cannot make the native stack or
            # application inflate bytes before our application-level limit.
            headers = {"Accept-Encoding": "identity"}
            if authenticated and self._access_token:
                headers["Authorization"] = "Bearer " + self._access_token
            try:
                self._acquire_global_request_lock()
                try:
                    self._wait_for_request_slot()
                    if self.stop_event.is_set():
                        raise CancelledError("操作已取消")
                    response = self._session.request(
                        method,
                        url,
                        params=params,
                        json=json_body,
                        headers=headers,
                        timeout=(min(15, self.timeout), self.timeout),
                        allow_redirects=False,
                        stream=True,
                    )
                    response_wait_seconds: float | None = None
                    if response.status_code == 429:
                        response_wait_seconds = _retry_after_seconds(response.headers)
                        _defer_global_api_requests_locked(response_wait_seconds)
                    elif response.status_code in {408, 500, 502, 503, 504}:
                        response_wait_seconds = _retry_after_seconds(
                            response.headers, default=0.0
                        )
                        if response_wait_seconds:
                            _defer_global_api_requests_locked(response_wait_seconds)
                finally:
                    _GLOBAL_API_REQUEST_LOCK.release()
            except TransportError as exc:
                if attempt >= retry_limit:
                    raise SankakuAPIError(
                        f"网络请求失败（{type(exc).__name__}）"
                    ) from exc
                self._backoff(attempt)
                continue

            try:
                if response.is_redirect:
                    raise SankakuAPIError("API 返回了意外跳转")
                if response.status_code == 401 or (
                    response.status_code == 403 and path == "/auth/token"
                ):
                    raise AuthenticationError("登录已失效或当前账号无权访问")
                if response.status_code == 403:
                    raise AccessDeniedError("当前账号无权访问该资源")
                if response.status_code == 429:
                    wait_seconds = response_wait_seconds
                    if wait_seconds is None:
                        wait_seconds = _retry_after_seconds(response.headers)
                    if wait_seconds > 600:
                        raise RateLimitError(
                            "站点要求较长冷却，已停止本批次；请稍后手动重试"
                        )
                    if attempt >= retry_limit:
                        raise RateLimitError("站点请求过于频繁，请稍后再试")
                    self._interruptible_wait(wait_seconds)
                    continue
                if response.status_code in {408, 500, 502, 503, 504}:
                    if attempt >= retry_limit:
                        raise SankakuAPIError(f"站点暂时不可用（HTTP {response.status_code}）")
                    wait_seconds = response_wait_seconds
                    if wait_seconds is None:
                        wait_seconds = _retry_after_seconds(
                            response.headers, default=0.0
                        )
                    if wait_seconds:
                        if wait_seconds > 600:
                            raise RateLimitError(
                                "站点要求较长冷却，已停止本批次；请稍后手动重试"
                            )
                        self._interruptible_wait(wait_seconds)
                    else:
                        self._backoff(attempt)
                    continue
                if response.status_code == 404:
                    raise SankakuAPIError("请求的资源不存在")
                if not 200 <= response.status_code < 300:
                    raise SankakuAPIError(f"站点请求失败（HTTP {response.status_code}）")
                content_encoding = response.headers.get("Content-Encoding", "")
                if (
                    not isinstance(content_encoding, str)
                    or content_encoding.strip().casefold() not in {"", "identity"}
                ):
                    raise SankakuAPIError("站点响应使用了不安全的压缩编码")
                content_type = response.headers.get("Content-Type", "").lower()
                if "json" not in content_type:
                    raise SankakuAPIError("站点返回了非 JSON 内容")
                try:
                    raw = _read_bounded_body(response, MAX_JSON_BYTES)
                    return json.loads(raw.decode("utf-8-sig"))
                except TransportError as exc:
                    raise SankakuAPIError(
                        f"读取站点响应失败（{type(exc).__name__}）"
                    ) from exc
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise SankakuAPIError("站点返回了损坏的 JSON") from exc
            finally:
                response.close()
        raise SankakuAPIError("请求重试次数已用尽")

    def _wait_for_request_slot(self) -> None:
        global _GLOBAL_API_NEXT_START
        while True:
            if self.stop_event.is_set():
                raise CancelledError("操作已取消")
            delay = _GLOBAL_API_NEXT_START - time.monotonic()
            if delay <= 0:
                _GLOBAL_API_NEXT_START = time.monotonic() + self.request_delay
                return
            # One interruptible wait is deliberately capped at 600 seconds.
            # Recompute until the shared deadline is actually reached so a
            # long Retry-After cannot be shortened or overwritten.
            self._interruptible_wait(delay)

    def _acquire_global_request_lock(self) -> None:
        while not _GLOBAL_API_REQUEST_LOCK.acquire(timeout=0.2):
            if self.stop_event.is_set():
                raise CancelledError("操作已取消")

    def _backoff(self, attempt: int) -> None:
        seconds = min(30.0, (2**attempt) + random.uniform(0.0, 0.5))
        self._interruptible_wait(seconds)

    def _interruptible_wait(self, seconds: float) -> None:
        if self.stop_event.wait(max(0.0, min(float(seconds), 600.0))):
            raise CancelledError("操作已取消")


def _parse_posts(items: Iterable[object]) -> tuple[SankakuPost, ...]:
    posts: list[SankakuPost] = []
    for item in items:
        try:
            posts.append(SankakuPost.from_payload(item))
        except SankakuAPIError:
            continue
    return tuple(posts)


def _read_bounded_body(response: Response, limit: int) -> bytes:
    declared = response.headers.get("Content-Length", "")
    if declared:
        try:
            declared_length = int(declared)
            if declared_length < 0:
                raise ValueError
            if declared_length > limit:
                raise SankakuAPIError("站点响应过大，已停止处理")
        except ValueError:
            raise SankakuAPIError("站点返回了无效长度")
    iterator = getattr(response, "iter_content", None)
    if not callable(iterator):
        data = bytes(response.content)
        if len(data) > limit:
            raise SankakuAPIError("站点响应过大，已停止处理")
        return data
    body = bytearray()
    for chunk in iterator(64 * 1024):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > limit:
            raise SankakuAPIError("站点响应过大，已停止处理")
    return bytes(body)


def _retry_after_seconds(headers: Mapping[str, str], default: float = 600.0) -> float:
    value = headers.get("Retry-After")
    if value:
        try:
            return max(0.0, min(float(value), 86_400.0))
        except ValueError:
            try:
                target = parsedate_to_datetime(value).timestamp()
                return max(0.0, min(target - time.time(), 86_400.0))
            except (TypeError, ValueError, OverflowError):
                pass
    reset = headers.get("X-RateLimit-Reset")
    if reset:
        try:
            return max(0.0, min(float(reset) - time.time(), 86_400.0))
        except ValueError:
            pass
    return max(0.0, min(default, 86_400.0))


def _defer_global_api_requests_locked(seconds: float) -> None:
    """Extend the process-wide API deadline while its request lock is held."""
    global _GLOBAL_API_NEXT_START
    delay = max(0.0, min(float(seconds), 86_400.0))
    _GLOBAL_API_NEXT_START = max(
        _GLOBAL_API_NEXT_START,
        time.monotonic() + delay,
    )


__all__ = [
    "API_ROOT",
    "AccessDeniedError",
    "AuthenticationError",
    "CancelledError",
    "RateLimitError",
    "SankakuAPI",
    "SankakuAPIError",
    "SankakuPost",
    "SearchPage",
]
