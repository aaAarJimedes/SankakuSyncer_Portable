# -*- coding: utf-8 -*-
"""Deterministic, fully offline tests for :mod:`sankaku_api`."""

from __future__ import annotations

import json
import threading
import unittest
from unittest import mock

import sankaku_api as sankaku_api_module
from http_transport import TransportError

from sankaku_api import (
    API_ROOT,
    AuthenticationError,
    CancelledError,
    RateLimitError,
    SankakuAPI,
    SankakuAPIError,
)


_UNSET = object()


class FakeResponse:
    """The small ``requests.Response`` surface used by ``SankakuAPI``."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        payload: object = _UNSET,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        json_error: Exception | None = None,
        chunks: list[bytes] | None = None,
        stream_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self._json_error = json_error
        self.headers = {"Content-Type": "application/json; charset=utf-8"}
        if headers:
            self.headers.update(headers)
        if content is None:
            if payload is _UNSET:
                content = b"{}"
            else:
                content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.content = content
        self._chunks = chunks
        self._stream_error = stream_error
        self.closed = False

    @property
    def is_redirect(self) -> bool:
        return self.status_code in {301, 302, 303, 307, 308} and bool(
            self.headers.get("Location")
        )

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        if self._payload is _UNSET:
            return json.loads(self.content.decode("utf-8"))
        return self._payload

    def iter_content(self, chunk_size: int = 1):
        if self._stream_error is not None:
            raise self._stream_error
        if self._chunks is not None:
            yield from self._chunks
            return
        for offset in range(0, len(self.content), max(1, chunk_size)):
            yield self.content[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Queue-backed session that fails instead of reaching the network."""

    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []
        self.headers: dict[str, str] = {}
        self.proxies: dict[str, str] = {}
        self.trust_env = True
        self.closed = False

    def request(self, method: str, url: str, **kwargs) -> FakeResponse:
        self.requests.append({"method": method, "url": url, "kwargs": kwargs})
        if not self.responses:
            raise AssertionError("fake session exhausted; live network is forbidden")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def close(self) -> None:
        self.closed = True


def _post_payload(post_id: str = "Post_1") -> dict[str, object]:
    return {
        "id": post_id,
        "rating": "s",
        "status": "active",
        "width": 1200,
        "height": 800,
        "file_type": "image/jpeg",
        "file_ext": "jpg",
        "file_size": 6,
        "preview_url": "https://cs.sankakucomplex.com/data/preview.jpg",
        "sample_url": "https://cs.sankakucomplex.com/data/sample.jpg",
        "file_url": "https://cs.sankakucomplex.com/data/original.jpg?e=1&m=sig",
        "tag_names": ["cat", "blue_eyes"],
        "author": {"name": "artist"},
        "created_at": {"s": "1700000000"},
        "md5": "0123456789abcdef0123456789abcdef",
        "is_premium": False,
    }


class SankakuAPIOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        previous = sankaku_api_module._GLOBAL_API_NEXT_START
        sankaku_api_module._GLOBAL_API_NEXT_START = 0.0
        self.addCleanup(
            setattr,
            sankaku_api_module,
            "_GLOBAL_API_NEXT_START",
            previous,
        )

    def _client(
        self,
        *responses: FakeResponse | Exception,
        access_token: str = "",
        max_retries: int = 0,
        stop_event: threading.Event | None = None,
    ) -> tuple[SankakuAPI, FakeSession]:
        session = FakeSession(list(responses))
        client = SankakuAPI(
            access_token=access_token,
            request_delay=0.5,
            timeout=5,
            max_retries=max_retries,
            stop_event=stop_event,
            session_factory=lambda: session,
        )
        # Rate-pacing itself is covered by production policy; replacing the wait
        # keeps this regression suite instant and deterministic.
        client._wait_for_request_slot = lambda: None
        self.addCleanup(client.close)
        return client, session

    def test_authenticate_stores_token_without_putting_credentials_in_url_or_headers(self):
        response = FakeResponse(payload={"success": True, "access_token": "TOKEN_123"})
        client, session = self._client(response)

        token = client.authenticate("user@example.test", "correct horse battery staple")

        self.assertEqual(token, "TOKEN_123")
        self.assertEqual(client.access_token, "TOKEN_123")
        self.assertTrue(response.closed)
        self.assertFalse(session.trust_env)
        self.assertNotIn("Origin", session.headers)
        call = session.requests[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], API_ROOT + "/auth/token")
        kwargs = call["kwargs"]
        self.assertEqual(
            kwargs["json"],
            {"login": "user@example.test", "password": "correct horse battery staple"},
        )
        self.assertEqual(kwargs["headers"], {"Accept-Encoding": "identity"})
        self.assertNotIn("user@example.test", call["url"])
        self.assertNotIn("correct horse", call["url"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])

    def test_authenticate_does_not_replay_password_post_after_network_failure(self):
        failure = TransportError("offline")
        unused_success = FakeResponse(
            payload={"success": True, "access_token": "MUST_NOT_BE_USED"}
        )
        client, session = self._client(failure, unused_success, max_retries=4)

        with self.assertRaisesRegex(SankakuAPIError, "网络请求失败"):
            client.authenticate("user@example.test", "secret")

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])

    def test_search_uses_keyset_cursor_and_parses_page(self):
        response = FakeResponse(
            payload={
                "data": [_post_payload("Keyset_7")],
                "meta": {"next": "next_ABC-123", "prev": "prev_1"},
            }
        )
        client, session = self._client(response, access_token="ACCESS_TOKEN")

        page = client.search_posts(
            "cat blue_eyes", rating="s", cursor="cursor_1", limit=2, language="en"
        )

        self.assertEqual([post.post_id for post in page.posts], ["Keyset_7"])
        self.assertEqual(page.next_cursor, "next_ABC-123")
        self.assertEqual(page.previous_cursor, "prev_1")
        self.assertEqual(page.posts[0].tag_names, ("cat", "blue_eyes"))
        call = session.requests[0]
        self.assertEqual(call["method"], "GET")
        self.assertEqual(call["url"], API_ROOT + "/v2/posts/keyset")
        self.assertEqual(
            call["kwargs"]["params"],
            {
                "lang": "en",
                "limit": 2,
                "tags": "cat blue_eyes rating:safe",
                "next": "cursor_1",
            },
        )
        self.assertEqual(
            call["kwargs"]["headers"],
            {
                "Accept-Encoding": "identity",
                "Authorization": "Bearer ACCESS_TOKEN",
            },
        )
        self.assertTrue(response.closed)

    def test_get_post_queries_exact_id_and_parses_single_result(self):
        response = FakeResponse(payload=[_post_payload("Post_1")])
        client, session = self._client(response)

        post = client.get_post("Post_1", language="ja")

        self.assertEqual(post.post_id, "Post_1")
        self.assertEqual(post.best_media_url(), _post_payload("Post_1")["file_url"])
        self.assertEqual(
            session.requests[0]["kwargs"]["params"],
            {
                "lang": "ja",
                "page": 1,
                "limit": 1,
                "tags": "id_range:Post_1",
            },
        )
        self.assertTrue(response.closed)

    def test_401_is_authentication_error_and_response_is_closed(self):
        response = FakeResponse(status_code=401, payload={"error": "unauthorized"})
        client, _session = self._client(response, access_token="DO_NOT_LEAK")

        with self.assertRaises(AuthenticationError) as raised:
            client.search_posts("cat")

        self.assertNotIn("DO_NOT_LEAK", str(raised.exception))
        self.assertTrue(response.closed)

    def test_429_honors_retry_after_then_raises_when_retries_are_exhausted(self):
        first = FakeResponse(status_code=429, headers={"Retry-After": "7"})
        second = FakeResponse(status_code=429, headers={"Retry-After": "9"})
        client, session = self._client(first, second, max_retries=1)
        waits: list[float] = []
        client._interruptible_wait = waits.append

        with self.assertRaises(RateLimitError):
            client.search_posts("cat")

        self.assertEqual(waits, [7.0])
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_429_defers_other_api_clients_process_wide(self):
        limited = FakeResponse(status_code=429, headers={"Retry-After": "30"})
        first_session = FakeSession([limited])
        first = SankakuAPI(
            request_delay=0.5,
            timeout=5,
            max_retries=0,
            session_factory=lambda: first_session,
        )
        self.addCleanup(first.close)

        success = FakeResponse(payload={"data": [], "meta": {}})
        second_session = FakeSession([success])
        second = SankakuAPI(
            request_delay=0.5,
            timeout=5,
            max_retries=0,
            session_factory=lambda: second_session,
        )
        self.addCleanup(second.close)
        second_waits: list[float] = []
        second._interruptible_wait = second_waits.append

        # First request starts at t=100 and records the 30-second server
        # cooldown before releasing the process-wide request lock.  The other
        # client reaches the gate at t=101 and must honor the remaining 29s.
        with mock.patch(
            "sankaku_api.time.monotonic",
            side_effect=[100.0, 100.0, 100.0, 101.0, 130.0, 130.0],
        ):
            with self.assertRaises(RateLimitError):
                first.search_posts("cat")
            page = second.search_posts("cat")

        self.assertEqual(page.posts, ())
        self.assertEqual(second_waits, [29.0])
        self.assertEqual(len(first_session.requests), 1)
        self.assertEqual(len(second_session.requests), 1)

    def test_long_global_cooldown_is_recomputed_until_fully_elapsed(self):
        client, _session = self._client()
        # Exercise the real request-slot method instead of the no-wait helper
        # installed by _client().
        client._wait_for_request_slot = SankakuAPI._wait_for_request_slot.__get__(
            client, SankakuAPI
        )
        now = [0.0]
        waits: list[float] = []

        def capped_wait(requested: float) -> None:
            waits.append(requested)
            now[0] += min(requested, 600.0)

        client._interruptible_wait = capped_wait
        sankaku_api_module._GLOBAL_API_NEXT_START = 1_001.0
        with mock.patch("sankaku_api.time.monotonic", side_effect=lambda: now[0]):
            client._wait_for_request_slot()

        self.assertEqual(waits, [1_001.0, 401.0])
        self.assertEqual(sankaku_api_module._GLOBAL_API_NEXT_START, 1_001.5)

    def test_redirect_is_never_followed(self):
        response = FakeResponse(
            status_code=302,
            headers={
                "Content-Type": "text/html",
                "Location": "https://login.sankakucomplex.com/login",
            },
            content=b"redirect",
        )
        client, session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "意外跳转"):
            client.search_posts("cat")

        self.assertEqual(len(session.requests), 1)
        self.assertFalse(session.requests[0]["kwargs"]["allow_redirects"])
        self.assertTrue(response.closed)

    def test_damaged_json_is_rejected(self):
        response = FakeResponse(
            content=b'{"data": [',
            json_error=ValueError("truncated JSON"),
        )
        client, _session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "损坏的 JSON"):
            client.search_posts("cat")

        self.assertTrue(response.closed)

    def test_html_response_is_rejected_before_parsing(self):
        response = FakeResponse(
            headers={"Content-Type": "text/html; charset=utf-8"},
            content=b"<html><title>Login</title></html>",
        )
        client, _session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "非 JSON"):
            client.search_posts("cat")

        self.assertTrue(response.closed)

    def test_compressed_json_is_rejected_before_reading_body(self):
        response = FakeResponse(
            headers={"Content-Encoding": "gzip"},
            stream_error=AssertionError("compressed body must not be read"),
        )
        client, session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "压缩编码"):
            client.search_posts("cat")

        self.assertEqual(
            session.requests[0]["kwargs"]["headers"]["Accept-Encoding"],
            "identity",
        )
        self.assertTrue(response.closed)

    def test_declared_oversize_json_is_rejected_without_reading_body(self):
        response = FakeResponse(
            headers={"Content-Length": str(32 * 1024 * 1024 + 1)},
            stream_error=AssertionError("body must not be read"),
        )
        client, _session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "响应过大"):
            client.search_posts("cat")

        self.assertTrue(response.closed)

    def test_stream_failure_is_sanitized_and_response_is_closed(self):
        response = FakeResponse(
            stream_error=TransportError("signed URL must not leak")
        )
        client, _session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "读取站点响应失败") as raised:
            client.search_posts("cat")

        self.assertNotIn("signed URL", str(raised.exception))
        self.assertTrue(response.closed)

    def test_pre_cancelled_request_never_reaches_session(self):
        stop_event = threading.Event()
        stop_event.set()
        queued = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(queued, stop_event=stop_event)

        with self.assertRaises(CancelledError):
            client.search_posts("cat")

        self.assertEqual(session.requests, [])
        self.assertEqual(session.responses, [queued])


if __name__ == "__main__":
    unittest.main()
