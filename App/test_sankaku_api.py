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
    AccessDeniedError,
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

    def test_authenticate_does_not_replay_password_post_after_body_failure(self):
        response = FakeResponse(
            stream_error=TransportError("password-bearing response detail")
        )
        unused_success = FakeResponse(
            payload={"success": True, "access_token": "MUST_NOT_BE_USED"}
        )
        client, session = self._client(response, unused_success, max_retries=4)
        client._backoff = mock.Mock()

        with self.assertRaisesRegex(
            SankakuAPIError, "读取站点响应失败"
        ) as raised:
            client.authenticate("user@example.test", "secret")

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(response.closed)
        self.assertFalse(unused_success.closed)
        self.assertNotIn("password-bearing", str(raised.exception))
        client._backoff.assert_not_called()

    def test_post_is_never_replayed_even_if_retryable_is_not_disabled(self):
        response = FakeResponse(
            stream_error=TransportError("mutation response detail")
        )
        unused_success = FakeResponse(payload={"success": True})
        client, session = self._client(response, unused_success, max_retries=4)
        client._backoff = mock.Mock()

        with self.assertRaisesRegex(
            SankakuAPIError, "读取站点响应失败"
        ) as raised:
            client._request_json(
                "POST",
                "/v2/example-mutation",
                json_body={"value": "non-secret test value"},
                authenticated=False,
            )

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(response.closed)
        self.assertFalse(unused_success.closed)
        self.assertNotIn("mutation response detail", str(raised.exception))
        client._backoff.assert_not_called()

    def test_request_transport_failure_after_cancellation_is_not_retried(self):
        stop_event = threading.Event()
        unused_success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(
            unused_success,
            max_retries=4,
            stop_event=stop_event,
        )

        def cancelled_request(method: str, url: str, **kwargs):
            session.requests.append(
                {"method": method, "url": url, "kwargs": kwargs}
            )
            stop_event.set()
            raise TransportError("cancelled request detail")

        session.request = cancelled_request
        client._backoff = mock.Mock()

        with self.assertRaises(CancelledError) as raised:
            client.search_posts("cat")

        self.assertEqual(str(raised.exception), "操作已取消")
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        client._backoff.assert_not_called()

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

    def test_ordinary_403_is_per_item_access_denied_and_response_is_closed(self):
        response = FakeResponse(status_code=403, payload={"error": "forbidden"})
        client, _session = self._client(response, access_token="DO_NOT_LEAK")

        with self.assertRaises(AccessDeniedError) as raised:
            client.get_post("Post_1")

        self.assertNotIsInstance(raised.exception, AuthenticationError)
        self.assertNotIn("DO_NOT_LEAK", str(raised.exception))
        self.assertTrue(response.closed)

    def test_authenticate_403_remains_authentication_error_without_replay(self):
        response = FakeResponse(status_code=403, payload={"error": "forbidden"})
        unused = FakeResponse(payload={"success": True, "access_token": "UNUSED"})
        client, session = self._client(response, unused, max_retries=4)

        with self.assertRaises(AuthenticationError):
            client.authenticate("user@example.test", "secret")

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused])
        self.assertTrue(response.closed)

    def test_429_honors_retry_after_then_raises_when_retries_are_exhausted(self):
        first = FakeResponse(status_code=429, headers={"Retry-After": "7"})
        second = FakeResponse(status_code=429, headers={"Retry-After": "9"})
        client, session = self._client(first, second, max_retries=1)
        waits: list[float] = []

        def record_wait(seconds: float) -> None:
            self.assertTrue(first.closed)
            waits.append(seconds)

        client._interruptible_wait = record_wait

        with self.assertRaises(RateLimitError):
            client.search_posts("cat")

        self.assertEqual(waits, [7.0])
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_non_finite_retry_after_uses_valid_reset_for_wait_and_global_gate(self):
        limited = FakeResponse(
            status_code=429,
            headers={
                "Retry-After": "NaN",
                "X-RateLimit-Reset": "1030",
            },
        )
        success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(limited, success, max_retries=1)
        waits: list[float] = []
        client._interruptible_wait = waits.append

        with (
            mock.patch("request_gate.time.time", return_value=1_000.0),
            mock.patch("sankaku_api.time.monotonic", return_value=50.0),
        ):
            page = client.search_posts("cat")

        self.assertEqual(page.posts, ())
        self.assertEqual(waits, [30.0])
        self.assertEqual(sankaku_api_module._GLOBAL_API_NEXT_START, 80.0)
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(limited.closed)
        self.assertTrue(success.closed)

    def test_transient_server_failure_closes_response_before_backoff(self):
        unavailable = FakeResponse(status_code=503)
        success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(unavailable, success, max_retries=1)
        backoffs: list[int] = []

        def record_backoff(attempt: int) -> None:
            self.assertTrue(unavailable.closed)
            backoffs.append(attempt)

        client._backoff = record_backoff

        page = client.search_posts("cat")

        self.assertEqual(page.posts, ())
        self.assertEqual(backoffs, [0])
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(unavailable.closed)
        self.assertTrue(success.closed)

    def test_transient_server_retry_after_closes_response_before_wait(self):
        unavailable = FakeResponse(status_code=503, headers={"Retry-After": "3"})
        success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(unavailable, success, max_retries=1)
        waits: list[float] = []

        def record_wait(seconds: float) -> None:
            self.assertTrue(unavailable.closed)
            waits.append(seconds)

        client._interruptible_wait = record_wait

        page = client.search_posts("cat")

        self.assertEqual(page.posts, ())
        self.assertEqual(waits, [3.0])
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(unavailable.closed)
        self.assertTrue(success.closed)

    def test_retry_after_cancellation_closes_without_replaying(self):
        stop_event = threading.Event()
        limited = FakeResponse(status_code=429, headers={"Retry-After": "3"})
        unused_success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(
            limited,
            unused_success,
            max_retries=4,
            stop_event=stop_event,
        )

        def cancel_wait(_seconds: float) -> None:
            self.assertTrue(limited.closed)
            stop_event.set()
            raise CancelledError("操作已取消")

        client._interruptible_wait = cancel_wait

        with self.assertRaises(CancelledError):
            client.search_posts("cat")

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(limited.closed)
        self.assertFalse(unused_success.closed)

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

    def test_global_rate_limit_gate_rejects_non_finite_or_overflowing_values(self):
        sankaku_api_module._GLOBAL_API_NEXT_START = 123.0
        invalid_values = (
            float("nan"),
            float("inf"),
            float("-inf"),
            10**1000,
        )
        for value in invalid_values:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                sankaku_api_module._defer_global_api_requests_locked(value)
            self.assertEqual(sankaku_api_module._GLOBAL_API_NEXT_START, 123.0)

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
        for declared in (str(32 * 1024 * 1024 + 1), "9" * 5000):
            with self.subTest(size=len(declared)):
                response = FakeResponse(
                    headers={"Content-Length": declared},
                    stream_error=AssertionError("body must not be read"),
                )
                client, _session = self._client(response)

                with self.assertRaisesRegex(SankakuAPIError, "响应过大"):
                    client.search_posts("cat")

                self.assertTrue(response.closed)

    def test_exact_or_missing_json_content_length_is_accepted(self):
        for declared in (None, "exact"):
            with self.subTest(declared=declared):
                response = FakeResponse(
                    payload={"data": [], "meta": {"next": "ok"}},
                )
                if declared == "exact":
                    response.headers["Content-Length"] = str(len(response.content))
                client, _session = self._client(response)

                page = client.search_posts("cat")

                self.assertEqual(page.posts, ())
                self.assertEqual(page.next_cursor, "ok")
                self.assertTrue(response.closed)

    def test_json_content_length_must_be_strict_and_match_the_body(self):
        invalid_values = (
            "",
            "-1",
            "+1",
            " 1",
            "\N{FULLWIDTH DIGIT ONE}",
            "\N{SUPERSCRIPT TWO}",
        )
        for declared in invalid_values:
            with self.subTest(declared=declared[:20]):
                response = FakeResponse(payload={"data": [], "meta": {}})
                response.headers["Content-Length"] = declared
                client, session = self._client(response)

                with self.assertRaisesRegex(
                    SankakuAPIError, "读取站点响应失败"
                ) as raised:
                    client.search_posts("cat")

                self.assertNotIn("data", str(raised.exception))
                self.assertEqual(len(session.requests), 1)
                self.assertTrue(response.closed)

        for adjustment in (-1, 1):
            with self.subTest(adjustment=adjustment):
                response = FakeResponse(payload={"data": [], "meta": {}})
                response.headers["Content-Length"] = str(
                    len(response.content) + adjustment
                )
                client, session = self._client(response)

                with self.assertRaisesRegex(
                    SankakuAPIError, "读取站点响应失败"
                ):
                    client.search_posts("cat")

                self.assertEqual(len(session.requests), 1)
                self.assertTrue(response.closed)

    def test_json_content_length_mismatch_retries_only_replayable_get(self):
        broken = FakeResponse(payload={"data": [], "meta": {}})
        broken.headers["Content-Length"] = str(len(broken.content) + 1)
        success = FakeResponse(
            payload={"data": [_post_payload("Length_Retry")], "meta": {}}
        )
        success.headers["Content-Length"] = str(len(success.content))
        client, session = self._client(broken, success, max_retries=1)
        backoffs: list[int] = []
        client._backoff = backoffs.append

        page = client.search_posts("cat")

        self.assertEqual([post.post_id for post in page.posts], ["Length_Retry"])
        self.assertEqual(backoffs, [0])
        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "GET"],
        )
        self.assertTrue(broken.closed)
        self.assertTrue(success.closed)

    def test_json_content_length_mismatch_never_replays_password_post(self):
        broken = FakeResponse(
            payload={"success": True, "access_token": "MUST_NOT_BE_ACCEPTED"}
        )
        broken.headers["Content-Length"] = str(len(broken.content) + 1)
        unused_success = FakeResponse(
            payload={"success": True, "access_token": "MUST_NOT_BE_USED"}
        )
        client, session = self._client(broken, unused_success, max_retries=4)
        client._backoff = mock.Mock()

        with self.assertRaisesRegex(SankakuAPIError, "读取站点响应失败"):
            client.authenticate("user@example.test", "secret")

        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(broken.closed)
        self.assertFalse(unused_success.closed)
        client._backoff.assert_not_called()

    def test_stream_failure_is_sanitized_and_response_is_closed(self):
        response = FakeResponse(
            stream_error=TransportError("signed URL must not leak")
        )
        client, _session = self._client(response)

        with self.assertRaisesRegex(SankakuAPIError, "读取站点响应失败") as raised:
            client.search_posts("cat")

        self.assertNotIn("signed URL", str(raised.exception))
        self.assertTrue(response.closed)

    def test_stream_failure_retries_after_closing_replayable_response(self):
        broken = FakeResponse(
            stream_error=TransportError("signed URL must not leak")
        )
        success = FakeResponse(
            payload={
                "data": [_post_payload("Retried_Post")],
                "meta": {"next": "after_retry"},
            }
        )
        client, session = self._client(broken, success, max_retries=1)
        backoffs: list[int] = []

        def record_backoff(attempt: int) -> None:
            self.assertTrue(broken.closed)
            backoffs.append(attempt)

        client._backoff = record_backoff

        page = client.search_posts("cat")

        self.assertEqual([post.post_id for post in page.posts], ["Retried_Post"])
        self.assertEqual(page.next_cursor, "after_retry")
        self.assertEqual(backoffs, [0])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "GET"],
        )
        self.assertTrue(broken.closed)
        self.assertTrue(success.closed)
        self.assertEqual(session.responses, [])

    def test_stream_failure_stops_after_retry_budget_is_exhausted(self):
        first = FakeResponse(
            stream_error=TransportError("first signed URL must not leak")
        )
        second = FakeResponse(
            stream_error=TransportError("second signed URL must not leak")
        )
        client, session = self._client(first, second, max_retries=1)
        backoffs: list[int] = []
        client._backoff = backoffs.append

        with self.assertRaisesRegex(
            SankakuAPIError, "读取站点响应失败"
        ) as raised:
            client.search_posts("cat")

        self.assertEqual(backoffs, [0])
        self.assertEqual(len(session.requests), 2)
        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "GET"],
        )
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        self.assertEqual(session.responses, [])
        self.assertNotIn("signed URL", str(raised.exception))

    def test_stream_failure_after_cancellation_closes_without_retrying(self):
        stop_event = threading.Event()
        response = FakeResponse()
        unused_success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(
            response,
            unused_success,
            max_retries=4,
            stop_event=stop_event,
        )

        def cancelled_stream(_chunk_size: int = 1):
            stop_event.set()
            raise TransportError("cancelled body detail")
            yield b""  # pragma: no cover - makes this a generator

        response.iter_content = cancelled_stream
        client._backoff = mock.Mock()

        with self.assertRaises(CancelledError) as raised:
            client.search_posts("cat")

        self.assertEqual(str(raised.exception), "操作已取消")
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(response.closed)
        client._backoff.assert_not_called()

    def test_silent_stream_eof_after_cancellation_is_not_mislabeled_as_bad_json(self):
        stop_event = threading.Event()
        response = FakeResponse()
        unused_success = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(
            response,
            unused_success,
            max_retries=4,
            stop_event=stop_event,
        )

        def cancelled_stream(_chunk_size: int = 1):
            stop_event.set()
            return
            yield b""  # pragma: no cover - makes this a generator

        response.iter_content = cancelled_stream
        client._backoff = mock.Mock()

        with self.assertRaises(CancelledError) as raised:
            client.search_posts("cat")

        self.assertEqual(str(raised.exception), "操作已取消")
        self.assertEqual(len(session.requests), 1)
        self.assertEqual(session.responses, [unused_success])
        self.assertTrue(response.closed)
        self.assertFalse(unused_success.closed)
        client._backoff.assert_not_called()

    def test_json_parse_failure_after_cancellation_is_reported_as_cancelled(self):
        stop_event = threading.Event()
        response = FakeResponse(payload={"data": [], "meta": {}})
        client, session = self._client(response, stop_event=stop_event)

        def cancelled_parse(_raw: str):
            stop_event.set()
            raise ValueError("parser detail must not be shown")

        with mock.patch("sankaku_api.json.loads", side_effect=cancelled_parse):
            with self.assertRaises(CancelledError) as raised:
                client.search_posts("cat")

        self.assertEqual(str(raised.exception), "操作已取消")
        self.assertEqual(len(session.requests), 1)
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
