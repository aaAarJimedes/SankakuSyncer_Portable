# -*- coding: utf-8 -*-
"""Offline tests for the ctypes WinHTTP/Schannel transport."""

from __future__ import annotations

import os
import threading
import unittest
from unittest import mock

import http_transport as transport


class FakeBindings:
    """In-memory WinHTTP ABI substitute; it has no native/network path."""

    def __init__(
        self,
        *,
        statuses: list[int] | None = None,
        response_headers: list[dict[str, str]] | None = None,
        bodies: list[bytes] | None = None,
        global_pooling_supported: bool = True,
        fail_at: str = "",
    ) -> None:
        self.statuses = list(statuses or [200])
        self.header_queue = list(response_headers or [{}])
        self.body_queue = list(bodies or [b""])
        self.global_pooling_supported = global_pooling_supported
        self.fail_at = fail_at
        self.opens: list[tuple[str, str]] = []
        self.connections: list[tuple[object, str, int]] = []
        self.requests: list[dict[str, object]] = []
        self.options: list[tuple[object, int, object]] = []
        self.timeouts: list[tuple[object, tuple[int, int, int, int]]] = []
        self.sent: list[bytes] = []
        self.closed: list[object] = []
        self._next = 0
        self._current_body: dict[object, bytearray] = {}
        self._current_headers: dict[object, transport.CaseInsensitiveHeaders] = {}
        self._current_status: dict[object, int] = {}

    def open(self, user_agent: str, proxy: str) -> object:
        if self.fail_at == "open":
            raise transport.TransportError("offline fake failure")
        self.opens.append((user_agent, proxy))
        return "session"

    def connect(self, session: object, host: str, port: int) -> object:
        self.connections.append((session, host, port))
        return f"connection-{len(self.connections)}"

    def open_request(
        self, connection: object, method: str, target: str, *, secure: bool
    ) -> object:
        handle = f"request-{len(self.requests) + 1}"
        self.requests.append(
            {
                "handle": handle,
                "connection": connection,
                "method": method,
                "target": target,
                "secure": secure,
                "headers": transport.CaseInsensitiveHeaders(),
            }
        )
        index = self._next
        self._next += 1
        self._current_status[handle] = self.statuses[min(index, len(self.statuses) - 1)]
        headers = self.header_queue[min(index, len(self.header_queue) - 1)]
        self._current_headers[handle] = transport.CaseInsensitiveHeaders(headers)
        body = self.body_queue[min(index, len(self.body_queue) - 1)]
        self._current_body[handle] = bytearray(body)
        return handle

    def set_dword(self, handle: object, option: int, value: int) -> None:
        self.options.append((handle, option, value))

    def set_bool(self, handle: object, option: int, value: bool) -> None:
        if (
            option == transport.WINHTTP_OPTION_DISABLE_GLOBAL_POOLING
            and not self.global_pooling_supported
        ):
            raise transport.TransportError(
                "unsupported", winerror=transport.ERROR_WINHTTP_INVALID_OPTION
            )
        self.options.append((handle, option, value))

    def set_timeouts(self, handle: object, values: tuple[int, int, int, int]) -> None:
        self.timeouts.append((handle, values))

    def add_headers(
        self, request: object, headers: transport.CaseInsensitiveHeaders
    ) -> None:
        self.requests[-1]["headers"] = headers.copy()

    def send(self, _request: object, body: bytes) -> None:
        if self.fail_at == "send":
            raise transport.TransportError("offline fake failure")
        self.sent.append(body)

    def receive(self, _request: object) -> None:
        return None

    def status_code(self, request: object) -> int:
        return self._current_status[request]

    def response_headers(self, request: object) -> transport.CaseInsensitiveHeaders:
        return self._current_headers[request]

    def data_available(self, request: object) -> int:
        return len(self._current_body[request])

    def read(self, request: object, size: int) -> bytes:
        body = self._current_body[request]
        result = bytes(body[:size])
        del body[:size]
        return result

    def close(self, handle: object | None) -> None:
        if handle is not None:
            self.closed.append(handle)


class BlockingSendBindings(FakeBindings):
    """A fake whose send returns only after its request handle is closed."""

    def __init__(self) -> None:
        super().__init__()
        self.send_entered = threading.Event()
        self.request_closed = threading.Event()
        self.close_lock = threading.Lock()

    def send(self, request: object, body: bytes) -> None:
        self.send_entered.set()
        if not self.request_closed.wait(5):
            raise AssertionError("blocked fake request was not cancelled")
        raise transport.TransportError(
            "offline fake cancelled",
            winerror=transport.ERROR_WINHTTP_OPERATION_CANCELLED,
        )

    def close(self, handle: object | None) -> None:
        if handle is None:
            return
        with self.close_lock:
            self.closed.append(handle)
        if str(handle).startswith("request"):
            self.request_closed.set()


class HeaderMappingTests(unittest.TestCase):
    def test_case_insensitive_replace_and_validation(self):
        headers = transport.CaseInsensitiveHeaders({"Content-Type": "text/plain"})
        headers["content-type"] = "application/json"
        self.assertEqual(headers["CONTENT-TYPE"], "application/json")
        self.assertEqual(len(headers), 1)
        with self.assertRaises(ValueError):
            headers["Bad\r\nName"] = "x"
        with self.assertRaises(ValueError):
            headers["X-Test"] = "ok\r\nInjected: yes"


class ContentLengthPolicyTests(unittest.TestCase):
    def test_missing_and_bounded_ascii_decimal_values_are_accepted(self):
        self.assertIsNone(transport.parse_content_length(None, 10))
        for value, expected in (("0", 0), ("000", 0), ("9", 9), ("0010", 10)):
            with self.subTest(value=value):
                self.assertEqual(
                    transport.parse_content_length(value, 10),
                    expected,
                )

    def test_noncanonical_or_non_ascii_values_are_rejected(self):
        for value in (
            b"1",
            1,
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1, 1",
            "\N{FULLWIDTH DIGIT ONE}",
            "\N{SUPERSCRIPT TWO}",
        ):
            with self.subTest(value=value), self.assertRaises(
                transport.ContentLengthError
            ):
                transport.parse_content_length(value, 10)

    def test_limit_is_checked_before_hostile_integer_conversion(self):
        for value in ("11", "9" * 5000):
            with self.subTest(size=len(value)), self.assertRaises(
                transport.ContentLengthLimitError
            ):
                transport.parse_content_length(value, 10)

    def test_invalid_internal_limit_is_rejected(self):
        for maximum in (-1, True, 1.0):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                transport.parse_content_length("0", maximum)  # type: ignore[arg-type]


class ResponseHeaderParsingTests(unittest.TestCase):
    def test_explicit_empty_content_length_is_preserved_for_strict_rejection(self):
        headers = transport._parse_response_headers(
            "HTTP/1.1 200 OK\r\nContent-Length:\r\nX-Test: ok\r\n\r\n"
        )

        self.assertIn("Content-Length", headers)
        self.assertEqual(headers["Content-Length"], "")
        with self.assertRaises(transport.ContentLengthError):
            transport.parse_content_length(headers.get("Content-Length"), 10)

    def test_duplicate_content_length_lines_are_rejected(self):
        for first, second in (("5", "5"), ("5", "9")):
            with self.subTest(first=first, second=second), self.assertRaises(
                transport.TransportError
            ):
                transport._parse_response_headers(
                    "HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {first}\r\n"
                    f"content-length: {second}\r\n\r\n"
                )


class ProxyPolicyTests(unittest.TestCase):
    def test_only_credential_free_cern_http_proxy_is_supported(self):
        self.assertEqual(
            transport.normalize_proxy("  http://proxy.example:8080/  "),
            "http://proxy.example:8080",
        )
        self.assertEqual(transport.normalize_proxy(""), "")
        for value in (
            "https://proxy.example:443",
            "socks5://127.0.0.1:1080",
            "http://user:pass@proxy.example:8080",
            "http://proxy.example",
            "http://proxy.example:8080/path",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport.normalize_proxy(value)


class SessionOfflineTests(unittest.TestCase):
    def _session(self, bindings: FakeBindings, *, proxy: str = "") -> transport.Session:
        session = transport.Session(
            proxy=proxy,
            bindings_factory=lambda: bindings,
        )
        session.headers.update({"User-Agent": "OfflineTest/1", "Accept": "*/*"})
        self.addCleanup(session.close)
        return session

    def test_secure_json_request_is_bounded_manual_and_hardened(self):
        bindings = FakeBindings(
            response_headers=[{"Content-Type": "application/json"}],
            bodies=[b'{"ok":true}'],
        )
        session = self._session(bindings, proxy="http://127.0.0.1:8080")
        response = session.request(
            "POST",
            "https://example.test/a%2Fb?q=already%20encoded",
            params={"tag": "blue eyes"},
            json={"hello": "世界"},
            headers={"Accept-Encoding": "gzip"},
            timeout=(5, 30),
            allow_redirects=False,
            stream=True,
        )
        try:
            self.assertEqual(b"".join(response.iter_content(3)), b'{"ok":true}')
        finally:
            response.close()

        self.assertEqual(bindings.opens, [("OfflineTest/1", "http://127.0.0.1:8080")])
        self.assertEqual(bindings.connections[0][1:], ("example.test", 443))
        request = bindings.requests[0]
        self.assertTrue(request["secure"])
        self.assertEqual(
            request["target"], "/a%2Fb?q=already%20encoded&tag=blue+eyes"
        )
        sent_headers = request["headers"]
        self.assertEqual(sent_headers["Accept-Encoding"], "identity")
        self.assertEqual(sent_headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(bindings.timeouts[0][1], (5000, 5000, 30000, 30000))
        self.assertEqual(bindings.sent, ['{"hello":"世界"}'.encode("utf-8")])

        options = {(option, value) for _handle, option, value in bindings.options}
        self.assertIn(
            (
                transport.WINHTTP_OPTION_SECURE_PROTOCOLS,
                transport.WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
            ),
            options,
        )
        self.assertIn(
            (transport.WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK, True),
            options,
        )
        self.assertIn(
            (
                transport.WINHTTP_OPTION_ENABLE_FEATURE,
                transport.WINHTTP_ENABLE_SSL_REVOCATION,
            ),
            options,
        )
        disabled = next(
            value
            for handle, option, value in bindings.options
            if str(handle).startswith("request")
            and option == transport.WINHTTP_OPTION_DISABLE_FEATURE
        )
        self.assertEqual(
            disabled,
            transport.WINHTTP_DISABLE_REDIRECTS
            | transport.WINHTTP_DISABLE_COOKIES
            | transport.WINHTTP_DISABLE_AUTHENTICATION,
        )

    def test_plain_http_auto_redirect_and_managed_headers_are_rejected(self):
        session = self._session(FakeBindings())
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            session.get("http://example.test/file")
        with self.assertRaisesRegex(ValueError, "automatic redirects"):
            session.get("https://example.test/file", allow_redirects=True)
        for header in (
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Cookie",
            "Connection",
            "Proxy-Authorization",
        ):
            with self.subTest(header=header), self.assertRaisesRegex(
                ValueError, "forbidden caller-managed"
            ):
                session.get("https://example.test/file", headers={header: "x"})

    def test_set_cookie_is_never_replayed_and_redirect_is_not_followed(self):
        bindings = FakeBindings(
            statuses=[302, 200],
            response_headers=[
                {"Location": "https://example.test/next", "Set-Cookie": "sid=secret"},
                {},
            ],
            bodies=[b"redirect", b"ok"],
        )
        session = self._session(bindings)
        first = session.get("https://example.test/start")
        self.assertTrue(first.is_redirect)
        first.close()
        second = session.get("https://example.test/next")
        second.close()

        self.assertEqual(len(bindings.requests), 2)
        for request in bindings.requests:
            self.assertNotIn("Cookie", request["headers"])
            self.assertNotIn("Authorization", request["headers"])

    def test_old_winhttp_pooling_fallback_disables_keep_alive(self):
        bindings = FakeBindings(global_pooling_supported=False)
        session = self._session(bindings)
        response = session.get("https://example.test/file")
        response.close()
        headers = bindings.requests[0]["headers"]
        self.assertEqual(headers["Connection"], "close")
        disabled = next(
            value
            for handle, option, value in bindings.options
            if str(handle).startswith("request")
            and option == transport.WINHTTP_OPTION_DISABLE_FEATURE
        )
        self.assertTrue(disabled & transport.WINHTTP_DISABLE_KEEP_ALIVE)

    def test_failure_closes_request_connection_and_session(self):
        bindings = FakeBindings(fail_at="send")
        session = self._session(bindings)
        with self.assertRaises(transport.TransportError):
            session.get("https://example.test/file")
        self.assertIn("request-1", bindings.closed)
        self.assertIn("connection-1", bindings.closed)
        session.close()
        self.assertIn("session", bindings.closed)

    def test_session_close_interrupts_a_blocked_request_without_double_close(self):
        bindings = BlockingSendBindings()
        session = self._session(bindings)
        failures: list[BaseException] = []

        def request() -> None:
            try:
                session.get("https://example.test/blocked")
            except BaseException as exc:  # captured for assertion in this thread
                failures.append(exc)

        thread = threading.Thread(target=request, daemon=True)
        thread.start()
        self.assertTrue(bindings.send_entered.wait(1), "fake send was not entered")
        session.close()
        thread.join(1)

        self.assertFalse(thread.is_alive(), "Session.close did not interrupt send")
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], transport.TransportError)
        self.assertEqual(
            getattr(failures[0], "winerror", None),
            transport.ERROR_WINHTTP_OPERATION_CANCELLED,
        )
        for handle in ("request-1", "connection-1", "session"):
            self.assertEqual(bindings.closed.count(handle), 1, handle)

    def test_response_and_session_close_are_concurrently_idempotent(self):
        bindings = FakeBindings(bodies=[b"body"])
        session = self._session(bindings)
        response = session.get("https://example.test/file")
        barrier = threading.Barrier(9)

        def close_response() -> None:
            barrier.wait()
            response.close()

        threads = [threading.Thread(target=close_response) for _ in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait()
        session.close()
        for thread in threads:
            thread.join(1)

        self.assertTrue(response.closed)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        for handle in ("request-1", "connection-1", "session"):
            self.assertEqual(bindings.closed.count(handle), 1, handle)

    def test_winhttp_dll_load_is_restricted_to_system32(self):
        fake_library = mock.MagicMock()
        with (
            mock.patch.object(transport.os, "name", "nt"),
            mock.patch.object(
                transport.ctypes, "WinDLL", create=True, return_value=fake_library
            ) as loader,
        ):
            transport._WinHttpBindings()
        loader.assert_called_once_with(
            "winhttp.dll",
            use_last_error=True,
            winmode=transport.LOAD_LIBRARY_SEARCH_SYSTEM32,
        )

    def test_native_binding_declarations_can_be_constructed_without_network(self):
        if os.name != "nt":
            self.skipTest("WinHTTP is Windows-only")
        bindings = transport._WinHttpBindings()
        self.assertTrue(hasattr(bindings._library, "WinHttpOpen"))
        self.assertIs(bindings._library.WinHttpOpen.restype, transport.wintypes.HANDLE)


if __name__ == "__main__":
    unittest.main()
