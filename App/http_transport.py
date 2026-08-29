# -*- coding: utf-8 -*-
"""Small synchronous WinHTTP transport with a requests-like surface.

The application only needs a deliberately narrow HTTP client.  Keeping that
surface here lets the portable build use the Windows WinHTTP/Schannel stack
without Python's ``ssl`` extension, OpenSSL, a CA bundle, or ambient proxy and
credential state.

Security properties are fail-closed:

* WinHTTP is opened in synchronous mode with either NO_PROXY or one explicit
  CERN-style HTTP proxy.  PAC/WPAD, environment and user proxy settings are
  never consulted.
* automatic redirects, cookies and authentication are disabled on every
  request before it is sent; the automatic-logon policy is set to HIGH.
* HTTPS is restricted to TLS 1.2, secure-protocol fallback is disabled, normal
  Schannel certificate/name checks remain enabled, and revocation checking is
  explicitly requested.  No certificate-ignore flag is ever set.
* response decompression is never enabled and ``Accept-Encoding: identity`` is
  forced for every request.

WinHTTP supports HTTP proxies (including CONNECT for HTTPS destinations), not
SOCKS or an encrypted HTTPS-to-proxy hop.  Unsupported proxy schemes are
rejected instead of silently falling back to a direct connection.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping
import ctypes
from ctypes import wintypes
import json as json_module
import os
import re
import threading
from typing import Callable
from urllib.parse import quote, urlencode, urlsplit
import weakref


_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_METHOD_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,32}$")
_VALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_REQUEST_BODY = 8 * 1024 * 1024
_MAX_URL_CHARS = 32_768
_MAX_HEADER_CHARS = 64 * 1024
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# winhttp.h constants.  They are kept local so the portable runtime does not
# need a compiler, pywin32, cffi, or generated bindings.
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_FLAG_SECURE = 0x00800000
WINHTTP_FLAG_ESCAPE_DISABLE = 0x00000040
WINHTTP_OPTION_DISABLE_FEATURE = 63
WINHTTP_OPTION_AUTOLOGON_POLICY = 77
WINHTTP_OPTION_ENABLE_FEATURE = 79
WINHTTP_OPTION_SECURE_PROTOCOLS = 84
WINHTTP_OPTION_REDIRECT_POLICY = 88
WINHTTP_OPTION_REJECT_USERPWD_IN_URL = 100
WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK = 144
WINHTTP_OPTION_DISABLE_GLOBAL_POOLING = 195
WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH = 2
WINHTTP_OPTION_REDIRECT_POLICY_NEVER = 0
WINHTTP_DISABLE_COOKIES = 0x00000001
WINHTTP_DISABLE_REDIRECTS = 0x00000002
WINHTTP_DISABLE_AUTHENTICATION = 0x00000004
WINHTTP_DISABLE_KEEP_ALIVE = 0x00000008
WINHTTP_ENABLE_SSL_REVOCATION = 0x00000001
WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800
WINHTTP_ADDREQ_FLAG_ADD = 0x20000000
WINHTTP_ADDREQ_FLAG_REPLACE = 0x80000000
WINHTTP_QUERY_STATUS_CODE = 19
WINHTTP_QUERY_RAW_HEADERS_CRLF = 22
WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
ERROR_NOT_SUPPORTED = 50
ERROR_WINHTTP_INVALID_OPTION = 12009
ERROR_WINHTTP_TIMEOUT = 12002
ERROR_WINHTTP_OPERATION_CANCELLED = 12017
_OPTION_UNSUPPORTED_ERRORS = frozenset(
    {ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_WINHTTP_INVALID_OPTION}
)


class TransportError(RuntimeError):
    """A sanitized native transport failure."""

    def __init__(self, message: str, *, winerror: int | None = None) -> None:
        super().__init__(message)
        self.winerror = winerror


class TransportTimeout(TransportError):
    """A WinHTTP operation exceeded an explicit timeout."""


class CaseInsensitiveHeaders(MutableMapping[str, str]):
    """Minimal case-insensitive string mapping used by Session/Response."""

    def __init__(self, values: Mapping[str, object] | None = None) -> None:
        self._values: dict[str, tuple[str, str]] = {}
        if values:
            self.update(values)

    def __getitem__(self, key: str) -> str:
        return self._values[str(key).casefold()][1]

    def __setitem__(self, key: str, value: object) -> None:
        name, text = _validate_header(key, value)
        self._values[name.casefold()] = (name, text)

    def __delitem__(self, key: str) -> None:
        del self._values[str(key).casefold()]

    def __iter__(self):
        return (pair[0] for pair in self._values.values())

    def __len__(self) -> int:
        return len(self._values)

    def copy(self) -> "CaseInsensitiveHeaders":
        return CaseInsensitiveHeaders(dict(self.items()))


def _validate_header(name: object, value: object) -> tuple[str, str]:
    if not isinstance(name, str) or _HEADER_NAME_RE.fullmatch(name) is None:
        raise ValueError("invalid HTTP header name")
    if not isinstance(value, str):
        value = str(value)
    if len(value) > _MAX_HEADER_CHARS or any(
        char in "\r\n\x00" or (ord(char) < 32 and char != "\t") or ord(char) == 127
        for char in value
    ):
        raise ValueError("invalid HTTP header value")
    return name, value


def normalize_proxy(proxy: str) -> str:
    """Return a canonical explicit HTTP proxy or reject it.

    WinHTTP's named-proxy mode supports CERN HTTP proxies.  Such a proxy can
    carry both HTTP traffic and HTTPS traffic via CONNECT, but SOCKS and an
    HTTPS-encrypted hop to the proxy itself are not supported by WinHTTP.
    """

    if not isinstance(proxy, str):
        raise ValueError("proxy must be a string")
    candidate = proxy.strip()
    if not candidate:
        return ""
    if len(candidate) > 2048 or any(char.isspace() or ord(char) < 32 for char in candidate):
        raise ValueError("invalid proxy")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid proxy") from exc
    scheme = parsed.scheme.casefold()
    if scheme != "http":
        if scheme.startswith("socks"):
            raise ValueError("SOCKS proxies are not supported by WinHTTP")
        if scheme == "https":
            raise ValueError("HTTPS-to-proxy transport is not supported by WinHTTP")
        raise ValueError("unsupported proxy scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("proxy credentials are not supported")
    if not parsed.hostname or port is None or not 1 <= port <= 65535:
        raise ValueError("proxy host and port are required")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("invalid proxy path")
    host = _ascii_hostname(parsed.hostname)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}"


def _ascii_hostname(value: str) -> str:
    if not value or "\x00" in value or any(char.isspace() for char in value):
        raise ValueError("invalid host")
    try:
        host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid host") from exc
    if len(host) > 253:
        raise ValueError("invalid host")
    return host


def _request_target(url: str, params: Mapping | list[tuple] | None) -> tuple[str, str, int, bool]:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_CHARS:
        raise ValueError("invalid URL")
    if "\x00" in url or "\r" in url or "\n" in url:
        raise ValueError("invalid URL")
    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    if scheme != "https" or not parsed.hostname:
        raise ValueError("only absolute HTTPS URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in URLs are forbidden")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent in HTTP requests")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    host = _ascii_hostname(parsed.hostname)
    path = parsed.path or "/"
    query = parsed.query
    if _VALID_PERCENT_RE.search(path) or _VALID_PERCENT_RE.search(query):
        raise ValueError("invalid percent escape in URL")
    path = quote(path, safe="%/:@!$&'()*+,;=-._~")
    query = quote(query, safe="%/:@!$&'()*+,;=?-._~")
    if params:
        encoded = urlencode(params, doseq=True)
        query = f"{query}&{encoded}" if query else encoded
    target = path + ("?" + query if query else "")
    if len(target) > _MAX_URL_CHARS:
        raise ValueError("request target is too long")
    return host, target, port, scheme == "https"


def _timeouts(value: object) -> tuple[int, int, int, int]:
    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("timeout must be seconds or (connect, read)")
        connect, read = value
    else:
        connect = read = value
    if isinstance(connect, bool) or isinstance(read, bool):
        raise ValueError("invalid timeout")
    try:
        connect_seconds = float(connect)
        read_seconds = float(read)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid timeout") from exc
    if not 0 < connect_seconds <= 300 or not 0 < read_seconds <= 600:
        raise ValueError("timeout out of range")

    def milliseconds(seconds: float) -> int:
        return max(1, min(int(seconds * 1000), 2_147_483_647))

    connect_ms = milliseconds(connect_seconds)
    read_ms = milliseconds(read_seconds)
    return connect_ms, connect_ms, read_ms, read_ms


class _WinHttpBindings:
    """Pointer-width-safe ctypes declarations and thin WinHTTP calls."""

    def __init__(self) -> None:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise TransportError("WinHTTP transport requires Windows")
        # Restrict DLL resolution to the real Windows system directory.  A
        # portable app commonly starts with its own directory first in the
        # legacy DLL search order, so an unqualified default load would allow a
        # sibling ``winhttp.dll`` to shadow the operating-system copy.
        library = ctypes.WinDLL(
            "winhttp.dll",
            use_last_error=True,
            winmode=LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        handle = wintypes.HANDLE
        dword_pointer = ctypes.POINTER(wintypes.DWORD)

        library.WinHttpOpen.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        library.WinHttpOpen.restype = handle
        library.WinHttpConnect.argtypes = [
            handle,
            wintypes.LPCWSTR,
            wintypes.WORD,
            wintypes.DWORD,
        ]
        library.WinHttpConnect.restype = handle
        library.WinHttpOpenRequest.argtypes = [
            handle,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPCWSTR),
            wintypes.DWORD,
        ]
        library.WinHttpOpenRequest.restype = handle
        library.WinHttpSetOption.argtypes = [
            handle,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        library.WinHttpSetOption.restype = wintypes.BOOL
        library.WinHttpSetTimeouts.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        ]
        library.WinHttpSetTimeouts.restype = wintypes.BOOL
        library.WinHttpAddRequestHeaders.argtypes = [
            handle,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        library.WinHttpAddRequestHeaders.restype = wintypes.BOOL
        library.WinHttpSendRequest.argtypes = [
            handle,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_size_t,
        ]
        library.WinHttpSendRequest.restype = wintypes.BOOL
        library.WinHttpReceiveResponse.argtypes = [handle, wintypes.LPVOID]
        library.WinHttpReceiveResponse.restype = wintypes.BOOL
        library.WinHttpQueryHeaders.argtypes = [
            handle,
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPVOID,
            dword_pointer,
            dword_pointer,
        ]
        library.WinHttpQueryHeaders.restype = wintypes.BOOL
        library.WinHttpQueryDataAvailable.argtypes = [handle, dword_pointer]
        library.WinHttpQueryDataAvailable.restype = wintypes.BOOL
        library.WinHttpReadData.argtypes = [
            handle,
            wintypes.LPVOID,
            wintypes.DWORD,
            dword_pointer,
        ]
        library.WinHttpReadData.restype = wintypes.BOOL
        library.WinHttpCloseHandle.argtypes = [handle]
        library.WinHttpCloseHandle.restype = wintypes.BOOL
        self._library = library

    @staticmethod
    def _handle_value(handle: object, operation: str):
        if not handle:
            _raise_last_error(operation)
        return handle

    def open(self, user_agent: str, proxy: str) -> object:
        access = WINHTTP_ACCESS_TYPE_NAMED_PROXY if proxy else WINHTTP_ACCESS_TYPE_NO_PROXY
        return self._handle_value(
            self._library.WinHttpOpen(user_agent, access, proxy or None, None, 0),
            "open session",
        )

    def connect(self, session: object, host: str, port: int) -> object:
        return self._handle_value(
            self._library.WinHttpConnect(session, host, port, 0), "connect handle"
        )

    def open_request(
        self, connection: object, method: str, target: str, *, secure: bool
    ) -> object:
        flags = WINHTTP_FLAG_ESCAPE_DISABLE | (WINHTTP_FLAG_SECURE if secure else 0)
        return self._handle_value(
            self._library.WinHttpOpenRequest(
                connection, method, target, None, None, None, flags
            ),
            "open request",
        )

    def set_dword(self, handle: object, option: int, value: int) -> None:
        buffer = wintypes.DWORD(value)
        if not self._library.WinHttpSetOption(
            handle, option, ctypes.byref(buffer), ctypes.sizeof(buffer)
        ):
            _raise_last_error("set security option")

    def set_bool(self, handle: object, option: int, value: bool) -> None:
        buffer = wintypes.BOOL(bool(value))
        if not self._library.WinHttpSetOption(
            handle, option, ctypes.byref(buffer), ctypes.sizeof(buffer)
        ):
            _raise_last_error("set security option")

    def set_timeouts(self, handle: object, values: tuple[int, int, int, int]) -> None:
        if not self._library.WinHttpSetTimeouts(handle, *values):
            _raise_last_error("set timeouts")

    def add_headers(self, request: object, headers: CaseInsensitiveHeaders) -> None:
        if not headers:
            return
        block = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
        if len(block) > _MAX_HEADER_CHARS:
            raise ValueError("HTTP headers are too large")
        if not self._library.WinHttpAddRequestHeaders(
            request,
            block,
            0xFFFFFFFF,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
        ):
            _raise_last_error("add request headers")

    def send(self, request: object, body: bytes) -> None:
        buffer = ctypes.create_string_buffer(body) if body else None
        pointer = ctypes.cast(buffer, wintypes.LPVOID) if buffer is not None else None
        if not self._library.WinHttpSendRequest(
            request, None, 0, pointer, len(body), len(body), 0
        ):
            _raise_last_error("send request")

    def receive(self, request: object) -> None:
        if not self._library.WinHttpReceiveResponse(request, None):
            _raise_last_error("receive response")

    def status_code(self, request: object) -> int:
        status = wintypes.DWORD()
        size = wintypes.DWORD(ctypes.sizeof(status))
        if not self._library.WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            None,
            ctypes.byref(status),
            ctypes.byref(size),
            None,
        ):
            _raise_last_error("query response status")
        return int(status.value)

    def response_headers(self, request: object) -> CaseInsensitiveHeaders:
        size = wintypes.DWORD(0)
        if self._library.WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            None,
            None,
            ctypes.byref(size),
            None,
        ):
            return CaseInsensitiveHeaders()
        error = ctypes.get_last_error()
        if error != ERROR_INSUFFICIENT_BUFFER or not size.value:
            _raise_winhttp_error("query response headers", error)
        buffer = ctypes.create_unicode_buffer(size.value // ctypes.sizeof(ctypes.c_wchar) + 1)
        if not self._library.WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            None,
            buffer,
            ctypes.byref(size),
            None,
        ):
            _raise_last_error("query response headers")
        headers = CaseInsensitiveHeaders()
        for line in buffer.value.split("\r\n")[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
        return headers

    def data_available(self, request: object) -> int:
        available = wintypes.DWORD()
        if not self._library.WinHttpQueryDataAvailable(request, ctypes.byref(available)):
            _raise_last_error("query response data")
        return int(available.value)

    def read(self, request: object, size: int) -> bytes:
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        if not self._library.WinHttpReadData(
            request, buffer, size, ctypes.byref(read)
        ):
            _raise_last_error("read response data")
        return buffer.raw[: read.value]

    def close(self, handle: object | None) -> None:
        if handle:
            self._library.WinHttpCloseHandle(handle)


def _raise_last_error(operation: str) -> None:
    _raise_winhttp_error(operation, ctypes.get_last_error())


def _raise_winhttp_error(operation: str, code: int) -> None:
    error_type = TransportTimeout if code == ERROR_WINHTTP_TIMEOUT else TransportError
    if code == ERROR_WINHTTP_OPERATION_CANCELLED:
        message = f"WinHTTP {operation} was cancelled"
    else:
        message = f"WinHTTP {operation} failed (error {code})"
    raise error_type(message, winerror=code)


class Response:
    """One forward-only WinHTTP response body."""

    def __init__(
        self,
        session: "Session",
        bindings: _WinHttpBindings,
        request_token: object,
        connection_token: object,
        status_code: int,
        headers: CaseInsensitiveHeaders,
        on_close: Callable[["Response"], None] | None = None,
    ) -> None:
        self.status_code = int(status_code)
        self.headers = headers
        self._session = session
        self._bindings = bindings
        self._request_token = request_token
        self._connection_token = connection_token
        self._on_close = on_close
        self._closed = False
        self._iteration_started = False
        self._lock = threading.RLock()

    @property
    def is_redirect(self) -> bool:
        return self.status_code in _REDIRECT_STATUSES and bool(self.headers.get("Location"))

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")
        with self._lock:
            if self._closed:
                raise TransportError("response is closed")
            if self._iteration_started:
                raise TransportError("response body is forward-only")
            self._iteration_started = True
        while True:
            with self._lock:
                if self._closed:
                    return
                request_token = self._request_token
            request_handle = self._session._handle_for(request_token)
            available = self._bindings.data_available(request_handle)
            if available <= 0:
                return
            remaining = available
            while remaining > 0:
                with self._lock:
                    if self._closed:
                        return
                    request_token = self._request_token
                request_handle = self._session._handle_for(request_token)
                data = self._bindings.read(
                    request_handle, min(remaining, chunk_size, 0xFFFFFFFF)
                )
                if not data:
                    return
                remaining -= len(data)
                yield data

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            tokens = (self._request_token, self._connection_token)
            self._request_token = None
            self._connection_token = None
            callback, self._on_close = self._on_close, None
        # Session owns every native handle.  Atomically taking the two tokens
        # makes Response.close, Session.close and an exception-unwind safe to
        # race without ever closing the same HINTERNET twice.
        self._session._close_handle_tokens(tokens)
        if callback is not None:
            callback(self)

    def __enter__(self) -> "Response":
        with self._lock:
            if self._closed:
                raise TransportError("response is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class Session:
    """Synchronous, state-minimal WinHTTP session."""

    def __init__(
        self,
        *,
        proxy: str = "",
        bindings_factory: Callable[[], _WinHttpBindings] = _WinHttpBindings,
    ) -> None:
        self.headers = CaseInsensitiveHeaders()
        self.trust_env = False
        self._proxy = normalize_proxy(proxy)
        self._bindings_factory = bindings_factory
        self._bindings: _WinHttpBindings | None = None
        self._session_token: object | None = None
        self._closed = False
        self._lock = threading.RLock()
        self._responses: weakref.WeakSet[Response] = weakref.WeakSet()
        self._live_handles: dict[object, tuple[str, _WinHttpBindings, object]] = {}
        self._global_pooling_disabled = False

    @property
    def proxy(self) -> str:
        return self._proxy

    def configure_proxy(self, proxy: str) -> None:
        normalized = normalize_proxy(proxy)
        with self._lock:
            if self._session_token is not None:
                raise RuntimeError("proxy cannot change after the first request")
            if self._closed:
                raise RuntimeError("session is closed")
            self._proxy = normalized

    def _create_child_handle(
        self,
        kind: str,
        bindings: _WinHttpBindings,
        parent_token: object,
        create: Callable[[object], object],
    ) -> tuple[object, object]:
        """Create and register a local child handle under the ownership lock.

        WinHttpConnect and WinHttpOpenRequest only allocate handles; they do
        not perform network I/O.  Holding the lock across those calls closes
        the otherwise dangerous gap where Session.close could close a parent
        before its newly returned child had entered the ownership registry.
        """

        with self._lock:
            if self._closed:
                raise TransportError(
                    "session closed during request",
                    winerror=ERROR_WINHTTP_OPERATION_CANCELLED,
                )
            parent = self._live_handles.get(parent_token)
            if parent is None:
                raise TransportError(
                    "WinHTTP operation was cancelled",
                    winerror=ERROR_WINHTTP_OPERATION_CANCELLED,
                )
            handle = create(parent[2])
            token = object()
            self._live_handles[token] = (kind, bindings, handle)
            return token, handle

    def _handle_for(self, token: object | None) -> object:
        with self._lock:
            record = self._live_handles.get(token)
        if record is None:
            raise TransportError(
                "WinHTTP operation was cancelled",
                winerror=ERROR_WINHTTP_OPERATION_CANCELLED,
            )
        return record[2]

    @staticmethod
    def _close_records(
        records: list[tuple[str, _WinHttpBindings, object]],
    ) -> None:
        # Closing a request is what interrupts a blocked synchronous send,
        # receive or read.  Close children before their parents so each raw
        # handle remains valid until its own single WinHttpCloseHandle call.
        priority = {"request": 0, "connection": 1, "session": 2}
        records.sort(key=lambda item: priority.get(item[0], 1))
        for _kind, bindings, handle in records:
            try:
                bindings.close(handle)
            except Exception:
                # Close is best-effort and must remain idempotent.  Continue so
                # one unusual native/fake close failure cannot leak parents.
                pass

    def _close_handle_tokens(self, tokens: tuple[object | None, ...]) -> None:
        records: list[tuple[str, _WinHttpBindings, object]] = []
        with self._lock:
            for token in tokens:
                if token is not None:
                    record = self._live_handles.pop(token, None)
                    if record is not None:
                        records.append(record)
        self._close_records(records)

    def _ensure_session(self, user_agent: str) -> tuple[_WinHttpBindings, object]:
        with self._lock:
            if self._closed:
                raise TransportError("session is closed")
            if self._session_token is not None and self._bindings is not None:
                return self._bindings, self._session_token
            bindings = self._bindings_factory()
            handle = bindings.open(user_agent, self._proxy)
            try:
                # One enabled protocol means TLS cannot be negotiated below 1.2,
                # even on systems whose registry defaults still include TLS 1.0.
                bindings.set_dword(
                    handle,
                    WINHTTP_OPTION_SECURE_PROTOCOLS,
                    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
                )
                # Windows 10 1903+ supports this explicit anti-downgrade option.
                # Failure is fatal: a release runtime must not silently weaken it.
                bindings.set_bool(
                    handle, WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK, True
                )
                try:
                    bindings.set_bool(handle, WINHTTP_OPTION_DISABLE_GLOBAL_POOLING, True)
                except TransportError as exc:
                    if exc.winerror not in _OPTION_UNSUPPORTED_ERRORS:
                        raise
                    # Older WinHTTP builds lack the option.  Per-request
                    # keep-alive is disabled below so a connection cannot enter
                    # the legacy cross-session pool.
                    self._global_pooling_disabled = False
                else:
                    self._global_pooling_disabled = True
            except Exception:
                bindings.close(handle)
                raise
            token = object()
            self._live_handles[token] = ("session", bindings, handle)
            self._bindings = bindings
            self._session_token = token
            return bindings, token

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping | list[tuple] | None = None,
        json: object | None = None,
        data: bytes | bytearray | memoryview | str | None = None,
        headers: Mapping[str, object] | None = None,
        timeout: object = 30,
        allow_redirects: bool = False,
        stream: bool = True,
    ) -> Response:
        if allow_redirects is not False:
            raise ValueError("automatic redirects are forbidden")
        if stream is not True:
            raise ValueError("WinHTTP responses must be consumed as a bounded stream")
        if not isinstance(method, str) or _METHOD_RE.fullmatch(method) is None:
            raise ValueError("invalid HTTP method")
        method = method.upper()
        if method not in {"GET", "POST", "HEAD"}:
            raise ValueError("unsupported HTTP method")
        if json is not None and data is not None:
            raise ValueError("json and data are mutually exclusive")
        host, target, port, secure = _request_target(url, params)
        timeout_values = _timeouts(timeout)

        merged = self.headers.copy()
        if headers:
            merged.update(headers)
        forbidden = {
            name.casefold() for name in merged if name.casefold() in _FORBIDDEN_REQUEST_HEADERS
        }
        if forbidden:
            raise ValueError(
                "forbidden caller-managed HTTP header: " + ", ".join(sorted(forbidden))
            )
        # This assignment is deliberately last.  Callers cannot opt into an
        # encoding WinHTTP or application code might inflate implicitly.
        merged["Accept-Encoding"] = "identity"
        if json is not None:
            body = json_module.dumps(
                json, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            merged.setdefault("Content-Type", "application/json; charset=utf-8")
        elif data is None:
            body = b""
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = bytes(data)
        if len(body) > _MAX_REQUEST_BODY:
            raise ValueError("request body is too large")

        user_agent = merged.get("User-Agent", "SankakuSyncer/WinHTTP")
        bindings, session_token = self._ensure_session(user_agent)
        connection_token = None
        request_token = None
        try:
            connection_token, _connection = self._create_child_handle(
                "connection",
                bindings,
                session_token,
                lambda session_handle: bindings.connect(session_handle, host, port),
            )
            request_token, request_handle = self._create_child_handle(
                "request",
                bindings,
                connection_token,
                lambda connection_handle: bindings.open_request(
                    connection_handle, method, target, secure=secure
                ),
            )
            bindings.set_timeouts(request_handle, timeout_values)
            disabled = (
                WINHTTP_DISABLE_REDIRECTS
                | WINHTTP_DISABLE_COOKIES
                | WINHTTP_DISABLE_AUTHENTICATION
            )
            if not self._global_pooling_disabled:
                disabled |= WINHTTP_DISABLE_KEEP_ALIVE
                merged["Connection"] = "close"
            bindings.set_dword(
                request_handle, WINHTTP_OPTION_DISABLE_FEATURE, disabled
            )
            bindings.set_dword(
                request_handle,
                WINHTTP_OPTION_AUTOLOGON_POLICY,
                WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
            )
            bindings.set_dword(
                request_handle,
                WINHTTP_OPTION_REDIRECT_POLICY,
                WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
            )
            bindings.set_bool(
                request_handle, WINHTTP_OPTION_REJECT_USERPWD_IN_URL, True
            )
            bindings.set_dword(
                request_handle,
                WINHTTP_OPTION_ENABLE_FEATURE,
                WINHTTP_ENABLE_SSL_REVOCATION,
            )
            bindings.add_headers(request_handle, merged)
            bindings.send(request_handle, body)
            bindings.receive(request_handle)
            status_code = bindings.status_code(request_handle)
            response_headers = bindings.response_headers(request_handle)
            response = Response(
                self,
                bindings,
                request_token,
                connection_token,
                status_code,
                response_headers,
                self._discard_response,
            )
            with self._lock:
                if self._closed:
                    response.close()
                    raise TransportError("session closed during request")
                self._responses.add(response)
            request_token = None
            connection_token = None
            return response
        except Exception:
            self._close_handle_tokens((request_token, connection_token))
            raise

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def _discard_response(self, response: Response) -> None:
        with self._lock:
            self._responses.discard(response)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            responses = list(self._responses)
            records = list(self._live_handles.values())
            self._live_handles.clear()
            self._session_token = None
            self._bindings = None
            self._responses.clear()
        # Native close happens before Response bookkeeping so a blocked call is
        # interrupted as soon as possible.  Response.close then only marks its
        # Python state because its tokens have already been atomically taken.
        self._close_records(records)
        for response in responses:
            response.close()

    def __enter__(self) -> "Session":
        if self._closed:
            raise TransportError("session is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


__all__ = [
    "CaseInsensitiveHeaders",
    "Response",
    "Session",
    "TransportError",
    "TransportTimeout",
    "normalize_proxy",
]
