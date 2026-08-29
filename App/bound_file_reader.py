# -*- coding: utf-8 -*-
"""Handle-bound, bounded reads of already verified first-level local files.

The public errors in this module are deliberately fixed strings.  Callers may
show them to a user without exposing absolute paths, operating-system errors,
or native status values.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import errno
import hashlib
import hmac
import ntpath
import os
import re
import stat
import threading
import unicodedata


MAX_BOUND_FILE_BYTES = 20 * 1024 * 1024
MAX_BOUND_STREAM_BYTES = 50 * 1024 * 1024 * 1024
MAX_BOUND_PREFIX_BYTES = 1024 * 1024
MAX_BOUND_DIRECTORY_ENTRIES = 100_000
MAX_BOUND_BASENAME_BYTES = 1024
_READ_CHUNK_BYTES = 256 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

_ERR_ARGUMENTS = "本地文件读取参数无效"
_ERR_CANCELLED = "本地文件读取已取消"
_ERR_ROOT_UNAVAILABLE = "本地文件根目录不可用"
_ERR_ROOT_UNSAFE = "本地文件根目录不安全"
_ERR_ROOT_CHANGED = "本地文件根目录已变化"
_ERR_CHILD_UNSAFE = "本地文件无法安全读取"
_ERR_CHILD_UNREADABLE = "本地文件不可读"
_ERR_CHILD_MISSING = "本地文件不存在"
_ERR_CHILD_TOO_LARGE = "本地文件超过安全大小上限"
_ERR_DIRECTORY_LIMIT = "本地目录项目超过安全上限"
_ERR_SIZE_CHANGED = "本地文件长度与已验证记录不匹配"
_ERR_DIGEST_CHANGED = "本地文件摘要与已验证记录不匹配"
_POSIX_UNREADABLE_ERRNOS = frozenset(
    value
    for value in (
        errno.EACCES,
        errno.EPERM,
        getattr(errno, "EBUSY", None),
        getattr(errno, "ETXTBSY", None),
        getattr(errno, "EIO", None),
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
        getattr(errno, "ENOMEM", None),
    )
    if isinstance(value, int)
)


class BoundFileError(RuntimeError):
    """A fixed, user-displayable failure from one bound local-file read."""


class BoundFileCancelled(BoundFileError):
    """The caller cancelled a bound read before it could commit a result."""


class BoundFileMissing(BoundFileError):
    """A direct child was absent, reported without disclosing its pathname."""


class BoundFileTooLarge(BoundFileError):
    """A regular child exceeded the caller's explicit size budget."""


class BoundFileUnreadable(BoundFileError):
    """A child could not be opened or read for an operational reason."""


@dataclass(frozen=True, slots=True)
class BoundRootIdentity:
    """Opaque, non-path identity of one opened filesystem directory."""

    platform: str
    volume_id: int
    file_id: bytes

    def __post_init__(self) -> None:
        if (
            type(self.platform) is not str
            or self.platform not in {"windows", "posix"}
            or type(self.volume_id) is not int
            or self.volume_id < 0
            or type(self.file_id) is not bytes
            or not self.file_id
            or len(self.file_id) > 32
        ):
            raise ValueError("invalid bound root identity")


@dataclass(frozen=True, slots=True)
class BoundFileInspection:
    """Streaming integrity facts for one regular direct child."""

    size: int
    sha256: str
    md5: str
    prefix: bytes


class BoundRootSession:
    """One root handle/file descriptor kept open for an entire local scan."""

    __slots__ = ("_identity", "_lock", "_path", "_token")

    def __init__(
        self,
        path: str,
        token: int,
        identity: BoundRootIdentity,
    ) -> None:
        self._path = path
        self._token: int | None = token
        self._identity = identity
        self._lock = threading.RLock()

    def __enter__(self) -> BoundRootSession:
        with self._lock:
            self._require_open()
            return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @property
    def identity(self) -> BoundRootIdentity:
        return self._identity

    @property
    def root_path(self) -> str:
        """Display-only original path; child security never depends on it."""

        return self._path

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._token is None

    def close(self) -> None:
        with self._lock:
            token = self._token
            self._token = None
            if token is None:
                return
            if self._identity.platform == "windows":
                _win_close_handle(token)
            else:
                _close_fd(token)

    def list_names(
        self,
        stop_event: threading.Event | None = None,
        max_entries: int = MAX_BOUND_DIRECTORY_ENTRIES,
    ) -> tuple[str, ...]:
        """Return bounded first-level names from the still-bound directory."""

        if (
            type(max_entries) is not int
            or not 1 <= max_entries <= MAX_BOUND_DIRECTORY_ENTRIES
        ):
            raise BoundFileError(_ERR_ARGUMENTS)
        try:
            with self._lock:
                token = self._require_open()
                _check_cancelled(stop_event)
                source: object = self._path if os.name == "nt" else token
                names: list[str] = []
                with os.scandir(source) as iterator:
                    for item in iterator:
                        _check_cancelled(stop_event)
                        if len(names) >= max_entries:
                            raise BoundFileError(_ERR_DIRECTORY_LIMIT)
                        if type(item.name) is not str:
                            raise BoundFileError(_ERR_ROOT_UNSAFE)
                        names.append(item.name)
                _check_cancelled(stop_event)
                if os.name == "nt" and _win_root_identity(token) != self._identity:
                    raise BoundFileError(_ERR_ROOT_CHANGED)
                return tuple(names)
        except BoundFileError:
            raise
        except OSError:
            raise BoundFileError(_ERR_ROOT_UNAVAILABLE) from None
        except Exception:
            raise BoundFileError(_ERR_ROOT_UNSAFE) from None

    def stat_child(
        self,
        basename: object,
        stop_event: threading.Event | None = None,
        max_bytes: int = MAX_BOUND_STREAM_BYTES,
    ) -> int:
        """Return the size of one safe regular child without reading its body."""

        name = _validated_basename(basename)
        limit = _validated_limit(max_bytes, MAX_BOUND_STREAM_BYTES)
        try:
            with self._lock:
                token = self._require_open()
                _check_cancelled(stop_event)
                descriptor = self._open_child_fd(token, name)
                try:
                    size = _fd_regular_size(descriptor, limit)
                    _check_cancelled(stop_event)
                    return size
                finally:
                    _close_fd(descriptor)
        except BoundFileError:
            raise
        except Exception:
            raise BoundFileError(_ERR_CHILD_UNSAFE) from None

    def read_small_file(
        self,
        basename: object,
        stop_event: threading.Event | None = None,
        max_bytes: int = MAX_BOUND_FILE_BYTES,
    ) -> bytes:
        """Read one safe direct child, never exceeding the 20 MiB memory cap."""

        name = _validated_basename(basename)
        limit = _validated_limit(max_bytes, MAX_BOUND_FILE_BYTES)
        try:
            with self._lock:
                token = self._require_open()
                _check_cancelled(stop_event)
                descriptor = self._open_child_fd(token, name)
                try:
                    _inspection, payload = _consume_fd(
                        descriptor,
                        stop_event=stop_event,
                        max_bytes=limit,
                        prefix_bytes=0,
                        collect_payload=True,
                    )
                    assert payload is not None
                    return payload
                finally:
                    _close_fd(descriptor)
        except BoundFileError:
            raise
        except Exception:
            raise BoundFileError(_ERR_CHILD_UNSAFE) from None

    def inspect_child(
        self,
        basename: object,
        stop_event: threading.Event | None = None,
        max_bytes: int = MAX_BOUND_STREAM_BYTES,
        prefix_bytes: int = 0,
    ) -> BoundFileInspection:
        """Stream SHA-256/MD5 and a bounded prefix without retaining the file."""

        name = _validated_basename(basename)
        limit = _validated_limit(max_bytes, MAX_BOUND_STREAM_BYTES)
        prefix_limit = _validated_prefix_limit(prefix_bytes)
        try:
            with self._lock:
                token = self._require_open()
                _check_cancelled(stop_event)
                descriptor = self._open_child_fd(token, name)
                try:
                    inspection, _payload = _consume_fd(
                        descriptor,
                        stop_event=stop_event,
                        max_bytes=limit,
                        prefix_bytes=prefix_limit,
                        collect_payload=False,
                    )
                    return inspection
                finally:
                    _close_fd(descriptor)
        except BoundFileError:
            raise
        except Exception:
            raise BoundFileError(_ERR_CHILD_UNSAFE) from None

    def read_verified_child(
        self,
        basename: object,
        expected_size: object,
        expected_sha256: object,
        stop_event: threading.Event | None,
        max_bytes: object,
    ) -> bytes:
        """Compatibility-quality verified read using this already-open root."""

        name = _validated_basename(basename)
        size, digest, limit = _validated_expectations(
            self._identity, expected_size, expected_sha256, max_bytes
        )
        try:
            with self._lock:
                token = self._require_open()
                _check_cancelled(stop_event)
                descriptor = self._open_child_fd(token, name)
                try:
                    current_size = _fd_regular_size(descriptor, limit)
                    if current_size != size:
                        raise BoundFileError(_ERR_SIZE_CHANGED)
                    return _read_fd_verified(
                        descriptor,
                        expected_size=size,
                        expected_sha256=digest,
                        stop_event=stop_event,
                        max_bytes=limit,
                    )
                finally:
                    _close_fd(descriptor)
        except BoundFileError:
            raise
        except Exception:
            raise BoundFileError(_ERR_CHILD_UNSAFE) from None

    def _require_open(self) -> int:
        if self._token is None:
            raise BoundFileError(_ERR_ROOT_UNAVAILABLE)
        return self._token

    def _open_child_fd(self, token: int, basename: str) -> int:
        if self._identity.platform == "windows":
            child_handle = _win_open_child(token, basename)
            try:
                _win_validate_child_kind(child_handle)
                descriptor = _win_handle_to_fd(child_handle)
            except BaseException:
                _win_close_handle(child_handle)
                raise
            return descriptor  # CRT fd now owns the native child handle.
        descriptor = _posix_open_child(token, basename)
        try:
            _fd_regular_size(descriptor, MAX_BOUND_STREAM_BYTES)
        except BaseException:
            _close_fd(descriptor)
            raise
        return descriptor


def open_bound_root(
    root: object,
    stop_event: threading.Event | None = None,
) -> BoundRootSession:
    """Open an unredirectable root session whose lifetime is caller-controlled."""

    try:
        path = _validated_root_path(root)
        _check_cancelled(stop_event)
        if os.name == "nt":
            token = _win_open_root(path)
            try:
                identity = _win_root_identity(token)
                _check_cancelled(stop_event)
            except BaseException:
                _win_close_handle(token)
                raise
        else:
            token = _posix_open_root(path)
            try:
                identity = _posix_root_identity(token)
                _check_cancelled(stop_event)
            except BaseException:
                _close_fd(token)
                raise
        return BoundRootSession(path, token, identity)
    except BoundFileError:
        raise
    except Exception:
        raise BoundFileError(_ERR_ROOT_UNAVAILABLE) from None


def get_bound_root_identity(root: object) -> BoundRootIdentity:
    """Open *root* without following its final reparse point and identify it."""

    with open_bound_root(root) as session:
        return session.identity


def read_verified_child(
    root: object,
    expected_root_identity: BoundRootIdentity,
    basename: object,
    expected_size: object,
    expected_sha256: object,
    stop_event: threading.Event | None,
    max_bytes: object,
) -> bytes:
    """Read one verified direct child, anchored to an opened root directory.

    The root identity, exact length, and SHA-256 must all match the committed
    report supplied by the caller.  No pathname is reopened after the root has
    been bound to a directory handle/file descriptor.
    """

    try:
        path = _validated_root_path(root)
        name = _validated_basename(basename)
        size, digest, limit = _validated_expectations(
            expected_root_identity,
            expected_size,
            expected_sha256,
            max_bytes,
        )
        _check_cancelled(stop_event)

        expected_platform = "windows" if os.name == "nt" else "posix"
        if expected_root_identity.platform != expected_platform:
            raise BoundFileError(_ERR_ARGUMENTS)
        with open_bound_root(path, stop_event) as session:
            if session.identity != expected_root_identity:
                raise BoundFileError(_ERR_ROOT_CHANGED)
            return session.read_verified_child(
                name, size, digest, stop_event, limit
            )
    except BoundFileError:
        raise
    except Exception:
        raise BoundFileError(_ERR_CHILD_UNSAFE) from None


def _validated_root_path(value: object) -> str:
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise ValueError("empty root")
        return os.path.abspath(raw)
    except Exception:
        raise BoundFileError(_ERR_ROOT_UNAVAILABLE) from None


def _validated_basename(value: object) -> str:
    if type(value) is not str or not value or value in {".", ".."}:
        raise BoundFileError(_ERR_ARGUMENTS)
    try:
        encoded = value.encode("utf-8")
        utf16_size = len(value.encode("utf-16-le"))
    except UnicodeError:
        raise BoundFileError(_ERR_ARGUMENTS) from None
    if (
        len(encoded) > MAX_BOUND_BASENAME_BYTES
        or utf16_size > 65_532
        or os.path.isabs(value)
        or ntpath.isabs(value)
        or os.path.basename(value) != value
        or ntpath.basename(value) != value
        or "/" in value
        or "\\" in value
        or ":" in value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise BoundFileError(_ERR_ARGUMENTS)
    return value


def _validated_expectations(
    identity: object,
    expected_size: object,
    expected_sha256: object,
    max_bytes: object,
) -> tuple[int, str, int]:
    if (
        type(identity) is not BoundRootIdentity
        or type(max_bytes) is not int
        or not 1 <= max_bytes <= MAX_BOUND_FILE_BYTES
        or type(expected_size) is not int
        or not 1 <= expected_size <= max_bytes
        or type(expected_sha256) is not str
        or _SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise BoundFileError(_ERR_ARGUMENTS)
    return expected_size, expected_sha256, max_bytes


def _validated_limit(value: object, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise BoundFileError(_ERR_ARGUMENTS)
    return value


def _validated_prefix_limit(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_BOUND_PREFIX_BYTES:
        raise BoundFileError(_ERR_ARGUMENTS)
    return value


def _check_cancelled(stop_event: threading.Event | None) -> None:
    if stop_event is None:
        return
    try:
        stopped = bool(stop_event.is_set())
    except Exception:
        stopped = True
    if stopped:
        raise BoundFileCancelled(_ERR_CANCELLED)


def _identity_bytes(value: int) -> bytes:
    if type(value) is not int or value < 0 or value.bit_length() > 128:
        raise BoundFileError(_ERR_ROOT_UNSAFE)
    return value.to_bytes(16, "little", signed=False)


def _fd_regular_size(descriptor: int, max_bytes: int) -> int:
    try:
        current = os.fstat(descriptor)
    except OSError:
        raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE) from None
    if not stat.S_ISREG(current.st_mode):
        raise BoundFileError(_ERR_CHILD_UNSAFE)
    size = int(current.st_size)
    if size < 0:
        raise BoundFileError(_ERR_CHILD_UNSAFE)
    if size > max_bytes:
        raise BoundFileTooLarge(_ERR_CHILD_TOO_LARGE)
    return size


def _consume_fd(
    descriptor: int,
    *,
    stop_event: threading.Event | None,
    max_bytes: int,
    prefix_bytes: int,
    collect_payload: bool,
) -> tuple[BoundFileInspection, bytes | None]:
    initial_size = _fd_regular_size(descriptor, max_bytes)
    payload = bytearray() if collect_payload else None
    prefix = bytearray()
    total = 0
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    try:
        while True:
            _check_cancelled(stop_event)
            remaining = max_bytes + 1 - total
            if remaining <= 0:
                raise BoundFileTooLarge(_ERR_CHILD_TOO_LARGE)
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BoundFileTooLarge(_ERR_CHILD_TOO_LARGE)
            sha256.update(chunk)
            md5.update(chunk)
            if payload is not None:
                payload.extend(chunk)
            if len(prefix) < prefix_bytes:
                prefix.extend(chunk[: prefix_bytes - len(prefix)])
        _check_cancelled(stop_event)
        final_size = _fd_regular_size(descriptor, max_bytes)
    except BoundFileError:
        raise
    except OSError:
        raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE) from None
    if final_size != initial_size or total != initial_size:
        raise BoundFileError(_ERR_SIZE_CHANGED)
    _check_cancelled(stop_event)
    result_payload = bytes(payload) if payload is not None else None
    _check_cancelled(stop_event)
    return (
        BoundFileInspection(
            size=total,
            sha256=sha256.hexdigest(),
            md5=md5.hexdigest(),
            prefix=bytes(prefix),
        ),
        result_payload,
    )


def _read_fd_verified(
    descriptor: int,
    *,
    expected_size: int,
    expected_sha256: str,
    stop_event: threading.Event | None,
    max_bytes: int,
) -> bytes:
    inspection, payload = _consume_fd(
        descriptor,
        stop_event=stop_event,
        max_bytes=max_bytes,
        prefix_bytes=0,
        collect_payload=True,
    )
    if inspection.size != expected_size:
        raise BoundFileError(_ERR_SIZE_CHANGED)
    if not hmac.compare_digest(inspection.sha256, expected_sha256):
        raise BoundFileError(_ERR_DIGEST_CHANGED)
    assert payload is not None
    return payload


def _close_fd(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _posix_open_root(path: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        nofollow is None
        or directory is None
        or os.open not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
    ):
        raise BoundFileError(_ERR_ROOT_UNSAFE)
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise BoundFileError(_ERR_ROOT_UNAVAILABLE) from None
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode):
            raise BoundFileError(_ERR_ROOT_UNSAFE)
    except BoundFileError:
        _close_fd(descriptor)
        raise
    except OSError:
        _close_fd(descriptor)
        raise BoundFileError(_ERR_ROOT_UNSAFE) from None
    except BaseException:
        _close_fd(descriptor)
        raise
    return descriptor


def _posix_root_identity(descriptor: int) -> BoundRootIdentity:
    try:
        value = os.fstat(descriptor)
    except OSError:
        raise BoundFileError(_ERR_ROOT_UNSAFE) from None
    if not stat.S_ISDIR(value.st_mode):
        raise BoundFileError(_ERR_ROOT_UNSAFE)
    return BoundRootIdentity(
        platform="posix",
        volume_id=int(value.st_dev),
        file_id=_identity_bytes(int(value.st_ino)),
    )


def _posix_child_open_error(error: OSError) -> BoundFileError:
    if error.errno in _POSIX_UNREADABLE_ERRNOS:
        return BoundFileUnreadable(_ERR_CHILD_UNREADABLE)
    return BoundFileError(_ERR_CHILD_UNSAFE)


def _posix_open_child(root_descriptor: int, basename: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblocking is None:
        raise BoundFileError(_ERR_CHILD_UNSAFE)
    flags = (
        os.O_RDONLY
        | nofollow
        | nonblocking
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        return os.open(basename, flags, dir_fd=root_descriptor)
    except FileNotFoundError:
        raise BoundFileMissing(_ERR_CHILD_MISSING) from None
    except OSError as exc:
        raise _posix_child_open_error(exc) from None


def _posix_validate_child(descriptor: int, expected_size: int) -> None:
    try:
        value = os.fstat(descriptor)
    except OSError:
        raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE) from None
    if not stat.S_ISREG(value.st_mode):
        raise BoundFileError(_ERR_CHILD_UNSAFE)
    if int(value.st_size) != expected_size:
        raise BoundFileError(_ERR_SIZE_CHANGED)


def _read_posix_child(
    path: str,
    expected_identity: BoundRootIdentity,
    basename: str,
    expected_size: int,
    expected_sha256: str,
    stop_event: threading.Event | None,
    max_bytes: int,
) -> bytes:
    root_descriptor = _posix_open_root(path)
    child_descriptor = None
    try:
        if _posix_root_identity(root_descriptor) != expected_identity:
            raise BoundFileError(_ERR_ROOT_CHANGED)
        _check_cancelled(stop_event)
        child_descriptor = _posix_open_child(root_descriptor, basename)
        _posix_validate_child(child_descriptor, expected_size)
        return _read_fd_verified(
            child_descriptor,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            stop_event=stop_event,
            max_bytes=max_bytes,
        )
    finally:
        try:
            _close_fd(child_descriptor)
        finally:
            _close_fd(root_descriptor)


if os.name == "nt":
    import msvcrt

    _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_READ_DATA = 0x0001
    _FILE_READ_ATTRIBUTES = 0x0080
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_TYPE_DISK = 0x0001

    _STATUS_NO_SUCH_FILE = ctypes.c_int32(0xC000000F).value
    _STATUS_ACCESS_DENIED = ctypes.c_int32(0xC0000022).value
    _STATUS_OBJECT_NAME_NOT_FOUND = ctypes.c_int32(0xC0000034).value
    _STATUS_OBJECT_PATH_NOT_FOUND = ctypes.c_int32(0xC000003A).value
    _STATUS_SHARING_VIOLATION = ctypes.c_int32(0xC0000043).value
    _STATUS_FILE_LOCK_CONFLICT = ctypes.c_int32(0xC0000054).value
    _STATUS_LOCK_NOT_GRANTED = ctypes.c_int32(0xC0000055).value
    _WINDOWS_UNREADABLE_OPEN_STATUSES = frozenset(
        {
            _STATUS_ACCESS_DENIED,
            _STATUS_SHARING_VIOLATION,
            _STATUS_FILE_LOCK_CONFLICT,
            _STATUS_LOCK_NOT_GRANTED,
        }
    )

    _OBJ_CASE_INSENSITIVE = 0x00000040
    _FILE_OPEN = 0x00000001
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_OPEN_REPARSE_POINT = 0x00200000

    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_INFO_CLASS = 18

    class _FILE_ID_128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


    class _FILE_ID_INFO(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FILE_ID_128),
        ]


    class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]


    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]


    class _OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p),
            ("SecurityQualityOfService", ctypes.c_void_p),
        ]


    class _IO_STATUS_VALUE(ctypes.Union):
        _fields_ = [("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p)]


    class _IO_STATUS_BLOCK(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [("value", _IO_STATUS_VALUE), ("Information", ctypes.c_size_t)]


    _kernel32 = ctypes.WinDLL(
        "kernel32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )
    _ntdll = ctypes.WinDLL(
        "ntdll.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _GetFileInformationByHandleEx.restype = wintypes.BOOL

    _GetFileSizeEx = _kernel32.GetFileSizeEx
    _GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    _GetFileSizeEx.restype = wintypes.BOOL

    _GetFileType = _kernel32.GetFileType
    _GetFileType.argtypes = [wintypes.HANDLE]
    _GetFileType.restype = wintypes.DWORD

    _NtCreateFile = _ntdll.NtCreateFile
    _NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    _NtCreateFile.restype = ctypes.c_long


def _win_handle_value(handle: object) -> int | None:
    if handle is None:
        return None
    if isinstance(handle, int):
        return handle
    return ctypes.cast(handle, ctypes.c_void_p).value


def _win_close_handle(handle: int | None) -> None:
    if os.name != "nt" or handle is None or handle == _INVALID_HANDLE_VALUE:
        return
    try:
        _CloseHandle(wintypes.HANDLE(handle))
    except Exception:
        pass


def _win_open_root(path: str) -> int:
    handle = _CreateFileW(
        path,
        _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    value = _win_handle_value(handle)
    if value is None or value == _INVALID_HANDLE_VALUE:
        raise BoundFileError(_ERR_ROOT_UNAVAILABLE)
    try:
        attributes = _win_attributes(value, root=True)
        if (
            not attributes & _FILE_ATTRIBUTE_DIRECTORY
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise BoundFileError(_ERR_ROOT_UNSAFE)
    except BaseException:
        _win_close_handle(value)
        raise
    return value


def _win_attributes(handle: int, *, root: bool) -> int:
    info = _FILE_ATTRIBUTE_TAG_INFO()
    if not _GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise BoundFileError(_ERR_ROOT_UNSAFE if root else _ERR_CHILD_UNSAFE)
    return int(info.FileAttributes)


def _win_root_identity(handle: int) -> BoundRootIdentity:
    attributes = _win_attributes(handle, root=True)
    if (
        not attributes & _FILE_ATTRIBUTE_DIRECTORY
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise BoundFileError(_ERR_ROOT_UNSAFE)
    info = _FILE_ID_INFO()
    if not _GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise BoundFileError(_ERR_ROOT_UNSAFE)
    return BoundRootIdentity(
        platform="windows",
        volume_id=int(info.VolumeSerialNumber),
        file_id=bytes(info.FileId.Identifier),
    )


def _win_open_child(root_handle: int, basename: str) -> int:
    name_buffer = ctypes.create_unicode_buffer(basename)
    encoded_length = len(basename.encode("utf-16-le"))
    name = _UNICODE_STRING(
        Length=encoded_length,
        MaximumLength=encoded_length + 2,
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(root_handle),
        ObjectName=ctypes.pointer(name),
        Attributes=_OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    status_block = _IO_STATUS_BLOCK()
    child = wintypes.HANDLE()
    status_code = int(
        _NtCreateFile(
            ctypes.byref(child),
            _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            0,
            _FILE_SHARE_READ,
            _FILE_OPEN,
            _FILE_SYNCHRONOUS_IO_NONALERT
            | _FILE_NON_DIRECTORY_FILE
            | _FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    )
    value = _win_handle_value(child)
    if status_code < 0 or value is None or value == _INVALID_HANDLE_VALUE:
        _win_close_handle(value)
        if status_code in {
            _STATUS_NO_SUCH_FILE,
            _STATUS_OBJECT_NAME_NOT_FOUND,
            _STATUS_OBJECT_PATH_NOT_FOUND,
        }:
            raise BoundFileMissing(_ERR_CHILD_MISSING)
        if status_code in _WINDOWS_UNREADABLE_OPEN_STATUSES:
            raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE)
        raise BoundFileError(_ERR_CHILD_UNSAFE)
    return value


def _win_validate_child_kind(handle: int) -> None:
    attributes = _win_attributes(handle, root=False)
    if (
        attributes & _FILE_ATTRIBUTE_DIRECTORY
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or int(_GetFileType(wintypes.HANDLE(handle))) != _FILE_TYPE_DISK
    ):
        raise BoundFileError(_ERR_CHILD_UNSAFE)


def _win_validate_child(handle: int, expected_size: int) -> None:
    _win_validate_child_kind(handle)
    size = ctypes.c_longlong()
    if not _GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
        raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE)
    if int(size.value) != expected_size:
        raise BoundFileError(_ERR_SIZE_CHANGED)


def _win_handle_to_fd(handle: int) -> int:
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError:
        raise BoundFileUnreadable(_ERR_CHILD_UNREADABLE) from None
    except (OverflowError, ValueError):
        raise BoundFileError(_ERR_CHILD_UNSAFE) from None


def _read_windows_child(
    path: str,
    expected_identity: BoundRootIdentity,
    basename: str,
    expected_size: int,
    expected_sha256: str,
    stop_event: threading.Event | None,
    max_bytes: int,
) -> bytes:
    root_handle = _win_open_root(path)
    child_handle = None
    child_descriptor = None
    try:
        if _win_root_identity(root_handle) != expected_identity:
            raise BoundFileError(_ERR_ROOT_CHANGED)
        _check_cancelled(stop_event)
        child_handle = _win_open_child(root_handle, basename)
        _win_validate_child(child_handle, expected_size)
        child_descriptor = _win_handle_to_fd(child_handle)
        child_handle = None  # open_osfhandle transferred ownership to the CRT fd.
        return _read_fd_verified(
            child_descriptor,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            stop_event=stop_event,
            max_bytes=max_bytes,
        )
    finally:
        try:
            _close_fd(child_descriptor)
        finally:
            try:
                _win_close_handle(child_handle)
            finally:
                _win_close_handle(root_handle)


__all__ = [
    "BoundFileCancelled",
    "BoundFileError",
    "BoundFileInspection",
    "BoundFileMissing",
    "BoundFileTooLarge",
    "BoundFileUnreadable",
    "BoundRootIdentity",
    "BoundRootSession",
    "MAX_BOUND_BASENAME_BYTES",
    "MAX_BOUND_DIRECTORY_ENTRIES",
    "MAX_BOUND_FILE_BYTES",
    "MAX_BOUND_PREFIX_BYTES",
    "MAX_BOUND_STREAM_BYTES",
    "get_bound_root_identity",
    "open_bound_root",
    "read_verified_child",
]
