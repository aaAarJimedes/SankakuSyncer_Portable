# -*- coding: utf-8 -*-
"""Handle-bound snapshots and verified reads of a release archive tree.

The original pathname is used only to acquire the root handle.  Every later
lookup is relative to an already-open directory handle/file descriptor, and
all public failures use fixed English strings so native paths and errors never
cross this module's boundary.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import errno
import hashlib
import os
import re
import stat
import threading
from types import MappingProxyType
from typing import Iterable, Literal, Mapping
import unicodedata


_DEFAULT_MAX_ENTRIES = 100_000
_DEFAULT_MAX_DEPTH = 128
_DEFAULT_MAX_COMPONENT_UTF8 = 1_024
_DEFAULT_MAX_RELATIVE_UTF8 = 32_768
_DEFAULT_MAX_FILE_BYTES = 50 * 1024**3
_DEFAULT_MAX_TOTAL_BYTES = 100 * 1024**3
_DEFAULT_CHUNK_SIZE = 1024 * 1024
_MAX_CHUNK_SIZE = 16 * 1024 * 1024
_READ_CHUNK_SIZE = 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

_ERR_ARGUMENTS = "invalid bound tree arguments"
_ERR_ROOT_UNAVAILABLE = "bound tree root unavailable"
_ERR_ROOT_UNSAFE = "bound tree root unsafe"
_ERR_ENTRY_UNAVAILABLE = "bound tree entry unavailable"
_ERR_ENTRY_UNSAFE = "bound tree entry unsafe"
_ERR_CHANGED = "bound tree changed"
_ERR_LIMIT = "bound tree limit exceeded"
_ERR_SNAPSHOT = "bound tree snapshot mismatch"
_ERR_TARGET = "bound tree target write failed"
_ERR_PRIVATE_CHANGED = "private archive directories changed while archiving"

_OPERATIONAL_ERRNOS = frozenset(
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


class BoundTreeError(RuntimeError):
    """A stable, path-redacted release-tree failure."""


class BoundTreeUnavailable(BoundTreeError):
    """An otherwise safe tree object could not be opened, read, or written."""


class BoundTreeUnsafe(BoundTreeError):
    """The tree contains an unsupported or redirectable object."""


class BoundTreeChanged(BoundTreeError):
    """A bound object no longer matches the committed snapshot."""


class BoundTreeLimitExceeded(BoundTreeError):
    """A configured tree resource budget was exceeded."""


@dataclass(frozen=True, slots=True)
class TreeLimits:
    max_entries: int = _DEFAULT_MAX_ENTRIES
    max_depth: int = _DEFAULT_MAX_DEPTH
    max_component_utf8: int = _DEFAULT_MAX_COMPONENT_UTF8
    max_relative_utf8: int = _DEFAULT_MAX_RELATIVE_UTF8
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        values = (
            (self.max_entries, _DEFAULT_MAX_ENTRIES),
            (self.max_depth, _DEFAULT_MAX_DEPTH),
            (self.max_component_utf8, _DEFAULT_MAX_COMPONENT_UTF8),
            (self.max_relative_utf8, _DEFAULT_MAX_RELATIVE_UTF8),
            (self.max_file_bytes, _DEFAULT_MAX_FILE_BYTES),
            (self.max_total_bytes, _DEFAULT_MAX_TOTAL_BYTES),
        )
        if any(type(value) is not int or not 1 <= value <= maximum for value, maximum in values):
            raise ValueError(_ERR_ARGUMENTS)


@dataclass(frozen=True, slots=True)
class TreeIdentity:
    platform: Literal["posix", "windows"]
    volume_id: int
    file_id: bytes

    def __post_init__(self) -> None:
        if (
            type(self.platform) is not str
            or self.platform not in {"posix", "windows"}
            or type(self.volume_id) is not int
            or self.volume_id < 0
            or type(self.file_id) is not bytes
            or not self.file_id
            or len(self.file_id) > 32
        ):
            raise ValueError(_ERR_ARGUMENTS)


@dataclass(frozen=True, slots=True)
class TreeNode:
    parent_index: int | None
    name: str
    kind: Literal["directory", "file"]
    identity: TreeIdentity
    size: int
    change_token: tuple[int, ...]
    sha256: str | None

    def __post_init__(self) -> None:
        if (
            (self.parent_index is not None and (type(self.parent_index) is not int or self.parent_index < 0))
            or type(self.name) is not str
            or not self.name
            or self.kind not in {"directory", "file"}
            or type(self.identity) is not TreeIdentity
            or type(self.size) is not int
            or self.size < 0
            or (self.kind == "directory" and self.size != 0)
            or type(self.change_token) is not tuple
            or not self.change_token
            or any(type(value) is not int for value in self.change_token)
            or (
                self.sha256 is not None
                and (
                    type(self.sha256) is not str
                    or _SHA256_RE.fullmatch(self.sha256) is None
                )
            )
        ):
            raise ValueError(_ERR_ARGUMENTS)


@dataclass(frozen=True, slots=True)
class TreeSnapshot:
    root_identity: TreeIdentity
    nodes: tuple[TreeNode, ...]
    directory_indexes: tuple[int, ...]
    file_indexes: tuple[int, ...]
    private_directories: tuple[int, ...]
    _parts: tuple[tuple[str, ...], ...] = field(init=False, repr=False, compare=False)
    _index_by_parts: Mapping[tuple[str, ...], int] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if (
            type(self.root_identity) is not TreeIdentity
            or type(self.nodes) is not tuple
            or type(self.directory_indexes) is not tuple
            or type(self.file_indexes) is not tuple
            or type(self.private_directories) is not tuple
            or any(type(node) is not TreeNode for node in self.nodes)
        ):
            raise ValueError(_ERR_ARGUMENTS)

        parts: list[tuple[str, ...]] = []
        index_by_parts: dict[tuple[str, ...], int] = {}
        names_by_parent: dict[int | None, set[str]] = {}
        directory_identities = {self.root_identity}
        for index, node in enumerate(self.nodes):
            parent = node.parent_index
            if parent is None:
                current_parts = (node.name,)
            else:
                if parent >= index or self.nodes[parent].kind != "directory":
                    raise ValueError(_ERR_ARGUMENTS)
                current_parts = parts[parent] + (node.name,)
            if (
                not _component_shape_is_safe(node.name)
                or current_parts in index_by_parts
                or node.identity.platform != self.root_identity.platform
                or node.identity.volume_id != self.root_identity.volume_id
            ):
                raise ValueError(_ERR_ARGUMENTS)
            folded = node.name.casefold()
            sibling_names = names_by_parent.setdefault(parent, set())
            if folded in sibling_names:
                raise ValueError(_ERR_ARGUMENTS)
            sibling_names.add(folded)
            if node.kind == "directory":
                if node.identity in directory_identities:
                    raise ValueError(_ERR_ARGUMENTS)
                directory_identities.add(node.identity)
            parts.append(current_parts)
            index_by_parts[current_parts] = index

        directories = _validated_index_tuple(self.directory_indexes, len(self.nodes))
        files = _validated_index_tuple(self.file_indexes, len(self.nodes))
        private = _validated_index_tuple(self.private_directories, len(self.nodes))
        if (
            directories & files
            or directories | files != set(range(len(self.nodes)))
            or any(self.nodes[index].kind != "directory" for index in directories)
            or any(self.nodes[index].kind != "file" for index in files)
            or not private <= directories
            or any(self.nodes[index].parent_index is not None for index in private)
        ):
            raise ValueError(_ERR_ARGUMENTS)
        object.__setattr__(self, "_parts", tuple(parts))
        object.__setattr__(self, "_index_by_parts", MappingProxyType(index_by_parts))

    def relative_parts(self, node_index: int) -> tuple[str, ...]:
        if type(node_index) is not int or not 0 <= node_index < len(self.nodes):
            raise BoundTreeError(_ERR_ARGUMENTS)
        return self._parts[node_index]

    def index(self, relative_parts: Iterable[str]) -> int:
        if isinstance(relative_parts, (str, bytes)):
            raise BoundTreeError(_ERR_ARGUMENTS)
        try:
            parts = tuple(relative_parts)
        except Exception:
            raise BoundTreeError(_ERR_ARGUMENTS) from None
        if not parts or any(type(part) is not str for part in parts):
            raise BoundTreeError(_ERR_ARGUMENTS)
        try:
            return self._index_by_parts[parts]
        except KeyError:
            raise BoundTreeChanged(_ERR_SNAPSHOT) from None


@dataclass(frozen=True, slots=True)
class _NodeState:
    identity: TreeIdentity
    kind: Literal["directory", "file"]
    size: int
    change_token: tuple[int, ...]


def _validated_index_tuple(values: tuple[int, ...], node_count: int) -> set[int]:
    if any(type(value) is not int or not 0 <= value < node_count for value in values):
        raise ValueError(_ERR_ARGUMENTS)
    result = set(values)
    if len(result) != len(values):
        raise ValueError(_ERR_ARGUMENTS)
    return result


def _component_shape_is_safe(name: str) -> bool:
    return (
        type(name) is str
        and bool(name)
        and name not in {".", ".."}
        and "/" not in name
        and "\\" not in name
        and ":" not in name
        and "\x00" not in name
        and not any(unicodedata.category(character).startswith("C") for character in name)
    )


def _validated_component(name: object, limits: TreeLimits) -> str:
    if not _component_shape_is_safe(name):
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    assert isinstance(name, str)
    try:
        encoded = name.encode("utf-8")
        utf16_size = len(name.encode("utf-16-le"))
    except UnicodeError:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None
    if len(encoded) > limits.max_component_utf8 or utf16_size > 65_532:
        raise BoundTreeLimitExceeded(_ERR_LIMIT)
    return name


def _validated_root_path(root: object) -> str:
    try:
        raw = os.fspath(root)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise ValueError
        return os.path.abspath(raw)
    except Exception:
        raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE) from None


def _identity_bytes(value: int) -> bytes:
    if type(value) is not int or value < 0 or value.bit_length() > 128:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    return value.to_bytes(16, "little", signed=False)


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
        raise BoundTreeUnsafe(_ERR_ROOT_UNSAFE)
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise BoundTreeUnsafe(_ERR_ROOT_UNSAFE) from None
        raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE) from None
    try:
        state = _posix_state(descriptor)
        if state.kind != "directory":
            raise BoundTreeUnsafe(_ERR_ROOT_UNSAFE)
        return descriptor
    except BaseException:
        _close_fd(descriptor)
        raise


def _posix_open_any(parent_descriptor: int, name: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblocking is None:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    flags = (
        os.O_RDONLY
        | nofollow
        | nonblocking
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        return os.open(name, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        raise BoundTreeChanged(_ERR_CHANGED) from None
    except OSError as exc:
        if exc.errno in _OPERATIONAL_ERRNOS:
            raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None


def _posix_state(descriptor: int) -> _NodeState:
    try:
        value = os.fstat(descriptor)
    except OSError:
        raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None
    if stat.S_ISDIR(value.st_mode):
        kind: Literal["directory", "file"] = "directory"
        size = 0
    elif stat.S_ISREG(value.st_mode):
        kind = "file"
        size = int(value.st_size)
        if int(value.st_nlink) != 1:
            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    else:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    if size < 0:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    identity = TreeIdentity(
        platform="posix",
        volume_id=int(value.st_dev),
        file_id=_identity_bytes(int(value.st_ino)),
    )
    token = (
        int(value.st_mode),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
        int(getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))),
        int(value.st_nlink),
    )
    return _NodeState(identity, kind, size, token)


def _posix_list_names(descriptor: int, max_entries: int) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as iterator:
            for item in iterator:
                if len(names) >= max_entries:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                if type(item.name) is not str:
                    raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
                names.append(item.name)
    except BoundTreeError:
        raise
    except OSError:
        raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None
    return tuple(names)


if os.name == "nt":
    _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_READ_DATA = 0x0001
    _FILE_READ_ATTRIBUTES = 0x0080
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_TYPE_DISK = 0x0001

    _FILE_OPEN = 0x00000001
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_OPEN_REPARSE_POINT = 0x00200000

    _FILE_BASIC_INFO_CLASS = 0
    _FILE_STANDARD_INFO_CLASS = 1
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_BOTH_DIRECTORY_INFO_CLASS = 10
    _FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS = 11
    _FILE_ID_INFO_CLASS = 18
    _WIN_DIRECTORY_BUFFER_BYTES = 64 * 1024

    _ERROR_FILE_NOT_FOUND = 2
    _ERROR_PATH_NOT_FOUND = 3
    _ERROR_TOO_MANY_OPEN_FILES = 4
    _ERROR_ACCESS_DENIED = 5
    _ERROR_NOT_ENOUGH_MEMORY = 8
    _ERROR_NO_MORE_FILES = 18
    _ERROR_SHARING_VIOLATION = 32
    _ERROR_LOCK_VIOLATION = 33
    _ERROR_HANDLE_EOF = 38
    _ERROR_INSUFFICIENT_BUFFER = 122
    _ERROR_MORE_DATA = 234
    _ERROR_IO_DEVICE = 1117
    _WINDOWS_OPERATIONAL_ERRORS = frozenset(
        {
            _ERROR_TOO_MANY_OPEN_FILES,
            _ERROR_ACCESS_DENIED,
            _ERROR_NOT_ENOUGH_MEMORY,
            _ERROR_SHARING_VIOLATION,
            _ERROR_LOCK_VIOLATION,
            _ERROR_IO_DEVICE,
        }
    )

    _STATUS_NO_SUCH_FILE = ctypes.c_int32(0xC000000F).value
    _STATUS_ACCESS_DENIED = ctypes.c_int32(0xC0000022).value
    _STATUS_OBJECT_NAME_NOT_FOUND = ctypes.c_int32(0xC0000034).value
    _STATUS_OBJECT_PATH_NOT_FOUND = ctypes.c_int32(0xC000003A).value
    _STATUS_SHARING_VIOLATION = ctypes.c_int32(0xC0000043).value
    _STATUS_FILE_LOCK_CONFLICT = ctypes.c_int32(0xC0000054).value
    _STATUS_LOCK_NOT_GRANTED = ctypes.c_int32(0xC0000055).value
    _WINDOWS_MISSING_STATUSES = frozenset(
        {
            _STATUS_NO_SUCH_FILE,
            _STATUS_OBJECT_NAME_NOT_FOUND,
            _STATUS_OBJECT_PATH_NOT_FOUND,
        }
    )
    _WINDOWS_OPERATIONAL_STATUSES = frozenset(
        {
            _STATUS_ACCESS_DENIED,
            _STATUS_SHARING_VIOLATION,
            _STATUS_FILE_LOCK_CONFLICT,
            _STATUS_LOCK_NOT_GRANTED,
        }
    )

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


    class _FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]


    class _FILE_STANDARD_INFO(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", wintypes.DWORD),
            ("DeletePending", ctypes.c_ubyte),
            ("Directory", ctypes.c_ubyte),
        ]


    class _FILE_ID_BOTH_DIR_INFO(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", wintypes.DWORD),
            ("FileIndex", wintypes.DWORD),
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("AllocationSize", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
            ("FileNameLength", wintypes.DWORD),
            ("EaSize", wintypes.DWORD),
            ("ShortNameLength", ctypes.c_byte),
            ("ShortName", wintypes.WCHAR * 12),
            ("FileId", ctypes.c_longlong),
            ("FileName", wintypes.WCHAR * 1),
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

    _GetFileType = _kernel32.GetFileType
    _GetFileType.argtypes = [wintypes.HANDLE]
    _GetFileType.restype = wintypes.DWORD

    _ReadFile = _kernel32.ReadFile
    _ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _ReadFile.restype = wintypes.BOOL

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


def _win_query(handle: int, information_class: int, value: ctypes.Structure) -> None:
    if not _GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        information_class,
        ctypes.byref(value),
        ctypes.sizeof(value),
    ):
        error = int(ctypes.get_last_error())
        if error in _WINDOWS_OPERATIONAL_ERRORS:
            raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE)
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)


def _win_state(handle: int) -> _NodeState:
    attributes = _FILE_ATTRIBUTE_TAG_INFO()
    basic = _FILE_BASIC_INFO()
    standard = _FILE_STANDARD_INFO()
    identity_info = _FILE_ID_INFO()
    _win_query(handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, attributes)
    _win_query(handle, _FILE_BASIC_INFO_CLASS, basic)
    _win_query(handle, _FILE_STANDARD_INFO_CLASS, standard)
    _win_query(handle, _FILE_ID_INFO_CLASS, identity_info)
    file_attributes = int(attributes.FileAttributes)
    is_directory = bool(standard.Directory)
    if (
        file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or bool(file_attributes & _FILE_ATTRIBUTE_DIRECTORY) != is_directory
        or bool(standard.DeletePending)
        or int(_GetFileType(wintypes.HANDLE(handle))) != _FILE_TYPE_DISK
    ):
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    kind: Literal["directory", "file"] = "directory" if is_directory else "file"
    size = 0 if is_directory else int(standard.EndOfFile)
    if size < 0 or (not is_directory and int(standard.NumberOfLinks) != 1):
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    identity = TreeIdentity(
        platform="windows",
        volume_id=int(identity_info.VolumeSerialNumber),
        file_id=bytes(identity_info.FileId.Identifier),
    )
    token = (
        int(basic.CreationTime),
        int(basic.LastWriteTime),
        int(basic.ChangeTime),
        file_attributes,
        int(standard.AllocationSize),
        int(standard.EndOfFile),
        int(standard.NumberOfLinks),
        int(standard.DeletePending),
        int(standard.Directory),
    )
    return _NodeState(identity, kind, size, token)


def _win_open_root(path: str) -> int:
    handle = _CreateFileW(
        path,
        _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    value = _win_handle_value(handle)
    if value is None or value == _INVALID_HANDLE_VALUE:
        raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE)
    try:
        if _win_state(value).kind != "directory":
            raise BoundTreeUnsafe(_ERR_ROOT_UNSAFE)
        return value
    except BoundTreeUnavailable:
        _win_close_handle(value)
        raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE) from None
    except BaseException:
        _win_close_handle(value)
        raise


def _win_open_any(parent_handle: int, name: str) -> int:
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UNICODE_STRING(
        Length=encoded_length,
        MaximumLength=encoded_length + 2,
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(parent_handle),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=0,
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
            _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    )
    value = _win_handle_value(child)
    if status_code < 0 or value is None or value == _INVALID_HANDLE_VALUE:
        _win_close_handle(value)
        if status_code in _WINDOWS_MISSING_STATUSES:
            raise BoundTreeChanged(_ERR_CHANGED)
        if status_code in _WINDOWS_OPERATIONAL_STATUSES:
            raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE)
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    return value


def _win_validate_directory_abi() -> None:
    expected_offsets = {
        "NextEntryOffset": 0,
        "FileAttributes": 56,
        "FileNameLength": 60,
        "ShortNameLength": 68,
        "ShortName": 70,
        "FileId": 96,
        "FileName": 104,
    }
    if any(
        getattr(_FILE_ID_BOTH_DIR_INFO, field_name).offset != expected
        for field_name, expected in expected_offsets.items()
    ) or ctypes.sizeof(_FILE_ID_BOTH_DIR_INFO) != 112:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)


def _win_list_names(handle: int, max_entries: int) -> tuple[str, ...]:
    _win_validate_directory_abi()
    names: list[str] = []
    restart = True
    filename_offset = _FILE_ID_BOTH_DIR_INFO.FileName.offset
    structure_size = ctypes.sizeof(_FILE_ID_BOTH_DIR_INFO)
    while True:
        buffer = ctypes.create_string_buffer(_WIN_DIRECTORY_BUFFER_BYTES)
        information_class = (
            _FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS
            if restart
            else _FILE_ID_BOTH_DIRECTORY_INFO_CLASS
        )
        restart = False
        ctypes.set_last_error(0)
        succeeded = bool(
            _GetFileInformationByHandleEx(
                wintypes.HANDLE(handle),
                information_class,
                buffer,
                _WIN_DIRECTORY_BUFFER_BYTES,
            )
        )
        if not succeeded:
            error = int(ctypes.get_last_error())
            if error == _ERROR_NO_MORE_FILES:
                break
            if error in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
                raise BoundTreeChanged(_ERR_CHANGED)
            if error in _WINDOWS_OPERATIONAL_ERRORS:
                raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE)
            if error in {_ERROR_INSUFFICIENT_BUFFER, _ERROR_MORE_DATA}:
                raise BoundTreeLimitExceeded(_ERR_LIMIT)
            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)

        offset = 0
        while True:
            if offset < 0 or offset + structure_size > _WIN_DIRECTORY_BUFFER_BYTES:
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            record = _FILE_ID_BOTH_DIR_INFO.from_buffer(buffer, offset)
            filename_length = int(record.FileNameLength)
            if filename_length <= 0 or filename_length % 2:
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            filename_start = offset + filename_offset
            filename_end = filename_start + filename_length
            if filename_end > _WIN_DIRECTORY_BUFFER_BYTES:
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            try:
                encoded = ctypes.string_at(
                    ctypes.addressof(buffer) + filename_start, filename_length
                )
                name = encoded.decode("utf-16-le", "strict")
            except (UnicodeError, ValueError):
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None
            if name not in {".", ".."}:
                if len(names) >= max_entries:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                names.append(name)

            next_offset = int(record.NextEntryOffset)
            if next_offset == 0:
                break
            if (
                next_offset % 8
                or next_offset < filename_offset + filename_length
                or offset + next_offset + structure_size > _WIN_DIRECTORY_BUFFER_BYTES
            ):
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            offset += next_offset
    return tuple(names)


def _win_read(handle: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    received = wintypes.DWORD()
    if not _ReadFile(
        wintypes.HANDLE(handle),
        buffer,
        size,
        ctypes.byref(received),
        None,
    ):
        error = int(ctypes.get_last_error())
        if error == _ERROR_HANDLE_EOF:
            return b""
        raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE)
    count = int(received.value)
    if not 0 <= count <= size:
        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
    return bytes(buffer.raw[:count])


class BoundTreeSession:
    """A root handle retained for snapshots and verified archive reads."""

    __slots__ = ("_limits", "_lock", "_path", "_root_identity", "_token")

    def __init__(
        self,
        path: str,
        token: int,
        identity: TreeIdentity,
        limits: TreeLimits,
    ) -> None:
        self._path = path
        self._token: int | None = token
        self._root_identity = identity
        self._limits = limits
        self._lock = threading.RLock()

    def __enter__(self) -> BoundTreeSession:
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
    def closed(self) -> bool:
        with self._lock:
            return self._token is None

    @property
    def root_identity(self) -> TreeIdentity:
        return self._root_identity

    @property
    def limits(self) -> TreeLimits:
        return self._limits

    def close(self) -> None:
        with self._lock:
            token = self._token
            self._token = None
            if token is None:
                return
            if os.name == "nt":
                _win_close_handle(token)
            else:
                _close_fd(token)

    def snapshot(
        self,
        private_directories: Iterable[str] = (),
        hash_files: bool = True,
    ) -> TreeSnapshot:
        try:
            with self._lock:
                token = self._require_open()
                private_names = self._validated_private_names(private_directories)
                if type(hash_files) is not bool:
                    raise BoundTreeError(_ERR_ARGUMENTS)
                return self._snapshot_locked(token, private_names, hash_files)
        except BoundTreeError:
            raise
        except Exception:
            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None

    def copy_verified_file(
        self,
        snapshot: TreeSnapshot,
        node_index: int,
        target: object,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> int:
        try:
            with self._lock:
                self._require_open()
                self._validate_snapshot(snapshot)
                if (
                    type(node_index) is not int
                    or not 0 <= node_index < len(snapshot.nodes)
                    or snapshot.nodes[node_index].kind != "file"
                    or snapshot.nodes[node_index].sha256 is None
                    or type(chunk_size) is not int
                    or not 1 <= chunk_size <= _MAX_CHUNK_SIZE
                ):
                    raise BoundTreeError(_ERR_ARGUMENTS)
                try:
                    writer = getattr(target, "write")
                except Exception:
                    raise BoundTreeError(_ERR_ARGUMENTS) from None
                if not callable(writer):
                    raise BoundTreeError(_ERR_ARGUMENTS)
                token = self._open_verified_node(snapshot, node_index)
                try:
                    node = snapshot.nodes[node_index]
                    before = self._state(token)
                    if not _state_matches_node(before, node):
                        raise BoundTreeChanged(_ERR_CHANGED)
                    total, digest = self._stream_file(
                        token,
                        max_bytes=node.size,
                        chunk_size=chunk_size,
                        writer=writer,
                    )
                    after = self._state(token)
                    if (
                        after != before
                        or total != node.size
                        or (node.sha256 is not None and digest != node.sha256)
                    ):
                        raise BoundTreeChanged(_ERR_CHANGED)
                    return total
                finally:
                    self._close_token(token)
        except BoundTreeError:
            raise
        except Exception:
            raise BoundTreeUnavailable(_ERR_TARGET) from None

    def verify_snapshot(
        self,
        snapshot: TreeSnapshot,
        verify_content: bool = False,
    ) -> None:
        try:
            with self._lock:
                token = self._require_open()
                self._validate_snapshot(snapshot)
                if type(verify_content) is not bool:
                    raise BoundTreeError(_ERR_ARGUMENTS)
                if verify_content and any(
                    snapshot.nodes[index].sha256 is None
                    for index in snapshot.file_indexes
                ):
                    raise BoundTreeError(_ERR_ARGUMENTS)
                private_names = tuple(
                    snapshot.nodes[index].name
                    for index in snapshot.private_directories
                )
                current = self._snapshot_locked(token, private_names, verify_content)
                if not _snapshots_match(snapshot, current, verify_content):
                    raise BoundTreeChanged(_ERR_SNAPSHOT)
        except BoundTreeError:
            raise
        except Exception:
            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None

    def verify_private_directories(self, snapshot: TreeSnapshot) -> None:
        try:
            with self._lock:
                self._require_open()
                self._validate_snapshot(snapshot)
                for node_index in snapshot.private_directories:
                    node = snapshot.nodes[node_index]
                    try:
                        token = self._open_verified_node(
                            snapshot,
                            node_index,
                            require_change_token=False,
                        )
                    except BoundTreeError:
                        raise BoundTreeChanged(_ERR_PRIVATE_CHANGED) from None
                    try:
                        before = self._state(token)
                        if not _state_matches_node(
                            before,
                            node,
                            require_change_token=False,
                        ):
                            raise BoundTreeChanged(_ERR_PRIVATE_CHANGED)
                        if self._list_names(token):
                            raise BoundTreeChanged(
                                "private archive directory must be empty: "
                                f"{node.name}"
                            )
                        if not _state_matches_node(before, node):
                            raise BoundTreeChanged(_ERR_PRIVATE_CHANGED)
                        if self._state(token) != before:
                            raise BoundTreeChanged(_ERR_PRIVATE_CHANGED)
                    finally:
                        self._close_token(token)
        except BoundTreeError:
            raise
        except Exception:
            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE) from None

    def _require_open(self) -> int:
        if self._token is None:
            raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE)
        return self._token

    def _validated_private_names(
        self, private_directories: Iterable[str]
    ) -> tuple[str, ...]:
        if isinstance(private_directories, (str, bytes)):
            raise BoundTreeError(_ERR_ARGUMENTS)
        try:
            names = tuple(private_directories)
        except Exception:
            raise BoundTreeError(_ERR_ARGUMENTS) from None
        folded: set[str] = set()
        validated: list[str] = []
        for value in names:
            name = _validated_component(value, self._limits)
            key = name.casefold()
            if key in folded:
                raise BoundTreeError(_ERR_ARGUMENTS)
            folded.add(key)
            validated.append(name)
        return tuple(validated)

    def _snapshot_locked(
        self,
        root_token: int,
        private_names: tuple[str, ...],
        hash_files: bool,
    ) -> TreeSnapshot:
        root_before = self._state(root_token)
        if root_before.kind != "directory" or root_before.identity != self._root_identity:
            raise BoundTreeChanged(_ERR_CHANGED)

        private_by_fold = {name.casefold(): name for name in private_names}
        found_private: set[str] = set()
        nodes: list[TreeNode] = []
        directories: list[int] = []
        files: list[int] = []
        private_indexes: list[int] = []
        directory_identities = {self._root_identity}
        total_bytes = 0

        def walk_directory(
            directory_token: int,
            parent_index: int | None,
            parent_parts: tuple[str, ...],
            depth: int,
        ) -> None:
            nonlocal total_bytes
            directory_before = self._state(directory_token)
            if directory_before.kind != "directory":
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            raw_names = self._list_names(directory_token)
            names = self._validated_sorted_names(raw_names)
            for name in names:
                current_depth = depth + 1
                if current_depth > self._limits.max_depth:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                parts = parent_parts + (name,)
                if len("/".join(parts).encode("utf-8")) > self._limits.max_relative_utf8:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                if len(nodes) >= self._limits.max_entries:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                private_name = private_by_fold.get(name.casefold()) if depth == 0 else None
                if private_name is not None and name != private_name:
                    raise BoundTreeUnsafe(
                        f"private directory must use canonical name: {private_name}"
                    )

                child_token = self._open_any(directory_token, name)
                try:
                    try:
                        before = self._state(child_token)
                    except BoundTreeUnsafe:
                        if private_name is not None:
                            raise BoundTreeUnsafe(
                                "private archive path must be a plain directory: "
                                f"{private_name}"
                            ) from None
                        raise
                    if before.identity.volume_id != self._root_identity.volume_id:
                        raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
                    node_index = len(nodes)
                    if before.kind == "directory":
                        if before.identity in directory_identities:
                            raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
                        directory_identities.add(before.identity)
                        node = TreeNode(
                            parent_index,
                            name,
                            "directory",
                            before.identity,
                            0,
                            before.change_token,
                            None,
                        )
                        nodes.append(node)
                        directories.append(node_index)
                        if private_name is not None:
                            found_private.add(private_name)
                            private_indexes.append(node_index)
                            if self._list_names(child_token):
                                raise BoundTreeUnsafe(
                                    "private archive directory must be empty: "
                                    f"{private_name}"
                                )
                        else:
                            walk_directory(
                                child_token,
                                node_index,
                                parts,
                                current_depth,
                            )
                        if self._state(child_token) != before:
                            raise BoundTreeChanged(_ERR_CHANGED)
                    else:
                        if private_name is not None:
                            raise BoundTreeUnsafe(
                                "private archive path must be a plain directory: "
                                f"{private_name}"
                            )
                        if before.size > self._limits.max_file_bytes:
                            raise BoundTreeLimitExceeded(_ERR_LIMIT)
                        total_bytes += before.size
                        if total_bytes > self._limits.max_total_bytes:
                            raise BoundTreeLimitExceeded(_ERR_LIMIT)
                        digest: str | None = None
                        if hash_files:
                            total, digest = self._stream_file(
                                child_token,
                                max_bytes=before.size,
                                chunk_size=_READ_CHUNK_SIZE,
                                writer=None,
                            )
                            if total != before.size:
                                raise BoundTreeChanged(_ERR_CHANGED)
                        after = self._state(child_token)
                        if after != before:
                            raise BoundTreeChanged(_ERR_CHANGED)
                        nodes.append(
                            TreeNode(
                                parent_index,
                                name,
                                "file",
                                before.identity,
                                before.size,
                                before.change_token,
                                digest,
                            )
                        )
                        files.append(node_index)
                finally:
                    self._close_token(child_token)
            if self._state(directory_token) != directory_before:
                raise BoundTreeChanged(_ERR_CHANGED)

        walk_directory(root_token, None, (), 0)
        if found_private != set(private_names):
            missing = next(
                name for name in private_names if name not in found_private
            )
            raise BoundTreeUnsafe(
                f"required private archive directory is missing: {missing}"
            )
        if self._state(root_token) != root_before:
            raise BoundTreeChanged(_ERR_CHANGED)

        sort_key = lambda index: (
            "/".join(_parts_for_nodes(nodes, index)).casefold(),
            "/".join(_parts_for_nodes(nodes, index)),
        )
        directories.sort(key=sort_key)
        files.sort(key=sort_key)
        private_indexes.sort(key=sort_key)
        return TreeSnapshot(
            root_identity=self._root_identity,
            nodes=tuple(nodes),
            directory_indexes=tuple(directories),
            file_indexes=tuple(files),
            private_directories=tuple(private_indexes),
        )

    def _validated_sorted_names(self, values: tuple[str, ...]) -> tuple[str, ...]:
        names: list[str] = []
        folded: set[str] = set()
        for value in values:
            name = _validated_component(value, self._limits)
            key = name.casefold()
            if key in folded:
                raise BoundTreeUnsafe(_ERR_ENTRY_UNSAFE)
            folded.add(key)
            names.append(name)
        return tuple(sorted(names, key=lambda value: (value.casefold(), value)))

    def _validate_snapshot(self, snapshot: object) -> None:
        if type(snapshot) is not TreeSnapshot or snapshot.root_identity != self._root_identity:
            raise BoundTreeError(_ERR_ARGUMENTS)
        if len(snapshot.nodes) > self._limits.max_entries:
            raise BoundTreeLimitExceeded(_ERR_LIMIT)
        total_bytes = 0
        for index, node in enumerate(snapshot.nodes):
            parts = snapshot.relative_parts(index)
            if len(parts) > self._limits.max_depth:
                raise BoundTreeLimitExceeded(_ERR_LIMIT)
            for part in parts:
                _validated_component(part, self._limits)
            if len("/".join(parts).encode("utf-8")) > self._limits.max_relative_utf8:
                raise BoundTreeLimitExceeded(_ERR_LIMIT)
            if node.kind == "file":
                if node.size > self._limits.max_file_bytes:
                    raise BoundTreeLimitExceeded(_ERR_LIMIT)
                total_bytes += node.size
        if total_bytes > self._limits.max_total_bytes:
            raise BoundTreeLimitExceeded(_ERR_LIMIT)

    def _open_verified_node(
        self,
        snapshot: TreeSnapshot,
        node_index: int,
        *,
        require_change_token: bool = True,
    ) -> int:
        chain: list[int] = []
        current: int | None = node_index
        while current is not None:
            chain.append(current)
            current = snapshot.nodes[current].parent_index
        chain.reverse()

        parent_token = self._require_open()
        owned_parent: int | None = None
        try:
            for current_index in chain:
                expected = snapshot.nodes[current_index]
                child = self._open_any(parent_token, expected.name)
                try:
                    state = self._state(child)
                    if not _state_matches_node(
                        state,
                        expected,
                        require_change_token=require_change_token,
                    ):
                        raise BoundTreeChanged(_ERR_CHANGED)
                except BaseException:
                    self._close_token(child)
                    raise
                if owned_parent is not None:
                    self._close_token(owned_parent)
                owned_parent = child
                parent_token = child
            if owned_parent is None:
                raise BoundTreeError(_ERR_ARGUMENTS)
            result = owned_parent
            owned_parent = None
            return result
        finally:
            if owned_parent is not None:
                self._close_token(owned_parent)

    def _stream_file(
        self,
        token: int,
        *,
        max_bytes: int,
        chunk_size: int,
        writer: object | None,
    ) -> tuple[int, str]:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = self._read_token(token, chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BoundTreeLimitExceeded(_ERR_LIMIT)
            digest.update(chunk)
            if writer is not None:
                try:
                    written = writer(chunk)  # type: ignore[operator]
                except Exception:
                    raise BoundTreeUnavailable(_ERR_TARGET) from None
                if written is not None and (type(written) is not int or written != len(chunk)):
                    raise BoundTreeUnavailable(_ERR_TARGET)
        return total, digest.hexdigest()

    def _state(self, token: int) -> _NodeState:
        return _win_state(token) if os.name == "nt" else _posix_state(token)

    def _open_any(self, parent_token: int, name: str) -> int:
        return _win_open_any(parent_token, name) if os.name == "nt" else _posix_open_any(parent_token, name)

    def _list_names(self, token: int) -> tuple[str, ...]:
        if os.name == "nt":
            return _win_list_names(token, self._limits.max_entries)
        return _posix_list_names(token, self._limits.max_entries)

    def _read_token(self, token: int, size: int) -> bytes:
        if os.name == "nt":
            return _win_read(token, size)
        try:
            return os.read(token, size)
        except OSError:
            raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None

    @staticmethod
    def _close_token(token: int | None) -> None:
        if os.name == "nt":
            _win_close_handle(token)
        else:
            _close_fd(token)


def _parts_for_nodes(nodes: list[TreeNode], node_index: int) -> tuple[str, ...]:
    parts: list[str] = []
    current: int | None = node_index
    while current is not None:
        node = nodes[current]
        parts.append(node.name)
        current = node.parent_index
    parts.reverse()
    return tuple(parts)


def _state_matches_node(
    state: _NodeState,
    node: TreeNode,
    *,
    require_change_token: bool = True,
) -> bool:
    return (
        state.identity == node.identity
        and state.kind == node.kind
        and state.size == node.size
        and (
            not require_change_token
            or state.change_token == node.change_token
        )
    )


def _snapshots_match(
    expected: TreeSnapshot,
    actual: TreeSnapshot,
    verify_content: bool,
) -> bool:
    if (
        expected.root_identity != actual.root_identity
        or len(expected.nodes) != len(actual.nodes)
        or tuple(expected.relative_parts(index) for index in expected.private_directories)
        != tuple(actual.relative_parts(index) for index in actual.private_directories)
    ):
        return False
    for index, expected_node in enumerate(expected.nodes):
        parts = expected.relative_parts(index)
        try:
            actual_index = actual.index(parts)
        except BoundTreeError:
            return False
        actual_node = actual.nodes[actual_index]
        if (
            expected_node.kind != actual_node.kind
            or expected_node.identity != actual_node.identity
            or expected_node.size != actual_node.size
            or expected_node.change_token != actual_node.change_token
            or (verify_content and expected_node.sha256 != actual_node.sha256)
        ):
            return False
    return True


def descriptor_change_token(descriptor: int) -> int:
    """Return a write-sensitive token for an already-open regular file."""

    if type(descriptor) is not int or descriptor < 0:
        raise BoundTreeError(_ERR_ARGUMENTS)
    if os.name == "nt":
        try:
            import msvcrt

            handle = int(msvcrt.get_osfhandle(descriptor))
        except (OSError, ValueError):
            raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None
        basic = _FILE_BASIC_INFO()
        _win_query(handle, _FILE_BASIC_INFO_CLASS, basic)
        return int(basic.ChangeTime)
    try:
        value = os.fstat(descriptor)
    except OSError:
        raise BoundTreeUnavailable(_ERR_ENTRY_UNAVAILABLE) from None
    return int(
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))
    )


def open_bound_tree(
    root: object,
    limits: TreeLimits = TreeLimits(),
) -> BoundTreeSession:
    """Open a plain release root without following its final redirector."""

    if type(limits) is not TreeLimits:
        raise BoundTreeError(_ERR_ARGUMENTS)
    path = _validated_root_path(root)
    token: int | None = None
    try:
        token = _win_open_root(path) if os.name == "nt" else _posix_open_root(path)
        state = _win_state(token) if os.name == "nt" else _posix_state(token)
        if state.kind != "directory":
            raise BoundTreeUnsafe(_ERR_ROOT_UNSAFE)
        session = BoundTreeSession(path, token, state.identity, limits)
        token = None
        return session
    except BoundTreeError:
        raise
    except Exception:
        raise BoundTreeUnavailable(_ERR_ROOT_UNAVAILABLE) from None
    finally:
        if token is not None:
            if os.name == "nt":
                _win_close_handle(token)
            else:
                _close_fd(token)


__all__ = [
    "BoundTreeChanged",
    "BoundTreeError",
    "BoundTreeLimitExceeded",
    "BoundTreeSession",
    "BoundTreeUnavailable",
    "BoundTreeUnsafe",
    "TreeIdentity",
    "TreeLimits",
    "TreeNode",
    "TreeSnapshot",
    "descriptor_change_token",
    "open_bound_tree",
]
