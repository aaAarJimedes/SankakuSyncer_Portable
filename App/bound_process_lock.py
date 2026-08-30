# -*- coding: utf-8 -*-
"""Handle-bound, content-free locks for short portable-store transactions."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import ntpath
import os
import stat


_ERR_UNAVAILABLE = "process lock is unavailable"


class BoundProcessLockError(RuntimeError):
    """The requested lock could not be acquired through a safe file object."""


def _validated_root(value: object) -> str:
    try:
        raw = os.fspath(value)
    except TypeError:
        raise BoundProcessLockError(_ERR_UNAVAILABLE) from None
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    try:
        return os.path.abspath(raw)
    except (OSError, ValueError):
        raise BoundProcessLockError(_ERR_UNAVAILABLE) from None


def _validated_name(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or ":" in value
        or os.path.basename(value) != value
        or ntpath.basename(value) != value
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    try:
        utf16_size = len(value.encode("utf-16-le"))
    except UnicodeError:
        raise BoundProcessLockError(_ERR_UNAVAILABLE) from None
    if utf16_size > 65_532:
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    return value


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _posix_open_root(path: str) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        nofollow is None
        or directory is None
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    descriptor = os.open(
        path,
        os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISDIR(current.st_mode):
            raise BoundProcessLockError(_ERR_UNAVAILABLE)
        return descriptor, current
    except BaseException:
        _close_descriptor(descriptor)
        raise


def _posix_validate_root_name(
    path: str,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    current = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISDIR(current.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or not os.path.samestat(expected, current)
        or not os.path.samestat(current, named)
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)


def _posix_validate_lock(
    root_descriptor: int,
    root_state: os.stat_result,
    name: str,
    descriptor: int,
) -> os.stat_result:
    current = os.fstat(descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or int(current.st_nlink) != 1
        or int(current.st_dev) != int(root_state.st_dev)
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    named = os.stat(
        name,
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(named.st_mode)
        or int(named.st_nlink) != 1
        or not os.path.samestat(current, named)
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    return current


def _posix_acquire(
    path: str,
    name: str,
) -> tuple[int, int, os.stat_result, os.stat_result]:
    root_descriptor = None
    lock_descriptor = None
    try:
        root_descriptor, root_state = _posix_open_root(path)
        _posix_validate_root_name(path, root_descriptor, root_state)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        nonblocking = getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblocking is None:
            raise BoundProcessLockError(_ERR_UNAVAILABLE)
        lock_descriptor = os.open(
            name,
            os.O_CREAT
            | os.O_RDWR
            | nofollow
            | nonblocking
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        _posix_validate_lock(
            root_descriptor,
            root_state,
            name,
            lock_descriptor,
        )
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        import fcntl

        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_state = _posix_validate_lock(
            root_descriptor,
            root_state,
            name,
            lock_descriptor,
        )
        _posix_validate_root_name(path, root_descriptor, root_state)
        result = (
            root_descriptor,
            lock_descriptor,
            root_state,
            lock_state,
        )
        root_descriptor = None
        lock_descriptor = None
        return result
    finally:
        try:
            _close_descriptor(lock_descriptor)
        finally:
            _close_descriptor(root_descriptor)


def _posix_validate_held(
    path: str,
    name: str,
    root_descriptor: int,
    lock_descriptor: int,
    root_identity: os.stat_result,
    lock_identity: os.stat_result,
) -> None:
    _posix_validate_root_name(path, root_descriptor, root_identity)
    current = _posix_validate_lock(
        root_descriptor,
        root_identity,
        name,
        lock_descriptor,
    )
    if not os.path.samestat(current, lock_identity):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)


if os.name == "nt":
    import msvcrt

    _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_ADD_FILE = 0x0002
    _FILE_READ_DATA = 0x0001
    _FILE_WRITE_DATA = 0x0002
    _FILE_READ_ATTRIBUTES = 0x0080
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_TYPE_DISK = 0x0001

    _OBJ_CASE_INSENSITIVE = 0x00000040
    _FILE_OPEN_IF = 0x00000003
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_OPEN_REPARSE_POINT = 0x00200000

    _FILE_STANDARD_INFO_CLASS = 1
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


    class _FILE_STANDARD_INFO(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", wintypes.DWORD),
            ("DeletePending", ctypes.c_ubyte),
            ("Directory", ctypes.c_ubyte),
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
        raise BoundProcessLockError(_ERR_UNAVAILABLE)


def _win_validate_abi() -> None:
    if os.name != "nt":
        return
    expected_offsets = {
        (_FILE_STANDARD_INFO, "AllocationSize"): 0,
        (_FILE_STANDARD_INFO, "EndOfFile"): 8,
        (_FILE_STANDARD_INFO, "NumberOfLinks"): 16,
        (_FILE_STANDARD_INFO, "DeletePending"): 20,
        (_FILE_STANDARD_INFO, "Directory"): 21,
        (_UNICODE_STRING, "Buffer"): 8,
        (_OBJECT_ATTRIBUTES, "RootDirectory"): 8,
        (_OBJECT_ATTRIBUTES, "ObjectName"): 16,
        (_OBJECT_ATTRIBUTES, "Attributes"): 24,
        (_IO_STATUS_BLOCK, "Information"): 8,
    }
    if (
        ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(_FILE_STANDARD_INFO) != 24
        or ctypes.sizeof(_UNICODE_STRING) != 16
        or ctypes.sizeof(_OBJECT_ATTRIBUTES) != 48
        or ctypes.sizeof(_IO_STATUS_BLOCK) != 16
        or any(
            getattr(structure, field_name).offset != expected
            for (structure, field_name), expected in expected_offsets.items()
        )
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)


def _win_state(handle: int, *, directory: bool) -> tuple[int, bytes]:
    attributes = _FILE_ATTRIBUTE_TAG_INFO()
    standard = _FILE_STANDARD_INFO()
    identity = _FILE_ID_INFO()
    _win_query(handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, attributes)
    _win_query(handle, _FILE_STANDARD_INFO_CLASS, standard)
    _win_query(handle, _FILE_ID_INFO_CLASS, identity)
    file_attributes = int(attributes.FileAttributes)
    is_directory = bool(standard.Directory)
    if (
        file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or bool(file_attributes & _FILE_ATTRIBUTE_DIRECTORY) != is_directory
        or is_directory != directory
        or bool(standard.DeletePending)
        or int(_GetFileType(wintypes.HANDLE(handle))) != _FILE_TYPE_DISK
        or (not directory and int(standard.NumberOfLinks) != 1)
    ):
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    return int(identity.VolumeSerialNumber), bytes(identity.FileId.Identifier)


def _win_open_root(path: str) -> tuple[int, tuple[int, bytes]]:
    handle = _CreateFileW(
        path,
        _FILE_LIST_DIRECTORY | _FILE_ADD_FILE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    value = _win_handle_value(handle)
    if value is None or value == _INVALID_HANDLE_VALUE:
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    try:
        return value, _win_state(value, directory=True)
    except BaseException:
        _win_close_handle(value)
        raise


def _win_open_lock(root_handle: int, name: str) -> int:
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UNICODE_STRING(
        Length=encoded_length,
        MaximumLength=encoded_length + 2,
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(root_handle),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=_OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    status_block = _IO_STATUS_BLOCK()
    child = wintypes.HANDLE()
    status = int(
        _NtCreateFile(
            ctypes.byref(child),
            _FILE_READ_DATA | _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            _FILE_SHARE_READ,
            _FILE_OPEN_IF,
            _FILE_SYNCHRONOUS_IO_NONALERT
            | _FILE_NON_DIRECTORY_FILE
            | _FILE_OPEN_REPARSE_POINT,
            None,
            0,
        )
    )
    value = _win_handle_value(child)
    if status < 0 or value is None or value == _INVALID_HANDLE_VALUE:
        _win_close_handle(value)
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    return value


def _win_handle_to_descriptor(handle: int) -> int:
    try:
        return msvcrt.open_osfhandle(
            handle,
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
        )
    except (OSError, OverflowError, ValueError):
        raise BoundProcessLockError(_ERR_UNAVAILABLE) from None


def _win_acquire(
    path: str,
    name: str,
) -> tuple[int, int, tuple[int, bytes], tuple[int, bytes]]:
    root_handle = None
    lock_handle = None
    lock_descriptor = None
    try:
        _win_validate_abi()
        root_handle, root_identity = _win_open_root(path)
        lock_handle = _win_open_lock(root_handle, name)
        lock_identity = _win_state(lock_handle, directory=False)
        if lock_identity[0] != root_identity[0]:
            raise BoundProcessLockError(_ERR_UNAVAILABLE)
        lock_descriptor = _win_handle_to_descriptor(lock_handle)
        lock_handle = None  # The CRT descriptor owns the native handle now.
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        msvcrt.locking(lock_descriptor, msvcrt.LK_NBLCK, 1)
        descriptor_handle = int(msvcrt.get_osfhandle(lock_descriptor))
        if _win_state(descriptor_handle, directory=False) != lock_identity:
            raise BoundProcessLockError(_ERR_UNAVAILABLE)
        result = (
            root_handle,
            lock_descriptor,
            root_identity,
            lock_identity,
        )
        root_handle = None
        lock_descriptor = None
        return result
    finally:
        try:
            _close_descriptor(lock_descriptor)
        finally:
            try:
                _win_close_handle(lock_handle)
            finally:
                _win_close_handle(root_handle)


def _win_validate_held(
    root_handle: int,
    lock_descriptor: int,
    root_identity: tuple[int, bytes],
    lock_identity: tuple[int, bytes],
) -> None:
    if _win_state(root_handle, directory=True) != root_identity:
        raise BoundProcessLockError(_ERR_UNAVAILABLE)
    descriptor_handle = int(msvcrt.get_osfhandle(lock_descriptor))
    if _win_state(descriptor_handle, directory=False) != lock_identity:
        raise BoundProcessLockError(_ERR_UNAVAILABLE)


class BoundProcessLock:
    """Hold a short lock through objects bound beneath one safe root handle."""

    def __init__(self, data_dir: object, name: object) -> None:
        self.data_dir = _validated_root(data_dir)
        self.name = _validated_name(name)
        self.path = os.path.join(self.data_dir, self.name)
        self._root: int | None = None
        self._descriptor: int | None = None
        self._root_identity: object | None = None
        self._lock_identity: object | None = None

    def __enter__(self) -> "BoundProcessLock":
        if self._root is not None or self._descriptor is not None:
            raise BoundProcessLockError(_ERR_UNAVAILABLE)
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            if os.name == "nt":
                root, descriptor, root_identity, lock_identity = _win_acquire(
                    self.data_dir,
                    self.name,
                )
            else:
                root, descriptor, root_identity, lock_identity = _posix_acquire(
                    self.data_dir,
                    self.name,
                )
        except BoundProcessLockError:
            raise
        except Exception:
            raise BoundProcessLockError(_ERR_UNAVAILABLE) from None
        self._root = root
        self._descriptor = descriptor
        self._root_identity = root_identity
        self._lock_identity = lock_identity
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        root = self._root
        descriptor = self._descriptor
        root_identity = self._root_identity
        lock_identity = self._lock_identity
        self._root = None
        self._descriptor = None
        self._root_identity = None
        self._lock_identity = None
        validation_error: BaseException | None = None
        if (
            root is not None
            and descriptor is not None
            and root_identity is not None
            and lock_identity is not None
        ):
            try:
                if os.name == "nt":
                    _win_validate_held(
                        root,
                        descriptor,
                        root_identity,
                        lock_identity,
                    )
                else:
                    _posix_validate_held(
                        self.data_dir,
                        self.name,
                        root,
                        descriptor,
                        root_identity,
                        lock_identity,
                    )
            except BoundProcessLockError as exc:
                validation_error = exc
            except Exception:
                validation_error = BoundProcessLockError(_ERR_UNAVAILABLE)
            except BaseException as exc:
                validation_error = exc
        try:
            _close_descriptor(descriptor)
        finally:
            if os.name == "nt":
                _win_close_handle(root)
            else:
                _close_descriptor(root)
        if _exc_type is None and validation_error is not None:
            raise validation_error


__all__ = ["BoundProcessLock", "BoundProcessLockError"]
