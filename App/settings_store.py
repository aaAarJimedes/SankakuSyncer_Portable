# -*- coding: utf-8 -*-
"""Validated, credential-free application settings."""

from __future__ import annotations

import copy
import hashlib
import json
import ntpath
import os
import tempfile
import threading
from typing import Callable

from http_transport import normalize_proxy


class SettingsError(RuntimeError):
    """Raised when settings cannot be validated or stored."""


class SettingsReadError(SettingsError):
    """The settings file exists but could not be read reliably."""


class SettingsCorruptError(SettingsError):
    """The settings bytes were read but failed the strict schema."""


class SettingsWriteError(SettingsError):
    """A validated settings update could not be committed."""


class SettingsConflictError(SettingsWriteError):
    """The settings baseline changed before a validated update could commit."""


_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {f"COM{suffix}" for suffix in ("¹", "²", "³")}
    | {f"LPT{suffix}" for suffix in ("¹", "²", "³")}
)
_WINDOWS_INVALID_COMPONENT_CHARS = frozenset('<>:"|?*')
_WINDOWS_DEVICE_PREFIXES = ("\\\\?\\", "\\\\.\\", "\\??\\", "\\\\??\\")
_MAX_SETTINGS_BYTES = 1024 * 1024
_SETTINGS_LOCK_NAME = ".settings-store.lock"
_UNKNOWN_BASELINE = object()


def normalize_download_directory(value: object) -> str:
    """Return an absolute Windows path or a portable ``Downloads`` path."""

    if not isinstance(value, str) or len(value) > 32768:
        raise SettingsError("invalid download directory")
    if any(ord(character) < 32 for character in value):
        raise SettingsError("invalid download directory")
    candidate = value.strip()
    if not candidate:
        return ""
    if candidate != value:
        raise SettingsError("invalid download directory")

    windows_value = candidate.replace("/", "\\")
    if windows_value.startswith(_WINDOWS_DEVICE_PREFIXES):
        raise SettingsError("invalid download directory")

    drive, _tail = ntpath.splitdrive(windows_value)
    absolute = ntpath.isabs(windows_value)
    if drive and not absolute:
        raise SettingsError("invalid download directory")

    normalized = ntpath.normpath(windows_value)
    if absolute:
        if not drive:
            raise SettingsError("invalid download directory")
        if drive.startswith("\\\\"):
            unc_parts = tuple(part for part in drive[2:].split("\\") if part)
            if len(unc_parts) != 2:
                raise SettingsError("invalid download directory")
        elif len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha():
            raise SettingsError("invalid download directory")
        _validate_windows_components(normalized, drive)
        return normalized

    if drive:
        raise SettingsError("invalid download directory")
    parts = tuple(part for part in normalized.split("\\") if part)
    if not parts or parts[0].casefold() != "downloads":
        raise SettingsError("invalid download directory")
    _validate_windows_components(normalized, "")
    return "/".join(("Downloads", *parts[1:]))


def _validate_windows_components(path: str, drive: str) -> None:
    components: list[str] = []
    if drive.startswith("\\\\"):
        components.extend(part for part in drive[2:].split("\\") if part)
    tail = path[len(drive) :] if drive else path
    components.extend(part for part in tail.split("\\") if part)
    if not components and not drive:
        raise SettingsError("invalid download directory")
    for component in components:
        if (
            component in {".", ".."}
            or component.endswith((".", " "))
            or any(character in _WINDOWS_INVALID_COMPONENT_CHARS for character in component)
            or component.split(".", 1)[0].upper() in _WINDOWS_RESERVED_BASENAMES
        ):
            raise SettingsError("invalid download directory")


class _SettingsProcessLock:
    """Short-lived cross-process lock around one settings transaction."""

    def __init__(self, data_dir: str) -> None:
        self.path = os.path.join(os.path.abspath(data_dir), _SETTINGS_LOCK_NAME)
        self._descriptor: int | None = None

    def __enter__(self) -> "_SettingsProcessLock":
        descriptor = None
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise SettingsConflictError(
                "设置正在被另一个程序更新，请稍后重试"
            ) from exc
        self._descriptor = descriptor
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except OSError:
            # Both Windows byte-range locks and POSIX flock locks are released
            # by closing the descriptor.  A close error must not turn an
            # already committed settings transaction into a reported failure.
            pass


class SettingsStore:
    SCHEMA_VERSION = 1
    DEFAULTS = {
        "download_dir": "",
        "default_rating": "s",
        "request_delay": 3.0,
        "request_timeout": 30,
        "max_retries": 4,
        "page_size": 24,
        "proxy": "",
        "remember_credentials": False,
        "credential_vault_receipt": "",
        "prefer_original": True,
        "save_metadata": True,
        "window_geometry": "",
    }

    def __init__(
        self,
        data_dir: str,
        *,
        lock_factory: Callable[[], object] | None = None,
    ) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, "settings.json")
        self._lock = threading.RLock()
        self._signature: tuple[int, str] | None | object = _UNKNOWN_BASELINE
        self._corrupt_signature: tuple[int, str] | None = None
        self._process_lock_factory = lock_factory or (
            lambda: _SettingsProcessLock(self.data_dir)
        )
        self.values = copy.deepcopy(self.DEFAULTS)
        self.last_error = ""
        self.last_load_error: SettingsError | None = None
        self.load()

    def get(self, key: str, default=None):
        with self._lock:
            if key not in self.DEFAULTS:
                return default
            return self.values.get(key, self.DEFAULTS[key])

    def set(self, key: str, value) -> None:
        with self._lock:
            if key not in self.DEFAULTS:
                raise SettingsError("unknown setting")
            self.values[key] = self._normalize(key, value)

    def update(self, mapping: dict) -> None:
        with self._lock:
            candidate = copy.deepcopy(self.values)
            for key, value in mapping.items():
                if key not in self.DEFAULTS:
                    raise SettingsError("unknown setting")
                candidate[key] = self._normalize(key, value)
            self.values = candidate

    def load(self) -> bool:
        with self._lock:
            self.values = copy.deepcopy(self.DEFAULTS)
            self.last_error = ""
            self.last_load_error = None
            self._signature = _UNKNOWN_BASELINE
            self._corrupt_signature = None
            failed_signature: tuple[int, str] | None = None
            try:
                with self._process_lock_factory():
                    snapshot = self._read_file_snapshot()
                    if snapshot is None:
                        normalized = copy.deepcopy(self.DEFAULTS)
                        signature: tuple[int, str] | None = None
                    else:
                        encoded, signature, oversized = snapshot
                        if oversized:
                            raise SettingsCorruptError(
                                "settings file is too large"
                            )
                        failed_signature = signature
                        saved = json.loads(encoded.decode("utf-8"))
                        if (
                            not isinstance(saved, dict)
                            or type(saved.get("schema_version")) is not int
                            or saved.get("schema_version") != self.SCHEMA_VERSION
                        ):
                            raise SettingsCorruptError(
                                "unsupported settings schema"
                            )
                        unknown = set(saved) - {
                            "schema_version",
                            *self.DEFAULTS,
                        }
                        if unknown:
                            raise SettingsCorruptError(
                                "settings contain unknown fields"
                            )
                        normalized = copy.deepcopy(self.DEFAULTS)
                        for key in self.DEFAULTS:
                            if key in saved:
                                normalized[key] = self._normalize(
                                    key, saved[key]
                                )
            except SettingsConflictError as exc:
                failure = SettingsReadError(
                    "设置文件正在被另一个程序更新，请稍后重试"
                )
                failure.__cause__ = exc
            except SettingsReadError as exc:
                failure = exc
            except OSError as exc:
                failure = SettingsReadError(
                    f"设置文件暂时无法读取（{type(exc).__name__}）"
                )
                failure.__cause__ = exc
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                SettingsError,
                OverflowError,
                TypeError,
                ValueError,
                RecursionError,
            ) as exc:
                failure = SettingsCorruptError(
                    f"设置内容损坏，已使用默认值（{type(exc).__name__}）"
                )
                failure.__cause__ = exc
                self._corrupt_signature = failed_signature
            else:
                self.values = normalized
                self._signature = signature
                return True
            self.last_load_error = failure
            self.last_error = str(failure)
            return False

    def save(self) -> None:
        with self._lock:
            normalized = {
                key: self._normalize(key, self.values.get(key, default))
                for key, default in self.DEFAULTS.items()
            }
            payload = {"schema_version": self.SCHEMA_VERSION, **normalized}
            try:
                encoded = json.dumps(
                    payload, ensure_ascii=False, indent=2
                ).encode("utf-8")
            except (TypeError, ValueError, OverflowError) as exc:
                raise SettingsWriteError(
                    f"设置序列化失败（{type(exc).__name__}）"
                ) from exc
            if len(encoded) > _MAX_SETTINGS_BYTES:
                raise SettingsWriteError("设置超过 1 MiB 安全上限")
            if self._signature is _UNKNOWN_BASELINE:
                raise SettingsWriteError(
                    "设置文件尚未可靠载入，不能安全覆盖"
                )
            try:
                with self._process_lock_factory():
                    if self._signature != self._file_signature():
                        raise SettingsConflictError(
                            "设置已被另一个程序修改，请重新启动后再试"
                        )
                    expected_signature = self._signature
                    self._atomic_write(encoded, expected_signature)
                    signature = self._verified_committed_signature(encoded)
            except OSError as exc:
                raise SettingsWriteError(
                    f"设置事务锁失败（{type(exc).__name__}）"
                ) from exc
            self.values = normalized
            self._signature = signature

    def quarantine_corrupt(self, recovery_path: str) -> None:
        """Move a fully hashed corrupt snapshot aside under the settings lock."""

        destination = os.path.abspath(os.fspath(recovery_path))
        with self._lock:
            expected = self._corrupt_signature
            if (
                not isinstance(self.last_load_error, SettingsCorruptError)
                or expected is None
                or self._signature is not _UNKNOWN_BASELINE
            ):
                raise SettingsWriteError("没有可安全隔离的损坏设置快照")
            if (
                os.path.dirname(destination) != self.data_dir
                or destination == self.path
                or os.path.lexists(destination)
            ):
                raise SettingsWriteError("损坏设置备份路径无效")
            try:
                with self._process_lock_factory():
                    if os.path.lexists(destination):
                        raise SettingsWriteError("损坏设置备份路径已被占用")
                    if self._file_signature() != expected:
                        raise SettingsConflictError(
                            "设置文件已在隔离前发生变化，请重新启动后再试"
                        )
                    try:
                        os.replace(self.path, destination)
                    except OSError as exc:
                        raise SettingsWriteError(
                            f"损坏设置备份失败（{type(exc).__name__}）"
                        ) from exc
            except OSError as exc:
                raise SettingsWriteError(
                    f"设置事务锁失败（{type(exc).__name__}）"
                ) from exc
            self._corrupt_signature = None

    @classmethod
    def _normalize(cls, key: str, value):
        if key == "download_dir":
            return normalize_download_directory(value)
        if key == "default_rating":
            if value not in {"s", "q", "e", "all"}:
                raise SettingsError("invalid rating")
            return value
        if key == "request_delay":
            if type(value) not in (int, float) or not 0.5 <= float(value) <= 30.0:
                raise SettingsError("invalid request delay")
            return float(value)
        if key == "request_timeout":
            if type(value) is not int or not 5 <= value <= 180:
                raise SettingsError("invalid timeout")
            return value
        if key == "max_retries":
            if type(value) is not int or not 0 <= value <= 10:
                raise SettingsError("invalid retry count")
            return value
        if key == "page_size":
            if type(value) is not int or not 8 <= value <= 40:
                raise SettingsError("invalid page size")
            return value
        if key in {"remember_credentials", "prefer_original", "save_metadata"}:
            if type(value) is not bool:
                raise SettingsError("invalid boolean setting")
            return value
        if key == "credential_vault_receipt":
            if value == "":
                return ""
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise SettingsError("invalid credential vault receipt")
            return value
        if key == "proxy":
            try:
                return normalize_proxy(value)
            except ValueError as exc:
                raise SettingsError("invalid or unsupported WinHTTP proxy") from exc
        if key == "window_geometry":
            if not isinstance(value, str) or len(value) > 16384:
                raise SettingsError("invalid window geometry")
            return value
        raise SettingsError("unknown setting")

    def _atomic_write(
        self,
        data: bytes,
        expected_signature: tuple[int, str] | None,
    ) -> None:
        temp_path = None
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".settings.", suffix=".tmp", dir=self.data_dir
            )
            with os.fdopen(descriptor, "wb") as file_obj:
                file_obj.write(data)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            if self._file_signature() != expected_signature:
                raise SettingsConflictError(
                    "设置在保存期间被另一个程序修改"
                )
            os.replace(temp_path, self.path)
            temp_path = None
        except OSError as exc:
            raise SettingsWriteError(
                f"设置保存失败（{type(exc).__name__}）"
            ) from exc
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @staticmethod
    def _signature_for(data: bytes) -> tuple[int, str]:
        return len(data), hashlib.sha256(data).hexdigest()

    @staticmethod
    def _stat_identity(file_stat: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_size,
            getattr(file_stat, "st_mtime_ns", 0),
            getattr(file_stat, "st_ctime_ns", 0),
        )

    def _read_file_snapshot(
        self,
    ) -> tuple[bytes, tuple[int, str], bool] | None:
        for _attempt in range(3):
            try:
                with open(self.path, "rb") as file_obj:
                    before = os.fstat(file_obj.fileno())
                    encoded = (
                        b""
                        if before.st_size > _MAX_SETTINGS_BYTES
                        else file_obj.read(_MAX_SETTINGS_BYTES + 1)
                    )
                    after = os.fstat(file_obj.fileno())
                current = os.stat(self.path)
            except FileNotFoundError:
                if os.path.lexists(self.path):
                    raise SettingsReadError("设置文件路径无法安全读取")
                return None
            except OSError as exc:
                raise SettingsReadError(
                    f"设置文件暂时无法读取（{type(exc).__name__}）"
                ) from exc
            if (
                self._stat_identity(before) != self._stat_identity(after)
                or not os.path.samestat(after, current)
                or after.st_size != current.st_size
                or getattr(after, "st_mtime_ns", 0)
                != getattr(current, "st_mtime_ns", 0)
            ):
                continue
            oversized = (
                after.st_size > _MAX_SETTINGS_BYTES
                or len(encoded) > _MAX_SETTINGS_BYTES
            )
            if oversized:
                return b"", (after.st_size, "oversized"), True
            if len(encoded) != after.st_size:
                continue
            return encoded, self._signature_for(encoded), False
        raise SettingsReadError("设置文件在读取期间持续发生变化")

    def _file_signature(self) -> tuple[int, str] | None:
        snapshot = self._read_file_snapshot()
        return None if snapshot is None else snapshot[1]

    def _verified_committed_signature(self, encoded: bytes) -> tuple[int, str]:
        expected = self._signature_for(encoded)
        if self._file_signature() != expected:
            raise SettingsConflictError("设置在保存后被另一个程序修改")
        return expected


__all__ = [
    "SettingsConflictError",
    "SettingsCorruptError",
    "SettingsError",
    "SettingsReadError",
    "SettingsStore",
    "SettingsWriteError",
    "normalize_download_directory",
]
