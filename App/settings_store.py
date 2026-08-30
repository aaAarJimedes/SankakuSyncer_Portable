# -*- coding: utf-8 -*-
"""Validated, credential-free application settings."""

from __future__ import annotations

import copy
import json
import ntpath
import os
import tempfile

from http_transport import normalize_proxy


class SettingsError(RuntimeError):
    """Raised when settings cannot be validated or stored."""


class SettingsReadError(SettingsError):
    """The settings file exists but could not be read reliably."""


class SettingsCorruptError(SettingsError):
    """The settings bytes were read but failed the strict schema."""


class SettingsWriteError(SettingsError):
    """A validated settings update could not be committed."""


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

    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, "settings.json")
        self.values = copy.deepcopy(self.DEFAULTS)
        self.last_error = ""
        self.last_load_error: SettingsError | None = None
        self.load()

    def get(self, key: str, default=None):
        if key not in self.DEFAULTS:
            return default
        return self.values.get(key, self.DEFAULTS[key])

    def set(self, key: str, value) -> None:
        if key not in self.DEFAULTS:
            raise SettingsError("unknown setting")
        self.values[key] = self._normalize(key, value)

    def update(self, mapping: dict) -> None:
        candidate = copy.deepcopy(self.values)
        for key, value in mapping.items():
            if key not in self.DEFAULTS:
                raise SettingsError("unknown setting")
            candidate[key] = self._normalize(key, value)
        self.values = candidate

    def load(self) -> bool:
        self.values = copy.deepcopy(self.DEFAULTS)
        self.last_error = ""
        self.last_load_error = None
        try:
            file_stat = os.stat(self.path)
        except FileNotFoundError:
            return True
        except OSError as exc:
            failure = SettingsReadError(
                f"设置文件暂时无法读取（{type(exc).__name__}）"
            )
            self.last_load_error = failure
            self.last_error = str(failure)
            return False
        try:
            if file_stat.st_size > _MAX_SETTINGS_BYTES:
                raise SettingsCorruptError("settings file is too large")
            with open(self.path, "rb") as file_obj:
                encoded = file_obj.read(_MAX_SETTINGS_BYTES + 1)
            if len(encoded) > _MAX_SETTINGS_BYTES:
                raise SettingsCorruptError("settings file is too large")
            saved = json.loads(encoded.decode("utf-8"))
            if (
                not isinstance(saved, dict)
                or type(saved.get("schema_version")) is not int
                or saved.get("schema_version") != self.SCHEMA_VERSION
            ):
                raise SettingsCorruptError("unsupported settings schema")
            unknown = set(saved) - {"schema_version", *self.DEFAULTS}
            if unknown:
                raise SettingsCorruptError("settings contain unknown fields")
            normalized = copy.deepcopy(self.DEFAULTS)
            for key in self.DEFAULTS:
                if key in saved:
                    normalized[key] = self._normalize(key, saved[key])
            self.values = normalized
            return True
        except OSError as exc:
            failure = SettingsReadError(
                f"设置文件暂时无法读取（{type(exc).__name__}）"
            )
            self.last_load_error = failure
            self.last_error = str(failure)
            return False
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
            self.last_load_error = failure
            self.last_error = str(failure)
            return False

    def save(self) -> None:
        normalized = {
            key: self._normalize(key, self.values.get(key, default))
            for key, default in self.DEFAULTS.items()
        }
        payload = {"schema_version": self.SCHEMA_VERSION, **normalized}
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._atomic_write(encoded)
        self.values = normalized

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

    def _atomic_write(self, data: bytes) -> None:
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


__all__ = [
    "SettingsCorruptError",
    "SettingsError",
    "SettingsReadError",
    "SettingsStore",
    "SettingsWriteError",
    "normalize_download_directory",
]
