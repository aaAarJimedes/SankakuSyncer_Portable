# -*- coding: utf-8 -*-
"""Validated, credential-free application settings."""

from __future__ import annotations

import copy
import json
import os
import tempfile

from http_transport import normalize_proxy


class SettingsError(RuntimeError):
    """Raised when settings cannot be validated or stored."""


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
        "prefer_original": True,
        "save_metadata": True,
        "window_geometry": "",
    }

    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, "settings.json")
        self.values = copy.deepcopy(self.DEFAULTS)
        self.last_error = ""
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
        if not os.path.exists(self.path):
            return True
        try:
            if os.path.getsize(self.path) > 1024 * 1024:
                raise SettingsError("settings file is too large")
            with open(self.path, "r", encoding="utf-8") as file_obj:
                saved = json.load(file_obj)
            if not isinstance(saved, dict) or saved.get("schema_version") != self.SCHEMA_VERSION:
                raise SettingsError("unsupported settings schema")
            unknown = set(saved) - {"schema_version", *self.DEFAULTS}
            if unknown:
                raise SettingsError("settings contain unknown fields")
            normalized = copy.deepcopy(self.DEFAULTS)
            for key in self.DEFAULTS:
                if key in saved:
                    normalized[key] = self._normalize(key, saved[key])
            self.values = normalized
            return True
        except (OSError, json.JSONDecodeError, SettingsError, TypeError, ValueError) as exc:
            self.last_error = f"设置读取失败，已使用默认值（{type(exc).__name__}）"
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
            if not isinstance(value, str) or len(value) > 32768:
                raise SettingsError("invalid download directory")
            if any(ord(char) < 32 for char in value):
                raise SettingsError("invalid download directory")
            return value
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
            raise SettingsError(f"设置保存失败（{type(exc).__name__}）") from exc
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass


__all__ = ["SettingsError", "SettingsStore"]
