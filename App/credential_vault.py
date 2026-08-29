# -*- coding: utf-8 -*-
"""DPAPI-protected Sankaku session persistence.

Login passwords are accepted only by the in-memory :class:`Credentials` value.
The persisted schema contains only a username and bearer token.  Its file never
contains plaintext session data: protection is scoped to the current Windows
user and uses UI-forbidden mode so a background save cannot display a security
prompt.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import json
import os
import tempfile
from typing import Callable


_MAGIC = b"SANKAKUSYNCER-DPAPI\x01"
_ENTROPY = b"SankakuSyncer.Credentials.v1"
_MAX_FILE_BYTES = 1024 * 1024
_MAX_USERNAME_CHARS = 320
_MAX_PASSWORD_CHARS = 4096
_MAX_TOKEN_CHARS = 128 * 1024
_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class VaultError(RuntimeError):
    """Raised when protected local authentication state cannot be handled."""


@dataclass(frozen=True, slots=True)
class Credentials:
    """Ephemeral username/password input used only for a fresh login."""

    username: str
    password: str

    def validated(self) -> "Credentials":
        username = _validate_secret_text(
            self.username, "username", _MAX_USERNAME_CHARS, allow_empty=False
        )
        password = _validate_secret_text(
            self.password, "password", _MAX_PASSWORD_CHARS, allow_empty=False
        )
        return Credentials(username=username, password=password)


@dataclass(frozen=True, slots=True)
class StoredSession:
    """DPAPI-protected, password-free session state persisted between runs."""

    username: str
    access_token: str

    def validated(self) -> "StoredSession":
        username = _validate_secret_text(
            self.username, "username", _MAX_USERNAME_CHARS, allow_empty=False
        )
        token = _validate_secret_text(
            self.access_token, "access token", _MAX_TOKEN_CHARS, allow_empty=False
        )
        return StoredSession(username=username, access_token=token)


@dataclass(frozen=True, slots=True)
class VaultSnapshot:
    """Opaque rollback state containing bounded raw vault bytes or absence."""

    _protected_payload: bytes | None = field(repr=False)

    def __post_init__(self) -> None:
        payload = self._protected_payload
        if payload is not None and (
            type(payload) is not bytes
            or len(payload) > _MAX_FILE_BYTES
        ):
            raise VaultError("invalid credential snapshot")

    @property
    def existed(self) -> bool:
        """Return whether the protected vault file existed when captured."""
        return self._protected_payload is not None


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _validate_secret_text(value: object, label: str, limit: int, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise VaultError(f"invalid {label}")
    if not value and not allow_empty:
        raise VaultError(f"missing {label}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise VaultError(f"invalid {label}")
    return value


def _make_blob(data: bytes) -> tuple[_DataBlob, object]:
    if not data:
        data = b"\x00"
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def dpapi_protect(data: bytes) -> bytes:
    """Protect bytes for the current Windows user."""
    if os.name != "nt":
        raise VaultError("Windows DPAPI is unavailable")
    if not isinstance(data, bytes) or not data:
        raise VaultError("invalid plaintext")

    crypt32 = ctypes.WinDLL(
        "crypt32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )
    kernel32 = ctypes.WinDLL(
        "kernel32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    input_blob, input_buffer = _make_blob(data)
    entropy_blob, entropy_buffer = _make_blob(_ENTROPY)
    output_blob = _DataBlob()
    _ = input_buffer, entropy_buffer
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "SankakuSyncer credentials",
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise VaultError(f"DPAPI protection failed ({ctypes.get_last_error()})")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


def dpapi_unprotect(data: bytes) -> bytes:
    """Unprotect bytes for the current Windows user."""
    if os.name != "nt":
        raise VaultError("Windows DPAPI is unavailable")
    if not isinstance(data, bytes) or not data:
        raise VaultError("invalid protected data")

    crypt32 = ctypes.WinDLL(
        "crypt32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )
    kernel32 = ctypes.WinDLL(
        "kernel32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
    )
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    input_blob, input_buffer = _make_blob(data)
    entropy_blob, entropy_buffer = _make_blob(_ENTROPY)
    output_blob = _DataBlob()
    _ = input_buffer, entropy_buffer
    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    ):
        raise VaultError(f"DPAPI unprotection failed ({ctypes.get_last_error()})")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


class CredentialVault:
    """Atomic repository for DPAPI-protected credentials."""

    def __init__(
        self,
        data_dir: str,
        *,
        protect: Callable[[bytes], bytes] = dpapi_protect,
        unprotect: Callable[[bytes], bytes] = dpapi_unprotect,
    ) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, ".credentials")
        self._protect = protect
        self._unprotect = unprotect

    def exists(self) -> bool:
        return os.path.isfile(self.path)

    def snapshot(self) -> VaultSnapshot:
        """Capture bounded raw bytes without interpreting or decrypting them."""
        try:
            with open(self.path, "rb") as file_obj:
                payload = file_obj.read(_MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            return VaultSnapshot(None)
        except OSError as exc:
            raise VaultError(f"credential snapshot failed ({type(exc).__name__})") from exc
        return VaultSnapshot(self._validated_snapshot_payload(payload))

    def restore(self, snapshot: VaultSnapshot) -> None:
        """Atomically restore opaque raw bytes, or restore file absence."""
        if not isinstance(snapshot, VaultSnapshot):
            raise VaultError("invalid credential snapshot")
        payload = snapshot._protected_payload
        if payload is None:
            self.clear()
            return
        self._atomic_write(self._validated_snapshot_payload(payload))

    def load(self) -> StoredSession | None:
        if not self.exists():
            return None
        try:
            with open(self.path, "rb") as file_obj:
                payload = file_obj.read(_MAX_FILE_BYTES + 1)
            if len(payload) > _MAX_FILE_BYTES or not payload.startswith(_MAGIC):
                raise VaultError("unsupported credential file")
            clear = self._unprotect(payload[len(_MAGIC) :])
            if type(clear) is not bytes or len(clear) > _MAX_FILE_BYTES:
                raise VaultError("invalid credential payload")
            decoded = json.loads(clear.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise VaultError("invalid credential payload")
            schema_version = decoded.get("schema_version")
            if type(schema_version) is not int:
                raise VaultError("unsupported credential schema")
            if schema_version == 2:
                if set(decoded) != {
                    "schema_version",
                    "username",
                    "access_token",
                }:
                    raise VaultError("invalid credential payload")
                return StoredSession(
                    username=decoded["username"],
                    access_token=decoded["access_token"],
                ).validated()
            if schema_version == 1:
                if set(decoded) != {
                    "schema_version",
                    "username",
                    "password",
                    "access_token",
                }:
                    raise VaultError("invalid credential payload")
                login = Credentials(
                    username=decoded["username"],
                    password=decoded["password"],
                ).validated()
                legacy_token = _validate_secret_text(
                    decoded["access_token"],
                    "access token",
                    _MAX_TOKEN_CHARS,
                    allow_empty=True,
                )
                if not legacy_token:
                    # Schema 1 explicitly allowed saving before a token was
                    # obtained.  Such a record has no reusable session, so
                    # remove the password-bearing legacy payload instead of
                    # leaving it to fail migration on every startup.
                    self.clear()
                    return None
                session = StoredSession(
                    username=login.username,
                    access_token=legacy_token,
                ).validated()
                # A legacy password must not remain at rest after a successful
                # read.  save() protects the schema-2 bytes before its atomic
                # replacement; any protection or replacement failure therefore
                # leaves the original schema-1 ciphertext untouched and is
                # propagated to the caller.
                self.save(session)
                return session
            raise VaultError("unsupported credential schema")
        except VaultError:
            raise
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise VaultError(f"credential load failed ({type(exc).__name__})") from exc

    def save(self, session: StoredSession) -> None:
        if not isinstance(session, StoredSession):
            raise VaultError("invalid stored session")
        values = session.validated()
        payload = json.dumps(
            {
                "schema_version": 2,
                "username": values.username,
                "access_token": values.access_token,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        protected = _MAGIC + self._protect(payload)
        if len(protected) > _MAX_FILE_BYTES:
            raise VaultError("credential payload is too large")
        self._atomic_write(protected)

    def clear(self) -> None:
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except OSError as exc:
            raise VaultError(f"credential removal failed ({type(exc).__name__})") from exc

    def _atomic_write(self, data: bytes) -> None:
        temp_path = None
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".credentials.", suffix=".tmp", dir=self.data_dir
            )
            with os.fdopen(descriptor, "wb") as file_obj:
                file_obj.write(data)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            os.replace(temp_path, self.path)
            temp_path = None
        except OSError as exc:
            raise VaultError(f"credential save failed ({type(exc).__name__})") from exc
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @staticmethod
    def _validated_snapshot_payload(payload: object) -> bytes:
        if (
            type(payload) is not bytes
            or len(payload) > _MAX_FILE_BYTES
        ):
            raise VaultError("invalid credential snapshot")
        return payload


__all__ = [
    "CredentialVault",
    "Credentials",
    "StoredSession",
    "VaultError",
    "VaultSnapshot",
    "dpapi_protect",
    "dpapi_unprotect",
]
