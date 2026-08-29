# -*- coding: utf-8 -*-
"""Crash-consistent coordination for the credential vault and settings flag.

The vault and ordinary settings are two independently replaced files.  This
module uses a small, strictly validated, secret-free journal to make their
combined state recoverable after power loss or process termination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import tempfile
from typing import Callable

from credential_vault import (
    CredentialVault,
    StoredSession,
    VaultError,
    VaultReceipt,
)
from settings_store import SettingsError, SettingsStore


_SCHEMA_VERSION = 1
_MAX_JOURNAL_BYTES = 16 * 1024
_JOURNAL_NAME = ".credential-transaction.json"
_LOCK_NAME = ".credential-transaction.lock"


class CredentialPersistenceError(RuntimeError):
    """Raised when credential state cannot be made durably consistent."""


@dataclass(frozen=True, slots=True)
class JournalEntry:
    operation: str
    phase: str
    previous_remember: bool | None = None
    vault_receipt: VaultReceipt | None = None

    def validated(self) -> "JournalEntry":
        if self.operation == "disable":
            if (
                self.phase != "pending"
                or self.previous_remember is not None
                or self.vault_receipt is not None
            ):
                raise CredentialPersistenceError("invalid credential transaction")
            return self
        if self.operation != "enable" or type(self.previous_remember) is not bool:
            raise CredentialPersistenceError("invalid credential transaction")
        if self.phase == "pending" and self.vault_receipt is None:
            return self
        if self.phase == "vault_written" and isinstance(
            self.vault_receipt, VaultReceipt
        ):
            try:
                self.vault_receipt.validated()
            except VaultError as exc:
                raise CredentialPersistenceError(
                    "invalid credential transaction"
                ) from exc
            return self
        raise CredentialPersistenceError("invalid credential transaction")


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Outcome of recovery; session is deliberately excluded from repr."""

    resolved: bool
    remember_credentials: bool
    session: StoredSession | None = field(default=None, repr=False)
    had_journal: bool = False
    message: str = ""


class CredentialJournal:
    """Strict atomic repository for the secret-free transaction marker."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.path = os.path.join(self.data_dir, _JOURNAL_NAME)

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def load(self) -> JournalEntry | None:
        try:
            with open(self.path, "rb") as file_obj:
                encoded = file_obj.read(_MAX_JOURNAL_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CredentialPersistenceError(
                f"credential transaction read failed ({type(exc).__name__})"
            ) from exc
        if len(encoded) > _MAX_JOURNAL_BYTES:
            raise CredentialPersistenceError("credential transaction is too large")
        try:
            payload = json.loads(encoded.decode("utf-8"))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise CredentialPersistenceError(
                f"invalid credential transaction ({type(exc).__name__})"
            ) from exc
        if (
            not isinstance(payload, dict)
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != _SCHEMA_VERSION
        ):
            raise CredentialPersistenceError("unsupported credential transaction")

        operation = payload.get("operation")
        phase = payload.get("phase")
        if operation == "disable":
            if set(payload) != {"schema_version", "operation", "phase"}:
                raise CredentialPersistenceError("invalid credential transaction")
            return JournalEntry(operation="disable", phase=phase).validated()
        if operation != "enable":
            raise CredentialPersistenceError("invalid credential transaction")
        previous = payload.get("previous_remember")
        if phase == "pending":
            if set(payload) != {
                "schema_version",
                "operation",
                "phase",
                "previous_remember",
            }:
                raise CredentialPersistenceError("invalid credential transaction")
            return JournalEntry(
                operation="enable",
                phase="pending",
                previous_remember=previous,
            ).validated()
        if phase == "vault_written":
            if set(payload) != {
                "schema_version",
                "operation",
                "phase",
                "previous_remember",
                "vault_receipt",
            }:
                raise CredentialPersistenceError("invalid credential transaction")
            receipt = VaultReceipt(payload.get("vault_receipt"))
            return JournalEntry(
                operation="enable",
                phase="vault_written",
                previous_remember=previous,
                vault_receipt=receipt,
            ).validated()
        raise CredentialPersistenceError("invalid credential transaction")

    def begin_enable(self, previous_remember: bool) -> None:
        if type(previous_remember) is not bool:
            raise CredentialPersistenceError("invalid previous credential state")
        if self.exists():
            raise CredentialPersistenceError("credential transaction is already pending")
        self.supersede_with_enable(previous_remember)

    def supersede_with_enable(self, previous_remember: bool) -> None:
        """Atomically replace any older intent with a fresh enable barrier."""
        if type(previous_remember) is not bool:
            raise CredentialPersistenceError("invalid previous credential state")
        self._write(
            {
                "schema_version": _SCHEMA_VERSION,
                "operation": "enable",
                "phase": "pending",
                "previous_remember": previous_remember,
            }
        )

    def mark_vault_written(
        self, previous_remember: bool, receipt: VaultReceipt
    ) -> None:
        current = self.load()
        if current != JournalEntry(
            operation="enable",
            phase="pending",
            previous_remember=previous_remember,
        ):
            raise CredentialPersistenceError("credential transaction changed unexpectedly")
        if not isinstance(receipt, VaultReceipt):
            raise CredentialPersistenceError("invalid credential receipt")
        value = receipt.validated().sha256
        self._write(
            {
                "schema_version": _SCHEMA_VERSION,
                "operation": "enable",
                "phase": "vault_written",
                "previous_remember": previous_remember,
                "vault_receipt": value,
            }
        )

    def begin_disable(self) -> None:
        if self.exists():
            raise CredentialPersistenceError("credential transaction is already pending")
        self.supersede_with_disable()

    def supersede_with_disable(self) -> None:
        """Atomically replace any older intent with an explicit disable intent."""
        self._write(
            {
                "schema_version": _SCHEMA_VERSION,
                "operation": "disable",
                "phase": "pending",
            }
        )

    def clear(self) -> None:
        try:
            os.remove(self.path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CredentialPersistenceError(
                f"credential transaction removal failed ({type(exc).__name__})"
            ) from exc

    def _write(self, payload: dict) -> None:
        encoded = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        if len(encoded) > _MAX_JOURNAL_BYTES:
            raise CredentialPersistenceError("credential transaction is too large")
        temp_path = None
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".credential-transaction.", suffix=".tmp", dir=self.data_dir
            )
            with os.fdopen(descriptor, "wb") as file_obj:
                file_obj.write(encoded)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            os.replace(temp_path, self.path)
            temp_path = None
        except OSError as exc:
            raise CredentialPersistenceError(
                f"credential transaction save failed ({type(exc).__name__})"
            ) from exc
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass


class _CredentialProcessLock:
    """Short-lived cross-process lock for one portable Data directory."""

    def __init__(self, data_dir: str) -> None:
        self.path = os.path.join(os.path.abspath(data_dir), _LOCK_NAME)
        self._descriptor: int | None = None

    def __enter__(self) -> "_CredentialProcessLock":
        descriptor = None
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
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
            raise CredentialPersistenceError(
                "credential state is being updated by another program instance"
            ) from exc
        self._descriptor = descriptor
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class CredentialPersistence:
    """Coordinate and recover credential vault/settings updates."""

    def __init__(
        self,
        data_dir: str,
        settings: SettingsStore,
        vault: CredentialVault,
        *,
        journal: CredentialJournal | None = None,
        lock_factory: Callable[[], object] | None = None,
    ) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.settings = settings
        self.vault = vault
        self.journal = journal or CredentialJournal(self.data_dir)
        self._lock_factory = lock_factory or (
            lambda: _CredentialProcessLock(self.data_dir)
        )

    def has_pending(self) -> bool:
        return self.journal.exists()

    def has_disable_barrier(self) -> bool:
        """Return whether the durable marker is exactly disable/pending."""
        try:
            with self._lock_factory():
                entry = self.journal.load()
                return entry == JournalEntry("disable", "pending")
        except CredentialPersistenceError:
            return False

    def has_enable_barrier(self, session: StoredSession) -> bool:
        """Return whether the marker and vault bind this exact live session."""
        if not isinstance(session, StoredSession):
            return False
        try:
            expected = session.validated()
        except VaultError:
            return False
        try:
            with self._lock_factory():
                entry = self.journal.load()
                if (
                    entry is None
                    or entry.operation != "enable"
                    or entry.phase != "vault_written"
                    or entry.vault_receipt is None
                ):
                    return False
                stored = self.vault.load_matching(entry.vault_receipt)
                return stored == expected
        except (CredentialPersistenceError, VaultError):
            return False

    def prevents_automatic_load_except(
        self, session: StoredSession | None
    ) -> bool:
        """Confirm that a marker can load no session other than ``session``."""
        expected = None
        if session is not None:
            if not isinstance(session, StoredSession):
                return False
            try:
                expected = session.validated()
            except VaultError:
                return False
        try:
            with self._lock_factory():
                if not self.journal.exists():
                    return False
                try:
                    entry = self.journal.load()
                except CredentialPersistenceError:
                    # A corrupt marker is itself a startup load barrier and is
                    # recovered by fail-closed disable logic.
                    return True
                if entry is None:
                    return False
                if entry.operation == "disable" or entry.phase == "pending":
                    return True
                if entry.vault_receipt is None:
                    return True
                stored = self.vault.load_matching(entry.vault_receipt)
                if stored is None:
                    return True
                return expected is not None and stored == expected
        except (CredentialPersistenceError, VaultError):
            return False

    def recover_and_load(self, *, settings_write_allowed: bool) -> RecoveryResult:
        """Recover a marker and load only a consistent remembered session."""
        with self._lock_factory():
            result = self._recover_locked(
                settings_write_allowed=settings_write_allowed
            )
            if not result.resolved:
                return result
            if not result.remember_credentials:
                if self.vault.exists() or self.settings.get(
                    "credential_vault_receipt"
                ):
                    try:
                        self.journal.begin_disable()
                    except CredentialPersistenceError as exc:
                        return RecoveryResult(
                            resolved=False,
                            remember_credentials=False,
                            had_journal=True,
                            message=f"credential cleanup could not start ({type(exc).__name__})",
                        )
                    return self._finish_disable_locked(
                        settings_write_allowed=settings_write_allowed,
                        had_journal=True,
                        reason="残留的未绑定凭据已安全清理",
                    )
                return result
            if result.session is not None:
                return result
            try:
                receipt = VaultReceipt(
                    self.settings.get("credential_vault_receipt")
                ).validated()
                session = self.vault.load_matching(receipt)
            except (VaultError, TypeError):
                session = None
            if session is None:
                try:
                    self.journal.begin_disable()
                except CredentialPersistenceError as exc:
                    return RecoveryResult(
                        resolved=False,
                        remember_credentials=False,
                        had_journal=True,
                        message=f"credential fail-closed could not start ({type(exc).__name__})",
                    )
                return self._finish_disable_locked(
                    settings_write_allowed=settings_write_allowed,
                    had_journal=True,
                    reason="旧版或不匹配的本机会话已安全清除，请重新登录",
                )
            return RecoveryResult(
                resolved=True,
                remember_credentials=True,
                session=session,
                had_journal=result.had_journal,
                message=result.message,
            )

    def enable(
        self,
        session: StoredSession,
        *,
        previous_remember: bool,
        settings_write_allowed: bool,
    ) -> None:
        if not isinstance(session, StoredSession):
            raise CredentialPersistenceError("a verified session is required")
        session = session.validated()
        if type(previous_remember) is not bool:
            raise CredentialPersistenceError("invalid previous credential state")
        with self._lock_factory():
            recovery = self._recover_locked(
                settings_write_allowed=settings_write_allowed
            )
            if (
                recovery.resolved
                and recovery.had_journal
                and recovery.remember_credentials
                and recovery.session == session
            ):
                return
            stable_previous = (
                recovery.remember_credentials
                if recovery.resolved and recovery.had_journal
                else previous_remember
            )
            try:
                if recovery.resolved:
                    self.journal.begin_enable(stable_previous)
                else:
                    stable_previous = False
                    self.journal.supersede_with_enable(stable_previous)
            except CredentialPersistenceError as marker_error:
                fallback_failures: list[str] = []
                try:
                    self.vault.clear()
                except VaultError as exc:
                    fallback_failures.append(f"vault:{type(exc).__name__}")
                try:
                    self.settings.set("remember_credentials", False)
                    self.settings.set("credential_vault_receipt", "")
                    if not settings_write_allowed:
                        raise SettingsError("settings write disabled")
                    self.settings.save()
                except SettingsError as exc:
                    fallback_failures.append(f"settings:{type(exc).__name__}")
                detail = (
                    ", ".join(fallback_failures)
                    if fallback_failures
                    else "fallback completed"
                )
                raise CredentialPersistenceError(
                    f"credential enable marker failed; {detail}"
                ) from marker_error
            receipt = self.vault.save(session)
            self.journal.mark_vault_written(stable_previous, receipt)
            self.settings.set("remember_credentials", True)
            self.settings.set("credential_vault_receipt", receipt.sha256)
            if not settings_write_allowed:
                raise SettingsError("当前设置文件无法安全覆盖")
            self.settings.save()
            self.journal.clear()

    def disable(self, *, settings_write_allowed: bool) -> None:
        with self._lock_factory():
            try:
                self.journal.supersede_with_disable()
            except CredentialPersistenceError as marker_error:
                # Explicit opt-out still gets a best-effort fail-closed path if
                # the durable marker itself cannot be created.  Either a
                # removed vault or a persisted false control prevents reload.
                fallback_failures: list[str] = []
                try:
                    self.vault.clear()
                except VaultError as exc:
                    fallback_failures.append(f"vault:{type(exc).__name__}")
                try:
                    self.settings.set("remember_credentials", False)
                    self.settings.set("credential_vault_receipt", "")
                    if not settings_write_allowed:
                        raise SettingsError("settings write disabled")
                    self.settings.save()
                except SettingsError as exc:
                    fallback_failures.append(f"settings:{type(exc).__name__}")
                detail = (
                    ", ".join(fallback_failures)
                    if fallback_failures
                    else "fallback completed"
                )
                raise CredentialPersistenceError(
                    f"credential disable marker failed; {detail}"
                ) from marker_error
            result = self._finish_disable_locked(
                settings_write_allowed=settings_write_allowed,
                had_journal=True,
            )
            if not result.resolved:
                raise CredentialPersistenceError(
                    result.message or "credential disable is incomplete"
                )

    def _recover_locked(self, *, settings_write_allowed: bool) -> RecoveryResult:
        had_journal = self.journal.exists()
        if not had_journal:
            return RecoveryResult(
                resolved=True,
                remember_credentials=bool(
                    self.settings.get("remember_credentials")
                ),
            )
        try:
            entry = self.journal.load()
        except CredentialPersistenceError:
            return self._finish_disable_locked(
                settings_write_allowed=settings_write_allowed,
                had_journal=True,
                reason="损坏的凭据事务已按禁用状态恢复",
            )
        if entry is None:
            return RecoveryResult(
                resolved=True,
                remember_credentials=bool(
                    self.settings.get("remember_credentials")
                ),
            )
        if entry.operation == "disable" or (
            entry.operation == "enable" and entry.phase == "pending"
        ):
            return self._finish_disable_locked(
                settings_write_allowed=settings_write_allowed,
                had_journal=True,
                reason="未完成且尚未绑定的新会话已安全回退为禁用状态",
            )
        if entry.operation == "enable" and entry.phase == "vault_written":
            receipt = entry.vault_receipt
            try:
                session = (
                    self.vault.load_matching(receipt)
                    if receipt is not None
                    else None
                )
            except VaultError:
                session = None
            if session is None:
                return self._finish_disable_locked(
                    settings_write_allowed=settings_write_allowed,
                    had_journal=True,
                    reason="未完成的新凭据无法验证，已安全禁用",
                )
            return self._finish_enable_recovery_locked(
                session,
                receipt,
                settings_write_allowed=settings_write_allowed,
                message="未完成的新凭据已安全完成保存",
            )
        return self._finish_disable_locked(
            settings_write_allowed=settings_write_allowed,
            had_journal=True,
            reason="未知凭据事务已安全禁用",
        )

    def _finish_enable_recovery_locked(
        self,
        session: StoredSession,
        receipt: VaultReceipt,
        *,
        settings_write_allowed: bool,
        message: str,
    ) -> RecoveryResult:
        if not settings_write_allowed:
            return RecoveryResult(
                resolved=False,
                remember_credentials=False,
                had_journal=True,
                message="凭据恢复等待设置文件恢复写权限",
            )
        try:
            self.settings.set("remember_credentials", True)
            self.settings.set("credential_vault_receipt", receipt.sha256)
            self.settings.save()
            self.journal.clear()
        except (SettingsError, CredentialPersistenceError) as exc:
            return RecoveryResult(
                resolved=False,
                remember_credentials=False,
                had_journal=True,
                message=f"credential recovery failed ({type(exc).__name__})",
            )
        return RecoveryResult(
            resolved=True,
            remember_credentials=True,
            session=session,
            had_journal=True,
            message=message,
        )

    def _finish_disable_locked(
        self,
        *,
        settings_write_allowed: bool,
        had_journal: bool,
        reason: str = "",
    ) -> RecoveryResult:
        failures: list[str] = []
        try:
            self.vault.clear()
        except VaultError as exc:
            failures.append(f"vault:{type(exc).__name__}")
        try:
            self.settings.set("remember_credentials", False)
            self.settings.set("credential_vault_receipt", "")
            if not settings_write_allowed:
                raise SettingsError("settings write disabled")
            self.settings.save()
        except SettingsError as exc:
            failures.append(f"settings:{type(exc).__name__}")
        if not failures:
            try:
                self.journal.clear()
            except CredentialPersistenceError as exc:
                failures.append(f"journal:{type(exc).__name__}")
        if failures:
            return RecoveryResult(
                resolved=False,
                remember_credentials=False,
                had_journal=had_journal,
                message="凭据禁用恢复尚未完成（" + ", ".join(failures) + "）",
            )
        return RecoveryResult(
            resolved=True,
            remember_credentials=False,
            had_journal=had_journal,
            message=reason,
        )


__all__ = [
    "CredentialJournal",
    "CredentialPersistence",
    "CredentialPersistenceError",
    "JournalEntry",
    "RecoveryResult",
]
