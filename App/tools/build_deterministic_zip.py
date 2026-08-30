# -*- coding: utf-8 -*-
"""Create a byte-reproducible ZIP from a verified portable staging tree."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
from typing import Iterable
import zipfile

if __package__:
    from .bound_archive_tree import (
        BoundTreeError,
        BoundTreeSession,
        TreeSnapshot,
        descriptor_change_token,
        open_bound_tree,
    )
else:
    script_directory = str(Path(__file__).resolve().parent)
    if script_directory not in sys.path:
        sys.path.insert(0, script_directory)
    from bound_archive_tree import (  # type: ignore[no-redef]
        BoundTreeError,
        BoundTreeSession,
        TreeSnapshot,
        descriptor_change_token,
        open_bound_tree,
    )


CHUNK_SIZE = 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = stat.S_IFREG | 0o644
DIRECTORY_MODE = stat.S_IFDIR | 0o755
PRIVATE_DIRECTORIES = ("Data", "Downloads")

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _CREATE_NEW = 1
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_GENERIC_READ = 0x00120089
    _ERROR_FILE_EXISTS = 80
    _ERROR_ALREADY_EXISTS = 183
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE
    _DuplicateHandle = _kernel32.DuplicateHandle
    _DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _DuplicateHandle.restype = wintypes.BOOL
    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.argtypes = []
    _GetCurrentProcess.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL


class DeterministicZipError(RuntimeError):
    """The source tree cannot be archived without ambiguity."""


def _windows_path(path: Path) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _handle_value(handle: object) -> int | None:
    if isinstance(handle, int):
        return handle
    return ctypes.cast(handle, ctypes.c_void_p).value


def _close_windows_handle(handle: int | None) -> None:
    if os.name == "nt" and handle not in {None, _INVALID_HANDLE_VALUE}:
        try:
            _CloseHandle(wintypes.HANDLE(handle))
        except Exception:
            pass


def _create_temporary(output: Path) -> tuple[int, Path]:
    if os.name != "nt":
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        return descriptor, Path(temporary)

    for _attempt in range(128):
        temporary = output.parent / (
            f".{output.name}.{secrets.token_hex(16)}.tmp"
        )
        handle = _CreateFileW(
            _windows_path(temporary),
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        handle_value = _handle_value(handle)
        if handle_value == _INVALID_HANDLE_VALUE:
            error = int(ctypes.get_last_error())
            if error in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
                continue
            raise DeterministicZipError(
                "cannot create protected temporary archive"
            )
        try:
            flags = os.O_RDWR | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOINHERIT", 0))
            descriptor = msvcrt.open_osfhandle(handle_value, flags)
            handle_value = None
            return descriptor, temporary
        except OSError as exc:
            raise DeterministicZipError(
                "cannot create protected temporary archive"
            ) from exc
        finally:
            _close_windows_handle(handle_value)
    raise DeterministicZipError("cannot create unique temporary archive")


def _protect_temporary_descriptor(
    path: Path,
    descriptor: int,
    baseline: os.stat_result,
) -> int:
    if os.name != "nt":
        return descriptor
    duplicate_handle = wintypes.HANDLE()
    protected_descriptor: int | None = None
    try:
        source_handle = int(msvcrt.get_osfhandle(descriptor))
        process = _GetCurrentProcess()
        if not _DuplicateHandle(
            process,
            wintypes.HANDLE(source_handle),
            process,
            ctypes.byref(duplicate_handle),
            _FILE_GENERIC_READ,
            False,
            0,
        ):
            raise DeterministicZipError(
                "cannot protect temporary archive descriptor"
            )
        duplicate_value = _handle_value(duplicate_handle)
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOINHERIT", 0))
        protected_descriptor = msvcrt.open_osfhandle(duplicate_value, flags)
        duplicate_handle = wintypes.HANDLE()
        current = os.fstat(protected_descriptor)
        _require_same_temporary(path, baseline, require_unchanged=True)
        if (
            not os.path.samestat(current, baseline)
            or _regular_file_state(current) != _regular_file_state(baseline)
        ):
            raise DeterministicZipError("temporary archive identity changed")
        os.close(descriptor)
        result = protected_descriptor
        protected_descriptor = None
        return result
    except DeterministicZipError:
        raise
    except (OSError, ValueError) as exc:
        raise DeterministicZipError(
            "cannot protect temporary archive descriptor"
        ) from exc
    finally:
        if protected_descriptor is not None:
            try:
                os.close(protected_descriptor)
            except OSError:
                pass
        _close_windows_handle(_handle_value(duplicate_handle))


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DeterministicZipError(f"cannot inspect archive path: {path.name}") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _regular_file_state(value: os.stat_result) -> tuple[int, int]:
    attributes = int(getattr(value, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if not stat.S_ISREG(value.st_mode) or bool(attributes & reparse):
        raise DeterministicZipError("temporary archive is not a plain file")
    return (
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
    )


def _require_same_temporary(
    path: Path,
    baseline: os.stat_result,
    *,
    require_unchanged: bool,
) -> os.stat_result:
    try:
        current = path.lstat()
        current_state = _regular_file_state(current)
        baseline_state = _regular_file_state(baseline)
        same = os.path.samestat(current, baseline)
    except (OSError, ValueError) as exc:
        raise DeterministicZipError("temporary archive identity changed") from exc
    if not same or (
        require_unchanged and current_state != baseline_state
    ):
        raise DeterministicZipError("temporary archive identity changed")
    return current


def _read_descriptor_chunk(source, size: int) -> bytes:
    return source.read(size)


def _descriptor_digest(
    descriptor: int,
    baseline: os.stat_result,
) -> tuple[str, int]:
    verification_descriptor: int | None = None
    try:
        before = os.fstat(descriptor)
        if (
            not os.path.samestat(before, baseline)
            or _regular_file_state(before) != _regular_file_state(baseline)
        ):
            raise DeterministicZipError("temporary archive identity changed")
        before_change = descriptor_change_token(descriptor)
        expected_size = int(before.st_size)
        verification_descriptor = os.dup(descriptor)
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(verification_descriptor, "rb") as raw:
            verification_descriptor = None
            raw.seek(0)
            while chunk := _read_descriptor_chunk(raw, CHUNK_SIZE):
                total += len(chunk)
                if total > expected_size:
                    raise DeterministicZipError(
                        "temporary archive changed while hashing"
                )
                digest.update(chunk)
        after = os.fstat(descriptor)
        after_change = descriptor_change_token(descriptor)
        if (
            total != expected_size
            or not os.path.samestat(after, baseline)
            or _regular_file_state(after) != _regular_file_state(baseline)
            or after_change != before_change
        ):
            raise DeterministicZipError("temporary archive changed while hashing")
        return digest.hexdigest(), after_change
    except DeterministicZipError:
        raise
    except BoundTreeError as exc:
        raise DeterministicZipError("cannot hash temporary archive") from exc
    except OSError as exc:
        raise DeterministicZipError("cannot hash temporary archive") from exc
    finally:
        if verification_descriptor is not None:
            try:
                os.close(verification_descriptor)
            except OSError:
                pass


def _descriptor_sha256(
    descriptor: int,
    baseline: os.stat_result,
) -> str:
    digest, _change_token = _descriptor_digest(descriptor, baseline)
    return digest


def _require_descriptor_digest(
    descriptor: int,
    baseline: os.stat_result,
    expected_sha256: str,
) -> int:
    digest, change_token = _descriptor_digest(descriptor, baseline)
    if digest != expected_sha256:
        raise DeterministicZipError("temporary archive content changed")
    return change_token


def _require_same_published(
    path: Path,
    descriptor: int,
    baseline: os.stat_result,
    *,
    expected_change_token: int | None = None,
) -> None:
    try:
        current = os.fstat(descriptor)
        named = path.lstat()
        same_descriptor = os.path.samestat(current, baseline)
        same_name = os.path.samestat(named, current)
        current_state = _regular_file_state(current)
        baseline_state = _regular_file_state(baseline)
        named_state = _regular_file_state(named)
        current_change_token = descriptor_change_token(descriptor)
    except (BoundTreeError, OSError, ValueError) as exc:
        raise DeterministicZipError(
            "published archive identity does not match verification"
        ) from exc
    if (
        not same_descriptor
        or not same_name
        or current_state != baseline_state
        or named_state != baseline_state
        or (
            expected_change_token is not None
            and current_change_token != expected_change_token
        )
    ):
        raise DeterministicZipError(
            "published archive identity does not match verification"
        )


def _open_published(path: Path, baseline: os.stat_result) -> int:
    flags = os.O_RDONLY
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    if os.name != "nt":
        flags |= int(getattr(os, "O_NONBLOCK", 0))
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        _require_same_published(path, descriptor, baseline)
        result = descriptor
        descriptor = None
        return result
    except DeterministicZipError:
        raise
    except OSError as exc:
        raise DeterministicZipError(
            "cannot verify published archive identity"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _zip_info(name: str, *, directory: bool) -> zipfile.ZipInfo:
    if directory and not name.endswith("/"):
        name += "/"
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED if directory else zipfile.ZIP_DEFLATED
    info.external_attr = (
        ((DIRECTORY_MODE if directory else FILE_MODE) << 16)
        | (0x10 if directory else 0)
    )
    if not directory:
        info._compresslevel = 9
    return info


def _archive_name(snapshot: TreeSnapshot, node_index: int) -> str:
    return "/".join(snapshot.relative_parts(node_index))


def _write_file(
    archive: zipfile.ZipFile,
    tree: BoundTreeSession,
    snapshot: TreeSnapshot,
    node_index: int,
) -> None:
    relative = _archive_name(snapshot, node_index)
    try:
        with archive.open(
            _zip_info(relative, directory=False),
            "w",
            force_zip64=True,
        ) as target:
            tree.copy_verified_file(
                snapshot,
                node_index,
                target,
                chunk_size=CHUNK_SIZE,
            )
    except BoundTreeError as exc:
        raise DeterministicZipError(str(exc)) from exc
    except OSError as exc:
        raise DeterministicZipError(f"cannot archive file: {relative}") from exc


def _verify_archive(
    descriptor: int,
    expected: list[str],
    baseline: os.stat_result,
    expected_sha256: str,
) -> None:
    verification_descriptor: int | None = None
    try:
        verification_descriptor = os.dup(descriptor)
        with os.fdopen(verification_descriptor, "rb") as raw:
            verification_descriptor = None
            raw.seek(0)
            with zipfile.ZipFile(raw, "r") as archive:
                if archive.namelist() != expected or archive.testzip() is not None:
                    raise DeterministicZipError(
                        "temporary archive failed verification"
                    )
        current = os.fstat(descriptor)
        if (
            not os.path.samestat(current, baseline)
            or _regular_file_state(current) != _regular_file_state(baseline)
        ):
            raise DeterministicZipError("temporary archive changed during verification")
        _require_descriptor_digest(descriptor, baseline, expected_sha256)
    except DeterministicZipError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise DeterministicZipError("temporary archive failed verification") from exc
    finally:
        if verification_descriptor is not None:
            try:
                os.close(verification_descriptor)
            except OSError:
                pass


def build_deterministic_zip(source: Path, output: Path) -> int:
    source_input = Path(source)
    try:
        source_for_relation = source_input.resolve(strict=True)
    except OSError as exc:
        raise DeterministicZipError("archive source must be a plain directory") from exc
    output = output.resolve(strict=False)
    if output.suffix.casefold() != ".zip":
        raise DeterministicZipError("archive output must use a .zip suffix")
    if _within(output, source_for_relation):
        raise DeterministicZipError("archive output cannot be inside its source tree")
    if output.exists() or _is_link_or_reparse(output.parent) or not output.parent.is_dir():
        raise DeterministicZipError("archive output must be a new file in a plain directory")

    try:
        tree = open_bound_tree(source_input)
    except BoundTreeError as exc:
        raise DeterministicZipError("archive source must be a plain directory") from exc

    descriptor: int | None = None
    temporary: Path | None = None
    temporary_identity: os.stat_result | None = None
    archive_baseline: os.stat_result | None = None
    archive_sha256: str | None = None
    published_descriptor: int | None = None
    with tree:
        try:
            try:
                snapshot = tree.snapshot(
                    private_directories=PRIVATE_DIRECTORIES,
                    hash_files=True,
                )
            except BoundTreeError as exc:
                raise DeterministicZipError(str(exc)) from exc
            key = lambda index: (
                _archive_name(snapshot, index).casefold(),
                _archive_name(snapshot, index),
            )
            directories = sorted(snapshot.directory_indexes, key=key)
            files = sorted(snapshot.file_indexes, key=key)
            expected = [f"{_archive_name(snapshot, index)}/" for index in directories]
            expected.extend(_archive_name(snapshot, index) for index in files)

            descriptor, temporary = _create_temporary(output)
            temporary_identity = os.fstat(descriptor)
            _regular_file_state(temporary_identity)
            with os.fdopen(descriptor, "w+b", closefd=False) as raw:
                with zipfile.ZipFile(
                    raw,
                    mode="w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                    allowZip64=True,
                    strict_timestamps=True,
                ) as archive:
                    archive.comment = b""
                    for node_index in directories:
                        archive.writestr(
                            _zip_info(
                                _archive_name(snapshot, node_index),
                                directory=True,
                            ),
                            b"",
                        )
                    for node_index in files:
                        _write_file(archive, tree, snapshot, node_index)
                    try:
                        tree.verify_snapshot(snapshot, verify_content=False)
                    except BoundTreeError as exc:
                        raise DeterministicZipError(str(exc)) from exc
                raw.flush()
                os.fsync(raw.fileno())
            archive_baseline = os.fstat(descriptor)
            _regular_file_state(archive_baseline)
            if not os.path.samestat(temporary_identity, archive_baseline):
                raise DeterministicZipError("temporary archive identity changed")
            descriptor = _protect_temporary_descriptor(
                temporary,
                descriptor,
                archive_baseline,
            )
            archive_sha256 = _descriptor_sha256(descriptor, archive_baseline)

            try:
                tree.verify_private_directories(snapshot)
            except BoundTreeError as exc:
                raise DeterministicZipError(str(exc)) from exc
            _require_same_temporary(
                temporary,
                archive_baseline,
                require_unchanged=True,
            )
            _verify_archive(
                descriptor,
                expected,
                archive_baseline,
                archive_sha256,
            )
            # Verification can be expensive for a full portable runtime.  Recheck
            # the bound private roots immediately before the no-clobber publish
            # step so a change during verification cannot satisfy the release
            # contract.
            try:
                tree.verify_private_directories(snapshot)
            except BoundTreeError as exc:
                raise DeterministicZipError(str(exc)) from exc
            _require_same_temporary(
                temporary,
                archive_baseline,
                require_unchanged=True,
            )
            _require_descriptor_digest(
                descriptor,
                archive_baseline,
                archive_sha256,
            )
            try:
                os.link(temporary, output, follow_symlinks=False)
            except FileExistsError as exc:
                raise DeterministicZipError("archive output appeared concurrently") from exc
            except OSError as exc:
                raise DeterministicZipError(
                    "cannot publish archive without a verified hard link"
                ) from exc
            published_descriptor = _open_published(output, archive_baseline)
            published_change_token = _require_descriptor_digest(
                published_descriptor,
                archive_baseline,
                archive_sha256,
            )
            _require_same_published(
                output,
                published_descriptor,
                archive_baseline,
                expected_change_token=published_change_token,
            )
            return len(directories) + len(files)
        finally:
            if published_descriptor is not None:
                try:
                    os.close(published_descriptor)
                except OSError:
                    pass
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    try:
        count = build_deterministic_zip(arguments.source, arguments.output)
    except (DeterministicZipError, OSError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"deterministic ZIP failed: {exc}\n")
    print(f"deterministic ZIP ready: {arguments.output.resolve()} ({count} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
