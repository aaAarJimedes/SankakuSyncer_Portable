# -*- coding: utf-8 -*-
"""Create a byte-reproducible ZIP from a verified portable staging tree."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterable
import zipfile


CHUNK_SIZE = 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = stat.S_IFREG | 0o644
DIRECTORY_MODE = stat.S_IFDIR | 0o755
PRIVATE_DIRECTORIES = ("Data", "Downloads")
_PRIVATE_DIRECTORY_NAMES = {
    name.casefold(): name for name in PRIVATE_DIRECTORIES
}


class DeterministicZipError(RuntimeError):
    """The source tree cannot be archived without ambiguity."""


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


def _private_directory_state(root: Path) -> dict[str, tuple[int, int, int, int]]:
    """Require canonical, plain, empty private roots without reading them."""
    states: dict[str, tuple[int, int, int, int]] = {}
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                expected = _PRIVATE_DIRECTORY_NAMES.get(entry.name.casefold())
                if expected is None:
                    continue
                if entry.name != expected or expected in states:
                    raise DeterministicZipError(
                        f"private directory must use canonical name: {expected}"
                    )
                path = root / entry.name
                info = path.lstat()
                attributes = int(getattr(info, "st_file_attributes", 0))
                reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse) or not stat.S_ISDIR(
                    info.st_mode
                ):
                    raise DeterministicZipError(
                        f"private archive path must be a plain directory: {expected}"
                    )
                with os.scandir(path) as children:
                    if next(children, None) is not None:
                        raise DeterministicZipError(
                            f"private archive directory must be empty: {expected}"
                        )
                states[expected] = (
                    int(getattr(info, "st_dev", 0)),
                    int(getattr(info, "st_ino", 0)),
                    int(getattr(info, "st_ctime_ns", 0)),
                    int(getattr(info, "st_mtime_ns", 0)),
                )
    except DeterministicZipError:
        raise
    except OSError as exc:
        raise DeterministicZipError("cannot inspect private archive directories") from exc
    missing = [name for name in PRIVATE_DIRECTORIES if name not in states]
    if missing:
        raise DeterministicZipError(
            f"required private archive directory is missing: {missing[0]}"
        )
    return states


def _require_unchanged_private_directories(
    root: Path, expected: dict[str, tuple[int, int, int, int]]
) -> None:
    if _private_directory_state(root) != expected:
        raise DeterministicZipError("private archive directories changed while archiving")


def _entries(root: Path) -> tuple[list[Path], list[Path]]:
    directories: list[Path] = []
    files: list[Path] = []
    for directory_text, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        relative_directory = directory.relative_to(root)
        kept: list[str] = []
        for name in directory_names:
            path = directory / name
            if _is_link_or_reparse(path) or not path.is_dir():
                raise DeterministicZipError(
                    f"link or non-directory in archive tree: {path.relative_to(root).as_posix()}"
                )
            relative = path.relative_to(root)
            if "\r" in relative.as_posix() or "\n" in relative.as_posix():
                raise DeterministicZipError("archive path contains a line break")
            directories.append(relative)
            private_name = (
                _PRIVATE_DIRECTORY_NAMES.get(name.casefold())
                if not relative_directory.parts
                else None
            )
            if private_name is not None:
                if name != private_name:
                    raise DeterministicZipError(
                        f"private directory must use canonical name: {private_name}"
                    )
                # These two entries are represented in the ZIP, but their
                # contents are never traversed or serialized.
                continue
            kept.append(name)
        directory_names[:] = kept
        for name in file_names:
            path = directory / name
            if _is_link_or_reparse(path) or not path.is_file():
                raise DeterministicZipError(
                    f"link or non-file in archive tree: {path.relative_to(root).as_posix()}"
                )
            relative = path.relative_to(root)
            if "\r" in relative.as_posix() or "\n" in relative.as_posix():
                raise DeterministicZipError("archive path contains a line break")
            if (
                not relative_directory.parts
                and name.casefold() in _PRIVATE_DIRECTORY_NAMES
            ):
                raise DeterministicZipError(
                    f"private archive path must be a plain directory: "
                    f"{_PRIVATE_DIRECTORY_NAMES[name.casefold()]}"
                )
            files.append(relative)
    key = lambda value: (value.as_posix().casefold(), value.as_posix())
    return sorted(directories, key=key), sorted(files, key=key)


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


def _write_file(
    archive: zipfile.ZipFile, root: Path, relative: Path
) -> None:
    path = root / relative
    try:
        before = path.stat()
        with path.open("rb") as source, archive.open(
            _zip_info(relative.as_posix(), directory=False),
            "w",
            force_zip64=True,
        ) as target:
            while chunk := source.read(CHUNK_SIZE):
                target.write(chunk)
        after = path.stat()
    except OSError as exc:
        raise DeterministicZipError(
            f"cannot archive file: {relative.as_posix()}"
        ) from exc
    if (
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_dev", None),
        getattr(before, "st_ino", None),
    ) != (
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_dev", None),
        getattr(after, "st_ino", None),
    ):
        raise DeterministicZipError(
            f"file changed while archiving: {relative.as_posix()}"
        )


def _verify_archive(path: Path, expected: list[str]) -> None:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.namelist() != expected or archive.testzip() is not None:
                raise DeterministicZipError("temporary archive failed verification")
    except DeterministicZipError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise DeterministicZipError("temporary archive failed verification") from exc


def build_deterministic_zip(source: Path, output: Path) -> int:
    source_input = Path(source)
    if _is_link_or_reparse(source_input) or not source_input.is_dir():
        raise DeterministicZipError("archive source must be a plain directory")
    try:
        source = source_input.resolve(strict=True)
    except OSError as exc:
        raise DeterministicZipError("archive source must be a plain directory") from exc
    output = output.resolve(strict=False)
    if output.suffix.casefold() != ".zip":
        raise DeterministicZipError("archive output must use a .zip suffix")
    if _within(output, source):
        raise DeterministicZipError("archive output cannot be inside its source tree")
    if output.exists() or _is_link_or_reparse(output.parent) or not output.parent.is_dir():
        raise DeterministicZipError("archive output must be a new file in a plain directory")

    private_state = _private_directory_state(source)
    directories, files = _entries(source)
    _require_unchanged_private_directories(source, private_state)
    expected = [f"{path.as_posix()}/" for path in directories]
    expected.extend(path.as_posix() for path in files)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, temporary_text = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        temporary = Path(temporary_text)
        with os.fdopen(descriptor, "w+b") as raw:
            descriptor = None
            with zipfile.ZipFile(
                raw,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                allowZip64=True,
                strict_timestamps=True,
            ) as archive:
                archive.comment = b""
                for relative in directories:
                    archive.writestr(
                        _zip_info(relative.as_posix(), directory=True), b""
                    )
                for relative in files:
                    _write_file(archive, source, relative)
                _require_unchanged_private_directories(source, private_state)
            raw.flush()
            os.fsync(raw.fileno())

        _require_unchanged_private_directories(source, private_state)
        _verify_archive(temporary, expected)
        # Verification can be expensive for a full portable runtime.  Recheck
        # the private roots immediately before the no-clobber publish step so
        # a change during verification cannot satisfy the release contract.
        _require_unchanged_private_directories(source, private_state)
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise DeterministicZipError("archive output appeared concurrently") from exc
        except OSError as exc:
            if os.name != "nt":
                raise DeterministicZipError("cannot publish archive without overwrite") from exc
            try:
                os.rename(temporary, output)
            except OSError as rename_exc:
                raise DeterministicZipError(
                    "cannot publish archive without overwrite"
                ) from rename_exc
            temporary = None
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                # The verified inode has already been published by a
                # no-clobber hard link.  A leftover hidden temporary is a
                # cleanup warning, not a reason to misreport the valid output
                # as failed; the finally block makes one more best effort.
                pass
            else:
                temporary = None
        return len(directories) + len(files)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink()
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
