# -*- coding: utf-8 -*-
"""Assemble a clean portable tree from reviewed source and a final Runtime."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROOT_FILES = (
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "LICENSE",
    "PORTABLE_BUILD.md",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "RUNTIME_INVENTORY.json",
    "SBOM.spdx.json",
    "VEX.openvex.json",
    "dev_console.bat",
    "run.bat",
    "run_debug.bat",
    "run_silent.vbs",
    "run_tests.bat",
    "verify_portable.bat",
    "启动Sankaku浏览下载器.bat",
    "启动_带调试窗口.bat",
    "启动_无控制台黑窗.vbs",
    "运行自动化测试.bat",
)
SOURCE_DIRECTORIES = ("App", "docs", "THIRD_PARTY_LICENSES")
PRIVATE_DIRECTORIES = ("Data", "Downloads")
RUNTIME_AUDIT_FILES = (
    "runtime_subset_manifest.sha256",
    "runtime_subset_report.json",
)
FORBIDDEN_NAMES = {
    ".app.lock",
    ".credentials",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "token.json",
    ".sankakusyncer-runtime-subset-builder",
}
FORBIDDEN_SUFFIXES = {
    ".key",
    ".kdbx",
    ".log",
    ".p12",
    ".part",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
}
FORBIDDEN_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
}
APP_ALLOWED_NAMES = {
    "requirements.lock.txt",
    "requirements.txt",
    "runtime_artifacts.lock.json",
}
APP_ALLOWED_SUFFIXES = {".py"}
DOCS_ALLOWED_SUFFIXES = {".png"}
LICENSE_ALLOWED_SUFFIXES = {
    ".docx",
    ".html",
    ".json",
    ".md",
    ".sha256",
    ".txt",
}


class AssemblyError(RuntimeError):
    """Raised when a portable staging tree cannot be assembled safely."""


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AssemblyError(f"cannot inspect source path: {path.name}") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _validate_destination(source: Path, runtime: Path, destination: Path) -> Path:
    resolved = destination.resolve()
    folded = resolved.name.casefold()
    if "sankakusyncer" not in folded or not any(
        marker in folded for marker in ("portable", "staging", "release")
    ):
        raise AssemblyError(
            "destination name must identify a SankakuSyncer portable/staging release"
        )
    if resolved.exists():
        raise AssemblyError("destination already exists; use a new staging directory")
    if _within(resolved, source) or _within(resolved, runtime):
        raise AssemblyError("destination cannot be inside source or Runtime")
    return resolved


def _is_private_name(name: str) -> bool:
    folded = name.casefold()
    return folded in FORBIDDEN_NAMES or folded.startswith(".env")


def _validate_source_policy(source_class: str, relative: Path) -> None:
    name = relative.name.casefold()
    suffix = relative.suffix.casefold()
    if source_class == "App":
        allowed = suffix in APP_ALLOWED_SUFFIXES or (
            len(relative.parts) == 1 and name in APP_ALLOWED_NAMES
        )
    elif source_class == "docs":
        allowed = suffix in DOCS_ALLOWED_SUFFIXES
    elif source_class == "THIRD_PARTY_LICENSES":
        allowed = suffix in LICENSE_ALLOWED_SUFFIXES
    elif source_class == "Runtime":
        allowed = True
    else:
        raise AssemblyError(f"unknown source directory policy: {source_class}")
    if not allowed:
        raise AssemblyError(
            f"unapproved {source_class} release file: {relative.as_posix()}"
        )


def _validate_launcher_line_endings(path: Path) -> None:
    if path.suffix.casefold() not in {".bat", ".vbs"}:
        return
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise AssemblyError(f"launcher is unreadable: {path.name}") from exc
    without_crlf = payload.replace(b"\r\n", b"")
    if b"\n" in without_crlf or b"\r" in without_crlf or b"\r\n" not in payload:
        raise AssemblyError(f"launcher must use CRLF line endings: {path.name}")


def _relative_files(root: Path, source_class: str) -> list[Path]:
    if _is_link_or_reparse(root) or not root.is_dir():
        raise AssemblyError(f"source directory is not plain: {root.name}")
    selected: list[Path] = []
    for directory_text, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        kept: list[str] = []
        for name in directory_names:
            path = directory / name
            if _is_link_or_reparse(path):
                raise AssemblyError(f"link/reparse point in source: {path}")
            folded = name.casefold()
            if folded in FORBIDDEN_DIRECTORY_NAMES or folded.startswith("."):
                raise AssemblyError(f"private/generated directory in source: {path}")
            kept.append(name)
        directory_names[:] = kept
        for name in file_names:
            path = directory / name
            if _is_link_or_reparse(path) or not path.is_file():
                raise AssemblyError(f"non-plain source file: {path}")
            if _is_private_name(name) or path.suffix.casefold() in FORBIDDEN_SUFFIXES:
                raise AssemblyError(f"private/generated source file: {path}")
            relative = path.relative_to(root)
            _validate_source_policy(source_class, relative)
            selected.append(relative)
    return sorted(selected, key=lambda value: (value.as_posix().casefold(), value.as_posix()))


def _copy_directory(source: Path, destination: Path, files: list[Path]) -> int:
    destination.mkdir(parents=True, exist_ok=False)
    for relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    return len(files)


def assemble_portable(source: Path, runtime: Path, destination: Path) -> int:
    source = source.resolve()
    runtime = runtime.resolve()
    if _is_link_or_reparse(source) or not source.is_dir():
        raise AssemblyError("project source is not a plain directory")
    if _is_link_or_reparse(runtime) or not runtime.is_dir():
        raise AssemblyError("Runtime is not a plain directory")
    for name in RUNTIME_AUDIT_FILES:
        path = runtime / name
        if _is_link_or_reparse(path) or not path.is_file():
            raise AssemblyError(f"Runtime audit file is missing: {name}")
    if (runtime / ".sankakusyncer-runtime-subset-builder").exists():
        raise AssemblyError("Runtime builder sentinel must be removed before assembly")

    root_sources: list[Path] = []
    for name in ROOT_FILES:
        path = source / name
        if _is_link_or_reparse(path) or not path.is_file():
            raise AssemblyError(f"required release file is missing: {name}")
        if _is_private_name(path.name) or path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            raise AssemblyError(f"private/generated release file: {name}")
        _validate_launcher_line_endings(path)
        root_sources.append(path)
    source_files = {
        name: _relative_files(source / name, name) for name in SOURCE_DIRECTORIES
    }
    runtime_files = _relative_files(runtime, "Runtime")

    destination = _validate_destination(source, runtime, destination)
    destination.mkdir(parents=True, exist_ok=False)
    copied = 0
    for path in root_sources:
        name = path.name
        shutil.copy2(path, destination / name)
        copied += 1
    for name in SOURCE_DIRECTORIES:
        copied += _copy_directory(
            source / name, destination / name, source_files[name]
        )
    copied += _copy_directory(runtime, destination / "Runtime", runtime_files)
    for name in PRIVATE_DIRECTORIES:
        (destination / name).mkdir()
    return copied


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    try:
        count = assemble_portable(
            arguments.source, arguments.runtime, arguments.destination
        )
    except (AssemblyError, OSError) as exc:
        parser.exit(1, f"portable assembly failed: {exc}\n")
    print(f"portable staging ready: {arguments.destination.resolve()} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
