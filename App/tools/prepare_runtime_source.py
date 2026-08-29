# -*- coding: utf-8 -*-
"""Create a verified full runtime source from locked official archives.

This stage is deliberately separate from ``build_runtime_subset.py``.  It
validates every downloaded artifact before touching an existing build, safely
extracts the official CPython embeddable distribution and wheels, and produces
the full source tree consumed by the lean-runtime builder.  It never downloads
from the network.
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import compat32
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
from typing import Iterable
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = PROJECT_ROOT / "App" / "runtime_artifacts.lock.json"
DEFAULT_DESTINATION = PROJECT_ROOT / "_runtime_source_build"
SENTINEL_NAME = ".sankakusyncer-runtime-source-builder"
SENTINEL_BYTES = (
    b"SankakuSyncer verified runtime source builder destination\n"
    b"schema-version: 1\n"
)
REPORT_NAME = "runtime_source_report.json"
DESTINATION_REQUIRED_MARKERS = ("build", "source", "staging")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class RuntimeSourceError(RuntimeError):
    """Raised when a locked runtime source cannot be built safely."""


def _canonical_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _safe_destination(path: Path) -> Path:
    resolved = path.resolve()
    name = resolved.name.casefold()
    if "runtime" not in name or not any(marker in name for marker in DESTINATION_REQUIRED_MARKERS):
        raise RuntimeSourceError(
            "destination name must contain 'runtime' and one of: "
            + ", ".join(DESTINATION_REQUIRED_MARKERS)
        )
    if resolved == resolved.anchor or resolved == PROJECT_ROOT.resolve():
        raise RuntimeSourceError("destination is too broad")
    return resolved


def _read_lock(path: Path) -> tuple[dict[str, str], list[dict[str, object]]]:
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeSourceError(f"artifact lock is unreadable ({type(exc).__name__})") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeSourceError("unsupported artifact lock schema")
    target = payload.get("target")
    artifacts = payload.get("artifacts")
    if not isinstance(target, dict) or not isinstance(artifacts, list) or not artifacts:
        raise RuntimeSourceError("artifact lock is incomplete")
    clean_target: dict[str, str] = {}
    for key in (
        "os",
        "architecture",
        "python",
        "python_abi",
        "pyside6",
        "transport",
    ):
        value = target.get(key)
        if not isinstance(value, str) or not value.strip():
            raise RuntimeSourceError(f"artifact lock target is missing {key}")
        clean_target[key] = value.strip()
    if clean_target["os"] != "windows" or clean_target["architecture"] != "x86_64":
        raise RuntimeSourceError("only the locked Windows x86-64 runtime is supported")
    if clean_target["transport"] != "winhttp-schannel":
        raise RuntimeSourceError("runtime transport must be locked to WinHTTP/Schannel")

    clean_artifacts: list[dict[str, object]] = []
    filenames: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeSourceError("artifact lock contains an invalid record")
        record: dict[str, object] = {}
        for key in ("kind", "distribution", "version", "filename", "url", "sha256"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                raise RuntimeSourceError(f"artifact record is missing {key}")
            record[key] = value.strip()
        filename = str(record["filename"])
        if Path(filename).name != filename or filename in filenames:
            raise RuntimeSourceError(f"unsafe or duplicate artifact filename: {filename}")
        filenames.add(filename)
        digest = str(record["sha256"]).casefold()
        if _SHA256_RE.fullmatch(digest) is None:
            raise RuntimeSourceError(f"invalid SHA-256 for {filename}")
        record["sha256"] = digest
        byte_count = item.get("bytes")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0:
            raise RuntimeSourceError(f"invalid byte count for {filename}")
        record["bytes"] = byte_count
        if record["kind"] not in {"python_embed", "wheel"}:
            raise RuntimeSourceError(f"unsupported artifact kind for {filename}")
        clean_artifacts.append(record)
    if sum(item["kind"] == "python_embed" for item in clean_artifacts) != 1:
        raise RuntimeSourceError("artifact lock must contain exactly one Python embed archive")
    return clean_target, clean_artifacts


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise RuntimeSourceError("archive contains an unsafe member name")
    member = PurePosixPath(name)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise RuntimeSourceError(f"archive member escapes destination: {name}")
    if member.parts and ":" in member.parts[0]:
        raise RuntimeSourceError(f"archive member has a drive prefix: {name}")
    return tuple(member.parts)


def _preflight_archive(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                _safe_member_parts(info.filename.rstrip("/"))
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise RuntimeSourceError(
                        f"archive contains a symbolic link: {info.filename}"
                    )
            bad = archive.testzip()
            if bad:
                raise RuntimeSourceError(f"archive CRC failed: {path.name}:{bad}")
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeSourceError(f"invalid archive: {path.name}") from exc


def _wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise RuntimeSourceError(f"wheel has ambiguous metadata: {path.name}")
        message = BytesParser(policy=compat32).parsebytes(archive.read(metadata_names[0]))
    name = str(message.get("Name", "")).strip()
    version = str(message.get("Version", "")).strip()
    if not name or not version:
        raise RuntimeSourceError(f"wheel metadata is incomplete: {path.name}")
    return name, version


def verify_artifacts(
    wheelhouse: Path, artifacts: Iterable[dict[str, object]]
) -> list[Path]:
    paths: list[Path] = []
    for record in artifacts:
        filename = str(record["filename"])
        path = wheelhouse / filename
        if not path.is_file() or path.is_symlink():
            raise RuntimeSourceError(f"locked artifact is missing or unsafe: {filename}")
        if path.stat().st_size != record["bytes"]:
            raise RuntimeSourceError(f"artifact size mismatch: {filename}")
        if _sha256(path) != record["sha256"]:
            raise RuntimeSourceError(f"artifact hash mismatch: {filename}")
        _preflight_archive(path)
        if record["kind"] == "wheel":
            actual_name, actual_version = _wheel_identity(path)
            if (
                _canonical_distribution(actual_name)
                != _canonical_distribution(str(record["distribution"]))
                or actual_version != record["version"]
            ):
                raise RuntimeSourceError(f"wheel identity mismatch: {filename}")
        paths.append(path)
    return paths


def _prepare_destination(destination: Path, *, clean: bool) -> None:
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise RuntimeSourceError("destination is not a plain directory")
        populated = next(destination.iterdir(), None) is not None
        if populated:
            if not clean:
                raise RuntimeSourceError("destination is not empty; use --clean")
            sentinel = destination / SENTINEL_NAME
            try:
                marker = sentinel.read_bytes()
            except OSError as exc:
                raise RuntimeSourceError("refusing to clean without the exact builder sentinel") from exc
            if marker != SENTINEL_BYTES or sentinel.is_symlink():
                raise RuntimeSourceError("refusing to clean without the exact builder sentinel")
            shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / SENTINEL_NAME).write_bytes(SENTINEL_BYTES)


def _same_archive_member(path: Path, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    if not path.is_file() or path.is_symlink() or path.stat().st_size != info.file_size:
        return False
    existing = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            existing.update(chunk)
    incoming = hashlib.sha256()
    with archive.open(info) as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            incoming.update(chunk)
    return existing.digest() == incoming.digest()


def _extract_archive(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            stripped = info.filename.rstrip("/")
            parts = _safe_member_parts(stripped)
            target = destination.joinpath(*parts)
            if not _within(target, destination):
                raise RuntimeSourceError(f"archive member escapes destination: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.exists():
                if _same_archive_member(target, archive, info):
                    continue
                raise RuntimeSourceError(f"archives contain conflicting file: {'/'.join(parts)}")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            except OSError as exc:
                raise RuntimeSourceError(
                    f"failed to extract archive member: {info.filename}"
                ) from exc


def _configure_embedded_python(destination: Path, target: dict[str, str]) -> None:
    compact = "".join(target["python"].split(".")[:2])
    pth = destination / f"python{compact}._pth"
    stdlib = destination / f"python{compact}.zip"
    dll = destination / f"python{compact}.dll"
    for path in (destination / "python.exe", destination / "pythonw.exe", stdlib, dll, pth):
        if not path.is_file():
            raise RuntimeSourceError(f"Python embed archive is missing {path.name}")
    pth.write_text(
        f"python{compact}.zip\n.\nLib\nLib\\site-packages\n..\\App\nimport site\n",
        encoding="utf-8",
        newline="\n",
    )


def build_runtime_source(
    lock_path: Path,
    wheelhouse: Path,
    destination: Path,
    *,
    clean: bool,
) -> dict[str, object]:
    target, artifacts = _read_lock(lock_path)
    wheelhouse = wheelhouse.resolve()
    destination = _safe_destination(destination)
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise RuntimeSourceError("wheelhouse is not a plain directory")
    if _within(destination, wheelhouse) or _within(wheelhouse, destination):
        raise RuntimeSourceError("wheelhouse and destination must not contain each other")
    paths = verify_artifacts(wheelhouse, artifacts)
    _prepare_destination(destination, clean=clean)

    python_records = [
        (record, path)
        for record, path in zip(artifacts, paths, strict=True)
        if record["kind"] == "python_embed"
    ]
    wheel_records = [
        (record, path)
        for record, path in zip(artifacts, paths, strict=True)
        if record["kind"] == "wheel"
    ]
    _extract_archive(python_records[0][1], destination)
    site_packages = destination / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    for _record, path in wheel_records:
        _extract_archive(path, site_packages)
    _configure_embedded_python(destination, target)

    report: dict[str, object] = {
        "schema_version": 1,
        "target": target,
        "artifacts": [
            {
                "kind": record["kind"],
                "distribution": record["distribution"],
                "version": record["version"],
                "filename": record["filename"],
                "bytes": record["bytes"],
                "sha256": record["sha256"],
            }
            for record in artifacts
        ],
    }
    (destination / REPORT_NAME).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = build_runtime_source(
            args.lock,
            args.wheelhouse,
            args.destination,
            clean=args.clean,
        )
    except RuntimeSourceError as exc:
        parser.exit(1, f"runtime source build failed: {exc}\n")
    print(
        "runtime source ready: "
        f"Python {report['target']['python']}, "
        f"PySide6 {report['target']['pyside6']}, "
        f"{len(report['artifacts'])} verified artifacts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
