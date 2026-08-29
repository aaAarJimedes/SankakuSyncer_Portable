# -*- coding: utf-8 -*-
"""Build a deterministic SHA-256 manifest for a staged portable release."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = "SHA256SUMS.txt"
_EXCLUDED_TOP_LEVEL = {"data", "downloads"}
_CHUNK_SIZE = 1024 * 1024


class ManifestError(RuntimeError):
    """Raised when a release tree cannot be represented safely."""


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _is_link_like(path: Path) -> bool:
    """Treat Windows junctions like symlinks; neither is portable in a ZIP."""
    try:
        return path.is_symlink() or path.is_junction()
    except (AttributeError, OSError):
        return path.is_symlink()


def iter_release_files(root: Path, manifest_path: Path) -> list[Path]:
    """Return sorted files, excluding private roots and this manifest itself."""
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    if not root.is_dir():
        raise ManifestError("release root is not a directory")
    if not _within(manifest_path, root):
        raise ManifestError("manifest output must be inside the release root")
    relative_manifest = manifest_path.relative_to(root)
    if relative_manifest.parts[0].casefold() in _EXCLUDED_TOP_LEVEL:
        raise ManifestError("manifest output cannot be inside Data or Downloads")

    selected: list[Path] = []
    for directory_text, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        relative_directory = directory.relative_to(root)
        kept_directories: list[str] = []
        for name in directory_names:
            path = directory / name
            relative = path.relative_to(root)
            if _is_link_like(path):
                raise ManifestError(f"symbolic link is not supported: {relative.as_posix()}")
            if relative.parts[0].casefold() in _EXCLUDED_TOP_LEVEL:
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories

        for name in file_names:
            path = directory / name
            relative = path.relative_to(root)
            if relative.parts[0].casefold() in _EXCLUDED_TOP_LEVEL:
                continue
            if _is_link_like(path):
                raise ManifestError(f"symbolic link is not supported: {relative.as_posix()}")
            if path.resolve() == manifest_path:
                continue
            if "\r" in relative.as_posix() or "\n" in relative.as_posix():
                raise ManifestError("release filename contains a line break")
            selected.append(path)
    return sorted(
        selected,
        key=lambda path: (path.relative_to(root).as_posix().casefold(), path.relative_to(root).as_posix()),
    )


def _sha256_file(path: Path) -> str:
    try:
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as file_obj:
            while chunk := file_obj.read(_CHUNK_SIZE):
                digest.update(chunk)
        after = path.stat()
    except OSError as exc:
        raise ManifestError(f"cannot hash {path.name} ({type(exc).__name__})") from exc
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ManifestError(f"file changed while hashing: {path.name}")
    return digest.hexdigest()


def manifest_lines(
    root: Path, manifest_path: Path, files: Iterable[Path] | None = None
) -> list[str]:
    root = root.resolve()
    selected = list(files) if files is not None else iter_release_files(root, manifest_path)
    return [
        f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in selected
    ]


def build_manifest(root: Path, manifest_path: Path) -> int:
    """Atomically write a manifest and return its number of hashed files."""
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    lines = manifest_lines(root, manifest_path)
    payload = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")

    descriptor: int | None = None
    temporary: str | None = None
    try:
        if not manifest_path.parent.is_dir():
            raise ManifestError("manifest output directory does not exist")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{manifest_path.name}.", suffix=".tmp", dir=manifest_path.parent
        )
        with os.fdopen(descriptor, "wb") as file_obj:
            descriptor = None
            file_obj.write(payload)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary, manifest_path)
        temporary = None
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"manifest write failed ({type(exc).__name__})") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.remove(temporary)
            except OSError:
                pass
    return len(lines)


def verify_manifest(root: Path, manifest_path: Path) -> int:
    """Re-hash the complete public release tree and require an exact manifest."""
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    if _is_link_like(manifest_path) or not manifest_path.is_file():
        raise ManifestError("manifest is missing or is not a plain file")
    lines = manifest_lines(root, manifest_path)
    expected = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    try:
        actual = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"manifest cannot be read ({type(exc).__name__})") from exc
    if actual != expected:
        raise ManifestError("manifest does not exactly match the release tree")
    return len(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build SHA256SUMS.txt for a clean SankakuSyncer release tree."
    )
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="staged portable root (default: package root)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="manifest path (default: <root>/SHA256SUMS.txt)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing manifest without writing files",
    )
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    output = (arguments.output or (root / DEFAULT_MANIFEST)).resolve()
    try:
        count = (
            verify_manifest(root, output)
            if arguments.check
            else build_manifest(root, output)
        )
    except ManifestError as exc:
        print(f"[FAIL] {exc}")
        return 1
    verb = "verified" if arguments.check else "wrote"
    print(f"[OK] {verb} {output} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
