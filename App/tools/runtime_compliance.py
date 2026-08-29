# -*- coding: utf-8 -*-
"""Create a verifiable inventory and SPDX view of the final lean Runtime.

This module is deliberately offline.  Artifact URLs and hashes come from the
reviewed runtime artifact lock; exact outer-hash-verified CPython/wheel ZIP
member maps establish which artifact provided each copied file (including
wheel ``RECORD`` and ``METADATA`` themselves); every final payload file is
re-hashed. Native
component versions are obtained from the exact CPython artifact SBOM, exact Qt
source release hashes, saved Qt attribution pages, PE version resources, and a
bounded probe using the packaged interpreter.
"""

from __future__ import annotations

from collections import defaultdict
import ctypes
from ctypes import wintypes
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Iterable, Mapping
from urllib.parse import urlsplit

try:
    from .build_runtime_subset import parse_pe_imports
except ImportError:  # Direct execution from App/tools.
    tools_directory = str(Path(__file__).resolve().parent)
    if tools_directory not in sys.path:
        sys.path.insert(0, tools_directory)
    from build_runtime_subset import parse_pe_imports


def _load_application_version() -> str:
    try:
        from version import APP_VERSION as value
    except ImportError:
        version_path = Path(__file__).resolve().parents[1] / "version.py"
        spec = importlib.util.spec_from_file_location("_sankakusyncer_version", version_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("App/version.py cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        value = getattr(module, "APP_VERSION", None)
    if not isinstance(value, str) or not value:
        raise RuntimeError("App/version.py has no APP_VERSION")
    return value


PYTHON_VERSION = "3.13.15"
PYSIDE_VERSION = "6.11.2"
QT_VERSION = "6.11.2"
APP_VERSION = _load_application_version()
BUILDER_SENTINEL = ".sankakusyncer-runtime-subset-builder"
BUILDER_MANIFEST = "runtime_subset_manifest.sha256"
BUILDER_REPORT = "runtime_subset_report.json"
PORTABLE_RELATIVE_PATH_LIMIT = 160
QT_ATTRIBUTION_ARCHIVE_FILENAME_LIMIT = 96
PE_SUFFIXES = {".dll", ".exe", ".pyd"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")
_QT_ATTRIBUTION_FILENAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.+-]*\.html$", re.IGNORECASE
)

CPYTHON_NATIVE_COMPONENTS = {
    "bzip2": ("_bz2.pyd",),
    "expat": ("pyexpat.pyd", "_elementtree.pyd"),
    "hacl-star": ("python313.dll",),
    "libb2": ("python313.dll",),
    "libffi": ("libffi-8.dll", "_ctypes.pyd"),
    "mpdecimal": ("_decimal.pyd",),
    "openssl": ("libcrypto-3.dll", "libssl-3.dll", "_hashlib.pyd", "_ssl.pyd"),
    "sqlite": ("sqlite3.dll", "_sqlite3.pyd"),
    "xz": ("_lzma.pyd",),
    "zlib": ("python313.dll",),
}

# These are demonstrably present in the selected Qt binaries/resources.  The
# full attribution bundle is broader and remains available for legal review;
# only this evidence-backed subset becomes runtime packages in our SPDX.
QT_NATIVE_ATTRIBUTIONS = {
    "qtcore-attribution-zlib.html",
    "qtgui-attribution-freetype.html",
    "qtgui-attribution-harfbuzz-ng.html",
    "qtgui-attribution-libjpeg.html",
    "qtgui-attribution-libpng.html",
    "qtimageformats-attribution-libwebp.html",
    "qt-attribution-llvmpipe.html",
    "qtwebengine-3rdparty-boringssl.html",
    "qtwebengine-3rdparty-expat-xml-parser.html",
    "qtwebengine-3rdparty-ffmpeg.html",
    "qtwebengine-3rdparty-icu.html",
    "qtwebengine-3rdparty-libpng.html",
    "qtwebengine-3rdparty-libvpx.html",
    "qtwebengine-3rdparty-opus.html",
    "qtwebengine-3rdparty-sqlite.html",
    "qtwebengine-3rdparty-the-chromium-project.html",
    "qtwebengine-3rdparty-webp-image-encoder-decoder.html",
    "qtwebengine-3rdparty-zlib.html",
    "qtwebengine-3rdparty-zstandard.html",
}


class RuntimeComplianceError(RuntimeError):
    """Runtime inventory, provenance, or upstream material is inconsistent."""


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def qt_attribution_archive_filename(source_filename: str) -> str:
    """Return the bounded, deterministic local name for a Qt notice page.

    Most upstream names are already short and remain byte-for-byte readable.
    Long names retain a readable stem prefix and append the *full* SHA-256 of
    the authoritative upstream basename.  The full digest makes the mapping
    collision-resistant without relying on a truncated identifier, while the
    fixed limit keeps default Windows Git checkouts below ``MAX_PATH``.
    """
    if (
        not isinstance(source_filename, str)
        or PurePosixPath(source_filename).name != source_filename
        or not _QT_ATTRIBUTION_FILENAME_RE.fullmatch(source_filename)
    ):
        raise RuntimeComplianceError(
            f"unsafe Qt attribution source filename: {source_filename!r}"
        )
    if len(source_filename) <= QT_ATTRIBUTION_ARCHIVE_FILENAME_LIMIT:
        return source_filename

    extension = ".html"
    digest = hashlib.sha256(source_filename.encode("ascii")).hexdigest()
    prefix_limit = (
        QT_ATTRIBUTION_ARCHIVE_FILENAME_LIMIT
        - len(extension)
        - len(digest)
        - 1
    )
    prefix = source_filename[: -len(extension)][:prefix_limit].rstrip("._-")
    if not prefix:
        raise RuntimeComplianceError(
            f"Qt attribution filename has no bounded prefix: {source_filename!r}"
        )
    archived = f"{prefix}-{digest}{extension}"
    if len(archived) > QT_ATTRIBUTION_ARCHIVE_FILENAME_LIMIT:
        raise RuntimeComplianceError("bounded Qt attribution filename overflow")
    return archived


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def read_artifact_lock(
    path: Path,
    locked: Mapping[str, tuple[str, str]],
) -> dict[str, object]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeComplianceError("runtime artifact lock is missing or invalid") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeComplianceError("unsupported runtime artifact lock schema")
    target = value.get("target")
    expected_target = {
        "os": "windows",
        "architecture": "x86_64",
        "python": PYTHON_VERSION,
        "python_abi": "cp313",
        "pyside6": PYSIDE_VERSION,
        "transport": "winhttp-schannel",
    }
    if target != expected_target:
        raise RuntimeComplianceError("runtime artifact lock target mismatch")
    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise RuntimeComplianceError("runtime artifact lock has no artifacts list")

    expected_versions = {name: version for name, (_display, version) in locked.items()}
    expected_versions["cpython"] = PYTHON_VERSION
    artifacts: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, dict):
            raise RuntimeComplianceError(f"invalid runtime artifact entry {index}")
        distribution = raw.get("distribution")
        version = raw.get("version")
        filename = raw.get("filename")
        url = raw.get("url")
        digest = raw.get("sha256")
        member_inventory_digest = raw.get("member_inventory_sha256")
        size = raw.get("bytes")
        kind = raw.get("kind")
        if not all(isinstance(item, str) and item for item in (
            distribution, version, filename, url, digest, kind
        )) or type(size) is not int or size < 1:
            raise RuntimeComplianceError(f"invalid runtime artifact metadata {index}")
        canonical = canonical_name(str(distribution))
        if canonical in seen:
            raise RuntimeComplianceError(f"duplicate runtime artifact: {distribution}")
        seen.add(canonical)
        if canonical not in expected_versions or version != expected_versions[canonical]:
            raise RuntimeComplianceError(
                f"runtime artifact version mismatch: {distribution}=={version}"
            )
        split = urlsplit(str(url))
        if split.scheme != "https" or split.hostname not in {
            "files.pythonhosted.org",
            "www.python.org",
        }:
            raise RuntimeComplianceError(f"unapproved runtime artifact URL: {url}")
        if not _SHA256_RE.fullmatch(str(digest)) or not _SHA256_RE.fullmatch(
            str(member_inventory_digest)
        ):
            raise RuntimeComplianceError(f"invalid artifact SHA-256: {distribution}")
        artifact = dict(raw)
        artifact["canonical_name"] = canonical
        artifact["artifact_id"] = f"{canonical}@{version}"
        artifacts.append(artifact)
    missing = sorted(set(expected_versions) - seen)
    if missing:
        raise RuntimeComplianceError("runtime artifact lock is missing: " + ", ".join(missing))
    return {
        "schema_version": 1,
        "target": expected_target,
        "artifacts": sorted(artifacts, key=lambda item: str(item["artifact_id"])),
    }


def _safe_record_path(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if not value or path.is_absolute() or ".." in path.parts:
        raise RuntimeComplianceError(f"unsafe wheel RECORD path: {value!r}")
    return path.as_posix()


def _installed_wheel_member_path(value: str) -> str | None:
    path = PurePosixPath(_safe_record_path(value))
    parts = path.parts
    data_index = next(
        (index for index, part in enumerate(parts) if part.casefold().endswith(".data")),
        None,
    )
    if data_index is None:
        return f"Lib/site-packages/{path.as_posix()}"
    if data_index + 2 > len(parts):
        raise RuntimeComplianceError("wheel .data member path is malformed")
    category = parts[data_index + 1].casefold()
    if category not in {"purelib", "platlib"}:
        return None  # Scripts/headers/data are not selected into this Runtime.
    installed = PurePosixPath(*parts[data_index + 2 :])
    if not installed.parts:
        raise RuntimeComplianceError("wheel library member path is empty")
    return f"Lib/site-packages/{installed.as_posix()}"


def _wheel_member_owners(
    artifacts: Iterable[Mapping[str, object]],
    member_inventories: Iterable[Mapping[str, object]],
) -> dict[str, list[tuple[str, str, int]]]:
    wheels = {
        str(artifact["artifact_id"]): artifact
        for artifact in artifacts
        if artifact.get("kind") == "wheel"
    }
    inventories_by_artifact: dict[str, Mapping[str, object]] = {}
    owners: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for inventory in member_inventories:
        if inventory.get("schema_version") != 1:
            raise RuntimeComplianceError("wheel member inventory schema mismatch")
        source = inventory.get("source_artifact")
        if not isinstance(source, dict):
            raise RuntimeComplianceError("wheel member inventory source is invalid")
        matches = [
            (artifact_id, artifact)
            for artifact_id, artifact in wheels.items()
            if all(
                source.get(key) == artifact.get(key)
                for key in ("filename", "url", "sha256", "bytes")
            )
        ]
        if len(matches) != 1:
            raise RuntimeComplianceError("wheel member inventory artifact mismatch")
        artifact_id, artifact = matches[0]
        if sha256_bytes(json_bytes(inventory)) != artifact.get(
            "member_inventory_sha256"
        ):
            raise RuntimeComplianceError(
                "wheel member inventory is not anchored by the artifact lock"
            )
        if artifact_id in inventories_by_artifact:
            raise RuntimeComplianceError("duplicate wheel member inventory")
        inventories_by_artifact[artifact_id] = inventory
        members = inventory.get("members")
        if not isinstance(members, list):
            raise RuntimeComplianceError("wheel member inventory has no members")
        seen: set[str] = set()
        for raw in members:
            if not isinstance(raw, dict):
                raise RuntimeComplianceError("wheel member inventory entry is invalid")
            path = raw.get("path")
            digest = raw.get("sha256")
            size = raw.get("size")
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or not _SHA256_RE.fullmatch(digest)
                or type(size) is not int
                or size < 0
                or path.casefold() in seen
            ):
                raise RuntimeComplianceError("wheel member inventory entry is malformed")
            seen.add(path.casefold())
            runtime_path = _installed_wheel_member_path(path)
            if runtime_path is not None:
                owners[runtime_path.casefold()].append((artifact_id, digest, size))
    missing = sorted(set(wheels) - set(inventories_by_artifact))
    if missing:
        raise RuntimeComplianceError(
            "wheel member inventory is missing: " + ", ".join(missing)
        )
    return owners


def _version_resource(path: Path) -> str | None:
    """Read the fixed PE file version without launching the binary."""
    if os.name != "nt":
        return None
    try:
        version = ctypes.windll.version
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            return None

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wintypes.DWORD),
                ("dwStrucVersion", wintypes.DWORD),
                ("dwFileVersionMS", wintypes.DWORD),
                ("dwFileVersionLS", wintypes.DWORD),
                ("dwProductVersionMS", wintypes.DWORD),
                ("dwProductVersionLS", wintypes.DWORD),
                ("dwFileFlagsMask", wintypes.DWORD),
                ("dwFileFlags", wintypes.DWORD),
                ("dwFileOS", wintypes.DWORD),
                ("dwFileType", wintypes.DWORD),
                ("dwFileSubtype", wintypes.DWORD),
                ("dwFileDateMS", wintypes.DWORD),
                ("dwFileDateLS", wintypes.DWORD),
            ]

        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return None
        info = ctypes.cast(pointer, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        if info.dwSignature != 0xFEEF04BD:
            return None
        return ".".join(
            str(value)
            for value in (
                info.dwFileVersionMS >> 16,
                info.dwFileVersionMS & 0xFFFF,
                info.dwFileVersionLS >> 16,
                info.dwFileVersionLS & 0xFFFF,
            )
        )
    except (AttributeError, OSError, ValueError):
        return None


_RUNTIME_PROBE = r"""
import json, platform, pyexpat, sqlite3, zlib
from PySide6.QtCore import qVersion
from PySide6.QtWebEngineCore import qWebEngineChromiumVersion
try:
    import ssl
    openssl = ssl.OPENSSL_VERSION
except (ImportError, OSError):
    openssl = "not-present"
try:
    from PySide6.QtWebEngineCore import qWebEngineChromiumSecurityPatchVersion
    chromium_patch = qWebEngineChromiumSecurityPatchVersion()
except (ImportError, AttributeError):
    chromium_patch = ""
print(json.dumps({
    "python": platform.python_version(),
    "openssl": openssl,
    "sqlite": sqlite3.sqlite_version,
    "zlib_compile": zlib.ZLIB_VERSION,
    "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
    "expat": pyexpat.EXPAT_VERSION,
    "qt": qVersion(),
    "chromium": qWebEngineChromiumVersion(),
    "chromium_security_patch": chromium_patch,
}, sort_keys=True))
"""


def _probe_runtime(runtime: Path) -> dict[str, str]:
    python = runtime / "python.exe"
    if not python.is_file():
        raise RuntimeComplianceError("Runtime/python.exe is missing")
    environment = {
        "PATH": os.pathsep.join(
            [
                str(runtime),
                str(runtime / "Lib" / "site-packages" / "PySide6"),
                os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
                os.environ.get("SystemRoot", r"C:\Windows"),
            ]
        ),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
    }
    try:
        completed = subprocess.run(
            [str(python), "-I", "-B", "-s", "-c", _RUNTIME_PROBE],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeComplianceError("Runtime version probe failed") from exc
    if completed.returncode != 0:
        raise RuntimeComplianceError(
            f"Runtime version probe exited with code {completed.returncode}"
        )
    try:
        value = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeComplianceError("Runtime version probe returned invalid JSON") from exc
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise RuntimeComplianceError("Runtime version probe returned invalid fields")
    if value.get("python") != PYTHON_VERSION:
        raise RuntimeComplianceError("Runtime Python patch version mismatch")
    if value.get("qt") != QT_VERSION:
        raise RuntimeComplianceError("Runtime Qt version mismatch")
    if not value.get("chromium"):
        raise RuntimeComplianceError("Runtime Chromium version unavailable")
    return dict(sorted(value.items()))


def _iter_payload_files(runtime: Path) -> list[Path]:
    if not runtime.is_dir():
        raise RuntimeComplianceError("Runtime directory is missing")
    if (runtime / BUILDER_SENTINEL).exists():
        raise RuntimeComplianceError("builder destination sentinel must not ship")
    files: list[Path] = []
    for path in sorted(runtime.rglob("*")):
        relative = path.relative_to(runtime).as_posix()
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise RuntimeComplianceError(f"Runtime link is not allowed: {relative}")
        if path.is_file() and relative.casefold() not in {
            BUILDER_MANIFEST.casefold(),
            BUILDER_REPORT.casefold(),
        }:
            if path.suffix.casefold() in {".pyc", ".pyo"} or "__pycache__" in {
                part.casefold() for part in path.parts
            }:
                raise RuntimeComplianceError(f"generated Runtime file present: {relative}")
            files.append(path)
    if not files:
        raise RuntimeComplianceError("Runtime payload is empty")
    return files


def _validate_builder_metadata(runtime: Path, files: Iterable[Path]) -> dict[str, object]:
    manifest = runtime / BUILDER_MANIFEST
    report_path = runtime / BUILDER_REPORT
    if not manifest.is_file():
        raise RuntimeComplianceError("builder Runtime manifest is missing")
    if not report_path.is_file():
        raise RuntimeComplianceError("builder Runtime report is missing")
    expected: dict[str, str] = {}
    previous_manifest_path: tuple[str, ...] | None = None
    try:
        for line in manifest.read_text("utf-8").splitlines():
            digest, separator, relative = line.partition(" *")
            relative = relative.replace("\\", "/")
            pure = PurePosixPath(relative)
            if (
                separator != " *"
                or not _SHA256_RE.fullmatch(digest)
                or not relative
                or pure.is_absolute()
                or ".." in pure.parts
                or pure.as_posix() != relative
            ):
                raise RuntimeComplianceError("builder Runtime manifest is malformed")
            folded = relative.casefold()
            if folded in expected:
                raise RuntimeComplianceError("builder Runtime manifest has duplicates")
            sort_key = tuple(part.casefold() for part in pure.parts)
            if previous_manifest_path is not None and sort_key < previous_manifest_path:
                raise RuntimeComplianceError("builder Runtime manifest is not sorted")
            previous_manifest_path = sort_key
            expected[folded] = digest
    except (OSError, UnicodeError) as exc:
        raise RuntimeComplianceError("builder Runtime manifest is unreadable") from exc
    actual = {
        path.relative_to(runtime).as_posix().casefold(): sha256_bytes(path.read_bytes())
        for path in files
    }
    if expected != actual:
        raise RuntimeComplianceError("builder Runtime manifest does not match payload")
    try:
        report = json.loads(report_path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeComplianceError("builder Runtime report is unreadable") from exc
    expected_report_keys = {
        "artifact_name",
        "bytes",
        "dynamic_seeds",
        "external_system_imports",
        "file_count",
        "forbidden_files",
        "mib",
        "pe_images_scanned",
        "python",
        "python_layout",
        "python_verification_target",
        "qt_layout",
        "schema_version",
        "unresolved_imports",
        "verification",
    }
    if (
        not isinstance(report, dict)
        or set(report) != expected_report_keys
        or report.get("schema_version") != 3
    ):
        raise RuntimeComplianceError("builder Runtime report schema mismatch")
    total_bytes = sum(path.stat().st_size for path in files)
    if (
        report.get("artifact_name") != "SankakuSyncer_Runtime_Lean"
        or report.get("python") != "3.13"
        or report.get("python_verification_target") != PYTHON_VERSION
        or report.get("python_layout") != "embedded"
        or report.get("qt_layout") != "pyside6-wheel"
        or type(report.get("file_count")) is not int
        or report.get("file_count") != len(actual)
        or type(report.get("bytes")) is not int
        or report.get("bytes") != total_bytes
        or type(report.get("mib")) not in {int, float}
        or report.get("mib") != round(total_bytes / (1024 * 1024), 2)
        or type(report.get("pe_images_scanned")) is not int
        or report.get("unresolved_imports") != {}
        or report.get("forbidden_files") != []
    ):
        raise RuntimeComplianceError("builder Runtime report does not match payload")
    reported_imports = report.get("external_system_imports")
    if (
        not isinstance(reported_imports, list)
        or not all(isinstance(value, str) and value for value in reported_imports)
        or reported_imports != sorted(set(reported_imports))
    ):
        raise RuntimeComplianceError("builder Runtime external import list is invalid")
    dynamic_seeds = report.get("dynamic_seeds")
    actual_paths = {path.relative_to(runtime).as_posix() for path in files}
    if (
        not isinstance(dynamic_seeds, list)
        or not all(isinstance(value, str) and value for value in dynamic_seeds)
        or len(dynamic_seeds) != len(set(dynamic_seeds))
        or not set(dynamic_seeds).issubset(actual_paths)
    ):
        raise RuntimeComplianceError("builder Runtime dynamic seed list is invalid")
    verification = report.get("verification")
    if not isinstance(verification, list) or not verification:
        raise RuntimeComplianceError("builder Runtime report has no verification results")
    verification_names: list[str] = []
    for item in verification:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "returncode"}
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or type(item.get("returncode")) is not int
            or item.get("returncode") != 0
        ):
            raise RuntimeComplianceError("builder Runtime verification did not pass")
        if item["name"] in verification_names:
            raise RuntimeComplianceError("builder Runtime verification names are duplicated")
        verification_names.append(str(item["name"]))
    expected_verification_names = [
        "python_hashlib_winhttp",
        "qtwidgets_qtwebengine_import",
        "offline_mainwindow_construction",
        "offline_regression_suite",
    ]
    if verification_names != expected_verification_names:
        raise RuntimeComplianceError("builder Runtime verification set is incomplete")
    return report


def _cpython_member_hashes(
    member_inventory: Mapping[str, object],
    cpython_artifact: Mapping[str, object],
) -> dict[str, tuple[str, int]]:
    if member_inventory.get("schema_version") != 1:
        raise RuntimeComplianceError("CPython member inventory schema mismatch")
    if sha256_bytes(json_bytes(member_inventory)) != cpython_artifact.get(
        "member_inventory_sha256"
    ):
        raise RuntimeComplianceError(
            "CPython member inventory is not anchored by the artifact lock"
        )
    source = member_inventory.get("source_artifact")
    if not isinstance(source, dict) or any(
        source.get(key) != cpython_artifact.get(key)
        for key in ("filename", "url", "sha256", "bytes")
    ):
        raise RuntimeComplianceError("CPython member inventory artifact mismatch")
    raw_members = member_inventory.get("members")
    if not isinstance(raw_members, list):
        raise RuntimeComplianceError("CPython member inventory has no members")
    members: dict[str, tuple[str, int]] = {}
    for raw in raw_members:
        if not isinstance(raw, dict):
            raise RuntimeComplianceError("CPython member inventory entry is invalid")
        path = raw.get("path")
        digest = raw.get("sha256")
        size = raw.get("size")
        if (
            not isinstance(path, str)
            or _safe_record_path(path) != path
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
            or type(size) is not int
            or size < 0
            or path.casefold() in members
        ):
            raise RuntimeComplianceError("CPython member inventory entry is malformed")
        members[path.casefold()] = (digest, size)
    if not members:
        raise RuntimeComplianceError("CPython member inventory is empty")
    return members


def _is_expected_pth_transformation(relative: str, data: bytes) -> bool:
    return relative.casefold() == "python313._pth" and data == (
        b"python313.zip\n.\nLib\nLib\\site-packages\n..\\App\nimport site\n"
    )


def build_runtime_inventory(
    runtime: Path,
    artifact_lock: Mapping[str, object],
    artifact_lock_sha256: str,
    cpython_member_inventory: Mapping[str, object],
    wheel_member_inventories: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    runtime = runtime.resolve()
    artifacts = artifact_lock["artifacts"]
    assert isinstance(artifacts, list)
    wheel_owners = _wheel_member_owners(artifacts, wheel_member_inventories)
    cpython_artifact = next(
        artifact for artifact in artifacts if artifact["canonical_name"] == "cpython"
    )
    cpython_id = str(cpython_artifact["artifact_id"])
    files = _iter_payload_files(runtime)
    report = _validate_builder_metadata(runtime, files)
    cpython_members = _cpython_member_hashes(
        cpython_member_inventory, cpython_artifact
    )

    entries: list[dict[str, object]] = []
    external_imports: set[str] = set()
    for path in files:
        relative = path.relative_to(runtime).as_posix()
        data = path.read_bytes()
        digest = sha256_bytes(data)
        provenance = {
            artifact_id
            for artifact_id, expected_digest, expected_size in wheel_owners.get(
                relative.casefold(), []
            )
            if expected_digest == digest and expected_size == len(data)
        }
        if relative.startswith("Lib/site-packages/") and not provenance:
            raise RuntimeComplianceError(
                f"Runtime site-package file does not match a locked wheel member: {relative}"
            )
        transformation: str | None = None
        if not provenance:
            expected_member = cpython_members.get(relative.casefold())
            if expected_member == (sha256_bytes(data), len(data)):
                provenance.add(cpython_id)
            elif _is_expected_pth_transformation(relative, data):
                provenance.add(cpython_id)
                transformation = (
                    "prepare_runtime_source.py deterministic embedded-path rewrite"
                )
            else:
                raise RuntimeComplianceError(
                    f"Runtime file has no locked artifact provenance: {relative}"
                )
        entry: dict[str, object] = {
            "path": relative,
            "provenance_artifacts": sorted(provenance),
            "sha1": hashlib.sha1(data).hexdigest(),  # SPDX verification-code input.
            "sha256": digest,
            "size": len(data),
        }
        if path.suffix.casefold() in PE_SUFFIXES:
            version = _version_resource(path)
            if version:
                entry["file_version"] = version
            try:
                external_imports.update(parse_pe_imports(path))
            except Exception as exc:
                raise RuntimeComplianceError(f"PE import scan failed: {relative}") from exc
        if transformation:
            entry["provenance_transformation"] = transformation
        entries.append(entry)

    local_pe_names = {
        path.name.casefold()
        for path in files
        if path.suffix.casefold() in PE_SUFFIXES
    }
    recomputed_external = {
        value.casefold() for value in external_imports if value.casefold() not in local_pe_names
    }
    reported_imports = report.get("external_system_imports")
    if not isinstance(reported_imports, list) or {
        str(value).casefold() for value in reported_imports
    } != recomputed_external:
        raise RuntimeComplianceError("builder Runtime external import report mismatch")
    if report.get("pe_images_scanned") != sum(
        1 for path in files if path.suffix.casefold() in PE_SUFFIXES
    ):
        raise RuntimeComplianceError("builder Runtime PE count mismatch")

    # The two required builder audit files ship with the final Runtime but are
    # intentionally outside the payload manifest to avoid a circular hash.
    for metadata_name in (BUILDER_MANIFEST, BUILDER_REPORT):
        path = runtime / metadata_name
        data = path.read_bytes()
        entries.append(
            {
                "path": metadata_name,
                "provenance_artifacts": [],
                "provenance_kind": "runtime-subset-builder-output",
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": sha256_bytes(data),
                "size": len(data),
            }
        )
    entries.sort(key=lambda value: str(value["path"]).casefold())

    probe = _probe_runtime(runtime)
    lines = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in entries
    ).encode("utf-8")
    return {
        "artifact_lock_sha256": artifact_lock_sha256,
        "components": probe,
        "external_pe_imports": sorted(recomputed_external, key=str.casefold),
        "file_count": len(entries),
        "files": entries,
        "payload_sha256": sha256_bytes(lines),
        "payload_file_count": len(files),
        "schema_version": 2,
        "target": {
            "architecture": "x86_64",
            "os": "windows",
            "python": PYTHON_VERSION,
            "pyside6": PYSIDE_VERSION,
            "qt": QT_VERSION,
            "transport": "winhttp-schannel",
        },
        "total_bytes": sum(int(entry["size"]) for entry in entries),
    }


def parse_attribution_page(filename: str, data: bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeComplianceError(f"Qt attribution is not UTF-8: {filename}") from exc
    match = re.search(r"<h1[^>]*>(.*?)</h1>", text, re.IGNORECASE | re.DOTALL)
    if match is None:
        raise RuntimeComplianceError(f"Qt attribution has no title: {filename}")
    title = html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip()
    version: str | None = None
    version_match = re.match(r"^(.*?),\s*version\s+(.+)$", title, re.IGNORECASE)
    if version_match:
        name = version_match.group(1).strip()
        version = version_match.group(2).strip()
    else:
        name = title
    identifiers = sorted(
        set(
            re.findall(
                r"https://spdx\.org/licenses/([A-Za-z0-9.+-]+)\.html",
                text,
                re.IGNORECASE,
            )
        ),
        key=str.casefold,
    )
    value: dict[str, object] = {
        "filename": filename,
        "license_identifiers": identifiers,
        "name": name,
    }
    if version:
        value["version"] = version
    return value


def _spdx_id(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.")
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{prefix}-{cleaned[:50]}-{digest}"


def _package(
    spdx_id: str,
    name: str,
    version: str | None,
    download_location: str,
    license_declared: str = "NOASSERTION",
    **extra: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "SPDXID": spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": download_location,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_declared,
        "name": name,
        "supplier": "NOASSERTION",
    }
    if version:
        value["versionInfo"] = version
    value.update(extra)
    return value


def _artifact_license(canonical: str) -> str:
    return {
        "certifi": "MPL-2.0",
        "charset-normalizer": "MIT",
        "cpython": "PSF-2.0",
        "idna": "BSD-3-Clause",
        "pysocks": "BSD-3-Clause",
        "requests": "Apache-2.0",
        "urllib3": "MIT",
    }.get(canonical, "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only")


def build_spdx(
    artifact_lock: Mapping[str, object],
    runtime_inventory: Mapping[str, object],
    python_artifact_sbom: Mapping[str, object],
    qt_source_archives: Mapping[str, Mapping[str, str]],
    qt_attributions: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    packages: list[dict[str, object]] = []
    relationships: list[dict[str, object]] = []
    files: list[dict[str, object]] = []

    app_id = "SPDXRef-Package-SankakuSyncer"
    runtime_id = "SPDXRef-Package-Portable-Runtime"
    packages.append(
        _package(
            app_id,
            "SankakuSyncer",
            APP_VERSION,
            "https://github.com/aaAarJimedes/SankakuSyncer_Portable",
            "MIT",
        )
    )
    file_sha1s = sorted(str(entry["sha1"]) for entry in runtime_inventory["files"])
    verification_code = hashlib.sha1("".join(file_sha1s).encode("ascii")).hexdigest()
    packages.append(
        {
            "SPDXID": runtime_id,
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": "SankakuSyncer Portable Runtime",
            "packageVerificationCode": {"packageVerificationCodeValue": verification_code},
            "supplier": "NOASSERTION",
            "versionInfo": APP_VERSION,
        }
    )
    relationships.extend(
        [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": app_id,
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": runtime_id,
            },
            {
                "spdxElementId": app_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": runtime_id,
            },
        ]
    )

    artifact_ids: dict[str, str] = {}
    for artifact in artifact_lock["artifacts"]:
        canonical = str(artifact["canonical_name"])
        artifact_key = str(artifact["artifact_id"])
        spdx_id = _spdx_id("Artifact", artifact_key)
        artifact_ids[artifact_key] = spdx_id
        packages.append(
            _package(
                spdx_id,
                str(artifact["distribution"]),
                str(artifact["version"]),
                str(artifact["url"]),
                _artifact_license(canonical),
                checksums=[
                    {
                        "algorithm": "SHA256",
                        "checksumValue": str(artifact["sha256"]),
                    }
                ],
                comment=(
                    f"Exact {artifact['kind']} artifact: {artifact['filename']} "
                    f"({artifact['bytes']} bytes)."
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": spdx_id,
            }
        )

    for entry in runtime_inventory["files"]:
        relative = str(entry["path"])
        file_id = _spdx_id("File", relative)
        files.append(
            {
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": str(entry["sha1"])},
                    {"algorithm": "SHA256", "checksumValue": str(entry["sha256"])},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": "./Runtime/" + relative,
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )
        for artifact_key in entry["provenance_artifacts"]:
            relationships.append(
                {
                    "spdxElementId": file_id,
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": artifact_ids[str(artifact_key)],
                }
            )

    # Import only native components evidenced by selected lean Runtime files
    # from Python.org's exact embeddable-artifact SPDX document.
    upstream_packages = python_artifact_sbom.get("packages", [])
    if not isinstance(upstream_packages, list):
        raise RuntimeComplianceError("official CPython artifact SPDX has no packages")
    selected_python_components: set[str] = set()
    runtime_paths = {str(entry["path"]) for entry in runtime_inventory["files"]}
    for name, evidence_paths in CPYTHON_NATIVE_COMPONENTS.items():
        # The lean builder is allowed to omit optional stdlib/native modules.
        # A component enters the final SBOM only when at least one of its
        # concrete Runtime payload files is present.
        if not any(path in runtime_paths for path in evidence_paths):
            continue
        candidates = [
            package
            for package in upstream_packages
            if isinstance(package, dict) and str(package.get("name", "")).casefold() == name
        ]
        if name == "mpdecimal":
            candidates = [p for p in candidates if p.get("versionInfo") == "4.0.0"]
        if len(candidates) != 1:
            raise RuntimeComplianceError(
                f"official CPython artifact SPDX component mismatch: {name}"
            )
        upstream = candidates[0]
        package_id = _spdx_id("CPython-Native", name + "@" + str(upstream.get("versionInfo")))
        value = _package(
            package_id,
            str(upstream["name"]),
            str(upstream.get("versionInfo", "")) or None,
            str(upstream.get("downloadLocation", "NOASSERTION")),
            "NOASSERTION",
            comment=(
                "Component and source-artifact checksum are imported from the "
                "official CPython 3.13.15 Windows embeddable artifact SPDX."
            ),
        )
        if isinstance(upstream.get("checksums"), list):
            value["checksums"] = upstream["checksums"]
        if isinstance(upstream.get("externalRefs"), list):
            value["externalRefs"] = upstream["externalRefs"]
        packages.append(value)
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
        selected_python_components.add(name)

    qt_package_ids: dict[str, str] = {}
    for module, source in sorted(qt_source_archives.items()):
        package_id = _spdx_id("Qt-Module", module)
        qt_package_ids[module] = package_id
        packages.append(
            _package(
                package_id,
                module,
                QT_VERSION,
                str(source["archive_url"]),
                "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
                checksums=[
                    {"algorithm": "SHA256", "checksumValue": str(source["sha256"])}
                ],
                comment=(
                    "The checksum is the Qt Project-published exact 6.11.2 source "
                    "archive checksum used to anchor licensing provenance. Final "
                    "binary hashes are recorded on Runtime files and PySide wheels."
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )

    for filename in sorted(QT_NATIVE_ATTRIBUTIONS):
        attribution = qt_attributions.get(filename)
        if attribution is None:
            raise RuntimeComplianceError(f"required Qt native attribution missing: {filename}")
        component_version = str(attribution.get("version", "")) or None
        if filename == "qtwebengine-3rdparty-the-chromium-project.html":
            component_version = str(
                runtime_inventory["components"].get("chromium", "")
            ) or None
            if component_version is None:
                raise RuntimeComplianceError("Runtime Chromium version is unavailable")
        identity = filename + "@" + str(component_version or "NOASSERTION")
        package_id = _spdx_id("Qt-Native", identity)
        identifiers = attribution.get("license_identifiers", [])
        declared = identifiers[0] if isinstance(identifiers, list) and len(identifiers) == 1 else "NOASSERTION"
        comment = (
            f"Exact Qt 6.11.2 attribution: THIRD_PARTY_LICENSES/Qt-6.11.2/"
            f"attributions/{filename}."
        )
        if identifiers and declared == "NOASSERTION":
            comment += " Upstream page references: " + ", ".join(str(x) for x in identifiers) + "."
        packages.append(
            _package(
                package_id,
                str(attribution["name"]),
                component_version,
                "NOASSERTION",
                declared,
                comment=comment,
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )

    # VC runtime files are carried by different exact upstream artifacts and
    # can legitimately have two versions.  UCRT is a Windows system dependency,
    # not a redistributed Runtime file.
    vc_versions: dict[str, list[str]] = defaultdict(list)
    for entry in runtime_inventory["files"]:
        filename = PurePosixPath(str(entry["path"])).name.casefold()
        if filename.startswith(("vcruntime", "msvcp")) and filename.endswith(".dll"):
            version = str(entry.get("file_version", ""))
            if not version:
                raise RuntimeComplianceError(f"VC runtime version unavailable: {entry['path']}")
            vc_versions[version].append(str(entry["path"]))
    if not vc_versions:
        raise RuntimeComplianceError("VC runtime files are missing")
    for version, paths in sorted(vc_versions.items()):
        package_id = _spdx_id("VC-Runtime", version)
        packages.append(
            _package(
                package_id,
                "Microsoft Visual C++ Runtime",
                version,
                "NOASSERTION",
                "NOASSERTION",
                comment=(
                    "Runtime files: " + ", ".join(sorted(paths)) + ". "
                    "The frozen Microsoft license landing page and its official "
                    "OOXML terms are shipped under THIRD_PARTY_LICENSES/Microsoft/."
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    external_imports = [str(value).casefold() for value in runtime_inventory["external_pe_imports"]]
    if any(value.startswith("api-ms-win-crt-") for value in external_imports):
        ucrt_id = "SPDXRef-System-Microsoft-UCRT"
        packages.append(
            _package(
                ucrt_id,
                "Microsoft Universal C Runtime (system dependency)",
                None,
                "NOASSERTION",
                "NOASSERTION",
                comment=(
                    "Not redistributed in Runtime; provided by supported Windows. "
                    "Presence is inferred from actual PE imports."
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ucrt_id,
            }
        )
    for system_id, name, evidence in (
        (
            "SPDXRef-System-Microsoft-WinHTTP",
            "Microsoft Windows HTTP Services (system dependency)",
            {"winhttp.dll"},
        ),
        (
            "SPDXRef-System-Microsoft-Schannel",
            "Microsoft Schannel (system dependency)",
            {"secur32.dll", "crypt32.dll", "bcrypt.dll"},
        ),
    ):
        matched = sorted(evidence.intersection(external_imports))
        if not matched:
            continue
        packages.append(
            _package(
                system_id,
                name,
                None,
                "NOASSERTION",
                "NOASSERTION",
                comment=(
                    "Not redistributed in Runtime; provided by supported Windows. "
                    "Actual PE-import evidence: " + ", ".join(matched) + "."
                ),
            )
        )
        relationships.append(
            {
                "spdxElementId": runtime_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": system_id,
            }
        )

    fingerprint = sha256_bytes(
        json.dumps(
            {
                "artifacts": [artifact["sha256"] for artifact in artifact_lock["artifacts"]],
                "runtime": runtime_inventory["payload_sha256"],
                "qt": {name: value["sha256"] for name, value in qt_source_archives.items()},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )[:24]
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-08-29T00:00:00Z",
            "creators": ["Tool: SankakuSyncer Runtime Compliance Collector"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://github.com/aaAarJimedes/SankakuSyncer_Portable/"
            f"sbom/{APP_VERSION}/{fingerprint}"
        ),
        "files": sorted(files, key=lambda value: str(value["fileName"]).casefold()),
        "name": f"SankakuSyncer-{APP_VERSION}-Windows-x64-runtime",
        "packages": sorted(packages, key=lambda value: str(value["SPDXID"])),
        "relationships": sorted(
            relationships,
            key=lambda value: (
                str(value["spdxElementId"]),
                str(value["relationshipType"]),
                str(value["relatedSpdxElement"]),
            ),
        ),
        "spdxVersion": "SPDX-2.3",
    }
