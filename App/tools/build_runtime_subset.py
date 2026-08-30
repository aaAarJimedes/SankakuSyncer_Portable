# -*- coding: utf-8 -*-
"""Build and verify a lean, allowlisted Windows runtime for SankakuSyncer.

The source is treated as immutable.  The destination is populated from an
explicit Python/package/Qt seed list, then PE normal and delay imports are
followed recursively to collect native DLL dependencies.  Qt components which
are loaded dynamically (platform/image/TLS plugins, WebEngine resources and
the software OpenGL fallback) are explicit seeds.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePath
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DESTINATION = PROJECT_ROOT / "_runtime_subset_staging"
DEFAULT_APP = PROJECT_ROOT / "App"
TARGET_PYTHON_VERSION = (3, 13, 15)

DESTINATION_REQUIRED_MARKERS = ("subset", "lean", "staging", "build")
BUILD_SENTINEL_NAME = ".sankakusyncer-runtime-subset-builder"
BUILD_SENTINEL_BYTES = (
    b"SankakuSyncer runtime subset builder destination\n"
    b"schema-version: 1\n"
)
MANIFEST_NAME = "runtime_subset_manifest.sha256"
REPORT_NAME = "runtime_subset_report.json"
BUILD_METADATA_NAMES = frozenset(
    {BUILD_SENTINEL_NAME.casefold(), MANIFEST_NAME.casefold(), REPORT_NAME.casefold()}
)

BINARY_SUFFIXES = frozenset({".dll", ".exe", ".pyd"})
ROOT_SEEDS = (
    "python.exe",
    "pythonw.exe",
    "python3.dll",
    "qt6.conf",
)
STDLIB_EXCLUDED_TOP_LEVEL = frozenset(
    {
        "__pycache__",
        "ensurepip",
        "idlelib",
        "lib2to3",
        "msilib",
        "pydoc_data",
        "site-packages",
        "test",
        "tkinter",
        "turtledemo",
        "venv",
    }
)
SITE_PACKAGE_DIRECTORIES: tuple[str, ...] = ()
SITE_PACKAGE_FILES: tuple[str, ...] = ()
DIST_INFO_PREFIXES = (
    "pyside6-",
    "pyside6_addons-",
    "pyside6_essentials-",
    "shiboken6-",
)
PYSIDE_PYTHON_FILES = (
    "__init__.py",
    "_config.py",
    "_git_pyside_version.py",
)
PYSIDE_MODULES = (
    "QtCore",
    "QtGui",
    "QtNetwork",
    "QtPrintSupport",
    "QtWidgets",
    "QtWebChannel",
    "QtWebEngineCore",
    "QtWebEngineWidgets",
)
STDLIB_EXTENSION_MODULES = (
    "_asyncio.pyd",
    "_bz2.pyd",
    "_ctypes.pyd",
    "_decimal.pyd",
    "_elementtree.pyd",
    "_lzma.pyd",
    "_multiprocessing.pyd",
    "_overlapped.pyd",
    "_queue.pyd",
    "_socket.pyd",
    "_sqlite3.pyd",
    "_uuid.pyd",
    "_wmi.pyd",
    "_zoneinfo.pyd",
    "pyexpat.pyd",
    "select.pyd",
    "unicodedata.pyd",
)
QT_PLUGIN_RELATIVE_SEEDS = (
    "imageformats/qgif.dll",
    "imageformats/qico.dll",
    "imageformats/qjpeg.dll",
    "imageformats/qwebp.dll",
    "networkinformation/qnetworklistmanager.dll",
    "platforms/qminimal.dll",
    "platforms/qoffscreen.dll",
    "platforms/qwindows.dll",
    "styles/qmodernwindowsstyle.dll",
    "tls/qcertonlybackend.dll",
    "tls/qschannelbackend.dll",
)
QT_RESOURCE_FILES = (
    "icudtl.dat",
    "qtwebengine_devtools_resources.pak",
    "qtwebengine_resources.pak",
    "qtwebengine_resources_100p.pak",
    "qtwebengine_resources_200p.pak",
    "v8_context_snapshot.bin",
)
QT_WEBENGINE_LOCALES = ("en-US.pak", "zh-CN.pak", "zh-TW.pak")

FORBIDDEN_COMPONENTS = frozenset(
    {
        "__pycache__",
        "conda-meta",
        "include",
        "pip",
        "scripts",
        "setuptools",
        "wheel",
    }
)
FORBIDDEN_SUFFIXES = frozenset(
    {".a", ".c", ".cpp", ".exp", ".h", ".hpp", ".lib", ".pdb", ".pyc", ".pyo"}
)
FORBIDDEN_BINARY_PREFIXES = (
    "libcrypto-",
    "libclang",
    "libssl-",
    "mkl_",
    "omptarget",
)
FORBIDDEN_BINARY_NAMES = frozenset(
    {
        "aomenc.exe",
        "_hashlib.pyd",
        "_ssl.pyd",
        "designer.exe",
        "designer6.exe",
        "linguist.exe",
        "linguist6.exe",
        "lrelease.exe",
        "lupdate.exe",
        "qmake.exe",
        "qmake6.exe",
        "qopensslbackend.dll",
        "qsvg.dll",
        "qsvgicon.dll",
        "socks.py",
        "sockshandler.py",
        "shiboken6.exe",
        "x265.exe",
    }
)
FORBIDDEN_COMPONENT_PREFIXES = (
    "certifi-",
    "charset_normalizer-",
    "idna-",
    "pysocks-",
    "requests-",
    "urllib3-",
)
FORBIDDEN_COMPONENTS = FORBIDDEN_COMPONENTS | frozenset(
    {"certifi", "charset_normalizer", "idna", "requests", "urllib3"}
)
KNOWN_SYSTEM_DLLS = frozenset(
    {
        "advapi32.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "cfgmgr32.dll",
        "combase.dll",
        "comctl32.dll",
        "crypt32.dll",
        "d2d1.dll",
        "d3d11.dll",
        "d3d12.dll",
        "dcomp.dll",
        "dbghelp.dll",
        "dnsapi.dll",
        "dwmapi.dll",
        "dxgi.dll",
        "gdi32.dll",
        "gdi32full.dll",
        "imm32.dll",
        "iphlpapi.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "mpr.dll",
        "ncrypt.dll",
        "netapi32.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "powrprof.dll",
        "propsys.dll",
        "rpcrt4.dll",
        "secur32.dll",
        "setupapi.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "userenv.dll",
        "usp10.dll",
        "uxtheme.dll",
        "version.dll",
        "winhttp.dll",
        "wininet.dll",
        "winmm.dll",
        "wldap32.dll",
        "ws2_32.dll",
        "wtsapi32.dll",
    }
)


class RuntimeBuildError(RuntimeError):
    """The subset cannot be built or verified safely."""


@dataclass(frozen=True)
class VerificationResult:
    name: str
    returncode: int
    seconds: float
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PythonRuntimeLayout:
    """Version-dependent files in a full or embeddable CPython runtime."""

    version: str
    version_info: tuple[int, int]
    version_dll: str
    extension_root: str
    stdlib_zip: str | None = None
    pth_file: str | None = None

    @property
    def embedded(self) -> bool:
        return self.stdlib_zip is not None


@dataclass(frozen=True)
class QtRuntimeLayout:
    """Paths which differ between conda-style and official PySide6 wheels."""

    name: str
    binary_root: str
    plugin_root: str
    webengine_process: str
    resources_root: str
    locales_root: str
    qt_conf: str | None = None

    def plugin_seeds(self) -> tuple[str, ...]:
        return tuple(f"{self.plugin_root}/{name}" for name in QT_PLUGIN_RELATIVE_SEEDS)

    def dynamic_seeds(self) -> tuple[str, ...]:
        seeds = [
            *self.plugin_seeds(),
            self.webengine_process,
            f"{self.binary_root}/opengl32sw.dll",
        ]
        if self.qt_conf:
            seeds.append(self.qt_conf)
        return tuple(seeds)


PIP_QT_LAYOUT = QtRuntimeLayout(
    name="pyside6-wheel",
    binary_root="Lib/site-packages/PySide6",
    plugin_root="Lib/site-packages/PySide6/plugins",
    webengine_process="Lib/site-packages/PySide6/QtWebEngineProcess.exe",
    resources_root="Lib/site-packages/PySide6/resources",
    locales_root="Lib/site-packages/PySide6/translations/qtwebengine_locales",
)
CONDA_QT_LAYOUT = QtRuntimeLayout(
    name="conda-qt",
    binary_root="Library/bin",
    plugin_root="Library/lib/qt6/plugins",
    webengine_process="bin/QtWebEngineProcess.exe",
    resources_root="resources",
    locales_root="translations/qtwebengine_locales",
    qt_conf="Library/bin/qt6.conf",
)

# Kept as conda-layout aliases for callers which inspected the old constants.
# RuntimeSubsetBuilder records and uses the paths for the layout it actually
# detected, so these aliases do not control wheel-layout builds.
QT_PLUGIN_SEEDS = CONDA_QT_LAYOUT.plugin_seeds()
QT_DYNAMIC_SEEDS = (
    CONDA_QT_LAYOUT.webengine_process,
    f"{CONDA_QT_LAYOUT.binary_root}/opengl32sw.dll",
    CONDA_QT_LAYOUT.qt_conf,
)


def detect_python_layout(runtime: Path) -> PythonRuntimeLayout:
    """Discover one CPython ABI and validate its embedded-path contract."""
    matches = sorted(
        path
        for path in runtime.glob("python[0-9][0-9][0-9].dll")
        if path.stem[6:].isdigit()
    )
    if len(matches) != 1:
        raise RuntimeBuildError(
            "expected exactly one versioned CPython DLL, got "
            f"{[path.name for path in matches]}"
        )
    digits = matches[0].stem[6:]
    major, minor = int(digits[0]), int(digits[1:])
    if major != 3 or minor < 10:
        raise RuntimeBuildError(f"unsupported CPython ABI: {matches[0].name}")

    stdlib_zip = runtime / f"python{digits}.zip"
    pth_file = runtime / f"python{digits}._pth"
    is_embedded = stdlib_zip.exists() or pth_file.exists()
    if is_embedded:
        if not stdlib_zip.is_file() or not pth_file.is_file():
            raise RuntimeBuildError(
                "embeddable CPython requires both its standard-library zip and _pth file"
            )
        try:
            pth_lines = [
                line.strip().replace("\\", "/").casefold()
                for line in pth_file.read_text("utf-8-sig").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        except (OSError, UnicodeError) as exc:
            raise RuntimeBuildError(f"cannot read embedded path file: {pth_file.name}") from exc
        if "lib/site-packages" not in pth_lines or "import site" not in pth_lines:
            raise RuntimeBuildError(
                f"{pth_file.name} must enable Lib/site-packages and import site"
            )
        if f"python{digits}.zip" not in pth_lines:
            raise RuntimeBuildError(
                f"{pth_file.name} must include python{digits}.zip"
            )
        return PythonRuntimeLayout(
            version=f"{major}.{minor}",
            version_info=(major, minor),
            version_dll=matches[0].name,
            extension_root="",
            stdlib_zip=stdlib_zip.name,
            pth_file=pth_file.name,
        )

    if not (runtime / "DLLs").is_dir():
        raise RuntimeBuildError("full CPython runtime is missing its DLLs directory")
    return PythonRuntimeLayout(
        version=f"{major}.{minor}",
        version_info=(major, minor),
        version_dll=matches[0].name,
        extension_root="DLLs",
    )


def detect_qt_layout(runtime: Path) -> QtRuntimeLayout:
    """Select one coherent Qt layout and reject accidental mixed runtimes."""
    matches = [
        layout
        for layout in (PIP_QT_LAYOUT, CONDA_QT_LAYOUT)
        if (runtime / layout.plugin_root / "platforms" / "qwindows.dll").is_file()
        and (runtime / layout.webengine_process).is_file()
        and (runtime / layout.binary_root / "Qt6Core.dll").is_file()
    ]
    if len(matches) != 1:
        names = [layout.name for layout in matches]
        raise RuntimeBuildError(
            f"expected exactly one complete Qt runtime layout, got {names}"
        )
    return matches[0]


def _read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise RuntimeBuildError("truncated PE uint16")
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise RuntimeBuildError("truncated PE uint32")
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise RuntimeBuildError("truncated PE uint64")
    return struct.unpack_from("<Q", data, offset)[0]


def parse_pe_imports_bytes(data: bytes) -> set[str]:
    """Return normal and delay-import DLL names from one PE image."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return set()
    pe_offset = _read_u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return set()

    section_count = _read_u16(data, pe_offset + 6)
    optional_size = _read_u16(data, pe_offset + 20)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise RuntimeBuildError("truncated PE optional header")
    magic = _read_u16(data, optional_offset)
    if magic == 0x10B:
        directory_offset = optional_offset + 96
        image_base = _read_u32(data, optional_offset + 28)
    elif magic == 0x20B:
        directory_offset = optional_offset + 112
        image_base = _read_u64(data, optional_offset + 24)
    else:
        return set()

    section_offset = optional_offset + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        header = section_offset + index * 40
        if header + 40 > len(data):
            raise RuntimeBuildError("truncated PE section table")
        virtual_size = _read_u32(data, header + 8)
        virtual_address = _read_u32(data, header + 12)
        raw_size = _read_u32(data, header + 16)
        raw_offset = _read_u32(data, header + 20)
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    size_of_headers = _read_u32(data, optional_offset + 60)

    def rva_to_offset(rva: int) -> int | None:
        if 0 <= rva < min(size_of_headers, len(data)):
            return rva
        for virtual_address, virtual_size, raw_offset, raw_size in sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                result = raw_offset + (rva - virtual_address)
                return result if 0 <= result < len(data) else None
        return None

    def read_name(rva: int) -> str | None:
        offset = rva_to_offset(rva)
        if offset is None:
            return None
        end = data.find(b"\0", offset, min(len(data), offset + 1024))
        if end < 0:
            return None
        try:
            name = data[offset:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        if not name or Path(name).name != name:
            return None
        return name.casefold()

    imports: set[str] = set()
    if directory_offset + 14 * 8 <= optional_offset + optional_size:
        import_rva = _read_u32(data, directory_offset + 8)
        import_offset = rva_to_offset(import_rva) if import_rva else None
        if import_offset is not None:
            for index in range(4096):
                descriptor = import_offset + index * 20
                if descriptor + 20 > len(data):
                    break
                values = struct.unpack_from("<IIIII", data, descriptor)
                if not any(values):
                    break
                name = read_name(values[3])
                if name:
                    imports.add(name)

        delay_rva = _read_u32(data, directory_offset + 13 * 8)
        delay_offset = rva_to_offset(delay_rva) if delay_rva else None
        if delay_offset is not None:
            for index in range(4096):
                descriptor = delay_offset + index * 32
                if descriptor + 32 > len(data):
                    break
                values = struct.unpack_from("<IIIIIIII", data, descriptor)
                if not any(values):
                    break
                attributes, name_value = values[:2]
                name_rva = name_value if attributes & 1 else name_value - image_base
                name = read_name(name_rva)
                if name:
                    imports.add(name)
    return imports


def parse_pe_imports(path: Path) -> set[str]:
    try:
        return parse_pe_imports_bytes(path.read_bytes())
    except OSError as exc:
        raise RuntimeBuildError(f"cannot read PE image: {path}") from exc


def is_forbidden_relative(relative: PurePath) -> bool:
    parts = tuple(part.casefold() for part in relative.parts)
    if any(part in FORBIDDEN_COMPONENTS for part in parts[:-1]):
        return True
    if any(
        part.startswith(FORBIDDEN_COMPONENT_PREFIXES) for part in parts[:-1]
    ):
        return True
    name = parts[-1] if parts else ""
    if PurePath(name).suffix.casefold() in FORBIDDEN_SUFFIXES:
        return True
    if name in FORBIDDEN_BINARY_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in FORBIDDEN_BINARY_PREFIXES)


def validate_build_paths(source: Path, destination: Path) -> tuple[Path, Path]:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir() or not (source / "python.exe").is_file():
        raise RuntimeBuildError(f"source is not a Python runtime: {source}")
    if source == destination or source in destination.parents or destination in source.parents:
        raise RuntimeBuildError("source and destination must be disjoint")
    if destination.parent == destination or len(destination.parts) < 3:
        raise RuntimeBuildError("destination is too broad")
    destination_name = destination.name.casefold()
    if "runtime" not in destination_name or not any(
        marker in destination_name for marker in DESTINATION_REQUIRED_MARKERS
    ):
        raise RuntimeBuildError(
            "destination directory name must clearly identify a runtime "
            "subset/lean/staging/build directory"
        )
    return source, destination


def is_build_metadata_relative(relative: PurePath) -> bool:
    """Return whether *relative* names top-level builder-only metadata."""
    return len(relative.parts) == 1 and relative.name.casefold() in BUILD_METADATA_NAMES


def _has_exact_build_sentinel(destination: Path) -> bool:
    sentinel = destination / BUILD_SENTINEL_NAME
    try:
        return (
            not sentinel.is_symlink()
            and sentinel.is_file()
            and sentinel.read_bytes() == BUILD_SENTINEL_BYTES
        )
    except OSError:
        return False


def _candidate_rank(importer: Path, candidate: Path, source: Path) -> tuple[int, int, str]:
    relative = candidate.relative_to(source).as_posix().casefold()
    same_directory = 0 if candidate.parent == importer.parent else 1
    prefixes = (
        "library/bin/",
        "dlls/",
        "lib/site-packages/pyside6/",
        "lib/site-packages/shiboken6/",
        "bin/",
    )
    prefix_rank = next(
        (index for index, prefix in enumerate(prefixes) if relative.startswith(prefix)),
        len(prefixes),
    )
    return same_directory, prefix_rank, relative


def _pyside_module_binaries(package: Path, module: str) -> list[Path]:
    """Return the requested extension module without prefix siblings.

    ``QtNetwork*.pyd`` also selects ``QtNetworkAuth.pyd`` in the official
    wheel. ABI-tagged extension names remain supported by accepting a dot
    immediately after the requested module name.
    """

    return sorted(
        path
        for path in package.glob(f"{module}*.pyd")
        if path.name == f"{module}.pyd" or path.name.startswith(f"{module}.")
    )


def _is_system_import(name: str) -> bool:
    folded = name.casefold()
    if folded in KNOWN_SYSTEM_DLLS:
        return True
    if folded.startswith(("api-ms-win-", "ext-ms-win-")):
        return True
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return any((directory / name).is_file() for directory in (windows / "System32", windows))


class RuntimeSubsetBuilder:
    def __init__(self, source: Path, destination: Path) -> None:
        self.source, self.destination = validate_build_paths(source, destination)
        self.python_layout = detect_python_layout(self.source)
        self.qt_layout = detect_qt_layout(self.source)
        self._copied: dict[str, Path] = {}
        self._binary_queue: deque[Path] = deque()
        self._binary_seen: set[Path] = set()
        self._external_system_imports: set[str] = set()
        self._unresolved: dict[str, set[str]] = defaultdict(set)
        self._source_index: dict[str, list[Path]] | None = None

    def prepare(self, *, clean: bool) -> None:
        if self.destination.exists():
            if not self.destination.is_dir():
                raise RuntimeBuildError("destination exists but is not a directory")
            has_entries = next(self.destination.iterdir(), None) is not None
            if has_entries:
                if not clean:
                    raise RuntimeBuildError(
                        "destination is not empty; pass --clean only for a prior "
                        "builder-owned destination"
                    )
                if not _has_exact_build_sentinel(self.destination):
                    raise RuntimeBuildError(
                        "refusing to clean a non-empty destination without the exact "
                        "runtime subset builder sentinel"
                    )
                shutil.rmtree(self.destination)
        self.destination.mkdir(parents=True, exist_ok=True)
        (self.destination / BUILD_SENTINEL_NAME).write_bytes(BUILD_SENTINEL_BYTES)

    def _copy_file(self, source_file: Path) -> None:
        source_file = source_file.resolve()
        try:
            relative = source_file.relative_to(self.source)
        except ValueError as exc:
            raise RuntimeBuildError(f"copy source escaped runtime: {source_file}") from exc
        if is_forbidden_relative(relative):
            raise RuntimeBuildError(f"forbidden runtime file selected: {relative}")
        key = relative.as_posix().casefold()
        if key in self._copied:
            return
        target = self.destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)
        self._copied[key] = relative
        if source_file.suffix.casefold() in BINARY_SUFFIXES:
            self._binary_queue.append(source_file)

    def copy_relative(self, relative: str, *, required: bool = True) -> None:
        source_path = self.source / Path(relative)
        if not source_path.is_file():
            if required:
                raise RuntimeBuildError(f"required runtime file is missing: {relative}")
            return
        self._copy_file(source_path)

    def copy_tree(self, source_directory: Path) -> None:
        if not source_directory.is_dir():
            raise RuntimeBuildError(f"required runtime directory is missing: {source_directory}")
        for path in sorted(source_directory.rglob("*")):
            if path.is_file():
                relative = path.relative_to(self.source)
                if not is_forbidden_relative(relative):
                    self._copy_file(path)

    def copy_python_and_packages(self) -> None:
        for relative in ROOT_SEEDS:
            self.copy_relative(relative, required=relative != "qt6.conf")
        self.copy_relative(self.python_layout.version_dll)
        if self.python_layout.embedded:
            assert self.python_layout.stdlib_zip is not None
            assert self.python_layout.pth_file is not None
            self.copy_relative(self.python_layout.stdlib_zip)
            self.copy_relative(self.python_layout.pth_file)

        lib = self.source / "Lib"
        if not lib.is_dir():
            raise RuntimeBuildError("required runtime directory is missing: Lib")
        for item in sorted(lib.iterdir()):
            if item.name.casefold() in STDLIB_EXCLUDED_TOP_LEVEL:
                continue
            if item.is_file():
                relative = item.relative_to(self.source)
                if not is_forbidden_relative(relative):
                    self._copy_file(item)
            elif item.is_dir():
                self.copy_tree(item)

        site = lib / "site-packages"
        for name in SITE_PACKAGE_DIRECTORIES:
            self.copy_tree(site / name)
        for name in SITE_PACKAGE_FILES:
            self._copy_file(site / name)
        for item in sorted(site.iterdir()):
            if item.is_dir() and item.name.casefold().startswith(DIST_INFO_PREFIXES):
                self.copy_tree(item)

        pyside = site / "PySide6"
        for name in PYSIDE_PYTHON_FILES:
            self._copy_file(pyside / name)
        for module in PYSIDE_MODULES:
            matches = _pyside_module_binaries(pyside, module)
            if len(matches) != 1:
                raise RuntimeBuildError(f"expected one PySide6 {module} binary, got {matches}")
            self._copy_file(matches[0])

        shiboken = site / "shiboken6"
        for name in ("__init__.py", "_config.py", "_git_shiboken_module_version.py"):
            self._copy_file(shiboken / name)
        matches = sorted(shiboken.glob("Shiboken*.pyd"))
        if len(matches) != 1:
            raise RuntimeBuildError(f"expected one Shiboken binary, got {matches}")
        self._copy_file(matches[0])

        for name in STDLIB_EXTENSION_MODULES:
            relative = (
                f"{self.python_layout.extension_root}/{name}"
                if self.python_layout.extension_root
                else name
            )
            self.copy_relative(relative)

    def copy_qt_dynamic_seeds(self) -> None:
        for relative in self.qt_layout.dynamic_seeds():
            self.copy_relative(relative)
        for name in QT_RESOURCE_FILES:
            self.copy_relative(f"{self.qt_layout.resources_root}/{name}")
        for name in QT_WEBENGINE_LOCALES:
            self.copy_relative(f"{self.qt_layout.locales_root}/{name}")

    def _build_source_index(self) -> dict[str, list[Path]]:
        index: dict[str, list[Path]] = defaultdict(list)
        for path in self.source.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in BINARY_SUFFIXES:
                continue
            relative = path.relative_to(self.source)
            if not is_forbidden_relative(relative):
                index[path.name.casefold()].append(path)
        return index

    def collect_pe_dependencies(self) -> None:
        if self._source_index is None:
            self._source_index = self._build_source_index()
        while self._binary_queue:
            importer = self._binary_queue.popleft()
            if importer in self._binary_seen:
                continue
            self._binary_seen.add(importer)
            importer_relative = importer.relative_to(self.source).as_posix()
            for name in sorted(parse_pe_imports(importer)):
                candidates = self._source_index.get(name.casefold(), [])
                if candidates:
                    selected = min(
                        candidates,
                        key=lambda path: _candidate_rank(importer, path, self.source),
                    )
                    self._copy_file(selected)
                elif _is_system_import(name):
                    self._external_system_imports.add(name.casefold())
                else:
                    self._unresolved[importer_relative].add(name.casefold())

        if self._unresolved:
            details = "; ".join(
                f"{importer}: {', '.join(sorted(names))}"
                for importer, names in sorted(self._unresolved.items())
            )
            raise RuntimeBuildError(f"unresolved non-system PE imports: {details}")

    def forbidden_output(self) -> list[str]:
        return sorted(
            path.relative_to(self.destination).as_posix()
            for path in self.destination.rglob("*")
            if path.is_file() and is_forbidden_relative(path.relative_to(self.destination))
        )

    def write_manifest(self, verification: Sequence[VerificationResult]) -> dict[str, object]:
        files = sorted(
            path
            for path in self.destination.rglob("*")
            if path.is_file()
            and not is_build_metadata_relative(path.relative_to(self.destination))
        )
        digest_lines: list[str] = []
        total_bytes = 0
        for path in files:
            relative = path.relative_to(self.destination).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            digest_lines.append(f"{digest} *{relative}")
            total_bytes += path.stat().st_size
        (self.destination / MANIFEST_NAME).write_text(
            "\n".join(digest_lines) + "\n", encoding="utf-8", newline="\n"
        )
        report: dict[str, object] = {
            "schema_version": 3,
            "artifact_name": "SankakuSyncer_Runtime_Lean",
            "python": self.python_layout.version,
            "python_verification_target": ".".join(map(str, TARGET_PYTHON_VERSION)),
            "python_layout": "embedded" if self.python_layout.embedded else "full",
            "qt_layout": self.qt_layout.name,
            "file_count": len(files),
            "bytes": total_bytes,
            "mib": round(total_bytes / (1024 * 1024), 2),
            "pe_images_scanned": len(self._binary_seen),
            "external_system_imports": sorted(self._external_system_imports),
            "unresolved_imports": {
                importer: sorted(names) for importer, names in sorted(self._unresolved.items())
            },
            "forbidden_files": self.forbidden_output(),
            "dynamic_seeds": list(self.qt_layout.dynamic_seeds()),
            "verification": [
                {
                    "name": item.name,
                    "returncode": item.returncode,
                }
                for item in verification
            ],
        }
        (self.destination / REPORT_NAME).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return report


def _verification_environment(runtime: Path, app: Path, temp_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    windows = Path(environment.get("SystemRoot", r"C:\Windows"))
    qt_layout = detect_qt_layout(runtime)
    qt_binary_root = runtime / qt_layout.binary_root
    plugin_root = runtime / qt_layout.plugin_root
    path_entries = (
        runtime,
        runtime / "bin",
        runtime / "Library" / "bin",
        qt_binary_root,
        runtime / "Lib" / "site-packages" / "shiboken6",
        runtime / "DLLs",
        windows / "System32",
        windows,
        windows / "System32" / "Wbem",
    )
    environment.update(
        {
            "PATH": os.pathsep.join(str(path) for path in path_entries),
            "PYTHONHOME": str(runtime),
            "PYTHONPATH": str(app),
            "PYTHONDONTWRITEBYTECODE": "1",
            "QT_PLUGIN_PATH": str(plugin_root),
            "QT_QPA_PLATFORM_PLUGIN_PATH": str(plugin_root / "platforms"),
            "QTWEBENGINEPROCESS_PATH": str(runtime / qt_layout.webengine_process),
            "QTWEBENGINE_RESOURCES_PATH": str(runtime / qt_layout.resources_root),
            "QTWEBENGINE_LOCALES_PATH": str(runtime / qt_layout.locales_root),
            "QT_QPA_PLATFORM": "offscreen",
            "QT_SSL_BACKEND": "schannel",
            "QTWEBENGINE_DISABLE_SANDBOX": "1",
            "QTWEBENGINE_CHROMIUM_FLAGS": (
                "--disable-gpu --host-resolver-rules=MAP * ~NOTFOUND,EXCLUDE localhost"
            ),
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
        }
    )
    for name in ("CONDA_PREFIX", "CONDA_DEFAULT_ENV", "VIRTUAL_ENV", "PYTHONSTARTUP"):
        environment.pop(name, None)
    return environment


def _run_verification_step(
    name: str,
    command: Sequence[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: int = 180,
) -> VerificationResult:
    started = time.monotonic()
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return VerificationResult(
        name=name,
        returncode=completed.returncode,
        seconds=round(time.monotonic() - started, 3),
        stdout=completed.stdout[-20000:],
        stderr=completed.stderr[-20000:],
    )


_OFFLINE_MAINWINDOW_SMOKE_CODE = "\n".join(
    (
        "import os, sys",
        "sys.path.insert(0, os.environ['SANKAKU_VERIFY_APP'])",
        "from PySide6.QtCore import QCoreApplication, Qt",
        "QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)",
        "from PySide6.QtWidgets import QApplication",
        "import ui_main_window",
        "app = QApplication([])",
        "root = os.environ['SANKAKU_VERIFY_ROOT']",
        "window = ui_main_window.MainWindow(root)",
        "expected = ui_main_window.MAIN_TAB_TITLES",
        "actual = tuple(window.tabs.tabText(index) for index in range(window.tabs.count()))",
        "if actual != expected:",
        "    raise RuntimeError(f'tab contract mismatch: expected={expected!r}, actual={actual!r}')",
        "window.close()",
        "window.deleteLater()",
        "app.processEvents()",
        "print('mainwindow-ok')",
    )
)


def _format_verification_failures(
    results: Sequence[VerificationResult],
) -> str:
    failed = tuple(result for result in results if result.returncode)
    if not failed:
        return ""
    lines = [f"verification failed: {', '.join(item.name for item in failed)}"]
    for item in failed:
        lines.append(f"[{item.name}] exit code {item.returncode}")
        stdout = item.stdout.rstrip()
        stderr = item.stderr.rstrip()
        if stdout:
            lines.extend(("stdout:", stdout))
        if stderr:
            lines.extend(("stderr:", stderr))
    return "\n".join(lines)


def verify_runtime(runtime: Path, app: Path) -> list[VerificationResult]:
    python = runtime / "python.exe"
    if not python.is_file():
        raise RuntimeBuildError(f"staging Python is missing: {python}")
    python_layout = detect_python_layout(runtime)
    if python_layout.version_info != TARGET_PYTHON_VERSION[:2]:
        raise RuntimeBuildError(
            "verification requires CPython "
            f"{TARGET_PYTHON_VERSION[0]}.{TARGET_PYTHON_VERSION[1]}"
        )
    results: list[VerificationResult] = []
    steps: tuple[tuple[str, Sequence[str], dict[str, str]], ...] = (
        (
            "python_hashlib_winhttp",
            (
                str(python),
                "-B",
                "-c",
                "import hashlib,os,sys; "
                "sys.path.insert(0, os.environ['SANKAKU_VERIFY_APP']); "
                "import http_transport; "
                f"assert sys.version_info[:3] == {TARGET_PYTHON_VERSION!r}; "
                "assert '_ssl' not in sys.modules and '_hashlib' not in sys.modules; "
                "assert type(hashlib.sha256()).__module__ == '_sha2'; "
                "assert hashlib.sha256(b'abc').hexdigest() == "
                "'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'; "
                "assert hashlib.md5(b'abc', usedforsecurity=False).hexdigest() == "
                "'900150983cd24fb0d6963f7d28e17f72'; "
                "http_transport._WinHttpBindings(); print(sys.version.split()[0], 'winhttp', 'builtin-hashlib')",
            ),
            {"SANKAKU_VERIFY_APP": str(app)},
        ),
        (
            "qtwidgets_qtwebengine_import",
            (
                str(python),
                "-B",
                "-c",
                "from PySide6.QtCore import qVersion; "
                "from PySide6.QtNetwork import QSslSocket; "
                "assert QSslSocket.setActiveBackend('schannel'); "
                "assert QSslSocket.activeBackend().casefold() == 'schannel'; "
                "from PySide6.QtWidgets import QApplication,QMainWindow; "
                "from PySide6.QtWebEngineCore import QWebEnginePage,QWebEngineProfile; "
                "from PySide6.QtWebEngineWidgets import QWebEngineView; "
                "print(qVersion(), QApplication, QWebEngineView)",
            ),
            {"SANKAKU_DISABLE_WEBENGINE": "0"},
        ),
        (
            "offline_mainwindow_construction",
            (
                str(python),
                "-B",
                "-c",
                _OFFLINE_MAINWINDOW_SMOKE_CODE,
            ),
            {
                "SANKAKU_DISABLE_WEBENGINE": "1",
                "SANKAKU_VERIFY_APP": str(app),
            },
        ),
        (
            "offline_regression_suite",
            (
                str(python),
                "-B",
                "-c",
                "import os,runpy,sys; p=os.environ['SANKAKU_VERIFY_APP']; "
                "sys.path.insert(0,p); "
                "runpy.run_path(os.path.join(p,'run_tests.py'),run_name='__main__')",
            ),
            {
                "SANKAKU_DISABLE_WEBENGINE": "1",
                "SANKAKU_VERIFY_APP": str(app),
            },
        ),
    )
    with tempfile.TemporaryDirectory(prefix="sankaku-runtime-verify-") as temporary:
        temp_root = Path(temporary)
        environment = _verification_environment(runtime, app, temp_root)
        for name, command, overrides in steps:
            step_environment = dict(environment)
            step_environment.update(overrides)
            if name == "offline_mainwindow_construction":
                step_environment["SANKAKU_VERIFY_ROOT"] = str(
                    temp_root / "portable_root"
                )
            results.append(
                _run_verification_step(
                    name,
                    command,
                    environment=step_environment,
                    cwd=app,
                )
            )
    return results


def build_runtime(
    source: Path,
    destination: Path,
    app: Path,
    *,
    clean: bool,
    verify: bool,
) -> tuple[dict[str, object], list[VerificationResult]]:
    builder = RuntimeSubsetBuilder(source, destination)
    builder.prepare(clean=clean)
    builder.copy_python_and_packages()
    builder.copy_qt_dynamic_seeds()
    builder.collect_pe_dependencies()
    forbidden = builder.forbidden_output()
    if forbidden:
        raise RuntimeBuildError(f"forbidden files reached output: {forbidden}")
    verification = verify_runtime(builder.destination, app.resolve()) if verify else []
    report = builder.write_manifest(verification)
    failure_message = _format_verification_failures(verification)
    if failure_message:
        raise RuntimeBuildError(failure_message)
    return report, verification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="audited source Python Runtime directory (required)",
    )
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    parser.add_argument(
        "--clean",
        action="store_true",
        help="replace the exact destination after safety validation",
    )
    parser.add_argument("--no-verify", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report, verification = build_runtime(
            args.source,
            args.destination,
            args.app,
            clean=args.clean,
            verify=not args.no_verify,
        )
    except (OSError, RuntimeBuildError, subprocess.TimeoutExpired) as exc:
        print(f"runtime subset build failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "artifact": report["artifact_name"],
                "files": report["file_count"],
                "mib": report["mib"],
                "pe_images_scanned": report["pe_images_scanned"],
                "verification": {
                    item.name: item.returncode for item in verification
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
