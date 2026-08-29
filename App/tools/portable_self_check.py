# -*- coding: utf-8 -*-
"""Offline checks for a relocatable SankakuSyncer directory.

The default mode is intended for an installed, user-owned portable directory
and therefore probes whether ``Data`` and ``Downloads`` are writable. The
``--release`` mode is a strictly read-only packaging gate: it never creates a
directory, temporary file, QApplication, or browser profile.
"""

from __future__ import annotations

import argparse
import importlib
from importlib import metadata, util
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import tempfile
from typing import Iterable

# Dynamic imports performed by this verifier must not create __pycache__ in a
# clean staging directory. Explicit compileall invocations are intentionally
# unaffected and are rejected by the release-tree scan below.
sys.dont_write_bytecode = True

try:
    from . import collect_third_party_licenses as license_bundle
except ImportError:  # Direct execution from App/tools in a portable release.
    tools_directory = str(Path(__file__).resolve().parent)
    if tools_directory not in sys.path:
        sys.path.insert(0, tools_directory)
    import collect_third_party_licenses as license_bundle


APP_DIR = Path(__file__).resolve().parents[1]
ROOT = APP_DIR.parent
RUNTIME = ROOT / "Runtime"
PORTABLE_RELATIVE_PATH_LIMIT = (
    license_bundle.runtime_compliance.PORTABLE_RELATIVE_PATH_LIMIT
)

_LOCK_LINE_RE = re.compile(r"([A-Za-z0-9_.-]+)==([^\s;]+)")
_WINDOWS_ABSOLUTE_RE = re.compile(
    r"(?i)(?:\b[A-Z]:[\\/]|\\\\[^\\/\r\n]+[\\/][^\\/\r\n]+)"
)
_CACHE_DIRECTORY_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    "cache",
    "code cache",
    "gpucache",
    "dawncache",
}
_VCS_DIRECTORY_NAMES = {".git", ".hg", ".svn"}
_PRIVATE_FILE_NAMES = {
    ".sankakusyncer-runtime-subset-builder",
    ".credentials",
    ".coverage",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "cookies",
    "credentials.json",
    "history",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "settings.json",
    "tasks.json",
    "token.json",
}
_PRIVATE_TEMP_PREFIXES = (
    ".credentials.",
    ".env",
    ".metadata.",
    ".portable-probe-",
    ".settings.",
    ".tasks.",
)
_EXPECTED_PYTHON = (3, 13, 15)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _is_link_like(path: Path) -> bool:
    """Treat Windows junctions like symlinks for release-boundary checks."""
    try:
        return path.is_symlink() or path.is_junction()
    except (AttributeError, OSError):
        return path.is_symlink()


def _display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _check_portable_relative_path(path: Path, root: Path, failures: list[str]) -> bool:
    """Reject paths that leave too little headroom for default Windows clones."""
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        failures.append(f"release path escapes root: {path}")
        return False
    if len(relative) > PORTABLE_RELATIVE_PATH_LIMIT:
        failures.append(
            "portable relative path is too long: "
            f"{len(relative)} > {PORTABLE_RELATIVE_PATH_LIMIT}: {relative}"
        )
        return False
    return True


def _canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def read_locked_requirements(path: Path) -> dict[str, tuple[str, str]]:
    """Read the deliberately simple, exactly-pinned portable lock file."""
    locked: dict[str, tuple[str, str]] = {}
    for line_number, raw_line in enumerate(path.read_text("utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_LINE_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"unsupported lock line {line_number}")
        display_name, version = match.groups()
        canonical = _canonical_distribution_name(display_name)
        if canonical in locked:
            raise ValueError(f"duplicate locked distribution: {display_name}")
        locked[canonical] = (display_name, version)
    if not locked:
        raise ValueError("dependency lock is empty")
    return locked


def _check_required_files(
    root: Path, runtime: Path, *, release: bool, failures: list[str]
) -> None:
    required = [
        root / "run.bat",
        root / "run_debug.bat",
        root / "run_tests.bat",
        root / "run_silent.vbs",
        root / "verify_portable.bat",
        root / "README.md",
        root / "CHANGELOG.md",
        root / "SECURITY.md",
        root / "LICENSE",
        root / "App" / "main.py",
        root / "App" / "http_transport.py",
        root / "App" / "runtime_environment.py",
        root / "App" / "requirements.lock.txt",
        root / "App" / "tools" / "build_manifest.py",
        runtime / "python.exe",
        runtime / "pythonw.exe",
    ]
    if release:
        required.extend(
            [
                root / "PORTABLE_BUILD.md",
                root / "THIRD_PARTY_NOTICES.md",
                root / "SBOM.spdx.json",
                root / "RUNTIME_INVENTORY.json",
                root / "VEX.openvex.json",
                root / "THIRD_PARTY_LICENSES" / "SOURCES.json",
                root / "App" / "tools" / "collect_third_party_licenses.py",
                root / "App" / "tools" / "runtime_compliance.py",
                root / "App" / "tools" / "probe_webengine_codecs.py",
                root / "App" / "runtime_artifacts.lock.json",
                runtime / "runtime_subset_manifest.sha256",
                runtime / "runtime_subset_report.json",
            ]
        )
    for path in required:
        if not path.is_file():
            failures.append(f"missing: {_display(path, root)}")


def _check_python_runtime(runtime: Path, failures: list[str]) -> None:
    if sys.version_info[:3] != _EXPECTED_PYTHON:
        failures.append(
            f"Python version mismatch: expected {'.'.join(map(str, _EXPECTED_PYTHON))}, got "
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
    if struct.calcsize("P") * 8 != 64:
        failures.append("Python architecture mismatch: expected 64-bit")
    machine = platform.machine().casefold()
    if machine and machine not in {"amd64", "x86_64"}:
        failures.append(f"machine architecture mismatch: expected x64, got {machine}")
    if not _within(Path(sys.executable), runtime):
        failures.append("self-check interpreter is outside Runtime")

    abi = f"{_EXPECTED_PYTHON[0]}{_EXPECTED_PYTHON[1]:02d}"
    version_dll = runtime / f"python{abi}.dll"
    stdlib_zip = runtime / f"python{abi}.zip"
    pth_file = runtime / f"python{abi}._pth"
    for path in (version_dll, stdlib_zip, pth_file):
        if not path.is_file():
            failures.append(f"embedded Python file missing: {path.name}")
    if pth_file.is_file():
        try:
            lines = [
                line.strip().replace("\\", "/").casefold()
                for line in pth_file.read_text("utf-8-sig").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        except (OSError, UnicodeError) as exc:
            failures.append(f"embedded Python path file unreadable ({type(exc).__name__})")
        else:
            for required in (f"python{abi}.zip", "lib/site-packages", "import site"):
                if required not in lines:
                    failures.append(f"embedded Python path missing: {required}")


def _check_locked_dependencies(
    lock_file: Path, runtime: Path, failures: list[str]
) -> None:
    try:
        locked = read_locked_requirements(lock_file)
    except (OSError, UnicodeError, ValueError) as exc:
        failures.append(f"dependency lock unreadable ({type(exc).__name__})")
        return

    component_fallbacks = {"pyside6-addons", "pyside6-essentials"}
    components_without_metadata: list[tuple[str, str]] = []
    for canonical, (name, expected) in sorted(locked.items()):
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            # Conda-style PySide6 runtimes may merge Addons/Essentials into the
            # main PySide6 distribution and omit their separate wheel metadata.
            # Their actual modules/files are checked below and by WebEngine's
            # component check, so missing metadata alone is not a failure.
            if canonical in component_fallbacks:
                components_without_metadata.append((name, expected))
                continue
            failures.append(f"locked distribution missing: {name}=={expected}")
            continue
        # Some wheel metadata writers leave harmless surrounding whitespace in
        # the Version header; compare the semantic field, not that formatting.
        actual = distribution.version.strip()
        if actual != expected:
            failures.append(
                f"locked distribution mismatch: {name} expected {expected}, got {actual}"
            )
        try:
            distribution_root = Path(distribution.locate_file("")).resolve()
        except (OSError, TypeError, ValueError):
            failures.append(f"distribution location unavailable: {name}")
            continue
        if not _within(distribution_root, runtime):
            failures.append(f"distribution outside Runtime: {name}")

    if components_without_metadata:
        try:
            pyside_module = importlib.import_module("PySide6")
            pyside_version = str(getattr(pyside_module, "__version__", "")).strip()
            pyside_file = Path(getattr(pyside_module, "__file__", ""))
        except Exception as exc:
            failures.append(
                f"merged PySide6 component validation failed ({type(exc).__name__})"
            )
        else:
            if not pyside_version:
                failures.append("PySide6.__version__ is unavailable for merged components")
            if not _within(pyside_file, runtime):
                failures.append("merged PySide6 components are outside Runtime")
            for name, expected in components_without_metadata:
                if pyside_version != expected:
                    failures.append(
                        f"merged component mismatch: {name} expected {expected}, "
                        f"PySide6 is {pyside_version or 'unknown'}"
                    )

    modules = [
        "PySide6",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
    ]
    for name in modules:
        try:
            module = importlib.import_module(name)
            module_file = getattr(module, "__file__", None)
            if not module_file or not _within(Path(module_file), runtime):
                failures.append(f"module outside Runtime: {name}")
        except Exception as exc:
            failures.append(f"module import failed: {name} ({type(exc).__name__})")


def _check_native_transport(app_dir: Path, runtime: Path, failures: list[str]) -> None:
    """Reject the removed Python/OpenSSL stack and exercise safe constructors."""

    forbidden_names = {
        "_hashlib.pyd",
        "_ssl.pyd",
        "libcrypto-3.dll",
        "libcrypto-3-x64.dll",
        "libssl-3.dll",
        "libssl-3-x64.dll",
        "qopensslbackend.dll",
        "socks.py",
        "sockshandler.py",
    }
    forbidden_directories = {
        "certifi",
        "charset_normalizer",
        "idna",
        "requests",
        "urllib3",
    }
    try:
        for path in runtime.rglob("*"):
            folded = path.name.casefold()
            if path.is_file() and (
                folded in forbidden_names
                or folded.startswith(("libcrypto-", "libssl-"))
            ):
                failures.append(f"forbidden removed TLS file present: {_display(path, runtime)}")
            elif path.is_dir() and (
                folded in forbidden_directories
                or folded.startswith(
                    (
                        "certifi-",
                        "charset_normalizer-",
                        "idna-",
                        "pysocks-",
                        "requests-",
                        "urllib3-",
                    )
                )
            ):
                failures.append(
                    f"forbidden removed HTTP package present: {_display(path, runtime)}"
                )
    except OSError as exc:
        failures.append(f"removed TLS stack scan failed ({type(exc).__name__})")

    try:
        import hashlib

        if util.find_spec("_ssl") is not None or util.find_spec("_hashlib") is not None:
            failures.append("Python OpenSSL extension remains importable")
        if type(hashlib.sha256()).__module__ != "_sha2":
            failures.append("hashlib SHA-256 is not using the CPython builtin fallback")
        if hashlib.sha256(b"abc").hexdigest() != (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ):
            failures.append("hashlib SHA-256 self-test failed")
        if hashlib.md5(b"abc", usedforsecurity=False).hexdigest() != (
            "900150983cd24fb0d6963f7d28e17f72"
        ):
            failures.append("hashlib MD5 compatibility self-test failed")
    except Exception as exc:
        failures.append(f"builtin hashlib validation failed ({type(exc).__name__})")

    try:
        module = importlib.import_module("http_transport")
        module_file = Path(getattr(module, "__file__", ""))
        if not _within(module_file, app_dir):
            failures.append("WinHTTP transport module is outside App")
        module._WinHttpBindings()
    except Exception as exc:
        failures.append(f"WinHTTP binding construction failed ({type(exc).__name__})")


def _find_first_file(candidates: Iterable[Path]) -> Path | None:
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _find_first_directory(candidates: Iterable[Path]) -> Path | None:
    return next((candidate for candidate in candidates if candidate.is_dir()), None)


def _check_qt_webengine(runtime: Path, failures: list[str]) -> None:
    try:
        spec = util.find_spec("PySide6")
        locations = list(spec.submodule_search_locations or ()) if spec else []
        pyside_dir = Path(locations[0]).resolve() if locations else None
    except (ImportError, OSError, TypeError, ValueError):
        pyside_dir = None
    if pyside_dir is None or not _within(pyside_dir, runtime):
        failures.append("PySide6 package directory is unavailable or outside Runtime")
        return

    helper = _find_first_file(
        [
            pyside_dir / "QtWebEngineProcess.exe",
            runtime / "bin" / "QtWebEngineProcess.exe",
            runtime / "Library" / "bin" / "QtWebEngineProcess.exe",
        ]
    )
    if helper is None:
        failures.append("Qt WebEngine helper missing: QtWebEngineProcess.exe")

    plugin_root = _find_first_directory(
        [pyside_dir / "plugins", runtime / "Library" / "lib" / "qt6" / "plugins"]
    )
    if plugin_root is None:
        failures.append("Qt plugin directory missing")
    else:
        for relative in (
            "platforms/qwindows.dll",
            "imageformats/qgif.dll",
            "imageformats/qico.dll",
            "imageformats/qjpeg.dll",
            "imageformats/qwebp.dll",
            "tls/qschannelbackend.dll",
        ):
            if not (plugin_root / relative).is_file():
                failures.append(f"Qt runtime plugin missing: {relative}")
        for relative in ("imageformats/qsvg.dll", "iconengines/qsvgicon.dll"):
            if (plugin_root / relative).exists():
                failures.append(f"forbidden SVG plugin present: {relative}")
        if (plugin_root / "tls" / "qopensslbackend.dll").exists():
            failures.append("forbidden Qt OpenSSL TLS plugin present")

        try:
            from PySide6.QtNetwork import QSslSocket

            if "schannel" not in {
                str(name).casefold() for name in QSslSocket.availableBackends()
            }:
                failures.append("Qt Schannel TLS backend is unavailable")
            else:
                QSslSocket.setActiveBackend("schannel")
                if str(QSslSocket.activeBackend()).casefold() != "schannel":
                    failures.append("Qt active TLS backend is not Schannel")
        except Exception as exc:
            failures.append(f"Qt Schannel activation failed ({type(exc).__name__})")

    resources = _find_first_directory(
        [pyside_dir / "resources", runtime / "resources"]
    )
    if resources is None:
        failures.append("Qt WebEngine resources directory missing")
    else:
        for filename in ("qtwebengine_resources.pak", "icudtl.dat"):
            if not (resources / filename).is_file():
                failures.append(f"Qt WebEngine resource missing: {filename}")

    locales = _find_first_directory(
        [
            pyside_dir / "translations" / "qtwebengine_locales",
            runtime / "translations" / "qtwebengine_locales",
        ]
    )
    if locales is None:
        failures.append("Qt WebEngine locales directory missing")
    elif not any(locales.glob("*.pak")):
        failures.append("Qt WebEngine locale packs missing")

    environment_paths = {
        "QT_PLUGIN_PATH": "directory-list",
        "QT_QPA_PLATFORM_PLUGIN_PATH": "directory",
        "QTWEBENGINEPROCESS_PATH": "file",
        "QTWEBENGINE_RESOURCES_PATH": "directory",
        "QTWEBENGINE_LOCALES_PATH": "directory",
    }
    for variable, kind in environment_paths.items():
        raw_value = os.environ.get(variable, "").strip()
        if not raw_value:
            continue
        values = raw_value.split(os.pathsep) if kind == "directory-list" else [raw_value]
        for value in values:
            path = Path(value.strip().strip('"'))
            exists = path.is_file() if kind == "file" else path.is_dir()
            if not exists:
                failures.append(f"{variable} points to a missing path")
            elif not _within(path, runtime):
                failures.append(f"{variable} points outside Runtime")


def _check_embedded_paths(root: Path, runtime: Path, failures: list[str]) -> None:
    launchers = (
        "run.bat",
        "run_debug.bat",
        "run_tests.bat",
        "verify_portable.bat",
        "dev_console.bat",
        "run_silent.vbs",
    )
    for launcher in launchers:
        path = root / launcher
        if not path.is_file():
            continue
        try:
            text = path.read_text("utf-8", errors="ignore")
        except OSError as exc:
            failures.append(f"launcher unreadable: {launcher} ({type(exc).__name__})")
            continue
        if _WINDOWS_ABSOLUTE_RE.search(text):
            failures.append(f"absolute build path embedded: {launcher}")

    config_files: list[Path] = []
    pyvenv = runtime / "pyvenv.cfg"
    if pyvenv.is_file():
        config_files.append(pyvenv)
    if runtime.is_dir():
        try:
            config_files.extend(runtime.rglob("*.pth"))
            config_files.extend(runtime.glob("python*._pth"))
        except OSError as exc:
            failures.append(f"Runtime path scan failed ({type(exc).__name__})")
    for path in config_files:
        try:
            text = path.read_text("utf-8", errors="ignore")
        except OSError as exc:
            failures.append(
                f"Runtime config unreadable: {_display(path, root)} ({type(exc).__name__})"
            )
            continue
        if _WINDOWS_ABSOLUTE_RE.search(text):
            failures.append(f"absolute path in Runtime config: {_display(path, root)}")


def _check_release_tree(root: Path, runtime: Path, failures: list[str]) -> None:
    """Read-only rejection scan for private and generated release content."""
    for private_name in ("Data", "Downloads"):
        directory = root / private_name
        if not directory.exists():
            continue
        if not directory.is_dir():
            failures.append(f"private path is not a directory: {private_name}")
            continue
        try:
            first_entry = next(directory.iterdir(), None)
        except OSError as exc:
            failures.append(f"private directory unreadable: {private_name} ({type(exc).__name__})")
            continue
        if first_entry is not None:
            failures.append(f"private directory is not empty: {private_name}")

    try:
        walker = os.walk(root, topdown=True, followlinks=False)
        for directory_text, directory_names, file_names in walker:
            directory = Path(directory_text)
            relative_directory = directory.relative_to(root)
            kept_directories: list[str] = []
            for name in directory_names:
                path = directory / name
                lowered = name.casefold()
                top_level_private = not relative_directory.parts and lowered in {
                    "data",
                    "downloads",
                }
                if _is_link_like(path):
                    failures.append(f"symbolic link is not allowed: {_display(path, root)}")
                    continue
                if not _check_portable_relative_path(path, root, failures):
                    continue
                if top_level_private:
                    continue
                if lowered in _CACHE_DIRECTORY_NAMES:
                    failures.append(f"cache directory present: {_display(path, root)}")
                    continue
                if lowered in _VCS_DIRECTORY_NAMES:
                    failures.append(f"VCS metadata present: {_display(path, root)}")
                    continue
                if lowered.startswith("."):
                    failures.append(f"hidden directory present: {_display(path, root)}")
                    continue
                kept_directories.append(name)
            directory_names[:] = kept_directories

            for name in file_names:
                path = directory / name
                lowered = name.casefold()
                allowed_root_dotfile = not relative_directory.parts and lowered in {
                    ".gitattributes",
                    ".gitignore",
                }
                if _is_link_like(path):
                    failures.append(f"symbolic link is not allowed: {_display(path, root)}")
                    continue
                if not _check_portable_relative_path(path, root, failures):
                    continue
                if lowered in _PRIVATE_FILE_NAMES:
                    failures.append(f"private file present: {_display(path, root)}")
                elif lowered.startswith(".") and not allowed_root_dotfile:
                    failures.append(f"hidden file present: {_display(path, root)}")
                elif lowered.endswith((".key", ".kdbx", ".p12", ".pem", ".pfx")):
                    failures.append(f"private key/container present: {_display(path, root)}")
                elif lowered.endswith((".part", ".log", ".tmp")):
                    failures.append(f"generated file present: {_display(path, root)}")
                elif lowered.endswith((".pyc", ".pyo")):
                    failures.append(f"generated file present: {_display(path, root)}")
                elif lowered.startswith(_PRIVATE_TEMP_PREFIXES):
                    failures.append(f"private temporary file present: {_display(path, root)}")
    except OSError as exc:
        failures.append(f"release tree scan failed ({type(exc).__name__})")


def _check_compliance_materials(
    root: Path, runtime: Path, failures: list[str]
) -> None:
    """Verify the complete pinned license bundle and deterministic SPDX offline."""
    try:
        bundle_failures = license_bundle.verify_bundle(
            root / "THIRD_PARTY_LICENSES",
            root / "SBOM.spdx.json",
            root / "App" / "requirements.lock.txt",
            runtime=runtime,
            artifact_lock_path=root / "App" / "runtime_artifacts.lock.json",
            inventory_path=root / "RUNTIME_INVENTORY.json",
            vex_path=root / "VEX.openvex.json",
            full_schema_validation=False,
        )
    except Exception as exc:
        failures.append(
            f"license/SBOM verification failed ({type(exc).__name__})"
        )
        return
    failures.extend(
        f"license/SBOM bundle: {failure}" for failure in bundle_failures
    )


def _check_writable_user_directories(root: Path, failures: list[str]) -> None:
    for directory_name in ("Data", "Downloads"):
        directory = root / directory_name
        descriptor: int | None = None
        probe: str | None = None
        try:
            directory.mkdir(parents=True, exist_ok=True)
            descriptor, probe = tempfile.mkstemp(prefix=".portable-probe-", dir=directory)
            os.close(descriptor)
            descriptor = None
            os.remove(probe)
            probe = None
        except OSError as exc:
            failures.append(f"not writable: {directory_name} ({type(exc).__name__})")
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if probe is not None:
                try:
                    os.remove(probe)
                except OSError:
                    pass


_GUI_SMOKE_CODE = r"""
import os
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.environ["SANKAKU_APP_DIR"])
from PySide6.QtCore import QCoreApplication, Qt
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
from PySide6.QtWidgets import QApplication
import ui_main_window
ui_main_window.BrowserTab = None
ui_main_window.MainWindow._start_search = lambda self, reset: None
application = QApplication(["portable-self-check", "-platform", "offscreen"])
window = ui_main_window.MainWindow(sys.argv[1])
actual_tab_titles = tuple(
    window.tabs.tabText(index) for index in range(window.tabs.count())
)
if actual_tab_titles != ui_main_window.MAIN_TAB_TITLES:
    raise RuntimeError("main window tab contract failed")
window.close()
window.deleteLater()
application.processEvents()
application.quit()
"""


def _offline_gui_smoke(
    app_dir: Path, runtime: Path, failures: list[str]
) -> None:
    """Construct the main window offline in a bounded child process."""
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(app_dir),
            "SANKAKU_APP_DIR": str(app_dir),
            "QT_QPA_PLATFORM": "offscreen",
            "QTWEBENGINE_DISABLE_SANDBOX": "1",
            "QTWEBENGINE_CHROMIUM_FLAGS": (
                "--disable-gpu --host-resolver-rules="
                "MAP * ~NOTFOUND,EXCLUDE localhost"
            ),
        }
    )
    try:
        spec = util.find_spec("PySide6")
        locations = list(spec.submodule_search_locations or ()) if spec else []
        pyside_dir = Path(locations[0]).resolve() if locations else None
    except (ImportError, OSError, TypeError, ValueError):
        pyside_dir = None
    plugin_root = _find_first_directory(
        [
            (pyside_dir / "plugins") if pyside_dir else Path("__missing__"),
            runtime / "Library" / "lib" / "qt6" / "plugins",
        ]
    )
    if plugin_root is not None:
        environment["QT_PLUGIN_PATH"] = str(plugin_root)
        environment["QT_QPA_PLATFORM_PLUGIN_PATH"] = str(plugin_root / "platforms")
    path_prefix = [runtime, runtime / "bin", runtime / "Library" / "bin"]
    if pyside_dir is not None:
        path_prefix.append(pyside_dir)
    environment["PATH"] = os.pathsep.join(
        [*(str(path) for path in path_prefix), environment.get("PATH", "")]
    )

    try:
        with tempfile.TemporaryDirectory(prefix="sankaku-ui-check-") as temp_root:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-s",
                    "-c",
                    _GUI_SMOKE_CODE,
                    temp_root,
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
    except subprocess.TimeoutExpired:
        failures.append("offline GUI smoke timed out")
    except (OSError, subprocess.SubprocessError) as exc:
        failures.append(f"offline GUI smoke failed ({type(exc).__name__})")
    else:
        if completed.returncode != 0:
            failures.append(f"offline GUI smoke exited with code {completed.returncode}")


def collect_failures(
    *, root: Path = ROOT, runtime: Path | None = None, release: bool = False
) -> list[str]:
    root = root.resolve()
    runtime = (runtime or (root / "Runtime")).resolve()
    app_dir = root / "App"
    failures: list[str] = []

    _check_required_files(root, runtime, release=release, failures=failures)
    _check_python_runtime(runtime, failures)
    _check_native_transport(app_dir, runtime, failures)
    _check_locked_dependencies(app_dir / "requirements.lock.txt", runtime, failures)
    _check_qt_webengine(runtime, failures)
    _check_embedded_paths(root, runtime, failures)

    if release:
        _check_compliance_materials(root, runtime, failures)
        _check_release_tree(root, runtime, failures)
    else:
        _offline_gui_smoke(app_dir, runtime, failures)
        _check_writable_user_directories(root, failures)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the SankakuSyncer portable directory offline."
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="run a read-only release gate and reject private/generated content",
    )
    arguments = parser.parse_args(argv)
    failures = collect_failures(release=arguments.release)

    mode = "release/read-only" if arguments.release else "installed/writable"
    if failures:
        print(f"[FAIL] SankakuSyncer portable self-check ({mode})")
        for failure in failures:
            print(" -", failure)
        return 1
    print(f"[OK] SankakuSyncer portable self-check ({mode})")
    print("Root:", ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
