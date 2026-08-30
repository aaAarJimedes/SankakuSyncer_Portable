# -*- coding: utf-8 -*-
"""Pure offline tests for the lean Runtime build planner and PE parser."""

from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import json
from pathlib import Path, PurePosixPath
import struct
import tempfile
import unittest
from unittest import mock

from tools import build_runtime_subset as runtime_builder


def _make_runtime_source(root: Path) -> Path:
    source = root / "AuditedReferenceRuntime"
    source.mkdir()
    (source / "python.exe").write_bytes(b"MZ")
    (source / "python313.dll").write_bytes(b"MZ")
    (source / "DLLs").mkdir()
    (source / "Library/lib/qt6/plugins/platforms").mkdir(parents=True)
    (source / "Library/lib/qt6/plugins/platforms/qwindows.dll").write_bytes(b"MZ")
    (source / "Library/bin").mkdir(parents=True)
    (source / "Library/bin/Qt6Core.dll").write_bytes(b"MZ")
    (source / "bin").mkdir()
    (source / "bin/QtWebEngineProcess.exe").write_bytes(b"MZ")
    return source


def _make_embedded_runtime_source(root: Path) -> Path:
    source = root / "AuditedEmbeddedRuntime"
    source.mkdir()
    for name in ("python.exe", "pythonw.exe", "python3.dll", "python313.dll"):
        (source / name).write_bytes(b"MZ")
    (source / "python313.zip").write_bytes(b"PK")
    (source / "python313._pth").write_text(
        "python313.zip\n.\nLib\\site-packages\nimport site\n",
        encoding="utf-8",
    )
    pyside = source / "Lib/site-packages/PySide6"
    (pyside / "plugins/platforms").mkdir(parents=True)
    (pyside / "plugins/platforms/qwindows.dll").write_bytes(b"MZ")
    (pyside / "QtWebEngineProcess.exe").write_bytes(b"MZ")
    (pyside / "Qt6Core.dll").write_bytes(b"MZ")
    return source


def _minimal_pe_with_imports() -> bytes:
    data = bytearray(0x700)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)  # AMD64
    struct.pack_into("<H", data, 0x86, 1)  # one section
    struct.pack_into("<H", data, 0x94, 0xF0)  # PE32+ optional header

    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    directories = optional + 112
    struct.pack_into("<II", data, directories + 8, 0x1000, 40)
    struct.pack_into("<II", data, directories + 13 * 8, 0x1080, 64)

    section = optional + 0xF0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x500, 0x1000, 0x500, 0x200)

    # IMAGE_IMPORT_DESCRIPTOR at RVA 0x1000 / raw 0x200.
    struct.pack_into("<IIIII", data, 0x200, 0, 0, 0, 0x1050, 0)
    data[0x250 : 0x250 + len(b"Qt6Core.dll\0")] = b"Qt6Core.dll\0"

    # RVA-based ImgDelayDescr at RVA 0x1080 / raw 0x280.
    struct.pack_into("<IIIIIIII", data, 0x280, 1, 0x10C0, 0, 0, 0, 0, 0, 0)
    data[0x2C0 : 0x2C0 + len(b"dynamic.dll\0")] = b"dynamic.dll\0"
    return bytes(data)


class PeImportParserTests(unittest.TestCase):
    def test_extracts_normal_and_delay_imports(self):
        self.assertEqual(
            runtime_builder.parse_pe_imports_bytes(_minimal_pe_with_imports()),
            {"qt6core.dll", "dynamic.dll"},
        )

    def test_non_pe_and_unknown_optional_header_are_ignored(self):
        self.assertEqual(runtime_builder.parse_pe_imports_bytes(b"not a PE"), set())
        payload = bytearray(_minimal_pe_with_imports())
        struct.pack_into("<H", payload, 0x98, 0x999)
        self.assertEqual(runtime_builder.parse_pe_imports_bytes(bytes(payload)), set())

    def test_truncated_declared_headers_fail_closed(self):
        payload = bytearray(0xA0)
        payload[:2] = b"MZ"
        struct.pack_into("<I", payload, 0x3C, 0x80)
        payload[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", payload, 0x94, 0xF0)
        with self.assertRaises(runtime_builder.RuntimeBuildError):
            runtime_builder.parse_pe_imports_bytes(bytes(payload))


class RuntimeAllowlistTests(unittest.TestCase):
    def test_mainwindow_smoke_uses_the_shared_tab_contract(self):
        code = runtime_builder._OFFLINE_MAINWINDOW_SMOKE_CODE
        self.assertIn("ui_main_window.MAIN_TAB_TITLES", code)
        self.assertNotIn("tabs.count()==", code)
        self.assertIn("expected=", code)
        self.assertIn("actual=", code)

    def test_verification_failure_formatter_keeps_only_failed_diagnostics(self):
        results = (
            runtime_builder.VerificationResult("passed", 0, 0.1, "secret", ""),
            runtime_builder.VerificationResult("first", 2, 0.2, "one\n", ""),
            runtime_builder.VerificationResult("second", 3, 0.3, "", "two\n"),
        )

        message = runtime_builder._format_verification_failures(results)

        self.assertTrue(message.startswith("verification failed: first, second"))
        self.assertNotIn("passed", message)
        self.assertNotIn("secret", message)
        self.assertLess(message.index("[first]"), message.index("[second]"))
        self.assertIn("[first] exit code 2\nstdout:\none", message)
        self.assertIn("[second] exit code 3\nstderr:\ntwo", message)
        self.assertEqual(runtime_builder._format_verification_failures(results[:1]), "")

    def test_runtime_verification_uses_a_temporary_root_outside_the_payload(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            runtime = root / "runtime"
            app = root / "app"
            runtime.mkdir()
            app.mkdir()
            (runtime / "python.exe").write_bytes(b"MZ")
            temporary_roots: list[Path] = []

            def capture_environment(_runtime, _app, temporary_root):
                temporary_roots.append(temporary_root)
                return {}

            def successful_step(name, _command, **_kwargs):
                return runtime_builder.VerificationResult(name, 0, 0.0, "", "")

            with (
                mock.patch.object(
                    runtime_builder,
                    "detect_python_layout",
                    return_value=mock.Mock(version_info=(3, 13)),
                ),
                mock.patch.object(
                    runtime_builder,
                    "_verification_environment",
                    side_effect=capture_environment,
                ),
                mock.patch.object(
                    runtime_builder,
                    "_run_verification_step",
                    side_effect=successful_step,
                ),
            ):
                results = runtime_builder.verify_runtime(runtime, app)

            self.assertEqual(len(results), 4)
            self.assertEqual(len(temporary_roots), 1)
            self.assertFalse(
                temporary_roots[0].resolve().is_relative_to(runtime.resolve())
            )
            self.assertFalse(temporary_roots[0].exists())

    def test_forbidden_cache_development_and_heavy_binaries(self):
        rejected = (
            "Lib/__pycache__/abc.pyc",
            "Lib/site-packages/pip/__init__.py",
            "Library/bin/libclang-13.dll",
            "Library/bin/mkl_core.2.dll",
            "Library/bin/aomenc.exe",
            "Library/bin/x265.exe",
            "Library/lib/qt6/plugins/imageformats/qsvg.dll",
            "Lib/site-packages/PySide6/plugins/iconengines/qsvgicon.dll",
            "Lib/site-packages/PySide6/plugins/tls/qopensslbackend.dll",
            "Lib/site-packages/requests/api.py",
            "Lib/site-packages/urllib3-2.7.0.dist-info/METADATA",
            "_ssl.pyd",
            "DLLs/_hashlib.pyd",
            "libssl-3.dll",
            "libcrypto-3-x64.dll",
            "Library/bin/tool.pdb",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertTrue(
                    runtime_builder.is_forbidden_relative(PurePosixPath(value))
                )

        accepted = (
            "python313.dll",
            "python313.zip",
            "python313._pth",
            "Library/bin/Qt6WebEngineCore.dll",
            "Library/bin/opengl32sw.dll",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertFalse(
                    runtime_builder.is_forbidden_relative(PurePosixPath(value))
                )

    def test_explicit_seeds_cover_required_runtime_features(self):
        self.assertEqual(runtime_builder.TARGET_PYTHON_VERSION, (3, 13, 15))
        self.assertIn("QtPrintSupport", runtime_builder.PYSIDE_MODULES)
        self.assertIn("QtWebChannel", runtime_builder.PYSIDE_MODULES)
        self.assertIn("QtWebEngineCore", runtime_builder.PYSIDE_MODULES)
        self.assertIn("QtWebEngineWidgets", runtime_builder.PYSIDE_MODULES)
        self.assertIn(
            "Library/lib/qt6/plugins/platforms/qwindows.dll",
            runtime_builder.QT_PLUGIN_SEEDS,
        )
        self.assertIn(
            "Library/lib/qt6/plugins/platforms/qoffscreen.dll",
            runtime_builder.QT_PLUGIN_SEEDS,
        )
        self.assertIn("imageformats/qwebp.dll", runtime_builder.QT_PLUGIN_RELATIVE_SEEDS)
        self.assertFalse(
            any("qsvg" in seed.casefold() for seed in runtime_builder.QT_PLUGIN_RELATIVE_SEEDS)
        )
        self.assertFalse(
            any("qopenssl" in seed.casefold() for seed in runtime_builder.QT_PLUGIN_RELATIVE_SEEDS)
        )
        self.assertIn("tls/qschannelbackend.dll", runtime_builder.QT_PLUGIN_RELATIVE_SEEDS)
        self.assertNotIn("_ssl.pyd", runtime_builder.STDLIB_EXTENSION_MODULES)
        self.assertNotIn("_hashlib.pyd", runtime_builder.STDLIB_EXTENSION_MODULES)
        self.assertEqual(runtime_builder.SITE_PACKAGE_DIRECTORIES, ())
        self.assertEqual(runtime_builder.SITE_PACKAGE_FILES, ())
        self.assertIn(
            "Lib/site-packages/PySide6/plugins/platforms/qwindows.dll",
            runtime_builder.PIP_QT_LAYOUT.plugin_seeds(),
        )
        self.assertEqual(
            set(runtime_builder.QT_WEBENGINE_LOCALES),
            {"en-US.pak", "zh-CN.pak", "zh-TW.pak"},
        )
        self.assertNotIn("pip", runtime_builder.SITE_PACKAGE_DIRECTORIES)
        self.assertNotIn("setuptools", runtime_builder.SITE_PACKAGE_DIRECTORIES)

    def test_dependency_candidate_prefers_importer_directory(self):
        source = Path("D:/runtime")
        importer = source / "Library/bin/Qt6Gui.dll"
        nearby = source / "Library/bin/zlib.dll"
        root_copy = source / "zlib.dll"
        self.assertLess(
            runtime_builder._candidate_rank(importer, nearby, source),
            runtime_builder._candidate_rank(importer, root_copy, source),
        )

    def test_pyside_module_selection_does_not_match_prefix_siblings(self):
        with tempfile.TemporaryDirectory() as raw_root:
            package = Path(raw_root)
            exact = package / "QtNetwork.pyd"
            exact.write_bytes(b"MZ")
            (package / "QtNetworkAuth.pyd").write_bytes(b"MZ")
            self.assertEqual(
                runtime_builder._pyside_module_binaries(package, "QtNetwork"),
                [exact],
            )

            exact.unlink()
            tagged = package / "QtNetwork.cp313-win_amd64.pyd"
            tagged.write_bytes(b"MZ")
            self.assertEqual(
                runtime_builder._pyside_module_binaries(package, "QtNetwork"),
                [tagged],
            )

    def test_known_windows_imports_are_external(self):
        self.assertTrue(runtime_builder._is_system_import("KERNEL32.dll"))
        self.assertTrue(
            runtime_builder._is_system_import("api-ms-win-core-handle-l1-1-0.dll")
        )

    def test_unknown_imports_never_inherit_the_build_host_system32_policy(self):
        with tempfile.TemporaryDirectory() as raw_root:
            windows = Path(raw_root) / "Windows"
            system32 = windows / "System32"
            system32.mkdir(parents=True)
            (system32 / "runner-only-not-in-policy.dll").write_bytes(b"MZ")

            with mock.patch.dict(
                runtime_builder.os.environ,
                {"SystemRoot": str(windows)},
            ):
                self.assertFalse(
                    runtime_builder._is_system_import(
                        "runner-only-not-in-policy.dll"
                    )
                )
                self.assertFalse(
                    runtime_builder._is_system_import(
                        "api-ms-win-sankaku-not-real-l9-9-9.dll"
                    )
                )
                self.assertFalse(
                    runtime_builder._is_system_import(
                        "ext-ms-win-sankaku-not-real-l9-9-9.dll"
                    )
                )

    def test_unknown_pe_import_remains_a_builder_failure(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_embedded_runtime_source(root)
            destination = root / "runtime-subset-build"
            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)
            builder._copy_file(source / "python.exe")
            builder._source_index = {}

            with mock.patch.object(
                runtime_builder,
                "parse_pe_imports",
                return_value={"runner-only-not-in-policy.dll"},
            ):
                with self.assertRaisesRegex(
                    runtime_builder.RuntimeBuildError,
                    "unresolved non-system PE imports",
                ):
                    builder.collect_pe_dependencies()

    def test_frozen_runtime_imports_exactly_match_the_reviewed_policy(self):
        inventory_path = Path(__file__).resolve().parents[1] / "RUNTIME_INVENTORY.json"
        inventory = json.loads(inventory_path.read_text("utf-8"))
        self.assertEqual(
            inventory["external_pe_imports"],
            sorted(runtime_builder.WINDOWS_10_1903_SYSTEM_IMPORTS),
        )


class RuntimeLayoutTests(unittest.TestCase):
    def test_embedded_python_313_layout_is_discovered_and_validated(self):
        with tempfile.TemporaryDirectory() as raw_root:
            source = _make_embedded_runtime_source(Path(raw_root))
            layout = runtime_builder.detect_python_layout(source)

            self.assertEqual(layout.version, "3.13")
            self.assertEqual(layout.version_info, (3, 13))
            self.assertEqual(layout.version_dll, "python313.dll")
            self.assertEqual(layout.stdlib_zip, "python313.zip")
            self.assertEqual(layout.pth_file, "python313._pth")
            self.assertEqual(layout.extension_root, "")
            self.assertTrue(layout.embedded)

    def test_embedded_path_file_must_enable_packages_and_site(self):
        with tempfile.TemporaryDirectory() as raw_root:
            source = _make_embedded_runtime_source(Path(raw_root))
            (source / "python313._pth").write_text(
                "python313.zip\n.\n#import site\n", encoding="utf-8"
            )
            with self.assertRaises(runtime_builder.RuntimeBuildError):
                runtime_builder.detect_python_layout(source)

    def test_full_python_layout_remains_supported(self):
        with tempfile.TemporaryDirectory() as raw_root:
            source = _make_runtime_source(Path(raw_root))
            layout = runtime_builder.detect_python_layout(source)
            self.assertEqual(layout.version_info, (3, 13))
            self.assertEqual(layout.extension_root, "DLLs")
            self.assertFalse(layout.embedded)

    def test_pyside_wheel_and_conda_qt_layouts_are_both_supported(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            conda_source = _make_runtime_source(root)
            self.assertEqual(
                runtime_builder.detect_qt_layout(conda_source).name, "conda-qt"
            )

            wheel_source = _make_embedded_runtime_source(root)
            wheel_layout = runtime_builder.detect_qt_layout(wheel_source)
            self.assertEqual(wheel_layout.name, "pyside6-wheel")
            self.assertEqual(
                wheel_layout.webengine_process,
                "Lib/site-packages/PySide6/QtWebEngineProcess.exe",
            )

    def test_mixed_qt_layout_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw_root:
            source = _make_embedded_runtime_source(Path(raw_root))
            conda_plugins = source / "Library/lib/qt6/plugins/platforms"
            conda_plugins.mkdir(parents=True)
            (conda_plugins / "qwindows.dll").write_bytes(b"MZ")
            (source / "Library/bin").mkdir(parents=True)
            (source / "Library/bin/Qt6Core.dll").write_bytes(b"MZ")
            (source / "bin").mkdir()
            (source / "bin/QtWebEngineProcess.exe").write_bytes(b"MZ")
            with self.assertRaises(runtime_builder.RuntimeBuildError):
                runtime_builder.detect_qt_layout(source)

    def test_verification_environment_uses_wheel_paths(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            runtime = _make_embedded_runtime_source(root)
            temp_root = root / "temp"
            temp_root.mkdir()
            environment = runtime_builder._verification_environment(
                runtime, root / "App", temp_root
            )
            pyside = runtime / "Lib/site-packages/PySide6"
            self.assertEqual(environment["QT_PLUGIN_PATH"], str(pyside / "plugins"))
            self.assertEqual(
                environment["QTWEBENGINEPROCESS_PATH"],
                str(pyside / "QtWebEngineProcess.exe"),
            )
            self.assertEqual(
                environment["QTWEBENGINE_RESOURCES_PATH"],
                str(pyside / "resources"),
            )

    def test_wheel_dynamic_seeds_are_copied_in_place_without_svg_plugins(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_embedded_runtime_source(root)
            layout = runtime_builder.PIP_QT_LAYOUT
            required = [
                *layout.dynamic_seeds(),
                *(f"{layout.resources_root}/{name}" for name in runtime_builder.QT_RESOURCE_FILES),
                *(f"{layout.locales_root}/{name}" for name in runtime_builder.QT_WEBENGINE_LOCALES),
            ]
            for relative in required:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"MZ" if path.suffix in {".dll", ".exe"} else b"data")

            destination = root / "runtime_subset_staging"
            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)
            builder.copy_qt_dynamic_seeds()

            for relative in required:
                self.assertTrue((destination / relative).is_file(), relative)
            copied = [path.name.casefold() for path in destination.rglob("*.dll")]
            self.assertNotIn("qsvg.dll", copied)
            self.assertNotIn("qsvgicon.dll", copied)


class RuntimeBuildPathSafetyTests(unittest.TestCase):
    def test_source_argument_is_explicit_and_local_defaults_stay_in_project(self):
        parser = runtime_builder._parser()
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args([])

        args = parser.parse_args(["--source", "ReferenceRuntime"])
        self.assertEqual(args.source, Path("ReferenceRuntime"))
        self.assertEqual(
            runtime_builder.DEFAULT_DESTINATION.parent,
            runtime_builder.PROJECT_ROOT,
        )
        self.assertEqual(runtime_builder.DEFAULT_APP, runtime_builder.PROJECT_ROOT / "App")
        self.assertIn("runtime", runtime_builder.DEFAULT_DESTINATION.name.casefold())
        self.assertTrue(
            any(
                marker in runtime_builder.DEFAULT_DESTINATION.name.casefold()
                for marker in runtime_builder.DESTINATION_REQUIRED_MARKERS
            )
        )

    def test_destination_name_requires_runtime_and_a_build_qualifier(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)

            accepted = root / "SankakuSyncer_Runtime_Lean"
            resolved_source, resolved_destination = runtime_builder.validate_build_paths(
                source, accepted
            )
            self.assertEqual(resolved_source, source.resolve())
            self.assertEqual(resolved_destination, accepted.resolve())

            rejected = (
                root / "Agent Delivery",
                root / "Runtime",
                root / "ordinary-staging",
                root,
            )
            for destination in rejected:
                with self.subTest(destination=destination):
                    with self.assertRaises(runtime_builder.RuntimeBuildError):
                        runtime_builder.validate_build_paths(source, destination)

    def test_destination_must_be_disjoint_from_source(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = source / "runtime_subset_build"
            with self.assertRaises(runtime_builder.RuntimeBuildError):
                runtime_builder.validate_build_paths(source, destination)


class RuntimeCleanSafetyTests(unittest.TestCase):
    def test_empty_directory_is_initialized_without_clean(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_subset_staging"
            destination.mkdir()

            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)

            self.assertEqual(
                (destination / runtime_builder.BUILD_SENTINEL_NAME).read_bytes(),
                runtime_builder.BUILD_SENTINEL_BYTES,
            )

    def test_clean_refuses_unmarked_nonempty_directory_and_preserves_contents(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_subset_staging"
            destination.mkdir()
            victim = destination / "must-survive.txt"
            victim.write_text("user data", encoding="utf-8")

            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            with self.assertRaises(runtime_builder.RuntimeBuildError):
                builder.prepare(clean=True)
            self.assertEqual(victim.read_text(encoding="utf-8"), "user data")

    def test_clean_refuses_inexact_sentinel_and_preserves_contents(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_lean_build"
            destination.mkdir()
            sentinel = destination / runtime_builder.BUILD_SENTINEL_NAME
            sentinel.write_bytes(runtime_builder.BUILD_SENTINEL_BYTES + b"tampered\n")
            victim = destination / "must-survive.txt"
            victim.write_text("user data", encoding="utf-8")

            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            with self.assertRaises(runtime_builder.RuntimeBuildError):
                builder.prepare(clean=True)
            self.assertTrue(victim.is_file())
            self.assertTrue(sentinel.is_file())

    def test_clean_replaces_only_exactly_marked_destination(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_lean_build"
            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)
            old_payload = destination / "old-runtime-file.dll"
            old_payload.write_bytes(b"old")

            builder.prepare(clean=True)

            self.assertFalse(old_payload.exists())
            self.assertEqual(
                (destination / runtime_builder.BUILD_SENTINEL_NAME).read_bytes(),
                runtime_builder.BUILD_SENTINEL_BYTES,
            )

    def test_nonempty_marked_destination_still_requires_clean(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_subset_build"
            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)
            payload = destination / "existing.dll"
            payload.write_bytes(b"old")

            with self.assertRaises(runtime_builder.RuntimeBuildError):
                builder.prepare(clean=False)
            self.assertTrue(payload.is_file())


class RuntimeMetadataTests(unittest.TestCase):
    def test_manifest_report_and_sentinel_are_not_payload_or_path_leaks(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = _make_runtime_source(root)
            destination = root / "runtime_subset_staging"
            builder = runtime_builder.RuntimeSubsetBuilder(source, destination)
            builder.prepare(clean=False)
            payload = destination / "payload.bin"
            payload.write_bytes(b"payload")
            (destination / runtime_builder.MANIFEST_NAME).write_text(
                "stale", encoding="utf-8"
            )
            (destination / runtime_builder.REPORT_NAME).write_text(
                "stale", encoding="utf-8"
            )
            verification = [
                runtime_builder.VerificationResult(
                    name="offline",
                    returncode=0,
                    seconds=0.1,
                    stdout=f"source={source}",
                    stderr=f"destination={destination}",
                )
            ]

            report = builder.write_manifest(verification)
            report_text = (destination / runtime_builder.REPORT_NAME).read_text(
                encoding="utf-8"
            )
            manifest_text = (destination / runtime_builder.MANIFEST_NAME).read_text(
                encoding="utf-8"
            )

            self.assertEqual(report["file_count"], 1)
            self.assertEqual(report["bytes"], len(b"payload"))
            self.assertEqual(report["schema_version"], 3)
            self.assertEqual(report["artifact_name"], "SankakuSyncer_Runtime_Lean")
            self.assertNotIn("created_utc", report)
            self.assertNotIn("seconds", report["verification"][0])
            self.assertNotIn("source", report)
            self.assertNotIn("destination", report)
            self.assertNotIn(str(source), report_text)
            self.assertNotIn(str(destination), report_text)
            self.assertEqual(json.loads(report_text), report)
            self.assertIn("*payload.bin", manifest_text)
            for name in runtime_builder.BUILD_METADATA_NAMES:
                self.assertNotIn(name, manifest_text.casefold())

            repeated = builder.write_manifest(
                [
                    runtime_builder.VerificationResult(
                        name="offline",
                        returncode=0,
                        seconds=999.0,
                        stdout="different timing",
                        stderr="different diagnostics",
                    )
                ]
            )
            self.assertEqual(repeated, report)
            self.assertEqual(
                (destination / runtime_builder.REPORT_NAME).read_text("utf-8"),
                report_text,
            )

    def test_builder_metadata_classifier_only_matches_top_level_files(self):
        for name in runtime_builder.BUILD_METADATA_NAMES:
            self.assertTrue(
                runtime_builder.is_build_metadata_relative(PurePosixPath(name))
            )
            self.assertFalse(
                runtime_builder.is_build_metadata_relative(
                    PurePosixPath("nested") / name
                )
            )


class LauncherLayoutTests(unittest.TestCase):
    def test_launchers_select_wheel_or_conda_qt_paths(self):
        for name in (
            "run.bat",
            "run_debug.bat",
            "run_tests.bat",
            "verify_portable.bat",
            "dev_console.bat",
        ):
            with self.subTest(name=name):
                text = (runtime_builder.PROJECT_ROOT / name).read_text("utf-8")
                self.assertIn(r"%PYSIDE_ROOT%\plugins\platforms\qwindows.dll", text)
                self.assertIn(
                    r"Runtime\Library\lib\qt6\plugins\platforms\qwindows.dll",
                    text,
                )
                self.assertIn(r"%PYSIDE_ROOT%\QtWebEngineProcess.exe", text)
                self.assertIn(r"Runtime\bin\QtWebEngineProcess.exe", text)
                self.assertIn("QT_QPA_PLATFORM_PLUGIN_PATH", text)

    def test_embedded_launch_commands_insert_app_directory_explicitly(self):
        for name in ("run.bat", "run_debug.bat", "run_tests.bat"):
            with self.subTest(name=name):
                text = (runtime_builder.PROJECT_ROOT / name).read_text("utf-8")
                self.assertIn("SANKAKU_APP_DIR", text)
                self.assertIn("sys.path.insert(0,p)", text)
                self.assertIn("runpy.run_path", text)

        verify_text = (runtime_builder.PROJECT_ROOT / "verify_portable.bat").read_text(
            "utf-8"
        )
        self.assertIn("SANKAKU_APP_DIR", verify_text)
        self.assertIn("sys.path.insert(0,p)", verify_text)
        self.assertIn("runpy.run_module('tools.portable_self_check'", verify_text)


if __name__ == "__main__":
    unittest.main()
