# -*- coding: utf-8 -*-
"""Offline tests for portable release validation and manifest generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools import build_manifest, portable_self_check


class PortableSelfCheckTests(unittest.TestCase):
    def test_gui_smoke_uses_the_shared_tab_contract(self):
        code = portable_self_check._GUI_SMOKE_CODE
        self.assertIn("ui_main_window.MAIN_TAB_TITLES", code)
        self.assertNotIn("window.tabs.count() !=", code)

    def test_image_codec_smoke_exercises_all_preview_formats(self):
        code = portable_self_check._IMAGE_CODEC_SMOKE_CODE
        self.assertIn('"png": b"PNG"', code)
        self.assertIn('"jpeg": b"JPEG"', code)
        self.assertIn('"webp": b"WEBP"', code)
        self.assertIn("QImageWriter", code)
        self.assertIn("QImageReader", code)

    def test_release_validation_runs_codec_smoke_without_gui_smoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "Runtime"
            with mock.patch.multiple(
                portable_self_check,
                _check_required_files=mock.DEFAULT,
                _check_python_runtime=mock.DEFAULT,
                _check_native_transport=mock.DEFAULT,
                _check_locked_dependencies=mock.DEFAULT,
                _check_qt_webengine=mock.DEFAULT,
                _check_embedded_paths=mock.DEFAULT,
                _offline_image_codec_smoke=mock.DEFAULT,
                _check_compliance_materials=mock.DEFAULT,
                _check_release_tree=mock.DEFAULT,
                _offline_gui_smoke=mock.DEFAULT,
                _check_writable_user_directories=mock.DEFAULT,
            ) as checks:
                failures = portable_self_check.collect_failures(
                    root=root, runtime=runtime, release=True
                )

            self.assertEqual(failures, [])
            checks["_offline_image_codec_smoke"].assert_called_once_with(
                root / "App", runtime, failures
            )
            checks["_offline_gui_smoke"].assert_not_called()

    def test_lock_parser_requires_exact_unique_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "requirements.lock.txt"
            lock.write_text(
                "# portable pins\nPySide6==6.11.2\ncharset-normalizer==3.5.1\n",
                encoding="utf-8",
            )
            parsed = portable_self_check.read_locked_requirements(lock)
            self.assertEqual(parsed["pyside6"], ("PySide6", "6.11.2"))
            self.assertEqual(
                parsed["charset-normalizer"], ("charset-normalizer", "3.5.1")
            )

            lock.write_text("requests>=2\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                portable_self_check.read_locked_requirements(lock)

    def test_merged_pyside_components_can_use_main_package_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "requirements.lock.txt"
            lock.write_text(
                "PySide6_Addons==6.11.2\nPySide6_Essentials==6.11.2\n",
                encoding="utf-8",
            )
            failures: list[str] = []
            fake_module = SimpleNamespace(
                __version__="6.11.2",
                __file__=str(Path(sys.prefix) / "Lib" / "site-packages" / "fake.py"),
            )
            with mock.patch.object(
                portable_self_check.metadata,
                "distribution",
                side_effect=portable_self_check.metadata.PackageNotFoundError,
            ), mock.patch.object(
                portable_self_check.importlib,
                "import_module",
                return_value=fake_module,
            ):
                portable_self_check._check_locked_dependencies(
                    lock, Path(sys.prefix), failures
                )
            self.assertFalse(
                any("locked distribution missing" in value for value in failures), failures
            )
            self.assertFalse(any("merged component mismatch" in value for value in failures), failures)

    def test_release_compliance_check_delegates_to_offline_bundle_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failures: list[str] = []
            runtime = root / "Runtime"
            with mock.patch.object(
                portable_self_check.license_bundle,
                "verify_bundle",
                return_value=["tampered license"],
            ) as verifier:
                portable_self_check._check_compliance_materials(
                    root, runtime, failures
                )

            verifier.assert_called_once_with(
                root / "THIRD_PARTY_LICENSES",
                root / "SBOM.spdx.json",
                root / "App" / "requirements.lock.txt",
                runtime=runtime,
                artifact_lock_path=root / "App" / "runtime_artifacts.lock.json",
                inventory_path=root / "RUNTIME_INVENTORY.json",
                vex_path=root / "VEX.openvex.json",
                full_schema_validation=False,
            )
            self.assertEqual(
                failures, ["license/SBOM bundle: tampered license"]
            )

    def test_release_scan_is_read_only_and_rejects_private_generated_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_cache = root / "Runtime" / "Lib" / "__pycache__"
            runtime_cache.mkdir(parents=True)
            (runtime_cache / "stdlib.pyc").write_bytes(b"runtime bytecode is expected")
            (root / "Runtime" / "installer.log").write_text("private build log", encoding="utf-8")
            app_cache = root / "App" / "__pycache__"
            app_cache.mkdir(parents=True)
            (app_cache / "main.pyc").write_bytes(b"build path")
            (root / "Data").mkdir()
            (root / "Data" / "settings.json").write_text("{}", encoding="utf-8")
            (root / "Downloads").mkdir()
            (root / "Downloads" / "1.part").write_bytes(b"partial")
            (root / ".credentials").write_bytes(b"secret")
            (root / "App" / ".env.production").write_text(
                "TOKEN=secret", encoding="utf-8"
            )
            (root / "docs").mkdir()
            (root / "docs" / "signing.key").write_text(
                "not-a-real-key", encoding="utf-8"
            )
            (root / "application.log").write_text("log", encoding="utf-8")

            before = sorted(path.relative_to(root) for path in root.rglob("*"))
            failures: list[str] = []
            portable_self_check._check_release_tree(
                root, root / "Runtime", failures
            )
            after = sorted(path.relative_to(root) for path in root.rglob("*"))

            self.assertEqual(before, after)
            self.assertIn("private directory is not empty: Data", failures)
            self.assertIn("private directory is not empty: Downloads", failures)
            self.assertTrue(any("App/__pycache__" in value for value in failures))
            self.assertTrue(any(".credentials" in value for value in failures))
            self.assertTrue(any("App/.env.production" in value for value in failures))
            self.assertTrue(any("docs/signing.key" in value for value in failures))
            self.assertTrue(any("application.log" in value for value in failures))
            self.assertTrue(any("Runtime/installer.log" in value for value in failures))
            self.assertTrue(any("Runtime/Lib/__pycache__" in value for value in failures))

    def test_empty_private_directories_are_allowed_and_write_probe_cleans_up(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "Runtime"
            runtime.mkdir()
            (root / "Data").mkdir()
            (root / "Downloads").mkdir()
            failures: list[str] = []
            portable_self_check._check_release_tree(root, runtime, failures)
            self.assertEqual(failures, [])

            portable_self_check._check_writable_user_directories(root, failures)
            self.assertEqual(failures, [])
            self.assertEqual(list((root / "Data").iterdir()), [])
            self.assertEqual(list((root / "Downloads").iterdir()), [])

    def test_release_scan_rejects_overlong_portable_relative_path(self):
        self.assertEqual(
            portable_self_check.PORTABLE_RELATIVE_PATH_LIMIT,
            portable_self_check.license_bundle.runtime_compliance.PORTABLE_RELATIVE_PATH_LIMIT,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "App"
            app.mkdir()
            overlong = app / (
                "x" * portable_self_check.PORTABLE_RELATIVE_PATH_LIMIT + ".py"
            )
            overlong.write_text("VALUE = 1\n", encoding="utf-8")
            failures: list[str] = []
            portable_self_check._check_release_tree(
                root, root / "Runtime", failures
            )
            self.assertTrue(
                any("portable relative path is too long" in value for value in failures),
                failures,
            )

    def test_tool_help_entrypoints_work_with_isolated_embedded_python(self):
        tools = Path(portable_self_check.__file__).resolve().parent
        for name in ("portable_self_check.py", "assemble_portable.py"):
            result = subprocess.run(
                [sys.executable, "-B", str(tools / name), "--help"],
                cwd=Path(tempfile.gettempdir()),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout.casefold())

        runtime_result = subprocess.run(
            [sys.executable, "-B", str(tools / "runtime_compliance.py")],
            cwd=Path(tempfile.gettempdir()),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(runtime_result.returncode, 0, runtime_result.stderr)

    def test_embedded_path_scan_rejects_old_build_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Runtime").mkdir()
            for launcher in (
                "run.bat",
                "run_debug.bat",
                "run_tests.bat",
                "verify_portable.bat",
                "dev_console.bat",
                "run_silent.vbs",
            ):
                (root / launcher).write_text('@call "%~dp0run.bat"\n', encoding="utf-8")
            failures: list[str] = []
            portable_self_check._check_embedded_paths(
                root, root / "Runtime", failures
            )
            self.assertEqual(failures, [])

            (root / "run.bat").write_text(
                'set "BUILD=C:\\Users\\builder\\SankakuSyncer"\n', encoding="utf-8"
            )
            portable_self_check._check_embedded_paths(
                root, root / "Runtime", failures
            )
            self.assertIn("absolute build path embedded: run.bat", failures)


class ManifestTests(unittest.TestCase):
    def test_manifest_excludes_private_roots_and_itself_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "App").mkdir()
            (root / "Runtime").mkdir()
            (root / "Data").mkdir()
            (root / "Downloads").mkdir()
            (root / "App" / "main.py").write_bytes(b"print('ok')\n")
            (root / "Runtime" / "python.exe").write_bytes(b"python")
            (root / "Data" / "settings.json").write_bytes(b"secret settings")
            (root / "Downloads" / "1.jpg").write_bytes(b"private media")
            output = root / "SHA256SUMS.txt"
            output.write_text("stale manifest\n", encoding="utf-8")

            count = build_manifest.build_manifest(root, output)
            first = output.read_text("utf-8")
            second_count = build_manifest.build_manifest(root, output)
            second = output.read_text("utf-8")

            self.assertEqual(count, 2)
            self.assertEqual(second_count, 2)
            self.assertEqual(first, second)
            self.assertNotIn("Data/", first)
            self.assertNotIn("Downloads/", first)
            self.assertNotIn("SHA256SUMS.txt", first)
            self.assertEqual(
                build_manifest.verify_manifest(root, output), second_count
            )
            (root / "App" / "main.py").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(build_manifest.ManifestError):
                build_manifest.verify_manifest(root, output)
            expected = hashlib.sha256(b"print('ok')\n").hexdigest()
            self.assertIn(f"{expected}  App/main.py", first)

    def test_manifest_output_must_stay_outside_private_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Data").mkdir()
            with self.assertRaises(build_manifest.ManifestError):
                build_manifest.iter_release_files(root, root / "Data" / "manifest.txt")


if __name__ == "__main__":
    unittest.main()
