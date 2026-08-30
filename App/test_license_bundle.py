# -*- coding: utf-8 -*-
"""Offline tests for Runtime license, provenance, SPDX, and VEX tooling."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
import zipfile

from tools import collect_third_party_licenses as licenses
from tools import runtime_compliance


LOCK_TEXT = """\
PySide6==6.11.2
PySide6_Addons==6.11.2
PySide6_Essentials==6.11.2
shiboken6==6.11.2
requests==2.34.2
certifi==2026.7.22
charset-normalizer==3.5.1
idna==3.19
urllib3==2.7.0
PySocks==1.7.1
"""


def _write_lock(root: Path, text: str = LOCK_TEXT) -> Path:
    path = root / "requirements.lock.txt"
    path.write_text(text, encoding="utf-8")
    return path


def _builder_metadata(runtime: Path, payload: list[Path]) -> None:
    lines = []
    for path in sorted(payload):
        relative = path.relative_to(runtime).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{relative}\n")
    (runtime / runtime_compliance.BUILDER_MANIFEST).write_text(
        "".join(lines), encoding="utf-8", newline="\n"
    )
    report = {
        "schema_version": 3,
        "artifact_name": "SankakuSyncer_Runtime_Lean",
        "python": "3.13",
        "python_verification_target": licenses.PYTHON_VERSION,
        "python_layout": "embedded",
        "qt_layout": "pyside6-wheel",
        "file_count": len(payload),
        "bytes": sum(path.stat().st_size for path in payload),
        "mib": round(sum(path.stat().st_size for path in payload) / (1024 * 1024), 2),
        "pe_images_scanned": 0,
        "external_system_imports": [],
        "unresolved_imports": {},
        "forbidden_files": [],
        "dynamic_seeds": [],
        "verification": [
            {"name": name, "returncode": 0}
            for name in (
                "python_hashlib_winhttp",
                "qtwidgets_qtwebengine_import",
                "offline_mainwindow_construction",
                "offline_regression_suite",
            )
        ],
    }
    (runtime / runtime_compliance.BUILDER_REPORT).write_text(
        json.dumps(report), encoding="utf-8", newline="\n"
    )


def _anchor_member_inventory(artifact: dict[str, object], archive: bytes) -> None:
    value = licenses._zip_member_inventory_value(artifact, archive)
    artifact["member_inventory_sha256"] = hashlib.sha256(
        licenses._json_bytes(value)
    ).hexdigest()


class LicenseBundleTests(unittest.TestCase):
    def test_lock_and_source_urls_are_exactly_versioned(self):
        with tempfile.TemporaryDirectory() as temporary:
            locked = licenses.read_locked_versions(_write_lock(Path(temporary)))
        self.assertEqual(locked["requests"][1], "2.34.2")
        self.assertEqual(locked["urllib3"][1], "2.7.0")
        self.assertIn("/v2.34.2/LICENSE", licenses.dependency_license_source("requests", "2.34.2")[0])
        self.assertIn("/2026.07.22/LICENSE", licenses.dependency_license_source("certifi", "2026.7.22")[0])
        self.assertIn("/2.7.0/LICENSE.txt", licenses.dependency_license_source("urllib3", "2.7.0")[0])

    def test_minimal_schannel_lock_does_not_require_network_packages(self):
        text = """PySide6==6.11.2
PySide6_Addons==6.11.2
PySide6_Essentials==6.11.2
shiboken6==6.11.2
"""
        with tempfile.TemporaryDirectory() as temporary:
            locked = licenses.read_locked_versions(_write_lock(Path(temporary), text))
        self.assertNotIn("requests", locked)

    def test_qt_attribution_discovery_is_module_and_origin_bounded(self):
        required = set(runtime_compliance.QT_NATIVE_ATTRIBUTIONS)
        self.assertTrue(
            {
                "qtwebengine-3rdparty-ffmpeg.html",
                "qtwebengine-3rdparty-libvpx.html",
                "qtwebengine-3rdparty-opus.html",
                "qtwebengine-3rdparty-the-chromium-project.html",
            }.issubset(required)
        )
        webengine = sorted(name for name in required if name.startswith("qtwebengine-"))
        while len(webengine) < licenses.MINIMUM_QT_WEBENGINE_NOTICE_PAGES:
            webengine.append(f"qtwebengine-3rdparty-test-{len(webengine):03d}.html")
        qtbase = sorted(required - set(webengine) - {"qt-attribution-llvmpipe.html"})
        links = [f'<h2 id="qt-webengine"></h2>']
        links.extend(f'<a href="{name}">x</a>' for name in webengine)
        links.append('<h2 id="qt-core"></h2>')
        links.extend(f'<a href="{name}">x</a>' for name in qtbase)
        links.append('<h2 id="additional-information"></h2>')
        links.append('<a href="qt-attribution-llvmpipe.html">x</a>')
        links.append('<a href="https://evil.example/qtcore-attribution-evil.html">x</a>')
        page = (
            f"<!doctype html><html><title>Qt {licenses.QT_VERSION}</title>"
            + "".join(links)
            + "</html>"
        ).encode("utf-8")
        discovered = licenses.discover_qt_attribution_urls(page)
        self.assertEqual(len(discovered), len(set(webengine) | set(qtbase) | {"qt-attribution-llvmpipe.html"}))
        self.assertFalse(any("evil.example" in url for url in discovered))

    def test_qt_attribution_archive_names_are_bounded_stable_and_auditable(self):
        source = (
            "qtwebengine-3rdparty-csp-evaluator-core-library-a-tool-that-allows-"
            "developers-to-check-if-a-content-security-policy-csp-serves-as-"
            "mitigation-against-xss-attacks.html"
        )
        archived = runtime_compliance.qt_attribution_archive_filename(source)
        digest = hashlib.sha256(source.encode("ascii")).hexdigest()
        self.assertEqual(
            len(archived),
            runtime_compliance.QT_ATTRIBUTION_ARCHIVE_FILENAME_LIMIT,
        )
        self.assertTrue(archived.startswith("qtwebengine-3rdparty-csp"))
        self.assertTrue(archived.endswith(f"-{digest}.html"))
        self.assertEqual(
            runtime_compliance.qt_attribution_archive_filename(source), archived
        )
        self.assertNotEqual(
            runtime_compliance.qt_attribution_archive_filename(
                source.replace("attacks.html", "attack.html")
            ),
            archived,
        )
        self.assertEqual(
            runtime_compliance.qt_attribution_archive_filename(
                "qtwebengine-3rdparty-ffmpeg.html"
            ),
            "qtwebengine-3rdparty-ffmpeg.html",
        )
        with self.assertRaisesRegex(
            runtime_compliance.RuntimeComplianceError, "unsafe Qt attribution"
        ):
            runtime_compliance.qt_attribution_archive_filename("../notice.html")

    def test_qt_attribution_archive_mapping_rejects_windows_name_collision(self):
        first = "https://doc.qt.io/qt-6.11/QtNotice.html"
        second = "https://doc.qt.io/qt-6.11/qtnotice.html"
        with self.assertRaisesRegex(
            licenses.LicenseBundleError, "archive filename collision"
        ):
            licenses.qt_attribution_archive_entries([first, second])

    def test_license_bundle_rejects_overlong_portable_relative_path(self):
        self.assertEqual(
            licenses.PORTABLE_RELATIVE_PATH_LIMIT,
            runtime_compliance.PORTABLE_RELATIVE_PATH_LIMIT,
        )
        allowed = "a" * (
            licenses.PORTABLE_RELATIVE_PATH_LIMIT
            - len(licenses._PORTABLE_LICENSE_PREFIX)
        )
        self.assertEqual(licenses._validate_relative_path(allowed).as_posix(), allowed)
        with self.assertRaisesRegex(
            licenses.LicenseBundleError, "portable relative path is too long"
        ):
            licenses._validate_relative_path(allowed + "x")

    def test_exact_qt_source_checksum_is_parsed(self):
        digest = "a" * 64
        value = licenses.parse_qt_source_checksum(
            "qtbase",
            f"{digest}  qtbase-everywhere-src-6.11.2.tar.xz\n".encode("ascii"),
        )
        self.assertEqual(value["sha256"], digest)
        self.assertIn("/6.11.2/submodules/", value["archive_url"])

    def test_cpython_member_inventory_is_anchored_to_locked_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("python313.dll", b"python")
            archive.writestr("python313.zip", b"stdlib")
        data = buffer.getvalue()
        artifact = {
            "artifact_id": "cpython@3.13.15",
            "bytes": len(data),
            "canonical_name": "cpython",
            "filename": "python-3.13.15-embed-amd64.zip",
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": "https://www.python.org/fake.zip",
        }
        _anchor_member_inventory(artifact, data)
        inventory_bytes, source_digest = licenses.build_cpython_member_inventory(
            {"artifacts": [artifact]}, lambda _url: data
        )
        inventory = json.loads(inventory_bytes)
        self.assertEqual(source_digest, artifact["sha256"])
        self.assertEqual([item["path"] for item in inventory["members"]], ["python313.dll", "python313.zip"])

    def test_wheel_record_and_metadata_use_outer_wheel_member_hashes(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")
            archive.writestr("demo-1.0.dist-info/RECORD", b"demo-1.0.dist-info/RECORD,,\n")
        data = buffer.getvalue()
        artifact = {
            "artifact_id": "demo@1.0",
            "bytes": len(data),
            "canonical_name": "demo",
            "filename": "demo-1.0-py3-none-any.whl",
            "kind": "wheel",
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": "https://files.pythonhosted.org/demo.whl",
            "version": "1.0",
        }
        _anchor_member_inventory(artifact, data)
        values = licenses.build_wheel_member_inventories(
            {"artifacts": [artifact]}, lambda _url: data
        )
        member_inventory = json.loads(next(iter(values.values()))[0])
        owners = runtime_compliance._wheel_member_owners(
            [artifact], [member_inventory]
        )
        record = owners["lib/site-packages/demo-1.0.dist-info/record"][0]
        self.assertEqual(record[0], "demo@1.0")
        self.assertEqual(record[1], hashlib.sha256(b"demo-1.0.dist-info/RECORD,,\n").hexdigest())
        with self.assertRaisesRegex(licenses.LicenseBundleError, "hash/size mismatch"):
            licenses.build_wheel_member_inventories(
                {"artifacts": [artifact]}, lambda _url: data + b"tamper"
            )
        member_inventory["members"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            runtime_compliance.RuntimeComplianceError, "not anchored"
        ):
            runtime_compliance._wheel_member_owners([artifact], [member_inventory])

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required")
    def test_frozen_json_schema_is_actually_enforced(self):
        schema = {
            "title": "Fixture",
            "type": "object",
            "additionalProperties": False,
            "required": ["count"],
            "properties": {"count": {"type": "integer", "minimum": 1}},
        }
        licenses.validate_against_frozen_schema(
            {"count": 1}, schema, title="fixture"
        )
        with self.assertRaisesRegex(licenses.LicenseBundleError, "fails frozen"):
            licenses.validate_against_frozen_schema(
                {"count": False}, schema, title="fixture"
            )

    def test_runtime_inventory_rejects_unknown_non_wheel_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            known = runtime / "known.bin"
            unknown = runtime / "unknown.bin"
            known.write_bytes(b"known")
            unknown.write_bytes(b"unknown")
            _builder_metadata(runtime, [known, unknown])
            artifact = {
                "artifact_id": "cpython@3.13.15",
                "bytes": 1,
                "canonical_name": "cpython",
                "filename": "python.zip",
                "sha256": "a" * 64,
                "url": "https://www.python.org/python.zip",
            }
            members = {
                "schema_version": 1,
                "source_artifact": {key: artifact[key] for key in ("bytes", "filename", "sha256", "url")},
                "members": [{"path": "known.bin", "sha256": hashlib.sha256(b"known").hexdigest(), "size": 5}],
            }
            artifact["member_inventory_sha256"] = hashlib.sha256(
                runtime_compliance.json_bytes(members)
            ).hexdigest()
            with mock.patch.object(
                runtime_compliance,
                "_probe_runtime",
                return_value={"python": "3.13.15", "qt": "6.11.2", "chromium": "140"},
            ):
                with self.assertRaisesRegex(runtime_compliance.RuntimeComplianceError, "no locked artifact provenance"):
                    runtime_compliance.build_runtime_inventory(
                        runtime, {"artifacts": [artifact]}, "b" * 64, members, []
                    )

    def test_builder_manifest_report_and_sentinel_are_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = runtime / "payload.txt"
            payload.write_bytes(b"payload")
            _builder_metadata(runtime, [payload])
            report = runtime_compliance._validate_builder_metadata(runtime, [payload])
            self.assertEqual(report["file_count"], 1)
            extra = runtime / "extra.txt"
            extra.write_bytes(b"extra")
            with self.assertRaisesRegex(runtime_compliance.RuntimeComplianceError, "does not match payload"):
                runtime_compliance._validate_builder_metadata(runtime, [payload, extra])
            report_path = runtime / runtime_compliance.BUILDER_REPORT
            report = json.loads(report_path.read_text("utf-8"))
            report["verification"][0]["returncode"] = False
            report_path.write_text(json.dumps(report), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(runtime_compliance.RuntimeComplianceError, "did not pass"):
                runtime_compliance._validate_builder_metadata(runtime, [payload])
            (runtime / runtime_compliance.BUILDER_SENTINEL).write_text("builder")
            with self.assertRaisesRegex(runtime_compliance.RuntimeComplianceError, "sentinel"):
                runtime_compliance._iter_payload_files(runtime)

    def test_builder_report_cannot_approve_a_runner_only_windows_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = runtime / "payload.dll"
            payload.write_bytes(b"MZ")
            _builder_metadata(runtime, [payload])
            report_path = runtime / runtime_compliance.BUILDER_REPORT
            report = json.loads(report_path.read_text("utf-8"))
            report["external_system_imports"] = [
                "runner-only-not-in-policy.dll"
            ]
            report["pe_images_scanned"] = 1
            report_path.write_text(
                json.dumps(report), encoding="utf-8", newline="\n"
            )

            with self.assertRaisesRegex(
                runtime_compliance.RuntimeComplianceError,
                "unsupported external Windows import",
            ):
                runtime_compliance._validate_builder_metadata(
                    runtime,
                    [payload],
                )

    def test_builder_report_schema_and_import_names_are_canonical(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = runtime / "payload.dll"
            payload.write_bytes(b"MZ")
            _builder_metadata(runtime, [payload])
            report_path = runtime / runtime_compliance.BUILDER_REPORT
            report = json.loads(report_path.read_text("utf-8"))
            report["schema_version"] = 3.0
            report_path.write_text(
                json.dumps(report), encoding="utf-8", newline="\n"
            )

            with self.assertRaisesRegex(
                runtime_compliance.RuntimeComplianceError,
                "report schema mismatch",
            ):
                runtime_compliance._validate_builder_metadata(runtime, [payload])

            report["schema_version"] = 3
            report["external_system_imports"] = [
                "KERNEL32.dll",
                "kernel32.dll",
            ]
            report_path.write_text(
                json.dumps(report), encoding="utf-8", newline="\n"
            )
            with self.assertRaisesRegex(
                runtime_compliance.RuntimeComplianceError,
                "external import list is invalid",
            ):
                runtime_compliance._validate_builder_metadata(runtime, [payload])

    def test_runtime_inventory_rejects_recomputed_unknown_windows_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = runtime / "payload.dll"
            payload_bytes = b"MZ"
            payload.write_bytes(payload_bytes)
            _builder_metadata(runtime, [payload])
            report_path = runtime / runtime_compliance.BUILDER_REPORT
            report = json.loads(report_path.read_text("utf-8"))
            report["external_system_imports"] = ["kernel32.dll"]
            report["pe_images_scanned"] = 1
            report_path.write_text(
                json.dumps(report), encoding="utf-8", newline="\n"
            )
            artifact = {
                "artifact_id": "cpython@3.13.15",
                "bytes": 1,
                "canonical_name": "cpython",
                "filename": "python.zip",
                "sha256": "a" * 64,
                "url": "https://www.python.org/python.zip",
            }
            members = {
                "schema_version": 1,
                "source_artifact": {
                    key: artifact[key]
                    for key in ("bytes", "filename", "sha256", "url")
                },
                "members": [
                    {
                        "path": payload.name,
                        "sha256": hashlib.sha256(payload_bytes).hexdigest(),
                        "size": len(payload_bytes),
                    }
                ],
            }
            artifact["member_inventory_sha256"] = hashlib.sha256(
                runtime_compliance.json_bytes(members)
            ).hexdigest()

            with mock.patch.object(
                runtime_compliance,
                "parse_pe_imports",
                return_value={"runner-only-not-in-policy.dll"},
            ):
                with self.assertRaisesRegex(
                    runtime_compliance.RuntimeComplianceError,
                    "unsupported external Windows import",
                ):
                    runtime_compliance.build_runtime_inventory(
                        runtime,
                        {"artifacts": [artifact]},
                        "b" * 64,
                        members,
                        [],
                    )

    def test_vex_never_marks_openssl_3021_not_affected(self):
        inventory = {
            "components": {"openssl": "OpenSSL 3.0.21 9 Jun 2026"},
            "files": [{"path": "libssl-3.dll"}],
            "payload_sha256": "a" * 64,
        }
        vex = licenses.build_vex(inventory, [])
        self.assertEqual(len(vex["statements"]), len(licenses.OPENSSL_3022_CVES))
        self.assertEqual({item["status"] for item in vex["statements"]}, {"under_investigation"})
        absent = licenses.build_vex(
            {
                "components": {"openssl": "not-present"},
                "files": [],
                "payload_sha256": "b" * 64,
                "target": {"transport": "winhttp-schannel"},
            },
            [],
        )
        self.assertEqual(
            {item["status"] for item in absent["statements"]}, {"not_affected"}
        )
        self.assertEqual(
            {item["justification"] for item in absent["statements"]},
            {"component_not_present"},
        )
        licenses.validate_openvex_document(absent)
        with self.assertRaisesRegex(licenses.LicenseBundleError, "payload evidence"):
            licenses.build_vex(
                {
                    "components": {"openssl": "not-present"},
                    "files": [{"path": "libcrypto-3-x64.dll"}],
                    "payload_sha256": "c" * 64,
                    "target": {"transport": "winhttp-schannel"},
                },
                [],
            )

    def test_write_bundle_refuses_unmanaged_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "licenses"
            output.mkdir()
            (output / "user-file.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(licenses.LicenseBundleError):
                licenses.write_bundle(
                    output,
                    root / "SBOM.spdx.json",
                    root / "RUNTIME_INVENTORY.json",
                    root / "VEX.openvex.json",
                    {"A/LICENSE.txt": b"license\n"},
                    {"schema_version": licenses.BUNDLE_SCHEMA_VERSION, "files": []},
                    b"{}\n",
                    b"{}\n",
                    b"{}\n",
                )
            self.assertEqual((output / "user-file.txt").read_text("utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
